//! Content-defined chunking and the copy plan a rollsum delta is built from.
//!
//! A static delta expresses a modified object as a sequence of runs: runs the
//! receiver copies out of the source object it already has, and runs the delta
//! carries as payload. Finding those runs is what this module does. Both
//! objects are cut into content-defined chunks by a rolling hash, the source's
//! chunks are indexed by content digest, and the target's chunks are matched
//! against that index. Chunk boundaries follow content rather than position, so
//! an insertion or deletion shifts only the chunks it touches and every chunk
//! after the edit still matches.
//!
//! The chunker's parameters are this port's own: they decide how large the
//! resulting delta is, not whether it is valid, and the receiver never sees
//! them. What the receiver sees is the operation stream the plan turns into
//! (`format-reference.md`, "Static delta wire format"): a copy run becomes an
//! `r`/`w`/`R` group naming the source object, and a payload run becomes a `w`
//! reading the part's own data source. Runs are therefore emitted in target
//! order and cover the target exactly once.

use std::collections::HashMap;

/// The rolling-hash window. Every byte in the window contributes to the hash,
/// so a match resynchronizes within one window of an edit.
const WINDOW: usize = 64;

/// A chunk boundary falls where the low [`MASK_BITS`] bits of the rolling hash
/// are all set, giving an average chunk of `2^MASK_BITS` bytes.
const MASK_BITS: u32 = 13;
const MASK: u32 = (1 << MASK_BITS) - 1;

/// The smallest chunk a boundary may close, so a run of boundary-triggering
/// bytes cannot produce a long tail of tiny chunks.
const MIN_CHUNK: usize = 2 * 1024;

/// The largest chunk emitted; a stretch of content with no boundary is cut
/// here, bounding the work a single mismatch can cost. It is also the size below
/// which an object is too few chunks for a failed match to say anything about
/// how related the two objects are, which is what bounds the bsdiff attempt in
/// [`crate::deltagen`].
pub(crate) const MAX_CHUNK: usize = 64 * 1024;

/// One run of a copy plan: bytes of the target that either come from the source
/// object or are carried in the delta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Run {
    /// Copy `length` bytes from `source_offset` in the source object.
    Copy { source_offset: u64, length: u64 },
    /// Take `length` bytes at `target_offset` from the target's own content.
    Payload { target_offset: u64, length: u64 },
}

/// A copy plan: the runs that reconstruct the target, in target order.
#[derive(Debug, Default)]
pub(crate) struct Plan {
    pub(crate) runs: Vec<Run>,
    /// The number of target bytes covered by [`Run::Copy`] runs.
    pub(crate) copied: u64,
}

/// Plan the reconstruction of `target` from `source`.
///
/// Chunks of `target` found in `source` become copy runs and the rest becomes
/// payload runs; adjacent runs of the same kind that are also contiguous in
/// their source are merged, so a target that differs from its source in one
/// place yields one copy run, one payload run, and one copy run rather than one
/// run per chunk.
pub(crate) fn plan(source: &[u8], target: &[u8]) -> Plan {
    let index = index_source(source);

    let mut plan = Plan::default();
    for (offset, len) in chunks(target) {
        let chunk = &target[offset..offset + len];
        // The offset that continues the run in progress. Repetitive content
        // gives many chunks one digest, so trying this candidate first is what
        // merges the runs and what stops the scan at its first comparison.
        let contiguous = match plan.runs.last() {
            Some(&Run::Copy {
                source_offset,
                length,
            }) => Some((source_offset + length) as usize),
            _ => None,
        };
        // Either path confirms the match by comparing the bytes, so a digest
        // collision costs one comparison and never produces a wrong run. A copy
        // run needs no source chunk boundary at its start, so the contiguous
        // candidate is decided by that comparison alone and neither the digest
        // nor the index is computed when it wins.
        let hit = contiguous
            .filter(|off| source[*off..].starts_with(chunk))
            .or_else(|| {
                index
                    .get(&digest_of(chunk))
                    .into_iter()
                    .flatten()
                    .copied()
                    .find(|&off| source[off..].starts_with(chunk))
            });
        match hit {
            Some(src_off) => plan.push_copy(src_off as u64, len as u64),
            None => plan.push_payload(offset as u64, len as u64),
        }
    }
    plan
}

impl Plan {
    /// Append a copy run, extending the previous run when it copies the
    /// immediately preceding source bytes.
    fn push_copy(&mut self, source_offset: u64, length: u64) {
        self.copied += length;
        if let Some(Run::Copy {
            source_offset: prev_off,
            length: prev_len,
        }) = self.runs.last_mut()
            && *prev_off + *prev_len == source_offset
        {
            *prev_len += length;
            return;
        }
        self.runs.push(Run::Copy {
            source_offset,
            length,
        });
    }

    /// Append a payload run, extending the previous run when it ends where this
    /// one begins (which consecutive payload chunks always do).
    fn push_payload(&mut self, target_offset: u64, length: u64) {
        if let Some(Run::Payload {
            target_offset: prev_off,
            length: prev_len,
        }) = self.runs.last_mut()
            && *prev_off + *prev_len == target_offset
        {
            *prev_len += length;
            return;
        }
        self.runs.push(Run::Payload {
            target_offset,
            length,
        });
    }
}

/// Index the source's chunks by content digest, mapping each digest to the
/// offsets of the chunks that carry it. The index holds one entry per chunk
/// rather than per byte, so it costs a fraction of the object's size.
fn index_source(source: &[u8]) -> HashMap<u64, Vec<usize>> {
    let mut index: HashMap<u64, Vec<usize>> = HashMap::new();
    for (offset, len) in chunks(source) {
        index
            .entry(digest_of(&source[offset..offset + len]))
            .or_default()
            .push(offset);
    }
    index
}

/// A 64-bit FNV-1a digest of a chunk's bytes.
fn digest_of(chunk: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &byte in chunk {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Cut `data` into content-defined chunks, yielding each chunk's offset and
/// length. The final chunk ends at the end of the data whether or not a
/// boundary falls there.
fn chunks(data: &[u8]) -> impl Iterator<Item = (usize, usize)> + '_ {
    let mut start = 0usize;
    std::iter::from_fn(move || {
        if start >= data.len() {
            return None;
        }
        let len = chunk_len(&data[start..]);
        let out = (start, len);
        start += len;
        Some(out)
    })
}

/// The length of the chunk beginning at the start of `data`: up to the first
/// boundary at or past [`MIN_CHUNK`], else [`MAX_CHUNK`], else the rest.
fn chunk_len(data: &[u8]) -> usize {
    let mut roll = Rollsum::default();
    let limit = data.len().min(MAX_CHUNK);
    for (i, &byte) in data[..limit].iter().enumerate() {
        roll.push(byte, i);
        if i + 1 >= MIN_CHUNK && roll.at_boundary() {
            return i + 1;
        }
    }
    limit
}

/// A rolling sum over the trailing [`WINDOW`] bytes: two accumulators, the
/// first the sum of the window's bytes and the second the sum of the first,
/// which makes the hash position-sensitive within the window.
struct Rollsum {
    a: u32,
    b: u32,
    window: [u8; WINDOW],
}

impl Default for Rollsum {
    fn default() -> Self {
        Rollsum {
            a: 0,
            b: 0,
            window: [0; WINDOW],
        }
    }
}

impl Rollsum {
    /// Add the byte at position `pos`, dropping the byte that leaves the window.
    fn push(&mut self, byte: u8, pos: usize) {
        let slot = pos % WINDOW;
        let dropped = self.window[slot];
        self.window[slot] = byte;
        self.a = self
            .a
            .wrapping_add(u32::from(byte))
            .wrapping_sub(u32::from(dropped));
        self.b = self
            .b
            .wrapping_add(self.a)
            .wrapping_sub(WINDOW as u32 * u32::from(dropped));
    }

    /// Whether the hash marks a chunk boundary.
    fn at_boundary(&self) -> bool {
        self.b & MASK == MASK
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic pseudo-random bytes; a fixed seed keeps the tests stable.
    fn data(len: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x & 0xff) as u8
            })
            .collect()
    }

    /// Apply a plan against the source and the target's own bytes; the result
    /// must be the target. This is the property the operation stream relies on.
    fn reconstruct(plan: &Plan, source: &[u8], target: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for run in &plan.runs {
            match *run {
                Run::Copy {
                    source_offset,
                    length,
                } => {
                    let start = source_offset as usize;
                    out.extend_from_slice(&source[start..start + length as usize]);
                }
                Run::Payload {
                    target_offset,
                    length,
                } => {
                    let start = target_offset as usize;
                    out.extend_from_slice(&target[start..start + length as usize]);
                }
            }
        }
        out
    }

    #[test]
    fn chunks_cover_the_input_exactly_once() {
        let bytes = data(500_000, 7);
        let mut position = 0;
        for (offset, len) in chunks(&bytes) {
            assert_eq!(offset, position);
            assert!(len > 0 && len <= MAX_CHUNK);
            position += len;
        }
        assert_eq!(position, bytes.len());
    }

    #[test]
    fn identical_input_plans_one_copy_run() {
        let bytes = data(300_000, 11);
        let plan = plan(&bytes, &bytes);
        assert_eq!(
            plan.runs,
            vec![Run::Copy {
                source_offset: 0,
                length: bytes.len() as u64
            }]
        );
        assert_eq!(plan.copied, bytes.len() as u64);
    }

    #[test]
    fn an_in_place_edit_keeps_the_surrounding_runs() {
        let source = data(400_000, 13);
        let mut target = source.clone();
        for byte in &mut target[200_000..200_512] {
            *byte = !*byte;
        }

        let plan = plan(&source, &target);
        assert_eq!(reconstruct(&plan, &source, &target), target);
        // Most of the object is copied, and the edit costs a bounded number of
        // runs rather than one per chunk.
        assert!(plan.copied > 300_000, "copied only {}", plan.copied);
        assert!(plan.runs.len() <= 5, "runs: {:?}", plan.runs);
    }

    #[test]
    fn an_insertion_resynchronizes() {
        let source = data(400_000, 17);
        let mut target = source[..150_000].to_vec();
        target.extend_from_slice(&data(1_000, 19));
        target.extend_from_slice(&source[150_000..]);

        let plan = plan(&source, &target);
        assert_eq!(reconstruct(&plan, &source, &target), target);
        assert!(plan.copied > 300_000, "copied only {}", plan.copied);
    }

    #[test]
    fn repetitive_content_plans_one_copy_run() {
        // All-zero content never triggers a boundary, so every chunk is
        // MAX_CHUNK long and they all carry the same digest. The candidate that
        // continues the previous run has to win for the runs to merge, and for
        // the candidate scan to stop at its first comparison.
        let bytes = vec![0u8; 16 * MAX_CHUNK];
        let plan = plan(&bytes, &bytes);
        assert_eq!(reconstruct(&plan, &bytes, &bytes), bytes);
        assert_eq!(
            plan.runs,
            vec![Run::Copy {
                source_offset: 0,
                length: bytes.len() as u64
            }]
        );
        assert_eq!(plan.copied, bytes.len() as u64);
    }

    #[test]
    fn a_contiguous_continuation_copies_without_a_digest_match() {
        // A target that ends inside a source chunk cuts its last chunk short, so
        // that chunk carries a digest the index does not hold. The offset that
        // continues the run in progress holds those bytes, and the byte
        // comparison alone is what makes them a copy: a copy run does not have
        // to begin on a source chunk boundary.
        let source = data(300_000, 41);
        let target = &source[..source.len() - 1];

        let (offset, len) = chunks(target).last().unwrap();
        assert!(
            !index_source(&source).contains_key(&digest_of(&target[offset..offset + len])),
            "the last chunk's digest is in the index, so the case is not exercised"
        );

        let plan = plan(&source, target);
        assert_eq!(reconstruct(&plan, &source, target), target);
        assert_eq!(
            plan.runs,
            vec![Run::Copy {
                source_offset: 0,
                length: target.len() as u64
            }]
        );
        assert_eq!(plan.copied, target.len() as u64);
    }

    #[test]
    fn a_zero_padded_tail_survives_an_edit_before_it() {
        // A binary with a zero-padded tail: the edit resynchronizes in the
        // random part and the repetitive tail still plans as copies.
        let mut source = data(200_000, 37);
        source.resize(200_000 + 8 * MAX_CHUNK, 0);
        let mut target = source.clone();
        for byte in &mut target[100_000..100_512] {
            *byte = !*byte;
        }

        let plan = plan(&source, &target);
        assert_eq!(reconstruct(&plan, &source, &target), target);
        assert!(
            plan.copied > (7 * MAX_CHUNK) as u64,
            "copied only {}",
            plan.copied
        );
        assert!(plan.runs.len() <= 5, "runs: {:?}", plan.runs);
    }

    #[test]
    fn unrelated_input_plans_payload_only() {
        let source = data(100_000, 23);
        let target = data(100_000, 29);
        let plan = plan(&source, &target);
        assert_eq!(plan.copied, 0);
        assert_eq!(reconstruct(&plan, &source, &target), target);
    }

    #[test]
    fn empty_target_plans_nothing() {
        let plan = plan(&data(1_000, 31), &[]);
        assert!(plan.runs.is_empty());
        assert_eq!(plan.copied, 0);
    }
}
