//! Content-defined chunking and the copy plan of a rollsum delta.
//!
//! A static delta writes a changed object as a sequence of runs. The receiver
//! copies a copy run out of the source object that it already holds. The delta
//! carries a payload run as data. This module finds those runs.
//!
//! A rolling hash cuts both objects into content-defined chunks. An index maps
//! the content digest of each source chunk to its offsets. The planner looks
//! up each target chunk in that index. The content sets the chunk boundaries,
//! so an insertion or a deletion moves only the chunks that it touches. Each
//! chunk after the edit still matches.
//!
//! The chunk parameters belong to ostrya alone. They set the size of the
//! delta. A delta is valid with any values of these parameters. The receiver
//! never sees them. The receiver sees the operation stream that the plan
//! becomes:
//!
//! - A copy run becomes an `r`/`w`/`R` group that names the source object.
//! - A payload run becomes a `w` that reads the data source of the part.
//!
//! The plan emits the runs in target order, and the runs cover the target
//! exactly once, because the operation stream needs this order.

use std::collections::HashMap;

/// The size of the rolling-hash window, in bytes.
///
/// Each byte in the window is part of the hash, so a match resynchronizes
/// within one window of an edit.
const WINDOW: usize = 64;

/// The number of low hash bits that mark a chunk boundary.
///
/// A chunk boundary falls where the low `MASK_BITS` bits of the rolling hash
/// are all set. The average chunk is `2^MASK_BITS` bytes.
const MASK_BITS: u32 = 13;
const MASK: u32 = (1 << MASK_BITS) - 1;

/// The smallest chunk that a boundary can close, in bytes.
///
/// Without this limit, a run of bytes that trigger boundaries can cut a long
/// tail of tiny chunks.
const MIN_CHUNK: usize = 2 * 1024;

/// The largest chunk, in bytes.
///
/// If a stretch of content has no boundary, the chunker cuts it at this size.
/// This limit bounds the work that one mismatch costs. An object smaller than
/// this size has too few chunks for a failed match to show how related the two
/// objects are. `deltagen` uses this size as the bound of its bsdiff attempt.
pub(crate) const MAX_CHUNK: usize = 64 * 1024;

/// One run of a copy plan.
///
/// A run is a range of target bytes. The bytes come from the source object or
/// from the payload of the delta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Run {
    /// A copy of `length` bytes at `source_offset` in the source object.
    Copy { source_offset: u64, length: u64 },
    /// The `length` bytes at `target_offset` in the target, carried as payload.
    Payload { target_offset: u64, length: u64 },
}

/// A copy plan: the runs that rebuild the target, in target order.
#[derive(Debug, Default)]
pub(crate) struct Plan {
    pub(crate) runs: Vec<Run>,
    /// The number of target bytes that `Run::Copy` runs cover.
    pub(crate) copied: u64,
}

/// Returns the plan that rebuilds `target` from `source`.
///
/// A chunk of `target` that occurs in `source` becomes a copy run. Each other
/// chunk becomes a payload run. The plan merges two adjacent runs of the same
/// kind if they are also contiguous in their source. A target that differs
/// from its source in one place gives a small number of runs. Typically these
/// are one copy run, one payload run, and one copy run.
pub(crate) fn plan(source: &[u8], target: &[u8]) -> Plan {
    let index = index_source(source);

    let mut plan = Plan::default();
    for (offset, len) in chunks(target) {
        let chunk = &target[offset..offset + len];
        // The source offset that continues the current run. Repetitive content
        // gives many chunks one digest. The scan tries this candidate first, so
        // the runs merge and the scan stops at its first comparison.
        let contiguous = match plan.runs.last() {
            Some(&Run::Copy {
                source_offset,
                length,
            }) => Some((source_offset + length) as usize),
            _ => None,
        };
        // Both paths compare the bytes before they accept a match. A digest
        // collision costs one comparison and never gives a wrong run. A copy
        // run needs no source chunk boundary at its start. The byte comparison
        // alone decides the contiguous candidate. If that candidate wins, the
        // code computes no digest and does no index lookup.
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
    /// Appends a copy run and adds its length to `copied`.
    ///
    /// If the previous run is a copy run that ends at `source_offset`, the
    /// method extends that run.
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

    /// Appends a payload run.
    ///
    /// If the previous run is a payload run that ends at `target_offset`, the
    /// method extends that run. Consecutive payload chunks always meet this
    /// condition.
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

/// Returns an index that maps each chunk digest of `source` to its offsets.
///
/// The index holds one entry for each chunk, so its size is a fraction of the
/// object size.
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

/// Returns the 64-bit FNV-1a digest of the bytes of a chunk.
fn digest_of(chunk: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &byte in chunk {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Returns the offset and the length of each content-defined chunk of `data`.
///
/// The last chunk ends at the end of `data`, with or without a boundary there.
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

/// Returns the length of the chunk at the start of `data`.
///
/// The chunk ends at the first of these positions:
///
/// - the first boundary at or after `MIN_CHUNK` bytes
/// - `MAX_CHUNK` bytes
/// - the end of `data`
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

/// A rolling sum over the last `WINDOW` bytes.
///
/// The sum has two accumulators. `a` is the sum of the bytes in the window.
/// `b` is the sum of the values of `a`, so the hash depends on the position of
/// each byte in the window.
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
    /// Adds the byte at position `pos` and drops the byte that leaves the
    /// window.
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

    /// Returns `true` if the hash marks a chunk boundary.
    fn at_boundary(&self) -> bool {
        self.b & MASK == MASK
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns deterministic pseudo-random bytes. A fixed seed keeps the tests
    /// stable.
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

    /// Applies a plan to the source and to the bytes of the target. The result
    /// must be the target. The operation stream depends on this property.
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
        // The plan copies most of the object. The plan has at most 5 runs, so
        // the edit costs a bounded number of runs.
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
        // All-zero content never gives a boundary, so each chunk is
        // `MAX_CHUNK` bytes long. All chunks have the same digest. The runs
        // merge only if the candidate that continues the previous run wins.
        // That win also stops the candidate scan at its first comparison.
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
        // The target ends inside a source chunk, so its last chunk is short.
        // The index does not hold the digest of that chunk. The offset that
        // continues the current run holds those bytes. The byte comparison
        // alone makes them a copy, because a copy run needs no source chunk
        // boundary at its start.
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
        // A binary with a zero-padded tail. The edit is in the random part,
        // and the match resynchronizes after it. The plan still copies the
        // repetitive tail.
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
