//! fs-verity digest computation in userspace.
//!
//! The digest is the fs-verity measurement with SHA-256, 4096-byte blocks, and
//! a zero-length salt. It is a Merkle tree over the data: each 4096-byte block
//! (the final block zero-padded) is hashed; block hashes are packed into
//! parent blocks (128 hashes per block) and hashed recursively up to a single
//! root hash. The digest is the SHA-256 of a 256-byte descriptor carrying the
//! root hash and the total data size.
//!
//! The hasher is streaming: feed data with [`FsVerityHasher::update`] in any
//! chunking, then call [`FsVerityHasher::finalize`]. This is reused for the
//! whole composefs image and, by the ostree layer, for each backing object.

use sha2::{Digest, Sha256};

/// log2 of the fs-verity block size (4096 bytes).
const LG_BLOCK: u32 = 12;
/// The fs-verity block size in bytes.
const BLOCK: usize = 1 << LG_BLOCK;
/// SHA-256 kernel algorithm identifier for the fs-verity descriptor.
const ALGORITHM_SHA256: u8 = 1;

/// One level of the Merkle tree: a SHA-256 context filling one block.
struct Layer {
    context: Sha256,
    remaining: usize,
}

impl Layer {
    fn new() -> Self {
        Self {
            context: Sha256::new(),
            remaining: BLOCK,
        }
    }

    fn add(&mut self, data: &[u8]) {
        self.context.update(data);
        self.remaining -= data.len();
    }

    /// Zero-pad to a full block and finalize, returning the block hash and
    /// resetting for reuse.
    fn complete(&mut self) -> [u8; 32] {
        let pad = self.remaining;
        self.context.update(vec![0u8; pad]);
        let out: [u8; 32] = std::mem::replace(&mut self.context, Sha256::new())
            .finalize()
            .into();
        self.remaining = BLOCK;
        out
    }
}

/// Streaming fs-verity digest hasher (SHA-256, 4096-byte blocks, zero salt).
pub struct FsVerityHasher {
    layers: Vec<Layer>,
    value: Option<[u8; 32]>,
    n_bytes: u64,
    partial: Vec<u8>,
    wrote_final_block: bool,
}

impl Default for FsVerityHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl FsVerityHasher {
    /// Create a new hasher.
    pub fn new() -> Self {
        Self {
            layers: Vec::new(),
            value: None,
            n_bytes: 0,
            partial: Vec::with_capacity(BLOCK),
            wrote_final_block: false,
        }
    }

    /// Hash a complete buffer and return the digest.
    pub fn hash(buffer: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(buffer);
        hasher.finalize()
    }

    /// Feed data into the hasher.
    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let want = BLOCK - self.partial.len();
            let take = want.min(data.len());
            self.partial.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.partial.len() == BLOCK {
                let block = std::mem::replace(&mut self.partial, Vec::with_capacity(BLOCK));
                self.add_block(&block);
            }
        }
    }

    /// Finalize and return the fs-verity digest.
    pub fn finalize(mut self) -> [u8; 32] {
        if !self.partial.is_empty() {
            let block = std::mem::take(&mut self.partial);
            self.add_block(&block);
        }

        let root = self.root_hash();

        let mut context = Sha256::new();
        context.update(1u8.to_le_bytes()); // version
        context.update(ALGORITHM_SHA256.to_le_bytes()); // hash algorithm
        context.update((LG_BLOCK as u8).to_le_bytes()); // log2 block size
        context.update(0u8.to_le_bytes()); // salt size
        context.update([0u8; 4]); // reserved
        context.update(self.n_bytes.to_le_bytes()); // data size
        context.update(root); // root hash ...
        context.update([0u8; 32]); // ... padded to 64 bytes
        context.update([0u8; 32]); // salt
        context.update([0u8; 144]); // reserved
        context.finalize().into()
    }

    fn add_block(&mut self, data: &[u8]) {
        assert!(!self.wrote_final_block, "data added after a partial block");
        if data.len() < BLOCK {
            self.wrote_final_block = true;
        }

        // A previously completed root value becomes the seed of a new layer.
        if let Some(value) = self.value.take() {
            let mut new_layer = Layer::new();
            new_layer.add(&value);
            self.layers.push(new_layer);
        }

        let mut context = Layer::new();
        context.add(data);
        let mut value = context.complete();
        self.n_bytes += data.len() as u64;

        for layer in self.layers.iter_mut() {
            layer.add(&value);
            if layer.remaining != 0 {
                return;
            }
            value = layer.complete();
        }

        self.value = Some(value);
    }

    fn root_hash(&mut self) -> [u8; 32] {
        if let Some(value) = self.value {
            return value;
        }
        let mut value = [0u8; 32];
        for layer in self.layers.iter_mut() {
            if value != [0u8; 32] {
                layer.add(&value);
            }
            if layer.remaining != BLOCK {
                value = layer.complete();
            } else {
                value = [0u8; 32];
            }
        }
        self.value = Some(value);
        value
    }
}

#[cfg(test)]
mod tests {
    use super::FsVerityHasher;

    fn hex(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn empty_file() {
        // fs-verity digest of a zero-length file (well-known value).
        assert_eq!(
            hex(&FsVerityHasher::hash(b"")),
            "3d248ca542a24fc62d1c43b916eae5016878e2533c88238480b26128a1f1af95"
        );
    }

    #[test]
    fn partial_and_multi_block() {
        // Single partial block.
        assert_eq!(
            hex(&FsVerityHasher::hash(b"Hello, ostree")),
            "265d3cbf204486354408d7fd9e41780cc61817b2a5dc5034597b5fcb9b638ec4"
        );

        // One full block plus a partial tail (spans two Merkle leaves).
        let five_k: Vec<u8> = (0..5000).map(|i| (i % 251) as u8).collect();
        assert_eq!(
            hex(&FsVerityHasher::hash(&five_k)),
            "219c2df1dc52c12b7f666570d48b3f57c2e1ef58aa4734111f36773c8e731829"
        );

        // Exactly two full blocks (no partial tail).
        let eight_k: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
        assert_eq!(
            hex(&FsVerityHasher::hash(&eight_k)),
            "e48d50c56c4f0178a98a035cb91d66be328eeff78bbddaa35c5ec4cc0d8340c0"
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        // Feeding data in small, block-unaligned chunks yields the same digest.
        let data: Vec<u8> = (0..20_000).map(|i| (i * 7 % 253) as u8).collect();
        let oneshot = FsVerityHasher::hash(&data);
        let mut streamed = FsVerityHasher::new();
        for chunk in data.chunks(37) {
            streamed.update(chunk);
        }
        assert_eq!(streamed.finalize(), oneshot);
    }
}
