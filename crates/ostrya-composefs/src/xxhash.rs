//! xxHash32, the hash of the EROFS xattr name filter.
//!
//! The name filter of an inode is a 32-bit Bloom filter over the names of its
//! xattrs. Each name sets the bit `xxh32(suffix, seed) % 32`. `suffix` is the
//! name without its prefix, and `seed` is `XATTR_FILTER_SEED + prefix_index`.
//! The inode stores the inverted word `!filter`. A set bit in the stored word
//! means that no xattr name of the inode has that bit.
//!
//! The name filter is the one use of xxHash32. The crate computes it itself, so
//! it needs no dependency.

const PRIME1: u32 = 0x9E37_79B1;
const PRIME2: u32 = 0x85EB_CA77;
const PRIME3: u32 = 0xC2B2_AE3D;
const PRIME4: u32 = 0x27D4_EB2F;
const PRIME5: u32 = 0x1656_67B1;

fn read_u32(data: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]])
}

fn round(acc: u32, lane: u32) -> u32 {
    acc.wrapping_add(lane.wrapping_mul(PRIME2))
        .rotate_left(13)
        .wrapping_mul(PRIME1)
}

/// Returns the 32-bit xxHash of `data` with the seed `seed`.
pub fn xxh32(data: &[u8], seed: u32) -> u32 {
    let len = data.len();
    let mut i = 0;
    let mut h: u32;

    if len >= 16 {
        let mut v1 = seed.wrapping_add(PRIME1).wrapping_add(PRIME2);
        let mut v2 = seed.wrapping_add(PRIME2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(PRIME1);
        while i + 16 <= len {
            v1 = round(v1, read_u32(data, i));
            v2 = round(v2, read_u32(data, i + 4));
            v3 = round(v3, read_u32(data, i + 8));
            v4 = round(v4, read_u32(data, i + 12));
            i += 16;
        }
        h = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
    } else {
        h = seed.wrapping_add(PRIME5);
    }

    h = h.wrapping_add(len as u32);

    while i + 4 <= len {
        h = h
            .wrapping_add(read_u32(data, i).wrapping_mul(PRIME3))
            .rotate_left(17)
            .wrapping_mul(PRIME4);
        i += 4;
    }
    while i < len {
        h = h
            .wrapping_add(u32::from(data[i]).wrapping_mul(PRIME5))
            .rotate_left(11)
            .wrapping_mul(PRIME1);
        i += 1;
    }

    h ^= h >> 15;
    h = h.wrapping_mul(PRIME2);
    h ^= h >> 13;
    h = h.wrapping_mul(PRIME3);
    h ^= h >> 16;
    h
}

#[cfg(test)]
mod tests {
    use super::xxh32;

    // The name-filter seed of EROFS. The golden images pin these results: each
    // bit is clear in the stored filter word of an inode with that xattr.
    const SEED: u32 = 0x25BB_E08F;

    fn bit(name: &[u8], prefix_index: u32) -> u32 {
        xxh32(name, SEED + prefix_index) % 32
    }

    #[test]
    fn golden_filter_bits() {
        // trusted. is prefix index 4.
        assert_eq!(bit(b"overlay.opaque", 4), 20);
        assert_eq!(bit(b"overlay.metacopy", 4), 31);
        assert_eq!(bit(b"overlay.redirect", 4), 17);
    }

    #[test]
    fn reference_vectors() {
        // Canonical xxHash32 test vectors for the empty input.
        assert_eq!(xxh32(b"", 0), 0x02CC_5D05);
        assert_eq!(xxh32(b"", 0x9E3779B1), 0x36B7_8AE7);
    }
}
