//! `ostree.sizes` packed entries.
//!
//! The commit-metadata key `ostree.sizes` has value type `aay`: an array of
//! packed byte buffers, one per object, sorted by ASCII checksum. Each buffer
//! is:
//!
//! ```text
//! [32 bytes checksum][varuint64 compressed size][varuint64 unpacked size][1 byte objtype]
//! ```
//!
//! The trailing objtype byte is present on newer commits; a parser tolerates
//! its absence.

use crate::checksum::Checksum;
use crate::error::{Error, Result};
use crate::objtype::ObjectType;
use crate::varint;

/// One decoded `ostree.sizes` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SizeEntry {
    /// The object identity.
    pub checksum: Checksum,
    /// On-disk (compressed) size in bytes.
    pub compressed: u64,
    /// Uncompressed size in bytes.
    pub unpacked: u64,
    /// Object type, absent on older commits that omit the trailing byte.
    pub objtype: Option<ObjectType>,
}

/// Append the packed form of one entry to `out`.
pub fn pack_entry(entry: &SizeEntry, out: &mut Vec<u8>) {
    out.extend_from_slice(entry.checksum.as_bytes());
    varint::encode(entry.compressed, out);
    varint::encode(entry.unpacked, out);
    if let Some(ty) = entry.objtype {
        out.push(ty.as_u32() as u8);
    }
}

/// Decode one packed entry from exactly `buf`.
pub fn unpack_entry(buf: &[u8]) -> Result<SizeEntry> {
    if buf.len() < 32 {
        return Err(Error::InvalidSizeEntry("entry is shorter than a checksum"));
    }
    let checksum = Checksum::from_ay(&buf[..32])?;
    let mut pos = 32;
    let (compressed, n) = varint::decode(&buf[pos..])?;
    pos += n;
    let (unpacked, m) = varint::decode(&buf[pos..])?;
    pos += m;
    let objtype = match buf.len() - pos {
        0 => None,
        1 => Some(ObjectType::from_u32(u32::from(buf[pos]))?),
        _ => return Err(Error::InvalidSizeEntry("entry has trailing bytes")),
    };
    Ok(SizeEntry {
        checksum,
        compressed,
        unpacked,
        objtype,
    })
}

/// Pack a set of entries into the `aay` element buffers, sorted by ASCII
/// checksum. Byte-wise `Checksum` ordering equals lexicographic ordering of
/// the hex form, which is the required entry order.
pub fn pack_sizes(mut entries: Vec<SizeEntry>) -> Vec<Vec<u8>> {
    entries.sort_by(|a, b| a.checksum.cmp(&b.checksum));
    entries
        .iter()
        .map(|e| {
            // Worst case: 32 checksum + two 10-byte varint u64 + 1 objtype.
            let mut buf = Vec::with_capacity(56);
            pack_entry(e, &mut buf);
            buf
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn csum(byte: u8) -> Checksum {
        Checksum::from_bytes([byte; 32])
    }

    #[test]
    fn entry_round_trips_with_objtype() {
        let entry = SizeEntry {
            checksum: csum(0xab),
            compressed: 300,
            unpacked: 16384,
            objtype: Some(ObjectType::File),
        };
        let mut buf = Vec::new();
        pack_entry(&entry, &mut buf);
        // 32 checksum + 2 (varint 300) + 3 (varint 16384) + 1 objtype.
        assert_eq!(buf.len(), 32 + 2 + 3 + 1);
        assert_eq!(unpack_entry(&buf).unwrap(), entry);
    }

    #[test]
    fn tolerates_absent_objtype_byte() {
        let entry = SizeEntry {
            checksum: csum(0x01),
            compressed: 1,
            unpacked: 2,
            objtype: None,
        };
        let mut buf = Vec::new();
        pack_entry(&entry, &mut buf);
        assert_eq!(buf.len(), 32 + 1 + 1);
        assert_eq!(unpack_entry(&buf).unwrap().objtype, None);
    }

    #[test]
    fn rejects_trailing_garbage() {
        let mut buf = Vec::new();
        pack_entry(
            &SizeEntry {
                checksum: csum(0x02),
                compressed: 5,
                unpacked: 6,
                objtype: Some(ObjectType::File),
            },
            &mut buf,
        );
        buf.push(0x00);
        assert!(matches!(
            unpack_entry(&buf),
            Err(Error::InvalidSizeEntry("entry has trailing bytes"))
        ));
    }

    #[test]
    fn pack_sizes_sorts_by_checksum() {
        let entries = vec![
            SizeEntry {
                checksum: csum(0xff),
                compressed: 1,
                unpacked: 1,
                objtype: Some(ObjectType::File),
            },
            SizeEntry {
                checksum: csum(0x00),
                compressed: 1,
                unpacked: 1,
                objtype: Some(ObjectType::File),
            },
        ];
        let packed = pack_sizes(entries);
        // First packed buffer must be the 0x00 checksum entry.
        assert_eq!(&packed[0][..32], &[0x00u8; 32]);
        assert_eq!(&packed[1][..32], &[0xffu8; 32]);
    }
}
