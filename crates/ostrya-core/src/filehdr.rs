//! File content-object headers and the content checksum.
//!
//! A content object (`.file` / `.filez`) is a header GVariant followed by the
//! payload. Three header wire forms exist:
//!
//! - uncompressed `(uuuusa(ayay))` -- bare-mode streams and checksum
//!   computation;
//! - archive `(tuuuusa(ayay))` -- stored on disk in archive mode, with the
//!   uncompressed payload size prepended;
//! - split-attrs `(uuuusa(ayay)ay)` -- the port's `.filea` object, the
//!   uncompressed header plus a `.fileb` blob reference (empty for symlinks).
//!
//! The scalar fields (uid, gid, mode, rdev, size) are big-endian at the value
//! level; [`FileHeader`] holds them in host order and the (de)serializers
//! convert. On parse, a nonzero rdev and a mode that is neither a regular
//! file nor a symlink are rejected.
//!
//! The on-disk framing of a content stream prefixes the header variant with
//! its length: `[4 bytes BE u32 length][4 NUL bytes][header variant]`. The
//! object checksum is SHA-256 over the framed uncompressed header followed by
//! the raw payload; [`ContentHasher`] computes it.

use ostrya_gvariant::{GvDecode, GvEncode, GvType};
use sha2::{Digest, Sha256};

use crate::be::{Be32, Be64};
use crate::checksum::Checksum;
use crate::error::{Error, Result};
use crate::xattr::Xattrs;

pub(crate) const S_IFMT: u32 = 0o170000;
pub(crate) const S_IFDIR: u32 = 0o040000;
pub(crate) const S_IFREG: u32 = 0o100000;
pub(crate) const S_IFLNK: u32 = 0o120000;

/// The metadata of one file content object, common to all header wire forms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    pub uid: u32,
    pub gid: u32,
    /// Full logical `st_mode`; the file-type bits must name a regular file or
    /// a symlink.
    pub mode: u32,
    /// Symlink target; must be empty for regular files.
    pub symlink_target: String,
    pub xattrs: Xattrs,
}

impl FileHeader {
    /// Whether the mode names a symlink.
    pub fn is_symlink(&self) -> bool {
        self.mode & S_IFMT == S_IFLNK
    }

    fn validate(&self) -> Result<()> {
        match self.mode & S_IFMT {
            S_IFREG => {
                if self.symlink_target.is_empty() {
                    Ok(())
                } else {
                    Err(Error::InvalidFileHeader(
                        "regular file with a symlink target",
                    ))
                }
            }
            S_IFLNK => Ok(()),
            _ => Err(Error::InvalidFileHeader(
                "mode is not a regular file or symlink",
            )),
        }
    }

    fn build(
        uid: u32,
        gid: u32,
        mode: u32,
        rdev: u32,
        target: &str,
        xattrs: &[u8],
    ) -> Result<FileHeader> {
        if rdev != 0 {
            return Err(Error::InvalidFileHeader("rdev is not zero"));
        }
        let header = FileHeader {
            uid,
            gid,
            mode,
            symlink_target: target.to_owned(),
            xattrs: Xattrs::from_gvariant(xattrs)?,
        };
        header.validate()?;
        Ok(header)
    }

    /// Parse the uncompressed header form `(uuuusa(ayay))`.
    pub fn parse(data: &[u8]) -> Result<FileHeader> {
        let (uid, gid, mode, rdev, target, xattrs): (Be32, Be32, Be32, Be32, &str, &[u8]) =
            GvDecode::decode(data)?;
        FileHeader::build(uid.0, gid.0, mode.0, rdev.0, target, xattrs)
    }

    /// Serialize the uncompressed header form `(uuuusa(ayay))`.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(ostrya_gvariant::encode_to_vec(self)?)
    }

    /// Parse the archive header form `(tuuuusa(ayay))`, returning the header
    /// and the uncompressed payload size.
    pub fn parse_archive(data: &[u8]) -> Result<(FileHeader, u64)> {
        let (size, uid, gid, mode, rdev, target, xattrs): (
            Be64,
            Be32,
            Be32,
            Be32,
            Be32,
            &str,
            &[u8],
        ) = GvDecode::decode(data)?;
        Ok((
            FileHeader::build(uid.0, gid.0, mode.0, rdev.0, target, xattrs)?,
            size.0,
        ))
    }

    /// Serialize the archive header form `(tuuuusa(ayay))`.
    pub fn serialize_archive(&self, uncompressed_size: u64) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(ostrya_gvariant::encode_to_vec(&(
            Be64(uncompressed_size),
            Be32(self.uid),
            Be32(self.gid),
            Be32(self.mode),
            Be32(0),
            self.symlink_target.as_str(),
            &self.xattrs,
        ))?)
    }

    /// Parse the split-attrs `.filea` form `(uuuusa(ayay)ay)`, returning the
    /// header and the `.fileb` blob reference (`None` for symlinks).
    pub fn parse_split_attrs(data: &[u8]) -> Result<(FileHeader, Option<Checksum>)> {
        let (uid, gid, mode, rdev, target, xattrs, blob): (
            Be32,
            Be32,
            Be32,
            Be32,
            &str,
            &[u8],
            &[u8],
        ) = GvDecode::decode(data)?;
        let header = FileHeader::build(uid.0, gid.0, mode.0, rdev.0, target, xattrs)?;
        let blob = match (header.is_symlink(), blob.len()) {
            (true, 0) => None,
            (true, _) => return Err(Error::InvalidFileHeader("symlink with a blob reference")),
            (false, 32) => Some(Checksum::from_ay(blob)?),
            (false, _) => {
                return Err(Error::InvalidFileHeader("blob reference is not 32 bytes"));
            }
        };
        Ok((header, blob))
    }

    /// Serialize the split-attrs `.filea` form `(uuuusa(ayay)ay)`. A regular
    /// file must reference its payload blob; a symlink must not.
    pub fn serialize_split_attrs(&self, blob: Option<&Checksum>) -> Result<Vec<u8>> {
        self.validate()?;
        let blob: &[u8] = match (self.is_symlink(), blob) {
            (true, None) => &[],
            (true, Some(_)) => {
                return Err(Error::InvalidFileHeader("symlink with a blob reference"));
            }
            (false, Some(c)) => c.as_bytes(),
            (false, None) => {
                return Err(Error::InvalidFileHeader(
                    "regular file without a blob reference",
                ));
            }
        };
        Ok(ostrya_gvariant::encode_to_vec(&(
            Be32(self.uid),
            Be32(self.gid),
            Be32(self.mode),
            Be32(0),
            self.symlink_target.as_str(),
            &self.xattrs,
            blob,
        ))?)
    }
}

/// The uncompressed header form, `(uuuusa(ayay))`.
impl GvType for FileHeader {
    const SIGNATURE: &'static str = "(uuuusa(ayay))";
    // Greatest member alignment: the u32 fields.
    const ALIGNMENT: usize = 4;
    const FIXED_SIZE: Option<usize> = None;
}

/// The encode path is purely mechanical: domain validation runs in the
/// `serialize*` entry points, which are the only callers.
impl GvEncode for FileHeader {
    fn encode(&self, out: &mut Vec<u8>) -> ostrya_gvariant::Result<()> {
        (
            Be32(self.uid),
            Be32(self.gid),
            Be32(self.mode),
            Be32(0),
            self.symlink_target.as_str(),
            &self.xattrs,
        )
            .encode(out)
    }
}

/// Prefix serialized header bytes with the content-stream framing:
/// `[4 bytes BE u32 length][4 NUL bytes][header]`.
pub fn frame(header: &[u8]) -> Result<Vec<u8>> {
    let len = u32::try_from(header.len())
        .map_err(|_| Error::InvalidFileHeader("header exceeds the framing length limit"))?;
    let mut out = Vec::with_capacity(8 + header.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(header);
    Ok(out)
}

/// Split a framed content stream into the header variant bytes and the
/// remainder (the payload, where present).
pub fn split_framed(data: &[u8]) -> Result<(&[u8], &[u8])> {
    if data.len() < 8 {
        return Err(Error::InvalidFileHeader(
            "framed stream is shorter than its length prefix",
        ));
    }
    let len = u32::from_be_bytes(data[..4].try_into().unwrap()) as usize;
    if data[4..8] != [0u8; 4] {
        return Err(Error::InvalidFileHeader("framing padding is not zero"));
    }
    let end = 8usize
        .checked_add(len)
        .filter(|&end| end <= data.len())
        .ok_or(Error::InvalidFileHeader(
            "framed header length is out of bounds",
        ))?;
    Ok((&data[8..end], &data[end..]))
}

/// Computes a content-object checksum: SHA-256 over the framed uncompressed
/// header followed by the raw (uncompressed) payload. Symlinks carry no
/// payload, so their checksum is [`finish`](ContentHasher::finish) right
/// after construction.
pub struct ContentHasher {
    hasher: Sha256,
}

impl ContentHasher {
    /// Start a checksum with the framed uncompressed form of `header`. The
    /// framing prefix and the header bytes are fed to the hasher directly,
    /// without materializing the framed buffer.
    pub fn new(header: &FileHeader) -> Result<ContentHasher> {
        let serialized = header.serialize()?;
        let len = u32::try_from(serialized.len())
            .map_err(|_| Error::InvalidFileHeader("header exceeds the framing length limit"))?;
        let mut hasher = Sha256::new();
        hasher.update(len.to_be_bytes());
        hasher.update([0u8; 4]);
        hasher.update(&serialized);
        Ok(ContentHasher { hasher })
    }

    /// Feed the next chunk of raw payload.
    pub fn update(&mut self, payload: &[u8]) {
        self.hasher.update(payload);
    }

    /// The content-object checksum.
    pub fn finish(self) -> Checksum {
        Checksum::from_bytes(self.hasher.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ostrya_gvariant::{Type, Value, to_bytes};

    fn regular(mode: u32) -> FileHeader {
        FileHeader {
            uid: 1000,
            gid: 1000,
            mode,
            symlink_target: String::new(),
            xattrs: Xattrs::empty(),
        }
    }

    fn symlink(target: &str) -> FileHeader {
        FileHeader {
            uid: 0,
            gid: 0,
            mode: 0o120777,
            symlink_target: target.to_owned(),
            xattrs: Xattrs::empty(),
        }
    }

    #[test]
    fn uncompressed_form_round_trips() {
        let header = FileHeader {
            xattrs: Xattrs::new([(b"user.a\0".to_vec(), b"1".to_vec())]).unwrap(),
            ..regular(0o100644)
        };
        let bytes = header.serialize().unwrap();
        assert_eq!(FileHeader::parse(&bytes).unwrap(), header);

        let link = symlink("target");
        let bytes = link.serialize().unwrap();
        assert_eq!(FileHeader::parse(&bytes).unwrap(), link);
    }

    #[test]
    fn archive_form_round_trips_with_the_size() {
        let header = regular(0o100755);
        let bytes = header.serialize_archive(1234).unwrap();
        assert_eq!(FileHeader::parse_archive(&bytes).unwrap(), (header, 1234));
    }

    #[test]
    fn split_attrs_form_round_trips() {
        let header = regular(0o100600);
        let blob = Checksum::sha256(b"payload");
        let bytes = header.serialize_split_attrs(Some(&blob)).unwrap();
        assert_eq!(
            FileHeader::parse_split_attrs(&bytes).unwrap(),
            (header, Some(blob))
        );

        let link = symlink("elsewhere");
        let bytes = link.serialize_split_attrs(None).unwrap();
        assert_eq!(FileHeader::parse_split_attrs(&bytes).unwrap(), (link, None));
    }

    #[test]
    fn split_attrs_blob_reference_rules_are_enforced() {
        assert_eq!(
            regular(0o100644).serialize_split_attrs(None),
            Err(Error::InvalidFileHeader(
                "regular file without a blob reference"
            ))
        );
        let blob = Checksum::sha256(b"");
        assert_eq!(
            symlink("t").serialize_split_attrs(Some(&blob)),
            Err(Error::InvalidFileHeader("symlink with a blob reference"))
        );
    }

    /// Serialize an arbitrary uncompressed-form header through the `Value`
    /// tree, bypassing the struct's validation.
    fn craft(uid: u32, gid: u32, mode: u32, rdev: u32, target: &str) -> Vec<u8> {
        let ty = Type::parse("(uuuusa(ayay))").unwrap();
        let value = Value::Tuple(vec![
            Value::U32(uid.swap_bytes()),
            Value::U32(gid.swap_bytes()),
            Value::U32(mode.swap_bytes()),
            Value::U32(rdev.swap_bytes()),
            Value::Str(target.to_owned()),
            Value::Array(Vec::new()),
        ]);
        to_bytes(&ty, &value).unwrap()
    }

    #[test]
    fn parse_rejects_nonzero_rdev_and_bad_modes() {
        assert_eq!(
            FileHeader::parse(&craft(0, 0, 0o100644, 5, "")),
            Err(Error::InvalidFileHeader("rdev is not zero"))
        );
        for mode in [0o040755, 0o020666, 0o010644, 0o140777] {
            assert_eq!(
                FileHeader::parse(&craft(0, 0, mode, 0, "")),
                Err(Error::InvalidFileHeader(
                    "mode is not a regular file or symlink"
                )),
                "mode {mode:o}"
            );
        }
        assert_eq!(
            FileHeader::parse(&craft(0, 0, 0o100644, 0, "oops")),
            Err(Error::InvalidFileHeader(
                "regular file with a symlink target"
            ))
        );
    }

    #[test]
    fn serialize_rejects_what_parse_rejects() {
        assert!(regular(0o040755).serialize().is_err());
        let mut bad = regular(0o100644);
        bad.symlink_target = "oops".into();
        assert!(bad.serialize().is_err());
    }

    #[test]
    fn framing_round_trips_and_is_strict() {
        let header = regular(0o100644).serialize().unwrap();
        let framed = frame(&header).unwrap();
        assert_eq!(
            u32::from_be_bytes(framed[..4].try_into().unwrap()) as usize,
            header.len()
        );
        assert_eq!(&framed[4..8], [0u8; 4]);
        let with_payload = [framed.clone(), b"payload".to_vec()].concat();
        let (got_header, payload) = split_framed(&with_payload).unwrap();
        assert_eq!(got_header, header);
        assert_eq!(payload, b"payload");

        let mut bad_pad = framed.clone();
        bad_pad[5] = 1;
        assert_eq!(
            split_framed(&bad_pad),
            Err(Error::InvalidFileHeader("framing padding is not zero"))
        );
        let mut bad_len = framed;
        bad_len[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            split_framed(&bad_len),
            Err(Error::InvalidFileHeader(
                "framed header length is out of bounds"
            ))
        );
        assert!(split_framed(&[0u8; 7]).is_err());
    }

    #[test]
    fn symlink_checksum_hashes_the_framed_header_only() {
        let link = symlink("hello.txt");
        let framed = frame(&link.serialize().unwrap()).unwrap();
        assert_eq!(
            ContentHasher::new(&link).unwrap().finish(),
            Checksum::sha256(&framed)
        );
    }

    #[test]
    fn scalar_fields_are_big_endian_on_the_wire() {
        // uid/gid/mode/rdev are the first four u32 members of (uuuusa(ayay))
        // and are stored big-endian; a missed or asymmetric swap shows here.
        let header = regular(0o100644); // uid 1000, gid 1000
        let bytes = header.serialize().unwrap();
        assert_eq!(&bytes[0..4], &1000u32.to_be_bytes());
        assert_eq!(&bytes[4..8], &1000u32.to_be_bytes());
        assert_eq!(&bytes[8..12], &0o100644u32.to_be_bytes());
        assert_eq!(&bytes[12..16], &[0, 0, 0, 0]);
        assert_eq!(FileHeader::parse(&bytes).unwrap(), header);
    }

    #[test]
    fn the_three_wire_forms_agree_on_the_common_fields() {
        let header = FileHeader {
            xattrs: Xattrs::new([(b"user.a\0".to_vec(), b"1".to_vec())]).unwrap(),
            ..regular(0o100640)
        };
        let blob = Checksum::sha256(b"payload");
        let from_uncompressed = FileHeader::parse(&header.serialize().unwrap()).unwrap();
        let (from_archive, _) =
            FileHeader::parse_archive(&header.serialize_archive(4096).unwrap()).unwrap();
        let (from_split, _) =
            FileHeader::parse_split_attrs(&header.serialize_split_attrs(Some(&blob)).unwrap())
                .unwrap();
        assert_eq!(from_uncompressed, header);
        assert_eq!(from_archive, header);
        assert_eq!(from_split, header);
    }
}
