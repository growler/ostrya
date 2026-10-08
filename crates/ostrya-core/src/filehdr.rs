//! The header of a content object, its framing, and the content checksum.
//!
//! A content object (a `.file` or a `.filez` object) holds a framed header and
//! then the payload. [`FileHeader`] reads and writes the header. [`frame`] and
//! [`split_framed`] add and remove the framing. [`ContentHasher`] computes the
//! checksum of a content object.

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
///
/// # Wire forms
///
/// The header has two GVariant forms:
///
/// - The uncompressed form `(uuuusa(ayay))` holds the uid, the gid, the mode,
///   the rdev, the symlink target, and the xattrs. The content stream of a
///   bare mode holds this form. The content checksum uses this form.
/// - The archive form `(tuuuusa(ayay))` holds the uncompressed payload size
///   first, then the fields of the uncompressed form. This form is the on-disk
///   form of `archive` mode.
///
/// The scalar fields (uid, gid, mode, rdev, and size) are big-endian in the
/// serialized bytes. A `FileHeader` holds them in host order, and the parse and
/// serialize functions convert them. The serialize functions write an rdev of
/// 0, and the parse functions refuse an rdev that is not 0.
///
/// [`parse_stat_metadata`](FileHeader::parse_stat_metadata) reads a third
/// layout, the `user.ostreemeta` xattr of a `bare-user` file object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    /// The owner uid.
    pub uid: u32,
    /// The owner gid.
    pub gid: u32,
    /// The full logical `st_mode`.
    ///
    /// The file-type bits must name a regular file or a symlink.
    pub mode: u32,
    /// The target of a symlink.
    ///
    /// A regular file must have an empty target.
    pub symlink_target: String,
    /// The extended attributes of the file.
    pub xattrs: Xattrs,
}

impl FileHeader {
    /// Returns `true` if the mode names a symlink.
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

    /// Parses the uncompressed header form `(uuuusa(ayay))`.
    ///
    /// `data` holds the header bytes with no framing. [`split_framed`] removes
    /// the framing.
    ///
    /// # Errors
    ///
    /// - [`Error::Gvariant`] if `data` is not a normal-form GVariant of type
    ///   `(uuuusa(ayay))`, or if the xattr array is not in normal form.
    /// - [`Error::InvalidFileHeader`] with the reason "rdev is not zero" if
    ///   the rdev field is not 0.
    /// - [`Error::InvalidXattrs`] if an xattr name is not in the stored form,
    ///   or if the names are not in strictly increasing byte order. The stored
    ///   form has one trailing NUL, no interior NUL, and a prefix that is not
    ///   empty.
    /// - [`Error::InvalidFileHeader`] with the reason "mode is not a regular
    ///   file or symlink" if the file-type bits of the mode name a different
    ///   type.
    /// - [`Error::InvalidFileHeader`] with the reason "regular file with a
    ///   symlink target" if a regular file has a symlink target that is not
    ///   empty.
    pub fn parse(data: &[u8]) -> Result<FileHeader> {
        let (uid, gid, mode, rdev, target, xattrs): (Be32, Be32, Be32, Be32, &str, &[u8]) =
            GvDecode::decode(data)?;
        FileHeader::build(uid.0, gid.0, mode.0, rdev.0, target, xattrs)
    }

    /// Serializes the uncompressed header form `(uuuusa(ayay))`.
    ///
    /// The output has no framing.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFileHeader`] with the reason "mode is not a regular
    ///   file or symlink" if the file-type bits of [`mode`](Self::mode) name a
    ///   different type.
    /// - [`Error::InvalidFileHeader`] with the reason "regular file with a
    ///   symlink target" if a regular file has a symlink target that is not
    ///   empty.
    /// - [`Error::Gvariant`] if the symlink target holds a NUL byte.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(ostrya_gvariant::encode_to_vec(self)?)
    }

    /// Parses the stat-metadata form `(uuua(ayay))`.
    ///
    /// The form holds the uid, the gid, and the full `st_mode`, big-endian,
    /// then the sorted xattr array. It is the layout of a dirmeta object. It is
    /// also the layout of the `user.ostreemeta` xattr of a `.file` object in
    /// `bare-user` mode.
    ///
    /// The form has no rdev field and no symlink-target field, so the returned
    /// header has an empty target. A `bare-user` symlink has a symlink
    /// `st_mode` in this form and keeps its target in the file content. The
    /// caller reads the target from the file content.
    ///
    /// # Errors
    ///
    /// - [`Error::Gvariant`] if `data` is not a normal-form GVariant of type
    ///   `(uuua(ayay))`, or if the xattr array is not in normal form.
    /// - [`Error::InvalidXattrs`] if an xattr name is not in the stored form,
    ///   or if the names are not in strictly increasing byte order. The stored
    ///   form has one trailing NUL, no interior NUL, and a prefix that is not
    ///   empty.
    /// - [`Error::InvalidFileHeader`] with the reason "mode is not a regular
    ///   file or symlink" if the file-type bits of the mode name a different
    ///   type. The function refuses a directory mode, so it does not read a
    ///   dirmeta object.
    pub fn parse_stat_metadata(data: &[u8]) -> Result<FileHeader> {
        let (uid, gid, mode, xattrs): (Be32, Be32, Be32, &[u8]) = GvDecode::decode(data)?;
        FileHeader::build(uid.0, gid.0, mode.0, 0, "", xattrs)
    }

    /// Serializes the stat-metadata form `(uuua(ayay))`.
    ///
    /// [`parse_stat_metadata`](Self::parse_stat_metadata) describes the form
    /// and reads the output back. The output holds no symlink target, so a
    /// symlink keeps only its `S_IFLNK` mode here.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFileHeader`] with the reason "mode is not a regular
    ///   file or symlink" if the file-type bits of [`mode`](Self::mode) name a
    ///   different type.
    /// - [`Error::InvalidFileHeader`] with the reason "regular file with a
    ///   symlink target" if a regular file has a symlink target that is not
    ///   empty.
    pub fn serialize_stat_metadata(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(ostrya_gvariant::encode_to_vec(&(
            Be32(self.uid),
            Be32(self.gid),
            Be32(self.mode),
            &self.xattrs,
        ))?)
    }

    /// Parses the archive header form `(tuuuusa(ayay))`.
    ///
    /// The function returns the header and the uncompressed payload size.
    /// `data` holds the header bytes with no framing.
    ///
    /// # Errors
    ///
    /// - [`Error::Gvariant`] if `data` is not a normal-form GVariant of type
    ///   `(tuuuusa(ayay))`, or if the xattr array is not in normal form.
    /// - [`Error::InvalidFileHeader`] with the reason "rdev is not zero" if
    ///   the rdev field is not 0.
    /// - [`Error::InvalidXattrs`] if an xattr name is not in the stored form,
    ///   or if the names are not in strictly increasing byte order.
    /// - [`Error::InvalidFileHeader`] with the reason "mode is not a regular
    ///   file or symlink" if the file-type bits of the mode name a different
    ///   type.
    /// - [`Error::InvalidFileHeader`] with the reason "regular file with a
    ///   symlink target" if a regular file has a symlink target that is not
    ///   empty.
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

    /// Serializes the archive header form `(tuuuusa(ayay))`.
    ///
    /// `uncompressed_size` is the size of the payload before compression. The
    /// output has no framing.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFileHeader`] with the reason "mode is not a regular
    ///   file or symlink" if the file-type bits of [`mode`](Self::mode) name a
    ///   different type.
    /// - [`Error::InvalidFileHeader`] with the reason "regular file with a
    ///   symlink target" if a regular file has a symlink target that is not
    ///   empty.
    /// - [`Error::Gvariant`] if the symlink target holds a NUL byte.
    pub fn serialize_archive(&self, uncompressed_size: u64) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(ostrya_gvariant::encode_to_vec(
            &self.archive_fields(uncompressed_size),
        )?)
    }

    /// Writes the framed uncompressed header form into `out`.
    ///
    /// The bytes equal `frame(&self.serialize()?)`. The function clears `out`
    /// first. A caller that uses one buffer for all its headers grows `out`
    /// only for a header that is longer than each header before it. After an
    /// error, the content of `out` is unspecified.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFileHeader`] with the reason "mode is not a regular
    ///   file or symlink" if the file-type bits of [`mode`](Self::mode) name a
    ///   different type.
    /// - [`Error::InvalidFileHeader`] with the reason "regular file with a
    ///   symlink target" if a regular file has a symlink target that is not
    ///   empty.
    /// - [`Error::Gvariant`] if the symlink target holds a NUL byte.
    /// - [`Error::InvalidFileHeader`] with the reason "header exceeds the
    ///   framing length limit" if the header is longer than `u32::MAX` bytes.
    pub fn write_framed(&self, out: &mut Vec<u8>) -> Result<()> {
        self.validate()?;
        write_framed_with(out, |out| self.encode(out))
    }

    /// Writes the framed archive header form into `out`.
    ///
    /// The bytes equal `frame(&self.serialize_archive(uncompressed_size)?)`.
    /// The buffer rules of [`write_framed`](Self::write_framed) apply.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFileHeader`] with the reason "mode is not a regular
    ///   file or symlink" if the file-type bits of [`mode`](Self::mode) name a
    ///   different type.
    /// - [`Error::InvalidFileHeader`] with the reason "regular file with a
    ///   symlink target" if a regular file has a symlink target that is not
    ///   empty.
    /// - [`Error::Gvariant`] if the symlink target holds a NUL byte.
    /// - [`Error::InvalidFileHeader`] with the reason "header exceeds the
    ///   framing length limit" if the header is longer than `u32::MAX` bytes.
    pub fn write_framed_archive(&self, uncompressed_size: u64, out: &mut Vec<u8>) -> Result<()> {
        self.validate()?;
        write_framed_with(out, |out| {
            self.archive_fields(uncompressed_size).encode(out)
        })
    }

    /// Returns the fields of the archive header form `(tuuuusa(ayay))`, with
    /// an rdev of 0.
    fn archive_fields(
        &self,
        uncompressed_size: u64,
    ) -> (Be64, Be32, Be32, Be32, Be32, &str, &Xattrs) {
        (
            Be64(uncompressed_size),
            Be32(self.uid),
            Be32(self.gid),
            Be32(self.mode),
            Be32(0),
            self.symlink_target.as_str(),
            &self.xattrs,
        )
    }
}

/// Writes a framed header into `out` in four steps:
///
/// 1. Clears `out`.
/// 2. Writes the framing prefix with a placeholder length.
/// 3. Appends the header variant that `encode` writes.
/// 4. Writes the length into the prefix.
///
/// The variant starts at offset 8, so its alignment in `out` is its own
/// alignment.
fn write_framed_with(
    out: &mut Vec<u8>,
    encode: impl FnOnce(&mut Vec<u8>) -> ostrya_gvariant::Result<()>,
) -> Result<()> {
    out.clear();
    out.extend_from_slice(&[0u8; 8]);
    encode(out)?;
    let len = u32::try_from(out.len() - 8)
        .map_err(|_| Error::InvalidFileHeader("header exceeds the framing length limit"))?;
    out[..4].copy_from_slice(&len.to_be_bytes());
    Ok(())
}

/// The GVariant type of the uncompressed header form, `(uuuusa(ayay))`.
impl GvType for FileHeader {
    const SIGNATURE: &'static str = "(uuuusa(ayay))";
    // Greatest member alignment: the u32 fields.
    const ALIGNMENT: usize = 4;
    const FIXED_SIZE: Option<usize> = None;
}

/// Writes the uncompressed header form with an rdev of 0.
///
/// The encoder does not check the mode or the symlink target.
/// [`FileHeader::serialize`] and [`FileHeader::write_framed`] check them.
// The `serialize*` and `write_framed*` functions are the only callers in this
// crate, and each one checks the header before it encodes.
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

/// Adds the content-stream framing in front of serialized header bytes.
///
/// The framed bytes are `[4 bytes BE u32 length][4 NUL bytes][header]`. The
/// length is the byte count of `header`.
///
/// # Errors
///
/// - [`Error::InvalidFileHeader`] with the reason "header exceeds the framing
///   length limit" if `header` is longer than `u32::MAX` bytes.
pub fn frame(header: &[u8]) -> Result<Vec<u8>> {
    let len = u32::try_from(header.len())
        .map_err(|_| Error::InvalidFileHeader("header exceeds the framing length limit"))?;
    let mut out = Vec::with_capacity(8 + header.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(header);
    Ok(out)
}

/// Splits a framed content stream into the header bytes and the rest.
///
/// The header bytes have no framing. The rest is the payload, if the stream
/// has one. [`frame`] describes the framing.
///
/// # Errors
///
/// - [`Error::InvalidFileHeader`] with the reason "framed stream is shorter
///   than its length prefix" if `data` is shorter than 8 bytes.
/// - [`Error::InvalidFileHeader`] with the reason "framing padding is not
///   zero" if one of the bytes 4 to 7 is not 0.
/// - [`Error::InvalidFileHeader`] with the reason "framed header length is out
///   of bounds" if the length in the prefix points past the end of `data`.
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

/// A streaming hasher for the checksum of a content object.
///
/// The checksum is the SHA-256 digest of the framed uncompressed header, then
/// the raw payload. The raw payload is the payload before compression. A
/// symlink has no payload, so its checksum is the result of
/// [`finish`](ContentHasher::finish) directly after
/// [`new`](ContentHasher::new).
///
/// # Examples
///
/// ```
/// use ostrya_core::filehdr::{ContentHasher, FileHeader, frame};
/// use ostrya_core::{Checksum, Xattrs};
///
/// // A regular file: uid 0, gid 0, mode 0644, no xattrs.
/// let header = FileHeader {
///     uid: 0,
///     gid: 0,
///     mode: 0o100644,
///     symlink_target: String::new(),
///     xattrs: Xattrs::empty(),
/// };
/// let payload = b"hello, world\n";
///
/// let mut hasher = ContentHasher::new(&header)?;
/// for chunk in payload.chunks(4) {
///     hasher.update(chunk);
/// }
/// let checksum = hasher.finish();
///
/// // The same digest over the framed header and the payload in one buffer.
/// let mut stream = frame(&header.serialize()?)?;
/// stream.extend_from_slice(payload);
/// assert_eq!(checksum, Checksum::sha256(&stream));
/// # Ok::<(), ostrya_core::Error>(())
/// ```
pub struct ContentHasher {
    hasher: Sha256,
}

impl ContentHasher {
    /// Creates a hasher and feeds it the framed uncompressed form of `header`.
    ///
    /// The function feeds the framing prefix and the header bytes to the
    /// hasher one after the other. It builds no framed buffer.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFileHeader`] with the reason "mode is not a regular
    ///   file or symlink" if the file-type bits of the mode name a different
    ///   type.
    /// - [`Error::InvalidFileHeader`] with the reason "regular file with a
    ///   symlink target" if a regular file has a symlink target that is not
    ///   empty.
    /// - [`Error::Gvariant`] if the symlink target holds a NUL byte.
    /// - [`Error::InvalidFileHeader`] with the reason "header exceeds the
    ///   framing length limit" if the header is longer than `u32::MAX` bytes.
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

    /// Feeds the next chunk of the raw payload to the hasher.
    pub fn update(&mut self, payload: &[u8]) {
        self.hasher.update(payload);
    }

    /// Returns the checksum of the content object.
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

    /// Checks that the framed forms equal the framing of the serialized forms.
    /// The test uses a regular file with xattrs and a symlink, and a buffer
    /// that holds bytes of an earlier call. A header that fails a check is
    /// refused.
    #[test]
    fn the_framed_forms_equal_the_framed_serialization() {
        let with_xattrs = FileHeader {
            xattrs: Xattrs::new([
                (b"user.a\0".to_vec(), b"1".to_vec()),
                (b"user.bb\0".to_vec(), vec![7; 300]),
            ])
            .unwrap(),
            ..regular(0o100644)
        };
        let mut out = vec![0xaa; 1000];
        for header in [regular(0o100755), with_xattrs, symlink("a/target")] {
            header.write_framed(&mut out).unwrap();
            assert_eq!(out, frame(&header.serialize().unwrap()).unwrap());
            for size in [0, 1234, u64::MAX] {
                header.write_framed_archive(size, &mut out).unwrap();
                assert_eq!(
                    out,
                    frame(&header.serialize_archive(size).unwrap()).unwrap()
                );
            }
        }
        let bad = FileHeader {
            symlink_target: "x".into(),
            ..regular(0o100644)
        };
        assert!(bad.write_framed(&mut out).is_err());
        assert!(bad.write_framed_archive(1, &mut out).is_err());
    }

    #[test]
    fn stat_metadata_decodes_the_bare_user_ostreemeta_form() {
        // The exact `user.ostreemeta` bytes of a bare-user `.file` object for
        // a 0644 regular file that root owns. The bytes come from a repository
        // that the `ostree` command created: uid 0, gid 0, mode 0o100644 (all
        // big-endian), no xattrs.
        let regular = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x81, 0xa4];
        let hdr = FileHeader::parse_stat_metadata(&regular).unwrap();
        assert_eq!((hdr.uid, hdr.gid, hdr.mode), (0, 0, 0o100644));
        assert!(!hdr.is_symlink());
        assert_eq!(hdr.symlink_target, "");
        assert!(hdr.xattrs.is_empty());

        // The symlink form holds an S_IFLNK mode. The target is in the file
        // content, so the target of the parsed header stays empty.
        let symlink = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa1, 0xff];
        let hdr = FileHeader::parse_stat_metadata(&symlink).unwrap();
        assert_eq!((hdr.uid, hdr.gid, hdr.mode), (0, 0, 0o120777));
        assert!(hdr.is_symlink());
        assert_eq!(hdr.symlink_target, "");

        // The wire layout is the dirmeta layout. A directory mode names no
        // regular file and no symlink, so the parse refuses it. This decoder
        // reads `.file` objects only.
        let dir_meta = crate::DirMeta {
            uid: 1000,
            gid: 100,
            mode: 0o40750,
            xattrs: Xattrs::empty(),
        };
        assert_eq!(
            FileHeader::parse_stat_metadata(&dir_meta.serialize().unwrap()),
            Err(Error::InvalidFileHeader(
                "mode is not a regular file or symlink"
            ))
        );

        // A file-mode header with xattrs round-trips its fields.
        let with_xattr = ostrya_gvariant::encode_to_vec(&(
            Be32(0),
            Be32(0),
            Be32(0o100600),
            &Xattrs::new([(b"user.a\0".to_vec(), b"v".to_vec())]).unwrap(),
        ))
        .unwrap();
        let hdr = FileHeader::parse_stat_metadata(&with_xattr).unwrap();
        assert_eq!(hdr.mode, 0o100600);
        assert_eq!(hdr.xattrs.len(), 1);
    }

    /// Serializes any uncompressed-form header through the `Value` tree. The
    /// checks of `FileHeader` do not run.
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
    fn stat_metadata_serialize_round_trips_and_matches_the_tool_bytes() {
        // A 0644 regular file that root owns. These are the exact
        // `user.ostreemeta` bytes of a bare-user `.file` object, from a
        // repository that the `ostree` command created.
        let header = regular(0o100644);
        let header = FileHeader {
            uid: 0,
            gid: 0,
            ..header
        };
        assert_eq!(
            header.serialize_stat_metadata().unwrap(),
            [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x81, 0xa4]
        );

        // A symlink stored as a regular file keeps mode S_IFLNK|0777 here. The
        // `ostree` command writes these 12 bytes to the user.ostreemeta xattr
        // of a symlink with uid 1000 and gid 100.
        let link = FileHeader {
            uid: 1000,
            gid: 100,
            ..symlink("hello.txt")
        };
        assert_eq!(
            link.serialize_stat_metadata().unwrap(),
            [0u8, 0, 3, 0xe8, 0, 0, 0, 0x64, 0, 0, 0xa1, 0xff]
        );

        // A header with xattrs round-trips through parse.
        let with_xattr = FileHeader {
            xattrs: Xattrs::new([(b"user.a\0".to_vec(), b"1".to_vec())]).unwrap(),
            ..regular(0o100600)
        };
        let bytes = with_xattr.serialize_stat_metadata().unwrap();
        let parsed = FileHeader::parse_stat_metadata(&bytes).unwrap();
        assert_eq!(
            (parsed.uid, parsed.gid, parsed.mode, parsed.xattrs),
            (
                with_xattr.uid,
                with_xattr.gid,
                with_xattr.mode,
                with_xattr.xattrs
            )
        );
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
        // The uid, gid, mode, and rdev are the first four u32 members of
        // (uuuusa(ayay)), stored big-endian. A missing or asymmetric byte
        // swap fails this test.
        let header = regular(0o100644); // uid 1000, gid 1000
        let bytes = header.serialize().unwrap();
        assert_eq!(&bytes[0..4], &1000u32.to_be_bytes());
        assert_eq!(&bytes[4..8], &1000u32.to_be_bytes());
        assert_eq!(&bytes[8..12], &0o100644u32.to_be_bytes());
        assert_eq!(&bytes[12..16], &[0, 0, 0, 0]);
        assert_eq!(FileHeader::parse(&bytes).unwrap(), header);
    }

    #[test]
    fn the_two_wire_forms_agree_on_the_common_fields() {
        let header = FileHeader {
            xattrs: Xattrs::new([(b"user.a\0".to_vec(), b"1".to_vec())]).unwrap(),
            ..regular(0o100640)
        };
        let from_uncompressed = FileHeader::parse(&header.serialize().unwrap()).unwrap();
        let (from_archive, _) =
            FileHeader::parse_archive(&header.serialize_archive(4096).unwrap()).unwrap();
        assert_eq!(from_uncompressed, header);
        assert_eq!(from_archive, header);
    }
}
