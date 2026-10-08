//! Dirmeta objects: the owner, the mode, and the xattrs of a directory.

use ostrya_gvariant::{GvDecode, GvEncode, GvType};

use crate::be::Be32;
use crate::error::{Error, Result};
use crate::filehdr::{S_IFDIR, S_IFMT};
use crate::xattr::{Xattrs, XattrsRef};

/// An owned dirmeta object: the owner, the mode, and the xattrs of a directory.
///
/// The scalar fields are in host byte order.
///
/// # Wire form
///
/// The GVariant type is `(uuua(ayay))`. The members are:
///
/// - the uid
/// - the gid
/// - the full `st_mode`, with the directory type bits
/// - the xattrs, sorted by name, in the storage form of [`Xattrs`]
///
/// The three `u` values are big-endian. The mode must be a directory mode, so
/// this type holds only `.dirmeta` objects. The same layout is the
/// `user.ostreemeta` xattr of a bare-user file object.
/// [`FileHeader::parse_stat_metadata`](crate::filehdr::FileHeader::parse_stat_metadata)
/// reads that xattr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirMeta {
    /// The owner uid.
    pub uid: u32,
    /// The owner gid.
    pub gid: u32,
    /// The full `st_mode`, with the directory type bits.
    pub mode: u32,
    /// The extended attributes of the directory.
    pub xattrs: Xattrs,
}

fn check_dir_mode(mode: u32) -> Result<()> {
    if mode & S_IFMT == S_IFDIR {
        Ok(())
    } else {
        Err(Error::InvalidDirMeta("mode is not a directory mode"))
    }
}

impl DirMeta {
    /// Parses a serialized dirmeta object.
    ///
    /// # Errors
    ///
    /// - [`Error::Gvariant`] if `data` is not a normal-form `(uuua(ayay))`
    ///   tuple, or if an xattr entry is not a normal-form `(ayay)` pair.
    /// - [`Error::InvalidDirMeta`] with the reason `mode is not a directory
    ///   mode` if the type bits of the mode are not the directory type.
    /// - [`Error::InvalidXattrs`] if an xattr name is not in the stored form,
    ///   or if the names are not strictly sorted.
    ///   [`Xattrs::from_gvariant`] lists the reasons.
    pub fn parse(data: &[u8]) -> Result<DirMeta> {
        DirMetaRef::parse(data)?.to_owned()
    }

    /// Serializes the object to normal-form bytes.
    ///
    /// The SHA-256 of these bytes is the checksum of the object.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidDirMeta`] with the reason `mode is not a directory mode`
    /// if the type bits of `mode` are not the directory type.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        check_dir_mode(self.mode)?;
        Ok(ostrya_gvariant::encode_to_vec(self)?)
    }
}

impl GvType for DirMeta {
    const SIGNATURE: &'static str = "(uuua(ayay))";
    // Greatest member alignment: the u32 fields.
    const ALIGNMENT: usize = 4;
    const FIXED_SIZE: Option<usize> = None;
}

/// The `(uuua(ayay))` encoding, with no check of the mode.
///
/// [`DirMeta::serialize`] checks that the mode is a directory mode.
impl GvEncode for DirMeta {
    fn encode(&self, out: &mut Vec<u8>) -> ostrya_gvariant::Result<()> {
        (
            Be32(self.uid),
            Be32(self.gid),
            Be32(self.mode),
            &self.xattrs,
        )
            .encode(out)
    }
}

/// A borrowed view of a serialized dirmeta object.
///
/// [`parse`](DirMetaRef::parse) decodes the scalar fields and checks the mode.
/// The xattrs stay serialized until a caller reads them.
#[derive(Clone, Copy)]
pub struct DirMetaRef<'a> {
    uid: u32,
    gid: u32,
    mode: u32,
    xattrs: XattrsRef<'a>,
}

impl<'a> DirMetaRef<'a> {
    /// Parses a slice that holds exactly one serialized dirmeta object.
    ///
    /// The function does not check the xattr names.
    /// [`to_owned`](DirMetaRef::to_owned) and the iterator of
    /// [`xattrs`](DirMetaRef::xattrs) check them.
    ///
    /// # Errors
    ///
    /// - [`Error::Gvariant`] if `data` is not a normal-form `(uuua(ayay))`
    ///   tuple, or if the framing of the xattr array is not normal form.
    /// - [`Error::InvalidDirMeta`] with the reason `mode is not a directory
    ///   mode` if the type bits of the mode are not the directory type.
    pub fn parse(data: &'a [u8]) -> Result<DirMetaRef<'a>> {
        let (uid, gid, mode, xattrs): (Be32, Be32, Be32, &[u8]) = GvDecode::decode(data)?;
        let mode = mode.0;
        check_dir_mode(mode)?;
        Ok(DirMetaRef {
            uid: uid.0,
            gid: gid.0,
            mode,
            xattrs: XattrsRef::parse(xattrs)?,
        })
    }

    /// Returns the owner uid, in host byte order.
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// Returns the owner gid, in host byte order.
    pub fn gid(&self) -> u32 {
        self.gid
    }

    /// Returns the full `st_mode`, in host byte order.
    pub fn mode(&self) -> u32 {
        self.mode
    }

    /// Returns a borrowed view of the extended attributes of the directory.
    pub fn xattrs(&self) -> XattrsRef<'a> {
        self.xattrs
    }

    /// Collects the view into an owned [`DirMeta`].
    ///
    /// # Errors
    ///
    /// - [`Error::Gvariant`] if an xattr entry is not a normal-form `(ayay)`
    ///   pair.
    /// - [`Error::InvalidXattrs`] if an xattr name is not in the stored form,
    ///   or if the names are not strictly sorted.
    ///   [`Xattrs::from_gvariant`] lists the reasons.
    pub fn to_owned(&self) -> Result<DirMeta> {
        Ok(DirMeta {
            uid: self.uid,
            gid: self.gid,
            mode: self.mode,
            xattrs: self.xattrs.to_owned()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_with_xattrs() {
        let meta = DirMeta {
            uid: 1000,
            gid: 100,
            mode: 0o40750,
            xattrs: Xattrs::new([(b"user.a\0".to_vec(), b"v".to_vec())]).unwrap(),
        };
        let bytes = meta.serialize().unwrap();
        let view = DirMetaRef::parse(&bytes).unwrap();
        assert_eq!(view.uid(), 1000);
        assert_eq!(view.gid(), 100);
        assert_eq!(view.mode(), 0o40750);
        assert_eq!(view.to_owned().unwrap(), meta);
        assert_eq!(meta.serialize().unwrap(), bytes);
    }

    #[test]
    fn rejects_a_non_directory_mode() {
        let meta = DirMeta {
            uid: 0,
            gid: 0,
            mode: 0o100644,
            xattrs: Xattrs::empty(),
        };
        assert_eq!(
            meta.serialize(),
            Err(Error::InvalidDirMeta("mode is not a directory mode"))
        );

        // Craft bytes carrying a regular-file mode via the raw tuple, so the
        // non-directory mode is rejected on the read path.
        let bytes =
            ostrya_gvariant::encode_to_vec(&(Be32(0), Be32(0), Be32(0o100644), &Xattrs::empty()))
                .unwrap();
        assert_eq!(
            DirMetaRef::parse(&bytes).err(),
            Some(Error::InvalidDirMeta("mode is not a directory mode"))
        );
    }
}
