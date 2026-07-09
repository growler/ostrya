//! Dirmeta objects: directory uid/gid/mode/xattrs.
//!
//! Wire form `(uuua(ayay))`: uid, gid, and the full `st_mode` (all big-endian
//! at the value level) plus the sorted xattr array. The mode must carry the
//! directory file-type bits. The same layout serves the `user.ostreemeta`
//! xattr of bare-user file objects, but this type models `.dirmeta` objects
//! and therefore requires a directory mode.

use ostrya_gvariant::{GvDecode, GvEncode, GvType};

use crate::be::Be32;
use crate::error::{Error, Result};
use crate::filehdr::{S_IFDIR, S_IFMT};
use crate::xattr::{Xattrs, XattrsRef};

/// An owned dirmeta object. Scalar fields are host-order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirMeta {
    pub uid: u32,
    pub gid: u32,
    /// Full `st_mode` including the directory file-type bits.
    pub mode: u32,
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
    /// Parse a serialized dirmeta object.
    pub fn parse(data: &[u8]) -> Result<DirMeta> {
        DirMetaRef::parse(data)?.to_owned()
    }

    /// Serialize to normal-form bytes; their SHA-256 is the object identity.
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

/// The encode path is purely mechanical: the directory-mode check runs in
/// [`DirMeta::serialize`], the only caller.
impl GvEncode for DirMeta {
    fn encode(&self, out: &mut Vec<u8>) -> ostrya_gvariant::Result<()> {
        (Be32(self.uid), Be32(self.gid), Be32(self.mode), &self.xattrs).encode(out)
    }
}

/// A borrowed view of a serialized dirmeta object. The scalar fields decode
/// on parse; the xattrs stay lazy.
#[derive(Clone, Copy)]
pub struct DirMetaRef<'a> {
    uid: u32,
    gid: u32,
    mode: u32,
    xattrs: XattrsRef<'a>,
}

impl<'a> DirMetaRef<'a> {
    /// Parse the slice covering exactly a serialized dirmeta object.
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

    pub fn uid(&self) -> u32 {
        self.uid
    }

    pub fn gid(&self) -> u32 {
        self.gid
    }

    /// Full `st_mode`, host-order.
    pub fn mode(&self) -> u32 {
        self.mode
    }

    pub fn xattrs(&self) -> XattrsRef<'a> {
        self.xattrs
    }

    /// Collect into an owned [`DirMeta`].
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
