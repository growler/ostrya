//! Extended-attribute sets, owned and borrowed.
//!
//! The `Xattrs` type doc states the storage form and the canonical-form
//! rules.

use ostrya_gvariant::{ArrayIter, GvDecode, GvEncode, GvType, encode_to_vec, write_array};

use crate::error::{Error, Result};
use crate::valiter::ValidatedIter;

/// A sorted set of extended attributes, in canonical form.
///
/// Equal sets hold equal bytes in equal order. Hashing agrees with equality,
/// so a set can be a lookup key.
///
/// # Storage form
///
/// The GVariant type is `a(ayay)`. Each element is a pair of byte strings:
/// the name and the value. The pairs are sorted by name in byte order.
///
/// A stored name is the attribute name with its namespace prefix, followed by
/// one NUL byte. The text before the NUL is not empty and holds no NUL. The
/// `ostree` command writes names in this form.
///
/// The xattr bytes are part of the object checksum, so each constructor
/// makes a canonical set. Each serialization and each hash of a set uses
/// this form.
///
/// [`new`](Xattrs::new) sorts the pairs.
/// [`from_gvariant`](Xattrs::from_gvariant) refuses pairs that are not
/// sorted. Each constructor refuses a duplicate name and checks each name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Xattrs(Vec<(Vec<u8>, Vec<u8>)>);

impl Xattrs {
    /// Creates an empty set.
    pub fn empty() -> Xattrs {
        Xattrs(Vec::new())
    }

    /// Creates a canonical set from (name, value) pairs in any order.
    ///
    /// The function sorts the pairs by name. Each name must be a stored name
    /// of the [storage form](Xattrs#storage-form), with one NUL byte at the
    /// end.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidXattrs`] with one of these reasons:
    ///
    /// - `duplicate xattr name` if two pairs have the same name.
    /// - `empty xattr name` if a name is empty.
    /// - `xattr name is missing its terminating NUL` if the last byte of a
    ///   name is not NUL.
    /// - `xattr name is empty before its NUL` if a name is one NUL byte only.
    /// - `xattr name has an interior NUL` if a name holds a NUL byte before
    ///   its last byte.
    pub fn new(pairs: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>) -> Result<Xattrs> {
        let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = pairs.into_iter().collect();
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        for window in pairs.windows(2) {
            if window[0].0 == window[1].0 {
                return Err(Error::InvalidXattrs("duplicate xattr name"));
            }
        }
        for (name, _) in &pairs {
            check_name(name)?;
        }
        Ok(Xattrs(pairs))
    }

    /// Returns `true` if the set has no entries.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns an iterator over the (name, value) entries, sorted by name.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.0.iter().map(|(n, v)| (n.as_slice(), v.as_slice()))
    }

    /// Serializes the set as normal-form GVariant `a(ayay)`.
    ///
    /// # Errors
    ///
    /// The function returns no error for any set. The encoder of `a(ayay)`
    /// has no failure case.
    pub fn to_gvariant(&self) -> Result<Vec<u8>> {
        Ok(encode_to_vec(&self)?)
    }

    /// Parses a normal-form GVariant `a(ayay)` set.
    ///
    /// Each name must be greater than the name before it, in byte order. This
    /// check refuses unsorted input and duplicate names.
    ///
    /// # Errors
    ///
    /// - [`Error::Gvariant`] if `bytes` is not a normal-form `a(ayay)` array.
    /// - [`Error::InvalidXattrs`] with the reason `xattr names are not
    ///   strictly sorted` if a name is not greater than the name before it.
    /// - [`Error::InvalidXattrs`] if a name is not in the stored form. The
    ///   reasons are `empty xattr name`, `xattr name is missing its
    ///   terminating NUL`, `xattr name is empty before its NUL`, and `xattr
    ///   name has an interior NUL`, as for [`new`](Xattrs::new).
    pub fn from_gvariant(bytes: &[u8]) -> Result<Xattrs> {
        XattrsRef::parse(bytes)?.to_owned()
    }
}

/// The `a(ayay)` encoding of a set, written from the owned entries.
///
/// A dirmeta or a file header encodes its set as a member of a larger tuple
/// with this impl. The encoder needs no list of borrowed pairs.
impl GvType for &Xattrs {
    const SIGNATURE: &'static str = "a(ayay)";
    const ALIGNMENT: usize = 1;
    const FIXED_SIZE: Option<usize> = None;
}

impl GvEncode for &Xattrs {
    fn encode(&self, out: &mut Vec<u8>) -> ostrya_gvariant::Result<()> {
        // Each element is (ayay): a two-member tuple of byte arrays.
        type Entry<'e> = (&'e [u8], &'e [u8]);
        write_array(
            out,
            <Entry as GvType>::ALIGNMENT,
            <Entry as GvType>::FIXED_SIZE.is_some(),
            self.0.len(),
            |out, i| {
                let (name, value) = &self.0[i];
                (name.as_slice(), value.as_slice()).encode(out)
            },
        )
    }
}

/// Checks a stored xattr name.
///
/// The name ends in one NUL byte. The text before the NUL is not empty and
/// holds no NUL. The `ostree` command writes names in this form: in the
/// `user.ostreemeta` blob of a committed file, one `\0` follows the name
/// `user.demo`.
fn check_name(name: &[u8]) -> Result<()> {
    let Some((&last, rest)) = name.split_last() else {
        return Err(Error::InvalidXattrs("empty xattr name"));
    };
    if last != 0 {
        return Err(Error::InvalidXattrs(
            "xattr name is missing its terminating NUL",
        ));
    }
    if rest.is_empty() {
        return Err(Error::InvalidXattrs("xattr name is empty before its NUL"));
    }
    if rest.contains(&0) {
        return Err(Error::InvalidXattrs("xattr name has an interior NUL"));
    }
    Ok(())
}

/// A borrowed view of a serialized `a(ayay)` xattr set.
///
/// [`parse`](XattrsRef::parse) checks the framing of the array. The name
/// checks and the order check run when [`iter`](XattrsRef::iter) visits each
/// entry, so the iterator yields `Result`. After an error, the iterator is
/// exhausted.
#[derive(Clone, Copy)]
pub struct XattrsRef<'a> {
    entries: ArrayIter<'a, (&'a [u8], &'a [u8])>,
}

impl<'a> XattrsRef<'a> {
    /// Creates a view of a slice that holds exactly one serialized `a(ayay)`.
    ///
    /// # Errors
    ///
    /// [`Error::Gvariant`] if the framing of the array is not normal form.
    pub fn parse(data: &'a [u8]) -> Result<XattrsRef<'a>> {
        Ok(XattrsRef {
            entries: ArrayIter::decode(data)?,
        })
    }

    /// Returns an iterator over the (name, value) entries.
    ///
    /// The iterator checks each entry when it visits it. The error items are
    /// the errors of [`to_owned`](XattrsRef::to_owned).
    pub fn iter(&self) -> impl Iterator<Item = Result<(&'a [u8], &'a [u8])>> + use<'a> {
        ValidatedIter::new(
            self.entries,
            None,
            |prev: &mut Option<&'a [u8]>, (name, value): (&'a [u8], &'a [u8])| {
                check_name(name)?;
                if let Some(prev) = prev
                    && *prev >= name
                {
                    return Err(Error::InvalidXattrs("xattr names are not strictly sorted"));
                }
                *prev = Some(name);
                Ok((name, value))
            },
        )
    }

    /// Collects the entries into an owned, canonical [`Xattrs`].
    ///
    /// # Errors
    ///
    /// - [`Error::Gvariant`] if an entry is not a normal-form `(ayay)` pair.
    /// - [`Error::InvalidXattrs`] if a name is not in the stored form, or with
    ///   the reason `xattr names are not strictly sorted`.
    ///   [`Xattrs::from_gvariant`] lists the reasons.
    pub fn to_owned(&self) -> Result<Xattrs> {
        let mut pairs = Vec::new();
        for item in self.iter() {
            let (name, value) = item?;
            pairs.push((name.to_vec(), value.to_vec()));
        }
        Ok(Xattrs(pairs))
    }
}

#[cfg(test)]
mod tests {
    use ostrya_gvariant::Slice;

    use super::*;

    #[test]
    fn new_sorts_by_name() {
        let x = Xattrs::new([
            (b"user.z\0".to_vec(), b"1".to_vec()),
            (b"security.selinux\0".to_vec(), b"2".to_vec()),
            (b"user.a\0".to_vec(), b"3".to_vec()),
        ])
        .unwrap();
        let names: Vec<&[u8]> = x.iter().map(|(n, _)| n).collect();
        assert_eq!(
            names,
            vec![
                b"security.selinux\0".as_slice(),
                b"user.a\0".as_slice(),
                b"user.z\0".as_slice()
            ]
        );
    }

    #[test]
    fn new_rejects_duplicate_and_empty_names() {
        assert!(matches!(
            Xattrs::new([
                (b"user.a\0".to_vec(), b"1".to_vec()),
                (b"user.a\0".to_vec(), b"2".to_vec()),
            ]),
            Err(Error::InvalidXattrs("duplicate xattr name"))
        ));
        assert!(matches!(
            Xattrs::new([(Vec::new(), b"1".to_vec())]),
            Err(Error::InvalidXattrs("empty xattr name"))
        ));
    }

    #[test]
    fn new_requires_terminating_nul_and_no_interior_nul() {
        // A name taken straight from listxattr(2) output lacks the stored NUL.
        assert_eq!(
            Xattrs::new([(b"user.demo".to_vec(), b"v".to_vec())]),
            Err(Error::InvalidXattrs(
                "xattr name is missing its terminating NUL"
            ))
        );
        // An interior NUL is not part of a real xattr name.
        assert_eq!(
            Xattrs::new([(b"user.\0demo\0".to_vec(), b"v".to_vec())]),
            Err(Error::InvalidXattrs("xattr name has an interior NUL"))
        );
        // A lone NUL has an empty name before it.
        assert_eq!(
            Xattrs::new([(b"\0".to_vec(), b"v".to_vec())]),
            Err(Error::InvalidXattrs("xattr name is empty before its NUL"))
        );
    }

    #[test]
    fn from_gvariant_rejects_names_without_terminating_nul() {
        // Encode an a(ayay) whose single name lacks the stored NUL.
        let raw: Vec<(&[u8], &[u8])> = vec![(b"user.demo", b"v")];
        let bytes = encode_to_vec(&Slice(&raw)).unwrap();
        assert_eq!(
            Xattrs::from_gvariant(&bytes),
            Err(Error::InvalidXattrs(
                "xattr name is missing its terminating NUL"
            ))
        );
    }

    #[test]
    fn gvariant_round_trips_and_reencodes_identically() {
        let x = Xattrs::new([
            (b"security.capability\0".to_vec(), vec![0x01, 0x00, 0x00]),
            (b"user.mime_type\0".to_vec(), b"text/plain".to_vec()),
        ])
        .unwrap();
        let bytes = x.to_gvariant().unwrap();
        let decoded = Xattrs::from_gvariant(&bytes).unwrap();
        assert_eq!(decoded, x);
        assert_eq!(decoded.to_gvariant().unwrap(), bytes);
    }

    #[test]
    fn empty_set_serializes_to_empty_array() {
        let bytes = Xattrs::empty().to_gvariant().unwrap();
        assert!(bytes.is_empty());
        assert_eq!(Xattrs::from_gvariant(&bytes).unwrap(), Xattrs::empty());
    }

    #[test]
    fn from_gvariant_rejects_unsorted_bytes() {
        // The test encodes an out-of-order a(ayay) with no sort, so the bytes
        // are not in canonical form.
        let unsorted: Vec<(&[u8], &[u8])> = vec![(b"user.z\0", b"1"), (b"user.a\0", b"2")];
        let bytes = encode_to_vec(&Slice(&unsorted)).unwrap();
        assert!(matches!(
            Xattrs::from_gvariant(&bytes),
            Err(Error::InvalidXattrs("xattr names are not strictly sorted"))
        ));
    }

    #[test]
    fn view_validates_as_visited_and_fuses_on_error() {
        let unsorted: Vec<(&[u8], &[u8])> = vec![(b"user.z\0", b"1"), (b"user.a\0", b"2")];
        let bytes = encode_to_vec(&Slice(&unsorted)).unwrap();
        let view = XattrsRef::parse(&bytes).unwrap();
        let mut iter = view.iter();
        assert_eq!(iter.next().unwrap(), Ok((&b"user.z\0"[..], &b"1"[..])));
        assert_eq!(
            iter.next().unwrap(),
            Err(Error::InvalidXattrs("xattr names are not strictly sorted"))
        );
        assert!(iter.next().is_none(), "iterator fuses after an error");
    }
}
