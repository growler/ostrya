//! Extended-attribute sets.
//!
//! The storage form is GVariant `a(ayay)`: an array of (name-bytes,
//! value-bytes), sorted by name with byte-wise comparison. A stored name
//! carries its namespace prefix and a single terminating NUL, with a non-empty
//! prefix and no interior NUL, matching the form the tool writes.
//! Canonicalization -- the sort plus the reject-duplicate and name-form checks
//! -- is applied before every serialization and hash, because the xattr bytes
//! feed the object checksum.

use ostrya_gvariant::{ArrayIter, GvDecode, GvEncode, GvType, encode_to_vec, write_array};

use crate::error::{Error, Result};
use crate::valiter::ValidatedIter;

/// A canonical, sorted xattr set.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Xattrs(Vec<(Vec<u8>, Vec<u8>)>);

impl Xattrs {
    /// The empty xattr set.
    pub fn empty() -> Xattrs {
        Xattrs(Vec::new())
    }

    /// Build a canonical set from arbitrary (name, value) pairs: sort by name,
    /// then reject duplicate names and names not in stored NUL-terminated form.
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

    /// Whether the set has no entries.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Iterate entries in canonical order.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.0.iter().map(|(n, v)| (n.as_slice(), v.as_slice()))
    }

    /// Serialize as normal-form GVariant `a(ayay)`.
    pub fn to_gvariant(&self) -> Result<Vec<u8>> {
        Ok(encode_to_vec(&self)?)
    }

    /// Parse normal-form GVariant `a(ayay)`, requiring the on-disk canonical
    /// order: names strictly increasing (which rejects both unsorted input and
    /// duplicates) and non-empty.
    pub fn from_gvariant(bytes: &[u8]) -> Result<Xattrs> {
        XattrsRef::parse(bytes)?.to_owned()
    }
}

/// Encode the canonical set as `a(ayay)` directly from the owned entries, so a
/// caller that holds an [`Xattrs`] (a dirmeta or file header) can splice it into
/// a larger tuple without first collecting a slice of borrowed pairs.
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

/// Validate a stored xattr name: non-empty, ending in a single NUL, with no
/// interior NUL and a non-empty prefix. Confirmed by reading the
/// `user.ostreemeta` blob of a committed file, where the name `user.demo` is
/// followed by one `\0`.
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
/// `parse` validates the array framing; the canonical-order checks (names
/// strictly increasing, non-empty) run as entries are visited, which is why
/// [`iter`](XattrsRef::iter) yields `Result`. After an error the iterator is
/// exhausted.
#[derive(Clone, Copy)]
pub struct XattrsRef<'a> {
    entries: ArrayIter<'a, (&'a [u8], &'a [u8])>,
}

impl<'a> XattrsRef<'a> {
    /// Wrap the slice covering exactly a serialized `a(ayay)`.
    pub fn parse(data: &'a [u8]) -> Result<XattrsRef<'a>> {
        Ok(XattrsRef {
            entries: ArrayIter::decode(data)?,
        })
    }

    /// Iterate (name, value) entries, validating canonical order as visited.
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

    /// Collect into an owned, canonical [`Xattrs`].
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
        // Encode an out-of-order a(ayay) directly, bypassing canonicalization.
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
