//! Dirtree objects: the sorted lists of child files and subdirectories.
//!
//! Wire form `(a(say)a(sayay))`: file entries (name, content checksum) and
//! directory entries (name, dirtree checksum, dirmeta checksum). Both lists
//! are sorted by name with byte-wise comparison; the sort order is mandatory
//! for reproducible checksums, so it is validated on both paths. Each entry
//! name is validated as a single path component (not `.` or `..`, no `/`,
//! non-empty; UTF-8 is enforced by the string decoder): this is the
//! path-traversal defense.
//!
//! No name may appear in both lists: the two entries would claim the same
//! checkout path. This is checked on the write path and when materializing an
//! owned [`DirTree`] (via [`DirTree::parse`]). The borrowed [`DirTreeRef`]
//! iterators stay per-list and allocation-free, matching the tool, which reads
//! such an object without a cross-list check (`ostree fsck` accepts it and
//! `ostree ls` lists both entries) and aborts only when it later resolves the
//! name as a directory.
//!
//! [`DirTreeRef`] is the borrowed read-path view: `parse` validates the
//! container framing, and the entry-level checks (name, checksum length,
//! sort order) run as entries are visited, which is why the iterators yield
//! `Result`. After an error an iterator is exhausted. A full dirtree walk
//! borrows the object buffer throughout.

use ostrya_gvariant::{ArrayIter, GvDecode, GvEncode, GvType, Slice};

use crate::checksum::Checksum;
use crate::error::{Error, Result};
use crate::valiter::ValidatedIter;

/// An owned dirtree object. Both lists must be name-sorted (byte-wise,
/// strictly increasing) and no name may appear in both lists; `serialize`
/// validates this.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DirTree {
    /// (file name, content checksum), name-sorted.
    pub files: Vec<(String, Checksum)>,
    /// (dir name, dirtree checksum, dirmeta checksum), name-sorted.
    pub dirs: Vec<(String, Checksum, Checksum)>,
}

/// The path-traversal defense for one entry name.
fn check_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidDirTree("empty entry name"));
    }
    if name == "." || name == ".." {
        return Err(Error::InvalidDirTree("entry name is a directory traversal"));
    }
    if name.contains('/') {
        return Err(Error::InvalidDirTree("entry name contains a slash"));
    }
    Ok(())
}

/// Validate one visited name against the previous one: valid component,
/// byte-wise strictly increasing (which rejects duplicates).
fn check_entry<'a>(prev: &mut Option<&'a str>, name: &'a str) -> Result<()> {
    check_name(name)?;
    if let Some(prev) = prev
        && *prev >= name
    {
        return Err(Error::InvalidDirTree("entry names are not sorted"));
    }
    *prev = Some(name);
    Ok(())
}

fn entry_checksum(bytes: &[u8]) -> Result<Checksum> {
    Checksum::from_ay(bytes).map_err(|_| Error::InvalidDirTree("entry checksum is not 32 bytes"))
}

impl DirTree {
    /// Parse a serialized dirtree object into an owned, structurally sound
    /// tree: the per-list checks run as entries are collected, then the
    /// cross-list duplicate-name check runs over the materialized lists.
    pub fn parse(data: &[u8]) -> Result<DirTree> {
        let tree = DirTreeRef::parse(data)?.to_owned()?;
        tree.check_no_shared_names()?;
        Ok(tree)
    }

    /// Serialize to normal-form bytes; their SHA-256 is the object identity.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(ostrya_gvariant::encode_to_vec(self)?)
    }

    fn validate(&self) -> Result<()> {
        let mut prev = None;
        for (name, _) in &self.files {
            check_entry(&mut prev, name)?;
        }
        let mut prev = None;
        for (name, _, _) in &self.dirs {
            check_entry(&mut prev, name)?;
        }
        self.check_no_shared_names()
    }

    /// No name may appear in both lists. Both lists are name-sorted by the
    /// time this runs (validated per list above, or by `to_owned` on the read
    /// path), so a merge-style walk finds any shared name without allocating.
    fn check_no_shared_names(&self) -> Result<()> {
        let mut files = self.files.iter().map(|(n, _)| n.as_str());
        let mut dirs = self.dirs.iter().map(|(n, _, _)| n.as_str());
        let (mut f, mut d) = (files.next(), dirs.next());
        while let (Some(fname), Some(dname)) = (f, d) {
            match fname.cmp(dname) {
                std::cmp::Ordering::Less => f = files.next(),
                std::cmp::Ordering::Greater => d = dirs.next(),
                std::cmp::Ordering::Equal => {
                    return Err(Error::InvalidDirTree(
                        "a name appears in both the file and directory lists",
                    ));
                }
            }
        }
        Ok(())
    }
}

impl GvType for DirTree {
    const SIGNATURE: &'static str = "(a(say)a(sayay))";
    // Every member is alignment-1 (strings and byte arrays).
    const ALIGNMENT: usize = 1;
    const FIXED_SIZE: Option<usize> = None;
}

/// The encode path is purely mechanical: sort and cross-list validation runs in
/// [`DirTree::serialize`], the only caller. The owned entry vectors encode
/// directly, since `String` and `Checksum` are themselves encodable.
impl GvEncode for DirTree {
    fn encode(&self, out: &mut Vec<u8>) -> ostrya_gvariant::Result<()> {
        (Slice(&self.files), Slice(&self.dirs)).encode(out)
    }
}

/// A borrowed view of a serialized dirtree object.
#[derive(Clone, Copy)]
pub struct DirTreeRef<'a> {
    files: ArrayIter<'a, (&'a str, &'a [u8])>,
    dirs: ArrayIter<'a, (&'a str, &'a [u8], &'a [u8])>,
}

impl<'a> DirTreeRef<'a> {
    /// Parse the slice covering exactly a serialized dirtree object.
    pub fn parse(data: &'a [u8]) -> Result<DirTreeRef<'a>> {
        let (files, dirs) = GvDecode::decode(data)?;
        Ok(DirTreeRef { files, dirs })
    }

    /// Iterate file entries, validating each as visited.
    pub fn files(&self) -> impl Iterator<Item = Result<(&'a str, Checksum)>> + use<'a> {
        ValidatedIter::new(
            self.files,
            None,
            |prev: &mut Option<&'a str>, (name, csum): (&'a str, &'a [u8])| {
                check_entry(prev, name)?;
                Ok((name, entry_checksum(csum)?))
            },
        )
    }

    /// Iterate directory entries, validating each as visited.
    pub fn dirs(&self) -> impl Iterator<Item = Result<(&'a str, Checksum, Checksum)>> + use<'a> {
        ValidatedIter::new(
            self.dirs,
            None,
            |prev: &mut Option<&'a str>, (name, tree, meta): (&'a str, &'a [u8], &'a [u8])| {
                check_entry(prev, name)?;
                Ok((name, entry_checksum(tree)?, entry_checksum(meta)?))
            },
        )
    }

    /// Collect into an owned [`DirTree`].
    pub fn to_owned(&self) -> Result<DirTree> {
        let mut owned = DirTree::default();
        for item in self.files() {
            let (name, checksum) = item?;
            owned.files.push((name.to_owned(), checksum));
        }
        for item in self.dirs() {
            let (name, tree, meta) = item?;
            owned.dirs.push((name.to_owned(), tree, meta));
        }
        Ok(owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ostrya_gvariant::{Type, Value, to_bytes};

    fn csum(byte: u8) -> Checksum {
        Checksum::from_bytes([byte; 32])
    }

    fn sample() -> DirTree {
        DirTree {
            files: vec![("a.txt".to_owned(), csum(1)), ("b.txt".to_owned(), csum(2))],
            dirs: vec![("sub".to_owned(), csum(3), csum(4))],
        }
    }

    #[test]
    fn round_trips_through_the_view() {
        let tree = sample();
        let bytes = tree.serialize().unwrap();
        let view = DirTreeRef::parse(&bytes).unwrap();
        let files: Vec<_> = view.files().map(Result::unwrap).collect();
        assert_eq!(files, [("a.txt", csum(1)), ("b.txt", csum(2))]);
        let dirs: Vec<_> = view.dirs().map(Result::unwrap).collect();
        assert_eq!(dirs, [("sub", csum(3), csum(4))]);
        assert_eq!(view.to_owned().unwrap(), tree);
        assert_eq!(DirTree::parse(&bytes).unwrap().serialize().unwrap(), bytes);
    }

    #[test]
    fn serialize_rejects_unsorted_and_invalid_names() {
        for (files, expected) in [
            (
                vec![("b".to_owned(), csum(1)), ("a".to_owned(), csum(2))],
                "entry names are not sorted",
            ),
            (
                vec![("a".to_owned(), csum(1)), ("a".to_owned(), csum(2))],
                "entry names are not sorted",
            ),
            (vec![(String::new(), csum(1))], "empty entry name"),
            (
                vec![("..".to_owned(), csum(1))],
                "entry name is a directory traversal",
            ),
            (
                vec![("a/b".to_owned(), csum(1))],
                "entry name contains a slash",
            ),
        ] {
            let tree = DirTree {
                files,
                dirs: Vec::new(),
            };
            assert_eq!(tree.serialize(), Err(Error::InvalidDirTree(expected)));
        }
    }

    /// Serialize an arbitrary dirtree through the `Value` tree, bypassing the
    /// struct's validation.
    fn craft(files: &[(&str, &[u8])]) -> Vec<u8> {
        let ty = Type::parse("(a(say)a(sayay))").unwrap();
        let value = Value::Tuple(vec![
            Value::Array(
                files
                    .iter()
                    .map(|(name, checksum)| {
                        Value::Tuple(vec![
                            Value::Str((*name).to_owned()),
                            Value::Bytes(checksum.to_vec()),
                        ])
                    })
                    .collect(),
            ),
            Value::Array(Vec::new()),
        ]);
        to_bytes(&ty, &value).unwrap()
    }

    #[test]
    fn view_validates_entries_as_visited_and_fuses_on_error() {
        let bytes = craft(&[("b", &[1; 32]), ("a", &[2; 32])]);
        let view = DirTreeRef::parse(&bytes).unwrap();
        let mut files = view.files();
        assert!(files.next().unwrap().is_ok());
        assert_eq!(
            files.next().unwrap(),
            Err(Error::InvalidDirTree("entry names are not sorted"))
        );
        assert!(files.next().is_none(), "iterator fuses after an error");

        let bytes = craft(&[("a", &[1; 31])]);
        let view = DirTreeRef::parse(&bytes).unwrap();
        assert_eq!(
            view.files().next().unwrap(),
            Err(Error::InvalidDirTree("entry checksum is not 32 bytes"))
        );

        let bytes = craft(&[("a/../b", &[1; 32])]);
        assert_eq!(
            DirTreeRef::parse(&bytes).unwrap().to_owned(),
            Err(Error::InvalidDirTree("entry name contains a slash"))
        );
    }

    /// Serialize an arbitrary dirtree with both lists populated, bypassing the
    /// struct's validation.
    fn craft2(files: &[(&str, &[u8])], dirs: &[(&str, &[u8], &[u8])]) -> Vec<u8> {
        let ty = Type::parse("(a(say)a(sayay))").unwrap();
        let value = Value::Tuple(vec![
            Value::Array(
                files
                    .iter()
                    .map(|(name, c)| {
                        Value::Tuple(vec![
                            Value::Str((*name).to_owned()),
                            Value::Bytes(c.to_vec()),
                        ])
                    })
                    .collect(),
            ),
            Value::Array(
                dirs.iter()
                    .map(|(name, t, m)| {
                        Value::Tuple(vec![
                            Value::Str((*name).to_owned()),
                            Value::Bytes(t.to_vec()),
                            Value::Bytes(m.to_vec()),
                        ])
                    })
                    .collect(),
            ),
        ]);
        to_bytes(&ty, &value).unwrap()
    }

    #[test]
    fn rejects_a_name_shared_across_file_and_dir_lists() {
        let shared = Error::InvalidDirTree("a name appears in both the file and directory lists");

        // Writer: minting such an object fails.
        let tree = DirTree {
            files: vec![("x".to_owned(), csum(1))],
            dirs: vec![("x".to_owned(), csum(2), csum(3))],
        };
        assert_eq!(tree.serialize(), Err(shared.clone()));

        // Owned read path: materializing the crafted object fails the same way.
        let bytes = craft2(&[("x", &[1; 32])], &[("x", &[2; 32], &[3; 32])]);
        assert_eq!(DirTree::parse(&bytes), Err(shared));

        // Borrowed traversal stays per-list: each list yields the shared name
        // with no cross-list check, matching what the tool reads.
        let view = DirTreeRef::parse(&bytes).unwrap();
        assert_eq!(view.files().next().unwrap().unwrap().0, "x");
        assert_eq!(view.dirs().next().unwrap().unwrap().0, "x");
    }

    #[test]
    fn distinct_names_across_lists_are_accepted() {
        // A file and a directory with different names round-trip cleanly.
        let bytes = craft2(&[("a", &[1; 32])], &[("b", &[2; 32], &[3; 32])]);
        let tree = DirTree::parse(&bytes).unwrap();
        assert_eq!(tree.files.len(), 1);
        assert_eq!(tree.dirs.len(), 1);
        assert_eq!(tree.serialize().unwrap(), bytes);
    }
}
