//! Dirtree objects: the sorted lists of child files and subdirectories.
//!
//! The owned [`DirTree`] checks all rules of the object when it parses and
//! when it serializes. The borrowed [`DirTreeRef`] checks each entry when an
//! iterator visits it, and does no check across the two lists.

use ostrya_gvariant::{ArrayIter, GvDecode, GvEncode, GvType, Slice};

use crate::checksum::Checksum;
use crate::error::{Error, Result};
use crate::valiter::ValidatedIter;

/// An owned dirtree object: the lists of child files and subdirectories.
///
/// # Wire form
///
/// The GVariant type is `(a(say)a(sayay))`. It holds two lists:
///
/// - the file entries `(say)`: the name and the checksum of the content object
/// - the directory entries `(sayay)`: the name, the checksum of the dirtree
///   object, and the checksum of the dirmeta object
///
/// Each checksum is a raw 32-byte `ay`.
///
/// # Rules
///
/// - Each list is sorted by name in byte-wise order. A name occurs at most
///   once in a list. The sort order makes the checksum of a tree
///   reproducible.
/// - Each name is one path component, as [`check_name`](Self::check_name)
///   states.
/// - No name is in both lists, because the two entries have the same
///   checkout path.
///
/// [`serialize`](Self::serialize) and [`parse`](Self::parse) check all three
/// rules. [`DirTreeRef`] checks the first two rules only.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DirTree {
    /// The file entries: the name and the content checksum, sorted by name.
    pub files: Vec<(String, Checksum)>,
    /// The directory entries, sorted by name.
    ///
    /// Each entry holds the name, the dirtree checksum, and the dirmeta
    /// checksum.
    pub dirs: Vec<(String, Checksum, Checksum)>,
}

/// Checks one visited name against the previous name of the same list. The
/// name must be a valid component and must sort strictly after the previous
/// name in byte-wise order, so a duplicate name is refused.
fn check_entry<'a>(prev: &mut Option<&'a str>, name: &'a str) -> Result<()> {
    DirTree::check_name(name)?;
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
    /// Checks that `name` is one path component.
    ///
    /// A valid name is not empty, is not `.` or `..`, and holds no `/`. This
    /// check is the defense against path traversal through a dirtree entry.
    /// The string decoder of the read path refuses a name that is not UTF-8.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidDirTree`] with one of these reasons:
    ///
    /// - `"empty entry name"` if `name` is empty
    /// - `"entry name is a directory traversal"` if `name` is `.` or `..`
    /// - `"entry name contains a slash"` if `name` holds a `/`
    pub fn check_name(name: &str) -> Result<()> {
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

    /// Parses a serialized dirtree object into an owned tree.
    ///
    /// The parse checks each entry when it collects the lists, as
    /// [`DirTreeRef::to_owned`] does. Then it checks that no name is in both
    /// lists. A tree that this function returns obeys all
    /// [rules](DirTree#rules).
    ///
    /// # Errors
    ///
    /// - [`Error::Gvariant`] if `data` is not a normal-form value of type
    ///   `(a(say)a(sayay))`.
    /// - [`Error::InvalidDirTree`] if an entry breaks a rule. These are the
    ///   reasons:
    ///   - a reason of [`check_name`](Self::check_name) if a name is not one
    ///     path component
    ///   - `"entry names are not sorted"` if a name does not sort strictly
    ///     after the previous name of its list
    ///   - `"entry checksum is not 32 bytes"` if a checksum has a different
    ///     length
    ///   - `"a name appears in both the file and directory lists"` if a name
    ///     is in both lists
    pub fn parse(data: &[u8]) -> Result<DirTree> {
        let tree = DirTreeRef::parse(data)?.to_owned()?;
        tree.check_no_shared_names()?;
        Ok(tree)
    }

    /// Serializes the tree to normal-form bytes.
    ///
    /// The SHA-256 of these bytes is the checksum of the dirtree object.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidDirTree`] if the tree breaks a
    ///   [rule](DirTree#rules). These are the reasons:
    ///   - a reason of [`check_name`](Self::check_name) if a name is not one
    ///     path component
    ///   - `"entry names are not sorted"` if a name does not sort strictly
    ///     after the previous name of its list
    ///   - `"a name appears in both the file and directory lists"` if a name
    ///     is in both lists
    /// - [`Error::Gvariant`] with
    ///   [`InvalidValue`](ostrya_gvariant::Error::InvalidValue) if a name
    ///   holds a NUL byte.
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

    /// Checks that no name is in both lists. Both lists are sorted when this
    /// function runs: `validate` checks the order on the write path, and
    /// `to_owned` checks it on the read path. For this reason, one merge walk
    /// over the two lists finds a shared name with no allocation.
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

/// The encoder writes the two lists as they are and checks no
/// [rule](DirTree#rules). [`DirTree::serialize`] checks the rules before it
/// encodes.
impl GvEncode for DirTree {
    // `DirTree::serialize` is the only caller in this crate. `String` and
    // `Checksum` implement `GvEncode`, so the owned entry vectors encode with
    // no conversion.
    fn encode(&self, out: &mut Vec<u8>) -> ostrya_gvariant::Result<()> {
        (Slice(&self.files), Slice(&self.dirs)).encode(out)
    }
}

/// A borrowed view of a serialized dirtree object.
///
/// A full walk of a dirtree borrows the object buffer for the whole walk and
/// does not allocate.
///
/// # Checks
///
/// [`parse`](Self::parse) checks the container framing only. The iterators
/// [`files`](Self::files) and [`dirs`](Self::dirs) check each entry when they
/// visit it, so they yield `Result`. These are the checks:
///
/// - The name is one path component, as [`DirTree::check_name`] states.
/// - Each checksum is 32 bytes long.
/// - The name sorts strictly after the previous name of the same list, in
///   byte-wise order.
///
/// After an error, an iterator is exhausted and returns `None`.
///
/// # Names in both lists
///
/// The view checks each list alone, because a check across the two lists
/// needs an allocation. [`DirTree::parse`] refuses an object with a name in
/// both lists.
///
/// The `ostree` command reads such an object in the same way as the view.
/// `ostree fsck` accepts it, and `ostree ls` lists both entries. The `ostree`
/// command aborts only when it resolves the name as a directory.
#[derive(Clone, Copy)]
pub struct DirTreeRef<'a> {
    files: ArrayIter<'a, (&'a str, &'a [u8])>,
    dirs: ArrayIter<'a, (&'a str, &'a [u8], &'a [u8])>,
}

impl<'a> DirTreeRef<'a> {
    /// Parses a serialized dirtree object into a borrowed view.
    ///
    /// `data` must cover exactly one serialized dirtree object. The parse
    /// checks the container framing only. The iterators check the entries,
    /// as the [checks](DirTreeRef#checks) state.
    ///
    /// # Errors
    ///
    /// [`Error::Gvariant`] if the framing of the tuple or of one of its two
    /// arrays is not in normal form.
    pub fn parse(data: &'a [u8]) -> Result<DirTreeRef<'a>> {
        let (files, dirs) = GvDecode::decode(data)?;
        Ok(DirTreeRef { files, dirs })
    }

    /// Returns an iterator over the file entries.
    ///
    /// The iterator checks each entry when it visits it, as the
    /// [checks](DirTreeRef#checks) state. An item is an error if the entry
    /// fails a check or if its framing is not in normal form.
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

    /// Returns an iterator over the directory entries.
    ///
    /// The iterator checks each entry when it visits it, as the
    /// [checks](DirTreeRef#checks) state. An item is an error if the entry
    /// fails a check or if its framing is not in normal form.
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

    /// Collects the entries into an owned [`DirTree`].
    ///
    /// The result can hold a name in both lists, because this function does
    /// no check across the two lists. [`DirTree::parse`] adds that check.
    ///
    /// # Errors
    ///
    /// - [`Error::Gvariant`] if the framing of an entry is not in normal form.
    /// - [`Error::InvalidDirTree`] if an entry fails a
    ///   [check](DirTreeRef#checks). These are the reasons:
    ///   - a reason of [`DirTree::check_name`] if a name is not one path
    ///     component
    ///   - `"entry names are not sorted"` if a name does not sort strictly
    ///     after the previous name of its list
    ///   - `"entry checksum is not 32 bytes"` if a checksum has a different
    ///     length
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
    fn check_name_refuses_what_is_not_one_component() {
        for name in ["", ".", "..", "a/b", "/"] {
            assert!(DirTree::check_name(name).is_err(), "{name:?}");
        }
        for name in ["a", "...", ".a", "a."] {
            assert!(DirTree::check_name(name).is_ok(), "{name:?}");
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

    /// Serializes a dirtree with file entries only through the `Value` tree,
    /// with none of the checks of `DirTree::serialize`.
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

    /// Serializes a dirtree with entries in both lists through the `Value`
    /// tree, with none of the checks of `DirTree::serialize`.
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

        // Write path: the serialization of such an object fails.
        let tree = DirTree {
            files: vec![("x".to_owned(), csum(1))],
            dirs: vec![("x".to_owned(), csum(2), csum(3))],
        };
        assert_eq!(tree.serialize(), Err(shared.clone()));

        // Owned read path: the parse of the crafted object fails with the
        // same error.
        let bytes = craft2(&[("x", &[1; 32])], &[("x", &[2; 32], &[3; 32])]);
        assert_eq!(DirTree::parse(&bytes), Err(shared));

        // Borrowed view: each list yields the shared name, because the view
        // checks each list alone. The `ostree` command reads it the same way.
        let view = DirTreeRef::parse(&bytes).unwrap();
        assert_eq!(view.files().next().unwrap().unwrap().0, "x");
        assert_eq!(view.dirs().next().unwrap().unwrap().0, "x");
    }

    #[test]
    fn distinct_names_across_lists_are_accepted() {
        // A file and a directory with different names make a round trip with
        // no change.
        let bytes = craft2(&[("a", &[1; 32])], &[("b", &[2; 32], &[3; 32])]);
        let tree = DirTree::parse(&bytes).unwrap();
        assert_eq!(tree.files.len(), 1);
        assert_eq!(tree.dirs.len(), 1);
        assert_eq!(tree.serialize().unwrap(), bytes);
    }
}
