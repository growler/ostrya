//! The subpaths an HTTP pull fetches a commit's tree under.
//!
//! [`PullOptions::subpaths`](crate::PullOptions::subpaths) names the parts of a
//! commit's tree a pull fetches. Each value is an absolute path, split on `/`
//! after its leading `/` with every component kept, empty ones included. The
//! walk descends from the root dirtree along each path one component at a time:
//!
//! - a directory entry named by a component that is not the path's last is
//!   fetched with its dirmeta, and the walk goes on inside it with the next
//!   component;
//! - an entry named by the path's last component is fetched whole: a file, or a
//!   directory with its dirmeta and everything under it;
//! - a file named by a component that is not the last, and a name the dirtree
//!   does not hold, end the path there.
//!
//! No other entry is fetched: not a sibling, not its dirmeta, and not a file in
//! a directory the path only passes through. The root dirtree and dirmeta are
//! always fetched. `/` is the one empty component, which names nothing, so it
//! fetches the root dirtree and dirmeta and nothing under them, and `/sub/`
//! fetches the `sub` dirtree and dirmeta and nothing in them. A component `.` or `..`, or an empty one from a
//! doubled `/`, matches no entry, since no dirtree entry has such a name. Several
//! values fetch the union of what each fetches on its own.
//!
//! A dirtree is walked under a [`Scope`]: every path position that reaches it,
//! as the path's index and the number of components matched on the way. One
//! dirtree checksum reached at two positions is walked under the union of both.

use std::collections::HashMap;

use ostrya_core::{DirTree, ObjectName, ObjectType};

use crate::error::{Error, Result};

/// The parsed subpath values of one pull, each split into its components.
pub(crate) struct Subpaths {
    paths: Vec<Vec<String>>,
}

impl Subpaths {
    /// Parse the values of [`PullOptions::subpaths`](crate::PullOptions::subpaths).
    ///
    /// An empty list is `None`, which fetches the whole tree. A value that does
    /// not start with `/`, the empty value included, is refused.
    pub(crate) fn parse(values: &[String]) -> Result<Option<Subpaths>> {
        if values.is_empty() {
            return Ok(None);
        }
        let mut paths = Vec::with_capacity(values.len());
        for value in values {
            let Some(rest) = value.strip_prefix('/') else {
                return Err(Error::Pull(format!(
                    "subpath '{value}' is not an absolute path"
                )));
            };
            paths.push(rest.split('/').map(str::to_owned).collect());
        }
        if u32::try_from(paths.len()).is_err() {
            return Err(Error::Pull("too many subpaths".into()));
        }
        Ok(Some(Subpaths { paths }))
    }

    /// The scope the root dirtree of every commit is walked under: each path at
    /// its first component.
    pub(crate) fn root(&self) -> Scope {
        // `parse` bounds the count by `u32`.
        Scope::Along((0..self.paths.len() as u32).map(|i| (i, 0)).collect())
    }

    /// The objects `dirtree` references that a walk under `scope` fetches, each
    /// with the scope a dirtree among them is walked under.
    ///
    /// Several positions naming one entry yield it once, under the union of
    /// their scopes.
    pub(crate) fn children(&self, dirtree: &DirTree, scope: &Scope) -> Vec<(ObjectName, Scope)> {
        let Scope::Along(positions) = scope else {
            return all_children(dirtree);
        };
        let mut out: Vec<(ObjectName, Scope)> = Vec::new();
        let mut index: HashMap<ObjectName, usize> = HashMap::new();
        let mut add = |name: ObjectName, scope: Scope| match index.get(&name) {
            Some(&at) => match (&mut out[at].1, scope) {
                (Scope::All, _) => {}
                (held, Scope::All) => *held = Scope::All,
                // Sorted and deduplicated once, below.
                (Scope::Along(held), Scope::Along(more)) => held.extend(more),
            },
            None => {
                index.insert(name, out.len());
                out.push((name, scope));
            }
        };
        for &(path, matched) in positions {
            let components = &self.paths[path as usize];
            let Some(component) = components.get(matched as usize) else {
                continue;
            };
            let last = matched as usize + 1 == components.len();
            // Both lists are name-sorted, which the dirtree parse validates.
            if let Ok(at) = dirtree
                .files
                .binary_search_by(|(name, _)| name.as_str().cmp(component))
            {
                if last {
                    add(
                        ObjectName::new(dirtree.files[at].1, ObjectType::File),
                        Scope::All,
                    );
                }
                continue;
            }
            if let Ok(at) = dirtree
                .dirs
                .binary_search_by(|(name, _, _)| name.as_str().cmp(component))
            {
                let (_, tree, meta) = &dirtree.dirs[at];
                let scope = if last {
                    Scope::All
                } else {
                    Scope::Along(vec![(path, matched + 1)])
                };
                add(ObjectName::new(*meta, ObjectType::DirMeta), Scope::All);
                add(ObjectName::new(*tree, ObjectType::DirTree), scope);
            }
        }
        for (_, scope) in &mut out {
            if let Scope::Along(positions) = scope {
                positions.sort_unstable();
                positions.dedup();
            }
        }
        out
    }
}

/// Where a walk of one dirtree stands against the subpaths.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum Scope {
    /// Everything under the dirtree is fetched.
    #[default]
    All,
    /// The path positions that reach the dirtree: a path's index and how many of
    /// its components the walk matched to get here. Sorted, with no duplicate.
    Along(Vec<(u32, u32)>),
}

impl Scope {
    /// Whether a walk under `self` fetches everything a walk under `other` does.
    pub(crate) fn covers(&self, other: &Scope) -> bool {
        match (self, other) {
            (Scope::All, _) => true,
            (Scope::Along(_), Scope::All) => false,
            (Scope::Along(mine), Scope::Along(theirs)) => {
                theirs.iter().all(|p| mine.binary_search(p).is_ok())
            }
        }
    }

    /// Widen `self` to cover `other` as well.
    pub(crate) fn widen(&mut self, other: &Scope) {
        match (&mut *self, other) {
            (Scope::All, _) => {}
            (_, Scope::All) => *self = Scope::All,
            (Scope::Along(mine), Scope::Along(theirs)) => {
                // A merge of the two sorted lists, linear in their lengths.
                let mut merged = Vec::with_capacity(mine.len() + theirs.len());
                let (mut a, mut b) = (mine.iter().peekable(), theirs.iter().peekable());
                while let (Some(&&x), Some(&&y)) = (a.peek(), b.peek()) {
                    merged.push(x.min(y));
                    if x <= y {
                        a.next();
                    }
                    if y <= x {
                        b.next();
                    }
                }
                merged.extend(a);
                merged.extend(b);
                *mine = merged;
            }
        }
    }
}

/// Every object a dirtree references: its files, and the dirmeta and dirtree of
/// each subdirectory, each walked whole.
fn all_children(dirtree: &DirTree) -> Vec<(ObjectName, Scope)> {
    let mut out = Vec::with_capacity(dirtree.files.len() + 2 * dirtree.dirs.len());
    for (_, file) in &dirtree.files {
        out.push((ObjectName::new(*file, ObjectType::File), Scope::All));
    }
    for (_, subtree, submeta) in &dirtree.dirs {
        out.push((ObjectName::new(*submeta, ObjectType::DirMeta), Scope::All));
        out.push((ObjectName::new(*subtree, ObjectType::DirTree), Scope::All));
    }
    out
}

#[cfg(test)]
mod tests {
    use ostrya_core::Checksum;

    use super::*;

    fn cs(byte: u8) -> Checksum {
        Checksum::from_bytes([byte; 32])
    }

    fn parse(values: &[&str]) -> Subpaths {
        let values: Vec<String> = values.iter().map(|v| (*v).to_owned()).collect();
        Subpaths::parse(&values).unwrap().unwrap()
    }

    /// A root holding the file `a` (1), the directory `sub` (dirtree 2, dirmeta
    /// 3), and the directory `other` (dirtree 4, dirmeta 5).
    fn root() -> DirTree {
        DirTree {
            files: vec![("a".into(), cs(1))],
            dirs: vec![("other".into(), cs(4), cs(5)), ("sub".into(), cs(2), cs(3))],
        }
    }

    fn file(b: u8) -> ObjectName {
        ObjectName::new(cs(b), ObjectType::File)
    }
    fn tree(b: u8) -> ObjectName {
        ObjectName::new(cs(b), ObjectType::DirTree)
    }
    fn meta(b: u8) -> ObjectName {
        ObjectName::new(cs(b), ObjectType::DirMeta)
    }

    #[test]
    fn parse_refuses_a_relative_and_an_empty_value() {
        for value in ["sub", "", "sub/"] {
            let err = Subpaths::parse(&[value.to_owned()]).err().unwrap();
            assert!(matches!(err, Error::Pull(_)), "{value}: {err}");
        }
        assert!(Subpaths::parse(&[]).unwrap().is_none());
    }

    #[test]
    fn parse_keeps_every_component() {
        assert_eq!(parse(&["/"]).paths, vec![vec![String::new()]]);
        assert_eq!(parse(&["/sub"]).paths, vec![vec!["sub".to_owned()]]);
        assert_eq!(
            parse(&["/sub/"]).paths,
            vec![vec!["sub".to_owned(), String::new()]]
        );
        assert_eq!(
            parse(&["//sub"]).paths,
            vec![vec![String::new(), "sub".to_owned()]]
        );
    }

    #[test]
    fn a_directory_path_fetches_it_whole_and_no_sibling() {
        let paths = parse(&["/sub"]);
        assert_eq!(
            paths.children(&root(), &paths.root()),
            vec![(meta(3), Scope::All), (tree(2), Scope::All)]
        );
    }

    #[test]
    fn a_path_through_a_directory_walks_it_under_the_next_component() {
        let paths = parse(&["/sub/deeper"]);
        assert_eq!(
            paths.children(&root(), &paths.root()),
            vec![(meta(3), Scope::All), (tree(2), Scope::Along(vec![(0, 1)]))]
        );
    }

    #[test]
    fn a_file_is_fetched_only_as_the_last_component() {
        let paths = parse(&["/a"]);
        assert_eq!(
            paths.children(&root(), &paths.root()),
            vec![(file(1), Scope::All)]
        );
        for value in ["/a/", "/a/x"] {
            let paths = parse(&[value]);
            assert!(paths.children(&root(), &paths.root()).is_empty(), "{value}");
        }
    }

    #[test]
    fn names_the_dirtree_cannot_hold_match_nothing() {
        for value in ["/", "//sub", "/./sub", "/../sub", "/nonexist"] {
            let paths = parse(&[value]);
            assert!(paths.children(&root(), &paths.root()).is_empty(), "{value}");
        }
    }

    #[test]
    fn several_paths_take_the_union() {
        let paths = parse(&["/sub/x", "/a", "/sub"]);
        assert_eq!(
            paths.children(&root(), &paths.root()),
            vec![
                (meta(3), Scope::All),
                (tree(2), Scope::All),
                (file(1), Scope::All),
            ]
        );
    }

    #[test]
    fn a_walk_under_all_fetches_everything() {
        let paths = parse(&["/sub"]);
        assert_eq!(
            paths.children(&root(), &Scope::All),
            vec![
                (file(1), Scope::All),
                (meta(5), Scope::All),
                (tree(4), Scope::All),
                (meta(3), Scope::All),
                (tree(2), Scope::All),
            ]
        );
    }

    #[test]
    fn many_values_under_one_directory_merge_in_near_linear_time() {
        let count = 20_000u32;
        let values: Vec<String> = (0..count).map(|i| format!("/sub/f{i:05}")).collect();
        let paths = Subpaths::parse(&values).unwrap().unwrap();
        let children = paths.children(&root(), &paths.root());
        let expected: Vec<(u32, u32)> = (0..count).map(|i| (i, 1)).collect();
        assert_eq!(
            children,
            vec![
                (meta(3), Scope::All),
                (tree(2), Scope::Along(expected.clone()))
            ]
        );
        let sub = DirTree {
            files: (0..count)
                .map(|i| (format!("f{i:05}"), cs((i % 200) as u8)))
                .collect(),
            dirs: Vec::new(),
        };
        let files = paths.children(&sub, &Scope::Along(expected));
        // 200 distinct file objects, each named by 100 values.
        assert_eq!(files.len(), 200);
        assert!(files.iter().all(|(_, scope)| *scope == Scope::All));
        let mut a = Scope::Along((0..count).step_by(2).map(|i| (i, 0)).collect());
        a.widen(&Scope::Along((0..count).map(|i| (i, 0)).collect()));
        assert_eq!(a, Scope::Along((0..count).map(|i| (i, 0)).collect()));
    }

    #[test]
    fn covers_and_widen() {
        let mut a = Scope::Along(vec![(0, 1)]);
        let b = Scope::Along(vec![(1, 2)]);
        assert!(!a.covers(&b));
        a.widen(&b);
        assert_eq!(a, Scope::Along(vec![(0, 1), (1, 2)]));
        assert!(a.covers(&b));
        assert!(!a.covers(&Scope::All));
        a.widen(&Scope::All);
        assert_eq!(a, Scope::All);
        assert!(a.covers(&b));
    }
}
