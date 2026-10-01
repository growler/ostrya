//! The ref-name rule.
//!
//! A ref name is a path below `refs/heads`: one or more components joined
//! with `/`. A component is not empty, is not `.` or `..`, and holds no NUL.
//! A refspec is a ref name, or `REMOTE:NAME`, split at the first `:`, where
//! `REMOTE` is one component and `NAME` is a ref name. A refspec of the
//! second form names a path below `refs/remotes/REMOTE`. The rule keeps
//! each name inside the `refs/` tree.

/// Whether `component` is one component of a ref name: not empty, not `.` or
/// `..`, and with no `/` and no NUL.
pub fn is_ref_component(component: &str) -> bool {
    !(component.is_empty()
        || component == "."
        || component == ".."
        || component.contains('/')
        || component.contains('\0'))
}

/// Whether `name` is a ref name: not empty, and each of its `/`-separated
/// components passes [`is_ref_component`].
pub fn is_ref_name(name: &str) -> bool {
    !name.is_empty() && name.split('/').all(is_ref_component)
}

/// Whether `refspec` passes the ref-name rule: a ref name, or `REMOTE:NAME`
/// split at the first `:`, with `REMOTE` one component and `NAME` a ref
/// name.
pub fn is_refspec(refspec: &str) -> bool {
    match refspec.split_once(':') {
        Some((remote, name)) => is_ref_component(remote) && is_ref_name(name),
        None => is_ref_name(refspec),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ref_name_holds_components_that_stay_in_the_tree() {
        for name in ["main", "a/b/c", "x.y", "..x", "a:b", "-dash", "a^"] {
            assert!(is_ref_name(name), "{name}");
        }
        for name in [
            "", "/", "/a", "a/", "a//b", ".", "..", "a/./b", "a/../b", "a\0b",
        ] {
            assert!(!is_ref_name(name), "{name:?}");
        }
    }

    #[test]
    fn a_refspec_splits_at_the_first_colon() {
        for spec in ["main", "a/b", "origin:main", "origin:a/b", "o:a:b"] {
            assert!(is_refspec(spec), "{spec}");
        }
        for spec in [
            "", ":", ":main", "origin:", "a/b:main", "..:main", ".:main", "o:..", "o:a/../b",
            "o\0:main",
        ] {
            assert!(!is_refspec(spec), "{spec:?}");
        }
    }

    #[test]
    fn a_component_holds_no_slash_and_no_nul() {
        assert!(is_ref_component("a.b"));
        for c in ["", ".", "..", "a/b", "a\0"] {
            assert!(!is_ref_component(c), "{c:?}");
        }
    }
}
