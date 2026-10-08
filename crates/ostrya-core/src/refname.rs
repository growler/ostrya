//! The ref-name rule.
//!
//! Each of the first three functions checks one level of the rule: a
//! component, a ref name, or a refspec. `is_checksum_shaped` marks a valid
//! ref name that a revision reads as a checksum.

use crate::Checksum;

/// Returns `true` if `component` is one valid component of a ref name.
///
/// A component is not empty, is not `.` or `..`, and holds no `/` and no NUL.
pub fn is_ref_component(component: &str) -> bool {
    !(component.is_empty()
        || component == "."
        || component == ".."
        || component.contains('/')
        || component.contains('\0'))
}

/// Returns `true` if `name` is a valid ref name.
///
/// A ref name is a path below `refs/heads`. It is not empty, and each of its
/// `/`-separated components passes [`is_ref_component`]. The rule keeps each
/// name inside the `refs/` tree.
pub fn is_ref_name(name: &str) -> bool {
    !name.is_empty() && name.split('/').all(is_ref_component)
}

/// Returns `true` if `refspec` is a valid refspec.
///
/// A refspec is a ref name, or `REMOTE:NAME` split at the first `:`. In the
/// second form, `REMOTE` must pass [`is_ref_component`] and `NAME` must pass
/// [`is_ref_name`]. Such a refspec names a path below `refs/remotes/REMOTE`,
/// so it stays inside the `refs/` tree.
pub fn is_refspec(refspec: &str) -> bool {
    match refspec.split_once(':') {
        Some((remote, name)) => is_ref_component(remote) && is_ref_name(name),
        None => is_ref_name(refspec),
    }
}

/// Returns `true` if `name` is 64 lowercase hex characters.
///
/// Such a name passes [`is_ref_name`]. A revision reads it as a commit
/// checksum. A push refuses to write a commit to a ref of that name. A name
/// with an uppercase hex character gives `false`.
pub fn is_checksum_shaped(name: &str) -> bool {
    Checksum::from_hex_lower(name).is_ok()
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

    #[test]
    fn a_checksum_shaped_name_is_64_lowercase_hex_characters() {
        let hex = "0123456789abcdef".repeat(4);
        assert!(is_checksum_shaped(&hex));
        assert!(is_ref_name(&hex));
        let mut one_off = hex.clone();
        one_off.replace_range(10..11, "g");
        for name in [
            hex.to_uppercase(),
            format!("A{}", &hex[1..]),
            hex[..63].to_owned(),
            format!("{hex}0"),
            one_off,
            format!("origin:{hex}"),
            String::new(),
        ] {
            assert!(!is_checksum_shaped(&name), "{name}");
        }
    }
}
