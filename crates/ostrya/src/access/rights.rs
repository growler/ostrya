//! The access modes, the allow items, and the effective rights of a ref.

use std::fmt;

use ostrya_core::RefPattern;

use crate::error::{Error, Result};

/// A set of access modes.
///
/// A mode is one letter of an allow item:
///
/// - `r` ([`READ`](AccessModes::READ)) -- read the ref.
/// - `w` ([`WRITE`](AccessModes::WRITE)) -- write a client-built commit to
///   the ref.
/// - `c` ([`COMMIT`](AccessModes::COMMIT)) -- the server makes a commit on
///   the branch.
/// - `t` ([`TAG`](AccessModes::TAG)) -- create the ref as a tag.
/// - `d` ([`DELETE`](AccessModes::DELETE)) -- delete the ref.
///
/// [`Display`](fmt::Display) writes the letters in the order `rwctd`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct AccessModes {
    inner: u8,
}

/// The letters of the modes, in the order of their bits.
const LETTERS: [(char, AccessModes); 5] = [
    ('r', AccessModes::READ),
    ('w', AccessModes::WRITE),
    ('c', AccessModes::COMMIT),
    ('t', AccessModes::TAG),
    ('d', AccessModes::DELETE),
];

impl AccessModes {
    /// The set with no mode.
    pub const NONE: AccessModes = AccessModes { inner: 0 };
    /// `r`: read the ref.
    pub const READ: AccessModes = AccessModes { inner: 1 };
    /// `w`: write a client-built commit to the ref.
    pub const WRITE: AccessModes = AccessModes { inner: 1 << 1 };
    /// `c`: the server makes a commit on the branch.
    pub const COMMIT: AccessModes = AccessModes { inner: 1 << 2 };
    /// `t`: create the ref as a tag.
    pub const TAG: AccessModes = AccessModes { inner: 1 << 3 };
    /// `d`: delete the ref.
    pub const DELETE: AccessModes = AccessModes { inner: 1 << 4 };

    /// Parses the modes of an allow item: one or more of `r`, `w`, `c`, `t`,
    /// and `d`, each at most one time, in any order.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFormat`] if `text` is empty, holds another character,
    /// or holds a letter two times.
    pub fn parse(text: &str) -> Result<AccessModes> {
        parse_modes(text)
            .map_err(|why| Error::InvalidFormat(format!("malformed access modes '{text}': {why}")))
    }

    /// Returns `true` if the set holds no mode.
    pub fn is_empty(self) -> bool {
        self.inner == 0
    }

    /// Returns `true` if the set holds each mode of `other`.
    pub fn contains(self, other: AccessModes) -> bool {
        self.inner & other.inner == other.inner
    }

    /// Returns `true` if the set holds a mode of `other`.
    pub fn intersects(self, other: AccessModes) -> bool {
        self.inner & other.inner != 0
    }

    /// Returns the set with the modes of `self` and of `other`.
    pub fn union(self, other: AccessModes) -> AccessModes {
        AccessModes {
            inner: self.inner | other.inner,
        }
    }
}

impl fmt::Display for AccessModes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (letter, mode) in LETTERS {
            if self.contains(mode) {
                write!(f, "{letter}")?;
            }
        }
        Ok(())
    }
}

/// Parses the modes of an allow item. The error is the reason.
fn parse_modes(text: &str) -> std::result::Result<AccessModes, &'static str> {
    if text.is_empty() {
        return Err("the modes are one or more of r, w, c, t, and d");
    }
    let mut modes = AccessModes::NONE;
    for c in text.chars() {
        let Some(&(_, mode)) = LETTERS.iter().find(|(letter, _)| *letter == c) else {
            return Err("the modes are one or more of r, w, c, t, and d");
        };
        if modes.contains(mode) {
            return Err("each mode occurs at most one time");
        }
        modes = modes.union(mode);
    }
    Ok(modes)
}

/// One allow item: the modes that a group has on the refs that a pattern
/// matches.
///
/// The text form is `[MODES:]PATTERN`. `MODES` is the text that
/// [`AccessModes::parse`] reads, and an item with no `MODES` has the mode
/// `r`. `PATTERN` is a [`RefPattern`]: literal parts, `*` for exactly one
/// part, and `**` for one or more parts. [`Display`](fmt::Display) writes the
/// form with `MODES`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowItem {
    /// The modes of the item.
    pub modes: AccessModes,
    /// The refs of the item.
    pub pattern: RefPattern,
}

impl AllowItem {
    /// Parses an allow item, `[MODES:]PATTERN`.
    ///
    /// The text splits at the first `:`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFormat`] if the modes or the pattern are malformed.
    pub fn parse(text: &str) -> Result<AllowItem> {
        parse_allow(text)
            .map_err(|why| Error::InvalidFormat(format!("malformed allow item '{text}': {why}")))
    }
}

impl fmt::Display for AllowItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.modes, self.pattern.as_str())
    }
}

/// Parses an allow item. The error is the reason.
pub(super) fn parse_allow(text: &str) -> std::result::Result<AllowItem, String> {
    let (modes, pattern) = match text.split_once(':') {
        Some((modes, pattern)) => (parse_modes(modes).map_err(str::to_owned)?, pattern),
        None => (AccessModes::READ, text),
    };
    Ok(AllowItem {
        modes,
        pattern: parse_pattern(pattern)?,
    })
}

/// Parses a ref pattern of an allow item or a deny item. The error is the
/// reason, without the pattern text.
pub(super) fn parse_pattern(text: &str) -> std::result::Result<RefPattern, String> {
    RefPattern::parse(text).map_err(|err| match err {
        ostrya_core::Error::InvalidRefPattern(reason) => {
            let quoted = format!("{text:?}: ");
            reason.strip_prefix(&quoted).unwrap_or(&reason).to_owned()
        }
        other => other.to_string(),
    })
}

/// The allow items and the deny items of a group.
///
/// [`rights`](AccessRules::rights) gives the effective rights of one ref.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccessRules {
    /// The allow items, in the order of the config.
    pub allow: Vec<AllowItem>,
    /// The deny items, in the order of the config.
    pub deny: Vec<RefPattern>,
}

impl AccessRules {
    /// Returns the effective rights of the ref `name`.
    ///
    /// When a deny item matches `name`, the result is empty. Else the result
    /// is the union of the modes of each allow item that matches `name`. When
    /// the union holds `w`, `c`, or `t`, the result also holds `r`. `d` alone
    /// does not add `r`.
    pub fn rights(&self, name: &str) -> AccessModes {
        if self.deny.iter().any(|pattern| pattern.matches(name)) {
            return AccessModes::NONE;
        }
        let modes = self
            .allow
            .iter()
            .filter(|item| item.pattern.matches(name))
            .fold(AccessModes::NONE, |modes, item| modes.union(item.modes));
        if modes.intersects(push_modes_with_read()) {
            modes.union(AccessModes::READ)
        } else {
            modes
        }
    }

    /// Returns `true` if the rules let a client open a push session.
    ///
    /// The result is `true` when an allow item has `w`, `c`, `t`, or `d`. The
    /// deny items have no effect on the result.
    pub fn opens_push_session(&self) -> bool {
        let push = push_modes_with_read().union(AccessModes::DELETE);
        self.allow.iter().any(|item| item.modes.intersects(push))
    }

    /// Returns `true` if an allow item gives `r`: it has `r`, `w`, `c`, or
    /// `t`. The deny items have no effect on the result.
    pub(crate) fn gives_read(&self) -> bool {
        let read = push_modes_with_read().union(AccessModes::READ);
        self.allow.iter().any(|item| item.modes.intersects(read))
    }
}

/// The modes that add `r`: `w`, `c`, and `t`.
fn push_modes_with_read() -> AccessModes {
    AccessModes::WRITE
        .union(AccessModes::COMMIT)
        .union(AccessModes::TAG)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn modes(text: &str) -> AccessModes {
        AccessModes::parse(text).unwrap()
    }

    fn rules(allow: &[&str], deny: &[&str]) -> AccessRules {
        AccessRules {
            allow: allow.iter().map(|t| AllowItem::parse(t).unwrap()).collect(),
            deny: deny.iter().map(|t| RefPattern::parse(t).unwrap()).collect(),
        }
    }

    /// The modes parse in any order, and `Display` writes them in the order
    /// `rwctd`.
    #[test]
    fn the_modes_parse_in_any_order() {
        assert_eq!(modes("r"), AccessModes::READ);
        assert_eq!(modes("dtcwr").to_string(), "rwctd");
        assert_eq!(modes("cd").to_string(), "cd");
        assert!(modes("wd").contains(AccessModes::DELETE));
        assert!(!modes("wd").contains(AccessModes::READ));
        assert!(AccessModes::NONE.is_empty());
        assert_eq!(AccessModes::NONE.to_string(), "");
    }

    /// An empty text, an unknown letter, an uppercase letter, and a letter
    /// that occurs two times are refused.
    #[test]
    fn the_other_modes_are_refused() {
        for text in ["", "x", "R", "rr", "rwr", "r w", "rw ", "r,w"] {
            let err = AccessModes::parse(text).unwrap_err();
            assert!(matches!(err, Error::InvalidFormat(_)), "{text:?}: {err}");
        }
    }

    /// An allow item splits at the first `:`, and an item with no modes has
    /// the mode `r`.
    #[test]
    fn an_allow_item_splits_at_the_first_colon() {
        let item = AllowItem::parse("os/**").unwrap();
        assert_eq!(item.modes, AccessModes::READ);
        assert_eq!(item.pattern.as_str(), "os/**");
        assert_eq!(item.to_string(), "r:os/**");
        let item = AllowItem::parse("tw:os/*/stable").unwrap();
        assert_eq!(item.modes, modes("wt"));
        assert_eq!(item.to_string(), "wt:os/*/stable");
        assert_eq!(AllowItem::parse(&item.to_string()).unwrap(), item);
    }

    /// A malformed allow item is refused with its text in the message.
    #[test]
    fn a_malformed_allow_item_is_refused() {
        for text in [
            "", ":a", "x:a", "R:a", "rr:a", "r:", "r:a:b", "r:a//b", "r:a*", "r:-a", "r:!a",
            "r: a", " r:a",
        ] {
            let Err(Error::InvalidFormat(message)) = AllowItem::parse(text) else {
                panic!("{text:?} was accepted");
            };
            assert!(
                message.starts_with(&format!("malformed allow item '{text}': ")),
                "{message}"
            );
        }
    }

    /// The rights are the union of the modes of each item that matches.
    #[test]
    fn the_rights_are_the_union_of_the_matching_items() {
        let r = rules(&["r:**", "d:devel/**", "rd:devel/x"], &[]);
        assert_eq!(r.rights("main"), modes("r"));
        assert_eq!(r.rights("devel/y"), modes("rd"));
        assert_eq!(r.rights("devel/x"), modes("rd"));
        let r = rules(&["d:devel/**"], &[]);
        assert_eq!(r.rights("main"), AccessModes::NONE);
    }

    /// `w`, `c`, and `t` add `r`, and `d` does not.
    #[test]
    fn w_c_and_t_add_read_and_d_does_not() {
        for (mode, want) in [
            ("w", "rw"),
            ("c", "rc"),
            ("t", "rt"),
            ("d", "d"),
            ("wd", "rwd"),
        ] {
            let r = rules(&[&format!("{mode}:a")], &[]);
            assert_eq!(r.rights("a"), modes(want), "{mode}");
        }
    }

    /// A deny item that matches the ref removes each mode.
    #[test]
    fn a_deny_item_wins_over_each_allow_item() {
        let r = rules(&["rwctd:**"], &["secret/**"]);
        assert_eq!(r.rights("secret/a"), AccessModes::NONE);
        assert_eq!(r.rights("public"), modes("rwctd"));
        let r = rules(&[], &["**"]);
        assert_eq!(r.rights("a"), AccessModes::NONE);
    }

    /// A push session needs an allow item with `w`, `c`, `t`, or `d`, and a
    /// deny item does not take it away.
    #[test]
    fn a_push_session_needs_a_push_mode_in_an_allow_item() {
        assert!(!rules(&[], &[]).opens_push_session());
        assert!(!rules(&["r:**"], &[]).opens_push_session());
        for mode in ["w", "c", "t", "d"] {
            assert!(
                rules(&["r:**", &format!("{mode}:a")], &["**"]).opens_push_session(),
                "{mode}"
            );
        }
    }
}
