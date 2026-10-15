//! The ref-name rule.
//!
//! `is_ref_name_component` checks one component of a ref name, `is_ref_name`
//! checks a whole ref name, and `is_refspec` checks a refspec. A component of
//! a ref name is not empty, does not start with `-` or `.`, and holds only
//! ASCII letters, ASCII digits, `-`, `.`, `_`, and non-ASCII characters for
//! which `char::is_alphanumeric` is `true`, less the characters that the
//! `ostree` tool refuses. The remote part of a refspec follows the rule of a
//! component. `is_ref_component` is a wider check for a part that is not a
//! ref name, such as a collection id. `is_checksum_shaped` marks a valid ref
//! name that a revision reads as a checksum. `is_collection_id` checks a
//! collection id.

use crate::Checksum;

/// Characters for which `char::is_alphanumeric` is `true` and that the
/// `ostree` tool refuses in a ref name, as inclusive ranges in ascending
/// order. They are spacing combining marks, enclosed and circled letters, and
/// letters of a Unicode version that the tool does not know. The table is the
/// result of a probe of each alphanumeric character of the Unicode version of
/// the standard library of Rust 1.92 against the tool.
const REFUSED_ALPHANUMERIC: &[(u32, u32)] = &[
    (0x903, 0x903),
    (0x93b, 0x93b),
    (0x93e, 0x940),
    (0x949, 0x94c),
    (0x94e, 0x94f),
    (0x982, 0x983),
    (0x9be, 0x9c0),
    (0x9c7, 0x9c8),
    (0x9cb, 0x9cc),
    (0x9d7, 0x9d7),
    (0xa03, 0xa03),
    (0xa3e, 0xa40),
    (0xa83, 0xa83),
    (0xabe, 0xac0),
    (0xac9, 0xac9),
    (0xacb, 0xacc),
    (0xb02, 0xb03),
    (0xb3e, 0xb3e),
    (0xb40, 0xb40),
    (0xb47, 0xb48),
    (0xb4b, 0xb4c),
    (0xb57, 0xb57),
    (0xbbe, 0xbbf),
    (0xbc1, 0xbc2),
    (0xbc6, 0xbc8),
    (0xbca, 0xbcc),
    (0xbd7, 0xbd7),
    (0xc01, 0xc03),
    (0xc41, 0xc44),
    (0xc82, 0xc83),
    (0xcbe, 0xcbe),
    (0xcc0, 0xcc4),
    (0xcc7, 0xcc8),
    (0xcca, 0xccb),
    (0xcd5, 0xcd6),
    (0xcf3, 0xcf3),
    (0xd02, 0xd03),
    (0xd3e, 0xd40),
    (0xd46, 0xd48),
    (0xd4a, 0xd4c),
    (0xd57, 0xd57),
    (0xd82, 0xd83),
    (0xdcf, 0xdd1),
    (0xdd8, 0xddf),
    (0xdf2, 0xdf3),
    (0xf7f, 0xf7f),
    (0x102b, 0x102c),
    (0x1031, 0x1031),
    (0x1038, 0x1038),
    (0x103b, 0x103c),
    (0x1056, 0x1057),
    (0x1062, 0x1064),
    (0x1067, 0x106d),
    (0x1083, 0x1084),
    (0x1087, 0x108c),
    (0x108f, 0x108f),
    (0x109a, 0x109c),
    (0x17b6, 0x17b6),
    (0x17be, 0x17c5),
    (0x17c7, 0x17c8),
    (0x1923, 0x1926),
    (0x1929, 0x192b),
    (0x1930, 0x1931),
    (0x1933, 0x1938),
    (0x1a19, 0x1a1a),
    (0x1a55, 0x1a55),
    (0x1a57, 0x1a57),
    (0x1a61, 0x1a61),
    (0x1a63, 0x1a64),
    (0x1a6d, 0x1a72),
    (0x1b04, 0x1b04),
    (0x1b35, 0x1b35),
    (0x1b3b, 0x1b3b),
    (0x1b3d, 0x1b41),
    (0x1b43, 0x1b43),
    (0x1b82, 0x1b82),
    (0x1ba1, 0x1ba1),
    (0x1ba6, 0x1ba7),
    (0x1be7, 0x1be7),
    (0x1bea, 0x1bec),
    (0x1bee, 0x1bee),
    (0x1c24, 0x1c2b),
    (0x1c34, 0x1c35),
    (0x24b6, 0x24e9),
    (0xa823, 0xa824),
    (0xa827, 0xa827),
    (0xa880, 0xa881),
    (0xa8b4, 0xa8c3),
    (0xa952, 0xa952),
    (0xa983, 0xa983),
    (0xa9b4, 0xa9b5),
    (0xa9ba, 0xa9bb),
    (0xa9be, 0xa9bf),
    (0xaa2f, 0xaa30),
    (0xaa33, 0xaa34),
    (0xaa4d, 0xaa4d),
    (0xaa7b, 0xaa7b),
    (0xaa7d, 0xaa7d),
    (0xaaeb, 0xaaeb),
    (0xaaee, 0xaaef),
    (0xaaf5, 0xaaf5),
    (0xabe3, 0xabe4),
    (0xabe6, 0xabe7),
    (0xabe9, 0xabea),
    (0x11000, 0x11000),
    (0x11002, 0x11002),
    (0x11082, 0x11082),
    (0x110b0, 0x110b2),
    (0x110b7, 0x110b8),
    (0x1112c, 0x1112c),
    (0x11145, 0x11146),
    (0x11182, 0x11182),
    (0x111b3, 0x111b5),
    (0x111bf, 0x111bf),
    (0x111ce, 0x111ce),
    (0x1122c, 0x1122e),
    (0x11232, 0x11233),
    (0x112e0, 0x112e2),
    (0x11302, 0x11303),
    (0x1133e, 0x1133f),
    (0x11341, 0x11344),
    (0x11347, 0x11348),
    (0x1134b, 0x1134c),
    (0x11357, 0x11357),
    (0x11362, 0x11363),
    (0x113b8, 0x113ba),
    (0x113c2, 0x113c2),
    (0x113c5, 0x113c5),
    (0x113c7, 0x113ca),
    (0x113cc, 0x113cd),
    (0x11435, 0x11437),
    (0x11440, 0x11441),
    (0x11445, 0x11445),
    (0x114b0, 0x114b2),
    (0x114b9, 0x114b9),
    (0x114bb, 0x114be),
    (0x114c1, 0x114c1),
    (0x115af, 0x115b1),
    (0x115b8, 0x115bb),
    (0x115be, 0x115be),
    (0x11630, 0x11632),
    (0x1163b, 0x1163c),
    (0x1163e, 0x1163e),
    (0x116ac, 0x116ac),
    (0x116ae, 0x116af),
    (0x1171e, 0x1171e),
    (0x11720, 0x11721),
    (0x11726, 0x11726),
    (0x1182c, 0x1182e),
    (0x11838, 0x11838),
    (0x11930, 0x11935),
    (0x11937, 0x11938),
    (0x11940, 0x11940),
    (0x11942, 0x11942),
    (0x119d1, 0x119d3),
    (0x119dc, 0x119df),
    (0x119e4, 0x119e4),
    (0x11a39, 0x11a39),
    (0x11a57, 0x11a58),
    (0x11a97, 0x11a97),
    (0x11b61, 0x11b61),
    (0x11b65, 0x11b65),
    (0x11b67, 0x11b67),
    (0x11c2f, 0x11c2f),
    (0x11c3e, 0x11c3e),
    (0x11ca9, 0x11ca9),
    (0x11cb1, 0x11cb1),
    (0x11cb4, 0x11cb4),
    (0x11d8a, 0x11d8e),
    (0x11d93, 0x11d94),
    (0x11d96, 0x11d96),
    (0x11ef5, 0x11ef6),
    (0x11f03, 0x11f03),
    (0x11f34, 0x11f35),
    (0x11f3e, 0x11f3f),
    (0x1612a, 0x1612c),
    (0x16f51, 0x16f87),
    (0x16ff0, 0x16ff1),
    (0x1f130, 0x1f149),
    (0x1f150, 0x1f169),
    (0x1f170, 0x1f189),
];

/// Returns `true` if `c` is a non-ASCII character that a component of a ref
/// name can hold.
fn is_name_character(c: char) -> bool {
    c.is_alphanumeric()
        && !REFUSED_ALPHANUMERIC
            .iter()
            .any(|&(first, last)| (first..=last).contains(&u32::from(c)))
}

/// Returns `true` if `component` is one valid component of a ref name.
///
/// A component is not empty and does not start with `-` or `.`. Each of its
/// characters is an ASCII letter, an ASCII digit, `-`, `.`, `_`, or a
/// non-ASCII character for which `char::is_alphanumeric` is `true`. So `.`
/// and `..` fail, and so does a component with `/`, `:`, a space, or NUL.
///
/// The tool also accepts a nonspacing combining mark (category Mn) and a
/// connector punctuation character that is not ASCII (category Pc), and this
/// function refuses them. The tool refuses the characters that
/// `REFUSED_ALPHANUMERIC` lists, and this function refuses them too. So each
/// name that this function accepts is a name that the tool accepts.
pub fn is_ref_name_component(component: &str) -> bool {
    !component.starts_with(['-', '.'])
        && !component.is_empty()
        && component.chars().all(|c| {
            if c.is_ascii() {
                c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_')
            } else {
                is_name_character(c)
            }
        })
}

/// Returns `true` if `component` is one valid component of a part that is
/// not a ref name, such as a collection id.
///
/// A component is not empty, is not `.` or `..`, and holds no `/` and no NUL.
/// A ref name uses the stricter [`is_ref_name_component`].
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
/// `/`-separated components passes [`is_ref_name_component`]. The rule keeps
/// each name inside the `refs/` tree.
pub fn is_ref_name(name: &str) -> bool {
    !name.is_empty() && name.split('/').all(is_ref_name_component)
}

/// Returns `true` if `refspec` is a valid refspec.
///
/// A refspec is a ref name, or `REMOTE:NAME` split at the first `:`. In the
/// second form, `REMOTE` must pass [`is_ref_name_component`] and `NAME` must
/// pass [`is_ref_name`]. So `NAME` holds no `:`. Such a refspec names a path below
/// `refs/remotes/REMOTE`, so it stays inside the `refs/` tree.
pub fn is_refspec(refspec: &str) -> bool {
    match refspec.split_once(':') {
        Some((remote, name)) => is_ref_name_component(remote) && is_ref_name(name),
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

/// Returns `true` if `id` is a collection id.
///
/// A collection id has two or more elements, separated by `.`. Each element
/// starts with an ASCII letter or `_` and continues with ASCII letters,
/// digits, or `_`.
///
/// Recovered by observation: the `ostree` command writes `a.b`, `A.b`,
/// `_a.b`, `a._b`, `a_b.c`, and `a.b.c.d`. It refuses `fresh`, `a..b`,
/// `a.b.`, `1a.b`, `a.1b`, `a-b.c`, and `a.b-c` with
/// `error: Invalid collection ID <id>`. Only the file system limits the
/// length, because the id is one path component.
pub fn is_collection_id(id: &str) -> bool {
    id.split('.').count() >= 2
        && id.split('.').all(|element| {
            let mut chars = element.chars();
            chars
                .next()
                .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ref_name_holds_components_of_the_rule() {
        for name in [
            "main",
            "a/b/c",
            "x.y",
            "a.",
            "a..b",
            "a.b",
            "a/b.",
            "_a",
            "a_b",
            "a/_b",
            "a-b",
            "1a",
            "A",
            "\u{e9}",
            "a\u{e9}",
            "\u{e9}a",
            "a/\u{e9}b",
            "\u{e9}/a",
        ] {
            assert!(is_ref_name(name), "{name}");
        }
        for name in [
            "", "/", "/a", "a/", "a//b", ".", "..", "a/./b", "a/../b", "a\0b", "-dash", "a^",
            "a:b", "..x", ".a", "a/.b", "a/-b", "a/..", "a*", "*", "a/*", "a/**", "!x", "x!",
            "a/!b", "a?b", "a[b]", "a b", "a~b", "a^b", "a@b", "a+b", "a,b", "a%b", "a=b", "a#b",
            "a\\b", "a'b", "a\"b", "a$b", "a&b", "a;b", "a|b", "a<b", "a(b", "a{b", "a`b", "-a",
        ] {
            assert!(!is_ref_name(name), "{name:?}");
        }
    }

    #[test]
    fn a_refspec_splits_at_the_first_colon() {
        for spec in [
            "main",
            "a/b",
            "origin:main",
            "origin:a/b",
            "o.:main",
            "_o:main",
            "o-:main",
            "\u{e9}:main",
        ] {
            assert!(is_refspec(spec), "{spec}");
        }
        for spec in [
            "",
            ":",
            ":main",
            "origin:",
            "a/b:main",
            "..:main",
            ".:main",
            "o:..",
            "o:a/../b",
            "o\0:main",
            "o:a:b",
            "o:a b",
            "o:-a",
            "o r:main",
            "o*:main",
            "-o:main",
            ".o:main",
            "o~:main",
            "o^:main",
            "o@:main",
            "o\u{a0}:main",
        ] {
            assert!(!is_refspec(spec), "{spec:?}");
        }
    }

    #[test]
    fn a_ref_name_component_follows_the_character_rule() {
        for c in ["a", "a.b", "a.", "_a", "1a", "\u{e9}", "a\u{e9}"] {
            assert!(is_ref_name_component(c), "{c:?}");
        }
        for c in ["", ".", "..", ".a", "-a", "a/b", "a:b", "a b", "a*", "a\0"] {
            assert!(!is_ref_name_component(c), "{c:?}");
        }
    }

    /// Each character is one that the `ostree` tool accepts or refuses in a
    /// ref name, by a probe of the tool.
    #[test]
    fn a_non_ascii_character_is_valid_if_it_is_alphanumeric() {
        for c in [
            '\u{e9}', '\u{b5}', '\u{2d0}', '\u{4e2d}', '\u{b2}', '\u{2160}', '\u{660}', '\u{aa}',
            '\u{ba}', '\u{bc}',
        ] {
            assert!(is_ref_name_component(&format!("a{c}b")), "{c:?}");
            assert!(is_ref_name_component(&c.to_string()), "{c:?}");
        }
        for c in [
            '\u{80}',
            '\u{85}',
            '\u{a0}',
            '\u{ad}',
            '\u{d7}',
            '\u{2013}',
            '\u{200b}',
            '\u{20ac}',
            '\u{feff}',
            '\u{e000}',
            '\u{1f600}',
            '\u{fffd}',
            '\u{2028}',
            '\u{3000}',
            '\u{ffff}',
            '\u{10ffff}',
        ] {
            assert!(!is_ref_name_component(&format!("a{c}b")), "{c:?}");
            assert!(!is_ref_name_component(&c.to_string()), "{c:?}");
        }
    }

    /// The tool accepts these characters. The port refuses them, so it never
    /// writes a name that the tool might skip.
    #[test]
    fn a_non_ascii_character_that_the_tool_accepts_but_is_not_alphanumeric_is_refused() {
        for c in ['\u{301}', '\u{203f}', '\u{ff3f}'] {
            assert!(!is_ref_name_component(&format!("a{c}b")), "{c:?}");
        }
    }

    /// The tool refuses these alphanumeric characters: spacing combining
    /// marks, circled letters, and enclosed letters.
    #[test]
    fn an_alphanumeric_character_that_the_tool_refuses_is_refused() {
        for c in ['\u{903}', '\u{93e}', '\u{24b6}', '\u{1f130}', '\u{1f170}'] {
            assert!(c.is_alphanumeric(), "{c:?}");
            assert!(!is_ref_name_component(&format!("a{c}b")), "{c:?}");
        }
        for pair in REFUSED_ALPHANUMERIC.windows(2) {
            assert!(pair[0].1 < pair[1].0, "{pair:?}");
        }
    }

    #[test]
    fn a_component_holds_no_slash_and_no_nul() {
        assert!(is_ref_component("a.b"));
        assert!(is_ref_component("a:b"));
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

    /// The ids that the `ostree` command writes are collection ids, and the
    /// ids that it refuses are not.
    #[test]
    fn a_collection_id_has_two_or_more_elements_of_the_rule() {
        for id in ["a.b", "A.b", "_a.b", "a._b", "a_b.c", "a.b.c.d"] {
            assert!(is_collection_id(id), "{id}");
        }
        for id in [
            "fresh", "a..b", "a.b.", "1a.b", "a.1b", "a-b.c", "a.b-c", "", ".", ".a.b", "a.b c",
            "a.\u{e9}",
        ] {
            assert!(!is_collection_id(id), "{id:?}");
        }
    }
}
