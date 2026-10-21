//! The keys of a bucket repository, and their encoding in a request.

use ostrya_core::{Checksum, is_ref_name};

use super::sigv4::uri_encode;
use crate::{Error, Result};

/// The keys of a bucket repository that hold one file each.
const SINGLE_KEYS: [&str; 4] = ["config", "summary", "summary.sig", "extensions/ostrya/lock"];

/// The extensions of an object key. A bucket repository is in `archive`
/// form, so a file object is `filez`.
const OBJECT_EXTENSIONS: [&str; 7] = [
    "commit",
    "commitmeta",
    "dirtree",
    "dirmeta",
    "filez",
    "tombstone-commit",
    "cfs",
];

/// Returns `true` if `key`, relative to the prefix of the repository, is a
/// key of a bucket repository.
///
/// The keys are:
///
/// - `config`, `summary`, `summary.sig`, and `extensions/ostrya/lock`
/// - `objects/XX/<62 hex digits>.<ext>`, with lowercase hex digits and an
///   extension of [`OBJECT_EXTENSIONS`]
/// - `refs/heads/<name>`, with a name that [`is_ref_name`] accepts
/// - `deltas/<2>/<41>/<target>` and `deltas/<2>/<41>-<43>/<target>`, with
///   checksums in modified base64, and the target `superblock` or a part
///   number with no leading zero
/// - `delta-indexes/<2>/<41>.index`, with a checksum in modified base64.
pub(crate) fn is_repository_key(key: &str) -> bool {
    if SINGLE_KEYS.contains(&key) {
        return true;
    }
    if let Some(rest) = key.strip_prefix("objects/") {
        return is_object_key(rest);
    }
    if let Some(name) = key.strip_prefix("refs/heads/") {
        return is_ref_name(name);
    }
    if let Some(rest) = key.strip_prefix("deltas/") {
        return is_delta_key(rest);
    }
    if let Some(rest) = key.strip_prefix("delta-indexes/") {
        return is_delta_index_key(rest);
    }
    false
}

/// Refuses `key` if it is not a key of a bucket repository.
pub(crate) fn check_key(key: &str) -> Result<()> {
    if is_repository_key(key) {
        Ok(())
    } else {
        Err(Error::InvalidInput(format!(
            "S3 key: {key:?} is not a key of a bucket repository"
        )))
    }
}

/// Refuses `prefix` if it is not the prefix of a list in a bucket
/// repository.
///
/// A list prefix is relative to the prefix of the repository and ends in
/// `/`, so a list never reaches the keys of a sibling prefix. Each segment
/// is not empty and is not `.` or `..`. It holds ASCII letters, digits, `-`,
/// `.`, `_`, `~`, `+`, and the non-ASCII letters and digits of a ref name.
pub(crate) fn check_list_prefix(prefix: &str) -> Result<()> {
    let refused = |why: &str| {
        Err(Error::InvalidInput(format!(
            "S3 list prefix: {prefix:?} {why}"
        )))
    };
    let Some(segments) = prefix.strip_suffix('/') else {
        return refused("does not end in '/'");
    };
    for segment in segments.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return refused("holds an empty segment, '.', or '..'");
        }
        let allowed = |c: char| {
            if c.is_ascii() {
                c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~' | '+')
            } else {
                c.is_alphanumeric()
            }
        };
        if !segment.chars().all(allowed) {
            return refused("holds a character outside the alphabet of a key");
        }
    }
    Ok(())
}

/// Returns `key` as a request path: each byte other than `A-Z`, `a-z`,
/// `0-9`, `-`, `.`, `_`, `~`, and `/` as `%XX` in uppercase.
///
/// This is the canonical URI of SigV4, so the signature of a key does not
/// depend on how a server reads a raw `+` of a path.
pub(crate) fn encode_path(key: &str) -> String {
    let mut path = String::with_capacity(key.len());
    uri_encode(key.as_bytes(), false, &mut path);
    path
}

/// Returns `value` as a part of a query: each byte other than `A-Z`, `a-z`,
/// `0-9`, `-`, `.`, `_`, and `~` as `%XX` in uppercase. A `/` and a `+` are
/// encoded.
pub(crate) fn encode_query(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    uri_encode(value.as_bytes(), true, &mut encoded);
    encoded
}

/// Returns a key or a prefix of a listing as text.
///
/// With `encoded` set, the listing has the encoding type `url`. Each `%XX`
/// is then the byte that it names, and each `+` is a space, as S3 writes a
/// space in that encoding. A text whose decoded bytes are not UTF-8, or
/// that holds a malformed escape, stays as it is. Such a text is never a key
/// of a bucket repository.
pub(crate) fn decode_listed(text: &str, encoded: bool) -> String {
    if !encoded {
        return text.to_owned();
    }
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'+' => {
                decoded.push(b' ');
                at += 1;
            }
            b'%' => {
                let Some(byte) = bytes
                    .get(at + 1..at + 3)
                    .and_then(|hex| std::str::from_utf8(hex).ok())
                    .filter(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()))
                    .and_then(|hex| u8::from_str_radix(hex, 16).ok())
                else {
                    return text.to_owned();
                };
                decoded.push(byte);
                at += 3;
            }
            byte => {
                decoded.push(byte);
                at += 1;
            }
        }
    }
    String::from_utf8(decoded).unwrap_or_else(|_| text.to_owned())
}

/// Returns `true` if `text` is `len` lowercase hex digits.
fn is_lower_hex(text: &str, len: usize) -> bool {
    text.len() == len
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Returns `true` if `rest` is `XX/<62 hex digits>.<ext>`.
fn is_object_key(rest: &str) -> bool {
    let Some((fan, name)) = rest.split_once('/') else {
        return false;
    };
    let Some((hex, ext)) = name.split_once('.') else {
        return false;
    };
    is_lower_hex(fan, 2) && is_lower_hex(hex, 62) && OBJECT_EXTENSIONS.contains(&ext)
}

/// Returns `true` if `head` and `tail` join to a checksum in modified
/// base64.
fn is_split_checksum(head: &str, tail: &str) -> bool {
    head.len() == 2 && Checksum::from_base64_modified(&format!("{head}{tail}")).is_ok()
}

/// Returns `true` if `rest` is the path of a delta file under `deltas/`.
fn is_delta_key(rest: &str) -> bool {
    let mut parts = rest.split('/');
    let (Some(head), Some(tail), Some(target), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let names_delta = match tail.split_once('-') {
        // A modified base64 checksum holds no `-`, so the first `-` splits
        // the source from the target.
        Some((from, to)) => {
            is_split_checksum(head, from) && Checksum::from_base64_modified(to).is_ok()
        }
        None => is_split_checksum(head, tail),
    };
    names_delta && is_delta_target(target)
}

/// Returns `true` if `target` is `superblock` or a part number with no
/// leading zero.
fn is_delta_target(target: &str) -> bool {
    target == "superblock"
        || (!target.is_empty()
            && target.len() <= 10
            && target.bytes().all(|b| b.is_ascii_digit())
            && (target == "0" || !target.starts_with('0')))
}

/// Returns `true` if `rest` is the path of a delta index under
/// `delta-indexes/`.
fn is_delta_index_key(rest: &str) -> bool {
    let Some((head, file)) = rest.split_once('/') else {
        return false;
    };
    let Some(tail) = file.strip_suffix(".index") else {
        return false;
    };
    !tail.contains('/') && is_split_checksum(head, tail)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A checksum whose modified base64 holds `+` and `_`.
    fn checksum_b64() -> String {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xfb;
        bytes[1] = 0xff;
        bytes[2] = 0xbf;
        let b64 = Checksum::from_bytes(bytes).to_base64_modified();
        assert!(b64.contains('+') && b64.contains('_'), "{b64}");
        b64
    }

    fn other_b64() -> String {
        Checksum::from_bytes([7u8; 32]).to_base64_modified()
    }

    #[test]
    fn each_kind_of_repository_key_passes() {
        let hex = "0123456789abcdef".repeat(4);
        let to = checksum_b64();
        let from = other_b64();
        let mut keys = vec![
            "config".to_owned(),
            "summary".to_owned(),
            "summary.sig".to_owned(),
            "extensions/ostrya/lock".to_owned(),
            "refs/heads/main".to_owned(),
            "refs/heads/exampleos/x86_64/stable".to_owned(),
            "refs/heads/a-b.c_d9".to_owned(),
            "refs/heads/grün".to_owned(),
            format!("deltas/{}/{}/superblock", &to[..2], &to[2..]),
            format!("deltas/{}/{}/0", &to[..2], &to[2..]),
            format!("deltas/{}/{}/12", &to[..2], &to[2..]),
            format!("deltas/{}/{}-{to}/superblock", &from[..2], &from[2..]),
            format!("delta-indexes/{}/{}.index", &to[..2], &to[2..]),
        ];
        for ext in OBJECT_EXTENSIONS {
            keys.push(format!("objects/{}/{}.{ext}", &hex[..2], &hex[2..]));
        }
        for key in keys {
            assert!(is_repository_key(&key), "{key}");
            check_key(&key).unwrap();
        }
    }

    #[test]
    fn a_key_out_of_the_rules_is_refused() {
        let hex = "0123456789abcdef".repeat(4);
        let to = checksum_b64();
        let keys = [
            String::new(),
            "/config".to_owned(),
            "../config".to_owned(),
            "config/".to_owned(),
            "summary.sig.tmp".to_owned(),
            "extensions/ostrya/other".to_owned(),
            format!("objects/{}/{}.commit", &hex[..2], &hex[2..63]),
            format!("objects/AB/{}.commit", &hex[2..]),
            format!("objects/ab/{}.commit", hex[2..].to_uppercase()),
            format!("objects/{}/{}.COMMIT", &hex[..2], &hex[2..]),
            format!("objects/{}/{}.file", &hex[..2], &hex[2..]),
            format!("objects/{}/{}.unknown", &hex[..2], &hex[2..]),
            format!("objects/zz/{}.commit", &hex[2..]),
            "objects/ab/..".to_owned(),
            "objects/abc".to_owned(),
            "refs/heads/-x".to_owned(),
            "refs/heads/".to_owned(),
            "refs/heads/a//b".to_owned(),
            "refs/heads/a b".to_owned(),
            "refs/mirrors/x".to_owned(),
            "refs/remotes/origin/main".to_owned(),
            format!("deltas/{}/{}/01", &to[..2], &to[2..]),
            format!("deltas/{}/{}/meta", &to[..2], &to[2..]),
            format!("deltas/{}/{}/", &to[..2], &to[2..]),
            format!("deltas/{}/{}x/superblock", &to[..2], &to[2..]),
            format!("deltas/{}/{}/superblock/x", &to[..2], &to[2..]),
            format!("deltas/{}/{}/superblock", &to[..3], &to[3..]),
            "deltas/AA/!!!/superblock".to_owned(),
            format!("delta-indexes/{}/{}.idx", &to[..2], &to[2..]),
        ];
        for key in keys {
            assert!(!is_repository_key(&key), "{key}");
            let err = check_key(&key).unwrap_err();
            assert!(matches!(err, Error::InvalidInput(_)), "{err}");
        }
    }

    #[test]
    fn a_list_prefix_ends_in_a_slash() {
        for prefix in [
            "objects/",
            "objects/ab/",
            "refs/heads/",
            "deltas/",
            "refs/heads/grün/",
        ] {
            check_list_prefix(prefix).unwrap();
        }
        for prefix in [
            "",
            "/",
            "objects",
            "objects//",
            "./",
            "../",
            "a/../",
            "a b/",
            "a%2F/",
        ] {
            assert!(check_list_prefix(prefix).is_err(), "{prefix}");
        }
    }

    #[test]
    fn a_path_encodes_each_byte_outside_the_unreserved_set() {
        assert_eq!(encode_path("repo/config"), "repo/config");
        assert_eq!(encode_path("deltas/a+/b_c~d"), "deltas/a%2B/b_c~d");
        assert_eq!(encode_path("refs/heads/grün"), "refs/heads/gr%C3%BCn");
        assert_eq!(encode_path("a b%"), "a%20b%25");
    }

    #[test]
    fn a_query_value_encodes_slash_and_plus() {
        assert_eq!(encode_query("repo/objects/"), "repo%2Fobjects%2F");
        assert_eq!(encode_query("a+b=c/d"), "a%2Bb%3Dc%2Fd");
        assert_eq!(encode_query("1ueGcx~_-."), "1ueGcx~_-.");
    }

    #[test]
    fn a_listed_key_decodes_as_s3_encodes_it() {
        assert_eq!(decode_listed("enc/a%2Bb", true), "enc/a+b");
        assert_eq!(decode_listed("enc/sp+ace", true), "enc/sp ace");
        assert_eq!(decode_listed("enc/%C3%BC", true), "enc/ü");
        assert_eq!(decode_listed("enc/pct%2541", true), "enc/pct%41");
        assert_eq!(decode_listed("enc/a+b", false), "enc/a+b");
        // A malformed escape and bytes that are not UTF-8 keep the text.
        assert_eq!(decode_listed("enc/%G1", true), "enc/%G1");
        assert_eq!(decode_listed("enc/%E9", true), "enc/%E9");
        assert_eq!(decode_listed("enc/%4", true), "enc/%4");
    }
}
