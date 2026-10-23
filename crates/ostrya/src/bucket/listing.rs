//! The listing of the objects of a bucket repository.

use std::collections::HashMap;

use ostrya_core::{Checksum, ObjectName, ObjectType};

use super::BucketRepo;
use crate::error::Result;
use crate::pull::drive::Slots;
use crate::remote::s3::Listed;

/// The number of fan-out prefixes `objects/XX/`.
const FANOUT: usize = 256;

/// The objects of a bucket repository, from the lists of the 256 fan-out
/// prefixes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ObjectListing {
    /// Each object, with its size in bytes from the listing.
    pub objects: HashMap<ObjectName, u64>,
    /// Each stray key under a fan-out prefix, with its size, sorted by key.
    ///
    /// A stray key is a key whose name is not `XX/<62 hex digits>.<ext>`, in
    /// lowercase hex, with `<ext>` one of `commit`, `commitmeta`, `dirtree`,
    /// `dirmeta`, `filez`, `tombstone-commit`, and `cfs`.
    pub strays: Vec<Listed>,
}

impl BucketRepo {
    /// Lists the objects of the repository, as [`BucketRepo::list_objects`]
    /// states.
    pub(super) async fn list_fanouts(&self) -> Result<ObjectListing> {
        let mut lists = Slots::new(self.max_outstanding);
        let mut fanouts = 0..FANOUT;
        let mut listing = ObjectListing::default();
        loop {
            while lists.has_room()
                && let Some(fanout) = fanouts.next()
            {
                let bucket = &self.bucket;
                let prefix = format!("objects/{fanout:02x}/");
                lists.push(async move { bucket.list(&prefix).await });
            }
            let Some(list) = lists.next_ready().await else {
                break;
            };
            for listed in list?.objects {
                match object_name(&listed.key) {
                    Some(name) => {
                        listing.objects.insert(name, listed.size);
                    }
                    None => listing.strays.push(listed),
                }
            }
        }
        listing.strays.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(listing)
    }
}

/// Returns the object that the key `key` names, or `None` for a stray key.
///
/// The key is `objects/XX/<62 hex digits>.<ext>`, in lowercase hex.
fn object_name(key: &str) -> Option<ObjectName> {
    let rest = key.strip_prefix("objects/")?;
    let (fanout, name) = rest.split_once('/')?;
    let (digits, ext) = name.split_once('.')?;
    let ty = match ext {
        "commit" => ObjectType::Commit,
        "commitmeta" => ObjectType::CommitMeta,
        "dirtree" => ObjectType::DirTree,
        "dirmeta" => ObjectType::DirMeta,
        "filez" => ObjectType::File,
        "tombstone-commit" => ObjectType::TombstoneCommit,
        "cfs" => ObjectType::ComposefsImage,
        _ => return None,
    };
    if fanout.len() != 2 || digits.len() != 62 {
        return None;
    }
    let mut hex = fanout.bytes().chain(digits.bytes());
    let mut checksum = [0u8; 32];
    for byte in &mut checksum {
        *byte = (lower_hex(hex.next()?)? << 4) | lower_hex(hex.next()?)?;
    }
    Some(ObjectName::new(Checksum::from_bytes(checksum), ty))
}

/// Returns `true` if `prefix` is a fan-out prefix `objects/XX/`, with two
/// lowercase hex digits.
pub(super) fn is_fanout_prefix(prefix: &str) -> bool {
    prefix
        .strip_prefix("objects/")
        .and_then(|rest| rest.strip_suffix('/'))
        .is_some_and(|fanout| fanout.len() == 2 && fanout.bytes().all(|b| lower_hex(b).is_some()))
}

/// Returns the value of the lowercase hex digit `digit`.
fn lower_hex(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_object_extension_names_its_type() {
        let digits = "cd".repeat(31);
        let hex = format!("ab{digits}");
        for (ext, ty) in [
            ("commit", ObjectType::Commit),
            ("commitmeta", ObjectType::CommitMeta),
            ("dirtree", ObjectType::DirTree),
            ("dirmeta", ObjectType::DirMeta),
            ("filez", ObjectType::File),
            ("tombstone-commit", ObjectType::TombstoneCommit),
            ("cfs", ObjectType::ComposefsImage),
        ] {
            let name = object_name(&format!("objects/ab/{digits}.{ext}"));
            assert_eq!(
                name,
                Some(ObjectName::new(Checksum::from_hex(&hex).unwrap(), ty)),
                "{ext}"
            );
        }
    }

    #[test]
    fn a_fanout_prefix_is_two_lowercase_hex_digits() {
        assert!(is_fanout_prefix("objects/ab/"));
        assert!(is_fanout_prefix("objects/09/"));
        for prefix in [
            "objects/AB/",
            "objects/zz/",
            "objects/abc/",
            "objects/a/",
            "objects/ab",
            "objects//",
            "refs/ab/",
        ] {
            assert!(!is_fanout_prefix(prefix), "{prefix}");
        }
    }

    #[test]
    fn a_key_out_of_the_object_rule_is_a_stray() {
        let digits = "cd".repeat(31);
        for key in [
            format!("objects/ab/{digits}.file"),
            format!("objects/ab/{digits}.payload-link"),
            format!("objects/ab/{}.commit", "CD".repeat(31)),
            format!("objects/AB/{digits}.commit"),
            format!("objects/ab/{}.commit", &digits[..61]),
            format!("objects/ab/{digits}c.commit"),
            format!("objects/ab/{digits}"),
            format!("objects/abc/{}.commit", &digits[..61]),
            "objects/ab/x/y".to_owned(),
            "objects/ab/zz".to_owned(),
            format!("refs/ab/{digits}.commit"),
        ] {
            assert_eq!(object_name(&key), None, "{key}");
        }
    }
}
