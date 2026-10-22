//! The state of a bucket repository that a writer reads: the `config`, the
//! refs, and the presence of a summary signature.

use std::collections::BTreeMap;

use ostrya_core::{Checksum, RepoMode, is_collection_id, is_ref_name};

use super::BucketRepo;
use crate::config::RepoConfig;
use crate::error::{Error, Result};
use crate::pull::drive::Slots;
use crate::refs::MAX_COLLECTION_ID_LEN;
use crate::repo::MAX_CONFIG_SIZE;
use crate::summary::SUMMARY_READ_CAP;

/// The size of a ref file: 64 hex digits and a newline.
const REF_FILE_SIZE: u64 = 65;

/// The refs of a bucket repository.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct BucketRefs {
    /// The refs `refs/heads/NAME`, by name.
    pub(crate) heads: BTreeMap<String, Checksum>,
    /// The refs `refs/mirrors/ID/NAME`, by collection id, then by name.
    pub(crate) mirrors: BTreeMap<String, BTreeMap<String, Checksum>>,
}

/// One ref key of a bucket repository.
enum RefKey<'a> {
    /// `refs/heads/NAME`.
    Head(&'a str),
    /// `refs/mirrors/ID/NAME`.
    Mirror(&'a str, &'a str),
}

impl BucketRepo {
    /// Reads the `config` of the repository, or returns `None` if the key
    /// holds no object.
    ///
    /// The config must state the mode `archive-z2` or `archive`, and a
    /// `[core] collection-id` must pass the collection id rule and be at most
    /// 255 bytes. `[core] tombstone-commits` and `[core] indexed-deltas`, which
    /// the summary takes, must be booleans if they are set. `[archive]
    /// zlib-level`, which a push takes, must be an integer if it is set.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if the config is larger than 1 MiB, is not
    ///   UTF-8, does not parse, or breaks a rule above.
    /// - [`Error::Remote`] for an error of the bucket client.
    #[cfg_attr(not(feature = "push"), allow(dead_code))]
    pub(crate) async fn read_config(&self) -> Result<Option<RepoConfig>> {
        let object = match self.bucket.get("config", MAX_CONFIG_SIZE).await {
            Ok(Some(object)) => object,
            Ok(None) => return Ok(None),
            Err(crate::remote::Error::LimitExceeded(_)) => {
                return Err(
                    self.malformed(format!("its config is larger than {MAX_CONFIG_SIZE} bytes"))
                );
            }
            Err(e) => return Err(e.into()),
        };
        let text = String::from_utf8(object.bytes)
            .map_err(|_| self.malformed("its config is not UTF-8".to_owned()))?;
        let config = RepoConfig::parse(&text)
            .map_err(|e| self.malformed(format!("its config does not parse: {e}")))?;
        if config.mode() != RepoMode::Archive {
            return Err(self.malformed(format!(
                "its config states the mode '{}', and a bucket repository is in archive form",
                config.mode().as_mode_str()
            )));
        }
        if let Some(id) = config.collection_id()
            && !is_namespace_id(id)
        {
            return Err(self.malformed(format!(
                "its config states the collection id '{}', which the collection id rule refuses",
                id.escape_debug()
            )));
        }
        for checked in [config.tombstone_commits(), config.indexed_deltas()] {
            checked.map_err(|e| {
                self.malformed(format!("its config has a key that is no boolean: {e}"))
            })?;
        }
        config.zlib_level().map_err(|e| {
            self.malformed(format!(
                "its config has a zlib-level that is no integer: {e}"
            ))
        })?;
        Ok(Some(config))
    }

    /// Reads the refs of the repository: one list of `refs/`, then a read of
    /// each ref file.
    ///
    /// Each key under `refs/` is `refs/heads/NAME`, or `refs/mirrors/ID/NAME`
    /// with an `ID` other than `own`, the collection id of the repository.
    /// `NAME` passes the ref name rule, and `ID` passes the collection id
    /// rule and is at most 255 bytes. A ref file holds 64 lowercase hex
    /// digits and a newline. At most `max_outstanding` reads run at a time.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if a key under `refs/` breaks a rule above,
    ///   if a ref file is malformed, or if a listed ref file is gone at its
    ///   read. The refs of `refs/mirrors/` of the own collection id are a
    ///   malformed state: the repository holds the refs of its own
    ///   collection under `refs/heads/`.
    /// - [`Error::Remote`] for an error of the bucket client.
    // A push reads the ref directory of its namespace alone. The read of all
    // refs stays for an explicit summary update, which lists each ref.
    #[allow(dead_code)]
    pub(crate) async fn read_refs(&self, own: Option<&str>) -> Result<BucketRefs> {
        let listing = self.bucket.list("refs/").await?;
        let mut keys = Vec::with_capacity(listing.objects.len());
        for listed in &listing.objects {
            let key = listed.key.as_str();
            match ref_key(key) {
                Some(RefKey::Mirror(id, _)) if Some(id) == own => {
                    return Err(self.own_mirror_ref(key));
                }
                Some(_) => keys.push(key),
                None => {
                    return Err(self.malformed(format!(
                        "it holds the key '{}' under refs/, which is no ref of refs/heads/ or of \
                         refs/mirrors/ID/",
                        key.escape_debug()
                    )));
                }
            }
        }
        let mut refs = BucketRefs::default();
        for (key, commit) in self.read_ref_files(keys).await? {
            match ref_key(key) {
                Some(RefKey::Head(name)) => {
                    refs.heads.insert(name.to_owned(), commit);
                }
                Some(RefKey::Mirror(id, name)) => {
                    refs.mirrors
                        .entry(id.to_owned())
                        .or_default()
                        .insert(name.to_owned(), commit);
                }
                None => unreachable!("each key passed the rule"),
            }
        }
        Ok(refs)
    }

    /// Reads the refs of the ref directory `dir`, `refs/heads/` or
    /// `refs/mirrors/ID/`: one list of `dir`, then a read of each ref file.
    /// The call reads no key outside `dir`.
    ///
    /// The part of each key after `dir` passes the ref name rule. A ref file
    /// holds 64 lowercase hex digits and a newline. At most
    /// `max_outstanding` reads run at a time.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if a key under `dir` is no ref name, if a
    ///   ref file is malformed, or if a listed ref file is gone at its read.
    /// - [`Error::Remote`] for an error of the bucket client.
    #[cfg_attr(not(feature = "push"), allow(dead_code))]
    pub(crate) async fn read_ref_dir(&self, dir: &str) -> Result<BTreeMap<String, Checksum>> {
        let listing = self.bucket.list(dir).await?;
        let mut keys = Vec::with_capacity(listing.objects.len());
        for listed in &listing.objects {
            let key = listed.key.as_str();
            match key.strip_prefix(dir) {
                Some(name) if is_ref_name(name) => keys.push(key),
                _ => {
                    return Err(self.malformed(format!(
                        "it holds the key '{}' under {dir}, which is no ref of {dir}",
                        key.escape_debug()
                    )));
                }
            }
        }
        Ok(self
            .read_ref_files(keys)
            .await?
            .into_iter()
            .map(|(key, commit)| (key[dir.len()..].to_owned(), commit))
            .collect())
    }

    /// Refuses a repository that holds a key under `refs/mirrors/` of its
    /// own collection id `own`. The call lists that directory alone.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if the repository holds such a key: the
    ///   repository holds the refs of its own collection under
    ///   `refs/heads/`.
    /// - [`Error::Remote`] for an error of the bucket client.
    #[cfg_attr(not(feature = "push"), allow(dead_code))]
    pub(crate) async fn refuse_own_mirror_refs(&self, own: &str) -> Result<()> {
        let listing = self.bucket.list(&format!("refs/mirrors/{own}/")).await?;
        match listing.objects.first() {
            Some(listed) => Err(self.own_mirror_ref(&listed.key)),
            None => Ok(()),
        }
    }

    /// Returns the error of the ref key `key` under `refs/mirrors/` of the
    /// own collection id.
    fn own_mirror_ref(&self, key: &str) -> Error {
        self.malformed(format!(
            "it holds the ref key '{}' under refs/mirrors/ of its own collection id; a bucket \
             repository holds the refs of its own collection under refs/heads/",
            key.escape_debug()
        ))
    }

    /// Reads the ref file of each key of `keys`, at most `max_outstanding`
    /// reads at a time, and returns each key with its commit.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if a ref file is malformed, or if a ref
    ///   file is gone at its read.
    /// - [`Error::Remote`] for an error of the bucket client.
    async fn read_ref_files<'k>(&self, keys: Vec<&'k str>) -> Result<Vec<(&'k str, Checksum)>> {
        let mut out = Vec::with_capacity(keys.len());
        let mut reads = Slots::new(self.max_outstanding);
        let mut pending = keys.into_iter();
        loop {
            while reads.has_room()
                && let Some(key) = pending.next()
            {
                let bucket = &self.bucket;
                reads.push(async move { (key, bucket.get(key, REF_FILE_SIZE).await) });
            }
            let Some((key, read)) = reads.next_ready().await else {
                break;
            };
            let bytes = match read {
                Ok(Some(object)) => object.bytes,
                Ok(None) => {
                    return Err(self.malformed(format!(
                        "the ref file '{}' was in the listing and is gone",
                        key.escape_debug()
                    )));
                }
                Err(crate::remote::Error::LimitExceeded(_)) => {
                    return Err(self.malformed(format!(
                        "the ref file '{}' is larger than {REF_FILE_SIZE} bytes",
                        key.escape_debug()
                    )));
                }
                Err(e) => return Err(e.into()),
            };
            let commit = parse_ref_file(&bytes).ok_or_else(|| {
                self.malformed(format!(
                    "the ref file '{}' does not hold 64 lowercase hex digits and a newline",
                    key.escape_debug()
                ))
            })?;
            out.push((key, commit));
        }
        Ok(out)
    }

    /// Returns `true` if the key `summary.sig` holds an object.
    ///
    /// The call reads the object to its end, so the connection stays open
    /// for the next request. An object larger than [`SUMMARY_READ_CAP`] is
    /// present, and the call reads no more of it.
    ///
    /// # Errors
    ///
    /// [`Error::Remote`] for an error of the bucket client.
    // No writer of this version writes the summary of a bucket repository,
    // so no writer reads the presence of its signature.
    #[allow(dead_code)]
    pub(crate) async fn is_signed(&self) -> Result<bool> {
        match self.bucket.get("summary.sig", SUMMARY_READ_CAP).await {
            Ok(object) => Ok(object.is_some()),
            Err(crate::remote::Error::LimitExceeded(_)) => Ok(true),
            Err(e) => Err(e.into()),
        }
    }

    /// Returns the error of a bucket repository whose content breaks a rule.
    /// `what` starts with the subject of the rule, for example "its config".
    pub(crate) fn malformed(&self, what: String) -> Error {
        Error::InvalidFormat(format!("the bucket repository {}: {what}", self.address()))
    }
}

/// Returns `true` if `id` can name a namespace of a bucket repository: it
/// passes the collection id rule and is at most 255 bytes.
pub(crate) fn is_namespace_id(id: &str) -> bool {
    id.len() <= MAX_COLLECTION_ID_LEN && is_collection_id(id)
}

/// Returns the ref that the key `key` names, or `None` for a key that is no
/// ref key.
fn ref_key(key: &str) -> Option<RefKey<'_>> {
    if let Some(name) = key.strip_prefix("refs/heads/") {
        return is_ref_name(name).then_some(RefKey::Head(name));
    }
    let (id, name) = key.strip_prefix("refs/mirrors/")?.split_once('/')?;
    (is_namespace_id(id) && is_ref_name(name)).then_some(RefKey::Mirror(id, name))
}

/// Returns the commit of the ref file `bytes`: 64 lowercase hex digits and a
/// newline.
fn parse_ref_file(bytes: &[u8]) -> Option<Checksum> {
    let hex = bytes.strip_suffix(b"\n")?;
    if hex.len() != 64 || !hex.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    Checksum::from_hex(std::str::from_utf8(hex).ok()?).ok()
}

/// Returns the two ref inputs of the summary of `refs`: the refs of field 0,
/// and the refs of `ostree.summary.collection-map` by collection id.
///
/// Field 0 holds the refs of `refs/heads/`. The map holds each collection of
/// `refs/mirrors/` with a ref. Each list is sorted byte-wise by name. A
/// writer refuses a bucket repository with `refs/mirrors/` of its own
/// collection id, so the two inputs are the inputs of the root summary of a
/// local repository with the same refs and the same `[core] collection-id`.
#[cfg_attr(not(feature = "push"), allow(dead_code))]
#[allow(clippy::type_complexity)]
pub(crate) fn summary_refs(
    refs: &BucketRefs,
) -> (
    Vec<(String, Checksum)>,
    BTreeMap<String, Vec<(String, Checksum)>>,
) {
    let list = |dir: &BTreeMap<String, Checksum>| -> Vec<(String, Checksum)> {
        dir.iter()
            .map(|(name, commit)| (name.clone(), *commit))
            .collect()
    };
    let collections = refs
        .mirrors
        .iter()
        .filter(|(_, dir)| !dir.is_empty())
        .map(|(id, dir)| (id.clone(), list(dir)))
        .collect();
    (list(&refs.heads), collections)
}

/// Refuses a ref directory in which one name is a directory prefix of
/// another name, as `a` and `a/b` are.
///
/// One pass looks up, for each name, each part of the name before a `/` as
/// a name of the directory.
#[cfg_attr(not(feature = "push"), allow(dead_code))]
pub(crate) fn check_prefixes(dir: &BTreeMap<String, Checksum>) -> Result<()> {
    for name in dir.keys() {
        for (at, _) in name.match_indices('/') {
            let directory = &name[..at];
            if dir.contains_key(directory) {
                return Err(super::invalid(format!(
                    "the ref '{directory}' is a directory of the ref '{name}', and one directory \
                     of refs cannot hold both"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn csum(byte: u8) -> Checksum {
        Checksum::from_bytes([byte; 32])
    }

    fn dir(names: &[&str]) -> BTreeMap<String, Checksum> {
        names
            .iter()
            .map(|name| ((*name).to_owned(), csum(1)))
            .collect()
    }

    #[test]
    fn a_ref_file_is_64_lowercase_hex_digits_and_a_newline() {
        let hex = "ab".repeat(32);
        assert_eq!(
            parse_ref_file(format!("{hex}\n").as_bytes()),
            Some(Checksum::from_hex(&hex).unwrap())
        );
        for body in [
            hex.clone(),
            format!("{}\n", hex.to_uppercase()),
            format!("{}\n", &hex[..63]),
            format!("{hex}\n\n"),
            format!("{hex} \n"),
            String::new(),
        ] {
            assert_eq!(parse_ref_file(body.as_bytes()), None, "{body:?}");
        }
    }

    #[test]
    fn a_ref_key_is_a_head_or_a_mirror_ref() {
        assert!(matches!(
            ref_key("refs/heads/a/b"),
            Some(RefKey::Head("a/b"))
        ));
        assert!(matches!(
            ref_key("refs/mirrors/org.example.Os/main"),
            Some(RefKey::Mirror("org.example.Os", "main"))
        ));
        for key in [
            "refs/remotes/origin/main",
            "refs/heads/-x",
            "refs/heads/",
            "refs/mirrors/nodot/main",
            "refs/mirrors/org.example.Os/",
            "refs/mirrors/org.example.Os",
            "refs/other",
        ] {
            assert!(ref_key(key).is_none(), "{key}");
        }
        let long = format!("refs/mirrors/org.{}/x", "a".repeat(252));
        assert!(ref_key(&long).is_none());
    }

    #[test]
    fn a_name_that_is_a_directory_of_another_is_refused() {
        check_prefixes(&dir(&["a", "a-b", "a.b", "ab", "b/c"])).unwrap();
        for names in [
            &["a", "a/b"][..],
            &["a", "a-b", "a.b", "a/b"],
            &["x", "x/y/z"],
            &["a/b", "a/b/c"],
        ] {
            match check_prefixes(&dir(names)) {
                Err(Error::Remote(crate::remote::Error::InvalidInput(message))) => {
                    assert!(message.contains("is a directory of the ref"), "{message}");
                }
                other => panic!("{names:?}: {other:?}"),
            }
        }
    }

    #[test]
    fn the_summary_refs_are_the_heads_and_a_map_of_the_mirrors() {
        let mut refs = BucketRefs::default();
        refs.heads.insert("main".into(), csum(1));
        refs.heads.insert("a".into(), csum(2));
        refs.mirrors.insert("org.example.B".into(), dir(&["main"]));
        refs.mirrors
            .insert("org.example.Empty".into(), BTreeMap::new());
        let (local, collections) = summary_refs(&refs);
        assert_eq!(
            local,
            [("a".to_owned(), csum(2)), ("main".to_owned(), csum(1))]
        );
        assert_eq!(collections.len(), 1);
        assert_eq!(collections["org.example.B"], [("main".to_owned(), csum(1))]);
    }

    #[test]
    fn a_namespace_id_passes_the_collection_id_rule_and_the_length() {
        assert!(is_namespace_id("org.example.Os"));
        assert!(is_namespace_id(&format!("org.{}", "a".repeat(251))));
        assert!(!is_namespace_id(&format!("org.{}", "a".repeat(252))));
        assert!(!is_namespace_id("nodot"));
        assert!(!is_namespace_id(""));
    }
}
