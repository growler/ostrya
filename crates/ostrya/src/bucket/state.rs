//! The state of a bucket repository that a writer reads: the `config`, the
//! refs, and the presence of a summary signature.

use std::collections::{BTreeMap, BTreeSet};

use ostrya_core::{Checksum, RepoMode, is_collection_id, is_ref_name};

use super::BucketRepo;
use crate::config::RepoConfig;
use crate::error::{Error, Result};
use crate::pull::drive::Slots;
use crate::refs::MAX_COLLECTION_ID_LEN;
use crate::remote::s3::Object;
use crate::repo::MAX_CONFIG_SIZE;

/// The size of a ref file: 64 hex digits and a newline.
const REF_FILE_SIZE: u64 = 65;

/// The one byte of a partial-commit marker, as the `ostree` command writes
/// it into a `.commitpartial` marker when its fsck finds a commit incomplete
/// (observed).
pub(super) const PARTIAL_STATE_BYTE: u8 = 0x66;

/// The refs of a bucket repository.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct BucketRefs {
    /// The refs `refs/heads/NAME`, by name.
    pub(crate) heads: BTreeMap<String, Checksum>,
    /// The refs `refs/mirrors/ID/NAME`, by collection id, then by name.
    pub(crate) mirrors: BTreeMap<String, BTreeMap<String, Checksum>>,
}

/// The result of the read of one ref file.
pub(super) enum RefRead {
    /// The file names the commit.
    Commit(Checksum),
    /// The key held no object at the read.
    Gone,
    /// The file breaks the rule of a ref file. The text states the rule,
    /// after the subject "the ref file".
    Malformed(String),
}

/// One ref key of a bucket repository.
pub(super) enum RefKey<'a> {
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
        let read = self.bucket.get("config", MAX_CONFIG_SIZE).await;
        self.check_config(read)
    }

    /// Reads the `config` of the repository as
    /// [`read_config`](BucketRepo::read_config) does, by the strict rule of
    /// an absent key of [`Bucket::get_strict`](crate::remote::s3::Bucket::get_strict).
    ///
    /// # Errors
    ///
    /// The errors of [`read_config`](BucketRepo::read_config). A 404 that is
    /// not an absent key gives [`Error::Remote`].
    pub(super) async fn read_config_strict(&self) -> Result<Option<RepoConfig>> {
        let read = self.bucket.get_strict("config", MAX_CONFIG_SIZE).await;
        self.check_config(read)
    }

    /// Returns the `config` of the read `read`, after the checks of
    /// [`read_config`](BucketRepo::read_config).
    fn check_config(
        &self,
        read: std::result::Result<Option<Object>, crate::remote::Error>,
    ) -> Result<Option<RepoConfig>> {
        let object = match read {
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
                reads.push(async move { (key, self.read_ref_file(key).await) });
            }
            let Some((key, read)) = reads.next_ready().await else {
                break;
            };
            match read? {
                RefRead::Commit(commit) => out.push((key, commit)),
                RefRead::Gone => {
                    return Err(self.malformed(format!(
                        "the ref file '{}' was in the listing and is gone",
                        key.escape_debug()
                    )));
                }
                RefRead::Malformed(why) => {
                    return Err(
                        self.malformed(format!("the ref file '{}' {why}", key.escape_debug()))
                    );
                }
            }
        }
        Ok(out)
    }

    /// Reads the ref file at `key`.
    ///
    /// # Errors
    ///
    /// [`Error::Remote`] for an error of the bucket client.
    async fn read_ref_file(&self, key: &str) -> Result<RefRead> {
        ref_read(self.bucket.get(key, REF_FILE_SIZE).await)
    }

    /// Reads the ref file at `key`, by the strict rule of an absent key of
    /// [`Bucket::get_strict`](crate::remote::s3::Bucket::get_strict).
    ///
    /// # Errors
    ///
    /// [`Error::Remote`] for an error of the bucket client, also for a 404
    /// that is not an absent key.
    pub(super) async fn read_ref_file_strict(&self, key: &str) -> Result<RefRead> {
        ref_read(self.bucket.get_strict(key, REF_FILE_SIZE).await)
    }

    /// Returns each commit that has a partial-commit marker: one list of
    /// `state/`.
    ///
    /// A marker is the key `state/<checksum>.commitpartial`, in lowercase
    /// hex. It marks a commit whose tree misses objects. Each other key under
    /// `state/` is ignored.
    ///
    /// # Errors
    ///
    /// [`Error::Remote`] for an error of the bucket client.
    pub(crate) async fn partial_commits(&self) -> Result<BTreeSet<Checksum>> {
        Ok(self
            .bucket
            .list("state/")
            .await?
            .objects
            .iter()
            .filter_map(|listed| marker_commit(&listed.key))
            .collect())
    }

    /// Returns `true` if the key `summary.sig` holds an object.
    ///
    /// The call is a check of
    /// [`Bucket::exists_strict`](crate::remote::s3::Bucket::exists_strict),
    /// by the strict rule of an absent key. It asks for the first byte of the
    /// key alone.
    ///
    /// # Errors
    ///
    /// [`Error::Remote`] for an error of the bucket client, also for a 404
    /// that is not an absent key.
    pub(super) async fn is_signed(&self) -> Result<bool> {
        Ok(self.bucket.exists_strict("summary.sig").await?)
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
pub(super) fn ref_key(key: &str) -> Option<RefKey<'_>> {
    if let Some(name) = key.strip_prefix("refs/heads/") {
        return is_ref_name(name).then_some(RefKey::Head(name));
    }
    let (id, name) = key.strip_prefix("refs/mirrors/")?.split_once('/')?;
    (is_namespace_id(id) && is_ref_name(name)).then_some(RefKey::Mirror(id, name))
}

/// Returns the key of the partial-commit marker of `commit`.
pub(crate) fn marker_key(commit: &Checksum) -> String {
    format!("state/{}.commitpartial", commit.to_hex())
}

/// Returns the commit of the partial-commit marker `key`, or `None` for a key
/// of another form.
fn marker_commit(key: &str) -> Option<Checksum> {
    let hex = key.strip_prefix("state/")?.strip_suffix(".commitpartial")?;
    if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    Checksum::from_hex(hex).ok()
}

/// Returns the result of the read `read` of a ref file.
fn ref_read(read: std::result::Result<Option<Object>, crate::remote::Error>) -> Result<RefRead> {
    let bytes = match read {
        Ok(Some(object)) => object.bytes,
        Ok(None) => return Ok(RefRead::Gone),
        Err(crate::remote::Error::LimitExceeded(_)) => {
            return Ok(RefRead::Malformed(format!(
                "is larger than {REF_FILE_SIZE} bytes"
            )));
        }
        Err(e) => return Err(e.into()),
    };
    Ok(match parse_ref_file(&bytes) {
        Some(commit) => RefRead::Commit(commit),
        None => {
            RefRead::Malformed("does not hold 64 lowercase hex digits and a newline".to_owned())
        }
    })
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
    fn a_marker_key_names_one_commit_in_lowercase_hex() {
        let commit = Checksum::from_bytes([0xab; 32]);
        let key = marker_key(&commit);
        assert_eq!(key, format!("state/{}.commitpartial", "ab".repeat(32)));
        assert_eq!(marker_commit(&key), Some(commit));
        for key in [
            format!("state/{}.commitpartial", "AB".repeat(32)),
            format!("state/{}.commitpartial", "a".repeat(63)),
            format!("state/{}.commit", "ab".repeat(32)),
            format!("state/x/{}.commitpartial", "ab".repeat(32)),
            "state/other".to_owned(),
        ] {
            assert_eq!(marker_commit(&key), None, "{key}");
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
