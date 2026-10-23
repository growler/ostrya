#![forbid(unsafe_code)]

//! Tests of the summary update of a bucket repository.
//!
//! Most tests build an `archive` repository with ostrya, copy its objects,
//! a `config`, and its ref files into the S3 stand-in of `common::s3`, and
//! then write the summary of the bucket. One test runs against `weed mini`
//! of SeaweedFS, and skips when `weed` is absent.
//! `OSTRYA_REQUIRE_SEAWEEDFS` turns the skip into a failure. The GPG test
//! skips when `gpg` is absent, and `OSTRYA_REQUIRE_GNUPG` turns the skip into
//! a failure.

#![cfg(feature = "s3")]

mod common;

use std::collections::BTreeMap;
use std::os::fd::AsFd;
use std::path::Path;
use std::sync::Arc;

use common::TmpDir;
use common::modes::object_path;
use common::s3::{PROBE_BODY, PROBE_KEY, StandIn, endpoint};
use ostrya::bucket::{
    BucketFindingKind, BucketFsckOptions, BucketRepo, BucketSummaryOptions, BucketSummaryReport,
};
use ostrya::remote::{Endpoint, PullSession, StreamSessionOptions};
use ostrya::verify::{PullTrust, TrustedKeys};
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, DeltaOptions,
    Ed25519Signer, Ed25519Verifier, Error, MutableTree, ObjectType, PullOptions, Repo, RepoMode,
    SignFuture, Signer, Summary, SummaryOptions, Value,
};
use ostrya_rt::block_on;

/// The address of the repository in each test.
const ADDRESS: &str = "s3://bkt/repo";

/// The key of the writer lock in the bucket.
const LOCK: &str = "repo/extensions/ostrya/lock";

/// The config of a bucket repository with no collection id.
const PLAIN: &str = "[core]\nrepo_version=1\nmode=archive-z2\n";

/// The collection id of the tests with one.
const ID: &str = "org.example.Os";

/// The collection id of the mirror refs of the tests.
const OTHER: &str = "org.example.Other";

/// The time of the commits, and the `last-modified` of the tests.
const T0: u64 = 1_700_000_000;

/// A fixed ed25519 key that signs the summary.
const SECRET_B64: &str =
    "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";

/// The body of a lock of a writer that ended with no release.
const DEAD_LOCK: &str = "[lock]\nid=9999999999999999999999999999999999999999999999999999999999999999\n\
                         host=deadhost\npid=99\noperation=push\nstarted=1700000000\n";

/// A local repository and the copy of its files in a bucket.
///
/// `main` is `c1 <- c2`, and `side` is `s1`, whose parent is `c1`.
struct Fixture {
    tmp: TmpDir,
    local: Repo,
    server: StandIn,
    bucket: BucketRepo,
    c1: Checksum,
    c2: Checksum,
    s1: Checksum,
}

impl Fixture {
    /// Builds the repository, and copies its objects, a `config` with the
    /// collection id `id`, and the ref files of `main` and `side` into a new
    /// stand-in.
    async fn new(id: Option<&str>) -> Fixture {
        let tmp = TmpDir::new("bucket-summary");
        let local = Repo::create(
            &tmp.path().join("repo"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let base = tmp.path();
        let c1 = commit(&local, base, Some("main"), "first", None, T0).await;
        let c2 = commit(&local, base, Some("main"), "second", Some(c1), T0 + 100).await;
        let s1 = commit(&local, base, Some("side"), "side", Some(c1), T0 + 50).await;
        let server = StandIn::start();
        let fixture = Fixture {
            bucket: BucketRepo::open(&endpoint(&server.endpoint(), ADDRESS))
                .await
                .unwrap(),
            tmp,
            local,
            server,
            c1,
            c2,
            s1,
        };
        fixture.copy("objects");
        let mut config = PLAIN.to_owned();
        if let Some(id) = id {
            config.push_str(&format!("collection-id={id}\n"));
        }
        fixture.put("config", config.as_bytes());
        fixture.put_ref("refs/heads/main", &c2);
        fixture.put_ref("refs/heads/side", &s1);
        // A bucket that a writer took the lock of holds the probe, so each
        // take sends one probe.
        fixture.put(PROBE_KEY, PROBE_BODY);
        fixture
    }

    /// Generates the deltas `c1-c2` and `s1` in the local repository, and
    /// copies them into the bucket.
    async fn deltas(&self) {
        for (from, to) in [(Some(self.c1), self.c2), (None, self.s1)] {
            self.local
                .generate_static_delta(from.as_ref(), &to, &DeltaOptions::default())
                .await
                .unwrap();
        }
        self.copy("deltas");
    }

    /// Copies each file under `sub` of the local repository into the bucket.
    fn copy(&self, sub: &str) {
        for (name, bytes) in common::file_inventory(self.local.path(), sub) {
            self.put(&name, &bytes);
        }
    }

    /// Writes `bytes` at `key`, under the prefix of the repository.
    fn put(&self, key: &str, bytes: &[u8]) {
        self.server.state().store(&format!("repo/{key}"), bytes);
    }

    /// Writes the ref file at `key` with `commit`.
    fn put_ref(&self, key: &str, commit: &Checksum) {
        self.put(key, format!("{}\n", commit.to_hex()).as_bytes());
    }

    /// Returns the bytes at `key`, under the prefix of the repository.
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.server
            .state()
            .objects
            .get(&format!("repo/{key}"))
            .map(|stored| stored.bytes.clone())
    }

    /// Removes the key `key`, under the prefix of the repository.
    fn remove(&self, key: &str) {
        let key = format!("repo/{key}");
        assert!(self.server.state().objects.remove(&key).is_some(), "{key}");
    }

    /// Returns each key and its bytes under the prefix of the repository.
    fn snapshot(&self) -> BTreeMap<String, Vec<u8>> {
        self.server
            .state()
            .objects
            .iter()
            .map(|(key, stored)| (key.clone(), stored.bytes.clone()))
            .collect()
    }

    /// Returns the requests of the server whose target is under the prefix
    /// of the repository, without the bucket.
    fn requests(&self) -> Vec<(String, String)> {
        self.server
            .state()
            .requests
            .iter()
            .filter_map(|(method, target)| {
                target
                    .strip_prefix("/bkt/repo/")
                    .map(|key| (method.clone(), key.to_owned()))
            })
            .collect()
    }

    /// Returns the key of each request other than a `GET`, in order.
    fn writes(&self) -> Vec<String> {
        self.requests()
            .into_iter()
            .filter(|(method, _)| method != "GET")
            .map(|(method, key)| format!("{method} {key}"))
            .collect()
    }

    /// Returns `true` if each request other than a `GET` writes the lock or
    /// the probe of the lock.
    fn lock_writes_alone(&self) -> bool {
        self.writes().iter().all(|write| {
            write.ends_with("extensions/ostrya/lock")
                || write.ends_with("extensions/ostrya/lock-probe")
        })
    }

    /// Returns the prefix of each list, without the prefix of the
    /// repository.
    fn lists(&self) -> Vec<String> {
        self.server
            .state()
            .requests
            .iter()
            .filter_map(|(_, target)| {
                let (_, query) = target.split_once('?')?;
                let prefix = query
                    .split('&')
                    .find_map(|pair| pair.strip_prefix("prefix="))?
                    .replace("%2F", "/");
                prefix.strip_prefix("repo/").map(str::to_owned)
            })
            .collect()
    }

    /// Runs the update with the signer of [`SECRET_B64`] and the
    /// `last-modified` [`T0`].
    async fn update(&self) -> ostrya::Result<BucketSummaryReport> {
        self.bucket.update_summary(&signed()).await
    }

    /// Returns the summary of the bucket, parsed.
    fn summary(&self) -> Summary {
        Summary::parse(&self.get("summary").expect("a summary")).unwrap()
    }
}

/// Commits a tree with the file `file`, which holds `content`, the symlink
/// `link` to `file`, and the directory `sub/deep`, which is the same in each
/// commit, at the time `timestamp`. Sets the ref `branch` to the commit if
/// it is given.
async fn commit(
    repo: &Repo,
    base: &Path,
    branch: Option<&str>,
    content: &str,
    parent: Option<Checksum>,
    timestamp: u64,
) -> Checksum {
    let tree = base.join(format!("tree-{content}"));
    std::fs::create_dir_all(tree.join("sub/deep")).unwrap();
    std::fs::write(tree.join("file"), content).unwrap();
    std::fs::write(tree.join("sub/deep/nested"), "the same in each commit\n").unwrap();
    std::os::unix::fs::symlink("file", tree.join("link")).unwrap();
    let txn = repo.transaction().await.unwrap();
    let dfd = std::fs::File::open(&tree).unwrap();
    let mut modifier = CommitModifier::new(
        CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::SKIP_XATTRS,
    );
    let mut mtree = MutableTree::new();
    txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("."), &mut mtree, Some(&mut modifier))
        .await
        .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let checksum = txn
        .write_commit(
            CommitOptions {
                parent,
                subject: Some(content.to_owned()),
                timestamp: Some(timestamp),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    if let Some(branch) = branch {
        txn.set_ref(branch, Some(&checksum));
    }
    txn.commit().await.unwrap();
    checksum
}

/// Returns the signer of [`SECRET_B64`].
fn signer() -> Ed25519Signer {
    Ed25519Signer::from_base64(SECRET_B64).unwrap()
}

/// Returns the options of an update with the signer of [`SECRET_B64`] and
/// the `last-modified` [`T0`].
fn signed() -> BucketSummaryOptions {
    let mut opts = BucketSummaryOptions::default();
    opts.summary_signers = vec![Arc::new(signer())];
    opts.last_modified = Some(T0);
    opts
}

/// Returns the options of an update with no signer.
fn unsigned() -> BucketSummaryOptions {
    let mut opts = BucketSummaryOptions::default();
    opts.last_modified = Some(T0);
    opts
}

/// Returns the trusted keys of the public key of [`SECRET_B64`], or of
/// another key if `wrong` is set.
fn keys(wrong: bool) -> TrustedKeys {
    let secret = ostrya::base64::decode(SECRET_B64).unwrap();
    let mut public = secret[32..].to_vec();
    if wrong {
        // The base point of the curve: a valid key of no signer of a test.
        public = vec![0x66; 32];
        public[0] = 0x58;
    }
    let verifier = Ed25519Verifier::new([public], Vec::<Vec<u8>>::new()).unwrap();
    TrustedKeys::new(vec![Arc::new(verifier)]).unwrap()
}

/// Returns the name and the commit of each ref of field 0 of `summary`.
fn heads(summary: &Summary) -> Vec<(String, Checksum)> {
    summary
        .refs
        .iter()
        .map(|entry| (entry.name.clone(), entry.commit))
        .collect()
}

/// Returns the bucket key of the commit object `commit`.
fn commit_key(commit: &Checksum) -> String {
    object_path(ObjectType::Commit, commit)
}

/// Returns the key of the superblock of the delta to `to` from `from`.
fn superblock_key(from: Option<&Checksum>, to: &Checksum) -> String {
    let to = to.to_base64_modified();
    match from {
        None => format!("deltas/{}/{}/superblock", &to[..2], &to[2..]),
        Some(from) => {
            let from = from.to_base64_modified();
            format!("deltas/{}/{}-{to}/superblock", &from[..2], &from[2..])
        }
    }
}

/// Pulls `refs` from the bucket at the server `url` into a new `archive`
/// repository under `dir` with `trust`.
async fn pull(dir: &Path, url: &str, refs: &[&str], trust: PullTrust) -> ostrya::Result<Repo> {
    let repo = Repo::create(dir, CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap();
    let session = PullSession::connect(
        Endpoint::S3(endpoint(url, ADDRESS)),
        StreamSessionOptions::default(),
    )
    .await
    .unwrap();
    let opts = PullOptions {
        refs: refs.iter().map(|r| (*r).to_owned()).collect(),
        ..PullOptions::default()
    };
    repo.pull_with_session(session, trust, opts).await?;
    Ok(repo)
}

/// Asserts that a fsck of `bucket` gives no `Summary` finding.
async fn assert_no_summary_finding(bucket: &BucketRepo) {
    let report = bucket.fsck(&BucketFsckOptions::default()).await.unwrap();
    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.kind == BucketFindingKind::Summary),
        "{:#?}",
        report.findings
    );
}

/// A signer that always fails.
struct FailingSigner;

impl Signer for FailingSigner {
    fn name(&self) -> &str {
        "failing"
    }

    fn metadata_key(&self) -> &str {
        "ostree.sign.failing"
    }

    fn sign<'a>(&'a self, _data: &'a [u8]) -> SignFuture<'a> {
        Box::pin(async {
            Err(ostrya::sign::Error::Signature(
                "the test signer fails".to_owned(),
            ))
        })
    }
}

// ---------------------------------------------------------------------------
// The content of the summary.
// ---------------------------------------------------------------------------

#[test]
fn a_copied_ref_file_is_in_the_summary_and_a_pull_verifies_it() {
    block_on(async {
        let f = Fixture::new(None).await;
        f.put_ref("refs/heads/copy", &f.c1);
        let report = f.update().await.unwrap();
        assert_eq!(report.refs, 3);
        assert_eq!(report.deltas, 0);
        assert_eq!(report.signers, ["ed25519"]);
        assert_eq!(report.last_modified, T0);
        assert_eq!(report.broken_lock, None);
        assert_eq!(
            heads(&f.summary()),
            [
                ("copy".to_owned(), f.c1),
                ("main".to_owned(), f.c2),
                ("side".to_owned(), f.s1),
            ]
        );
        assert!(f.get("summary.sig").is_some());
        assert!(f.get("extensions/ostrya/lock").is_none());
        let url = f.server.endpoint();
        let trust = PullTrust::unverified().with_summary(keys(false));
        let pulled = pull(&f.tmp.path().join("good"), &url, &["copy"], trust)
            .await
            .unwrap();
        assert_eq!(pulled.resolve_rev("copy", false).await.unwrap(), Some(f.c1));
        let trust = PullTrust::unverified().with_summary(keys(true));
        let err = pull(&f.tmp.path().join("wrong"), &url, &["copy"], trust)
            .await
            .expect_err("a summary signed by another key is refused");
        assert!(matches!(err, Error::Signature(_)), "{err}");
        assert_no_summary_finding(&f.bucket).await;
    });
}

#[test]
fn the_summary_has_the_bytes_of_the_local_summary_of_a_copy() {
    block_on(async {
        let f = Fixture::new(None).await;
        f.deltas().await;
        f.put_ref(&format!("refs/mirrors/{OTHER}/main"), &f.s1);
        f.put_ref("refs/heads/a/b", &f.c1);
        let report = f.update().await.unwrap();
        assert_eq!(report.refs, 4);
        assert_eq!(report.deltas, 2);
        let dir = f.tmp.path().join("copy");
        f.server.dump("repo", &dir);
        let copy = Repo::open(&dir).await.unwrap();
        let opts = SummaryOptions {
            last_modified: Some(T0),
            ..SummaryOptions::default()
        };
        let signer = signer();
        copy.regenerate_summaries(&opts, &[&signer as &dyn Signer])
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(dir.join("summary")).unwrap(),
            f.get("summary").unwrap()
        );
        assert_eq!(
            std::fs::read(dir.join("summary.sig")).unwrap(),
            f.get("summary.sig").unwrap()
        );
        let summary = f.summary();
        let map = summary.collection_map().unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map[0].0, OTHER);
        assert_eq!(map[0].1[0].commit, f.s1);
        assert_no_summary_finding(&f.bucket).await;
    });
}

#[test]
fn the_delta_map_holds_each_delta_with_a_superblock() {
    block_on(async {
        let f = Fixture::new(None).await;
        f.deltas().await;
        // A delta of a target whose name has a `+` in the key, with a
        // superblock, and a delta directory with no superblock.
        let mut bytes = [7u8; 32];
        bytes[0] = 0xfb;
        bytes[1] = 0xff;
        let plus = Checksum::from_bytes(bytes);
        let key = superblock_key(None, &plus);
        assert!(key.contains('+'), "{key}");
        f.put(&key, b"a superblock with a plus");
        let bare = Checksum::sha256(b"no superblock");
        let b64 = bare.to_base64_modified();
        f.put(&format!("deltas/{}/{}/0", &b64[..2], &b64[2..]), b"part");
        let report = f.update().await.unwrap();
        assert_eq!(report.deltas, 3);
        let mut expected = vec![
            (None, plus, Checksum::sha256(b"a superblock with a plus")),
            (
                Some(f.c1),
                f.c2,
                Checksum::sha256(&f.get(&superblock_key(Some(&f.c1), &f.c2)).unwrap()),
            ),
            (
                None,
                f.s1,
                Checksum::sha256(&f.get(&superblock_key(None, &f.s1)).unwrap()),
            ),
        ];
        expected.sort();
        let mut deltas: Vec<(Option<Checksum>, Checksum, Checksum)> = f
            .summary()
            .static_deltas()
            .unwrap()
            .into_iter()
            .map(|delta| (delta.from, delta.to, delta.superblock))
            .collect();
        deltas.sort();
        assert_eq!(deltas, expected);
    });
}

#[test]
fn a_bucket_with_a_collection_id_states_it_and_maps_the_mirror_refs() {
    block_on(async {
        let f = Fixture::new(Some(ID)).await;
        f.put_ref(&format!("refs/mirrors/{OTHER}/main"), &f.c1);
        f.put_ref(&format!("refs/mirrors/{OTHER}/next"), &f.c2);
        let report = f.update().await.unwrap();
        assert_eq!(report.refs, 4);
        let summary = f.summary();
        assert_eq!(
            summary.metadata_value("ostree.summary.collection-id"),
            Some(&Value::Str(ID.to_owned()))
        );
        assert_eq!(heads(&summary).len(), 2);
        let map = summary.collection_map().unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map[0].0, OTHER);
        let refs: Vec<(String, Checksum)> = map[0]
            .1
            .iter()
            .map(|entry| (entry.name.clone(), entry.commit))
            .collect();
        assert_eq!(refs, [("main".to_owned(), f.c1), ("next".to_owned(), f.c2)]);
        assert_no_summary_finding(&f.bucket).await;
    });
}

#[test]
fn the_config_values_and_an_empty_ref_set_are_written() {
    block_on(async {
        let f = Fixture::new(None).await;
        f.put(
            "config",
            format!("{PLAIN}tombstone-commits=true\nindexed-deltas=true\n").as_bytes(),
        );
        f.update().await.unwrap();
        let summary = f.summary();
        for key in [
            "ostree.summary.tombstone-commits",
            "ostree.summary.indexed-deltas",
        ] {
            assert_eq!(
                summary.metadata_value(key),
                Some(&Value::Bool(true)),
                "{key}"
            );
        }
        // A bucket with no ref gets a summary with an empty field 0.
        f.remove("refs/heads/main");
        f.remove("refs/heads/side");
        // The bucket holds the summary.sig of the first run, so the update
        // needs a signer.
        let report = f.update().await.unwrap();
        assert_eq!(report.refs, 0);
        assert!(f.summary().refs.is_empty());
    });
}

#[test]
fn the_commit_of_a_partial_marker_is_listed_and_the_update_reads_no_marker() {
    block_on(async {
        let f = Fixture::new(None).await;
        f.put(&format!("state/{}.commitpartial", f.c2.to_hex()), &[0x66]);
        f.server.state().requests.clear();
        f.update().await.unwrap();
        assert_eq!(f.summary().lookup("main"), Some(f.c2));
        assert!(
            !f.requests()
                .iter()
                .any(|(_, key)| key.starts_with("state/")),
            "{:?}",
            f.requests()
        );
        assert!(
            !f.lists().iter().any(|prefix| prefix.starts_with("state/")),
            "{:?}",
            f.lists()
        );
    });
}

// ---------------------------------------------------------------------------
// The requests of an update.
// ---------------------------------------------------------------------------

#[test]
fn the_update_reads_each_ref_commit_once_and_writes_the_summary_alone() {
    block_on(async {
        let f = Fixture::new(None).await;
        f.put_ref("refs/heads/again", &f.c2);
        f.server.state().requests.clear();
        f.update().await.unwrap();
        let mut gets: Vec<String> = f
            .requests()
            .into_iter()
            .filter(|(method, key)| method == "GET" && key.starts_with("objects/"))
            .map(|(_, key)| key)
            .collect();
        gets.sort();
        let mut expected = vec![commit_key(&f.c2), commit_key(&f.s1)];
        expected.sort();
        assert_eq!(gets, expected);
        let mut lists = f.lists();
        lists.sort();
        assert_eq!(lists, ["deltas/", "refs/"]);
        // An update with a signer does not probe summary.sig.
        assert!(
            !f.requests()
                .iter()
                .any(|(method, key)| method == "GET" && key == "summary.sig"),
            "{:?}",
            f.requests()
        );
        assert_eq!(
            f.writes(),
            [
                "PUT extensions/ostrya/lock-probe",
                "PUT extensions/ostrya/lock",
                "PUT summary",
                "PUT summary.sig",
                "DELETE extensions/ostrya/lock",
            ]
        );
        // The config is read before the lock.
        let requests = f.requests();
        assert_eq!(requests[0], ("GET".to_owned(), "config".to_owned()));
        assert!(
            !f.snapshot()
                .keys()
                .any(|key| key.starts_with("repo/extensions/ostrya/summary")),
        );
    });
}

// ---------------------------------------------------------------------------
// Refusals.
// ---------------------------------------------------------------------------

#[test]
fn a_signed_bucket_refuses_an_update_with_no_signer() {
    block_on(async {
        let f = Fixture::new(None).await;
        f.update().await.unwrap();
        let before = f.snapshot();
        f.server.state().requests.clear();
        let err = f.bucket.update_summary(&unsigned()).await.unwrap_err();
        assert!(
            matches!(&err, Error::Remote(ostrya::remote::Error::InvalidInput(m))
                if m.contains("holds a summary.sig")),
            "{err}"
        );
        assert_eq!(f.snapshot(), before);
        assert!(f.lock_writes_alone(), "{:?}", f.writes());
        assert!(f.get("extensions/ostrya/lock").is_none());
        // An unsigned bucket takes an update with no signer.
        f.remove("summary.sig");
        f.bucket.update_summary(&unsigned()).await.unwrap();
        assert!(f.get("summary.sig").is_none());
    });
}

#[test]
fn a_404_that_is_no_absent_key_fails_the_probe_of_the_signature() {
    block_on(async {
        let f = Fixture::new(None).await;
        f.update().await.unwrap();
        let before = f.snapshot();
        f.server.state().not_found = Some(("repo/summary.sig".to_owned(), Vec::new()));
        f.server.state().requests.clear();
        let err = f.bucket.update_summary(&unsigned()).await.unwrap_err();
        assert!(
            matches!(
                &err,
                Error::Remote(ostrya::remote::Error::S3 {
                    status: 404,
                    code: None,
                    ..
                })
            ),
            "{err}"
        );
        assert_eq!(f.snapshot(), before);
        assert!(f.lock_writes_alone(), "{:?}", f.writes());
        assert!(f.get("extensions/ostrya/lock").is_none());
    });
}

#[test]
fn a_404_that_is_no_absent_key_on_a_superblock_refuses_the_update() {
    block_on(async {
        let f = Fixture::new(None).await;
        f.deltas().await;
        let before = f.snapshot();
        let key = superblock_key(None, &f.s1);
        f.server.state().not_found = Some((format!("repo/{key}"), Vec::new()));
        f.server.state().requests.clear();
        let err = f.update().await.unwrap_err();
        assert!(
            matches!(
                &err,
                Error::Remote(ostrya::remote::Error::S3 {
                    status: 404,
                    code: None,
                    ..
                })
            ),
            "{err}"
        );
        assert_eq!(f.snapshot(), before);
        assert!(f.lock_writes_alone(), "{:?}", f.writes());
        assert!(f.get("extensions/ostrya/lock").is_none());
        // A superblock that is gone at its read, with `NoSuchKey`, is not in
        // the map.
        let no_such_key = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error>\
                            <Code>NoSuchKey</Code><Message>gone</Message></Error>";
        f.server.state().not_found = Some((format!("repo/{key}"), no_such_key.to_vec()));
        let report = f.update().await.unwrap();
        assert_eq!(report.deltas, 1);
        let deltas = f.summary().static_deltas().unwrap();
        assert_eq!(deltas.len(), 1);
        assert_eq!((deltas[0].from, deltas[0].to), (Some(f.c1), f.c2));
    });
}

#[test]
fn a_bad_ref_or_commit_refuses_the_update_and_changes_nothing() {
    type Spoil = fn(&Fixture);
    let cases: Vec<(&str, Option<&str>, Spoil, &str)> = vec![
        (
            "a key under refs/remotes",
            None,
            |f| f.put_ref("refs/remotes/origin/main", &f.c2),
            "refs/remotes/origin/main",
        ),
        (
            "a ref whose commit is absent",
            None,
            |f| f.put_ref("refs/heads/gone", &Checksum::sha256(b"absent")),
            "which the bucket does not hold",
        ),
        (
            "a mirror ref of the own collection id",
            Some(ID),
            |f| f.put_ref(&format!("refs/mirrors/{ID}/main"), &f.c2),
            "of its own collection id",
        ),
        (
            "a commit object with other bytes",
            None,
            |f| {
                let other = f.get(&commit_key(&f.s1)).unwrap();
                f.put(&commit_key(&f.c2), &other);
            },
            "has the checksum",
        ),
        (
            "a ref that is a directory of another ref",
            None,
            |f| f.put_ref("refs/heads/main/x", &f.c1),
            "is a directory of the ref",
        ),
        (
            "a directory clash in a mirror directory",
            None,
            |f| {
                f.put_ref(&format!("refs/mirrors/{OTHER}/a"), &f.c1);
                f.put_ref(&format!("refs/mirrors/{OTHER}/a/b"), &f.c1);
            },
            "is a directory of the ref",
        ),
    ];
    for (case, id, spoil, words) in cases {
        block_on(async {
            let f = Fixture::new(id).await;
            spoil(&f);
            let before = f.snapshot();
            f.server.state().requests.clear();
            let err = f.update().await.unwrap_err();
            assert!(
                matches!(&err, Error::InvalidFormat(m) if m.contains(words))
                    || matches!(&err, Error::Remote(ostrya::remote::Error::InvalidInput(m))
                        if m.contains(words)),
                "{case}: {err}"
            );
            assert_eq!(f.snapshot(), before, "{case}");
            assert!(f.lock_writes_alone(), "{case}: {:?}", f.writes());
        });
    }
}

#[test]
fn a_failed_signer_writes_nothing() {
    block_on(async {
        let f = Fixture::new(None).await;
        let before = f.snapshot();
        let mut opts = BucketSummaryOptions::default();
        opts.summary_signers = vec![Arc::new(signer()), Arc::new(FailingSigner)];
        let err = f.bucket.update_summary(&opts).await.unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m)
                if m.starts_with("the summary signature with the failing key")),
            "{err}"
        );
        assert_eq!(f.snapshot(), before);
    });
}

#[test]
fn a_bucket_with_no_config_takes_no_lock() {
    block_on(async {
        let f = Fixture::new(None).await;
        f.remove("config");
        let before = f.snapshot();
        f.server.state().requests.clear();
        let err = f.update().await.unwrap_err();
        assert!(
            matches!(&err, Error::Remote(ostrya::remote::Error::InvalidInput(m))
                if m.ends_with("has no config; init it first")),
            "{err}"
        );
        assert_eq!(f.requests(), [("GET".to_owned(), "config".to_owned())]);
        assert_eq!(f.snapshot(), before);
    });
}

// ---------------------------------------------------------------------------
// The writer lock.
// ---------------------------------------------------------------------------

#[test]
fn the_lock_of_another_writer_fails_the_update_and_break_lock_removes_it() {
    block_on(async {
        let f = Fixture::new(None).await;
        f.server.state().store(LOCK, DEAD_LOCK.as_bytes());
        let err = f.update().await.unwrap_err();
        assert!(
            matches!(&err, Error::BucketLocked { .. }) && err.to_string().contains("deadhost"),
            "{err}"
        );
        assert!(f.get("summary").is_none());
        let mut opts = signed();
        opts.break_lock = true;
        let report = f.bucket.update_summary(&opts).await.unwrap();
        let holder = report.broken_lock.unwrap();
        assert_eq!(holder.id.as_deref(), Some("9".repeat(64).as_str()));
        assert!(f.get("summary").is_some());
        assert!(f.get("extensions/ostrya/lock").is_none());
    });
}

#[test]
fn a_lock_broken_before_the_write_stops_the_update() {
    block_on(async {
        let f = Fixture::new(None).await;
        f.server.state().before_key = Some((
            "GET",
            format!("repo/{}", commit_key(&f.c2)),
            Box::new(|objects| {
                let stored = objects.get_mut(LOCK).unwrap();
                stored.bytes = DEAD_LOCK.as_bytes().to_vec();
                stored.etag = "\"replaced\"".into();
            }),
        ));
        let err = f.update().await.unwrap_err();
        assert!(matches!(err, Error::BucketLockLost { .. }), "{err}");
        assert!(f.get("summary").is_none());
        assert!(f.get("summary.sig").is_none());
        assert_eq!(f.get("extensions/ostrya/lock"), Some(DEAD_LOCK.into()));
    });
}

#[test]
fn a_server_that_ignores_if_none_match_gets_no_summary() {
    block_on(async {
        let f = Fixture::new(None).await;
        f.server.state().honor_if_none_match = false;
        let before = f.snapshot();
        let err = f.update().await.unwrap_err();
        assert!(matches!(err, Error::BucketNoExclusion { .. }), "{err}");
        assert_eq!(f.snapshot(), before);
    });
}

#[test]
fn a_failed_write_of_the_signature_names_the_mismatch_and_a_run_again_repairs_it() {
    block_on(async {
        let f = Fixture::new(None).await;
        f.update().await.unwrap();
        let old_sig = f.get("summary.sig").unwrap();
        f.put_ref("refs/heads/new", &f.c1);
        f.server.state().refuse = Some(("PUT", "repo/summary.sig".to_owned()));
        let err = f.update().await.unwrap_err();
        let Error::BucketSummaryIncomplete {
            address,
            summary_written: true,
            report,
            error,
        } = &err
        else {
            panic!("{err:?}");
        };
        assert_eq!(address, ADDRESS);
        assert_eq!(report.refs, 3);
        assert_eq!(report.signers, ["ed25519"]);
        assert_eq!(report.broken_lock, None);
        let text = err.to_string();
        assert!(
            text.starts_with(&format!(
                "the summary update of the bucket repository {ADDRESS} wrote summary, and the \
                 write of summary.sig failed: "
            )),
            "{text}"
        );
        assert!(text.contains("ostrya remote summary -u"), "{text}");
        assert!(
            matches!(
                &**error,
                Error::Remote(ostrya::remote::Error::S3 { status: 403, .. })
            ),
            "{error:?}"
        );
        let source = std::error::Error::source(&err).unwrap();
        assert_eq!(source.to_string(), error.to_string());
        assert!(f.get("extensions/ostrya/lock").is_none());
        // The new summary and the old signature: a check of the signature
        // fails.
        assert_eq!(f.summary().lookup("new"), Some(f.c1));
        assert_eq!(f.get("summary.sig"), Some(old_sig));
        let mut opts = BucketFsckOptions::default();
        opts.summary_keys = Some(keys(false));
        let report = f.bucket.fsck(&opts).await.unwrap();
        assert!(
            report.findings.iter().any(|finding| {
                finding.kind == BucketFindingKind::Summary
                    && finding.error
                    && finding.key == "summary.sig"
                    && finding
                        .detail
                        .ends_with("a summary update with these signers writes a matching pair")
            }),
            "{:#?}",
            report.findings
        );
        f.server.state().refuse = None;
        f.update().await.unwrap();
        let report = f.bucket.fsck(&opts).await.unwrap();
        assert!(report.findings.is_empty(), "{:#?}", report.findings);
    });
}

#[test]
fn a_failed_write_of_the_signature_carries_the_holder_of_a_broken_lock() {
    block_on(async {
        let f = Fixture::new(None).await;
        f.server.state().store(LOCK, DEAD_LOCK.as_bytes());
        f.server.state().refuse = Some(("PUT", "repo/summary.sig".to_owned()));
        let mut opts = signed();
        opts.break_lock = true;
        let err = f.bucket.update_summary(&opts).await.unwrap_err();
        let Error::BucketSummaryIncomplete { report, .. } = &err else {
            panic!("{err:?}");
        };
        let holder = report.broken_lock.as_ref().unwrap();
        assert_eq!(holder.id.as_deref(), Some("9".repeat(64).as_str()));
        assert!(f.get("summary").is_some());
        assert!(f.get("summary.sig").is_none());
        assert!(f.get("extensions/ostrya/lock").is_none());
    });
}

#[test]
fn a_write_of_the_summary_with_an_unknown_outcome_names_the_mismatch() {
    // A connection that closes after the server wrote the summary, and an
    // answer 503 with no write.
    for (case, interrupted) in [("interrupted", true), ("503", false)] {
        block_on(async {
            let f = Fixture::new(None).await;
            f.update().await.unwrap();
            let old_summary = f.get("summary").unwrap();
            let old_sig = f.get("summary.sig").unwrap();
            f.put_ref("refs/heads/new", &f.c1);
            let mut once = endpoint(&f.server.endpoint(), ADDRESS);
            once.http.max_retries = 0;
            let bucket = BucketRepo::open(&once).await.unwrap();
            {
                let mut state = f.server.state();
                // The update sends the probe of the lock, the lock, and then
                // the summary.
                let puts = state
                    .requests
                    .iter()
                    .filter(|(method, _)| method == "PUT")
                    .count();
                if interrupted {
                    state.close_after = Some(("PUT", puts + 3));
                } else {
                    state.slow_down = Some(("PUT", puts + 3));
                }
            }
            let err = bucket.update_summary(&signed()).await.unwrap_err();
            let Error::BucketSummaryIncomplete {
                summary_written: false,
                report,
                error,
                ..
            } = &err
            else {
                panic!("{case}: {err:?}");
            };
            assert_eq!(report.refs, 3, "{case}");
            let text = err.to_string();
            assert!(
                text.starts_with(&format!(
                    "the summary update of the bucket repository {ADDRESS} failed to write \
                     summary with an unknown outcome: "
                )),
                "{case}: {text}"
            );
            assert!(text.contains("ostrya remote summary -u"), "{case}: {text}");
            let source = std::error::Error::source(&err).unwrap();
            assert_eq!(source.to_string(), error.to_string(), "{case}");
            if interrupted {
                assert!(
                    matches!(&**error, Error::Remote(ostrya::remote::Error::Fetch(_))),
                    "{error:?}"
                );
                assert_eq!(f.summary().lookup("new"), Some(f.c1));
            } else {
                assert!(
                    matches!(
                        &**error,
                        Error::Remote(ostrya::remote::Error::S3 { status: 503, .. })
                    ),
                    "{error:?}"
                );
                assert_eq!(f.get("summary"), Some(old_summary));
            }
            // The second update sent no write of the signature.
            assert_eq!(f.get("summary.sig"), Some(old_sig), "{case}");
            let sig_writes = f
                .writes()
                .iter()
                .filter(|w| *w == "PUT summary.sig")
                .count();
            assert_eq!(sig_writes, 1, "{case}: {:?}", f.writes());
            assert!(f.get("extensions/ostrya/lock").is_none(), "{case}");
        });
    }
}

#[test]
fn a_refused_write_of_the_summary_is_the_error_of_the_bucket_client() {
    for (case, opts) in [("signed", signed()), ("unsigned", unsigned())] {
        block_on(async {
            let f = Fixture::new(None).await;
            f.put_ref("refs/heads/new", &f.c1);
            let before = f.snapshot();
            f.server.state().refuse = Some(("PUT", "repo/summary".to_owned()));
            let err = f.bucket.update_summary(&opts).await.unwrap_err();
            assert!(
                matches!(
                    &err,
                    Error::Remote(ostrya::remote::Error::S3 { status: 403, .. })
                ),
                "{case}: {err:?}"
            );
            assert_eq!(f.snapshot(), before, "{case}");
            assert!(f.get("extensions/ostrya/lock").is_none(), "{case}");
        });
    }
}

// ---------------------------------------------------------------------------
// GPG and SeaweedFS.
// ---------------------------------------------------------------------------

#[cfg(feature = "sign-gpg")]
#[test]
fn a_gpg_signed_summary_verifies_in_a_pull() {
    use std::process::Command;

    if !common::gnupg_available(&["gpg"]) {
        return;
    }
    /// A private GnuPG home directory with one new ed25519 signing key.
    struct GpgHome {
        dir: std::path::PathBuf,
    }
    impl GpgHome {
        fn gpg(&self) -> Command {
            let mut cmd = Command::new("gpg");
            cmd.arg("--homedir").arg(&self.dir).arg("--batch");
            cmd
        }
    }
    impl Drop for GpgHome {
        fn drop(&mut self) {
            common::remove_gnupg_sockets(&self.dir);
        }
    }
    block_on(async {
        use std::os::unix::fs::DirBuilderExt;
        let f = Fixture::new(None).await;
        let dir = f.tmp.path().join("gnupg");
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let home = GpgHome { dir };
        let status = home
            .gpg()
            .args(["--pinentry-mode", "loopback", "--passphrase", ""])
            .args(["--quick-gen-key", "summary@example.org", "ed25519", "sign"])
            .arg("never")
            .status()
            .unwrap();
        assert!(status.success(), "gpg --quick-gen-key failed");
        let export = home.gpg().arg("--export").output().unwrap();
        assert!(export.status.success() && !export.stdout.is_empty());
        let mut opts = BucketSummaryOptions::default();
        opts.summary_signers = vec![Arc::new(
            ostrya::GpgSigner::new("summary@example.org").with_homedir(&home.dir),
        )];
        let report = f.bucket.update_summary(&opts).await.unwrap();
        assert_eq!(report.signers, ["gpg"]);
        let verifier = ostrya::GpgVerifier::from_keyring_bytes([export.stdout]).unwrap();
        let keys = TrustedKeys::with_gpg(verifier, Vec::new()).unwrap();
        let trust = PullTrust::unverified().with_summary(keys);
        let pulled = pull(
            &f.tmp.path().join("pulled"),
            &f.server.endpoint(),
            &["main"],
            trust,
        )
        .await
        .unwrap();
        assert_eq!(pulled.resolve_rev("main", false).await.unwrap(), Some(f.c2));
    });
}

#[cfg(feature = "push")]
#[test]
fn a_summary_update_on_seaweedfs_after_a_push() {
    use common::s3::{Seaweed, seaweed_available};
    if !seaweed_available("a_summary_update_on_seaweedfs_after_a_push") {
        return;
    }
    // The start of the server runs its own `block_on`, so it comes before
    // the one of the test.
    let scratch = TmpDir::new("bucket-summary-weed");
    let server = Seaweed::start(scratch.path(), "bkt");
    block_on(async {
        let f = Fixture::new(None).await;
        let s3 = endpoint(&server.endpoint(), ADDRESS);
        let bucket = BucketRepo::open(&s3).await.unwrap();
        bucket.init(None, None, false).await.unwrap();
        let opts = ostrya::RepoPushOptions {
            refspecs: vec!["main".to_owned(), "side".to_owned()],
            ..ostrya::RepoPushOptions::default()
        };
        f.local.push_to_bucket(s3.clone(), opts).await.unwrap();
        let report = bucket.update_summary(&signed()).await.unwrap();
        assert_eq!(report.refs, 2);
        assert!(bucket.lock_holder().await.unwrap().is_none());
        let trust = PullTrust::unverified().with_summary(keys(false));
        let pulled = pull(
            &f.tmp.path().join("pulled"),
            &server.endpoint(),
            &["main", "side"],
            trust,
        )
        .await
        .unwrap();
        assert_eq!(pulled.resolve_rev("main", false).await.unwrap(), Some(f.c2));
        let mut fsck = BucketFsckOptions::default();
        fsck.summary_keys = Some(keys(false));
        let report = bucket.fsck(&fsck).await.unwrap();
        assert!(report.findings.is_empty(), "{:#?}", report.findings);
        for key in ["summary", "summary.sig"] {
            assert!(
                bucket.bucket().get(key, 1 << 20).await.unwrap().is_some(),
                "{key}"
            );
        }
    });
}
