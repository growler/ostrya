#![forbid(unsafe_code)]

//! Tests of the prune of a bucket repository.
//!
//! Most tests build an `archive` repository with ostrya, copy its objects,
//! a `config`, and its ref files into the S3 stand-in of `common::s3`, and
//! then prune the bucket. Other tests run against `rclone serve s3`, which
//! refuses each writer, and against `weed mini` of SeaweedFS. A test on a
//! real server skips when its program is absent. `OSTRYA_REQUIRE_S3` and
//! `OSTRYA_REQUIRE_SEAWEEDFS` turn each skip into a failure.

#![cfg(feature = "s3")]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::AsFd;
use std::path::Path;

use common::TmpDir;
use common::modes::object_path;
use common::s3::{PROBE_BODY, PROBE_KEY, Rclone, StandIn, endpoint, rclone_available};
use ostrya::bucket::{
    BucketFsckOptions, BucketPruneOptions, BucketPruneReport, BucketRepo, BucketSummaryOptions,
};
use ostrya::remote::{Endpoint, PullSession, StreamSessionOptions};
use ostrya::verify::PullTrust;
use ostrya::{
    Checksum, CollectionRef, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions,
    DeltaOptions, Error, MutableTree, ObjectType, PruneOptions, PruneStats, PullOptions, Repo,
    RepoMode, Summary, SummaryOptions, WeakRefFilter,
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

/// The time of the first commit.
const T0: u64 = 1_700_000_000;

/// The body of a lock of a writer that ended with no release.
const DEAD_LOCK: &str = "[lock]\nid=9999999999999999999999999999999999999999999999999999999999999999\n\
                         host=deadhost\npid=99\noperation=push\nstarted=1700000000\n";

/// A local repository and the copy of its files in a bucket.
///
/// `main` is `c1 <- c2 <- c3`, and `side` is `s1`, whose parent is `c1`.
/// The commits are at `T0`, `T0 + 100`, `T0 + 200`, and `T0 + 150`.
struct Fixture {
    tmp: TmpDir,
    local: Repo,
    server: StandIn,
    bucket: BucketRepo,
    c1: Checksum,
    c2: Checksum,
    c3: Checksum,
    s1: Checksum,
}

impl Fixture {
    /// Builds the repository, and copies its objects, a `config` with the
    /// collection id `id`, and the ref files of `main` and `side` into a new
    /// stand-in.
    async fn new(id: Option<&str>) -> Fixture {
        let tmp = TmpDir::new("bucket-prune");
        let local = Repo::create(
            &tmp.path().join("repo"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let base = tmp.path();
        let c1 = commit(&local, base, Some("main"), "first", None, T0).await;
        let c2 = commit(&local, base, Some("main"), "second", Some(c1), T0 + 100).await;
        let c3 = commit(&local, base, Some("main"), "third", Some(c2), T0 + 200).await;
        let s1 = commit(&local, base, Some("side"), "side", Some(c1), T0 + 150).await;
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
            c3,
            s1,
        };
        fixture.copy("objects");
        let mut config = PLAIN.to_owned();
        if let Some(id) = id {
            config.push_str(&format!("collection-id={id}\n"));
        }
        fixture.put("config", config.as_bytes());
        fixture.put_ref("refs/heads/main", &c3);
        fixture.put_ref("refs/heads/side", &s1);
        // A bucket that a writer took the lock of holds the probe, so each
        // take sends one probe.
        fixture.put(PROBE_KEY, PROBE_BODY);
        fixture
    }

    /// Builds the repository of [`Fixture::new`] with more state, in the
    /// local repository and in the bucket: a commit that no ref names,
    /// the deltas `c2-c3` and `c1`, the partial-commit markers of `c1`,
    /// `c3`, and of an absent commit, the detached metadata of `c1` and of
    /// an absent commit, the composefs image of `c1`, and the tombstone of
    /// an absent commit.
    async fn rich() -> (Fixture, Checksum) {
        let f = Fixture::new(None).await;
        let loose = commit(&f.local, f.tmp.path(), None, "loose", None, T0 + 50).await;
        for (from, to) in [(Some(f.c2), f.c3), (None, f.c1)] {
            f.local
                .generate_static_delta(from.as_ref(), &to, &DeltaOptions::default())
                .await
                .unwrap();
        }
        let absent = Checksum::sha256(b"absent");
        for commit in [f.c1, f.c3, absent] {
            std::fs::create_dir_all(f.local.path().join("state")).unwrap();
            std::fs::write(
                f.local
                    .path()
                    .join(format!("state/{}.commitpartial", commit.to_hex())),
                [0x66],
            )
            .unwrap();
        }
        for (ty, commit) in [
            (ObjectType::CommitMeta, f.c1),
            (ObjectType::ComposefsImage, f.c1),
            (ObjectType::CommitMeta, absent),
            (ObjectType::TombstoneCommit, absent),
        ] {
            let path = f.local.path().join(object_path(ty, &commit));
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, format!("sidecar {ty:?}")).unwrap();
        }
        for sub in ["objects", "deltas", "state"] {
            f.copy(sub);
        }
        (f, loose)
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

    /// Returns each key under `sub/` of the repository, without the prefix
    /// of the repository.
    fn keys(&self, sub: &str) -> BTreeSet<String> {
        let prefix = format!("repo/{sub}/");
        self.server
            .state()
            .objects
            .keys()
            .filter(|key| key.starts_with(&prefix))
            .map(|key| key["repo/".len()..].to_owned())
            .collect()
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

    /// Returns the key of each `DELETE`, in order. The request path holds a
    /// `+` of a delta key as `%2B`.
    fn deletes(&self) -> Vec<String> {
        self.requests()
            .into_iter()
            .filter(|(method, _)| method == "DELETE")
            .map(|(_, key)| key.replace("%2B", "+"))
            .collect()
    }

    /// Runs the prune with `opts`.
    async fn prune(&self, opts: &PruneOptions) -> ostrya::Result<BucketPruneReport> {
        self.bucket
            .prune(opts, &BucketPruneOptions::default())
            .await
    }

    /// Returns the bucket keys of the objects that `roots` reach in the
    /// local repository with `depth` parents.
    async fn reachable(&self, roots: &[Checksum], depth: i32) -> BTreeSet<String> {
        self.local
            .traverse_reachable(roots.iter().copied(), depth)
            .await
            .unwrap()
            .into_iter()
            .map(|name| object_path(name.ty, &name.checksum))
            .collect()
    }

    /// Sets the local ref `branch` to `commit`.
    async fn set_local_ref(&self, branch: &str, commit: &Checksum) {
        let txn = self.local.transaction().await.unwrap();
        txn.set_ref(branch, Some(commit));
        txn.commit().await.unwrap();
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

/// Returns the options of a run on the refs alone with `depth`.
fn refs_only(depth: i32) -> PruneOptions {
    PruneOptions {
        refs_only: true,
        depth,
        ..PruneOptions::default()
    }
}

/// Returns the key of the object of `ty` and `checksum`.
fn key(ty: ObjectType, checksum: &Checksum) -> String {
    object_path(ty, checksum)
}

/// Returns the position of `key` in `deletes`.
fn at(deletes: &[String], key: &str) -> usize {
    deletes
        .iter()
        .position(|deleted| deleted == key)
        .unwrap_or_else(|| panic!("no DELETE of {key}: {deletes:?}"))
}

/// Copies the directory `from` to `to`, with each file and symlink.
fn copy_dir(from: &Path, to: &Path) {
    let status = std::process::Command::new("cp")
        .arg("-a")
        .arg(from)
        .arg(to)
        .status()
        .unwrap();
    assert!(status.success(), "cp -a {}", from.display());
}

/// Pulls `refs` from the bucket of `f` into a new `archive` repository, and
/// returns it.
async fn pull(f: &Fixture, server: &str, refs: &[&str]) -> Repo {
    let path = f.tmp.path().join(format!("pulled-{}", refs.join("-")));
    let repo = Repo::create(&path, CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap();
    let session = PullSession::connect(
        Endpoint::S3(endpoint(server, ADDRESS)),
        StreamSessionOptions::default(),
    )
    .await
    .unwrap();
    let opts = PullOptions {
        refs: refs.iter().map(|r| (*r).to_owned()).collect(),
        ..PullOptions::default()
    };
    repo.pull_with_session(session, PullTrust::unverified(), opts)
        .await
        .unwrap();
    repo
}

/// Asserts that a fsck of the bucket finds no error.
async fn assert_fsck_clean(bucket: &BucketRepo) {
    let report = bucket.fsck(&BucketFsckOptions::default()).await.unwrap();
    assert!(!report.has_errors(), "{:#?}", report.findings);
}

// ---------------------------------------------------------------------------
// The objects that a run deletes.
// ---------------------------------------------------------------------------

#[test]
fn a_prune_after_a_ref_move_deletes_the_old_commits_and_a_pull_works() {
    block_on(async {
        let f = Fixture::new(None).await;
        let before = f.keys("objects");
        let report = f.prune(&refs_only(0)).await.unwrap();
        let kept = f.reachable(&[f.c3, f.s1], 0).await;
        assert_eq!(f.keys("objects"), kept);
        for commit in [f.c1, f.c2] {
            assert!(!kept.contains(&key(ObjectType::Commit, &commit)));
        }
        let gone: BTreeSet<String> = before.difference(&kept).cloned().collect();
        assert_eq!(report.stats.pruned_objects, gone.len());
        assert_eq!(report.stats.total_objects, before.len());
        assert!(report.stats.deleted_refs.is_empty());
        assert!(report.deleted_deltas.is_empty());
        assert!(report.broken_lock.is_none());
        assert!(f.get("extensions/ostrya/lock").is_none());
        assert_fsck_clean(&f.bucket).await;
        let pulled = pull(&f, &f.server.endpoint(), &["main", "side"]).await;
        assert_eq!(pulled.resolve_rev("main", false).await.unwrap(), Some(f.c3));
        if common::ostree_available() {
            let dir = f.tmp.path().join("dump");
            f.server.dump("repo", &dir);
            common::tool_fsck(&dir);
        } else {
            eprintln!("skipping the ostree fsck of the pruned bucket: ostree is not installed");
        }
        // A second run finds nothing.
        let report = f.prune(&refs_only(0)).await.unwrap();
        assert_eq!(report.stats.pruned_objects, 0);
        assert_eq!(report.stats.freed_bytes, 0);
    });
}

#[test]
fn a_run_deletes_what_the_local_prune_deletes() {
    type Kept = fn(&Fixture, Checksum) -> Vec<Checksum>;
    let cases: Vec<(&str, PruneOptions, Kept)> = vec![
        ("default", PruneOptions::default(), |f, loose| {
            vec![f.c1, f.c2, f.c3, f.s1, loose]
        }),
        ("refs_only", refs_only(-1), |f, _| {
            vec![f.c1, f.c2, f.c3, f.s1]
        }),
        ("depth 0", refs_only(0), |f, _| vec![f.c3, f.s1]),
        ("depth 1", refs_only(1), |f, _| vec![f.c1, f.c2, f.c3, f.s1]),
        ("depth -2", refs_only(-2), |f, _| vec![f.c3, f.s1]),
        (
            "keep_younger_than",
            PruneOptions {
                keep_younger_than: Some(T0 + 120),
                ..PruneOptions::default()
            },
            |f, _| vec![f.c3, f.s1],
        ),
        // `c2` is younger than the bound, and `c1` is older.
        (
            "keep_younger_than over a parent",
            PruneOptions {
                keep_younger_than: Some(T0 + 50),
                ..PruneOptions::default()
            },
            |f, _| vec![f.c2, f.c3, f.s1],
        ),
        // Each ref target is older than the bound.
        (
            "keep_younger_than after each ref",
            PruneOptions {
                keep_younger_than: Some(T0 + 250),
                ..PruneOptions::default()
            },
            |f, _| vec![f.c3, f.s1],
        ),
    ];
    for (case, opts, kept) in cases {
        block_on(async {
            let (f, loose) = Fixture::rich().await;
            let copy = f.tmp.path().join("copy");
            copy_dir(f.local.path(), &copy);
            let local = Repo::open(&copy).await.unwrap();
            let stats = local.prune(&opts).await.unwrap();
            let report = f.prune(&opts).await.unwrap();
            assert_eq!(report.stats, stats, "{case}");
            for sub in ["objects", "deltas", "state"] {
                let local: BTreeSet<String> = common::file_inventory(&copy, sub)
                    .into_iter()
                    .map(|(name, _)| name)
                    .collect();
                assert_eq!(f.keys(sub), local, "{case}: {sub}");
            }
            let commits: BTreeSet<String> = f
                .keys("objects")
                .into_iter()
                .filter(|key| key.ends_with(".commit"))
                .collect();
            let expected: BTreeSet<String> = kept(&f, loose)
                .iter()
                .map(|commit| key(ObjectType::Commit, commit))
                .collect();
            assert_eq!(commits, expected, "{case}");
        });
    }
    // A parent commit that the listing does not hold: without the roots on
    // the refs alone, the run deletes its detached metadata and its
    // composefs image, which the local prune keeps.
    block_on(async {
        let (f, _) = Fixture::rich().await;
        let commit = key(ObjectType::Commit, &f.c1);
        f.remove(&commit);
        std::fs::remove_file(f.local.path().join(&commit)).unwrap();
        let copy = f.tmp.path().join("copy");
        copy_dir(f.local.path(), &copy);
        let local = Repo::open(&copy).await.unwrap();
        let opts = PruneOptions::default();
        let stats = local.prune(&opts).await.unwrap();
        let report = f.prune(&opts).await.unwrap();
        assert_eq!(report.stats, stats);
        let sidecars: BTreeSet<String> = [ObjectType::CommitMeta, ObjectType::ComposefsImage]
            .iter()
            .map(|ty| key(*ty, &f.c1))
            .collect();
        let deletes = f.deletes();
        for sidecar in &sidecars {
            assert!(f.get(sidecar).is_none(), "{sidecar}");
            at(&deletes, sidecar);
        }
        for sub in ["objects", "deltas", "state"] {
            let mut local: BTreeSet<String> = common::file_inventory(&copy, sub)
                .into_iter()
                .map(|(name, _)| name)
                .collect();
            if sub == "objects" {
                for sidecar in &sidecars {
                    assert!(local.remove(sidecar), "{sidecar}");
                }
            }
            assert_eq!(f.keys(sub), local, "{sub}");
        }
    });
}

#[test]
fn a_dry_run_takes_the_lock_deletes_nothing_and_gives_the_counts_of_a_run() {
    block_on(async {
        let (f, _) = Fixture::rich().await;
        let upload = format!(
            "repo/{}",
            key(ObjectType::File, &Checksum::sha256(b"upload"))
        );
        f.server
            .state()
            .uploads
            .push((upload, "u1".into(), "t".into()));
        let before = f.snapshot();
        let opts = PruneOptions {
            no_prune: true,
            ..refs_only(0)
        };
        let dry = f.prune(&opts).await.unwrap();
        assert_eq!(f.snapshot(), before);
        assert_eq!(f.deletes(), ["extensions/ostrya/lock"]);
        assert!(
            f.requests()
                .iter()
                .any(|(method, key)| method == "PUT" && key == "extensions/ostrya/lock")
        );
        assert_eq!(f.server.state().uploads.len(), 1);
        let real = f.prune(&refs_only(0)).await.unwrap();
        assert_eq!(dry, real);
        assert!(real.stats.pruned_objects > 0);
        assert_eq!(real.deleted_deltas.len(), 1);
        assert_eq!(real.deleted_markers.len(), 2);
        assert_eq!(real.aborted_uploads.len(), 1);
    });
}

#[test]
fn a_stray_key_stays() {
    block_on(async {
        let f = Fixture::new(None).await;
        let strays = [
            "objects/abc".to_owned(),
            "objects/zz/x".to_owned(),
            format!("objects/ab/{}.file", "cd".repeat(31)),
        ];
        for stray in &strays {
            f.put(stray, b"stray");
        }
        f.prune(&refs_only(0)).await.unwrap();
        for stray in &strays {
            assert_eq!(f.get(stray), Some(b"stray".to_vec()), "{stray}");
        }
    });
}

#[test]
fn an_interrupted_run_leaves_a_usable_bucket_and_a_second_run_completes_it() {
    let expected = block_on(async {
        let f = Fixture::new(None).await;
        f.prune(&refs_only(0)).await.unwrap();
        f.keys("objects")
    });
    for n in [1, 2, 3, 5, 6] {
        block_on(async {
            let f = Fixture::new(None).await;
            f.server.state().refuse_from = Some(("DELETE", "repo/objects/".to_owned(), n));
            let err = f.prune(&refs_only(0)).await.unwrap_err();
            assert!(
                matches!(
                    &err,
                    Error::Remote(ostrya::remote::Error::S3 { status: 403, .. })
                ),
                "{n}: {err}"
            );
            assert!(f.get("extensions/ostrya/lock").is_none(), "{n}");
            assert_fsck_clean(&f.bucket).await;
            f.server.state().refuse_from = None;
            f.prune(&refs_only(0)).await.unwrap();
            assert_eq!(f.keys("objects"), expected, "{n}");
        });
    }
}

#[test]
fn each_incomplete_upload_of_the_repository_is_aborted() {
    block_on(async {
        let f = Fixture::new(None).await;
        let own = key(ObjectType::File, &Checksum::sha256(b"upload"));
        {
            let mut state = f.server.state();
            state
                .uploads
                .push((format!("repo/{own}"), "u2".into(), "t2".into()));
            state
                .uploads
                .push((format!("repo/{own}"), "u1".into(), "t1".into()));
            state
                .uploads
                .push((format!("repo2/{own}"), "u3".into(), "t3".into()));
        }
        let report = f.prune(&PruneOptions::default()).await.unwrap();
        let aborted: Vec<(String, String)> = report
            .aborted_uploads
            .iter()
            .map(|upload| (upload.key.clone(), upload.upload_id.clone()))
            .collect();
        assert_eq!(
            aborted,
            [
                (own.clone(), "u1".to_owned()),
                (own.clone(), "u2".to_owned())
            ]
        );
        let left = f.server.state().uploads.clone();
        assert_eq!(left, [(format!("repo2/{own}"), "u3".into(), "t3".into())]);
        assert!(f.get(&own).is_none());
    });
}

#[test]
fn the_deltas_of_absent_targets_go_with_the_superblock_first() {
    block_on(async {
        let (f, _) = Fixture::rich().await;
        let absent = Checksum::sha256(b"no superblock");
        let b64 = absent.to_base64_modified();
        let bare = format!("deltas/{}/{}/0", &b64[..2], &b64[2..]);
        f.put(&bare, b"part");
        f.put("deltas/!!/bad/superblock", b"undecodable");
        let index = format!("delta-indexes/{}/{}.index", &b64[..2], &b64[2..]);
        f.put(&index, b"index");
        f.local
            .regenerate_summary(&SummaryOptions::default())
            .await
            .unwrap();
        let summary = std::fs::read(f.local.path().join("summary")).unwrap();
        f.put("summary", &summary);
        let report = f.prune(&refs_only(0)).await.unwrap();
        let mut names = vec![f.c1.to_hex(), absent.to_hex()];
        names.sort();
        assert_eq!(report.deleted_deltas, names);
        let c1 = f.c1.to_base64_modified();
        let dir = format!("deltas/{}/{}/", &c1[..2], &c1[2..]);
        let deletes = f.deletes();
        let superblock = at(&deletes, &format!("{dir}superblock"));
        let parts: Vec<&String> = deletes
            .iter()
            .filter(|key| key.starts_with(&dir) && !key.ends_with("superblock"))
            .collect();
        assert!(!parts.is_empty());
        for part in parts {
            assert!(superblock < at(&deletes, part), "{deletes:?}");
        }
        assert!(f.get(&bare).is_none());
        let deltas = f.keys("deltas");
        assert!(deltas.contains("deltas/!!/bad/superblock"), "{deltas:?}");
        let c3 = f.c3.to_base64_modified();
        assert!(
            deltas
                .iter()
                .any(|key| key.ends_with(&format!("-{c3}/superblock"))),
            "{deltas:?}"
        );
        assert!(deltas.iter().all(|key| !key.starts_with(&dir)));
        assert_eq!(f.get(&index), Some(b"index".to_vec()));
        assert_eq!(f.get("summary"), Some(summary));
    });
}

#[test]
fn a_summary_update_after_a_prune_names_no_deleted_delta() {
    block_on(async {
        let (f, _) = Fixture::rich().await;
        f.local
            .regenerate_summary(&SummaryOptions::default())
            .await
            .unwrap();
        let summary = std::fs::read(f.local.path().join("summary")).unwrap();
        f.put("summary", &summary);
        let report = f.prune(&refs_only(0)).await.unwrap();
        assert_eq!(report.deleted_deltas, [f.c1.to_hex()]);
        let advertised = |f: &Fixture| -> Vec<Checksum> {
            Summary::parse(&f.get("summary").unwrap())
                .unwrap()
                .static_deltas()
                .unwrap()
                .into_iter()
                .map(|delta| delta.to)
                .collect()
        };
        assert!(advertised(&f).contains(&f.c1));
        f.bucket
            .update_summary(&BucketSummaryOptions::default())
            .await
            .unwrap();
        assert_eq!(advertised(&f), [f.c3]);
        let report = f.bucket.fsck(&BucketFsckOptions::default()).await.unwrap();
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.kind == ostrya::bucket::BucketFindingKind::Summary),
            "{:#?}",
            report.findings
        );
    });
}

#[test]
fn the_markers_of_absent_commits_go_after_their_commits() {
    block_on(async {
        let (f, _) = Fixture::rich().await;
        f.put("state/other", b"other");
        // The tree of the kept partial commit misses an object.
        f.remove(&key(ObjectType::File, &file_of(&f, &f.c3).await));
        let report = f.prune(&refs_only(0)).await.unwrap();
        let absent = Checksum::sha256(b"absent");
        let mut markers = vec![f.c1, absent];
        markers.sort();
        assert_eq!(report.deleted_markers, markers);
        let deletes = f.deletes();
        assert!(
            at(&deletes, &key(ObjectType::Commit, &f.c1))
                < at(&deletes, &format!("state/{}.commitpartial", f.c1.to_hex()))
        );
        let state = f.keys("state");
        assert_eq!(
            state,
            [
                format!("state/{}.commitpartial", f.c3.to_hex()),
                "state/other".to_owned()
            ]
            .into_iter()
            .collect()
        );
    });
}

/// Returns the file object of the file `file` of the root of `commit`.
async fn file_of(f: &Fixture, commit: &Checksum) -> Checksum {
    let (parsed, _) = f.local.load_commit(commit).await.unwrap();
    let tree = f.local.load_dirtree(&parsed.root_dirtree).await.unwrap();
    tree.files
        .iter()
        .find(|(name, _)| name == "file")
        .map(|(_, checksum)| *checksum)
        .unwrap()
}

#[test]
fn the_sidecars_go_after_their_commit_and_the_counts_leave_them_out() {
    block_on(async {
        let (f, _) = Fixture::rich().await;
        let absent = Checksum::sha256(b"absent");
        let counted = |key: &String| {
            key.starts_with("objects/")
                && !key.ends_with(".commitmeta")
                && !key.ends_with(".cfs")
                && !key.ends_with(".tombstone-commit")
        };
        let total = f.keys("objects").iter().filter(|key| counted(key)).count();
        let report = f.prune(&refs_only(0)).await.unwrap();
        let deletes = f.deletes();
        let commit = at(&deletes, &key(ObjectType::Commit, &f.c1));
        let meta = at(&deletes, &key(ObjectType::CommitMeta, &f.c1));
        let image = at(&deletes, &key(ObjectType::ComposefsImage, &f.c1));
        assert!(commit < meta && meta < image, "{deletes:?}");
        at(&deletes, &key(ObjectType::CommitMeta, &absent));
        let tombstone = key(ObjectType::TombstoneCommit, &absent);
        assert!(f.get(&tombstone).is_some());
        assert!(!deletes.contains(&tombstone));
        assert_eq!(
            report.stats.pruned_objects,
            deletes.iter().filter(|key| counted(key)).count()
        );
        assert_eq!(report.stats.total_objects, total);
    });
}

// ---------------------------------------------------------------------------
// Refusals, the lock, and the walk.
// ---------------------------------------------------------------------------

#[test]
fn each_refused_option_fails_before_a_request() {
    block_on(async {
        let f = Fixture::new(None).await;
        let before = f.snapshot();
        let cases: Vec<(&str, PruneOptions)> = vec![
            (
                "delete_commit",
                PruneOptions {
                    delete_commit: Some(f.c1),
                    ..PruneOptions::default()
                },
            ),
            (
                "only_branch",
                PruneOptions {
                    only_branch: vec!["main".into()],
                    ..PruneOptions::default()
                },
            ),
            (
                "retain_branch_depth",
                PruneOptions {
                    retain_branch_depth: vec![("main".into(), 1)],
                    ..PruneOptions::default()
                },
            ),
            (
                "commit_only",
                PruneOptions {
                    commit_only: true,
                    ..PruneOptions::default()
                },
            ),
            (
                "static_deltas_only",
                PruneOptions {
                    static_deltas_only: true,
                    ..PruneOptions::default()
                },
            ),
            (
                "gc_root_metadata_keys",
                PruneOptions {
                    gc_root_metadata_keys: vec!["k".into()],
                    ..PruneOptions::default()
                },
            ),
            (
                "traverse_parent",
                PruneOptions {
                    traverse_parent: false,
                    ..PruneOptions::default()
                },
            ),
            (
                "weak_ref_filter",
                PruneOptions {
                    refs_only: true,
                    weak_ref_filter: WeakRefFilter::new(|_, _| true),
                    ..PruneOptions::default()
                },
            ),
        ];
        for (field, opts) in cases {
            let err = f.prune(&opts).await.unwrap_err();
            assert!(
                matches!(&err, Error::InvalidInput(m) if m.contains(&format!("option {field};"))),
                "{field}: {err}"
            );
        }
        let mut break_lock = BucketPruneOptions::default();
        break_lock.break_lock = true;
        let dry = PruneOptions {
            no_prune: true,
            ..refs_only(0)
        };
        let err = f.bucket.prune(&dry, &break_lock).await.unwrap_err();
        assert!(
            matches!(&err, Error::InvalidInput(m)
                if m.contains("break_lock") && m.contains("no_prune")),
            "{err}"
        );
        // A refused field of the prune options comes first.
        let refused = PruneOptions {
            commit_only: true,
            no_prune: true,
            ..PruneOptions::default()
        };
        let err = f.bucket.prune(&refused, &break_lock).await.unwrap_err();
        assert!(
            matches!(&err, Error::InvalidInput(m)
                if m.contains("option commit_only;") && !m.contains("break_lock")),
            "{err}"
        );
        assert!(f.server.state().requests.is_empty());
        assert_eq!(f.snapshot(), before);
        // Without the break, the dry run takes the lock and fails on it.
        f.server.state().store(LOCK, DEAD_LOCK.as_bytes());
        let err = f.prune(&dry).await.unwrap_err();
        assert!(matches!(err, Error::BucketLocked { .. }), "{err}");
    });
}

#[test]
fn a_bucket_with_no_config_or_a_refused_config_takes_no_lock() {
    block_on(async {
        let f = Fixture::new(None).await;
        f.remove("config");
        let before = f.snapshot();
        let err = f.prune(&refs_only(0)).await.unwrap_err();
        assert!(
            matches!(&err, Error::Remote(ostrya::remote::Error::InvalidInput(m))
                if m.ends_with("has no config; init it first")),
            "{err}"
        );
        for (config, words) in [
            (
                format!("{PLAIN}tombstone-commits=true\n"),
                "tombstone-commits",
            ),
            (
                format!("{PLAIN}\n[ex-ostrya]\ngc-root-metadata-keys=\n"),
                "gc-root-metadata-keys",
            ),
        ] {
            f.put("config", config.as_bytes());
            f.server.state().requests.clear();
            let err = f.prune(&refs_only(0)).await.unwrap_err();
            assert!(
                matches!(&err, Error::Remote(ostrya::remote::Error::InvalidInput(m))
                    if m.contains(words)),
                "{err}"
            );
            assert_eq!(f.requests(), [("GET".to_owned(), "config".to_owned())]);
        }
        f.remove("config");
        assert_eq!(f.snapshot(), before);
        // `tombstone-commits=false` is no refusal.
        f.put(
            "config",
            format!("{PLAIN}tombstone-commits=false\n").as_bytes(),
        );
        f.prune(&refs_only(0)).await.unwrap();
    });
}

#[test]
fn a_bad_ref_key_fails_the_run_before_a_delete_and_releases_the_lock() {
    block_on(async {
        for id in [None, Some(ID)] {
            let f = Fixture::new(id).await;
            let bad = match id {
                None => "refs/remotes/origin/main".to_owned(),
                Some(id) => format!("refs/mirrors/{id}/main"),
            };
            f.put_ref(&bad, &f.c3);
            let before = f.snapshot();
            let err = f.prune(&refs_only(0)).await.unwrap_err();
            assert!(
                matches!(&err, Error::InvalidFormat(m) if m.contains(&bad)),
                "{err}"
            );
            assert_eq!(f.snapshot(), before);
            assert!(
                f.deletes()
                    .iter()
                    .all(|key| key == "extensions/ostrya/lock")
            );
        }
    });
}

#[test]
fn the_lock_of_another_writer_fails_the_run_and_break_lock_removes_it() {
    block_on(async {
        let f = Fixture::new(None).await;
        f.server.state().store(LOCK, DEAD_LOCK.as_bytes());
        let err = f.prune(&refs_only(0)).await.unwrap_err();
        assert!(matches!(err, Error::BucketLocked { .. }), "{err}");
        assert!(f.deletes().is_empty());
        let mut opts = BucketPruneOptions::default();
        opts.break_lock = true;
        let report = f.bucket.prune(&refs_only(0), &opts).await.unwrap();
        let holder = report.broken_lock.unwrap();
        assert_eq!(holder.id.as_deref(), Some("9".repeat(64).as_str()));
        assert!(report.stats.pruned_objects > 0);
        assert!(f.get("extensions/ostrya/lock").is_none());
    });
}

#[test]
fn a_lock_broken_between_the_steps_stops_the_run() {
    block_on(async {
        let f = Fixture::new(None).await;
        f.server.state().before_key = Some((
            "DELETE",
            format!("repo/{}", key(ObjectType::Commit, &f.c1)),
            Box::new(|objects| {
                let stored = objects.get_mut(LOCK).unwrap();
                stored.bytes = DEAD_LOCK.as_bytes().to_vec();
                stored.etag = "\"replaced\"".into();
            }),
        ));
        let err = f.prune(&refs_only(0)).await.unwrap_err();
        assert!(matches!(err, Error::BucketLockLost { .. }), "{err}");
        let deletes = f.deletes();
        assert!(!deletes.is_empty());
        assert!(
            deletes.iter().all(|key| key.ends_with(".commit")),
            "{deletes:?}"
        );
        assert_eq!(f.get("extensions/ostrya/lock"), Some(DEAD_LOCK.into()));
    });
}

#[test]
fn a_refused_read_of_a_dirtree_fails_the_run_before_a_delete() {
    block_on(async {
        let f = Fixture::new(None).await;
        let (parsed, _) = f.local.load_commit(&f.c3).await.unwrap();
        f.server.state().refuse = Some((
            "GET",
            format!("repo/{}", key(ObjectType::DirTree, &parsed.root_dirtree)),
        ));
        let before = f.snapshot();
        let err = f.prune(&refs_only(0)).await.unwrap_err();
        assert!(
            matches!(
                &err,
                Error::Remote(ostrya::remote::Error::S3 { status: 403, .. })
            ),
            "{err}"
        );
        assert_eq!(f.snapshot(), before);
        assert_eq!(f.deletes(), ["extensions/ostrya/lock"]);
    });
}

#[test]
fn an_object_whose_bytes_do_not_match_its_name_fails_the_run_before_a_delete() {
    block_on(async {
        let f = Fixture::new(None).await;
        let other = f.get(&key(ObjectType::Commit, &f.c1)).unwrap();
        f.put(&key(ObjectType::Commit, &f.c2), &other);
        let before = f.snapshot();
        let err = f.prune(&PruneOptions::default()).await.unwrap_err();
        assert!(
            matches!(&err, Error::InvalidFormat(m)
                if m.contains(&key(ObjectType::Commit, &f.c2))
                    && m.contains("ostrya remote fsck --delete")),
            "{err}"
        );
        assert_eq!(f.snapshot(), before);
        assert_eq!(f.deletes(), ["extensions/ostrya/lock"]);
        // A dirtree too.
        let f = Fixture::new(None).await;
        let (parsed, _) = f.local.load_commit(&f.c3).await.unwrap();
        let (first, _) = f.local.load_commit(&f.c1).await.unwrap();
        let other = f
            .get(&key(ObjectType::DirTree, &first.root_dirtree))
            .unwrap();
        f.put(&key(ObjectType::DirTree, &parsed.root_dirtree), &other);
        let err = f.prune(&refs_only(0)).await.unwrap_err();
        assert!(matches!(&err, Error::InvalidFormat(_)), "{err}");
        assert_eq!(f.deletes(), ["extensions/ostrya/lock"]);
    });
}

#[test]
fn the_default_run_reads_each_commit_once_and_no_unlisted_object() {
    block_on(async {
        let f = Fixture::new(None).await;
        // A ref to an absent commit is no error.
        let absent = Checksum::sha256(b"absent commit");
        f.put_ref("refs/heads/gone", &absent);
        let report = f.prune(&PruneOptions::default()).await.unwrap();
        assert_eq!(report.stats.pruned_objects, 0);
        let gets: Vec<String> = f
            .requests()
            .into_iter()
            .filter(|(method, key)| method == "GET" && key.ends_with(".commit"))
            .map(|(_, key)| key)
            .collect();
        let mut expected: Vec<String> = [f.c1, f.c2, f.c3, f.s1]
            .iter()
            .map(|commit| key(ObjectType::Commit, commit))
            .collect();
        expected.sort();
        let mut sorted = gets.clone();
        sorted.sort();
        assert_eq!(sorted, expected);
        let absent_key = key(ObjectType::Commit, &absent);
        assert!(!f.requests().iter().any(|(_, key)| *key == absent_key));
        // On the refs alone, an unlisted parent gets no read either.
        f.remove(&key(ObjectType::Commit, &f.c1));
        f.server.state().requests.clear();
        f.prune(&refs_only(-1)).await.unwrap();
        let c1 = key(ObjectType::Commit, &f.c1);
        assert!(!f.requests().iter().any(|(_, key)| *key == c1));
    });
}

#[test]
fn a_run_on_the_refs_alone_reads_a_ref_target_of_the_summary_once() {
    let cases: Vec<(&str, PruneOptions)> = vec![
        ("refs_only", refs_only(-1)),
        ("depth 1", refs_only(1)),
        (
            "keep_younger_than",
            PruneOptions {
                keep_younger_than: Some(T0 + 120),
                ..PruneOptions::default()
            },
        ),
    ];
    for (case, opts) in cases {
        block_on(async {
            let f = Fixture::new(None).await;
            // The summary names `c3` and `s1`, the commits of the refs.
            f.local
                .regenerate_summary(&SummaryOptions::default())
                .await
                .unwrap();
            let summary = std::fs::read(f.local.path().join("summary")).unwrap();
            f.put("summary", &summary);
            f.prune(&PruneOptions {
                no_prune: true,
                ..opts
            })
            .await
            .unwrap();
            let mut gets: Vec<String> = f
                .requests()
                .into_iter()
                .filter(|(method, key)| method == "GET" && key.ends_with(".commit"))
                .map(|(_, key)| key)
                .collect();
            gets.sort();
            let mut expected: Vec<String> = [f.c1, f.c2, f.c3, f.s1]
                .iter()
                .map(|commit| key(ObjectType::Commit, commit))
                .collect();
            expected.sort();
            assert_eq!(gets, expected, "{case}");
        });
    }
}

#[test]
fn the_run_checks_the_lock_once_for_each_step_with_a_change() {
    let lock_gets = |f: &Fixture| {
        f.requests()
            .iter()
            .filter(|(method, key)| method == "GET" && key == "extensions/ostrya/lock")
            .count()
    };
    block_on(async {
        // Each step has a change: the commits with an absent commit's
        // detached metadata, the other objects, the static deltas with the
        // markers, and the uploads.
        let (f, _) = Fixture::rich().await;
        let upload = format!(
            "repo/{}",
            key(ObjectType::File, &Checksum::sha256(b"upload"))
        );
        f.server
            .state()
            .uploads
            .push((upload, "u1".into(), "t".into()));
        let report = f.prune(&refs_only(0)).await.unwrap();
        assert!(!report.deleted_deltas.is_empty());
        assert!(!report.deleted_markers.is_empty());
        // One check for each of the four steps, and one read at the
        // release. The take reads no lock.
        assert_eq!(lock_gets(&f), 4 + 1);
        // The commits and the other objects alone.
        let f = Fixture::new(None).await;
        f.prune(&refs_only(0)).await.unwrap();
        assert_eq!(lock_gets(&f), 2 + 1);
    });
}

#[test]
fn the_commits_of_the_summary_are_kept_with_no_parent() {
    block_on(async {
        let f = Fixture::new(None).await;
        // The summary was written when `main` named `c2`, and `side` is gone
        // from the bucket since.
        f.set_local_ref("main", &f.c2).await;
        f.local
            .regenerate_summary(&SummaryOptions::default())
            .await
            .unwrap();
        let summary = std::fs::read(f.local.path().join("summary")).unwrap();
        f.put("summary", &summary);
        f.remove("refs/heads/side");
        // The bound of the refs keeps `c2`, the parent of `c3`, and no
        // parent of `c2`. Each commit of the summary keeps no parent, so
        // `c1`, the parent of `c2` and `s1`, goes.
        f.prune(&refs_only(1)).await.unwrap();
        for commit in [f.c2, f.c3, f.s1] {
            assert!(f.get(&key(ObjectType::Commit, &commit)).is_some());
        }
        assert!(f.get(&key(ObjectType::Commit, &f.c1)).is_none());
        assert_eq!(f.get("summary"), Some(summary));
        // A summary that does not parse fails the run before a delete.
        let f = Fixture::new(None).await;
        f.put("summary", b"not a summary");
        let before = f.snapshot();
        let err = f.prune(&refs_only(0)).await.unwrap_err();
        assert!(
            matches!(&err, Error::InvalidFormat(m) if m.contains("its summary does not parse")),
            "{err}"
        );
        assert_eq!(f.snapshot(), before);
    });
}

#[test]
fn the_commits_of_the_collection_map_of_the_summary_are_roots() {
    block_on(async {
        let f = Fixture::new(None).await;
        f.local
            .set_collection_ref_immediate(
                &CollectionRef::new("org.example.Other", "old"),
                Some(&f.c1),
            )
            .await
            .unwrap();
        f.local
            .regenerate_summary(&SummaryOptions::default())
            .await
            .unwrap();
        let summary = std::fs::read(f.local.path().join("summary")).unwrap();
        let parsed = Summary::parse(&summary).unwrap();
        assert!(parsed.refs.iter().all(|entry| entry.commit != f.c1));
        let map = parsed.collection_map().unwrap();
        assert!(
            map.iter()
                .any(|(_, entries)| entries.iter().any(|entry| entry.commit == f.c1))
        );
        f.put("summary", &summary);
        f.prune(&refs_only(0)).await.unwrap();
        for commit in [f.c1, f.c3, f.s1] {
            assert!(f.get(&key(ObjectType::Commit, &commit)).is_some());
        }
        assert!(f.get(&key(ObjectType::Commit, &f.c2)).is_none());
    });
}

#[test]
fn the_mirror_refs_of_another_collection_are_roots() {
    block_on(async {
        let f = Fixture::new(Some(ID)).await;
        f.remove("refs/heads/side");
        f.put_ref("refs/mirrors/org.example.Other/side", &f.s1);
        f.prune(&refs_only(0)).await.unwrap();
        assert_eq!(f.keys("objects"), f.reachable(&[f.c3, f.s1], 0).await);
    });
}

#[test]
fn a_time_bound_keeps_the_commit_of_each_ref_at_any_age() {
    block_on(async {
        let f = Fixture::new(None).await;
        // Each ref target is older than the bound.
        let opts = PruneOptions {
            keep_younger_than: Some(T0 + 250),
            ..PruneOptions::default()
        };
        let report = f
            .prune(&PruneOptions {
                no_prune: true,
                ..opts.clone()
            })
            .await
            .unwrap();
        let kept = f.reachable(&[f.c3, f.s1], 0).await;
        let before = f.snapshot();
        let objects: Vec<(&str, usize)> = before
            .iter()
            .filter_map(|(key, bytes)| {
                key.strip_prefix("repo/")
                    .filter(|key| key.starts_with("objects/"))
                    .map(|key| (key, bytes.len()))
            })
            .collect();
        let freed: usize = objects
            .iter()
            .filter(|(key, _)| !kept.contains(*key))
            .map(|(_, size)| size)
            .sum();
        assert_eq!(
            report.stats,
            PruneStats {
                total_objects: objects.len(),
                pruned_objects: objects.len() - kept.len(),
                freed_bytes: freed as u64,
                deleted_refs: Vec::new(),
            }
        );
        f.prune(&opts).await.unwrap();
        assert_eq!(f.keys("objects"), kept);
    });
}

// ---------------------------------------------------------------------------
// Real servers.
// ---------------------------------------------------------------------------

#[test]
fn a_prune_on_rclone_is_refused_and_writes_only_the_probe() {
    if !rclone_available("a_prune_on_rclone_is_refused_and_writes_only_the_probe") {
        return;
    }
    block_on(async {
        let f = Fixture::new(None).await;
        let root = f.tmp.path().join("served");
        let dir = root.join("bkt/repo");
        for (name, bytes) in common::file_inventory(f.local.path(), "objects") {
            let path = dir.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
        std::fs::write(dir.join("config"), PLAIN).unwrap();
        std::fs::create_dir_all(dir.join("refs/heads")).unwrap();
        std::fs::write(dir.join("refs/heads/main"), format!("{}\n", f.c3)).unwrap();
        let server = Rclone::start(f.tmp.path(), &root);
        let bucket = BucketRepo::open(&endpoint(&server.endpoint(), ADDRESS))
            .await
            .unwrap();
        let before = common::file_inventory(&root, "bkt");
        let err = bucket
            .prune(&refs_only(0), &BucketPruneOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::BucketNoExclusion { .. }), "{err}");
        let mut expected = before;
        expected.push((format!("bkt/repo/{PROBE_KEY}"), PROBE_BODY.to_vec()));
        expected.sort();
        assert_eq!(common::file_inventory(&root, "bkt"), expected);
    });
}

#[cfg(feature = "push")]
#[test]
fn the_probe_of_the_lock_is_no_finding_of_fsck_and_a_prune_keeps_it() {
    block_on(async {
        let f = Fixture::new(None).await;
        // The bucket starts empty, so the init and the push write the probe.
        f.server.state().objects.clear();
        let s3 = endpoint(&f.server.endpoint(), ADDRESS);
        f.bucket.init(None, None, false).await.unwrap();
        let opts = ostrya::RepoPushOptions {
            refspecs: vec!["main".to_owned()],
            ..ostrya::RepoPushOptions::default()
        };
        f.local.push_to_bucket(s3, opts).await.unwrap();
        assert_eq!(f.get(PROBE_KEY).as_deref(), Some(PROBE_BODY));
        // The fsck gives no finding on a key under `extensions/`.
        let report = f.bucket.fsck(&BucketFsckOptions::default()).await.unwrap();
        assert!(
            !report.has_errors()
                && !report
                    .findings
                    .iter()
                    .any(|found| found.key.starts_with("extensions/")),
            "{:#?}",
            report.findings
        );
        f.bucket
            .prune(&refs_only(0), &BucketPruneOptions::default())
            .await
            .unwrap();
        assert_eq!(f.get(PROBE_KEY).as_deref(), Some(PROBE_BODY));
    });
}

#[cfg(feature = "push")]
#[test]
fn a_prune_on_seaweedfs_after_two_pushes() {
    use common::s3::{Seaweed, seaweed_available};
    if !seaweed_available("a_prune_on_seaweedfs_after_two_pushes") {
        return;
    }
    // The start of the server runs its own `block_on`, so it comes before
    // the one of the test.
    let scratch = TmpDir::new("bucket-prune-weed");
    let server = Seaweed::start(scratch.path(), "bkt");
    block_on(async {
        let f = Fixture::new(None).await;
        let s3 = endpoint(&server.endpoint(), ADDRESS);
        let bucket = BucketRepo::open(&s3).await.unwrap();
        bucket.init(None, None, false).await.unwrap();
        let push = |refspec: &str| ostrya::RepoPushOptions {
            refspecs: vec![refspec.to_owned()],
            ..ostrya::RepoPushOptions::default()
        };
        f.set_local_ref("main", &f.c2).await;
        f.local
            .push_to_bucket(s3.clone(), push("main"))
            .await
            .unwrap();
        f.set_local_ref("main", &f.c3).await;
        f.local
            .push_to_bucket(s3.clone(), push("main"))
            .await
            .unwrap();
        let c2 = key(ObjectType::Commit, &f.c2);
        assert!(bucket.bucket().get(&c2, 1 << 20).await.unwrap().is_some());
        let report = bucket
            .prune(&refs_only(0), &BucketPruneOptions::default())
            .await
            .unwrap();
        assert!(report.stats.pruned_objects > 0);
        assert!(bucket.bucket().get(&c2, 1 << 20).await.unwrap().is_none());
        let listing = bucket.list_objects().await.unwrap();
        let listed: BTreeSet<String> = listing
            .objects
            .keys()
            .map(|name| object_path(name.ty, &name.checksum))
            .collect();
        assert_eq!(listed, f.reachable(&[f.c3], 0).await);
        assert_fsck_clean(&bucket).await;
        assert!(bucket.lock_holder().await.unwrap().is_none());
        let pulled = pull(&f, &server.endpoint(), &["main"]).await;
        assert_eq!(pulled.resolve_rev("main", false).await.unwrap(), Some(f.c3));
    });
}
