#![forbid(unsafe_code)]

//! Tests of the fsck of a bucket repository.
//!
//! Most tests build an `archive` repository with ostrya, copy its objects,
//! a `config`, and its ref files into the S3 stand-in of `common::s3`, and
//! then change the bucket. Other tests run against `rclone serve s3`, which
//! refuses each writer, and against `weed mini` of SeaweedFS. A test on a
//! real server skips when its program is absent. `OSTRYA_REQUIRE_S3` and
//! `OSTRYA_REQUIRE_SEAWEEDFS` turn each skip into a failure. One test runs
//! `ostree fsck` on a dump of the stand-in, and skips when `ostree` is
//! absent. `OSTRYA_REQUIRE_OSTREE` turns that skip into a failure.

#![cfg(feature = "s3")]

mod common;

use std::collections::BTreeSet;
use std::os::fd::AsFd;
use std::path::Path;
use std::sync::Arc;

use common::TmpDir;
use common::modes::object_path;
use common::s3::{Rclone, StandIn, endpoint, rclone_available};
use ostrya::bucket::{
    BucketFinding, BucketFindingKind, BucketFsckOptions, BucketFsckReport, BucketRepo,
    BucketSummaryOptions,
};
use ostrya::verify::TrustedKeys;
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, DeltaOptions,
    Ed25519Signer, Ed25519Verifier, Error, FsckErrorKind, FsckOptions, MutableTree, ObjectName,
    ObjectType, Repo, RepoMode, Signer, SummaryOptions,
};
use ostrya_rt::block_on;

use BucketFindingKind::{
    Config, Corrupt, Lock, Marker, Mismatch, Missing, Ref, Stray, Summary, Upload,
};

/// The address of the repository in each test.
const ADDRESS: &str = "s3://bkt/repo";

/// The key of the writer lock in the bucket.
const LOCK: &str = "repo/extensions/ostrya/lock";

/// The config of a bucket repository with no collection id.
const PLAIN: &str = "[core]\nrepo_version=1\nmode=archive-z2\n";

/// The collection id of the tests with one.
const ID: &str = "org.example.Os";

/// A fixed ed25519 key that signs the summary.
const SECRET_B64: &str =
    "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";

/// The body of a lock of a writer that ended with no release.
const DEAD_LOCK: &str = "[lock]\nid=9999999999999999999999999999999999999999999999999999999999999999\n\
                         host=deadhost\npid=99\noperation=push\nstarted=1700000000\n";

/// A local repository and the copy of its files in a bucket.
struct Fixture {
    tmp: TmpDir,
    local: Repo,
    server: StandIn,
    bucket: BucketRepo,
    /// The first commit of `main`, and the parent of the two others.
    first: Checksum,
    /// The tip of `main`.
    head: Checksum,
    /// The tip of `side`.
    side: Checksum,
}

impl Fixture {
    /// Builds the repository, and copies its objects, a `config` with the
    /// collection id `id`, and the ref files of `main` and `side` into a new
    /// stand-in.
    async fn new(id: Option<&str>) -> Fixture {
        let tmp = TmpDir::new("bucket-fsck");
        let local = Repo::create(
            &tmp.path().join("repo"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let first = commit(&local, tmp.path(), "main", "first", None).await;
        let head = commit(&local, tmp.path(), "main", "head", Some(first)).await;
        let side = commit(&local, tmp.path(), "side", "side", Some(first)).await;
        let server = StandIn::start();
        let fixture = Fixture {
            bucket: BucketRepo::open(&endpoint(&server.endpoint(), ADDRESS))
                .await
                .unwrap(),
            tmp,
            local,
            server,
            first,
            head,
            side,
        };
        fixture.copy("objects");
        let mut config = PLAIN.to_owned();
        if let Some(id) = id {
            config.push_str(&format!("collection-id={id}\n"));
        }
        fixture.put("config", config.as_bytes());
        fixture.put_ref("refs/heads/main", &head);
        fixture.put_ref("refs/heads/side", &side);
        fixture
    }

    /// Copies each file under `sub` of the local repository into the bucket.
    fn copy(&self, sub: &str) {
        for (name, bytes) in common::file_inventory(self.local.path(), sub) {
            self.put(&name, &bytes);
        }
    }

    /// Copies the file `name` of the local repository into the bucket.
    fn copy_file(&self, name: &str) {
        self.put(name, &std::fs::read(self.local.path().join(name)).unwrap());
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

    /// Writes `bytes` in place of the object of `ty` and `checksum` in the
    /// bucket.
    fn replace(&self, ty: ObjectType, checksum: &Checksum, bytes: &[u8]) {
        self.put(&object_path(ty, checksum), bytes);
    }

    /// Writes `bytes` in place of the object of `ty` and `checksum` in the
    /// bucket and in the local repository.
    fn replace_both(&self, ty: ObjectType, checksum: &Checksum, bytes: &[u8]) {
        let path = object_path(ty, checksum);
        std::fs::write(self.local.path().join(&path), bytes).unwrap();
        self.put(&path, bytes);
    }

    /// Returns the bytes of the object of `ty` and `checksum` in the bucket.
    fn object(&self, ty: ObjectType, checksum: &Checksum) -> Vec<u8> {
        self.get(&object_path(ty, checksum)).unwrap()
    }

    /// Removes the object of `ty` and `checksum` from the bucket.
    fn remove(&self, ty: ObjectType, checksum: &Checksum) {
        let key = format!("repo/{}", object_path(ty, checksum));
        assert!(self.server.state().objects.remove(&key).is_some(), "{key}");
    }

    /// Runs the fsck with no option.
    async fn fsck(&self) -> BucketFsckReport {
        self.bucket
            .fsck(&BucketFsckOptions::default())
            .await
            .unwrap()
    }

    /// Runs the fsck with `delete`.
    async fn repair(&self) -> ostrya::Result<BucketFsckReport> {
        let mut opts = BucketFsckOptions::default();
        opts.delete = true;
        self.bucket.fsck(&opts).await
    }

    /// Returns the object of the entry `name` of the dirtree at `path`
    /// under the root of `commit`: a file, or a dirtree if `dir` is set.
    async fn entry(&self, commit: &Checksum, path: &[&str], name: &str, dir: bool) -> Checksum {
        let (parsed, _) = self.local.load_commit(commit).await.unwrap();
        let mut tree = parsed.root_dirtree;
        for part in path {
            tree = self.subtree(&tree, part).await;
        }
        if dir {
            return self.subtree(&tree, name).await;
        }
        let tree = self.local.load_dirtree(&tree).await.unwrap();
        tree.files
            .iter()
            .find(|(file, _)| file == name)
            .map(|(_, checksum)| *checksum)
            .unwrap()
    }

    /// Returns the dirtree of the directory `name` in the dirtree `tree`.
    async fn subtree(&self, tree: &Checksum, name: &str) -> Checksum {
        let tree = self.local.load_dirtree(tree).await.unwrap();
        tree.dirs
            .iter()
            .find(|(dir, _, _)| dir == name)
            .map(|(_, tree, _)| *tree)
            .unwrap()
    }

    /// Returns the root dirtree of `commit`.
    async fn root(&self, commit: &Checksum) -> Checksum {
        self.local.load_commit(commit).await.unwrap().0.root_dirtree
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
}

/// Commits a tree with the file `file`, which holds `content`, the
/// symlink `link` to `file`, and the directory `sub/deep`, which is the same
/// in each commit. Sets the ref `branch` to the commit.
async fn commit(
    repo: &Repo,
    base: &Path,
    branch: &str,
    content: &str,
    parent: Option<Checksum>,
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
                timestamp: Some(1_700_000_000),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    txn.set_ref(branch, Some(&checksum));
    txn.commit().await.unwrap();
    checksum
}

/// Returns the kind, the key, and the error flag of each finding.
fn kinds(report: &BucketFsckReport) -> Vec<(BucketFindingKind, String, bool)> {
    report
        .findings
        .iter()
        .map(|finding| (finding.kind, finding.key.clone(), finding.error))
        .collect()
}

/// Returns the finding of `kind` on the object of `ty` and `checksum`.
fn finding<'r>(
    report: &'r BucketFsckReport,
    kind: BucketFindingKind,
    ty: ObjectType,
    checksum: &Checksum,
) -> &'r BucketFinding {
    let name = ObjectName::new(*checksum, ty);
    report
        .findings
        .iter()
        .find(|finding| finding.kind == kind && finding.object == Some(name))
        .unwrap_or_else(|| panic!("no {kind} finding on {name}: {:#?}", report.findings))
}

/// Returns the findings of the report other than the note of a bucket with
/// no summary.
fn without_summary_note(report: &BucketFsckReport) -> Vec<&BucketFinding> {
    report
        .findings
        .iter()
        .filter(|finding| finding.kind != Summary || finding.error)
        .collect()
}

/// Returns `commits`, sorted.
fn sorted(commits: &[Checksum]) -> Vec<Checksum> {
    let mut commits = commits.to_vec();
    commits.sort();
    commits
}

/// Returns the signer of [`SECRET_B64`].
fn signer() -> Ed25519Signer {
    Ed25519Signer::from_base64(SECRET_B64).unwrap()
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

// ---------------------------------------------------------------------------
// A clean bucket, and the counts.
// ---------------------------------------------------------------------------

#[test]
fn a_clean_bucket_gives_the_counts_of_the_local_repository() {
    block_on(async {
        let f = Fixture::new(None).await;
        let inventory = common::file_inventory(f.local.path(), "objects");
        let report = f.fsck().await;
        assert!(!report.has_errors(), "{:#?}", report.findings);
        assert_eq!(
            kinds(&report),
            [(Summary, "summary".to_owned(), false)],
            "a bucket with no summary gets one note"
        );
        assert_eq!(report.objects_listed, inventory.len() as u64);
        assert_eq!(report.commits_checked, 3);
        assert_eq!(report.objects_checked, inventory.len() as u64 - 3);
        assert_eq!(
            report.bytes_read,
            inventory
                .iter()
                .map(|(_, bytes)| bytes.len() as u64)
                .sum::<u64>()
        );
        assert_eq!(report.objects_unreached, 0);
        assert!(report.deleted.is_empty() && report.marked_partial.is_empty());
        assert!(report.commits_partial.is_empty() && report.orphan_images.is_empty());
        // A run with no delete takes no lock and changes nothing.
        assert!(
            f.server
                .state()
                .requests
                .iter()
                .all(|(method, _)| method == "GET"),
            "{:?}",
            f.server.state().requests
        );
    });
}

#[test]
fn an_object_that_no_commit_reaches_is_counted_and_not_read() {
    block_on(async {
        let f = Fixture::new(None).await;
        let stray_commit = Checksum::sha256(b"no such commit");
        f.replace(ObjectType::CommitMeta, &f.head, b"");
        f.replace(ObjectType::TombstoneCommit, &stray_commit, b"x");
        f.replace(ObjectType::DirMeta, &Checksum::sha256(b"unreached"), b"x");
        let report = f.fsck().await;
        assert!(!report.has_errors(), "{:#?}", report.findings);
        // The `.commitmeta` of a listed commit is reached.
        assert_eq!(report.objects_unreached, 2);
        assert!(
            !f.requests()
                .iter()
                .any(|(_, key)| key.ends_with(".tombstone-commit") || key.ends_with(".commitmeta")),
            "{:?}",
            f.requests()
        );
    });
}

// ---------------------------------------------------------------------------
// The objects of the trees.
// ---------------------------------------------------------------------------

#[test]
fn a_changed_filez_is_a_mismatch_in_the_commits_that_reach_it() {
    block_on(async {
        let f = Fixture::new(None).await;
        let head_file = f.entry(&f.head, &[], "file", false).await;
        let first_file = f.entry(&f.first, &[], "file", false).await;
        let other = f.object(ObjectType::File, &first_file);
        f.replace(ObjectType::File, &head_file, &other);
        let report = f.fsck().await;
        assert!(report.has_errors());
        let found = finding(&report, Mismatch, ObjectType::File, &head_file);
        assert_eq!(found.commits, [f.head]);
        assert!(found.detail.contains(&first_file.to_hex()), "{found}");
        assert_eq!(
            without_summary_note(&report).len(),
            1,
            "{:#?}",
            report.findings
        );
        assert_eq!(
            found.to_string(),
            format!(
                "mismatch objects/{}: the object has the checksum {first_file}; in commits {}",
                &object_path(ObjectType::File, &head_file)["objects/".len()..],
                f.head
            )
        );
    });
}

#[test]
fn a_removed_object_is_missing_in_each_commit_that_reaches_it() {
    block_on(async {
        let f = Fixture::new(None).await;
        let nested = f.entry(&f.head, &["sub", "deep"], "nested", false).await;
        let deep = f.entry(&f.head, &["sub"], "deep", true).await;
        f.remove(ObjectType::File, &nested);
        let report = f.fsck().await;
        let found = finding(&report, Missing, ObjectType::File, &nested);
        assert_eq!(found.commits, sorted(&[f.first, f.head, f.side]));
        assert_eq!(found.detail, "the listing does not hold the object");
        // A removed dirtree hides its subtree.
        let f = Fixture::new(None).await;
        f.remove(ObjectType::DirTree, &deep);
        let report = f.fsck().await;
        let found = finding(&report, Missing, ObjectType::DirTree, &deep);
        assert_eq!(found.commits, sorted(&[f.first, f.head, f.side]));
        assert_eq!(
            without_summary_note(&report).len(),
            1,
            "{:#?}",
            report.findings
        );
        assert_eq!(report.objects_unreached, 1, "the nested file");
    });
}

#[test]
fn bytes_after_a_payload_or_a_symlink_header_are_corrupt() {
    block_on(async {
        let f = Fixture::new(None).await;
        let side_file = f.entry(&f.side, &[], "file", false).await;
        let link = f.entry(&f.side, &[], "link", false).await;
        for checksum in [&side_file, &link] {
            let mut bytes = f.object(ObjectType::File, checksum);
            bytes.push(0);
            f.replace(ObjectType::File, checksum, &bytes);
        }
        let report = f.fsck().await;
        let found = finding(&report, Corrupt, ObjectType::File, &side_file);
        assert_eq!(found.commits, [f.side]);
        assert!(found.detail.contains("bytes follow"), "{found}");
        let found = finding(&report, Corrupt, ObjectType::File, &link);
        assert_eq!(found.commits, sorted(&[f.first, f.head, f.side]));
        assert!(found.detail.contains("symlink header"), "{found}");
    });
}

#[test]
fn a_dirtree_that_does_not_parse_is_a_mismatch_and_ends_its_subtree() {
    block_on(async {
        let f = Fixture::new(None).await;
        let root = f.root(&f.side).await;
        let side_file = f.entry(&f.side, &[], "file", false).await;
        f.replace(ObjectType::DirTree, &root, b"\xff");
        let report = f.fsck().await;
        let found = finding(&report, Mismatch, ObjectType::DirTree, &root);
        assert_eq!(found.commits, [f.side]);
        assert!(
            found.detail.contains("do not parse as a dirtree"),
            "{found}"
        );
        assert_eq!(
            without_summary_note(&report).len(),
            1,
            "{:#?}",
            report.findings
        );
        // The file of `side` alone is in no other tree.
        assert_eq!(report.objects_unreached, 1);
        assert!(
            !f.requests()
                .iter()
                .any(|(_, key)| *key == object_path(ObjectType::File, &side_file))
        );
    });
}

#[test]
fn a_changed_commit_is_a_mismatch_and_its_tree_is_walked() {
    block_on(async {
        let f = Fixture::new(None).await;
        let other = f.object(ObjectType::Commit, &f.side);
        f.replace(ObjectType::Commit, &f.first, &other);
        let mut bad = f.object(ObjectType::Commit, &f.head);
        bad.truncate(bad.len() / 2);
        f.replace(ObjectType::Commit, &f.head, &bad);
        let report = f.fsck().await;
        let found = finding(&report, Mismatch, ObjectType::Commit, &f.first);
        assert!(found.commits.is_empty());
        assert!(found.detail.contains(&f.side.to_hex()), "{found}");
        let found = finding(&report, Mismatch, ObjectType::Commit, &f.head);
        assert!(found.detail.contains("do not parse as a commit"), "{found}");
        assert_eq!(report.commits_checked, 3);
        // The run walks the tree of `side` for `first`, and no tree for
        // `head`. So the root dirtrees and the files of `first` and `head` are
        // in no walked tree.
        assert_eq!(report.objects_unreached, 4);
    });
}

#[test]
fn the_findings_on_the_objects_are_those_of_the_local_fsck() {
    block_on(async {
        let f = Fixture::new(None).await;
        let head_file = f.entry(&f.head, &[], "file", false).await;
        let first_file = f.entry(&f.first, &[], "file", false).await;
        let nested = f.entry(&f.head, &["sub", "deep"], "nested", false).await;
        let other = f.object(ObjectType::File, &first_file);
        f.replace_both(ObjectType::File, &head_file, &other);
        // Each directory of each commit has the one dirmeta.
        let meta = f.local.load_commit(&f.side).await.unwrap().0.root_dirmeta;
        let mut changed = f.object(ObjectType::DirMeta, &meta);
        changed[0] ^= 1;
        f.replace_both(ObjectType::DirMeta, &meta, &changed);
        f.remove(ObjectType::File, &nested);
        std::fs::remove_file(f.local.path().join(object_path(ObjectType::File, &nested))).unwrap();
        let local = f
            .local
            .fsck(&FsckOptions {
                mark_partial: false,
                ..FsckOptions::default()
            })
            .await
            .unwrap();
        let local: BTreeSet<(String, &str, Vec<Checksum>)> = local
            .errors
            .iter()
            .map(|error| {
                let kind = match error.kind {
                    FsckErrorKind::Missing => "missing",
                    FsckErrorKind::ChecksumMismatch { .. } => "mismatch",
                    FsckErrorKind::Corrupt(_) => "corrupt",
                };
                (error.object.to_string(), kind, error.in_commits.clone())
            })
            .collect();
        let report = f.fsck().await;
        let bucket: BTreeSet<(String, &str, Vec<Checksum>)> = without_summary_note(&report)
            .iter()
            .map(|found| {
                (
                    found.object.unwrap().to_string(),
                    found.kind.as_str(),
                    found.commits.clone(),
                )
            })
            .collect();
        assert_eq!(bucket, local);
        assert_eq!(bucket.len(), 3);
    });
}

/// One finding on an object: the object name, the kind, and the commits
/// that reach the object, sorted.
type ObjectFinding = (String, &'static str, Vec<Checksum>);

/// Returns the finding of each line that `ostree fsck -a` writes to standard
/// error.
///
/// A line names the commits that reach the object. For a commit object, the
/// line names the commit itself. If a ref names the commit, a line with no
/// commits comes first, and then the line that names the commit. So the
/// commit itself is not in the commits of the finding, and the two lines
/// give one finding. The fsck of a bucket names no commit for a commit
/// object.
fn tool_findings(stderr: &str) -> BTreeSet<ObjectFinding> {
    let mut findings = BTreeSet::new();
    for line in stderr.lines() {
        if line.starts_with("Marking commit as partial: ")
            || line == "error: Repository corruption encountered"
        {
            continue;
        }
        let (commits, rest) = match line.strip_prefix("In commits ") {
            Some(rest) => rest.split_once(": ").unwrap(),
            None => match line.strip_prefix("Object missing in commits ") {
                Some(rest) => {
                    let (commits, object) = rest.split_once(": ").unwrap();
                    findings.insert((object.to_owned(), "missing", parse_commits(commits)));
                    continue;
                }
                None => ("", line),
            },
        };
        let (object, detail) = rest
            .strip_prefix("fsck ")
            .and_then(|rest| rest.split_once(": "))
            .unwrap_or_else(|| panic!("a line of ostree fsck: {line}"));
        let object = match object.strip_prefix("content object ") {
            Some(checksum) => format!("{checksum}.file"),
            None => object.to_owned(),
        };
        let kind = if detail.contains("; checksum expected=") {
            "mismatch"
        } else {
            "corrupt"
        };
        let own = object.strip_suffix(".commit");
        let commits = parse_commits(commits)
            .into_iter()
            .filter(|commit| Some(commit.to_hex().as_str()) != own)
            .collect();
        findings.insert((object, kind, commits));
    }
    findings
}

/// Returns the commits of a list `<c>, <c>`, sorted.
fn parse_commits(list: &str) -> Vec<Checksum> {
    let commits: Vec<Checksum> = list
        .split(", ")
        .filter(|commit| !commit.is_empty())
        .map(|commit| Checksum::from_hex(commit).unwrap())
        .collect();
    sorted(&commits)
}

/// Asserts that `ostree fsck -a` on a dump of the bucket of `f` to `dump`
/// gives the same `count` findings on the objects as the fsck of the
/// bucket, and exits 0 only if the fsck of the bucket finds no error.
async fn assert_tool_agrees(f: &Fixture, dump: &str, count: usize) {
    let dir = f.tmp.path().join(dump);
    f.server.dump("repo", &dir);
    let out = common::tool_fsck_output(&dir, &["-a"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let tool = tool_findings(&stderr);
    let report = f.fsck().await;
    let bucket: BTreeSet<ObjectFinding> = report
        .findings
        .iter()
        .filter(|found| found.error)
        .map(|found| {
            (
                found.object.unwrap().to_string(),
                found.kind.as_str(),
                found.commits.clone(),
            )
        })
        .collect();
    assert_eq!(bucket, tool, "{dump}: {stderr}");
    assert_eq!(tool.len(), count, "{dump}: {stderr}");
    assert_eq!(
        out.status.success(),
        !report.has_errors(),
        "{dump}: {stderr}"
    );
}

/// `ostree fsck -a` on a dump of the bucket gives the same findings on the
/// objects as the fsck of the bucket, and exits 0 only if the fsck of the
/// bucket finds no error. One fixture is clean, and then gets the changes
/// that keep the walk: a filez with the bytes of another file, a changed
/// dirmeta, and a removed file. A changed dirtree and a changed commit
/// change the walk, so each gets a fixture of its own.
#[test]
fn the_findings_agree_with_ostree_fsck_on_a_dump_of_the_bucket() {
    if !common::ostree_available() {
        eprintln!(
            "skipping the_findings_agree_with_ostree_fsck_on_a_dump_of_the_bucket: \
             ostree is not installed"
        );
        return;
    }
    block_on(async {
        let f = Fixture::new(None).await;
        assert_tool_agrees(&f, "clean", 0).await;
        let head_file = f.entry(&f.head, &[], "file", false).await;
        let first_file = f.entry(&f.first, &[], "file", false).await;
        let other = f.object(ObjectType::File, &first_file);
        f.replace(ObjectType::File, &head_file, &other);
        // Each directory of each commit has the one dirmeta.
        let meta = f.local.load_commit(&f.side).await.unwrap().0.root_dirmeta;
        let mut changed = f.object(ObjectType::DirMeta, &meta);
        changed[0] ^= 1;
        f.replace(ObjectType::DirMeta, &meta, &changed);
        let nested = f.entry(&f.head, &["sub", "deep"], "nested", false).await;
        f.remove(ObjectType::File, &nested);
        assert_tool_agrees(&f, "objects", 3).await;

        let f = Fixture::new(None).await;
        let other = f.object(ObjectType::DirTree, &f.root(&f.head).await);
        f.replace(ObjectType::DirTree, &f.root(&f.side).await, &other);
        assert_tool_agrees(&f, "dirtree", 1).await;

        let f = Fixture::new(None).await;
        let other = f.object(ObjectType::Commit, &f.side);
        f.replace(ObjectType::Commit, &f.first, &other);
        assert_tool_agrees(&f, "commit", 1).await;

        // A ref names `head`.
        let f = Fixture::new(None).await;
        let other = f.object(ObjectType::Commit, &f.first);
        f.replace(ObjectType::Commit, &f.head, &other);
        assert_tool_agrees(&f, "ref-commit", 1).await;
    });
}

// ---------------------------------------------------------------------------
// Strays, refs, and config.
// ---------------------------------------------------------------------------

#[test]
fn each_key_under_objects_that_is_no_object_key_is_a_stray() {
    block_on(async {
        let f = Fixture::new(None).await;
        let digits = "cd".repeat(31);
        f.put("objects/ab/zz", b"1");
        f.put(&format!("objects/AB/{digits}.commit"), b"22");
        f.put("objects/abc", b"333");
        f.put("objects/zz/x", b"4444");
        f.put("objects/zz/y/z", b"55555");
        let report = f.fsck().await;
        let strays: Vec<(String, bool)> = report
            .findings
            .iter()
            .filter(|found| found.kind == Stray)
            .map(|found| (found.key.clone(), found.error))
            .collect();
        assert_eq!(
            strays,
            [
                (format!("objects/AB/{digits}.commit"), true),
                ("objects/ab/zz".to_owned(), true),
                ("objects/abc".to_owned(), true),
                ("objects/zz/x".to_owned(), true),
                ("objects/zz/y/z".to_owned(), true),
            ]
        );
        assert!(
            report.findings[0]
                .to_string()
                .contains("is no object key, with 2 bytes")
        );
        // The delimited list is one request of objects/.
        let lists = f
            .server
            .state()
            .requests
            .iter()
            .filter(|(_, target)| target.contains("delimiter=%2F"))
            .count();
        assert_eq!(lists, 1);
    });
}

#[test]
fn the_ref_findings_name_each_bad_ref_key() {
    block_on(async {
        let f = Fixture::new(Some(ID)).await;
        f.put("refs/heads/bad", b"not a checksum\n");
        f.put_ref("refs/remotes/origin/main", &f.head);
        f.put_ref(&format!("refs/mirrors/{ID}/main"), &f.head);
        f.put_ref("refs/mirrors/org.example.B/main", &f.side);
        let absent = Checksum::sha256(b"absent");
        f.put_ref("refs/heads/gone", &absent);
        let report = f.fsck().await;
        let refs: Vec<(String, String)> = report
            .findings
            .iter()
            .filter(|found| found.kind == Ref)
            .map(|found| (found.key.clone(), found.detail.clone()))
            .collect();
        assert_eq!(
            refs,
            [
                (
                    "refs/heads/bad".to_owned(),
                    "does not hold 64 lowercase hex digits and a newline".to_owned()
                ),
                (
                    "refs/heads/gone".to_owned(),
                    format!("names the commit {absent}, which the bucket does not hold")
                ),
                (
                    format!("refs/mirrors/{ID}/main"),
                    "is a ref under refs/mirrors/ of the own collection id; a bucket repository \
                     holds the refs of its own collection under refs/heads/"
                        .to_owned()
                ),
                (
                    "refs/remotes/origin/main".to_owned(),
                    "is no ref of refs/heads/ or of refs/mirrors/ID/".to_owned()
                ),
            ]
        );
        assert!(report.has_errors());
    });
}

#[test]
fn an_absent_or_bad_config_is_a_config_error() {
    block_on(async {
        let f = Fixture::new(None).await;
        f.server.state().objects.remove("repo/config");
        let report = f.fsck().await;
        assert_eq!(
            report.findings[0].to_string(),
            "config config: the bucket repository has no config"
        );
        assert!(report.has_errors());
        f.put("config", b"[core]\nrepo_version=1\nmode=bare\n");
        let report = f.fsck().await;
        let found = &report.findings[0];
        assert_eq!(found.kind, Config);
        assert!(
            found
                .detail
                .starts_with("its config states the mode 'bare'"),
            "{found}"
        );
        // The other checks still run.
        assert_eq!(report.commits_checked, 3);
    });
}

// ---------------------------------------------------------------------------
// The summary.
// ---------------------------------------------------------------------------

#[test]
fn a_summary_of_the_refs_gives_no_finding_and_a_stale_one_a_note() {
    block_on(async {
        let f = Fixture::new(None).await;
        f.local
            .regenerate_summary(&SummaryOptions::default())
            .await
            .unwrap();
        f.copy_file("summary");
        let report = f.fsck().await;
        assert!(report.findings.is_empty(), "{:#?}", report.findings);
        // A ref that moved after the summary.
        f.put_ref("refs/heads/side", &f.first);
        f.put_ref("refs/heads/new", &f.first);
        let report = f.fsck().await;
        assert!(!report.has_errors(), "{:#?}", report.findings);
        assert_eq!(kinds(&report), [(Summary, "summary".to_owned(), false)]);
        assert_eq!(
            report.findings[0].detail,
            "the summary is older than the refs or the deltas: 2 ref(s) differ from the ref \
             files: refs/heads/new, refs/heads/side"
        );
        // A summary that names a commit that the bucket does not hold.
        f.remove(ObjectType::Commit, &f.side);
        let report = f.fsck().await;
        let errors: Vec<&BucketFinding> =
            report.findings.iter().filter(|found| found.error).collect();
        assert_eq!(errors.len(), 1, "{:#?}", report.findings);
        assert_eq!(errors[0].kind, Summary);
        assert_eq!(
            errors[0].detail,
            format!(
                "names the ref refs/heads/side at the commit {}, which the bucket does not hold",
                f.side
            )
        );
    });
}

#[test]
fn a_summary_that_does_not_parse_is_an_error() {
    block_on(async {
        let f = Fixture::new(None).await;
        f.put("summary", b"\xff\xff");
        let report = f.fsck().await;
        assert_eq!(kinds(&report), [(Summary, "summary".to_owned(), true)]);
        assert!(report.findings[0].detail.starts_with("does not parse"));
    });
}

#[test]
fn the_signature_of_the_summary_verifies_with_the_keys_of_the_run() {
    block_on(async {
        let f = Fixture::new(None).await;
        let signer = signer();
        f.local
            .regenerate_summaries(&SummaryOptions::default(), &[&signer as &dyn Signer])
            .await
            .unwrap();
        f.copy_file("summary");
        f.copy_file("summary.sig");
        let mut opts = BucketFsckOptions::default();
        opts.summary_keys = Some(keys(false));
        let report = f.bucket.fsck(&opts).await.unwrap();
        assert!(report.findings.is_empty(), "{:#?}", report.findings);
        opts.summary_keys = Some(keys(true));
        let report = f.bucket.fsck(&opts).await.unwrap();
        assert_eq!(kinds(&report), [(Summary, "summary.sig".to_owned(), true)]);
        // The same bucket with no keys verifies nothing, and reads no
        // summary.sig.
        f.server.state().requests.clear();
        let report = f.fsck().await;
        assert!(report.findings.is_empty(), "{:#?}", report.findings);
        assert!(!f.requests().iter().any(|(_, key)| key == "summary.sig"));
        f.server.state().objects.remove("repo/summary.sig");
        opts.summary_keys = Some(keys(false));
        let report = f.bucket.fsck(&opts).await.unwrap();
        assert_eq!(kinds(&report), [(Summary, "summary.sig".to_owned(), true)]);
        assert!(report.findings[0].detail.contains("no summary.sig"));
        f.server.state().objects.remove("repo/summary");
        let report = f.bucket.fsck(&opts).await.unwrap();
        assert_eq!(kinds(&report), [(Summary, "summary".to_owned(), true)]);
    });
}

#[test]
fn the_delta_map_of_the_summary_is_checked_against_the_superblocks() {
    block_on(async {
        let f = Fixture::new(None).await;
        f.local
            .generate_static_delta(Some(&f.first), &f.head, &DeltaOptions::default())
            .await
            .unwrap();
        f.local
            .regenerate_summary(&SummaryOptions::default())
            .await
            .unwrap();
        f.copy("deltas");
        f.copy_file("summary");
        let report = f.fsck().await;
        assert!(report.findings.is_empty(), "{:#?}", report.findings);
        // A delta of the bucket that the summary does not list is a note.
        f.local
            .generate_static_delta(None, &f.side, &DeltaOptions::default())
            .await
            .unwrap();
        f.copy("deltas");
        let report = f.fsck().await;
        assert_eq!(kinds(&report), [(Summary, "summary".to_owned(), false)]);
        assert!(
            report.findings[0].detail.contains(&format!(
                "1 delta(s) of the bucket are not in it: {}",
                f.side
            )),
            "{}",
            report.findings[0]
        );
        // A changed superblock is an error.
        let superblock = f
            .server
            .state()
            .objects
            .keys()
            .find(|key| key.contains('-') && key.ends_with("/superblock"))
            .cloned()
            .unwrap();
        // The run reads the superblock of an advertised delta alone, by the
        // strict rule of an absent key.
        f.server.state().requests.clear();
        f.fsck().await;
        let reads: Vec<String> = f
            .requests()
            .into_iter()
            .filter(|(_, key)| key.ends_with("/superblock"))
            .map(|(_, key)| key)
            .collect();
        assert_eq!(reads.len(), 1, "{reads:?}");
        assert!(reads[0].contains('-'), "{reads:?}");
        f.server.state().not_found = Some((superblock.clone(), Vec::new()));
        let err = f
            .bucket
            .fsck(&BucketFsckOptions::default())
            .await
            .unwrap_err();
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
        f.server.state().not_found = None;
        f.server
            .state()
            .objects
            .get_mut(&superblock)
            .unwrap()
            .bytes
            .push(0);
        let report = f.fsck().await;
        let errors: Vec<&BucketFinding> =
            report.findings.iter().filter(|found| found.error).collect();
        assert_eq!(errors.len(), 1, "{:#?}", report.findings);
        assert!(
            errors[0].detail.contains("superblock digest"),
            "{}",
            errors[0]
        );
        // An absent superblock is an error.
        f.server.state().objects.remove(&superblock);
        let report = f.fsck().await;
        let errors: Vec<&BucketFinding> =
            report.findings.iter().filter(|found| found.error).collect();
        assert_eq!(errors.len(), 1, "{:#?}", report.findings);
        assert!(
            errors[0]
                .detail
                .ends_with("whose superblock the bucket does not hold"),
            "{}",
            errors[0]
        );
    });
}

// ---------------------------------------------------------------------------
// Composefs images.
// ---------------------------------------------------------------------------

#[test]
fn each_image_is_checked_against_the_digest_of_its_commit() {
    block_on(async {
        let f = Fixture::new(None).await;
        let base = f.tmp.path().join("owned");
        std::fs::create_dir_all(&base).unwrap();
        common::composefs::build_owned_source(&base);
        let (image, _) =
            common::composefs::commit_tree(&f.local, &base, 1_700_000_000, true, Some("img")).await;
        f.copy("objects");
        f.put_ref("refs/heads/img", &image);
        let report = f.fsck().await;
        assert!(!report.has_errors(), "{:#?}", report.findings);
        // A `.cfs` of a commit that the bucket does not hold is no finding.
        let orphan = Checksum::sha256(b"no such commit");
        f.replace(ObjectType::ComposefsImage, &orphan, b"image");
        // A `.cfs` of a commit with no digest key.
        f.replace(ObjectType::ComposefsImage, &f.head, b"image");
        let mut bytes = f.object(ObjectType::ComposefsImage, &image);
        bytes[0] ^= 1;
        f.replace(ObjectType::ComposefsImage, &image, &bytes);
        let report = f.fsck().await;
        assert_eq!(report.orphan_images, [orphan]);
        let found = finding(&report, Mismatch, ObjectType::ComposefsImage, &image);
        assert_eq!(found.commits, [image]);
        assert!(
            found.detail.starts_with("the commit records the digest"),
            "{found}"
        );
        let found = finding(&report, Corrupt, ObjectType::ComposefsImage, &f.head);
        assert_eq!(
            found.detail,
            "the commit does not carry ostree.composefs.digest.v0"
        );
        assert_eq!(
            without_summary_note(&report).len(),
            2,
            "{:#?}",
            report.findings
        );
    });
}

// ---------------------------------------------------------------------------
// Notes, strict reads, and reads in transit.
// ---------------------------------------------------------------------------

#[test]
fn an_incomplete_upload_and_a_lock_are_notes() {
    block_on(async {
        let f = Fixture::new(None).await;
        f.server.state().uploads.push((
            format!("repo/{}", object_path(ObjectType::File, &f.head)),
            "upload-1".to_owned(),
            "2026-10-22T10:00:00.000Z".to_owned(),
        ));
        f.server.state().store(LOCK, DEAD_LOCK.as_bytes());
        let report = f.fsck().await;
        assert!(!report.has_errors(), "{:#?}", report.findings);
        let notes: Vec<(BucketFindingKind, String)> = without_summary_note(&report)
            .iter()
            .map(|found| (found.kind, found.key.clone()))
            .collect();
        assert_eq!(
            notes,
            [
                (Lock, "extensions/ostrya/lock".to_owned()),
                (Upload, object_path(ObjectType::File, &f.head)),
            ]
        );
        assert!(
            report.findings[0]
                .detail
                .starts_with("a writer held the lock at the start of the run: operation push"),
            "{}",
            report.findings[0]
        );
        // A lock that a writer takes during the run is a note at the end.
        f.server.state().objects.remove(LOCK);
        f.server.state().uploads.clear();
        let config = format!("repo/{}", object_path(ObjectType::Commit, &f.side));
        f.server.state().before_key = Some((
            "GET",
            config,
            Box::new(|objects| {
                objects.insert(
                    LOCK.to_owned(),
                    common::s3::Stored {
                        bytes: DEAD_LOCK.as_bytes().to_vec(),
                        etag: "\"dead\"".into(),
                    },
                );
            }),
        ));
        let report = f.fsck().await;
        let notes: Vec<&BucketFinding> = without_summary_note(&report);
        assert_eq!(notes.len(), 1, "{:#?}", report.findings);
        assert_eq!(notes[0].kind, Lock);
        assert!(
            notes[0].detail.contains("at the end of the run"),
            "{}",
            notes[0]
        );
    });
}

#[test]
fn a_404_without_no_such_key_fails_the_run() {
    block_on(async {
        let f = Fixture::new(None).await;
        let sub = f.entry(&f.head, &[], "sub", true).await;
        let nested = f.entry(&f.head, &["sub", "deep"], "nested", false).await;
        for key in [
            "config".to_owned(),
            "refs/heads/main".to_owned(),
            object_path(ObjectType::Commit, &f.side),
            object_path(ObjectType::DirTree, &sub),
            object_path(ObjectType::File, &nested),
        ] {
            f.server.state().not_found = Some((format!("repo/{key}"), Vec::new()));
            let err = f
                .bucket
                .fsck(&BucketFsckOptions::default())
                .await
                .unwrap_err();
            assert!(
                matches!(
                    &err,
                    Error::Remote(ostrya::remote::Error::S3 {
                        status: 404,
                        code: None,
                        ..
                    })
                ),
                "{key}: {err}"
            );
        }
    });
}

#[test]
fn a_body_cut_once_is_read_again_and_cut_twice_fails_the_run() {
    block_on(async {
        let f = Fixture::new(None).await;
        let head_file = f.entry(&f.head, &[], "file", false).await;
        let key = format!("repo/{}", object_path(ObjectType::File, &head_file));
        f.server.state().truncate = Some((key.clone(), 10, 1));
        let report = f.fsck().await;
        assert!(!report.has_errors(), "{:#?}", report.findings);
        let gets = f
            .server
            .state()
            .requests
            .iter()
            .filter(|(method, target)| method == "GET" && target == &format!("/bkt/{key}"))
            .count();
        assert_eq!(gets, 2);
        f.server.state().truncate = Some((key.clone(), 10, 2));
        let err = f
            .bucket
            .fsck(&BucketFsckOptions::default())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Io(e) if e.to_string().contains("failed in transit two times")),
            "{err}"
        );
    });
}

// ---------------------------------------------------------------------------
// The repair.
// ---------------------------------------------------------------------------

#[test]
fn the_repair_marks_the_commits_and_deletes_the_bad_objects_in_order() {
    block_on(async {
        let f = Fixture::new(None).await;
        let head_file = f.entry(&f.head, &[], "file", false).await;
        let first_file = f.entry(&f.first, &[], "file", false).await;
        let nested = f.entry(&f.head, &["sub", "deep"], "nested", false).await;
        let other = f.object(ObjectType::File, &first_file);
        f.replace(ObjectType::File, &head_file, &other);
        f.remove(ObjectType::File, &nested);
        let other = f.object(ObjectType::Commit, &f.side);
        f.replace(ObjectType::Commit, &f.first, &other);
        f.server.state().requests.clear();
        let report = f.repair().await.unwrap();
        // The commits of the bad tree objects get a marker, except `first`,
        // whose own object is bad and goes.
        let mut wanted = vec![
            (f.head, vec!["refs/heads/main".to_owned()]),
            (f.side, vec!["refs/heads/side".to_owned()]),
        ];
        wanted.sort();
        assert_eq!(report.marked_partial, wanted);
        assert_eq!(
            report.deleted,
            [
                object_path(ObjectType::Commit, &f.first),
                object_path(ObjectType::File, &head_file),
            ]
        );
        for (commit, _) in &wanted {
            assert_eq!(
                f.get(&format!("state/{}.commitpartial", commit.to_hex())),
                Some(vec![0x66])
            );
        }
        // No ref names `first`.
        assert!(report.deleted_ref_targets.is_empty());
        assert!(f.get(&object_path(ObjectType::Commit, &f.first)).is_none());
        assert!(f.get(&object_path(ObjectType::File, &head_file)).is_none());
        assert!(f.get(&object_path(ObjectType::Commit, &f.head)).is_some());
        assert!(!f.server.state().objects.contains_key(LOCK));
        assert_eq!(report.broken_lock, None);
        assert!(
            !report.findings.iter().any(|found| found.kind == Lock),
            "{:#?}",
            report.findings
        );
        // The writes: the lock, the markers, the deletes, then the release.
        let writes: Vec<(String, String)> = f
            .requests()
            .into_iter()
            .filter(|(method, _)| method != "GET")
            .collect();
        let mut expected = vec![
            ("PUT".to_owned(), "extensions/ostrya/lock".to_owned()),
            ("PUT".to_owned(), "extensions/ostrya/lock".to_owned()),
        ];
        for (commit, _) in &wanted {
            expected.push((
                "PUT".to_owned(),
                format!("state/{}.commitpartial", commit.to_hex()),
            ));
        }
        expected.push((
            "DELETE".to_owned(),
            object_path(ObjectType::Commit, &f.first),
        ));
        expected.push((
            "DELETE".to_owned(),
            object_path(ObjectType::File, &head_file),
        ));
        expected.push(("DELETE".to_owned(), "extensions/ostrya/lock".to_owned()));
        assert_eq!(writes, expected);
        // The next run finds the missing objects and the markers, and a
        // repair again changes no object.
        let report = f.fsck().await;
        assert_eq!(report.commits_partial, sorted(&[f.head, f.side]));
        let found = finding(&report, Missing, ObjectType::File, &head_file);
        assert_eq!(found.commits, [f.head]);
        let found = finding(&report, Missing, ObjectType::File, &nested);
        assert_eq!(found.commits, sorted(&[f.head, f.side]));
        f.server.state().requests.clear();
        let report = f.repair().await.unwrap();
        assert!(report.marked_partial.is_empty() && report.deleted.is_empty());
        let writes: Vec<String> = f
            .requests()
            .into_iter()
            .filter(|(method, _)| method != "GET")
            .map(|(_, key)| key)
            .collect();
        assert!(
            writes.iter().all(|key| key == "extensions/ostrya/lock"),
            "{writes:?}"
        );
    });
}

#[test]
fn a_lock_of_another_writer_fails_the_repair_before_an_object_read() {
    block_on(async {
        let f = Fixture::new(None).await;
        f.server.state().store(LOCK, DEAD_LOCK.as_bytes());
        f.server.state().requests.clear();
        let err = f.repair().await.unwrap_err();
        assert!(matches!(err, Error::BucketLocked { .. }), "{err}");
        assert!(
            !f.requests()
                .iter()
                .any(|(_, key)| key.starts_with("objects/")),
            "{:?}",
            f.requests()
        );
        let mut opts = BucketFsckOptions::default();
        opts.delete = true;
        opts.break_lock = true;
        let report = f.bucket.fsck(&opts).await.unwrap();
        assert_eq!(report.broken_lock.unwrap().pid, Some(99));
        assert!(!f.server.state().objects.contains_key(LOCK));
    });
}

#[test]
fn break_lock_without_delete_is_refused_before_a_request() {
    block_on(async {
        let f = Fixture::new(None).await;
        f.server.state().requests.clear();
        let mut opts = BucketFsckOptions::default();
        opts.break_lock = true;
        let err = f.bucket.fsck(&opts).await.unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)), "{err}");
        assert!(f.server.state().requests.is_empty());
    });
}

#[test]
fn a_lock_broken_before_the_deletes_stops_the_repair() {
    block_on(async {
        let f = Fixture::new(None).await;
        let head_file = f.entry(&f.head, &[], "file", false).await;
        let first_file = f.entry(&f.first, &[], "file", false).await;
        let other = f.object(ObjectType::File, &first_file);
        f.replace(ObjectType::File, &head_file, &other);
        let marker = format!("repo/state/{}.commitpartial", f.head.to_hex());
        f.server.state().before_key = Some((
            "PUT",
            marker,
            Box::new(|objects| {
                let stored = objects.get_mut(LOCK).unwrap();
                stored.bytes = DEAD_LOCK.as_bytes().to_vec();
                stored.etag = "\"replaced\"".into();
            }),
        ));
        let err = f.repair().await.unwrap_err();
        let Error::BucketRepairIncomplete { report, error, .. } = &err else {
            panic!("{err}");
        };
        assert!(matches!(**error, Error::BucketLockLost { .. }), "{err}");
        assert!(
            err.to_string()
                .ends_with("; run the fsck with delete again before a push"),
            "{err}"
        );
        // The report holds the marker that the run wrote, and no delete.
        assert_eq!(
            report.marked_partial,
            [(f.head, vec!["refs/heads/main".to_owned()])]
        );
        assert!(report.deleted.is_empty());
        finding(report, Mismatch, ObjectType::File, &head_file);
        assert!(f.get(&object_path(ObjectType::File, &head_file)).is_some());
        assert!(
            !f.requests().iter().any(|(method, _)| method == "DELETE"),
            "{:?}",
            f.requests()
        );
        assert_eq!(f.get("extensions/ostrya/lock"), Some(DEAD_LOCK.into()));
    });
}

#[test]
fn a_repair_of_a_bucket_with_no_valid_config_changes_nothing() {
    block_on(async {
        let f = Fixture::new(None).await;
        let head_file = f.entry(&f.head, &[], "file", false).await;
        let first_file = f.entry(&f.first, &[], "file", false).await;
        let other = f.object(ObjectType::File, &first_file);
        f.replace(ObjectType::File, &head_file, &other);
        for config in [None, Some(&b"[core]\nmode=bare\n"[..])] {
            match config {
                None => {
                    f.server.state().objects.remove("repo/config");
                }
                Some(bytes) => f.put("config", bytes),
            }
            f.server.state().requests.clear();
            let report = f.repair().await.unwrap();
            assert!(report.has_errors());
            assert_eq!(report.findings[0].kind, Config);
            assert!(
                report.findings[0]
                    .detail
                    .ends_with("the run refuses the repair, and changes nothing"),
                "{}",
                report.findings[0]
            );
            finding(&report, Mismatch, ObjectType::File, &head_file);
            assert!(report.deleted.is_empty() && report.marked_partial.is_empty());
            assert!(
                f.server
                    .state()
                    .requests
                    .iter()
                    .all(|(method, _)| method == "GET"),
                "{:?}",
                f.server.state().requests
            );
        }
    });
}

#[cfg(feature = "push")]
#[test]
fn a_push_of_a_marked_commit_uploads_its_missing_objects_and_clears_the_marker() {
    block_on(async {
        let f = Fixture::new(None).await;
        let nested = f.entry(&f.head, &["sub", "deep"], "nested", false).await;
        f.remove(ObjectType::File, &nested);
        let report = f.repair().await.unwrap();
        assert_eq!(report.marked_partial.len(), 3);
        assert!(report.deleted.is_empty());
        f.server.state().requests.clear();
        let opts = ostrya::RepoPushOptions {
            refspecs: vec!["main".to_owned()],
            ..ostrya::RepoPushOptions::default()
        };
        f.local
            .push_to_bucket(endpoint(&f.server.endpoint(), ADDRESS), opts)
            .await
            .unwrap();
        let writes: Vec<(String, String)> = f
            .requests()
            .into_iter()
            .filter(|(method, key)| method != "GET" && key != "extensions/ostrya/lock")
            .collect();
        assert_eq!(
            writes,
            [
                ("PUT".to_owned(), object_path(ObjectType::File, &nested)),
                (
                    "DELETE".to_owned(),
                    format!("state/{}.commitpartial", f.head.to_hex())
                ),
            ]
        );
        // The markers of the commits that the push did not offer stay. Their
        // trees are whole now, so each one is a note, and a repair deletes
        // them.
        let report = f.fsck().await;
        assert!(!report.has_errors(), "{:#?}", report.findings);
        assert_eq!(report.commits_partial, sorted(&[f.first, f.side]));
        let markers: Vec<&BucketFinding> = report
            .findings
            .iter()
            .filter(|found| found.kind == Marker)
            .collect();
        assert_eq!(markers.len(), 2, "{:#?}", report.findings);
        let report = f.repair().await.unwrap();
        assert_eq!(report.cleared_partial, sorted(&[f.first, f.side]));
        assert!(f.fsck().await.commits_partial.is_empty());
    });
}

#[test]
fn a_summary_update_after_a_repair_lists_a_marked_ref_target_and_refuses_a_deleted_one() {
    block_on(async {
        let f = Fixture::new(None).await;
        let nested = f.entry(&f.head, &["sub", "deep"], "nested", false).await;
        f.remove(ObjectType::File, &nested);
        let report = f.repair().await.unwrap();
        assert!(
            report
                .marked_partial
                .iter()
                .any(|(commit, _)| *commit == f.head)
        );
        let opts = BucketSummaryOptions::default();
        f.bucket.update_summary(&opts).await.unwrap();
        let summary = f.get("summary").unwrap();
        let parsed = ostrya::Summary::parse(&summary).unwrap();
        assert_eq!(parsed.lookup("main"), Some(f.head));
        let report = f.fsck().await;
        assert!(
            !report.findings.iter().any(|found| found.kind == Summary),
            "{:#?}",
            report.findings
        );
        // A repair deletes the commit object of `side`, whose bytes are
        // bad, and the update then refuses the ref of `side`.
        let other = f.object(ObjectType::Commit, &f.head);
        f.replace(ObjectType::Commit, &f.side, &other);
        let report = f.repair().await.unwrap();
        assert!(
            report
                .deleted_ref_targets
                .iter()
                .any(|(commit, _)| *commit == f.side),
            "{report:#?}"
        );
        let err = f.bucket.update_summary(&opts).await.unwrap_err();
        assert!(
            matches!(&err, Error::InvalidFormat(m) if m.contains("which the bucket does not hold")),
            "{err}"
        );
        assert_eq!(f.get("summary"), Some(summary));
        assert!(!f.server.state().objects.contains_key(LOCK));
        // A push of `side` uploads the commit again, and the update then
        // succeeds.
        #[cfg(feature = "push")]
        {
            let push = ostrya::RepoPushOptions {
                refspecs: vec!["side".to_owned()],
                ..ostrya::RepoPushOptions::default()
            };
            f.local
                .push_to_bucket(endpoint(&f.server.endpoint(), ADDRESS), push)
                .await
                .unwrap();
            f.bucket.update_summary(&opts).await.unwrap();
            let parsed = ostrya::Summary::parse(&f.get("summary").unwrap()).unwrap();
            assert_eq!(parsed.lookup("side"), Some(f.side));
        }
    });
}

// ---------------------------------------------------------------------------
// Writers during a run, refused lists, strict reads of images, and large
// summaries.
// ---------------------------------------------------------------------------

/// Commits a tree with a composefs image to the ref `img`, copies the
/// objects into the bucket, and writes the ref file. Returns the commit.
async fn image_commit(f: &Fixture) -> Checksum {
    let base = f.tmp.path().join("owned");
    std::fs::create_dir_all(&base).unwrap();
    common::composefs::build_owned_source(&base);
    let (image, _) =
        common::composefs::commit_tree(&f.local, &base, 1_700_000_000, true, Some("img")).await;
    f.copy("objects");
    f.put_ref("refs/heads/img", &image);
    image
}

#[test]
fn an_object_that_a_writer_adds_during_the_run_is_a_note() {
    block_on(async {
        let f = Fixture::new(None).await;
        let nested = f.entry(&f.head, &["sub", "deep"], "nested", false).await;
        let key = object_path(ObjectType::File, &nested);
        let bytes = f.object(ObjectType::File, &nested);
        f.remove(ObjectType::File, &nested);
        // A writer puts the object back after the listing, at the read of the
        // first commit.
        let stored = format!("repo/{key}");
        f.server.state().before_key = Some((
            "GET",
            format!("repo/{}", object_path(ObjectType::Commit, &f.first)),
            Box::new(move |objects| {
                objects.insert(
                    stored,
                    common::s3::Stored {
                        bytes,
                        etag: "\"back\"".into(),
                    },
                );
            }),
        ));
        f.server.state().requests.clear();
        let report = f.fsck().await;
        assert!(!report.has_errors(), "{:#?}", report.findings);
        let found = finding(&report, Missing, ObjectType::File, &nested);
        assert!(!found.error);
        assert!(
            found
                .detail
                .ends_with("a writer changed the bucket during the run"),
            "{found}"
        );
        assert_eq!(found.commits, sorted(&[f.first, f.head, f.side]));
        // One read of the object, and no read again of its commits.
        let reads: Vec<String> = f
            .requests()
            .into_iter()
            .filter(|(method, k)| method == "GET" && (*k == key || k.ends_with(".commit")))
            .map(|(_, k)| k)
            .collect();
        assert_eq!(reads.len(), 4, "{reads:?}");
        assert_eq!(reads.iter().filter(|k| **k == key).count(), 1);
    });
}

#[test]
fn a_missing_object_of_commits_that_a_writer_removes_during_the_run_names_the_rest() {
    block_on(async {
        let f = Fixture::new(None).await;
        let nested = f.entry(&f.head, &["sub", "deep"], "nested", false).await;
        f.remove(ObjectType::File, &nested);
        let key = format!("repo/{}", object_path(ObjectType::File, &nested));
        let commit_key =
            |commit: &Checksum| format!("repo/{}", object_path(ObjectType::Commit, commit));
        // A prune removes `side` before the read again of the object.
        let side = commit_key(&f.side);
        f.server.state().before_key = Some((
            "GET",
            key.clone(),
            Box::new(move |objects| {
                objects.remove(&side);
            }),
        ));
        let report = f.fsck().await;
        let found = finding(&report, Missing, ObjectType::File, &nested);
        assert!(found.error);
        assert_eq!(found.detail, "the listing does not hold the object");
        assert_eq!(found.commits, sorted(&[f.first, f.head]));
        // A prune of each commit of the object leaves no finding.
        f.copy_file(&object_path(ObjectType::Commit, &f.side));
        let commits: Vec<String> = [f.first, f.head, f.side].iter().map(commit_key).collect();
        f.server.state().before_key = Some((
            "GET",
            key,
            Box::new(move |objects| {
                for commit in &commits {
                    objects.remove(commit);
                }
            }),
        ));
        let report = f.fsck().await;
        assert!(!report.has_errors(), "{:#?}", report.findings);
        assert!(
            !report.findings.iter().any(|found| found.kind == Missing),
            "{:#?}",
            report.findings
        );
    });
}

#[test]
fn a_refused_list_fails_the_run_before_an_object_read() {
    block_on(async {
        let f = Fixture::new(None).await;
        for list in ["uploads", "repo/refs/", "repo/state/", "repo/objects/00/"] {
            f.server.state().refuse_list = Some(list.to_owned());
            f.server.state().requests.clear();
            let err = f
                .bucket
                .fsck(&BucketFsckOptions::default())
                .await
                .unwrap_err();
            assert!(
                matches!(
                    &err,
                    Error::Remote(ostrya::remote::Error::S3 {
                        status: 403,
                        code: Some(code),
                        ..
                    }) if code == "AccessDenied"
                ),
                "{list}: {err}"
            );
            assert!(
                !f.requests()
                    .iter()
                    .any(|(_, key)| key.starts_with("objects/")),
                "{list}: {:?}",
                f.requests()
            );
        }
    });
}

#[test]
fn an_image_read_takes_the_strict_rule_and_is_read_again_after_a_cut() {
    block_on(async {
        let f = Fixture::new(None).await;
        let image = image_commit(&f).await;
        let key = format!("repo/{}", object_path(ObjectType::ComposefsImage, &image));
        f.server.state().truncate = Some((key.clone(), 10, 1));
        f.server.state().requests.clear();
        let report = f.fsck().await;
        assert!(!report.has_errors(), "{:#?}", report.findings);
        let gets = f
            .server
            .state()
            .requests
            .iter()
            .filter(|(method, target)| method == "GET" && target == &format!("/bkt/{key}"))
            .count();
        assert_eq!(gets, 2);
        f.server.state().truncate = Some((key.clone(), 10, 2));
        let err = f
            .bucket
            .fsck(&BucketFsckOptions::default())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Io(e) if e.to_string().contains("failed in transit two times")),
            "{err}"
        );
        f.server.state().truncate = None;
        f.server.state().not_found = Some((key, Vec::new()));
        let err = f
            .bucket
            .fsck(&BucketFsckOptions::default())
            .await
            .unwrap_err();
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
    });
}

#[test]
fn a_summary_over_the_read_cap_gives_one_finding() {
    block_on(async {
        let f = Fixture::new(None).await;
        let big = vec![0u8; (64 << 20) + 1];
        f.put("summary", &big);
        let report = f.fsck().await;
        assert_eq!(kinds(&report), [(Summary, "summary".to_owned(), true)]);
        assert!(
            report.findings[0].detail.starts_with("is larger than"),
            "{}",
            report.findings[0]
        );
        // With the keys, a summary.sig over the cap gives one finding too.
        f.local
            .regenerate_summaries(&SummaryOptions::default(), &[&signer() as &dyn Signer])
            .await
            .unwrap();
        f.copy_file("summary");
        f.put("summary.sig", &big);
        drop(big);
        let mut opts = BucketFsckOptions::default();
        opts.summary_keys = Some(keys(false));
        let report = f.bucket.fsck(&opts).await.unwrap();
        assert_eq!(kinds(&report), [(Summary, "summary.sig".to_owned(), true)]);
        assert!(
            report.findings[0].detail.starts_with("is larger than"),
            "{}",
            report.findings[0]
        );
    });
}

// ---------------------------------------------------------------------------
// The markers, the refs of a deleted commit, and a repair that fails.
// ---------------------------------------------------------------------------

#[test]
fn a_marker_of_a_whole_tree_is_a_note_and_the_repair_deletes_it() {
    block_on(async {
        let f = Fixture::new(None).await;
        let marker = format!("state/{}.commitpartial", f.side.to_hex());
        f.put(&marker, &[0x66]);
        // The marker of a commit that the bucket does not hold stays.
        let gone = Checksum::sha256(b"no such commit");
        let other = format!("state/{}.commitpartial", gone.to_hex());
        f.put(&other, &[0x66]);
        let report = f.fsck().await;
        assert!(!report.has_errors(), "{:#?}", report.findings);
        assert_eq!(report.commits_partial, sorted(&[f.side, gone]));
        let notes: Vec<(BucketFindingKind, String, bool)> = kinds(&report)
            .into_iter()
            .filter(|(kind, _, _)| *kind == Marker)
            .collect();
        assert_eq!(notes, [(Marker, marker.clone(), false)]);
        f.server.state().requests.clear();
        let report = f.repair().await.unwrap();
        assert_eq!(report.cleared_partial, [f.side]);
        assert!(report.marked_partial.is_empty() && report.deleted.is_empty());
        assert!(
            !report.findings.iter().any(|found| found.kind == Marker),
            "{:#?}",
            report.findings
        );
        assert!(f.get(&marker).is_none());
        assert!(f.get(&other).is_some());
        let writes: Vec<(String, String)> = f
            .requests()
            .into_iter()
            .filter(|(method, _)| method != "GET")
            .collect();
        assert_eq!(
            writes,
            [
                ("PUT".to_owned(), "extensions/ostrya/lock".to_owned()),
                ("PUT".to_owned(), "extensions/ostrya/lock".to_owned()),
                ("DELETE".to_owned(), marker.clone()),
                ("DELETE".to_owned(), "extensions/ostrya/lock".to_owned()),
            ]
        );
        // The marker of a commit with a missing object of its tree stays.
        f.put(&marker, &[0x66]);
        let nested = f.entry(&f.head, &["sub", "deep"], "nested", false).await;
        f.remove(ObjectType::File, &nested);
        let report = f.repair().await.unwrap();
        assert!(report.cleared_partial.is_empty());
        let marked: Vec<Checksum> = report
            .marked_partial
            .iter()
            .map(|(commit, _)| *commit)
            .collect();
        assert_eq!(marked, sorted(&[f.first, f.head]));
        assert!(f.get(&marker).is_some());
    });
}

#[test]
fn a_failed_delete_keeps_the_record_of_each_change_and_names_the_ref_of_a_deleted_commit() {
    block_on(async {
        let f = Fixture::new(None).await;
        let head_file = f.entry(&f.head, &[], "file", false).await;
        let first_file = f.entry(&f.first, &[], "file", false).await;
        let other = f.object(ObjectType::File, &first_file);
        f.replace(ObjectType::File, &head_file, &other);
        // The ref `side` names a commit whose bytes are bad.
        let other = f.object(ObjectType::Commit, &f.first);
        f.replace(ObjectType::Commit, &f.side, &other);
        let file_key = object_path(ObjectType::File, &head_file);
        f.server.state().refuse = Some(("DELETE", format!("repo/{file_key}")));
        let err = f.repair().await.unwrap_err();
        let Error::BucketRepairIncomplete { report, error, .. } = &err else {
            panic!("{err}");
        };
        assert!(
            matches!(
                &**error,
                Error::Remote(ostrya::remote::Error::S3 { status: 403, .. })
            ),
            "{err}"
        );
        assert_eq!(
            report.marked_partial,
            [(f.head, vec!["refs/heads/main".to_owned()])]
        );
        assert_eq!(report.deleted, [object_path(ObjectType::Commit, &f.side)]);
        assert_eq!(
            report.deleted_ref_targets,
            [(f.side, vec!["refs/heads/side".to_owned()])]
        );
        assert!(f.get(&file_key).is_some());
        // The run released its lock.
        assert!(!f.server.state().objects.contains_key(LOCK));
        // A run again deletes the object, and the ref names an absent commit.
        f.server.state().refuse = None;
        let report = f.repair().await.unwrap();
        assert_eq!(report.deleted, [file_key]);
        assert!(report.marked_partial.is_empty() && report.deleted_ref_targets.is_empty());
        assert_eq!(
            kinds(&report)
                .into_iter()
                .filter(|(kind, _, _)| *kind == Ref)
                .collect::<Vec<_>>(),
            [(Ref, "refs/heads/side".to_owned(), true)]
        );
    });
}

#[test]
fn the_repair_leaves_the_image_of_a_commit_that_it_deletes() {
    block_on(async {
        let f = Fixture::new(None).await;
        let image = image_commit(&f).await;
        let other = f.object(ObjectType::Commit, &f.side);
        f.replace(ObjectType::Commit, &image, &other);
        let report = f.repair().await.unwrap();
        assert_eq!(report.orphan_images, [image]);
        assert!(
            !report.findings.iter().any(|found| found
                .object
                .is_some_and(|name| name.ty == ObjectType::ComposefsImage)),
            "{:#?}",
            report.findings
        );
        assert_eq!(report.deleted, [object_path(ObjectType::Commit, &image)]);
        assert_eq!(
            report.deleted_ref_targets,
            [(image, vec!["refs/heads/img".to_owned()])]
        );
        assert!(
            f.get(&object_path(ObjectType::ComposefsImage, &image))
                .is_some()
        );
    });
}

#[cfg(feature = "push")]
async fn push_main(f: &Fixture) {
    let opts = ostrya::RepoPushOptions {
        refspecs: vec!["main".to_owned()],
        ..ostrya::RepoPushOptions::default()
    };
    f.local
        .push_to_bucket(endpoint(&f.server.endpoint(), ADDRESS), opts)
        .await
        .unwrap();
}

#[cfg(feature = "push")]
#[test]
fn a_push_lists_the_markers_only_if_the_bucket_holds_an_offered_commit() {
    block_on(async {
        let f = Fixture::new(None).await;
        let next = commit(&f.local, f.tmp.path(), "main", "next", Some(f.head)).await;
        let state_lists = |f: &Fixture| {
            f.server
                .state()
                .requests
                .iter()
                .filter(|(method, target)| {
                    method == "GET" && target.contains("prefix=repo%2Fstate%2F")
                })
                .count()
        };
        f.server.state().requests.clear();
        push_main(&f).await;
        assert!(f.get(&object_path(ObjectType::Commit, &next)).is_some());
        assert_eq!(state_lists(&f), 0, "{:?}", f.server.state().requests);
        // A push of a commit that the bucket holds lists `state/` once.
        f.server.state().requests.clear();
        push_main(&f).await;
        assert_eq!(state_lists(&f), 1, "{:?}", f.server.state().requests);
    });
}

// ---------------------------------------------------------------------------
// Real servers.
// ---------------------------------------------------------------------------

/// Copies each file of the repository at `repo` into the directory of the
/// bucket repository `root/bkt/repo`, with the config `config` and the ref
/// files `refs`.
fn fill(root: &Path, repo: &Repo, config: &str, refs: &[(&str, &Checksum)]) {
    let dir = root.join("bkt/repo");
    for (name, bytes) in common::file_inventory(repo.path(), "objects") {
        let path = dir.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
    std::fs::write(dir.join("config"), config).unwrap();
    for (key, commit) in refs {
        let path = dir.join(key);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, format!("{}\n", commit.to_hex())).unwrap();
    }
}

#[test]
fn a_read_only_fsck_on_rclone_and_a_refused_repair() {
    if !rclone_available("a_read_only_fsck_on_rclone_and_a_refused_repair") {
        return;
    }
    block_on(async {
        let f = Fixture::new(None).await;
        let root = f.tmp.path().join("served");
        fill(&root, &f.local, PLAIN, &[("refs/heads/main", &f.head)]);
        let head_file = f.entry(&f.head, &[], "file", false).await;
        let first_file = f.entry(&f.first, &[], "file", false).await;
        let dir = root.join("bkt/repo");
        std::fs::copy(
            dir.join(object_path(ObjectType::File, &first_file)),
            dir.join(object_path(ObjectType::File, &head_file)),
        )
        .unwrap();
        std::fs::write(dir.join("objects/abc"), b"stray").unwrap();
        std::fs::create_dir_all(dir.join("objects/zz")).unwrap();
        std::fs::write(dir.join("objects/zz/x"), b"stray").unwrap();
        let server = Rclone::start(f.tmp.path(), &root);
        let bucket = BucketRepo::open(&endpoint(&server.endpoint(), ADDRESS))
            .await
            .unwrap();
        let report = bucket.fsck(&BucketFsckOptions::default()).await.unwrap();
        let found = finding(&report, Mismatch, ObjectType::File, &head_file);
        assert_eq!(found.commits, [f.head]);
        let strays: Vec<&str> = report
            .findings
            .iter()
            .filter(|found| found.kind == Stray)
            .map(|found| found.key.as_str())
            .collect();
        assert_eq!(strays, ["objects/abc", "objects/zz/x"]);
        assert_eq!(report.commits_checked, 3);
        let before = common::file_inventory(&root, "bkt");
        let mut opts = BucketFsckOptions::default();
        opts.delete = true;
        let err = bucket.fsck(&opts).await.unwrap_err();
        assert!(matches!(err, Error::BucketNoExclusion { .. }), "{err}");
        assert_eq!(common::file_inventory(&root, "bkt"), before);
        // A wrong secret fails the run.
        let mut s3 = endpoint(&server.endpoint(), ADDRESS);
        s3.credentials = ostrya::remote::s3::Credentials::new(
            common::s3::ACCESS_KEY.into(),
            "wrongsecret".into(),
            None,
        )
        .unwrap();
        let wrong = BucketRepo::open(&s3).await.unwrap();
        let err = wrong.fsck(&BucketFsckOptions::default()).await.unwrap_err();
        assert!(
            matches!(
                &err,
                Error::Remote(ostrya::remote::Error::S3 { code: Some(code), .. })
                    if code == "SignatureDoesNotMatch"
            ),
            "{err}"
        );
    });
}

/// A body of `len` bytes and then no end: a read after the last byte waits
/// for ever.
#[cfg(feature = "push")]
struct Stalled {
    left: usize,
}

#[cfg(feature = "push")]
impl futures_io::AsyncRead for Stalled {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.left == 0 {
            return std::task::Poll::Pending;
        }
        let n = buf.len().min(self.left);
        buf[..n].fill(7);
        self.left -= n;
        std::task::Poll::Ready(Ok(n))
    }
}

#[cfg(feature = "push")]
#[test]
fn a_fsck_and_a_repair_on_seaweedfs() {
    use common::s3::{Seaweed, seaweed_available};
    if !seaweed_available("a_fsck_and_a_repair_on_seaweedfs") {
        return;
    }
    // The start of the server runs its own `block_on`, so it comes before
    // the one of the test.
    let scratch = TmpDir::new("bucket-fsck-weed");
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
        let report = bucket.fsck(&BucketFsckOptions::default()).await.unwrap();
        assert!(
            report.findings.iter().all(|found| !found.error),
            "{:#?}",
            report.findings
        );
        // A push with no depth sends the tips alone.
        assert_eq!(report.commits_checked, 2);
        assert_eq!(report.objects_unreached, 0);

        // A changed object, two strays, a summary, a delta with a `+` in its
        // key, and an incomplete upload.
        let head_file = f.entry(&f.head, &[], "file", false).await;
        let first_file = f.entry(&f.first, &[], "file", false).await;
        let other = f.object(ObjectType::File, &first_file);
        bucket
            .bucket()
            .put(&object_path(ObjectType::File, &head_file), other)
            .await
            .unwrap();
        server.put_raw("bkt", "repo/objects/abc", b"stray");
        server.put_raw("bkt", "repo/objects/zz/x", b"stray");
        f.local
            .regenerate_summary(&SummaryOptions::default())
            .await
            .unwrap();
        let summary = std::fs::read(f.local.path().join("summary")).unwrap();
        bucket.bucket().put("summary", summary).await.unwrap();
        let mut to = [7u8; 32];
        to[0] = 0xfb;
        to[1] = 0xff;
        let to = Checksum::from_bytes(to);
        let b64 = to.to_base64_modified();
        assert!(b64.contains('+'), "{b64}");
        bucket
            .bucket()
            .put(
                &format!("deltas/{}/{}/superblock", &b64[..2], &b64[2..]),
                b"superblock".to_vec(),
            )
            .await
            .unwrap();
        let upload_key = object_path(ObjectType::File, &Checksum::sha256(b"upload"));
        let started = {
            let put = async {
                let _ = bucket
                    .bucket()
                    .put_stream(
                        &upload_key,
                        Stalled {
                            left: (5 << 20) + 1,
                        },
                        5 << 20,
                    )
                    .await;
            };
            let listed = async {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
                loop {
                    let uploads = bucket.bucket().list_uploads().await.unwrap();
                    if !uploads.is_empty() {
                        return uploads;
                    }
                    assert!(
                        std::time::Instant::now() < deadline,
                        "SeaweedFS listed no incomplete upload within 30 s"
                    );
                    ostrya_rt::Timer::after(std::time::Duration::from_millis(100)).await;
                }
            };
            futures_lite::future::or(
                async {
                    put.await;
                    Vec::new()
                },
                listed,
            )
            .await
        };
        assert_eq!(started.len(), 1, "{started:?}");
        let report = bucket.fsck(&BucketFsckOptions::default()).await.unwrap();
        let found = finding(&report, Mismatch, ObjectType::File, &head_file);
        assert_eq!(found.commits, [f.head]);
        let rest: Vec<(BucketFindingKind, String, bool)> = kinds(&report)
            .into_iter()
            .filter(|(kind, _, _)| *kind != Mismatch)
            .collect();
        assert_eq!(
            rest,
            [
                (Stray, "objects/abc".to_owned(), true),
                (Upload, upload_key.clone(), false),
                (Stray, "objects/zz/x".to_owned(), true),
                (Summary, "summary".to_owned(), false),
            ]
        );
        let note = report
            .findings
            .iter()
            .find(|found| found.kind == Summary)
            .unwrap();
        assert!(
            note.detail
                .ends_with(&format!("1 delta(s) of the bucket are not in it: {to}")),
            "{note}"
        );

        // The repair marks `head` and deletes the object, and a push of
        // `main` uploads it again and removes the marker.
        let mut opts = BucketFsckOptions::default();
        opts.delete = true;
        let report = bucket.fsck(&opts).await.unwrap();
        assert_eq!(
            report.marked_partial,
            [(f.head, vec!["refs/heads/main".to_owned()])]
        );
        assert_eq!(report.deleted, [object_path(ObjectType::File, &head_file)]);
        let opts = ostrya::RepoPushOptions {
            refspecs: vec!["main".to_owned()],
            ..ostrya::RepoPushOptions::default()
        };
        f.local.push_to_bucket(s3.clone(), opts).await.unwrap();
        let report = bucket.fsck(&BucketFsckOptions::default()).await.unwrap();
        assert!(report.commits_partial.is_empty());
        assert!(
            !report
                .findings
                .iter()
                .any(|found| matches!(found.kind, Mismatch | Missing)),
            "{:#?}",
            report.findings
        );
        bucket
            .bucket()
            .abort_upload(&upload_key, &started[0].upload_id)
            .await
            .unwrap();
    });
}
