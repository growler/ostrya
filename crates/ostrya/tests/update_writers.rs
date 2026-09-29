//! The writers of refs, config, summary, and detached metadata take the update
//! lock: each waits for an `UpdateGuard` that another process or another task
//! holds, and with `lock-timeout-secs=0` each fails with `LockTimeout` and
//! writes nothing. A transaction publishes its objects under a held guard and
//! waits only at the step that writes detached metadata and refs. Two
//! processes that sign one commit keep both signatures.

mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::{
    GUARD_HELD_MARKER, GUARD_RELEASING_MARKER, TmpDir, file_inventory, guard_holder,
    guard_holder_main, lock_holder_main, writer_child, writer_child_main,
};
use futures_lite::future::poll_once;
use ostrya::{
    Checksum, CollectionRef, CommitOptions, CreateOptions, DirMeta, Ed25519Signer, Ed25519Verifier,
    Error, MutableTree, ObjectType, Repo, RepoMode, SummaryOptions, Value,
};
use ostrya_rt::block_on;

/// The base64 of two 64-byte ed25519 secret keys (seed followed by public
/// key).
const SECRET_B64: &str =
    "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";
const OTHER_SECRET_B64: &str =
    "5ILWxT+l9G/u3h0BptRpmSi35C9uog7YDdD+Fp1Xk+Hz52p0NlYh6xBA73kJEJKhKbbnjcE0rsWA5XA/K5Sq5Q==";

/// The detached metadata key of the ed25519 engine.
const ED25519_KEY: &str = "ostree.sign.ed25519";

/// The trusted keyring of the remote `origin`, at the repository root.
const KEYRING: &str = "origin.trustedkeys.gpg";

#[test]
#[ignore = "helper process for the update writer tests"]
fn lock_holder_subprocess() {
    lock_holder_main();
}

#[test]
#[ignore = "helper process for the update writer tests"]
fn guard_holder_subprocess() {
    guard_holder_main();
}

/// The writer child signs the commit its argument names, as `<secret>
/// <commit>`, and writes nothing else in the repository. Right before the
/// call that signs, it writes the marker [`signing_marker`] names beside the
/// repository.
#[test]
#[ignore = "helper process for the update writer tests"]
fn writer_child_subprocess() {
    writer_child_main(|path, arg| {
        let (secret, commit) = arg.split_once(' ').unwrap();
        let commit = Checksum::from_hex(commit).unwrap();
        block_on(async {
            let repo = Repo::open(path).await.unwrap();
            let signer = Ed25519Signer::from_base64(secret).unwrap();
            let marker = signing_marker(path, &commit, std::process::id());
            std::fs::write(marker, b"1").unwrap();
            repo.sign_commit(&commit, &signer).await.unwrap();
        });
    });
}

/// The marker a writer child with the process id `pid` writes beside the
/// repository at `path` before it signs `commit`.
fn signing_marker(path: &Path, commit: &Checksum, pid: u32) -> PathBuf {
    let name = format!("signing-{}-{pid}", commit.to_hex());
    path.parent().unwrap().join(name)
}

/// The number of writer children that reached the signing call for `commit`
/// in the repository at `path`.
fn signing_children(path: &Path, commit: &Checksum) -> usize {
    let prefix = format!("signing-{}-", commit.to_hex());
    std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .filter(|entry| {
            let entry = entry.as_ref().unwrap();
            entry.file_name().to_string_lossy().starts_with(&prefix)
        })
        .count()
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// Replace `lock-timeout-secs` in the config of the repository at `path`.
fn set_timeout(path: &Path, secs: i64) {
    let config = path.join("config");
    let text = std::fs::read_to_string(&config).unwrap();
    let mut kept: String = text
        .lines()
        .filter(|l| !l.starts_with("lock-timeout-secs="))
        .map(|l| format!("{l}\n"))
        .collect();
    kept.push_str(&format!("lock-timeout-secs={secs}\n"));
    std::fs::write(&config, kept).unwrap();
}

fn open(path: &Path) -> Repo {
    block_on(Repo::open(path)).unwrap()
}

/// Commit an empty tree with `subject` onto `main`.
async fn commit_empty(repo: &Repo, subject: &str) -> Checksum {
    let txn = repo.transaction().await.unwrap();
    let dirmeta = DirMeta {
        uid: 0,
        gid: 0,
        mode: 0o40755,
        xattrs: Default::default(),
    }
    .serialize()
    .unwrap();
    let dirmeta = txn
        .write_metadata(ObjectType::DirMeta, None, &dirmeta)
        .await
        .unwrap();
    let mut mtree = MutableTree::new();
    mtree.set_metadata_checksum(dirmeta);
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(
            CommitOptions {
                subject: Some(subject.to_owned()),
                timestamp: Some(1_700_000_000),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    txn.set_ref("main", Some(&commit));
    txn.commit().await.unwrap();
    commit
}

/// A repository at `<tmp>/repo` that holds a commit on `main` with one
/// ed25519 signature, a summary, and a keyring of `origin`. Returns its path
/// and the commit.
fn populated(tmp: &TmpDir) -> (PathBuf, Checksum) {
    let path = tmp.path().join("repo");
    let commit = block_on(async {
        let repo = Repo::create(&path, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let commit = commit_empty(&repo, "update writers").await;
        let signer = Ed25519Signer::from_base64(SECRET_B64).unwrap();
        repo.sign_commit(&commit, &signer).await.unwrap();
        repo.regenerate_summary(&SummaryOptions {
            last_modified: Some(1_700_000_000),
            ..SummaryOptions::default()
        })
        .await
        .unwrap();
        commit
    });
    std::fs::write(path.join(KEYRING), b"keyring bytes").unwrap();
    (path, commit)
}

/// Every file of the repository outside `tmp/`, with its bytes. The update
/// lock file and the markers of the guard helper are left out.
fn snapshot(path: &Path) -> Vec<(String, Vec<u8>)> {
    file_inventory(path, "")
        .into_iter()
        .filter(|(name, _)| {
            !name.starts_with("tmp/") && !name.starts_with(".guard-") && name != ".update.lock"
        })
        .collect()
}

/// The ed25519 signatures the detached metadata of `commit` carries.
async fn ed25519_signatures(repo: &Repo, commit: &Checksum) -> usize {
    let Some(dict) = repo.read_commit_detached_metadata(commit).await.unwrap() else {
        return 0;
    };
    let Some(value) = dict.dict_get(ED25519_KEY) else {
        return 0;
    };
    let array = match value {
        Value::Variant(inner) => &inner.1,
        other => other,
    };
    array.as_array().map_or(0, <[Value]>::len)
}

/// Whether the detached metadata of `commit` carries a signature that the
/// ed25519 key `secret_b64` made.
async fn signed_by(repo: &Repo, commit: &Checksum, secret_b64: &str) -> bool {
    let public = ostrya::base64::decode(secret_b64).unwrap()[32..].to_vec();
    let verifier = Ed25519Verifier::new([public], Vec::<Vec<u8>>::new()).unwrap();
    repo.verify_commit(commit, &[&verifier])
        .await
        .unwrap()
        .valid
}

fn assert_timeout<T: std::fmt::Debug>(result: ostrya::Result<T>) {
    let err = result.unwrap_err();
    assert!(matches!(err, Error::LockTimeout { secs: 0 }), "{err:?}");
}

/// The writers of the update lock, each by its name. Each call writes
/// something when it runs, so a writer that does not wait for a held guard
/// changes the snapshot. `gpg_import_keys` builds under the `verify-gpg`
/// feature alone.
const WRITERS: [&str; 12] = [
    "set_ref_immediate",
    "set_collection_ref_immediate",
    "set_ref_alias_immediate",
    "write_config",
    "remove_remote_keyring",
    "gpg_import_keys",
    "regenerate_summary",
    "sign_summary",
    "write_commit_detached_metadata",
    "sign_commit",
    "delete_signatures",
    "transaction_commit",
];

/// The writers of [`WRITERS`] that this build carries.
fn writers() -> impl Iterator<Item = &'static str> {
    WRITERS
        .into_iter()
        .filter(|name| *name != "gpg_import_keys" || cfg!(feature = "verify-gpg"))
}

/// Run the writer `name` against `repo`, over the commit `commit`.
async fn run_writer(repo: &Repo, name: &str, commit: &Checksum) -> ostrya::Result<()> {
    let other = Ed25519Signer::from_base64(OTHER_SECRET_B64).unwrap();
    match name {
        "set_ref_immediate" => repo.set_ref_immediate("other", Some(commit)).await,
        "set_collection_ref_immediate" => {
            let cref = CollectionRef::new("org.example.C", "app/main");
            repo.set_collection_ref_immediate(&cref, Some(commit)).await
        }
        "set_ref_alias_immediate" => repo.set_ref_alias_immediate("current", "main").await,
        "write_config" => {
            let mut keyfile = repo.config().keyfile().clone();
            keyfile.set_value("ex-test", "written", "yes").unwrap();
            repo.write_config(&keyfile).await
        }
        "remove_remote_keyring" => repo.remove_remote_keyring("origin").await,
        #[cfg(feature = "verify-gpg")]
        "gpg_import_keys" => match repo.gpg_import_keys("origin", b"", &[]).await {
            // The empty stream holds no certificate, so the import is refused
            // once it holds the lock.
            Err(Error::LockTimeout { secs }) => Err(Error::LockTimeout { secs }),
            _ => Ok(()),
        },
        "regenerate_summary" => {
            repo.regenerate_summary(&SummaryOptions {
                last_modified: Some(1_700_000_001),
                ..SummaryOptions::default()
            })
            .await
        }
        "sign_summary" => repo.sign_summary(&other).await,
        "write_commit_detached_metadata" => repo.write_commit_detached_metadata(commit, None).await,
        "sign_commit" => repo.sign_commit(commit, &other).await,
        "delete_signatures" => repo
            .delete_signatures(commit, ED25519_KEY, |_, _| true)
            .await
            .map(drop),
        "transaction_commit" => {
            let txn = repo.transaction().await?;
            txn.set_ref("other", Some(commit));
            txn.commit().await.map(drop)
        }
        other => panic!("no writer {other}"),
    }
}

// ---------------------------------------------------------------------------
// A guard in another process.
// ---------------------------------------------------------------------------

/// A guard that another process holds makes each writer fail at once with
/// `lock-timeout-secs=0`, with nothing written, and wait with `-1` until the
/// holder released the guard.
#[test]
fn a_foreign_guard_makes_each_writer_wait() {
    let tmp = TmpDir::new("writers-foreign");
    let (path, commit) = populated(&tmp);
    set_timeout(&path, 0);
    let no_wait = open(&path);
    set_timeout(&path, -1);
    let no_limit = open(&path);

    let holder = guard_holder(&path);
    let before = snapshot(&path);
    for name in writers() {
        assert_timeout(block_on(run_writer(&no_wait, name, &commit)));
        assert!(snapshot(&path) == before, "{name} wrote under the guard");
    }
    holder.release();

    for name in writers() {
        // Each helper waits for its own readiness marker and writes its own
        // releasing marker.
        let marker = path.join(GUARD_RELEASING_MARKER);
        let _ = std::fs::remove_file(&marker);
        let _ = std::fs::remove_file(path.join(GUARD_HELD_MARKER));
        let holder = guard_holder(&path);
        // The releasing marker proves the order, so the release needs no
        // delay.
        let release = std::thread::spawn(move || holder.release());
        block_on(run_writer(&no_limit, name, &commit)).unwrap();
        assert!(marker.exists(), "{name} ran only after the release");
        release.join().unwrap();
    }
}

// ---------------------------------------------------------------------------
// A guard in another task of this process.
// ---------------------------------------------------------------------------

/// A guard that another task of this process holds makes each writer fail at
/// once with `lock-timeout-secs=0`, with nothing written, and wait with a
/// longer timeout until the guard is finished.
#[test]
fn an_in_process_guard_makes_each_writer_wait() {
    let tmp = TmpDir::new("writers-in-process");
    let (path, commit) = populated(&tmp);
    set_timeout(&path, 0);
    let no_wait = open(&path);
    set_timeout(&path, 30);
    let repo = open(&path);

    block_on(async {
        let guard = repo.begin_update().await.unwrap();
        let before = snapshot(&path);
        for name in writers() {
            assert_timeout(run_writer(&no_wait, name, &commit).await);
            assert!(snapshot(&path) == before, "{name} wrote under the guard");
        }
        guard.finish().await.unwrap();

        for name in writers() {
            let guard = repo.begin_update().await.unwrap();
            let mut writing = Box::pin(run_writer(&repo, name, &commit));
            assert!(poll_once(&mut writing).await.is_none(), "{name} waits");
            let before = snapshot(&path);
            assert!(poll_once(&mut writing).await.is_none(), "{name} waits");
            assert!(snapshot(&path) == before, "{name} wrote under the guard");
            guard.finish().await.unwrap();
            writing.await.unwrap();
        }
    });
}

// ---------------------------------------------------------------------------
// Transactions.
// ---------------------------------------------------------------------------

/// A transaction publishes its objects while another process holds a guard,
/// and waits only at the step that writes its ref: with
/// `lock-timeout-secs=0` it fails there with the objects published and no
/// ref, and with `-1` it writes the ref after the release.
#[test]
fn a_transaction_publishes_under_a_guard_and_waits_at_the_ref_step() {
    let tmp = TmpDir::new("writers-transaction");
    let (path, _) = populated(&tmp);
    set_timeout(&path, 0);
    let no_wait = open(&path);
    set_timeout(&path, -1);
    let no_limit = open(&path);

    let holder = guard_holder(&path);
    let refused = block_on(async {
        let txn = no_wait.transaction().await.unwrap();
        let commit = commit_in(&txn, "refused").await;
        txn.set_ref("refused", Some(&commit));
        assert_timeout(txn.commit().await);
        commit
    });
    block_on(async {
        assert!(
            no_wait
                .has_object(ObjectType::Commit, &refused)
                .await
                .unwrap()
        );
        assert_eq!(no_wait.resolve_ref_tip("refused").await.unwrap(), None);
    });

    let release = std::thread::spawn(move || holder.release());
    let commit = block_on(async {
        let txn = no_limit.transaction().await.unwrap();
        let commit = commit_in(&txn, "waited").await;
        txn.set_ref("waited", Some(&commit));
        txn.commit().await.unwrap();
        commit
    });
    assert!(path.join(GUARD_RELEASING_MARKER).exists());
    release.join().unwrap();
    assert_eq!(
        block_on(no_limit.resolve_ref_tip("waited")).unwrap(),
        Some(commit)
    );
}

/// A transaction that writes no ref and no detached metadata commits while
/// another process holds a guard.
#[test]
fn a_transaction_with_no_ref_and_no_detached_metadata_commits_under_a_guard() {
    let tmp = TmpDir::new("writers-transaction-no-ref");
    let (path, _) = populated(&tmp);
    set_timeout(&path, 0);
    let repo = open(&path);

    let holder = guard_holder(&path);
    block_on(async {
        let txn = repo.transaction().await.unwrap();
        let commit = commit_in(&txn, "no ref").await;
        txn.commit().await.unwrap();
        assert!(repo.has_object(ObjectType::Commit, &commit).await.unwrap());
    });
    holder.release();
}

/// Stage a commit of an empty tree with `subject` in `txn`.
async fn commit_in(txn: &ostrya::Transaction, subject: &str) -> Checksum {
    let dirmeta = DirMeta {
        uid: 0,
        gid: 0,
        mode: 0o40755,
        xattrs: Default::default(),
    }
    .serialize()
    .unwrap();
    let dirmeta = txn
        .write_metadata(ObjectType::DirMeta, None, &dirmeta)
        .await
        .unwrap();
    let mut mtree = MutableTree::new();
    mtree.set_metadata_checksum(dirmeta);
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    txn.write_commit(
        CommitOptions {
            subject: Some(subject.to_owned()),
            timestamp: Some(1_700_000_000),
            ..CommitOptions::default()
        },
        &root,
    )
    .await
    .unwrap()
}

// ---------------------------------------------------------------------------
// Signatures.
// ---------------------------------------------------------------------------

/// Two processes that sign one commit at the same time keep both
/// signatures: once while a third process holds a guard, and in rounds with
/// no guard. Under the guard both children reach the signing call, and
/// neither exits until the guard is released, so both wait for the lock.
#[test]
fn two_processes_signing_one_commit_keep_both_signatures() {
    let tmp = TmpDir::new("writers-two-signers");
    let path = tmp.path().join("repo");
    let commits = block_on(async {
        let repo = Repo::create(&path, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let mut commits = Vec::new();
        for round in 0..4 {
            commits.push(commit_empty(&repo, &format!("round {round}")).await);
        }
        commits
    });
    set_timeout(&path, -1);
    let repo = open(&path);

    let holder = guard_holder(&path);
    let arg = |secret: &str, commit: &Checksum| format!("{secret} {}", commit.to_hex());
    let mut first = writer_child(&path, &arg(SECRET_B64, &commits[0]));
    let mut second = writer_child(&path, &arg(OTHER_SECRET_B64, &commits[0]));
    let deadline = Instant::now() + Duration::from_secs(30);
    while signing_children(&path, &commits[0]) < 2 {
        assert!(Instant::now() < deadline, "the signers never started");
        std::thread::sleep(Duration::from_millis(10));
    }
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !first.finished() && !second.finished(),
        "a signer finished while the guard was held"
    );
    holder.release();
    first.wait();
    second.wait();

    for commit in &commits[1..] {
        let first = writer_child(&path, &arg(SECRET_B64, commit));
        let second = writer_child(&path, &arg(OTHER_SECRET_B64, commit));
        first.wait();
        second.wait();
    }

    block_on(async {
        for commit in &commits {
            assert_eq!(ed25519_signatures(&repo, commit).await, 2, "{commit:?}");
            assert!(signed_by(&repo, commit, SECRET_B64).await);
            assert!(signed_by(&repo, commit, OTHER_SECRET_B64).await);
        }
    });
}
