//! Repository fs-verity (ex-integrity) write-path integration tests (Phase
//! pre13).
//!
//! These drive commits through the write path with `[ex-integrity] fsverity`
//! set and observe the loose objects: every object stored as a regular file is
//! sealed with fs-verity, real symlink objects are skipped, `maybe` is best
//! effort, and `yes` fails where the filesystem cannot provide verity. A sealed
//! regular file is detected by a rejected write-open, which needs no privileged
//! syscall. Every check that requires a working verity kernel is gated on
//! filesystem support, so the suite passes on filesystems without it.

mod common;

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::{TmpDir, ostree_available};
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, Error,
    MutableTree, Repo, RepoMode,
};
use ostrya_rt::block_on;
use std::os::fd::AsFd;

/// Build a small source tree under `base/src`: two regular files (one nested),
/// and a symlink, so a commit produces content, dirtree, dirmeta, and commit
/// objects plus one symlink object.
fn build_source(base: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let chmod = |p: PathBuf, m: u32| {
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(m)).unwrap();
    };
    let src = base.join("src");
    std::fs::create_dir_all(src.join("subdir")).unwrap();
    std::fs::write(src.join("hello.txt"), b"hello fs-verity\n").unwrap();
    std::fs::write(src.join("subdir/nested.txt"), b"nested payload\n").unwrap();
    std::os::unix::fs::symlink("hello.txt", src.join("link")).unwrap();
    chmod(src.join("hello.txt"), 0o644);
    chmod(src.join("subdir/nested.txt"), 0o644);
    chmod(src.join("subdir"), 0o755);
    chmod(src.clone(), 0o755);
}

/// Create a repository at `root` in `mode`, set `[ex-integrity] fsverity` to
/// `fsverity`, and reopen it so the setting is parsed.
async fn make_repo(root: &Path, mode: RepoMode, fsverity: &str) -> Repo {
    drop(Repo::create(root, CreateOptions::new(mode)).await.unwrap());
    let cfg = root.join("config");
    let mut text = std::fs::read_to_string(&cfg).unwrap();
    text.push_str(&format!("[ex-integrity]\nfsverity={fsverity}\n"));
    std::fs::write(&cfg, text).unwrap();
    Repo::open(root).await.unwrap()
}

/// Ingest `base/src` with canonical permissions (owner 0:0, unprivileged-safe),
/// write the tree and a commit, and point `test/main` at it.
async fn commit_source(repo: &Repo, base: &Path) -> Result<Checksum, Error> {
    let txn = repo.transaction().await?;
    let mut modifier = CommitModifier::new(
        CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::SKIP_XATTRS,
    );
    let mut mtree = MutableTree::new();
    let dfd = std::fs::File::open(base).unwrap();
    txn.write_dfd_to_mtree(
        dfd.as_fd(),
        Path::new("src"),
        &mut mtree,
        Some(&mut modifier),
    )
    .await?;
    let root = txn.write_mtree(&mut mtree).await?;
    let commit = txn.write_commit(CommitOptions::default(), &root).await?;
    txn.set_ref("test/main", Some(&commit));
    txn.commit().await?;
    Ok(commit)
}

/// Whether a regular file is sealed with fs-verity: a sealed file rejects being
/// opened for writing. The objects examined are owner-writable (mode 0644), so a
/// write-open failure signals verity rather than permissions.
fn is_sealed(path: &Path) -> bool {
    OpenOptions::new().write(true).open(path).is_err()
}

/// Classify the loose objects under `root/objects`: return (regular-file object
/// paths, count of real-symlink objects).
fn loose_objects(root: &Path) -> (Vec<PathBuf>, usize) {
    let mut regulars = Vec::new();
    let mut symlinks = 0usize;
    let objects = root.join("objects");
    for fanout in std::fs::read_dir(&objects).unwrap() {
        let fanout = fanout.unwrap();
        if !fanout.file_type().unwrap().is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(fanout.path()).unwrap() {
            let entry = entry.unwrap();
            let meta = std::fs::symlink_metadata(entry.path()).unwrap();
            if meta.file_type().is_symlink() {
                symlinks += 1;
            } else if meta.file_type().is_file() {
                regulars.push(entry.path());
            }
        }
    }
    (regulars, symlinks)
}

/// Whether the test's temporary filesystem supports fs-verity, probed by
/// committing one object with `fsverity=maybe` and checking whether it sealed.
async fn fs_supports_verity(tmp: &TmpDir) -> bool {
    let root = tmp.path().join("probe-repo");
    let base = tmp.path().join("probe");
    build_source(&base);
    let repo = make_repo(&root, RepoMode::BareUserShared, "maybe").await;
    commit_source(&repo, &base).await.unwrap();
    let (regulars, _) = loose_objects(&root);
    regulars.iter().any(|p| is_sealed(p))
}

#[test]
fn seals_every_regular_object_when_supported() {
    block_on(async {
        let tmp = TmpDir::new("fsverity-seals");
        if !fs_supports_verity(&tmp).await {
            eprintln!("skipping: filesystem does not support fs-verity");
            return;
        }
        // bare-user-shared stores objects at mode 0644 and symlinks as regular
        // files, so every object is a regular file and must be sealed.
        let base = tmp.path().join("shared");
        build_source(&base);
        let root = tmp.path().join("shared-repo");
        let repo = make_repo(&root, RepoMode::BareUserShared, "yes").await;
        commit_source(&repo, &base).await.unwrap();

        let (regulars, symlinks) = loose_objects(&root);
        assert!(
            regulars.len() >= 5,
            "content + dirtree + dirmeta + commit + symlink-as-file"
        );
        assert_eq!(
            symlinks, 0,
            "bare-user-shared stores symlinks as regular files"
        );
        for path in &regulars {
            assert!(is_sealed(path), "object not sealed: {}", path.display());
        }
    });
}

#[test]
fn skips_real_symlink_objects_under_yes() {
    block_on(async {
        let tmp = TmpDir::new("fsverity-symlink-skip");
        if !fs_supports_verity(&tmp).await {
            eprintln!("skipping: filesystem does not support fs-verity");
            return;
        }
        // bare-user-only stores real symlink objects. Under `yes` the commit
        // must still succeed, which proves the symlink object was skipped (a
        // verity-enable attempt on a symlink would fail and fail the commit).
        let base = tmp.path().join("only");
        build_source(&base);
        let root = tmp.path().join("only-repo");
        let repo = make_repo(&root, RepoMode::BareUserOnly, "yes").await;
        commit_source(&repo, &base)
            .await
            .expect("yes commit succeeds: the real symlink object is skipped");

        let (regulars, symlinks) = loose_objects(&root);
        assert_eq!(
            symlinks, 1,
            "the one symlink is stored as a real symlink object"
        );
        for path in &regulars {
            assert!(
                is_sealed(path),
                "regular object not sealed: {}",
                path.display()
            );
        }
    });
}

#[test]
fn maybe_commits_regardless_of_support() {
    // `maybe` is best effort: the commit succeeds whether or not the filesystem
    // can seal objects.
    block_on(async {
        let tmp = TmpDir::new("fsverity-maybe");
        let base = tmp.path().join("src-base");
        build_source(&base);
        let root = tmp.path().join("maybe-repo");
        let repo = make_repo(&root, RepoMode::BareUserShared, "maybe").await;
        commit_source(&repo, &base)
            .await
            .expect("maybe commit always succeeds");
    });
}

#[test]
fn yes_fails_without_filesystem_support() {
    // On a filesystem without fs-verity, `yes` fails the commit. tmpfs (found at
    // /dev/shm on Linux) never supports verity; where it is unavailable or, in
    // an unusual setup, does support verity, the check is skipped.
    let shm = PathBuf::from("/dev/shm");
    if !shm.is_dir() {
        eprintln!("skipping: no tmpfs at /dev/shm");
        return;
    }
    let dir = shm.join(format!("ostrya-fsverity-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let result = block_on(async {
        // If tmpfs somehow sealed a maybe-commit, it supports verity: skip.
        let probe_root = dir.join("probe-repo");
        let probe_base = dir.join("probe");
        build_source(&probe_base);
        let probe = make_repo(&probe_root, RepoMode::BareUserShared, "maybe").await;
        commit_source(&probe, &probe_base).await.unwrap();
        let (regulars, _) = loose_objects(&probe_root);
        if regulars.iter().any(|p| is_sealed(p)) {
            return None;
        }

        let base = dir.join("src-base");
        build_source(&base);
        let root = dir.join("yes-repo");
        let repo = make_repo(&root, RepoMode::BareUserShared, "yes").await;
        Some(commit_source(&repo, &base).await)
    });
    let _ = std::fs::remove_dir_all(&dir);

    match result {
        None => eprintln!("skipping: /dev/shm unexpectedly supports fs-verity"),
        Some(Ok(_)) => panic!("yes commit should fail on a filesystem without fs-verity"),
        Some(Err(err)) => {
            let msg = err.to_string();
            assert!(msg.contains("fsverity"), "unexpected error: {msg}");
        }
    }
}

#[test]
fn tool_reads_a_port_written_verity_repo() {
    if !ostree_available() {
        eprintln!("skipping: ostree tool not available");
        return;
    }
    block_on(async {
        let tmp = TmpDir::new("fsverity-tool-read");
        if !fs_supports_verity(&tmp).await {
            eprintln!("skipping: filesystem does not support fs-verity");
            return;
        }
        // archive is a mode the tool recognizes; its objects are regular files
        // and are sealed. The tool reads verity-sealed objects transparently.
        let base = tmp.path().join("archive");
        build_source(&base);
        let root = tmp.path().join("archive-repo");
        let repo = make_repo(&root, RepoMode::Archive, "yes").await;
        commit_source(&repo, &base).await.unwrap();

        // Sanity: the objects really are sealed.
        let (regulars, _) = loose_objects(&root);
        assert!(
            regulars.iter().all(|p| is_sealed(p)),
            "archive objects sealed"
        );

        let fsck = Command::new("ostree")
            .arg(format!("--repo={}", root.display()))
            .arg("fsck")
            .output()
            .unwrap();
        assert!(
            fsck.status.success(),
            "ostree fsck failed: {}",
            String::from_utf8_lossy(&fsck.stderr)
        );

        let ls = Command::new("ostree")
            .arg(format!("--repo={}", root.display()))
            .args(["ls", "-R", "test/main"])
            .output()
            .unwrap();
        assert!(
            ls.status.success(),
            "ostree ls failed: {}",
            String::from_utf8_lossy(&ls.stderr)
        );
    });
}
