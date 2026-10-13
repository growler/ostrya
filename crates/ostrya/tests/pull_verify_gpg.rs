//! Tests of GPG verification in a pull.
//!
//! GPG verification is the same for each source of a pull. These tests use a
//! local pull, which needs no server. They test the sources of the trusted
//! keyrings and the error that each refusal reports.
//!
//! Each test generates a temporary signing key in a private GnuPG home
//! directory under its scratch tree. ostrya signs a commit through the `gpg`
//! binary. The pull verifies the signature in the process against the
//! exported keyring. The tests do not use the GnuPG home or the agent of the
//! user.

#![cfg(feature = "sign-gpg")]

mod common;

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::TmpDir;
use ostrya::{
    AdvertisedDelta, Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CommitState,
    CreateOptions, DeltaOptions, Error, GpgSigner, MutableTree, PullOptions, PullVerify, Repo,
    RepoMode,
};
use ostrya_rt::block_on;

/// A fixed timestamp that makes the commit of a source repository
/// reproducible.
const FIXED_TS: u64 = 1_700_000_000;

/// Returns `true` if the `gpg` binary is available.
///
/// The GnuPG tests build their fixtures with `gpg`. If it is absent, these
/// tests skip: they return before an assertion runs.
/// [`common::REQUIRE_GNUPG`] changes the skip into a failure.
fn gpg_available() -> bool {
    common::gnupg_available(&["gpg"])
}

/// A private GnuPG home directory with one new ed25519 signing key.
///
/// The key has no passphrase. A drop of the fixture stops the GnuPG daemons
/// of the directory and removes their socket directory.
struct GpgHome {
    dir: PathBuf,
}

impl GpgHome {
    /// Generates a signing key for `uid` in a new home directory under `base`.
    fn create(base: &Path, name: &str, uid: &str) -> GpgHome {
        use std::os::unix::fs::DirBuilderExt;
        let dir = base.join(name);
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let home = GpgHome { dir };
        let status = home
            .gpg()
            .args(["--pinentry-mode", "loopback", "--passphrase", ""])
            .args(["--quick-gen-key", uid, "ed25519", "sign", "never"])
            .status()
            .unwrap();
        assert!(status.success(), "gpg --quick-gen-key failed");
        home
    }

    /// Returns a `gpg` command in batch mode for this home directory.
    fn gpg(&self) -> Command {
        let mut cmd = Command::new("gpg");
        cmd.arg("--homedir").arg(&self.dir).arg("--batch");
        cmd
    }

    /// Returns the fingerprint of the primary key as uppercase hex.
    fn fingerprint(&self) -> String {
        let out = self
            .gpg()
            .args(["--with-colons", "--list-keys"])
            .output()
            .unwrap();
        assert!(out.status.success());
        let text = String::from_utf8(out.stdout).unwrap();
        text.lines()
            .find_map(|line| {
                let mut fields = line.split(':');
                (fields.next() == Some("fpr")).then(|| fields.nth(8).unwrap().to_owned())
            })
            .expect("a fpr record in the key listing")
    }

    /// Writes the exported public keyring to `path`.
    fn export_to(&self, path: &Path) {
        let out = self.gpg().arg("--export").output().unwrap();
        assert!(out.status.success() && !out.stdout.is_empty());
        std::fs::write(path, out.stdout).unwrap();
    }

    /// Returns a signer for this key.
    fn signer(&self) -> GpgSigner {
        GpgSigner::new(self.fingerprint()).with_homedir(&self.dir)
    }
}

impl Drop for GpgHome {
    fn drop(&mut self) {
        common::remove_gnupg_sockets(&self.dir);
    }
}

/// Creates a source repository under `base/src` with the ref `main`.
///
/// The commit of `main` holds a tree with one file.
async fn source_repo(base: &Path) -> (Repo, Checksum) {
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("hello.txt"), b"hello\n").unwrap();

    let repo = Repo::create(&base.join("src"), CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap();
    let txn = repo.transaction().await.unwrap();
    let mut mtree = MutableTree::new();
    let mut modifier = CommitModifier::new(CommitModifierFlags::SKIP_XATTRS);
    let dfd = std::fs::File::open(base).unwrap();
    txn.write_dfd_to_mtree(
        dfd.as_fd(),
        Path::new("tree"),
        &mut mtree,
        Some(&mut modifier),
    )
    .await
    .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(
            CommitOptions {
                subject: Some("main".to_owned()),
                timestamp: Some(FIXED_TS),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    txn.set_ref("main", Some(&commit));
    txn.commit().await.unwrap();
    (repo, commit)
}

/// Creates a destination repository under `base/<name>` with the remote
/// `origin`.
///
/// The `[remote "origin"]` group of the config gets the keys in `extra`.
async fn dest_with_remote(base: &Path, name: &str, extra: &str) -> (PathBuf, Repo) {
    let path = base.join(name);
    let repo = Repo::create(&path, CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap();
    drop(repo);
    let config = path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str(&format!(
        "\n[remote \"origin\"]\nurl=file:///dev/null\n{extra}"
    ));
    std::fs::write(&config, text).unwrap();
    let repo = Repo::open(&path).await.unwrap();
    (path, repo)
}

/// Pulls `main` from `src` into `dst` with GPG verification turned on.
async fn gpg_pull(dst: &Repo, src: &Repo) -> Result<(), Error> {
    dst.pull_local(
        src,
        PullOptions {
            refs: vec!["main".to_owned()],
            remote: Some("origin".to_owned()),
            verify: PullVerify {
                gpg: Some(true),
                ..PullVerify::default()
            },
            ..PullOptions::default()
        },
    )
    .await
    .map(|_| ())
}

/// Commits the tree under `base/<name>` into `repo` on `main`, with `parent`.
/// The tree holds one file with the marker `<name>`.
async fn commit_marker(repo: &Repo, base: &Path, name: &str, parent: Option<Checksum>) -> Checksum {
    let tree = base.join(name);
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("marker.txt"), format!("{name}\n")).unwrap();
    let txn = repo.transaction().await.unwrap();
    let mut mtree = MutableTree::new();
    let mut modifier = CommitModifier::new(CommitModifierFlags::SKIP_XATTRS);
    let dfd = std::fs::File::open(base).unwrap();
    txn.write_dfd_to_mtree(
        dfd.as_fd(),
        Path::new(name),
        &mut mtree,
        Some(&mut modifier),
    )
    .await
    .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(
            CommitOptions {
                parent,
                subject: Some(name.to_owned()),
                timestamp: Some(FIXED_TS),
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

/// Creates an archive source under `base/src` with the commit B and its
/// child C on `main`, and the deltas from scratch to B and from B to C.
///
/// Returns the source, B, C, and the list of the two deltas, each with the
/// SHA-256 of its superblock.
async fn chain_source(base: &Path) -> (Repo, Checksum, Checksum, Vec<AdvertisedDelta>) {
    let repo = Repo::create(&base.join("src"), CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap();
    let b = commit_marker(&repo, base, "b", None).await;
    let c = commit_marker(&repo, base, "c", Some(b)).await;
    let mut list = Vec::new();
    for (from, to) in [(None, b), (Some(b), c)] {
        let dir = repo
            .generate_static_delta(from.as_ref(), &to, &DeltaOptions::default())
            .await
            .unwrap();
        let bytes = std::fs::read(repo.path().join(dir).join("superblock")).unwrap();
        list.push(AdvertisedDelta {
            from,
            to,
            superblock: Checksum::sha256(&bytes),
        });
    }
    (repo, b, c, list)
}

/// Pulls `main` from `src` into `dst` under the remote `origin`, with the
/// list `list`. GPG verification is on if `gpg` is `true`.
async fn gpg_chain_pull(
    dst: &Repo,
    src: &Repo,
    list: Vec<AdvertisedDelta>,
    gpg: bool,
) -> Result<(), Error> {
    dst.pull_local(
        src,
        PullOptions {
            refs: vec!["main".to_owned()],
            remote: Some("origin".to_owned()),
            static_deltas: Some(list),
            verify: PullVerify {
                gpg: Some(gpg),
                ..PullVerify::default()
            },
            ..PullOptions::default()
        },
    )
    .await
    .map(|_| ())
}

/// Asserts that the repository at `dir` keeps no `.commitpartial` marker and
/// no staging directory.
fn assert_no_markers(dir: &Path) {
    let markers: Vec<String> = std::fs::read_dir(dir.join("state"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".commitpartial"))
        .collect();
    assert!(markers.is_empty(), "{markers:?}");
    let staging: Vec<String> = std::fs::read_dir(dir.join("tmp"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("staging-"))
        .collect();
    assert!(staging.is_empty(), "{staging:?}");
}

/// Asserts that `dst` holds `commit` complete: the commit has no
/// `.commitpartial` marker, and `dst` holds each object that `src` reaches
/// from it.
async fn assert_complete(src: &Repo, dst: &Repo, commit: &Checksum) {
    assert_eq!(dst.commit_state(commit).await.unwrap(), CommitState::Normal);
    for name in &src.traverse_commit(commit, 0).await.unwrap() {
        assert!(
            dst.has_object(name.ty, &name.checksum).await.unwrap(),
            "{name} missing from the destination"
        );
    }
}

/// GPG verification applies to the intermediate commit of a chain of static
/// deltas.
///
/// - The chain is the delta from scratch to B, then the delta from B to C.
///   The key signs C alone. The pull refuses B before the transaction opens:
///   it writes no ref, no object, no marker, and no staging directory.
/// - With GPG verification off, the same list passes into another
///   destination.
/// - After the key signs B, the list passes under GPG verification into the
///   first destination.
#[test]
fn an_unsigned_intermediate_commit_fails_gpg_verification() {
    if !gpg_available() {
        return;
    }
    let tmp = TmpDir::new("pull-verify-gpg-chain");
    let base = tmp.path();
    let signer_home = GpgHome::create(base, "gnupg", "Ostrya Pull <pull@example.invalid>");

    block_on(async {
        let (src, b, c, list) = chain_source(base).await;
        let signer = signer_home.signer();
        src.sign_commit(&c, &signer).await.unwrap();

        let (path, dst) = dest_with_remote(base, "dst-gpg", "").await;
        signer_home.export_to(&path.join("origin.trustedkeys.gpg"));
        let err = gpg_chain_pull(&dst, &src, list.clone(), true)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.starts_with(&format!("commit {b}: GPG "))),
            "{err}"
        );
        assert!(dst.list_refs(None).await.unwrap().is_empty());
        assert!(dst.list_objects().await.unwrap().is_empty());
        assert_no_markers(&path);

        let (off_path, off) = dest_with_remote(base, "dst-off", "").await;
        gpg_chain_pull(&off, &src, list.clone(), false)
            .await
            .unwrap();
        assert_eq!(off.resolve_rev("origin:main", true).await.unwrap(), Some(c));
        for commit in [b, c] {
            assert_complete(&src, &off, &commit).await;
        }
        assert_no_markers(&off_path);

        src.sign_commit(&b, &signer).await.unwrap();
        gpg_chain_pull(&dst, &src, list, true).await.unwrap();
        assert_eq!(dst.resolve_rev("origin:main", true).await.unwrap(), Some(c));
        for commit in [b, c] {
            assert_complete(&src, &dst, &commit).await;
        }
        assert_no_markers(&path);
    });
}

/// The trusted set of a remote starts with `<remote>.trustedkeys.gpg` in the
/// repository.
///
/// - A commit that the key of this keyring signed passes.
/// - If the keyring of the destination holds a different key, the pull
///   refuses the same commit.
/// - The pull refuses an unsigned commit, because it has no signature to
///   verify.
#[test]
fn the_repository_keyring_is_what_a_remote_trusts() {
    if !gpg_available() {
        return;
    }
    let tmp = TmpDir::new("pull-verify-gpg-keyring");
    let base = tmp.path();
    let signer_home = GpgHome::create(base, "gnupg", "Ostrya Pull <pull@example.invalid>");
    let other_home = GpgHome::create(base, "gnupg-other", "Other <other@example.invalid>");

    block_on(async {
        let (src, commit) = source_repo(base).await;

        // An unsigned commit has no signature to verify.
        let (path, dst) = dest_with_remote(base, "dst-unsigned", "").await;
        signer_home.export_to(&path.join("origin.trustedkeys.gpg"));
        let err = gpg_pull(&dst, &src).await.unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("carries no signature")),
            "{err}"
        );
        assert!(dst.list_refs(None).await.unwrap().is_empty());

        src.sign_commit(&commit, &signer_home.signer())
            .await
            .unwrap();

        // A keyring with the signing key accepts the commit.
        let (path, dst) = dest_with_remote(base, "dst-trusted", "").await;
        signer_home.export_to(&path.join("origin.trustedkeys.gpg"));
        gpg_pull(&dst, &src).await.unwrap();
        assert_eq!(
            dst.resolve_rev("origin:main", true).await.unwrap(),
            Some(commit)
        );

        // A keyring with a different key refuses the commit.
        let (path, dst) = dest_with_remote(base, "dst-other", "").await;
        other_home.export_to(&path.join("origin.trustedkeys.gpg"));
        let err = gpg_pull(&dst, &src).await.unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("is from a trusted key")),
            "{err}"
        );
        assert!(dst.list_refs(None).await.unwrap().is_empty());
    });
}

/// The pull follows a symlink at `<remote>.trustedkeys.gpg`.
///
/// The remote trusts the keyring that the symlink names. The `ostree` command
/// does the same in observation. If `origin.trustedkeys.gpg` is a symlink to
/// an exported keyring, the pull accepts a commit that the key of this keyring
/// signed.
#[test]
fn a_symlinked_repository_keyring_is_followed() {
    if !gpg_available() {
        return;
    }
    let tmp = TmpDir::new("pull-verify-gpg-symlink");
    let base = tmp.path();
    let signer_home = GpgHome::create(base, "gnupg", "Ostrya Pull <pull@example.invalid>");

    block_on(async {
        let (src, commit) = source_repo(base).await;
        src.sign_commit(&commit, &signer_home.signer())
            .await
            .unwrap();

        let keyring = base.join("elsewhere.gpg");
        signer_home.export_to(&keyring);
        let (path, dst) = dest_with_remote(base, "dst-symlink", "").await;
        std::os::unix::fs::symlink(&keyring, path.join("origin.trustedkeys.gpg")).unwrap();

        gpg_pull(&dst, &src).await.unwrap();
        assert_eq!(
            dst.resolve_rev("origin:main", true).await.unwrap(),
            Some(commit)
        );
    });
}

/// `gpgkeypath` adds keyrings to the trusted set, as a file or as a directory.
///
/// If an entry names no file and no directory, the pull fails. The trusted
/// set does not silently become smaller.
#[test]
fn gpgkeypath_adds_keyrings_and_a_missing_entry_fails() {
    if !gpg_available() {
        return;
    }
    let tmp = TmpDir::new("pull-verify-gpg-keypath");
    let base = tmp.path();
    let signer_home = GpgHome::create(base, "gnupg", "Ostrya Pull <pull@example.invalid>");

    block_on(async {
        let (src, commit) = source_repo(base).await;
        src.sign_commit(&commit, &signer_home.signer())
            .await
            .unwrap();

        let keyring = base.join("trusted.gpg");
        signer_home.export_to(&keyring);
        let keydir = base.join("keydir");
        std::fs::create_dir(&keydir).unwrap();
        signer_home.export_to(&keydir.join("pull.gpg"));
        // The directory scan reads only regular files that end in `.gpg`, so
        // it skips this file. This shows that the scan selects the keyrings.
        std::fs::write(keydir.join("notes.txt"), b"not a keyring\n").unwrap();

        for (name, entry) in [
            ("dst-file", keyring.display().to_string()),
            ("dst-dir", keydir.display().to_string()),
        ] {
            let (_path, dst) = dest_with_remote(base, name, &format!("gpgkeypath={entry}\n")).await;
            gpg_pull(&dst, &src).await.unwrap();
            assert_eq!(
                dst.resolve_rev("origin:main", true).await.unwrap(),
                Some(commit),
                "gpgkeypath={entry}"
            );
        }

        let (_path, dst) = dest_with_remote(
            base,
            "dst-missing",
            &format!(
                "gpgkeypath={}/absent;{}\n",
                base.display(),
                keyring.display()
            ),
        )
        .await;
        let err = gpg_pull(&dst, &src).await.unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("cannot be read")),
            "{err}"
        );
        assert!(dst.list_refs(None).await.unwrap().is_empty());
    });
}

/// The pull refuses a fifo at a `gpgkeypath` entry, and the error names the
/// entry.
///
/// A read of a fifo returns the data that its writers sent. If the pull read
/// a fifo, its writers set the trusted set. This test returns only
/// because the pull refuses the file type before a read. No `gpg` binary runs,
/// because the pull builds the trusted set before it examines a signature.
#[test]
fn a_fifo_gpgkeypath_entry_is_refused_by_name() {
    let tmp = TmpDir::new("pull-verify-gpg-keypath-fifo");
    let base = tmp.path();

    block_on(async {
        let (src, _commit) = source_repo(base).await;
        let entry = base.join("fifo.gpg");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &entry,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();

        let (_path, dst) = dest_with_remote(
            base,
            "dst-fifo",
            &format!("gpgkeypath={}\n", entry.display()),
        )
        .await;
        let err = gpg_pull(&dst, &src).await.unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("fifo.gpg")
                && m.contains("regular file")),
            "{err}"
        );
        assert!(dst.list_refs(None).await.unwrap().is_empty());
    });
}

/// The pull refuses a `gpgkeypath` entry that is larger than the keyring
/// ceiling, and the error names the entry.
///
/// A read of only the part under the ceiling gives a trusted set that the
/// operator did not put there, and no message reports it.
#[test]
fn an_oversized_gpgkeypath_entry_is_refused_by_name() {
    /// The keyring ceiling that `src/gpg.rs` applies to each keyring source.
    const MAX_KEYRING: u64 = 4 * 1024 * 1024;

    let tmp = TmpDir::new("pull-verify-gpg-keypath-size");
    let base = tmp.path();

    block_on(async {
        let (src, _commit) = source_repo(base).await;
        let entry = base.join("huge.gpg");
        std::fs::File::create(&entry)
            .unwrap()
            .set_len(MAX_KEYRING + 1)
            .unwrap();

        let (_path, dst) = dest_with_remote(
            base,
            "dst-huge",
            &format!("gpgkeypath={}\n", entry.display()),
        )
        .await;
        let err = gpg_pull(&dst, &src).await.unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("huge.gpg")
                && m.contains("ceiling")),
            "{err}"
        );
        assert!(dst.list_refs(None).await.unwrap().is_empty());
    });
}
