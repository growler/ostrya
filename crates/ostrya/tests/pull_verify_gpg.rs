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

/// A remote with a GPG trust group takes the keys of the commits from the
/// keyrings that the group names alone. The repository keyring
/// `<repo>/origin.trustedkeys.gpg` does not verify a commit of the remote.
/// The GPG check of the summary still reads the repository keyring.
///
/// - The repository keyring holds the key of the commit, and the group names
///   a keyring of another key: the pull refuses the commit.
/// - The group names the keyring of the key of the commit, and the
///   repository holds no keyring: the pull takes the commit.
/// - The remote sets `gpg-verify-summary=true`, and the summary has a
///   signature of a key that the repository keyring alone holds: the pull
///   takes the commit and the summary. If the repository keyring holds the
///   key of the group in place of that key, the pull refuses the summary.
#[test]
fn a_gpg_trust_group_reads_no_repository_keyring() {
    if !gpg_available() {
        return;
    }
    let tmp = TmpDir::new("pull-verify-gpg-trust");
    let base = tmp.path();
    let signer_home = GpgHome::create(base, "gnupg", "Ostrya Pull <pull@example.invalid>");
    let other_home = GpgHome::create(base, "gnupg-other", "Other <other@example.invalid>");
    let signer_keyring = base.join("signer.gpg");
    let other_keyring = base.join("other.gpg");
    signer_home.export_to(&signer_keyring);
    other_home.export_to(&other_keyring);
    let trust = |keyring: &Path, extra: &str| {
        format!(
            "gpg-verify=false\ntrust=t\n{extra}[ex-ostrya trust \"t\"]\ngpg-verify=true\n\
             gpgkeypath={}\n",
            keyring.display()
        )
    };
    // The default policy: the remote and its trust group set the checks.
    let opts = PullOptions {
        refs: vec!["main".to_owned()],
        remote: Some("origin".to_owned()),
        ..PullOptions::default()
    };

    block_on(async {
        let (src, commit) = source_repo(base).await;
        src.sign_commit(&commit, &signer_home.signer())
            .await
            .unwrap();

        let (path, dst) = dest_with_remote(base, "dst-keyring", &trust(&other_keyring, "")).await;
        signer_home.export_to(&path.join("origin.trustedkeys.gpg"));
        let err = dst.pull_local(&src, opts.clone()).await.unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("is from a trusted key")),
            "{err}"
        );
        assert!(dst.list_refs(None).await.unwrap().is_empty());

        let (_path, dst) = dest_with_remote(base, "dst-group", &trust(&signer_keyring, "")).await;
        dst.pull_local(&src, opts.clone()).await.unwrap();
        assert_eq!(
            dst.resolve_rev("origin:main", true).await.unwrap(),
            Some(commit)
        );

        src.regenerate_summary(&ostrya::SummaryOptions {
            last_modified: Some(FIXED_TS),
            ..ostrya::SummaryOptions::default()
        })
        .await
        .unwrap();
        src.sign_summary(&other_home.signer()).await.unwrap();
        let (path, dst) = dest_with_remote(
            base,
            "dst-summary",
            &trust(&signer_keyring, "gpg-verify-summary=true\n"),
        )
        .await;
        // The repository keyring holds the key of the group alone, and the
        // summary check refuses the summary.
        signer_home.export_to(&path.join("origin.trustedkeys.gpg"));
        let err = dst.pull_local(&src, opts.clone()).await.unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("is from a trusted key")),
            "{err}"
        );
        assert!(dst.list_refs(None).await.unwrap().is_empty());
        other_home.export_to(&path.join("origin.trustedkeys.gpg"));
        dst.pull_local(&src, opts.clone()).await.unwrap();
        assert_eq!(
            dst.resolve_rev("origin:main", true).await.unwrap(),
            Some(commit)
        );
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
        // The directory scan reads this file too. It is not an OpenPGP
        // keyring, so the load skips it and the pull does not fail.
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

/// A `gpgkeypath` directory gives each regular file in it, with any name. A
/// file that is not an OpenPGP keyring adds no key, and the pull does not
/// fail on it. The same rule applies to a file entry. A file that cannot be
/// read fails the pull by its name.
#[test]
fn a_gpgkeypath_directory_reads_each_regular_file() {
    use std::os::unix::fs::PermissionsExt;

    if !gpg_available() {
        return;
    }
    let tmp = TmpDir::new("pull-verify-gpg-keypath-files");
    let base = tmp.path();
    let signer_home = GpgHome::create(base, "gnupg", "Ostrya Pull <pull@example.invalid>");
    let text = b"This directory holds the trusted keys of the remote.\n";

    block_on(async {
        let (src, commit) = source_repo(base).await;
        src.sign_commit(&commit, &signer_home.signer())
            .await
            .unwrap();

        let keyring_alone = base.join("keyring-alone");
        std::fs::create_dir(&keyring_alone).unwrap();
        signer_home.export_to(&keyring_alone.join("a.keyring"));
        let junk_first = base.join("junk-first");
        std::fs::create_dir(&junk_first).unwrap();
        std::fs::write(junk_first.join("junk.gpg"), text).unwrap();
        signer_home.export_to(&junk_first.join("b.keyring"));
        let junk_file = base.join("junk.txt");
        std::fs::write(&junk_file, text).unwrap();
        let keyring = base.join("trusted.gpg");
        signer_home.export_to(&keyring);
        for (name, keypath) in [
            ("dst-keyring-alone", keyring_alone.display().to_string()),
            ("dst-junk-first", junk_first.display().to_string()),
            (
                "dst-junk-file",
                format!("{};{}", junk_file.display(), keyring.display()),
            ),
        ] {
            let (_path, dst) =
                dest_with_remote(base, name, &format!("gpgkeypath={keypath}\n")).await;
            gpg_pull(&dst, &src).await.unwrap();
            assert_eq!(
                dst.resolve_rev("origin:main", true).await.unwrap(),
                Some(commit),
                "gpgkeypath={keypath}"
            );
        }

        // A directory of text alone gives no key. The pull reads the
        // directory with no error, and then trusts no signature.
        let text_alone = base.join("text-alone");
        std::fs::create_dir(&text_alone).unwrap();
        std::fs::write(text_alone.join("README"), text).unwrap();
        let (_path, dst) = dest_with_remote(
            base,
            "dst-text-alone",
            &format!("gpgkeypath={}\n", text_alone.display()),
        )
        .await;
        let err = gpg_pull(&dst, &src).await.unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m)
                if m.contains("no GPG signature is from a trusted key")),
            "{err}"
        );
        assert!(dst.list_refs(None).await.unwrap().is_empty());

        // A file that cannot be opened fails the pull by its name, though the
        // directory holds the key in a second file.
        let unreadable = base.join("unreadable");
        std::fs::create_dir(&unreadable).unwrap();
        signer_home.export_to(&unreadable.join("a.gpg"));
        let locked = unreadable.join("z.gpg");
        signer_home.export_to(&locked);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        // A process that holds the override of file permissions, as root
        // does, opens the file. The arm then has no refusal to observe.
        if std::fs::File::open(&locked).is_ok() {
            eprintln!("skipping the unreadable arm: the file opens with mode 000");
            return;
        }
        let (_path, dst) = dest_with_remote(
            base,
            "dst-unreadable",
            &format!("gpgkeypath={}\n", unreadable.display()),
        )
        .await;
        let err = gpg_pull(&dst, &src).await.unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("z.gpg")
                && m.contains("cannot be opened")),
            "{err}"
        );
        assert!(dst.list_refs(None).await.unwrap().is_empty());
    });
}

/// A revocation in an armored file of a `gpgkeypath` directory refuses the
/// commit, also when a second file trusts the key. A pull with
/// `remote=origin` reads the directory.
///
/// The directory holds the key in `a.gpg` and the revoked key in `b.asc`.
/// With the armor alone in `b.asc`, the pull reads the revocation and trusts
/// no signature. With a line of text before the armor, the pull cannot read
/// `b.asc` whole, and refuses it by its path. A skip of `b.asc` would trust
/// the revoked key, and the `ostree` command reads the revocation from both
/// forms of the file.
#[test]
fn a_revocation_in_armor_of_a_gpgkeypath_file_refuses_the_commit() {
    if !gpg_available() {
        return;
    }
    let tmp = TmpDir::new("pull-verify-gpg-keypath-revocation");
    let base = tmp.path();
    let signer_home = GpgHome::create(base, "gnupg", "Ostrya Pull <pull@example.invalid>");

    block_on(async {
        let (src, commit) = source_repo(base).await;
        src.sign_commit(&commit, &signer_home.signer())
            .await
            .unwrap();
        let keyring = base.join("a.gpg");
        signer_home.export_to(&keyring);

        // `gpg` stores a revocation certificate when it generates a key. Its
        // armor lines start with `:`, so that an import needs an edit.
        let stored = signer_home
            .dir
            .join("openpgp-revocs.d")
            .join(format!("{}.rev", signer_home.fingerprint()));
        let certificate = std::fs::read_to_string(stored)
            .unwrap()
            .replace(":-----BEGIN", "-----BEGIN");
        let revocation = base.join("revocation.asc");
        std::fs::write(&revocation, certificate).unwrap();
        let status = signer_home
            .gpg()
            .arg("--import")
            .arg(&revocation)
            .status()
            .unwrap();
        assert!(status.success(), "gpg --import of the revocation failed");
        let out = signer_home
            .gpg()
            .args(["--armor", "--export"])
            .output()
            .unwrap();
        assert!(out.status.success() && !out.stdout.is_empty());
        let revoked = out.stdout;

        for (name, text) in [("plain", &b""[..]), ("after-text", &b"Trusted keys\n"[..])] {
            let keys = base.join(format!("keys-{name}"));
            std::fs::create_dir(&keys).unwrap();
            std::fs::copy(&keyring, keys.join("a.gpg")).unwrap();
            let armored = keys.join("b.asc");
            std::fs::write(&armored, [text, &revoked].concat()).unwrap();
            let (_path, dst) = dest_with_remote(
                base,
                &format!("dst-{name}"),
                &format!("gpgkeypath={}\n", keys.display()),
            )
            .await;
            let err = gpg_pull(&dst, &src).await.unwrap_err();
            let message = match &err {
                Error::Signature(m) => m.clone(),
                other => panic!("{name}: {other}"),
            };
            if text.is_empty() {
                assert!(
                    message.contains("no GPG signature is from a trusted key"),
                    "{name}: {message}"
                );
            } else {
                let named = format!("the keyring '{}'", armored.display());
                assert!(
                    message.contains(&named) && message.contains("armor"),
                    "{name}: {message}"
                );
            }
            assert!(dst.list_refs(None).await.unwrap().is_empty(), "{name}");
        }
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
    /// The keyring ceiling, `MAX_KEYRING` of `ostrya-sign`, that applies to
    /// each keyring source.
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
