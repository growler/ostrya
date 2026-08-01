//! GPG verification during a pull (Phase 16e).
//!
//! The GPG axis is the same whichever source a pull reads, so these run over a
//! local pull, which needs no server: what they cover is where the trusted
//! keyrings come from and what each refusal reports. A throwaway signing key is
//! generated in a private GnuPG home directory under the test's scratch tree,
//! the port signs a commit through the `gpg` binary, and the pull verifies it
//! through `gpgv` over the exported keyring. The user's GnuPG home and any agent
//! of theirs are never touched.

#![cfg(feature = "sign-gpg")]

mod common;

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::TmpDir;
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, Error, GpgSigner,
    MutableTree, PullOptions, PullVerify, Repo, RepoMode,
};
use ostrya_rt::block_on;

/// A fixed timestamp, so a source repository's commit is reproducible.
const FIXED_TS: u64 = 1_700_000_000;

/// Whether the gpg and gpgv binaries are available.
fn gpg_available() -> bool {
    let has = |program: &str| {
        Command::new(program)
            .arg("--version")
            .output()
            .is_ok_and(|out| out.status.success())
    };
    has("gpg") && has("gpgv")
}

/// A private GnuPG home directory holding one freshly generated,
/// passphrase-free ed25519 signing key. Dropping the fixture kills the
/// gpg-agent GnuPG auto-started for the directory.
struct GpgHome {
    dir: PathBuf,
}

impl GpgHome {
    /// Generate a signing key for `uid` in a new home directory under `base`.
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

    /// A gpg command bound to this home directory, batch mode.
    fn gpg(&self) -> Command {
        let mut cmd = Command::new("gpg");
        cmd.arg("--homedir").arg(&self.dir).arg("--batch");
        cmd
    }

    /// The primary-key fingerprint, as uppercase hex.
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

    /// Write the exported public keyring to `path`.
    fn export_to(&self, path: &Path) {
        let out = self.gpg().arg("--export").output().unwrap();
        assert!(out.status.success() && !out.stdout.is_empty());
        std::fs::write(path, out.stdout).unwrap();
    }

    /// A signer for this key.
    fn signer(&self) -> GpgSigner {
        GpgSigner::new(self.fingerprint()).with_homedir(&self.dir)
    }
}

impl Drop for GpgHome {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .arg("--homedir")
            .arg(&self.dir)
            .args(["--kill", "gpg-agent"])
            .status();
    }
}

/// A source repository under `base/src` holding `main`, over a one-file tree.
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

/// A destination repository under `base/<name>` whose config names the remote
/// `origin`, with the `[remote]` keys `extra` supplies.
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

/// Pull `main` from `src` into `dst`, asking for the GPG check.
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

/// The trusted set a pull reads for a remote starts with the repository's own
/// `<remote>.trustedkeys.gpg`: a commit that keyring's key signed passes, the
/// same commit against a destination holding another key is refused, and an
/// unsigned commit is refused for carrying nothing to check.
#[test]
fn the_repository_keyring_is_what_a_remote_trusts() {
    if !gpg_available() {
        eprintln!("skipping: gpg or gpgv not available");
        return;
    }
    let tmp = TmpDir::new("pull-verify-gpg-keyring");
    let base = tmp.path();
    let signer_home = GpgHome::create(base, "gnupg", "Ostrya Pull <pull@example.invalid>");
    let other_home = GpgHome::create(base, "gnupg-other", "Other <other@example.invalid>");

    block_on(async {
        let (src, commit) = source_repo(base).await;

        // An unsigned commit carries nothing the check can read.
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

        // The keyring holding the signing key accepts it.
        let (path, dst) = dest_with_remote(base, "dst-trusted", "").await;
        signer_home.export_to(&path.join("origin.trustedkeys.gpg"));
        gpg_pull(&dst, &src).await.unwrap();
        assert_eq!(
            dst.resolve_rev("origin:main", true).await.unwrap(),
            Some(commit)
        );

        // A keyring holding another key does not.
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

/// A symlink at `<remote>.trustedkeys.gpg` is followed, so the keyring it names
/// is what the remote trusts. The tool was observed to do the same: a
/// destination whose `origin.trustedkeys.gpg` is a symlink to an exported
/// keyring accepts the commit that keyring's key signed.
#[test]
fn a_symlinked_repository_keyring_is_followed() {
    if !gpg_available() {
        eprintln!("skipping: gpg or gpgv not available");
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

/// `gpgkeypath` adds keyrings to that set, by file and by directory, and an
/// entry that names neither fails the pull rather than quietly reducing what is
/// trusted.
#[test]
fn gpgkeypath_adds_keyrings_and_a_missing_entry_fails() {
    if !gpg_available() {
        eprintln!("skipping: gpg or gpgv not available");
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
        // A file the directory scan passes over, so the scan is what selects
        // the keyrings rather than the pull reading whatever is there.
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

/// A fifo at a `gpgkeypath` entry is refused by that entry's name. What a fifo
/// answers a read with is what its writers sent, so a pull reading one would
/// take its trusted set from them. This test returns only because the read
/// refuses the kind before it reads; no gpg binary runs, since the trusted set
/// is built before any signature is examined.
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

/// A `gpgkeypath` entry over the keyring ceiling is refused by that entry's
/// name. Reading the part the ceiling admits would hand the pull a trusted set
/// the operator never placed there, with nothing said about it.
#[test]
fn an_oversized_gpgkeypath_entry_is_refused_by_name() {
    /// The keyring ceiling `gpg.rs` holds every keyring source to.
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
