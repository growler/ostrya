#![forbid(unsafe_code)]

//! Tests of a pull from an `s3://` address.
//!
//! Each test serves a repository with `rclone serve s3` on a scratch
//! directory. The test of a dependency serves a repository that ostrya
//! builds. Each other test serves a copy of the `archive` fixture of the
//! `ostree` command. The `ostree` command signs the summary of the copy with
//! a new GPG key, before the server starts.
//!
//! A pull through `Repo::pull` reads the key pair from the environment of the
//! process. The test sets the variables only in a child process, so it needs
//! no in-process `set_var`, and the keys do not reach other tests. The child
//! also gets the two shared AWS files at absent paths, and no proxy
//! variable.
//!
//! A test skips when `rclone`, the `ostree` command, or `gpg` is absent.
//! `OSTRYA_REQUIRE_S3`, `OSTRYA_REQUIRE_OSTREE`, and `OSTRYA_REQUIRE_GNUPG`
//! turn each skip into a failure.

#![cfg(all(feature = "s3", feature = "verify-gpg"))]

mod common;
#[path = "common/pull.rs"]
mod pull;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::TmpDir;
use common::s3::{ACCESS_KEY, Rclone, SECRET_KEY, rclone_available};
use ostrya::endpoint::EndpointOverrides;
use ostrya::remote::s3::{Address, Credentials, Location, S3Endpoint};
use ostrya::remote::{Endpoint, PullSession, StreamSessionOptions};
use ostrya::verify::PullTrust;
use ostrya::{
    Checksum, CommitState, CreateOptions, Error, Proxy, PullOptions, Repo, RepoMode, SummaryOptions,
};
use ostrya_rt::block_on;
use pull::{FIXED_TS, build_tree, commit_tree, commit_tree_related};

/// The variable that names the case of the child process.
const CASE: &str = "OSTRYA_TEST_S3_CASE";
/// The variable that names the scratch directory of the parent test.
const SCRATCH: &str = "OSTRYA_TEST_S3_SCRATCH";
/// The variable that holds the endpoint URL of the server.
const ENDPOINT: &str = "OSTRYA_TEST_S3_ENDPOINT";

/// The proxy variables that the fetcher reads. The child process gets none
/// of them, so it connects to the server directly.
const PROXY_VARIABLES: [&str; 7] = [
    "http_proxy",
    "HTTP_PROXY",
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "no_proxy",
];

/// A private GnuPG home directory with one new ed25519 signing key.
///
/// The key has no passphrase. A drop of the fixture stops the GnuPG daemons
/// of the directory and removes their socket directory.
struct GpgHome {
    dir: PathBuf,
}

impl GpgHome {
    /// Generates a signing key for `uid` in the new home directory `dir`.
    fn create(dir: PathBuf, uid: &str) -> GpgHome {
        use std::os::unix::fs::DirBuilderExt;
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
}

impl Drop for GpgHome {
    fn drop(&mut self) {
        common::remove_gnupg_sockets(&self.dir);
    }
}

/// Copies the directory `from` to `to` with `cp -r`.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to.parent().unwrap()).unwrap();
    let status = Command::new("cp")
        .arg("-r")
        .arg(from)
        .arg(to)
        .status()
        .unwrap();
    assert!(status.success(), "cp -r {}", from.display());
}

/// The ref of the fixture.
const REF: &str = "test/main";

/// Returns the commit of the ref [`REF`] of the fixture.
fn fixture_commit() -> Checksum {
    Checksum::from_hex(common::COMMIT).unwrap()
}

/// Returns the names of the object files under `repo`, sorted.
fn object_names(repo: &Path) -> Vec<String> {
    common::file_inventory(repo, "objects")
        .into_iter()
        .map(|(name, _)| name)
        .collect()
}

/// The port pulls an `archive` fixture of the `ostree` command over
/// `s3://`, and verifies the summary that the `ostree` command signed. A
/// changed byte of the summary fails the pull, and a wrong secret key gives
/// the S3 error `SignatureDoesNotMatch`. Neither failure writes a ref or an
/// object.
#[test]
fn the_port_pulls_a_signed_archive_fixture_over_s3() {
    let test = "the_port_pulls_a_signed_archive_fixture_over_s3";
    if !rclone_available(test) {
        return;
    }
    if !common::ostree_available() {
        eprintln!("skipping {test}: ostree is not installed");
        return;
    }
    if !common::gnupg_available(&["gpg"]) {
        return;
    }
    let scratch = TmpDir::new("pull-s3");
    let root = scratch.path().join("root");
    let repo = root.join("bkt").join("repo");
    copy_tree(&common::fixture_repo("archive"), &repo);
    let home = GpgHome::create(scratch.path().join("gnupg"), "S3 Pull <s3@example.com>");
    let out = Command::new("ostree")
        .arg("summary")
        .arg("-u")
        .arg(format!("--repo={}", repo.display()))
        .arg(format!("--gpg-sign={}", home.fingerprint()))
        .arg(format!("--gpg-homedir={}", home.dir.display()))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "ostree summary -u: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    home.export_to(&scratch.path().join("key.gpg"));
    // A copy of the bucket repository with one changed byte of its summary.
    let tampered = root.join("tampered").join("repo");
    copy_tree(&repo, &tampered);
    let mut summary = std::fs::read(tampered.join("summary")).unwrap();
    let middle = summary.len() / 2;
    summary[middle] ^= 0x01;
    std::fs::write(tampered.join("summary"), summary).unwrap();

    let server = Rclone::start(scratch.path(), &root);
    for (case, secret) in [("pull", SECRET_KEY), ("wrong-secret", "wrong-secret-key")] {
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .args(["pull_s3_subprocess", "--exact", "--ignored", "--nocapture"])
            .env(CASE, case)
            .env(SCRATCH, scratch.path())
            .env(ENDPOINT, server.endpoint())
            .env("AWS_ACCESS_KEY_ID", ACCESS_KEY)
            .env("AWS_SECRET_ACCESS_KEY", secret)
            .env("AWS_CONFIG_FILE", scratch.path().join("absent-aws-config"))
            .env(
                "AWS_SHARED_CREDENTIALS_FILE",
                scratch.path().join("absent-aws-credentials"),
            );
        for (name, _) in std::env::vars_os() {
            let text = name.to_string_lossy();
            if text.starts_with("AWS_") && !child.get_envs().any(|(set, _)| set == name) {
                child.env_remove(&name);
            }
        }
        for name in PROXY_VARIABLES {
            child.env_remove(name);
        }
        let output = child.output().expect("re-execute this test binary");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "the child of the case {case} reported {}:\n{stdout}{}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

/// Runs a case of `the_port_pulls_a_signed_archive_fixture_over_s3`.
///
/// This test does its work only when the parent test runs this binary again
/// with the variables set.
#[test]
#[ignore = "helper process for the_port_pulls_a_signed_archive_fixture_over_s3"]
fn pull_s3_subprocess() {
    let Some(case) = std::env::var_os(CASE) else {
        return;
    };
    let scratch = PathBuf::from(std::env::var_os(SCRATCH).unwrap());
    let endpoint = std::env::var(ENDPOINT).unwrap();
    block_on(async {
        match case.to_str().unwrap() {
            "pull" => pull_and_verify(&scratch, &endpoint).await,
            "wrong-secret" => pull_with_a_wrong_secret(&scratch, &endpoint).await,
            other => panic!("unknown case {other}"),
        }
    });
}

/// Creates the repository `scratch/<name>` with `min-free-space-percent=0`
/// and the remotes `origin` and `tampered` of the server at `endpoint`. Each
/// remote trusts the exported key of the parent test.
async fn dest(scratch: &Path, name: &str, endpoint: &str) -> (PathBuf, Repo) {
    let path = scratch.join(name);
    let repo = Repo::create(&path, CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap();
    drop(repo);
    let config = path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    // The host of the tests has little free space.
    text.push_str("min-free-space-percent=0\n");
    for (remote, bucket) in [("origin", "bkt"), ("tampered", "tampered")] {
        text.push_str(&format!(
            "\n[remote \"{remote}\"]\npull-url=s3://{bucket}/repo\ns3-endpoint={endpoint}\n\
             gpg-verify=false\ngpg-verify-summary=true\n"
        ));
    }
    std::fs::write(&config, text).unwrap();
    let repo = Repo::open(&path).await.unwrap();
    let keys = std::fs::read(scratch.join("key.gpg")).unwrap();
    for remote in ["origin", "tampered"] {
        assert_eq!(repo.gpg_import_keys(remote, &keys, &[]).await.unwrap(), 1);
    }
    (path, repo)
}

/// Returns the options of a pull of [`REF`] over cleartext HTTP.
fn options() -> PullOptions {
    PullOptions {
        refs: vec![REF.to_owned()],
        overrides: EndpointOverrides {
            allow_cleartext_credentials: true,
            ..EndpointOverrides::default()
        },
        ..PullOptions::default()
    }
}

/// The pull from `origin` writes the ref and the objects of the fixture,
/// after the check of the summary signature. The pull from `tampered` fails
/// the check and writes nothing.
async fn pull_and_verify(scratch: &Path, endpoint: &str) {
    let bucket = scratch.join("root").join("bkt").join("repo");
    let (path, repo) = dest(scratch, "dest", endpoint).await;
    let stats = repo.pull("origin", options()).await.unwrap();
    assert!(stats.bytes_transferred > 0);
    assert_eq!(
        repo.resolve_rev(&format!("origin:{REF}"), false)
            .await
            .unwrap(),
        Some(fixture_commit())
    );
    assert_eq!(object_names(&path), object_names(&bucket));
    common::tool_fsck(&path);

    match repo.pull("tampered", options()).await {
        Err(Error::Signature(message)) => assert!(message.contains("summary"), "{message}"),
        other => panic!("a pull of a changed summary: {other:?}"),
    }
    assert_eq!(
        repo.resolve_rev(&format!("tampered:{REF}"), true)
            .await
            .unwrap(),
        None
    );
}

/// A wrong secret key gives the S3 error `SignatureDoesNotMatch`, and the
/// pull writes no ref and no object.
async fn pull_with_a_wrong_secret(scratch: &Path, endpoint: &str) {
    let (path, repo) = dest(scratch, "dest-wrong-secret", endpoint).await;
    let error = repo.pull("origin", options()).await.unwrap_err();
    let message = error.to_string();
    assert!(message.contains("SignatureDoesNotMatch"), "{message}");
    assert!(matches!(error, Error::Remote(_)), "{error:?}");
    assert!(repo.list_refs(None).await.unwrap().is_empty());
    assert!(
        repo.list_refs(Some("refs/remotes"))
            .await
            .unwrap()
            .is_empty()
    );
    assert!(object_names(&path).is_empty());
}

/// A pull session that `PullSession::connect` opens to an `Endpoint::S3`
/// pulls the fixture through `Repo::pull_with_session`.
#[test]
fn a_session_to_an_s3_endpoint_pulls_with_the_session() {
    if !rclone_available("a_session_to_an_s3_endpoint_pulls_with_the_session") {
        return;
    }
    let scratch = TmpDir::new("pull-s3-session");
    let root = scratch.path().join("root");
    let bucket = root.join("bkt").join("repo");
    copy_tree(&common::fixture_repo("archive"), &bucket);
    let server = Rclone::start(scratch.path(), &root);
    block_on(async {
        let location = Location::new(
            Address::parse("s3://bkt/repo").unwrap(),
            "us-east-1",
            Some(&server.endpoint()),
            None,
        )
        .unwrap();
        let credentials = Credentials::new(ACCESS_KEY.into(), SECRET_KEY.into(), None).unwrap();
        let mut s3 = S3Endpoint::new(location, credentials);
        s3.http.allow_cleartext_credentials = true;
        s3.http.proxy = Proxy::None;
        let session = PullSession::connect(Endpoint::S3(s3), StreamSessionOptions::default())
            .await
            .unwrap();
        let path = scratch.path().join("dest");
        let repo = Repo::create(&path, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let opts = PullOptions {
            refs: vec![REF.to_owned()],
            ..PullOptions::default()
        };
        repo.pull_with_session(session, PullTrust::unverified(), opts)
            .await
            .unwrap();
        assert_eq!(
            repo.resolve_rev(REF, false).await.unwrap(),
            Some(fixture_commit())
        );
        assert_eq!(object_names(&path), object_names(&bucket));
    });
}

/// A pull through a session to an `Endpoint::S3` fetches the dependency that
/// field 2 of the pulled commit names, complete, and writes no ref for it.
#[test]
fn a_session_to_an_s3_endpoint_fetches_a_dependency() {
    if !rclone_available("a_session_to_an_s3_endpoint_fetches_a_dependency") {
        return;
    }
    let scratch = TmpDir::new("pull-s3-dependency");
    let root = scratch.path().join("root");
    let bucket = root.join("bkt").join("repo");
    std::fs::create_dir_all(bucket.parent().unwrap()).unwrap();
    let (tip, dep) = block_on(async {
        build_tree(&scratch.path().join("uki"), b"uki\n");
        build_tree(&scratch.path().join("main"), b"main\n");
        let remote = Repo::create(&bucket, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let dep = commit_tree(&remote, scratch.path(), "uki", "dep/uki", None, FIXED_TS).await;
        let tip = commit_tree_related(
            &remote,
            scratch.path(),
            "main",
            REF,
            None,
            &[("boot/uki", dep)],
        )
        .await;
        remote
            .regenerate_summary(&SummaryOptions {
                last_modified: Some(FIXED_TS),
                ..SummaryOptions::default()
            })
            .await
            .unwrap();
        (tip, dep)
    });
    let server = Rclone::start(scratch.path(), &root);
    block_on(async {
        let endpoint = common::s3::endpoint(&server.endpoint(), "s3://bkt/repo");
        let session = PullSession::connect(Endpoint::S3(endpoint), StreamSessionOptions::default())
            .await
            .unwrap();
        let path = scratch.path().join("dest");
        let repo = Repo::create(&path, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let opts = PullOptions {
            refs: vec![REF.to_owned()],
            ..PullOptions::default()
        };
        repo.pull_with_session(session, PullTrust::unverified(), opts)
            .await
            .unwrap();
        assert_eq!(repo.list_refs(None).await.unwrap(), [(REF.to_owned(), tip)]);
        assert!(repo.list_remote_refs().await.unwrap().is_empty());
        assert_eq!(repo.commit_state(&dep).await.unwrap(), CommitState::Normal);
        assert_eq!(object_names(&path), object_names(&bucket));
    });
}
