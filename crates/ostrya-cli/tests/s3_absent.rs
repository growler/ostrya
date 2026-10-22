#![forbid(unsafe_code)]

//! `ostrya` built without the feature `s3`.
//!
//! A pull and a push refuse an `s3://` address with a message that names
//! the feature. `remote add` writes an `s3://` address as a build with the
//! feature does. `remote init` and the S3 options do not exist. The tests
//! run in a build with no default features, for example
//! `cargo test -p ostrya-cli --no-default-features --features smol,push --test s3_absent`.

#![cfg(not(feature = "s3"))]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

/// A scratch directory, removed at drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "ostrya-cli-s3-absent-{}-{tag}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Scratch(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A run of the built `ostrya` on the repository `repo`, with no AWS
/// variable and no repository from the environment.
fn ostrya(repo: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ostrya"));
    command
        .arg(format!("--repo={}", repo.display()))
        .args(args)
        .env_remove("OSTREE_REPO")
        .env_remove("OSTRYA_SSH_COMMAND")
        .stdin(Stdio::null());
    for name in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE"] {
        command.env_remove(name);
    }
    command.output().unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8(out.stderr.clone()).unwrap()
}

/// Creates an `archive` repository in `scratch` and returns its path.
fn repo(scratch: &Scratch) -> PathBuf {
    let path = scratch.path().join("repo");
    let out = ostrya(&path, &["init", "--mode=archive"]);
    assert!(out.status.success(), "{}", stderr(&out));
    path
}

/// The text that the refusal of an `s3://` address holds.
const FEATURE: &str = "has no S3 support: turn on the feature s3 of ostrya";

#[test]
fn a_pull_from_an_s3_address_names_the_feature() {
    let scratch = Scratch::new("pull");
    let repo = repo(&scratch);
    let out = ostrya(
        &repo,
        &[
            "pull",
            "--url=s3://bkt/repo",
            "--gpg-verify=false",
            "x",
            "main",
        ],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains(FEATURE), "{}", stderr(&out));
    assert!(stderr(&out).contains("'s3://bkt/repo'"), "{}", stderr(&out));
}

#[cfg(feature = "push")]
#[test]
fn a_push_to_an_s3_address_names_the_feature() {
    let scratch = Scratch::new("push");
    let repo = repo(&scratch);
    let out = ostrya(&repo, &["push", "s3://bkt/repo", "main"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains(FEATURE), "{}", stderr(&out));
}

#[test]
fn remote_add_writes_an_s3_address_to_pull_url_and_push_url() {
    let scratch = Scratch::new("add");
    let repo = repo(&scratch);
    let out = ostrya(&repo, &["remote", "add", "r", "s3://bkt/repo"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let config = std::fs::read_to_string(repo.join("config")).unwrap();
    assert!(
        config.ends_with("[remote \"r\"]\npull-url=s3://bkt/repo\npush-url=s3://bkt/repo\n"),
        "{config}"
    );
    let out = ostrya(&repo, &["remote", "refs", "r"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains(FEATURE), "{}", stderr(&out));
}

#[test]
fn remote_init_and_the_s3_options_do_not_exist() {
    let scratch = Scratch::new("options");
    let repo = repo(&scratch);
    for args in [
        &["remote", "init", "s3://bkt/repo"][..],
        &["pull", "--s3-region=eu-west-1", "r", "main"][..],
        &["pull", "--allow-cleartext-credentials", "r", "main"][..],
        &["remote", "refs", "--s3-endpoint=https://s3.ex.com", "r"][..],
    ] {
        let out = ostrya(&repo, args);
        assert!(!out.status.success(), "{args:?}");
        let message = stderr(&out);
        assert!(
            message.contains("unrecognized subcommand") || message.contains("unexpected argument"),
            "{args:?}: {message}"
        );
    }
}
