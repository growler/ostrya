#![forbid(unsafe_code)]

//! `ostrya` with a bucket repository at an `s3://` address: `remote init`,
//! `push`, `push-tree`, `pull`, `remote refs`, `remote summary`, `remote
//! summary -u`, `remote fsck`, `remote prune`, and `remote add`.
//!
//! Most tests run against the S3 stand-in of
//! `crates/ostrya/tests/common/s3.rs`, which holds its objects in memory,
//! honors `If-None-Match` and `If-Match`, and keeps the `Authorization`
//! header of each request. The stand-in serves `http://`, so each command
//! takes `--allow-cleartext-credentials`. Other tests run against `rclone
//! serve s3`, which checks each signature and refuses each writer, and
//! against `weed mini` of SeaweedFS. A test on a real server skips when its
//! program is absent. `OSTRYA_REQUIRE_S3` and `OSTRYA_REQUIRE_SEAWEEDFS` turn
//! each skip into a failure. The test on SeaweedFS also pulls the push with
//! the `ostree` command, and skips that part when `ostree` is absent.
//! `OSTRYA_REQUIRE_OSTREE` turns that skip into a failure.
//!
//! Each run of `ostrya` gets the key pair of the servers, the two shared AWS
//! files at absent paths in the scratch directory, a scratch `HOME`, and no
//! other AWS variable, no proxy variable, and no repository variable.

#![cfg(feature = "s3")]

#[allow(dead_code)]
#[path = "../../ostrya/tests/common/s3.rs"]
mod s3;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

use s3::{ACCESS_KEY, Rclone, SECRET_KEY, StandIn, rclone_available};
#[cfg(feature = "push")]
use s3::{Seaweed, seaweed_available};

/// The address of the bucket repository of each test.
const ADDRESS: &str = "s3://bkt/repo";

/// The key of the writer lock in the bucket.
const LOCK: &str = "repo/extensions/ostrya/lock";

/// The key of the config in the bucket.
const CONFIG: &str = "repo/config";

/// The config that an init with no collection id writes.
const PLAIN: &str = "[core]\nrepo_version=1\nmode=archive-z2\n";

/// The collection id of the tests.
const ID: &str = "org.example.Os";

/// The body of a lock of a writer that ended with no release.
const DEAD_LOCK: &str = "[lock]\nid=9999999999999999999999999999999999999999999999999999999999999999\n\
                         host=deadhost\npid=99\noperation=push\nstarted=1700000000\n";

/// The line that a removal of [`DEAD_LOCK`] writes to standard error.
const DEAD_LOCK_LINE: &str = "warning: removed the writer lock of operation push, host \
                              deadhost, pid 99, started at 1700000000 seconds since the epoch, \
                              UTC, id 9999999999999999999999999999999999999999999999999999999999999999";

/// The timestamp of the commits.
const TS: u64 = 1_700_000_000;

/// The variables that no run of `ostrya` inherits.
const REMOVED: [&str; 18] = [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_ENDPOINT_URL",
    "AWS_ENDPOINT_URL_S3",
    "http_proxy",
    "HTTP_PROXY",
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "no_proxy",
    "NO_PROXY",
    "OSTREE_REPO",
    "OSTRYA_SSH_COMMAND",
];

/// A scratch directory, removed at drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "ostrya-cli-s3-{}-{tag}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        for dir in ["cwd", "home"] {
            std::fs::create_dir_all(path.join(dir)).unwrap();
        }
        Scratch(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    /// Runs the built `ostrya` with `args` in the directory `cwd` of the
    /// scratch directory, which is no repository. Each pair of `env` sets a
    /// variable, or removes it with `None`.
    fn run_with(&self, args: &[&str], env: &[(&str, Option<&str>)]) -> Output {
        self.command(args, env).output().unwrap()
    }

    /// Returns the command of [`run_with`](Scratch::run_with), which a test
    /// can change before it runs.
    fn command(&self, args: &[&str], env: &[(&str, Option<&str>)]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ostrya"));
        command
            .args(args)
            .current_dir(self.0.join("cwd"))
            .stdin(Stdio::null());
        for name in REMOVED {
            command.env_remove(name);
        }
        command
            .env("AWS_ACCESS_KEY_ID", ACCESS_KEY)
            .env("AWS_SECRET_ACCESS_KEY", SECRET_KEY)
            .env("AWS_CONFIG_FILE", self.0.join("aws-config"))
            .env(
                "AWS_SHARED_CREDENTIALS_FILE",
                self.0.join("aws-credentials"),
            )
            .env("HOME", self.0.join("home"));
        for (name, value) in env {
            match value {
                Some(value) => command.env(name, value),
                None => command.env_remove(name),
            };
        }
        command
    }

    /// Runs `ostrya` with `args`, as [`run_with`](Scratch::run_with) does with
    /// no change of the environment.
    fn run(&self, args: &[&str]) -> Output {
        self.run_with(args, &[])
    }

    /// Runs `ostrya` with `args`, and returns its standard output. If the
    /// command fails, the test fails.
    fn ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(out.status.success(), "{args:?}: {}", stderr(&out));
        stdout(&out)
    }

    /// Runs `ostrya` with `args`, and returns its standard error. If the
    /// command succeeds, the test fails.
    fn fails(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            !out.status.success(),
            "{args:?} succeeded: {}",
            stdout(&out)
        );
        assert!(out.stdout.is_empty(), "{args:?}: {}", stdout(&out));
        stderr(&out)
    }

    /// Creates an `archive` repository at `name` in the scratch directory
    /// and returns its `--repo` option.
    fn repo(&self, name: &str) -> String {
        let path = self.0.join(name);
        let repo = format!("--repo={}", path.display());
        self.ok(&[&repo, "init", "--mode=archive"]);
        // The host of the tests can have little free space.
        let config = path.join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str("min-free-space-percent=0\n");
        std::fs::write(&config, text).unwrap();
        repo
    }

    /// Commits a small tree with `marker` to the ref `branch` of `repo`, and
    /// returns the commit.
    fn commit(&self, repo: &str, branch: &str, marker: &str) -> String {
        let tree = self.0.join(format!("tree-{marker}"));
        std::fs::create_dir_all(tree.join("dir")).unwrap();
        std::fs::write(tree.join("a"), format!("{marker}\n")).unwrap();
        std::fs::write(tree.join("dir/b"), b"beta\n").unwrap();
        let out = self.ok(&[
            repo,
            "commit",
            &format!("--branch={branch}"),
            &format!("--timestamp=@{TS}"),
            "-s",
            marker,
            tree.to_str().unwrap(),
        ]);
        out.trim().to_owned()
    }

    /// Appends `text` to the config of the repository of `repo`.
    fn append_config(&self, repo: &str, text: &str) {
        let config = Path::new(repo.strip_prefix("--repo=").unwrap()).join("config");
        let mut current = std::fs::read_to_string(&config).unwrap();
        current.push_str(text);
        std::fs::write(&config, current).unwrap();
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8(out.stderr.clone()).unwrap()
}

/// Returns the `--s3-endpoint` option of `server`.
fn endpoint_of(server: &StandIn) -> String {
    format!("--s3-endpoint={}", server.endpoint())
}

/// The switch that permits the `http://` endpoint of the stand-in.
const CLEARTEXT: &str = "--allow-cleartext-credentials";

/// Writes the `config` of the bucket repository at [`ADDRESS`] with
/// `remote init`, with the collection id `id`.
fn init(scratch: &Scratch, server: &StandIn, id: Option<&str>) {
    let endpoint = endpoint_of(server);
    let mut args = vec!["remote", "init", ADDRESS, &endpoint, CLEARTEXT];
    let collection = id.map(|id| format!("--collection-id={id}"));
    if let Some(collection) = &collection {
        args.push(collection);
    }
    assert_eq!(scratch.ok(&args), "");
}

/// Returns the bytes of the object `key` of `server`, or `None`.
fn object(server: &StandIn, key: &str) -> Option<Vec<u8>> {
    server
        .state()
        .objects
        .get(key)
        .map(|stored| stored.bytes.clone())
}

/// Returns the commit of the ref file `key` of `server`, or `None`.
#[cfg(feature = "push")]
fn ref_of(server: &StandIn, key: &str) -> Option<String> {
    object(server, key).map(|bytes| String::from_utf8(bytes).unwrap().trim().to_owned())
}

/// Returns the `Authorization` headers that `server` got.
fn authorizations(server: &StandIn) -> Vec<String> {
    server
        .state()
        .authorizations
        .iter()
        .map(|header| header.clone().expect("each request is signed"))
        .collect()
}

// ---------------------------------------------------------------------------
// remote init
// ---------------------------------------------------------------------------

#[test]
fn remote_init_at_an_address_writes_the_config_and_needs_no_repository() {
    let scratch = Scratch::new("init");
    let server = StandIn::start();
    init(&scratch, &server, None);
    assert_eq!(object(&server, CONFIG).unwrap(), PLAIN.as_bytes());
    assert!(object(&server, LOCK).is_none());
    let keys: Vec<String> = server.state().objects.keys().cloned().collect();
    assert_eq!(keys, [CONFIG]);
}

#[test]
fn remote_init_writes_the_collection_id() {
    let scratch = Scratch::new("init-id");
    let server = StandIn::start();
    init(&scratch, &server, Some(ID));
    assert_eq!(
        object(&server, CONFIG).unwrap(),
        format!("{PLAIN}collection-id={ID}\n").as_bytes()
    );
}

#[test]
fn remote_init_of_a_remote_takes_push_url_then_pull_url() {
    let scratch = Scratch::new("init-remote");
    let server = StandIn::start();
    let repo = scratch.repo("local");
    scratch.append_config(
        &repo,
        &format!(
            "\n[remote \"both\"]\npull-url=s3://bkt/two\npush-url=s3://bkt/one\n\
             s3-endpoint={0}\n\n[remote \"pull\"]\nurl=https://ex.com/r\n\
             pull-url=s3://bkt/two\ns3-endpoint={0}\n",
            server.endpoint()
        ),
    );
    scratch.ok(&[&repo, "remote", "init", "both", CLEARTEXT]);
    assert_eq!(object(&server, "one/config").unwrap(), PLAIN.as_bytes());
    assert!(object(&server, "two/config").is_none());
    scratch.ok(&[&repo, "remote", "init", "pull", CLEARTEXT]);
    assert_eq!(object(&server, "two/config").unwrap(), PLAIN.as_bytes());
}

#[test]
fn remote_init_refuses_a_remote_or_an_address_that_is_not_s3() {
    let scratch = Scratch::new("init-not-s3");
    let server = StandIn::start();
    let repo = scratch.repo("local");
    scratch.append_config(
        &repo,
        "\n[remote \"url\"]\nurl=s3://bkt/repo\n\n[remote \"http\"]\nurl=https://ex.com/r\n",
    );
    for name in ["url", "http"] {
        let message = scratch.fails(&[&repo, "remote", "init", name, CLEARTEXT]);
        assert_eq!(
            message,
            format!(
                "error: invalid input: remote '{name}' holds no s3:// address in push-url or \
                 pull-url\n"
            )
        );
    }
    let message = scratch.fails(&["remote", "init", "https://ex.com/r"]);
    assert_eq!(
        message,
        "error: invalid input: 'https://ex.com/r' is no s3:// address\n"
    );
    assert!(server.state().requests.is_empty());
}

#[test]
fn a_second_remote_init_is_refused_and_keeps_the_config() {
    let scratch = Scratch::new("init-again");
    let server = StandIn::start();
    init(&scratch, &server, Some(ID));
    let endpoint = endpoint_of(&server);
    let message = scratch.fails(&["remote", "init", ADDRESS, &endpoint, CLEARTEXT]);
    assert!(message.contains("holds a config already"), "{message}");
    assert_eq!(
        object(&server, CONFIG).unwrap(),
        format!("{PLAIN}collection-id={ID}\n").as_bytes()
    );
    assert!(object(&server, LOCK).is_none());
}

#[test]
fn remote_init_refuses_an_invalid_collection_id_before_a_request() {
    let scratch = Scratch::new("init-bad-id");
    let server = StandIn::start();
    let endpoint = endpoint_of(&server);
    let message = scratch.fails(&[
        "remote",
        "init",
        ADDRESS,
        &endpoint,
        CLEARTEXT,
        "--collection-id=nodot",
    ]);
    assert!(message.contains("'nodot'"), "{message}");
    assert!(server.state().requests.is_empty());
}

#[test]
fn remote_init_writes_the_zlib_level_and_refuses_one_outside_1_to_9() {
    let scratch = Scratch::new("init-level");
    let server = StandIn::start();
    let endpoint = endpoint_of(&server);
    for level in ["0", "10", "x"] {
        let out = scratch.run(&[
            "remote",
            "init",
            ADDRESS,
            &endpoint,
            CLEARTEXT,
            &format!("--zlib-level={level}"),
        ]);
        assert!(!out.status.success(), "{level}");
        assert!(
            stderr(&out).contains("--zlib-level"),
            "{level}: {}",
            stderr(&out)
        );
    }
    assert!(server.state().requests.is_empty());
    let out = scratch.ok(&[
        "remote",
        "init",
        ADDRESS,
        &endpoint,
        CLEARTEXT,
        "--zlib-level=9",
    ]);
    assert_eq!(out, "");
    assert_eq!(
        object(&server, CONFIG).unwrap(),
        format!("{PLAIN}\n[archive]\nzlib-level=9\n").as_bytes()
    );
}

#[test]
fn remote_init_with_break_lock_removes_a_lock_and_prints_its_holder() {
    let scratch = Scratch::new("init-break");
    let server = StandIn::start();
    server.state().store(LOCK, DEAD_LOCK.as_bytes());
    let endpoint = endpoint_of(&server);
    let args = ["remote", "init", ADDRESS, &endpoint, CLEARTEXT];
    let message = scratch.fails(&args);
    assert!(message.contains("is locked"), "{message}");
    assert!(message.contains("host deadhost"), "{message}");
    assert!(object(&server, CONFIG).is_none());
    let out = scratch.run(&[&args[..], &["--break-lock"]].concat());
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
    assert_eq!(stderr(&out), format!("{DEAD_LOCK_LINE}\n"));
    assert_eq!(object(&server, CONFIG).unwrap(), PLAIN.as_bytes());
    assert!(object(&server, LOCK).is_none());
}

/// Each command refuses an `http://` S3 endpoint without
/// `--allow-cleartext-credentials`, before a request.
#[test]
fn an_http_s3_endpoint_needs_allow_cleartext_credentials() {
    let scratch = Scratch::new("cleartext");
    let server = StandIn::start();
    let repo = scratch.repo("local");
    scratch.commit(&repo, "main", "one");
    let endpoint = endpoint_of(&server);
    scratch.ok(&[
        &repo,
        "remote",
        "add",
        "--no-gpg-verify",
        "r",
        ADDRESS,
        &format!("--set=s3-endpoint={}", server.endpoint()),
    ]);
    let mut runs: Vec<Vec<&str>> = vec![
        vec!["remote", "init", ADDRESS, &endpoint],
        vec!["remote", "prune", ADDRESS, &endpoint],
        vec![&repo, "pull", "r", "main"],
        vec![&repo, "remote", "refs", "r"],
        vec![&repo, "remote", "summary", "r"],
    ];
    if cfg!(feature = "push") {
        runs.push(vec![&repo, "push", ADDRESS, "main", &endpoint]);
    }
    for args in runs {
        let message = scratch.fails(&args);
        assert!(
            message.contains("is http://, so the signature of each request would travel"),
            "{args:?}: {message}"
        );
    }
    assert!(server.state().requests.is_empty());
}

// ---------------------------------------------------------------------------
// Precedence of the S3 settings
// ---------------------------------------------------------------------------

#[test]
fn the_s3_endpoint_option_wins_over_the_key_and_the_environment() {
    let scratch = Scratch::new("endpoint-option");
    let server = StandIn::start();
    let repo = scratch.repo("local");
    // Nothing listens on the port 1 of the loopback address.
    scratch.append_config(
        &repo,
        "\n[remote \"r\"]\npush-url=s3://bkt/repo\ns3-endpoint=http://127.0.0.1:1\n",
    );
    let endpoint = endpoint_of(&server);
    let out = scratch.run_with(
        &[&repo, "remote", "init", "r", &endpoint, CLEARTEXT],
        &[
            ("AWS_ENDPOINT_URL", Some("http://127.0.0.1:1")),
            ("AWS_ENDPOINT_URL_S3", Some("http://127.0.0.1:1")),
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(object(&server, CONFIG).unwrap(), PLAIN.as_bytes());
}

#[test]
fn the_s3_region_option_signs_for_its_region() {
    let scratch = Scratch::new("region-option");
    let server = StandIn::start();
    let repo = scratch.repo("local");
    scratch.append_config(
        &repo,
        &format!(
            "\n[remote \"r\"]\npush-url=s3://bkt/repo\ns3-region=eu-west-1\ns3-endpoint={}\n",
            server.endpoint()
        ),
    );
    let out = scratch.run_with(
        &[
            &repo,
            "remote",
            "init",
            "r",
            CLEARTEXT,
            "--s3-region=eu-north-1",
        ],
        &[("AWS_REGION", Some("ap-south-1"))],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let headers = authorizations(&server);
    assert!(!headers.is_empty());
    for header in headers {
        assert!(
            header.contains(&format!("Credential={ACCESS_KEY}/"))
                && header.contains("/eu-north-1/s3/aws4_request"),
            "{header}"
        );
    }
}

#[test]
fn the_s3_profile_option_skips_the_keys_of_the_environment() {
    let scratch = Scratch::new("profile-option");
    let server = StandIn::start();
    std::fs::write(
        scratch.path().join("aws-credentials"),
        "[p]\naws_access_key_id = profilekey\naws_secret_access_key = profilesecret\n",
    )
    .unwrap();
    let endpoint = endpoint_of(&server);
    scratch.ok(&[
        "remote",
        "init",
        ADDRESS,
        &endpoint,
        CLEARTEXT,
        "--s3-profile=p",
    ]);
    let headers = authorizations(&server);
    assert!(!headers.is_empty());
    assert!(
        headers
            .iter()
            .all(|header| header.contains("Credential=profilekey/")),
        "{headers:?}"
    );
    // Without the option, the keys of the environment sign.
    server.state().authorizations.clear();
    let endpoint = format!("--s3-endpoint={}", server.endpoint());
    scratch.ok(&["remote", "init", "s3://bkt/other", &endpoint, CLEARTEXT]);
    let headers = authorizations(&server);
    assert!(
        headers
            .iter()
            .all(|header| header.contains(&format!("Credential={ACCESS_KEY}/"))),
        "{headers:?}"
    );
}

#[test]
fn the_s3_addressing_option_takes_path_or_virtual() {
    let scratch = Scratch::new("addressing");
    let server = StandIn::start();
    let endpoint = endpoint_of(&server);
    let out = scratch.run(&[
        "remote",
        "init",
        ADDRESS,
        &endpoint,
        CLEARTEXT,
        "--s3-addressing=host",
    ]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("invalid value 'host' for '--s3-addressing <STYLE>'"),
        "{}",
        stderr(&out)
    );
    // An IP address cannot carry the bucket name in its host.
    let message = scratch.fails(&[
        "remote",
        "init",
        ADDRESS,
        &endpoint,
        CLEARTEXT,
        "--s3-addressing=virtual",
    ]);
    assert!(message.contains("is an IP address"), "{message}");
    scratch.ok(&[
        "remote",
        "init",
        ADDRESS,
        &endpoint,
        CLEARTEXT,
        "--s3-addressing=path",
    ]);
    assert_eq!(object(&server, CONFIG).unwrap(), PLAIN.as_bytes());
}

#[test]
fn no_key_pair_refuses_the_command() {
    let scratch = Scratch::new("no-keys");
    let server = StandIn::start();
    let endpoint = endpoint_of(&server);
    let out = scratch.run_with(
        &["remote", "init", ADDRESS, &endpoint, CLEARTEXT],
        &[("AWS_ACCESS_KEY_ID", None), ("AWS_SECRET_ACCESS_KEY", None)],
    );
    assert!(!out.status.success());
    let message = stderr(&out);
    assert!(
        message.contains("no S3 credentials for the profile 'default'"),
        "{message}"
    );
    assert!(server.state().requests.is_empty());
}

#[test]
fn an_s3_key_in_a_remote_with_no_s3_address_is_refused() {
    let scratch = Scratch::new("stray-key");
    let repo = scratch.repo("local");
    scratch.append_config(
        &repo,
        "\n[remote \"h\"]\nurl=https://ex.com/r\ns3-region=eu-west-1\n",
    );
    let message = scratch.fails(&[&repo, "pull", "h", "main"]);
    assert_eq!(
        message,
        "error: pull: remote 'h': s3-region applies to an s3:// address, and neither pull-url \
         nor push-url holds one\n"
    );
}

// ---------------------------------------------------------------------------
// push
// ---------------------------------------------------------------------------

#[cfg(feature = "push")]
#[test]
fn a_push_to_an_s3_address_prints_the_ref_lines_and_writes_no_summary() {
    let scratch = Scratch::new("push");
    let server = StandIn::start();
    init(&scratch, &server, None);
    let repo = scratch.repo("local");
    let tip = scratch.commit(&repo, "main", "one");
    let endpoint = endpoint_of(&server);
    let out = scratch.ok(&[&repo, "push", ADDRESS, "main", &endpoint, CLEARTEXT]);
    assert_eq!(out, format!("main (new) {tip}\n"));
    assert_eq!(ref_of(&server, "repo/refs/heads/main").unwrap(), tip);
    assert!(object(&server, "repo/summary").is_none());
    assert!(object(&server, LOCK).is_none());
    // A summary of the bucket stays as it is.
    server.state().store("repo/summary", b"old summary");
    let other = scratch.commit(&repo, "other", "two");
    let out = scratch.ok(&[&repo, "push", ADDRESS, "other", &endpoint, CLEARTEXT]);
    assert_eq!(out, format!("other (new) {other}\n"));
    assert_eq!(object(&server, "repo/summary").unwrap(), b"old summary");
    let out = scratch.ok(&[&repo, "push", ADDRESS, "main", &endpoint, CLEARTEXT]);
    assert_eq!(out, format!("main {tip} (unchanged)\n"));
}

#[cfg(feature = "push")]
#[test]
fn a_push_to_an_s3_remote_uses_its_push_url() {
    let scratch = Scratch::new("push-remote");
    let server = StandIn::start();
    init(&scratch, &server, None);
    let repo = scratch.repo("local");
    let tip = scratch.commit(&repo, "main", "one");
    scratch.append_config(
        &repo,
        &format!(
            "\n[remote \"r\"]\nurl=https://ex.com/r\npush-url={ADDRESS}\ns3-endpoint={}\n",
            server.endpoint()
        ),
    );
    let out = scratch.ok(&[&repo, "push", "r", "main", CLEARTEXT]);
    assert_eq!(out, format!("main (new) {tip}\n"));
    assert_eq!(ref_of(&server, "repo/refs/heads/main").unwrap(), tip);
}

#[cfg(feature = "push")]
#[test]
fn a_push_refuses_an_s3_address_in_url() {
    let scratch = Scratch::new("push-url-key");
    let repo = scratch.repo("local");
    scratch.commit(&repo, "main", "one");
    scratch.append_config(&repo, "\n[remote \"r\"]\nurl=s3://bkt/repo\n");
    let message = scratch.fails(&[&repo, "push", "r", "main"]);
    assert_eq!(
        message,
        "error: invalid input: remote 'r' has no push-url, and its url 's3://bkt/repo' is an \
         s3:// address; the port reads an s3:// address from push-url alone\n"
    );
}

#[cfg(feature = "push")]
#[test]
fn a_push_with_collection_writes_the_namespace_of_the_bucket() {
    let scratch = Scratch::new("push-collection");
    let server = StandIn::start();
    init(&scratch, &server, Some(ID));
    let repo = scratch.repo("local");
    let tip = scratch.commit(&repo, "main", "one");
    let endpoint = endpoint_of(&server);
    // The commit has no binding. The collection of the bucket writes the
    // local refs of the bucket.
    scratch.ok(&[
        &repo,
        "push",
        ADDRESS,
        "main",
        &endpoint,
        CLEARTEXT,
        &format!("--collection={ID}"),
    ]);
    assert_eq!(ref_of(&server, "repo/refs/heads/main").unwrap(), tip);
    // A commit bound to another collection goes to its mirror refs.
    let other = "org.example.Other";
    let mirror = scratch.repo("mirror");
    scratch.ok(&[&mirror, "config", "set", "core.collection-id", other]);
    let bound = scratch.commit(&mirror, "stable", "two");
    scratch.ok(&[
        &mirror,
        "push",
        ADDRESS,
        "stable",
        &endpoint,
        CLEARTEXT,
        &format!("--collection={other}"),
    ]);
    assert_eq!(
        ref_of(&server, &format!("repo/refs/mirrors/{other}/stable")).unwrap(),
        bound
    );
    assert!(object(&server, "repo/refs/heads/stable").is_none());
}

#[cfg(feature = "push")]
#[test]
fn a_push_to_a_bucket_with_no_config_is_refused() {
    let scratch = Scratch::new("push-no-config");
    let server = StandIn::start();
    let repo = scratch.repo("local");
    scratch.commit(&repo, "main", "one");
    let endpoint = endpoint_of(&server);
    let message = scratch.fails(&[&repo, "push", ADDRESS, "main", &endpoint, CLEARTEXT]);
    assert_eq!(
        message,
        "error: invalid input: the bucket repository s3://bkt/repo has no config; init it first\n"
    );
    assert!(server.state().objects.is_empty());
}

/// `--tag`, `--compress`, `--onto`, and a delete refspec are refused for an
/// `s3://` destination, and the stand-in gets no request.
#[cfg(feature = "push")]
#[test]
fn a_push_to_an_s3_address_refuses_the_options_of_a_session() {
    let scratch = Scratch::new("push-session-options");
    let server = StandIn::start();
    init(&scratch, &server, None);
    server.state().requests.clear();
    let repo = scratch.repo("local");
    scratch.commit(&repo, "main", "one");
    let endpoint = endpoint_of(&server);
    for (options, needle) in [
        (&["main", "--tag=v1"][..], "creates no tag"),
        (&["main", "--compress=6"][..], "names a compression"),
        (&[":old"][..], "is a delete"),
        (
            &["main", "--onto=other"][..],
            "this endpoint is an s3:// address",
        ),
    ] {
        let mut args = vec![repo.as_str(), "push", ADDRESS, &endpoint, CLEARTEXT];
        args.extend_from_slice(options);
        let message = scratch.fails(&args);
        assert!(message.contains(needle), "{options:?}: {message}");
    }
    assert!(server.state().requests.is_empty());
}

/// The token options of an HTTP push are refused for an `s3://`
/// destination, as options and as keys.
#[cfg(feature = "push")]
#[test]
fn a_push_to_an_s3_address_refuses_the_token_options() {
    let scratch = Scratch::new("push-token");
    let server = StandIn::start();
    init(&scratch, &server, None);
    server.state().requests.clear();
    let repo = scratch.repo("local");
    scratch.commit(&repo, "main", "one");
    scratch.append_config(
        &repo,
        &format!(
            "\n[remote \"keyed\"]\npush-url={ADDRESS}\npush-token-file=/t\ns3-endpoint={}\n",
            server.endpoint()
        ),
    );
    let endpoint = endpoint_of(&server);
    for (args, name) in [
        (
            vec![
                &*repo,
                "push",
                ADDRESS,
                "main",
                &endpoint,
                CLEARTEXT,
                "--push-token-file=/t",
            ],
            "push-token-file",
        ),
        (
            vec![
                &*repo,
                "push",
                ADDRESS,
                "main",
                &endpoint,
                CLEARTEXT,
                "--push-user=u",
            ],
            "push-user",
        ),
        (
            vec![&*repo, "push", "keyed", "main", CLEARTEXT],
            "push-token-file",
        ),
    ] {
        let message = scratch.fails(&args);
        assert_eq!(
            message,
            format!(
                "error: invalid input: {name} applies to an HTTP address, and 's3://bkt/repo' \
                 is an s3:// address\n"
            ),
            "{args:?}"
        );
    }
    assert!(server.state().requests.is_empty());
}

/// The S3 options and `--break-lock` are refused for an HTTP or an ssh
/// destination, with the name of the option.
#[cfg(feature = "push")]
#[test]
fn the_s3_options_of_push_are_refused_for_an_http_or_ssh_destination() {
    let scratch = Scratch::new("push-not-s3");
    let repo = scratch.repo("local");
    scratch.commit(&repo, "main", "one");
    scratch.append_config(&repo, "\n[remote \"h\"]\npush-url=https://ex.com/repo\n");
    for (option, name) in [
        ("--s3-region=eu-west-1", "--s3-region"),
        ("--s3-endpoint=https://s3.ex.com", "--s3-endpoint"),
        ("--s3-addressing=path", "--s3-addressing"),
        ("--s3-profile=p", "--s3-profile"),
        ("--break-lock", "--break-lock"),
    ] {
        for (destination, shown) in [
            ("https://u:p@ex.com/repo", "https://ex.com/repo"),
            ("ssh://h/srv/repo", "ssh://h/srv/repo"),
            ("h", "h"),
        ] {
            let message = scratch.fails(&[&repo, "push", destination, "main", option]);
            assert_eq!(
                message,
                format!(
                    "error: {name} applies to an s3:// address, and the push address of \
                     '{shown}' is not one\n"
                ),
                "{option} {destination}"
            );
        }
    }
    // `--break-lock` conflicts with `--onto`.
    let out = scratch.run(&[
        &repo,
        "push",
        ADDRESS,
        "main",
        "--break-lock",
        "--onto=other",
    ]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("cannot be used with"),
        "{}",
        stderr(&out)
    );
}

#[cfg(feature = "push")]
#[test]
fn a_push_with_break_lock_removes_a_lock_and_prints_its_holder() {
    let scratch = Scratch::new("push-break");
    let server = StandIn::start();
    init(&scratch, &server, None);
    server.state().store(LOCK, DEAD_LOCK.as_bytes());
    let repo = scratch.repo("local");
    let tip = scratch.commit(&repo, "main", "one");
    let endpoint = endpoint_of(&server);
    let args = [repo.as_str(), "push", ADDRESS, "main", &endpoint, CLEARTEXT];
    let message = scratch.fails(&args);
    assert!(message.contains("is locked"), "{message}");
    assert!(message.contains("host deadhost, pid 99"), "{message}");
    assert!(object(&server, "repo/refs/heads/main").is_none());
    let out = scratch.run(&[&args[..], &["--break-lock"]].concat());
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), format!("main (new) {tip}\n"));
    assert_eq!(stderr(&out), format!("{DEAD_LOCK_LINE}\n"));
    assert!(object(&server, LOCK).is_none());
    // With no lock to remove, the push writes no warning.
    let out = scratch.run(&[&args[..], &["--break-lock"]].concat());
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stderr(&out), "");
}

/// Writes a small tree with `marker` in the scratch directory and returns
/// its path.
#[cfg(feature = "push")]
fn tree(scratch: &Scratch, marker: &str) -> String {
    let tree = scratch.path().join(format!("push-tree-{marker}"));
    std::fs::create_dir_all(tree.join("dir")).unwrap();
    std::fs::write(tree.join("a"), format!("{marker}\n")).unwrap();
    std::fs::write(tree.join("dir/b"), b"beta\n").unwrap();
    tree.to_str().unwrap().to_owned()
}

/// Returns the parent of the commit object `commit` of `server`.
#[cfg(feature = "push")]
fn parent_of(server: &StandIn, commit: &str) -> Option<String> {
    let key = format!("repo/objects/{}/{}.commit", &commit[..2], &commit[2..]);
    let bytes = object(server, &key).expect("the commit object");
    ostrya::Commit::parse(&bytes)
        .unwrap()
        .parent
        .map(|parent| parent.to_hex())
}

/// `push-tree` to an `s3://` address and to a remote whose push address is
/// one prints the new commit. The second push takes the first commit as its
/// parent.
#[cfg(feature = "push")]
#[test]
fn push_tree_to_an_s3_address_and_remote_prints_the_commit() {
    let scratch = Scratch::new("push-tree");
    let server = StandIn::start();
    init(&scratch, &server, None);
    let repo = scratch.repo("local");
    scratch.append_config(
        &repo,
        &format!(
            "\n[remote \"r\"]\nurl=https://ex.com/r\npush-url={ADDRESS}\ns3-endpoint={}\n",
            server.endpoint()
        ),
    );
    let endpoint = endpoint_of(&server);
    let timestamp = format!("--timestamp=@{TS}");
    let dir = tree(&scratch, "one");
    let out = scratch.run(&[
        "push-tree",
        ADDRESS,
        &dir,
        "--onto=main",
        &endpoint,
        CLEARTEXT,
        &timestamp,
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stderr(&out), "");
    let first = stdout(&out).trim().to_owned();
    assert_eq!(stdout(&out), format!("{first}\n"));
    assert_eq!(first.len(), 64);
    assert_eq!(ref_of(&server, "repo/refs/heads/main").unwrap(), first);
    assert_eq!(parent_of(&server, &first), None);
    let dir = tree(&scratch, "two");
    let second = scratch.ok(&[&repo, "push-tree", "r", &dir, "--onto=main", CLEARTEXT]);
    let second = second.trim();
    assert_eq!(ref_of(&server, "repo/refs/heads/main").unwrap(), second);
    assert_eq!(parent_of(&server, second), Some(first));
    assert!(object(&server, "repo/summary").is_none());
    assert!(object(&server, LOCK).is_none());
    // `--collection` with another id writes the mirror refs.
    let mirrored = scratch.ok(&[
        "push-tree",
        ADDRESS,
        &dir,
        "--onto=main",
        &endpoint,
        CLEARTEXT,
        &format!("--collection={ID}"),
    ]);
    assert_eq!(
        ref_of(&server, &format!("repo/refs/mirrors/{ID}/main")).unwrap(),
        mirrored.trim()
    );
}

#[cfg(feature = "push")]
#[test]
fn push_tree_with_break_lock_removes_a_lock_and_prints_its_holder() {
    let scratch = Scratch::new("push-tree-break");
    let server = StandIn::start();
    init(&scratch, &server, None);
    server.state().store(LOCK, DEAD_LOCK.as_bytes());
    let endpoint = endpoint_of(&server);
    let dir = tree(&scratch, "one");
    let args = [
        "push-tree",
        ADDRESS,
        dir.as_str(),
        "--onto=main",
        &endpoint,
        CLEARTEXT,
    ];
    let message = scratch.fails(&args);
    assert!(message.contains("is locked"), "{message}");
    assert!(object(&server, "repo/refs/heads/main").is_none());
    let out = scratch.run(&[&args[..], &["--break-lock"]].concat());
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stderr(&out), format!("{DEAD_LOCK_LINE}\n"));
    assert_eq!(
        stdout(&out).trim(),
        ref_of(&server, "repo/refs/heads/main").unwrap()
    );
    assert!(object(&server, LOCK).is_none());
}

/// A push of a tree to an `s3://` address refuses `--tag` before any
/// request.
#[cfg(feature = "push")]
#[test]
fn push_tree_to_an_s3_address_refuses_a_tag() {
    let scratch = Scratch::new("push-tree-tag");
    let server = StandIn::start();
    init(&scratch, &server, None);
    server.state().requests.clear();
    let endpoint = endpoint_of(&server);
    let dir = tree(&scratch, "one");
    let message = scratch.fails(&[
        "push-tree",
        ADDRESS,
        &dir,
        "--onto=main",
        "--tag=v1",
        &endpoint,
        CLEARTEXT,
    ]);
    assert_eq!(
        message,
        "error: invalid input: a push to an s3:// address creates no tag, and the push names \
         tags\n"
    );
    assert!(server.state().requests.is_empty());
}

/// The S3 options and `--break-lock` of `push-tree` are refused for an HTTP
/// or an ssh destination, with the name of the option.
#[cfg(feature = "push")]
#[test]
fn the_s3_options_of_push_tree_are_refused_for_an_http_or_ssh_destination() {
    let scratch = Scratch::new("push-tree-not-s3");
    let repo = scratch.repo("local");
    scratch.append_config(&repo, "\n[remote \"h\"]\npush-url=https://ex.com/repo\n");
    let dir = tree(&scratch, "one");
    for (option, name) in [
        ("--s3-region=eu-west-1", "--s3-region"),
        ("--s3-endpoint=https://s3.ex.com", "--s3-endpoint"),
        ("--s3-addressing=path", "--s3-addressing"),
        ("--s3-profile=p", "--s3-profile"),
        ("--break-lock", "--break-lock"),
    ] {
        for (destination, shown) in [
            ("https://u:p@ex.com/repo", "https://ex.com/repo"),
            ("ssh://h/srv/repo", "ssh://h/srv/repo"),
            ("h", "h"),
        ] {
            let message =
                scratch.fails(&[&repo, "push-tree", destination, &dir, "--onto=main", option]);
            assert_eq!(
                message,
                format!(
                    "error: {name} applies to an s3:// address, and the push address of \
                     '{shown}' is not one\n"
                ),
                "{option} {destination}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// pull
// ---------------------------------------------------------------------------

#[cfg(feature = "push")]
#[test]
fn a_pull_from_an_s3_remote_takes_the_pushed_refs() {
    let scratch = Scratch::new("pull");
    let server = StandIn::start();
    init(&scratch, &server, None);
    let src = scratch.repo("src");
    let tip = scratch.commit(&src, "main", "one");
    let endpoint = endpoint_of(&server);
    scratch.ok(&[&src, "push", ADDRESS, "main", &endpoint, CLEARTEXT]);
    // The bucket has no summary, so the pull reads the ref file.
    let dest = scratch.repo("dest");
    scratch.ok(&[
        &dest,
        "remote",
        "add",
        "--no-gpg-verify",
        "r",
        ADDRESS,
        &format!("--set=s3-endpoint={}", server.endpoint()),
    ]);
    scratch.ok(&[&dest, "pull", "r", "main", CLEARTEXT]);
    assert_eq!(scratch.ok(&[&dest, "rev-parse", "r:main"]).trim(), tip);
    // `--url` reads a bucket for a remote that the config does not
    // describe.
    let other = scratch.repo("other");
    scratch.ok(&[
        &other,
        "pull",
        &format!("--url={ADDRESS}"),
        &endpoint,
        CLEARTEXT,
        "--gpg-verify=false",
        "x",
        "main",
    ]);
    assert_eq!(scratch.ok(&[&other, "rev-parse", "x:main"]).trim(), tip);
}

#[test]
fn a_pull_refuses_an_s3_address_in_url() {
    let scratch = Scratch::new("pull-url-key");
    let repo = scratch.repo("local");
    scratch.append_config(&repo, "\n[remote \"r\"]\nurl=s3://bkt/repo\n");
    // An S3 option does not hide the refusal of the address.
    for args in [
        vec![&*repo, "pull", "r", "main"],
        vec![&*repo, "pull", "r", "main", "--s3-region=eu-west-1"],
        vec![&*repo, "pull", "r", "main", CLEARTEXT],
    ] {
        let message = scratch.fails(&args);
        assert_eq!(
            message,
            "error: pull: remote 'r': url 's3://bkt/repo' is an s3:// address; the port reads \
             an s3:// address from pull-url alone\n",
            "{args:?}"
        );
    }
    for command in ["refs", "summary"] {
        let message = scratch.fails(&[&repo, "remote", command, "r", "--s3-region=eu-west-1"]);
        assert!(
            message.contains("url 's3://bkt/repo' is an s3:// address"),
            "{command}: {message}"
        );
    }
}

/// An S3 option for a remote that the config does not describe gives the
/// refusal of the remote.
#[test]
fn an_s3_option_for_an_unknown_remote_gives_the_no_remote_error() {
    let scratch = Scratch::new("pull-no-remote");
    let repo = scratch.repo("local");
    let plain = scratch.fails(&[&repo, "pull", "absent", "main"]);
    assert!(plain.contains("absent"), "{plain}");
    let message = scratch.fails(&[&repo, "pull", "absent", "main", "--s3-region=eu-west-1"]);
    assert_eq!(message, plain);
    for command in ["refs", "summary"] {
        let plain = scratch.fails(&[&repo, "remote", command, "absent"]);
        let message = scratch.fails(&[&repo, "remote", command, "absent", "--s3-profile=p"]);
        assert_eq!(message, plain, "{command}");
        assert!(
            !message.contains("applies to an s3:// address"),
            "{message}"
        );
    }
}

/// `pull`, `remote refs`, and `remote summary` refuse each S3 option and
/// `--allow-cleartext-credentials` for a pull address that is not `s3://`.
#[test]
fn the_s3_options_of_a_pull_are_refused_for_an_address_that_is_not_s3() {
    let scratch = Scratch::new("pull-not-s3");
    let repo = scratch.repo("local");
    scratch.append_config(
        &repo,
        "\n[remote \"h\"]\nurl=https://ex.com/repo\npush-url=s3://bkt/repo\n",
    );
    for (option, name) in [
        ("--s3-region=eu-west-1", "--s3-region"),
        ("--s3-endpoint=https://s3.ex.com", "--s3-endpoint"),
        ("--s3-addressing=path", "--s3-addressing"),
        ("--s3-profile=p", "--s3-profile"),
        (CLEARTEXT, CLEARTEXT),
    ] {
        for args in [
            vec![&*repo, "pull", "h", "main", option],
            vec![
                &*repo,
                "pull",
                "--url=https://ex.com/r",
                "h",
                "main",
                option,
            ],
            vec![&*repo, "remote", "refs", "h", option],
            vec![&*repo, "remote", "summary", "h", option],
        ] {
            let message = scratch.fails(&args);
            assert_eq!(
                message,
                format!(
                    "error: {name} applies to an s3:// address, and the pull address of remote \
                     'h' is not one\n"
                ),
                "{args:?}"
            );
        }
    }
}

/// Stores each file under the directory `dir` in `server`, at its path
/// under `dir` with the prefix `repo/`.
fn store_tree(server: &StandIn, dir: &Path) {
    let mut pending = vec![dir.to_path_buf()];
    while let Some(at) = pending.pop() {
        for entry in std::fs::read_dir(&at).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                let key = path.strip_prefix(dir).unwrap().to_str().unwrap();
                let bytes = std::fs::read(&path).unwrap();
                server.state().store(&format!("repo/{key}"), &bytes);
            }
        }
    }
}

/// A pull with `--collection` reads a candidate at an `s3://` address from
/// the summary of its bucket repository. It refuses each `--s3-*` option.
/// It takes `--allow-cleartext-credentials` when the pull address of each
/// candidate is `s3://`, and refuses it with a candidate that is not S3.
#[test]
fn a_pull_of_a_collection_reads_an_s3_remote() {
    let scratch = Scratch::new("pull-collection");
    let server = StandIn::start();
    // The bucket repository is a copy of a local repository of the
    // collection, with its summary.
    let source = scratch.repo("source");
    scratch.append_config(&source, &format!("collection-id={ID}\n"));
    let tip = scratch.commit(&source, "main", "one");
    scratch.ok(&[&source, "summary", "-u"]);
    store_tree(&server, &scratch.path().join("source"));
    let repo = scratch.repo("local");
    scratch.append_config(
        &repo,
        &format!(
            "\n[remote \"r\"]\npull-url={ADDRESS}\ncollection-id={ID}\ngpg-verify=false\n\
             s3-endpoint={}\n",
            server.endpoint()
        ),
    );
    let collection = format!("--collection={ID}");
    let message = scratch.fails(&[&repo, "pull", &collection, "main", "--s3-region=eu-west-1"]);
    assert_eq!(
        message,
        "error: --s3-region applies to one remote, and a pull with --collection takes the S3 \
         settings of each candidate from the config\n"
    );
    // The library refuses the `http://` endpoint with no switch.
    let message = scratch.fails(&[&repo, "pull", &collection, "main"]);
    assert!(message.contains("allow-cleartext-credentials"), "{message}");
    assert!(server.state().requests.is_empty());

    let out = scratch.run(&[&repo, "pull", &collection, "main", CLEARTEXT]);
    assert!(out.status.success(), "{}", stderr(&out));
    let written =
        std::fs::read_to_string(scratch.path().join(format!("local/refs/mirrors/{ID}/main")))
            .unwrap();
    assert_eq!(written.trim(), tip);
    assert!(
        !server
            .state()
            .requests
            .iter()
            .any(|(_, target)| target.contains("_ostrya/refs/v1"))
    );
    let requests = server.state().requests.len();
    assert_eq!(authorizations(&server).len(), requests);

    // A candidate that is not S3 refuses the switch, before any request.
    scratch.append_config(
        &repo,
        &format!("\n[remote \"h\"]\nurl=https://ex.com/repo\ncollection-id={ID}\n"),
    );
    let message = scratch.fails(&[&repo, "pull", &collection, "main", CLEARTEXT]);
    assert_eq!(
        message,
        "error: --allow-cleartext-credentials applies to an s3:// address, and the pull \
         address of remote 'h' is not one\n"
    );
    assert_eq!(server.state().requests.len(), requests);
}

/// A candidate whose pull address the resolver refuses passes the check of
/// --allow-cleartext-credentials, and the pull gives the refusal of the
/// resolver before any request.
#[test]
fn a_pull_of_a_collection_gives_the_refusal_of_the_resolver_with_the_switch() {
    let scratch = Scratch::new("pull-collection-url-key");
    let server = StandIn::start();
    let repo = scratch.repo("local");
    scratch.append_config(
        &repo,
        &format!(
            "\n[remote \"r\"]\npull-url={ADDRESS}\ncollection-id={ID}\ngpg-verify=false\n\
             s3-endpoint={}\n[remote \"b\"]\nurl=s3://bkt/repo\ncollection-id={ID}\n",
            server.endpoint()
        ),
    );
    let collection = format!("--collection={ID}");
    let message = scratch.fails(&[&repo, "pull", &collection, "main", CLEARTEXT]);
    assert_eq!(
        message,
        "error: pull: remote 'b': url 's3://bkt/repo' is an s3:// address; the port reads an \
         s3:// address from pull-url alone\n"
    );
    assert!(server.state().requests.is_empty());
}

// ---------------------------------------------------------------------------
// remote fsck
// ---------------------------------------------------------------------------

/// The secret key of the ed25519 signer of the summary.
const SECRET_B64: &str =
    "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";
/// The public key of [`SECRET_B64`].
const PUBLIC_B64: &str = "wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=";
/// A public key of no signer of the tests.
const OTHER_PUBLIC_B64: &str = "5WYA48XDLt1Tw6UD6mF5sMzJRCXqpaUjPPrO2C37pto=";

/// Makes a local repository `local` with the ref `main`, writes its summary,
/// and copies its objects, its ref files, and its summary into the bucket
/// repository at [`ADDRESS`] of `server`, with the config [`PLAIN`].
/// Returns the `--repo` option of the local repository and the commit.
fn fsck_fixture(scratch: &Scratch, server: &StandIn, summary: &[&str]) -> (String, String) {
    let repo = scratch.repo("local");
    let tip = scratch.commit(&repo, "main", "one");
    let mut args = vec![repo.as_str(), "summary", "-u"];
    args.extend_from_slice(summary);
    scratch.ok(&args);
    let local = scratch.path().join("local");
    for sub in ["objects", "refs"] {
        let dir = local.join(sub);
        let mut pending = vec![dir.clone()];
        while let Some(at) = pending.pop() {
            for entry in std::fs::read_dir(&at).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                } else {
                    let key = path.strip_prefix(&local).unwrap().to_str().unwrap();
                    let bytes = std::fs::read(&path).unwrap();
                    server.state().store(&format!("repo/{key}"), &bytes);
                }
            }
        }
    }
    for file in ["summary", "summary.sig"] {
        if let Ok(bytes) = std::fs::read(local.join(file)) {
            server.state().store(&format!("repo/{file}"), &bytes);
        }
    }
    server.state().store(CONFIG, PLAIN.as_bytes());
    (repo, tip)
}

/// Returns the key of each `.filez` object of `server`, sorted.
fn filez_keys(server: &StandIn) -> Vec<String> {
    server
        .state()
        .objects
        .keys()
        .filter(|key| key.ends_with(".filez"))
        .cloned()
        .collect()
}

#[test]
fn remote_fsck_of_a_clean_bucket_prints_the_counts_and_exits_0() {
    let scratch = Scratch::new("fsck-clean");
    let server = StandIn::start();
    fsck_fixture(&scratch, &server, &[]);
    let endpoint = endpoint_of(&server);
    let objects = server
        .state()
        .objects
        .keys()
        .filter(|key| key.starts_with("repo/objects/"))
        .count();
    let out = scratch.run(&["remote", "fsck", ADDRESS, &endpoint, CLEARTEXT]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stderr(&out), "");
    let lines: Vec<String> = stdout(&out).lines().map(str::to_owned).collect();
    assert_eq!(lines.len(), 4, "{lines:?}");
    assert_eq!(lines[0], format!("Listed {objects} objects"));
    assert!(
        lines[1].starts_with(&format!("Checked 1 commits and {} objects, ", objects - 1)),
        "{}",
        lines[1]
    );
    assert_eq!(lines[2], "0 objects not reached by a commit");
    assert_eq!(
        lines[3],
        format!("fsck of the bucket repository {ADDRESS}: no errors found")
    );
    assert_eq!(
        scratch.ok(&["remote", "fsck", "-q", ADDRESS, &endpoint, CLEARTEXT]),
        format!("fsck of the bucket repository {ADDRESS}: no errors found\n")
    );
    // A run with no --delete writes nothing.
    assert!(
        server
            .state()
            .requests
            .iter()
            .all(|(method, _)| method == "GET")
    );
}

#[test]
fn remote_fsck_of_a_corrupt_bucket_prints_each_finding_and_exits_1() {
    let scratch = Scratch::new("fsck-corrupt");
    let server = StandIn::start();
    let (_, tip) = fsck_fixture(&scratch, &server, &[]);
    let gone = filez_keys(&server)[0].clone();
    server.state().objects.remove(&gone);
    server.state().store(LOCK, DEAD_LOCK.as_bytes());
    let endpoint = endpoint_of(&server);
    let out = scratch.run(&["remote", "fsck", "-q", ADDRESS, &endpoint, CLEARTEXT]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(stdout(&out), "");
    let key = gone.strip_prefix("repo/").unwrap();
    assert_eq!(
        stderr(&out),
        format!(
            "note: lock extensions/ostrya/lock: a writer held the lock at the start of the run: \
             operation push, host deadhost, pid 99, started at 1700000000 seconds since the \
             epoch, UTC, id {}\n\
             missing {key}: the listing does not hold the object; in commits {tip}\n\
             error: Bucket repository corruption encountered\n",
            "9".repeat(64)
        )
    );
}

#[test]
fn remote_fsck_reports_a_stale_summary_as_a_note() {
    let scratch = Scratch::new("fsck-stale");
    let server = StandIn::start();
    let (_, tip) = fsck_fixture(&scratch, &server, &[]);
    server
        .state()
        .store("repo/refs/heads/other", format!("{tip}\n").as_bytes());
    let endpoint = endpoint_of(&server);
    let out = scratch.run(&["remote", "fsck", "-q", ADDRESS, &endpoint, CLEARTEXT]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        stderr(&out),
        "note: summary summary: the summary is older than the refs or the deltas: 1 ref(s) \
         differ from the ref files: refs/heads/other\n"
    );
}

#[test]
fn remote_fsck_with_delete_marks_the_commit_and_deletes_the_bad_object() {
    let scratch = Scratch::new("fsck-delete");
    let server = StandIn::start();
    let (_, tip) = fsck_fixture(&scratch, &server, &[]);
    let keys = filez_keys(&server);
    let other = object(&server, &keys[1]).unwrap();
    server.state().store(&keys[0], &other);
    server.state().store(LOCK, DEAD_LOCK.as_bytes());
    let endpoint = endpoint_of(&server);
    let message = scratch.fails(&["remote", "fsck", "--delete", ADDRESS, &endpoint, CLEARTEXT]);
    assert!(message.contains("is locked"), "{message}");
    let out = scratch.run(&[
        "remote",
        "fsck",
        "-q",
        "--delete",
        "--break-lock",
        ADDRESS,
        &endpoint,
        CLEARTEXT,
    ]);
    assert_eq!(out.status.code(), Some(1));
    let key = keys[0].strip_prefix("repo/").unwrap();
    assert_eq!(
        stdout(&out),
        format!("Marking commit as partial: {tip} (refs/heads/main)\nDeleted {key}\n")
    );
    let err = stderr(&out);
    assert!(err.starts_with(&format!("mismatch {key}: ")), "{err}");
    assert!(err.contains(&format!("\n{DEAD_LOCK_LINE}\n")), "{err}");
    assert!(
        err.ends_with("error: Bucket repository corruption encountered\n"),
        "{err}"
    );
    assert!(object(&server, &keys[0]).is_none());
    assert_eq!(
        object(&server, &format!("repo/state/{tip}.commitpartial")).unwrap(),
        [0x66]
    );
    assert!(object(&server, LOCK).is_none());
    // The option parser refuses --break-lock without --delete.
    server.state().requests.clear();
    let message = scratch.fails(&[
        "remote",
        "fsck",
        "--break-lock",
        ADDRESS,
        &endpoint,
        CLEARTEXT,
    ]);
    assert!(message.contains("--delete"), "{message}");
    assert!(server.state().requests.is_empty());
}

#[test]
fn remote_fsck_with_delete_prints_the_changes_of_a_repair_that_fails() {
    let scratch = Scratch::new("fsck-incomplete");
    let server = StandIn::start();
    let (_, tip) = fsck_fixture(&scratch, &server, &[]);
    let keys = filez_keys(&server);
    let other = object(&server, &keys[1]).unwrap();
    server.state().store(&keys[0], &other);
    server.state().refuse = Some(("DELETE", keys[0].clone()));
    let endpoint = endpoint_of(&server);
    let out = scratch.run(&[
        "remote", "fsck", "-q", "--delete", ADDRESS, &endpoint, CLEARTEXT,
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        stdout(&out),
        format!("Marking commit as partial: {tip} (refs/heads/main)\n")
    );
    let err = stderr(&out);
    let key = keys[0].strip_prefix("repo/").unwrap();
    assert!(err.starts_with(&format!("mismatch {key}: ")), "{err}");
    let last = err.lines().last().unwrap();
    assert!(
        last.starts_with(&format!(
            "error: the repair of the bucket repository {ADDRESS} is incomplete: "
        )) && last.ends_with("; run the fsck with delete again before a push"),
        "{err}"
    );
    assert!(!err.contains("corruption encountered"), "{err}");
    assert!(object(&server, &keys[0]).is_some());
}

#[test]
fn remote_fsck_with_delete_names_the_ref_of_a_deleted_commit_and_clears_a_marker() {
    let scratch = Scratch::new("fsck-refs");
    let server = StandIn::start();
    let (repo, tip) = fsck_fixture(&scratch, &server, &[]);
    let second = scratch.commit(&repo, "side", "two");
    let local = scratch.path().join("local");
    let commit_key = |commit: &str| format!("objects/{}/{}.commit", &commit[..2], &commit[2..]);
    for key in [commit_key(&second), "refs/heads/side".to_owned()] {
        let bytes = std::fs::read(local.join(&key)).unwrap();
        server.state().store(&format!("repo/{key}"), &bytes);
    }
    // The bytes of `side` are the bytes of `main`, and `main` has a marker
    // of a whole tree.
    let main = object(&server, &format!("repo/{}", commit_key(&tip))).unwrap();
    server
        .state()
        .store(&format!("repo/{}", commit_key(&second)), &main);
    server
        .state()
        .store(&format!("repo/state/{tip}.commitpartial"), &[0x66]);
    let endpoint = endpoint_of(&server);
    let out = scratch.run(&[
        "remote", "fsck", "-q", "--delete", ADDRESS, &endpoint, CLEARTEXT,
    ]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(
        stdout(&out),
        format!(
            "Deleted the partial-commit marker of commit {tip}\n\
             Deleted {}\n\
             Deleted the commit object of a ref: {second} (refs/heads/side)\n",
            commit_key(&second)
        )
    );
    assert!(object(&server, &format!("repo/state/{tip}.commitpartial")).is_none());
    // The next run reports the ref.
    let out = scratch.run(&["remote", "fsck", "-q", ADDRESS, &endpoint, CLEARTEXT]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).starts_with(&format!(
            "ref refs/heads/side: names the commit {second}, which the bucket does not hold\n"
        )),
        "{}",
        stderr(&out)
    );
}

/// A count line that standard output cannot take, here on `/dev/full`,
/// gives the error line and exit 1.
#[cfg(target_os = "linux")]
#[test]
fn remote_fsck_with_a_failed_write_of_the_counts_exits_one() {
    let scratch = Scratch::new("fsck-dev-full");
    let server = StandIn::start();
    fsck_fixture(&scratch, &server, &[]);
    let endpoint = endpoint_of(&server);
    let out = scratch
        .command(&["remote", "fsck", ADDRESS, &endpoint, CLEARTEXT], &[])
        .stdout(std::fs::File::create("/dev/full").unwrap())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.starts_with("error: "), "{err}");
    assert!(err.contains("os error 28"), "{err}");
}

#[test]
fn remote_fsck_of_a_remote_takes_its_address_and_its_summary_keys() {
    let scratch = Scratch::new("fsck-remote");
    let server = StandIn::start();
    let (repo, _) = fsck_fixture(&scratch, &server, &[&format!("--sign={SECRET_B64}")]);
    assert!(object(&server, "repo/summary.sig").is_some());
    scratch.append_config(
        &repo,
        &format!(
            "\n[remote \"good\"]\npull-url=s3://bkt/other\npush-url={ADDRESS}\n\
             s3-endpoint={0}\nsign-verify-summary=true\nverification-ed25519-key={PUBLIC_B64}\n\
             \n[remote \"wrong\"]\npull-url={ADDRESS}\ns3-endpoint={0}\n\
             sign-verify-summary=true\nverification-ed25519-key={OTHER_PUBLIC_B64}\n\
             \n[remote \"http\"]\nurl=https://ex.com/r\n",
            server.endpoint()
        ),
    );
    let out = scratch.ok(&[&repo, "remote", "fsck", "-q", "good", CLEARTEXT]);
    assert_eq!(
        out,
        format!("fsck of the bucket repository {ADDRESS}: no errors found\n")
    );
    let out = scratch.run(&[&repo, "remote", "fsck", "-q", "wrong", CLEARTEXT]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).starts_with("summary summary.sig: "),
        "{}",
        stderr(&out)
    );
    // The same bucket at its address verifies no signature.
    let endpoint = endpoint_of(&server);
    scratch.ok(&["remote", "fsck", ADDRESS, &endpoint, CLEARTEXT]);
    let message = scratch.fails(&[&repo, "remote", "fsck", "http", CLEARTEXT]);
    assert_eq!(
        message,
        "error: invalid input: remote 'http' holds no s3:// address in push-url or pull-url\n"
    );
    let message = scratch.fails(&["remote", "fsck", "https://ex.com/r"]);
    assert!(message.starts_with("error: "), "{message}");
}

// ---------------------------------------------------------------------------
// remote prune
// ---------------------------------------------------------------------------

/// Makes a local repository `local` with the commits `one` and `two` on
/// `main`, and copies its objects and its ref files into the bucket
/// repository at [`ADDRESS`] of `server`, with the config [`PLAIN`].
/// Returns the `--repo` option of the local repository, and the two commits.
fn prune_fixture(scratch: &Scratch, server: &StandIn) -> (String, String, String) {
    let repo = scratch.repo("local");
    let one = scratch.commit(&repo, "main", "one");
    let two = scratch.commit(&repo, "main", "two");
    let local = scratch.path().join("local");
    for sub in ["objects", "refs"] {
        let mut pending = vec![local.join(sub)];
        while let Some(at) = pending.pop() {
            for entry in std::fs::read_dir(&at).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                } else {
                    let key = path.strip_prefix(&local).unwrap().to_str().unwrap();
                    let bytes = std::fs::read(&path).unwrap();
                    server.state().store(&format!("repo/{key}"), &bytes);
                }
            }
        }
    }
    server.state().store(CONFIG, PLAIN.as_bytes());
    (repo, one, two)
}

/// Returns the number of keys under `repo/objects/` of `server`.
fn object_count(server: &StandIn) -> usize {
    server
        .state()
        .objects
        .keys()
        .filter(|key| key.starts_with("repo/objects/"))
        .count()
}

#[test]
fn remote_prune_prints_the_lines_of_prune_and_exits_0() {
    let scratch = Scratch::new("prune-lines");
    let server = StandIn::start();
    let (_, one, _) = prune_fixture(&scratch, &server);
    let total = object_count(&server);
    let absent = "ab".repeat(32);
    server
        .state()
        .store(&format!("repo/state/{absent}.commitpartial"), &[0x66]);
    server.state().uploads.push((
        format!("repo/objects/{}/{}.filez", &absent[..2], &absent[2..]),
        "u1".to_owned(),
        "2026-10-22T10:00:00.000Z".to_owned(),
    ));
    let endpoint = endpoint_of(&server);
    let args = [
        "remote",
        "prune",
        "--refs-only",
        "--depth=0",
        ADDRESS,
        &endpoint,
        CLEARTEXT,
    ];
    let mut dry = args.to_vec();
    dry.push("--no-prune");
    let out = scratch.run(&dry);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stderr(&out), "");
    let lines: Vec<String> = stdout(&out).lines().map(str::to_owned).collect();
    assert_eq!(lines.len(), 4, "{lines:?}");
    assert_eq!(lines[0], format!("Total objects: {total}"));
    assert!(
        lines[1].starts_with("Would delete: 3 objects, freeing "),
        "{}",
        lines[1]
    );
    assert_eq!(lines[2], "Would delete 1 partial-commit markers");
    assert_eq!(lines[3], "Would abort 1 incomplete multipart uploads");
    assert_eq!(object_count(&server), total);
    let out = scratch.ok(&args);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 4, "{lines:?}");
    assert_eq!(lines[0], format!("Total objects: {total}"));
    assert!(lines[1].starts_with("Deleted 3 objects, "), "{}", lines[1]);
    assert!(lines[1].ends_with(" freed"), "{}", lines[1]);
    assert_eq!(lines[2], "Deleted 1 partial-commit markers");
    assert_eq!(lines[3], "Aborted 1 incomplete multipart uploads");
    assert_eq!(object_count(&server), total - 3);
    let commit = format!("repo/objects/{}/{}.commit", &one[..2], &one[2..]);
    assert!(object(&server, &commit).is_none());
    assert!(object(&server, LOCK).is_none());
    assert_eq!(
        scratch.ok(&args),
        format!("Total objects: {}\nNo unreachable objects\n", total - 3)
    );
}

#[test]
fn remote_prune_of_a_remote_takes_push_url_then_pull_url() {
    let scratch = Scratch::new("prune-remote");
    let server = StandIn::start();
    let (repo, _, _) = prune_fixture(&scratch, &server);
    let total = object_count(&server);
    scratch.append_config(
        &repo,
        &format!(
            "\n[remote \"push\"]\npull-url=s3://bkt/other\npush-url={ADDRESS}\ns3-endpoint={0}\n\
             \n[remote \"pull\"]\npull-url={ADDRESS}\ns3-endpoint={0}\n\
             \n[remote \"http\"]\nurl=https://ex.com/r\n",
            server.endpoint()
        ),
    );
    assert_eq!(
        scratch.ok(&[&repo, "remote", "prune", "push", CLEARTEXT]),
        format!("Total objects: {total}\nNo unreachable objects\n")
    );
    let out = scratch.ok(&[
        &repo,
        "remote",
        "prune",
        "--refs-only",
        "--depth",
        "0",
        "pull",
        CLEARTEXT,
    ]);
    assert!(out.contains("\nDeleted 3 objects, "), "{out}");
    let message = scratch.fails(&[&repo, "remote", "prune", "http", CLEARTEXT]);
    assert_eq!(
        message,
        "error: invalid input: remote 'http' holds no s3:// address in push-url or pull-url\n"
    );
}

#[test]
fn remote_prune_refuses_a_bad_date_and_an_option_of_the_local_prune_before_a_request() {
    let scratch = Scratch::new("prune-refusals");
    let server = StandIn::start();
    let endpoint = endpoint_of(&server);
    let message = scratch.fails(&[
        "remote",
        "prune",
        "--keep-younger-than=yesterday",
        ADDRESS,
        &endpoint,
        CLEARTEXT,
    ]);
    assert_eq!(message, "error: Could not parse 'yesterday'\n");
    for option in [
        "--delete-commit=main",
        "--commit-only",
        "--only-branch=main",
    ] {
        let message = scratch.fails(&["remote", "prune", option, ADDRESS, &endpoint, CLEARTEXT]);
        assert!(
            message.contains("unexpected argument"),
            "{option}: {message}"
        );
    }
    let message = scratch.fails(&["remote", "prune", "https://ex.com/r", &endpoint]);
    assert!(message.starts_with("error: "), "{message}");
    assert!(server.state().requests.is_empty());
}

#[test]
fn remote_prune_with_break_lock_removes_a_lock_and_prints_its_holder() {
    let scratch = Scratch::new("prune-break-lock");
    let server = StandIn::start();
    prune_fixture(&scratch, &server);
    server.state().store(LOCK, DEAD_LOCK.as_bytes());
    let endpoint = endpoint_of(&server);
    let message = scratch.fails(&["remote", "prune", ADDRESS, &endpoint, CLEARTEXT]);
    assert!(message.contains("is locked"), "{message}");
    let out = scratch.run(&[
        "remote",
        "prune",
        "--break-lock",
        ADDRESS,
        &endpoint,
        CLEARTEXT,
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stderr(&out), format!("{DEAD_LOCK_LINE}\n"));
    assert!(stdout(&out).ends_with("No unreachable objects\n"));
    assert!(object(&server, LOCK).is_none());
}

// ---------------------------------------------------------------------------
// remote summary -u
// ---------------------------------------------------------------------------

/// Writes each key of the bucket repository at [`ADDRESS`] of `server`
/// under the directory `name` of the scratch directory, with the
/// directories of a repository, and returns its `--repo` option. Keys under
/// `extensions/` stay out.
fn dump(scratch: &Scratch, server: &StandIn, name: &str) -> String {
    let dir = scratch.path().join(name);
    let objects: Vec<(String, Vec<u8>)> = server
        .state()
        .objects
        .iter()
        .map(|(key, stored)| (key.clone(), stored.bytes.clone()))
        .collect();
    for (key, bytes) in objects {
        let Some(rel) = key.strip_prefix("repo/") else {
            continue;
        };
        if rel.starts_with("extensions/") {
            continue;
        }
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
    for sub in ["tmp", "refs/heads", "refs/remotes", "refs/mirrors", "state"] {
        std::fs::create_dir_all(dir.join(sub)).unwrap();
    }
    let repo = format!("--repo={}", dir.display());
    // The host of the tests can have little free space.
    scratch.append_config(&repo, "min-free-space-percent=0\n");
    repo
}

#[test]
fn remote_summary_update_at_an_address_needs_no_repository_and_prints_nothing() {
    let scratch = Scratch::new("summary-update");
    let server = StandIn::start();
    let (repo, _, two) = prune_fixture(&scratch, &server);
    let endpoint = endpoint_of(&server);
    let out = scratch.run(&["remote", "summary", "-u", ADDRESS, &endpoint, CLEARTEXT]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
    assert_eq!(stderr(&out), "");
    assert!(object(&server, "repo/summary").is_some());
    assert!(object(&server, "repo/summary.sig").is_none());
    assert!(object(&server, LOCK).is_none());
    scratch.append_config(
        &repo,
        &format!(
            "\n[remote \"r\"]\npull-url={ADDRESS}\ns3-endpoint={}\n",
            server.endpoint()
        ),
    );
    assert_eq!(
        scratch.ok(&[&repo, "remote", "refs", "-r", "r", CLEARTEXT]),
        format!("r:main\t{two}\n")
    );
}

#[test]
fn remote_summary_update_of_a_remote_takes_push_url_then_pull_url() {
    let scratch = Scratch::new("summary-update-remote");
    let server = StandIn::start();
    let (repo, _, _) = prune_fixture(&scratch, &server);
    scratch.append_config(
        &repo,
        &format!(
            "\n[remote \"push\"]\npull-url=s3://bkt/other\npush-url={ADDRESS}\ns3-endpoint={0}\n\
             \n[remote \"pull\"]\npull-url={ADDRESS}\ns3-endpoint={0}\n\
             \n[remote \"http\"]\nurl=https://ex.com/r\n",
            server.endpoint()
        ),
    );
    assert_eq!(
        scratch.ok(&[&repo, "remote", "summary", "-u", "push", CLEARTEXT]),
        ""
    );
    assert!(object(&server, "repo/summary").is_some());
    assert!(object(&server, "other/summary").is_none());
    server.state().objects.remove("repo/summary");
    assert_eq!(
        scratch.ok(&[&repo, "remote", "summary", "-u", "pull", CLEARTEXT]),
        ""
    );
    assert!(object(&server, "repo/summary").is_some());
    let message = scratch.fails(&[&repo, "remote", "summary", "-u", "http", CLEARTEXT]);
    assert_eq!(
        message,
        "error: invalid input: remote 'http' holds no s3:// address in push-url or pull-url\n"
    );
    let message = scratch.fails(&["remote", "summary", "-u", "https://ex.com/r"]);
    assert!(message.starts_with("error: "), "{message}");
}

#[test]
fn remote_summary_update_conflicts_with_the_read_options_and_its_options_need_it() {
    let scratch = Scratch::new("summary-update-options");
    let server = StandIn::start();
    let endpoint = endpoint_of(&server);
    for option in ["--raw", "--list-metadata-keys", "--print-metadata-key=k"] {
        let message = scratch.fails(&[
            "remote", "summary", "-u", option, ADDRESS, &endpoint, CLEARTEXT,
        ]);
        assert!(
            message.contains("cannot be used with"),
            "{option}: {message}"
        );
    }
    let sign = format!("--sign={SECRET_B64}");
    for option in [
        "--gpg-sign=KEY",
        "--gpg-homedir=/nonexistent",
        sign.as_str(),
        "--sign-type=ed25519",
        "--keys-file=/nonexistent",
        "--break-lock",
        "--last-modified=1",
    ] {
        let message = scratch.fails(&["remote", "summary", option, ADDRESS, &endpoint, CLEARTEXT]);
        assert!(
            message.contains("required arguments were not provided")
                && message.contains("--update"),
            "{option}: {message}"
        );
    }
    for option in ["-m", "-c", "--metadata-commit-timestamp=1", "--keys-dir=/x"] {
        let message = scratch.fails(&[
            "remote", "summary", "-u", option, ADDRESS, &endpoint, CLEARTEXT,
        ]);
        assert!(
            message.contains("unexpected argument"),
            "{option}: {message}"
        );
    }
    // An engine that does not exist is refused before any request.
    let message = scratch.fails(&[
        "remote",
        "summary",
        "-u",
        "--sign-type=rsa",
        &sign,
        ADDRESS,
        &endpoint,
        CLEARTEXT,
    ]);
    assert!(message.starts_with("error: "), "{message}");
    assert!(server.state().requests.is_empty());
}

#[test]
fn remote_summary_update_refuses_a_key_file_with_the_options_of_the_command() {
    let scratch = Scratch::new("summary-update-key-file");
    let server = StandIn::start();
    let endpoint = endpoint_of(&server);
    let blank = scratch.path().join("blank");
    std::fs::write(&blank, "\n\n").unwrap();
    let keys_file = format!("--keys-file={}", blank.display());
    let message = scratch.fails(&[
        "remote", "summary", "-u", &keys_file, ADDRESS, &endpoint, CLEARTEXT,
    ]);
    assert_eq!(
        message,
        "error: signature: no signing key given; pass --sign or --keys-file\n"
    );
    #[cfg(feature = "gpg")]
    {
        let message = scratch.fails(&[
            "remote",
            "summary",
            "-u",
            "--sign-type=gpg",
            &keys_file,
            ADDRESS,
            &endpoint,
            CLEARTEXT,
        ]);
        assert_eq!(
            message,
            "error: signature: gpg signing takes --gpg-sign and --sign KEY-ID arguments; \
             --keys-file serves the other engines\n"
        );
    }
    assert!(server.state().requests.is_empty());
}

#[test]
fn remote_summary_update_signs_with_ed25519_and_a_pull_verifies_it() {
    let scratch = Scratch::new("summary-update-sign");
    let server = StandIn::start();
    let (_, _, two) = prune_fixture(&scratch, &server);
    let endpoint = endpoint_of(&server);
    let keys = scratch.path().join("keys");
    std::fs::write(&keys, format!("{SECRET_B64}\n")).unwrap();
    let last_modified = format!("--last-modified={TS}");
    scratch.ok(&[
        "remote",
        "summary",
        "-u",
        &format!("--keys-file={}", keys.display()),
        &last_modified,
        ADDRESS,
        &endpoint,
        CLEARTEXT,
    ]);
    let by_file = object(&server, "repo/summary.sig").unwrap();
    scratch.ok(&[
        "remote",
        "summary",
        "-u",
        &format!("--sign={SECRET_B64}"),
        "-s",
        "ed25519",
        &last_modified,
        ADDRESS,
        &endpoint,
        CLEARTEXT,
    ]);
    assert_eq!(object(&server, "repo/summary.sig").unwrap(), by_file);
    let dest = scratch.repo("dest");
    scratch.append_config(
        &dest,
        &format!(
            "\n[remote \"good\"]\npull-url={ADDRESS}\ns3-endpoint={0}\ngpg-verify=false\n\
             sign-verify-summary=true\nverification-ed25519-key={PUBLIC_B64}\n\
             \n[remote \"wrong\"]\npull-url={ADDRESS}\ns3-endpoint={0}\ngpg-verify=false\n\
             sign-verify-summary=true\nverification-ed25519-key={OTHER_PUBLIC_B64}\n",
            server.endpoint()
        ),
    );
    scratch.ok(&[&dest, "pull", "good", "main", CLEARTEXT]);
    assert_eq!(scratch.ok(&[&dest, "rev-parse", "good:main"]).trim(), two);
    scratch.fails(&[&dest, "pull", "wrong", "main", CLEARTEXT]);
}

#[test]
fn remote_summary_update_with_last_modified_writes_the_bytes_of_summary_u() {
    let scratch = Scratch::new("summary-update-bytes");
    let server = StandIn::start();
    prune_fixture(&scratch, &server);
    let endpoint = endpoint_of(&server);
    let last_modified = format!("--last-modified={TS}");
    let sign = format!("--sign={SECRET_B64}");
    scratch.ok(&[
        "remote",
        "summary",
        "-u",
        &sign,
        &last_modified,
        ADDRESS,
        &endpoint,
        CLEARTEXT,
    ]);
    let copy = dump(&scratch, &server, "copy");
    scratch.ok(&[&copy, "summary", "-u", &sign, &last_modified]);
    for file in ["summary", "summary.sig"] {
        assert_eq!(
            std::fs::read(scratch.path().join("copy").join(file)).unwrap(),
            object(&server, &format!("repo/{file}")).unwrap(),
            "{file}"
        );
    }
}

#[test]
fn remote_summary_update_of_a_signed_bucket_needs_a_signing_key() {
    let scratch = Scratch::new("summary-update-signed");
    let server = StandIn::start();
    prune_fixture(&scratch, &server);
    let endpoint = endpoint_of(&server);
    scratch.ok(&[
        "remote",
        "summary",
        "-u",
        &format!("--sign={SECRET_B64}"),
        ADDRESS,
        &endpoint,
        CLEARTEXT,
    ]);
    let summary = object(&server, "repo/summary").unwrap();
    let message = scratch.fails(&["remote", "summary", "-u", ADDRESS, &endpoint, CLEARTEXT]);
    assert!(message.contains("holds a summary.sig"), "{message}");
    assert_eq!(object(&server, "repo/summary").unwrap(), summary);
    assert!(object(&server, LOCK).is_none());
}

#[test]
fn remote_summary_update_with_break_lock_removes_a_lock_and_prints_its_holder() {
    let scratch = Scratch::new("summary-update-break-lock");
    let server = StandIn::start();
    prune_fixture(&scratch, &server);
    server.state().store(LOCK, DEAD_LOCK.as_bytes());
    let endpoint = endpoint_of(&server);
    let message = scratch.fails(&["remote", "summary", "-u", ADDRESS, &endpoint, CLEARTEXT]);
    assert!(message.contains("is locked"), "{message}");
    assert!(object(&server, "repo/summary").is_none());
    let out = scratch.run(&[
        "remote",
        "summary",
        "-u",
        "--break-lock",
        ADDRESS,
        &endpoint,
        CLEARTEXT,
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
    assert_eq!(stderr(&out), format!("{DEAD_LOCK_LINE}\n"));
    assert!(object(&server, "repo/summary").is_some());
    assert!(object(&server, LOCK).is_none());
}

#[cfg(feature = "push")]
#[test]
fn a_push_and_remote_summary_u_serve_remote_refs_and_a_mirror_pull() {
    let scratch = Scratch::new("summary-update-chain");
    let server = StandIn::start();
    init(&scratch, &server, None);
    let endpoint = endpoint_of(&server);
    let src = scratch.repo("src");
    let tip = scratch.commit(&src, "main", "one");
    scratch.ok(&[&src, "push", ADDRESS, "main", &endpoint, CLEARTEXT]);
    let dest = scratch.repo("dest");
    scratch.ok(&[
        &dest,
        "remote",
        "add",
        "--no-gpg-verify",
        "r",
        ADDRESS,
        &format!("--set=s3-endpoint={}", server.endpoint()),
    ]);
    scratch.fails(&[&dest, "remote", "refs", "r", CLEARTEXT]);
    assert_eq!(
        scratch.ok(&[&dest, "remote", "summary", "-u", "r", CLEARTEXT]),
        ""
    );
    assert_eq!(
        scratch.ok(&[&dest, "remote", "refs", "r", CLEARTEXT]),
        "r:main\n"
    );
    scratch.ok(&[&dest, "pull", "--mirror", "r", CLEARTEXT]);
    assert_eq!(scratch.ok(&[&dest, "rev-parse", "main"]).trim(), tip);
}

// ---------------------------------------------------------------------------
// remote refs, remote summary, remote add
// ---------------------------------------------------------------------------

#[test]
fn remote_refs_and_remote_summary_read_an_s3_remote() {
    let scratch = Scratch::new("remote-refs");
    let server = StandIn::start();
    let repo = scratch.repo("local");
    scratch.ok(&[
        &repo,
        "remote",
        "add",
        "r",
        ADDRESS,
        &format!("--set=s3-endpoint={}", server.endpoint()),
    ]);
    let message = scratch.fails(&[&repo, "remote", "refs", "r", CLEARTEXT]);
    assert_eq!(
        message,
        "error: Remote refs not available; server has no summary file\n"
    );
    let message = scratch.fails(&[&repo, "remote", "summary", "r", CLEARTEXT]);
    assert_eq!(message, "error: Remote server has no summary file\n");
    // The summary of a local repository with the ref.
    let tip = scratch.commit(&repo, "main", "one");
    scratch.ok(&[&repo, "summary", "-u"]);
    let summary = std::fs::read(scratch.path().join("local/summary")).unwrap();
    server.state().store("repo/summary", &summary);
    assert_eq!(
        scratch.ok(&[&repo, "remote", "refs", "r", CLEARTEXT]),
        "r:main\n"
    );
    assert_eq!(
        scratch.ok(&[&repo, "remote", "refs", "-r", "r", CLEARTEXT]),
        format!("r:main\t{tip}\n")
    );
    let report = scratch.ok(&[&repo, "remote", "summary", "r", CLEARTEXT]);
    assert!(report.contains("* main"), "{report}");
    assert!(report.contains(&tip), "{report}");
    let keys = scratch.ok(&[
        &repo,
        "remote",
        "summary",
        "--list-metadata-keys",
        "r",
        CLEARTEXT,
    ]);
    assert!(keys.contains("ostree.summary.last-modified"), "{keys}");
}

#[test]
fn remote_add_with_an_s3_address_writes_pull_url_and_push_url() {
    let scratch = Scratch::new("remote-add");
    let repo = scratch.repo("local");
    scratch.ok(&[
        &repo,
        "remote",
        "add",
        "r",
        "s3://bkt/repo",
        "b1",
        "b2",
        "--set=s3-region=eu-west-1",
        "--set=s3-addressing=path",
        "--collection-id=org.example.Os",
    ]);
    let config = std::fs::read_to_string(scratch.path().join("local/config")).unwrap();
    let section = config.split_once("[remote \"r\"]\n").unwrap().1;
    assert_eq!(
        section,
        "branches=b1;b2;\npull-url=s3://bkt/repo\npush-url=s3://bkt/repo\n\
         s3-region=eu-west-1\ns3-addressing=path\ncollection-id=org.example.Os\n"
    );
    let message = scratch.fails(&[&repo, "remote", "show-url", "r"]);
    assert_eq!(message, "error: No \"url\" option in remote \"r\"\n");
}

// ---------------------------------------------------------------------------
// rclone serve s3
// ---------------------------------------------------------------------------

/// The ref and the commit of the `archive` fixture of the `ostree` command.
const FIXTURE_REF: &str = "test/main";
const FIXTURE_COMMIT: &str = "b3c8e8525e8a5c3409bf6e6db5f5d656da77ae76d08cbc4f8b75b71879757a89";

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

/// `remote refs`, `remote summary`, `remote fsck`, and `pull` read a copy of
/// the `archive` fixture through `rclone serve s3`, which checks each
/// signature. A wrong secret gives `SignatureDoesNotMatch`, and `remote
/// init`, `remote fsck --delete`, `remote summary -u`, and `push` are
/// refused, because the server does not honor `If-None-Match`.
#[test]
fn rclone_serves_a_bucket_to_each_reader_and_refuses_each_writer() {
    if !rclone_available("rclone_serves_a_bucket_to_each_reader_and_refuses_each_writer") {
        return;
    }
    let scratch = Scratch::new("rclone");
    let root = scratch.path().join("root");
    let bucket = root.join("bkt").join("repo");
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/generated/archive/repo");
    copy_tree(&fixture, &bucket);
    // The server keeps the listing of each directory, so each file of the
    // bucket is written before it starts.
    let copy = format!("--repo={}", bucket.display());
    scratch.ok(&[&copy, "summary", "-u"]);
    let server = Rclone::start(scratch.path(), &root);
    let dest = scratch.repo("dest");
    scratch.ok(&[
        &dest,
        "remote",
        "add",
        "--no-gpg-verify",
        "r",
        ADDRESS,
        &format!("--set=s3-endpoint={}", server.endpoint()),
    ]);
    assert_eq!(
        scratch.ok(&[&dest, "remote", "refs", "r", CLEARTEXT]),
        format!("r:{FIXTURE_REF}\n")
    );
    let report = scratch.ok(&[&dest, "remote", "summary", "r", CLEARTEXT]);
    assert!(report.contains(FIXTURE_COMMIT), "{report}");
    scratch.ok(&[&dest, "pull", "r", FIXTURE_REF, CLEARTEXT]);
    assert_eq!(
        scratch
            .ok(&[&dest, "rev-parse", &format!("r:{FIXTURE_REF}")])
            .trim(),
        FIXTURE_COMMIT
    );
    let out = scratch.run_with(
        &[&dest, "remote", "refs", "r", CLEARTEXT],
        &[("AWS_SECRET_ACCESS_KEY", Some("wrong-secret-key"))],
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("SignatureDoesNotMatch"),
        "{}",
        stderr(&out)
    );
    let fsck = scratch.ok(&[&dest, "remote", "fsck", "-q", "r", CLEARTEXT]);
    assert_eq!(
        fsck,
        format!("fsck of the bucket repository {ADDRESS}: no errors found\n")
    );
    let message = scratch.fails(&[&dest, "remote", "fsck", "--delete", "r", CLEARTEXT]);
    assert!(
        message.contains("does not honor If-None-Match"),
        "{message}"
    );
    let summary = std::fs::read(bucket.join("summary")).unwrap();
    let message = scratch.fails(&[&dest, "remote", "summary", "-u", "r", CLEARTEXT]);
    assert!(
        message.contains("does not honor If-None-Match"),
        "{message}"
    );
    assert_eq!(std::fs::read(bucket.join("summary")).unwrap(), summary);
    let endpoint = format!("--s3-endpoint={}", server.endpoint());
    let message = scratch.fails(&["remote", "init", "s3://bkt/fresh", &endpoint, CLEARTEXT]);
    assert!(
        message.contains("does not honor If-None-Match"),
        "{message}"
    );
    assert!(!root.join("bkt/fresh/config").exists());
    if cfg!(feature = "push") {
        let src = scratch.repo("src");
        scratch.commit(&src, "main", "one");
        let message = scratch.fails(&[&src, "push", ADDRESS, "main", &endpoint, CLEARTEXT]);
        assert!(
            message.contains("does not honor If-None-Match"),
            "{message}"
        );
        assert!(!bucket.join("refs/heads/main").exists());
    }
}

// ---------------------------------------------------------------------------
// SeaweedFS
// ---------------------------------------------------------------------------

/// `ostrya` inits a bucket repository on SeaweedFS, pushes to it, and pulls
/// from it. The `ostree` command pulls the push with no signature over the
/// S3 port of the bucket, with the anonymous read. After `remote summary
/// -u`, `ostree remote refs` reads the ref from the summary.
#[cfg(feature = "push")]
#[test]
fn seaweedfs_takes_an_init_a_push_and_a_pull() {
    let test = "seaweedfs_takes_an_init_a_push_and_a_pull";
    if !seaweed_available(test) {
        return;
    }
    let scratch = Scratch::new("seaweed");
    let server = Seaweed::start_anonymous(scratch.path(), "bkt");
    let endpoint = format!("--s3-endpoint={}", server.endpoint());
    scratch.ok(&[
        "remote",
        "init",
        ADDRESS,
        &endpoint,
        CLEARTEXT,
        &format!("--collection-id={ID}"),
    ]);
    let src = scratch.repo("src");
    scratch.ok(&[&src, "config", "set", "core.collection-id", ID]);
    let tip = scratch.commit(&src, "main", "one");
    let out = scratch.ok(&[&src, "push", ADDRESS, "main", &endpoint, CLEARTEXT]);
    assert_eq!(out, format!("main (new) {tip}\n"));
    let dest = scratch.repo("dest");
    scratch.ok(&[
        &dest,
        "pull",
        &format!("--url={ADDRESS}"),
        &endpoint,
        CLEARTEXT,
        "--gpg-verify=false",
        "x",
        "main",
    ]);
    assert_eq!(scratch.ok(&[&dest, "rev-parse", "x:main"]).trim(), tip);
    let tool = ostree_available(&format!("the ostree pull of {test}"));
    let client = format!("--repo={}", scratch.path().join("client").display());
    if tool {
        ostree(&[&client, "init", "--mode=bare-user"]);
        ostree(&[&client, "config", "set", "core.min-free-space-percent", "0"]);
        let url = server.url("bkt", "repo");
        ostree(&[&client, "remote", "add", "--no-gpg-verify", "w", &url]);
        ostree(&[&client, "pull", "w", "main"]);
        assert_eq!(ostree(&[&client, "rev-parse", "w:main"]).trim(), tip);
        ostree(&[&client, "fsck"]);
    }
    assert_eq!(
        scratch.ok(&["remote", "summary", "-u", ADDRESS, &endpoint, CLEARTEXT]),
        ""
    );
    if tool {
        assert_eq!(ostree(&[&client, "remote", "refs", "w"]), "w:main\n");
    }
    scratch.ok(&[
        &dest,
        "remote",
        "add",
        "--no-gpg-verify",
        "w",
        ADDRESS,
        &format!("--set=s3-endpoint={}", server.endpoint()),
    ]);
    let report = scratch.ok(&[&dest, "remote", "summary", "w", CLEARTEXT]);
    assert!(report.contains(&format!("* ({ID}, main)")), "{report}");
    assert!(report.contains(&tip), "{report}");
}

/// The environment variable that turns the skip for an absent `ostree`
/// command into a failure.
#[cfg(feature = "push")]
const REQUIRE_OSTREE: &str = "OSTRYA_REQUIRE_OSTREE";

/// Returns `true` if the `ostree` command runs. With [`REQUIRE_OSTREE`] set,
/// an absent command fails the test. Else the function writes the reason of
/// the skip of `test` to standard error.
#[cfg(feature = "push")]
fn ostree_available(test: &str) -> bool {
    let found = Command::new("ostree")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success());
    assert!(
        found || std::env::var_os(REQUIRE_OSTREE).is_none(),
        "{REQUIRE_OSTREE} is set and `ostree` is not installed, so the \
         tool-comparison tests cannot run"
    );
    if !found {
        eprintln!("skipping {test}: ostree is not installed");
    }
    found
}

/// Runs the `ostree` command with `args`, asserts that it succeeds, and
/// returns its standard output.
#[cfg(feature = "push")]
fn ostree(args: &[&str]) -> String {
    let out = Command::new("ostree").args(args).output().unwrap();
    assert!(out.status.success(), "ostree {args:?}: {}", stderr(&out));
    stdout(&out)
}
