#![forbid(unsafe_code)]

//! `ostrya` with a bucket repository at an `s3://` address: `remote init`,
//! `push`, `pull`, `remote refs`, `remote summary`, and `remote add`.
//!
//! Most tests run against the S3 stand-in of
//! `crates/ostrya/tests/common/s3.rs`, which holds its objects in memory,
//! honors `If-None-Match` and `If-Match`, and keeps the `Authorization`
//! header of each request. The stand-in serves `http://`, so each command
//! takes `--allow-cleartext-credentials`. Other tests run against `rclone
//! serve s3`, which checks each signature and refuses each writer, and
//! against `weed mini` of SeaweedFS. A test on a real server skips when its
//! program is absent. `OSTRYA_REQUIRE_S3` and `OSTRYA_REQUIRE_SEAWEEDFS` turn
//! each skip into a failure.
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
        command.output().unwrap()
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

/// `push-tree` refuses an `s3://` operand and a remote whose push address
/// is one, before it reads the AWS environment.
#[cfg(feature = "push")]
#[test]
fn push_tree_refuses_an_s3_destination() {
    let scratch = Scratch::new("push-tree");
    let server = StandIn::start();
    let repo = scratch.repo("local");
    scratch.append_config(
        &repo,
        &format!(
            "\n[remote \"r\"]\nurl=https://ex.com/r\npush-url={ADDRESS}\ns3-endpoint={}\n",
            server.endpoint()
        ),
    );
    let tree = scratch.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a"), b"a\n").unwrap();
    let dir = tree.to_str().unwrap();
    for (remote, shown) in [
        (ADDRESS, ADDRESS),
        ("s3://key:secret@bkt/repo", "s3://bkt/repo"),
        ("r", "r"),
    ] {
        // No key pair: a read of the AWS environment would fail with
        // another message.
        let out = scratch.run_with(
            &[&repo, "push-tree", remote, dir, "--onto=main"],
            &[("AWS_ACCESS_KEY_ID", None), ("AWS_SECRET_ACCESS_KEY", None)],
        );
        assert!(!out.status.success(), "{remote}");
        assert!(out.stdout.is_empty(), "{remote}: {}", stdout(&out));
        assert_eq!(
            stderr(&out),
            format!(
                "error: push-tree does not write a bucket repository, and the push address \
                 of '{shown}' is an s3:// address\n"
            ),
            "{remote}"
        );
    }
    assert!(server.state().requests.is_empty());
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

#[test]
fn a_pull_of_a_collection_refuses_the_s3_options_and_an_s3_remote() {
    let scratch = Scratch::new("pull-collection");
    let server = StandIn::start();
    let repo = scratch.repo("local");
    scratch.append_config(
        &repo,
        &format!(
            "\n[remote \"r\"]\npull-url={ADDRESS}\ncollection-id={ID}\ngpg-verify=false\n\
             s3-endpoint={}\n",
            server.endpoint()
        ),
    );
    for (option, name) in [
        (CLEARTEXT, CLEARTEXT),
        ("--s3-region=eu-west-1", "--s3-region"),
    ] {
        let message =
            scratch.fails(&[&repo, "pull", &format!("--collection={ID}"), "main", option]);
        assert_eq!(
            message,
            format!(
                "error: {name} applies to an s3:// address, and a pull with --collection reads \
                 no s3:// address\n"
            ),
            "{option}"
        );
    }
    let out = scratch.run(&[&repo, "pull", &format!("--collection={ID}"), "main"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("this remote is an S3 bucket repository"),
        "{}",
        stderr(&out)
    );
    assert!(server.state().requests.is_empty());
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

/// `remote refs`, `remote summary`, and `pull` read a copy of the `archive`
/// fixture through `rclone serve s3`, which checks each signature. A wrong
/// secret gives `SignatureDoesNotMatch`, and `remote init` and `push` are
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

#[cfg(feature = "push")]
#[test]
fn seaweedfs_takes_an_init_a_push_and_a_pull() {
    if !seaweed_available("seaweedfs_takes_an_init_a_push_and_a_pull") {
        return;
    }
    let scratch = Scratch::new("seaweed");
    let server = Seaweed::start(scratch.path(), "bkt");
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
}
