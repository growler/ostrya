//! `ostrya pull --collection`: the pull of the refs of a collection from the
//! remotes whose `collection-id` names it. An HTTP candidate is an `ostrya
//! serve` process. An ssh candidate runs the built `ostrya send` through a
//! stand-in ssh client, which runs the remote command locally.

#![cfg(all(feature = "serve", feature = "send"))]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

/// The collection that the tests pull.
const ID: &str = "org.example.Os";
/// The ref that the tests pull.
const REF: &str = "os/stable";
/// A timestamp of the commits.
const TS: u64 = 1_700_000_000;

/// The stand-in ssh client. Its first argument is a file that gets the
/// standard error of the remote command. It skips `-p PORT` and the host, and
/// runs the remote command string with `sh`.
const STANDIN: &str = r#"stderr_file=$1; shift
if [ "$1" = "-p" ]; then shift 2; fi
shift
sh -c "$*" 2> "$stderr_file"
"#;

struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> TmpDir {
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "ostrya-cli-pull-collection-{}-{tag}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        TmpDir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Quotes `s` for a POSIX shell.
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// A run of the built `ostrya` on the repository `repo`, with no ssh command
/// and no repository from the environment.
fn ostrya(repo: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ostrya"))
        .arg(format!("--repo={}", repo.display()))
        .args(args)
        .env_remove("OSTRYA_SSH_COMMAND")
        .env_remove("OSTREE_REPO")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// Runs `ostrya` as [`ostrya`] does, and returns its standard output. If the
/// command fails, the test fails.
fn ok(repo: &Path, args: &[&str]) -> String {
    let out = ostrya(repo, args);
    assert!(out.status.success(), "{args:?}: {}", stderr(&out));
    stdout(&out)
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8(out.stderr.clone()).unwrap()
}

/// Creates an archive repository at `path` with the collection id `own`.
fn init(path: &Path, own: Option<&str>) {
    let mut args = vec!["init".to_owned(), "--mode=archive".to_owned()];
    if let Some(own) = own {
        args.push(format!("--collection-id={own}"));
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    ok(path, &args);
}

/// Commits a small tree with the marker `marker` to the ref `name` of
/// `repo`, with the timestamp `timestamp`, and returns the commit. The
/// command binds the commit to the ref and to the collection of the
/// repository.
fn commit(repo: &Path, marker: &str, name: &str, timestamp: u64) -> String {
    let tree = repo.with_file_name(format!("tree-{marker}"));
    std::fs::create_dir_all(tree.join("dir")).unwrap();
    std::fs::write(tree.join("a"), format!("{marker}\n")).unwrap();
    std::fs::write(tree.join("dir/b"), b"beta\n").unwrap();
    let out = ok(
        repo,
        &[
            "commit",
            &format!("--branch={name}"),
            &format!("--timestamp=@{timestamp}"),
            "-s",
            marker,
            tree.to_str().unwrap(),
        ],
    );
    out.trim().to_owned()
}

/// A running `ostrya serve` process. A drop of this value kills the process.
struct Serving {
    child: Child,
    url: String,
}

impl Serving {
    /// Starts the server over `repo` on a port that the kernel chooses, and
    /// reads the URL that the server writes.
    fn start(repo: &Path) -> Serving {
        let mut child = Command::new(env!("CARGO_BIN_EXE_ostrya"))
            .arg(format!("--repo={}", repo.display()))
            .args(["serve", "--listen=127.0.0.1:0"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(line.starts_with("http"), "serve wrote {line:?}");
        Serving {
            child,
            url: line.trim_end().to_owned(),
        }
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Returns the keys of a remote at `url` with the collection id `id`.
fn http_remote(name: &str, url: &str, id: &str) -> String {
    format!("\n[remote \"{name}\"]\nurl={url}\ngpg-verify=false\ncollection-id={id}\n")
}

/// Returns the keys of a remote over ssh to the repository `repo`, through
/// the stand-in ssh client `standin` and the built `ostrya send`.
fn ssh_remote(name: &str, repo: &Path, standin: &Path) -> String {
    format!(
        "\n[remote \"{name}\"]\npull-url=ssh://localhost{}\nssh-command=sh {} {}\n\
         send-command={} send --client=puller\ngpg-verify=false\ncollection-id={ID}\n",
        repo.display(),
        standin.display(),
        standin.with_extension("stderr").display(),
        quote(env!("CARGO_BIN_EXE_ostrya"))
    )
}

/// Appends `sections` to the config of the repository at `repo`.
fn configure(repo: &Path, sections: &str) {
    let config = repo.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str(sections);
    std::fs::write(&config, text).unwrap();
}

/// Returns the commit of the ref file at `relpath` of the repository `repo`,
/// or `None` if there is no such file.
fn ref_file(repo: &Path, relpath: &str) -> Option<String> {
    std::fs::read_to_string(repo.join(relpath))
        .ok()
        .map(|text| text.trim().to_owned())
}

/// Checks the shape of a pull that succeeded: one statistics line on
/// standard output, and `warnings` as the lines on standard error.
fn assert_pulled(out: &Output, warnings: usize) {
    assert!(out.status.success(), "{}", stderr(out));
    let line = stdout(out);
    assert_eq!(line.lines().count(), 1, "{line}");
    assert!(line.contains(" content objects fetched; "), "{line}");
    assert!(line.ends_with(" content written\n"), "{line}");
    let err = stderr(out);
    assert_eq!(err.lines().count(), warnings, "{err}");
    assert!(err.lines().all(|l| l.starts_with("warning: ")), "{err}");
}

/// An HTTP candidate and an ssh candidate each give the ref with the newer
/// commit, with the refs named and with no operand. A remote of another
/// collection is not a candidate. The pull writes the collection refs and no
/// remote ref, and the repository passes fsck.
#[test]
fn the_newest_commit_comes_over_http_or_ssh() {
    let dir = TmpDir::new("mixed");
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    init(&a, Some(ID));
    init(&b, Some(ID));
    let a_stable = commit(&a, "a1", REF, TS);
    let a_next = commit(&a, "a2", "os/next", TS + 20);
    let b_stable = commit(&b, "b1", REF, TS + 10);
    let b_next = commit(&b, "b2", "os/next", TS);
    let serving = Serving::start(&a);
    let standin = dir.path().join("standin");
    std::fs::write(&standin, STANDIN).unwrap();

    for operands in [&[REF, "os/next"][..], &[][..]] {
        let client = dir.path().join(format!("client-{}", operands.len()));
        init(&client, None);
        configure(
            &client,
            &format!(
                "{}{}{}",
                http_remote("a", &serving.url, ID),
                ssh_remote("b", &b, &standin),
                http_remote("other", "http://127.0.0.1:1/", "org.example.Other"),
            ),
        );

        let mut args = vec!["pull", "--collection", ID];
        args.extend_from_slice(operands);
        let out = ostrya(&client, &args);
        assert_pulled(&out, 0);
        let mirrors = format!("refs/mirrors/{ID}");
        assert_eq!(
            ref_file(&client, &format!("{mirrors}/{REF}")),
            Some(b_stable.clone())
        );
        assert_eq!(
            ref_file(&client, &format!("{mirrors}/os/next")),
            Some(a_next.clone())
        );
        assert!(!client.join("refs/remotes/a").exists());
        assert!(!client.join("refs/remotes/b").exists());
        ok(&client, &["fsck"]);
    }
    assert_ne!(a_stable, b_next);
}

/// A candidate that fails to answer is skipped with one warning line. With
/// no operand, the pull takes each ref of the collection. Into a repository
/// with the same collection id, the pull writes the local refs.
#[test]
fn a_failing_candidate_is_skipped_and_the_local_refs_are_written() {
    let dir = TmpDir::new("skip");
    let a = dir.path().join("a");
    let client = dir.path().join("client");
    init(&a, Some(ID));
    init(&client, Some(ID));
    let stable = commit(&a, "a1", REF, TS);
    let next = commit(&a, "a2", "os/next", TS);
    let serving = Serving::start(&a);
    configure(
        &client,
        &format!(
            "{}{}",
            http_remote("dead", "http://127.0.0.1:1/", ID),
            http_remote("a", &serving.url, ID)
        ),
    );

    let out = ostrya(
        &client,
        &["pull", "--collection", ID, "--network-retries=0"],
    );
    assert_pulled(&out, 1);
    assert!(
        stderr(&out).starts_with("warning: remote dead skipped: "),
        "{}",
        stderr(&out)
    );
    assert_eq!(
        ref_file(&client, &format!("refs/heads/{REF}")),
        Some(stable)
    );
    assert_eq!(ref_file(&client, "refs/heads/os/next"), Some(next));
    assert!(!client.join("refs/mirrors").join(ID).exists());
}

/// A ref that no candidate lists fails the pull with exit 1, and the pull
/// writes no ref.
#[test]
fn a_ref_that_no_candidate_lists_fails() {
    let dir = TmpDir::new("missing");
    let a = dir.path().join("a");
    let client = dir.path().join("client");
    init(&a, Some(ID));
    init(&client, None);
    commit(&a, "a1", REF, TS);
    let serving = Serving::start(&a);
    configure(&client, &http_remote("a", &serving.url, ID));

    let out = ostrya(&client, &["pull", "--collection", ID, REF, "os/absent"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
    assert_eq!(
        stderr(&out),
        format!("error: pull: no remote of collection '{ID}' lists the ref 'os/absent'\n")
    );
    assert!(!client.join("refs/mirrors").join(ID).exists());
}

/// The command refuses `--collection` with `--url`, `--mirror`, and
/// `--disable-verify-bindings`, and an id that no remote has. A malformed
/// `collection-id` of any remote fails the command.
#[test]
fn the_command_refuses_what_a_collection_pull_cannot_take() {
    let dir = TmpDir::new("refusals");
    let client = dir.path().join("client");
    init(&client, None);
    configure(&client, &http_remote("a", "http://127.0.0.1:1/", ID));

    for option in [
        "--url=http://127.0.0.1:1/",
        "--mirror",
        "--disable-verify-bindings",
    ] {
        let out = ostrya(&client, &["pull", "--collection", ID, option, REF]);
        assert_ne!(out.status.code(), Some(0), "{option}");
        assert!(
            stderr(&out).contains("cannot be used with"),
            "{option}: {}",
            stderr(&out)
        );
    }

    let out = ostrya(&client, &["pull", "--collection", "org.example.None", REF]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
    assert_eq!(
        stderr(&out),
        "error: no remote has collection-id org.example.None\n"
    );

    let out = ostrya(&client, &["pull", "--collection", "fresh", REF]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(
        stderr(&out),
        "error: invalid input: invalid collection id: fresh\n"
    );

    configure(
        &client,
        "\n[remote \"bad\"]\nurl=http://127.0.0.1:1/\ncollection-id=a\\zb\n",
    );
    let out = ostrya(&client, &["pull", "--collection", ID, REF]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
    assert!(stderr(&out).contains("invalid escape"), "{}", stderr(&out));
}

/// An `ostrya serve` of another collection lists the refs of ID in the
/// collection map of its listing. The pull takes the collection ref, and
/// ignores the local ref of the same name in field 0, which is newer and
/// bound to the other collection. With no operand, the listing request
/// selects no local ref, and the pull takes the collection ref too.
#[test]
fn a_server_of_another_collection_lists_the_refs_in_its_map() {
    let dir = TmpDir::new("map");
    let scratch = dir.path().join("scratch");
    let b = dir.path().join("b");
    init(&scratch, Some(ID));
    init(&b, Some("org.example.Other"));
    let mirrored = commit(&scratch, "s1", REF, TS + 10);
    ok(&b, &["pull-local", scratch.to_str().unwrap(), REF]);
    ok(
        &b,
        &[
            "refs",
            "--collections",
            &format!("--create={ID}:{REF}"),
            &mirrored,
        ],
    );
    let local = commit(&b, "b1", REF, TS + 50);
    assert_ne!(local, mirrored);
    let serving = Serving::start(&b);

    for operands in [&[REF][..], &[][..]] {
        let client = dir.path().join(format!("client-{}", operands.len()));
        init(&client, None);
        configure(&client, &http_remote("b", &serving.url, ID));
        let mut args = vec!["pull", "--collection", ID];
        args.extend_from_slice(operands);
        let out = ostrya(&client, &args);
        assert_pulled(&out, 0);
        assert_eq!(
            ref_file(&client, &format!("refs/mirrors/{ID}/{REF}")),
            Some(mirrored.clone())
        );
        assert!(!client.join("refs/heads").join(REF).exists());
        ok(&client, &["fsck"]);
    }
}

/// With no operand, a pull in which no candidate lists a ref of the
/// collection fails with exit 1 and writes no ref.
#[test]
fn no_operand_and_no_listed_ref_fails() {
    let dir = TmpDir::new("none");
    let b = dir.path().join("b");
    let client = dir.path().join("client");
    init(&b, Some("org.example.Other"));
    init(&client, None);
    commit(&b, "b1", REF, TS);
    let serving = Serving::start(&b);
    configure(&client, &http_remote("b", &serving.url, ID));

    let out = ostrya(&client, &["pull", "--collection", ID]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
    assert_eq!(
        stderr(&out),
        format!("error: pull: no remote lists a ref of collection '{ID}'\n")
    );
    assert!(!client.join("refs/mirrors").join(ID).exists());
}
