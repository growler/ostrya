//! `ostrya pull`, `ostrya remote refs`, and `ostrya remote summary` over
//! ssh, for a remote whose `pull-url` is an ssh address. A stand-in ssh
//! client runs the built `ostrya send` locally, the way the remote shell of
//! ssh runs the remote command. An opt-in test pulls over ssh to localhost.

#![cfg(feature = "send")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

const REQUIRE_OSTREE: &str = "OSTRYA_REQUIRE_OSTREE";

/// Opts in to the test that pulls over ssh to localhost, with the value `1`
/// alone.
const SSH_LOCALHOST: &str = "OSTRYA_TEST_SSH_LOCALHOST";

/// The stand-in ssh client. Its first two arguments are a file that gets the
/// exit status of the remote command and a file that gets its standard
/// error. It skips `-p PORT` and the host, and runs the remote command string
/// with `sh`.
const STANDIN: &str = r#"status_file=$1; stderr_file=$2; shift 2
if [ "$1" = "-p" ]; then shift 2; fi
shift
sh -c "$*" 2> "$stderr_file"
code=$?
echo "$code" > "$status_file"
exit "$code"
"#;

/// The files of the commit of each source.
const FILES: &[(&str, &str)] = &[("a", "alpha\n"), ("dir/b", "beta\n")];

struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> TmpDir {
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "ostrya-pull-ssh-{}-{tag}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        TmpDir(path)
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Quote `s` for a POSIX shell.
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// A run of the built `ostrya` in `dir`, with no ssh command and no
/// repository from the environment, and the variables of `envs`.
fn ostrya(dir: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ostrya"));
    command
        .args(args)
        .current_dir(dir)
        .env_remove("OSTRYA_SSH_COMMAND")
        .env_remove("OSTREE_REPO")
        .stdin(Stdio::null());
    for (key, value) in envs {
        command.env(key, value);
    }
    command.output().unwrap()
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8(out.stderr.clone()).unwrap()
}

/// The failure shape of a command: exit 1, nothing on standard output, and
/// `message` as the one line on standard error.
fn assert_failed(out: &Output, message: &str) {
    assert_eq!(out.status.code(), Some(1), "{}", stderr(out));
    assert_eq!(stdout(out), "");
    assert_eq!(stderr(out), format!("error: {message}\n"));
}

/// The standard output of `ostree --version`, or `None` when the tool does
/// not run. The first call runs the tool, and each later call reuses its
/// answer.
fn ostree_version() -> Option<&'static str> {
    static VERSION: OnceLock<Option<String>> = OnceLock::new();
    VERSION
        .get_or_init(|| {
            Command::new("ostree")
                .arg("--version")
                .output()
                .ok()
                .filter(|out| out.status.success())
                .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
        })
        .as_deref()
}

/// Whether the `ostree` tool can run. With `OSTRYA_REQUIRE_OSTREE` set, a
/// missing tool fails the test.
fn ostree_available() -> bool {
    let found = ostree_version().is_some();
    assert!(
        found || std::env::var_os(REQUIRE_OSTREE).is_none(),
        "{REQUIRE_OSTREE} is set and `ostree` is not installed"
    );
    if !found {
        eprintln!("skipped: `ostree` is not installed");
    }
    found
}

/// `ostree fsck` passes on `repo`, and `ostree rev-parse` resolves
/// `origin:main` to `commit`, where the tool is installed.
fn tool_checks(repo: &Path, commit: &str) {
    if !ostree_available() {
        return;
    }
    let tool = |args: &[&str]| {
        let out = Command::new("ostree")
            .arg(format!("--repo={}", repo.display()))
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "ostree {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    tool(&["fsck"]);
    assert_eq!(tool(&["rev-parse", "origin:main"]).trim(), commit);
}

/// The names of the objects of the repository at `repo`, each as
/// `XX/REST.KIND` with the content suffix of the mode dropped.
fn object_names(repo: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for fanout in std::fs::read_dir(repo.join("objects")).unwrap() {
        let fanout = fanout.unwrap();
        for object in std::fs::read_dir(fanout.path()).unwrap() {
            let name = object.unwrap().file_name().into_string().unwrap();
            let name = match name.strip_suffix("z") {
                Some(file) if file.ends_with(".file") => file.to_owned(),
                _ => name,
            };
            out.push(format!(
                "{}/{name}",
                fanout.file_name().into_string().unwrap()
            ));
        }
    }
    out.sort();
    out
}

/// The paths of one test: the base, the source repository, the client
/// repository, the stand-in script, and the status file of the stand-in.
struct Setup {
    base: TmpDir,
    src: PathBuf,
    client: PathBuf,
    standin: PathBuf,
    status: PathBuf,
    /// The commit of `main` in the source.
    commit: String,
}

impl Setup {
    /// A source of `src_mode` with one commit on `main` and a summary, a
    /// client of `client_mode`, and the stand-in script.
    fn new(tag: &str, src_mode: &str, client_mode: &str) -> Setup {
        let base = TmpDir::new(tag);
        let src = base.0.join("src");
        let client = base.0.join("client");
        for (repo, mode) in [(&src, src_mode), (&client, client_mode)] {
            let arg = format!("--repo={}", repo.display());
            let out = ostrya(&base.0, &[&arg, "init", &format!("--mode={mode}")], &[]);
            assert!(out.status.success(), "{}", stderr(&out));
        }
        let tree = base.0.join("tree");
        for (path, content) in FILES {
            let path = tree.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        }
        std::os::unix::fs::symlink("a", tree.join("link")).unwrap();
        let src_arg = format!("--repo={}", src.display());
        let out = ostrya(
            &base.0,
            &[
                &src_arg,
                "commit",
                "--branch=main",
                "-s",
                "subject",
                tree.to_str().unwrap(),
            ],
            &[],
        );
        assert!(out.status.success(), "{}", stderr(&out));
        let commit = stdout(&out).trim().to_owned();
        let out = ostrya(&base.0, &[&src_arg, "summary", "-u"], &[]);
        assert!(out.status.success(), "{}", stderr(&out));
        let standin = base.0.join("standin");
        std::fs::write(&standin, STANDIN).unwrap();
        let status = base.0.join("status");
        Setup {
            base,
            src,
            client,
            standin,
            status,
            commit,
        }
    }

    /// The ssh address of the source.
    fn address(&self) -> String {
        format!("ssh://localhost{}", self.src.display())
    }

    /// `ssh-command` of the stand-in and `send-command` of the built
    /// `ostrya send`.
    fn standin_keys(&self) -> String {
        format!(
            "ssh-command=sh {} {} {}\nsend-command={} send\n",
            self.standin.display(),
            self.status.display(),
            self.status.with_extension("stderr").display(),
            quote(env!("CARGO_BIN_EXE_ostrya"))
        )
    }

    /// Replace the section of `origin` in the client config with `keys`,
    /// and with no signature check. Remove the status file of the stand-in.
    fn configure(&self, keys: &str) {
        let config = self.client.join("config");
        let text = std::fs::read_to_string(&config).unwrap();
        let core = text.split("\n[remote").next().unwrap().to_owned();
        std::fs::write(
            &config,
            format!("{core}\n[remote \"origin\"]\n{keys}gpg-verify=false\n"),
        )
        .unwrap();
        let _ = std::fs::remove_file(&self.status);
    }

    /// Run `ostrya` on the client with `args` and the variables of `envs`.
    fn client(&self, args: &[&str], envs: &[(&str, &str)]) -> Output {
        let repo = format!("--repo={}", self.client.display());
        let mut all = vec![repo.as_str()];
        all.extend_from_slice(args);
        ostrya(&self.base.0, &all, envs)
    }

    fn ssh_started(&self) -> bool {
        self.status.exists()
    }

    /// The pull of `main` succeeded: the statistics line counts each content
    /// object of the source, the client resolves `origin:main` to the
    /// commit, holds the objects of the source, passes `ostrya fsck`, and the
    /// tool checks.
    fn assert_pulled(&self, out: &Output) {
        assert!(out.status.success(), "{}", stderr(out));
        let objects = object_names(&self.src);
        let content = objects.iter().filter(|n| n.ends_with(".file")).count();
        let line = stdout(out);
        let (metadata, rest) = line.split_once(" metadata, ").expect(&line);
        assert!(metadata.parse::<u32>().is_ok(), "{line}");
        assert!(
            rest.starts_with(&format!("{content} content objects fetched; ")),
            "{line}"
        );
        assert!(line.contains(" transferred in "), "{line}");
        assert!(line.ends_with(" content written\n"), "{line}");
        assert_eq!(line.lines().count(), 1, "{line}");
        let out = self.client(&["rev-parse", "origin:main"], &[]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out).trim(), self.commit);
        assert_eq!(object_names(&self.client), objects);
        let out = self.client(&["fsck"], &[]);
        assert!(out.status.success(), "{}", stderr(&out));
        tool_checks(&self.client, &self.commit);
    }
}

/// A remote whose `pull-url` is an ssh address pulls over ssh, with `url`
/// and without it. A `url` that answers no request is not read.
#[test]
fn a_pull_over_ssh_writes_the_refs_and_the_objects() {
    for (tag, url) in [("no-url", ""), ("dead-url", "url=http://127.0.0.1:1/\n")] {
        let setup = Setup::new(tag, "archive", "archive");
        setup.configure(&format!(
            "{url}pull-url={}\n{}",
            setup.address(),
            setup.standin_keys()
        ));
        let out = setup.client(&["pull", "origin", "main"], &[]);
        setup.assert_pulled(&out);
        assert!(setup.ssh_started());
    }
}

/// An ssh address in `url` is refused in the `ssh://` form and in the scp
/// form, and the ssh client does not start.
#[test]
fn an_ssh_address_in_url_is_refused() {
    let setup = Setup::new("ssh-url", "archive", "archive");
    for url in [
        setup.address(),
        format!("localhost:{}", setup.src.display()),
    ] {
        setup.configure(&format!("url={url}\n{}", setup.standin_keys()));
        let out = setup.client(&["pull", "origin", "main"], &[]);
        assert_failed(
            &out,
            &format!(
                "pull: remote 'origin': url '{url}' is an ssh address; the port reads an ssh \
                 address from pull-url alone"
            ),
        );
        assert!(!setup.ssh_started(), "{url}");
    }
}

/// Each option of HTTP alone is refused with an ssh address before the ssh
/// client starts. `--disable-retry-on-network-errors` sets a retry count of
/// 0, which is accepted.
#[test]
fn the_options_of_http_alone_are_refused_before_the_ssh_client_starts() {
    let setup = Setup::new("http-options", "archive", "bare-user");
    let address = setup.address();
    for (option, name) in [
        ("--http-header=A=B", "http-header"),
        ("--network-retries=1", "network-retries"),
        ("--low-speed-limit-bytes=5", "low-speed-limit-bytes"),
        ("--low-speed-time-seconds=5", "low-speed-time-seconds"),
    ] {
        setup.configure(&format!("pull-url={address}\n{}", setup.standin_keys()));
        let out = setup.client(&["pull", option, "origin", "main"], &[]);
        assert_failed(
            &out,
            &format!(
                "invalid input: {name} applies to a pull over HTTP, and '{address}' is an ssh \
                 address"
            ),
        );
        assert!(!setup.ssh_started(), "{option}");
    }
    setup.configure(&format!("pull-url={address}\n{}", setup.standin_keys()));
    let out = setup.client(
        &[
            "pull",
            "--disable-retry-on-network-errors",
            "origin",
            "main",
        ],
        &[],
    );
    setup.assert_pulled(&out);
}

/// `--url` wins over `pull-url`: a malformed `pull-url` is not read.
#[test]
fn the_url_option_wins_over_pull_url() {
    let setup = Setup::new("url-option", "archive", "archive");
    setup.configure(&format!(
        "pull-url=ssh://localhost\n{}",
        setup.standin_keys()
    ));
    let url = format!("--url={}", setup.address());
    let out = setup.client(&["pull", &url, "origin", "main"], &[]);
    setup.assert_pulled(&out);

    // The same pull with no --url reads the malformed key.
    let out = setup.client(&["pull", "origin", "main"], &[]);
    assert_failed(
        &out,
        "invalid input: address 'ssh://localhost': an ssh:// address needs a path",
    );
}

/// `remote refs` and `remote summary` read the summary of the remote over
/// ssh. With no summary on the remote, each fails with its message.
#[test]
fn remote_refs_and_remote_summary_read_the_remote_over_ssh() {
    let setup = Setup::new("remote-summary", "archive", "archive");
    setup.configure(&format!(
        "pull-url={}\n{}",
        setup.address(),
        setup.standin_keys()
    ));
    let out = setup.client(&["remote", "refs", "origin"], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "origin:main\n");
    assert!(setup.ssh_started());

    let out = setup.client(&["remote", "summary", "origin"], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    let src_arg = format!("--repo={}", setup.src.display());
    let view = ostrya(&setup.base.0, &[&src_arg, "summary", "--view"], &[]);
    assert!(view.status.success(), "{}", stderr(&view));
    assert_eq!(stdout(&out), stdout(&view));

    std::fs::remove_file(setup.src.join("summary")).unwrap();
    let _ = std::fs::remove_file(setup.src.join("summary.sig"));
    let out = setup.client(&["remote", "refs", "origin"], &[]);
    assert_failed(
        &out,
        "Remote refs not available; server has no summary file",
    );
    let out = setup.client(&["remote", "summary", "origin"], &[]);
    assert_failed(&out, "Remote server has no summary file");
}

/// `OSTRYA_SSH_COMMAND` wins over the remote key `ssh-command`.
#[test]
fn the_environment_wins_over_the_ssh_command_key() {
    let setup = Setup::new("ssh-env", "archive", "archive");
    setup.configure(&format!(
        "pull-url={}\n{}",
        setup.address(),
        setup.standin_keys()
    ));
    let out = setup.client(
        &["pull", "origin", "main"],
        &[("OSTRYA_SSH_COMMAND", "/nonexistent/ssh")],
    );
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).starts_with("error: transport: cannot run '/nonexistent/ssh': "),
        "{}",
        stderr(&out)
    );
    assert!(!setup.ssh_started());
}

/// Pull over ssh to localhost from an `archive` and a `bare-user` source
/// into an `archive` and a `bare-user` client, and check each client with
/// the tool.
#[test]
fn a_pull_over_ssh_to_localhost_is_read_by_the_tool() {
    if std::env::var(SSH_LOCALHOST).as_deref() != Ok("1") {
        eprintln!("skipped: {SSH_LOCALHOST} is not 1; set it to 1 to pull over ssh to localhost");
        return;
    }
    for src_mode in ["archive", "bare-user"] {
        for client_mode in ["archive", "bare-user"] {
            let setup = Setup::new("ssh-localhost", src_mode, client_mode);
            let known_hosts = setup.base.0.join("known_hosts");
            setup.configure(&format!(
                "pull-url={}\nssh-command=ssh -o UserKnownHostsFile={} \
                 -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o LogLevel=ERROR \
                 -o ConnectTimeout=10\nsend-command={} send\n",
                setup.address(),
                known_hosts.display(),
                quote(env!("CARGO_BIN_EXE_ostrya"))
            ));
            let out = setup.client(&["pull", "origin", "main"], &[]);
            assert!(
                out.status.success(),
                "{src_mode} to {client_mode}: {}",
                stderr(&out)
            );
            setup.assert_pulled(&out);
        }
    }
}
