//! Tests of `ostrya serve` against the `ostree` command. The tests run these
//! pulls with `ostree`:
//!
//! - a pull from a repository of each mode that ostrya reads, over HTTP and
//!   HTTPS,
//! - a pull of a ref alias from a repository with no summary,
//! - a pull from a repository whose summary names deltas that the server
//!   does not serve.
//!
//! The tests of the refusals of `ostrya serve`, of its settings, and of the
//! routing of the receive endpoint run without `ostree`.

#![cfg(feature = "serve")]

use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

const REQUIRE_OSTREE: &str = "OSTRYA_REQUIRE_OSTREE";

/// The digest of the empty `a(ayay)`, the shared `.file-xattrs` object of a
/// file with no extended attributes.
const EMPTY_XATTRS: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/tls")
        .join(name)
}

struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> TmpDir {
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "ostrya-cli-serve-{}-{tag}-{}",
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

/// Returns `true` if the `ostree` command is installed. If `REQUIRE_OSTREE`
/// is set and `ostree` is absent, the test fails. If `REQUIRE_OSTREE` is not
/// set, the test skips and prints a message.
fn ostree_available() -> bool {
    let found = Command::new("ostree")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    assert!(
        found || std::env::var_os(REQUIRE_OSTREE).is_none(),
        "{REQUIRE_OSTREE} is set and `ostree` is not installed"
    );
    if !found {
        eprintln!("skipped: `ostree` is not installed");
    }
    found
}

fn run(program: &str, args: &[&str]) -> Output {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// Run `program` with `args` and return its standard output. If the program
/// fails, the test fails.
fn ok(program: &str, args: &[&str]) -> String {
    let out = run(program, args);
    assert!(
        out.status.success(),
        "{program} {args:?} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn ostrya() -> &'static str {
    env!("CARGO_BIN_EXE_ostrya")
}

/// A running `ostrya serve` process. A drop of this value kills the process.
struct Serving {
    child: Child,
    url: String,
    stdout: BufReader<ChildStdout>,
}

/// The command `ostrya serve` over `repo`, with standard output on a pipe.
fn serve_command(repo: &Path) -> Command {
    let mut command = Command::new(ostrya());
    command
        .arg(format!("--repo={}", repo.display()))
        .arg("serve")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    command
}

impl Serving {
    /// Start the server over `repo` with the options `args`, on a port that
    /// the kernel chooses. Then read the URL that the server writes.
    fn start(repo: &Path, args: &[&str]) -> Serving {
        Serving::spawn(serve_command(repo).arg("--listen=127.0.0.1:0").args(args))
    }

    /// Start `command`, and read the first URL that the server writes.
    fn spawn(command: &mut Command) -> Serving {
        let mut child = command.spawn().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut serving = Serving {
            child,
            url: String::new(),
            stdout,
        };
        serving.url = serving.next_url();
        serving
    }

    /// Read the next URL that the server writes.
    fn next_url(&mut self) -> String {
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        assert!(line.starts_with("http"), "serve wrote {line:?}");
        assert!(line.ends_with("/\n"), "serve wrote {line:?}");
        line.trim_end().to_owned()
    }

    /// Kill the server, and return what it wrote to standard output after
    /// the URLs that the test read.
    fn rest(&mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let mut rest = String::new();
        std::io::Read::read_to_string(&mut self.stdout, &mut rest).unwrap();
        rest
    }

    fn tls(repo: &Path, pki: &Pki) -> Serving {
        Serving::start(
            repo,
            &[
                &format!("--tls-cert={}", pki.cert.display()),
                &format!("--tls-key={}", pki.key.display()),
            ],
        )
    }
}

/// A CA, a server certificate for `127.0.0.1` that the CA signed, and a
/// client certificate with the subject CN `puller` that the CA signed, for
/// the HTTPS pulls of the `ostree` command. The TLS fixtures name one subject
/// for the CA and the server certificate. An OpenSSL client reads that server
/// certificate as a self-signed leaf, so `ostree` needs a pair of its own.
struct Pki {
    ca: PathBuf,
    cert: PathBuf,
    key: PathBuf,
    client_cert: PathBuf,
    client_key: PathBuf,
}

/// Generate a `Pki` under `dir` with `openssl`. Each certificate takes a
/// config file of its own, and `OPENSSL_CONF` names no file. As a result, no
/// distinguished-name section of a host config replaces the subject.
fn make_pki(dir: &Path) -> Pki {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("ca.cnf"),
        "[req]\ndistinguished_name = dn\nx509_extensions = v3\n[dn]\n[v3]\n\
         basicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign,cRLSign\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("leaf.cnf"),
        "[req]\ndistinguished_name = dn\n[dn]\n[v3]\nbasicConstraints = critical,CA:FALSE\n\
         keyUsage = critical,digitalSignature\nextendedKeyUsage = serverAuth\n\
         subjectAltName = IP:127.0.0.1\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("client.cnf"),
        "[req]\ndistinguished_name = dn\n[dn]\n[v3]\nbasicConstraints = critical,CA:FALSE\n\
         keyUsage = critical,digitalSignature\nextendedKeyUsage = clientAuth\n",
    )
    .unwrap();
    let at = |name: &str| dir.join(name).to_str().unwrap().to_owned();
    let openssl = |args: &[&str]| {
        let out = Command::new("openssl")
            .args(args)
            .env("OPENSSL_CONF", "/dev/null")
            .stdin(Stdio::null())
            .output()
            .expect("run openssl");
        assert!(
            out.status.success(),
            "openssl {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    let p256 = [
        "genpkey",
        "-algorithm",
        "EC",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
    ];
    openssl(&[&p256[..], &["-out", &at("ca.key")]].concat());
    openssl(&[
        "req",
        "-x509",
        "-new",
        "-sha256",
        "-key",
        &at("ca.key"),
        "-subj",
        "/CN=ostrya serve test ca",
        "-days",
        "2",
        "-config",
        &at("ca.cnf"),
        "-out",
        &at("ca.pem"),
    ]);
    openssl(&[&p256[..], &["-out", &at("server.key")]].concat());
    openssl(&[
        "req",
        "-new",
        "-sha256",
        "-key",
        &at("server.key"),
        "-subj",
        "/CN=127.0.0.1",
        "-config",
        &at("leaf.cnf"),
        "-out",
        &at("server.csr"),
    ]);
    openssl(&[
        "x509",
        "-req",
        "-sha256",
        "-in",
        &at("server.csr"),
        "-CA",
        &at("ca.pem"),
        "-CAkey",
        &at("ca.key"),
        "-CAcreateserial",
        "-days",
        "2",
        "-extfile",
        &at("leaf.cnf"),
        "-extensions",
        "v3",
        "-out",
        &at("server.pem"),
    ]);
    openssl(&[&p256[..], &["-out", &at("client.key")]].concat());
    openssl(&[
        "req",
        "-new",
        "-sha256",
        "-key",
        &at("client.key"),
        "-subj",
        "/CN=puller",
        "-config",
        &at("client.cnf"),
        "-out",
        &at("client.csr"),
    ]);
    openssl(&[
        "x509",
        "-req",
        "-sha256",
        "-in",
        &at("client.csr"),
        "-CA",
        &at("ca.pem"),
        "-CAkey",
        &at("ca.key"),
        "-CAcreateserial",
        "-days",
        "2",
        "-extfile",
        &at("client.cnf"),
        "-extensions",
        "v3",
        "-out",
        &at("client.pem"),
    ]);
    Pki {
        ca: dir.join("ca.pem"),
        cert: dir.join("server.pem"),
        key: dir.join("server.key"),
        client_cert: dir.join("client.pem"),
        client_key: dir.join("client.key"),
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A tree with a regular file, an executable, an empty file, a file larger
/// than one 64 KiB chunk, a nested file, and a symlink.
fn build_tree(base: &Path) -> PathBuf {
    let src = base.join("src");
    std::fs::create_dir_all(src.join("subdir")).unwrap();
    std::fs::write(src.join("hello"), b"hello ostree\n").unwrap();
    std::fs::write(src.join("exec"), b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(src.join("exec"), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(src.join("empty"), b"").unwrap();
    let big: Vec<u8> = (0..300_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    std::fs::write(src.join("big"), big).unwrap();
    std::fs::write(src.join("subdir/nested"), b"nested\n").unwrap();
    std::os::unix::fs::symlink("hello", src.join("link")).unwrap();
    src
}

/// Create a repository of `mode` at `path` with the tree of `src` on `main`,
/// committed with the options `extra`, and return the commit.
fn server_repo(path: &Path, mode: &str, src: &Path, extra: &[&str]) -> String {
    let repo = format!("--repo={}", path.display());
    ok(ostrya(), &[&repo, "init", &format!("--mode={mode}")]);
    let mut commit = vec![
        repo.as_str(),
        "commit",
        "-b",
        "main",
        "-s",
        "served",
        "--no-xattrs",
    ];
    commit.extend(extra);
    commit.push(src.to_str().unwrap());
    ok(ostrya(), &commit).trim().to_owned()
}

/// Turn a `bare` repository whose objects carry no extended attributes into
/// a `bare-split-xattrs` repository:
///
/// - the inodes stay,
/// - the `config` file names the mode `bare-split-xattrs`,
/// - each file object gets a `.file-xattrs-link` to the shared empty
///   `.file-xattrs` object.
fn split_xattrs(path: &Path) {
    let objects = path.join("objects");
    let empty = objects.join(&EMPTY_XATTRS[..2]);
    std::fs::create_dir_all(&empty).unwrap();
    let empty = empty.join(format!("{}.file-xattrs", &EMPTY_XATTRS[2..]));
    std::fs::write(&empty, b"").unwrap();
    for fanout in std::fs::read_dir(&objects).unwrap() {
        for entry in std::fs::read_dir(fanout.unwrap().path()).unwrap() {
            let file = entry.unwrap().path();
            let name = file.to_str().unwrap();
            if name.ends_with(".file") {
                std::fs::hard_link(&empty, format!("{name}-xattrs-link")).unwrap();
            }
        }
    }
    let config = std::fs::read_to_string(path.join("config")).unwrap();
    std::fs::write(
        path.join("config"),
        config.replace("mode=bare\n", "mode=bare-split-xattrs\n"),
    )
    .unwrap();
}

/// A client repository of `mode` with the remote `origin` at `url`. If `pki`
/// is set, the remote trusts the CA of `pki` for HTTPS.
fn client(path: &Path, mode: &str, url: &str, pki: Option<&Pki>) -> String {
    let repo = format!("--repo={}", path.display());
    ok("ostree", &[&repo, "init", &format!("--mode={mode}")]);
    let ca = pki.map(|pki| format!("--set=tls-ca-path={}", pki.ca.display()));
    let mut add = vec![repo.as_str(), "remote", "add", "--no-gpg-verify"];
    add.extend(ca.as_deref());
    add.extend(["origin", url]);
    ok("ostree", &add);
    repo
}

/// Pull `rev` from `url` into a new client of `mode` under `path`, check the
/// client with `ostree fsck`, and return the commit of `origin:<rev>`.
fn pull(path: &Path, mode: &str, url: &str, pki: Option<&Pki>, rev: &str) -> String {
    let repo = client(path, mode, url, pki);
    ok("ostree", &[&repo, "pull", "origin", rev]);
    ok("ostree", &[&repo, "fsck"]);
    ok("ostree", &[&repo, "rev-parse", &format!("origin:{rev}")])
        .trim()
        .to_owned()
}

/// The `ostree` command pulls from a repository of each mode that ostrya
/// reads, over HTTP and over HTTPS. Each pulled repository passes
/// `ostree fsck`.
///
/// The summary of a `bare-user-shared` repository states that mode in
/// `ostree.summary.mode`. `ostree` cannot parse this value, so the pull from
/// that repository runs with no summary. The test also checks that a pull
/// with the summary fails with the error of `ostree`.
#[test]
fn the_tool_pulls_from_every_mode() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("modes");
    let src = build_tree(tmp.path());
    let pki = make_pki(&tmp.path().join("pki"));
    for mode in [
        "archive",
        "bare",
        "bare-user",
        "bare-user-only",
        "bare-user-shared",
        "bare-split-xattrs",
    ] {
        let path = tmp.path().join(mode);
        let initial = if mode == "bare-split-xattrs" {
            "bare"
        } else {
            mode
        };
        let commit = server_repo(&path, initial, &src, &[]);
        if mode != "bare-user-shared" {
            ok(
                ostrya(),
                &[&format!("--repo={}", path.display()), "summary", "-u"],
            );
        }
        if mode == "bare-split-xattrs" {
            split_xattrs(&path);
            ok("ostree", &[&format!("--repo={}", path.display()), "fsck"]);
        }
        let plain = Serving::start(&path, &[]);
        assert!(plain.url.starts_with("http://"));
        let dest = tmp.path().join(format!("{mode}-http"));
        let pulled = pull(&dest, "archive", &plain.url, None, "main");
        assert_eq!(pulled, commit, "{mode} over http");
        let secure = Serving::tls(&path, &pki);
        assert!(secure.url.starts_with("https://"));
        let dest = tmp.path().join(format!("{mode}-https"));
        let pulled = pull(&dest, "archive", &secure.url, Some(&pki), "main");
        assert_eq!(pulled, commit, "{mode} over https");
        if mode == "bare-user-shared" {
            ok(
                ostrya(),
                &[&format!("--repo={}", path.display()), "summary", "-u"],
            );
            let repo = client(
                &tmp.path().join("shared-summary"),
                "archive",
                &plain.url,
                None,
            );
            let out = run("ostree", &[&repo, "pull", "origin", "main"]);
            assert!(!out.status.success());
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                stderr.contains("Invalid mode 'bare-user-shared'"),
                "{stderr}"
            );
        }
    }
}

/// If the repository has no summary, the `ostree` command requests
/// `refs/heads/<ref>`. The view serves a ref alias as the ref that the alias
/// names. The commit carries no ref binding, because the test commits with
/// `--no-bindings`. With a binding, `ostree` holds the commit to the bound
/// name `main`.
#[test]
fn the_tool_pulls_an_alias_with_no_summary() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("alias");
    let src = build_tree(tmp.path());
    let path = tmp.path().join("server");
    let commit = server_repo(&path, "bare-user", &src, &["--no-bindings"]);
    let repo = format!("--repo={}", path.display());
    ok(ostrya(), &[&repo, "refs", "-A", "--create=alias", "main"]);
    assert!(!path.join("summary").exists());
    let server = Serving::start(&path, &[]);
    let pulled = pull(
        &tmp.path().join("client"),
        "archive",
        &server.url,
        None,
        "alias",
    );
    assert_eq!(pulled, commit);
}

/// With a client group, the server serves no summary, so the `ostree`
/// command requests `refs/heads/<ref>`. It pulls a ref that the group of
/// `anonymous` reads. A ref that the group does not read gets 404, so the
/// pull of that ref fails.
#[test]
fn the_tool_pulls_a_readable_ref_with_no_summary() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("read-rights");
    let src = build_tree(tmp.path());
    let path = tmp.path().join("server");
    let commit = server_repo(&path, "bare-user", &src, &[]);
    let repo = format!("--repo={}", path.display());
    let src = src.to_str().unwrap();
    ok(
        ostrya(),
        &[
            &repo,
            "commit",
            "-b",
            "secret",
            "-s",
            "secret",
            "--no-xattrs",
            src,
        ],
    );
    ok(ostrya(), &[&repo, "summary", "-u"]);
    assert!(path.join("summary").exists());
    let config = path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str("[ex-ostrya client \"public\"]\nauth=anonymous\nallow=r:main\n");
    std::fs::write(&config, text).unwrap();
    let server = Serving::start(&path, &[]);

    let response = raw(
        &server.url,
        "GET /summary HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n",
    );
    assert!(response.starts_with("HTTP/1.1 404 "), "{response}");
    let pulled = pull(
        &tmp.path().join("client"),
        "archive",
        &server.url,
        None,
        "main",
    );
    assert_eq!(pulled, commit);

    let denied = client(&tmp.path().join("denied"), "archive", &server.url, None);
    let out = run("ostree", &[&denied, "pull", "origin", "secret"]);
    // The tool 2026.1 writes `error: While fetching URL/refs/heads/secret:
    // Server returned HTTP 404`. The test checks the path and the status.
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("/refs/heads/secret"), "{stderr}");
    assert!(stderr.contains("404"), "{stderr}");
}

/// Returns the names of the refs that `ostree remote refs` lists for the
/// remote `origin` of the client `repo`, each with the remote prefix.
fn remote_refs(repo: &str) -> Vec<String> {
    let mut names: Vec<String> = ok("ostree", &[repo, "remote", "refs", "origin"])
        .lines()
        .map(str::to_owned)
        .collect();
    names.sort();
    names
}

/// The `ostree` command pulls through the root summary of the `anonymous`
/// item, whose group has a deny item. The summary lists the refs that the
/// group reads, and a pull of a denied ref fails.
#[test]
fn the_tool_pulls_through_the_summary_of_the_anonymous_item() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("anonymous-summary");
    let src = build_tree(tmp.path());
    let path = tmp.path().join("server");
    let commit = server_repo(&path, "bare-user", &src, &[]);
    let repo = format!("--repo={}", path.display());
    let src = src.to_str().unwrap();
    ok(
        ostrya(),
        &[
            &repo,
            "commit",
            "-b",
            "secret",
            "-s",
            "secret",
            "--no-xattrs",
            src,
        ],
    );
    let config = path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str(
        "[ex-ostrya client \"public\"]\nauth=anonymous\nallow=r:**\ndeny=secret\n\
         summary=true\n",
    );
    std::fs::write(&config, text).unwrap();
    ok(ostrya(), &[&repo, "summary", "-u"]);
    let server = Serving::start(&path, &[]);
    let client = client(&tmp.path().join("client"), "archive", &server.url, None);
    assert_eq!(remote_refs(&client), ["origin:main"]);
    ok("ostree", &[&client, "pull", "origin", "main"]);
    ok("ostree", &[&client, "fsck"]);
    let pulled = ok("ostree", &[&client, "rev-parse", "origin:main"]);
    assert_eq!(pulled.trim(), commit);
    let out = run("ostree", &[&client, "pull", "origin", "secret"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
}

/// The `ostree` command pulls through the summary of a `tls:NAME` item, with
/// the client certificate of `tls-client-cert-path` and
/// `tls-client-key-path`. A client with no certificate gets 401 for the
/// summary, and its pull fails.
#[test]
fn the_tool_pulls_through_the_summary_of_a_tls_item() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("tls-summary");
    let src = build_tree(tmp.path());
    let pki = make_pki(&tmp.path().join("pki"));
    let path = tmp.path().join("server");
    let commit = server_repo(&path, "bare-user", &src, &[]);
    let repo = format!("--repo={}", path.display());
    let src = src.to_str().unwrap();
    ok(
        ostrya(),
        &[
            &repo,
            "commit",
            "-b",
            "other",
            "-s",
            "other",
            "--no-xattrs",
            src,
        ],
    );
    let config = path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str("[ex-ostrya client \"puller\"]\nauth=tls:puller\nallow=r:main\nsummary=true\n");
    std::fs::write(&config, text).unwrap();
    ok(ostrya(), &[&repo, "summary", "-u"]);
    assert!(!path.join("summary").exists());
    let server = Serving::start(
        &path,
        &[
            &format!("--tls-cert={}", pki.cert.display()),
            &format!("--tls-key={}", pki.key.display()),
            &format!("--tls-client-ca={}", pki.ca.display()),
        ],
    );
    let client_path = tmp.path().join("client");
    let client = format!("--repo={}", client_path.display());
    ok("ostree", &[&client, "init", "--mode=archive"]);
    ok(
        "ostree",
        &[
            &client,
            "remote",
            "add",
            "--no-gpg-verify",
            &format!("--set=tls-ca-path={}", pki.ca.display()),
            &format!("--set=tls-client-cert-path={}", pki.client_cert.display()),
            &format!("--set=tls-client-key-path={}", pki.client_key.display()),
            "origin",
            &server.url,
        ],
    );
    assert_eq!(remote_refs(&client), ["origin:main"]);
    ok("ostree", &[&client, "pull", "origin", "main"]);
    ok("ostree", &[&client, "fsck"]);
    let pulled = ok("ostree", &[&client, "rev-parse", "origin:main"]);
    assert_eq!(pulled.trim(), commit);

    let stranger = client_without_cert(&tmp.path().join("stranger"), &server.url, &pki);
    let out = run("ostree", &[&stranger, "pull", "origin", "main"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
}

/// A client repository with the remote `origin` at `url`, which trusts the
/// CA of `pki` and has no client certificate.
fn client_without_cert(path: &Path, url: &str, pki: &Pki) -> String {
    client(path, "archive", url, Some(pki))
}

/// In a repository with a collection id, `ostrya summary -u` and `ostree
/// summary -u` put the refs of `refs/mirrors/ID/` of the own id into field 0,
/// with the mirror ref in place of the ref of `refs/heads` of the same name.
/// Both keep the other collections in the collection map, and neither has
/// the own id there. The anchor commit differs in each run, so the test
/// compares each other ref.
#[test]
fn the_summary_merges_the_own_mirrors_as_the_tool_does() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("own-mirrors");
    let src = build_tree(tmp.path());
    let path = tmp.path().join("port");
    let main = server_repo(&path, "archive", &src, &[]);
    let repo = format!("--repo={}", path.display());
    let other = ok(
        ostrya(),
        &[
            &repo,
            "commit",
            "-b",
            "other",
            "-s",
            "other",
            "--no-xattrs",
            src.to_str().unwrap(),
        ],
    )
    .trim()
    .to_owned();
    ok(
        ostrya(),
        &[
            &repo,
            "config",
            "set",
            "core.collection-id",
            "org.example.Own",
        ],
    );
    for (rel, commit) in [
        ("org.example.Own/main", &other),
        ("org.example.Own/extra/x", &main),
        ("org.example.Other/m", &main),
    ] {
        let file = path.join("refs/mirrors").join(rel);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, format!("{commit}\n")).unwrap();
    }
    let tool = tmp.path().join("tool");
    ok(
        "cp",
        &["-a", path.to_str().unwrap(), tool.to_str().unwrap()],
    );
    ok(ostrya(), &[&repo, "summary", "-u"]);
    ok(
        "ostree",
        &[&format!("--repo={}", tool.display()), "summary", "-u"],
    );

    type Refs = Vec<(String, ostrya::Checksum)>;
    let parse = |dir: &Path| -> (Refs, Vec<(String, Refs)>) {
        let bytes = std::fs::read(dir.join("summary")).unwrap();
        let summary = ostrya::Summary::parse(&bytes).unwrap();
        let entries = |refs: Vec<ostrya::SummaryRef>| -> Refs {
            refs.into_iter()
                .filter(|entry| entry.name != "ostree-metadata")
                .map(|entry| (entry.name, entry.commit))
                .collect()
        };
        let map = summary
            .collection_map()
            .unwrap()
            .into_iter()
            .map(|(id, refs)| (id, entries(refs)))
            .collect();
        (entries(summary.refs.clone()), map)
    };
    let (port_refs, port_map) = parse(&path);
    let (tool_refs, tool_map) = parse(&tool);
    assert_eq!(port_refs, tool_refs);
    assert_eq!(port_map, tool_map);
    let names: Vec<&str> = port_refs.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["extra/x", "main", "other"]);
    assert_eq!(port_refs[1].1.to_hex(), other);
    let ids: Vec<&str> = port_map.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(ids, ["org.example.Other"]);
}

/// The summary of a repository in a mode other than `archive` names a delta
/// that the view does not serve. A `bare-user` client of the `ostree` command
/// fetches the objects loose. With `--require-static-deltas`, the pull fails.
/// The client is `bare-user` because an `archive` client of `ostree` uses no
/// delta.
#[test]
fn the_tool_pulls_loose_past_unserved_deltas() {
    if !ostree_available() {
        return;
    }
    let tmp = TmpDir::new("deltas");
    let src = build_tree(tmp.path());
    let path = tmp.path().join("server");
    let commit = server_repo(&path, "bare-user", &src, &[]);
    let repo = format!("--repo={}", path.display());
    ok(
        ostrya(),
        &[
            &repo,
            "static-delta",
            "generate",
            "--empty",
            "--to",
            &commit,
        ],
    );
    ok(ostrya(), &[&repo, "summary", "-u"]);
    let summary = ok(ostrya(), &[&repo, "summary", "--view"]);
    assert!(
        summary.contains(&format!(
            "Static Deltas (ostree.static-deltas): {{'{commit}'"
        )),
        "{summary}"
    );
    assert!(path.join("deltas").exists());
    let server = Serving::start(&path, &[]);
    let pulled = pull(
        &tmp.path().join("loose"),
        "bare-user",
        &server.url,
        None,
        "main",
    );
    assert_eq!(pulled, commit);

    let client_repo = client(&tmp.path().join("required"), "bare-user", &server.url, None);
    let out = run(
        "ostree",
        &[
            &client_repo,
            "pull",
            "--require-static-deltas",
            "origin",
            "main",
        ],
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("error: Static deltas required, but none found for"),
        "{stderr}"
    );
}

/// `ostrya serve` refuses these inputs:
///
/// - `--policy`, `--push-credentials`, `--allow-anonymous-push`,
///   `--read-only`, and `--client-ca`, which it does not take,
/// - `[ex-ostrya receive]` in the config,
/// - a client group with a TLS item and no client CA,
/// - a key group whose key it cannot read,
/// - a TLS file that it cannot use, or that is larger than the size cap,
/// - a TLS file with no partner, from an option or from a key,
/// - a key of the server group with a bad value, also when an option
///   replaces the key,
/// - a proxy key of the server group.
///
/// Each refusal exits 1 and writes no URL.
#[test]
fn serve_refuses_what_it_cannot_serve() {
    let tmp = TmpDir::new("refusals");
    let path = tmp.path().join("repo");
    let repo = format!("--repo={}", path.display());
    ok(ostrya(), &[&repo, "init", "--mode=bare-user"]);
    let cert = format!("--tls-cert={}", fixture("server.pem").display());
    let key = format!("--tls-key={}", fixture("server.key.pem").display());
    let ca = format!("--tls-client-ca={}", fixture("ca.pem").display());
    let old_ca = format!("--client-ca={}", fixture("ca.pem").display());
    let enc_cert = format!("--tls-cert={}", fixture("client.pem").display());
    let enc_key = format!("--tls-key={}", fixture("client.key.enc.pem").display());
    let absent = format!("--tls-key={}", tmp.path().join("absent").display());
    let big = tmp.path().join("big.pem");
    std::fs::write(&big, vec![b'#'; 1024 * 1024 + 1]).unwrap();
    let big_cert = format!("--tls-cert={}", big.display());
    let listen = "--listen=127.0.0.1:0";
    let no_repo = format!("--repo={}", tmp.path().join("no-repo").display());
    // The path holds no word of the refusals, so a message that names it
    // does not pass for the refusal.
    let policy = format!("--policy={}", tmp.path().join("absent-rules").display());
    let creds = format!("--push-credentials={}", tmp.path().join("creds").display());
    let with_groups = |name: &str, groups: &str| {
        let path = tmp.path().join(name);
        let arg = format!("--repo={}", path.display());
        ok(ostrya(), &[&arg, "init", "--mode=archive"]);
        let config = path.join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str(groups);
        std::fs::write(&config, text).unwrap();
        arg
    };
    let server = |name: &str, keys: &str| with_groups(name, &format!("[ex-ostrya server]\n{keys}"));
    let removed = with_groups("removed", "[ex-ostrya receive]\naccept=true\n");
    let tls_item = with_groups("tls-item", "[ex-ostrya client \"c\"]\nauth=tls:*\n");
    let bad_key = with_groups(
        "bad-key",
        "[ex-ostrya key \"k\"]\ntype=ed25519\nsecret-key-file=/nonexistent/ostrya/k\n",
    );
    let cert_key = server(
        "cert-key",
        &format!("tls-cert={}\n", fixture("server.pem").display()),
    );
    let ca_key = server(
        "ca-key",
        &format!("tls-client-ca={}\n", fixture("ca.pem").display()),
    );
    let listen_key = server("listen-key", "listen=localhost:8080\n");
    let session_key = server("session-key", "session-timeout=0\n");
    let max_key = server("max-key", "max-sessions=0\n");
    let parallel_key = server("parallel-key", "parallel-uploads=32\n");
    let body_key = server("body-key", "body-timeout=0\n");
    let header_key = server("header-key", "trusted-proxy-header=X-Real-IP\n");
    let proxy_alone = server("proxy-alone", "trusted-proxy=10.0.0.0/8\n");
    let header_alone = server("header-alone", "trusted-proxy-header=x-real-ip\n");
    let cert_no_ca = server(
        "cert-no-ca",
        "trusted-proxy=10.0.0.0/8\ntrusted-proxy-header=x-real-ip\n\
         trusted-proxy-client-cert=X-Client-Cert\n",
    );
    let cert_no_proxy = server(
        "cert-no-proxy",
        &format!(
            "tls-client-ca={}\ntrusted-proxy-client-cert=X-Client-Cert\n",
            fixture("ca.pem").display()
        ),
    );
    let anon = "--allow-anonymous-push";
    let tls_pair = "tls-cert is set, and tls-key is not";
    let ca_alone = "tls-client-ca is set, and tls-cert and trusted-proxy-client-cert are not";
    let cases: &[(&[&str], &str)] = &[
        (&[&no_repo, "serve", listen, &policy], "--policy"),
        (&[&repo, "serve", listen, &policy], "--policy"),
        (&[&repo, "serve", listen, &creds], "--push-credentials"),
        (&[&no_repo, "serve", listen, &creds], "--push-credentials"),
        (&[&repo, "serve", listen, anon], "--allow-anonymous-push"),
        (&[&no_repo, "serve", listen, anon], "--allow-anonymous-push"),
        (&[&no_repo, "serve", listen, "--read-only"], "--read-only"),
        (
            &[&no_repo, "serve", listen, &old_ca, &cert, &key],
            "--client-ca",
        ),
        (&[&removed, "serve", listen], "[ex-ostrya client \"NAME\"]"),
        (&[&tls_item, "serve", listen], "tls-client-ca"),
        (&[&bad_key, "serve", listen], "/nonexistent/ostrya/k"),
        (
            &[&repo, "serve", listen, "--parallel-uploads=32"],
            "--parallel-uploads",
        ),
        (
            &[&repo, "serve", listen, "--session-timeout=0"],
            "--session-timeout",
        ),
        (
            &[&repo, "serve", listen, "--max-sessions=0"],
            "--max-sessions",
        ),
        (
            &[&repo, "serve", listen, "--body-timeout=0"],
            "--body-timeout",
        ),
        (
            &[&repo, "serve", listen, "--allow-cleartext-credentials=yes"],
            "--allow-cleartext-credentials",
        ),
        (&[&repo, "serve", listen, &ca], ca_alone),
        (&[&repo, "serve", listen, &cert], tls_pair),
        (
            &[&repo, "serve", listen, &key],
            "tls-key is set, and tls-cert is not",
        ),
        (&[&repo, "serve", listen, &enc_cert, &enc_key], "passphrase"),
        (&[&repo, "serve", listen, &big_cert, &key], "size cap"),
        (&[&cert_key, "serve", listen], tls_pair),
        (&[&ca_key, "serve", listen], ca_alone),
        (
            &[&ca_key, "serve", listen, &key],
            "tls-key is set, and tls-cert is not",
        ),
        (&[&listen_key, "serve"], "listen item 'localhost:8080'"),
        (
            &[&listen_key, "serve", listen],
            "listen item 'localhost:8080'",
        ),
        (&[&session_key, "serve", listen], "session-timeout is 0"),
        (&[&max_key, "serve", listen], "max-sessions is 0"),
        (&[&parallel_key, "serve", listen], "parallel-uploads is 32"),
        (
            &[&parallel_key, "serve", listen, "--parallel-uploads=4"],
            "parallel-uploads is 32",
        ),
        (&[&body_key, "serve", listen], "body-timeout is 0"),
        (
            &[&repo, "serve", listen, "--trusted-proxy=10.0.0.1/24"],
            "--trusted-proxy",
        ),
        (
            &[&repo, "serve", listen, "--trusted-proxy=fe80::1%eth0"],
            "--trusted-proxy",
        ),
        (
            &[&repo, "serve", listen, "--trusted-proxy-header=X-Real-IP"],
            "--trusted-proxy-header",
        ),
        (
            &[
                &repo,
                "serve",
                listen,
                "--trusted-proxy-client-cert=X Client",
            ],
            "--trusted-proxy-client-cert",
        ),
        (
            &[&repo, "serve", listen, "--trusted-proxy-client-cert="],
            "--trusted-proxy-client-cert",
        ),
        (
            &[&repo, "serve", listen, "--proxy-protocol=yes"],
            "--proxy-protocol",
        ),
        (
            &[&header_key, "serve", listen],
            "trusted-proxy-header value 'X-Real-IP'",
        ),
        (
            &[&proxy_alone, "serve", listen],
            "trusted-proxy is set, and the server has no trusted-proxy-header",
        ),
        (
            &[&repo, "serve", listen, "--trusted-proxy=10.0.0.0/8"],
            "trusted-proxy is set, and the server has no trusted-proxy-header",
        ),
        (
            &[&header_alone, "serve", listen],
            "trusted-proxy-header is set, and the server has no trusted-proxy",
        ),
        (
            &[&cert_no_ca, "serve", listen],
            "trusted-proxy-client-cert is set, and the server has no tls-client-ca",
        ),
        (
            &[&cert_no_proxy, "serve", listen],
            "trusted-proxy-client-cert is set, and the server has no trusted-proxy",
        ),
    ];
    for &(args, message) in cases {
        let out = run(ostrya(), args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(out.stdout.is_empty(), "{args:?}");
        assert!(stderr.contains(message), "{args:?}: {stderr}");
    }
    let out = run(ostrya(), &[&repo, "serve", listen, &cert, &absent]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("absent"));
}

/// Returns a request that opens a push session of the ref `name`, with no
/// credential.
fn session_request(name: &str) -> Vec<u8> {
    session_request_with(name, "")
}

/// Returns a request that opens a push session of the ref `name`, with the
/// header lines `headers`, each with its CRLF.
fn session_request_with(name: &str, headers: &str) -> Vec<u8> {
    use ostrya::remote::proto::{FrameWriter, Hello, Message};

    let hello = Message::Hello(Hello {
        version: 1,
        agent: None,
        refs: vec![name.into()],
        collection: None,
        one_way: false,
    });
    let body = ostrya_rt::block_on(async {
        let mut writer = FrameWriter::new(Vec::new());
        writer.write_message(&hello).await.unwrap();
        writer.into_inner()
    });
    let mut request = format!(
        "POST /_ostrya/receive/v1/session HTTP/1.1\r\nhost: x\r\n{headers}\
         content-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(&body);
    request
}

/// `ostrya serve` takes its settings from `[ex-ostrya server]`, and an option
/// replaces the key of its name:
///
/// - `tls-cert`, `tls-key`, and `tls-client-ca` in the server group, with a
///   `tls:*` item and no option, serve HTTPS. A relative path in a key is
///   relative to the repository directory, also when the command runs in
///   another directory.
/// - A relative path in an option is relative to the current directory.
/// - An option replaces the path of a key, and the command does not read
///   the file of the key. `tls-cert` from a key and `--tls-key` go together.
/// - A `listen` key with two addresses gives two listeners, and `--listen`
///   replaces both with one. Standard output carries the URL lines alone.
/// - `allow-cleartext-credentials=true` takes a bearer token over plain
///   HTTP, and `--allow-cleartext-credentials=false` refuses it with 403.
/// - `max-sessions=1` refuses a second session with 503, and
///   `--max-sessions=2` opens it.
#[test]
fn serve_takes_its_settings_from_the_server_group() {
    let tmp = TmpDir::new("settings");
    let with_config = |name: &str, sections: &str| {
        let path = tmp.path().join(name);
        ok(
            ostrya(),
            &[
                &format!("--repo={}", path.display()),
                "init",
                "--mode=archive",
            ],
        );
        let config = path.join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str(sections);
        std::fs::write(&config, text).unwrap();
        path
    };
    let listen = "--listen=127.0.0.1:0";
    let pem = |name: &str| fixture(name).display().to_string();

    let keys = with_config(
        "keys",
        "[ex-ostrya server]\ntls-cert=server.pem\ntls-key=server.key.pem\n\
         tls-client-ca=ca.pem\n[ex-ostrya client \"c\"]\nauth=tls:*\nallow=r:**\n",
    );
    for name in ["server.pem", "server.key.pem", "ca.pem"] {
        std::fs::copy(fixture(name), keys.join(name)).unwrap();
    }
    let mut server = Serving::spawn(serve_command(&keys).arg(listen).current_dir(tmp.path()));
    assert!(server.url.starts_with("https://"), "{}", server.url);
    assert_eq!(server.rest(), "");

    let flags = with_config("flags", "");
    let server = Serving::spawn(
        serve_command(&flags)
            .args([
                listen,
                "--tls-cert=server.pem",
                "--tls-key=server.key.pem",
                "--tls-client-ca=ca.pem",
            ])
            .current_dir(fixture("")),
    );
    assert!(server.url.starts_with("https://"), "{}", server.url);
    drop(server);

    let replaced = with_config(
        "replaced",
        "[ex-ostrya server]\ntls-cert=absent.pem\ntls-key=absent.key.pem\n",
    );
    let server = Serving::start(
        &replaced,
        &[
            &format!("--tls-cert={}", pem("server.pem")),
            &format!("--tls-key={}", pem("server.key.pem")),
        ],
    );
    assert!(server.url.starts_with("https://"), "{}", server.url);
    drop(server);
    let mixed = with_config("mixed", "[ex-ostrya server]\ntls-cert=server.pem\n");
    std::fs::copy(fixture("server.pem"), mixed.join("server.pem")).unwrap();
    let server = Serving::start(&mixed, &[&format!("--tls-key={}", pem("server.key.pem"))]);
    assert!(server.url.starts_with("https://"), "{}", server.url);
    drop(server);

    let two = with_config(
        "listen",
        "[ex-ostrya server]\nlisten=127.0.0.1:0;127.0.0.1:0\n",
    );
    let mut server = Serving::spawn(&mut serve_command(&two));
    let second = server.next_url();
    assert!(server.url.starts_with("http://"), "{}", server.url);
    assert!(second.starts_with("http://"), "{second}");
    assert_ne!(server.url, second);
    assert_eq!(server.rest(), "");
    let mut server = Serving::start(&two, &[]);
    assert!(server.url.starts_with("http://"), "{}", server.url);
    assert_eq!(server.rest(), "");

    // The SHA-256 digest of `token`.
    let digest = "3c469e9d6c5875d37a43f353d4f88e61fcf812c66eee3457465a40b0da4153e0";
    let cleartext = with_config(
        "cleartext",
        &format!(
            "[ex-ostrya server]\nallow-cleartext-credentials=true\n\
             [ex-ostrya client \"builders\"]\nauth=token-sha256:{digest}\nallow=w:**\n"
        ),
    );
    let post = "POST /_ostrya/receive/v1/session HTTP/1.1\r\nhost: x\r\n\
                authorization: Bearer token\r\ncontent-length: 0\r\n\
                connection: close\r\n\r\n";
    let server = Serving::start(&cleartext, &[]);
    let response = raw(&server.url, post);
    // A 422 shows that the request passed the authentication. The empty
    // body holds no `Hello`, so the endpoint refuses it with `protocol`.
    assert!(response.starts_with("HTTP/1.1 422 "), "{response}");
    drop(server);
    let server = Serving::start(&cleartext, &["--allow-cleartext-credentials=false"]);
    let response = raw(&server.url, post);
    assert!(response.starts_with("HTTP/1.1 403 "), "{response}");
    assert!(response.contains("the server takes no credential over plain HTTP"));
    drop(server);

    let sessions = with_config(
        "sessions",
        "[ex-ostrya server]\nmax-sessions=1\n\
         [ex-ostrya client \"push\"]\nauth=anonymous\nallow=w:**\n",
    );
    let server = Serving::start(&sessions, &[]);
    let response = raw(&server.url, session_request("a"));
    assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
    let response = raw(&server.url, session_request("b"));
    assert!(response.starts_with("HTTP/1.1 503 "), "{response}");
    drop(server);
    let server = Serving::start(&sessions, &["--max-sessions=2"]);
    for name in ["a", "b"] {
        let response = raw(&server.url, session_request(name));
        assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
    }
}

/// Send `request` to the server at `url` on a new connection, and read the
/// response until the server closes it.
fn raw(url: &str, request: impl AsRef<[u8]>) -> String {
    use std::io::{Read, Write};

    let addr = url.trim_start_matches("http://").trim_end_matches('/');
    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    stream.write_all(request.as_ref()).unwrap();
    let mut out = Vec::new();
    stream.read_to_end(&mut out).unwrap();
    String::from_utf8_lossy(&out).into_owned()
}

/// Send `request` to the server at `url` on a new connection, and read until
/// the server closes it. A reset of the connection ends the read with no
/// error, so a connection that the server closes with no response gives an
/// empty string.
fn raw_or_closed(url: &str, request: impl AsRef<[u8]>) -> String {
    use std::io::{Read, Write};

    let addr = url.trim_start_matches("http://").trim_end_matches('/');
    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    let _ = stream.write_all(request.as_ref());
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    while let Ok(n) = stream.read(&mut chunk) {
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A directory under `refs/mirrors/` whose name is not a collection id
/// gives one `warning:` line on standard error in a run, at the first ref
/// listing whose query holds a `collection` pair. Each listing gets 200,
/// and standard output holds the URL alone.
#[test]
fn serve_warns_one_time_for_each_invalid_collection_dir() {
    use std::io::Read;

    let tmp = TmpDir::new("serve-invalid-collection-dir");
    let src = build_tree(tmp.path());
    let path = tmp.path().join("repo");
    server_repo(&path, "archive", &src, &[]);
    for dir in ["bad", "a..b"] {
        let dir = path.join("refs/mirrors").join(dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("x"), "no checksum\n").unwrap();
    }
    let mut command = serve_command(&path);
    command.arg("--listen=127.0.0.1:0").stderr(Stdio::piped());
    let mut serving = Serving::spawn(&mut command);
    for query in ["", "?collection=%2A%2A", "?pattern=main&collection=%2A%2A"] {
        let response = raw(
            &serving.url,
            format!("GET /_ostrya/refs/v1{query} HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n"),
        );
        assert!(response.starts_with("HTTP/1.1 200 "), "{query}: {response}");
    }
    assert_eq!(serving.rest(), "");
    let mut stderr = String::new();
    serving
        .child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    let line = |name: &str| {
        format!(
            "warning: refs/mirrors/{name}: the directory name is not a collection id, and \
             the ref listing leaves out the directory\n"
        )
    };
    assert_eq!(stderr, format!("{}{}", line("a..b"), line("bad")));
}

/// `ostrya serve` takes the proxy settings from `[ex-ostrya server]`, and an
/// option replaces the key of its name:
///
/// - `proxy-protocol=true` serves a request after a PROXY header and closes
///   a connection with no header. `--proxy-protocol=false` serves the
///   request with no header. With no key, `--proxy-protocol` with no value
///   reads the header.
/// - `trusted-proxy` and `trusted-proxy-header` give the client address of
///   `X-Forwarded-For`, which a `net:` item matches. `--trusted-proxy`
///   replaces the networks of the key, so the server ignores the header of
///   the loopback peer. `--trusted-proxy-header` replaces the header of the
///   key.
/// - `tls-client-ca` and `trusted-proxy-client-cert`, with no `tls-cert`,
///   start a plain HTTP server, and a forwarded certificate opens a session.
///   `--trusted-proxy-client-cert` replaces the header of the key.
#[test]
fn serve_takes_the_proxy_settings_from_the_server_group() {
    let tmp = TmpDir::new("proxies");
    let with_config = |name: &str, sections: &str| {
        let path = tmp.path().join(name);
        ok(
            ostrya(),
            &[
                &format!("--repo={}", path.display()),
                "init",
                "--mode=archive",
            ],
        );
        let config = path.join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str(sections);
        std::fs::write(&config, text).unwrap();
        path
    };
    let get = "GET /config HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n";
    let header = "PROXY TCP4 192.0.2.7 127.0.0.1 56324 8080\r\n";

    let proxy_protocol = with_config(
        "proxy-protocol",
        "[ex-ostrya server]\nproxy-protocol=true\n",
    );
    let server = Serving::start(&proxy_protocol, &[]);
    let response = raw_or_closed(&server.url, format!("{header}{get}"));
    assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
    assert_eq!(raw_or_closed(&server.url, get), "");
    drop(server);
    let server = Serving::start(&proxy_protocol, &["--proxy-protocol=false"]);
    assert!(raw(&server.url, get).starts_with("HTTP/1.1 200 "));
    drop(server);
    let no_key = with_config("no-key", "");
    let server = Serving::start(&no_key, &["--proxy-protocol"]);
    let response = raw_or_closed(&server.url, format!("{header}{get}"));
    assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
    assert_eq!(raw_or_closed(&server.url, get), "");
    drop(server);

    let farm = "[ex-ostrya client \"farm\"]\nauth=net:192.0.2.0/24\nallow=w:**\n";
    let forwarded = with_config(
        "forwarded",
        &format!(
            "[ex-ostrya server]\ntrusted-proxy=127.0.0.1\n\
             trusted-proxy-header=x-forwarded-for\n{farm}"
        ),
    );
    let request = session_request_with("a", "x-forwarded-for: 192.0.2.7\r\n");
    let server = Serving::start(&forwarded, &[]);
    let response = raw(&server.url, &request);
    assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
    drop(server);
    let server = Serving::start(&forwarded, &["--trusted-proxy=192.0.2.0/24"]);
    let response = raw(&server.url, &request);
    assert!(response.starts_with("HTTP/1.1 403 "), "{response}");
    assert!(response.contains("matches no auth item"), "{response}");
    drop(server);
    let server = Serving::start(&forwarded, &["--trusted-proxy-header=x-real-ip"]);
    let response = raw(
        &server.url,
        session_request_with("b", "x-forwarded-for: 192.0.2.7\r\n"),
    );
    assert!(response.starts_with("HTTP/1.1 403 "), "{response}");
    let response = raw(
        &server.url,
        session_request_with("b", "x-real-ip: 192.0.2.7\r\n"),
    );
    assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
    drop(server);

    let certs = with_config(
        "certs",
        "[ex-ostrya server]\ntls-client-ca=ca.pem\ntrusted-proxy=127.0.0.1\n\
         trusted-proxy-header=x-real-ip\ntrusted-proxy-client-cert=X-SSL-Client-Cert\n\
         [ex-ostrya client \"certs\"]\nauth=tls:ostrya test\nallow=w:**\n",
    );
    std::fs::copy(fixture("ca.pem"), certs.join("ca.pem")).unwrap();
    let client: String = std::fs::read_to_string(fixture("client.pem"))
        .unwrap()
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let server = Serving::start(&certs, &[]);
    assert!(server.url.starts_with("http://"), "{}", server.url);
    let line = format!("x-ssl-client-cert: {client}\r\n");
    let response = raw(&server.url, session_request_with("a", &line));
    assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
    let response = raw(&server.url, session_request("a"));
    assert!(response.starts_with("HTTP/1.1 403 "), "{response}");
    drop(server);
    let server = Serving::start(&certs, &["--trusted-proxy-client-cert=X-Other-Cert"]);
    let response = raw(&server.url, session_request_with("c", &line));
    assert!(response.starts_with("HTTP/1.1 403 "), "{response}");
    let line = format!("x-other-cert: {client}\r\n");
    let response = raw(&server.url, session_request_with("c", &line));
    assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
}

/// With a client group of anonymous push, the receive endpoint answers a
/// `session` request, and the archive view still serves `config`. With a
/// group that reads each ref and opens no push session, a `Hello` gets 403.
#[test]
fn serve_runs_the_receive_endpoint_with_anonymous_push() {
    let tmp = TmpDir::new("receive");
    let path = tmp.path().join("repo");
    let repo = format!("--repo={}", path.display());
    ok(ostrya(), &[&repo, "init", "--mode=archive"]);
    let config = path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str("[ex-ostrya client \"push\"]\nauth=anonymous\nallow=w:**\n");
    std::fs::write(&config, text).unwrap();
    let post = "POST /_ostrya/receive/v1/session HTTP/1.1\r\nhost: x\r\n\
                content-length: 0\r\nconnection: close\r\n\r\n";
    let get = "GET /config HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n";
    let server = Serving::start(
        &path,
        &[
            "--session-timeout=30",
            "--max-sessions=2",
            "--parallel-uploads=2",
        ],
    );
    let response = raw(&server.url, post);
    // An empty body holds no `Hello`, so the endpoint refuses it with
    // `protocol`.
    assert!(response.starts_with("HTTP/1.1 422 "), "{response}");
    assert!(response.contains("the request body holds no message"));
    assert!(raw(&server.url, get).starts_with("HTTP/1.1 200 "));
    drop(server);
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(&config, text.replace("allow=w:**", "allow=r:**")).unwrap();
    let server = Serving::start(&path, &[]);
    let response = raw(&server.url, session_request("main"));
    assert!(response.starts_with("HTTP/1.1 403 "), "{response}");
    assert!(
        response.contains("client group 'push' opens no push session"),
        "{response}"
    );
}

/// With a `token-sha256` item and an anonymous item, and with no
/// `--allow-cleartext-credentials`, a bearer token over plain HTTP gets 403.
/// With `--allow-cleartext-credentials`, the token passes the
/// authentication, and a token that matches no item gets 401. With no client
/// group, the server starts. With a client CA, the server serves HTTPS.
#[test]
fn serve_takes_the_credentials_of_the_client_groups() {
    let tmp = TmpDir::new("credentials");
    let path = tmp.path().join("repo");
    let repo = format!("--repo={}", path.display());
    ok(ostrya(), &[&repo, "init", "--mode=archive"]);
    let server = Serving::start(&path, &[]);
    assert!(server.url.starts_with("http://"), "{}", server.url);
    drop(server);
    // The SHA-256 digest of `token`.
    let digest = "3c469e9d6c5875d37a43f353d4f88e61fcf812c66eee3457465a40b0da4153e0";
    let config = path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str(&format!(
        "[ex-ostrya client \"builders\"]\nauth=token-sha256:{digest}\nallow=w:**\n\
         [ex-ostrya client \"anyone\"]\nauth=anonymous\nallow=w:**\n"
    ));
    std::fs::write(&config, text).unwrap();
    let post = "POST /_ostrya/receive/v1/session HTTP/1.1\r\nhost: x\r\n\
                authorization: Bearer token\r\ncontent-length: 0\r\n\
                connection: close\r\n\r\n";
    let server = Serving::start(&path, &[]);
    let response = raw(&server.url, post);
    assert!(response.starts_with("HTTP/1.1 403 "), "{response}");
    assert!(response.contains("the server takes no credential over plain HTTP"));
    drop(server);
    let server = Serving::start(&path, &["--allow-cleartext-credentials"]);
    let response = raw(&server.url, post);
    // A 422 shows that the request passed the authentication. The empty
    // body holds no `Hello`, so the endpoint refuses it with `protocol`.
    assert!(response.starts_with("HTTP/1.1 422 "), "{response}");
    let unknown = post.replace("Bearer token", "Bearer other");
    let response = raw(&server.url, &unknown);
    assert!(response.starts_with("HTTP/1.1 401 "), "{response}");
    drop(server);
    let server = Serving::start(
        &path,
        &[
            &format!("--tls-cert={}", fixture("server.pem").display()),
            &format!("--tls-key={}", fixture("server.key.pem").display()),
            &format!("--tls-client-ca={}", fixture("ca.pem").display()),
        ],
    );
    assert!(server.url.starts_with("https://"), "{}", server.url);
}
