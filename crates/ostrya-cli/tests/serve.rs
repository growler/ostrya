//! `ostrya serve --read-only` against the `ostree` tool: a pull from a
//! repository of each mode the port reads, over HTTP and HTTPS, a pull of a
//! ref alias with no summary, and a pull from a repository whose summary
//! names deltas the server does not serve. The refusals of the command run
//! without the tool.

#![cfg(feature = "serve")]

use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
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

/// Whether the `ostree` tool is installed. With [`REQUIRE_OSTREE`] set its
/// absence fails the test; without it the test skips and says so.
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

/// Run `program` with `args` and return its standard output, failing the
/// test when it fails.
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

/// A running `ostrya serve`, killed when it drops.
struct Serving {
    child: Child,
    url: String,
}

impl Serving {
    /// Start the server over `repo` with `extra` options, on a port the
    /// kernel chooses, and read the URL it writes.
    fn start(repo: &Path, extra: &[&str]) -> Serving {
        let mut child = Command::new(ostrya())
            .arg(format!("--repo={}", repo.display()))
            .args(["serve", "--read-only", "--listen=127.0.0.1:0"])
            .args(extra)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(line.ends_with("/\n"), "serve wrote {line:?}");
        Serving {
            child,
            url: line.trim_end().to_owned(),
        }
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

/// A CA and a server certificate for `127.0.0.1` that it signed, for the
/// HTTPS pulls of the tool. The TLS fixtures name one subject for the CA and
/// the server certificate, which an OpenSSL client reads as a self-signed
/// leaf, so the tool needs a pair of its own.
struct Pki {
    ca: PathBuf,
    cert: PathBuf,
    key: PathBuf,
}

/// Generate a [`Pki`] under `dir` with `openssl`. Each certificate takes a
/// config file of its own, and `OPENSSL_CONF` names no file, so no
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
    Pki {
        ca: dir.join("ca.pem"),
        cert: dir.join("server.pem"),
        key: dir.join("server.key"),
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
/// a `bare-split-xattrs` one: the inodes stay, the config names the mode,
/// and each file object gets a `.file-xattrs-link` to the shared empty
/// `.file-xattrs` object.
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

/// A client repository of `mode` with the remote `origin` at `url`, which
/// trusts the CA of `pki` for HTTPS.
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

/// The tool pulls from a repository of each mode the port reads, over HTTP
/// and over HTTPS, and the pulled repository passes `ostree fsck`.
///
/// The summary of a `bare-user-shared` repository states that mode in
/// `ostree.summary.mode`, which the tool cannot parse, so the pull from that
/// repository runs with no summary, and a pull with the summary is checked to
/// fail with the error of the tool.
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

/// With no summary the tool requests `refs/heads/<ref>`, and the view serves
/// a ref alias as the ref it names. The commit carries no ref binding, which
/// the tool would hold to the name `main`.
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

/// The summary of a repository in a mode other than `archive` names a delta
/// that the view does not serve. A `bare-user` client of the tool fetches
/// the objects loose, and with `--require-static-deltas` it fails. The
/// client is `bare-user` because an `archive` client of the tool uses no
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

/// The command refuses to run without `--read-only`, with or without a
/// client CA, and refuses a TLS file it cannot use. Each refusal exits 1 and
/// writes no URL.
#[test]
fn serve_refuses_what_it_cannot_serve() {
    let tmp = TmpDir::new("refusals");
    let path = tmp.path().join("repo");
    let repo = format!("--repo={}", path.display());
    ok(ostrya(), &[&repo, "init", "--mode=bare-user"]);
    let cert = format!("--tls-cert={}", fixture("server.pem").display());
    let key = format!("--tls-key={}", fixture("server.key.pem").display());
    let ca = format!("--client-ca={}", fixture("ca.pem").display());
    let enc_cert = format!("--tls-cert={}", fixture("client.pem").display());
    let enc_key = format!("--tls-key={}", fixture("client.key.enc.pem").display());
    let absent = format!("--tls-key={}", tmp.path().join("absent").display());
    let listen = "--listen=127.0.0.1:0";
    let cases: [(&[&str], &str); 7] = [
        (&[&repo, "serve", listen], "--read-only"),
        (
            &[&repo, "serve", "--read-only", listen, "--body-timeout=0"],
            "--body-timeout",
        ),
        (&[&repo, "serve", listen, &cert, &key, &ca], "--read-only"),
        (&[&repo, "serve", "--read-only", listen, &ca], "--tls-cert"),
        (&[&repo, "serve", "--read-only", listen, &cert], "--tls-key"),
        (
            &[&repo, "serve", "--read-only", listen, &enc_cert, &enc_key],
            "passphrase",
        ),
        (
            &[&repo, "serve", "--read-only", listen, &cert, &absent],
            "absent",
        ),
    ];
    for (args, message) in cases {
        let out = run(ostrya(), args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(out.stdout.is_empty(), "{args:?}");
        assert!(stderr.contains(message), "{args:?}: {stderr}");
    }
}
