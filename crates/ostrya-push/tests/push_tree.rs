//! Tests of the refusals of a tree push before a session.
//!
//! A walk error, a hash error, and an option that the push refuses before the
//! scan start no ssh client. These refusals send no request. For these
//! refusals, the push over a pair of streams writes no byte.

#![cfg(unix)]

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use futures_io::AsyncWrite;
use ostrya_push::{
    Compression, ConnectOptions, Error, PushRemote, TreePushOptions, push_tree,
    push_tree_over_stream,
};

/// A scratch directory under the temporary directory. A drop removes it.
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ostrya-push-tree-push-{}-{tag}-{n}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Scratch { path }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// A tree of one directory and two files under `base/tree`.
fn tree(base: &Path) -> PathBuf {
    let root = base.join("tree");
    fs::create_dir_all(root.join("dir")).unwrap();
    fs::write(root.join("file"), b"file\n").unwrap();
    fs::write(root.join("dir/inner"), b"inner\n").unwrap();
    root
}

/// The connect options of a stand-in ssh client that creates `marker` and
/// exits.
fn stand_in(marker: &Path) -> ConnectOptions {
    let script = format!("touch '{}'", marker.to_str().unwrap());
    ConnectOptions {
        ssh_command: Some(
            ["sh", "-c", &script, "stand-in"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        ),
        ..Default::default()
    }
}

fn options(refs: &[&str]) -> TreePushOptions {
    TreePushOptions {
        refs: refs.iter().map(|s| s.to_string()).collect(),
        timestamp: Some(1_700_000_000),
        ..Default::default()
    }
}

/// An output stream that counts the bytes that it receives.
struct Counted(Arc<AtomicU64>);

impl AsyncWrite for Counted {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.fetch_add(buf.len() as u64, Ordering::Relaxed);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Runs `push_tree` of `root` over the stand-in and returns its error.
///
/// The function checks that the stand-in did not start. It also runs
/// `push_tree_over_stream` with the same options. That push must write no byte
/// and must fail with the same `Error` variant. `opts` builds the options for
/// each push, because the options are not `Clone`.
fn refused_with_no_start(
    tag: &str,
    address: &str,
    root: &Path,
    opts: impl Fn() -> TreePushOptions,
) -> Error {
    let scratch = Scratch::new(tag);
    let marker = scratch.path.join("started");
    let remote = PushRemote::parse(address).unwrap();
    let result = ostrya_rt::block_on(push_tree(&remote, root, stand_in(&marker), opts()));
    assert!(!marker.exists(), "{tag}: the ssh client started");

    let written = Arc::new(AtomicU64::new(0));
    let over_stream = ostrya_rt::block_on(push_tree_over_stream(
        futures_lite::io::empty(),
        Counted(written.clone()),
        root,
        opts(),
    ));
    assert_eq!(written.load(Ordering::Relaxed), 0, "{tag}: bytes written");
    let e = match result {
        Err(e) => e,
        Ok(outcome) => panic!("{tag}: pushed: {outcome:?}"),
    };
    match over_stream {
        Err(other) => assert_eq!(
            std::mem::discriminant(&other),
            std::mem::discriminant(&e),
            "{tag}: {other:?} against {e:?}"
        ),
        Ok(outcome) => panic!("{tag}: pushed over the streams: {outcome:?}"),
    }
    e
}

/// Returns the path and the I/O error kind of an `Error::Walk`.
fn walk_error(tag: &str, e: Error) -> (PathBuf, io::ErrorKind) {
    match e {
        Error::Walk { path, source } => (path, source.kind()),
        other => panic!("{tag}: expected Error::Walk, got {other:?}"),
    }
}

fn invalid_input(tag: &str, e: Error, part: &str) {
    match e {
        Error::InvalidInput(m) => assert!(m.contains(part), "{tag}: {m}"),
        other => panic!("{tag}: expected Error::InvalidInput, got {other:?}"),
    }
}

const ADDRESS: &str = "host:repo";

/// A builder of the options of one push.
type MakeOptions = Box<dyn Fn() -> TreePushOptions>;

#[test]
fn a_tree_that_scans_starts_the_ssh_client() {
    let scratch = Scratch::new("control");
    let root = tree(&scratch.path);
    let marker = scratch.path.join("started");
    let remote = PushRemote::parse(ADDRESS).unwrap();
    let result = ostrya_rt::block_on(push_tree(
        &remote,
        &root,
        stand_in(&marker),
        options(&["main"]),
    ));
    assert!(marker.exists(), "the ssh client did not start");
    // The stand-in exits with no reply, so the session cannot open.
    assert!(
        matches!(result, Err(Error::Io(_) | Error::Transport(_))),
        "{result:?}"
    );
}

#[test]
fn a_walk_error_starts_no_ssh_client() {
    let scratch = Scratch::new("walk");
    let missing = scratch.path.join("missing");
    let e = refused_with_no_start("missing root", ADDRESS, &missing, || options(&["main"]));
    assert_eq!(
        walk_error("missing root", e),
        (missing.clone(), io::ErrorKind::NotFound)
    );

    let root = tree(&scratch.path);
    let fifo = root.join("dir/fifo");
    match std::process::Command::new("mkfifo").arg(&fifo).status() {
        Ok(status) if status.success() => {
            let e = refused_with_no_start("fifo", ADDRESS, &root, || options(&["main"]));
            assert_eq!(
                walk_error("fifo", e),
                (fifo.clone(), io::ErrorKind::Unsupported)
            );
        }
        other => eprintln!("skipping the fifo: mkfifo did not create one: {other:?}"),
    }
}

#[test]
fn a_hash_error_starts_no_ssh_client() {
    let scratch = Scratch::new("hash");
    let root = tree(&scratch.path);
    let file = root.join("dir/inner");
    set_mode(&file, 0o000);
    if fs::File::open(&file).is_ok() {
        eprintln!("skipping: the process opens a file at mode 0000");
        return;
    }
    let e = refused_with_no_start("hash", ADDRESS, &root, || options(&["main"]));
    assert_eq!(
        walk_error("hash", e),
        (file.clone(), io::ErrorKind::PermissionDenied)
    );
}

#[test]
fn options_refused_before_the_scan_start_no_ssh_client() {
    let scratch = Scratch::new("options");
    let root = tree(&scratch.path);
    let variant =
        || ostrya_core::Value::variant(ostrya_core::Type::Str, ostrya_core::Value::Str("v".into()));
    // One `ay` value at the size limit. The dict that holds this value is
    // larger than the limit.
    let oversized = || {
        let bytes = vec![0; ostrya_core::MAX_METADATA_SIZE as usize];
        let ty = ostrya_core::Type::parse("ay").unwrap();
        vec![(
            "big".to_owned(),
            ostrya_core::Value::variant(ty, ostrya_core::Value::Bytes(bytes)),
        )]
    };
    let cases: Vec<(&str, MakeOptions, &str)> = vec![
        (
            "hash_jobs 0",
            Box::new(|| TreePushOptions {
                hash_jobs: Some(0),
                ..options(&["main"])
            }),
            "hash_jobs",
        ),
        ("no refs", Box::new(|| options(&[])), "at least one"),
        ("a ref twice", Box::new(|| options(&["a", "a"])), "twice"),
        (
            "a bad ref",
            Box::new(|| options(&["a/../b"])),
            "not a valid ref name",
        ),
        (
            "a remote ref",
            Box::new(|| options(&["origin:main"])),
            "':'",
        ),
        (
            "a parent revision",
            Box::new(|| options(&["main", "main^"])),
            "'^'",
        ),
        (
            "a level out of range",
            Box::new(|| TreePushOptions {
                compression: Compression::Deflate { level: 10 },
                ..options(&["main"])
            }),
            "compression level",
        ),
        (
            "an empty metadata key",
            Box::new(move || TreePushOptions {
                metadata: vec![(String::new(), variant())],
                ..options(&["main"])
            }),
            "empty key",
        ),
        (
            "an empty detached key",
            Box::new(move || TreePushOptions {
                detached_metadata: vec![(String::new(), variant())],
                ..options(&["main"])
            }),
            "empty key",
        ),
        (
            "an oversized metadata dict",
            Box::new(move || TreePushOptions {
                metadata: oversized(),
                ..options(&["main"])
            }),
            "over the limit",
        ),
        (
            "an oversized detached dict",
            Box::new(move || TreePushOptions {
                detached_metadata: oversized(),
                ..options(&["main"])
            }),
            "over the limit",
        ),
    ];
    for (tag, opts, part) in cases {
        let e = refused_with_no_start(tag, ADDRESS, &root, opts);
        invalid_input(tag, e, part);
    }

    // Before it sends a request, the push refuses an ssh option with an HTTP
    // address. It also refuses a token to an `http://` address without the
    // cleartext switch.
    let marker = scratch.path.join("started");
    let remote = PushRemote::parse("http://host/repo").unwrap();
    let result = ostrya_rt::block_on(push_tree(
        &remote,
        &root,
        stand_in(&marker),
        options(&["main"]),
    ));
    assert!(!marker.exists(), "http: the ssh client started");
    invalid_input("http", result.unwrap_err(), "is an HTTP address");
    let token = scratch.path.join("token");
    fs::write(&token, b"token\n").unwrap();
    let connect = ConnectOptions {
        push_token_file: Some(token),
        ..Default::default()
    };
    let result = ostrya_rt::block_on(push_tree(&remote, &root, connect, options(&["main"])));
    invalid_input("cleartext", result.unwrap_err(), "cleartext");
}
