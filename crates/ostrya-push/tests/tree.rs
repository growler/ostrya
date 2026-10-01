//! The tree walk and the hash pass over trees built on disk: the refusals of
//! structure, the unreadable entries, the entry filter, and the files of the
//! pass after an error. The send pass of the model as an object source, and
//! the bytes a session sends from it to a scripted server.

#![cfg(unix)]

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_io::AsyncWrite;
use futures_lite::io::{AsyncReadExt, Cursor};
use ostrya_core::filehdr::{frame, split_framed};
use ostrya_core::{Checksum, FileHeader, ObjectName, ObjectType};
use ostrya_gvariant::{DictBuilder, Value};
use ostrya_push::proto::{
    FrameReader, FrameWriter, HelloReply, MIN_FRAME_LIMIT, Message, ObjectRead, ObjectsReply,
    RefState,
};
use ostrya_push::tree::{EntryAction, EntryFilter, EntryKind, EntryMeta, ScanOptions, TreeModel};
use ostrya_push::{
    Compression, Encoding, Error, ObjectData, ObjectSource, PushSession, SessionOptions,
};

/// A scratch directory under the temporary directory, removed when dropped.
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("ostrya-push-tree-{}-{tag}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Scratch { path }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        open_up(&self.path);
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Give each directory under `path` the mode 0755, so the tree can be removed.
fn open_up(path: &Path) {
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o755));
    if let Ok(listing) = fs::read_dir(path) {
        for entry in listing.flatten() {
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                open_up(&entry.path());
            }
        }
    }
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// Make a fifo at `path` with the `mkfifo` command. False when the command
/// does not make one.
fn mkfifo(path: &Path) -> bool {
    match std::process::Command::new("mkfifo").arg(path).status() {
        Ok(status) if status.success() => true,
        other => {
            eprintln!("skipping: mkfifo did not create a fifo: {other:?}");
            false
        }
    }
}

fn scan(root: &Path, options: ScanOptions) -> ostrya_push::Result<TreeModel> {
    ostrya_rt::block_on(TreeModel::scan(root, options))
}

fn with_filter(filter: EntryFilter) -> ScanOptions {
    ScanOptions {
        entry_filter: Some(filter),
        hash_jobs: None,
    }
}

/// The path and the kind of an `Error::Walk`.
fn walk_error(result: ostrya_push::Result<TreeModel>) -> (PathBuf, io::ErrorKind) {
    match result {
        Err(Error::Walk { path, source }) => (path, source.kind()),
        Err(other) => panic!("expected Error::Walk, got {other:?}"),
        Ok(_) => panic!("expected Error::Walk, got a model"),
    }
}

/// A filter that records each path it sees and keeps each entry.
fn recorder(seen: Arc<Mutex<Vec<String>>>) -> EntryFilter {
    Box::new(move |path, _meta| {
        seen.lock().unwrap().push(path.as_str().to_owned());
        EntryAction::Keep
    })
}

/// A filter that skips the entries named in `skip` and keeps the rest.
fn skipping(skip: &'static [&'static str]) -> EntryFilter {
    Box::new(move |path, _meta| {
        if skip.contains(&path.as_str()) {
            EntryAction::Skip
        } else {
            EntryAction::Keep
        }
    })
}

#[test]
fn a_fifo_is_refused_before_the_filter_sees_it() {
    let dir = Scratch::new("fifo");
    let root = &dir.path;
    fs::write(root.join("file"), b"x").unwrap();
    fs::create_dir(root.join("sub")).unwrap();
    if !mkfifo(&root.join("sub/fifo")) {
        return;
    }
    let seen = Arc::new(Mutex::new(Vec::new()));
    let result = scan(root, with_filter(recorder(seen.clone())));
    assert_eq!(
        walk_error(result),
        (root.join("sub/fifo"), io::ErrorKind::Unsupported)
    );
    let seen = seen.lock().unwrap();
    assert!(seen.iter().any(|p| p == "file"), "{seen:?}");
    assert!(!seen.iter().any(|p| p.starts_with("sub/")), "{seen:?}");
}

#[test]
fn a_socket_is_refused_before_the_filter_sees_it() {
    let dir = Scratch::new("sock");
    let root = &dir.path;
    fs::create_dir(root.join("sub")).unwrap();
    let socket = root.join("sub/s");
    let _listener = match std::os::unix::net::UnixListener::bind(&socket) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("skipping: bind refused {}: {e}", socket.display());
            return;
        }
    };
    let seen = Arc::new(Mutex::new(Vec::new()));
    let result = scan(root, with_filter(recorder(seen.clone())));
    assert_eq!(walk_error(result), (socket, io::ErrorKind::Unsupported));
    let seen = seen.lock().unwrap();
    assert!(!seen.iter().any(|p| p.starts_with("sub/")), "{seen:?}");
}

#[test]
fn a_name_that_is_not_utf8_is_refused() {
    let dir = Scratch::new("name");
    let root = &dir.path;
    let bad = root.join(OsStr::from_bytes(b"bad\xff"));
    fs::write(&bad, b"x").unwrap();
    let result = scan(root, ScanOptions::default());
    assert_eq!(walk_error(result), (bad, io::ErrorKind::InvalidData));
}

#[test]
fn a_symlink_target_that_is_not_utf8_is_refused() {
    let dir = Scratch::new("target");
    let root = &dir.path;
    let link = root.join("link");
    std::os::unix::fs::symlink(OsStr::from_bytes(b"t\xff"), &link).unwrap();
    let result = scan(root, ScanOptions::default());
    assert_eq!(walk_error(result), (link, io::ErrorKind::InvalidData));
}

#[test]
fn a_filter_that_changes_the_type_bits_is_refused() {
    let dir = Scratch::new("typebits");
    let root = &dir.path;
    fs::write(root.join("file"), b"x").unwrap();
    let filter: EntryFilter = Box::new(|path, meta| {
        if path.as_str() == "file" {
            meta.mode = 0o120644;
        }
        EntryAction::Keep
    });
    let result = scan(root, with_filter(filter));
    assert_eq!(
        walk_error(result),
        (root.join("file"), io::ErrorKind::InvalidData)
    );
}

#[test]
fn a_filter_that_changes_the_kind_is_refused() {
    let dir = Scratch::new("kind");
    let root = &dir.path;
    fs::write(root.join("file"), b"x").unwrap();
    let filter: EntryFilter = Box::new(|path, meta| {
        if path.as_str() == "file" {
            meta.kind = EntryKind::Dir;
        }
        EntryAction::Keep
    });
    let result = scan(root, with_filter(filter));
    assert_eq!(
        walk_error(result),
        (root.join("file"), io::ErrorKind::InvalidData)
    );
}

#[test]
fn a_filter_that_sets_a_bit_above_the_mode_is_refused() {
    let dir = Scratch::new("highbits");
    let root = &dir.path;
    fs::write(root.join("file"), b"x").unwrap();
    for target in ["file", ""] {
        let filter: EntryFilter = Box::new(move |path, meta| {
            if path.as_str() == target {
                meta.mode |= 0o200000;
            }
            EntryAction::Keep
        });
        let expected = if target.is_empty() {
            root.clone()
        } else {
            root.join(target)
        };
        assert_eq!(
            walk_error(scan(root, with_filter(filter))),
            (expected, io::ErrorKind::InvalidData),
            "{target:?}"
        );
    }
}

#[test]
fn a_filter_must_keep_the_target_with_the_symlink() {
    let dir = Scratch::new("presence");
    let root = &dir.path;
    fs::write(root.join("file"), b"x").unwrap();
    std::os::unix::fs::symlink("file", root.join("link")).unwrap();

    let removed: EntryFilter = Box::new(|path, meta| {
        if path.as_str() == "link" {
            meta.symlink_target = None;
        }
        EntryAction::Keep
    });
    assert_eq!(
        walk_error(scan(root, with_filter(removed))),
        (root.join("link"), io::ErrorKind::InvalidData)
    );

    let given: EntryFilter = Box::new(|path, meta| {
        if path.as_str() == "file" {
            meta.symlink_target = Some("elsewhere".into());
        }
        EntryAction::Keep
    });
    assert_eq!(
        walk_error(scan(root, with_filter(given))),
        (root.join("file"), io::ErrorKind::InvalidData)
    );

    let empty: EntryFilter = Box::new(|path, meta| {
        if path.as_str() == "link" {
            meta.symlink_target = Some(String::new());
        }
        EntryAction::Keep
    });
    scan(root, with_filter(empty)).unwrap();
}

/// The unreadable entries of the permission tests.
const UNREADABLE: [&str; 3] = ["file0000", "dir0000", "dir0311"];

/// Make the unreadable entry `name` under `root`, beside a readable file.
/// False when the process can open the entry, as root can.
fn unreadable_entry(root: &Path, name: &str) -> bool {
    fs::write(root.join("kept"), b"kept").unwrap();
    let path = root.join(name);
    let denied = match name {
        "file0000" => {
            fs::write(&path, b"secret").unwrap();
            set_mode(&path, 0o000);
            fs::File::open(&path).is_err()
        }
        _ => {
            fs::create_dir(&path).unwrap();
            fs::write(path.join("inner"), b"x").unwrap();
            set_mode(&path, if name == "dir0000" { 0o000 } else { 0o311 });
            fs::read_dir(&path).is_err()
        }
    };
    if !denied {
        eprintln!("skipping {name}: the process opens it");
    }
    denied
}

#[test]
fn unreadable_entries_fail_with_their_path() {
    for name in UNREADABLE {
        let dir = Scratch::new("unreadable");
        let root = &dir.path;
        if !unreadable_entry(root, name) {
            continue;
        }
        assert_eq!(
            walk_error(scan(root, ScanOptions::default())),
            (root.join(name), io::ErrorKind::PermissionDenied),
            "{name}"
        );
    }
}

#[test]
fn a_skip_of_an_unreadable_entry_prevents_the_error() {
    for name in UNREADABLE {
        let dir = Scratch::new("skip-unreadable");
        let root = &dir.path;
        unreadable_entry(root, name);
        let skip: EntryFilter = Box::new(move |path, _meta| {
            if path.as_str() == name {
                EntryAction::Skip
            } else {
                EntryAction::Keep
            }
        });
        let model = scan(root, with_filter(skip)).unwrap();
        // The root dirtree, the root dirmeta, and the content of `kept`.
        assert_eq!(model.object_names().len(), 3, "{name}");
    }
}

#[test]
fn a_directory_without_search_permission_names_its_entry() {
    let dir = Scratch::new("dir0644");
    let root = &dir.path;
    fs::create_dir(root.join("dir0644")).unwrap();
    fs::write(root.join("dir0644/child"), b"x").unwrap();
    set_mode(&root.join("dir0644"), 0o644);
    if fs::symlink_metadata(root.join("dir0644/child")).is_ok() {
        eprintln!("skipping: the process reads an entry without search permission");
        return;
    }
    assert_eq!(
        walk_error(scan(root, ScanOptions::default())),
        (root.join("dir0644/child"), io::ErrorKind::PermissionDenied)
    );
    // The metadata read of the entry comes before the filter, so a skip of
    // the entry does not prevent the error.
    assert_eq!(
        walk_error(scan(root, with_filter(skipping(&["dir0644/child"])))),
        (root.join("dir0644/child"), io::ErrorKind::PermissionDenied)
    );
    // A skip of the directory does.
    scan(root, with_filter(skipping(&["dir0644"]))).unwrap();
}

#[test]
fn an_unreadable_root_fails_with_the_root() {
    for mode in [0o000, 0o311] {
        let dir = Scratch::new("root-mode");
        let root = dir.path.join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("file"), b"x").unwrap();
        set_mode(&root, mode);
        if fs::read_dir(&root).is_ok() {
            eprintln!("skipping root mode {mode:o}: the process lists it");
            continue;
        }
        let seen = Arc::new(Mutex::new(Vec::new()));
        let result = scan(&root, with_filter(recorder(seen.clone())));
        assert_eq!(
            walk_error(result),
            (root.clone(), io::ErrorKind::PermissionDenied),
            "mode {mode:o}"
        );
        assert_eq!(*seen.lock().unwrap(), [""]);
    }
}

#[test]
fn a_skip_of_the_root_is_invalid_input() {
    let dir = Scratch::new("root-skip");
    let root = &dir.path;
    fs::write(root.join("file"), b"x").unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    let filter: EntryFilter = Box::new(move |path, meta| {
        record.lock().unwrap().push(path.as_str().to_owned());
        assert!(path.is_root());
        assert_eq!(meta.kind, EntryKind::Dir);
        EntryAction::Skip
    });
    assert_eq!(
        walk_error(scan(root, with_filter(filter))),
        (root.clone(), io::ErrorKind::InvalidInput)
    );
    assert_eq!(*seen.lock().unwrap(), [""]);
}

#[test]
fn a_root_that_is_not_a_directory_is_invalid_input() {
    let dir = Scratch::new("root-kind");
    let file = dir.path.join("file");
    fs::write(&file, b"x").unwrap();
    fs::create_dir(dir.path.join("real")).unwrap();
    let link = dir.path.join("link");
    std::os::unix::fs::symlink("real", &link).unwrap();
    for root in [file, link] {
        assert_eq!(
            walk_error(scan(&root, ScanOptions::default())),
            (root.clone(), io::ErrorKind::InvalidInput)
        );
    }
}

#[test]
fn zero_hash_jobs_is_invalid_input() {
    // The root does not exist, so a walk that started would fail with
    // `Error::Walk`.
    let dir = Scratch::new("jobs0");
    let options = ScanOptions {
        entry_filter: None,
        hash_jobs: Some(0),
    };
    match scan(&dir.path.join("absent"), options) {
        Err(Error::InvalidInput(_)) => {}
        Err(other) => panic!("expected Error::InvalidInput, got {other:?}"),
        Ok(_) => panic!("expected Error::InvalidInput, got a model"),
    }
}

#[test]
fn a_skip_of_a_directory_leaves_out_its_subtree() {
    let dir = Scratch::new("skip-dir");
    let root = &dir.path;
    fs::create_dir_all(root.join("gone/deeper")).unwrap();
    fs::write(root.join("gone/file"), b"x").unwrap();
    fs::write(root.join("gone/deeper/file"), b"y").unwrap();
    fs::write(root.join("kept"), b"z").unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    let filter: EntryFilter = Box::new(move |path, _meta| {
        record.lock().unwrap().push(path.as_str().to_owned());
        if path.as_str() == "gone" {
            EntryAction::Skip
        } else {
            EntryAction::Keep
        }
    });
    let model = scan(root, with_filter(filter)).unwrap();
    let mut seen = seen.lock().unwrap().clone();
    seen.sort();
    assert_eq!(seen, ["", "gone", "kept"]);
    // The root dirtree, the root dirmeta, and the content of `kept`.
    assert_eq!(model.object_names().len(), 3);
}

#[test]
fn a_symlink_has_the_mode_0o120777() {
    let dir = Scratch::new("symlink-mode");
    let root = &dir.path;
    fs::write(root.join("target"), b"x").unwrap();
    std::os::unix::fs::symlink("target", root.join("link")).unwrap();
    let seen: Arc<Mutex<Vec<EntryMeta>>> = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    let filter: EntryFilter = Box::new(move |path, meta| {
        if path.as_str() == "link" {
            record.lock().unwrap().push(meta.clone());
        }
        EntryAction::Keep
    });
    scan(root, with_filter(filter)).unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].kind, EntryKind::Symlink);
    assert_eq!(seen[0].mode, 0o120777);
    assert_eq!(seen[0].symlink_target.as_deref(), Some("target"));
}

#[test]
fn a_file_replaced_by_a_fifo_fails_without_blocking() {
    let dir = Scratch::new("fifo-swap");
    let root = dir.path.clone();
    fs::write(root.join("victim"), b"x").unwrap();
    // The probe fifo shows that the command works, before the filter runs it.
    if !mkfifo(&root.join("probe")) {
        return;
    }
    fs::remove_file(root.join("probe")).unwrap();
    let victim = root.join("victim");
    let swap = victim.clone();
    let filter: EntryFilter = Box::new(move |path, _meta| {
        if path.as_str() == "victim" {
            fs::remove_file(&swap).unwrap();
            assert!(mkfifo(&swap));
        }
        EntryAction::Keep
    });
    let result = ostrya_rt::block_on(futures_lite::future::or(
        TreeModel::scan(&root, with_filter(filter)),
        async {
            ostrya_rt::Timer::after(Duration::from_secs(30)).await;
            panic!("the open of a fifo blocked the hash pass");
        },
    ));
    assert_eq!(walk_error(result), (victim, io::ErrorKind::InvalidData));
}

/// Scan `root` with a filter that runs `swap` on the entry `victim` and keeps
/// it, and give the error of the scan.
fn scan_with_swap(
    root: &Path,
    victim: &'static str,
    swap: impl FnMut() + Send + 'static,
) -> (PathBuf, io::ErrorKind) {
    let mut swap = swap;
    let filter: EntryFilter = Box::new(move |path, _meta| {
        if path.as_str() == victim {
            swap();
        }
        EntryAction::Keep
    });
    walk_error(scan(root, with_filter(filter)))
}

#[test]
fn a_file_replaced_by_a_symlink_is_invalid_data() {
    let dir = Scratch::new("symlink-swap");
    let root = dir.path.clone();
    fs::write(root.join("target"), b"target").unwrap();
    fs::write(root.join("victim"), b"x").unwrap();
    let victim = root.join("victim");
    let swap = victim.clone();
    let error = scan_with_swap(&root, "victim", move || {
        fs::remove_file(&swap).unwrap();
        std::os::unix::fs::symlink("target", &swap).unwrap();
    });
    assert_eq!(error, (victim, io::ErrorKind::InvalidData));
}

#[test]
fn a_file_replaced_by_a_socket_is_invalid_data() {
    let dir = Scratch::new("socket-swap");
    let root = dir.path.clone();
    fs::write(root.join("victim"), b"x").unwrap();
    // The probe socket shows that `bind` takes a path of this length.
    let probe = root.join("probe");
    match std::os::unix::net::UnixListener::bind(&probe) {
        Ok(listener) => drop(listener),
        Err(e) => {
            eprintln!("skipping: bind refused {}: {e}", probe.display());
            return;
        }
    }
    fs::remove_file(&probe).unwrap();
    let victim = root.join("victim");
    let swap = victim.clone();
    let listener = Arc::new(Mutex::new(None));
    let keep = listener.clone();
    let error = scan_with_swap(&root, "victim", move || {
        fs::remove_file(&swap).unwrap();
        let bound = std::os::unix::net::UnixListener::bind(&swap).unwrap();
        *keep.lock().unwrap() = Some(bound);
    });
    assert!(listener.lock().unwrap().is_some());
    assert_eq!(error, (victim, io::ErrorKind::InvalidData));
}

#[test]
fn a_parent_directory_replaced_by_a_symlink_is_invalid_data() {
    let dir = Scratch::new("parent-swap");
    let root = dir.path.join("root");
    fs::create_dir_all(root.join("sub")).unwrap();
    fs::write(root.join("sub/file"), b"walked").unwrap();
    // Another directory, outside the root, with a regular file of the same
    // name.
    fs::create_dir(dir.path.join("other")).unwrap();
    fs::write(dir.path.join("other/file"), b"other").unwrap();
    let sub = root.join("sub");
    let moved = dir.path.join("moved");
    let other = dir.path.join("other");
    let error = scan_with_swap(&root, "sub/file", move || {
        fs::rename(&sub, &moved).unwrap();
        std::os::unix::fs::symlink(&other, &sub).unwrap();
    });
    assert_eq!(error, (root.join("sub/file"), io::ErrorKind::InvalidData));
}

/// After a hash error with more than one job, no file of the pass is open.
#[cfg(target_os = "linux")]
#[test]
fn no_file_of_the_pass_is_open_after_a_hash_error() {
    let dir = Scratch::new("open-after");
    let root = dir.path.clone();
    let chunk = vec![0x5au8; 4 * 1024 * 1024];
    for i in 0..8 {
        fs::write(root.join(format!("f{i}")), &chunk).unwrap();
    }
    fs::create_dir(root.join("sub")).unwrap();
    fs::write(root.join("sub/gone"), b"x").unwrap();
    let gone = root.join("sub/gone");
    let remove = gone.clone();
    let filter: EntryFilter = Box::new(move |path, _meta| {
        if path.as_str() == "sub/gone" {
            fs::remove_file(&remove).unwrap();
        }
        EntryAction::Keep
    });
    let options = ScanOptions {
        entry_filter: Some(filter),
        hash_jobs: Some(4),
    };
    assert_eq!(
        walk_error(scan(&root, options)),
        (gone, io::ErrorKind::NotFound)
    );
    let open: Vec<PathBuf> = fs::read_dir("/proc/self/fd")
        .unwrap()
        .flatten()
        .filter_map(|fd| fs::read_link(fd.path()).ok())
        .filter(|target| target.starts_with(&root))
        .collect();
    assert!(open.is_empty(), "files of the pass still open: {open:?}");
}

// ---------------------------------------------------------------------------
// The send pass.
// ---------------------------------------------------------------------------

/// A commit checksum and bytes for the object-source calls. The model does
/// not check them.
fn stand_in_commit() -> (Checksum, Vec<u8>) {
    (Checksum::from_bytes([0xc0; 32]), b"commit bytes".to_vec())
}

fn detached() -> Value {
    let mut dict = DictBuilder::new();
    dict.insert_str("xa.from", "tree");
    dict.build()
}

fn run<T>(future: impl std::future::Future<Output = T>) -> T {
    ostrya_rt::block_on(future)
}

fn open(model: &TreeModel, name: &ObjectName) -> ostrya_push::Result<ObjectData> {
    run(model.open(name, Encoding::Raw))
}

async fn read_all(mut reader: Box<dyn ostrya_push::ObjectReader>) -> Vec<u8> {
    let mut out = Vec::new();
    reader.read_to_end(&mut out).await.unwrap();
    out
}

/// The header, the size, and the payload bytes of a content object.
fn content(data: ObjectData) -> (FileHeader, u64, Option<Vec<u8>>) {
    match data {
        ObjectData::Content {
            header,
            size,
            payload,
        } => (header, size, payload.map(|p| run(read_all(p)))),
        other => panic!("expected Content, got {other:?}"),
    }
}

/// The bytes of an object given in `raw`.
fn raw_bytes(data: ObjectData) -> Vec<u8> {
    match data {
        ObjectData::Encoded {
            encoding: Encoding::Raw,
            reader,
        } => run(read_all(reader)),
        other => panic!("expected Encoded in raw, got {other:?}"),
    }
}

fn assert_invalid_input<T: std::fmt::Debug>(result: ostrya_push::Result<T>) {
    match result {
        Err(Error::InvalidInput(_)) => {}
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

/// The name of the content object of `header` and `payload`, which `model`
/// must hold.
fn file_name(model: &TreeModel, header: &FileHeader, payload: &[u8]) -> ObjectName {
    let mut hasher = ostrya_core::ContentHasher::new(header).unwrap();
    hasher.update(payload);
    let name = ObjectName::new(hasher.finish(), ObjectType::File);
    assert!(model.object_names().contains(&name), "{name:?}");
    name
}

fn header(mode: u32, target: &str) -> FileHeader {
    FileHeader {
        uid: 0,
        gid: 0,
        mode,
        symlink_target: target.into(),
        xattrs: ostrya_core::Xattrs::empty(),
    }
}

/// A filter that gives each entry the owner 0:0.
fn root_owned() -> ScanOptions {
    with_filter(Box::new(|_path, meta| {
        meta.uid = 0;
        meta.gid = 0;
        EntryAction::Keep
    }))
}

/// A tree of a regular file at mode 0644, a symlink, and a subdirectory with
/// one file, scanned with the owner 0:0.
fn small_tree(root: &Path) -> TreeModel {
    fs::write(root.join("file"), b"file content\n").unwrap();
    set_mode(&root.join("file"), 0o644);
    std::os::unix::fs::symlink("file", root.join("link")).unwrap();
    fs::create_dir(root.join("sub")).unwrap();
    fs::write(root.join("sub/inner"), b"inner\n").unwrap();
    scan(root, root_owned()).unwrap()
}

#[test]
fn objects_of_the_commit_are_the_tree_objects_and_the_commit() {
    let dir = Scratch::new("send-objects");
    let mut model = small_tree(&dir.path);
    let (commit, bytes) = stand_in_commit();

    // With no commit, each call about a commit is refused.
    assert_invalid_input(run(model.objects(&commit)));
    assert_invalid_input(run(model.detached_metadata(&commit)));
    assert_invalid_input(open(&model, &ObjectName::new(commit, ObjectType::Commit)));

    model.set_commit(commit, bytes.clone(), Some(detached()));
    let mut want = model.object_names();
    want.push(ObjectName::new(commit, ObjectType::Commit));
    assert_eq!(run(model.objects(&commit)).unwrap(), want);
    // Three content objects, and two directories of distinct dirtrees that
    // share one dirmeta.
    assert_eq!(want.len(), 3 + 2 + 1 + 1);

    let commit_object = open(&model, &ObjectName::new(commit, ObjectType::Commit)).unwrap();
    assert_eq!(raw_bytes(commit_object), bytes);
    assert_eq!(
        run(model.detached_metadata(&commit)).unwrap(),
        Some(detached())
    );

    // Another commit is refused by each call.
    let other = Checksum::from_bytes([0xc1; 32]);
    assert_invalid_input(run(model.objects(&other)));
    assert_invalid_input(run(model.detached_metadata(&other)));
    assert_invalid_input(open(&model, &ObjectName::new(other, ObjectType::Commit)));

    // A later call replaces the commit, and no detached dict gives none.
    model.set_commit(other, b"other".to_vec(), None);
    assert_invalid_input(run(model.objects(&commit)));
    assert_eq!(run(model.detached_metadata(&other)).unwrap(), None);
}

#[test]
fn an_object_the_model_does_not_hold_is_invalid_input() {
    let dir = Scratch::new("send-unknown");
    let mut model = small_tree(&dir.path);
    let (commit, bytes) = stand_in_commit();
    model.set_commit(commit, bytes, None);
    let unknown = Checksum::from_bytes([0xee; 32]);
    for ty in [ObjectType::File, ObjectType::DirTree, ObjectType::DirMeta] {
        assert_invalid_input(open(&model, &ObjectName::new(unknown, ty)));
    }
    // A dirtree checksum is not the name of a dirmeta or a content object.
    let dirtree = model.root_dirtree();
    assert_invalid_input(open(&model, &ObjectName::new(dirtree, ObjectType::DirMeta)));
    assert_invalid_input(open(&model, &ObjectName::new(dirtree, ObjectType::File)));
    // The model is the source of no detached metadata object.
    assert_invalid_input(open(
        &model,
        &ObjectName::new(commit, ObjectType::CommitMeta),
    ));
}

#[test]
fn metadata_objects_are_serialized_again_in_raw() {
    let dir = Scratch::new("send-metadata");
    let model = small_tree(&dir.path);
    for name in model.object_names() {
        if name.ty == ObjectType::File {
            continue;
        }
        let bytes = raw_bytes(open(&model, &name).unwrap());
        assert_eq!(Checksum::sha256(&bytes), name.checksum, "{name:?}");
    }
    let root = raw_bytes(
        open(
            &model,
            &ObjectName::new(model.root_dirtree(), ObjectType::DirTree),
        )
        .unwrap(),
    );
    assert_eq!(Checksum::sha256(&root), model.root_dirtree());
}

#[test]
fn a_regular_file_is_opened_again_with_the_size_of_the_hash_pass() {
    let dir = Scratch::new("send-file");
    let model = small_tree(&dir.path);
    let name = file_name(&model, &header(0o100644, ""), b"file content\n");
    let (got, size, payload) = content(open(&model, &name).unwrap());
    assert_eq!(got, header(0o100644, ""));
    assert_eq!(size, 13);
    assert_eq!(payload.as_deref(), Some(&b"file content\n"[..]));

    // The size is the count of the hash pass. A file that grew after it is
    // given with the old size and its first size + 1 bytes.
    fs::write(dir.path.join("file"), b"file content\nand more\n").unwrap();
    let (_, size, payload) = content(open(&model, &name).unwrap());
    assert_eq!(size, 13);
    assert_eq!(payload.as_deref(), Some(&b"file content\na"[..]));
}

/// The bytes of a file that grows by 1 MiB after the scan.
fn grown_file(root: &Path) -> (TreeModel, ObjectName, Vec<u8>) {
    fs::write(root.join("file"), b"file content\n").unwrap();
    set_mode(&root.join("file"), 0o644);
    let model = scan(root, root_owned()).unwrap();
    let name = file_name(&model, &header(0o100644, ""), b"file content\n");
    let mut grown = b"file content\n".to_vec();
    grown.extend((0..1024 * 1024).map(|i| (i % 251) as u8));
    fs::write(root.join("file"), &grown).unwrap();
    (model, name, grown)
}

#[test]
fn the_payload_of_a_file_that_grew_stops_one_byte_past_the_hash_pass() {
    let dir = Scratch::new("send-grown");
    let (model, name, grown) = grown_file(&dir.path);
    let (_, size, payload) = content(open(&model, &name).unwrap());
    assert_eq!(size, 13);
    assert_eq!(payload.as_deref(), Some(&grown[..14]));
}

#[test]
fn a_raw_push_of_a_file_that_grew_sends_one_byte_past_the_hash_pass() {
    let dir = Scratch::new("send-grown-raw");
    let (model, name, grown) = grown_file(&dir.path);
    let sent = send_scripted(&model, &[name], Compression::None);
    let mut want = frame(&header(0o100644, "").serialize().unwrap()).unwrap();
    want.extend_from_slice(&grown[..14]);
    assert_eq!(sent, vec![(name, Encoding::Raw, want)]);
}

#[test]
fn a_symlink_opens_nothing_and_has_the_mode_0o120777() {
    let dir = Scratch::new("send-symlink");
    let model = small_tree(&dir.path);
    let name = file_name(&model, &header(0o120777, "file"), b"");
    // The link is gone, and the open still gives its content object: the
    // model opens nothing for a symlink.
    fs::remove_file(dir.path.join("link")).unwrap();
    let (got, size, payload) = content(open(&model, &name).unwrap());
    assert_eq!(got.mode, 0o120777);
    assert_eq!(got, header(0o120777, "file"));
    assert_eq!(size, 0);
    assert_eq!(payload, None);
}

/// The kind and the path of the `Error::Walk` of a failed open.
fn open_walk_error(result: ostrya_push::Result<ObjectData>) -> (PathBuf, io::ErrorKind) {
    match result {
        Err(Error::Walk { path, source }) => (path, source.kind()),
        other => panic!("expected Error::Walk, got {other:?}"),
    }
}

#[test]
fn the_send_pass_refuses_a_file_that_is_not_the_one_the_walk_read() {
    let dir = Scratch::new("send-identity");
    let root = dir.path.clone();
    let model = small_tree(&root);
    let name = file_name(&model, &header(0o100644, ""), b"file content\n");
    let file = root.join("file");

    // Another file at the same path, with the same bytes. The new file is
    // made before the rename, so it has an inode of its own.
    fs::write(root.join("new"), b"file content\n").unwrap();
    fs::rename(root.join("new"), &file).unwrap();
    assert_eq!(
        open_walk_error(open(&model, &name)),
        (file.clone(), io::ErrorKind::InvalidData)
    );

    // A symlink at the path.
    fs::remove_file(&file).unwrap();
    std::os::unix::fs::symlink("sub/inner", &file).unwrap();
    assert_eq!(
        open_walk_error(open(&model, &name)),
        (file.clone(), io::ErrorKind::InvalidData)
    );

    // Nothing at the path.
    fs::remove_file(&file).unwrap();
    assert_eq!(
        open_walk_error(open(&model, &name)),
        (file, io::ErrorKind::NotFound)
    );
}

#[test]
fn the_send_pass_refuses_a_parent_directory_replaced_by_a_symlink() {
    let dir = Scratch::new("send-parent");
    let root = dir.path.join("root");
    fs::create_dir_all(root.join("sub")).unwrap();
    fs::write(root.join("sub/file"), b"walked").unwrap();
    fs::create_dir(dir.path.join("other")).unwrap();
    fs::write(dir.path.join("other/file"), b"walked").unwrap();
    set_mode(&root.join("sub/file"), 0o644);
    set_mode(&dir.path.join("other/file"), 0o644);
    let model = scan(&root, root_owned()).unwrap();
    let name = file_name(&model, &header(0o100644, ""), b"walked");
    fs::rename(root.join("sub"), dir.path.join("moved")).unwrap();
    std::os::unix::fs::symlink(dir.path.join("other"), root.join("sub")).unwrap();
    assert_eq!(
        open_walk_error(open(&model, &name)),
        (root.join("sub/file"), io::ErrorKind::InvalidData)
    );
}

// ---------------------------------------------------------------------------
// The bytes of the send pass, over a scripted server.
// ---------------------------------------------------------------------------

/// The bytes a session writes.
#[derive(Clone, Default)]
struct Capture {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl AsyncWrite for Capture {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.bytes.lock().unwrap().extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// The replies of a server that lists `raw` and `deflate`, needs each
/// object, and takes one object stream.
fn scripted_replies() -> Vec<u8> {
    let msgs = [
        Message::HelloReply(HelloReply {
            version: 1,
            mode: "archive".into(),
            collection_id: None,
            max_frame: MIN_FRAME_LIMIT,
            max_have: 16_384,
            encodings: vec![Encoding::Raw, Encoding::Deflate],
            parallel_uploads: 1,
            refs: vec![RefState {
                name: "main".into(),
                commit: None,
            }],
        }),
        Message::ObjectsReply(ObjectsReply {
            objects: 0,
            payload_bytes: 0,
        }),
    ];
    let mut w = FrameWriter::new(Vec::new());
    for msg in &msgs {
        run(w.write_message(msg)).unwrap();
    }
    w.into_inner()
}

/// The objects a session wrote, as (name, encoding, bytes).
fn written_objects(bytes: &[u8]) -> Vec<(ObjectName, Encoding, Vec<u8>)> {
    run(async {
        let mut r = FrameReader::new(bytes);
        let mut out = Vec::new();
        let mut buf = vec![0u8; 8192];
        while let Some(msg) = r.read_message().await.unwrap() {
            let Message::ObjectHeader(header) = msg else {
                continue;
            };
            let mut data = Vec::new();
            loop {
                match r.read_object_data(&mut buf).await.unwrap() {
                    ObjectRead::Data(n) => data.extend_from_slice(&buf[..n]),
                    ObjectRead::End => break,
                    ObjectRead::Abandoned => panic!("the session abandoned {:?}", header.name),
                }
            }
            out.push((header.name, header.encoding, data));
        }
        out
    })
}

/// Send `names` of `model` to the scripted server with `compression`, and
/// give the objects the session wrote.
fn send_scripted(
    model: &TreeModel,
    names: &[ObjectName],
    compression: Compression,
) -> Vec<(ObjectName, Encoding, Vec<u8>)> {
    let out = Capture::default();
    let replies = scripted_replies();
    run(async {
        let session = PushSession::over_stream(
            Cursor::new(replies),
            out.clone(),
            &["main".to_string()],
            SessionOptions::default(),
        )
        .await
        .unwrap();
        session.send(model, names, &[], compression).await.unwrap();
    });
    let bytes = out.bytes.lock().unwrap().clone();
    written_objects(&bytes)
}

/// `DEFLATE_CHUNK` of crates/ostrya-core/src/deflate.rs.
const DEFLATE_CHUNK: usize = 64 * 1024;

/// The SHA-256 of the raw-DEFLATE stream of [`golden_payload`] at levels 1
/// through 9, copied from `GOLDEN` of crates/ostrya-core/src/deflate.rs.
const GOLDEN: [&str; 9] = [
    "a1fd96479b110a51c3b9c333da0ff6879cd295fc27a98b48c88b70a0ea558bb4",
    "7964fd5c5e4ffb18bf953852b31704681eaf7a4590d488a01be5f213978c0876",
    "e5ff230c2f7715f8883cbd5c19ee1255f165c7e25fc886516c290b0d246954a0",
    "7ae743a6aa5027a1ef08604f6c0a4e6062d39f73879dd0789780aca2e8027932",
    "95b7d927a18b71b941598bf6411029653910307881528355a5b18cccfd3dea0a",
    "b9b31232e8e4458ff831e1de64ba695c0c07b630215e2ce01d372fa2fd8bbcc3",
    "8436585ce3c3eea757ab9d5020de4b41c3f32ac29fdd8b5c02ec8ec51df9067d",
    "c1bc0d4abcb002a3e15241b86c7f200ddc4c71ff30752a7ce933755433ceb88c",
    "b6ddd39fc7e629dfcc81b42ba9706eb6e4e46cd4f90527d3e1ccda0d072faca7",
];

/// One xorshift32 step.
fn xorshift(state: &mut u32) -> u32 {
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    *state
}

/// The golden payload of crates/ostrya-core/src/deflate.rs: one and a half
/// `DEFLATE_CHUNK` in three half-chunk blocks, one over a four-symbol
/// alphabet and two of an xorshift32 stream.
fn golden_payload() -> Vec<u8> {
    const BLOCK: usize = DEFLATE_CHUNK / 2;
    let mut out = Vec::with_capacity(3 * BLOCK);
    let mut state: u32 = 0x1234_5678;
    // Two bits per byte, sixteen bytes per step, over `A` to `D`.
    for _ in 0..BLOCK / 16 {
        let word = xorshift(&mut state);
        for k in 0..16 {
            out.push(b'A' + ((word >> (2 * k)) & 3) as u8);
        }
    }
    for _ in 0..2 * BLOCK {
        out.push((xorshift(&mut state) >> 24) as u8);
    }
    out
}

#[test]
fn deflated_bytes_of_a_tree_file_equal_the_golden_vectors() {
    let dir = Scratch::new("send-golden");
    let data = golden_payload();
    fs::write(dir.path.join("golden"), &data).unwrap();
    set_mode(&dir.path.join("golden"), 0o644);
    let model = scan(&dir.path, root_owned()).unwrap();
    let file = header(0o100644, "");
    let name = file_name(&model, &file, &data);
    let want_header = file.serialize_archive(data.len() as u64).unwrap();
    for (level, golden) in (1u8..).zip(GOLDEN) {
        let sent = send_scripted(&model, &[name], Compression::Deflate { level });
        let [(got, encoding, bytes)] = &sent[..] else {
            panic!("level {level}: {} objects", sent.len());
        };
        assert_eq!(
            (got, *encoding),
            (&name, Encoding::Deflate),
            "level {level}"
        );
        let (archive_header, deflated) = split_framed(bytes).unwrap();
        assert_eq!(archive_header, &want_header[..], "level {level}");
        assert_eq!(Checksum::sha256(deflated).to_hex(), golden, "level {level}");
    }
}

#[test]
fn raw_bytes_of_a_tree_file_are_the_framed_header_and_the_file() {
    let dir = Scratch::new("send-raw");
    let model = small_tree(&dir.path);
    let file = header(0o100644, "");
    let name = file_name(&model, &file, b"file content\n");
    let link = file_name(&model, &header(0o120777, "file"), b"");
    let sent = send_scripted(&model, &[name, link], Compression::None);
    let mut want_file = frame(&file.serialize().unwrap()).unwrap();
    want_file.extend_from_slice(b"file content\n");
    let want_link = frame(&header(0o120777, "file").serialize().unwrap()).unwrap();
    assert_eq!(
        sent,
        vec![
            (name, Encoding::Raw, want_file),
            (link, Encoding::Raw, want_link),
        ]
    );
}

#[test]
fn a_failed_open_of_the_send_pass_aborts_the_session_with_the_walk_error() {
    let dir = Scratch::new("send-abort");
    let model = small_tree(&dir.path);
    let name = file_name(&model, &header(0o100644, ""), b"file content\n");
    fs::remove_file(dir.path.join("file")).unwrap();
    let out = Capture::default();
    let replies = scripted_replies();
    let result = run(async {
        let session = PushSession::over_stream(
            Cursor::new(replies),
            out.clone(),
            &["main".to_string()],
            SessionOptions::default(),
        )
        .await
        .unwrap();
        session.send(&model, &[name], &[], Compression::None).await
    });
    let source = match result {
        Err(Error::Source(source)) => source,
        other => panic!("expected Error::Source, got {other:?}"),
    };
    match source.downcast_ref::<Error>() {
        Some(Error::Walk { path, source }) => {
            assert_eq!(path, &dir.path.join("file"));
            assert_eq!(source.kind(), io::ErrorKind::NotFound);
        }
        other => panic!("expected Error::Walk inside, got {other:?}"),
    }
    let bytes = out.bytes.lock().unwrap().clone();
    let last = run(async {
        let mut r = FrameReader::new(&bytes[..]);
        let mut last = None;
        while let Some(msg) = r.read_message().await.unwrap() {
            last = Some(msg);
        }
        last
    });
    assert!(matches!(last, Some(Message::Abort)), "{last:?}");
}
