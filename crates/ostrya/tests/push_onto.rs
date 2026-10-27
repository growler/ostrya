//! Tests of `Repo::push_onto_over_stream` against `Repo::receive` over two
//! in-process pipes. The push sends the tree of a local commit, and the
//! server makes a server commit with the fields of that commit.
//!
//! The tests compare the commit of the server with a commit that the test
//! builds from the fields of the local commit, the tip of the server branch
//! as its parent, and the bindings of the namespace. They also cover the
//! options of the push and its refusals.

#![cfg(all(feature = "push", feature = "receive"))]

mod common;

use std::collections::HashSet;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use common::receive::{PIPE_CAP, collections_policy, new_repo, pipe, policy_allowing};
use common::{Counting, TmpDir, mark_partial};
use futures_lite::future::zip;
use ostrya::remote::{self, PushOutcome};
use ostrya::{
    Checksum, Commit, CommitModifier, CommitModifierFlags, CommitOptions, Ed25519Signer, Error,
    MutableTree, ObjectType, PushOntoOptions, ReceivePolicy, ReceiveReport, Repo, RepoMode, Type,
    Value,
};
use ostrya_rt::block_on;

/// The base64 of a 64-byte ed25519 secret key (seed, then public key).
const SECRET_B64: &str =
    "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";

/// The timestamp of each local commit.
const TIMESTAMP: u64 = 1_700_000_000;

/// A client repository and a server repository, each in a directory of its
/// own.
struct Pair {
    _client_dir: TmpDir,
    _server_dir: TmpDir,
    client: Repo,
    server: Repo,
}

impl Pair {
    /// A client repository whose config has the core keys `client_core`, and
    /// an archive server repository with the core keys `server_core`.
    fn new(tag: &str, client_core: &str, server_core: &str) -> Pair {
        let client_dir = TmpDir::new(&format!("push-onto-{tag}-client"));
        let server_dir = TmpDir::new(&format!("push-onto-{tag}-server"));
        let client = new_repo(&client_dir, RepoMode::BareUser, client_core);
        let server = new_repo(&server_dir, RepoMode::Archive, server_core);
        Pair {
            _client_dir: client_dir,
            _server_dir: server_dir,
            client,
            server,
        }
    }
}

fn string(s: &str) -> Value {
    Value::variant(Type::Str, Value::Str(s.into()))
}

fn entry(key: &str, value: Value) -> Value {
    Value::Tuple(vec![Value::Str(key.into()), value])
}

/// The value of an `ostree.sizes` entry with one record.
fn sizes() -> Value {
    Value::variant(
        Type::parse("a(ayay)").unwrap(),
        Value::Array(vec![Value::Tuple(vec![
            Value::Bytes(vec![0xab; 32]),
            Value::Bytes(vec![5, 7]),
        ])]),
    )
}

/// The value of an `ostree.composefs.digest.v0` entry.
fn digest() -> Value {
    Value::variant(Type::parse("ay").unwrap(), Value::Bytes(vec![0xcd; 32]))
}

/// The metadata of a local commit: two entries with one key twice, the
/// bindings of the local repository, a composefs digest, and sizes, in the
/// order of a commit of the `ostree` command.
fn local_metadata() -> Value {
    Value::Array(vec![
        entry("version", string("1")),
        entry("xa.note", string("note")),
        entry("version", string("2")),
        entry(
            "ostree.ref-binding",
            ostrya_core::ref_binding(&["main", "local/only"]),
        ),
        entry("ostree.collection-binding", string("org.example.Local")),
        entry("ostree.composefs.digest.v0", digest()),
        entry("ostree.sizes", sizes()),
    ])
}

/// Commits a tree onto `branch` of `repo` with `metadata`, and signs the
/// commit. The tree holds a file `file` with `content`, a symlink `link` to
/// it, and a directory `sub` whose file is the same in each commit.
fn commit(repo: &Repo, branch: &str, content: &str, metadata: Value) -> Checksum {
    commit_with(
        repo,
        branch,
        content,
        metadata,
        CommitModifierFlags::empty(),
    )
}

/// [`commit`] with the modifier flags `flags` added to the flags of
/// [`commit`].
fn commit_with(
    repo: &Repo,
    branch: &str,
    content: &str,
    metadata: Value,
    flags: CommitModifierFlags,
) -> Checksum {
    let tree = repo
        .path()
        .parent()
        .unwrap()
        .join(format!("tree-{branch}-{content}"));
    std::fs::create_dir_all(tree.join("sub")).unwrap();
    std::fs::write(tree.join("file"), content).unwrap();
    std::fs::write(tree.join("sub/nested"), "the same in each commit\n").unwrap();
    let _ = std::fs::remove_file(tree.join("link"));
    std::os::unix::fs::symlink("file", tree.join("link")).unwrap();
    let signer =
        Ed25519Signer::from_secret_key(&ostrya::base64::decode(SECRET_B64).unwrap()).unwrap();
    block_on(async {
        let txn = repo.transaction().await.unwrap();
        let dfd = std::fs::File::open(&tree).unwrap();
        let mut modifier = CommitModifier::new(
            CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::SKIP_XATTRS | flags,
        );
        let mut mtree = MutableTree::new();
        txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("."), &mut mtree, Some(&mut modifier))
            .await
            .unwrap();
        let root = txn.write_mtree(&mut mtree).await.unwrap();
        let checksum = txn
            .write_commit(
                CommitOptions {
                    parent: None,
                    subject: Some(format!("subject {content}")),
                    body: Some("body".into()),
                    timestamp: Some(TIMESTAMP),
                    metadata: Some(metadata),
                    related: Vec::new(),
                },
                &root,
            )
            .await
            .unwrap();
        txn.sign_commit(&checksum, &signer).await.unwrap();
        txn.set_ref(branch, Some(&checksum));
        txn.commit().await.unwrap();
        checksum
    })
}

fn load(repo: &Repo, checksum: &Checksum) -> Commit {
    block_on(repo.load_commit(checksum)).unwrap().0
}

fn tip(repo: &Repo, name: &str) -> Option<Checksum> {
    block_on(repo.resolve_rev(name, true)).unwrap()
}

fn has_object(repo: &Repo, ty: ObjectType, checksum: &Checksum) -> bool {
    block_on(repo.has_object(ty, checksum)).unwrap()
}

/// The checksum of the commit that the server makes from `local`, with
/// `parent`, the timestamp `timestamp`, the ref binding `bound`, and the
/// collection binding `collection`.
///
/// The metadata holds the entries of `local` without the bindings, the
/// composefs digest, and the sizes. Then come the ref binding, the
/// collection binding, the digest, and the sizes.
fn expected(
    local: &Commit,
    parent: Option<Checksum>,
    timestamp: u64,
    bound: &[&str],
    collection: Option<&str>,
) -> Checksum {
    let entries = local.metadata.as_array().unwrap();
    let key = |e: &Value| e.as_tuple().unwrap()[0].as_str().unwrap().to_owned();
    let tail = ["ostree.composefs.digest.v0", "ostree.sizes"];
    let mut metadata: Vec<Value> = entries
        .iter()
        .filter(|e| !key(e).starts_with("ostree."))
        .cloned()
        .collect();
    metadata.push(entry("ostree.ref-binding", ostrya_core::ref_binding(bound)));
    if let Some(id) = collection {
        metadata.push(entry("ostree.collection-binding", string(id)));
    }
    for name in tail {
        metadata.extend(entries.iter().filter(|e| key(e) == name).cloned());
    }
    Commit {
        metadata: Value::Array(metadata),
        parent,
        related: Vec::new(),
        subject: local.subject.clone(),
        body: local.body.clone(),
        timestamp,
        root_dirtree: local.root_dirtree,
        root_dirmeta: local.root_dirmeta,
    }
    .checksum()
    .unwrap()
}

type Pushed = (ostrya::Result<ReceiveReport>, ostrya::Result<PushOutcome>);

/// One server commit from the client into the server under `policy`.
fn push_under(pair: &Pair, policy: &ReceivePolicy, opts: PushOntoOptions) -> Pushed {
    let (client_out, server_in) = pipe(PIPE_CAP);
    let (server_out, client_in) = pipe(PIPE_CAP);
    block_on(zip(
        pair.server.receive(server_in, server_out, policy),
        pair.client
            .push_onto_over_stream(client_in, client_out, opts),
    ))
}

/// The policy of these tests: a server commit and a tag on each ref.
fn policy() -> ReceivePolicy {
    policy_allowing(&["c:**", "t:**"])
}

/// One server commit that must succeed under [`policy`]. Checks the outcome
/// against the report of the server, and returns the commit and the outcome.
fn pushed(pair: &Pair, opts: PushOntoOptions) -> (Checksum, PushOutcome) {
    let (report, outcome) = push_under(pair, &policy(), opts);
    let report = report.unwrap();
    let outcome = outcome.unwrap();
    assert_eq!(outcome.refs, report.refs);
    let commit = outcome.commit.expect("the server names its commit");
    for r in &outcome.refs {
        assert_eq!(r.new, Some(commit), "{r:?}");
    }
    (commit, outcome)
}

fn onto(rev: &str, branch: &str) -> PushOntoOptions {
    PushOntoOptions {
        rev: rev.into(),
        onto: branch.into(),
        ..PushOntoOptions::default()
    }
}

/// The first server commit has no parent, and a second one has the tip of
/// the branch as its parent. Each commit holds the fields and the metadata of
/// its local commit, with the bindings of the server, and the timestamp of
/// the local commit. The server holds no local commit object and no
/// detached metadata, and the second push sends only the objects that the
/// first did not send.
#[test]
fn a_server_commit_takes_the_fields_of_the_local_commit() {
    let pair = Pair::new("fields", "", "");
    let c1 = commit(&pair.client, "main", "one", local_metadata());
    let local1 = load(&pair.client, &c1);
    let (s1, outcome) = pushed(&pair, onto("main", "srv/main"));
    assert_eq!(s1, expected(&local1, None, TIMESTAMP, &["srv/main"], None));
    assert_eq!(outcome.refs[0].old, None);
    assert_eq!(tip(&pair.server, "srv/main"), Some(s1));
    assert_eq!(load(&pair.server, &s1).timestamp, TIMESTAMP);
    let first_sent = outcome.stats.objects_sent;
    assert_eq!(first_sent, outcome.stats.objects_total);

    let c2 = commit(&pair.client, "main", "two", local_metadata());
    let local2 = load(&pair.client, &c2);
    let (s2, outcome) = pushed(&pair, onto(&c2.to_hex(), "srv/main"));
    assert_eq!(
        s2,
        expected(&local2, Some(s1), TIMESTAMP, &["srv/main"], None)
    );
    assert_eq!(outcome.refs[0].old, Some(s1));
    assert_eq!(tip(&pair.server, "srv/main"), Some(s2));
    // The new file and the dirtree of the root are new. The symlink, the
    // directory `sub`, and the dirmeta are on the server.
    assert_eq!(outcome.stats.objects_needed, 2, "{:?}", outcome.stats);
    assert_eq!(outcome.stats.objects_sent, 2, "{:?}", outcome.stats);

    for (local, server) in [(c1, s1), (c2, s2)] {
        assert!(!has_object(&pair.server, ObjectType::Commit, &local));
        assert!(!has_object(&pair.server, ObjectType::CommitMeta, &local));
        assert!(!has_object(&pair.server, ObjectType::CommitMeta, &server));
    }
    let fsck = block_on(pair.server.fsck(&ostrya::FsckOptions::default())).unwrap();
    assert!(fsck.is_ok(), "{fsck:?}");
}

/// Tags and bound names join the ref binding, the timestamp option replaces
/// the timestamp of the local commit, `orphan` makes a root commit, and the
/// collection option selects the namespace and the collection binding.
#[test]
fn the_options_of_a_server_commit_reach_the_commit() {
    let pair = Pair::new("options", "", "collection-id=org.example.Server\n");
    let c1 = commit(&pair.client, "main", "one", local_metadata());
    let local = load(&pair.client, &c1);

    let (s1, outcome) = pushed(
        &pair,
        PushOntoOptions {
            tags: vec!["v2".into(), "v1".into()],
            bind_refs: vec!["bound".into(), "bound".into()],
            timestamp: Some(42),
            ..onto("main", "main")
        },
    );
    let bound = ["main", "v2", "v1", "bound", "bound"];
    assert_eq!(
        s1,
        expected(&local, None, 42, &bound, Some("org.example.Server"))
    );
    let names: Vec<&str> = outcome.refs.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["main", "v2", "v1"]);
    for name in ["main", "v1", "v2"] {
        assert_eq!(tip(&pair.server, name), Some(s1), "{name}");
    }
    assert_eq!(tip(&pair.server, "bound"), None);

    // `orphan` on a present branch needs `d`.
    let (report, client) = push_under(
        &pair,
        &policy(),
        PushOntoOptions {
            orphan: true,
            ..onto("main", "main")
        },
    );
    assert!(
        matches!(client, Err(Error::Remote(remote::Error::NonFastForward(_)))),
        "{client:?}"
    );
    assert!(report.is_err());
    let (report, client) = push_under(
        &pair,
        &policy_allowing(&["cd:**"]),
        PushOntoOptions {
            orphan: true,
            ..onto("main", "main")
        },
    );
    report.unwrap();
    let orphan = client.unwrap().commit.unwrap();
    assert_eq!(
        orphan,
        expected(
            &local,
            None,
            TIMESTAMP,
            &["main"],
            Some("org.example.Server")
        )
    );
    assert_eq!(tip(&pair.server, "main"), Some(orphan));

    // A collection names the namespace, and the bindings of the local commit
    // do not apply.
    let (report, client) = push_under(
        &pair,
        &collections_policy(&["c:**"]),
        PushOntoOptions {
            collection: Some("org.example.Other".into()),
            ..onto("main", "main")
        },
    );
    report.unwrap();
    let mirrored = client.unwrap().commit.unwrap();
    assert_eq!(
        mirrored,
        expected(
            &local,
            None,
            TIMESTAMP,
            &["main"],
            Some("org.example.Other")
        )
    );
    let mirror = pair
        .server
        .path()
        .join("refs/mirrors/org.example.Other/main");
    assert_eq!(
        std::fs::read_to_string(mirror).ok(),
        Some(format!("{mirrored}\n"))
    );
    assert_eq!(tip(&pair.server, "main"), Some(orphan));
}

/// Returns the metadata entries of the serialized commit object `bytes`:
/// each key and the bytes of its `v`, in order.
///
/// The function reads the framing of the object and of the dict from the
/// bytes, and decodes no value. The commit `(a{sv}aya(say)sstayay)` ends with
/// the framing offsets of its members in reverse order, so its last offset
/// is the end of the dict. The dict ends with one offset for the end of each
/// entry. An entry `{sv}` is the key and its NUL, padding to 8 bytes, the
/// `v`, and one offset for the end of the key.
fn raw_metadata_entries(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    fn offset_size(len: usize) -> usize {
        match len {
            0..=0xff => 1,
            0x100..=0xffff => 2,
            _ => 4,
        }
    }
    fn read_offset(bytes: &[u8], at: usize, size: usize) -> usize {
        let mut le = [0u8; 8];
        le[..size].copy_from_slice(&bytes[at..at + size]);
        u64::from_le_bytes(le) as usize
    }
    let size = offset_size(bytes.len());
    let dict = &bytes[..read_offset(bytes, bytes.len() - size, size)];
    if dict.is_empty() {
        return Vec::new();
    }
    let size = offset_size(dict.len());
    let table = read_offset(dict, dict.len() - size, size);
    let mut start = 0;
    let mut out = Vec::new();
    for at in (table..dict.len()).step_by(size) {
        let end = read_offset(dict, at, size);
        let entry = &dict[start..end];
        let key_end = entry.iter().position(|&b| b == 0).unwrap();
        let value_start = (key_end + 1).next_multiple_of(8);
        let value_end = entry.len() - offset_size(entry.len());
        out.push((
            String::from_utf8(entry[..key_end].to_vec()).unwrap(),
            entry[value_start..value_end].to_vec(),
        ));
        start = end.next_multiple_of(8);
    }
    out
}

fn object_bytes(repo: &Repo, checksum: &Checksum) -> Vec<u8> {
    block_on(repo.load_object_bytes(ObjectType::Commit, checksum)).unwrap()
}

/// Each metadata entry of the server commit, other than the bindings, holds
/// the bytes of the same entry in the local commit object, in the order of a
/// commit of the `ostree` command. The local commit holds `ostree.sizes` from
/// size generation and an `ostree.composefs.digest.v0` entry.
#[test]
fn the_metadata_entries_of_a_server_commit_are_the_bytes_of_the_local_object() {
    let client_dir = TmpDir::new("push-onto-raw-client");
    let server_dir = TmpDir::new("push-onto-raw-server");
    let pair = Pair {
        client: new_repo(&client_dir, RepoMode::Archive, ""),
        server: new_repo(&server_dir, RepoMode::Archive, ""),
        _client_dir: client_dir,
        _server_dir: server_dir,
    };
    let nested = Value::variant(
        Type::parse("(uaymv)").unwrap(),
        Value::Tuple(vec![
            Value::U32(7),
            Value::Bytes(vec![1, 2, 3]),
            Value::Maybe(Some(Box::new(Value::variant(
                Type::Bool,
                Value::Bool(true),
            )))),
        ]),
    );
    let mut metadata = local_metadata();
    if let Value::Array(entries) = &mut metadata {
        // `ostree.sizes` comes from size generation.
        entries.retain(|e| e.as_tuple().unwrap()[0].as_str() != Some("ostree.sizes"));
        entries.insert(1, entry("xa.nested", nested));
    }
    let local = commit_with(
        &pair.client,
        "main",
        "one",
        metadata,
        CommitModifierFlags::GENERATE_SIZES,
    );
    let (server, _) = pushed(&pair, onto("main", "srv/main"));

    let local = raw_metadata_entries(&object_bytes(&pair.client, &local));
    let keys: Vec<&str> = local.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        keys,
        [
            "version",
            "xa.nested",
            "xa.note",
            "version",
            "ostree.ref-binding",
            "ostree.collection-binding",
            "ostree.composefs.digest.v0",
            "ostree.sizes",
        ]
    );
    let tail = ["ostree.composefs.digest.v0", "ostree.sizes"];
    let mut want: Vec<_> = local
        .iter()
        .filter(|(k, _)| !k.starts_with("ostree."))
        .collect();
    for name in tail {
        want.extend(local.iter().filter(|(k, _)| k == name));
    }
    let server = raw_metadata_entries(&object_bytes(&pair.server, &server));
    let got: Vec<_> = server
        .iter()
        .filter(|(k, _)| !k.ends_with("-binding"))
        .collect();
    assert_eq!(got, want);
}

/// The object files of the store of `repo`.
fn object_files(repo: &Repo) -> HashSet<PathBuf> {
    fn walk(dir: &Path, out: &mut HashSet<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                walk(&path, out);
            } else {
                out.insert(path);
            }
        }
    }
    let mut out = HashSet::new();
    walk(&repo.path().join("objects"), &mut out);
    out
}

/// The error of a push that the client refuses before it writes a byte, and
/// the number of bytes it wrote.
fn refused(repo: &Repo, opts: PushOntoOptions) -> (Error, u64) {
    let written = Arc::new(AtomicU64::new(0));
    let output = Counting {
        inner: futures_lite::io::sink(),
        written: Arc::clone(&written),
    };
    let result = block_on(repo.push_onto_over_stream(futures_lite::io::empty(), output, opts));
    let error = result.expect_err("the push is refused");
    (error, written.load(Ordering::Relaxed))
}

fn invalid_input(e: &Error) -> &str {
    match e {
        Error::Remote(remote::Error::InvalidInput(m)) => m,
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

/// The names, the collection, and the local commit are checked before the
/// push writes a byte.
#[test]
fn a_bad_name_or_a_bad_local_commit_is_refused_before_a_byte() {
    let pair = Pair::new("refused", "", "");
    let c1 = commit(&pair.client, "main", "one", local_metadata());
    let hex = "ab".repeat(32);
    for (opts, name) in [
        (onto("main", "a:b"), "a:b"),
        (onto("main", "main^"), "main^"),
        (onto("main", &hex), hex.as_str()),
        (
            PushOntoOptions {
                tags: vec!["t:x".into()],
                ..onto("main", "main")
            },
            "t:x",
        ),
        (
            PushOntoOptions {
                bind_refs: vec!["o:b".into()],
                ..onto("main", "main")
            },
            "o:b",
        ),
    ] {
        let (e, written) = refused(&pair.client, opts);
        assert!(
            matches!(&e, Error::InvalidRefspec(n) if n == name),
            "{name}: {e:?}"
        );
        assert_eq!(written, 0, "{name}");
    }
    for (opts, needle) in [
        (
            PushOntoOptions {
                tags: vec!["main".into()],
                ..onto("main", "main")
            },
            "also the branch",
        ),
        (
            PushOntoOptions {
                tags: vec!["t".into(), "t".into()],
                ..onto("main", "main")
            },
            "named twice",
        ),
        (
            PushOntoOptions {
                collection: Some("no-dot".into()),
                ..onto("main", "main")
            },
            "invalid collection id",
        ),
    ] {
        let (e, written) = refused(&pair.client, opts);
        assert!(invalid_input(&e).contains(needle), "{e:?}");
        assert_eq!(written, 0, "{needle}");
    }
    let (e, written) = refused(&pair.client, onto("absent", "main"));
    assert!(matches!(e, Error::RefNotFound(_)), "{e:?}");
    assert_eq!(written, 0);

    mark_partial(&pair.client, &c1);
    let (e, written) = refused(&pair.client, onto("main", "main"));
    assert!(invalid_input(&e).contains("partial"), "{e:?}");
    assert_eq!(written, 0);

    // A commit with related objects.
    let local = load(&pair.client, &c1);
    let bytes = Commit {
        related: vec![("related".into(), vec![0x11; 32])],
        ..local
    }
    .serialize()
    .unwrap();
    let related = block_on(async {
        let txn = pair.client.transaction().await.unwrap();
        let checksum = txn
            .write_metadata(ObjectType::Commit, None, &bytes)
            .await
            .unwrap();
        txn.commit().await.unwrap();
        checksum
    });
    let (e, written) = refused(&pair.client, onto(&related.to_hex(), "main"));
    assert!(invalid_input(&e).contains("related objects"), "{e:?}");
    assert_eq!(written, 0);
}

/// A tag that the server holds and a client group with no `c` refuse the
/// push. The tag is refused after `HelloReply` and before any object.
#[test]
fn an_existing_tag_and_a_client_with_no_c_are_refused() {
    let pair = Pair::new("server-refused", "", "");
    commit(&pair.client, "main", "one", local_metadata());
    let (first, _) = pushed(
        &pair,
        PushOntoOptions {
            tags: vec!["v1".into()],
            ..onto("main", "main")
        },
    );
    commit(&pair.client, "main", "two", local_metadata());

    let before = object_files(&pair.server);
    let (report, client) = push_under(
        &pair,
        &policy(),
        PushOntoOptions {
            tags: vec!["v1".into()],
            ..onto("main", "main")
        },
    );
    match client {
        Err(Error::Remote(remote::Error::RefMismatch { name, current, .. })) => {
            assert_eq!(name, "v1");
            assert_eq!(current, Some(first));
        }
        other => panic!("{other:?}"),
    }
    assert!(
        matches!(report, Err(Error::Remote(remote::Error::Aborted))),
        "{report:?}"
    );
    assert_eq!(object_files(&pair.server), before);
    assert_eq!(tip(&pair.server, "main"), Some(first));

    let (report, client) = push_under(&pair, &policy_allowing(&["w:**"]), onto("main", "main"));
    assert!(
        matches!(client, Err(Error::Remote(remote::Error::RefDenied(_)))),
        "{client:?}"
    );
    assert!(report.is_err());
    assert_eq!(tip(&pair.server, "main"), Some(first));
}

/// A server commit whose `Commit` frame is over the `max-frame` of the
/// server fails after `HelloReply`, and the server stores no object.
#[test]
fn a_server_commit_over_the_frame_limit_is_refused_before_any_object() {
    let pair = Pair::new("frame", "", "");
    let big = Value::variant(
        Type::parse("ay").unwrap(),
        Value::Bytes(vec![7; remote::proto::MAX_FRAME as usize]),
    );
    commit(
        &pair.client,
        "main",
        "one",
        Value::Array(vec![entry("xa.big", big)]),
    );
    let before = object_files(&pair.server);
    let (report, client) = push_under(&pair, &policy(), onto("main", "main"));
    assert!(
        matches!(client, Err(Error::Remote(remote::Error::LimitExceeded(_)))),
        "{client:?}"
    );
    assert!(
        matches!(report, Err(Error::Remote(remote::Error::Aborted))),
        "{report:?}"
    );
    assert_eq!(object_files(&pair.server), before);
    assert_eq!(tip(&pair.server, "main"), None);
}

/// The options are `Send` and `Sync`, so they can move across tasks and
/// threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PushOntoOptions>();
};

/// The futures of a server commit can run on a multi-threaded executor.
#[allow(dead_code)]
fn push_onto_futures_are_send(
    repo: &Repo,
    endpoint: remote::Endpoint,
    input: common::receive::PipeReader,
    output: common::receive::PipeWriter,
) {
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&repo.push_onto(endpoint, PushOntoOptions::default()));
    assert_send(&repo.push_onto_over_stream(input, output, PushOntoOptions::default()));
}
