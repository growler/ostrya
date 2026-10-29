//! `Repo::receive` at `Commit`: the checks of each ref update, the update
//! lock, the ref writes, the transaction commit, and `CommitReply`.
//!
//! A test client drives the session over two in-process pipes with the frame
//! codec of `ostrya::remote::proto`. It sends the objects of the golden fixture
//! commit, which binds the ref `test/main`, or of commits that the tests build
//! over the fixture tree.

#![cfg(feature = "receive")]

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use common::receive::{
    ED25519_KEY, OTHER_SECRET_B64, Obj, SECOND_SERVER_SECRET_B64, SECRET_B64, SERVER_SECRET_B64,
    build_commit, collections_policy, connect, ed25519_signature, ed25519_signatures,
    fixture_objects, new_repo, policy_allowing, returned_code, secret, server_signer, session, sha,
    signed_dict, staging_entries, trust,
};
use common::{
    COMMIT, Field2Entry, GUARD_RELEASING_MARKER, ROOT_DIRMETA, ROOT_DIRTREE, TmpDir,
    file_inventory, foreign_holder, guard_holder, guard_holder_main, is_sealed, lock_holder_main,
    mark_partial, regular_objects, store_with_field2, tool_fsck,
};
use ostrya::remote::proto::ErrorMessage;
use ostrya::remote::{Encoding, ErrorCode, Expected, RefOutcome, RefUpdate};
use ostrya::sign::append_signature;
use ostrya::{
    Checksum, Commit, DictBuilder, Ed25519Verifier, Error, FsckOptions, ObjectName, ObjectType,
    ReceivePolicies, ReceivePolicy, ReceiveReport, ReceiveStep, ReceiveVerify, Repo, RepoMode,
    Summary, SummaryOptions, Type, Value,
};
use ostrya_rt::block_on;

#[test]
#[ignore = "helper process for the receive lock tests"]
fn lock_holder_subprocess() {
    lock_holder_main();
}

#[test]
#[ignore = "helper process for the update guard tests"]
fn guard_holder_subprocess() {
    guard_holder_main();
}

// ---------------------------------------------------------------------------
// Objects.
// ---------------------------------------------------------------------------

fn checksum(hex: &str) -> Checksum {
    Checksum::from_hex(hex).unwrap()
}

fn fixture_commit() -> Checksum {
    checksum(COMMIT)
}

/// The objects of the fixture tree, without the fixture commit.
fn tree_objects() -> Vec<Obj> {
    fixture_objects(Encoding::Raw)
        .into_iter()
        .filter(|o| o.ty != ObjectType::Commit)
        .collect()
}

fn no_metadata() -> Value {
    Value::Array(Vec::new())
}

fn dict_bytes(dict: &Value) -> Vec<u8> {
    ostrya_core::to_bytes(&Type::parse("a{sv}").unwrap(), dict).unwrap()
}

/// The blobs under `key` in the `a{sv}` dict `dict`.
fn signatures(dict: &Value, key: &str) -> Vec<Vec<u8>> {
    let (_, list) = dict.dict_get(key).unwrap().as_variant().unwrap();
    list.as_array()
        .unwrap()
        .iter()
        .map(|blob| blob.as_bytes().unwrap().to_vec())
        .collect()
}

/// A verifier that trusts the ed25519 key `secret_b64`.
fn ed25519_verifier(secret_b64: &str) -> Ed25519Verifier {
    Ed25519Verifier::new([secret(secret_b64)[32..].to_vec()], Vec::<Vec<u8>>::new()).unwrap()
}

// ---------------------------------------------------------------------------
// Sessions.
// ---------------------------------------------------------------------------

fn update(name: &str, expected: Expected, new: Option<Checksum>) -> RefUpdate {
    RefUpdate {
        name: name.into(),
        expected,
        new,
    }
}

/// The output of one push session: the result that the server returned, and
/// the reply that the client read.
type Pushed = (
    ostrya::Result<ReceiveReport>,
    Result<Vec<RefOutcome>, ErrorMessage>,
);

/// One push: `Hello` with the names of `updates`, one object stream with
/// `objects` and the detached metadata `meta`, and `Commit`.
fn push(
    repo: &Repo,
    policy: &ReceivePolicy,
    objects: &[Obj],
    meta: &[(Checksum, Vec<u8>)],
    updates: Vec<RefUpdate>,
    force: bool,
) -> Pushed {
    let names: Vec<String> = updates.iter().map(|u| u.name.clone()).collect();
    push_named(repo, policy, &names, objects, meta, updates, force)
}

/// Runs one [`push`] with refs in `Hello` that the caller gives apart from the
/// updates.
fn push_named(
    repo: &Repo,
    policy: &ReceivePolicy,
    names: &[String],
    objects: &[Obj],
    meta: &[(Checksum, Vec<u8>)],
    updates: Vec<RefUpdate>,
    force: bool,
) -> Pushed {
    session(repo, policy, |c| {
        script(c, names, None, objects, meta, updates, force)
    })
}

/// Runs one [`push`] whose `Hello` names the collection id `collection`.
fn push_in(
    repo: &Repo,
    policy: &ReceivePolicy,
    collection: &str,
    objects: &[Obj],
    updates: Vec<RefUpdate>,
    force: bool,
) -> Pushed {
    let names: Vec<String> = updates.iter().map(|u| u.name.clone()).collect();
    session(repo, policy, |c| {
        script(c, &names, Some(collection), objects, &[], updates, force)
    })
}

async fn script(
    mut c: common::receive::Client,
    names: &[String],
    collection: Option<&str>,
    objects: &[Obj],
    meta: &[(Checksum, Vec<u8>)],
    updates: Vec<RefUpdate>,
    force: bool,
) -> Result<Vec<RefOutcome>, ErrorMessage> {
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    c.hello_reply_in(&names, collection).await;
    if !objects.is_empty() || !meta.is_empty() {
        for o in objects {
            c.object(o.ty, o.checksum, o.encoding, &o.bytes)
                .await
                .unwrap();
        }
        for (commit, dict) in meta {
            c.object(ObjectType::CommitMeta, *commit, Encoding::Raw, dict)
                .await
                .unwrap();
        }
        c.objects_end().await;
    }
    c.commit(updates, force).await.unwrap();
    c.commit_reply().await
}

/// Asserts that a push succeeded and returns its report.
fn committed(pushed: Pushed) -> ReceiveReport {
    let (result, reply) = pushed;
    let report = result.unwrap_or_else(|e| panic!("the push failed: {e}"));
    assert_eq!(
        reply.as_ref(),
        Ok(&report.refs),
        "CommitReply is the report"
    );
    report
}

/// Asserts that a push failed with `code`, on the wire and to the caller, and
/// returns the `Error` message.
fn refused(pushed: Pushed, code: ErrorCode) -> ErrorMessage {
    let (result, reply) = pushed;
    let error = reply.expect_err("the push is refused");
    assert_eq!(error.code, code, "{error:?}");
    if code != ErrorCode::Internal {
        assert_eq!(returned_code(&result), Some(code));
    } else {
        assert!(result.is_err(), "{result:?}");
    }
    error
}

/// The objects and refs of a repository, for [`assert_unchanged`].
type Snapshot = (Vec<(String, Vec<u8>)>, Vec<(String, Vec<u8>)>);

fn snapshot(repo: &Repo) -> Snapshot {
    (
        file_inventory(repo.path(), "objects"),
        file_inventory(repo.path(), "refs"),
    )
}

/// Asserts that a failed session published nothing, wrote no ref, and left no
/// staging entry.
fn assert_unchanged(repo: &Repo, before: &Snapshot) {
    let after = snapshot(repo);
    assert_eq!(after.0, before.0, "no object published");
    assert_eq!(after.1, before.1, "no ref written");
    assert!(
        staging_entries(repo.path()).is_empty(),
        "no staging entry left"
    );
}

fn ref_file(repo: &Repo, relpath: &str) -> Option<String> {
    std::fs::read_to_string(repo.path().join(relpath)).ok()
}

/// A policy that writes a commit to each ref as a fast-forward.
fn policy() -> ReceivePolicy {
    policy_allowing(&["w:**"])
}

/// Runs a session that sends `Hello` with `names` and reads the `Error` that
/// the server answers.
fn hello_refused(repo: &Repo, policy: &ReceivePolicy, names: &[&str]) -> ErrorMessage {
    let names: Vec<String> = names.iter().map(|&n| n.into()).collect();
    let (result, error) = session(repo, policy, |mut c| async move {
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        c.hello(&names).await.unwrap();
        c.error().await
    });
    assert_eq!(returned_code(&result), Some(error.code), "{error:?}");
    error
}

/// A repository with the fixture commit on `test/main`, pushed through a
/// session.
fn repo_with_fixture(tmp: &TmpDir, mode: RepoMode, core: &str) -> Repo {
    let repo = new_repo(tmp, mode, core);
    committed(push(
        &repo,
        &policy(),
        &fixture_objects(Encoding::Raw),
        &[],
        vec![update(
            "test/main",
            Expected::Absent,
            Some(fixture_commit()),
        )],
        false,
    ));
    repo
}

fn commit_meta_path(repo: &Repo, commit: &Checksum) -> PathBuf {
    repo.path().join("objects").join(ostrya::loose_path(
        commit,
        ObjectType::CommitMeta,
        repo.mode(),
    ))
}

// ---------------------------------------------------------------------------
// The commit.
// ---------------------------------------------------------------------------

#[test]
fn the_fixture_commit_lands_in_each_mode() {
    let tool = common::ostree_available();
    if !tool {
        eprintln!("skipping the ostree fsck checks: ostree is not installed");
    }
    let mut modes = vec![
        (RepoMode::Archive, Encoding::Deflate),
        (RepoMode::BareUser, Encoding::Raw),
        (RepoMode::BareUserOnly, Encoding::Deflate),
        (RepoMode::BareUserShared, Encoding::Raw),
    ];
    if common::receive::is_root() {
        modes.push((RepoMode::Bare, Encoding::Deflate));
    } else {
        eprintln!("skipping the bare mode: the test does not run as root");
    }
    for (mode, encoding) in modes {
        let tmp = TmpDir::new("recv-commit-mode");
        let repo = new_repo(&tmp, mode, "");
        let objects = fixture_objects(encoding);
        let report = committed(push(
            &repo,
            &policy(),
            &objects,
            &[],
            vec![update(
                "test/main",
                Expected::Absent,
                Some(fixture_commit()),
            )],
            false,
        ));
        assert_eq!(
            report.refs,
            vec![RefOutcome {
                name: "test/main".into(),
                old: None,
                new: Some(fixture_commit()),
            }],
            "{mode:?}"
        );
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        assert_eq!(
            report.stats.metadata_written + report.stats.content_written,
            objects.len() as u32,
            "{mode:?}"
        );
        assert_eq!(
            ref_file(&repo, "refs/heads/test/main"),
            Some(format!("{COMMIT}\n"))
        );
        assert!(staging_entries(repo.path()).is_empty());
        let reopened = block_on(Repo::open(repo.path())).unwrap();
        let fsck = block_on(reopened.fsck(&FsckOptions::default())).unwrap();
        assert!(fsck.is_ok(), "{mode:?}: {fsck:?}");
        assert_eq!(fsck.commits_checked, 1);
        if tool && mode != RepoMode::BareUserShared {
            tool_fsck(repo.path());
        }
    }
}

/// Under `[ex-integrity] fsverity=yes`, the session seals each regular-file
/// object that it writes. This includes `raw` content, `deflate` content that
/// the server inflates, and `deflate` content that an archive server stores as
/// it is.
#[test]
fn fsverity_yes_seals_every_object_the_session_writes() {
    let probe = TmpDir::new("recv-verity-probe");
    let repo = new_repo(
        &probe,
        RepoMode::BareUserShared,
        "[ex-integrity]\nfsverity=maybe\n",
    );
    committed(push(
        &repo,
        &policy(),
        &fixture_objects(Encoding::Raw),
        &[],
        vec![update(
            "test/main",
            Expected::Absent,
            Some(fixture_commit()),
        )],
        false,
    ));
    if !regular_objects(repo.path()).iter().any(|p| is_sealed(p)) {
        eprintln!("skipping: the filesystem does not support fs-verity");
        return;
    }
    for (mode, encoding) in [
        (RepoMode::BareUserShared, Encoding::Raw),
        (RepoMode::BareUserShared, Encoding::Deflate),
        (RepoMode::Archive, Encoding::Raw),
        (RepoMode::Archive, Encoding::Deflate),
    ] {
        let tmp = TmpDir::new("recv-verity");
        let repo = new_repo(&tmp, mode, "[ex-integrity]\nfsverity=yes\n");
        committed(push(
            &repo,
            &policy(),
            &fixture_objects(encoding),
            &[],
            vec![update(
                "test/main",
                Expected::Absent,
                Some(fixture_commit()),
            )],
            false,
        ));
        let regulars = regular_objects(repo.path());
        assert!(!regulars.is_empty());
        for path in regulars {
            assert!(
                is_sealed(&path),
                "{mode:?} {encoding:?}: {}",
                path.display()
            );
        }
    }
}

/// Two sessions that create one ref at the same time: the update lock
/// orders them, and the second one finds the ref present.
#[test]
fn two_sessions_from_absent_give_one_success_and_one_ref_mismatch() {
    let tmp = TmpDir::new("recv-two-sessions");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let objects = fixture_objects(Encoding::Raw);
    let names = vec!["test/main".to_string()];
    let updates = || {
        vec![update(
            "test/main",
            Expected::Absent,
            Some(fixture_commit()),
        )]
    };
    let policy = policy();
    let (c1, in1, out1) = connect();
    let (c2, in2, out2) = connect();
    let ((r1, reply1), (r2, reply2)) = block_on(futures_lite::future::zip(
        futures_lite::future::zip(
            repo.receive(in1, out1, &policy),
            script(c1, &names, None, &objects, &[], updates(), false),
        ),
        futures_lite::future::zip(
            repo.receive(in2, out2, &policy),
            script(c2, &names, None, &objects, &[], updates(), false),
        ),
    ));
    let (ok, failed) = match (r1.is_ok(), r2.is_ok()) {
        (true, false) => ((r1, reply1), (r2, reply2)),
        (false, true) => ((r2, reply2), (r1, reply1)),
        other => panic!("expected one success, got {other:?}: {r1:?} {r2:?}"),
    };
    committed(ok);
    let error = refused(failed, ErrorCode::RefMismatch);
    let current = error.current.unwrap();
    assert_eq!(current.name, "test/main");
    assert_eq!(current.commit, Some(fixture_commit()));
    assert_eq!(
        ref_file(&repo, "refs/heads/test/main"),
        Some(format!("{COMMIT}\n"))
    );
}

/// The repository holds a commit with a partial marker. If a session sends the
/// missing objects and names the commit again, the session removes the marker.
/// An update to the current commit writes no ref.
#[test]
fn a_partial_commit_pushed_again_loses_its_marker() {
    let tmp = TmpDir::new("recv-partial");
    let repo = repo_with_fixture(&tmp, RepoMode::Archive, "");
    let content = fixture_objects(Encoding::Deflate)
        .into_iter()
        .find(|o| o.ty == ObjectType::File)
        .unwrap();
    let content_path = repo.path().join("objects").join(ostrya::loose_path(
        &content.checksum,
        ObjectType::File,
        RepoMode::Archive,
    ));
    std::fs::remove_file(&content_path).unwrap();
    let marker = repo.path().join(format!("state/{COMMIT}.commitpartial"));
    std::fs::write(&marker, b"").unwrap();

    let report = committed(push(
        &repo,
        &policy(),
        &fixture_objects(Encoding::Deflate),
        &[],
        vec![update(
            "test/main",
            Expected::Commit(fixture_commit()),
            Some(fixture_commit()),
        )],
        false,
    ));
    assert_eq!(
        report.refs,
        vec![RefOutcome {
            name: "test/main".into(),
            old: Some(fixture_commit()),
            new: Some(fixture_commit()),
        }]
    );
    assert!(!marker.exists(), "the marker is removed");
    assert!(content_path.exists(), "the missing object is published");
    let fsck = block_on(repo.fsck(&FsckOptions::default())).unwrap();
    assert!(fsck.is_ok(), "{fsck:?}");
}

/// If the session cannot remove a partial marker, the report holds a warning,
/// and the refs stay written.
#[test]
fn a_marker_that_stays_is_a_warning() {
    let tmp = TmpDir::new("recv-marker-warning");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let marker = repo.path().join(format!("state/{COMMIT}.commitpartial"));
    std::fs::create_dir_all(marker.join("entry")).unwrap();
    let report = committed(push(
        &repo,
        &policy(),
        &fixture_objects(Encoding::Raw),
        &[],
        vec![update(
            "test/main",
            Expected::Absent,
            Some(fixture_commit()),
        )],
        false,
    ));
    assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
    assert_eq!(report.warnings[0].step, ReceiveStep::PartialMarker);
    assert!(report.warnings[0].message.contains(COMMIT));
    assert_eq!(
        ref_file(&repo, "refs/heads/test/main"),
        Some(format!("{COMMIT}\n"))
    );
}

/// If the client does not read `CommitReply`, the report holds a warning, and
/// the call returns `Ok`.
#[test]
fn a_reply_the_client_does_not_read_is_a_warning() {
    let tmp = TmpDir::new("recv-reply-lost");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let objects = fixture_objects(Encoding::Raw);
    let (result, ()) = session(&repo, &policy(), |mut c| async move {
        c.hello_reply(&["test/main"]).await;
        for o in &objects {
            c.object(o.ty, o.checksum, o.encoding, &o.bytes)
                .await
                .unwrap();
        }
        c.objects_end().await;
        c.commit(
            vec![update(
                "test/main",
                Expected::Absent,
                Some(fixture_commit()),
            )],
            false,
        )
        .await
        .unwrap();
        drop(c);
    });
    let report = result.unwrap();
    assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
    assert_eq!(report.warnings[0].step, ReceiveStep::ReplyNotDelivered);
    assert_eq!(
        ref_file(&repo, "refs/heads/test/main"),
        Some(format!("{COMMIT}\n"))
    );
}

/// A second client signature joins the signature that the repository holds for
/// the commit, and the stored one stays first.
#[test]
fn a_second_client_signature_joins_the_stored_one() {
    let tmp = TmpDir::new("recv-join");
    let repo = repo_with_fixture(&tmp, RepoMode::Archive, "");
    let payload = block_on(repo.load_object_bytes(ObjectType::Commit, &fixture_commit())).unwrap();
    let first = ed25519_signature(SECRET_B64, &payload);
    let second = ed25519_signature(OTHER_SECRET_B64, &payload);
    let mut stored = no_metadata();
    append_signature(&mut stored, ED25519_KEY, first.clone()).unwrap();
    block_on(repo.write_commit_detached_metadata(&fixture_commit(), Some(&stored))).unwrap();

    let mut incoming = no_metadata();
    append_signature(&mut incoming, ED25519_KEY, second.clone()).unwrap();
    committed(push(
        &repo,
        &policy(),
        &[],
        &[(fixture_commit(), dict_bytes(&incoming))],
        vec![update("test/main", Expected::Any, Some(fixture_commit()))],
        false,
    ));
    let merged = block_on(repo.read_commit_detached_metadata(&fixture_commit()))
        .unwrap()
        .unwrap();
    assert_eq!(signatures(&merged, ED25519_KEY), vec![first, second]);
}

/// The `[ex-ostrya]` group that turns the related switch off.
const DROP_RELATED: &str = "\n[ex-ostrya]\nkeep-detached-related=false\n";

/// Returns the keys of the stored detached metadata of the fixture commit, in
/// order.
fn fixture_detached_keys(repo: &Repo) -> Vec<String> {
    let stored = block_on(repo.read_commit_detached_metadata(&fixture_commit()))
        .unwrap()
        .unwrap();
    stored
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e.as_tuple().unwrap()[0].as_str().unwrap().to_owned())
        .collect()
}

/// Inserts an `ostrya.related` value with one entry that names `commit`.
fn insert_related(dict: &mut DictBuilder, name: &str, commit: &Checksum) {
    dict.insert(
        "ostrya.related",
        Type::parse("a(say)").unwrap(),
        Value::Array(vec![Value::Tuple(vec![
            Value::Str(name.to_owned()),
            Value::Bytes(commit.as_bytes().to_vec()),
        ])]),
    );
}

/// With `keep-detached-related=false` in the repository, the session drops
/// `ostrya.related` from the incoming dict and stores each other property.
#[test]
fn the_switch_removes_the_related_key_from_the_incoming_dict() {
    let tmp = TmpDir::new("recv-keep-related");
    let repo = new_repo(&tmp, RepoMode::Archive, DROP_RELATED);
    let mut dict = DictBuilder::new();
    dict.insert_str("kept", "a");
    dict.insert_str("other", "b");
    insert_related(&mut dict, "layer/base", &fixture_commit());
    committed(push(
        &repo,
        &policy(),
        &fixture_objects(Encoding::Raw),
        &[(fixture_commit(), dict_bytes(&dict.build()))],
        vec![update(
            "test/main",
            Expected::Absent,
            Some(fixture_commit()),
        )],
        false,
    ));
    assert_eq!(fixture_detached_keys(&repo), ["kept", "other"]);
}

/// Under the switch, a receive merges into the stored dict, so it keeps a
/// value that the repository holds. A local write stores `ostrya.related` under the switch, and a later session keeps
/// the stored value and drops the incoming one.
#[test]
fn the_switch_keeps_a_stored_related_value() {
    let tmp = TmpDir::new("recv-keep-related-stored");
    let repo = repo_with_fixture(&tmp, RepoMode::Archive, DROP_RELATED);
    block_on(repo.add_detached_related(&fixture_commit(), "layer/base", &fixture_commit()))
        .unwrap();
    let held = block_on(repo.read_commit_detached_metadata(&fixture_commit()))
        .unwrap()
        .unwrap();

    let mut dict = DictBuilder::new();
    dict.insert_str("kept", "a");
    insert_related(&mut dict, "layer/other", &checksum(ROOT_DIRTREE));
    committed(push(
        &repo,
        &policy(),
        &[],
        &[(fixture_commit(), dict_bytes(&dict.build()))],
        vec![update("test/main", Expected::Any, Some(fixture_commit()))],
        false,
    ));

    assert_eq!(fixture_detached_keys(&repo), ["ostrya.related", "kept"]);
    let stored = block_on(repo.read_commit_detached_metadata(&fixture_commit()))
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.dict_get("ostrya.related"),
        held.dict_get("ostrya.related")
    );
}

/// A push session writes no remote ref. A `Hello` that names a remote ref is
/// `ref-denied`, also under an allow item that matches each ref, and the
/// session opens no transaction.
#[test]
fn a_remote_ref_is_ref_denied_at_hello() {
    let tmp = TmpDir::new("recv-remote");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let before = snapshot(&repo);
    let error = hello_refused(
        &repo,
        &policy_allowing(&["rwctd:**"]),
        &["test/main", "origin:test/main"],
    );
    assert_eq!(error.code, ErrorCode::RefDenied);
    assert!(error.message.contains("'origin:test/main'"), "{error:?}");
    assert!(error.message.contains("remote ref"), "{error:?}");
    assert_unchanged(&repo, &before);
}

/// `Hello` needs a policy that opens a push session, and `r` on each ref.
/// `d` does not add `r`, and a deny item removes each mode. Each refusal is
/// `ref-denied`, and nothing is published.
#[test]
fn hello_needs_a_push_mode_and_read_on_each_ref() {
    let tmp = TmpDir::new("recv-hello-rights");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let before = snapshot(&repo);
    let deny = ReceivePolicy {
        rules: ostrya::access::AccessRules {
            deny: vec![ostrya::RefPattern::parse("test/**").unwrap()],
            ..policy().rules
        },
        ..policy()
    };
    let cases: Vec<(ReceivePolicy, Vec<&str>, &str)> = vec![
        (
            ReceivePolicy::default(),
            vec!["test/main"],
            "opens no push session",
        ),
        (
            policy_allowing(&["r:**"]),
            vec!["test/main"],
            "opens no push session",
        ),
        (policy_allowing(&["w:a"]), vec!["a", "b"], "'b'"),
        (policy_allowing(&["d:test/main"]), vec!["test/main"], "no r"),
        (deny, vec!["main", "test/main"], "'test/main'"),
    ];
    for (policy, names, needle) in cases {
        let error = hello_refused(&repo, &policy, &names);
        assert_eq!(error.code, ErrorCode::RefDenied, "{names:?}");
        assert!(error.message.contains(needle), "{names:?}: {error:?}");
        assert_unchanged(&repo, &before);
    }
    // `r` on a ref that the session does not write is enough for `Hello`.
    let commit = build_commit(None, "unbound", no_metadata(), &[]);
    let mut objects = tree_objects();
    objects.push(commit.clone());
    committed(push_named(
        &repo,
        &policy_allowing(&["r:**", "w:a"]),
        &["a".to_owned(), "b".to_owned()],
        &objects,
        &[],
        vec![update("a", Expected::Absent, Some(commit.checksum))],
        false,
    ));
}

// ---------------------------------------------------------------------------
// The checks before the lock.
// ---------------------------------------------------------------------------

/// Each of these is `protocol`:
///
/// - a `Commit` with no update
/// - an update of a ref that `Hello` did not name
/// - a second update of one ref
#[test]
fn a_commit_outside_the_named_refs_is_protocol() {
    let tmp = TmpDir::new("recv-protocol");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let objects = fixture_objects(Encoding::Raw);
    let before = snapshot(&repo);
    let names = vec!["test/main".to_string()];
    let new = Some(fixture_commit());
    for updates in [
        vec![],
        vec![update("other", Expected::Absent, new)],
        vec![
            update("test/main", Expected::Absent, new),
            update("test/main", Expected::Any, new),
        ],
    ] {
        refused(
            push_named(&repo, &policy(), &names, &objects, &[], updates, false),
            ErrorCode::Protocol,
        );
        assert_unchanged(&repo, &before);
    }
}

/// A ref name that `validate_refspec` refuses is `invalid-ref`, also if `Hello`
/// did not name it.
#[test]
fn an_invalid_name_at_commit_is_invalid_ref() {
    let tmp = TmpDir::new("recv-invalid");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let before = snapshot(&repo);
    let names = vec!["test/main".to_string()];
    refused(
        push_named(
            &repo,
            &policy(),
            &names,
            &fixture_objects(Encoding::Raw),
            &[],
            vec![update("a/../b", Expected::Absent, Some(fixture_commit()))],
            false,
        ),
        ErrorCode::InvalidRef,
    );
    assert_unchanged(&repo, &before);
}

/// A ref name that fails the ref-name rule, here a name with a space, is
/// `invalid-ref` at `Commit`, also if `Hello` did not name it.
#[test]
fn a_name_outside_the_ref_name_rule_at_commit_is_invalid_ref() {
    let tmp = TmpDir::new("recv-invalid-rule");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let before = snapshot(&repo);
    let names = vec!["test/main".to_string()];
    refused(
        push_named(
            &repo,
            &policy(),
            &names,
            &fixture_objects(Encoding::Raw),
            &[],
            vec![update("a b", Expected::Absent, Some(fixture_commit()))],
            false,
        ),
        ErrorCode::InvalidRef,
    );
    assert_unchanged(&repo, &before);
}

/// A ref name of 64 lowercase hex characters passes `Hello`. A revision reads
/// such a name as a commit checksum. An update that writes a commit to it is
/// `invalid-ref` at `Commit`, also if `Hello` did not name it.
#[test]
fn a_write_to_a_checksum_shaped_name_is_invalid_ref_at_commit() {
    let tmp = TmpDir::new("recv-hex-commit");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let before = snapshot(&repo);
    let hex = "a".repeat(64);
    for names in [vec![hex.clone()], vec!["test/main".to_string()]] {
        let error = refused(
            push_named(
                &repo,
                &policy(),
                &names,
                &fixture_objects(Encoding::Raw),
                &[],
                vec![update(&hex, Expected::Absent, Some(fixture_commit()))],
                false,
            ),
            ErrorCode::InvalidRef,
        );
        assert_eq!(error.message, format!("invalid ref name '{hex}'"));
        assert_unchanged(&repo, &before);
    }
}

/// A delete of a ref of 64 lowercase hex characters passes the check of the
/// name. A policy with `d` on the ref removes the ref.
#[test]
fn a_delete_of_a_checksum_shaped_name_removes_the_ref() {
    let tmp = TmpDir::new("recv-hex-delete");
    let repo = repo_with_fixture(&tmp, RepoMode::Archive, "");
    let hex = "a".repeat(64);
    block_on(repo.set_ref_immediate(&hex, Some(&fixture_commit()))).unwrap();
    let path = format!("refs/heads/{hex}");
    assert_eq!(ref_file(&repo, &path), Some(format!("{COMMIT}\n")));
    let allow = policy_allowing(&["rd:**"]);
    let report = committed(push(
        &repo,
        &allow,
        &[],
        &[],
        vec![update(&hex, Expected::Commit(fixture_commit()), None)],
        false,
    ));
    assert_eq!(
        report.refs,
        vec![RefOutcome {
            name: hex.clone(),
            old: Some(fixture_commit()),
            new: None,
        }]
    );
    assert_eq!(ref_file(&repo, &path), None);
    assert_eq!(
        ref_file(&repo, "refs/heads/test/main"),
        Some(format!("{COMMIT}\n"))
    );
}

/// Detached metadata for a commit that is neither staged nor present is
/// `protocol` at `Commit`.
#[test]
fn detached_metadata_for_an_absent_commit_is_protocol() {
    let tmp = TmpDir::new("recv-meta-absent");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let before = snapshot(&repo);
    refused(
        push(
            &repo,
            &policy(),
            &fixture_objects(Encoding::Raw),
            &[(sha(b"no such commit"), dict_bytes(&no_metadata()))],
            vec![update(
                "test/main",
                Expected::Absent,
                Some(fixture_commit()),
            )],
            false,
        ),
        ErrorCode::Protocol,
    );
    assert_unchanged(&repo, &before);
}

/// A detached metadata dict that holds a key twice, or a signature key whose
/// value is not `aay`, is `protocol` when it arrives.
#[test]
fn detached_metadata_the_merge_refuses_is_protocol_at_ingest() {
    let twice = Value::Array(vec![
        Value::Tuple(vec![
            Value::Str("k".into()),
            Value::Variant(Box::new((
                Type::parse("s").unwrap(),
                Value::Str("a".into()),
            ))),
        ]),
        Value::Tuple(vec![
            Value::Str("k".into()),
            Value::Variant(Box::new((
                Type::parse("s").unwrap(),
                Value::Str("b".into()),
            ))),
        ]),
    ]);
    let mut not_aay = DictBuilder::new();
    not_aay.insert_str(ED25519_KEY, "not a list");
    for dict in [dict_bytes(&twice), dict_bytes(&not_aay.build())] {
        let tmp = TmpDir::new("recv-meta-bad");
        let repo = new_repo(&tmp, RepoMode::Archive, "");
        let (result, error) = session(&repo, &policy(), |mut c| async move {
            c.hello_reply(&["test/main"]).await;
            let _ = c
                .object(
                    ObjectType::CommitMeta,
                    fixture_commit(),
                    Encoding::Raw,
                    &dict,
                )
                .await;
            c.error().await
        });
        assert_eq!(error.code, ErrorCode::Protocol, "{error:?}");
        assert_eq!(returned_code(&result), Some(ErrorCode::Protocol));
    }
}

/// The repository holds a commit, and the session neither stages it nor names
/// it as a new ref value. Detached metadata for this commit is `protocol`.
/// With this check, a session cannot edit the detached metadata of a commit
/// that its rules do not cover. The session writes nothing, and the stored
/// dict stays.
#[test]
fn detached_metadata_for_a_commit_outside_the_session_is_protocol() {
    let tmp = TmpDir::new("recv-meta-outside");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let protected = build_commit(None, "protected", no_metadata(), &[]);
    let free = build_commit(None, "free", no_metadata(), &[]);
    let mut objects = tree_objects();
    objects.push(protected.clone());
    committed(push(
        &repo,
        &policy(),
        &objects,
        &[],
        vec![update(
            "protected",
            Expected::Absent,
            Some(protected.checksum),
        )],
        false,
    ));
    let policy = policy_allowing(&["w:free"]);
    let before = snapshot(&repo);
    let error = refused(
        push(
            &repo,
            &policy,
            std::slice::from_ref(&free),
            &[(
                protected.checksum,
                signed_dict(&protected.bytes, &[SECRET_B64]),
            )],
            vec![update("free", Expected::Absent, Some(free.checksum))],
            false,
        ),
        ErrorCode::Protocol,
    );
    assert!(
        error.message.contains(&protected.checksum.to_string()),
        "{error:?}"
    );
    assert_unchanged(&repo, &before);
    assert!(!commit_meta_path(&repo, &protected.checksum).exists());
}

/// Writes `bytes` into `objects/` as the object `checksum` of type `ty`, as a
/// corrupt store holds it.
fn plant_object(repo: &Repo, ty: ObjectType, checksum: &Checksum, bytes: &[u8]) {
    let path = repo
        .path()
        .join("objects")
        .join(ostrya::loose_path(checksum, ty, repo.mode()));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

/// A commit or a dirtree that does not parse is `protocol` if the session
/// staged it, and `internal` if the repository holds it. In both cases, the
/// session publishes nothing.
#[test]
fn an_object_that_does_not_parse_is_protocol_when_staged_and_internal_when_stored() {
    let garbage = b"not a gvariant object".to_vec();
    let bad = sha(&garbage);
    let over_bad_tree = Commit {
        metadata: no_metadata(),
        parent: None,
        related: Vec::new(),
        subject: "over a bad tree".into(),
        body: String::new(),
        timestamp: 1_700_000_100,
        root_dirtree: bad,
        root_dirmeta: checksum(ROOT_DIRMETA),
    }
    .serialize()
    .unwrap();
    let over_bad_tree = Obj {
        ty: ObjectType::Commit,
        checksum: sha(&over_bad_tree),
        encoding: Encoding::Raw,
        bytes: over_bad_tree,
    };
    let object = |ty| Obj {
        ty,
        checksum: bad,
        encoding: Encoding::Raw,
        bytes: garbage.clone(),
    };
    for (ty, stored) in [
        (ObjectType::Commit, false),
        (ObjectType::Commit, true),
        (ObjectType::DirTree, false),
        (ObjectType::DirTree, true),
    ] {
        let tmp = TmpDir::new("recv-unparsable");
        let repo = new_repo(&tmp, RepoMode::Archive, "");
        let mut objects = tree_objects();
        if stored {
            plant_object(&repo, ty, &bad, &garbage);
        } else {
            objects.push(object(ty));
        }
        let new = if ty == ObjectType::Commit {
            bad
        } else {
            objects.push(over_bad_tree.clone());
            over_bad_tree.checksum
        };
        let before = snapshot(&repo);
        let code = if stored {
            ErrorCode::Internal
        } else {
            ErrorCode::Protocol
        };
        let error = refused(
            push(
                &repo,
                &policy(),
                &objects,
                &[],
                vec![update("main", Expected::Absent, Some(new))],
                false,
            ),
            code,
        );
        assert!(
            error.message.contains("does not parse"),
            "{ty:?} stored={stored}: {error:?}"
        );
        assert_unchanged(&repo, &before);
    }
}

/// Each of these refs is `ref-denied` at `Commit`:
///
/// - a ref that the update writes a commit to, with `r` and no `w` or `t`
/// - the collection anchor ref of a repository with a collection id
/// - a ref that is an alias
#[test]
fn ref_denied_covers_each_refused_ref() {
    // An unbound commit, so the binding check passes each name.
    let commit = build_commit(None, "unbound", no_metadata(), &[]);
    let mut objects = tree_objects();
    objects.push(commit.clone());
    let new = Some(commit.checksum);
    let cases: Vec<(&str, ReceivePolicy, &str, &str)> = vec![
        ("", policy_allowing(&["rd:**"]), "test/main", "no w or t"),
        (
            "collection-id=org.example.C\n",
            policy(),
            "ostree-metadata",
            "anchor",
        ),
        ("", policy(), "alias", "alias"),
    ];
    for (core, policy, name, needle) in cases {
        let tmp = TmpDir::new("recv-denied");
        let repo = new_repo(&tmp, RepoMode::Archive, core);
        if name == "alias" {
            std::os::unix::fs::symlink("test/main", repo.path().join("refs/heads/alias")).unwrap();
        }
        let before = snapshot(&repo);
        let error = refused(
            push(
                &repo,
                &policy,
                &objects,
                &[],
                vec![update(name, Expected::Any, new)],
                false,
            ),
            ErrorCode::RefDenied,
        );
        assert!(error.message.contains(needle), "{name}: {error:?}");
        assert_unchanged(&repo, &before);
    }
}

/// An object that the trees reach and that the session did not send is
/// `missing-objects`. A new commit that the session did not send is
/// `missing-objects` too.
#[test]
fn missing_objects_lists_what_was_not_sent() {
    let tmp = TmpDir::new("recv-missing");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let before = snapshot(&repo);
    let mut objects = fixture_objects(Encoding::Raw);
    let dropped: Vec<Obj> = objects
        .iter()
        .filter(|o| o.ty == ObjectType::File)
        .take(2)
        .cloned()
        .collect();
    objects.retain(|o| !dropped.iter().any(|d| d.checksum == o.checksum));
    let error = refused(
        push(
            &repo,
            &policy(),
            &objects,
            &[],
            vec![update(
                "test/main",
                Expected::Absent,
                Some(fixture_commit()),
            )],
            false,
        ),
        ErrorCode::MissingObjects,
    );
    let mut missing = error.missing.clone();
    missing.sort_by_key(|n| n.checksum);
    let mut expected: Vec<ObjectName> = dropped
        .iter()
        .map(|o| ObjectName::new(o.checksum, o.ty))
        .collect();
    expected.sort_by_key(|n| n.checksum);
    assert_eq!(missing, expected);
    assert!(error.message.starts_with("2 objects"), "{error:?}");
    assert_unchanged(&repo, &before);

    let absent = sha(b"a commit nobody sent");
    let error = refused(
        push(
            &repo,
            &policy(),
            &[],
            &[],
            vec![update("test/main", Expected::Absent, Some(absent))],
            false,
        ),
        ErrorCode::MissingObjects,
    );
    assert_eq!(
        error.missing,
        vec![ObjectName::new(absent, ObjectType::Commit)]
    );
    assert_unchanged(&repo, &before);
}

/// A commit whose `ostree.ref-binding` does not list the target ref is
/// `binding-mismatch`.
#[test]
fn a_foreign_ref_binding_is_binding_mismatch() {
    let tmp = TmpDir::new("recv-ref-binding");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let before = snapshot(&repo);
    refused(
        push(
            &repo,
            &policy(),
            &fixture_objects(Encoding::Raw),
            &[],
            vec![update("other", Expected::Absent, Some(fixture_commit()))],
            false,
        ),
        ErrorCode::BindingMismatch,
    );
    assert_unchanged(&repo, &before);
}

/// A commit whose `ostree.collection-binding` is not the collection id of the
/// repository is `binding-mismatch`. If the repository has that id, the same
/// binding passes.
#[test]
fn a_foreign_collection_binding_is_binding_mismatch() {
    let mut metadata = DictBuilder::new();
    metadata.insert_str("ostree.collection-binding", "org.example.Other");
    let commit = build_commit(None, "bound", metadata.build(), &[]);
    let mut objects = tree_objects();
    objects.push(commit.clone());

    let tmp = TmpDir::new("recv-collection-binding");
    let repo = new_repo(&tmp, RepoMode::Archive, "collection-id=org.example.C\n");
    let before = snapshot(&repo);
    let error = refused(
        push(
            &repo,
            &policy(),
            &objects,
            &[],
            vec![update("main", Expected::Absent, Some(commit.checksum))],
            false,
        ),
        ErrorCode::BindingMismatch,
    );
    assert!(error.message.contains("org.example.Other"), "{error:?}");
    assert_unchanged(&repo, &before);

    let tmp = TmpDir::new("recv-collection-binding-ok");
    let repo = new_repo(&tmp, RepoMode::Archive, "collection-id=org.example.Other\n");
    committed(push(
        &repo,
        &policy(),
        &objects,
        &[],
        vec![update("main", Expected::Absent, Some(commit.checksum))],
        false,
    ));
}

/// In the local refs of a repository with no collection id, a commit with
/// a collection binding is `binding-mismatch`. A commit with no binding
/// passes.
#[test]
fn a_collection_binding_needs_a_namespace_of_that_id() {
    let mut metadata = DictBuilder::new();
    metadata.insert_str("ostree.collection-binding", "org.example.Os");
    let bound = build_commit(None, "bound", metadata.build(), &[]);
    let unbound = build_commit(None, "unbound", no_metadata(), &[]);
    let mut objects = tree_objects();
    objects.extend([bound.clone(), unbound.clone()]);

    let tmp = TmpDir::new("recv-binding-no-id");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let before = snapshot(&repo);
    let error = refused(
        push(
            &repo,
            &policy(),
            &objects,
            &[],
            vec![update("main", Expected::Absent, Some(bound.checksum))],
            false,
        ),
        ErrorCode::BindingMismatch,
    );
    assert!(error.message.contains("no collection id"), "{error:?}");
    assert_unchanged(&repo, &before);

    // In the namespace of the collection, the bound commit and the unbound
    // commit pass. Another collection refuses the bound commit.
    let all = collections_policy(&["w:**"]);
    committed(push_in(
        &repo,
        &all,
        "org.example.Os",
        &objects,
        vec![
            update("bound", Expected::Absent, Some(bound.checksum)),
            update("unbound", Expected::Absent, Some(unbound.checksum)),
        ],
        false,
    ));
    let before = snapshot(&repo);
    let error = refused(
        push_in(
            &repo,
            &all,
            "org.example.Other",
            &[],
            vec![update("main", Expected::Absent, Some(bound.checksum))],
            false,
        ),
        ErrorCode::BindingMismatch,
    );
    assert!(
        error.message.contains("not 'org.example.Other'"),
        "{error:?}"
    );
    assert_unchanged(&repo, &before);
}

/// A session of a collection namespace reads and writes the refs under
/// `refs/mirrors/ID/`, and does not touch `refs/heads/`. The fast-forward
/// check, the delete, and the rule of `t` apply to these refs.
#[test]
fn a_collection_namespace_writes_the_mirror_refs() {
    let tmp = TmpDir::new("recv-mirror-refs");
    let repo = new_repo(&tmp, RepoMode::Archive, "collection-id=org.example.C\n");
    let mut metadata = DictBuilder::new();
    metadata.insert_str("ostree.collection-binding", "org.example.Os");
    let first = build_commit(None, "first", metadata.build(), &[]);
    let mut metadata = DictBuilder::new();
    metadata.insert_str("ostree.collection-binding", "org.example.Os");
    let second = build_commit(Some(first.checksum), "second", metadata.build(), &[]);
    let mut objects = tree_objects();
    objects.extend([first.clone(), second.clone()]);
    let local = sha(b"local");
    std::fs::write(repo.path().join("refs/heads/main"), format!("{local}\n")).unwrap();
    let mirror = "refs/mirrors/org.example.Os/main";
    let all = collections_policy(&["w:**"]);

    let report = committed(push_in(
        &repo,
        &all,
        "org.example.Os",
        &objects,
        vec![update("main", Expected::Absent, Some(first.checksum))],
        false,
    ));
    assert_eq!(report.collection.as_deref(), Some("org.example.Os"));
    assert_eq!(report.refs[0].old, None);
    assert_eq!(
        ref_file(&repo, mirror),
        Some(format!("{}\n", first.checksum))
    );
    assert_eq!(
        ref_file(&repo, "refs/heads/main"),
        Some(format!("{local}\n"))
    );

    // The expected state is the state of the mirror ref.
    let report = committed(push_in(
        &repo,
        &all,
        "org.example.Os",
        &[],
        vec![update(
            "main",
            Expected::Commit(first.checksum),
            Some(second.checksum),
        )],
        false,
    ));
    assert_eq!(report.refs[0].old, Some(first.checksum));
    assert_eq!(
        ref_file(&repo, mirror),
        Some(format!("{}\n", second.checksum))
    );

    // A tag that exists is `ref-mismatch`, and a delete needs `d`.
    let before = snapshot(&repo);
    let error = refused(
        push_in(
            &repo,
            &collections_policy(&["t:**"]),
            "org.example.Os",
            &[],
            vec![update("main", Expected::Any, Some(second.checksum))],
            false,
        ),
        ErrorCode::RefMismatch,
    );
    assert_eq!(error.current.unwrap().commit, Some(second.checksum));
    assert_unchanged(&repo, &before);
    let current = Expected::Commit(second.checksum);
    refused(
        push_in(
            &repo,
            &all,
            "org.example.Os",
            &[],
            vec![update("main", current, None)],
            false,
        ),
        ErrorCode::DeleteDenied,
    );
    assert_unchanged(&repo, &before);
    committed(push_in(
        &repo,
        &collections_policy(&["rd:**"]),
        "org.example.Os",
        &[],
        vec![update("main", current, None)],
        false,
    ));
    assert_eq!(ref_file(&repo, mirror), None);
    assert_eq!(
        ref_file(&repo, "refs/heads/main"),
        Some(format!("{local}\n"))
    );
}

/// `ostree-metadata` is the anchor ref of the local refs of a repository
/// with a collection id. In a collection namespace, the name is a normal ref.
#[test]
fn ostree_metadata_is_a_normal_ref_in_a_collection() {
    let tmp = TmpDir::new("recv-mirror-anchor");
    let repo = new_repo(&tmp, RepoMode::Archive, "collection-id=org.example.C\n");
    let commit = build_commit(None, "unbound", no_metadata(), &[]);
    let mut objects = tree_objects();
    objects.push(commit.clone());
    let before = snapshot(&repo);
    let error = refused(
        push_in(
            &repo,
            &policy(),
            "org.example.C",
            &objects,
            vec![update(
                "ostree-metadata",
                Expected::Any,
                Some(commit.checksum),
            )],
            false,
        ),
        ErrorCode::RefDenied,
    );
    assert!(error.message.contains("anchor"), "{error:?}");
    assert_unchanged(&repo, &before);
    committed(push_in(
        &repo,
        &collections_policy(&["w:**"]),
        "org.example.Os",
        &objects,
        vec![update(
            "ostree-metadata",
            Expected::Absent,
            Some(commit.checksum),
        )],
        false,
    ));
    assert_eq!(
        ref_file(&repo, "refs/mirrors/org.example.Os/ostree-metadata"),
        Some(format!("{}\n", commit.checksum))
    );
    assert_eq!(ref_file(&repo, "refs/heads/ostree-metadata"), None);
}

/// A commit that carries no signature that the policy trusts is
/// `signature-required`. The check reads the incoming signatures and the
/// stored ones.
#[test]
fn an_unsigned_commit_is_signature_required() {
    let policy = ReceivePolicy {
        verify: ReceiveVerify::Keys(trust(SECRET_B64)),
        ..policy()
    };
    let objects = fixture_objects(Encoding::Raw);
    let payload = &objects
        .iter()
        .find(|o| o.ty == ObjectType::Commit)
        .unwrap()
        .bytes;
    let updates = || {
        vec![update(
            "test/main",
            Expected::Absent,
            Some(fixture_commit()),
        )]
    };

    let tmp = TmpDir::new("recv-unsigned");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let before = snapshot(&repo);
    refused(
        push(&repo, &policy, &objects, &[], updates(), false),
        ErrorCode::SignatureRequired,
    );
    assert_unchanged(&repo, &before);
    // A signature from a key that the rule does not trust.
    let untrusted = signed_dict(payload, &[OTHER_SECRET_B64]);
    refused(
        push(
            &repo,
            &policy,
            &objects,
            &[(fixture_commit(), untrusted)],
            updates(),
            false,
        ),
        ErrorCode::SignatureRequired,
    );
    assert_unchanged(&repo, &before);
    // An incoming signature from the trusted key.
    let signed = signed_dict(payload, &[SECRET_B64]);
    committed(push(
        &repo,
        &policy,
        &objects,
        &[(fixture_commit(), signed)],
        updates(),
        false,
    ));

    // A stored signature from the trusted key, and no incoming one.
    let tmp = TmpDir::new("recv-stored-signature");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let objects_only: Vec<Obj> = objects
        .iter()
        .filter(|o| o.ty != ObjectType::Commit)
        .cloned()
        .collect();
    committed(push(
        &repo,
        &self::policy(),
        &objects,
        &[(fixture_commit(), signed_dict(payload, &[SECRET_B64]))],
        vec![update(
            "test/main",
            Expected::Absent,
            Some(fixture_commit()),
        )],
        false,
    ));
    committed(push(
        &repo,
        &policy,
        &objects_only,
        &[],
        vec![update(
            "test/main",
            Expected::Commit(fixture_commit()),
            Some(fixture_commit()),
        )],
        false,
    ));
}

/// With `allow_unsigned`, a commit with no signature blob passes. A signature
/// blob under any signature key must pass the verification: a key that the
/// trust does not hold fails, and so does a blob of an engine that the trust
/// does not read. An empty signature list holds no blob. With no
/// verification, a signature that does not verify passes.
#[test]
fn allow_unsigned_accepts_only_a_commit_with_no_signature() {
    let commit = build_commit(None, "unbound", no_metadata(), &[]);
    let mut objects = tree_objects();
    objects.push(commit.clone());
    let dict = |key: &str, blobs: Vec<Vec<u8>>| {
        let list = Value::Array(blobs.into_iter().map(Value::Bytes).collect());
        dict_bytes(&Value::Array(vec![Value::Tuple(vec![
            Value::Str(key.into()),
            Value::variant(Type::parse("aay").unwrap(), list),
        ])]))
    };
    let valid = signed_dict(&commit.bytes, &[SECRET_B64]);
    let untrusted = signed_dict(&commit.bytes, &[OTHER_SECRET_B64]);
    let foreign = dict("ostree.sign.dummy", vec![b"dummy".to_vec()]);
    let empty = dict(ED25519_KEY, Vec::new());
    let keys = ReceiveVerify::Keys(trust(SECRET_B64));
    let unsigned_ok = ReceivePolicy {
        verify: keys.clone(),
        allow_unsigned: true,
        ..policy()
    };
    let signed_only = ReceivePolicy {
        verify: keys,
        ..policy()
    };
    let cases: Vec<(&ReceivePolicy, Option<&Vec<u8>>, bool)> = vec![
        (&unsigned_ok, None, true),
        (&unsigned_ok, Some(&empty), true),
        (&unsigned_ok, Some(&valid), true),
        (&unsigned_ok, Some(&untrusted), false),
        (&unsigned_ok, Some(&foreign), false),
        (&signed_only, None, false),
        (&signed_only, Some(&empty), false),
        (&signed_only, Some(&foreign), false),
        (&signed_only, Some(&valid), true),
    ];
    for (policy, meta, accepted) in cases {
        let tmp = TmpDir::new("recv-allow-unsigned");
        let repo = new_repo(&tmp, RepoMode::Archive, "");
        let before = snapshot(&repo);
        let meta: Vec<(Checksum, Vec<u8>)> = meta
            .map(|d| (commit.checksum, d.clone()))
            .into_iter()
            .collect();
        let pushed = push(
            &repo,
            policy,
            &objects,
            &meta,
            vec![update("main", Expected::Absent, Some(commit.checksum))],
            false,
        );
        if accepted {
            committed(pushed);
        } else {
            refused(pushed, ErrorCode::SignatureRequired);
            assert_unchanged(&repo, &before);
        }
    }
    // With no verification, the session checks no signature.
    let tmp = TmpDir::new("recv-verify-off");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    committed(push(
        &repo,
        &policy(),
        &objects,
        &[(commit.checksum, untrusted)],
        vec![update("main", Expected::Absent, Some(commit.checksum))],
        false,
    ));
}

/// A commit that is the new value of two refs passes the verification once
/// and gets each server key of the policy once, also a key that the list
/// holds two times. A second push adds no signature.
#[test]
fn a_commit_of_two_refs_gets_each_key_once() {
    let commit = build_commit(None, "unbound", no_metadata(), &[]);
    let mut objects = tree_objects();
    objects.push(commit.clone());
    let shared = server_signer(SECOND_SERVER_SECRET_B64);
    let policy = ReceivePolicy {
        verify: ReceiveVerify::Keys(trust(SECRET_B64)),
        signers: vec![server_signer(SERVER_SECRET_B64), shared.clone(), shared],
        ..policy()
    };
    let updates = || {
        vec![
            update("a", Expected::Absent, Some(commit.checksum)),
            update("b", Expected::Absent, Some(commit.checksum)),
        ]
    };
    let tmp = TmpDir::new("recv-two-refs");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let before = snapshot(&repo);
    let dict = signed_dict(&commit.bytes, &[OTHER_SECRET_B64]);
    refused(
        push(
            &repo,
            &policy,
            &objects,
            &[(commit.checksum, dict)],
            updates(),
            false,
        ),
        ErrorCode::SignatureRequired,
    );
    assert_unchanged(&repo, &before);
    let dict = signed_dict(&commit.bytes, &[SECRET_B64]);
    let report = committed(push(
        &repo,
        &policy,
        &objects,
        &[(commit.checksum, dict)],
        updates(),
        false,
    ));
    assert_eq!(report.refs.len(), 2);
    let expected = vec![
        ed25519_signature(SECRET_B64, &commit.bytes),
        ed25519_signature(SERVER_SECRET_B64, &commit.bytes),
        ed25519_signature(SECOND_SERVER_SECRET_B64, &commit.bytes),
    ];
    let stored = || {
        let dict = block_on(repo.read_commit_detached_metadata(&commit.checksum))
            .unwrap()
            .unwrap();
        signatures(&dict, ED25519_KEY)
    };
    assert_eq!(
        stored(),
        expected,
        "the client key, then each server key once"
    );

    let again = vec![
        update(
            "a",
            Expected::Commit(commit.checksum),
            Some(commit.checksum),
        ),
        update(
            "b",
            Expected::Commit(commit.checksum),
            Some(commit.checksum),
        ),
    ];
    committed(push(&repo, &policy, &[], &[], again, false));
    assert_eq!(
        stored(),
        expected,
        "a key that signed the commit signs no more"
    );
}

/// Two key groups that name one key file give two server signers that hold
/// one key. The commit gets one signature of that key.
#[test]
fn two_key_groups_with_one_key_file_sign_once() {
    let tmp = TmpDir::new("recv-one-key-twice");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let key = tmp.path().join("server.ed25519");
    std::fs::write(&key, format!("{SERVER_SECRET_B64}\n")).unwrap();
    let group = |name: &str| {
        format!(
            "[ex-ostrya key \"{name}\"]\ntype=ed25519\nsecret-key-file={}\n",
            key.display()
        )
    };
    let config = repo.path().join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str(&format!(
        "[ex-ostrya client \"c\"]\nauth=ssh:c\nallow=w:**\nsign=first;second\n{}{}",
        group("first"),
        group("second")
    ));
    std::fs::write(&config, text).unwrap();
    let repo = block_on(Repo::open(repo.path())).unwrap();
    let policies = block_on(ReceivePolicies::from_config(&repo)).unwrap();
    let policy = policies.get("c").unwrap();
    assert_eq!(policy.signers.len(), 2);
    let commit = build_commit(None, "signed once", no_metadata(), &[]);
    let mut objects = tree_objects();
    objects.push(commit.clone());
    committed(push(
        &repo,
        policy,
        &objects,
        &[],
        vec![update("main", Expected::Absent, Some(commit.checksum))],
        false,
    ));
    let dict = block_on(repo.read_commit_detached_metadata(&commit.checksum))
        .unwrap()
        .unwrap();
    assert_eq!(
        signatures(&dict, ED25519_KEY),
        vec![ed25519_signature(SERVER_SECRET_B64, &commit.bytes)]
    );
}

// ---------------------------------------------------------------------------
// Dependencies.
// ---------------------------------------------------------------------------

/// The field 2 entry `name` that names `commit`.
fn entry<'a>(name: &'a str, commit: &'a Obj) -> Field2Entry<'a> {
    (name, &commit.checksum.as_bytes()[..])
}

/// The objects of the fixture tree, then `commits`.
fn with_tree(commits: &[&Obj]) -> Vec<Obj> {
    let mut objects = tree_objects();
    objects.extend(commits.iter().map(|commit| (*commit).clone()));
    objects
}

/// The detached metadata of `commit` with a signature of the key
/// [`SECRET_B64`].
fn client_signed(commit: &Obj) -> (Checksum, Vec<u8>) {
    (commit.checksum, signed_dict(&commit.bytes, &[SECRET_B64]))
}

/// A policy that needs a signature of the key [`SECRET_B64`] on each commit
/// that it verifies.
fn verify_policy() -> ReceivePolicy {
    ReceivePolicy {
        verify: ReceiveVerify::Keys(trust(SECRET_B64)),
        ..policy()
    }
}

fn refs(repo: &Repo) -> Vec<(String, Checksum)> {
    block_on(repo.list_refs(None)).unwrap()
}

/// A staged dependency of a new commit gets no verification. A dependency
/// with no dict passes and gets no dict. A dependency with a signature of a
/// key that the rule does not trust passes, and keeps that signature. The
/// dependency gets no ref.
#[test]
fn an_unsigned_dependency_is_accepted() {
    let dep = build_commit(None, "dependency", no_metadata(), &[]);
    let target = build_commit(None, "target", no_metadata(), &[entry("lib/d", &dep)]);
    let objects = with_tree(&[&dep, &target]);
    let updates = || vec![update("main", Expected::Absent, Some(target.checksum))];

    let tmp = TmpDir::new("recv-dep-unsigned");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    committed(push(
        &repo,
        &verify_policy(),
        &objects,
        &[client_signed(&target)],
        updates(),
        false,
    ));
    assert!(!commit_meta_path(&repo, &dep.checksum).exists());
    assert_eq!(refs(&repo), [("main".to_owned(), target.checksum)]);

    let tmp = TmpDir::new("recv-dep-untrusted");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let untrusted = (dep.checksum, signed_dict(&dep.bytes, &[OTHER_SECRET_B64]));
    committed(push(
        &repo,
        &verify_policy(),
        &objects,
        &[client_signed(&target), untrusted],
        updates(),
        false,
    ));
    assert_eq!(
        ed25519_signatures(&repo, &dep.checksum),
        [ed25519_signature(OTHER_SECRET_B64, &dep.bytes)]
    );
    assert_eq!(refs(&repo), [("main".to_owned(), target.checksum)]);
}

/// A dependency that only a staged parent of a new commit names gets no
/// verification. The parent itself needs no signature either.
#[test]
fn a_dependency_of_a_staged_parent_gets_no_rule() {
    let dep = build_commit(None, "dependency", no_metadata(), &[]);
    let parent = build_commit(None, "parent", no_metadata(), &[entry("lib/d", &dep)]);
    let target = build_commit(Some(parent.checksum), "target", no_metadata(), &[]);
    let tmp = TmpDir::new("recv-dep-parent");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    committed(push(
        &repo,
        &verify_policy(),
        &with_tree(&[&dep, &parent, &target]),
        &[client_signed(&target)],
        vec![update("main", Expected::Absent, Some(target.checksum))],
        false,
    ));
    assert!(!commit_meta_path(&repo, &dep.checksum).exists());
    assert!(!commit_meta_path(&repo, &parent.checksum).exists());
}

/// A staged commit that no update names and that no parent chain reaches,
/// and the staged dependency that its field 2 names, get the completeness
/// check alone: no verification and no server signature.
#[test]
fn a_staged_commit_outside_each_history_gets_no_rule() {
    let dep = build_commit(None, "dependency", no_metadata(), &[]);
    let other = build_commit(None, "other", no_metadata(), &[entry("lib/d", &dep)]);
    let target = build_commit(None, "target", no_metadata(), &[]);
    let policy = ReceivePolicy {
        signers: vec![server_signer(SERVER_SECRET_B64)],
        ..verify_policy()
    };
    let tmp = TmpDir::new("recv-dep-outside");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    committed(push(
        &repo,
        &policy,
        &with_tree(&[&dep, &other, &target]),
        &[client_signed(&target)],
        vec![update("main", Expected::Absent, Some(target.checksum))],
        false,
    ));
    assert!(!commit_meta_path(&repo, &dep.checksum).exists());
    assert!(!commit_meta_path(&repo, &other.checksum).exists());
    assert_eq!(
        ed25519_signatures(&repo, &target.checksum),
        [
            ed25519_signature(SECRET_B64, &target.bytes),
            ed25519_signature(SERVER_SECRET_B64, &target.bytes),
        ]
    );
}

/// A dependency of a new commit or of a staged parent that is neither staged
/// nor held is `missing-objects`. The error lists each such dependency, in
/// the order of the commits that name them.
#[test]
fn absent_dependencies_are_missing_objects_together() {
    let first = build_commit(None, "first dependency", no_metadata(), &[]);
    let second = build_commit(None, "second dependency", no_metadata(), &[]);
    let parent = build_commit(None, "parent", no_metadata(), &[entry("lib/b", &second)]);
    let target = build_commit(
        Some(parent.checksum),
        "target",
        no_metadata(),
        &[entry("lib/a", &first)],
    );
    let tmp = TmpDir::new("recv-dep-absent");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let before = snapshot(&repo);
    let error = refused(
        push(
            &repo,
            &policy(),
            &with_tree(&[&parent, &target]),
            &[],
            vec![update("main", Expected::Absent, Some(target.checksum))],
            false,
        ),
        ErrorCode::MissingObjects,
    );
    assert_eq!(
        error.missing,
        [
            ObjectName::new(first.checksum, ObjectType::Commit),
            ObjectName::new(second.checksum, ObjectType::Commit),
        ]
    );
    assert!(
        error
            .message
            .contains("2 objects that the staged commits name as dependencies"),
        "{}",
        error.message
    );
    assert_unchanged(&repo, &before);
}

/// An entry of field 2 with an empty name, in a new commit, or with a
/// checksum that is not 32 bytes, in a staged parent, is `protocol`. The
/// message names the commit that holds the entry.
#[test]
fn a_defective_field_2_entry_is_protocol() {
    let dep = build_commit(None, "dependency", no_metadata(), &[]);
    let empty = build_commit(None, "empty name", no_metadata(), &[entry("", &dep)]);
    let short = build_commit(None, "short", no_metadata(), &[("lib/s", &[7; 31])]);
    let over_short = build_commit(Some(short.checksum), "over short", no_metadata(), &[]);
    let cases = [
        (
            vec![&dep, &empty],
            empty.checksum,
            format!(
                "related commits in field 2 of commit {}: entry 0 has an empty name",
                empty.checksum
            ),
        ),
        (
            vec![&short, &over_short],
            over_short.checksum,
            format!(
                "related commits in field 2 of commit {}: entry 0 (lib/s) has a checksum of 31 \
                 bytes, not 32",
                short.checksum
            ),
        ),
    ];
    for (commits, target, text) in cases {
        let tmp = TmpDir::new("recv-dep-defect");
        let repo = new_repo(&tmp, RepoMode::Archive, "");
        let before = snapshot(&repo);
        let error = refused(
            push(
                &repo,
                &policy(),
                &with_tree(&commits),
                &[],
                vec![update("main", Expected::Absent, Some(target))],
                false,
            ),
            ErrorCode::Protocol,
        );
        assert_eq!(error.message, text);
        assert_unchanged(&repo, &before);
    }
}

/// A dependency whose own field 2 is not empty is `protocol`, for a staged
/// dependency and for a dependency that the repository holds.
#[test]
fn a_nested_dependency_is_protocol() {
    let inner = build_commit(None, "inner", no_metadata(), &[]);
    let dep = build_commit(None, "dependency", no_metadata(), &[entry("lib/i", &inner)]);
    let target = build_commit(None, "target", no_metadata(), &[entry("lib/d", &dep)]);
    let tmp = TmpDir::new("recv-dep-nested");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let before = snapshot(&repo);
    let error = refused(
        push(
            &repo,
            &policy(),
            &with_tree(&[&inner, &dep, &target]),
            &[],
            vec![update("main", Expected::Absent, Some(target.checksum))],
            false,
        ),
        ErrorCode::Protocol,
    );
    assert_eq!(
        error.message,
        format!(
            "related commits in field 2 of commit {}: dependency lib/d names commit {}, which \
             has dependencies of its own",
            target.checksum, dep.checksum
        )
    );
    assert_unchanged(&repo, &before);

    let tmp = TmpDir::new("recv-dep-nested-held");
    let repo = repo_with_fixture(&tmp, RepoMode::Archive, "");
    let held = block_on(store_with_field2(
        &repo,
        &fixture_commit(),
        &[("lib/x", &[7; 32])],
    ));
    let target = build_commit(
        None,
        "target",
        no_metadata(),
        &[("lib/h", &held.as_bytes()[..])],
    );
    let before = snapshot(&repo);
    let error = refused(
        push(
            &repo,
            &policy(),
            std::slice::from_ref(&target),
            &[],
            vec![update("main", Expected::Absent, Some(target.checksum))],
            false,
        ),
        ErrorCode::Protocol,
    );
    assert!(
        error.message.contains(&format!(
            "dependency lib/h names commit {held}, which has dependencies of its own"
        )),
        "{}",
        error.message
    );
    assert_unchanged(&repo, &before);
}

/// A dependency that the repository holds complete passes with no
/// verification, and the server does not sign it: its detached metadata
/// stays as it was.
#[test]
fn a_held_dependency_gets_no_check_and_no_signature() {
    let dep = build_commit(None, "dependency", no_metadata(), &[]);
    let target = build_commit(None, "target", no_metadata(), &[entry("lib/d", &dep)]);
    let tmp = TmpDir::new("recv-dep-held");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    committed(push(
        &repo,
        &policy(),
        &with_tree(&[&dep]),
        &[],
        vec![update("dep", Expected::Absent, Some(dep.checksum))],
        false,
    ));
    assert!(!commit_meta_path(&repo, &dep.checksum).exists());
    let policy = ReceivePolicy {
        signers: vec![server_signer(SERVER_SECRET_B64)],
        ..verify_policy()
    };
    committed(push(
        &repo,
        &policy,
        std::slice::from_ref(&target),
        &[client_signed(&target)],
        vec![update("main", Expected::Absent, Some(target.checksum))],
        false,
    ));
    assert!(!commit_meta_path(&repo, &dep.checksum).exists());
    assert_eq!(
        ed25519_signatures(&repo, &target.checksum),
        [
            ed25519_signature(SECRET_B64, &target.bytes),
            ed25519_signature(SERVER_SECRET_B64, &target.bytes),
        ]
    );
}

/// A dependency that the repository holds and marks partial is
/// `missing-objects`, with no object listed.
#[test]
fn a_partial_held_dependency_is_missing_objects() {
    let dep = build_commit(None, "dependency", no_metadata(), &[]);
    let target = build_commit(None, "target", no_metadata(), &[entry("lib/d", &dep)]);
    let tmp = TmpDir::new("recv-dep-partial");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    committed(push(
        &repo,
        &policy(),
        &with_tree(&[&dep]),
        &[],
        vec![update("dep", Expected::Absent, Some(dep.checksum))],
        false,
    ));
    mark_partial(&repo, &dep.checksum);
    let before = snapshot(&repo);
    let error = refused(
        push(
            &repo,
            &policy(),
            std::slice::from_ref(&target),
            &[],
            vec![update("main", Expected::Absent, Some(target.checksum))],
            false,
        ),
        ErrorCode::MissingObjects,
    );
    assert!(error.missing.is_empty(), "{:?}", error.missing);
    assert_eq!(
        error.message,
        format!(
            "related commits in field 2 of commit {}: dependency lib/d names commit {}, which \
             is partial",
            target.checksum, dep.checksum
        )
    );
    assert_unchanged(&repo, &before);
}

/// The repository holds a dependency with a signed dict. A session sends
/// the commit object of the dependency again, a new commit whose field 2
/// names it, and a dict for it with another signature. The server drops that
/// dict, so the stored dict keeps its bytes. A dict for a held commit that no
/// field 2 of a commit of the session names stays `protocol`.
#[test]
fn a_dict_for_a_held_dependency_is_dropped() {
    let dep = build_commit(None, "dependency", no_metadata(), &[]);
    let lone = build_commit(None, "lone", no_metadata(), &[]);
    let target = build_commit(None, "target", no_metadata(), &[entry("lib/d", &dep)]);
    let second = build_commit(None, "second", no_metadata(), &[entry("lib/d", &dep)]);
    let tmp = TmpDir::new("recv-dep-held-dict");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    committed(push(
        &repo,
        &policy(),
        &with_tree(&[&dep, &lone]),
        &[client_signed(&dep)],
        vec![
            update("dep", Expected::Absent, Some(dep.checksum)),
            update("lone", Expected::Absent, Some(lone.checksum)),
        ],
        false,
    ));
    let held = std::fs::read(commit_meta_path(&repo, &dep.checksum)).unwrap();

    let other = (dep.checksum, signed_dict(&dep.bytes, &[OTHER_SECRET_B64]));
    committed(push(
        &repo,
        &policy(),
        &[dep.clone(), target.clone()],
        std::slice::from_ref(&other),
        vec![update("main", Expected::Absent, Some(target.checksum))],
        false,
    ));
    assert_eq!(
        std::fs::read(commit_meta_path(&repo, &dep.checksum)).unwrap(),
        held
    );
    assert_eq!(
        ed25519_signatures(&repo, &dep.checksum),
        [ed25519_signature(SECRET_B64, &dep.bytes)]
    );
    assert_eq!(
        ref_file(&repo, "refs/heads/main"),
        Some(format!("{}\n", target.checksum))
    );

    let before = snapshot(&repo);
    let error = refused(
        push(
            &repo,
            &policy(),
            std::slice::from_ref(&second),
            &[other, client_signed(&lone)],
            vec![update("second", Expected::Absent, Some(second.checksum))],
            false,
        ),
        ErrorCode::Protocol,
    );
    assert!(
        error.message.contains(&lone.checksum.to_string()),
        "{}",
        error.message
    );
    assert_unchanged(&repo, &before);
}

/// A staged dependency that two new commits name gets no server signature.
/// Each new commit gets each server key of its rule once, also a key that the
/// list holds two times.
#[test]
fn a_dependency_of_two_targets_gets_no_server_signature() {
    let dep = build_commit(None, "dependency", no_metadata(), &[]);
    let a = build_commit(None, "a", no_metadata(), &[entry("lib/d", &dep)]);
    let b = build_commit(None, "b", no_metadata(), &[entry("lib/d", &dep)]);
    let shared = server_signer(SECOND_SERVER_SECRET_B64);
    let policy = ReceivePolicy {
        signers: vec![server_signer(SERVER_SECRET_B64), shared.clone(), shared],
        ..policy()
    };
    let tmp = TmpDir::new("recv-dep-two-targets");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    committed(push(
        &repo,
        &policy,
        &with_tree(&[&dep, &a, &b]),
        &[],
        vec![
            update("a", Expected::Absent, Some(a.checksum)),
            update("b", Expected::Absent, Some(b.checksum)),
        ],
        false,
    ));
    assert!(!commit_meta_path(&repo, &dep.checksum).exists());
    for commit in [&a, &b] {
        assert_eq!(
            ed25519_signatures(&repo, &commit.checksum),
            [
                ed25519_signature(SERVER_SECRET_B64, &commit.bytes),
                ed25519_signature(SECOND_SERVER_SECRET_B64, &commit.bytes),
            ]
        );
    }
}

/// A staged dependency that is also a new commit passes the verification of
/// its update, and the refusal names it as a new commit. It gets each server
/// key of its update once.
#[test]
fn a_dependency_that_is_also_a_target_is_signed_once() {
    let dep = build_commit(None, "dependency", no_metadata(), &[]);
    let target = build_commit(None, "target", no_metadata(), &[entry("lib/d", &dep)]);
    let policy = ReceivePolicy {
        signers: vec![server_signer(SERVER_SECRET_B64)],
        ..verify_policy()
    };
    let updates = || {
        vec![
            update("main", Expected::Absent, Some(target.checksum)),
            update("dep", Expected::Absent, Some(dep.checksum)),
        ]
    };
    let tmp = TmpDir::new("recv-dep-target");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let before = snapshot(&repo);
    let error = refused(
        push(
            &repo,
            &policy,
            &with_tree(&[&dep, &target]),
            &[client_signed(&target)],
            updates(),
            false,
        ),
        ErrorCode::SignatureRequired,
    );
    let subject = format!("commit {}: ", dep.checksum);
    assert!(error.message.starts_with(&subject), "{}", error.message);
    assert_unchanged(&repo, &before);

    committed(push(
        &repo,
        &policy,
        &with_tree(&[&dep, &target]),
        &[client_signed(&target), client_signed(&dep)],
        updates(),
        false,
    ));
    assert_eq!(
        ed25519_signatures(&repo, &dep.checksum),
        [
            ed25519_signature(SECRET_B64, &dep.bytes),
            ed25519_signature(SERVER_SECRET_B64, &dep.bytes),
        ]
    );
}

/// Stores the commit object `commit` in `repo`, with no check of its field 2
/// and no object of its tree.
fn hold_commit(repo: &Repo, commit: &Obj) {
    block_on(async {
        let txn = repo.transaction().await.unwrap();
        txn.write_metadata(ObjectType::Commit, Some(&commit.checksum), &commit.bytes)
            .await
            .unwrap();
        txn.commit().await.unwrap();
    });
}

fn marker(repo: &Repo, commit: &Checksum) -> PathBuf {
    repo.path().join(format!("state/{commit}.commitpartial"))
}

/// The repository holds a new commit with a partial marker, and the session
/// sends its tree. Field 2 of the commit gets the checks of a staged commit:
/// an absent dependency is `missing-objects`, and a defective entry and a
/// nested dependency are `protocol`. The session publishes nothing, and the
/// marker stays.
#[test]
fn a_partial_held_target_gets_the_dependency_checks() {
    let dep = build_commit(None, "dependency", no_metadata(), &[]);
    let nested = build_commit(None, "nested", no_metadata(), &[("lib/x", &[7; 32])]);
    let absent = build_commit(None, "absent", no_metadata(), &[entry("lib/d", &dep)]);
    let short = build_commit(None, "short", no_metadata(), &[("lib/s", &[7; 31])]);
    let over_nested = build_commit(
        None,
        "over nested",
        no_metadata(),
        &[entry("lib/n", &nested)],
    );
    let cases = [
        (&absent, ErrorCode::MissingObjects, None),
        (
            &short,
            ErrorCode::Protocol,
            Some(format!(
                "related commits in field 2 of commit {}: entry 0 (lib/s) has a checksum of 31 \
                 bytes, not 32",
                short.checksum
            )),
        ),
        (
            &over_nested,
            ErrorCode::Protocol,
            Some(format!(
                "related commits in field 2 of commit {}: dependency lib/n names commit {}, \
                 which has dependencies of its own",
                over_nested.checksum, nested.checksum
            )),
        ),
    ];
    for (target, code, text) in cases {
        let tmp = TmpDir::new("recv-dep-partial-target");
        let repo = new_repo(&tmp, RepoMode::Archive, "");
        hold_commit(&repo, &nested);
        hold_commit(&repo, target);
        mark_partial(&repo, &target.checksum);
        let before = snapshot(&repo);
        let error = refused(
            push(
                &repo,
                &policy(),
                &tree_objects(),
                &[],
                vec![update("main", Expected::Absent, Some(target.checksum))],
                false,
            ),
            code,
        );
        match text {
            None => assert_eq!(
                error.missing,
                [ObjectName::new(dep.checksum, ObjectType::Commit)]
            ),
            Some(text) => assert_eq!(error.message, text),
        }
        assert!(marker(&repo, &target.checksum).exists(), "the marker stays");
        assert_unchanged(&repo, &before);
    }
}

/// The repository holds a dependency with a partial marker. A session that
/// sends its tree and names it as a new commit counts it as complete: the
/// session commits, and the marker goes.
#[test]
fn a_partial_held_dependency_that_is_a_new_commit_counts_as_complete() {
    let dep = build_commit(None, "dependency", no_metadata(), &[]);
    let target = build_commit(None, "target", no_metadata(), &[entry("lib/d", &dep)]);
    let tmp = TmpDir::new("recv-dep-partial-new");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    hold_commit(&repo, &dep);
    mark_partial(&repo, &dep.checksum);
    committed(push(
        &repo,
        &policy(),
        &with_tree(&[&target]),
        &[],
        vec![
            update("dep", Expected::Absent, Some(dep.checksum)),
            update("main", Expected::Absent, Some(target.checksum)),
        ],
        false,
    ));
    assert!(!marker(&repo, &dep.checksum).exists(), "the marker goes");
    assert_eq!(
        refs(&repo),
        [
            ("dep".to_owned(), dep.checksum),
            ("main".to_owned(), target.checksum),
        ]
    );
}

/// Field 2 of a new commit that the repository holds gives no rule to a
/// staged dependency: the dependency gets no verification and no server
/// signature.
#[test]
fn a_held_target_gives_no_rule_to_a_staged_dependency() {
    let dep = build_commit(None, "dependency", no_metadata(), &[]);
    let target = build_commit(None, "target", no_metadata(), &[entry("lib/d", &dep)]);
    let policy = ReceivePolicy {
        signers: vec![server_signer(SERVER_SECRET_B64)],
        ..verify_policy()
    };
    let tmp = TmpDir::new("recv-dep-held-target");
    let repo = repo_with_fixture(&tmp, RepoMode::Archive, "");
    hold_commit(&repo, &target);
    committed(push(
        &repo,
        &policy,
        std::slice::from_ref(&dep),
        &[client_signed(&target)],
        vec![update("main", Expected::Absent, Some(target.checksum))],
        false,
    ));
    assert!(!commit_meta_path(&repo, &dep.checksum).exists());
    assert_eq!(
        ed25519_signatures(&repo, &target.checksum),
        [
            ed25519_signature(SECRET_B64, &target.bytes),
            ed25519_signature(SERVER_SECRET_B64, &target.bytes),
        ]
    );
}

/// A staged dependency with a partial marker that no object backs counts as
/// complete, and the session removes the marker.
#[test]
fn a_staged_dependency_with_a_stale_marker_counts_as_complete() {
    let dep = build_commit(None, "dependency", no_metadata(), &[]);
    let target = build_commit(None, "target", no_metadata(), &[entry("lib/d", &dep)]);
    let tmp = TmpDir::new("recv-dep-stale-marker");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    mark_partial(&repo, &dep.checksum);
    committed(push(
        &repo,
        &policy(),
        &with_tree(&[&dep, &target]),
        &[],
        vec![update("main", Expected::Absent, Some(target.checksum))],
        false,
    ));
    assert!(!marker(&repo, &dep.checksum).exists(), "the marker goes");
}

/// The refusal of a nested dependency that two new commits name names the
/// new commit of the first update, also when its checksum sorts last.
#[test]
fn a_nested_dependency_refusal_names_the_first_new_commit_in_update_order() {
    let inner = build_commit(None, "inner", no_metadata(), &[]);
    let dep = build_commit(None, "dependency", no_metadata(), &[entry("lib/i", &inner)]);
    let a = build_commit(None, "a", no_metadata(), &[entry("lib/d", &dep)]);
    let b = build_commit(None, "b", no_metadata(), &[entry("lib/d", &dep)]);
    let (first, last) = if a.checksum > b.checksum {
        (a, b)
    } else {
        (b, a)
    };
    let tmp = TmpDir::new("recv-dep-first-target");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let before = snapshot(&repo);
    let error = refused(
        push(
            &repo,
            &policy(),
            &with_tree(&[&inner, &dep, &first, &last]),
            &[],
            vec![
                update("x", Expected::Absent, Some(first.checksum)),
                update("y", Expected::Absent, Some(last.checksum)),
            ],
            false,
        ),
        ErrorCode::Protocol,
    );
    assert_eq!(
        error.message,
        format!(
            "related commits in field 2 of commit {}: dependency lib/d names commit {}, which \
             has dependencies of its own",
            first.checksum, dep.checksum
        )
    );
    assert!(
        !error.message.contains(&last.checksum.to_string()),
        "{}",
        error.message
    );
    assert_unchanged(&repo, &before);
}

/// A staged parent that field 2 of its new commit names gets no
/// verification and no server signature.
#[test]
fn a_staged_parent_that_field_2_names_gets_no_rule() {
    let parent = build_commit(None, "parent", no_metadata(), &[]);
    let target = build_commit(
        Some(parent.checksum),
        "target",
        no_metadata(),
        &[entry("lib/p", &parent)],
    );
    let policy = ReceivePolicy {
        signers: vec![server_signer(SERVER_SECRET_B64)],
        ..verify_policy()
    };
    let tmp = TmpDir::new("recv-dep-parent-named");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    committed(push(
        &repo,
        &policy,
        &with_tree(&[&parent, &target]),
        &[client_signed(&target)],
        vec![update("main", Expected::Absent, Some(target.checksum))],
        false,
    ));
    assert!(!commit_meta_path(&repo, &parent.checksum).exists());
    assert_eq!(
        ed25519_signatures(&repo, &target.checksum),
        [
            ed25519_signature(SECRET_B64, &target.bytes),
            ed25519_signature(SERVER_SECRET_B64, &target.bytes),
        ]
    );
}

// ---------------------------------------------------------------------------
// The checks under the lock.
// ---------------------------------------------------------------------------

/// A ref that is not in the state that the update expects is `ref-mismatch`.
/// The detail holds the current state.
#[test]
fn an_expected_state_that_differs_is_ref_mismatch() {
    let tmp = TmpDir::new("recv-mismatch");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let before = snapshot(&repo);
    let error = refused(
        push(
            &repo,
            &policy(),
            &fixture_objects(Encoding::Raw),
            &[],
            vec![update(
                "test/main",
                Expected::Commit(sha(b"another commit")),
                Some(fixture_commit()),
            )],
            false,
        ),
        ErrorCode::RefMismatch,
    );
    assert_eq!(error.current.unwrap().commit, None);
    assert_unchanged(&repo, &before);

    let tmp = TmpDir::new("recv-mismatch-present");
    let repo = repo_with_fixture(&tmp, RepoMode::Archive, "");
    let before = snapshot(&repo);
    let error = refused(
        push(
            &repo,
            &policy(),
            &[],
            &[],
            vec![update(
                "test/main",
                Expected::Absent,
                Some(fixture_commit()),
            )],
            false,
        ),
        ErrorCode::RefMismatch,
    );
    assert_eq!(error.current.unwrap().commit, Some(fixture_commit()));
    assert_unchanged(&repo, &before);
}

/// An update whose new commit does not descend from the current one is
/// `non-fast-forward`. With `w`, `force` does not change it, and with `wd`,
/// an update without `force` is refused too. With `wd` and `force`, the update
/// passes. A chain that reaches a commit that the repository does not hold
/// proves no fast-forward. A child of the current commit is a fast-forward.
#[test]
fn a_non_ancestor_is_non_fast_forward() {
    let unrelated = build_commit(None, "unrelated", no_metadata(), &[]);
    let orphan = build_commit(Some(sha(b"an absent parent")), "orphan", no_metadata(), &[]);
    let child = build_commit(Some(fixture_commit()), "child", no_metadata(), &[]);
    let forced = || policy_allowing(&["wd:**"]);
    let current = Expected::Commit(fixture_commit());
    for commit in [&unrelated, &orphan] {
        for (policy, force) in [(policy(), false), (policy(), true), (forced(), false)] {
            let tmp = TmpDir::new("recv-nff");
            let repo = repo_with_fixture(&tmp, RepoMode::Archive, "");
            write_ref(&repo, "main", &fixture_commit());
            let before = snapshot(&repo);
            refused(
                push(
                    &repo,
                    &policy,
                    std::slice::from_ref(commit),
                    &[],
                    vec![update("main", current, Some(commit.checksum))],
                    force,
                ),
                ErrorCode::NonFastForward,
            );
            assert_unchanged(&repo, &before);
        }
        // The check runs for `Any` too.
        let tmp = TmpDir::new("recv-nff-any");
        let repo = repo_with_fixture(&tmp, RepoMode::Archive, "");
        write_ref(&repo, "main", &fixture_commit());
        refused(
            push(
                &repo,
                &policy(),
                std::slice::from_ref(commit),
                &[],
                vec![update("main", Expected::Any, Some(commit.checksum))],
                false,
            ),
            ErrorCode::NonFastForward,
        );
        // A forced update under `wd`.
        let report = committed(push(
            &repo,
            &forced(),
            std::slice::from_ref(commit),
            &[],
            vec![update("main", current, Some(commit.checksum))],
            true,
        ));
        assert_eq!(report.refs[0].old, Some(fixture_commit()));
        assert_eq!(report.refs[0].new, Some(commit.checksum));
    }
    let tmp = TmpDir::new("recv-ff");
    let repo = repo_with_fixture(&tmp, RepoMode::Archive, "");
    write_ref(&repo, "main", &fixture_commit());
    committed(push(
        &repo,
        &policy(),
        std::slice::from_ref(&child),
        &[],
        vec![update("main", current, Some(child.checksum))],
        false,
    ));
    assert_eq!(
        ref_file(&repo, "refs/heads/main"),
        Some(format!("{}\n", child.checksum))
    );
}

/// The parent chain of a new branch can stop at any depth. On a branch that
/// exists, a chain that reaches the current commit is a fast-forward, also
/// when the parents before the current commit are absent.
#[test]
fn a_partial_history_is_a_fast_forward_when_it_reaches_the_tip() {
    let tmp = TmpDir::new("recv-partial");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    // A commit whose parent the repository never holds.
    let base = build_commit(Some(sha(b"an absent parent")), "base", no_metadata(), &[]);
    let mut objects = tree_objects();
    objects.push(base.clone());
    committed(push(
        &repo,
        &policy(),
        &objects,
        &[],
        vec![update("main", Expected::Absent, Some(base.checksum))],
        false,
    ));
    // A chain of two commits on top of it. The session sends both.
    let middle = build_commit(Some(base.checksum), "middle", no_metadata(), &[]);
    let top = build_commit(Some(middle.checksum), "top", no_metadata(), &[]);
    committed(push(
        &repo,
        &policy(),
        &[middle.clone(), top.clone()],
        &[],
        vec![update(
            "main",
            Expected::Commit(base.checksum),
            Some(top.checksum),
        )],
        false,
    ));
    assert_eq!(
        ref_file(&repo, "refs/heads/main"),
        Some(format!("{}\n", top.checksum))
    );
    // A chain that stops at an absent commit before the tip is refused.
    let stray = build_commit(
        Some(sha(b"another absent parent")),
        "stray",
        no_metadata(),
        &[],
    );
    let before = snapshot(&repo);
    refused(
        push(
            &repo,
            &policy(),
            std::slice::from_ref(&stray),
            &[],
            vec![update("main", Expected::Any, Some(stray.checksum))],
            false,
        ),
        ErrorCode::NonFastForward,
    );
    assert_unchanged(&repo, &before);
}

/// A tag is a ref that an update creates and does not move. With `t` and no
/// `w`, an update creates an absent ref. A write to the ref after that is
/// `ref-mismatch` in each expected state, also with the current commit. With
/// `w` and `t`, the update moves the ref.
#[test]
fn t_creates_a_ref_and_never_moves_it() {
    let tmp = TmpDir::new("recv-tag");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let tag = policy_allowing(&["t:tags/**"]);
    let first = build_commit(None, "first", no_metadata(), &[]);
    let second = build_commit(Some(first.checksum), "second", no_metadata(), &[]);
    let mut objects = tree_objects();
    objects.push(first.clone());
    committed(push(
        &repo,
        &tag,
        &objects,
        &[],
        vec![update("tags/v1", Expected::Absent, Some(first.checksum))],
        false,
    ));
    let before = snapshot(&repo);
    let current = Expected::Commit(first.checksum);
    for (expected, new) in [
        (current, &first),
        (Expected::Any, &first),
        (current, &second),
        (Expected::Any, &second),
    ] {
        let error = refused(
            push(
                &repo,
                &tag,
                std::slice::from_ref(new),
                &[],
                vec![update("tags/v1", expected, Some(new.checksum))],
                true,
            ),
            ErrorCode::RefMismatch,
        );
        assert_eq!(
            error.current.unwrap().commit,
            Some(first.checksum),
            "{expected:?}"
        );
        assert_unchanged(&repo, &before);
    }
    // `t` gives no right outside its pattern.
    refused(
        push(
            &repo,
            &policy_allowing(&["t:tags/**", "r:**"]),
            std::slice::from_ref(&first),
            &[],
            vec![update("main", Expected::Absent, Some(first.checksum))],
            false,
        ),
        ErrorCode::RefDenied,
    );
    committed(push(
        &repo,
        &policy_allowing(&["wt:tags/**"]),
        std::slice::from_ref(&second),
        &[],
        vec![update("tags/v1", current, Some(second.checksum))],
        false,
    ));
    assert_eq!(
        ref_file(&repo, "refs/heads/tags/v1"),
        Some(format!("{}\n", second.checksum))
    );
}

/// An update with `t` and no `w` to a ref that is present is `ref-mismatch`
/// with no walk of the parent chain. The parent of the new commit is a stored
/// commit that does not parse: a walk reads it and fails with `internal`, as
/// the same update with `wt` shows.
#[test]
fn t_refuses_a_present_ref_with_no_walk_of_the_parent_chain() {
    let tmp = TmpDir::new("recv-tag-walk");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let first = build_commit(None, "first", no_metadata(), &[]);
    let mut objects = tree_objects();
    objects.push(first.clone());
    committed(push(
        &repo,
        &policy_allowing(&["t:tags/**"]),
        &objects,
        &[],
        vec![update("tags/v1", Expected::Absent, Some(first.checksum))],
        false,
    ));
    let garbage = b"not a gvariant commit".to_vec();
    let bad = sha(&garbage);
    plant_object(&repo, ObjectType::Commit, &bad, &garbage);
    let top = build_commit(Some(bad), "top", no_metadata(), &[]);
    let before = snapshot(&repo);
    let error = refused(
        push(
            &repo,
            &policy_allowing(&["t:tags/**"]),
            std::slice::from_ref(&top),
            &[],
            vec![update("tags/v1", Expected::Any, Some(top.checksum))],
            false,
        ),
        ErrorCode::RefMismatch,
    );
    assert_eq!(error.current.unwrap().commit, Some(first.checksum));
    assert_unchanged(&repo, &before);
    let error = refused(
        push(
            &repo,
            &policy_allowing(&["wt:tags/**"]),
            std::slice::from_ref(&top),
            &[],
            vec![update("tags/v1", Expected::Any, Some(top.checksum))],
            false,
        ),
        ErrorCode::Internal,
    );
    assert!(error.message.contains("does not parse"), "{error:?}");
    assert_unchanged(&repo, &before);
}

fn write_ref(repo: &Repo, name: &str, commit: &Checksum) {
    std::fs::write(
        repo.path().join("refs/heads").join(name),
        format!("{commit}\n"),
    )
    .unwrap();
}

/// A delete of a ref that is present needs `d`, else it is `delete-denied`.
/// A policy with `r` and `d` deletes the ref. A delete of an absent ref changes
/// nothing.
#[test]
fn a_delete_the_rule_refuses_is_delete_denied() {
    let tmp = TmpDir::new("recv-delete");
    let repo = repo_with_fixture(&tmp, RepoMode::Archive, "");
    let before = snapshot(&repo);
    let current = Expected::Commit(fixture_commit());
    refused(
        push(
            &repo,
            &policy(),
            &[],
            &[],
            vec![update("test/main", current, None)],
            false,
        ),
        ErrorCode::DeleteDenied,
    );
    assert_unchanged(&repo, &before);

    let report = committed(push(
        &repo,
        &policy(),
        &[],
        &[],
        vec![update("absent", Expected::Absent, None)],
        false,
    ));
    assert_eq!(
        report.refs,
        vec![RefOutcome {
            name: "absent".into(),
            old: None,
            new: None,
        }]
    );
    assert_eq!(snapshot(&repo), before);

    let report = committed(push(
        &repo,
        &policy_allowing(&["rd:test/**"]),
        &[],
        &[],
        vec![update("test/main", current, None)],
        false,
    ));
    assert_eq!(report.refs[0].old, Some(fixture_commit()));
    assert_eq!(report.refs[0].new, None);
    assert_eq!(ref_file(&repo, "refs/heads/test/main"), None);
}

/// A ref path that a ref write cannot replace is `ref-denied` under the lock,
/// before the session writes anything. The cases are:
///
/// - a path below a ref file
/// - a path that names a directory of refs
/// - two updates, of which one writes below the other
///
/// The other updates of the message write nothing either.
#[test]
fn a_ref_path_that_a_write_cannot_replace_is_ref_denied() {
    let commit = build_commit(None, "unbound", no_metadata(), &[]);
    let mut objects = tree_objects();
    objects.push(commit.clone());
    let new = Some(commit.checksum);
    let cases: Vec<(&str, Vec<&str>, &str)> = vec![
        ("y", vec!["a", "y/z"], "'y/z'"),
        ("y/z", vec!["a", "y"], "'y'"),
        ("", vec!["b", "b/c"], "'b/c'"),
    ];
    for (held, names, needle) in cases {
        let tmp = TmpDir::new("recv-ref-path");
        let repo = new_repo(&tmp, RepoMode::Archive, "");
        if !held.is_empty() {
            committed(push(
                &repo,
                &policy(),
                &objects,
                &[],
                vec![update(held, Expected::Absent, new)],
                false,
            ));
        }
        let before = snapshot(&repo);
        let updates = names
            .iter()
            .map(|name| update(name, Expected::Absent, new))
            .collect();
        let error = refused(
            push(&repo, &policy(), &objects, &[], updates, false),
            ErrorCode::RefDenied,
        );
        assert!(error.message.contains(needle), "{names:?}: {error:?}");
        assert_unchanged(&repo, &before);
    }
}

// ---------------------------------------------------------------------------
// Faults of the server.
// ---------------------------------------------------------------------------

/// An update lock that another process holds past `lock-timeout-secs` is
/// `internal`, with the text of the timeout.
#[test]
fn a_held_update_lock_is_internal() {
    let tmp = TmpDir::new("recv-update-lock");
    let repo = new_repo(&tmp, RepoMode::Archive, "lock-timeout-secs=0\n");
    let before = snapshot(&repo);
    let holder = foreign_holder(repo.path(), ".update.lock");
    let (result, reply) = push(
        &repo,
        &policy(),
        &fixture_objects(Encoding::Raw),
        &[],
        vec![update(
            "test/main",
            Expected::Absent,
            Some(fixture_commit()),
        )],
        false,
    );
    drop(holder);
    let error = reply.unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
    assert!(error.message.contains("timed out"), "{error:?}");
    assert!(
        matches!(result, Err(Error::LockTimeout { secs: 0 })),
        "{result:?}"
    );
    assert_unchanged(&repo, &before);
}

/// An `UpdateGuard` that another process holds makes the session wait at
/// `Commit`. The session completes after the holder releases the guard.
#[test]
fn a_session_waits_for_a_guard_of_another_process() {
    let tmp = TmpDir::new("recv-guard-wait");
    let repo = new_repo(&tmp, RepoMode::Archive, "lock-timeout-secs=30\n");
    let holder = guard_holder(repo.path());
    let releasing = repo.path().join(GUARD_RELEASING_MARKER);
    let root = repo.path().to_path_buf();
    // The releasing marker proves the order. The release waits only until the
    // session makes its staging directory, so the session starts before the
    // release.
    let release = std::thread::spawn(move || {
        let started = std::time::Instant::now();
        while staging_entries(&root).is_empty() {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(20),
                "the session never started"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        holder.release();
    });
    let report = committed(push(
        &repo,
        &policy(),
        &fixture_objects(Encoding::Raw),
        &[],
        vec![update(
            "test/main",
            Expected::Absent,
            Some(fixture_commit()),
        )],
        false,
    ));
    assert!(
        releasing.exists(),
        "the session committed before the release"
    );
    release.join().unwrap();
    assert_eq!(report.refs.len(), 1);
    assert_eq!(
        ref_file(&repo, "refs/heads/test/main"),
        Some(format!("{COMMIT}\n"))
    );
}

/// A policy that regenerates the summary, for the tests of the summary
/// step.
fn summary_policy() -> ReceivePolicy {
    ReceivePolicy {
        update_summary: true,
        ..policy()
    }
}

/// In a repository with a collection id and `lock-timeout-secs=0`, a session
/// that regenerates the summary and a later `regenerate_summary` both
/// complete. Neither waits for a lock that it holds itself.
#[test]
fn a_session_and_a_regeneration_complete_with_no_self_wait() {
    let tmp = TmpDir::new("recv-no-self-wait");
    let repo = new_repo(
        &tmp,
        RepoMode::Archive,
        "collection-id=org.example.C\nlock-timeout-secs=0\n",
    );
    let report = committed(push(
        &repo,
        &summary_policy(),
        &fixture_objects(Encoding::Raw),
        &[],
        vec![update(
            "test/main",
            Expected::Absent,
            Some(fixture_commit()),
        )],
        false,
    ));
    assert_eq!(report.warnings, vec![]);
    let first = block_on(repo.resolve_ref_tip("ostree-metadata"))
        .unwrap()
        .unwrap();
    block_on(repo.regenerate_summary(&SummaryOptions::default())).unwrap();
    let second = block_on(repo.resolve_ref_tip("ostree-metadata"))
        .unwrap()
        .unwrap();
    assert_ne!(first, second, "the regeneration refreshed the anchor");
    let summary = Summary::parse(&block_on(repo.read_summary()).unwrap().unwrap()).unwrap();
    assert_eq!(summary.lookup("ostree-metadata"), Some(second));
    assert_eq!(summary.lookup("test/main"), Some(fixture_commit()));
}

/// The anchor commits that `ostree-metadata` chains, from the tip back to the
/// root anchor.
fn anchor_chain(repo: &Repo) -> Vec<Checksum> {
    let mut chain = Vec::new();
    let mut next = block_on(repo.resolve_ref_tip("ostree-metadata")).unwrap();
    while let Some(anchor) = next {
        chain.push(anchor);
        let bytes = block_on(repo.load_object_bytes(ObjectType::Commit, &anchor)).unwrap();
        next = Commit::parse(&bytes).unwrap().parent;
    }
    chain
}

/// In a repository with a collection id, a session and two
/// `regenerate_summary` calls wait for one guard. All three complete after the
/// guard goes, and the three anchor commits chain. The parent of each anchor
/// is the anchor before it.
///
/// Each writer reads the parent of its anchor under the update lock. A writer
/// that reads the parent before its wait can chain onto an anchor that another
/// writer replaced.
#[test]
fn a_session_and_concurrent_regenerations_chain_their_anchors() {
    let tmp = TmpDir::new("recv-concurrent-regen");
    let repo = new_repo(
        &tmp,
        RepoMode::Archive,
        "collection-id=org.example.C\nlock-timeout-secs=30\n",
    );
    let objects = fixture_objects(Encoding::Raw);
    let names = vec!["test/main".to_string()];
    let updates = vec![update(
        "test/main",
        Expected::Absent,
        Some(fixture_commit()),
    )];
    let policy = summary_policy();
    let opts = SummaryOptions::default();
    let holder = guard_holder(repo.path());
    let root = repo.path().to_path_buf();
    // The session and each regeneration make their staging directory before
    // they wait for the update lock. The settle time covers the step from the
    // staging directory to the wait.
    let release = std::thread::spawn(move || {
        let started = std::time::Instant::now();
        while staging_entries(&root).len() < 3 {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(20),
                "the writers never reached the lock"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
        holder.release();
    });
    let (c, input, output) = connect();
    let (((result, reply), first), second) = block_on(futures_lite::future::zip(
        futures_lite::future::zip(
            futures_lite::future::zip(
                repo.receive(input, output, &policy),
                script(c, &names, None, &objects, &[], updates, false),
            ),
            repo.regenerate_summary(&opts),
        ),
        repo.regenerate_summary(&opts),
    ));
    release.join().unwrap();
    first.unwrap();
    second.unwrap();
    let report = committed((result, reply));
    assert_eq!(report.warnings, vec![]);
    assert_eq!(anchor_chain(&repo).len(), 3, "the three anchors chain");
    assert_eq!(
        ref_file(&repo, "refs/heads/test/main"),
        Some(format!("{COMMIT}\n"))
    );
}

/// Detached metadata that the repository stores and that does not parse fails
/// the merge on the server side. The error is `internal`, and the session
/// publishes nothing.
#[test]
fn a_corrupt_stored_commitmeta_is_internal() {
    let tmp = TmpDir::new("recv-corrupt-meta");
    let repo = repo_with_fixture(&tmp, RepoMode::Archive, "");
    std::fs::write(commit_meta_path(&repo, &fixture_commit()), b"\x01\x02\x03").unwrap();
    let before = snapshot(&repo);
    let (result, reply) = push(
        &repo,
        &policy(),
        &[],
        &[(fixture_commit(), signed_dict(b"x", &[SECRET_B64]))],
        vec![update(
            "test/main",
            Expected::Commit(fixture_commit()),
            Some(fixture_commit()),
        )],
        false,
    );
    assert_eq!(reply.unwrap_err().code, ErrorCode::Internal);
    assert!(
        result.is_err() && !matches!(result, Err(Error::Remote(_))),
        "{result:?}"
    );
    assert_unchanged(&repo, &before);
}

// ---------------------------------------------------------------------------
// Server signatures, the anchor commit, and the summary.
// ---------------------------------------------------------------------------

/// A GPG signature holds the time of its creation, so a second signature of
/// one key over one commit has other bytes. Two pushes of one commit under a
/// rule with a GPG server key leave one signature of that key.
#[cfg(feature = "sign-gpg")]
#[test]
fn two_pushes_with_a_gpg_server_key_leave_one_server_signature() {
    if !common::gnupg_available(&["gpg", "gpgconf"]) {
        eprintln!("skipping two_pushes_with_a_gpg_server_key_leave_one_server_signature: no GnuPG");
        return;
    }
    let tmp = TmpDir::new("recv-gpg-server");
    let home = common::receive::GnupgHome::new(
        &tmp.path().join("gnupg"),
        "Receive Server <server@example.org>",
    );
    let signer = ostrya::GpgSigner::new("server@example.org").with_homedir(&home.dir);
    let policy = ReceivePolicy {
        signers: vec![std::sync::Arc::new(
            block_on(ostrya::ServerSigner::gpg(signer)).unwrap(),
        )],
        ..policy()
    };
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    committed(push(
        &repo,
        &policy,
        &fixture_objects(Encoding::Raw),
        &[],
        vec![update(
            "test/main",
            Expected::Absent,
            Some(fixture_commit()),
        )],
        false,
    ));
    committed(push(
        &repo,
        &policy,
        &[],
        &[],
        vec![update("test/main", Expected::Any, Some(fixture_commit()))],
        false,
    ));
    let dict = block_on(repo.read_commit_detached_metadata(&fixture_commit()))
        .unwrap()
        .unwrap();
    assert_eq!(signatures(&dict, "ostree.gpgsigs").len(), 1);
    let verifier = ostrya::GpgVerifier::from_keyring_bytes([home.export()]).unwrap();
    let outcome = block_on(repo.verify_commit(&fixture_commit(), &[Arc::new(verifier)])).unwrap();
    assert!(outcome.valid, "the server signature verifies");
}

/// If `update_summary` is `true`, the session regenerates the summary under
/// its lock. It signs the bytes that it built with each summary key. A policy
/// with no summary key removes `summary.sig`. An update that changes no ref
/// does not regenerate the summary.
#[test]
fn summary_is_regenerated_and_signed_from_the_built_bytes() {
    let tmp = TmpDir::new("recv-summary");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let signed = ReceivePolicy {
        update_summary: true,
        summary_signers: vec![
            server_signer(SERVER_SECRET_B64),
            server_signer(SECOND_SERVER_SECRET_B64),
        ],
        ..policy()
    };
    let report = committed(push(
        &repo,
        &signed,
        &fixture_objects(Encoding::Raw),
        &[],
        vec![update(
            "test/main",
            Expected::Absent,
            Some(fixture_commit()),
        )],
        false,
    ));
    assert_eq!(report.warnings, vec![]);
    let bytes = block_on(repo.read_summary()).unwrap().unwrap();
    let summary = Summary::parse(&bytes).unwrap();
    assert_eq!(summary.lookup("test/main"), Some(fixture_commit()));
    let sig = block_on(repo.read_summary_signature()).unwrap().unwrap();
    assert_eq!(
        signatures(&sig, ED25519_KEY),
        vec![
            ed25519_signature(SERVER_SECRET_B64, &bytes),
            ed25519_signature(SECOND_SERVER_SECRET_B64, &bytes),
        ],
        "each summary key signed the bytes written, in order"
    );
    for key in [SERVER_SECRET_B64, SECOND_SERVER_SECRET_B64] {
        let verifier = ed25519_verifier(key);
        assert!(
            block_on(repo.verify_summary(&[Arc::new(verifier)]))
                .unwrap()
                .valid
        );
    }

    // An update to the current commit changes no ref and writes no summary.
    std::fs::remove_file(repo.path().join("summary")).unwrap();
    committed(push(
        &repo,
        &signed,
        &[],
        &[],
        vec![update("test/main", Expected::Any, Some(fixture_commit()))],
        false,
    ));
    assert!(!repo.path().join("summary").exists());

    // A policy with no summary key writes the summary and removes the stale
    // signatures.
    let unsigned = ReceivePolicy {
        update_summary: true,
        ..policy()
    };
    let other = build_commit(None, "other", no_metadata(), &[]);
    committed(push(
        &repo,
        &unsigned,
        std::slice::from_ref(&other),
        &[],
        vec![update("other", Expected::Absent, Some(other.checksum))],
        false,
    ));
    let summary = Summary::parse(&block_on(repo.read_summary()).unwrap().unwrap()).unwrap();
    assert_eq!(summary.lookup("other"), Some(other.checksum));
    assert_eq!(summary.lookup("test/main"), Some(fixture_commit()));
    assert!(!repo.path().join("summary.sig").exists());
}

/// The session writes the root summary and the summary of each auth item of
/// the client groups of the config, signs each one, and writes the `.access`
/// file of each item. An item with no summary gets no file. With no summary
/// of `anonymous`, the root summary holds each ref.
#[test]
fn the_session_writes_the_summary_of_each_item() {
    let tmp = TmpDir::new("recv-summary-items");
    let repo = new_repo(
        &tmp,
        RepoMode::Archive,
        "[ex-ostrya client \"ci\"]\nauth=ssh:ci\nallow=r:test/**\nsummary=true\n\
         [ex-ostrya client \"ops\"]\nauth=ssh:ops\nallow=r:**\n",
    );
    let signed = ReceivePolicy {
        update_summary: true,
        summary_signers: vec![server_signer(SERVER_SECRET_B64)],
        ..policy()
    };
    let report = committed(push(
        &repo,
        &signed,
        &fixture_objects(Encoding::Raw),
        &[],
        vec![update(
            "test/main",
            Expected::Absent,
            Some(fixture_commit()),
        )],
        false,
    ));
    assert_eq!(report.warnings, vec![]);
    let root = block_on(repo.read_summary()).unwrap().unwrap();
    assert_eq!(
        Summary::parse(&root).unwrap().lookup("test/main"),
        Some(fixture_commit())
    );
    let sig = std::fs::read(repo.path().join("summary.sig")).unwrap();
    let sig = ostrya::from_bytes(&ostrya::Type::parse("a{sv}").unwrap(), &sig).unwrap();
    assert_eq!(
        signatures(&sig, ED25519_KEY),
        vec![ed25519_signature(SERVER_SECRET_B64, &root)]
    );
    let ci = ostrya::access::AuthItem::parse("ssh:ci").unwrap();
    let bytes = block_on(repo.read_summary_of(&ci)).unwrap().unwrap();
    let summary = Summary::parse(&bytes).unwrap();
    assert_eq!(summary.lookup("test/main"), Some(fixture_commit()));
    let dir = repo.path().join("extensions/ostrya/summary");
    let stem = ostrya::Checksum::sha256(b"ssh:ci");
    let sig = std::fs::read(dir.join(format!("{stem}.sig"))).unwrap();
    let sig = ostrya::from_bytes(&ostrya::Type::parse("a{sv}").unwrap(), &sig).unwrap();
    assert_eq!(
        signatures(&sig, ED25519_KEY),
        vec![ed25519_signature(SERVER_SECRET_B64, &bytes)]
    );
    let access = ostrya::access::ClientAccess::from_config(repo.config(), repo.path()).unwrap();
    let digest = access.summary_digest(&ci).unwrap();
    assert_eq!(
        std::fs::read(dir.join(format!("{stem}.access"))).unwrap(),
        format!("{digest}\n").into_bytes()
    );
    let ops = ostrya::Checksum::sha256(b"ssh:ops");
    assert!(!dir.join(format!("{ops}.access")).exists());
}

/// If a summary write fails after the commit, the report holds a warning. The
/// refs stay written, and the client gets `CommitReply`.
#[test]
fn a_summary_failure_is_reported_and_the_refs_stay() {
    let tmp = TmpDir::new("recv-summary-failure");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    std::fs::create_dir(repo.path().join("summary")).unwrap();
    let policy = ReceivePolicy {
        update_summary: true,
        ..policy()
    };
    let report = committed(push(
        &repo,
        &policy,
        &fixture_objects(Encoding::Raw),
        &[],
        vec![update(
            "test/main",
            Expected::Absent,
            Some(fixture_commit()),
        )],
        false,
    ));
    let steps: Vec<ReceiveStep> = report.warnings.iter().map(|w| w.step).collect();
    assert_eq!(
        steps,
        vec![ReceiveStep::SummaryWrite],
        "{:?}",
        report.warnings
    );
    assert_eq!(
        ref_file(&repo, "refs/heads/test/main").as_deref(),
        Some(format!("{}\n", fixture_commit()).as_str())
    );
    assert!(repo.path().join("summary").is_dir());
}

/// In a repository with a collection id, the session writes the refreshed
/// anchor commit on `ostree-metadata` in its own transaction. The parent of
/// the new anchor is the anchor before it, and the summary lists the new
/// anchor.
#[test]
fn a_collection_repo_writes_the_anchor_in_the_session() {
    let tmp = TmpDir::new("recv-anchor");
    let repo = new_repo(&tmp, RepoMode::Archive, "collection-id=org.example.C\n");
    let policy = ReceivePolicy {
        update_summary: true,
        ..policy()
    };
    let report = committed(push(
        &repo,
        &policy,
        &fixture_objects(Encoding::Raw),
        &[],
        vec![update(
            "test/main",
            Expected::Absent,
            Some(fixture_commit()),
        )],
        false,
    ));
    assert_eq!(report.warnings, vec![]);
    let anchor = |repo: &Repo| {
        let tip = block_on(repo.resolve_ref_tip("ostree-metadata"))
            .unwrap()
            .expect("the anchor ref");
        let bytes = block_on(repo.load_object_bytes(ObjectType::Commit, &tip)).unwrap();
        (tip, Commit::parse(&bytes).unwrap())
    };
    let (first, commit) = anchor(&repo);
    assert_eq!(commit.parent, None);
    assert_eq!(commit.collection_binding(), Some("org.example.C"));
    assert_eq!(commit.ref_bindings(), vec!["ostree-metadata"]);
    let summary = Summary::parse(&block_on(repo.read_summary()).unwrap().unwrap()).unwrap();
    assert_eq!(summary.lookup("ostree-metadata"), Some(first));
    assert_eq!(summary.lookup("test/main"), Some(fixture_commit()));
    assert!(staging_entries(repo.path()).is_empty());

    let other = build_commit(None, "other", no_metadata(), &[]);
    committed(push(
        &repo,
        &policy,
        std::slice::from_ref(&other),
        &[],
        vec![update("other", Expected::Absent, Some(other.checksum))],
        false,
    ));
    let (second, commit) = anchor(&repo);
    assert_eq!(commit.parent, Some(first), "the anchor chains its parents");
    let summary = Summary::parse(&block_on(repo.read_summary()).unwrap().unwrap()).unwrap();
    assert_eq!(summary.lookup("ostree-metadata"), Some(second));
    if common::ostree_available() {
        tool_fsck(repo.path());
    }
}

/// If the session cannot write an anchor commit, the session fails with
/// `internal` before the commit and publishes nothing. In this test,
/// `refs/heads/ostree-metadata` holds no checksum.
#[test]
fn an_anchor_failure_is_internal() {
    let tmp = TmpDir::new("recv-anchor-failure");
    let repo = new_repo(&tmp, RepoMode::Archive, "collection-id=org.example.C\n");
    std::fs::write(repo.path().join("refs/heads/ostree-metadata"), b"garbage\n").unwrap();
    let before = snapshot(&repo);
    let policy = ReceivePolicy {
        update_summary: true,
        ..policy()
    };
    let error = refused(
        push(
            &repo,
            &policy,
            &fixture_objects(Encoding::Raw),
            &[],
            vec![update(
                "test/main",
                Expected::Absent,
                Some(fixture_commit()),
            )],
            false,
        ),
        ErrorCode::Internal,
    );
    assert!(!error.message.is_empty());
    assert_unchanged(&repo, &before);
    assert!(!repo.path().join("summary").exists());
}
