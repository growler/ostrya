//! `Repo::receive` at `Commit`: the checks of each ref update, the update
//! lock, the ref writes, the transaction commit, and `CommitReply`.
//!
//! A test client drives the session over two in-process pipes with the frame
//! codec of `ostrya::push::proto`. It sends the objects of the golden fixture
//! commit, which binds the ref `test/main`, or of commits the tests build over
//! the fixture tree.

#![cfg(feature = "receive")]

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use common::receive::{
    Obj, connect, fixture_objects, new_repo, returned_code, session, sha, staging_entries,
};
use common::{
    COMMIT, GUARD_RELEASING_MARKER, ROOT_DIRMETA, ROOT_DIRTREE, TmpDir, file_inventory,
    foreign_holder, guard_holder, guard_holder_main, is_sealed, lock_holder_main, regular_objects,
    tool_fsck,
};
use ostrya::push::proto::ErrorMessage;
use ostrya::push::{Encoding, ErrorCode, Expected, RefOutcome, RefUpdate};
use ostrya::sign::append_signature;
use ostrya::{
    Checksum, Commit, DictBuilder, Ed25519Signer, Ed25519Verifier, Error, FsckOptions, ObjectName,
    ObjectType, ReceivePolicy, ReceiveReport, ReceiveRule, ReceiveStep, ReceiveVerify, RefPattern,
    Repo, RepoMode, ServerSigner, Signer, Summary, SummaryOptions, TrustedKeys, Type, Value,
    Verifier,
};
use ostrya_rt::block_on;

/// The base64 of a 64-byte ed25519 secret key (seed, then public key).
const SECRET_B64: &str =
    "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";
/// Another ed25519 secret key.
const OTHER_SECRET_B64: &str =
    "5ILWxT+l9G/u3h0BptRpmSi35C9uog7YDdD+Fp1Xk+Hz52p0NlYh6xBA73kJEJKhKbbnjcE0rsWA5XA/K5Sq5Q==";
/// The ed25519 secret key of a server signer.
const SERVER_SECRET_B64: &str =
    "Rdkqts/v6AXV6N+XOTlBGoGiItwTHGWaip72oFWzQDDMGsL2Sdl/Bcj+xg4EA2iJqHUuBsmdnNCFKNZMBqTiFw==";
/// The ed25519 secret key of a second server signer.
const SECOND_SERVER_SECRET_B64: &str =
    "l/anh/DXkHapldUSa0GdgaH5ISN03SHhYNSK+Ru3aAtpU8w6rtwuSrlO1kD+T1+eddwLhqHxd9ui+B+v52iDOw==";

const ED25519_KEY: &str = "ostree.sign.ed25519";

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

/// A commit over the fixture tree with `metadata`, `parent`, and `subject`.
fn build_commit(parent: Option<Checksum>, subject: &str, metadata: Value) -> Obj {
    let bytes = Commit {
        metadata,
        parent,
        related: Vec::new(),
        subject: subject.into(),
        body: String::new(),
        timestamp: 1_700_000_100,
        root_dirtree: checksum(ROOT_DIRTREE),
        root_dirmeta: checksum(ROOT_DIRMETA),
    }
    .serialize()
    .unwrap();
    Obj {
        ty: ObjectType::Commit,
        checksum: sha(&bytes),
        encoding: Encoding::Raw,
        bytes,
    }
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

fn secret(b64: &str) -> Vec<u8> {
    ostrya::base64::decode(b64).unwrap()
}

/// An ed25519 signature of `payload` with the key `secret_b64`.
fn ed25519_signature(secret_b64: &str, payload: &[u8]) -> Vec<u8> {
    let signer = Ed25519Signer::from_secret_key(&secret(secret_b64)).unwrap();
    block_on(signer.sign(payload)).unwrap()
}

/// A detached metadata dict with one ed25519 signature for each key.
fn signed_dict(payload: &[u8], secrets: &[&str]) -> Vec<u8> {
    let mut dict = no_metadata();
    for key in secrets {
        append_signature(&mut dict, ED25519_KEY, ed25519_signature(key, payload)).unwrap();
    }
    dict_bytes(&dict)
}

/// A server signer with the ed25519 key `secret_b64`.
fn server_signer(secret_b64: &str) -> Arc<ServerSigner> {
    Arc::new(ServerSigner::ed25519(&secret(secret_b64)).unwrap())
}

/// A verifier that trusts the ed25519 key `secret_b64`.
fn ed25519_verifier(secret_b64: &str) -> Ed25519Verifier {
    Ed25519Verifier::new([secret(secret_b64)[32..].to_vec()], Vec::<Vec<u8>>::new()).unwrap()
}

/// Trusted keys that trust the ed25519 key `secret_b64`.
fn trust(secret_b64: &str) -> Arc<TrustedKeys> {
    let public = secret(secret_b64)[32..].to_vec();
    let verifier: Arc<dyn Verifier> =
        Arc::new(Ed25519Verifier::new([public], Vec::<Vec<u8>>::new()).unwrap());
    Arc::new(TrustedKeys::new(vec![verifier]).unwrap())
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

/// What one push session gives: the result the server returned, and the reply
/// the client read.
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

/// [`push`], with the refs of `Hello` given apart from the updates.
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
        script(c, names, objects, meta, updates, force)
    })
}

async fn script(
    mut c: common::receive::Client,
    names: &[String],
    objects: &[Obj],
    meta: &[(Checksum, Vec<u8>)],
    updates: Vec<RefUpdate>,
    force: bool,
) -> Result<Vec<RefOutcome>, ErrorMessage> {
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    c.hello_reply(&names).await;
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

/// Assert that a push succeeded, and give its report.
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

/// Assert that a push failed with `code`, on the wire and to the caller, and
/// give the `Error` message.
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

/// Assert that a failed session published nothing, wrote no ref, and left no
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

fn policy() -> ReceivePolicy {
    ReceivePolicy::default()
}

/// A policy whose one pattern rule is `rule` under `pattern`.
fn policy_with(pattern: &str, rule: ReceiveRule) -> ReceivePolicy {
    ReceivePolicy {
        rules: vec![(RefPattern::parse(pattern).unwrap(), rule)],
        ..ReceivePolicy::default()
    }
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

/// With `[ex-integrity] fsverity=yes` each regular-file object the session
/// writes is sealed, for `raw` content, for `deflate` content the server
/// inflates, and for `deflate` content an archive server stores as it is.
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
            script(c1, &names, &objects, &[], updates(), false),
        ),
        futures_lite::future::zip(
            repo.receive(in2, out2, &policy),
            script(c2, &names, &objects, &[], updates(), false),
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

/// A commit the repository holds with a partial marker loses the marker when a
/// session sends the objects it lacks and names it again. An update to the
/// current commit writes no ref.
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

/// A partial marker that cannot be removed is a warning of the report, and the
/// refs stay written.
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

/// A `CommitReply` the client does not read is a warning of the report, and
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

/// A second client signature joins the signature the repository holds for the
/// commit, and the stored one stays first.
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

/// The detached-metadata filter removes its keys from the incoming dict before
/// the merge.
#[test]
fn the_filter_removes_its_keys_from_the_incoming_dict() {
    let tmp = TmpDir::new("recv-filter");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let mut dict = DictBuilder::new();
    dict.insert_str("kept", "a");
    dict.insert_str("dropped", "b");
    let policy = ReceivePolicy {
        detached_metadata_filter: Some(ostrya::DetachedMetadataFilter::excluding(["dropped"])),
        ..ReceivePolicy::default()
    };
    committed(push(
        &repo,
        &policy,
        &fixture_objects(Encoding::Raw),
        &[(fixture_commit(), dict_bytes(&dict.build()))],
        vec![update(
            "test/main",
            Expected::Absent,
            Some(fixture_commit()),
        )],
        false,
    ));
    let stored = block_on(repo.read_commit_detached_metadata(&fixture_commit()))
        .unwrap()
        .unwrap();
    let keys: Vec<&str> = stored
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e.as_tuple().unwrap()[0].as_str().unwrap())
        .collect();
    assert_eq!(keys, vec!["kept"]);
}

/// Under a rule for `origin:*`, an update of `origin:test/main` writes
/// `refs/remotes/origin/test/main`, and the binding check compares
/// `test/main`.
#[test]
fn a_remote_rule_writes_refs_remotes_and_binds_the_name() {
    let tmp = TmpDir::new("recv-remote");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let policy = policy_with("origin:*", ReceiveRule::default());
    let before = snapshot(&repo);
    let error = refused(
        push(
            &repo,
            &policy,
            &fixture_objects(Encoding::Raw),
            &[],
            vec![update(
                "origin:other",
                Expected::Absent,
                Some(fixture_commit()),
            )],
            false,
        ),
        ErrorCode::BindingMismatch,
    );
    assert!(error.message.contains("'other'"), "{error:?}");
    assert_unchanged(&repo, &before);

    committed(push(
        &repo,
        &policy,
        &fixture_objects(Encoding::Raw),
        &[],
        vec![update(
            "origin:test/main",
            Expected::Absent,
            Some(fixture_commit()),
        )],
        false,
    ));
    assert_eq!(
        ref_file(&repo, "refs/remotes/origin/test/main"),
        Some(format!("{COMMIT}\n"))
    );
    assert_eq!(ref_file(&repo, "refs/heads/test/main"), None);
}

// ---------------------------------------------------------------------------
// The checks before the lock.
// ---------------------------------------------------------------------------

/// A `Commit` with no update is `protocol`, and so is an update of a ref that
/// `Hello` did not name, and a second update of one ref.
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

/// A ref name that `validate_refspec` refuses is `invalid-ref`, also where
/// `Hello` did not name it.
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

/// A ref name of 64 lowercase hex characters, which a revision reads as a
/// commit checksum, passes `Hello`. An update that writes a commit to it is
/// `invalid-ref` at `Commit`, also where `Hello` did not name it. With a
/// `REMOTE:` part the name passes the check, and the binding check of the
/// fixture commit refuses it.
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

    let remote = format!("origin:{hex}");
    refused(
        push(
            &repo,
            &policy_with("origin:*", ReceiveRule::default()),
            &fixture_objects(Encoding::Raw),
            &[],
            vec![update(&remote, Expected::Absent, Some(fixture_commit()))],
            false,
        ),
        ErrorCode::BindingMismatch,
    );
    assert_unchanged(&repo, &before);
}

/// A delete of a ref of 64 lowercase hex characters passes the check of the
/// name, and a rule that allows the delete removes the ref.
#[test]
fn a_delete_of_a_checksum_shaped_name_removes_the_ref() {
    let tmp = TmpDir::new("recv-hex-delete");
    let repo = repo_with_fixture(&tmp, RepoMode::Archive, "");
    let hex = "a".repeat(64);
    block_on(repo.set_ref_immediate(&hex, Some(&fixture_commit()))).unwrap();
    let path = format!("refs/heads/{hex}");
    assert_eq!(ref_file(&repo, &path), Some(format!("{COMMIT}\n")));
    let allow = ReceivePolicy {
        default_rule: ReceiveRule {
            allow_delete: true,
            ..ReceiveRule::default()
        },
        ..ReceivePolicy::default()
    };
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

/// Detached metadata for a commit that the repository holds, and that the
/// session neither stages nor names as a new ref value, is `protocol`, so a
/// session cannot edit the detached metadata of a commit that its rules do
/// not cover. Nothing is written, and the stored dict stays.
#[test]
fn detached_metadata_for_a_commit_outside_the_session_is_protocol() {
    let tmp = TmpDir::new("recv-meta-outside");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let protected = build_commit(None, "protected", no_metadata());
    let free = build_commit(None, "free", no_metadata());
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
    let policy = policy_with(
        "protected",
        ReceiveRule {
            accept: false,
            ..ReceiveRule::default()
        },
    );
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

/// Write `bytes` into `objects/` as the object `checksum` of type `ty`, as a
/// corrupt store holds it.
fn plant_object(repo: &Repo, ty: ObjectType, checksum: &Checksum, bytes: &[u8]) {
    let path = repo
        .path()
        .join("objects")
        .join(ostrya::loose_path(checksum, ty, repo.mode()));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

/// A commit or a dirtree that does not parse is `protocol` where the session
/// staged it and `internal` where the repository holds it. Nothing is
/// published either way.
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

/// A rule with `accept=false` refuses its refs, a remote ref that no rule
/// covers is refused, the collection anchor ref of a repository with a
/// collection id is refused, and so is a ref that is an alias.
#[test]
fn ref_denied_covers_each_refused_ref() {
    // An unbound commit, so the binding check passes each name.
    let commit = build_commit(None, "unbound", no_metadata());
    let mut objects = tree_objects();
    objects.push(commit.clone());
    let new = Some(commit.checksum);
    let denied = ReceiveRule {
        accept: false,
        ..ReceiveRule::default()
    };
    let cases: Vec<(&str, ReceivePolicy, &str, &str)> = vec![
        ("", policy_with("test/*", denied), "test/main", "refuses"),
        ("", policy(), "origin:test/main", "no rule"),
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

/// An object the trees reach that the session did not send is
/// `missing-objects`, and so is a new commit the session did not send.
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
/// repository is `binding-mismatch`. The same binding passes where the
/// repository has that id.
#[test]
fn a_foreign_collection_binding_is_binding_mismatch() {
    let mut metadata = DictBuilder::new();
    metadata.insert_str("ostree.collection-binding", "org.example.Other");
    let commit = build_commit(None, "bound", metadata.build());
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

/// A commit that carries no signature a rule trusts is `signature-required`.
/// The check reads the incoming signatures and the stored ones.
#[test]
fn an_unsigned_commit_is_signature_required() {
    let policy = ReceivePolicy {
        default_rule: ReceiveRule {
            verify: ReceiveVerify::Keys(trust(SECRET_B64)),
            ..ReceiveRule::default()
        },
        ..ReceivePolicy::default()
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
    // A signature from a key the rule does not trust.
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
        &ReceivePolicy::default(),
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

/// A commit that is the new value of two refs under two rules must pass the
/// signature check of both. It gets a signature from each key of the `sign`
/// lists of both rules, each key once, and a second push adds none.
#[test]
fn a_commit_under_two_rules_passes_both_and_gets_each_key_once() {
    let commit = build_commit(None, "unbound", no_metadata());
    let mut objects = tree_objects();
    objects.push(commit.clone());
    let shared = server_signer(SECOND_SERVER_SECRET_B64);
    let policy = ReceivePolicy {
        rules: vec![
            (
                RefPattern::parse("a").unwrap(),
                ReceiveRule {
                    verify: ReceiveVerify::Keys(trust(SECRET_B64)),
                    signers: vec![server_signer(SERVER_SECRET_B64), shared.clone()],
                    ..ReceiveRule::default()
                },
            ),
            (
                RefPattern::parse("b").unwrap(),
                ReceiveRule {
                    verify: ReceiveVerify::Keys(trust(OTHER_SECRET_B64)),
                    signers: vec![shared],
                    ..ReceiveRule::default()
                },
            ),
        ],
        ..ReceivePolicy::default()
    };
    let updates = || {
        vec![
            update("a", Expected::Absent, Some(commit.checksum)),
            update("b", Expected::Absent, Some(commit.checksum)),
        ]
    };
    let tmp = TmpDir::new("recv-two-rules");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let before = snapshot(&repo);
    for keys in [&[SECRET_B64][..], &[OTHER_SECRET_B64][..]] {
        let dict = signed_dict(&commit.bytes, keys);
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
    }
    let dict = signed_dict(&commit.bytes, &[SECRET_B64, OTHER_SECRET_B64]);
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
        ed25519_signature(OTHER_SECRET_B64, &commit.bytes),
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
        "the client keys, then each server key once"
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
    let file = tmp.path().join("receive.conf");
    std::fs::write(
        &file,
        format!(
            "[ex-ostrya receive]\nsign=first;second\n{}{}",
            group("first"),
            group("second")
        ),
    )
    .unwrap();
    let policy = block_on(ReceivePolicy::from_file(&repo, &file)).unwrap();
    assert_eq!(policy.default_rule.signers.len(), 2);
    let commit = build_commit(None, "signed once", no_metadata());
    let mut objects = tree_objects();
    objects.push(commit.clone());
    committed(push(
        &repo,
        &policy,
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
// The checks under the lock.
// ---------------------------------------------------------------------------

/// A ref that is not in the state the update expects is `ref-mismatch`, with
/// the current state in the detail.
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
/// `non-fast-forward`, unless the client sends `force` and the rule allows
/// it. A chain that reaches a commit the repository does not hold proves no
/// fast-forward. A child of the current commit is a fast-forward.
#[test]
fn a_non_ancestor_is_non_fast_forward() {
    let unrelated = build_commit(None, "unrelated", no_metadata());
    let orphan = build_commit(Some(sha(b"an absent parent")), "orphan", no_metadata());
    let child = build_commit(Some(fixture_commit()), "child", no_metadata());
    let allow = ReceiveRule {
        allow_non_fast_forward: true,
        ..ReceiveRule::default()
    };
    let current = Expected::Commit(fixture_commit());
    for commit in [&unrelated, &orphan] {
        for (policy, force) in [
            (policy_with("main", ReceiveRule::default()), false),
            (policy_with("main", ReceiveRule::default()), true),
            (policy_with("main", allow.clone()), false),
        ] {
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
        // Forced under a rule that allows it.
        let report = committed(push(
            &repo,
            &policy_with("main", allow.clone()),
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

fn write_ref(repo: &Repo, name: &str, commit: &Checksum) {
    std::fs::write(
        repo.path().join("refs/heads").join(name),
        format!("{commit}\n"),
    )
    .unwrap();
}

/// A delete the rule does not allow is `delete-denied`. A rule that allows it
/// deletes the ref, and a delete of an absent ref changes nothing.
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

    let allow = ReceivePolicy {
        default_rule: ReceiveRule {
            allow_delete: true,
            ..ReceiveRule::default()
        },
        ..ReceivePolicy::default()
    };
    let report = committed(push(
        &repo,
        &allow,
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
/// before anything is written: a path below a ref file, a path that names a
/// directory of refs, and two updates of which one writes below the other.
/// The other updates of the message write nothing either.
#[test]
fn a_ref_path_that_a_write_cannot_replace_is_ref_denied() {
    let commit = build_commit(None, "unbound", no_metadata());
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
/// `Commit`. The session completes once the holder releases the guard.
#[test]
fn a_session_waits_for_a_guard_of_another_process() {
    let tmp = TmpDir::new("recv-guard-wait");
    let repo = new_repo(&tmp, RepoMode::Archive, "lock-timeout-secs=30\n");
    let holder = guard_holder(repo.path());
    let releasing = repo.path().join(GUARD_RELEASING_MARKER);
    let root = repo.path().to_path_buf();
    // The releasing marker proves the order. The release waits only until the
    // session made its staging directory, so the session runs before it.
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
        ..ReceivePolicy::default()
    }
}

/// In a repository with a collection id and `lock-timeout-secs=0`, a session
/// that regenerates the summary and a later `regenerate_summary` both
/// complete: neither waits for a lock it holds itself.
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

/// A session and two `regenerate_summary` calls that wait for one guard in a
/// repository with a collection id all complete once the guard goes, and
/// the three anchor commits chain: each one's parent is the anchor before
/// it. Each writer reads the parent of its anchor under the update lock, so
/// a writer that read it before its wait would chain onto an anchor another
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
    // they wait for the update lock. The settle time covers the step between
    // that and the wait.
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
                script(c, &names, &objects, &[], updates, false),
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
/// the merge on the server side: `internal`, with nothing published.
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
        result.is_err() && !matches!(result, Err(Error::Push(_))),
        "{result:?}"
    );
    assert_unchanged(&repo, &before);
}

// ---------------------------------------------------------------------------
// Server signatures, the anchor commit, and the summary.
// ---------------------------------------------------------------------------

/// A GPG signature carries the time it was made, so a second signature of one
/// key over one commit has other bytes. Two pushes of one commit under a rule
/// with a GPG server key leave one signature of that key.
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
        default_rule: ReceiveRule {
            signers: vec![Arc::new(block_on(ServerSigner::gpg(signer)).unwrap())],
            ..ReceiveRule::default()
        },
        ..ReceivePolicy::default()
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
    let outcome = block_on(repo.verify_commit(&fixture_commit(), &[&verifier])).unwrap();
    assert!(outcome.valid, "the server signature verifies");
}

/// With `update_summary` the session regenerates the summary under its lock
/// and signs the bytes it built with each summary key. A policy with no
/// summary key removes `summary.sig`, and an update that changes no ref does
/// not regenerate the summary.
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
        ..ReceivePolicy::default()
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
        assert!(block_on(repo.verify_summary(&[&verifier])).unwrap().valid);
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
        ..ReceivePolicy::default()
    };
    let other = build_commit(None, "other", no_metadata());
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

/// A summary write that fails after the commit is a warning of the report.
/// The refs stay written and the client gets `CommitReply`.
#[test]
fn a_summary_failure_is_reported_and_the_refs_stay() {
    let tmp = TmpDir::new("recv-summary-failure");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    std::fs::create_dir(repo.path().join("summary")).unwrap();
    let policy = ReceivePolicy {
        update_summary: true,
        ..ReceivePolicy::default()
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
/// anchor commit on `ostree-metadata` in its own transaction, with the anchor
/// before it as parent, and the summary lists it.
#[test]
fn a_collection_repo_writes_the_anchor_in_the_session() {
    let tmp = TmpDir::new("recv-anchor");
    let repo = new_repo(&tmp, RepoMode::Archive, "collection-id=org.example.C\n");
    let policy = ReceivePolicy {
        update_summary: true,
        ..ReceivePolicy::default()
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

    let other = build_commit(None, "other", no_metadata());
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

/// An anchor commit the session cannot write, here because
/// `refs/heads/ostree-metadata` holds no checksum, fails the session with
/// `internal` before the commit, and nothing is published.
#[test]
fn an_anchor_failure_is_internal() {
    let tmp = TmpDir::new("recv-anchor-failure");
    let repo = new_repo(&tmp, RepoMode::Archive, "collection-id=org.example.C\n");
    std::fs::write(repo.path().join("refs/heads/ostree-metadata"), b"garbage\n").unwrap();
    let before = snapshot(&repo);
    let policy = ReceivePolicy {
        update_summary: true,
        ..ReceivePolicy::default()
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
