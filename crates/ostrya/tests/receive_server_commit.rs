//! `Repo::receive` at a `Commit` with a server commit: the checks, the commit
//! that the server builds, its refs, its signatures, and the races of two
//! sessions.
//!
//! A test client drives the session over two in-process pipes with the frame
//! codec of `ostrya::remote::proto`. The tree of each server commit is the
//! tree of the golden fixture commit.
//!
//! The module `tool` compares the commit of the server with the commit of
//! `ostree commit` over equal inputs. It runs only if the `ostree` command is
//! installed, and `OSTRYA_REQUIRE_OSTREE` turns the skip into a failure.

#![cfg(feature = "receive")]

mod common;

use std::sync::Arc;

use common::receive::{
    Obj, build_commit, collections_policy, commit_objects, connect, fixture_objects, new_repo,
    policy_allowing, returned_code, session, staging_entries,
};
use common::{
    ROOT_DIRMETA, ROOT_DIRTREE, TmpDir, file_inventory, tool_fsck, writer_child_main,
    writer_child_with,
};
use ostrya::remote::proto::{CommitRequest, ErrorMessage, Message, ServerCommit};
use ostrya::remote::{Encoding, ErrorCode, Expected, RefOutcome, RefUpdate};
use ostrya::{
    Checksum, Commit, Ed25519Signer, Ed25519Verifier, ObjectType, ReceivePolicies, ReceivePolicy,
    ReceiveReport, ReceiveVerify, Repo, RepoMode, ServerSigner, Signer, Summary, TrustedKeys, Type,
    Value, Verifier,
};
use ostrya_rt::block_on;

/// The base64 of the 64-byte ed25519 secret key of a server signer.
const SERVER_SECRET_B64: &str =
    "Rdkqts/v6AXV6N+XOTlBGoGiItwTHGWaip72oFWzQDDMGsL2Sdl/Bcj+xg4EA2iJqHUuBsmdnNCFKNZMBqTiFw==";
/// The ed25519 secret key of a second server signer.
const SECOND_SERVER_SECRET_B64: &str =
    "l/anh/DXkHapldUSa0GdgaH5ISN03SHhYNSK+Ru3aAtpU8w6rtwuSrlO1kD+T1+eddwLhqHxd9ui+B+v52iDOw==";
/// An ed25519 secret key that no server signer holds.
const OTHER_SECRET_B64: &str =
    "5ILWxT+l9G/u3h0BptRpmSi35C9uog7YDdD+Fp1Xk+Hz52p0NlYh6xBA73kJEJKhKbbnjcE0rsWA5XA/K5Sq5Q==";

const ED25519_KEY: &str = "ostree.sign.ed25519";

/// The timestamp of each server commit that states one.
const TIMESTAMP: u64 = 1_700_000_000;

#[test]
#[ignore = "helper process for the timestamp test"]
fn writer_child_subprocess() {
    writer_child_main(|path, branch| {
        let repo = block_on(Repo::open(path)).unwrap();
        let sc = ServerCommit {
            timestamp: None,
            ..server_commit(branch)
        };
        committed(server_push(
            &repo,
            &policy_allowing(&["c:**"]),
            &[branch],
            &tree_objects(),
            sc,
        ));
    });
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

fn checksum(hex: &str) -> Checksum {
    Checksum::from_hex(hex).unwrap()
}

/// The objects of the fixture tree, without the fixture commit.
fn tree_objects() -> Vec<Obj> {
    fixture_objects(Encoding::Raw)
        .into_iter()
        .filter(|o| o.ty != ObjectType::Commit)
        .collect()
}

/// The bytes of the `v` `value`, the form of a metadata entry of a server
/// commit.
fn v(value: &Value) -> Vec<u8> {
    ostrya_core::to_bytes(&Type::Variant, value).unwrap()
}

/// The bytes of a `v` that holds the string `value`.
fn text(value: &str) -> Vec<u8> {
    v(&Value::variant(Type::Str, Value::Str(value.into())))
}

/// A server commit on `branch` over the fixture tree, with no tag, no bound
/// name, the subject `subject`, the body `body`, one metadata entry, and
/// [`TIMESTAMP`].
fn server_commit(branch: &str) -> ServerCommit {
    ServerCommit {
        branch: branch.into(),
        tags: Vec::new(),
        bind_refs: Vec::new(),
        root_dirtree: checksum(ROOT_DIRTREE),
        root_dirmeta: checksum(ROOT_DIRMETA),
        subject: "subject".into(),
        body: "body".into(),
        metadata: vec![("version".into(), text("1"))],
        timestamp: Some(TIMESTAMP),
        orphan: false,
    }
}

/// The output of one push session: the result that the server returned, and
/// the reply that the client read.
type Pushed = (
    ostrya::Result<ReceiveReport>,
    Result<Vec<RefOutcome>, ErrorMessage>,
);

/// One session: `Hello` with `names` in the namespace `collection`, one
/// object stream with `objects` and the detached metadata `meta`, and the
/// `Commit` `request`.
fn push_request(
    repo: &Repo,
    policy: &ReceivePolicy,
    names: &[&str],
    collection: Option<&str>,
    objects: &[Obj],
    meta: &[(Checksum, Vec<u8>)],
    request: CommitRequest,
) -> Pushed {
    let names: Vec<String> = names.iter().map(|&n| n.into()).collect();
    session(repo, policy, |c| {
        script(c, names, collection, objects, meta, request)
    })
}

async fn script(
    mut c: common::receive::Client,
    names: Vec<String>,
    collection: Option<&str>,
    objects: &[Obj],
    meta: &[(Checksum, Vec<u8>)],
    request: CommitRequest,
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
    c.send(&Message::Commit(request)).await.unwrap();
    c.commit_reply().await
}

/// The `Commit` request of the server commit `sc` alone.
fn request(sc: ServerCommit) -> CommitRequest {
    CommitRequest {
        updates: Vec::new(),
        force: false,
        server_commit: Some(Box::new(sc)),
    }
}

/// One session that sends `objects` and the server commit `sc` in the local
/// refs, with `names` in `Hello`.
fn server_push(
    repo: &Repo,
    policy: &ReceivePolicy,
    names: &[&str],
    objects: &[Obj],
    sc: ServerCommit,
) -> Pushed {
    push_request(repo, policy, names, None, objects, &[], request(sc))
}

/// [`server_push`] with the branch and the tags of `sc` in `Hello`.
fn push_sc(repo: &Repo, policy: &ReceivePolicy, objects: &[Obj], sc: ServerCommit) -> Pushed {
    let names = hello_names(&sc);
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    server_push(repo, policy, &names, objects, sc)
}

/// The branch and the tags of `sc`.
fn hello_names(sc: &ServerCommit) -> Vec<String> {
    std::iter::once(sc.branch.clone())
        .chain(sc.tags.iter().cloned())
        .collect()
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
    assert_eq!(returned_code(&result), Some(code));
    error
}

/// The new commit of a server commit: the `new` of the first entry.
fn new_commit(report: &ReceiveReport) -> Checksum {
    report.refs[0].new.unwrap()
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

/// The commit of the ref file at `relpath` under the repository, if any.
fn ref_at(repo: &Repo, relpath: &str) -> Option<Checksum> {
    std::fs::read_to_string(repo.path().join(relpath))
        .ok()
        .map(|text| checksum(text.trim()))
}

fn load(repo: &Repo, commit: &Checksum) -> (Vec<u8>, Commit) {
    let bytes = block_on(repo.load_object_bytes(ObjectType::Commit, commit)).unwrap();
    let parsed = Commit::parse(&bytes).unwrap();
    (bytes, parsed)
}

/// The bytes of the commit that a server commit of `sc` writes with `parent`,
/// the refs `refs` in its ref binding, and the collection binding
/// `collection`. The metadata of `sc` holds no binding key.
fn expected_bytes(
    sc: &ServerCommit,
    parent: Option<Checksum>,
    refs: &[&str],
    collection: Option<&str>,
) -> Vec<u8> {
    let metadata = sc.metadata.iter().map(|(key, value)| {
        let value = ostrya_core::from_bytes(&Type::Variant, value).unwrap();
        (key.clone(), value)
    });
    Commit {
        metadata: ostrya::commit::commit_metadata(metadata, Some(refs), collection),
        parent,
        related: Vec::new(),
        subject: sc.subject.clone(),
        body: sc.body.clone(),
        timestamp: sc.timestamp.unwrap(),
        root_dirtree: sc.root_dirtree,
        root_dirmeta: sc.root_dirmeta,
    }
    .serialize()
    .unwrap()
}

fn sha(bytes: &[u8]) -> Checksum {
    common::receive::sha(bytes)
}

fn secret(b64: &str) -> Vec<u8> {
    ostrya::base64::decode(b64).unwrap()
}

fn server_signer(secret_b64: &str) -> Arc<ServerSigner> {
    Arc::new(ServerSigner::ed25519(&secret(secret_b64)).unwrap())
}

fn ed25519_signature(secret_b64: &str, payload: &[u8]) -> Vec<u8> {
    let signer = Ed25519Signer::from_secret_key(&secret(secret_b64)).unwrap();
    block_on(signer.sign(payload)).unwrap()
}

/// The blobs under `key` in the detached metadata of `commit`.
fn stored_signatures(repo: &Repo, commit: &Checksum, key: &str) -> Vec<Vec<u8>> {
    let Some(dict) = block_on(repo.read_commit_detached_metadata(commit)).unwrap() else {
        return Vec::new();
    };
    let Some(value) = dict.dict_get(key) else {
        return Vec::new();
    };
    let (_, list) = value.as_variant().unwrap();
    list.as_array()
        .unwrap()
        .iter()
        .map(|blob| blob.as_bytes().unwrap().to_vec())
        .collect()
}

/// A repository whose branch `main` holds a server commit, and that commit.
fn repo_with_main(tmp: &TmpDir, core: &str) -> (Repo, Checksum) {
    let repo = new_repo(tmp, RepoMode::Archive, core);
    let report = committed(push_sc(
        &repo,
        &policy_allowing(&["c:**"]),
        &tree_objects(),
        server_commit("main"),
    ));
    let tip = new_commit(&report);
    (repo, tip)
}

// ---------------------------------------------------------------------------
// The commit and its parent.
// ---------------------------------------------------------------------------

/// A server commit on an absent branch has no parent. The reply has one
/// entry for the branch, and the branch names the new commit. The commit is
/// the commit of the fields of the client, with the ref binding of the branch
/// and no collection binding in a repository with no collection id.
#[test]
fn a_server_commit_on_an_absent_branch_has_no_parent() {
    let tmp = TmpDir::new("sc-absent");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let sc = server_commit("main");
    let report = committed(push_sc(
        &repo,
        &policy_allowing(&["c:**"]),
        &tree_objects(),
        sc.clone(),
    ));
    let expected = expected_bytes(&sc, None, &["main"], None);
    let commit = sha(&expected);
    assert_eq!(
        report.refs,
        vec![RefOutcome {
            name: "main".into(),
            old: None,
            new: Some(commit),
        }]
    );
    assert_eq!(ref_at(&repo, "refs/heads/main"), Some(commit));
    let (bytes, parsed) = load(&repo, &commit);
    assert_eq!(bytes, expected);
    assert_eq!(parsed.parent, None);
    assert_eq!(parsed.root_dirtree, checksum(ROOT_DIRTREE));
    assert_eq!(parsed.root_dirmeta, checksum(ROOT_DIRMETA));
    assert_eq!(parsed.timestamp, TIMESTAMP);
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    assert!(staging_entries(repo.path()).is_empty());
}

/// A second server commit on a branch takes the tip as its parent. The reply
/// gives the tip as the old commit of the branch.
#[test]
fn a_server_commit_takes_the_tip_as_parent() {
    let tmp = TmpDir::new("sc-parent");
    let (repo, first) = repo_with_main(&tmp, "");
    let sc = ServerCommit {
        subject: "second".into(),
        ..server_commit("main")
    };
    let report = committed(push_sc(&repo, &policy_allowing(&["c:**"]), &[], sc.clone()));
    let second = new_commit(&report);
    assert_eq!(report.refs[0].old, Some(first));
    assert_eq!(load(&repo, &second).1.parent, Some(first));
    assert_eq!(
        load(&repo, &second).0,
        expected_bytes(&sc, Some(first), &["main"], None)
    );
    assert_eq!(ref_at(&repo, "refs/heads/main"), Some(second));
}

/// `orphan` on a branch that exists needs `d`. With `c` alone it is
/// `non-fast-forward`, and nothing changes. With `cd`, the commit has no
/// parent and the branch moves. `orphan` on an absent branch needs `c` alone.
#[test]
fn orphan_on_a_present_branch_needs_d() {
    let tmp = TmpDir::new("sc-orphan");
    let (repo, first) = repo_with_main(&tmp, "");
    let orphan = ServerCommit {
        subject: "orphan".into(),
        orphan: true,
        ..server_commit("main")
    };
    let before = snapshot(&repo);
    let error = refused(
        push_sc(&repo, &policy_allowing(&["c:**"]), &[], orphan.clone()),
        ErrorCode::NonFastForward,
    );
    assert!(error.message.contains("'main'"), "{error:?}");
    assert_unchanged(&repo, &before);

    let report = committed(push_sc(
        &repo,
        &policy_allowing(&["cd:main"]),
        &[],
        orphan.clone(),
    ));
    let commit = new_commit(&report);
    assert_eq!(report.refs[0].old, Some(first));
    assert_eq!(load(&repo, &commit).1.parent, None);
    assert_eq!(ref_at(&repo, "refs/heads/main"), Some(commit));

    let report = committed(push_sc(
        &repo,
        &policy_allowing(&["c:**"]),
        &[],
        ServerCommit {
            branch: "other".into(),
            ..orphan
        },
    ));
    assert_eq!(report.refs[0].old, None);
    assert_eq!(load(&repo, &new_commit(&report)).1.parent, None);
}

/// The branch needs `c`: `w`, `t`, and `d` do not take its place.
#[test]
fn the_branch_needs_c() {
    let tmp = TmpDir::new("sc-needs-c");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let before = snapshot(&repo);
    for allow in [&["wtd:**"][..], &["c:other", "w:main"][..]] {
        let error = refused(
            push_sc(
                &repo,
                &policy_allowing(allow),
                &tree_objects(),
                server_commit("main"),
            ),
            ErrorCode::RefDenied,
        );
        assert!(error.message.contains("no c on ref 'main'"), "{error:?}");
        assert_unchanged(&repo, &before);
    }
    let denying = ReceivePolicy {
        rules: ostrya::access::AccessRules {
            allow: vec![ostrya::access::AllowItem::parse("c:**").unwrap()],
            deny: vec![ostrya_core::RefPattern::parse("main").unwrap()],
        },
        ..ReceivePolicy::default()
    };
    let error = refused(
        server_push(
            &repo,
            &policy_allowing(&["r:main", "c:other"]),
            &["main"],
            &tree_objects(),
            server_commit("main"),
        ),
        ErrorCode::RefDenied,
    );
    assert!(error.message.contains("no c"), "{error:?}");
    // A deny item takes the `r` of `Hello` too, so `Hello` refuses the ref.
    let (result, error) = session(&repo, &denying, |mut c| async move {
        c.hello(&["main"]).await.unwrap();
        c.error().await
    });
    assert_eq!(error.code, ErrorCode::RefDenied);
    assert_eq!(returned_code(&result), Some(ErrorCode::RefDenied));
    assert_unchanged(&repo, &before);
}

/// Each tag needs `t` or `w`. A tag with `c` or `d` alone is `ref-denied`,
/// and nothing changes.
#[test]
fn a_tag_needs_t_or_w() {
    let tmp = TmpDir::new("sc-tag-rights");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let before = snapshot(&repo);
    let sc = ServerCommit {
        tags: vec!["v1".into()],
        ..server_commit("main")
    };
    for allow in [&["c:main", "cd:v1"][..], &["c:main", "r:v1"][..]] {
        let error = refused(
            push_sc(&repo, &policy_allowing(allow), &tree_objects(), sc.clone()),
            ErrorCode::RefDenied,
        );
        assert!(error.message.contains("no t or w on ref 'v1'"), "{error:?}");
        assert_unchanged(&repo, &before);
    }
    for allow in [&["c:main", "t:v1"][..], &["c:main", "w:v1"][..]] {
        let tmp = TmpDir::new("sc-tag-rights-ok");
        let repo = new_repo(&tmp, RepoMode::Archive, "");
        let report = committed(push_sc(
            &repo,
            &policy_allowing(allow),
            &tree_objects(),
            sc.clone(),
        ));
        assert_eq!(ref_at(&repo, "refs/heads/v1"), report.refs[1].new);
    }
}

/// A tag that exists is `ref-mismatch` with the ref and its commit, also
/// with `w` on the tag. The branch does not change.
#[test]
fn an_existing_tag_is_ref_mismatch() {
    let tmp = TmpDir::new("sc-tag-exists");
    let (repo, first) = repo_with_main(&tmp, "");
    let tagged = ServerCommit {
        tags: vec!["v1".into()],
        ..server_commit("other")
    };
    let report = committed(push_sc(
        &repo,
        &policy_allowing(&["c:**", "t:v1"]),
        &[],
        tagged,
    ));
    let tag = report.refs[1].new.unwrap();
    for allow in [&["c:**", "t:v1"][..], &["c:**", "w:v1"][..]] {
        let before = snapshot(&repo);
        let sc = ServerCommit {
            subject: "again".into(),
            tags: vec!["v1".into()],
            ..server_commit("main")
        };
        let error = refused(
            push_sc(&repo, &policy_allowing(allow), &[], sc),
            ErrorCode::RefMismatch,
        );
        let current = error.current.unwrap();
        assert_eq!(current.name, "v1");
        assert_eq!(current.commit, Some(tag));
        assert_unchanged(&repo, &before);
        assert_eq!(ref_at(&repo, "refs/heads/main"), Some(first));
    }
}

/// Each tag gets a ref at the new commit, and a bound name gets none. The
/// reply holds the branch, then each tag in order. The ref binding holds the
/// branch, the tags, and the bound names, sorted, with duplicates kept.
#[test]
fn tags_get_refs_and_bound_names_do_not() {
    let tmp = TmpDir::new("sc-tags");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let sc = ServerCommit {
        tags: vec!["v2".into(), "v1".into()],
        bind_refs: vec!["alias".into(), "main".into(), "alias".into()],
        ..server_commit("main")
    };
    let report = committed(push_sc(
        &repo,
        &policy_allowing(&["c:main", "t:v1", "t:v2"]),
        &tree_objects(),
        sc.clone(),
    ));
    let commit = sha(&expected_bytes(
        &sc,
        None,
        &["main", "v2", "v1", "alias", "main", "alias"],
        None,
    ));
    let entry = |name: &str| RefOutcome {
        name: name.into(),
        old: None,
        new: Some(commit),
    };
    assert_eq!(report.refs, vec![entry("main"), entry("v2"), entry("v1")]);
    for name in ["main", "v1", "v2"] {
        assert_eq!(ref_at(&repo, &format!("refs/heads/{name}")), Some(commit));
    }
    assert_eq!(ref_at(&repo, "refs/heads/alias"), None);
    assert_eq!(
        load(&repo, &commit).1.ref_bindings(),
        ["alias", "alias", "main", "main", "v1", "v2"]
    );
}

/// The metadata of the commit holds the entries of the client in order, with
/// a duplicate key, without the binding keys of the client, and then the
/// binding keys of the server. The collection binding is the own collection
/// id in the local refs, absent in a repository with no collection id, and
/// the collection of a collection namespace.
#[test]
fn the_metadata_and_the_bindings() {
    let client = vec![
        ("b".to_owned(), text("1")),
        (
            "ostree.ref-binding".to_owned(),
            v(&Value::variant(
                Type::parse("as").unwrap(),
                Value::Array(vec![Value::Str("x".into())]),
            )),
        ),
        ("a".to_owned(), v(&Value::variant(Type::U32, Value::U32(7)))),
        ("ostree.collection-binding".to_owned(), text("org.x")),
        ("b".to_owned(), text("2")),
    ];
    let kept = vec![
        ("b".to_owned(), text("1")),
        ("a".to_owned(), v(&Value::variant(Type::U32, Value::U32(7)))),
        ("b".to_owned(), text("2")),
    ];
    let sc = ServerCommit {
        metadata: client,
        ..server_commit("main")
    };
    let expected = ServerCommit {
        metadata: kept,
        ..server_commit("main")
    };
    let cases: [(&str, Option<&str>, Option<&str>, &str); 4] = [
        ("", None, None, "refs/heads/main"),
        (
            "collection-id=org.example.Own\n",
            None,
            Some("org.example.Own"),
            "refs/heads/main",
        ),
        (
            "",
            Some("org.example.Os"),
            Some("org.example.Os"),
            "refs/mirrors/org.example.Os/main",
        ),
        (
            "collection-id=org.example.Own\n",
            Some("org.example.Os"),
            Some("org.example.Os"),
            "refs/mirrors/org.example.Os/main",
        ),
    ];
    for (core, hello, binding, relpath) in cases {
        let tmp = TmpDir::new("sc-metadata");
        let repo = new_repo(&tmp, RepoMode::Archive, core);
        let policy = match hello {
            Some(_) => collections_policy(&["c:**"]),
            None => policy_allowing(&["c:**"]),
        };
        let report = committed(push_request(
            &repo,
            &policy,
            &["main"],
            hello,
            &tree_objects(),
            &[],
            request(sc.clone()),
        ));
        let commit = new_commit(&report);
        assert_eq!(
            load(&repo, &commit).0,
            expected_bytes(&expected, None, &["main"], binding),
            "{core} {hello:?}"
        );
        assert_eq!(load(&repo, &commit).1.collection_binding(), binding);
        assert_eq!(ref_at(&repo, relpath), Some(commit));
        assert_eq!(report.collection.as_deref(), hello);
    }
}

/// The entries of the client under `ostree.composefs.digest.v0` and
/// `ostree.sizes` come after the binding keys, the digest first, as in a
/// commit of `ostree commit`.
#[test]
fn the_digest_and_the_sizes_come_after_the_bindings() {
    let tmp = TmpDir::new("sc-digest");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let digest = Value::variant(Type::parse("ay").unwrap(), Value::Bytes(vec![7; 32]));
    let sizes = Value::variant(
        Type::parse("aay").unwrap(),
        Value::Array(vec![Value::Bytes(vec![1, 2])]),
    );
    let sc = ServerCommit {
        metadata: vec![
            ("ostree.sizes".into(), v(&sizes)),
            ("ostree.composefs.digest.v0".into(), v(&digest)),
            ("k".into(), text("v")),
        ],
        ..server_commit("main")
    };
    let report = committed(push_sc(
        &repo,
        &policy_allowing(&["c:**"]),
        &tree_objects(),
        sc,
    ));
    let commit = load(&repo, &new_commit(&report)).1;
    let Value::Array(entries) = &commit.metadata else {
        panic!("the metadata is an array")
    };
    let keys: Vec<&str> = entries
        .iter()
        .map(|entry| match entry {
            Value::Tuple(fields) => fields[0].as_str().unwrap(),
            other => panic!("an entry {other:?}"),
        })
        .collect();
    assert_eq!(
        keys,
        [
            "k",
            "ostree.ref-binding",
            "ostree.composefs.digest.v0",
            "ostree.sizes"
        ]
    );
    assert_eq!(commit.metadata.dict_get("ostree.sizes"), Some(&sizes));
}

/// The commit takes the timestamp of the client. With no timestamp, it takes
/// the clock of the server, also when the server process has
/// `SOURCE_DATE_EPOCH`. That case runs in a child process, so no test writes
/// to the environment of this process.
#[test]
fn the_timestamp_rule() {
    let tmp = TmpDir::new("sc-timestamp");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let sc = ServerCommit {
        timestamp: Some(12_345),
        ..server_commit("given")
    };
    let report = committed(push_sc(
        &repo,
        &policy_allowing(&["c:**"]),
        &tree_objects(),
        sc,
    ));
    assert_eq!(load(&repo, &new_commit(&report)).1.timestamp, 12_345);

    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    };
    let before = now();
    let sc = ServerCommit {
        timestamp: None,
        ..server_commit("clock")
    };
    let report = committed(push_sc(&repo, &policy_allowing(&["c:**"]), &[], sc));
    let after = now();
    let timestamp = load(&repo, &new_commit(&report)).1.timestamp;
    assert!(
        (before..=after).contains(&timestamp),
        "{before} {timestamp} {after}"
    );

    let before = now();
    writer_child_with(repo.path(), "child", |command| {
        command.env("SOURCE_DATE_EPOCH", "1");
    })
    .wait();
    let after = now();
    let repo = block_on(Repo::open(repo.path())).unwrap();
    let commit = ref_at(&repo, "refs/heads/child").unwrap();
    let timestamp = load(&repo, &commit).1.timestamp;
    assert!(
        (before..=after).contains(&timestamp),
        "{before} {timestamp} {after}"
    );
}

// ---------------------------------------------------------------------------
// Signatures.
// ---------------------------------------------------------------------------

/// The server key of the policy signs the commit, over the stored commit
/// bytes.
#[test]
fn server_keys_sign_the_commit() {
    let tmp = TmpDir::new("sc-sign");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let policy = ReceivePolicy {
        signers: vec![server_signer(SERVER_SECRET_B64)],
        ..policy_allowing(&["c:**"])
    };
    let report = committed(push_sc(
        &repo,
        &policy,
        &tree_objects(),
        server_commit("main"),
    ));
    let commit = new_commit(&report);
    let (bytes, _) = load(&repo, &commit);
    assert_eq!(
        stored_signatures(&repo, &commit, ED25519_KEY),
        vec![ed25519_signature(SERVER_SECRET_B64, &bytes)]
    );
    let public = secret(SERVER_SECRET_B64)[32..].to_vec();
    let verifier = Ed25519Verifier::new([public], Vec::<Vec<u8>>::new()).unwrap();
    let outcome = block_on(repo.verify_commit(&commit, &[&verifier])).unwrap();
    assert!(outcome.valid, "the server signature verifies");
}

/// A server commit onto a tip that names a dependency signs the new commit
/// alone. The dependency gets no server signature.
#[test]
fn a_dependency_of_the_tip_gets_no_server_signature() {
    let tmp = TmpDir::new("sc-sign-dependency");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let dep = build_commit(None, "dependency", Value::Array(Vec::new()), &[]);
    let tip = build_commit(
        None,
        "tip",
        Value::Array(Vec::new()),
        &[("lib/d", &dep.checksum.as_bytes()[..])],
    );
    let mut objects = tree_objects();
    objects.extend([dep.clone(), tip.clone()]);
    let updates = vec![RefUpdate {
        name: "main".into(),
        expected: Expected::Absent,
        new: Some(tip.checksum),
    }];
    committed(push_request(
        &repo,
        &policy_allowing(&["w:**"]),
        &["main"],
        None,
        &objects,
        &[],
        CommitRequest {
            updates,
            force: false,
            server_commit: None,
        },
    ));

    let policy = ReceivePolicy {
        signers: vec![server_signer(SERVER_SECRET_B64)],
        ..policy_allowing(&["c:**"])
    };
    let report = committed(push_sc(&repo, &policy, &[], server_commit("main")));
    let commit = new_commit(&report);
    let (bytes, parsed) = load(&repo, &commit);
    assert_eq!(parsed.parent, Some(tip.checksum));
    assert!(parsed.related.is_empty());
    assert_eq!(
        stored_signatures(&repo, &commit, ED25519_KEY),
        vec![ed25519_signature(SERVER_SECRET_B64, &bytes)]
    );
    assert!(stored_signatures(&repo, &dep.checksum, ED25519_KEY).is_empty());
    assert!(stored_signatures(&repo, &tip.checksum, ED25519_KEY).is_empty());
}

/// A policy with `verify` and no `allow_unsigned` accepts a server commit,
/// which carries no signature of the client.
#[test]
fn verify_does_not_apply() {
    let tmp = TmpDir::new("sc-verify");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let public = secret(OTHER_SECRET_B64)[32..].to_vec();
    let verifier: Arc<dyn Verifier> =
        Arc::new(Ed25519Verifier::new([public], Vec::<Vec<u8>>::new()).unwrap());
    let policy = ReceivePolicy {
        verify: ReceiveVerify::Keys(Arc::new(TrustedKeys::new(vec![verifier]).unwrap())),
        allow_unsigned: false,
        ..policy_allowing(&["c:**"])
    };
    let report = committed(push_sc(
        &repo,
        &policy,
        &tree_objects(),
        server_commit("main"),
    ));
    assert_eq!(ref_at(&repo, "refs/heads/main"), Some(new_commit(&report)));
}

/// Two key groups that read one key file sign the commit once.
#[test]
fn two_key_groups_with_one_key_file_sign_once() {
    let tmp = TmpDir::new("sc-one-key-twice");
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
        "[ex-ostrya client \"c\"]\nauth=ssh:c\nallow=c:**\nsign=first;second\n{}{}",
        group("first"),
        group("second")
    ));
    std::fs::write(&config, text).unwrap();
    let repo = block_on(Repo::open(repo.path())).unwrap();
    let policies = block_on(ReceivePolicies::from_config(&repo)).unwrap();
    let policy = policies.get("c").unwrap();
    assert_eq!(policy.signers.len(), 2);
    let report = committed(push_sc(
        &repo,
        policy,
        &tree_objects(),
        server_commit("main"),
    ));
    let commit = new_commit(&report);
    let (bytes, _) = load(&repo, &commit);
    assert_eq!(
        stored_signatures(&repo, &commit, ED25519_KEY),
        vec![ed25519_signature(SERVER_SECRET_B64, &bytes)]
    );
}

/// An `orphan` server commit whose inputs equal those of a commit that the
/// repository holds gets the checksum of that commit. Its stored signature
/// stays, a second key adds one, and a key that signed it adds none. The
/// branch does not change.
#[test]
fn a_commit_with_equal_inputs_keeps_its_stored_signature() {
    let tmp = TmpDir::new("sc-equal");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let orphan = ServerCommit {
        orphan: true,
        ..server_commit("main")
    };
    let first = ReceivePolicy {
        signers: vec![server_signer(SERVER_SECRET_B64)],
        ..policy_allowing(&["cd:**"])
    };
    let commit = new_commit(&committed(push_sc(
        &repo,
        &first,
        &tree_objects(),
        orphan.clone(),
    )));
    let bytes = load(&repo, &commit).0;
    let both = ReceivePolicy {
        signers: vec![
            server_signer(SERVER_SECRET_B64),
            server_signer(SECOND_SERVER_SECRET_B64),
        ],
        ..policy_allowing(&["cd:**"])
    };
    let report = committed(push_sc(&repo, &both, &[], orphan));
    assert_eq!(
        report.refs,
        vec![RefOutcome {
            name: "main".into(),
            old: Some(commit),
            new: Some(commit),
        }]
    );
    assert_eq!(
        stored_signatures(&repo, &commit, ED25519_KEY),
        vec![
            ed25519_signature(SERVER_SECRET_B64, &bytes),
            ed25519_signature(SECOND_SERVER_SECRET_B64, &bytes),
        ]
    );
}

/// A GPG server key signs the commit under the update lock, and the
/// signature verifies.
#[cfg(feature = "sign-gpg")]
#[test]
fn a_gpg_server_key_signs_the_commit() {
    if !common::gnupg_available(&["gpg", "gpgconf"]) {
        eprintln!("skipping a_gpg_server_key_signs_the_commit: no GnuPG");
        return;
    }
    let tmp = TmpDir::new("sc-gpg");
    let home = common::receive::GnupgHome::new(
        &tmp.path().join("gnupg"),
        "Receive Server <server@example.org>",
    );
    let signer = ostrya::GpgSigner::new("server@example.org").with_homedir(&home.dir);
    let policy = ReceivePolicy {
        signers: vec![Arc::new(block_on(ServerSigner::gpg(signer)).unwrap())],
        ..policy_allowing(&["c:**"])
    };
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let report = committed(push_sc(
        &repo,
        &policy,
        &tree_objects(),
        server_commit("main"),
    ));
    let commit = new_commit(&report);
    assert_eq!(stored_signatures(&repo, &commit, "ostree.gpgsigs").len(), 1);
    let verifier = ostrya::GpgVerifier::from_keyring_bytes([home.export()]).unwrap();
    let outcome = block_on(repo.verify_commit(&commit, &[&verifier])).unwrap();
    assert!(outcome.valid, "the server signature verifies");
}

// ---------------------------------------------------------------------------
// The refusals before the update lock.
// ---------------------------------------------------------------------------

/// A tree that the session did not send and the repository does not hold is
/// `missing-objects`, and the detail names the root dirtree.
#[test]
fn missing_tree_objects_are_missing_objects() {
    let tmp = TmpDir::new("sc-missing");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let before = snapshot(&repo);
    let error = refused(
        push_sc(
            &repo,
            &policy_allowing(&["c:**"]),
            &[],
            server_commit("main"),
        ),
        ErrorCode::MissingObjects,
    );
    assert!(
        error
            .missing
            .iter()
            .any(|n| n.ty == ObjectType::DirTree && n.checksum == checksum(ROOT_DIRTREE)),
        "{error:?}"
    );
    assert_unchanged(&repo, &before);
}

/// A detached metadata dict, and a staged commit object, in a session with a
/// server commit are `protocol`.
#[test]
fn detached_metadata_in_a_server_commit_session_is_protocol() {
    let tmp = TmpDir::new("sc-detached");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let before = snapshot(&repo);
    let dict =
        ostrya_core::to_bytes(&Type::parse("a{sv}").unwrap(), &Value::Array(Vec::new())).unwrap();
    let commit = sha(&expected_bytes(
        &server_commit("main"),
        None,
        &["main"],
        None,
    ));
    let error = refused(
        push_request(
            &repo,
            &policy_allowing(&["c:**"]),
            &["main"],
            None,
            &tree_objects(),
            &[(commit, dict)],
            request(server_commit("main")),
        ),
        ErrorCode::Protocol,
    );
    assert!(error.message.contains("detached metadata"), "{error:?}");
    assert_unchanged(&repo, &before);

    let error = refused(
        push_sc(
            &repo,
            &policy_allowing(&["c:**"]),
            &fixture_objects(Encoding::Raw),
            server_commit("main"),
        ),
        ErrorCode::Protocol,
    );
    assert!(error.message.contains("is staged"), "{error:?}");
    assert_unchanged(&repo, &before);
}

/// The form of the message: a server commit with an update, a server commit
/// with `force`, a tag that `Hello` does not name, and a ref that the message
/// writes two times are each `protocol`.
#[test]
fn the_form_of_a_server_commit_message() {
    let tmp = TmpDir::new("sc-form");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let before = snapshot(&repo);
    let policy = policy_allowing(&["c:**", "t:**", "w:**"]);
    let with_update = CommitRequest {
        updates: vec![RefUpdate {
            name: "other".into(),
            expected: Expected::Absent,
            new: Some(checksum(ROOT_DIRTREE)),
        }],
        ..request(server_commit("main"))
    };
    let with_force = CommitRequest {
        force: true,
        ..request(server_commit("main"))
    };
    let tagged = |tags: &[&str]| ServerCommit {
        tags: tags.iter().map(|&t| t.into()).collect(),
        ..server_commit("main")
    };
    let cases: [(&[&str], CommitRequest, &str); 5] = [
        (&["main", "other"], with_update, "ref updates"),
        (&["main"], with_force, "force"),
        (&["main"], request(tagged(&["v1"])), "'v1' was not named"),
        (&["main"], request(tagged(&["main"])), "more than once"),
        (
            &["main", "v1"],
            request(tagged(&["v1", "v1"])),
            "more than once",
        ),
    ];
    for (names, request, needle) in cases {
        let error = refused(
            push_request(&repo, &policy, names, None, &tree_objects(), &[], request),
            ErrorCode::Protocol,
        );
        assert!(error.message.contains(needle), "{needle}: {error:?}");
        assert_unchanged(&repo, &before);
    }
}

/// The bytes of a `v` that holds a `y` under `levels` levels of maybe.
fn nested_maybe(levels: usize) -> Vec<u8> {
    let ty = (0..levels).fold(Type::Byte, |ty, _| Type::maybe(ty));
    let value = (0..levels).fold(Value::Byte(1), |value, _| {
        Value::Maybe(Some(Box::new(value)))
    });
    v(&Value::variant(ty, value))
}

/// A metadata value that a commit cannot hold within the depth limit is
/// `protocol` before the update lock, and the session writes nothing. A `y`
/// under 125 levels of maybe is the deepest value that a commit holds, and
/// the commit holds its bytes. The message carries 126 levels.
#[test]
fn a_metadata_value_too_deep_for_a_commit_is_protocol() {
    let tmp = TmpDir::new("sc-depth");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let policy = policy_allowing(&["c:**"]);
    let deep = |branch: &str, levels: usize| ServerCommit {
        metadata: vec![("deep".into(), nested_maybe(levels))],
        ..server_commit(branch)
    };
    let before = snapshot(&repo);
    let error = refused(
        push_sc(&repo, &policy, &tree_objects(), deep("main", 126)),
        ErrorCode::Protocol,
    );
    assert!(error.message.contains("'deep'"), "{error:?}");
    assert_unchanged(&repo, &before);

    let sc = deep("main", 125);
    let report = committed(push_sc(&repo, &policy, &tree_objects(), sc.clone()));
    let commit = new_commit(&report);
    assert_eq!(
        load(&repo, &commit).0,
        expected_bytes(&sc, None, &["main"], None)
    );
}

/// A branch or a tag of 64 lowercase hex characters, and a bound name that
/// fails the refspec rule or holds `:`, are `invalid-ref`.
#[test]
fn invalid_names_are_invalid_ref() {
    let tmp = TmpDir::new("sc-names");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let before = snapshot(&repo);
    let hex = "a".repeat(64);
    let policy = policy_allowing(&["c:**", "t:**"]);
    let cases = [
        (vec![hex.clone()], server_commit(&hex)),
        (
            vec!["main".to_owned(), hex.clone()],
            ServerCommit {
                tags: vec![hex.clone()],
                ..server_commit("main")
            },
        ),
        (
            vec!["main".to_owned()],
            ServerCommit {
                bind_refs: vec!["origin:main".into()],
                ..server_commit("main")
            },
        ),
        (
            vec!["main".to_owned()],
            ServerCommit {
                bind_refs: vec!["a b".into()],
                ..server_commit("main")
            },
        ),
    ];
    for (names, sc) in cases {
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        let error = refused(
            server_push(&repo, &policy, &names, &tree_objects(), sc),
            ErrorCode::InvalidRef,
        );
        assert!(error.message.contains("invalid"), "{error:?}");
        assert_unchanged(&repo, &before);
    }
}

/// In the local refs of a repository with a collection id, a server commit
/// cannot write `ostree-metadata`, as a branch or as a tag.
#[test]
fn ostree_metadata_is_ref_denied_in_the_local_refs_of_a_collection_repo() {
    let tmp = TmpDir::new("sc-anchor-ref");
    let repo = new_repo(&tmp, RepoMode::Archive, "collection-id=org.example.C\n");
    let before = snapshot(&repo);
    let policy = policy_allowing(&["c:**", "t:**"]);
    for sc in [
        server_commit("ostree-metadata"),
        ServerCommit {
            tags: vec!["ostree-metadata".into()],
            ..server_commit("main")
        },
    ] {
        let error = refused(
            push_sc(&repo, &policy, &tree_objects(), sc),
            ErrorCode::RefDenied,
        );
        assert!(error.message.contains("anchor"), "{error:?}");
        assert_unchanged(&repo, &before);
    }
}

/// In a repository with a collection id and a policy that regenerates the
/// summary, a server commit also writes the anchor commit, and the summary
/// names the new commit.
#[test]
fn a_collection_repo_writes_the_anchor_after_a_server_commit() {
    let tmp = TmpDir::new("sc-anchor");
    let repo = new_repo(&tmp, RepoMode::Archive, "collection-id=org.example.C\n");
    let policy = ReceivePolicy {
        update_summary: true,
        ..policy_allowing(&["c:**"])
    };
    let report = committed(push_sc(
        &repo,
        &policy,
        &tree_objects(),
        server_commit("main"),
    ));
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    let commit = new_commit(&report);
    assert_eq!(
        load(&repo, &commit).1.collection_binding(),
        Some("org.example.C")
    );
    let anchor = block_on(repo.resolve_ref_tip("ostree-metadata"))
        .unwrap()
        .expect("the anchor ref");
    let summary = Summary::parse(&block_on(repo.read_summary()).unwrap().unwrap()).unwrap();
    assert_eq!(summary.lookup("ostree-metadata"), Some(anchor));
    assert_eq!(summary.lookup("main"), Some(commit));
}

// ---------------------------------------------------------------------------
// Races.
// ---------------------------------------------------------------------------

/// Runs two sessions of `repo` at the same time, each one with its policy and
/// its server commit, and no object.
fn race(
    repo: &Repo,
    first: (&ReceivePolicy, ServerCommit),
    second: (&ReceivePolicy, ServerCommit),
) -> (Pushed, Pushed) {
    let (c1, in1, out1) = connect();
    let (c2, in2, out2) = connect();
    let names1 = hello_names(&first.1);
    let names2 = hello_names(&second.1);
    let ((r1, reply1), (r2, reply2)) = block_on(futures_lite::future::zip(
        futures_lite::future::zip(
            repo.receive(in1, out1, first.0),
            script(c1, names1, None, &[], &[], request(first.1)),
        ),
        futures_lite::future::zip(
            repo.receive(in2, out2, second.0),
            script(c2, names2, None, &[], &[], request(second.1)),
        ),
    ));
    ((r1, reply1), (r2, reply2))
}

/// Two server commits on one branch at the same time both succeed. The
/// second one under the update lock takes the first one as its parent.
#[test]
fn two_server_commits_on_one_branch_chain() {
    let tmp = TmpDir::new("sc-race-chain");
    let (repo, tip) = repo_with_main(&tmp, "");
    let policy = policy_allowing(&["c:**"]);
    let one = ServerCommit {
        subject: "one".into(),
        ..server_commit("main")
    };
    let two = ServerCommit {
        subject: "two".into(),
        ..server_commit("main")
    };
    let (a, b) = race(&repo, (&policy, one), (&policy, two));
    let (a, b) = (committed(a), committed(b));
    let (early, late) = if a.refs[0].old == Some(tip) {
        (a, b)
    } else {
        (b, a)
    };
    let first = new_commit(&early);
    let second = new_commit(&late);
    assert_eq!(early.refs[0].old, Some(tip));
    assert_eq!(late.refs[0].old, Some(first));
    assert_eq!(load(&repo, &first).1.parent, Some(tip));
    assert_eq!(load(&repo, &second).1.parent, Some(first));
    assert_eq!(ref_at(&repo, "refs/heads/main"), Some(second));
}

/// Two server commits that create one tag at the same time: one succeeds,
/// and the other is `ref-mismatch` with the commit of the winner.
#[test]
fn two_server_commits_that_create_one_tag() {
    let tmp = TmpDir::new("sc-race-tag");
    let (repo, _) = repo_with_main(&tmp, "");
    let policy = policy_allowing(&["c:**", "t:v1"]);
    let tagged = |branch: &str| ServerCommit {
        tags: vec!["v1".into()],
        ..server_commit(branch)
    };
    let (a, b) = race(&repo, (&policy, tagged("main")), (&policy, tagged("other")));
    let (ok, failed) = match (a.0.is_ok(), b.0.is_ok()) {
        (true, false) => (a, b),
        (false, true) => (b, a),
        other => panic!("expected one success, got {other:?}"),
    };
    let winner = new_commit(&committed(ok));
    let error = refused(failed, ErrorCode::RefMismatch);
    let current = error.current.unwrap();
    assert_eq!(current.name, "v1");
    assert_eq!(current.commit, Some(winner));
    assert_eq!(ref_at(&repo, "refs/heads/v1"), Some(winner));
}

/// An `orphan` server commit with `c` alone on an absent branch races a
/// server commit that creates the branch. If the orphan commit comes second,
/// it is `non-fast-forward`. If it comes first, both succeed, and the other
/// commit takes it as its parent.
#[test]
fn an_orphan_commit_that_comes_second_is_non_fast_forward() {
    let tmp = TmpDir::new("sc-race-orphan");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    committed(push_sc(
        &repo,
        &policy_allowing(&["c:**"]),
        &tree_objects(),
        server_commit("seed"),
    ));
    let policy = policy_allowing(&["c:**"]);
    let orphan = ServerCommit {
        subject: "orphan".into(),
        orphan: true,
        ..server_commit("main")
    };
    let normal = ServerCommit {
        subject: "normal".into(),
        ..server_commit("main")
    };
    let (o, n) = race(&repo, (&policy, orphan), (&policy, normal));
    match (o.0.is_ok(), n.0.is_ok()) {
        (false, true) => {
            let created = new_commit(&committed(n));
            refused(o, ErrorCode::NonFastForward);
            assert_eq!(ref_at(&repo, "refs/heads/main"), Some(created));
        }
        (true, true) => {
            let root = new_commit(&committed(o));
            let child = new_commit(&committed(n));
            assert_eq!(load(&repo, &child).1.parent, Some(root));
            assert_eq!(ref_at(&repo, "refs/heads/main"), Some(child));
        }
        other => panic!("unexpected outcome {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Comparison with the `ostree` command.
// ---------------------------------------------------------------------------

/// The commit of the server with the inputs of a commit of `ostree commit`
/// has the checksum of that commit.
///
/// Each case runs `ostree commit --no-xattrs -b BRANCH` with `--bind-ref`
/// names, a subject, a body, and metadata, in an `archive` repository of the
/// tool. The port then reads the commit and its tree objects from that
/// repository. A session sends the tree objects and a server commit with the
/// fields of the commit: its subject, body, timestamp, and metadata without
/// the two binding keys. The reply must give the checksum of the tool.
mod tool {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    /// The timestamp of each commit of the tool.
    const EPOCH: &str = "1700000000";

    /// A tree with a file, a directory with a file, and a symlink.
    fn tree(base: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let root = base.join("tree");
        std::fs::create_dir_all(root.join("dir")).unwrap();
        std::fs::write(root.join("a"), "alpha\n").unwrap();
        std::fs::write(root.join("dir/b"), "beta\n").unwrap();
        std::os::unix::fs::symlink("a", root.join("link")).unwrap();
        for (path, mode) in [("a", 0o644), ("dir/b", 0o755), ("dir", 0o755), ("", 0o755)] {
            std::fs::set_permissions(root.join(path), std::fs::Permissions::from_mode(mode))
                .unwrap();
        }
        root
    }

    fn run(repo: &Path, args: &[&str]) -> String {
        let out = Command::new("ostree")
            .arg(format!("--repo={}", repo.display()))
            .args(args)
            .env("SOURCE_DATE_EPOCH", EPOCH)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "ostree {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    /// An `archive` repository of the tool at `<base>/tool`, with the
    /// collection id `collection`.
    fn tool_repo(base: &Path, collection: Option<&str>) -> PathBuf {
        let repo = base.join("tool");
        let mut args = vec!["init".to_owned(), "--mode=archive".to_owned()];
        if let Some(id) = collection {
            args.push(format!("--collection-id={id}"));
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        run(&repo, &args);
        repo
    }

    /// Runs `ostree commit --no-xattrs` of `tree` in `repo` with `args` and
    /// the subject `subject`, and returns the commit.
    fn tool_commit(repo: &Path, tree: &Path, subject: &str, args: &[&str]) -> Checksum {
        let subject = format!("--subject={subject}");
        let mut all = vec![
            "commit",
            "--no-xattrs",
            subject.as_str(),
            "--body=Body\nline",
            "--add-metadata-string=version=1.0",
            "--add-metadata=n=uint32 1",
            "--add-metadata-string=version=2.0",
        ];
        all.extend_from_slice(args);
        all.push(tree.to_str().unwrap());
        checksum(run(repo, &all).trim())
    }

    /// The server commit of the commit `commit` of the tool repository
    /// `tool`, on `branch` with `tags`, `bind_refs`, and `orphan`.
    fn fields(
        tool: &Path,
        commit: &Checksum,
        branch: &str,
        tags: &[&str],
        bind_refs: &[&str],
        orphan: bool,
    ) -> ServerCommit {
        let repo = block_on(Repo::open(tool)).unwrap();
        let (_, parsed) = load(&repo, commit);
        let Value::Array(entries) = parsed.metadata else {
            panic!("the metadata is an array")
        };
        let metadata = entries
            .into_iter()
            .filter_map(|entry| {
                let Value::Tuple(mut fields) = entry else {
                    panic!("an entry")
                };
                let value = fields.pop().unwrap();
                let Value::Str(key) = fields.pop().unwrap() else {
                    panic!("a key")
                };
                (key != "ostree.ref-binding" && key != "ostree.collection-binding")
                    .then(|| (key, v(&value)))
            })
            .collect();
        let names = |names: &[&str]| names.iter().map(|&n| n.to_owned()).collect();
        ServerCommit {
            branch: branch.into(),
            tags: names(tags),
            bind_refs: names(bind_refs),
            root_dirtree: parsed.root_dirtree,
            root_dirmeta: parsed.root_dirmeta,
            subject: parsed.subject,
            body: parsed.body,
            metadata,
            timestamp: Some(parsed.timestamp),
            orphan,
        }
    }

    /// The tree objects of `commit` of the tool repository `tool`, with the
    /// content objects as their `.filez` files.
    fn tree_of(tool: &Path, commit: &Checksum) -> Vec<Obj> {
        commit_objects(tool, commit, Encoding::Deflate)
            .into_iter()
            .filter(|o| o.ty != ObjectType::Commit)
            .collect()
    }

    /// Sends the tree of `commit` of the tool and the server commit `sc` to
    /// `port` in the namespace `collection`, and returns the new commit.
    fn server(
        port: &Repo,
        policy: &ReceivePolicy,
        collection: Option<&str>,
        tool: &Path,
        commit: &Checksum,
        sc: ServerCommit,
    ) -> Checksum {
        let names = hello_names(&sc);
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        let objects = tree_of(tool, commit);
        let report = committed(push_request(
            port,
            policy,
            &names,
            collection,
            &objects,
            &[],
            request(sc),
        ));
        new_commit(&report)
    }

    /// Returns `true` if the tool is installed, else writes the skip.
    fn available(test: &str) -> bool {
        let found = common::ostree_available();
        if !found {
            eprintln!("skipping {test}: `ostree` is not installed");
        }
        found
    }

    /// With no collection id on either side, a server commit equals
    /// `ostree commit -b main --bind-ref v1 --bind-ref alias`, where `v1` is
    /// a tag and `alias` a bound name. A second commit on the branch takes the
    /// tip as its parent on both sides. An `orphan` commit with `cd` equals
    /// `--parent=none`. `ostree fsck` passes on the repository of the port,
    /// and `ostree show` reads the commit.
    #[test]
    fn a_server_commit_equals_the_commit_of_the_tool() {
        if !available("a_server_commit_equals_the_commit_of_the_tool") {
            return;
        }
        let tmp = TmpDir::new("sc-tool-local");
        let tree = tree(tmp.path());
        let tool = tool_repo(tmp.path(), None);
        let port = new_repo(&tmp, RepoMode::Archive, "");
        let policy = policy_allowing(&["cd:main", "t:v1", "t:v2"]);

        let first = tool_commit(
            &tool,
            &tree,
            "first",
            &["-b", "main", "--bind-ref=v1", "--bind-ref=alias"],
        );
        let sc = fields(&tool, &first, "main", &["v1"], &["alias"], false);
        assert_eq!(server(&port, &policy, None, &tool, &first, sc), first);
        assert_eq!(ref_at(&port, "refs/heads/v1"), Some(first));
        assert_eq!(ref_at(&port, "refs/heads/alias"), None);

        let second = tool_commit(&tool, &tree, "second", &["-b", "main"]);
        let sc = fields(&tool, &second, "main", &[], &[], false);
        assert_eq!(server(&port, &policy, None, &tool, &second, sc), second);
        assert_eq!(load(&port, &second).1.parent, Some(first));

        let orphan = tool_commit(&tool, &tree, "orphan", &["-b", "main", "--parent=none"]);
        let sc = fields(&tool, &orphan, "main", &[], &[], true);
        assert_eq!(server(&port, &policy, None, &tool, &orphan, sc), orphan);
        assert_eq!(ref_at(&port, "refs/heads/main"), Some(orphan));

        tool_fsck(port.path());
        let shown = run(port.path(), &["show", &orphan.to_hex()]);
        assert!(shown.contains(&orphan.to_hex()), "{shown}");
        assert!(shown.contains("orphan"), "{shown}");
    }

    /// With the collection id `org.example.T` in the repository of the tool,
    /// a server commit equals the commit of the tool in two namespaces of the
    /// port: the local refs of a repository with the same id, and the
    /// collection `org.example.T` of a repository with another id or with no
    /// id. `ostree refs -c` lists the collection ref that the port writes.
    #[test]
    fn a_server_commit_equals_the_commit_of_the_tool_with_a_collection() {
        if !available("a_server_commit_equals_the_commit_of_the_tool_with_a_collection") {
            return;
        }
        const ID: &str = "org.example.T";
        let tmp = TmpDir::new("sc-tool-collection");
        let tree = tree(tmp.path());
        let tool = tool_repo(tmp.path(), Some(ID));
        let first = tool_commit(&tool, &tree, "first", &["-b", "main", "--bind-ref=v1"]);
        let second = tool_commit(&tool, &tree, "second", &["-b", "main"]);
        for (core, hello, relpath) in [
            (format!("collection-id={ID}\n"), None, "refs/heads"),
            (
                "collection-id=org.example.Other\n".to_owned(),
                Some(ID),
                "refs/mirrors/org.example.T",
            ),
            (String::new(), Some(ID), "refs/mirrors/org.example.T"),
        ] {
            let base = TmpDir::new("sc-tool-port");
            let port = new_repo(&base, RepoMode::Archive, &core);
            let policy = match hello {
                Some(_) => collections_policy(&["c:main", "t:v1", "t:v2"]),
                None => policy_allowing(&["c:main", "t:v1", "t:v2"]),
            };
            let sc = fields(&tool, &first, "main", &["v1"], &[], false);
            assert_eq!(
                server(&port, &policy, hello, &tool, &first, sc),
                first,
                "{core} {hello:?}"
            );
            let sc = fields(&tool, &second, "main", &[], &[], false);
            assert_eq!(
                server(&port, &policy, hello, &tool, &second, sc),
                second,
                "{core} {hello:?}"
            );
            assert_eq!(ref_at(&port, &format!("{relpath}/main")), Some(second));
            assert_eq!(ref_at(&port, &format!("{relpath}/v1")), Some(first));
            tool_fsck(port.path());
            if hello.is_some() {
                let listed = run(port.path(), &["refs", "-c"]);
                assert!(listed.contains("(org.example.T, main)"), "{listed}");
                assert!(listed.contains("(org.example.T, v1)"), "{listed}");
            }
        }
    }
}
