//! Tests of the hooks of a receive session:
//!
//! - `before_update`, which runs before the update lock
//! - the detached-metadata entries of the host, and their merge
//! - the checks of the plan
//! - the refusals of the hook
//! - the drop of the carried value
//! - `after_update`, which runs after the release of the update lock

#![cfg(feature = "receive")]

mod common;

use std::any::Any;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use common::receive::{Obj, assert_staging_removed, body, fixture_objects, is_root, new_repo};
use common::{COMMIT, TmpDir, foreign_holder, lock_holder_main};
use ostrya::push::proto::{CommitRequest, Hello};
use ostrya::push::{self, Encoding, Expected, RefUpdate};
use ostrya::{
    Checksum, DetachedMetadataFilter, Error, HookFuture, HookRefusal, HostEntry, LockKind,
    MAX_METADATA_SIZE, ObjectType, ReceiveHooks, ReceivePolicy, ReceiveReport, ReceiveRule,
    ReceiveService, Repo, RepoMode, Type, UpdatePlan, Value,
};
use ostrya_rt::block_on;

#[test]
#[ignore = "helper process for the lock tests"]
fn lock_holder_subprocess() {
    lock_holder_main();
}

// ---------------------------------------------------------------------------
// The test hook.
// ---------------------------------------------------------------------------

/// The detached-metadata entries of a plan.
type Metadata = Vec<(Checksum, Vec<HostEntry>)>;

type PlanFn = dyn Fn(&[RefUpdate]) -> Result<UpdatePlan, HookRefusal> + Send + Sync;

type AfterFn = dyn Fn(&ReceiveReport, Box<dyn Any + Send>) -> HookFuture<'static, Result<(), String>>
    + Send
    + Sync;

/// A hook that gives the result of `plan` before the update lock, and the
/// result of `after` after it. It counts the calls of each, and records each
/// report that `after_update` gets.
struct Hook {
    plan: Box<PlanFn>,
    after: Box<AfterFn>,
    calls: AtomicUsize,
    after_calls: AtomicUsize,
    reports: Mutex<Vec<ReceiveReport>>,
}

impl ReceiveHooks for Hook {
    fn before_update<'a>(
        &'a self,
        updates: &'a [RefUpdate],
    ) -> HookFuture<'a, Result<UpdatePlan, HookRefusal>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let result = (self.plan)(updates);
        Box::pin(async move { result })
    }

    fn after_update<'a>(
        &'a self,
        report: &'a ReceiveReport,
        carried: Box<dyn Any + Send>,
    ) -> HookFuture<'a, Result<(), String>> {
        self.after_calls.fetch_add(1, Ordering::SeqCst);
        self.reports.lock().unwrap().push(report.clone());
        (self.after)(report, carried)
    }
}

impl Hook {
    /// A hook whose `after_update` drops the carried value and succeeds.
    fn new(
        plan: impl Fn(&[RefUpdate]) -> Result<UpdatePlan, HookRefusal> + Send + Sync + 'static,
    ) -> Arc<Hook> {
        Hook::with_after(plan, |_, carried| {
            drop(carried);
            Box::pin(async { Ok(()) })
        })
    }

    fn with_after(
        plan: impl Fn(&[RefUpdate]) -> Result<UpdatePlan, HookRefusal> + Send + Sync + 'static,
        after: impl Fn(&ReceiveReport, Box<dyn Any + Send>) -> HookFuture<'static, Result<(), String>>
        + Send
        + Sync
        + 'static,
    ) -> Arc<Hook> {
        Arc::new(Hook {
            plan: Box::new(plan),
            after: Box::new(after),
            calls: AtomicUsize::new(0),
            after_calls: AtomicUsize::new(0),
            reports: Mutex::new(Vec::new()),
        })
    }

    /// A hook whose plan gives `metadata` each time, with a carried value
    /// that counts its drops in `drops`.
    fn giving(metadata: Metadata, drops: &Arc<AtomicUsize>) -> Arc<Hook> {
        let drops = drops.clone();
        Hook::new(move |_| {
            Ok(UpdatePlan {
                metadata: metadata.clone(),
                carried: Box::new(DropCount(drops.clone())),
            })
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn after_calls(&self) -> usize {
        self.after_calls.load(Ordering::SeqCst)
    }

    /// The reports that `after_update` got, in order.
    fn reports(&self) -> Vec<ReceiveReport> {
        self.reports.lock().unwrap().clone()
    }
}

/// A carried value that counts its drops.
struct DropCount(Arc<AtomicUsize>);

impl Drop for DropCount {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// A carried value that takes an update guard of `repo` on another thread
/// when it drops, and records the result in `seen`. With
/// `lock-timeout-secs=0`, the take fails at once while another holder has the
/// update lock.
struct LockProbe {
    repo: Repo,
    seen: Arc<Mutex<Vec<Result<(), String>>>>,
}

impl Drop for LockProbe {
    fn drop(&mut self) {
        let repo = self.repo.clone();
        let taken = std::thread::spawn(move || {
            block_on(async {
                let guard = repo.begin_update().await.map_err(|e| e.to_string())?;
                guard.finish().await.map_err(|e| e.to_string())
            })
        })
        .join()
        .unwrap();
        self.seen.lock().unwrap().push(taken);
    }
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

fn hello(refs: &[&str]) -> Hello {
    Hello {
        version: 1,
        agent: None,
        refs: refs.iter().map(|r| r.to_string()).collect(),
        one_way: false,
    }
}

fn fixture_commit() -> Checksum {
    Checksum::from_hex(COMMIT).unwrap()
}

fn main_update() -> RefUpdate {
    RefUpdate {
        name: "test/main".into(),
        expected: Expected::Absent,
        new: Some(fixture_commit()),
    }
}

/// Runs one session of `repo` with `hooks`: one object stream of `objects`,
/// then `Commit` with `updates`. Returns the service for the steps after the
/// commit, and the result of the commit.
fn run(
    repo: &Repo,
    hooks: Option<Arc<Hook>>,
    objects: &[Obj],
    updates: Vec<RefUpdate>,
) -> (ReceiveService, ostrya::Result<ReceiveReport>) {
    run_with(repo, ReceivePolicy::default(), hooks, objects, updates)
}

/// [`run`] with `policy`.
fn run_with(
    repo: &Repo,
    policy: ReceivePolicy,
    hooks: Option<Arc<Hook>>,
    objects: &[Obj],
    updates: Vec<RefUpdate>,
) -> (ReceiveService, ostrya::Result<ReceiveReport>) {
    let names: Vec<&str> = updates.iter().map(|u| u.name.as_str()).collect();
    let hooks = hooks.map(|h| h as Arc<dyn ReceiveHooks>);
    let (service, _) = block_on(ReceiveService::hello_with_hooks(
        repo.clone(),
        Arc::new(policy),
        hooks,
        1,
        hello(&names),
    ))
    .unwrap();
    block_on(service.objects(&body(objects)[..])).unwrap();
    let result = block_on(service.commit(CommitRequest {
        updates,
        force: false,
    }));
    (service, result)
}

/// Pushes the fixture commit and the objects `extra` to `test/main` with
/// `hooks`.
fn push(repo: &Repo, hooks: Option<Arc<Hook>>, extra: &[Obj]) -> ostrya::Result<ReceiveReport> {
    let mut objects = fixture_objects(Encoding::Raw);
    objects.extend_from_slice(extra);
    run(repo, hooks, &objects, vec![main_update()]).1
}

/// A string as a variant.
fn text(value: &str) -> Value {
    Value::variant(Type::Str, Value::Str(value.into()))
}

/// A string as a variant, inside `depth` more variants.
fn nested_variants(depth: usize) -> Value {
    (0..depth).fold(text("x"), |value, _| Value::variant(Type::Variant, value))
}

/// A variant whose type is `depth` nested maybe types around a byte, with
/// the value `nothing`. The value is shallow, and its type can nest over the
/// depth limit.
fn deep_maybe(depth: usize) -> Value {
    let ty = (0..depth).fold(Type::Byte, |ty, _| Type::Maybe(Box::new(ty)));
    Value::variant(ty, Value::Maybe(None))
}

fn entry(key: &str, value: Value, keep_existing: bool) -> HostEntry {
    HostEntry {
        key: key.into(),
        value,
        keep_existing,
    }
}

/// The serialized `a{sv}` dict of `entries`, in order.
fn dict_bytes(entries: Vec<(&str, Value)>) -> Vec<u8> {
    let dict = Value::Array(
        entries
            .into_iter()
            .map(|(key, value)| Value::Tuple(vec![Value::Str(key.into()), value]))
            .collect(),
    );
    ostrya_core::to_bytes(&Type::parse("a{sv}").unwrap(), &dict).unwrap()
}

/// The detached metadata object of the fixture commit that a client sends.
fn client_dict(entries: Vec<(&str, Value)>) -> Obj {
    Obj {
        ty: ObjectType::CommitMeta,
        checksum: fixture_commit(),
        encoding: Encoding::Raw,
        bytes: dict_bytes(entries),
    }
}

/// The path of the `.commitmeta` file of the fixture commit.
fn commitmeta_path(repo: &Repo) -> PathBuf {
    repo.path().join("objects").join(ostrya::loose_path(
        &fixture_commit(),
        ObjectType::CommitMeta,
        repo.mode(),
    ))
}

/// Writes `bytes` as the stored detached metadata of the fixture commit.
fn plant_stored(repo: &Repo, bytes: Vec<u8>) {
    let path = commitmeta_path(repo);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, bytes).unwrap();
}

/// The stored detached metadata of the fixture commit.
fn stored(repo: &Repo) -> Option<Value> {
    block_on(repo.read_commit_detached_metadata(&fixture_commit())).unwrap()
}

/// The string under `key` of `dict`, at its first entry.
fn text_of(dict: &Value, key: &str) -> Option<String> {
    dict.dict_get(key)
        .and_then(Value::as_variant)
        .and_then(|(_, value)| value.as_str().map(str::to_owned))
}

/// The keys of `dict`, in order.
fn keys(dict: &Value) -> Vec<String> {
    let Value::Array(entries) = dict else {
        panic!("not a dict: {dict:?}");
    };
    entries
        .iter()
        .map(|entry| match entry {
            Value::Tuple(fields) => fields[0].as_str().unwrap().to_owned(),
            other => panic!("not an entry: {other:?}"),
        })
        .collect()
}

/// Asserts that the session of `service` is aborted. A `have` step after the
/// commit fails as `protocol`, with the message "the session was aborted".
fn assert_aborted(service: &ReceiveService, case: &str) {
    match block_on(service.have(Vec::new())) {
        Err(Error::Push(push::Error::Protocol(message))) => {
            assert!(
                message.contains("the session was aborted"),
                "{case}: {message}"
            )
        }
        other => panic!("{case}: expected protocol, got {other:?}"),
    }
}

/// The commit that `test/main` names, if the ref is present.
fn main_ref(repo: &Repo) -> Option<String> {
    std::fs::read_to_string(repo.path().join("refs/heads/test/main"))
        .ok()
        .map(|text| text.trim().to_owned())
}

/// The commit that `test/after` names, if the ref is present.
fn after_ref(repo: &Repo) -> Option<String> {
    std::fs::read_to_string(repo.path().join("refs/heads/test/after"))
        .ok()
        .map(|text| text.trim().to_owned())
}

/// A plan of one host entry for the fixture commit, with a carried value
/// that counts its drops in `drops`.
fn one_entry_plan(drops: &Arc<AtomicUsize>) -> UpdatePlan {
    UpdatePlan {
        metadata: vec![(
            fixture_commit(),
            vec![entry("centrex.uploader", text("host"), false)],
        )],
        carried: Box::new(DropCount(drops.clone())),
    }
}

/// A hook that gives [`one_entry_plan`]. Its `after_update` does these
/// steps:
///
/// 1. It asserts that `test/main` and the report name the fixture commit.
/// 2. It asserts that the carried value is the [`DropCount`] of `drops`, and
///    that the count of drops is 0.
/// 3. While it holds the carried value, it writes `test/after` with
///    `Repo::set_ref_immediate`.
/// 4. It drops the carried value and returns the result of the write.
fn writing_after(repo: &Repo, drops: &Arc<AtomicUsize>) -> Arc<Hook> {
    let plan_drops = drops.clone();
    let drops = drops.clone();
    let repo = repo.clone();
    Hook::with_after(
        move |_| Ok(one_entry_plan(&plan_drops)),
        move |report, carried| {
            assert_eq!(main_ref(&repo).as_deref(), Some(COMMIT));
            assert_eq!(report.refs[0].new, Some(fixture_commit()));
            let carried = carried
                .downcast::<DropCount>()
                .expect("the carried value of the plan");
            assert!(Arc::ptr_eq(&carried.0, &drops));
            assert_eq!(drops.load(Ordering::SeqCst), 0);
            let repo = repo.clone();
            Box::pin(async move {
                let written = repo
                    .set_ref_immediate("test/after", Some(&fixture_commit()))
                    .await;
                drop(carried);
                written.map_err(|e| e.to_string())
            })
        },
    )
}

// ---------------------------------------------------------------------------
// The entries of the host.
// ---------------------------------------------------------------------------

/// The session stores the entries of the host with the ref. A commit with no
/// client dict gets a new dict.
#[test]
fn the_entries_are_stored_with_the_ref() {
    let tmp = TmpDir::new("hooks-stored");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let drops = Arc::new(AtomicUsize::new(0));
    let hook = Hook::giving(
        vec![(
            fixture_commit(),
            vec![
                entry("centrex.uploader", text("host"), false),
                entry("centrex.source", text("ci"), true),
            ],
        )],
        &drops,
    );
    let report = push(&repo, Some(hook.clone()), &[]).unwrap();
    assert_eq!(report.refs.len(), 1);
    assert_eq!(hook.calls(), 1);
    assert_eq!(main_ref(&repo).as_deref(), Some(COMMIT));
    let dict = stored(&repo).expect("a dict");
    assert_eq!(keys(&dict), ["centrex.uploader", "centrex.source"]);
    assert_eq!(text_of(&dict, "centrex.uploader").as_deref(), Some("host"));
    assert_eq!(text_of(&dict, "centrex.source").as_deref(), Some("ci"));
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

/// The session writes the detached metadata before the refs. If the ref
/// directory is read-only, the commit fails at the ref write, and the
/// `.commitmeta` file holds the entries of the host.
#[test]
fn the_entries_are_written_before_the_refs() {
    use std::os::unix::fs::PermissionsExt;

    if is_root() {
        eprintln!("skipped: root writes into a read-only directory");
        return;
    }
    let tmp = TmpDir::new("hooks-order");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let heads = repo.path().join("refs/heads");
    std::fs::set_permissions(&heads, std::fs::Permissions::from_mode(0o555)).unwrap();
    let drops = Arc::new(AtomicUsize::new(0));
    let hook = Hook::giving(
        vec![(
            fixture_commit(),
            vec![entry("centrex.uploader", text("host"), false)],
        )],
        &drops,
    );
    let result = push(&repo, Some(hook), &[]);
    std::fs::set_permissions(&heads, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        matches!(&result, Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::PermissionDenied),
        "{result:?}"
    );
    assert_eq!(main_ref(&repo), None);
    let dict = stored(&repo).expect("the detached metadata is written");
    assert_eq!(text_of(&dict, "centrex.uploader").as_deref(), Some("host"));
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

/// A host entry replaces the client entry of the same key, with no
/// duplicate-key error, and the other client entries stay.
#[test]
fn a_host_entry_wins_over_the_client() {
    let tmp = TmpDir::new("hooks-host-wins");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let drops = Arc::new(AtomicUsize::new(0));
    let hook = Hook::giving(
        vec![(
            fixture_commit(),
            vec![entry("centrex.uploader", text("host"), false)],
        )],
        &drops,
    );
    let client = client_dict(vec![
        ("centrex.uploader", text("client")),
        ("x", Value::variant(Type::U32, Value::U32(1))),
    ]);
    push(&repo, Some(hook), &[client]).unwrap();
    let dict = stored(&repo).unwrap();
    assert_eq!(keys(&dict), ["x", "centrex.uploader"]);
    assert_eq!(text_of(&dict, "centrex.uploader").as_deref(), Some("host"));
    assert_eq!(
        dict.dict_get("x"),
        Some(&Value::variant(Type::U32, Value::U32(1)))
    );
}

/// A host entry with `keep_existing` keeps the value that the stored dict
/// holds under its key. If the stored dict has no such key, the session
/// writes the entry. An entry without `keep_existing` replaces the stored
/// value. The session drops the client value of a key of the host. A commit
/// with no client dict reads its stored dict for the merge.
#[test]
fn keep_existing_keeps_a_stored_value() {
    for with_client in [true, false] {
        let tmp = TmpDir::new("hooks-keep");
        let repo = new_repo(&tmp, RepoMode::Archive, "");
        plant_stored(
            &repo,
            dict_bytes(vec![
                ("centrex.uploader", text("first")),
                ("other", text("stored")),
            ]),
        );
        let drops = Arc::new(AtomicUsize::new(0));
        let hook = Hook::giving(
            vec![(
                fixture_commit(),
                vec![
                    entry("centrex.uploader", text("second"), true),
                    entry("centrex.source", text("src"), true),
                    entry("other", text("host"), false),
                ],
            )],
            &drops,
        );
        let extra = if with_client {
            vec![client_dict(vec![("centrex.uploader", text("client"))])]
        } else {
            Vec::new()
        };
        push(&repo, Some(hook), &extra).unwrap();
        let dict = stored(&repo).unwrap();
        assert_eq!(
            keys(&dict),
            ["centrex.uploader", "other", "centrex.source"],
            "with client dict {with_client}"
        );
        assert_eq!(text_of(&dict, "centrex.uploader").as_deref(), Some("first"));
        assert_eq!(text_of(&dict, "centrex.source").as_deref(), Some("src"));
        assert_eq!(text_of(&dict, "other").as_deref(), Some("host"));
    }
}

/// The host merge takes a stored dict that the edit plan of the session read
/// and that no edit took. The exclude filter empties the client dict, so the
/// edit plan reads the stored dict and adds no edit. `keep_existing` keeps the
/// stored value. An entry without `keep_existing` replaces the stored value,
/// and the other stored entries stay.
#[test]
fn the_host_merge_takes_a_stored_dict_the_plan_read() {
    let tmp = TmpDir::new("hooks-leftover");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    plant_stored(
        &repo,
        dict_bytes(vec![
            ("centrex.uploader", text("first")),
            ("other", text("stored")),
            ("kept", text("stored")),
        ]),
    );
    let drops = Arc::new(AtomicUsize::new(0));
    let hook = Hook::giving(
        vec![(
            fixture_commit(),
            vec![
                entry("centrex.uploader", text("second"), true),
                entry("other", text("host"), false),
                entry("centrex.source", text("src"), true),
            ],
        )],
        &drops,
    );
    let policy = ReceivePolicy {
        detached_metadata_filter: Some(DetachedMetadataFilter::excluding(["dropped"])),
        ..ReceivePolicy::default()
    };
    let mut objects = fixture_objects(Encoding::Raw);
    objects.push(client_dict(vec![("dropped", text("client"))]));
    let (_, result) = run_with(&repo, policy, Some(hook), &objects, vec![main_update()]);
    result.unwrap();
    let dict = stored(&repo).unwrap();
    assert_eq!(
        keys(&dict),
        ["centrex.uploader", "other", "kept", "centrex.source"]
    );
    assert_eq!(text_of(&dict, "centrex.uploader").as_deref(), Some("first"));
    assert_eq!(text_of(&dict, "other").as_deref(), Some("host"));
    assert_eq!(text_of(&dict, "kept").as_deref(), Some("stored"));
    assert_eq!(text_of(&dict, "centrex.source").as_deref(), Some("src"));
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

/// A plan with no entry, and a plan whose tuple holds no entry, write no
/// detached metadata.
#[test]
fn an_empty_plan_writes_no_detached_metadata() {
    for metadata in [Vec::new(), vec![(fixture_commit(), Vec::new())]] {
        let tmp = TmpDir::new("hooks-empty");
        let repo = new_repo(&tmp, RepoMode::Archive, "");
        let drops = Arc::new(AtomicUsize::new(0));
        let hook = Hook::giving(metadata, &drops);
        push(&repo, Some(hook.clone()), &[]).unwrap();
        assert_eq!(hook.calls(), 1);
        assert_eq!(main_ref(&repo).as_deref(), Some(COMMIT));
        assert!(!commitmeta_path(&repo).exists());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}

// ---------------------------------------------------------------------------
// Refusals.
// ---------------------------------------------------------------------------

/// Each plan that the checks refuse fails as `internal`, with
/// `Error::InvalidInput`. For each plan, the test checks these results:
///
/// - The session writes no ref and no detached metadata.
/// - The session removes the staging directory and ends.
/// - The hook runs once.
#[test]
fn a_refused_plan_is_internal_and_writes_nothing() {
    let random = Checksum::from_bytes([0x5a; 32]);
    let old = Checksum::from_bytes([0x6b; 32]);
    let ok = || entry("centrex.uploader", text("host"), false);
    let cases: Vec<(&str, Metadata, &str)> = vec![
        (
            "unknown commit",
            vec![(random, vec![ok()])],
            "no ref update names",
        ),
        (
            "old commit of an update",
            vec![(old, vec![ok()])],
            "no ref update names",
        ),
        (
            "duplicate tuple",
            vec![
                (fixture_commit(), vec![ok()]),
                (fixture_commit(), vec![entry("b", text("b"), false)]),
            ],
            "in two tuples",
        ),
        (
            "signature key",
            vec![(
                fixture_commit(),
                vec![entry("ostree.sign.ed25519", text("x"), false)],
            )],
            "signature key",
        ),
        (
            "duplicate key",
            vec![(fixture_commit(), vec![ok(), ok()])],
            "two times",
        ),
        (
            "not a variant",
            vec![(
                fixture_commit(),
                vec![entry("centrex.uploader", Value::U32(1), false)],
            )],
            "not a variant",
        ),
        (
            "inner type mismatch",
            vec![(
                fixture_commit(),
                vec![entry(
                    "centrex.uploader",
                    Value::variant(Type::U32, Value::Str("x".into())),
                    false,
                )],
            )],
            "does not encode",
        ),
        (
            "key with NUL",
            vec![(fixture_commit(), vec![entry("a\0b", text("x"), false)])],
            "does not encode",
        ),
        (
            "value string with NUL",
            vec![(
                fixture_commit(),
                vec![entry("centrex.uploader", text("a\0b"), false)],
            )],
            "does not encode",
        ),
        (
            "value nested over the depth limit",
            vec![(
                fixture_commit(),
                vec![entry("centrex.uploader", nested_variants(140), false)],
            )],
            "does not encode",
        ),
        (
            "dict entry with a container key",
            vec![(
                fixture_commit(),
                vec![entry(
                    "centrex.uploader",
                    Value::variant(
                        Type::DictEntry(Box::new(Type::Variant), Box::new(Type::Byte)),
                        Value::Tuple(vec![text("k"), Value::Byte(1)]),
                    ),
                    false,
                )],
            )],
            "does not encode",
        ),
        (
            "type nested over the depth limit",
            vec![(
                fixture_commit(),
                vec![entry("centrex.uploader", deep_maybe(140), false)],
            )],
            "does not encode",
        ),
    ];
    for (case, metadata, needle) in cases {
        let tmp = TmpDir::new("hooks-refused");
        let repo = new_repo(&tmp, RepoMode::Archive, "");
        let drops = Arc::new(AtomicUsize::new(0));
        let hook = Hook::giving(metadata, &drops);
        let updates = vec![
            main_update(),
            // A delete of a ref that the client expects at `old`.
            RefUpdate {
                name: "test/other".into(),
                expected: Expected::Commit(old),
                new: None,
            },
        ];
        let (service, result) = run(
            &repo,
            Some(hook.clone()),
            &fixture_objects(Encoding::Raw),
            updates,
        );
        match &result {
            Err(Error::InvalidInput(message)) => {
                assert!(message.contains(needle), "{case}: {message}")
            }
            other => panic!("{case}: expected InvalidInput, got {other:?}"),
        }
        assert_eq!(hook.calls(), 1, "{case}");
        assert_eq!(hook.after_calls(), 0, "{case}");
        assert_eq!(drops.load(Ordering::SeqCst), 1, "{case}");
        assert_eq!(main_ref(&repo), None, "{case}");
        assert!(!commitmeta_path(&repo).exists(), "{case}");
        assert_staging_removed(repo.path());
        assert_aborted(&service, case);
    }
}

/// The checks refuse a plan that names the commit of a delete-only push,
/// because that commit is not the new commit of an update.
#[test]
fn a_delete_only_push_refuses_entries() {
    let tmp = TmpDir::new("hooks-delete");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    push(&repo, None, &[]).unwrap();
    let drops = Arc::new(AtomicUsize::new(0));
    let hook = Hook::giving(
        vec![(
            fixture_commit(),
            vec![entry("centrex.uploader", text("host"), false)],
        )],
        &drops,
    );
    let delete = RefUpdate {
        name: "test/main".into(),
        expected: Expected::Commit(fixture_commit()),
        new: None,
    };
    let (_, result) = run(&repo, Some(hook.clone()), &[], vec![delete]);
    assert!(
        matches!(&result, Err(Error::InvalidInput(m)) if m.contains("no ref update names")),
        "{result:?}"
    );
    assert_eq!(hook.calls(), 1);
    assert_eq!(main_ref(&repo).as_deref(), Some(COMMIT));
    assert!(!commitmeta_path(&repo).exists());
}

/// `HookRefusal::denied` fails as `ref-denied` and `HookRefusal::internal`
/// fails as `internal`, each with its message. The session writes no ref,
/// removes the staging directory, and ends. If a message is longer than 4096
/// bytes, the session cuts it at a character boundary.
#[test]
fn a_hook_refusal_keeps_its_code() {
    let long = format!("a{}", "\u{e9}".repeat(3000));
    for (denied, message) in [
        (true, "no such release".to_owned()),
        (false, "the database is down".to_owned()),
        (true, long.clone()),
    ] {
        let tmp = TmpDir::new("hooks-refusal");
        let repo = new_repo(&tmp, RepoMode::Archive, "");
        let given = message.clone();
        let hook = Hook::new(move |_| {
            Err(if denied {
                HookRefusal::denied(given.clone())
            } else {
                HookRefusal::internal(given.clone())
            })
        });
        let (service, result) = run(
            &repo,
            Some(hook.clone()),
            &fixture_objects(Encoding::Raw),
            vec![main_update()],
        );
        let got = match (denied, result) {
            (true, Err(Error::Push(push::Error::RefDenied(m)))) => m,
            (false, Err(Error::Push(push::Error::Internal(m)))) => m,
            (_, other) => panic!("denied {denied}: {other:?}"),
        };
        if message.len() > 4096 {
            assert_eq!(got.len(), 4095);
            assert!(message.starts_with(&got));
        } else {
            assert_eq!(got, message);
        }
        assert_eq!(hook.calls(), 1);
        assert_eq!(hook.after_calls(), 0);
        assert_eq!(main_ref(&repo), None);
        assert!(!commitmeta_path(&repo).exists());
        assert_staging_removed(repo.path());
        assert_aborted(&service, &format!("denied {denied}"));
    }
}

/// A merged dict over the size limit fails as `limit-exceeded` before the
/// update lock. Another process holds the update lock with
/// `lock-timeout-secs=0`, and the commit does not get the timeout.
#[test]
fn a_merged_dict_over_the_limit_is_refused_before_the_lock() {
    let tmp = TmpDir::new("hooks-over-limit");
    let repo = new_repo(&tmp, RepoMode::Archive, "lock-timeout-secs=0\n");
    let big = || Value::variant(Type::parse("ay").unwrap(), Value::Bytes(vec![0; 65 << 20]));
    let client = client_dict(vec![("a", big())]);
    assert!(client.bytes.len() as u64 <= MAX_METADATA_SIZE);
    let mut objects = fixture_objects(Encoding::Raw);
    objects.push(client);
    let drops = Arc::new(AtomicUsize::new(0));
    // The hook gives its plan once, so the test does not copy the large entry.
    let plan = Mutex::new(Some(vec![(
        fixture_commit(),
        vec![entry("k", big(), false)],
    )]));
    let carried = drops.clone();
    let hook = Hook::new(move |_| {
        Ok(UpdatePlan {
            metadata: plan.lock().unwrap().take().expect("one call"),
            carried: Box::new(DropCount(carried.clone())),
        })
    });
    let holder = foreign_holder(repo.path(), ".update.lock");
    let (_, result) = run(&repo, Some(hook.clone()), &objects, vec![main_update()]);
    drop(holder);
    assert!(
        matches!(
            &result,
            Err(Error::Push(push::Error::LimitExceeded(m))) if m.contains("merged detached metadata")
        ),
        "{result:?}"
    );
    assert_eq!(hook.calls(), 1);
    assert_eq!(hook.after_calls(), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(main_ref(&repo), None);
    assert!(!commitmeta_path(&repo).exists());
}

// ---------------------------------------------------------------------------
// The carried value and the order of the checks.
// ---------------------------------------------------------------------------

/// The carried value drops once when a ref check fails under the lock.
#[test]
fn the_carried_value_drops_once_on_a_ref_mismatch() {
    let tmp = TmpDir::new("hooks-mismatch");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let drops = Arc::new(AtomicUsize::new(0));
    let hook = Hook::giving(
        vec![(
            fixture_commit(),
            vec![entry("centrex.uploader", text("host"), false)],
        )],
        &drops,
    );
    let update = RefUpdate {
        expected: Expected::Commit(Checksum::from_bytes([0x11; 32])),
        ..main_update()
    };
    let (_, result) = run(
        &repo,
        Some(hook.clone()),
        &fixture_objects(Encoding::Raw),
        vec![update],
    );
    assert!(
        matches!(&result, Err(Error::Push(push::Error::RefMismatch { .. }))),
        "{result:?}"
    );
    assert_eq!(hook.calls(), 1);
    assert_eq!(hook.after_calls(), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(main_ref(&repo), None);
    assert!(!commitmeta_path(&repo).exists());
}

/// The carried value drops after the release of the update lock, on success
/// and when a ref check under the lock fails. First, the test checks that the
/// probe sees a held update lock as held.
#[test]
fn the_carried_value_drops_after_the_update_lock_is_released() {
    let tmp = TmpDir::new("hooks-lock-free");
    let repo = new_repo(&tmp, RepoMode::Archive, "lock-timeout-secs=0\n");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let guard = block_on(repo.begin_update()).unwrap();
    drop(LockProbe {
        repo: repo.clone(),
        seen: seen.clone(),
    });
    block_on(guard.finish()).unwrap();
    assert!(
        matches!(seen.lock().unwrap().as_slice(), [Err(_)]),
        "the probe took a held lock"
    );

    for expected in [
        Expected::Absent,
        Expected::Commit(Checksum::from_bytes([0x11; 32])),
    ] {
        let tmp = TmpDir::new("hooks-lock-free");
        let repo = new_repo(&tmp, RepoMode::Archive, "lock-timeout-secs=0\n");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let probe = (repo.clone(), seen.clone());
        let hook = Hook::new(move |_| {
            Ok(UpdatePlan {
                metadata: vec![(
                    fixture_commit(),
                    vec![entry("centrex.uploader", text("host"), false)],
                )],
                carried: Box::new(LockProbe {
                    repo: probe.0.clone(),
                    seen: probe.1.clone(),
                }),
            })
        });
        let update = RefUpdate {
            expected,
            ..main_update()
        };
        let (_, result) = run(
            &repo,
            Some(hook),
            &fixture_objects(Encoding::Raw),
            vec![update],
        );
        match expected {
            Expected::Absent => assert!(result.is_ok(), "{result:?}"),
            _ => assert!(
                matches!(&result, Err(Error::Push(push::Error::RefMismatch { .. }))),
                "{result:?}"
            ),
        }
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            [Ok(())],
            "expected {expected:?}"
        );
    }
}

/// A commit whose objects are missing fails before the hook.
#[test]
fn missing_objects_do_not_call_the_hook() {
    let tmp = TmpDir::new("hooks-missing");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let drops = Arc::new(AtomicUsize::new(0));
    let hook = Hook::giving(Vec::new(), &drops);
    let (_, result) = run(&repo, Some(hook.clone()), &[], vec![main_update()]);
    assert!(
        matches!(
            &result,
            Err(Error::Push(push::Error::MissingObjects { .. }))
        ),
        "{result:?}"
    );
    assert_eq!(hook.calls(), 0);
    assert_eq!(hook.after_calls(), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
}

// ---------------------------------------------------------------------------
// `after_update`.
// ---------------------------------------------------------------------------

/// `after_update` runs after the release of the update lock, when the refs
/// are written. With `lock-timeout-secs=0`, `Repo::set_ref_immediate` fails
/// at once while another holder has an update guard. In the hook, the same
/// call writes its ref. The hook gets the carried value of the plan and the
/// report that the commit returns.
#[test]
fn after_update_runs_with_the_update_lock_free() {
    let tmp = TmpDir::new("hooks-after-free");
    let repo = new_repo(&tmp, RepoMode::Archive, "lock-timeout-secs=0\n");
    let guard = block_on(repo.begin_update()).unwrap();
    let held = block_on(repo.set_ref_immediate("test/after", Some(&fixture_commit())));
    block_on(guard.finish()).unwrap();
    assert!(
        matches!(&held, Err(Error::LockTimeout { .. })),
        "the write took a held lock: {held:?}"
    );
    assert_eq!(after_ref(&repo), None);

    let drops = Arc::new(AtomicUsize::new(0));
    let hook = writing_after(&repo, &drops);
    let report = push(&repo, Some(hook.clone()), &[]).unwrap();
    assert_eq!(hook.calls(), 1);
    assert_eq!(hook.after_calls(), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(after_ref(&repo).as_deref(), Some(COMMIT));
    assert_eq!(hook.reports(), std::slice::from_ref(&report));
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
}

/// [`after_update_runs_with_the_update_lock_free`] with
/// `lock-timeout-secs=-1`, where a held lock makes the write in the hook wait
/// with no end. The commit runs on a thread. If the commit does not end in
/// 30 s, the test fails.
#[test]
fn after_update_does_not_wait_with_no_lock_timeout() {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let tmp = TmpDir::new("hooks-after-wait");
        let repo = new_repo(&tmp, RepoMode::Archive, "lock-timeout-secs=-1\n");
        let drops = Arc::new(AtomicUsize::new(0));
        let hook = writing_after(&repo, &drops);
        let result = push(&repo, Some(hook.clone()), &[]);
        let _ = sender.send((
            result.map(|_| ()).map_err(|e| e.to_string()),
            hook.after_calls(),
            drops.load(Ordering::SeqCst),
            after_ref(&repo),
        ));
    });
    let (result, after_calls, drops, written) = match receiver.recv_timeout(Duration::from_secs(30))
    {
        Ok(got) => got,
        Err(mpsc::RecvTimeoutError::Timeout) => panic!("the commit did not end in 30 s"),
        Err(mpsc::RecvTimeoutError::Disconnected) => panic!("the commit thread panicked"),
    };
    assert_eq!(result, Ok(()));
    assert_eq!(after_calls, 1);
    assert_eq!(drops, 1);
    assert_eq!(written.as_deref(), Some(COMMIT));
}

/// An error of `after_update` fails the commit as `internal`, with its
/// message. The refs and the detached metadata stay written. The session
/// removes the staging directory and ends as aborted. If a message is longer
/// than 4096 bytes, the session cuts it at a character boundary.
#[test]
fn an_after_update_error_is_internal_with_the_refs_written() {
    let long = format!("a{}", "\u{e9}".repeat(3000));
    for message in ["the database is down".to_owned(), long] {
        let tmp = TmpDir::new("hooks-after-error");
        let repo = new_repo(&tmp, RepoMode::Archive, "");
        let drops = Arc::new(AtomicUsize::new(0));
        let plan_drops = drops.clone();
        let given = message.clone();
        let hook = Hook::with_after(
            move |_| Ok(one_entry_plan(&plan_drops)),
            move |_, carried| {
                drop(carried);
                let given = given.clone();
                Box::pin(async move { Err(given) })
            },
        );
        let (service, result) = run(
            &repo,
            Some(hook.clone()),
            &fixture_objects(Encoding::Raw),
            vec![main_update()],
        );
        let got = match result {
            Err(Error::Push(push::Error::Internal(m))) => m,
            other => panic!("expected internal, got {other:?}"),
        };
        if message.len() > 4096 {
            assert!(got.len() <= 4096, "{}", got.len());
            assert!(message.is_char_boundary(got.len()));
            assert_eq!(got.len(), 4095);
            assert!(message.starts_with(&got));
        } else {
            assert_eq!(got, message);
        }
        assert_eq!(main_ref(&repo).as_deref(), Some(COMMIT));
        let dict = stored(&repo).expect("the detached metadata is written");
        assert_eq!(text_of(&dict, "centrex.uploader").as_deref(), Some("host"));
        assert_staging_removed(repo.path());
        assert_aborted(&service, "after_update error");
        assert_eq!(hook.calls(), 1);
        assert_eq!(hook.after_calls(), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}

/// If the commit fails after `before_update`, `after_update` does not run.
/// The test makes two failures: a ref mismatch, and an update lock that
/// another process holds with `lock-timeout-secs=0`. In both cases, the
/// carried value drops once, and the session writes no ref.
#[test]
fn after_update_does_not_run_when_the_commit_fails_after_before_update() {
    for mismatch in [true, false] {
        let tmp = TmpDir::new("hooks-after-failure");
        let repo = new_repo(&tmp, RepoMode::Archive, "lock-timeout-secs=0\n");
        let drops = Arc::new(AtomicUsize::new(0));
        let plan_drops = drops.clone();
        let hook = Hook::new(move |_| Ok(one_entry_plan(&plan_drops)));
        let update = if mismatch {
            RefUpdate {
                expected: Expected::Commit(Checksum::from_bytes([0x11; 32])),
                ..main_update()
            }
        } else {
            main_update()
        };
        let holder = (!mismatch).then(|| foreign_holder(repo.path(), ".update.lock"));
        let (_, result) = run(
            &repo,
            Some(hook.clone()),
            &fixture_objects(Encoding::Raw),
            vec![update],
        );
        drop(holder);
        if mismatch {
            assert!(
                matches!(&result, Err(Error::Push(push::Error::RefMismatch { .. }))),
                "{result:?}"
            );
        } else {
            assert!(
                matches!(&result, Err(Error::LockTimeout { .. })),
                "{result:?}"
            );
        }
        assert_eq!(hook.calls(), 1, "mismatch {mismatch}");
        assert_eq!(hook.after_calls(), 0, "mismatch {mismatch}");
        assert_eq!(drops.load(Ordering::SeqCst), 1, "mismatch {mismatch}");
        assert_eq!(main_ref(&repo), None, "mismatch {mismatch}");
    }
}

/// `after_update` also runs when no ref changes. A second session pushes the
/// commit that the ref already names.
#[test]
fn after_update_runs_when_no_ref_changes() {
    let tmp = TmpDir::new("hooks-after-same");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    push(&repo, None, &[]).unwrap();
    let drops = Arc::new(AtomicUsize::new(0));
    let hook = Hook::giving(Vec::new(), &drops);
    let update = RefUpdate {
        expected: Expected::Commit(fixture_commit()),
        ..main_update()
    };
    let (_, result) = run(&repo, Some(hook.clone()), &[], vec![update]);
    let report = result.unwrap();
    assert_eq!(report.refs[0].old, Some(fixture_commit()));
    assert_eq!(report.refs[0].new, Some(fixture_commit()));
    assert_eq!(hook.calls(), 1);
    assert_eq!(hook.after_calls(), 1);
    assert_eq!(hook.reports(), [report]);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(main_ref(&repo).as_deref(), Some(COMMIT));
}

/// Opens a transaction of `repo` that holds the repository lock exclusive,
/// and aborts it.
async fn take_exclusive(repo: &Repo) -> ostrya::Result<()> {
    repo.transaction_with_lock(LockKind::Exclusive)
        .await?
        .abort()
        .await
}

/// `after_update` runs with the repository lock free. With
/// `lock-timeout-secs=0`, a transaction that takes the repository lock
/// exclusive fails at once while another transaction holds the lock shared.
/// In the hook, the same transaction opens.
#[test]
fn after_update_runs_with_the_repository_lock_free() {
    let tmp = TmpDir::new("hooks-after-repo-lock");
    let repo = new_repo(&tmp, RepoMode::Archive, "lock-timeout-secs=0\n");
    let shared = block_on(repo.transaction()).unwrap();
    let held = block_on(take_exclusive(&repo));
    block_on(shared.abort()).unwrap();
    assert!(
        matches!(&held, Err(Error::LockTimeout { .. })),
        "the transaction took a held lock: {held:?}"
    );

    let drops = Arc::new(AtomicUsize::new(0));
    let plan_drops = drops.clone();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let probe = (repo.clone(), seen.clone());
    let hook = Hook::with_after(
        move |_| Ok(one_entry_plan(&plan_drops)),
        move |_, carried| {
            let (repo, seen) = probe.clone();
            Box::pin(async move {
                let taken = take_exclusive(&repo).await;
                seen.lock().unwrap().push(taken.map_err(|e| e.to_string()));
                drop(carried);
                Ok(())
            })
        },
    );
    push(&repo, Some(hook.clone()), &[]).unwrap();
    assert_eq!(seen.lock().unwrap().as_slice(), [Ok(())]);
    assert_eq!(hook.after_calls(), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

/// The transaction commit is not atomic. If the directory of the second ref
/// is read-only, the commit deletes the first ref and then fails at the
/// delete of the second. The commit returns the error of the write, and the
/// session ends as aborted. `after_update` does not run, and the carried
/// value drops once.
#[test]
fn after_update_does_not_run_when_the_transaction_commit_fails() {
    use std::os::unix::fs::PermissionsExt;

    if is_root() {
        eprintln!("skipped: root writes into a read-only directory");
        return;
    }
    let tmp = TmpDir::new("hooks-after-partial");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    push(&repo, None, &[]).unwrap();
    block_on(repo.set_ref_immediate("ro/x", Some(&fixture_commit()))).unwrap();
    let ro = repo.path().join("refs/heads/ro");
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();
    let drops = Arc::new(AtomicUsize::new(0));
    let hook = Hook::giving(Vec::new(), &drops);
    let policy = ReceivePolicy {
        default_rule: ReceiveRule {
            allow_delete: true,
            ..ReceiveRule::default()
        },
        ..ReceivePolicy::default()
    };
    let delete = |name: &str| RefUpdate {
        name: name.into(),
        expected: Expected::Commit(fixture_commit()),
        new: None,
    };
    let (service, result) = run_with(
        &repo,
        policy,
        Some(hook.clone()),
        &[],
        vec![delete("test/main"), delete("ro/x")],
    );
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o755)).unwrap();
    let access = rustix::io::Errno::ACCESS.raw_os_error();
    assert!(
        matches!(&result, Err(Error::Io(e)) if e.raw_os_error() == Some(access)),
        "{result:?}"
    );
    assert_eq!(main_ref(&repo), None);
    assert!(ro.join("x").exists());
    assert_staging_removed(repo.path());
    assert_aborted(&service, "transaction commit failure");
    assert_eq!(hook.calls(), 1);
    assert_eq!(hook.after_calls(), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

/// The futures of a session with hooks can run on a thread pool.
const _: fn() = || {
    fn assert_send<T: Send>(_: T) {}
    let _ = |repo: Repo, policy: Arc<ReceivePolicy>, hooks: Arc<dyn ReceiveHooks>, hello: Hello| {
        assert_send(ReceiveService::hello_with_hooks(
            repo,
            policy,
            Some(hooks),
            1,
            hello,
        ))
    };
    let _ = |service: &ReceiveService, request: CommitRequest| {
        assert_send(service.commit(request));
    };
};
