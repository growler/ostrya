//! The hooks of a receive session: `before_update` before the update lock,
//! the detached-metadata entries of the host and their merge, the checks of
//! the plan, the refusals of the hook, and the drop of the carried value.

#![cfg(feature = "receive")]

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use common::receive::{Obj, assert_staging_removed, body, fixture_objects, is_root, new_repo};
use common::{COMMIT, TmpDir, foreign_holder, lock_holder_main};
use ostrya::push::proto::{CommitRequest, Hello};
use ostrya::push::{self, Encoding, Expected, RefUpdate};
use ostrya::{
    Checksum, DetachedMetadataFilter, Error, HookFuture, HookRefusal, HostEntry, MAX_METADATA_SIZE,
    ObjectType, ReceiveHooks, ReceivePolicy, ReceiveReport, ReceiveService, Repo, RepoMode, Type,
    UpdatePlan, Value,
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

/// A hook that gives the result of `plan` and counts its calls.
struct Hook {
    plan: Box<PlanFn>,
    calls: AtomicUsize,
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
}

impl Hook {
    fn new(
        plan: impl Fn(&[RefUpdate]) -> Result<UpdatePlan, HookRefusal> + Send + Sync + 'static,
    ) -> Arc<Hook> {
        Arc::new(Hook {
            plan: Box::new(plan),
            calls: AtomicUsize::new(0),
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
}

/// A carried value that counts its drops.
struct DropCount(Arc<AtomicUsize>);

impl Drop for DropCount {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// A carried value that takes an update guard of `repo` when it drops, on
/// another thread, and records the result in `seen`. With
/// `lock-timeout-secs=0` a held update lock fails the take at once.
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

/// Run one session of `repo` with `hooks`: one object stream of `objects`,
/// then `Commit` with `updates`. The service is returned for the steps after
/// the commit.
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

/// Push the fixture commit to `test/main` with `hooks`.
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

/// A variant of a type of `depth` nested maybe types around a byte, with the
/// value `nothing`: a shallow value of a type nested over the limit.
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

/// Write `bytes` as the stored detached metadata of the fixture commit.
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

/// Each step of `service` after the commit is `protocol`: the session was
/// aborted.
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

/// The commit `test/main` names, where the ref is present.
fn main_ref(repo: &Repo) -> Option<String> {
    std::fs::read_to_string(repo.path().join("refs/heads/test/main"))
        .ok()
        .map(|text| text.trim().to_owned())
}

// ---------------------------------------------------------------------------
// The entries of the host.
// ---------------------------------------------------------------------------

/// The entries of the host are stored with the ref, and a commit with no
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

/// The detached metadata is written before the refs: with the ref directory
/// read-only, the commit fails at the ref write, and the `.commitmeta` file
/// holds the entries of the host.
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

/// A host entry with `keep_existing` keeps the value the stored dict holds
/// under its key, and is written where the stored dict has no such key. An
/// entry without it replaces the stored value. The client value of a key of
/// the host is dropped. A commit with no client dict reads its stored dict
/// for the merge.
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

/// A stored dict that the plan read and no edit took is the stored dict of
/// the host merge. The client dict that the exclude filter empties makes the
/// plan read the stored dict and add no edit. `keep_existing` keeps the
/// stored value, an entry without it replaces the stored value, and the
/// other stored entries stay.
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

/// Each plan the checks refuse is `internal`, as `Error::InvalidInput`: no
/// ref is written, no detached metadata is written, the staging directory is
/// removed, the session ends, and the hook ran once.
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
            // A delete of a ref the client expects at `old`.
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
        assert_eq!(drops.load(Ordering::SeqCst), 1, "{case}");
        assert_eq!(main_ref(&repo), None, "{case}");
        assert!(!commitmeta_path(&repo).exists(), "{case}");
        assert_staging_removed(repo.path());
        assert_aborted(&service, case);
    }
}

/// A plan that names the commit of a delete-only push is refused: the
/// commit is not the new commit of an update.
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

/// `HookRefusal::denied` is `ref-denied` and `HookRefusal::internal` is
/// `internal`, each with its message. No ref is written, the staging
/// directory is removed, and the session ends. A message longer than 4096
/// bytes is cut at a character boundary.
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
        assert_eq!(main_ref(&repo), None);
        assert!(!commitmeta_path(&repo).exists());
        assert_staging_removed(repo.path());
        assert_aborted(&service, &format!("denied {denied}"));
    }
}

/// A merged dict over the size limit is `limit-exceeded` before the update
/// lock: another process holds the update lock with `lock-timeout-secs=0`,
/// and the commit does not get the timeout.
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
    // The hook gives its plan once, so the large entry is not copied.
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
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(main_ref(&repo), None);
    assert!(!commitmeta_path(&repo).exists());
}

/// The carried value drops after the update lock is released: on success,
/// and when a ref check under the lock fails. The probe first sees a held
/// update lock as held.
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
    assert_eq!(drops.load(Ordering::SeqCst), 0);
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
