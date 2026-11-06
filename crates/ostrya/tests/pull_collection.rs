//! The pull of the refs of a collection from the remotes that serve it.
//!
//! Each test serves remote repositories from in-process static file servers.
//! A server answers the ref listing with fixed bytes that the test builds
//! with `Repo::build_ref_listing`, whatever the query. A server with no such
//! bytes answers 404, as a static server does, and the pull reads its
//! summary.
//!
//! ostrya builds the remote repositories. A remote with the collection id
//! `org.example.Os` lists its refs in field 0, and a remote with another id
//! lists them in its collection map.

mod common;
#[path = "common/pull.rs"]
mod pull;

use std::os::fd::AsFd;
use std::path::Path;
use std::sync::{Arc, Mutex};

use common::{TmpDir, anyone, store_with_field2};
use ostrya::endpoint::EndpointOverrides;
use ostrya::{
    Checksum, CollectionPullEvent, CollectionPullOptions, CollectionPullStats, CommitModifier,
    CommitModifierFlags, CommitOptions, CreateOptions, DeltaOptions, Ed25519Signer, Error,
    FileKind, FsckOptions, MAX_REF_PATTERNS, MutableTree, ObjectName, ObjectType, PullFlags,
    PullOptions, PullStats, Ref, RefSelector, Repo, RepoMode, SummaryOptions, TimestampCheck, Type,
    Value,
};
use ostrya_rt::block_on;
use pull::*;

/// The collection that the tests pull.
const ID: &str = "org.example.Os";
/// Another collection.
const OTHER: &str = "org.example.Other";
/// The ref that the tests pull.
const REF: &str = "os/stable";
/// A fixed ed25519 keypair. A destination trusts its public key.
const SECRET_B64: &str =
    "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";
const PUBLIC_B64: &str = "wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=";
/// A second keypair. It stands for a key that a destination does not trust.
const OTHER_SECRET_B64: &str =
    "5ILWxT+l9G/u3h0BptRpmSi35C9uog7YDdD+Fp1Xk+Hz52p0NlYh6xBA73kJEJKhKbbnjcE0rsWA5XA/K5Sq5Q==";
/// The path of the ref listing on a server.
const LISTING: &str = "_ostrya/refs/v1";

/// The bindings of a test commit.
#[derive(Clone, Copy)]
struct Bind<'a> {
    /// The `ostree.collection-binding`, or `None` for no key.
    collection: Option<&'a str>,
    /// The `ostree.ref-binding`, or `None` for no key.
    refs: Option<&'a [&'a str]>,
}

/// The bindings of a commit of `REF` in `ID`.
const BOUND: Bind<'static> = Bind {
    collection: Some(ID),
    refs: Some(&[REF]),
};

/// Returns a metadata entry `key` with the value `value` of type `ty`.
fn entry(key: &str, ty: &str, value: Value) -> Value {
    Value::Tuple(vec![
        Value::Str(key.to_owned()),
        Value::Variant(Box::new((Type::parse(ty).unwrap(), value))),
    ])
}

/// Creates an archive repository at `dir/name` with the collection id `own`.
async fn create(dir: &Path, name: &str, own: Option<&str>) -> Repo {
    let mut opts = CreateOptions::new(RepoMode::Archive);
    if let Some(id) = own {
        opts = opts.collection_id(id);
    }
    Repo::create(&dir.join(name), opts).await.unwrap()
}

/// Commits a small tree with the marker `marker` into `repo`, with the
/// timestamp `timestamp` and the bindings `bind`. Writes the commit to the
/// ref `name` of the collection `collection`, or to the local ref `name` if
/// `collection` is `None`.
async fn commit(
    repo: &Repo,
    dir: &Path,
    marker: &str,
    collection: Option<&str>,
    name: &str,
    timestamp: u64,
    bind: Bind<'_>,
) -> Checksum {
    let sub = format!("src-{marker}");
    build_tree(&dir.join(&sub), marker.as_bytes());
    let txn = repo.transaction().await.unwrap();
    let mut mtree = MutableTree::new();
    let mut modifier = CommitModifier::new(
        CommitModifierFlags::SKIP_XATTRS | CommitModifierFlags::CANONICAL_PERMISSIONS,
    );
    let dfd = std::fs::File::open(dir).unwrap();
    txn.write_dfd_to_mtree(
        dfd.as_fd(),
        Path::new(&sub),
        &mut mtree,
        Some(&mut modifier),
    )
    .await
    .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let mut metadata = Vec::new();
    if let Some(id) = bind.collection {
        metadata.push(entry(
            "ostree.collection-binding",
            "s",
            Value::Str(id.to_owned()),
        ));
    }
    if let Some(refs) = bind.refs {
        let refs = refs.iter().map(|r| Value::Str((*r).to_owned())).collect();
        metadata.push(entry("ostree.ref-binding", "as", Value::Array(refs)));
    }
    let checksum = txn
        .write_commit(
            CommitOptions {
                subject: Some(marker.to_owned()),
                timestamp: Some(timestamp),
                metadata: Some(Value::Array(metadata)),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    match collection {
        Some(id) => txn.set_ref(&Ref::collection(id, name), Some(&checksum)),
        None => txn.set_ref(&Ref::local(name), Some(&checksum)),
    }
    txn.commit().await.unwrap();
    checksum
}

/// Writes the summary of `repo`.
async fn summarize(repo: &Repo) {
    repo.regenerate_summary(&SummaryOptions {
        last_modified: Some(FIXED_TS),
        ..SummaryOptions::default()
    })
    .await
    .unwrap();
}

/// Makes `server` answer each ref listing request with the listing of `repo`
/// for the names `names` in `ID`, or for each ref of `ID` if `names` is
/// empty.
async fn serve_listing(server: &RepoServer, repo: &Repo, names: &[&str]) {
    server.tamper("_ostrya/refs/v1", listing(repo, names).await);
}

/// Returns the ref listing of `repo` for the names `names` in `ID`, or for
/// each ref of `ID` and no local ref if `names` is empty.
async fn listing(repo: &Repo, names: &[&str]) -> Vec<u8> {
    let refs = if names.is_empty() {
        RefSelector::parse(["!**"]).unwrap()
    } else {
        RefSelector::parse(names.iter().copied()).unwrap()
    };
    let entries: Vec<String> = if names.is_empty() {
        vec![format!("{ID}/**")]
    } else {
        names.iter().map(|name| format!("{ID}/{name}")).collect()
    };
    let collections = RefSelector::parse(entries.iter().map(String::as_str)).unwrap();
    repo_listing(repo, &refs, Some(&collections)).await
}

/// Returns the ref listing of `repo` for the selectors `refs` and
/// `collections`.
async fn repo_listing(
    repo: &Repo,
    refs: &RefSelector,
    collections: Option<&RefSelector>,
) -> Vec<u8> {
    repo.build_ref_listing(refs, collections, &anyone())
        .await
        .unwrap()
        .bytes
}

/// Creates the destination repository at `dir/dest`, with the collection id
/// `own` and the remotes `remotes`: each a name, a URL, and extra keys.
async fn dest(dir: &Path, own: Option<&str>, remotes: &[(&str, &str, &str)]) -> Repo {
    let path = dir.join("dest");
    drop(create(dir, "dest", own).await);
    let config = path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    for (name, url, extra) in remotes {
        text.push_str(&format!(
            "\n[remote \"{name}\"]\nurl={url}\ngpg-verify=false\ncollection-id={ID}\n{extra}"
        ));
    }
    std::fs::write(&config, text).unwrap();
    Repo::open(&path).await.unwrap()
}

/// Returns the options of a pull of `refs`, with no retry, and a sink for
/// its events.
fn options(refs: &[&str]) -> (CollectionPullOptions, Arc<Mutex<Vec<CollectionPullEvent>>>) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&events);
    let mut opts = CollectionPullOptions::default();
    opts.pull = PullOptions {
        refs: refs.iter().map(|r| (*r).to_owned()).collect(),
        overrides: EndpointOverrides {
            max_retries: Some(0),
            ..EndpointOverrides::default()
        },
        ..PullOptions::default()
    };
    opts.on_event = Some(Box::new(move |event| sink.lock().unwrap().push(event)));
    (opts, events)
}

/// Returns the commit of the collection ref `name` of `ID` in `repo`.
async fn mirror(repo: &Repo, name: &str) -> Option<Checksum> {
    repo.list_mirror_refs()
        .await
        .unwrap()
        .into_iter()
        .find(|(id, n, _)| id == ID && n == name)
        .map(|(_, _, commit)| commit)
}

/// Starts a server over `root` that answers each ref listing request with
/// `status`.
async fn listing_status(root: &Path, status: u16) -> RepoServer {
    let server = RepoServer::start(root, false).await;
    server.answer_status(LISTING, status);
    server
}

/// Appends `text` to the config of the repository `repo` at `dir/dest`, and
/// opens the repository again.
async fn reconfigure(dir: &Path, text: &str) -> Repo {
    let path = dir.join("dest/config");
    let mut config = std::fs::read_to_string(&path).unwrap();
    config.push_str(text);
    std::fs::write(&path, config).unwrap();
    Repo::open(&dir.join("dest")).await.unwrap()
}

/// Asserts that `repo` holds no ref and no object.
async fn assert_nothing_written(repo: &Repo) {
    assert!(repo.list_refs(None).await.unwrap().is_empty());
    assert!(repo.list_mirror_refs().await.unwrap().is_empty());
    assert!(repo.list_remote_refs().await.unwrap().is_empty());
    let objects = repo.list_objects().await.unwrap();
    assert!(objects.is_empty(), "{objects:?}");
}

/// Returns `true` if `server` received a request for an object.
fn objects_requested(server: &RepoServer) -> bool {
    server
        .seen()
        .iter()
        .any(|path| path.starts_with("objects/"))
}

// --- selection ---------------------------------------------------------------

/// The newest commit wins. The first remote serves no listing and lists the
/// ref in field 0 of its summary. The second remote serves a listing with
/// the ref in its collection map. The pull takes the objects from the second
/// remote alone, and writes the collection ref and no remote ref.
#[test]
fn the_newest_commit_wins_from_a_listing_or_a_summary() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-newest");
        let a = create(dir.path(), "a", Some(ID)).await;
        commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
        summarize(&a).await;
        let b = create(dir.path(), "b", Some(OTHER)).await;
        let newer = commit(&b, dir.path(), "b", Some(ID), REF, FIXED_TS + 10, BOUND).await;
        let server_a = RepoServer::start(&dir.path().join("a"), false).await;
        let server_b = RepoServer::start(&dir.path().join("b"), false).await;
        serve_listing(&server_b, &b, &[REF]).await;
        let dest = dest(
            dir.path(),
            None,
            &[("a", &server_a.url(), ""), ("b", &server_b.url(), "")],
        )
        .await;

        let (opts, events) = options(&[REF]);
        let pulled: CollectionPullStats =
            dest.pull_collection(ID, &["a", "b"], opts).await.unwrap();

        assert!(events.lock().unwrap().is_empty());
        assert_eq!(pulled.refs.len(), 1);
        assert_eq!(pulled.refs[0].name, REF);
        assert_eq!(pulled.refs[0].remote, "b");
        assert_eq!(pulled.refs[0].commit, newer);
        assert_eq!(pulled.refs[0].timestamp, FIXED_TS + 10);
        assert_eq!(mirror(&dest, REF).await, Some(newer));
        assert!(dest.list_refs(None).await.unwrap().is_empty());
        assert!(dest.list_remote_refs().await.unwrap().is_empty());
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
        assert_eq!(pulled.stats.content_fetched, 4);
        assert_eq!(pulled.local, PullStats::default());

        // The remote with no listing answered the probe from its summary,
        // and the pull asked it for no object.
        // With no summary policy, the probe reads no `summary.sig`.
        assert_eq!(server_a.seen(), [LISTING, "summary"]);
        assert!(objects_requested(&server_b));
    });
}

/// A tie of timestamps goes to the earlier remote of the list.
#[test]
fn a_tie_goes_to_the_earlier_remote() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-tie");
        let a = create(dir.path(), "a", Some(ID)).await;
        let first = commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
        summarize(&a).await;
        let b = create(dir.path(), "b", Some(ID)).await;
        commit(&b, dir.path(), "b", None, REF, FIXED_TS, BOUND).await;
        summarize(&b).await;
        let server_a = RepoServer::start(&dir.path().join("a"), false).await;
        let server_b = RepoServer::start(&dir.path().join("b"), false).await;
        let dest = dest(
            dir.path(),
            None,
            &[("a", &server_a.url(), ""), ("b", &server_b.url(), "")],
        )
        .await;

        let (opts, _) = options(&[REF]);
        let pulled = dest.pull_collection(ID, &["a", "b"], opts).await.unwrap();
        assert_eq!(pulled.refs[0].remote, "a");
        assert_eq!(mirror(&dest, REF).await, Some(first));
        assert!(!objects_requested(&server_b));
        // The pull from the selected remote uses the summary that the probe
        // read, and does not fetch it again.
        assert_eq!(server_a.requests_for("summary"), 1);
        assert_eq!(server_a.requests_for("summary.sig"), 0);
        assert_eq!(server_a.requests_for("config"), 1);
    });
}

/// A remote that answers the listing with a server error is skipped with an
/// event, and the pull takes the ref from the next remote. The skipped
/// remote holds a newer commit, and the pull reads no summary from it.
#[test]
fn a_failing_remote_is_skipped() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-skip");
        let a = create(dir.path(), "a", Some(ID)).await;
        commit(&a, dir.path(), "a", None, REF, FIXED_TS + 10, BOUND).await;
        summarize(&a).await;
        let b = create(dir.path(), "b", Some(ID)).await;
        let tip = commit(&b, dir.path(), "b", None, REF, FIXED_TS, BOUND).await;
        summarize(&b).await;
        let server_a = listing_status(&dir.path().join("a"), 500).await;
        let server_b = RepoServer::start(&dir.path().join("b"), false).await;
        let dest = dest(
            dir.path(),
            None,
            &[("a", &server_a.url(), ""), ("b", &server_b.url(), "")],
        )
        .await;

        let (opts, events) = options(&[REF]);
        let pulled = dest.pull_collection(ID, &["a", "b"], opts).await.unwrap();
        assert_eq!(pulled.refs[0].remote, "b");
        assert_eq!(mirror(&dest, REF).await, Some(tip));
        let events = events.lock().unwrap();
        assert_eq!(events.len(), 1, "{events:?}");
        let CollectionPullEvent::RemoteSkipped {
            remote, message, ..
        } = &events[0]
        else {
            panic!("{events:?}");
        };
        assert_eq!(remote, "a");
        assert!(message.contains("500"), "{message}");
        assert!(events[0].to_string().starts_with("remote a skipped: "));
        assert_eq!(server_a.seen(), [LISTING]);
    });
}

/// A remote that refuses the listing request with a status from 400 to 499
/// serves no listing, and the pull reads its summary.
#[test]
fn a_client_error_on_the_listing_reads_the_summary() {
    block_on(async {
        for status in [400, 403] {
            let dir = TmpDir::new("pull-collection-client-error");
            let a = create(dir.path(), "a", Some(ID)).await;
            let tip = commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
            summarize(&a).await;
            let server_a = listing_status(&dir.path().join("a"), status).await;
            let dest = dest(dir.path(), None, &[("a", &server_a.url(), "")]).await;

            let (opts, events) = options(&[REF]);
            let pulled = dest.pull_collection(ID, &["a"], opts).await.unwrap();
            assert_eq!(pulled.refs[0].remote, "a", "{status}");
            assert_eq!(mirror(&dest, REF).await, Some(tip), "{status}");
            assert!(events.lock().unwrap().is_empty(), "{status}");
            assert_eq!(server_a.statuses_for(LISTING), [status]);
            assert_eq!(server_a.requests_for("summary"), 1, "{status}");
        }
    });
}

/// A remote whose summary fails the summary policy of the remote is
/// skipped: a summary with no `summary.sig`, and a summary that an untrusted
/// key signed. The remote serves a listing, and the pull does not read it,
/// because no signature covers it.
#[test]
fn a_summary_that_fails_the_policy_skips_the_remote() {
    block_on(async {
        for signer in [None, Some(OTHER_SECRET_B64)] {
            let dir = TmpDir::new("pull-collection-summary-policy");
            let a = create(dir.path(), "a", Some(ID)).await;
            commit(&a, dir.path(), "a", None, REF, FIXED_TS + 10, BOUND).await;
            summarize(&a).await;
            if let Some(secret) = signer {
                let signer = Ed25519Signer::from_base64(secret).unwrap();
                a.sign_summary(&signer).await.unwrap();
            }
            let b = create(dir.path(), "b", Some(ID)).await;
            let tip = commit(&b, dir.path(), "b", None, REF, FIXED_TS, BOUND).await;
            summarize(&b).await;
            let server_a = RepoServer::start(&dir.path().join("a"), false).await;
            serve_listing(&server_a, &a, &[REF]).await;
            let server_b = RepoServer::start(&dir.path().join("b"), false).await;
            let policy =
                format!("sign-verify-summary=ed25519\nverification-ed25519-key={PUBLIC_B64}\n");
            let dest = dest(
                dir.path(),
                None,
                &[("a", &server_a.url(), &policy), ("b", &server_b.url(), "")],
            )
            .await;

            let (opts, events) = options(&[REF]);
            let pulled = dest.pull_collection(ID, &["a", "b"], opts).await.unwrap();
            assert_eq!(pulled.refs[0].remote, "b");
            assert_eq!(mirror(&dest, REF).await, Some(tip));
            let events = events.lock().unwrap();
            assert!(
                matches!(&events[..], [CollectionPullEvent::RemoteSkipped { remote, .. }] if remote == "a"),
                "{events:?}"
            );
            assert!(!objects_requested(&server_a));
            assert_eq!(server_a.requests_for(LISTING), 0);
        }
    });
}

/// Under a summary policy, the pull reads the refs from the verified
/// summary, also when the remote serves a listing. The listing names a newer
/// commit of another repository, and the pull takes the commit of the
/// summary. The pull from the selected remote reads the summary and its
/// signature one time, in the probe.
#[test]
fn a_summary_policy_takes_the_refs_from_the_verified_summary() {
    block_on(async {
        for with_listing in [false, true] {
            let dir = TmpDir::new("pull-collection-signed-summary");
            let a = create(dir.path(), "a", Some(ID)).await;
            let tip = commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
            summarize(&a).await;
            let signer = Ed25519Signer::from_base64(SECRET_B64).unwrap();
            a.sign_summary(&signer).await.unwrap();
            let decoy = create(dir.path(), "decoy", Some(ID)).await;
            commit(&decoy, dir.path(), "d", None, REF, FIXED_TS + 10, BOUND).await;
            let server_a = RepoServer::start(&dir.path().join("a"), false).await;
            if with_listing {
                serve_listing(&server_a, &decoy, &[REF]).await;
            }
            let policy =
                format!("sign-verify-summary=ed25519\nverification-ed25519-key={PUBLIC_B64}\n");
            let dest = dest(dir.path(), None, &[("a", &server_a.url(), &policy)]).await;

            let (opts, events) = options(&[REF]);
            let pulled = dest.pull_collection(ID, &["a"], opts).await.unwrap();
            assert!(events.lock().unwrap().is_empty());
            assert_eq!(pulled.refs[0].commit, tip, "{with_listing}");
            assert_eq!(pulled.refs[0].timestamp, FIXED_TS);
            assert_eq!(mirror(&dest, REF).await, Some(tip));
            assert_eq!(server_a.requests_for(LISTING), 0);
            assert_eq!(server_a.requests_for("summary"), 1);
            assert_eq!(server_a.requests_for("summary.sig"), 1);
        }
    });
}

/// A ref that no remote lists fails the pull before an object request. A
/// pull in which each remote fails fails too.
#[test]
fn a_ref_that_no_remote_lists_fails_the_pull() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-missing");
        let a = create(dir.path(), "a", Some(ID)).await;
        commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
        summarize(&a).await;
        let server_a = RepoServer::start(&dir.path().join("a"), false).await;
        let server_dead = listing_status(dir.path(), 500).await;
        let dest = dest(
            dir.path(),
            None,
            &[("a", &server_a.url(), ""), ("dead", &server_dead.url(), "")],
        )
        .await;

        let (opts, _) = options(&[REF, "os/absent"]);
        let err = dest
            .pull_collection(ID, &["a", "dead"], opts)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Pull(m) if m.contains("os/absent") && m.contains(ID)),
            "{err:?}"
        );
        assert!(!objects_requested(&server_a));
        assert_nothing_written(&dest).await;

        let (opts, events) = options(&[REF]);
        let err = dest.pull_collection(ID, &["dead"], opts).await.unwrap_err();
        assert!(matches!(err, Error::Pull(_)), "{err:?}");
        assert_eq!(events.lock().unwrap().len(), 1);
    });
}

/// With no ref name, the pull takes each ref of the collection that a remote
/// lists, and no ref of another collection. The listing request selects no
/// local ref, so a remote of another collection sends none.
#[test]
fn no_ref_name_pulls_each_ref_of_the_collection() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-all");
        let b = create(dir.path(), "b", Some(OTHER)).await;
        let stable = commit(&b, dir.path(), "s", Some(ID), REF, FIXED_TS, BOUND).await;
        let next_bind = Bind {
            collection: Some(ID),
            refs: Some(&["os/next"]),
        };
        let next = commit(
            &b,
            dir.path(),
            "n",
            Some(ID),
            "os/next",
            FIXED_TS,
            next_bind,
        )
        .await;
        let other_bind = Bind {
            collection: Some(OTHER),
            refs: Some(&["other"]),
        };
        commit(&b, dir.path(), "o", None, "other", FIXED_TS, other_bind).await;
        let server_b = RepoServer::start(&dir.path().join("b"), false).await;
        serve_listing(&server_b, &b, &[]).await;
        let dest = dest(dir.path(), None, &[("b", &server_b.url(), "")]).await;

        let (opts, _) = options(&[]);
        let pulled = dest.pull_collection(ID, &["b"], opts).await.unwrap();
        let names: Vec<&str> = pulled.refs.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["os/next", REF]);
        assert_eq!(mirror(&dest, REF).await, Some(stable));
        assert_eq!(mirror(&dest, "os/next").await, Some(next));
        assert_eq!(dest.list_mirror_refs().await.unwrap().len(), 2);
        assert!(dest.list_refs(None).await.unwrap().is_empty());
        assert_eq!(
            server_b.queries_for(LISTING),
            ["pattern=%21%2A%2A&collection=org.example.Os%2F%2A%2A"]
        );
    });
}

/// With no ref name, a remote whose own collection id is the pulled id
/// lists the refs in field 0. The pull asks it a second time, for each local
/// ref and no collection ref.
#[test]
fn no_ref_name_asks_a_remote_of_the_collection_for_its_local_refs() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-all-own");
        let a = create(dir.path(), "a", Some(ID)).await;
        let stable = commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
        let server_a = RepoServer::start(&dir.path().join("a"), false).await;
        let refs = RefSelector::parse(std::iter::empty()).unwrap();
        let every = repo_listing(&a, &refs, None).await;
        server_a.tamper(LISTING, every);
        let dest = dest(dir.path(), None, &[("a", &server_a.url(), "")]).await;

        let (opts, _) = options(&[]);
        let pulled = dest.pull_collection(ID, &["a"], opts).await.unwrap();
        assert_eq!(pulled.refs.len(), 1);
        assert_eq!(mirror(&dest, REF).await, Some(stable));
        assert_eq!(
            server_a.queries_for(LISTING),
            ["pattern=%21%2A%2A&collection=org.example.Os%2F%2A%2A", ""]
        );
    });
}

/// With no ref name, a pull in which no remote lists a ref of the collection
/// fails before an object request, and writes nothing.
#[test]
fn no_ref_name_and_no_listed_ref_fails_the_pull() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-none");
        let b = create(dir.path(), "b", Some(OTHER)).await;
        let other_bind = Bind {
            collection: Some(OTHER),
            refs: Some(&["other"]),
        };
        commit(&b, dir.path(), "o", None, "other", FIXED_TS, other_bind).await;
        summarize(&b).await;
        let server_b = RepoServer::start(&dir.path().join("b"), false).await;
        let dest = dest(dir.path(), None, &[("b", &server_b.url(), "")]).await;

        let (opts, events) = options(&[]);
        let err = dest.pull_collection(ID, &["b"], opts).await.unwrap_err();
        assert!(
            matches!(&err, Error::Pull(m) if m == &format!("no remote lists a ref of collection '{ID}'")),
            "{err:?}"
        );
        assert!(events.lock().unwrap().is_empty());
        assert!(!objects_requested(&server_b));
        assert_nothing_written(&dest).await;
    });
}

// --- checks of the commit ----------------------------------------------------

/// The pull refuses a commit bound to another collection, a commit with no
/// collection binding, and a commit whose ref binding does not hold the ref.
/// A commit with no ref binding passes. With `allow_unbound`, a commit bound
/// to another collection and a commit whose ref binding does not hold the ref
/// also fail.
#[test]
fn the_bindings_of_each_commit_are_checked() {
    block_on(async {
        let cases: [(&str, Bind<'static>, bool, Option<&str>); 6] = [
            (
                "other collection",
                Bind {
                    collection: Some(OTHER),
                    refs: Some(&[REF]),
                },
                false,
                Some(OTHER),
            ),
            (
                "other collection",
                Bind {
                    collection: Some(OTHER),
                    refs: Some(&[REF]),
                },
                true,
                Some(OTHER),
            ),
            (
                "no collection binding",
                Bind {
                    collection: None,
                    refs: Some(&[REF]),
                },
                false,
                Some("no collection binding"),
            ),
            (
                "other ref",
                Bind {
                    collection: Some(ID),
                    refs: Some(&["os/next"]),
                },
                false,
                Some("in ref binding metadata"),
            ),
            (
                "other ref",
                Bind {
                    collection: None,
                    refs: Some(&["os/next"]),
                },
                true,
                Some("in ref binding metadata"),
            ),
            (
                "no ref binding",
                Bind {
                    collection: Some(ID),
                    refs: None,
                },
                false,
                None,
            ),
        ];
        for (tag, bind, allow_unbound, fragment) in cases {
            let dir = TmpDir::new("pull-collection-bindings");
            let a = create(dir.path(), "a", Some(ID)).await;
            let tip = commit(&a, dir.path(), "a", None, REF, FIXED_TS, bind).await;
            summarize(&a).await;
            let server_a = RepoServer::start(&dir.path().join("a"), false).await;
            let dest = dest(dir.path(), None, &[("a", &server_a.url(), "")]).await;

            let (mut opts, _) = options(&[REF]);
            opts.allow_unbound = allow_unbound;
            let pulled = dest.pull_collection(ID, &["a"], opts).await;
            let Some(fragment) = fragment else {
                pulled.unwrap();
                assert_eq!(
                    mirror(&dest, REF).await,
                    Some(tip),
                    "{tag}, allow_unbound={allow_unbound}"
                );
                continue;
            };
            let err = pulled.unwrap_err();
            assert!(
                matches!(&err, Error::Pull(m) if m.contains(fragment)),
                "{tag}, allow_unbound={allow_unbound}: {err:?}"
            );
            assert_nothing_written(&dest).await;
        }
    });
}

/// With `allow_unbound`, a tip with no collection binding passes, with or
/// without a ref binding that holds the ref. The pull writes the collection
/// ref.
#[test]
fn allow_unbound_pulls_a_tip_with_no_collection_binding() {
    block_on(async {
        let cases: [(&str, Bind<'static>); 2] = [
            (
                "ref binding",
                Bind {
                    collection: None,
                    refs: Some(&[REF]),
                },
            ),
            (
                "no binding",
                Bind {
                    collection: None,
                    refs: None,
                },
            ),
        ];
        for (tag, bind) in cases {
            let dir = TmpDir::new("pull-collection-unbound");
            let a = create(dir.path(), "a", Some(ID)).await;
            let tip = commit(&a, dir.path(), "a", None, REF, FIXED_TS, bind).await;
            summarize(&a).await;
            let server_a = RepoServer::start(&dir.path().join("a"), false).await;
            let dest = dest(dir.path(), None, &[("a", &server_a.url(), "")]).await;

            let (mut opts, _) = options(&[REF]);
            opts.allow_unbound = true;
            let pulled = dest.pull_collection(ID, &["a"], opts).await.unwrap();

            assert_eq!(pulled.refs.len(), 1, "{tag}");
            assert_eq!(pulled.refs[0].commit, tip, "{tag}");
            assert_eq!(mirror(&dest, REF).await, Some(tip), "{tag}");
            assert!(
                dest.fsck(&FsckOptions::default()).await.unwrap().is_ok(),
                "{tag}"
            );
        }
    });
}

/// With `allow_unbound`, the pull takes a tip with no collection binding from
/// a static delta. Without it, the same pull fails and writes nothing.
#[test]
fn allow_unbound_reaches_a_tip_from_a_static_delta() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-unbound-delta");
        let a = create(dir.path(), "a", Some(ID)).await;
        let bind = Bind {
            collection: None,
            refs: Some(&[REF]),
        };
        let tip = commit(&a, dir.path(), "a", None, REF, FIXED_TS, bind).await;
        a.generate_static_delta(None, &tip, &DeltaOptions::default())
            .await
            .unwrap();
        summarize(&a).await;
        let server_a = RepoServer::start(&dir.path().join("a"), false).await;
        let dest = dest(dir.path(), None, &[("a", &server_a.url(), "")]).await;

        let (mut opts, _) = options(&[REF]);
        opts.pull.require_static_deltas = true;
        let err = dest.pull_collection(ID, &["a"], opts).await.unwrap_err();
        assert!(
            matches!(&err, Error::Pull(m) if m.contains("no collection binding")),
            "{err:?}"
        );
        let seen = server_a.seen();
        assert!(seen.iter().any(|p| p.starts_with("deltas/")), "{seen:?}");
        assert_nothing_written(&dest).await;

        let (mut opts, _) = options(&[REF]);
        opts.pull.require_static_deltas = true;
        opts.allow_unbound = true;
        let pulled = dest.pull_collection(ID, &["a"], opts).await.unwrap();
        assert!(pulled.stats.delta_parts > 0, "{:?}", pulled.stats);
        assert_eq!(mirror(&dest, REF).await, Some(tip));
    });
}

/// A commit whose timestamp differs from the timestamp that the remote
/// listed fails the pull.
#[test]
fn a_commit_with_another_timestamp_than_listed_fails() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-listed-timestamp");
        let b = create(dir.path(), "b", Some(OTHER)).await;
        commit(&b, dir.path(), "b", Some(ID), REF, FIXED_TS, BOUND).await;
        let server_b = RepoServer::start(&dir.path().join("b"), false).await;
        // The listing states one second more than the commit holds.
        let mut bytes = listing(&b, &[REF]).await;
        let real = FIXED_TS.to_be_bytes();
        let at = bytes
            .windows(8)
            .position(|w| w == real)
            .expect("the listing holds the timestamp");
        bytes[at..at + 8].copy_from_slice(&(FIXED_TS + 1).to_be_bytes());
        server_b.tamper("_ostrya/refs/v1", bytes);
        let dest = dest(dir.path(), None, &[("b", &server_b.url(), "")]).await;

        let (opts, _) = options(&[REF]);
        let err = dest.pull_collection(ID, &["b"], opts).await.unwrap_err();
        assert!(
            matches!(&err, Error::Pull(m) if m.contains("timestamp")),
            "{err:?}"
        );
        assert_nothing_written(&dest).await;
    });
}

/// The keys of the selected remote apply. The newer remote requires a
/// signature, and its unsigned commit fails the pull. With an older commit
/// there, the other remote is selected, and its policy passes the commit.
#[test]
fn the_keys_of_the_selected_remote_apply() {
    block_on(async {
        for newer_signed_remote in [true, false] {
            let dir = TmpDir::new("pull-collection-keys");
            let a = create(dir.path(), "a", Some(ID)).await;
            let a_ts = if newer_signed_remote {
                FIXED_TS
            } else {
                FIXED_TS + 10
            };
            let a_tip = commit(&a, dir.path(), "a", None, REF, a_ts, BOUND).await;
            summarize(&a).await;
            let b = create(dir.path(), "b", Some(ID)).await;
            commit(&b, dir.path(), "b", None, REF, FIXED_TS + 5, BOUND).await;
            summarize(&b).await;
            let server_a = RepoServer::start(&dir.path().join("a"), false).await;
            let server_b = RepoServer::start(&dir.path().join("b"), false).await;
            let policy = format!("sign-verify=ed25519\nverification-ed25519-key={PUBLIC_B64}\n");
            let dest = dest(
                dir.path(),
                None,
                &[("a", &server_a.url(), ""), ("b", &server_b.url(), &policy)],
            )
            .await;

            let (opts, _) = options(&[REF]);
            let pulled = dest.pull_collection(ID, &["a", "b"], opts).await;
            if newer_signed_remote {
                let err = pulled.unwrap_err();
                assert!(matches!(err, Error::Signature(_)), "{err:?}");
                assert_nothing_written(&dest).await;
            } else {
                assert_eq!(pulled.unwrap().refs[0].remote, "a");
                assert_eq!(mirror(&dest, REF).await, Some(a_tip));
            }
        }
    });
}

/// The trust group option applies to the pull from each remote. The group
/// trusts one key, and the remote section names no key. An unsigned commit
/// fails the pull, and a commit of the key of the group passes.
#[test]
fn a_collection_pull_takes_the_trust_group_option() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-trust-group");
        let a = create(dir.path(), "a", Some(ID)).await;
        let tip = commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
        summarize(&a).await;
        let server = RepoServer::start(&dir.path().join("a"), false).await;
        let group = format!(
            "[ex-ostrya trust \"t\"]\nsign-verify=ed25519\nverification-ed25519-key={PUBLIC_B64}\n"
        );
        let dest = dest(dir.path(), None, &[("a", &server.url(), &group)]).await;
        let pull = || {
            let (mut opts, _) = options(&[REF]);
            opts.pull.trust_group = Some("t".to_owned());
            dest.pull_collection(ID, &["a"], opts)
        };

        let err = pull().await.unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("carries no signature")),
            "{err:?}"
        );
        assert_nothing_written(&dest).await;

        a.sign_commit(&tip, &Ed25519Signer::from_base64(SECRET_B64).unwrap())
            .await
            .unwrap();
        let pulled = pull().await.unwrap();
        assert_eq!(pulled.refs[0].remote, "a");
        assert_eq!(mirror(&dest, REF).await, Some(tip));
    });
}

// --- the place of the refs ---------------------------------------------------

/// Into a repository whose own collection id is the pulled id, and that holds
/// no collection ref of the name, the pull writes the local ref, and the
/// timestamp check reads that ref.
#[test]
fn the_own_collection_writes_the_local_ref() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-local");
        let a = create(dir.path(), "a", Some(ID)).await;
        let tip = commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
        summarize(&a).await;
        let server_a = RepoServer::start(&dir.path().join("a"), false).await;
        let dest = dest(dir.path(), Some(ID), &[("a", &server_a.url(), "")]).await;

        let (mut opts, _) = options(&[REF]);
        opts.pull.timestamp_check = TimestampCheck::CurrentRef;
        dest.pull_collection(ID, &["a"], opts).await.unwrap();
        assert_eq!(
            dest.resolve_ref_tip(&Ref::local(REF)).await.unwrap(),
            Some(tip)
        );
        assert!(dest.list_mirror_refs().await.unwrap().is_empty());

        // An older commit on the remote now fails the timestamp check against
        // the local ref.
        let older = create(dir.path(), "older", Some(ID)).await;
        commit(&older, dir.path(), "older", None, REF, FIXED_TS - 10, BOUND).await;
        summarize(&older).await;
        let server_older = RepoServer::start(&dir.path().join("older"), false).await;
        let path = dir.path().join("dest/config");
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str(&format!(
            "\n[remote \"older\"]\nurl={}\ngpg-verify=false\n",
            server_older.url()
        ));
        std::fs::write(&path, text).unwrap();
        let dest = Repo::open(&dir.path().join("dest")).await.unwrap();
        let (mut opts, _) = options(&[REF]);
        opts.pull.timestamp_check = TimestampCheck::CurrentRef;
        let err = dest
            .pull_collection(ID, &["older"], opts)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Pull(m) if m.contains("chronologically older")),
            "{err:?}"
        );
        assert_eq!(
            dest.resolve_ref_tip(&Ref::local(REF)).await.unwrap(),
            Some(tip)
        );
    });
}

/// Creates the destination at `dir/dest` with the collection id `ID` and the
/// remote `a` at `url`. The destination holds `refs/mirrors/ID/REF`, written
/// by hand, at a commit with the timestamp `mirror_ts`, and the local ref
/// `REF` at a commit with the timestamp `local_ts`. Returns the destination
/// and the two commits.
async fn dest_with_own_mirror(
    dir: &Path,
    url: &str,
    mirror_ts: u64,
    local_ts: u64,
) -> (Repo, Checksum, Checksum) {
    let dest = dest(dir, Some(ID), &[("a", url, "")]).await;
    let held = commit(&dest, dir, "held", None, REF, mirror_ts, BOUND).await;
    let mirror = dir.join(format!("dest/refs/mirrors/{ID}/{REF}"));
    std::fs::create_dir_all(mirror.parent().unwrap()).unwrap();
    std::fs::write(&mirror, format!("{}\n", held.to_hex())).unwrap();
    let local = commit(&dest, dir, "local", None, REF, local_ts, BOUND).await;
    (dest, held, local)
}

/// Asserts that the destination `dest` at `dir/dest` holds
/// `refs/mirrors/ID/REF` at `held` and the local ref `REF` at `local`, and
/// that the resolve and the listing of the collection ref give `local`.
async fn assert_own_refs(dir: &Path, dest: &Repo, held: Checksum, local: Checksum) {
    let path = dir.join(format!("dest/refs/mirrors/{ID}/{REF}"));
    let file = std::fs::read_to_string(path).unwrap();
    assert_eq!(file.trim(), held.to_hex());
    assert_eq!(
        dest.resolve_ref_tip(&Ref::local(REF)).await.unwrap(),
        Some(local)
    );
    let cref = Ref::collection(ID, REF);
    assert_eq!(dest.resolve_ref_tip(&cref).await.unwrap(), Some(local));
    let all = RefSelector::parse([]).unwrap();
    assert_eq!(
        dest.list_collection_refs_in(ID, &all).await.unwrap(),
        vec![(REF.to_owned(), local)]
    );
}

/// Into a repository whose own collection id is the pulled id, and that holds
/// `refs/mirrors/ID/REF`, the pull writes the local ref of the name. The
/// mirror ref keeps its commit, and the resolve and the listing of the
/// collection ref read the local ref.
#[test]
fn the_own_collection_writes_the_local_ref_beside_a_mirror_ref() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-own-mirror");
        let a = create(dir.path(), "a", Some(ID)).await;
        let tip = commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
        summarize(&a).await;
        let server_a = RepoServer::start(&dir.path().join("a"), false).await;
        let (dest, held, _) =
            dest_with_own_mirror(dir.path(), &server_a.url(), FIXED_TS - 10, FIXED_TS - 10).await;

        let (opts, _) = options(&[REF]);
        dest.pull_collection(ID, &["a"], opts).await.unwrap();

        assert_own_refs(dir.path(), &dest, held, tip).await;
    });
}

/// Into a repository whose own collection id is the pulled id, and that holds
/// `refs/mirrors/ID/REF`, the timestamp check reads the local ref and not the
/// mirror ref. A local ref newer than the tip fails the pull, and the pull
/// writes no ref. A local ref older than the tip passes, and the pull writes
/// the local ref. The mirror ref has the other timestamp in each case.
#[test]
fn the_timestamp_check_of_the_own_collection_reads_the_local_ref() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-own-mirror-timestamp");
        let a = create(dir.path(), "a", Some(ID)).await;
        let tip = commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
        summarize(&a).await;
        let server_a = RepoServer::start(&dir.path().join("a"), false).await;
        for (case, mirror_ts, local_ts) in [
            ("newer", FIXED_TS - 10, FIXED_TS + 10),
            ("older", FIXED_TS + 10, FIXED_TS - 10),
        ] {
            let path = dir.path().join(case);
            std::fs::create_dir(&path).unwrap();
            let (dest, held, local) =
                dest_with_own_mirror(&path, &server_a.url(), mirror_ts, local_ts).await;

            let (mut opts, _) = options(&[REF]);
            opts.pull.timestamp_check = TimestampCheck::CurrentRef;
            let pulled = dest.pull_collection(ID, &["a"], opts).await;

            if local_ts > FIXED_TS {
                let err = pulled.unwrap_err();
                assert!(
                    matches!(&err, Error::Pull(m) if m.contains("chronologically older")),
                    "{case}: {err:?}"
                );
                assert_own_refs(&path, &dest, held, local).await;
            } else {
                pulled.unwrap();
                assert_own_refs(&path, &dest, held, tip).await;
            }
        }
    });
}

/// Into a repository of another collection, the timestamp check reads the
/// collection ref that the pull writes.
#[test]
fn the_timestamp_check_reads_the_collection_ref() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-mirror-timestamp");
        let a = create(dir.path(), "a", Some(ID)).await;
        let tip = commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
        summarize(&a).await;
        let older = create(dir.path(), "older", Some(ID)).await;
        commit(&older, dir.path(), "older", None, REF, FIXED_TS - 10, BOUND).await;
        summarize(&older).await;
        let server_a = RepoServer::start(&dir.path().join("a"), false).await;
        let server_older = RepoServer::start(&dir.path().join("older"), false).await;
        let dest = dest(
            dir.path(),
            Some(OTHER),
            &[
                ("a", &server_a.url(), ""),
                ("older", &server_older.url(), ""),
            ],
        )
        .await;

        let (mut opts, _) = options(&[REF]);
        opts.pull.timestamp_check = TimestampCheck::CurrentRef;
        dest.pull_collection(ID, &["a"], opts).await.unwrap();
        assert_eq!(mirror(&dest, REF).await, Some(tip));

        let (mut opts, _) = options(&[REF]);
        opts.pull.timestamp_check = TimestampCheck::CurrentRef;
        let err = dest
            .pull_collection(ID, &["older"], opts)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Pull(m) if m.contains("chronologically older")),
            "{err:?}"
        );
        assert_eq!(mirror(&dest, REF).await, Some(tip));
        assert!(dest.list_refs(None).await.unwrap().is_empty());
    });
}

// --- detached metadata -------------------------------------------------------

/// With `keep-detached-related=false` in the destination, the pull drops
/// `ostrya.related` from the detached metadata that it stores, and stores
/// each other property.
#[test]
fn the_switch_drops_the_related_key_of_a_collection_pull() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-keep-related");
        let a = create(dir.path(), "a", Some(ID)).await;
        let base = commit(&a, dir.path(), "base", None, "os/base", FIXED_TS, BOUND).await;
        let tip = commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
        let kept = Value::Array(vec![entry("test.kept", "s", Value::Str("a".to_owned()))]);
        a.write_commit_detached_metadata(&tip, Some(&kept))
            .await
            .unwrap();
        a.add_detached_related(&tip, "layer/base", &base)
            .await
            .unwrap();
        summarize(&a).await;
        let server_a = RepoServer::start(&dir.path().join("a"), false).await;
        drop(dest(dir.path(), None, &[("a", &server_a.url(), "")]).await);
        let dest = reconfigure(dir.path(), "\n[ex-ostrya]\nkeep-detached-related=false\n").await;
        assert!(!dest.config().keep_detached_related().unwrap());

        let (opts, _) = options(&[REF]);
        dest.pull_collection(ID, &["a"], opts).await.unwrap();

        assert_eq!(mirror(&dest, REF).await, Some(tip));
        let stored = dest
            .read_commit_detached_metadata(&tip)
            .await
            .unwrap()
            .unwrap();
        assert!(stored.dict_get("test.kept").is_some(), "{stored:?}");
        assert!(stored.dict_get("ostrya.related").is_none(), "{stored:?}");
    });
}

// --- composefs images --------------------------------------------------------

/// A value of `[ex-ostrya] generate-composefs` that is not a boolean, and the
/// value `true` in the `archive` destination, stop a collection pull before
/// its first request.
#[test]
fn a_bad_generate_composefs_value_refuses_a_collection_pull() {
    for value in ["maybe", "true"] {
        block_on(async {
            let dir = TmpDir::new("pull-collection-cfs-bad-value");
            let a = create(dir.path(), "a", Some(ID)).await;
            commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
            summarize(&a).await;
            let server_a = RepoServer::start(&dir.path().join("a"), false).await;
            drop(dest(dir.path(), None, &[("a", &server_a.url(), "")]).await);
            let dest = reconfigure(
                dir.path(),
                &format!("\n[ex-ostrya]\ngenerate-composefs={value}\n"),
            )
            .await;

            let (opts, _) = options(&[REF]);
            let err = dest.pull_collection(ID, &["a"], opts).await.unwrap_err();
            match value {
                "true" => assert!(matches!(err, Error::Unsupported(_)), "{err}"),
                _ => assert!(matches!(err, Error::Core(_)), "{err}"),
            }
            assert!(server_a.seen().is_empty(), "{:?}", server_a.seen());
            assert_nothing_written(&dest).await;
        });
    }
}

// --- dependencies ------------------------------------------------------------

/// A collection pull fetches the dependency that field 2 of the pulled commit
/// names, complete, and writes no ref for it. The dependency gets no binding
/// check.
#[test]
fn a_collection_pull_fetches_the_dependency() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-dependency");
        let a = create(dir.path(), "a", Some(ID)).await;
        let unbound = Bind {
            collection: None,
            refs: None,
        };
        let dep = commit(&a, dir.path(), "dep", None, "os/dep", FIXED_TS, unbound).await;
        let plain = commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
        let tip = store_with_field2(&a, &plain, &[("boot/uki", dep.as_bytes())]).await;
        let txn = a.transaction().await.unwrap();
        txn.set_ref(&Ref::local(REF), Some(&tip));
        txn.commit().await.unwrap();
        summarize(&a).await;
        let server_a = RepoServer::start(&dir.path().join("a"), false).await;
        let dest = dest(dir.path(), None, &[("a", &server_a.url(), "")]).await;

        let (opts, _) = options(&[REF]);
        dest.pull_collection(ID, &["a"], opts).await.unwrap();

        assert_eq!(mirror(&dest, REF).await, Some(tip));
        assert_eq!(dest.list_mirror_refs().await.unwrap().len(), 1);
        assert!(dest.list_refs(None).await.unwrap().is_empty());
        assert!(dest.list_remote_refs().await.unwrap().is_empty());
        assert!(dest.has_object(ObjectType::Commit, &dep).await.unwrap());
        assert_eq!(
            dest.commit_state(&dep).await.unwrap(),
            ostrya::CommitState::Normal
        );
        for name in &a.traverse_commit(&dep, 0).await.unwrap() {
            assert!(
                dest.has_object(name.ty, &name.checksum).await.unwrap(),
                "{name} missing from the destination"
            );
        }
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
    });
}

// --- local repositories ------------------------------------------------------

/// The bindings of a commit bound to `ID` with no ref binding.
const COLLECTION_ONLY: Bind<'static> = Bind {
    collection: Some(ID),
    refs: None,
};

/// Returns the `file://` address of the repository at `dir/name`.
fn file_url(dir: &Path, name: &str) -> String {
    format!("file://{}", dir.join(name).display())
}

/// Returns the names of the remotes of the skip events of `events`, and
/// checks that each message holds the path of the remote at `dir/NAME`.
fn skipped(dir: &Path, events: &Mutex<Vec<CollectionPullEvent>>) -> Vec<String> {
    events
        .lock()
        .unwrap()
        .iter()
        .map(|event| match event {
            CollectionPullEvent::RemoteSkipped {
                remote, message, ..
            } => {
                let path = dir.join(remote).display().to_string();
                assert!(message.contains(&path), "{remote}: {message}");
                remote.clone()
            }
            other => panic!("{other:?}"),
        })
        .collect()
}

/// Sets `mode` on `path`. Returns `false`, with mode `restore` set again
/// and a skip message on standard error, when the process still reads the
/// path: a user that ignores the mode cannot run the test.
fn lock(path: &Path, mode: u32, restore: u32) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    let readable = if path.is_dir() {
        std::fs::read_dir(path).is_ok()
    } else {
        std::fs::read(path).is_ok()
    };
    if readable {
        unlock(path, restore);
        eprintln!(
            "skipping: the process reads {} with mode {mode:o}, so it ignores the mode",
            path.display()
        );
        return false;
    }
    true
}

/// Sets `mode` on `path`.
fn unlock(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// A remote at a `file://` address is a local repository, and the pull reads
/// its refs and objects through the file system. Without `allow_unbound`, a
/// tip with no collection binding fails the pull, and the pull writes
/// nothing. With it, the pull writes each ref with the commit and the
/// timestamp of the ref file of the source, and copies the `.commitmeta` of
/// a commit. The pull fetches nothing. With no ref name, the pull takes each
/// ref of the collection.
#[test]
fn a_file_remote_pulls_from_a_local_repository() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-file");
        let a = create(dir.path(), "a", Some(OTHER)).await;
        let unbound = Bind {
            collection: None,
            refs: None,
        };
        let stable = commit(&a, dir.path(), "a1", Some(ID), REF, FIXED_TS, unbound).await;
        let next = commit(
            &a,
            dir.path(),
            "a2",
            Some(ID),
            "os/next",
            FIXED_TS + 5,
            unbound,
        )
        .await;
        let signer = Ed25519Signer::from_base64(SECRET_B64).unwrap();
        a.sign_commit(&stable, &signer).await.unwrap();
        let dest = dest(dir.path(), None, &[("a", &file_url(dir.path(), "a"), "")]).await;

        let (opts, events) = options(&[REF, "os/next"]);
        let err = dest.pull_collection(ID, &["a"], opts).await.unwrap_err();
        assert!(
            matches!(&err, Error::Pull(m) if m.contains("no collection binding")),
            "{err:?}"
        );
        assert!(events.lock().unwrap().is_empty());
        assert_nothing_written(&dest).await;

        let (mut opts, events) = options(&[REF, "os/next"]);
        opts.allow_unbound = true;
        let pulled = dest.pull_collection(ID, &["a"], opts).await.unwrap();
        assert!(events.lock().unwrap().is_empty());
        let got: Vec<(&str, &str, Checksum, u64)> = pulled
            .refs
            .iter()
            .map(|r| (r.name.as_str(), r.remote.as_str(), r.commit, r.timestamp))
            .collect();
        assert_eq!(
            got,
            [
                (REF, "a", stable, FIXED_TS),
                ("os/next", "a", next, FIXED_TS + 5)
            ]
        );
        assert_eq!(mirror(&dest, REF).await, Some(stable));
        assert_eq!(mirror(&dest, "os/next").await, Some(next));
        assert!(dest.list_refs(None).await.unwrap().is_empty());
        assert!(dest.list_remote_refs().await.unwrap().is_empty());
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
        let detached = dest.read_commit_detached_metadata(&stable).await.unwrap();
        assert!(detached.is_some());
        assert_eq!(
            detached,
            a.read_commit_detached_metadata(&stable).await.unwrap()
        );
        assert!(pulled.stats.metadata_imported > 0, "{:?}", pulled.stats);
        assert!(pulled.stats.content_imported > 0, "{:?}", pulled.stats);
        assert_eq!(pulled.stats.metadata_fetched, 0);
        assert_eq!(pulled.stats.content_fetched, 0);
        assert_eq!(pulled.stats.bytes_transferred, 0);
        assert_eq!(
            PullStats {
                elapsed: pulled.stats.elapsed,
                ..pulled.local
            },
            pulled.stats
        );

        let (mut opts, _) = options(&[]);
        opts.allow_unbound = true;
        let pulled = dest.pull_collection(ID, &["a"], opts).await.unwrap();
        let names: Vec<&str> = pulled.refs.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["os/next", REF]);
    });
}

/// An HTTP remote and a `file://` remote each give the ref for which they
/// list the newer commit.
#[test]
fn an_http_remote_and_a_file_remote_each_give_the_newer_commit() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-file-mixed");
        let next_bound = Bind {
            collection: Some(ID),
            refs: Some(&["os/next"]),
        };
        let a = create(dir.path(), "a", Some(ID)).await;
        let a_stable = commit(&a, dir.path(), "a1", None, REF, FIXED_TS + 10, BOUND).await;
        commit(&a, dir.path(), "a2", None, "os/next", FIXED_TS, next_bound).await;
        summarize(&a).await;
        let b = create(dir.path(), "b", Some(OTHER)).await;
        commit(&b, dir.path(), "b1", Some(ID), REF, FIXED_TS, BOUND).await;
        let b_next = commit(
            &b,
            dir.path(),
            "b2",
            Some(ID),
            "os/next",
            FIXED_TS + 10,
            next_bound,
        )
        .await;
        let server_a = RepoServer::start(&dir.path().join("a"), false).await;
        let dest = dest(
            dir.path(),
            None,
            &[
                ("a", &server_a.url(), ""),
                ("b", &file_url(dir.path(), "b"), ""),
            ],
        )
        .await;

        let (opts, events) = options(&[REF, "os/next"]);
        let pulled = dest.pull_collection(ID, &["a", "b"], opts).await.unwrap();
        assert!(events.lock().unwrap().is_empty());
        let got: Vec<(&str, &str)> = pulled
            .refs
            .iter()
            .map(|r| (r.name.as_str(), r.remote.as_str()))
            .collect();
        assert_eq!(got, [(REF, "a"), ("os/next", "b")]);
        assert_eq!(mirror(&dest, REF).await, Some(a_stable));
        assert_eq!(mirror(&dest, "os/next").await, Some(b_next));
        assert!(objects_requested(&server_a));
        assert!(pulled.stats.content_fetched > 0, "{:?}", pulled.stats);
        assert!(pulled.local.metadata_imported > 0, "{:?}", pulled.local);
        assert!(pulled.local.content_imported > 0, "{:?}", pulled.local);
        assert_eq!(pulled.local.metadata_fetched, 0);
        assert_eq!(pulled.local.content_fetched, 0);
        assert_eq!(pulled.local.bytes_transferred, 0);
        assert!(
            pulled.stats.metadata_imported > pulled.local.metadata_imported,
            "{:?} {:?}",
            pulled.stats,
            pulled.local
        );
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
    });
}

/// A `file://` address with a host part, `localhost` included, with no
/// path, or with `%`, `?`, or `#` stops the pull before the request to the
/// first remote. The pull writes nothing.
#[test]
fn a_malformed_file_address_stops_the_pull_before_the_first_request() {
    block_on(async {
        for (tag, reason) in [
            ("localhost", "names a host"),
            ("host", "names a host"),
            ("empty", "has no path"),
            ("percent", "holds '%'"),
            ("query", "holds '%'"),
            ("fragment", "holds '%'"),
        ] {
            let dir = TmpDir::new("pull-collection-file-address");
            let a = create(dir.path(), "a", Some(ID)).await;
            commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
            summarize(&a).await;
            let path = dir.path().join("a").display().to_string();
            let address = match tag {
                "localhost" => format!("file://localhost{path}"),
                "host" => format!("file://host{path}"),
                "empty" => "file://".to_owned(),
                "percent" => format!("file://{path}%41"),
                "query" => format!("file://{path}?x"),
                _ => format!("file://{path}#x"),
            };
            let server_a = RepoServer::start(&dir.path().join("a"), false).await;
            let dest = dest(
                dir.path(),
                None,
                &[("a", &server_a.url(), ""), ("b", &address, "")],
            )
            .await;

            let (opts, events) = options(&[REF]);
            let err = dest
                .pull_collection(ID, &["a", "b"], opts)
                .await
                .unwrap_err();
            assert!(
                matches!(&err, Error::Pull(m)
                    if m.starts_with("remote 'b': the file address") && m.contains(reason)),
                "{tag}: {err:?}"
            );
            assert!(events.lock().unwrap().is_empty(), "{tag}");
            assert!(server_a.seen().is_empty(), "{tag}: {:?}", server_a.seen());
            assert_nothing_written(&dest).await;
        }
    });
}

/// A `file://` path with no repository, absent or an empty directory, skips
/// the remote. The message holds the path. The pull takes the ref from the
/// next remote.
#[test]
fn a_file_path_with_no_repository_skips_the_remote() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-file-none");
        let a = create(dir.path(), "a", Some(ID)).await;
        let tip = commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
        std::fs::create_dir(dir.path().join("empty")).unwrap();
        let dest = dest(
            dir.path(),
            None,
            &[
                ("missing", &file_url(dir.path(), "missing"), ""),
                ("empty", &file_url(dir.path(), "empty"), ""),
                ("a", &file_url(dir.path(), "a"), ""),
            ],
        )
        .await;

        let (opts, events) = options(&[REF]);
        let pulled = dest
            .pull_collection(ID, &["missing", "empty", "a"], opts)
            .await
            .unwrap();
        assert_eq!(skipped(dir.path(), &events), ["missing", "empty"]);
        assert_eq!(pulled.refs[0].remote, "a");
        assert_eq!(mirror(&dest, REF).await, Some(tip));
    });
}

/// The client groups of a local source do not apply: a `file://` pull reads
/// a ref that no group of the source lets a client read.
#[test]
fn the_client_groups_of_a_local_source_do_not_apply() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-file-groups");
        let a = create(dir.path(), "a", Some(OTHER)).await;
        let tip = commit(&a, dir.path(), "a", Some(ID), REF, FIXED_TS, BOUND).await;
        let config = dir.path().join("a/config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str(
            "[ex-ostrya client \"c\"]\nauth=anonymous\nallow=r:pub/**\n\
             [ex-ostrya client \"d\"]\nauth=anonymous\ncollection=*\nallow=r:pub/**\n",
        );
        std::fs::write(&config, text).unwrap();
        // Over HTTP, the groups hide the ref from an anonymous client.
        let source = Repo::open(&dir.path().join("a")).await.unwrap();
        let holds_ref = |bytes: &[u8]| bytes.windows(REF.len()).any(|w| w == REF.as_bytes());
        let refs = RefSelector::parse(["!**"]).unwrap();
        let collections = RefSelector::parse([format!("{ID}/**").as_str()]).unwrap();
        let hidden = source
            .build_ref_listing(
                &refs,
                Some(&collections),
                &common::repo_access(&source, "anonymous"),
            )
            .await
            .unwrap();
        assert!(!holds_ref(&hidden.bytes));
        assert!(holds_ref(
            &repo_listing(&source, &refs, Some(&collections)).await
        ));
        let dest = dest(dir.path(), None, &[("a", &file_url(dir.path(), "a"), "")]).await;

        let (opts, events) = options(&[REF]);
        let pulled = dest.pull_collection(ID, &["a"], opts).await.unwrap();
        assert!(events.lock().unwrap().is_empty());
        assert_eq!(pulled.refs[0].commit, tip);
        assert_eq!(mirror(&dest, REF).await, Some(tip));
    });
}

/// A directory or a ref file inside the selection that the probe cannot read
/// skips the remote, and the pull takes the ref from the next remote. A
/// directory outside the selection that the probe cannot read fails nothing.
/// The test returns at once for a user that ignores the mode.
#[test]
fn an_unreadable_path_skips_the_remote_only_inside_the_selection() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-file-perm");
        let a = create(dir.path(), "a", Some(OTHER)).await;
        let a_pool = commit(
            &a,
            dir.path(),
            "a1",
            Some(ID),
            "pool/x",
            FIXED_TS + 10,
            COLLECTION_ONLY,
        )
        .await;
        commit(
            &a,
            dir.path(),
            "a2",
            Some(ID),
            "builds/locked/y",
            FIXED_TS,
            COLLECTION_ONLY,
        )
        .await;
        let b = create(dir.path(), "b", Some(OTHER)).await;
        let b_pool = commit(
            &b,
            dir.path(),
            "b1",
            Some(ID),
            "pool/x",
            FIXED_TS,
            COLLECTION_ONLY,
        )
        .await;
        let b_build = commit(
            &b,
            dir.path(),
            "b2",
            Some(ID),
            "builds/locked/y",
            FIXED_TS,
            COLLECTION_ONLY,
        )
        .await;
        let dest = dest(
            dir.path(),
            None,
            &[
                ("a", &file_url(dir.path(), "a"), ""),
                ("b", &file_url(dir.path(), "b"), ""),
            ],
        )
        .await;
        let mirrors = dir.path().join("a/refs/mirrors").join(ID);
        let locked = mirrors.join("builds/locked");
        if !lock(&locked, 0o000, 0o755) {
            return;
        }

        let (opts, events) = options(&["pool/x"]);
        let pulled = dest.pull_collection(ID, &["a", "b"], opts).await;
        let (opts, all_events) = options(&[]);
        let all = dest.pull_collection(ID, &["a", "b"], opts).await;
        unlock(&locked, 0o755);

        let pulled = pulled.unwrap();
        assert!(events.lock().unwrap().is_empty());
        assert_eq!(pulled.refs[0].remote, "a");
        assert_eq!(pulled.refs[0].commit, a_pool);
        let all = all.unwrap();
        assert_eq!(skipped(dir.path(), &all_events), ["a"]);
        let got: Vec<(&str, &str, Checksum)> = all
            .refs
            .iter()
            .map(|r| (r.name.as_str(), r.remote.as_str(), r.commit))
            .collect();
        assert_eq!(
            got,
            [("builds/locked/y", "b", b_build), ("pool/x", "b", b_pool)]
        );

        let file = mirrors.join("pool/x");
        if !lock(&file, 0o000, 0o644) {
            return;
        }
        let (opts, events) = options(&["pool/x"]);
        let pulled = dest.pull_collection(ID, &["a", "b"], opts).await;
        unlock(&file, 0o644);
        let pulled = pulled.unwrap();
        assert_eq!(skipped(dir.path(), &events), ["a"]);
        assert_eq!(pulled.refs[0].remote, "b");
    });
}

/// A source whose collection id is `ID` holds the refs of the collection
/// under `refs/heads`. The pull reads them there, with a ref name and with
/// no ref name.
#[test]
fn a_file_remote_of_the_collection_gives_its_local_refs() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-file-own");
        let a = create(dir.path(), "a", Some(ID)).await;
        let tip = commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
        let dest = dest(dir.path(), None, &[("a", &file_url(dir.path(), "a"), "")]).await;
        for names in [&[REF][..], &[][..]] {
            let (opts, events) = options(names);
            let pulled = dest.pull_collection(ID, &["a"], opts).await.unwrap();
            assert!(events.lock().unwrap().is_empty());
            assert_eq!(pulled.refs.len(), 1);
            assert_eq!(pulled.refs[0].name, REF);
            assert_eq!(pulled.refs[0].commit, tip);
            assert_eq!(mirror(&dest, REF).await, Some(tip));
        }
    });
}

/// Returns the remote and the ref of each ref skip event of `events`, and
/// fails on each other event.
fn skipped_refs(events: &Mutex<Vec<CollectionPullEvent>>) -> Vec<(String, String)> {
    events
        .lock()
        .unwrap()
        .iter()
        .map(|event| match event {
            CollectionPullEvent::RefSkipped { remote, name, .. } => (remote.clone(), name.clone()),
            other => panic!("{other:?}"),
        })
        .collect()
}

/// Returns the remote and the ref of each ref skip event of a query of each
/// ref of `ID` on the remote `remote` of `repo`, and the result of the query.
async fn query_skipped(
    repo: &Repo,
    remote: &str,
) -> (Vec<(String, Checksum)>, Vec<(String, String)>) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&events);
    let listed = repo
        .remote_list_collection_refs_with(
            remote,
            ID,
            &[],
            EndpointOverrides::default(),
            Some(Box::new(move |event| sink.lock().unwrap().push(event))),
        )
        .await
        .unwrap();
    (listed, skipped_refs(&events))
}

/// A listed ref whose name fails the ref-name rule is skipped with an event,
/// and the other refs of the remote stay in the selection. The skipped ref
/// file names a commit that the repository does not hold, so the probe reads
/// no commit of a skipped ref. This is true for a repository of the
/// collection, which lists `refs/heads/origin:main`, and for a repository of
/// another collection, which lists `refs/mirrors/ID/origin:main`. A query of
/// the refs skips the same ref, with and without a callback.
#[test]
fn a_file_remote_skips_a_listed_name_that_fails_the_ref_name_rule() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-file-bad-name");
        let a = create(dir.path(), "a", Some(ID)).await;
        let stable = commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
        let b = create(dir.path(), "b", Some(OTHER)).await;
        let next = commit(
            &b,
            dir.path(),
            "b",
            Some(ID),
            "os/next",
            FIXED_TS,
            COLLECTION_ONLY,
        )
        .await;
        let ghost = format!("{}\n", "ab".repeat(32));
        std::fs::write(dir.path().join("a/refs/heads/origin:main"), &ghost).unwrap();
        let mirrors = dir.path().join("b/refs/mirrors").join(ID);
        std::fs::write(mirrors.join("origin:main"), &ghost).unwrap();
        let dest = dest(
            dir.path(),
            None,
            &[
                ("a", &file_url(dir.path(), "a"), ""),
                ("b", &file_url(dir.path(), "b"), ""),
            ],
        )
        .await;

        let (opts, events) = options(&[]);
        let pulled = dest.pull_collection(ID, &["a", "b"], opts).await.unwrap();
        let bad = "origin:main".to_owned();
        assert_eq!(
            skipped_refs(&events),
            [("a".to_owned(), bad.clone()), ("b".to_owned(), bad.clone())]
        );
        let mut got: Vec<(&str, &str, Checksum)> = pulled
            .refs
            .iter()
            .map(|r| (r.name.as_str(), r.remote.as_str(), r.commit))
            .collect();
        got.sort_unstable();
        assert_eq!(got, [("os/next", "b", next), (REF, "a", stable)]);
        assert_eq!(mirror(&dest, REF).await, Some(stable));
        assert_eq!(mirror(&dest, "os/next").await, Some(next));
        assert_eq!(dest.list_mirror_refs().await.unwrap().len(), 2);

        for (remote, name, tip) in [("a", REF, stable), ("b", "os/next", next)] {
            let expected = [(name.to_owned(), tip)];
            let (listed, skipped) = query_skipped(&dest, remote).await;
            assert_eq!(listed, expected, "{remote}");
            assert_eq!(skipped, [(remote.to_owned(), bad.clone())]);
            let listed = dest
                .remote_list_collection_refs(remote, ID, &[])
                .await
                .unwrap();
            assert_eq!(listed, expected, "{remote}");
        }
    });
}

/// A served listing that lists a name that fails the ref-name rule gives the
/// same skip, in a pull and in a query. The server answers each listing
/// request with the local refs of a remote of the collection. So the probe
/// sends the second request, and the event comes from the answer to that
/// request alone.
#[test]
fn an_http_remote_skips_a_listed_name_that_fails_the_ref_name_rule() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-http-bad-name");
        let a = create(dir.path(), "a", Some(ID)).await;
        let stable = commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
        std::fs::write(
            dir.path().join("a/refs/heads/origin:main"),
            format!("{stable}\n"),
        )
        .unwrap();
        let server_a = RepoServer::start(&dir.path().join("a"), false).await;
        let refs = RefSelector::parse(std::iter::empty()).unwrap();
        let listing = repo_listing(&a, &refs, None).await;
        server_a.tamper(LISTING, listing);
        let dest = dest(dir.path(), None, &[("a", &server_a.url(), "")]).await;
        let skip = [("a".to_owned(), "origin:main".to_owned())];

        let (listed, skipped) = query_skipped(&dest, "a").await;
        assert_eq!(listed, [(REF.to_owned(), stable)]);
        assert_eq!(skipped, skip);
        assert_eq!(server_a.queries_for(LISTING).len(), 2);

        let (opts, events) = options(&[]);
        let pulled = dest.pull_collection(ID, &["a"], opts).await.unwrap();
        assert_eq!(skipped_refs(&events), skip);
        assert_eq!(pulled.refs.len(), 1);
        assert_eq!(pulled.refs[0].name, REF);
        assert_eq!(mirror(&dest, REF).await, Some(stable));
        assert_eq!(dest.list_mirror_refs().await.unwrap().len(), 1);
    });
}

/// The timestamp check applies to a pull from a `file://` remote.
#[test]
fn the_timestamp_check_applies_to_a_file_remote() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-file-timestamp");
        let a = create(dir.path(), "a", Some(ID)).await;
        let tip = commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
        let older = create(dir.path(), "older", Some(ID)).await;
        commit(&older, dir.path(), "older", None, REF, FIXED_TS - 10, BOUND).await;
        let dest = dest(
            dir.path(),
            None,
            &[
                ("a", &file_url(dir.path(), "a"), ""),
                ("older", &file_url(dir.path(), "older"), ""),
            ],
        )
        .await;

        let (mut opts, _) = options(&[REF]);
        opts.pull.timestamp_check = TimestampCheck::CurrentRef;
        dest.pull_collection(ID, &["a"], opts).await.unwrap();
        assert_eq!(mirror(&dest, REF).await, Some(tip));

        let (mut opts, _) = options(&[REF]);
        opts.pull.timestamp_check = TimestampCheck::CurrentRef;
        let err = dest
            .pull_collection(ID, &["older"], opts)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Pull(m) if m.contains("chronologically older")),
            "{err:?}"
        );
        assert_eq!(mirror(&dest, REF).await, Some(tip));
    });
}

/// From a `file://` remote into a repository whose own collection id is the
/// pulled id, and that holds `refs/mirrors/ID/REF`, the timestamp check reads
/// the local ref, and the pull writes it. The local ref is older than the
/// tip, and the mirror ref is newer.
#[test]
fn a_file_remote_into_the_own_collection_writes_the_local_ref() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-file-own-mirror");
        let a = create(dir.path(), "a", Some(ID)).await;
        let tip = commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
        let (dest, held, _) = dest_with_own_mirror(
            dir.path(),
            &file_url(dir.path(), "a"),
            FIXED_TS + 10,
            FIXED_TS - 10,
        )
        .await;

        let (mut opts, events) = options(&[REF]);
        opts.pull.timestamp_check = TimestampCheck::CurrentRef;
        dest.pull_collection(ID, &["a"], opts).await.unwrap();

        assert!(events.lock().unwrap().is_empty());
        assert_own_refs(dir.path(), &dest, held, tip).await;
    });
}

/// With a `file://` remote, the pull refuses a subpath with `Unsupported`,
/// and a field of another transport with `InvalidInput` that names it,
/// before the request to the first remote. The pull writes nothing.
#[test]
fn a_file_remote_refuses_subpaths_and_the_fields_of_other_transports() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-file-refusals");
        let a = create(dir.path(), "a", Some(ID)).await;
        commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
        summarize(&a).await;
        let server_a = RepoServer::start(&dir.path().join("a"), false).await;
        let dest = dest(
            dir.path(),
            None,
            &[
                ("a", &server_a.url(), ""),
                ("b", &file_url(dir.path(), "a"), ""),
            ],
        )
        .await;

        let (mut opts, _) = options(&[REF]);
        opts.pull.subpaths = vec!["/dir".to_owned()];
        let err = dest
            .pull_collection(ID, &["a", "b"], opts)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Unsupported(m) if m.contains("remote 'b'")),
            "{err:?}"
        );

        let (mut opts, _) = options(&[REF]);
        opts.pull.overrides.http_headers = vec![("X-A".to_owned(), "b".to_owned())];
        let err = dest
            .pull_collection(ID, &["a", "b"], opts)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::InvalidInput(m) if m.starts_with("http-header applies to")),
            "{err:?}"
        );
        assert!(server_a.seen().is_empty(), "{:?}", server_a.seen());
        assert_nothing_written(&dest).await;
    });
}

/// Under a summary policy, the probe of a `file://` remote reads the refs
/// from the verified summary of the source, and the pull takes the commit
/// that the summary lists, also when the ref file names a newer commit. A
/// summary signed with a key that is not trusted, and a summary with no
/// `summary.sig`, skip the remote.
#[test]
fn a_summary_policy_reads_the_verified_summary_of_a_file_remote() {
    block_on(async {
        for case in ["trusted", "other key", "no signature"] {
            let dir = TmpDir::new("pull-collection-file-summary");
            let a = create(dir.path(), "a", Some(ID)).await;
            let tip = commit(&a, dir.path(), "a1", None, REF, FIXED_TS, BOUND).await;
            summarize(&a).await;
            let secret = match case {
                "trusted" => Some(SECRET_B64),
                "other key" => Some(OTHER_SECRET_B64),
                _ => None,
            };
            if let Some(secret) = secret {
                let signer = Ed25519Signer::from_base64(secret).unwrap();
                a.sign_summary(&signer).await.unwrap();
            }
            commit(&a, dir.path(), "a2", None, REF, FIXED_TS + 10, BOUND).await;
            let b = create(dir.path(), "b", Some(ID)).await;
            let fallback = commit(&b, dir.path(), "b", None, REF, FIXED_TS - 10, BOUND).await;
            let policy =
                format!("sign-verify-summary=ed25519\nverification-ed25519-key={PUBLIC_B64}\n");
            let dest = dest(
                dir.path(),
                None,
                &[
                    ("a", &file_url(dir.path(), "a"), &policy),
                    ("b", &file_url(dir.path(), "b"), ""),
                ],
            )
            .await;

            let (opts, events) = options(&[REF]);
            let pulled = dest.pull_collection(ID, &["a", "b"], opts).await.unwrap();
            if case == "trusted" {
                assert!(events.lock().unwrap().is_empty());
                assert_eq!(pulled.refs[0].remote, "a");
                assert_eq!(pulled.refs[0].commit, tip);
                assert_eq!(mirror(&dest, REF).await, Some(tip));
            } else {
                assert_eq!(skipped(dir.path(), &events), ["a"], "{case}");
                assert_eq!(pulled.refs[0].remote, "b", "{case}");
                assert_eq!(mirror(&dest, REF).await, Some(fallback), "{case}");
            }
        }
    });
}

/// Under a summary policy, a commit of a `file://` remote whose timestamp
/// differs from the timestamp that the verified summary lists fails the
/// pull, as over HTTP. The summary lists one ref, with a timestamp that the
/// commit does not hold, and a trusted key signs that summary.
#[test]
fn a_file_remote_commit_with_another_timestamp_than_listed_fails() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-file-listed-timestamp");
        let a = create(dir.path(), "a", Some(ID)).await;
        commit(&a, dir.path(), "a", None, REF, FIXED_TS + 1, BOUND).await;
        summarize(&a).await;
        // The summary states 99 seconds more than the commit holds.
        let path = dir.path().join("a/summary");
        let mut bytes = std::fs::read(&path).unwrap();
        let real = (FIXED_TS + 1).to_be_bytes();
        let at = bytes
            .windows(8)
            .position(|w| w == real)
            .expect("the summary holds the timestamp");
        bytes[at..at + 8].copy_from_slice(&(FIXED_TS + 100).to_be_bytes());
        std::fs::write(&path, bytes).unwrap();
        let signer = Ed25519Signer::from_base64(SECRET_B64).unwrap();
        a.sign_summary(&signer).await.unwrap();
        let policy =
            format!("sign-verify-summary=ed25519\nverification-ed25519-key={PUBLIC_B64}\n");
        let dest = dest(
            dir.path(),
            None,
            &[("a", &file_url(dir.path(), "a"), &policy)],
        )
        .await;

        let (opts, events) = options(&[REF]);
        let err = dest.pull_collection(ID, &["a"], opts).await.unwrap_err();
        assert!(events.lock().unwrap().is_empty());
        assert!(
            matches!(&err, Error::Pull(m) if m.contains("timestamp")),
            "{err:?}"
        );
        assert_nothing_written(&dest).await;
    });
}

/// The commit keys of a `file://` remote apply to the pull from it. The
/// remote trusts one key. A commit signed with another key fails the pull,
/// and the pull writes nothing. A commit signed with the trusted key passes.
#[test]
fn the_keys_of_a_file_remote_apply() {
    block_on(async {
        for secret in [OTHER_SECRET_B64, SECRET_B64] {
            let dir = TmpDir::new("pull-collection-file-keys");
            let a = create(dir.path(), "a", Some(ID)).await;
            let tip = commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
            let signer = Ed25519Signer::from_base64(secret).unwrap();
            a.sign_commit(&tip, &signer).await.unwrap();
            let policy = format!("sign-verify=true\nverification-ed25519-key={PUBLIC_B64}\n");
            let dest = dest(
                dir.path(),
                None,
                &[("a", &file_url(dir.path(), "a"), &policy)],
            )
            .await;

            let (opts, events) = options(&[REF]);
            let pulled = dest.pull_collection(ID, &["a"], opts).await;
            assert!(events.lock().unwrap().is_empty());
            if secret == SECRET_B64 {
                assert_eq!(pulled.unwrap().refs[0].remote, "a");
                assert_eq!(mirror(&dest, REF).await, Some(tip));
            } else {
                let err = pulled.unwrap_err();
                assert!(matches!(err, Error::Signature(_)), "{err:?}");
                assert_nothing_written(&dest).await;
            }
        }
    });
}

/// With `require_static_deltas`, the pull from a `file://` remote applies
/// the static delta that the summary of the source advertises. Under a
/// summary policy, the probe reads the refs from the verified summary, and
/// the pull takes the commit that the summary lists, also when the ref file
/// names a newer commit. Without the policy, the probe reads the ref file,
/// and the pull reads the summary for the delta.
#[test]
fn a_file_remote_with_require_static_deltas_applies_the_delta() {
    block_on(async {
        for case in ["summary policy", "ref files"] {
            let dir = TmpDir::new("pull-collection-file-delta");
            let a = create(dir.path(), "a", Some(ID)).await;
            let tip = commit(&a, dir.path(), "a1", None, REF, FIXED_TS, BOUND).await;
            a.generate_static_delta(None, &tip, &DeltaOptions::default())
                .await
                .unwrap();
            summarize(&a).await;
            let policy = if case == "summary policy" {
                let signer = Ed25519Signer::from_base64(SECRET_B64).unwrap();
                a.sign_summary(&signer).await.unwrap();
                commit(&a, dir.path(), "a2", None, REF, FIXED_TS + 10, BOUND).await;
                format!("sign-verify-summary=ed25519\nverification-ed25519-key={PUBLIC_B64}\n")
            } else {
                String::new()
            };
            let dest = dest(
                dir.path(),
                None,
                &[("a", &file_url(dir.path(), "a"), &policy)],
            )
            .await;

            let (mut opts, events) = options(&[REF]);
            opts.pull.require_static_deltas = true;
            let pulled = dest.pull_collection(ID, &["a"], opts).await.unwrap();

            assert!(events.lock().unwrap().is_empty(), "{case}");
            assert_eq!(pulled.refs[0].commit, tip, "{case}");
            assert!(pulled.stats.delta_parts > 0, "{case}: {:?}", pulled.stats);
            assert_eq!(mirror(&dest, REF).await, Some(tip), "{case}");
            assert!(
                dest.has_object(ObjectType::Commit, &tip).await.unwrap(),
                "{case}"
            );
            assert!(
                dest.fsck(&FsckOptions::default()).await.unwrap().is_ok(),
                "{case}"
            );
        }
    });
}

/// Writes the bytes of the second regular content object of `commit` in
/// `repo` at `dir/a` under the name of the first, in the order of the
/// checksums. Returns the checksum of the first.
async fn swap_content(dir: &Path, repo: &Repo, commit: &Checksum) -> Checksum {
    let mut names: Vec<Checksum> = repo
        .traverse_commit(commit, 0)
        .await
        .unwrap()
        .into_iter()
        .filter(|name| name.ty == ObjectType::File)
        .map(|name| name.checksum)
        .collect();
    names.sort_by_key(Checksum::to_hex);
    let mut regular = Vec::new();
    for checksum in names {
        let file = repo.load_file(&checksum).await.unwrap();
        if matches!(file.kind, FileKind::Regular { .. }) {
            regular.push(checksum);
        }
    }
    let path = |checksum: Checksum| {
        dir.join("a/objects")
            .join(ObjectName::new(checksum, ObjectType::File).loose_path(RepoMode::Archive))
    };
    std::fs::remove_file(path(regular[0])).unwrap();
    std::fs::copy(path(regular[1]), path(regular[0])).unwrap();
    regular[0]
}

/// Writes the bytes of the dirtree of the one subdirectory of the root of
/// `commit` in `repo` at `dir/a` under the name of the root dirtree. Returns
/// the checksum of the root dirtree.
///
/// The bytes parse as a dirtree, and each object that they name is an object
/// of the commit. So the walk of the pull reads them, and each content object
/// that the pull imports hashes to its name.
async fn swap_dirtree(dir: &Path, repo: &Repo, commit: &Checksum) -> Checksum {
    let (commit, _) = repo.load_commit(commit).await.unwrap();
    let root = commit.root_dirtree;
    let dirs = repo.load_dirtree(&root).await.unwrap().dirs;
    assert_eq!(dirs.len(), 1);
    let path = |checksum: Checksum| {
        dir.join("a/objects")
            .join(ObjectName::new(checksum, ObjectType::DirTree).loose_path(RepoMode::Archive))
    };
    std::fs::remove_file(path(root)).unwrap();
    std::fs::copy(path(dirs[0].1), path(root)).unwrap();
    root
}

/// A signature covers the commit, or the summary its checksum, and not the
/// objects of the tree. So the pull from a `file://` remote whose keys check
/// the signatures of the commits or of the summary hashes each object that
/// it imports. The source holds a signed commit and a signed summary, and
/// the bytes of one content object under the name of another. With commit
/// keys, with the commit keys of a trust group, and with summary keys alone,
/// the pull fails and writes nothing. With no keys, the pull does not read
/// the objects, and the bad object goes to the destination. `UNTRUSTED` from
/// the caller makes that pull fail. A dirtree under the name of another
/// dirtree fails the pull with commit keys in the same way.
#[test]
fn a_file_remote_with_signature_keys_hashes_each_imported_object() {
    block_on(async {
        let keys = format!("verification-ed25519-key={PUBLIC_B64}\n");
        for case in [
            "commit keys",
            "trust group",
            "summary keys",
            "no keys",
            "untrusted",
            "dirtree",
        ] {
            let dir = TmpDir::new("pull-collection-file-hash");
            let a = create(dir.path(), "a", Some(ID)).await;
            let tip = commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
            let signer = Ed25519Signer::from_base64(SECRET_B64).unwrap();
            a.sign_commit(&tip, &signer).await.unwrap();
            summarize(&a).await;
            a.sign_summary(&signer).await.unwrap();
            let target = if case == "dirtree" {
                swap_dirtree(dir.path(), &a, &tip).await
            } else {
                swap_content(dir.path(), &a, &tip).await
            };
            let extra = match case {
                "commit keys" | "dirtree" => format!("sign-verify=true\n{keys}"),
                "trust group" => format!("[ex-ostrya trust \"t\"]\nsign-verify=ed25519\n{keys}"),
                "summary keys" => format!("sign-verify-summary=ed25519\n{keys}"),
                _ => String::new(),
            };
            let dest = dest(
                dir.path(),
                None,
                &[("a", &file_url(dir.path(), "a"), &extra)],
            )
            .await;

            let (mut opts, events) = options(&[REF]);
            if case == "trust group" {
                opts.pull.trust_group = Some("t".to_owned());
            }
            if case == "untrusted" {
                opts.pull.flags = PullFlags::UNTRUSTED;
            }
            let pulled = dest.pull_collection(ID, &["a"], opts).await;
            assert!(events.lock().unwrap().is_empty(), "{case}");
            if case == "no keys" {
                assert_eq!(pulled.unwrap().refs[0].commit, tip);
                assert_eq!(mirror(&dest, REF).await, Some(tip));
                let report = dest.fsck(&FsckOptions::default()).await.unwrap();
                let bad: Vec<Checksum> = report.errors.iter().map(|e| e.object.checksum).collect();
                assert_eq!(bad, [target]);
            } else {
                let err = pulled.unwrap_err();
                assert!(
                    matches!(err, Error::ChecksumMismatch { expected, .. } if expected == target),
                    "{case}: {err:?}"
                );
                assert_nothing_written(&dest).await;
            }
        }
    });
}

/// A pull of one remote and the fetch of its summary still refuse a
/// `file://` address: the fetcher reads `http` and `https` alone.
#[test]
fn a_pull_from_one_remote_refuses_a_file_address() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-file-plain");
        let a = create(dir.path(), "a", Some(ID)).await;
        commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
        summarize(&a).await;
        let dest = dest(dir.path(), None, &[("a", &file_url(dir.path(), "a"), "")]).await;

        let opts = PullOptions {
            refs: vec![REF.to_owned()],
            ..PullOptions::default()
        };
        let err = dest.pull("a", opts).await.unwrap_err();
        assert!(err.to_string().contains("fetch url scheme file"), "{err:?}");
        let err = dest.remote_fetch_summary("a").await.unwrap_err();
        assert!(err.to_string().contains("fetch url scheme file"), "{err:?}");
        assert_nothing_written(&dest).await;
    });
}

// --- refusals ----------------------------------------------------------------

/// The pull refuses each option that it cannot carry before its first
/// request, and writes nothing.
#[test]
fn refused_options_send_no_request() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-refusals");
        let a = create(dir.path(), "a", Some(ID)).await;
        commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
        summarize(&a).await;
        let server_a = RepoServer::start(&dir.path().join("a"), false).await;
        let dest = dest(dir.path(), None, &[("a", &server_a.url(), "")]).await;

        let long = "a.b".repeat(100);
        let base = || PullOptions {
            refs: vec![REF.to_owned()],
            ..PullOptions::default()
        };
        let cases: Vec<(&str, &str, Vec<&str>, PullOptions)> = vec![
            ("invalid id", "fresh", vec!["a"], base()),
            ("long id", &long, vec!["a"], base()),
            ("no remote", ID, vec![], base()),
            (
                "remote",
                ID,
                vec!["a"],
                PullOptions {
                    remote: Some("a".to_owned()),
                    ..base()
                },
            ),
            (
                "mirror",
                ID,
                vec!["a"],
                PullOptions {
                    flags: PullFlags::MIRROR,
                    ..base()
                },
            ),
            (
                "static deltas",
                ID,
                vec!["a"],
                PullOptions {
                    static_deltas: Some(Vec::new()),
                    ..base()
                },
            ),
            (
                "url",
                ID,
                vec!["a"],
                PullOptions {
                    overrides: EndpointOverrides {
                        url: Some(server_a.url()),
                        ..EndpointOverrides::default()
                    },
                    ..base()
                },
            ),
            (
                "disable bindings",
                ID,
                vec!["a"],
                PullOptions {
                    flags: PullFlags::DISABLE_VERIFY_BINDINGS,
                    ..base()
                },
            ),
            (
                "ref name",
                ID,
                vec!["a"],
                PullOptions {
                    refs: vec!["a:b".to_owned()],
                    ..base()
                },
            ),
            (
                "long ref name",
                ID,
                vec!["a"],
                PullOptions {
                    refs: vec![REF.to_owned(), "x".repeat(4090)],
                    ..base()
                },
            ),
            ("unknown remote", ID, vec!["a", "nowhere"], base()),
        ];
        for (tag, id, remotes, pull) in cases {
            let mut opts = CollectionPullOptions::default();
            opts.pull = pull;
            let err = dest.pull_collection(id, &remotes, opts).await.unwrap_err();
            let expected = match tag {
                "ref name" => matches!(err, Error::InvalidRefspec(_)),
                "unknown remote" => true,
                _ => matches!(err, Error::InvalidInput(_)),
            };
            assert!(expected, "{tag}: {err:?}");
            assert!(server_a.seen().is_empty(), "{tag}: {:?}", server_a.seen());
            assert_nothing_written(&dest).await;
        }
    });
}

/// An empty ssh command or send command of a later remote fails the pull
/// before the request to the first remote, and the pull starts no ssh
/// client.
#[test]
fn an_empty_ssh_command_fails_before_the_first_request() {
    block_on(async {
        for key in ["ssh-command", "send-command"] {
            let dir = TmpDir::new("pull-collection-empty-ssh");
            let a = create(dir.path(), "a", Some(ID)).await;
            commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
            summarize(&a).await;
            let server_a = RepoServer::start(&dir.path().join("a"), false).await;
            drop(dest(dir.path(), None, &[("a", &server_a.url(), "")]).await);
            let dest = reconfigure(
                dir.path(),
                &format!(
                    "\n[remote \"b\"]\npull-url=ssh://localhost/nowhere\ngpg-verify=false\n\
                     collection-id={ID}\n{key}=\n"
                ),
            )
            .await;

            let (opts, events) = options(&[REF]);
            let err = dest
                .pull_collection(ID, &["a", "b"], opts)
                .await
                .unwrap_err();
            assert!(
                matches!(&err, Error::Remote(_)) && err.to_string().contains("is empty"),
                "{key}: {err:?}"
            );
            assert!(events.lock().unwrap().is_empty());
            assert!(server_a.seen().is_empty(), "{key}: {:?}", server_a.seen());
            assert_nothing_written(&dest).await;
        }
    });
}

// --- the listing of collection refs ------------------------------------------

/// Returns the overrides of a query with no retry.
fn no_retry() -> EndpointOverrides {
    EndpointOverrides {
        max_retries: Some(0),
        ..EndpointOverrides::default()
    }
}

/// Lists the refs `names` of `ID` on the remote `remote` of `repo`, with no
/// retry.
async fn query(
    repo: &Repo,
    remote: &str,
    names: &[&str],
) -> ostrya::Result<Vec<(String, Checksum)>> {
    repo.remote_list_collection_refs_with(remote, ID, names, no_retry(), None)
        .await
}

/// A list of 300 names takes more than one listing request. The result holds
/// each listed ref once, sorted by name, whatever the order of the names. A
/// name that the remote does not hold, and a name that occurs again, add
/// nothing.
#[test]
fn a_query_of_300_names_takes_more_than_one_request() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-query-many");
        let b = create(dir.path(), "b", Some(OTHER)).await;
        let tip = commit(
            &b,
            dir.path(),
            "b",
            Some(ID),
            "pool/n000",
            FIXED_TS,
            COLLECTION_ONLY,
        )
        .await;
        let names: Vec<String> = (0..300).map(|n| format!("pool/n{n:03}")).collect();
        let txn = b.transaction().await.unwrap();
        for name in &names[1..] {
            txn.set_ref(&Ref::collection(ID, name), Some(&tip));
        }
        txn.commit().await.unwrap();
        let server_b = RepoServer::start(&dir.path().join("b"), false).await;
        serve_listing(&server_b, &b, &[]).await;
        let dest = dest(dir.path(), None, &[("b", &server_b.url(), "")]).await;

        let mut asked: Vec<&str> = names.iter().rev().map(String::as_str).collect();
        asked.push("pool/absent");
        asked.push("pool/n007");
        let listed = query(&dest, "b", &asked).await.unwrap();
        let expected: Vec<(String, Checksum)> =
            names.iter().map(|name| (name.clone(), tip)).collect();
        assert_eq!(listed, expected);
        let requests = (asked.len() - 1).div_ceil(MAX_REF_PATTERNS / 2);
        assert!(requests > 1);
        assert_eq!(server_b.requests_for(LISTING), requests);
        assert_eq!(server_b.requests_for("summary"), 0);
        assert_nothing_written(&dest).await;
    });
}

/// A remote whose own collection id is the queried id lists the refs in
/// field 0. With no name, the query asks it a second time, for each local
/// ref. With names, one request names each ref and each ref under the id.
#[test]
fn a_query_reads_the_local_refs_of_a_remote_of_the_collection() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-query-own");
        let a = create(dir.path(), "a", Some(ID)).await;
        let stable = commit(&a, dir.path(), "a1", None, REF, FIXED_TS, BOUND).await;
        let next_bind = Bind {
            collection: Some(ID),
            refs: Some(&["os/next"]),
        };
        let next = commit(&a, dir.path(), "a2", None, "os/next", FIXED_TS, next_bind).await;
        let server_a = RepoServer::start(&dir.path().join("a"), false).await;
        let refs = RefSelector::parse(std::iter::empty()).unwrap();
        server_a.tamper(LISTING, repo_listing(&a, &refs, None).await);
        let dest = dest(dir.path(), None, &[("a", &server_a.url(), "")]).await;

        let listed = dest
            .remote_list_collection_refs("a", ID, &[])
            .await
            .unwrap();
        assert_eq!(
            listed,
            [("os/next".to_owned(), next), (REF.to_owned(), stable)]
        );
        assert_eq!(
            server_a.queries_for(LISTING),
            ["pattern=%21%2A%2A&collection=org.example.Os%2F%2A%2A", ""]
        );

        server_a.forget();
        let listed = query(&dest, "a", &[REF, REF]).await.unwrap();
        assert_eq!(listed, [(REF.to_owned(), stable)]);
        assert_eq!(
            server_a.queries_for(LISTING),
            ["pattern=os%2Fstable&collection=org.example.Os%2Fos%2Fstable"]
        );
        assert_nothing_written(&dest).await;
    });
}

/// A remote that answers the listing request with a status from 400 to 499
/// serves no listing, and the query reads the refs from its summary: a
/// static server that answers 404, and a server that answers 400 or 403.
#[test]
fn a_query_with_no_listing_reads_the_summary() {
    block_on(async {
        for status in [404, 400, 403] {
            let dir = TmpDir::new("pull-collection-query-summary");
            let a = create(dir.path(), "a", Some(ID)).await;
            let tip = commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
            summarize(&a).await;
            let server_a = match status {
                404 => RepoServer::start(&dir.path().join("a"), false).await,
                _ => listing_status(&dir.path().join("a"), status).await,
            };
            let dest = dest(dir.path(), None, &[("a", &server_a.url(), "")]).await;

            let listed = query(&dest, "a", &[REF, "os/absent"]).await.unwrap();
            assert_eq!(listed, [(REF.to_owned(), tip)], "{status}");
            assert_eq!(server_a.statuses_for(LISTING), [status]);
            assert_eq!(server_a.seen(), [LISTING, "summary"], "{status}");
        }
    });
}

/// Under a summary policy, the query reads the refs from the verified
/// summary, and sends no listing request. The listing names a newer commit
/// of another repository, and the query gives the commit of the summary. A
/// summary that a key that is not trusted signed, a summary with no
/// `summary.sig`, and a remote with no summary give `Error::Signature`.
#[test]
fn a_query_under_a_summary_policy_reads_the_verified_summary() {
    block_on(async {
        for case in ["trusted", "other key", "no signature", "no summary"] {
            let dir = TmpDir::new("pull-collection-query-policy");
            let a = create(dir.path(), "a", Some(ID)).await;
            let tip = commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
            if case != "no summary" {
                summarize(&a).await;
            }
            let secret = match case {
                "trusted" => Some(SECRET_B64),
                "other key" => Some(OTHER_SECRET_B64),
                _ => None,
            };
            if let Some(secret) = secret {
                let signer = Ed25519Signer::from_base64(secret).unwrap();
                a.sign_summary(&signer).await.unwrap();
            }
            let decoy = create(dir.path(), "decoy", Some(ID)).await;
            commit(&decoy, dir.path(), "d", None, REF, FIXED_TS + 10, BOUND).await;
            let server_a = RepoServer::start(&dir.path().join("a"), false).await;
            serve_listing(&server_a, &decoy, &[REF]).await;
            let policy =
                format!("sign-verify-summary=ed25519\nverification-ed25519-key={PUBLIC_B64}\n");
            let dest = dest(dir.path(), None, &[("a", &server_a.url(), &policy)]).await;

            let listed = query(&dest, "a", &[REF]).await;
            if case == "trusted" {
                assert_eq!(listed.unwrap(), [(REF.to_owned(), tip)]);
                assert_eq!(server_a.requests_for("summary.sig"), 1);
            } else {
                assert!(
                    matches!(listed, Err(Error::Signature(_))),
                    "{case}: {listed:?}"
                );
            }
            assert_eq!(server_a.requests_for(LISTING), 0, "{case}");
            assert_eq!(server_a.requests_for("summary"), 1, "{case}");
        }
    });
}

/// A remote with no listing and no summary gives an empty vector, with a
/// name and with no name. After a write of its summary, the same query
/// gives the ref.
#[test]
fn a_remote_with_no_listing_and_no_summary_gives_no_ref() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-query-none");
        let a = create(dir.path(), "a", Some(ID)).await;
        let tip = commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
        let server_a = RepoServer::start(&dir.path().join("a"), false).await;
        let dest = dest(dir.path(), None, &[("a", &server_a.url(), "")]).await;

        for names in [&[REF][..], &[][..]] {
            server_a.forget();
            assert_eq!(query(&dest, "a", names).await.unwrap(), []);
            assert_eq!(server_a.seen(), [LISTING, "summary"]);
        }
        summarize(&a).await;
        assert_eq!(
            query(&dest, "a", &[REF]).await.unwrap(),
            [(REF.to_owned(), tip)]
        );
    });
}

/// A status from 500 to 599 on the listing, or on the summary of a remote
/// with no listing, is the error of the query.
#[test]
fn a_server_error_fails_the_query() {
    block_on(async {
        for path in [LISTING, "summary"] {
            let dir = TmpDir::new("pull-collection-query-5xx");
            let a = create(dir.path(), "a", Some(ID)).await;
            commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
            summarize(&a).await;
            let server_a = RepoServer::start(&dir.path().join("a"), false).await;
            server_a.answer_status(path, 503);
            let dest = dest(dir.path(), None, &[("a", &server_a.url(), "")]).await;

            let err = query(&dest, "a", &[REF]).await.unwrap_err();
            assert!(
                matches!(err, Error::HttpStatus { status: 503, .. }),
                "{path}: {err:?}"
            );
            assert_eq!(server_a.statuses_for(path), [503]);
        }
    });
}

/// The query reads the summary policy of the remote alone, and no commit
/// policy. A remote with no `gpg-verify` key, whose GPG check of the commits
/// is on, and a remote with `sign-verify=true` and no trusted key list the
/// refs. A remote with a malformed `gpg-verify` value and a remote with a
/// malformed `sign-verify` value also list the refs, in each feature set. A
/// collection pull from the first remote reads its commit policy and fails.
/// A remote whose `trust` names a trust group with the GPG check of the
/// commits keeps its summary policy: the query reads the verified summary,
/// and sends no listing request.
#[test]
fn a_query_reads_no_commit_policy() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-query-commit-policy");
        let a = create(dir.path(), "a", Some(ID)).await;
        let tip = commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
        summarize(&a).await;
        a.sign_summary(&Ed25519Signer::from_base64(SECRET_B64).unwrap())
            .await
            .unwrap();
        let server_a = RepoServer::start(&dir.path().join("a"), false).await;
        drop(create(dir.path(), "dest", None).await);
        let url = server_a.url();
        let dest = reconfigure(
            dir.path(),
            &format!(
                "\n[remote \"gpg\"]\nurl={url}\n\
                 [remote \"sign\"]\nurl={url}\ngpg-verify=false\nsign-verify=true\n\
                 [remote \"bad-gpg\"]\nurl={url}\ngpg-verify=maybe\n\
                 [remote \"bad-sign\"]\nurl={url}\ngpg-verify=false\nsign-verify=\\q\n\
                 [remote \"trust\"]\nurl={url}\ntrust=t\nsign-verify-summary=ed25519\n\
                 verification-ed25519-key={PUBLIC_B64}\n\
                 [ex-ostrya trust \"t\"]\ngpg-verify=true\n"
            ),
        )
        .await;
        let config = dest.config();
        assert!(config.remote("bad-gpg").unwrap().gpg_verify().is_err());
        assert!(config.remote("bad-sign").unwrap().sign_verify().is_err());

        for remote in ["gpg", "sign", "bad-gpg", "bad-sign"] {
            server_a.forget();
            let listed = query(&dest, remote, &[REF]).await.unwrap();
            assert_eq!(listed, [(REF.to_owned(), tip)], "{remote}");
            assert_eq!(server_a.requests_for(LISTING), 1, "{remote}");
        }
        server_a.forget();
        let listed = query(&dest, "trust", &[REF]).await.unwrap();
        assert_eq!(listed, [(REF.to_owned(), tip)]);
        assert_eq!(server_a.requests_for(LISTING), 0);
        assert_eq!(server_a.requests_for("summary.sig"), 1);

        let (opts, _) = options(&[REF]);
        assert!(dest.pull_collection(ID, &["gpg"], opts).await.is_err());
        assert_nothing_written(&dest).await;
    });
}

/// A remote at a closed port gives the transport error of the request. The
/// query makes no retry.
#[test]
fn a_closed_port_fails_the_query() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-query-closed");
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let url = format!("http://127.0.0.1:{port}/");
        let dest = dest(dir.path(), None, &[("a", &url, "")]).await;

        let err = query(&dest, "a", &[REF]).await.unwrap_err();
        assert!(matches!(err, Error::Fetch(_)), "{err:?}");
    });
}

/// A remote at a `file://` address is a local repository, and the query
/// reads its ref files. The query returns each error of the local
/// repository unchanged: a path with no repository, a ref whose commit the
/// repository does not hold, and a summary policy with no summary. A host
/// part in the address stops the query before it opens the path.
#[test]
fn a_query_reads_a_file_remote() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-query-file");
        let a = create(dir.path(), "a", Some(OTHER)).await;
        let stable = commit(
            &a,
            dir.path(),
            "a1",
            Some(ID),
            REF,
            FIXED_TS,
            COLLECTION_ONLY,
        )
        .await;
        let next = commit(
            &a,
            dir.path(),
            "a2",
            Some(ID),
            "os/next",
            FIXED_TS,
            COLLECTION_ONLY,
        )
        .await;
        commit(
            &a,
            dir.path(),
            "a3",
            None,
            "local",
            FIXED_TS,
            COLLECTION_ONLY,
        )
        .await;
        let missing = dir.path().join("missing");
        let policy =
            format!("sign-verify-summary=ed25519\nverification-ed25519-key={PUBLIC_B64}\n");
        let host = format!("file://host{}", dir.path().join("a").display());
        let dest = dest(
            dir.path(),
            None,
            &[
                ("a", &file_url(dir.path(), "a"), ""),
                ("missing", &file_url(dir.path(), "missing"), ""),
                ("signed", &file_url(dir.path(), "a"), &policy),
                ("host", &host, ""),
            ],
        )
        .await;

        let listed = dest
            .remote_list_collection_refs("a", ID, &[])
            .await
            .unwrap();
        assert_eq!(
            listed,
            [("os/next".to_owned(), next), (REF.to_owned(), stable)]
        );
        let listed = query(&dest, "a", &[REF, "os/absent"]).await.unwrap();
        assert_eq!(listed, [(REF.to_owned(), stable)]);

        let err = query(&dest, "missing", &[REF]).await.unwrap_err();
        let opened = Repo::open(&missing).await.unwrap_err();
        assert_eq!(err.to_string(), opened.to_string());
        let err = query(&dest, "signed", &[REF]).await.unwrap_err();
        assert!(matches!(err, Error::Signature(_)), "{err:?}");
        let err = query(&dest, "host", &[REF]).await.unwrap_err();
        assert!(
            matches!(&err, Error::Pull(m) if m.contains("names a host")),
            "{err:?}"
        );

        let ghost = dir.path().join("a/refs/mirrors").join(ID).join("os/ghost");
        std::fs::write(&ghost, format!("{}\n", "ab".repeat(32))).unwrap();
        let err = query(&dest, "a", &["os/ghost"]).await.unwrap_err();
        assert!(matches!(err, Error::ObjectNotFound { .. }), "{err:?}");
        std::fs::remove_file(&ghost).unwrap();
        assert_nothing_written(&dest).await;
    });
}

/// The query of 300 names of a local repository reads the ref of each name,
/// under the collection id of the repository and under another id.
#[test]
fn a_file_query_of_300_names_reads_each_ref() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-query-file-many");
        let a = create(dir.path(), "a", Some(OTHER)).await;
        let tip = commit(
            &a,
            dir.path(),
            "a",
            Some(ID),
            "pool/n000",
            FIXED_TS,
            COLLECTION_ONLY,
        )
        .await;
        let names: Vec<String> = (0..300).map(|n| format!("pool/n{n:03}")).collect();
        let txn = a.transaction().await.unwrap();
        for name in &names {
            txn.set_ref(&Ref::collection(ID, name), Some(&tip));
            txn.set_ref(&Ref::local(name), Some(&tip));
        }
        txn.commit().await.unwrap();
        let dest = dest(dir.path(), None, &[("a", &file_url(dir.path(), "a"), "")]).await;

        let mut asked: Vec<&str> = names.iter().rev().map(String::as_str).collect();
        asked.push("pool/absent");
        let expected: Vec<(String, Checksum)> =
            names.iter().map(|name| (name.clone(), tip)).collect();
        for id in [ID, OTHER] {
            let listed = dest
                .remote_list_collection_refs_with("a", id, &asked, no_retry(), None)
                .await
                .unwrap();
            assert_eq!(listed, expected, "{id}");
        }
    });
}

/// A directory inside the selection that the query cannot read gives
/// `Error::Io`. A directory outside the selection that it cannot read fails
/// nothing. The test skips, with a message, for a user that ignores the
/// mode.
#[test]
fn an_unreadable_directory_fails_a_file_query_only_inside_the_selection() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-query-file-perm");
        let a = create(dir.path(), "a", Some(OTHER)).await;
        let pool = commit(
            &a,
            dir.path(),
            "a1",
            Some(ID),
            "pool/x",
            FIXED_TS,
            COLLECTION_ONLY,
        )
        .await;
        commit(
            &a,
            dir.path(),
            "a2",
            Some(ID),
            "builds/locked/y",
            FIXED_TS,
            COLLECTION_ONLY,
        )
        .await;
        let dest = dest(dir.path(), None, &[("a", &file_url(dir.path(), "a"), "")]).await;
        let locked = dir
            .path()
            .join("a/refs/mirrors")
            .join(ID)
            .join("builds/locked");
        if !lock(&locked, 0o000, 0o755) {
            return;
        }
        let named = query(&dest, "a", &["pool/x"]).await;
        let all = query(&dest, "a", &[]).await;
        unlock(&locked, 0o755);

        assert_eq!(named.unwrap(), [("pool/x".to_owned(), pool)]);
        assert!(matches!(all, Err(Error::Io(_))), "{all:?}");
    });
}

/// The query refuses a bad collection id, a bad ref name, a name that no
/// listing request can hold, and a `url` override before its first request.
/// With a `file://` remote, it refuses a field of another transport.
#[test]
fn a_query_refuses_bad_arguments_before_the_first_request() {
    block_on(async {
        let dir = TmpDir::new("pull-collection-query-refusals");
        let a = create(dir.path(), "a", Some(ID)).await;
        commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
        summarize(&a).await;
        let server_a = RepoServer::start(&dir.path().join("a"), false).await;
        let dest = dest(
            dir.path(),
            None,
            &[
                ("a", &server_a.url(), ""),
                ("b", &file_url(dir.path(), "a"), ""),
            ],
        )
        .await;

        let long_id = "a.b".repeat(100);
        let long_name = "x".repeat(4090);
        let url = EndpointOverrides {
            url: Some(server_a.url()),
            ..EndpointOverrides::default()
        };
        let header = EndpointOverrides {
            http_headers: vec![("X-A".to_owned(), "b".to_owned())],
            ..EndpointOverrides::default()
        };
        let cases: Vec<(&str, &str, &str, Vec<&str>, EndpointOverrides)> = vec![
            ("invalid id", "a", "fresh", vec![REF], no_retry()),
            ("long id", "a", &long_id, vec![REF], no_retry()),
            ("ref name", "a", ID, vec![REF, "a:b"], no_retry()),
            ("long ref name", "a", ID, vec![REF, &long_name], no_retry()),
            ("url", "a", ID, vec![REF], url),
            ("header", "b", ID, vec![REF], header),
        ];
        for (tag, remote, id, names, overrides) in cases {
            let err = dest
                .remote_list_collection_refs_with(remote, id, &names, overrides, None)
                .await
                .unwrap_err();
            let expected = match tag {
                "ref name" => matches!(err, Error::InvalidRefspec(_)),
                "header" => matches!(&err, Error::InvalidInput(m) if m.starts_with("http-header")),
                _ => matches!(err, Error::InvalidInput(_)),
            };
            assert!(expected, "{tag}: {err:?}");
            assert!(server_a.seen().is_empty(), "{tag}: {:?}", server_a.seen());
        }
    });
}

// --- interoperability with the `ostree` command ------------------------------

/// The pull reads the summaries that the `ostree` command writes: field 0 of
/// a repository whose collection id is the pulled id, and the collection map
/// of a repository with another id. The tool then lists the pulled
/// collection refs and passes fsck on the destination.
#[test]
fn the_pull_reads_the_summaries_of_the_tool() {
    if !common::ostree_available() {
        eprintln!("skipped: `ostree` is not installed");
        return;
    }
    block_on(async {
        let dir = TmpDir::new("pull-collection-tool");
        let root = dir.path();
        let repo = |name: &str| format!("--repo={}", root.join(name).display());
        let tree = |name: &str, text: &str| {
            let path = root.join(name);
            std::fs::create_dir_all(path.join("dir")).unwrap();
            std::fs::write(path.join("a"), text).unwrap();
            std::fs::write(path.join("dir/b"), b"beta\n").unwrap();
            path.display().to_string()
        };
        let checksum = |out: Vec<u8>| String::from_utf8(out).unwrap().trim().to_owned();
        let collection = format!("--collection-id={ID}");
        let other = format!("--collection-id={OTHER}");

        // `a` has the collection id, and lists the refs in field 0.
        ostree(&[&repo("a"), "init", "--mode=archive", &collection]);
        let older = checksum(ostree(&[
            &repo("a"),
            "commit",
            &format!("--branch={REF}"),
            "--timestamp=@1700000000",
            "-s",
            "older",
            &tree("t1", "one\n"),
        ]));
        let next = checksum(ostree(&[
            &repo("a"),
            "commit",
            "--branch=os/next",
            "--timestamp=@1700000000",
            "-s",
            "next",
            &tree("t2", "two\n"),
        ]));
        ostree(&[&repo("a"), "summary", "-u"]);

        // `b` has another id, and lists the newer commit in its collection
        // map. The commit comes from a scratch repository of the collection,
        // so it is bound to the collection.
        ostree(&[&repo("scratch"), "init", "--mode=archive", &collection]);
        let newer = checksum(ostree(&[
            &repo("scratch"),
            "commit",
            &format!("--branch={REF}"),
            "--timestamp=@1700000100",
            "-s",
            "newer",
            &tree("t3", "three\n"),
        ]));
        ostree(&[&repo("b"), "init", "--mode=archive", &other]);
        let scratch = root.join("scratch").display().to_string();
        ostree(&[&repo("b"), "pull-local", &scratch, REF]);
        ostree(&[
            &repo("b"),
            "refs",
            "--collections",
            &format!("--create={ID}:{REF}"),
            &newer,
        ]);
        ostree(&[&repo("b"), "refs", "--delete", REF]);
        ostree(&[&repo("b"), "summary", "-u"]);

        let server_a = RepoServer::start(&root.join("a"), false).await;
        let server_b = RepoServer::start(&root.join("b"), false).await;
        let dest = dest(
            root,
            None,
            &[("a", &server_a.url(), ""), ("b", &server_b.url(), "")],
        )
        .await;
        let (opts, events) = options(&[REF, "os/next"]);
        let pulled = dest.pull_collection(ID, &["a", "b"], opts).await.unwrap();
        assert!(events.lock().unwrap().is_empty());
        let selected: Vec<(&str, &str)> = pulled
            .refs
            .iter()
            .map(|r| (r.name.as_str(), r.remote.as_str()))
            .collect();
        assert_eq!(selected, [(REF, "b"), ("os/next", "a")]);
        assert_eq!(mirror(&dest, REF).await.unwrap().to_hex(), newer);
        assert_eq!(mirror(&dest, "os/next").await.unwrap().to_hex(), next);
        assert_ne!(older, newer);

        let listed = String::from_utf8(ostree(&[&repo("dest"), "refs", "--collections"])).unwrap();
        let mut lines: Vec<&str> = listed.lines().collect();
        lines.sort_unstable();
        assert_eq!(
            lines,
            [
                format!("({ID}, os/next)").as_str(),
                format!("({ID}, {REF})").as_str()
            ]
        );
        common::tool_fsck(&root.join("dest"));
    });
}

// --- bucket repositories -----------------------------------------------------

/// The pull of collection refs from bucket repositories at `s3://`
/// addresses.
///
/// Most cases serve the bucket `bkt` from the S3 stand-in of
/// `common/s3.rs`, which accepts each signature and keeps each request. Two
/// cases serve it from `rclone serve s3`, which checks each signature. A
/// case copies the files of a local `archive` repository, its summary
/// included, into the bucket.
///
/// `Repo::pull_collection` reads the key pair from the environment of the
/// process. So each test runs its case in a child process of this test
/// binary, which gets the key pair, the two shared AWS files at absent
/// paths, no other AWS variable, and no proxy variable. The rclone cases
/// skip when `rclone` is absent, and `OSTRYA_REQUIRE_S3` turns the skip into
/// a failure.
#[cfg(feature = "s3")]
mod s3_remote {
    use std::path::Path;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use ostrya::PullProgress;

    use super::*;
    use crate::common::s3::{ACCESS_KEY, Rclone, SECRET_KEY, StandIn, rclone_available};

    /// The variable that names the case of the child process.
    const CASE: &str = "OSTRYA_TEST_S3_CASE";

    /// The proxy variables that the fetcher reads. The child process gets
    /// none of them, so it connects to the server directly.
    const PROXY_VARIABLES: [&str; 7] = [
        "http_proxy",
        "HTTP_PROXY",
        "https_proxy",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
        "no_proxy",
    ];

    /// The request target of a key of the bucket repository `s3://bkt/repo`
    /// on the stand-in.
    fn target(key: &str) -> String {
        format!("/bkt/repo/{key}")
    }

    /// Runs the case `case` in a child process with the secret key `secret`.
    fn run_case(case: &str, secret: &str) {
        let scratch = TmpDir::new("pull-collection-s3-env");
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "s3_remote::subprocess",
                "--exact",
                "--ignored",
                "--nocapture",
            ])
            .env(CASE, case)
            .env("AWS_ACCESS_KEY_ID", ACCESS_KEY)
            .env("AWS_SECRET_ACCESS_KEY", secret)
            .env("AWS_CONFIG_FILE", scratch.path().join("absent-aws-config"))
            .env(
                "AWS_SHARED_CREDENTIALS_FILE",
                scratch.path().join("absent-aws-credentials"),
            );
        for (name, _) in std::env::vars_os() {
            let text = name.to_string_lossy();
            if text.starts_with("AWS_") && !child.get_envs().any(|(set, _)| set == name) {
                child.env_remove(&name);
            }
        }
        for name in PROXY_VARIABLES {
            child.env_remove(name);
        }
        let output = child.output().expect("re-execute this test binary");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "the child of the case {case} reported {}:\n{stdout}{}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
        );
    }

    /// Runs a case of a test of this module.
    ///
    /// This test does its work only when a test of this module runs this
    /// binary again with the variables set.
    #[test]
    #[ignore = "helper process for the tests of bucket repositories"]
    fn subprocess() {
        let Some(case) = std::env::var_os(CASE) else {
            return;
        };
        block_on(async {
            match case.to_str().unwrap() {
                "collection-map" => collection_map().await,
                "field-0" => field_0().await,
                "live-count" => live_count().await,
                "across-transports" => across_transports().await,
                "no-summary" => no_summary().await,
                "summary-policy" => summary_policy().await,
                "stale-summary" => stale_summary().await,
                "absent-bucket" => absent_bucket().await,
                "rclone" => rclone(false).await,
                "rclone-wrong-secret" => rclone(true).await,
                "query" => query_bucket().await,
                "rclone-query" => rclone_query().await,
                other => panic!("unknown case {other}"),
            }
        });
    }

    /// Stores each file under the directory `dir` in `server`, at its path
    /// under `dir` with the prefix `repo/`.
    fn store_tree(server: &StandIn, dir: &Path) {
        let mut pending = vec![dir.to_path_buf()];
        while let Some(at) = pending.pop() {
            for entry in std::fs::read_dir(&at).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                } else {
                    let key = path.strip_prefix(dir).unwrap().to_str().unwrap();
                    let bytes = std::fs::read(&path).unwrap();
                    server.state().store(&format!("repo/{key}"), &bytes);
                }
            }
        }
    }

    /// Returns the keys of a remote at the address `address` on the server
    /// at `url`.
    fn bucket(url: &str, address: &str) -> String {
        format!("pull-url={address}\ns3-endpoint={url}\n")
    }

    /// Creates the destination repository at `dir/name`, with the collection
    /// id `own` and the remotes `remotes`: each a name and its keys.
    async fn bucket_dest(
        dir: &Path,
        name: &str,
        own: Option<&str>,
        remotes: &[(&str, &str)],
    ) -> Repo {
        drop(create(dir, name, own).await);
        let config = dir.join(name).join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        for (remote, keys) in remotes {
            text.push_str(&format!(
                "\n[remote \"{remote}\"]\ngpg-verify=false\ncollection-id={ID}\n{keys}"
            ));
        }
        std::fs::write(&config, text).unwrap();
        Repo::open(&dir.join(name)).await.unwrap()
    }

    /// Returns the options of [`options`] that allow the `http://`
    /// endpoint of the server.
    fn bucket_options(
        refs: &[&str],
    ) -> (CollectionPullOptions, Arc<Mutex<Vec<CollectionPullEvent>>>) {
        let (mut opts, events) = options(refs);
        opts.pull.overrides.allow_cleartext_credentials = true;
        (opts, events)
    }

    /// Asserts that each request to `server` is signed, and that no request
    /// asks for the ref listing.
    fn assert_signed_with_no_listing(server: &StandIn) {
        let state = server.state();
        assert!(state.authorizations.iter().all(Option::is_some));
        assert!(
            !state
                .requests
                .iter()
                .any(|(_, target)| target.contains(LISTING)),
            "{:?}",
            state.requests
        );
    }

    /// Returns the number of requests to `server` for the key `key` of the
    /// bucket repository.
    fn requests_for(server: &StandIn, key: &str) -> usize {
        let wanted = target(key);
        server
            .state()
            .requests
            .iter()
            .filter(|(_, target)| *target == wanted)
            .count()
    }

    /// Returns `true` if `server` received a request for an object of the
    /// bucket repository.
    fn bucket_objects_requested(server: &StandIn) -> bool {
        let objects = target("objects/");
        server
            .state()
            .requests
            .iter()
            .any(|(_, target)| target.starts_with(&objects))
    }

    /// Returns the single skip event of `events`, as the remote and the
    /// message.
    fn skipped(events: &Mutex<Vec<CollectionPullEvent>>) -> (String, String) {
        let events = events.lock().unwrap();
        match &events[..] {
            [
                CollectionPullEvent::RemoteSkipped {
                    remote, message, ..
                },
            ] => (remote.clone(), message.clone()),
            other => panic!("{other:?}"),
        }
    }

    /// A bucket repository with no collection id holds the ref of the
    /// collection under `refs/mirrors/ID/`, and its summary lists it in the
    /// collection map. A pull of the named ref and a pull of each ref read
    /// the summary alone, then the `config`, and write the collection ref.
    #[test]
    fn a_bucket_serves_the_refs_of_its_collection_map() {
        run_case("collection-map", SECRET_KEY);
    }

    async fn collection_map() {
        let dir = TmpDir::new("pull-collection-s3-map");
        let source = create(dir.path(), "source", None).await;
        let tip = commit(&source, dir.path(), "a", Some(ID), REF, FIXED_TS, BOUND).await;
        summarize(&source).await;
        for refs in [&[REF][..], &[]] {
            let server = StandIn::start();
            store_tree(&server, &dir.path().join("source"));
            let keys = bucket(&server.endpoint(), "s3://bkt/repo");
            let name = format!("dest-{}", refs.len());
            let dest = bucket_dest(dir.path(), &name, None, &[("bkt", &keys)]).await;
            let (opts, events) = bucket_options(refs);
            let pulled = dest.pull_collection(ID, &["bkt"], opts).await.unwrap();
            assert!(events.lock().unwrap().is_empty());
            assert_eq!(pulled.refs.len(), 1);
            assert_eq!(pulled.refs[0].remote, "bkt");
            assert_eq!(pulled.refs[0].commit, tip);
            assert_eq!(pulled.refs[0].timestamp, FIXED_TS);
            assert_eq!(mirror(&dest, REF).await, Some(tip));
            assert!(dest.list_refs(None).await.unwrap().is_empty());
            assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
            let requests = server.state().requests.clone();
            assert_eq!(
                requests[..2],
                [
                    ("GET".to_owned(), target("summary")),
                    ("GET".to_owned(), target("config")),
                ]
            );
            assert_eq!(requests_for(&server, "summary.sig"), 0);
            assert_eq!(requests_for(&server, "summary"), 1);
            assert_signed_with_no_listing(&server);
        }
    }

    /// A bucket repository whose summary states the collection id lists the
    /// refs of the collection in field 0. A destination of the same
    /// collection writes the local ref.
    #[test]
    fn a_bucket_of_the_collection_serves_field_0() {
        run_case("field-0", SECRET_KEY);
    }

    async fn field_0() {
        let dir = TmpDir::new("pull-collection-s3-field-0");
        let source = create(dir.path(), "source", Some(ID)).await;
        let tip = commit(&source, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
        summarize(&source).await;
        let server = StandIn::start();
        store_tree(&server, &dir.path().join("source"));
        let keys = bucket(&server.endpoint(), "s3://bkt/repo");
        let dest = bucket_dest(dir.path(), "dest", Some(ID), &[("bkt", &keys)]).await;
        let (opts, events) = bucket_options(&[REF]);
        let pulled = dest.pull_collection(ID, &["bkt"], opts).await.unwrap();
        assert!(events.lock().unwrap().is_empty());
        assert_eq!(pulled.refs[0].commit, tip);
        assert_eq!(dest.resolve_rev(REF, false).await.unwrap(), Some(tip));
        assert!(dest.list_mirror_refs().await.unwrap().is_empty());
        assert_signed_with_no_listing(&server);
    }

    /// The live count of a pull from a bucket repository includes the bytes
    /// of `summary` and `summary.sig` until the pull reads the `config`, as
    /// over HTTP. The count of the stats starts after the root files.
    #[test]
    fn the_live_count_of_a_bucket_pull_includes_the_summary() {
        run_case("live-count", SECRET_KEY);
    }

    async fn live_count() {
        let dir = TmpDir::new("pull-collection-s3-live-count");
        let source = create(dir.path(), "source", Some(ID)).await;
        let tip = commit(&source, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
        summarize(&source).await;
        let signer = Ed25519Signer::from_base64(SECRET_B64).unwrap();
        source.sign_summary(&signer).await.unwrap();
        let server = StandIn::start();
        store_tree(&server, &dir.path().join("source"));
        let keys = bucket(&server.endpoint(), "s3://bkt/repo");
        let dest = bucket_dest(dir.path(), "dest", Some(ID), &[("bkt", &keys)]).await;
        let progress = PullProgress::new();
        let at_config = Arc::new(AtomicU64::new(u64::MAX));
        let root = {
            let mut state = server.state();
            let (seen, stored) = (progress.clone(), Arc::clone(&at_config));
            state.before_key = Some((
                "GET",
                "repo/config".to_owned(),
                Box::new(move |_| {
                    stored.store(seen.snapshot().bytes_transferred, Ordering::Relaxed);
                }),
            ));
            state.objects["repo/summary"].bytes.len()
                + state.objects["repo/summary.sig"].bytes.len()
        };
        let stats = dest
            .pull(
                "bkt",
                PullOptions {
                    refs: vec![REF.to_owned()],
                    progress: Some(progress.clone()),
                    overrides: EndpointOverrides {
                        allow_cleartext_credentials: true,
                        ..EndpointOverrides::default()
                    },
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            dest.resolve_rev(&format!("bkt:{REF}"), false)
                .await
                .unwrap(),
            Some(tip)
        );
        assert_eq!(at_config.load(Ordering::Relaxed), root as u64);
        assert_eq!(
            progress.snapshot().bytes_transferred,
            stats.bytes_transferred
        );
        assert_signed_with_no_listing(&server);
    }

    /// An HTTP remote and a bucket repository serve the collection. The
    /// newest commit wins across the two transports, and the pull takes the
    /// objects from the selected remote alone.
    #[test]
    fn the_newest_commit_wins_across_http_and_s3() {
        run_case("across-transports", SECRET_KEY);
    }

    async fn across_transports() {
        for bucket_newer in [true, false] {
            let dir = TmpDir::new("pull-collection-s3-across");
            let (http_ts, bucket_ts) = if bucket_newer {
                (FIXED_TS, FIXED_TS + 10)
            } else {
                (FIXED_TS + 10, FIXED_TS)
            };
            let a = create(dir.path(), "a", Some(ID)).await;
            let http_tip = commit(&a, dir.path(), "a", None, REF, http_ts, BOUND).await;
            summarize(&a).await;
            let source = create(dir.path(), "source", None).await;
            let bucket_tip =
                commit(&source, dir.path(), "b", Some(ID), REF, bucket_ts, BOUND).await;
            summarize(&source).await;
            let server_a = RepoServer::start(&dir.path().join("a"), false).await;
            let server = StandIn::start();
            store_tree(&server, &dir.path().join("source"));
            let http = format!("url={}\n", server_a.url());
            let keys = bucket(&server.endpoint(), "s3://bkt/repo");
            let dest = bucket_dest(dir.path(), "dest", None, &[("a", &http), ("bkt", &keys)]).await;
            let (opts, events) = bucket_options(&[REF]);
            let pulled = dest.pull_collection(ID, &["a", "bkt"], opts).await.unwrap();
            assert!(events.lock().unwrap().is_empty());
            let (winner, tip) = if bucket_newer {
                ("bkt", bucket_tip)
            } else {
                ("a", http_tip)
            };
            assert_eq!(pulled.refs[0].remote, winner);
            assert_eq!(mirror(&dest, REF).await, Some(tip));
            assert_eq!(objects_requested(&server_a), !bucket_newer);
            assert_eq!(bucket_objects_requested(&server), bucket_newer);
            assert_signed_with_no_listing(&server);
        }
    }

    /// A bucket repository with no `summary` fails the probe, and the next
    /// remote serves the ref. A bucket repository alone with no `summary`
    /// fails the pull before an object request, and the pull writes nothing.
    #[test]
    fn a_bucket_with_no_summary_is_skipped() {
        run_case("no-summary", SECRET_KEY);
    }

    async fn no_summary() {
        let dir = TmpDir::new("pull-collection-s3-no-summary");
        let source = create(dir.path(), "source", None).await;
        commit(
            &source,
            dir.path(),
            "b",
            Some(ID),
            REF,
            FIXED_TS + 10,
            BOUND,
        )
        .await;
        let a = create(dir.path(), "a", Some(ID)).await;
        let tip = commit(&a, dir.path(), "a", None, REF, FIXED_TS, BOUND).await;
        summarize(&a).await;
        let server_a = RepoServer::start(&dir.path().join("a"), false).await;
        let server = StandIn::start();
        store_tree(&server, &dir.path().join("source"));
        let http = format!("url={}\n", server_a.url());
        let keys = bucket(&server.endpoint(), "s3://bkt/repo");

        let dest = bucket_dest(dir.path(), "dest", None, &[("bkt", &keys), ("a", &http)]).await;
        let (opts, events) = bucket_options(&[REF]);
        let pulled = dest.pull_collection(ID, &["bkt", "a"], opts).await.unwrap();
        assert_eq!(pulled.refs[0].remote, "a");
        assert_eq!(mirror(&dest, REF).await, Some(tip));
        let (remote, message) = skipped(&events);
        assert_eq!(remote, "bkt");
        assert!(
            message.contains("the bucket repository has no summary"),
            "{message}"
        );

        let alone = bucket_dest(dir.path(), "alone", None, &[("bkt", &keys)]).await;
        let (opts, events) = bucket_options(&[REF]);
        let err = alone.pull_collection(ID, &["bkt"], opts).await.unwrap_err();
        assert!(matches!(err, Error::Pull(_)), "{err:?}");
        assert_eq!(skipped(&events).0, "bkt");
        assert_nothing_written(&alone).await;
        assert!(!bucket_objects_requested(&server));
        assert_signed_with_no_listing(&server);
    }

    /// Under a summary policy, the pull reads `summary.sig` and `summary`
    /// through the bucket client, and verifies the summary. The two requests
    /// are in flight together: in the first pull, the server waits before it
    /// answers `summary.sig`, and logs `summary` first. The pull asks for
    /// `summary.sig` first: in the second pull, with a fetch limit of one,
    /// the server logs `summary.sig` first. A summary that an untrusted key
    /// signed, and a summary with no `summary.sig`, skip the bucket
    /// repository.
    #[test]
    fn a_summary_policy_verifies_the_summary_of_a_bucket() {
        run_case("summary-policy", SECRET_KEY);
    }

    async fn summary_policy() {
        for signer in [Some(SECRET_B64), Some(OTHER_SECRET_B64), None] {
            let dir = TmpDir::new("pull-collection-s3-policy");
            let source = create(dir.path(), "source", None).await;
            let tip = commit(&source, dir.path(), "a", Some(ID), REF, FIXED_TS, BOUND).await;
            summarize(&source).await;
            if let Some(secret) = signer {
                let signer = Ed25519Signer::from_base64(secret).unwrap();
                source.sign_summary(&signer).await.unwrap();
            }
            let server = StandIn::start();
            store_tree(&server, &dir.path().join("source"));
            if signer == Some(SECRET_B64) {
                server.state().delay = Some((
                    "GET",
                    "repo/summary.sig".to_owned(),
                    Duration::from_millis(500),
                ));
            }
            let keys = format!(
                "{}sign-verify-summary=ed25519\nverification-ed25519-key={PUBLIC_B64}\n",
                bucket(&server.endpoint(), "s3://bkt/repo")
            );
            let dest = bucket_dest(dir.path(), "dest", None, &[("bkt", &keys)]).await;
            let (mut opts, events) = bucket_options(&[REF]);
            if signer == Some(OTHER_SECRET_B64) {
                opts.pull.max_outstanding_fetches = Some(1);
            }
            let pulled = dest.pull_collection(ID, &["bkt"], opts).await;
            let requests = server.state().requests.clone();
            let summary = ("GET".to_owned(), target("summary"));
            let signature = ("GET".to_owned(), target("summary.sig"));
            let mut first = requests[..2].to_vec();
            if signer == Some(SECRET_B64) {
                assert_eq!(first, [summary, signature]);
            } else if signer == Some(OTHER_SECRET_B64) {
                assert_eq!(first, [signature, summary]);
            } else {
                first.sort();
                assert_eq!(first, [summary, signature]);
            }
            if signer == Some(SECRET_B64) {
                let pulled = pulled.unwrap();
                assert!(events.lock().unwrap().is_empty());
                assert_eq!(pulled.refs[0].commit, tip);
                assert_eq!(mirror(&dest, REF).await, Some(tip));
                assert_eq!(requests_for(&server, "summary.sig"), 1);
                assert_eq!(requests_for(&server, "summary"), 1);
            } else {
                assert!(matches!(pulled, Err(Error::Pull(_))), "{pulled:?}");
                assert_eq!(skipped(&events).0, "bkt");
                assert_nothing_written(&dest).await;
                assert!(!bucket_objects_requested(&server));
            }
            assert_signed_with_no_listing(&server);
        }
    }

    /// A ref file of the bucket repository that names a newer commit than
    /// its summary: the pull takes the commit of the summary, and reads no
    /// ref file.
    #[test]
    fn a_stale_summary_gives_the_commit_of_the_summary() {
        run_case("stale-summary", SECRET_KEY);
    }

    async fn stale_summary() {
        let dir = TmpDir::new("pull-collection-s3-stale");
        let source = create(dir.path(), "source", None).await;
        let old = commit(&source, dir.path(), "a", Some(ID), REF, FIXED_TS, BOUND).await;
        summarize(&source).await;
        let new = commit(
            &source,
            dir.path(),
            "b",
            Some(ID),
            REF,
            FIXED_TS + 10,
            BOUND,
        )
        .await;
        let server = StandIn::start();
        store_tree(&server, &dir.path().join("source"));
        assert_eq!(
            server.state().objects[&format!("repo/refs/mirrors/{ID}/{REF}")].bytes,
            format!("{new}\n").into_bytes()
        );
        let keys = bucket(&server.endpoint(), "s3://bkt/repo");
        let dest = bucket_dest(dir.path(), "dest", None, &[("bkt", &keys)]).await;
        let (opts, _) = bucket_options(&[REF]);
        let pulled = dest.pull_collection(ID, &["bkt"], opts).await.unwrap();
        assert_eq!(pulled.refs[0].commit, old);
        assert_eq!(mirror(&dest, REF).await, Some(old));
        let refs = target("refs/");
        assert!(
            !server
                .state()
                .requests
                .iter()
                .any(|(_, target)| target.starts_with(&refs))
        );
    }

    /// A remote whose bucket the server does not hold is skipped with the S3
    /// code `NoSuchBucket`, which the bucket client reads, and the next
    /// remote serves the ref.
    #[test]
    fn an_absent_bucket_is_skipped_with_the_s3_error() {
        run_case("absent-bucket", SECRET_KEY);
    }

    async fn absent_bucket() {
        let dir = TmpDir::new("pull-collection-s3-absent");
        let source = create(dir.path(), "source", None).await;
        let tip = commit(&source, dir.path(), "a", Some(ID), REF, FIXED_TS, BOUND).await;
        summarize(&source).await;
        let server = StandIn::start();
        store_tree(&server, &dir.path().join("source"));
        let gone = bucket(&server.endpoint(), "s3://other/repo");
        let keys = bucket(&server.endpoint(), "s3://bkt/repo");
        let dest = bucket_dest(dir.path(), "dest", None, &[("gone", &gone), ("bkt", &keys)]).await;
        let (opts, events) = bucket_options(&[REF]);
        let pulled = dest
            .pull_collection(ID, &["gone", "bkt"], opts)
            .await
            .unwrap();
        assert_eq!(pulled.refs[0].remote, "bkt");
        assert_eq!(mirror(&dest, REF).await, Some(tip));
        let (remote, message) = skipped(&events);
        assert_eq!(remote, "gone");
        assert!(message.contains("NoSuchBucket"), "{message}");
        assert_signed_with_no_listing(&server);
    }

    /// `rclone serve s3` checks the signature of each request. The pull
    /// reads the collection map of the summary of a bucket directory, and
    /// writes the collection ref. A wrong secret key skips the remote with
    /// the S3 code `SignatureDoesNotMatch`, and the pull writes nothing.
    #[test]
    fn a_bucket_on_rclone_serves_the_refs_of_a_collection() {
        if !rclone_available("a_bucket_on_rclone_serves_the_refs_of_a_collection") {
            return;
        }
        run_case("rclone", SECRET_KEY);
        run_case("rclone-wrong-secret", "wrong-secret-key");
    }

    async fn rclone(wrong_secret: bool) {
        let dir = TmpDir::new("pull-collection-s3-rclone");
        let source = create(dir.path(), "source", None).await;
        let tip = commit(&source, dir.path(), "a", Some(ID), REF, FIXED_TS, BOUND).await;
        summarize(&source).await;
        drop(source);
        // rclone keeps the listing of each directory, so the files of the
        // bucket directory are in place before the server starts.
        let root = dir.path().join("root");
        std::fs::create_dir_all(root.join("bkt")).unwrap();
        let status = Command::new("cp")
            .arg("-r")
            .arg(dir.path().join("source"))
            .arg(root.join("bkt").join("repo"))
            .status()
            .unwrap();
        assert!(status.success(), "cp -r");
        let server = Rclone::start(dir.path(), &root);
        let keys = bucket(&server.endpoint(), "s3://bkt/repo");
        let dest = bucket_dest(dir.path(), "dest", None, &[("bkt", &keys)]).await;
        let (opts, events) = bucket_options(&[REF]);
        let pulled = dest.pull_collection(ID, &["bkt"], opts).await;
        if wrong_secret {
            assert!(matches!(pulled, Err(Error::Pull(_))), "{pulled:?}");
            let (remote, message) = skipped(&events);
            assert_eq!(remote, "bkt");
            assert!(message.contains("SignatureDoesNotMatch"), "{message}");
            assert_nothing_written(&dest).await;
        } else {
            let pulled = pulled.unwrap();
            assert!(events.lock().unwrap().is_empty());
            assert_eq!(pulled.refs[0].commit, tip);
            assert_eq!(mirror(&dest, REF).await, Some(tip));
            assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
        }
    }

    /// Returns the overrides that allow the `http://` endpoint of the
    /// server.
    fn cleartext() -> EndpointOverrides {
        EndpointOverrides {
            allow_cleartext_credentials: true,
            ..EndpointOverrides::default()
        }
    }

    /// The listing of collection refs reads the refs of a bucket repository
    /// from its summary alone, with a name and with no name, and sends no
    /// listing request. A bucket repository with no `summary` gives
    /// `Error::Pull`. The call with the default overrides refuses the
    /// `http://` endpoint of the server before its first request.
    #[test]
    fn a_query_reads_the_summary_of_a_bucket() {
        run_case("query", SECRET_KEY);
    }

    async fn query_bucket() {
        let dir = TmpDir::new("pull-collection-s3-query");
        let source = create(dir.path(), "source", None).await;
        let tip = commit(&source, dir.path(), "a", Some(ID), REF, FIXED_TS, BOUND).await;
        let bare = StandIn::start();
        store_tree(&bare, &dir.path().join("source"));
        summarize(&source).await;
        let server = StandIn::start();
        store_tree(&server, &dir.path().join("source"));
        let keys = bucket(&server.endpoint(), "s3://bkt/repo");
        let bare_keys = bucket(&bare.endpoint(), "s3://bkt/repo");
        let dest = bucket_dest(
            dir.path(),
            "dest",
            None,
            &[("bkt", &keys), ("bare", &bare_keys)],
        )
        .await;

        for names in [&[REF, "os/absent"][..], &[]] {
            let listed = dest
                .remote_list_collection_refs_with("bkt", ID, names, cleartext(), None)
                .await
                .unwrap();
            assert_eq!(listed, [(REF.to_owned(), tip)]);
        }
        assert_eq!(requests_for(&server, "summary"), 2);
        assert_eq!(requests_for(&server, "summary.sig"), 0);
        assert_signed_with_no_listing(&server);

        let err = dest
            .remote_list_collection_refs_with("bare", ID, &[REF], cleartext(), None)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Pull(m) if m.contains("the bucket repository has no summary")),
            "{err:?}"
        );
        assert_eq!(requests_for(&bare, "summary"), 1);
        assert_signed_with_no_listing(&bare);

        let err = dest
            .remote_list_collection_refs("bkt", ID, &[REF])
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
        assert_eq!(requests_for(&server, "summary"), 2);
        assert_nothing_written(&dest).await;
    }

    /// `rclone serve s3` checks the signature of each request. The listing
    /// of collection refs reads the collection map of the summary of a
    /// bucket directory.
    #[test]
    fn a_query_on_rclone_reads_the_summary_of_a_bucket() {
        if !rclone_available("a_query_on_rclone_reads_the_summary_of_a_bucket") {
            return;
        }
        run_case("rclone-query", SECRET_KEY);
    }

    async fn rclone_query() {
        let dir = TmpDir::new("pull-collection-s3-rclone-query");
        let source = create(dir.path(), "source", None).await;
        let tip = commit(&source, dir.path(), "a", Some(ID), REF, FIXED_TS, BOUND).await;
        summarize(&source).await;
        drop(source);
        // rclone keeps the listing of each directory, so the files of the
        // bucket directory are in place before the server starts.
        let root = dir.path().join("root");
        std::fs::create_dir_all(root.join("bkt")).unwrap();
        let status = Command::new("cp")
            .arg("-r")
            .arg(dir.path().join("source"))
            .arg(root.join("bkt").join("repo"))
            .status()
            .unwrap();
        assert!(status.success(), "cp -r");
        let server = Rclone::start(dir.path(), &root);
        let keys = bucket(&server.endpoint(), "s3://bkt/repo");
        let dest = bucket_dest(dir.path(), "dest", None, &[("bkt", &keys)]).await;
        let listed = dest
            .remote_list_collection_refs_with("bkt", ID, &[], cleartext(), None)
            .await
            .unwrap();
        assert_eq!(listed, [(REF.to_owned(), tip)]);
        assert_nothing_written(&dest).await;
    }
}
