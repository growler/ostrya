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

use common::{TmpDir, anyone};
use ostrya::endpoint::EndpointOverrides;
use ostrya::{
    Checksum, CollectionPullEvent, CollectionPullOptions, CollectionPullStats, CollectionRef,
    CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, Ed25519Signer, Error,
    FsckOptions, MutableTree, PullFlags, PullOptions, RefSelector, Repo, RepoMode, SummaryOptions,
    TimestampCheck, Type, Value,
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
    Repo::create(
        &dir.join(name),
        CreateOptions {
            mode: RepoMode::Archive,
            collection_id: own.map(str::to_owned),
        },
    )
    .await
    .unwrap()
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
        Some(id) => txn.set_collection_ref(&CollectionRef::new(id, name), Some(&checksum)),
        None => txn.set_ref(name, Some(&checksum)),
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

/// Asserts that `repo` holds no ref and no commit object.
async fn assert_nothing_written(repo: &Repo) {
    assert!(repo.list_refs(None).await.unwrap().is_empty());
    assert!(repo.list_mirror_refs().await.unwrap().is_empty());
    assert!(repo.list_remote_refs().await.unwrap().is_empty());
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
/// A commit with no ref binding passes.
#[test]
fn the_bindings_of_each_commit_are_checked() {
    block_on(async {
        let cases: [(&str, Bind<'static>, bool); 4] = [
            (
                "other collection",
                Bind {
                    collection: Some(OTHER),
                    refs: Some(&[REF]),
                },
                false,
            ),
            (
                "no collection binding",
                Bind {
                    collection: None,
                    refs: Some(&[REF]),
                },
                false,
            ),
            (
                "other ref",
                Bind {
                    collection: Some(ID),
                    refs: Some(&["os/next"]),
                },
                false,
            ),
            (
                "no ref binding",
                Bind {
                    collection: Some(ID),
                    refs: None,
                },
                true,
            ),
        ];
        for (tag, bind, passes) in cases {
            let dir = TmpDir::new("pull-collection-bindings");
            let a = create(dir.path(), "a", Some(ID)).await;
            let tip = commit(&a, dir.path(), "a", None, REF, FIXED_TS, bind).await;
            summarize(&a).await;
            let server_a = RepoServer::start(&dir.path().join("a"), false).await;
            let dest = dest(dir.path(), None, &[("a", &server_a.url(), "")]).await;

            let (opts, _) = options(&[REF]);
            let pulled = dest.pull_collection(ID, &["a"], opts).await;
            if passes {
                pulled.unwrap();
                assert_eq!(mirror(&dest, REF).await, Some(tip), "{tag}");
                continue;
            }
            let err = pulled.unwrap_err();
            assert!(matches!(err, Error::Pull(_)), "{tag}: {err:?}");
            assert_nothing_written(&dest).await;
        }
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

// --- the place of the refs ---------------------------------------------------

/// Into a repository whose own collection id is the pulled id, the pull
/// writes the local ref, and the timestamp check reads that ref.
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
        assert_eq!(dest.resolve_ref_tip(REF).await.unwrap(), Some(tip));
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
        assert_eq!(dest.resolve_ref_tip(REF).await.unwrap(), Some(tip));
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
                "collection_id",
                ID,
                vec!["a"],
                PullOptions {
                    collection_id: Some(ID.to_owned()),
                    ..base()
                },
            ),
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
                "collection_id" => matches!(err, Error::Unsupported(_)),
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
}
