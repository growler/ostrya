//! HTTP pull from a remote repository.
//!
//! Each test serves a repository directory from an in-process static file
//! server. The server uses cleartext HTTP/1.1. If the transport matters, it
//! uses TLS, and ALPN selects HTTP/2. The test of the size cap of the summary
//! uses a scripted peer that states a length and sends no body.
//!
//! ostrya builds the source repositories. If the `ostree` command is absent,
//! each interop test that needs it returns early.
//!
//! The server records these values for the assertions:
//!
//! - the request paths that it receives, for the request-set assertions
//! - the status of each answer, for the status assertions
//! - the peak number of requests in flight at one time, for the concurrency
//!   assertion
//! - the number of connections that it accepts, for the connection-reuse
//!   assertion.

mod common;
#[path = "common/proxy.rs"]
mod proxy;
#[path = "common/pull.rs"]
mod pull;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use common::{
    TmpDir, dependency_error, file_inventory, ostree_available, ostree_supports_ed25519,
    store_with_field2, wait_for_commit_under_guard, within, writer_child_main, writer_child_with,
};
use futures_lite::future::poll_once;
use futures_lite::io::{AsyncReadExt, AsyncWriteExt};
use ostrya::RefSelector;
use ostrya::endpoint::EndpointOverrides;
use ostrya::fetch::{BearerToken, ClientIdentity, Fetcher, FetcherOptions, Proxy};
use ostrya::remote::{Endpoint, PullSession, StreamSessionOptions};
use ostrya::sign::Ed25519Verifier;
use ostrya::verify::{PullTrust, TrustedKeys};
use ostrya::{
    AdvertisedDelta, ArchiveAnswer, ArchiveView, Checksum, CommitModifierFlags, CommitState,
    CreateOptions, DeltaEndianness, DeltaOptions, DeltaSuperblock, Ed25519Signer, Error,
    FsckOptions, ObjectType, PullFlags, PullOptions, PullStats, PullVerify, Repo, RepoMode, Signer,
    SummaryOptions, TimestampCheck, TreeEntry, Type, Value, static_delta_relative_dir,
};
use ostrya_rt::{TcpListener, block_on, spawn};
use proxy::{TestProxy, Tunnel};
use pull::*;

/// The overrides that set the retry count alone.
fn retries(max_retries: u32) -> EndpointOverrides {
    EndpointOverrides {
        max_retries: Some(max_retries),
        ..EndpointOverrides::default()
    }
}

// --- tests -----------------------------------------------------------------

/// A pull of one ref fetches its commit and its whole tree. The ref goes under
/// `refs/remotes/`. A second pull of the unchanged ref fetches no object.
#[test]
fn pulls_a_ref_and_its_tree_then_fetches_nothing_the_second_time() {
    block_on(async {
        let dir = TmpDir::new("pull-http-basic");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let progress = ostrya::PullProgress::new();
        let stats = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    progress: Some(progress.clone()),
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();

        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(commit)
        );
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
        assert_eq!(
            dest.commit_state(&commit).await.unwrap(),
            CommitState::Normal
        );
        assert_eq!(stats.content_imported, 4);
        assert!(stats.metadata_imported >= 4);

        // The request order of a pull by the `ostree` command: the signature,
        // the summary, the config, the detached metadata of the commit, and
        // the commit.
        let seen = server.seen();
        assert_eq!(&seen[..3], ["summary.sig", "summary", "config"]);
        assert!(seen.contains(&meta_path(&commit, "commitmeta")));
        assert!(seen.contains(&meta_path(&commit, "commit")));
        for content in content_checksums(&remote, &commit).await {
            assert!(
                seen.contains(&filez_path(&content.to_hex())),
                "{content} was not fetched"
            );
        }

        // The statistics: each object arrives as a loose object from the
        // remote, and the pull requests the delta index. The transferred count
        // is the sum of the served bytes after the summary and the config. The
        // payloads of the three regular files are 6, 18, and 7 bytes. The
        // symlink adds nothing.
        let served: u64 = seen[3..]
            .iter()
            .filter_map(|path| std::fs::metadata(dir.path().join("remote").join(path)).ok())
            .map(|meta| meta.len())
            .sum();
        assert_eq!(stats.bytes_transferred, served);
        assert_eq!(stats.content_fetched, 4);
        // The delta index request counts as a fetch for each answer. Here it is
        // a 404.
        assert!(seen.iter().any(|path| path.starts_with("delta-indexes/")));
        assert_eq!(stats.metadata_fetched, stats.metadata_imported + 1);
        assert_eq!(stats.delta_parts, 0);
        assert_eq!(stats.content_bytes_unpacked, 6 + 18 + 7);
        let snapshot = progress.snapshot();
        assert_eq!(snapshot.bytes_transferred, stats.bytes_transferred);
        assert_eq!(snapshot.metadata_fetched, stats.metadata_fetched);
        assert_eq!(snapshot.content_fetched, stats.content_fetched);
        assert_eq!(snapshot.objects_done, snapshot.objects_total);
        assert!(!snapshot.scanning);

        // A repeat pull reads again the files that can change, and stops at the
        // commit that it holds. It fetches no object.
        server.forget();
        let repeated = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            (
                repeated.metadata_fetched,
                repeated.content_fetched,
                repeated.bytes_transferred,
                repeated.content_bytes_unpacked
            ),
            (0, 0, 0, 0)
        );
        let repeat = server.seen();
        assert_eq!(
            repeat,
            [
                "summary.sig".to_owned(),
                "summary".to_owned(),
                "config".to_owned(),
                meta_path(&commit, "commitmeta"),
            ]
        );
    });
}

/// The `[ex-ostrya]` group that turns the related switch off.
const DROP_RELATED: &str = "\n[ex-ostrya]\nkeep-detached-related=false\n";

/// Returns the keys of the stored detached metadata of a commit, in order.
async fn detached_keys(repo: &Repo, commit: &Checksum) -> Vec<String> {
    let Some(Value::Array(entries)) = repo.read_commit_detached_metadata(commit).await.unwrap()
    else {
        return Vec::new();
    };
    entries
        .iter()
        .map(|entry| entry.as_tuple().unwrap()[0].as_str().unwrap().to_owned())
        .collect()
}

/// Builds a remote as [`build_remote_chain`] does. The second commit holds
/// `test.detached` and names the first commit in `ostrya.related`.
async fn build_related_remote(dir: &Path) -> (Repo, Checksum) {
    let (remote, first, second) = build_remote_chain(dir).await;
    remote
        .write_commit_detached_metadata(&second, Some(&detached_dict()))
        .await
        .unwrap();
    remote
        .add_detached_related(&second, "layer/base", &first)
        .await
        .unwrap();
    assert_eq!(
        detached_keys(&remote, &second).await,
        ["test.detached", "ostrya.related"]
    );
    (remote, second)
}

/// With `keep-detached-related=false` in the destination, an HTTP pull drops
/// `ostrya.related` and stores each other property. With the default, it
/// stores the `.commitmeta` of the remote byte for byte.
#[test]
fn the_switch_shapes_the_detached_metadata_an_http_pull_stores() {
    for (extra, keys) in [
        (DROP_RELATED, &["test.detached"][..]),
        ("", &["test.detached", "ostrya.related"][..]),
    ] {
        block_on(async {
            let dir = TmpDir::new("pull-http-keep-related");
            let (_remote, commit) = build_related_remote(dir.path()).await;
            let server = RepoServer::start(&dir.path().join("remote"), false).await;
            let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), extra).await;

            dest.pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();

            assert_eq!(detached_keys(&dest, &commit).await, keys, "{extra:?}");
            if extra.is_empty() {
                let path = meta_path(&commit, "commitmeta");
                assert_eq!(
                    std::fs::read(dir.path().join("dest").join(&path)).unwrap(),
                    std::fs::read(dir.path().join("remote").join(&path)).unwrap()
                );
            }
        });
    }
}

/// A pull through a session applies the switch of the destination.
#[test]
fn the_switch_applies_to_a_pull_through_a_session() {
    block_on(async {
        let dir = TmpDir::new("pull-http-session-keep-related");
        let (_remote, commit) = build_related_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), DROP_RELATED).await;

        dest.pull_with_session(
            http_session(&server).await,
            PullTrust::unverified(),
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(detached_keys(&dest, &commit).await, ["test.detached"]);
    });
}

/// A switch that is not a boolean fails the pull before its first request.
/// The pull writes no object and no ref.
#[test]
fn a_switch_that_is_no_boolean_refuses_an_http_pull() {
    block_on(async {
        let dir = TmpDir::new("pull-http-keep-related-malformed");
        let (_remote, _commit) = build_related_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let extra = "\n[ex-ostrya]\nkeep-detached-related=maybe\n";
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), extra).await;

        let opts = || PullOptions {
            refs: vec!["test/main".to_owned()],
            ..PullOptions::default()
        };
        let err = dest.pull("origin", opts()).await.unwrap_err();
        assert!(matches!(&err, Error::Core(_)), "{err}");
        assert!(err.to_string().contains("keep-detached-related"), "{err}");
        let err = dest
            .pull_with_session(http_session(&server).await, PullTrust::unverified(), opts())
            .await
            .unwrap_err();
        assert!(matches!(&err, Error::Core(_)), "{err}");

        assert!(server.seen().is_empty(), "{:?}", server.seen());
        assert_no_refs(&dest).await;
        assert!(dest.list_objects().await.unwrap().is_empty());
    });
}

/// A guard holds the update lock, so an HTTP pull fails at the step that writes
/// detached metadata and refs. The pull keeps the marker of the commit that it
/// published. It writes no `.commitmeta` and no ref. The next pull completes
/// the commit, with its detached metadata.
#[test]
fn a_pull_that_times_out_at_the_ref_step_keeps_its_markers() {
    block_on(async {
        let dir = TmpDir::new("pull-http-ref-step-timeout");
        let (remote, commit) = build_remote(dir.path()).await;
        remote
            .write_commit_detached_metadata(&commit, Some(&detached_dict()))
            .await
            .unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        drop(build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await);
        let dest_dir = dir.path().join("dest");
        let config = dest_dir.join("config");
        let text = std::fs::read_to_string(&config).unwrap();
        std::fs::write(
            &config,
            text.replacen("[core]\n", "[core]\nlock-timeout-secs=0\n", 1),
        )
        .unwrap();
        let dest = Repo::open(&dest_dir).await.unwrap();
        let commitmeta = |root: &Path| root.join(meta_path(&commit, "commitmeta"));
        let opts = || PullOptions {
            refs: vec!["test/main".to_owned()],
            ..PullOptions::default()
        };

        let guard = dest.begin_update().await.unwrap();
        let err = dest.pull("origin", opts()).await.unwrap_err();
        assert!(matches!(err, Error::LockTimeout { secs: 0 }), "{err:?}");
        assert!(
            dest.has_object(ostrya::ObjectType::Commit, &commit)
                .await
                .unwrap()
        );
        assert_partial_marker(&dest_dir, &commit);
        assert!(!commitmeta(&dest_dir).exists(), "no detached metadata");
        assert_eq!(
            dest.resolve_ref_tip("origin:test/main").await.unwrap(),
            None
        );
        guard.finish().await.unwrap();

        dest.pull("origin", opts()).await.unwrap();
        assert!(
            !dest_dir
                .join("state")
                .join(format!("{}.commitpartial", commit.to_hex()))
                .exists()
        );
        assert_eq!(
            std::fs::read(commitmeta(&dest_dir)).unwrap(),
            std::fs::read(commitmeta(&dir.path().join("remote"))).unwrap()
        );
        assert_eq!(
            dest.resolve_ref_tip("origin:test/main").await.unwrap(),
            Some(commit)
        );
    });
}

/// Two handles open one repository, and one handle holds a guard. An HTTP pull
/// into the other handle publishes its objects. Then it waits at the step that
/// writes detached metadata and refs. With `lock-timeout-secs=-1`, it completes
/// that step after the guard is finished.
#[test]
fn a_pull_under_a_guard_publishes_its_objects_and_waits_at_the_ref_step() {
    block_on(async {
        let dir = TmpDir::new("pull-http-under-guard");
        let (remote, commit) = build_remote(dir.path()).await;
        remote
            .write_commit_detached_metadata(&commit, Some(&detached_dict()))
            .await
            .unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        drop(build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await);
        let dest_dir = dir.path().join("dest");
        let config = dest_dir.join("config");
        let text = std::fs::read_to_string(&config).unwrap();
        std::fs::write(
            &config,
            text.replacen("[core]\n", "[core]\nlock-timeout-secs=-1\n", 1),
        )
        .unwrap();
        let a = Repo::open(&dest_dir).await.unwrap();
        let b = Repo::open(&dest_dir).await.unwrap();
        let commitmeta = |root: &Path| root.join(meta_path(&commit, "commitmeta"));

        let guard = a.begin_update().await.unwrap();
        let mut task = spawn(async move {
            let opts = PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            };
            b.pull("origin", opts).await
        });
        wait_for_commit_under_guard(&a, &commit, &mut task).await;
        assert_eq!(a.resolve_ref_tip("origin:test/main").await.unwrap(), None);
        assert_partial_marker(&dest_dir, &commit);
        assert!(!commitmeta(&dest_dir).exists(), "no detached metadata");
        assert!(poll_once(&mut task).await.is_none(), "the pull waits");
        guard.finish().await.unwrap();

        within("the pull", task).await.unwrap();
        assert_eq!(
            a.resolve_ref_tip("origin:test/main").await.unwrap(),
            Some(commit)
        );
        assert!(
            !dest_dir
                .join("state")
                .join(format!("{}.commitpartial", commit.to_hex()))
                .exists()
        );
        assert_eq!(
            std::fs::read(commitmeta(&dest_dir)).unwrap(),
            std::fs::read(commitmeta(&dir.path().join("remote"))).unwrap()
        );
    });
}

/// The same pull over TLS. ALPN selects HTTP/2, and all objects use one
/// multiplexed connection.
#[test]
fn pulls_over_tls_with_http2() {
    block_on(async {
        let dir = TmpDir::new("pull-http-h2");
        let (_remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), true).await;
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, CA_PEM).unwrap();
        let dest = build_dest(
            dir.path(),
            RepoMode::Archive,
            &server.url(),
            &format!("tls-ca-path={}\n", ca.display()),
        )
        .await;

        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(commit)
        );
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
    });
}

/// A pull from an archive remote into each destination mode. Each destination
/// gets the same commit and passes its own fsck. For the bare family, this
/// means that the objects ingested again hash to the names that they arrived
/// under.
#[test]
fn pulls_an_archive_remote_into_every_destination_mode() {
    block_on(async {
        for mode in [
            RepoMode::Archive,
            RepoMode::BareUser,
            RepoMode::BareUserOnly,
            RepoMode::Bare,
        ] {
            // A bare destination writes the uid and gid of each object. For a
            // remote with canonical commits, both are root.
            if mode == RepoMode::Bare && !rustix::process::geteuid().is_root() {
                eprintln!("skipping the bare destination: not running as root");
                continue;
            }
            let dir = TmpDir::new(&format!("pull-http-mode-{}", mode.as_mode_str()));
            let (_remote, commit) = build_remote(dir.path()).await;
            let server = RepoServer::start(&dir.path().join("remote"), false).await;
            let dest = build_dest(dir.path(), mode, &server.url(), "").await;

            dest.pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();

            assert_eq!(
                dest.resolve_rev("origin:test/main", true).await.unwrap(),
                Some(commit),
                "{mode:?}"
            );
            let report = dest.fsck(&FsckOptions::default()).await.unwrap();
            assert!(report.is_ok(), "{mode:?}: {:?}", report.errors);

            // The symlink object and the two regular files with different modes
            // all arrive, so the whole tree reads back.
            let (tree, _) = dest.read_commit(&commit.to_hex()).await.unwrap();
            let mut names: Vec<String> = tree
                .read_dir()
                .await
                .unwrap()
                .into_iter()
                .map(|entry| match entry {
                    TreeEntry::File { name, .. } | TreeEntry::Dir { name, .. } => name,
                })
                .collect();
            names.sort();
            assert_eq!(
                names,
                ["exec.sh", "hello.txt", "link", "subdir"],
                "{mode:?}"
            );
        }
    });
}

/// The `ostree` command reads what an HTTP pull wrote. It resolves the ref,
/// passes its own fsck, and reads the tree back.
#[test]
fn the_tool_reads_what_an_http_pull_wrote() {
    if !ostree_available() {
        eprintln!("skipping: the ostree tool is not installed");
        return;
    }
    block_on(async {
        let dir = TmpDir::new("pull-http-interop");
        let (_remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;

        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        let path = dir.path().join("dest");
        let repo_arg = format!("--repo={}", path.display());
        let resolved = ostree(&[&repo_arg, "rev-parse", "origin:test/main"]);
        assert_eq!(String::from_utf8_lossy(&resolved).trim(), commit.to_hex());
        ostree(&[&repo_arg, "fsck"]);
        let listing = ostree(&[&repo_arg, "ls", "-R", &commit.to_hex()]);
        let listing = String::from_utf8_lossy(&listing);
        assert!(listing.contains("/hello.txt"), "{listing}");
        assert!(listing.contains("/subdir/nested.txt"), "{listing}");
    });
}

/// A pull reads a payload that takes several reads, from a remote that the
/// `ostree` command built.
///
/// The object is 256 KiB of incompressible content, so the streaming loop runs
/// several iterations. The input buffer of the decoder refills several times.
/// The end-of-stream check meets the framing that the `ostree` command wrote.
/// The `ostree` command verifies the checksum of each object and reads the
/// payload.
#[test]
fn pulls_a_multi_read_payload_from_a_tool_built_remote() {
    if !ostree_available() {
        eprintln!("skipping: the ostree tool is not installed");
        return;
    }
    block_on(async {
        let dir = TmpDir::new("pull-http-tool-remote");
        let src = dir.path().join("src");
        build_tree(&src, b"hello\n");
        let payload = incompressible(256 * 1024);
        std::fs::write(src.join("big.bin"), &payload).unwrap();

        let remote = dir.path().join("remote");
        let remote_arg = format!("--repo={}", remote.display());
        ostree(&[&remote_arg, "init", "--mode=archive"]);
        let commit = String::from_utf8(ostree(&[
            &remote_arg,
            "commit",
            "-b",
            "test/main",
            "--timestamp=2020-01-01 00:00:00 +0000",
            &format!("--tree=dir={}", src.display()),
        ]))
        .unwrap()
        .trim()
        .to_owned();
        ostree(&[&remote_arg, "summary", "-u"]);
        // The premise of the test: one body is longer than one read of the 128
        // KiB payload buffer of the receive path.
        let largest = largest_filez(&remote);
        assert!(largest > 128 * 1024, "largest object is {largest} byte(s)");

        let server = RepoServer::start(&remote, false).await;
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;
        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(Checksum::from_hex(&commit).unwrap())
        );
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());

        let dest_arg = format!("--repo={}", dir.path().join("dest").display());
        ostree(&[&dest_arg, "fsck"]);
        let read_back = ostree(&[&dest_arg, "cat", &commit, "/big.bin"]);
        assert_eq!(read_back.len(), payload.len());
        assert!(
            read_back == payload,
            "the payload the tool read back differs"
        );
    });
}

/// An archive-to-archive pull stores each `.filez` object as the remote holds
/// it. It does not inflate the object and compress it again at the `zlib-level`
/// of the destination.
///
/// The destination sets a level far from the default level of the remote. The
/// payload is long and repetitive, so a different level gives a visibly
/// different byte sequence. A match shows that the destination stored the
/// fetched bytes without change.
#[test]
fn an_archive_pull_reproduces_filez_bytes_at_a_different_zlib_level() {
    block_on(async {
        let dir = TmpDir::new("pull-http-passthrough-level");
        let src = dir.path().join("src");
        build_tree(&src, b"hello\n");
        let big = "the quick brown fox jumps over the lazy dog\n".repeat(4000);
        std::fs::write(src.join("big.txt"), big.as_bytes()).unwrap();
        let remote_path = dir.path().join("remote");
        let remote = Repo::create(&remote_path, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let commit = commit_tree(&remote, dir.path(), "src", "test/main", None, FIXED_TS).await;
        remote
            .regenerate_summary(&SummaryOptions {
                last_modified: Some(FIXED_TS),
                ..SummaryOptions::default()
            })
            .await
            .unwrap();

        let server = RepoServer::start(&remote_path, false).await;

        let dest_path = dir.path().join("dest");
        let dest_repo = Repo::create(&dest_path, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        drop(dest_repo);
        let config = dest_path.join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str(&format!(
            "\n[archive]\nzlib-level=1\n[remote \"origin\"]\nurl={}\ngpg-verify=false\n",
            server.url()
        ));
        std::fs::write(&config, text).unwrap();
        let dest = Repo::open(&dest_path).await.unwrap();

        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        let checksums = content_checksums(&remote, &commit).await;
        assert!(!checksums.is_empty());
        for checksum in checksums {
            let path = filez_path(&checksum.to_hex());
            let remote_bytes = std::fs::read(remote_path.join(&path)).unwrap();
            let dest_bytes = std::fs::read(dest_path.join(&path)).unwrap();
            assert_eq!(
                dest_bytes, remote_bytes,
                "{checksum}: the destination's .filez bytes differ from the remote's"
            );
        }
    });
}

/// An archive-to-archive pull from a remote that the `ostree` command built
/// stores each `.filez` object as the `ostree` command wrote it. The zlib
/// encoder of the `ostree` command and the raw-DEFLATE encoder of ostrya are
/// different implementations. If the bytes match, the destination stored the
/// fetched bytes without change. It did not inflate them and compress them
/// again.
#[test]
fn an_archive_pull_reproduces_filez_bytes_from_a_tool_built_remote() {
    if !ostree_available() {
        eprintln!("skipping: the ostree tool is not installed");
        return;
    }
    block_on(async {
        let dir = TmpDir::new("pull-http-passthrough-tool-remote");
        let src = dir.path().join("src");
        build_tree(&src, b"hello\n");
        let payload = incompressible(256 * 1024);
        std::fs::write(src.join("big.bin"), &payload).unwrap();

        let remote_path = dir.path().join("remote");
        let remote_arg = format!("--repo={}", remote_path.display());
        ostree(&[&remote_arg, "init", "--mode=archive"]);
        let commit = String::from_utf8(ostree(&[
            &remote_arg,
            "commit",
            "-b",
            "test/main",
            "--timestamp=2020-01-01 00:00:00 +0000",
            &format!("--tree=dir={}", src.display()),
        ]))
        .unwrap()
        .trim()
        .to_owned();
        ostree(&[&remote_arg, "summary", "-u"]);

        let server = RepoServer::start(&remote_path, false).await;
        let dest_path = dir.path().join("dest");
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        let commit_checksum = Checksum::from_hex(&commit).unwrap();
        let checksums = content_checksums(&dest, &commit_checksum).await;
        assert!(!checksums.is_empty());
        for checksum in checksums {
            let path = filez_path(&checksum.to_hex());
            let remote_bytes = std::fs::read(remote_path.join(&path)).unwrap();
            let dest_bytes = std::fs::read(dest_path.join(&path)).unwrap();
            assert_eq!(
                dest_bytes, remote_bytes,
                "{checksum}: the destination's .filez bytes differ from the tool-built remote's"
            );
        }

        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
        let dest_arg = format!("--repo={}", dest_path.display());
        ostree(&[&dest_arg, "fsck"]);
        let read_back = ostree(&[&dest_arg, "cat", &commit, "/big.bin"]);
        assert!(
            read_back == payload,
            "the payload the tool read back differs"
        );
    });
}

/// A bare-family destination stores the inflated payload, because the
/// pass-through path applies only to an archive destination. The content object
/// of a bare-user destination holds the plain, uncompressed bytes. It does not
/// hold the raw-DEFLATE bytes of the remote.
#[test]
fn a_bare_family_destination_still_stores_the_inflated_payload() {
    block_on(async {
        let dir = TmpDir::new("pull-http-passthrough-bare");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;

        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        let (tree, _) = remote.read_commit(&commit.to_hex()).await.unwrap();
        let mut content = None;
        for entry in tree.read_dir().await.unwrap() {
            if let TreeEntry::File { name, checksum } = entry
                && name == "hello.txt"
            {
                content = Some(checksum);
            }
        }
        let hex = content.expect("hello.txt").to_hex();
        let stored = std::fs::read(
            dir.path()
                .join("dest")
                .join("objects")
                .join(&hex[..2])
                .join(format!("{}.file", &hex[2..])),
        )
        .unwrap();
        assert_eq!(stored, b"hello\n");
    });
}

/// The pass-through path holds the declared size to equality. The declared size
/// is not a ceiling. If a payload inflates to fewer bytes than its header
/// declares, the path refuses it, the same as a payload that inflates to more.
#[test]
fn a_payload_underrunning_its_declared_size_fails_the_pull() {
    block_on(async {
        let dir = TmpDir::new("pull-http-declared-size-under");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        // Replace the compressed bytes of an object with a payload by a final
        // stored DEFLATE block of one byte. Keep the header and the size that
        // it declares.
        let mut victim = None;
        for checksum in content_checksums(&remote, &commit).await {
            let path = filez_path(&checksum.to_hex());
            let stored = std::fs::read(dir.path().join("remote").join(&path)).unwrap();
            let declared = u64::from_be_bytes(stored[8..16].try_into().unwrap());
            if declared > 1 {
                victim = Some((path, stored));
                break;
            }
        }
        let (path, stored) = victim.expect("the fixture tree holds a payload-bearing file");
        let header_len = u32::from_be_bytes(stored[..4].try_into().unwrap()) as usize;
        let mut tampered = stored[..8 + header_len].to_vec();
        // A final stored block: BFINAL=1, BTYPE=00, then LEN=1, NLEN=!LEN, and
        // one byte of content.
        tampered.extend_from_slice(&[0x01, 0x01, 0x00, 0xfe, 0xff, b'x']);
        server.tamper(&path, tampered);

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidFormat(_)), "{err}");
        assert!(err.to_string().contains("inflates to 1 byte"), "{err}");
        assert_nothing_published(&dest).await;
        // The body arrived whole, so the refusal is about the object itself. A
        // second fetch gets the same refusal, so the pull does not request the
        // object again, for any retry count.
        assert_eq!(server.requests_for(&path), 1);
    });
}

/// A bare-family destination also holds the declared size to equality. If a
/// payload inflates to fewer bytes than its header declares, the pull refuses
/// it. This occurs also when the bytes hash to the name of the object.
#[test]
fn a_bare_family_destination_refuses_a_payload_under_its_declared_size() {
    block_on(async {
        let dir = TmpDir::new("pull-http-declared-size-under-bare");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;

        // Increase the declared size of an object with a payload by 100 and
        // keep its compressed bytes. The content then still hashes to the name
        // of the object.
        let mut victim = None;
        for checksum in content_checksums(&remote, &commit).await {
            let path = filez_path(&checksum.to_hex());
            let stored = std::fs::read(dir.path().join("remote").join(&path)).unwrap();
            let declared = u64::from_be_bytes(stored[8..16].try_into().unwrap());
            if declared > 0 {
                victim = Some((path, stored, declared));
                break;
            }
        }
        let (path, mut tampered, declared) =
            victim.expect("the fixture tree holds a payload-bearing file");
        tampered[8..16].copy_from_slice(&(declared + 100).to_be_bytes());
        server.tamper(&path, tampered);

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidFormat(_)), "{err}");
        assert!(err.to_string().contains("inflates to"), "{err}");
        assert_nothing_published(&dest).await;
        assert_eq!(server.requests_for(&path), 1);
    });
}

/// The overrun check reports its own message also when the compressed payload
/// arrives over more than one read. The pass-through path decodes into a
/// decoder that buffers decoded bytes and forwards them on a later call.
///
/// A small fixture object takes one read, one decode, and one forward. With
/// such an object, the test cannot tell the overrun message from a generic
/// "trailing bytes" report that wraps it. A multi-read object shows the
/// difference.
#[test]
fn an_overrunning_payload_over_multiple_reads_reports_the_overrun() {
    block_on(async {
        let dir = TmpDir::new("pull-http-declared-size-over-multiread");
        let src = dir.path().join("src");
        build_tree(&src, b"hello\n");
        std::fs::write(src.join("big.bin"), incompressible(200 * 1024)).unwrap();
        let remote_path = dir.path().join("remote");
        let remote = Repo::create(&remote_path, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let commit = commit_tree(&remote, dir.path(), "src", "test/main", None, FIXED_TS).await;
        remote
            .regenerate_summary(&SummaryOptions {
                last_modified: Some(FIXED_TS),
                ..SummaryOptions::default()
            })
            .await
            .unwrap();

        let server = RepoServer::start(&remote_path, false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        // Declare a size much larger than one read from the connection
        // (`COPY_CHUNK` is 64 KiB). Keep it smaller than the real uncompressed
        // size of the object, so the decode of the object spans more than one
        // read.
        let mut victim = None;
        for checksum in content_checksums(&remote, &commit).await {
            let path = filez_path(&checksum.to_hex());
            let stored = std::fs::read(remote_path.join(&path)).unwrap();
            let declared = u64::from_be_bytes(stored[8..16].try_into().unwrap());
            if declared > 150_000 {
                victim = Some((path, stored));
                break;
            }
        }
        let (path, mut stored) = victim.expect("the fixture tree holds a large payload object");
        stored[8..16].copy_from_slice(&150_000u64.to_be_bytes());
        server.tamper(&path, stored);

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidFormat(_)), "{err}");
        assert!(err.to_string().contains("outgrew the 150000 byte"), "{err}");
        assert_nothing_published(&dest).await;
    });
}

/// A remote with no summary answers 404 for it. Each requested ref then
/// resolves through `refs/heads/<ref>`.
#[test]
fn a_remote_with_no_summary_resolves_through_refs_heads() {
    block_on(async {
        let dir = TmpDir::new("pull-http-no-summary");
        let (_remote, commit) = build_remote(dir.path()).await;
        std::fs::remove_file(dir.path().join("remote/summary")).unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(commit)
        );
        assert!(server.seen().contains(&"refs/heads/test/main".to_owned()));
    });
}

/// A pull from a remote with no summary reads each ref from `refs/heads` before
/// it counts the transferred bytes. It does the same with the summary and the
/// config. The transferred figure starts after the ref files.
#[test]
fn the_transferred_count_leaves_out_the_ref_files() {
    block_on(async {
        let dir = TmpDir::new("pull-http-no-summary-transferred");
        build_remote(dir.path()).await;
        std::fs::remove_file(dir.path().join("remote/summary")).unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let stats = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();

        let seen = server.seen();
        assert_eq!(
            &seen[..4],
            ["summary.sig", "summary", "config", "refs/heads/test/main"]
        );
        // The 404 answers have empty bodies, so only the served files count.
        let served: u64 = seen[4..]
            .iter()
            .filter_map(|path| std::fs::metadata(dir.path().join("remote").join(path)).ok())
            .map(|meta| meta.len())
            .sum();
        assert!(served > 0);
        assert_eq!(stats.bytes_transferred, served);
    });
}

/// Two concurrent pulls share one progress handle. Each pull reports the
/// statistics of its own work, and the handle shows the sum of both.
#[test]
fn concurrent_pulls_sharing_a_progress_handle_keep_their_own_statistics() {
    block_on(async {
        let dir = TmpDir::new("pull-http-shared-progress");
        build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let mut dests = Vec::new();
        for name in ["solo", "a", "b"] {
            let sub = dir.path().join(name);
            std::fs::create_dir(&sub).unwrap();
            dests.push(build_dest(&sub, RepoMode::Archive, &server.url(), "").await);
        }
        let opts = |progress: Option<ostrya::PullProgress>| PullOptions {
            refs: vec!["test/main".to_owned()],
            progress,
            ..PullOptions::default()
        };
        // The statistics of one pull alone, without the elapsed time.
        let solo = dests[0].pull("origin", opts(None)).await.unwrap();
        let solo = PullStats {
            elapsed: std::time::Duration::ZERO,
            ..solo
        };
        assert_eq!(solo.content_fetched, 4);

        let shared = ostrya::PullProgress::new();
        let (a, b) = futures_lite::future::zip(
            dests[1].pull("origin", opts(Some(shared.clone()))),
            dests[2].pull("origin", opts(Some(shared.clone()))),
        )
        .await;
        for stats in [a.unwrap(), b.unwrap()] {
            assert_eq!(
                PullStats {
                    elapsed: std::time::Duration::ZERO,
                    ..stats
                },
                solo
            );
        }
        let snapshot = shared.snapshot();
        assert_eq!(snapshot.bytes_transferred, 2 * solo.bytes_transferred);
        assert_eq!(snapshot.metadata_fetched, 2 * solo.metadata_fetched);
        assert_eq!(snapshot.content_fetched, 2 * solo.content_fetched);
        assert_eq!(snapshot.objects_done, snapshot.objects_total);
        assert!(!snapshot.scanning);
    });
}

/// Because a ref name goes on the wire percent-encoded, a name with `%` asks
/// the server for that exact name. The server does not decode the escape.
#[test]
fn a_ref_name_reaches_the_wire_percent_encoded() {
    block_on(async {
        let dir = TmpDir::new("pull-http-ref-encoded");
        build_remote(dir.path()).await;
        std::fs::remove_file(dir.path().join("remote/summary")).unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        // Without encoding, the bytes of `é` reach the wire as raw bytes in the
        // request target. The name is absent on the remote.
        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["é".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::RefNotFound(_)), "{err}");
        let seen = server.seen();
        assert!(
            seen.contains(&"refs/heads/%C3%A9".to_owned()),
            "the name reached the wire unencoded: {seen:?}"
        );
    });
}

/// A requested ref name that fails the ref-name rule gives `InvalidRefspec`
/// before the pull sends a request for a ref.
#[test]
fn a_requested_name_outside_the_ref_name_rule_is_refused_before_a_request() {
    block_on(async {
        let dir = TmpDir::new("pull-http-name-rule");
        build_remote(dir.path()).await;
        std::fs::remove_file(dir.path().join("remote/summary")).unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        for name in ["a b", "a*", "-a", "a/.b", "a:b:c"] {
            let err = dest
                .pull(
                    "origin",
                    PullOptions {
                        refs: vec![name.to_owned()],
                        ..PullOptions::default()
                    },
                )
                .await
                .unwrap_err();
            assert!(
                matches!(&err, Error::InvalidRefspec(got) if got == name),
                "{name:?}: {err}"
            );
        }
        let seen = server.seen();
        assert!(
            !seen.iter().any(|path| path.starts_with("refs/")),
            "a ref was requested: {seen:?}"
        );
        assert_nothing_published(&dest).await;
    });
}

/// If a ref is in neither the summary nor `refs/heads`, the pull fails before
/// it fetches anything.
#[test]
fn an_absent_ref_fails_the_pull() {
    block_on(async {
        let dir = TmpDir::new("pull-http-absent-ref");
        build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/other".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::RefNotFound(_)), "{err}");
        assert_nothing_published(&dest).await;
    });
}

/// An empty ref list takes the `branches` that the remote configures. If the
/// remote configures none, the pull fails.
#[test]
fn an_empty_ref_list_takes_the_configured_branches() {
    block_on(async {
        let dir = TmpDir::new("pull-http-branches");
        let (_remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(
            dir.path(),
            RepoMode::Archive,
            &server.url(),
            "branches=test/main;\n",
        )
        .await;

        dest.pull("origin", PullOptions::default()).await.unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(commit)
        );
    });
}

#[test]
fn an_empty_ref_list_with_no_branches_fails() {
    block_on(async {
        let dir = TmpDir::new("pull-http-no-branches");
        build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let err = dest
            .pull("origin", PullOptions::default())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no configured branches"), "{err}");
        assert_nothing_published(&dest).await;
    });
}

/// A mirror pull of all refs takes them from the summary and writes them under
/// `refs/heads`. It copies the summary and its signature without change. Here
/// the signature bytes are arbitrary. The remote turns on no summary
/// verification, so the pull copies the bytes and does not read them. The
/// pull writes no file under `extensions/ostrya/summary`, and the archive
/// view serves the summary of the `anonymous` item from there.
#[test]
fn a_mirror_pull_writes_local_refs_and_copies_the_summary() {
    block_on(async {
        let dir = TmpDir::new("pull-http-mirror");
        let (_remote, commit) = build_remote(dir.path()).await;
        std::fs::write(dir.path().join("remote/summary.sig"), SUMMARY_SIG).unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        dest.regenerate_summary(&ostrya::SummaryOptions::default())
            .await
            .unwrap();
        let stem = dir.path().join(format!(
            "dest/extensions/ostrya/summary/{}",
            Checksum::sha256(b"anonymous")
        ));
        let access = stem.with_extension("access");
        let item_summary = std::fs::read(&stem).unwrap();
        let item_access = std::fs::read(&access).unwrap();

        dest.pull(
            "origin",
            PullOptions {
                flags: PullFlags::MIRROR,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        // The ref is local. It is not under refs/remotes.
        assert_eq!(
            dest.resolve_rev("test/main", true).await.unwrap(),
            Some(commit)
        );
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            None
        );
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());

        let published = std::fs::read(dir.path().join("remote/summary")).unwrap();
        let copied = std::fs::read(dir.path().join("dest/summary")).unwrap();
        assert_eq!(copied, published);
        // A client that pulls from this repository with
        // `gpg-verify-summary=true` needs the signature that covers those
        // bytes.
        let signature = std::fs::read(dir.path().join("dest/summary.sig")).unwrap();
        assert_eq!(signature, SUMMARY_SIG);

        assert_eq!(std::fs::read(&stem).unwrap(), item_summary);
        assert_eq!(std::fs::read(&access).unwrap(), item_access);
        let view = ArchiveView::new(dest.clone());
        let anonymous = common::repo_access(&dest, "anonymous");
        let served = match view.get("summary", &anonymous).await.unwrap() {
            ArchiveAnswer::Stream { mut body, .. } => {
                let mut out = Vec::new();
                body.read_to_end(&mut out).await.unwrap();
                out
            }
            other => panic!("not served: {other:?}"),
        };
        assert_eq!(served, item_summary);
    });
}

/// If the remote has no `summary.sig`, the pull keeps the file of the
/// destination unchanged. This is the observed behavior of the `ostree`
/// command.
#[test]
fn a_mirror_pull_from_an_unsigned_summary_keeps_the_signature_here() {
    block_on(async {
        let dir = TmpDir::new("pull-http-mirror-unsigned");
        build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        std::fs::write(dir.path().join("dest/summary.sig"), b"an earlier pull").unwrap();

        dest.pull(
            "origin",
            PullOptions {
                flags: PullFlags::MIRROR,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        let published = std::fs::read(dir.path().join("remote/summary")).unwrap();
        let copied = std::fs::read(dir.path().join("dest/summary")).unwrap();
        assert_eq!(copied, published);
        let signature = std::fs::read(dir.path().join("dest/summary.sig")).unwrap();
        assert_eq!(signature, b"an earlier pull");
    });
}

/// A mirror pull takes its ref names from the summary. The pull refuses a
/// malformed name there at the same point as a malformed requested name, before
/// the first object request. It does not wait until the transaction resolves
/// the refspec at publication.
#[test]
fn a_mirror_pull_rejects_a_malformed_summary_ref_name_before_fetching() {
    // The length stays the same, so the frame offsets of the summary stay
    // valid. The name gets a traversal component, which the ref store
    // refuses.
    mirror_pull_refuses_summary_name("pull-http-mirror-bad-ref", b"test/../m");
}

/// A mirror pull refuses a summary name that fails the ref-name rule, here a
/// name with a space, at the same point.
#[test]
fn a_mirror_pull_rejects_a_summary_ref_name_outside_the_rule_before_fetching() {
    mirror_pull_refuses_summary_name("pull-http-mirror-space-ref", b"test/m an");
}

/// Replaces the ref name `test/main` of the published summary with
/// `replacement`, which has the same length, and checks that a mirror pull
/// refuses the name before it fetches an object.
fn mirror_pull_refuses_summary_name(tag: &str, replacement: &'static [u8]) {
    block_on(async {
        const NAME: &[u8] = b"test/main";
        let dir = TmpDir::new(tag);
        build_remote(dir.path()).await;
        let published = std::fs::read(dir.path().join("remote/summary")).unwrap();
        let at = published
            .windows(NAME.len())
            .position(|window| window == NAME)
            .expect("the summary names the ref");
        let mut tampered = published.clone();
        tampered[at..at + NAME.len()].copy_from_slice(replacement);

        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        server.tamper("summary", tampered);
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    flags: PullFlags::MIRROR,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::InvalidRefspec(name) if name.as_bytes() == replacement),
            "{err}"
        );
        assert_nothing_published(&dest).await;
        let seen = server.seen();
        assert!(
            !seen.iter().any(|path| path.starts_with("objects/")),
            "an object was fetched before the ref names were checked: {seen:?}"
        );
    });
}

/// A mirror pull of named refs holds only part of what the remote publishes, so
/// it writes neither the summary nor its signature.
#[test]
fn a_mirror_pull_of_named_refs_writes_no_summary() {
    block_on(async {
        let dir = TmpDir::new("pull-http-mirror-named");
        build_remote(dir.path()).await;
        std::fs::write(dir.path().join("remote/summary.sig"), SUMMARY_SIG).unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                flags: PullFlags::MIRROR,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert!(!dir.path().join("dest/summary").exists());
        assert!(!dir.path().join("dest/summary.sig").exists());
    });
}

/// A mirror pull of all refs needs the summary to know all the refs.
#[test]
fn a_mirror_pull_of_every_ref_needs_a_summary() {
    block_on(async {
        let dir = TmpDir::new("pull-http-mirror-no-summary");
        build_remote(dir.path()).await;
        std::fs::remove_file(dir.path().join("remote/summary")).unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    flags: PullFlags::MIRROR,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("mirror mode"), "{err}");
        assert_nothing_published(&dest).await;
    });
}

/// `depth` follows the commit chain. If the remote does not hold a parent, that
/// parent ends the chain, and the pull does not fail.
#[test]
fn depth_follows_parents_and_an_absent_parent_ends_the_chain() {
    block_on(async {
        let dir = TmpDir::new("pull-http-depth");
        let src = dir.path().join("src");
        build_tree(&src, b"first\n");
        let remote = Repo::create(
            &dir.path().join("remote"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let first = commit_tree(&remote, dir.path(), "src", "test/main", None, FIXED_TS).await;
        std::fs::write(src.join("hello.txt"), b"second\n").unwrap();
        let second = commit_tree(
            &remote,
            dir.path(),
            "src",
            "test/main",
            Some(first),
            FIXED_TS + 1,
        )
        .await;
        std::fs::write(src.join("hello.txt"), b"third\n").unwrap();
        let third = commit_tree(
            &remote,
            dir.path(),
            "src",
            "test/main",
            Some(second),
            FIXED_TS + 2,
        )
        .await;
        remote
            .regenerate_summary(&SummaryOptions {
                last_modified: Some(FIXED_TS),
                ..SummaryOptions::default()
            })
            .await
            .unwrap();

        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        // A depth of two parents reaches all three commits.
        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                depth: 2,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        for commit in [first, second, third] {
            assert!(
                dest.has_object(ostrya::ObjectType::Commit, &commit)
                    .await
                    .unwrap(),
                "{commit} was not pulled"
            );
            assert_eq!(
                dest.commit_state(&commit).await.unwrap(),
                CommitState::Normal
            );
        }
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());

        // If the remote pruned the root, the chain ends there, and the pull
        // does not fail. A local source with truncated history gives the same
        // result.
        let dir2 = TmpDir::new("pull-http-depth-truncated");
        let dest2 = build_dest(dir2.path(), RepoMode::Archive, &server.url(), "").await;
        server.hide(&meta_path(&first, "commit"));
        dest2
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    depth: -1,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();
        assert!(
            dest2
                .has_object(ostrya::ObjectType::Commit, &second)
                .await
                .unwrap()
        );
        assert!(
            !dest2
                .has_object(ostrya::ObjectType::Commit, &first)
                .await
                .unwrap()
        );
        assert_eq!(
            dest2.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(third)
        );
    });
}

/// A pull at a greater depth extends the history that a shallower pull left.
/// The pull walks past the complete tip that this repository holds, and the
/// parent arrives.
#[test]
fn a_deep_pull_extends_a_shallow_history() {
    block_on(async {
        let dir = TmpDir::new("pull-http-deepen");
        let src = dir.path().join("src");
        build_tree(&src, b"first\n");
        let remote = Repo::create(
            &dir.path().join("remote"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let first = commit_tree(&remote, dir.path(), "src", "test/main", None, FIXED_TS).await;
        std::fs::write(src.join("hello.txt"), b"second\n").unwrap();
        let second = commit_tree(
            &remote,
            dir.path(),
            "src",
            "test/main",
            Some(first),
            FIXED_TS + 1,
        )
        .await;
        remote
            .regenerate_summary(&SummaryOptions {
                last_modified: Some(FIXED_TS),
                ..SummaryOptions::default()
            })
            .await
            .unwrap();

        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        // The tip alone, so the parent stays absent.
        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                depth: 0,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            dest.commit_state(&second).await.unwrap(),
            CommitState::Normal
        );
        assert!(
            !dest
                .has_object(ostrya::ObjectType::Commit, &first)
                .await
                .unwrap()
        );

        // The whole history. The pull must walk past the tip that is already
        // here.
        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                depth: -1,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert!(
            dest.has_object(ostrya::ObjectType::Commit, &first)
                .await
                .unwrap(),
            "the deep pull did not fetch the parent commit"
        );
        assert_eq!(
            dest.commit_state(&first).await.unwrap(),
            CommitState::Normal
        );
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
    });
}

/// If the remote answers 404 for a parent, that parent ends the chain. The pull
/// drops the detached metadata of that parent and does not write it. The pull
/// fetches the `.commitmeta` before the commit, and writes it when the commit
/// object is here.
#[test]
fn a_chain_ending_parent_leaves_no_detached_metadata() {
    block_on(async {
        let dir = TmpDir::new("pull-http-detached-chain-end");
        let src = dir.path().join("src");
        build_tree(&src, b"first\n");
        let remote = Repo::create(
            &dir.path().join("remote"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let first = commit_tree(&remote, dir.path(), "src", "test/main", None, FIXED_TS).await;
        std::fs::write(src.join("hello.txt"), b"second\n").unwrap();
        let second = commit_tree(
            &remote,
            dir.path(),
            "src",
            "test/main",
            Some(first),
            FIXED_TS + 1,
        )
        .await;
        // Both commits have detached metadata, so the pull holds bytes for the
        // parent whose commit object it cannot fetch.
        for commit in [first, second] {
            remote
                .write_commit_detached_metadata(&commit, Some(&detached_dict()))
                .await
                .unwrap();
        }
        remote
            .regenerate_summary(&SummaryOptions {
                last_modified: Some(FIXED_TS),
                ..SummaryOptions::default()
            })
            .await
            .unwrap();

        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        server.hide(&meta_path(&first, "commit"));
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                depth: -1,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        // The pull fetched and dropped the detached metadata of the parent. It
        // wrote the detached metadata of the tip with the commit that it
        // belongs to.
        assert!(
            server.seen_set().contains(&meta_path(&first, "commitmeta")),
            "the parent's detached metadata was not requested"
        );
        let orphan = dir
            .path()
            .join("dest")
            .join(meta_path(&first, "commitmeta"));
        assert!(!orphan.exists(), "{} was written", orphan.display());
        assert!(
            dest.read_commit_detached_metadata(&second)
                .await
                .unwrap()
                .is_some()
        );
    });
}

/// The pull refuses a remote that is not archive by the mode in its config,
/// before it requests an object.
#[test]
fn a_non_archive_remote_is_refused_on_its_config_mode() {
    block_on(async {
        let dir = TmpDir::new("pull-http-bare-remote");
        let src = dir.path().join("src");
        build_tree(&src, b"hello\n");
        let remote = Repo::create(
            &dir.path().join("remote"),
            CreateOptions::new(RepoMode::BareUser),
        )
        .await
        .unwrap();
        commit_tree(&remote, dir.path(), "src", "test/main", None, FIXED_TS).await;
        remote
            .regenerate_summary(&SummaryOptions {
                last_modified: Some(FIXED_TS),
                ..SummaryOptions::default()
            })
            .await
            .unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "{err}");
        assert!(err.to_string().contains("bare-user"), "{err}");
        // The pull requested nothing more than the three root files.
        assert_eq!(server.seen(), ["summary.sig", "summary", "config"]);
        assert_nothing_published(&dest).await;
    });
}

/// The pull finds a corrupt object on the remote when it stores the object. The
/// write path computes the name of each object that it stores, so the pull
/// fails and publishes nothing.
#[test]
fn a_corrupt_object_fails_the_pull_with_a_checksum_mismatch() {
    block_on(async {
        let dir = TmpDir::new("pull-http-corrupt");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        // Replace the stored bytes of one content object with the bytes of
        // another. The result is a well-formed object under the wrong name.
        let contents = content_checksums(&remote, &commit).await;
        let victim = filez_path(&contents[0].to_hex());
        let donor = filez_path(&contents[1].to_hex());
        let bytes = std::fs::read(dir.path().join("remote").join(&donor)).unwrap();
        server.tamper(&victim, bytes);

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::ChecksumMismatch { .. }), "{err}");
        assert_nothing_published(&dest).await;
    });
}

/// If a payload decompresses past the size that its header declares, the pull
/// refuses it at that point. This limits the bytes written before the pull
/// reaches the checksum comparison at the end of the payload. The declared size
/// is not part of the identity of the object, so no other part of the pull
/// checks it.
#[test]
fn a_payload_outgrowing_its_declared_size_fails_the_pull() {
    block_on(async {
        let dir = TmpDir::new("pull-http-declared-size");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        // The stored form is a four-byte header length, four zero bytes, and
        // the header. The first field of the header is the uncompressed size of
        // the payload. A declared size of one byte keeps all other bytes of the
        // object unchanged.
        let mut victim = None;
        for checksum in content_checksums(&remote, &commit).await {
            let path = filez_path(&checksum.to_hex());
            let stored = std::fs::read(dir.path().join("remote").join(&path)).unwrap();
            let declared = u64::from_be_bytes(stored[8..16].try_into().unwrap());
            if declared > 1 {
                victim = Some((path, stored));
                break;
            }
        }
        let (path, mut stored) = victim.expect("the fixture tree holds a payload-bearing file");
        stored[8..16].copy_from_slice(&1u64.to_be_bytes());
        server.tamper(&path, stored);

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidFormat(_)), "{err}");
        assert!(err.to_string().contains("outgrew the 1 byte"), "{err}");
        assert_nothing_published(&dest).await;
    });
}

/// A payload can decompress to nothing for any length: non-final empty DEFLATE
/// blocks of five bytes each. The pull refuses it against the bound that its
/// declared size sets for the compressed side. The decompressed bound never
/// trips for such a stream. The progress deadline measures silence, and a
/// stream that continues to deliver bytes is never silent.
#[test]
fn a_compressed_payload_passing_its_bound_fails_the_pull() {
    block_on(async {
        let dir = TmpDir::new("pull-http-compressed-bound");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        // The header stays unchanged, so the object declares its usual size.
        // The replacement payload behind it decompresses to nothing.
        let mut victim = None;
        for checksum in content_checksums(&remote, &commit).await {
            let path = filez_path(&checksum.to_hex());
            let stored = std::fs::read(dir.path().join("remote").join(&path)).unwrap();
            let declared = u64::from_be_bytes(stored[8..16].try_into().unwrap());
            if declared > 1 {
                victim = Some((path, stored, declared));
                break;
            }
        }
        let (path, stored, declared) =
            victim.expect("the fixture tree holds a payload-bearing file");
        let header_len = u32::from_be_bytes(stored[..4].try_into().unwrap()) as usize;
        let bound = declared + declared / 1024 + 64 * 1024;
        let mut tampered = stored[..8 + header_len].to_vec();
        for _ in 0..(bound / 5 + 2) {
            tampered.extend_from_slice(&[0x00, 0x00, 0x00, 0xff, 0xff]);
        }
        server.tamper(&path, tampered);

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidFormat(_)), "{err}");
        assert!(
            err.to_string()
                .contains(&format!("passed the {bound} byte")),
            "{err}"
        );
        assert_nothing_published(&dest).await;
    });
}

/// The remote serves a substituted commit object: the bytes of another commit,
/// on the same ref, under the wrong name. The pull fails when it stores the
/// commit object, before it requests the tree. The step of the commit wrote
/// the marker before it failed, and the pull removes that marker.
#[test]
fn a_substituted_commit_object_fails_before_its_tree_is_fetched() {
    block_on(async {
        let dir = TmpDir::new("pull-http-commit-substituted");
        let src = dir.path().join("src");
        build_tree(&src, b"first\n");
        let remote = Repo::create(
            &dir.path().join("remote"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let first = commit_tree(&remote, dir.path(), "src", "test/main", None, FIXED_TS).await;
        std::fs::write(src.join("hello.txt"), b"second\n").unwrap();
        let second = commit_tree(
            &remote,
            dir.path(),
            "src",
            "test/main",
            Some(first),
            FIXED_TS + 1,
        )
        .await;
        remote
            .regenerate_summary(&SummaryOptions {
                last_modified: Some(FIXED_TS),
                ..SummaryOptions::default()
            })
            .await
            .unwrap();

        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        // The tip serves the bytes of its parent. That commit parses and has
        // the same ref binding. It is a different commit from the requested
        // one.
        let donor =
            std::fs::read(dir.path().join("remote").join(meta_path(&first, "commit"))).unwrap();
        server.tamper(&meta_path(&second, "commit"), donor);

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::ChecksumMismatch { .. }), "{err}");
        assert_nothing_published(&dest).await;
        assert_no_markers(&dir.path().join("dest"));
        let seen = server.seen();
        assert!(
            !seen.iter().any(|path| path.ends_with(".filez")),
            "the tree was fetched before the commit was checked: {seen:?}"
        );
    });
}

/// If the remote does not hold an object, the pull fails and publishes nothing.
/// It removes the marker that it wrote for the unpublished commit.
#[test]
fn a_missing_object_fails_the_pull_and_clears_the_marker() {
    block_on(async {
        let dir = TmpDir::new("pull-http-missing");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let contents = content_checksums(&remote, &commit).await;
        server.hide(&filez_path(&contents[0].to_hex()));

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::ObjectNotFound { .. }), "{err}");
        assert_nothing_published(&dest).await;
        let marker = dir
            .path()
            .join("dest/state")
            .join(format!("{}.commitpartial", commit.to_hex()));
        assert!(!marker.exists(), "the marker was left behind");
    });
}

/// A failed pull keeps the marker of a commit that this repository holds. That
/// commit was partial before the pull ran, so the pull found the marker in
/// place and did not write it.
#[test]
fn a_failed_pull_keeps_the_marker_of_a_commit_it_holds() {
    block_on(async {
        let dir = TmpDir::new("pull-http-keeps-marker");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        // A commit-only pull publishes the commit object and keeps its marker.
        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                flags: PullFlags::COMMIT_ONLY,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        let marker = dir
            .path()
            .join("dest/state")
            .join(format!("{}.commitpartial", commit.to_hex()));
        assert!(marker.exists());

        // The next pull of the commit fails on an object that the remote no
        // longer serves.
        let contents = content_checksums(&remote, &commit).await;
        server.hide(&filez_path(&contents[0].to_hex()));
        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::ObjectNotFound { .. }), "{err}");
        assert!(marker.exists(), "the marker of a held commit was removed");
        assert_eq!(
            dest.commit_state(&commit).await.unwrap(),
            CommitState::Partial
        );
    });
}

/// A commit-only pull fetches only the commit object. It leaves a zero-length
/// marker and reports the commit as partial.
#[test]
fn a_commit_only_pull_leaves_the_commit_partial() {
    block_on(async {
        let dir = TmpDir::new("pull-http-commit-only");
        let (_remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let stats = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    flags: PullFlags::COMMIT_ONLY,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(stats.metadata_imported, 1);
        assert_eq!(stats.content_imported, 0);
        assert_eq!(
            dest.commit_state(&commit).await.unwrap(),
            CommitState::Partial
        );
        let marker = dir
            .path()
            .join("dest/state")
            .join(format!("{}.commitpartial", commit.to_hex()));
        assert_eq!(std::fs::metadata(&marker).unwrap().len(), 0);

        // A complete pull clears the marker.
        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            dest.commit_state(&commit).await.unwrap(),
            CommitState::Normal
        );
        assert!(!marker.exists());
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
    });
}

/// The timestamp check refuses a fetched tip that is strictly older than the
/// commit that it compares with. It accepts a tip with an equal timestamp.
#[test]
fn the_timestamp_check_refuses_only_a_strictly_older_tip() {
    block_on(async {
        let dir = TmpDir::new("pull-http-timestamp");
        let src = dir.path().join("src");
        build_tree(&src, b"older\n");
        let remote = Repo::create(
            &dir.path().join("remote"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let older = commit_tree(&remote, dir.path(), "src", "test/main", None, FIXED_TS).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        // The destination already holds a newer commit under the same ref.
        std::fs::write(src.join("hello.txt"), b"newer\n").unwrap();
        let newer = commit_tree(
            &dest,
            dir.path(),
            "src",
            "origin:test/main",
            None,
            FIXED_TS + 100,
        )
        .await;

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    timestamp_check: TimestampCheck::CurrentRef,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(message.contains(&older.to_hex()), "{message}");
        assert!(message.contains(&newer.to_hex()), "{message}");
        assert!(message.contains(&FIXED_TS.to_string()), "{message}");
        assert!(message.contains(&(FIXED_TS + 100).to_string()), "{message}");
        // The ref still points to the same commit.
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(newer)
        );

        // An equal timestamp passes, because the check is strict.
        let equal = commit_tree(&dest, dir.path(), "src", "origin:test/main", None, FIXED_TS).await;
        assert_ne!(equal, older);
        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                timestamp_check: TimestampCheck::CurrentRef,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(older)
        );
    });
}

/// `TimestampCheck::Rev` compares against a named commit. It does not use the
/// current tip of the ref.
#[test]
fn the_timestamp_check_can_name_the_commit_to_compare_against() {
    block_on(async {
        let dir = TmpDir::new("pull-http-timestamp-rev");
        let src = dir.path().join("src");
        build_tree(&src, b"older\n");
        let remote = Repo::create(
            &dir.path().join("remote"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        commit_tree(&remote, dir.path(), "src", "test/main", None, FIXED_TS).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        // A commit in the destination, under an unrelated ref, that is newer
        // than the tip of the remote.
        std::fs::write(src.join("hello.txt"), b"newer\n").unwrap();
        let reference = commit_tree(
            &dest,
            dir.path(),
            "src",
            "local/reference",
            None,
            FIXED_TS + 100,
        )
        .await;

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    timestamp_check: TimestampCheck::Rev(reference),
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains(&reference.to_hex()), "{err}");
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            None
        );
    });
}

/// `TimestampCheck::Rev` compares the tip with the timestamp of the named
/// commit. The timestamps of the current ref commit and of the tip do not take
/// its place. A named commit that is newer than the tip refuses the pull, also
/// if the current ref commit is older. A named commit that is older than the
/// tip lets the pull pass, also if the current ref commit is newer.
#[test]
fn the_timestamp_check_reads_the_timestamp_of_the_named_commit() {
    block_on(async {
        let dir = TmpDir::new("pull-http-timestamp-rev-base");
        let src = dir.path().join("src");
        build_tree(&src, b"tip\n");
        let remote = Repo::create(
            &dir.path().join("remote"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let tip = commit_tree(&remote, dir.path(), "src", "test/main", None, FIXED_TS).await;
        let server = RepoServer::start(remote.path(), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        let pull = |rev| {
            dest.pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    timestamp_check: TimestampCheck::Rev(rev),
                    ..PullOptions::default()
                },
            )
        };

        // The current ref commit is older than the tip, and the named commit
        // is newer.
        std::fs::write(src.join("hello.txt"), b"older\n").unwrap();
        let older = commit_tree(
            &dest,
            dir.path(),
            "src",
            "origin:test/main",
            None,
            FIXED_TS - 100,
        )
        .await;
        std::fs::write(src.join("hello.txt"), b"newer\n").unwrap();
        let newer = commit_tree(
            &dest,
            dir.path(),
            "src",
            "local/newer",
            None,
            FIXED_TS + 100,
        )
        .await;
        let err = pull(newer).await.unwrap_err();
        let message = err.to_string();
        assert!(message.contains(&newer.to_hex()), "{message}");
        assert!(message.contains(&(FIXED_TS + 100).to_string()), "{message}");
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(older)
        );

        // The current ref commit is newer than the tip, and the named commit
        // is older.
        let current = commit_tree(
            &dest,
            dir.path(),
            "src",
            "origin:test/main",
            None,
            FIXED_TS + 200,
        )
        .await;
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(current)
        );
        pull(older).await.unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(tip)
        );
    });
}

/// If two requested refs point to one commit, the pull checks each ref against
/// the ref binding of the commit. The pull fetches the commit once, so the
/// second ref has no step of its own. Only `PullFlags::DISABLE_VERIFY_BINDINGS`
/// lets the pull pass.
#[test]
fn a_second_ref_at_one_commit_is_checked_against_the_binding() {
    block_on(async {
        let dir = TmpDir::new("pull-http-two-refs-binding");
        let (_remote, commit) = build_remote_two_refs(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned(), "test/other".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("test/other"), "{message}");
        assert!(message.contains(&commit.to_hex()), "{message}");
        assert_nothing_published(&dest).await;

        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned(), "test/other".to_owned()],
                flags: PullFlags::DISABLE_VERIFY_BINDINGS,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/other", true).await.unwrap(),
            Some(commit)
        );
    });
}

/// The timestamp check runs for each of two requested refs that point to one
/// commit. If the current tip of the second ref here is newer, the check
/// refuses the pull.
#[test]
fn a_second_ref_at_one_commit_is_checked_against_its_timestamp() {
    block_on(async {
        let dir = TmpDir::new("pull-http-two-refs-timestamp");
        let (_remote, older) = build_remote_two_refs(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        // Only the second ref points to a newer commit here, so only its check
        // refuses the fetched tip.
        std::fs::write(dir.path().join("src/hello.txt"), b"newer\n").unwrap();
        let newer = commit_tree(
            &dest,
            dir.path(),
            "src",
            "origin:test/other",
            None,
            FIXED_TS + 100,
        )
        .await;

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned(), "test/other".to_owned()],
                    flags: PullFlags::DISABLE_VERIFY_BINDINGS,
                    timestamp_check: TimestampCheck::CurrentRef,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(message.contains(&older.to_hex()), "{message}");
        assert!(message.contains(&newer.to_hex()), "{message}");
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            None
        );
        assert_eq!(
            dest.resolve_rev("origin:test/other", true).await.unwrap(),
            Some(newer)
        );
    });
}

/// A localcache repository supplies an object for which the remote answers 404.
/// Without the cache, the same pull fails.
#[test]
fn a_localcache_repository_supplies_an_object_the_remote_lost() {
    block_on(async {
        let dir = TmpDir::new("pull-http-localcache");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;

        // A cache that holds the whole commit. A pull fills it before the
        // remote loses the object.
        let cache = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        cache
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();
        std::fs::rename(dir.path().join("dest"), dir.path().join("cache")).unwrap();
        let cache = Repo::open(&dir.path().join("cache")).await.unwrap();

        let contents = content_checksums(&remote, &commit).await;
        server.hide(&filez_path(&contents[0].to_hex()));

        // Without the cache, the object is gone and the pull fails.
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::ObjectNotFound { .. }), "{err}");

        // With the cache, the pull completes and never requests the object.
        std::fs::remove_dir_all(dir.path().join("dest")).unwrap();
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        server.forget();
        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                localcache_repos: vec![cache],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
        assert!(!server.seen().contains(&filez_path(&contents[0].to_hex())));
    });
}

/// With one slot, the request order is the drain order of the plan: the commit,
/// then the scan, then the content.
#[test]
fn a_single_slot_pins_the_request_order() {
    block_on(async {
        let dir = TmpDir::new("pull-http-serial");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                max_outstanding_fetches: Some(1),
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(server.peak_inflight(), 1);
        let seen = server.seen();
        let objects: Vec<&String> = seen
            .iter()
            .filter(|path| path.starts_with("objects/"))
            .collect();
        // First the detached metadata of the commit and the commit. Then the
        // metadata that the scan waits for, and last the content.
        assert_eq!(*objects[0], meta_path(&commit, "commitmeta"));
        assert_eq!(*objects[1], meta_path(&commit, "commit"));
        let first_content = objects
            .iter()
            .position(|path| path.ends_with(".filez"))
            .expect("content was fetched");
        let last_meta = objects
            .iter()
            .rposition(|path| path.ends_with(".dirtree") || path.ends_with(".dirmeta"))
            .expect("metadata was fetched");
        assert!(
            last_meta < first_content,
            "content was fetched before the scan finished: {objects:?}"
        );
        let _ = remote;
    });
}

/// A pull reuses one connection for each slot. Each step reads its response to
/// the end, which returns the connection to the pool for the next step. With
/// one slot, all requests share one connection. If a step left its response
/// unfinished, the next step needs a new connection setup, and this test sees
/// it.
#[test]
fn one_slot_pulls_every_object_over_one_connection() {
    block_on(async {
        let dir = TmpDir::new("pull-http-one-connection");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                max_outstanding_fetches: Some(1),
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        // The fixture tree has regular files and a symlink, so the test covers
        // both content paths.
        let contents = content_checksums(&remote, &commit).await;
        assert!(contents.len() > 1);
        assert_eq!(server.connections(), 1, "requests: {:?}", server.seen());
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
    });
}

/// The pull refuses a content object that declares a header larger than the
/// header cap, so the receive path allocates no buffer for it.
#[test]
fn an_oversized_content_header_fails_the_pull() {
    block_on(async {
        let dir = TmpDir::new("pull-http-big-header");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        // One byte past the 1 MiB header cap. The rest of the object stays
        // unchanged. The pull refuses the length before it reads the bytes.
        let checksum = content_checksums(&remote, &commit)
            .await
            .pop()
            .expect("the fixture tree holds a content object");
        let path = filez_path(&checksum.to_hex());
        let mut bytes = std::fs::read(dir.path().join("remote").join(&path)).unwrap();
        bytes[..4].copy_from_slice(&(1024u32 * 1024 + 1).to_be_bytes());
        server.tamper(&path, bytes);

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidFormat(_)), "{err}");
        assert!(err.to_string().contains("size cap"), "{err}");
        assert_nothing_published(&dest).await;
    });
}

/// The pull refuses a content object that has extra bytes after its payload,
/// because a correct object ends at the end of the response stream.
#[test]
fn trailing_bytes_after_a_payload_fail_the_pull() {
    block_on(async {
        let dir = TmpDir::new("pull-http-trailing");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        // A regular file, so the extra bytes come after a deflated payload.
        // They do not come after the header of a symlink.
        let (tree, _) = remote.read_commit(&commit.to_hex()).await.unwrap();
        let mut content = None;
        for entry in tree.read_dir().await.unwrap() {
            if let TreeEntry::File { name, checksum } = entry
                && name == "hello.txt"
            {
                content = Some(checksum);
            }
        }
        let path = filez_path(&content.expect("hello.txt").to_hex());
        let mut bytes = std::fs::read(dir.path().join("remote").join(&path)).unwrap();
        bytes.extend_from_slice(b"trailing");
        server.tamper(&path, bytes);

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("bytes follow"), "{err}");
        assert_nothing_published(&dest).await;
    });
}

/// The default limit fetches concurrently. The request set is the same, and the
/// server sees more than one request in flight at one time.
#[test]
fn the_default_limit_fetches_concurrently() {
    block_on(async {
        let dir = TmpDir::new("pull-http-concurrent");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert!(
            server.peak_inflight() > 1,
            "the pull never had two fetches in flight"
        );
        let seen = server.seen_set();
        for content in content_checksums(&remote, &commit).await {
            assert!(seen.contains(&filez_path(&content.to_hex())));
        }
        assert!(seen.contains(&meta_path(&commit, "commit")));
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
    });
}

/// If the connection is cut in the middle of an object, the pull fails and
/// stores no truncated object. It publishes nothing.
#[test]
fn a_connection_cut_mid_pull_fails_and_publishes_nothing() {
    block_on(async {
        let dir = TmpDir::new("pull-http-cut");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let contents = content_checksums(&remote, &commit).await;
        server.truncate(&filez_path(&contents[0].to_hex()));

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    // With one slot, the failure stays on the object that the
                    // test cut.
                    max_outstanding_fetches: Some(1),
                    overrides: retries(0),
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        // The pull fails on the object with the cut delivery. It publishes
        // nothing that it received under a name that the bytes do not hash to.
        assert!(err.to_string().contains(".filez"), "{err}");
        assert_nothing_published(&dest).await;
        assert!(
            !dest
                .has_object(ostrya::ObjectType::File, &contents[0])
                .await
                .unwrap()
        );
    });
}

/// If a body is cut in transit, the pull fetches it again from the start, and
/// this uses one repeat of the retry count. The pull completes with all objects
/// intact and leaves no staging file.
#[test]
fn a_body_cut_once_is_fetched_again_and_the_pull_completes() {
    block_on(async {
        for mode in [RepoMode::Archive, RepoMode::BareUser] {
            let dir = TmpDir::new("pull-http-cut-once");
            let (remote, commit) = build_remote(dir.path()).await;
            let server = RepoServer::start(&dir.path().join("remote"), false).await;
            let dest = build_dest(dir.path(), mode, &server.url(), "").await;

            let contents = content_checksums(&remote, &commit).await;
            let cut = filez_path(&contents[0].to_hex());
            server.truncate_times(&cut, 1);
            // The pull reads a metadata object whole, and fetches it again in
            // the same way.
            let root = meta_path(&commit, "commit");
            server.truncate_times(&root, 1);

            dest.pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();
            assert_eq!(server.requests_for(&cut), 2, "{mode:?}");
            assert_eq!(server.requests_for(&root), 2, "{mode:?}");
            assert_eq!(
                dest.resolve_rev("origin:test/main", true).await.unwrap(),
                Some(commit)
            );
            assert!(
                dest.has_object(ostrya::ObjectType::File, &contents[0])
                    .await
                    .unwrap()
            );
            assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
            let staging = std::fs::read_dir(dir.path().join("dest/tmp"))
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|name| name.starts_with("staging-"))
                .collect::<Vec<_>>();
            assert!(staging.is_empty(), "{staging:?}");
        }
    });
}

/// If each request cuts the body, the pull uses the whole retry count, one
/// request more than the count. Then the pull fails.
#[test]
fn a_body_cut_every_time_spends_the_retry_count() {
    block_on(async {
        let dir = TmpDir::new("pull-http-cut-always");
        let (remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let contents = content_checksums(&remote, &commit).await;
        let cut = filez_path(&contents[0].to_hex());
        server.truncate(&cut);

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    max_outstanding_fetches: Some(1),
                    overrides: retries(2),
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains(".filez"), "{err}");
        assert_eq!(server.requests_for(&cut), 3);
        assert_nothing_published(&dest).await;
    });
}

/// If a remote sets `tls-permissive`, the pull accepts a server whose chain no
/// authority of the destination signed. A unit test of `resolve_pull` checks
/// that the key also leaves `tls-ca-path` unread. That test needs no server.
#[test]
fn a_tls_permissive_remote_accepts_an_untrusted_chain() {
    block_on(async {
        let dir = TmpDir::new("pull-http-permissive");
        let (_remote, commit) = build_remote(dir.path()).await;
        let server =
            RepoServer::start_with_leaf(&dir.path().join("remote"), true, Leaf::Untrusted).await;
        let dest = build_dest(
            dir.path(),
            RepoMode::Archive,
            &server.url(),
            "tls-permissive=true\n",
        )
        .await;

        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(commit)
        );
    });
}

/// `tls-permissive` keeps the host name check, so the pull refuses a leaf that
/// covers neither name of the harness. The pull writes no ref.
#[test]
fn a_tls_permissive_remote_keeps_the_name_check() {
    block_on(async {
        let dir = TmpDir::new("pull-http-permissive-name");
        build_remote(dir.path()).await;
        let server =
            RepoServer::start_with_leaf(&dir.path().join("remote"), true, Leaf::OtherName).await;
        let dest = build_dest(
            dir.path(),
            RepoMode::Archive,
            &server.url(),
            "tls-permissive=true\n",
        )
        .await;

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    // A failed handshake is retryable, so the test turns off
                    // the retry rounds. Then the pull reports the refusal at
                    // once.
                    overrides: retries(0),
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains(r#"certificate not valid for name "localhost""#),
            "{err}"
        );
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            None
        );
    });
}

/// `remote_fetch_summary` returns the summary of the remote and its signature.
/// It returns an absent signature as `None`.
#[test]
fn remote_fetch_summary_reports_both_files() {
    block_on(async {
        let dir = TmpDir::new("pull-http-fetch-summary");
        build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let (summary, signature) = dest.remote_fetch_summary("origin").await.unwrap();
        assert_eq!(
            summary.as_deref(),
            Some(
                std::fs::read(dir.path().join("remote/summary"))
                    .unwrap()
                    .as_slice()
            )
        );
        assert_eq!(signature, None);

        // If the remote publishes a signature, the call returns it with the
        // summary.
        std::fs::write(dir.path().join("remote/summary.sig"), b"signature bytes").unwrap();
        let (_, signature) = dest.remote_fetch_summary("origin").await.unwrap();
        assert_eq!(signature.as_deref(), Some(b"signature bytes".as_slice()));
    });
}

/// `PullSession::fetch_summary` over HTTP asks for `summary.sig` and then for
/// `summary`, and returns the summary first. A file that the remote does not
/// serve is `None`. One session serves each call.
#[test]
fn a_pull_session_fetches_the_summary_over_http() {
    block_on(async {
        let dir = TmpDir::new("pull-http-session-fetch-summary");
        build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), true).await;
        let session = PullSession::connect(
            Endpoint::Http(https_endpoint(&server)),
            StreamSessionOptions::default(),
        )
        .await
        .unwrap();
        let summary = std::fs::read(dir.path().join("remote/summary")).unwrap();

        let (got, signature) = session.fetch_summary().await.unwrap();
        assert_eq!(got.as_deref(), Some(summary.as_slice()));
        assert_eq!(signature, None);
        assert_eq!(server.seen(), ["summary.sig", "summary"]);

        std::fs::write(dir.path().join("remote/summary.sig"), SUMMARY_SIG).unwrap();
        let (got, signature) = session.fetch_summary().await.unwrap();
        assert_eq!(got.as_deref(), Some(summary.as_slice()));
        assert_eq!(signature.as_deref(), Some(SUMMARY_SIG));

        std::fs::remove_file(dir.path().join("remote/summary")).unwrap();
        let (got, signature) = session.fetch_summary().await.unwrap();
        assert_eq!(got, None);
        assert_eq!(signature.as_deref(), Some(SUMMARY_SIG));
        assert_eq!(
            server.seen(),
            [
                "summary.sig",
                "summary",
                "summary.sig",
                "summary",
                "summary.sig",
                "summary"
            ]
        );
        session.finish().await.unwrap();
    });
}

/// `PullSession::fetch_refs` against a static server of the repository files
/// gives `None`: the server answers 404 to the listing. The session still
/// reads the summary.
#[test]
fn a_pull_session_fetches_no_ref_listing_from_a_static_server() {
    block_on(async {
        let dir = TmpDir::new("pull-http-session-fetch-refs-static");
        build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), true).await;
        let session = PullSession::connect(
            Endpoint::Http(https_endpoint(&server)),
            StreamSessionOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            session
                .fetch_refs(&RefSelector::parse(["main"]).unwrap(), None)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            session
                .fetch_refs(&RefSelector::parse([]).unwrap(), None)
                .await
                .unwrap(),
            None
        );
        assert_eq!(server.seen(), ["_ostrya/refs/v1", "_ostrya/refs/v1"]);

        let summary = std::fs::read(dir.path().join("remote/summary")).unwrap();
        let (got, _) = session.fetch_summary().await.unwrap();
        assert_eq!(got.as_deref(), Some(summary.as_slice()));
        session.finish().await.unwrap();
    });
}

/// `PullSession::fetch_refs` over HTTP refuses a listing whose stated length
/// is over the cap of 128 MiB, from the head of the answer. The request
/// target holds each entry that stays, percent-encoded, the positive entries
/// first, and the call does not ask again.
#[test]
fn a_pull_session_refuses_a_ref_listing_over_the_cap_over_http() {
    block_on(async {
        let target = "_ostrya/refs/v1?pattern=a%2Fb&pattern=x-y&pattern=a%2Fb%2Fc&pattern=%C3%A9%2F%C3%BC\
                      &pattern=%21a%2F%2A";
        let (addr, seen) = oversized_file_server(target, ostrya::MAX_REF_LISTING + 1).await;
        let mut http = FetcherOptions::new(format!("http://{addr}"));
        http.proxy = Proxy::None;
        let session = PullSession::connect(Endpoint::Http(http), StreamSessionOptions::default())
            .await
            .unwrap();
        let selector = RefSelector::parse(["a/b", "!a/*", "x-y", "a/b/c", "é/ü", "x-y"]).unwrap();
        let err = session.fetch_refs(&selector, None).await.unwrap_err();
        assert!(
            matches!(
                err,
                ostrya::remote::Error::Fetch(ostrya::fetch::Error::FetchTooLarge {
                    limit: 134_217_728
                })
            ),
            "{err}"
        );
        assert_eq!(*seen.lock().unwrap(), [target]);
        session.finish().await.unwrap();
    });
}

/// Starts a peer that answers a request for `oversized` with a head that
/// states a length of `len` bytes, and sends no body. The peer answers each
/// other request with a 404. Each answer closes its connection.
///
/// The list gives the request targets that the peer read, in order, without
/// the leading slash. A target holds its query.
async fn oversized_file_server(
    oversized: &'static str,
    len: u64,
) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    drop(spawn(async move {
        while let Ok((mut stream, _peer)) = listener.accept().await {
            let mut head = Vec::new();
            let mut chunk = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&chunk[..n]),
                }
            }
            let line = String::from_utf8_lossy(&head);
            let Some(path) = line.split(' ').nth(1) else {
                continue;
            };
            let path = path.trim_start_matches('/').to_owned();
            let answer = if path == oversized {
                format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n")
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_owned()
            };
            log.lock().unwrap().push(path);
            let _ = stream.write_all(answer.as_bytes()).await;
            let _ = stream.flush().await;
            let _ = stream.close().await;
        }
    }));
    (addr, seen)
}

/// `PullSession::fetch_summary` over HTTP refuses a `summary.sig` or a
/// `summary` whose stated length is over the cap of 64 MiB. The refusal comes
/// from the head of the answer, before the body, and the call does not ask
/// again.
#[test]
fn a_pull_session_refuses_a_summary_file_over_the_cap_over_http() {
    for (oversized, asked) in [
        ("summary.sig", &["summary.sig"][..]),
        ("summary", &["summary.sig", "summary"][..]),
    ] {
        block_on(async {
            let (addr, seen) = oversized_file_server(oversized, 64 * 1024 * 1024 + 1).await;
            let mut http = FetcherOptions::new(format!("http://{addr}"));
            http.proxy = Proxy::None;
            let session =
                PullSession::connect(Endpoint::Http(http), StreamSessionOptions::default())
                    .await
                    .unwrap();

            let err = session.fetch_summary().await.unwrap_err();
            assert!(
                matches!(
                    err,
                    ostrya::remote::Error::Fetch(ostrya::fetch::Error::FetchTooLarge {
                        limit: 67_108_864
                    })
                ),
                "{oversized}: {err}"
            );
            assert_eq!(*seen.lock().unwrap(), asked, "{oversized}");
            session.finish().await.unwrap();
        });
    }
}

/// `remote_fetch_summary` reads from an HTTP `pull-url` when no `url` is set.
/// It also uses `pull-url` when the `url` answers no request.
#[test]
fn remote_fetch_summary_reads_an_http_pull_url() {
    block_on(async {
        let dir = TmpDir::new("pull-http-fetch-summary-pull-url");
        build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let expected = std::fs::read(dir.path().join("remote/summary")).unwrap();
        for (tag, url) in [("no-url", ""), ("dead-url", "url=http://127.0.0.1:1/\n")] {
            let path = dir.path().join(tag);
            drop(
                Repo::create(&path, CreateOptions::new(RepoMode::Archive))
                    .await
                    .unwrap(),
            );
            let config = path.join("config");
            let mut text = std::fs::read_to_string(&config).unwrap();
            text.push_str(&format!(
                "\n[remote \"origin\"]\n{url}pull-url={}\ngpg-verify=false\n",
                server.url()
            ));
            std::fs::write(&config, text).unwrap();
            let dest = Repo::open(&path).await.unwrap();
            let (summary, signature) = dest.remote_fetch_summary("origin").await.unwrap();
            assert_eq!(summary.as_deref(), Some(expected.as_slice()), "{tag}");
            assert_eq!(signature, None, "{tag}");
        }
    });
}

/// A pull needs a URL. If the config does not describe the remote, the pull
/// fails unless the caller supplies a URL.
#[test]
fn an_unconfigured_remote_needs_a_url() {
    block_on(async {
        let dir = TmpDir::new("pull-http-no-remote");
        let (_remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        // A remote that the config does not describe takes the default
        // configuration values. Because `gpg-verify` is one of these defaults,
        // both pulls of this unsigned commit state their own policy.
        let err = dest
            .pull(
                "elsewhere",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    verify: PullVerify {
                        gpg: Some(false),
                        ..PullVerify::default()
                    },
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no remote 'elsewhere'"), "{err}");

        // With a URL, the same pull runs, and the refs go under the requested
        // remote name.
        dest.pull(
            "elsewhere",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                overrides: EndpointOverrides {
                    url: Some(server.url()),
                    ..EndpointOverrides::default()
                },
                verify: PullVerify {
                    gpg: Some(false),
                    ..PullVerify::default()
                },
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            dest.resolve_rev("elsewhere:test/main", true).await.unwrap(),
            Some(commit)
        );
    });
}

/// If a remote has an HTTP `pull-url` and no `url`, the pull uses `pull-url`.
/// `pull-url` also has priority over a `url` that answers no request. An HTTP
/// pull reads neither `ssh-command` nor `send-command`. If either key holds a
/// value that does not parse, no pull fails.
#[test]
fn an_http_pull_url_wins_over_url() {
    block_on(async {
        let dir = TmpDir::new("pull-http-pull-url");
        let (_remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        for (tag, url) in [("no-url", ""), ("dead-url", "url=http://127.0.0.1:1/\n")] {
            let path = dir.path().join(tag);
            drop(
                Repo::create(&path, CreateOptions::new(RepoMode::Archive))
                    .await
                    .unwrap(),
            );
            let config = path.join("config");
            let mut text = std::fs::read_to_string(&config).unwrap();
            text.push_str(&format!(
                "\n[remote \"origin\"]\n{url}pull-url={}\ngpg-verify=false\n\
                 ssh-command=a\\zb\nsend-command=a\\zb\n",
                server.url()
            ));
            std::fs::write(&config, text).unwrap();
            let dest = Repo::open(&path).await.unwrap();
            dest.pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();
            assert_eq!(
                dest.resolve_rev("origin:test/main", true).await.unwrap(),
                Some(commit),
                "{tag}"
            );
        }
    });
}

/// A symlink object and an object with xattrs both cross the pull. The identity
/// of a symlink object is its header alone. The xattrs are part of the header
/// that the destination stores.
#[test]
fn symlink_and_xattr_bearing_objects_cross() {
    block_on(async {
        let dir = TmpDir::new("pull-http-xattrs");
        let src = dir.path().join("src");
        build_tree(&src, b"hello\n");
        // The commit records a user xattr, so the header of the object holds
        // it.
        if rustix::fs::setxattr(
            src.join("hello.txt"),
            "user.marked",
            b"yes",
            rustix::fs::XattrFlags::empty(),
        )
        .is_err()
        {
            eprintln!("skipping: the filesystem does not support user xattrs");
            return;
        }
        let remote = Repo::create(
            &dir.path().join("remote"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let commit = commit_tree_with(
            &remote,
            dir.path(),
            "src",
            "test/main",
            None,
            FIXED_TS,
            // No SKIP_XATTRS and no CANONICAL_PERMISSIONS, because each one
            // drops the xattr set. A bare-user destination stores the header
            // that an object arrives with.
            CommitModifierFlags::empty(),
        )
        .await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;

        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());

        let (tree, _) = dest.read_commit(&commit.to_hex()).await.unwrap();
        let mut marked = None;
        let mut link = None;
        for entry in tree.read_dir().await.unwrap() {
            if let TreeEntry::File { name, checksum } = entry {
                match name.as_str() {
                    "hello.txt" => marked = Some(checksum),
                    "link" => link = Some(checksum),
                    _ => {}
                }
            }
        }
        let marked = dest.load_file(&marked.expect("hello.txt")).await.unwrap();
        let xattrs: Vec<(String, String)> = marked
            .xattrs
            .iter()
            .map(|(name, value)| {
                (
                    String::from_utf8_lossy(name)
                        .trim_end_matches('\0')
                        .to_owned(),
                    String::from_utf8_lossy(value).into_owned(),
                )
            })
            .collect();
        assert_eq!(xattrs, [("user.marked".to_owned(), "yes".to_owned())]);
        let link = dest.load_file(&link.expect("link")).await.unwrap();
        assert!(link.is_symlink());
    });
}

/// A bare-user-only destination stores no ownership and no xattrs. If the
/// header of an object is not in the canonical form, the destination cannot
/// hold the object under its own name. The pull is refused.
#[test]
fn a_bare_user_only_destination_refuses_a_non_canonical_object() {
    block_on(async {
        let dir = TmpDir::new("pull-http-non-canonical");
        let src = dir.path().join("src");
        build_tree(&src, b"hello\n");
        let remote = Repo::create(
            &dir.path().join("remote"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        // The commit records the ownership of the process. A bare-user-only
        // destination does not store that header.
        commit_tree_with(
            &remote,
            dir.path(),
            "src",
            "test/main",
            None,
            FIXED_TS,
            CommitModifierFlags::SKIP_XATTRS,
        )
        .await;
        if rustix::process::geteuid().is_root() {
            eprintln!("skipping: running as root commits the canonical ownership");
            return;
        }
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::BareUserOnly, &server.url(), "").await;

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Pull(_)), "{err}");
        assert!(err.to_string().contains("bare-user-only"), "{err}");
        assert_nothing_published(&dest).await;
    });
}

/// `BAREUSERONLY_FILES` rejects a regular-file mode with bits outside `0775`.
/// The check reads the mode in the header that the object arrives with.
#[test]
fn bareuseronly_files_rejects_a_mode_outside_0775() {
    block_on(async {
        use std::os::unix::fs::PermissionsExt;

        let dir = TmpDir::new("pull-http-mode-bits");
        let src = dir.path().join("src");
        build_tree(&src, b"hello\n");
        std::fs::set_permissions(src.join("exec.sh"), std::fs::Permissions::from_mode(0o4755))
            .unwrap();
        let remote = Repo::create(
            &dir.path().join("remote"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        commit_tree_with(
            &remote,
            dir.path(),
            "src",
            "test/main",
            None,
            FIXED_TS,
            CommitModifierFlags::SKIP_XATTRS,
        )
        .await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    flags: PullFlags::BAREUSERONLY_FILES,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid mode"), "{err}");
        assert_nothing_published(&dest).await;

        // Without the flag, an archive destination stores the object.
        std::fs::remove_dir_all(dir.path().join("dest")).unwrap();
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
    });
}

/// Returns the request path of one part of the single delta in a served
/// repository.
/// The function walks `deltas/<fanout>/<leaf>/` to find the path. It does not
/// build the name again.
fn served_part_path(root: &Path, index: usize) -> String {
    let deltas = root.join("deltas");
    let fanout = std::fs::read_dir(&deltas)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let leaf = std::fs::read_dir(&fanout).unwrap().next().unwrap().unwrap();
    let dir = leaf.path().strip_prefix(root).unwrap().to_owned();
    format!("{}/{index}", dir.display())
}

/// A remote answers a part request with more bytes than the part holds. The
/// fetcher reads no more than the size that the superblock declares for that
/// part. It refuses the oversized body, and the pull publishes nothing.
#[test]
fn a_part_larger_than_the_superblock_declares_is_refused() {
    block_on(async {
        let dir = TmpDir::new("pull-http-delta-part-size");
        let src = dir.path().join("src");
        build_tree(&src, b"hello\n");
        let remote_path = dir.path().join("remote");
        let remote = Repo::create(&remote_path, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let tip = commit_tree_with(
            &remote,
            dir.path(),
            "src",
            "test/main",
            None,
            FIXED_TS,
            CommitModifierFlags::SKIP_XATTRS,
        )
        .await;
        remote
            .generate_static_delta(
                None,
                &tip,
                &DeltaOptions {
                    timestamp: Some(FIXED_TS),
                    ..DeltaOptions::default()
                },
            )
            .await
            .unwrap();

        // The server answers the part request with a body of four times the
        // size that the superblock declares for the part.
        let part = served_part_path(&remote_path, 0);
        let declared = std::fs::metadata(remote_path.join(&part)).unwrap().len();
        let server = RepoServer::start(&remote_path, false).await;
        server.tamper(&part, vec![0u8; declared as usize * 4]);

        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;
        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::FetchTooLarge { limit } if limit == declared),
            "{err}"
        );
        assert_nothing_published(&dest).await;
        assert!(
            server.seen().contains(&part),
            "the part was requested: {:?}",
            server.seen()
        );
    });
}

/// `BAREUSERONLY_FILES` applies to an object that a static delta delivers. The
/// pull checks the mode in the table of a part before it writes the object. If
/// the pull refuses a loose fetch of an object, a delta cannot deliver it.
#[test]
fn bareuseronly_files_rejects_a_delta_delivered_mode_outside_0775() {
    block_on(async {
        use std::os::unix::fs::PermissionsExt;

        let dir = TmpDir::new("pull-http-delta-mode-bits");
        let src = dir.path().join("src");
        build_tree(&src, b"hello\n");
        std::fs::set_permissions(src.join("exec.sh"), std::fs::Permissions::from_mode(0o4755))
            .unwrap();
        let remote = Repo::create(
            &dir.path().join("remote"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let tip = commit_tree_with(
            &remote,
            dir.path(),
            "src",
            "test/main",
            None,
            FIXED_TS,
            CommitModifierFlags::SKIP_XATTRS,
        )
        .await;
        // The remote publishes a from-scratch delta of the commit, for a fresh
        // destination. The remote serves no summary, so the pull requests the
        // delta by name.
        remote
            .generate_static_delta(
                None,
                &tip,
                &DeltaOptions {
                    timestamp: Some(FIXED_TS),
                    ..DeltaOptions::default()
                },
            )
            .await
            .unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;

        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;
        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    flags: PullFlags::BAREUSERONLY_FILES,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid mode"), "{err}");
        assert_nothing_published(&dest).await;
        assert!(
            server
                .seen()
                .iter()
                .any(|path| path.ends_with("/superblock")),
            "the pull took the delta: {:?}",
            server.seen()
        );

        // Without the flag, the same delta delivers the object. This shows
        // that the delta path works and that the flag causes the refusal.
        std::fs::remove_dir_all(dir.path().join("dest")).unwrap();
        server.forget();
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;
        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert!(
            server
                .seen()
                .iter()
                .any(|path| path.ends_with("/superblock")),
            "the second pull took the delta as well: {:?}",
            server.seen()
        );
        assert_eq!(
            dest.commit_state(&tip).await.unwrap(),
            CommitState::Normal,
            "the delta delivered the whole commit"
        );
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
    });
}

/// A delta pull into each destination mode. Each mode gets the whole target
/// commit and passes its own fsck.
///
/// The destination is one commit behind, so the delta patches objects that the
/// destination already stores. The applier reads a source object in the storage
/// form of the destination. For an archive destination, this form is a deflated
/// `.filez`. The applier writes the output of the part in the same form.
#[test]
fn a_delta_delivers_a_commit_into_every_destination_mode() {
    block_on(async {
        for mode in [
            RepoMode::Archive,
            RepoMode::BareUser,
            RepoMode::BareUserOnly,
        ] {
            let dir = TmpDir::new(&format!("pull-http-delta-dest-{}", mode.as_mode_str()));
            let src = dir.path().join("src");
            build_tree(&src, b"hello\n");
            // A file of several chunks. After the edit of 4 bytes, the applier
            // copies most of the file from the object that the destination
            // holds.
            let mut bulk = incompressible(256 * 1024);
            std::fs::write(src.join("bulk.bin"), &bulk).unwrap();

            let remote_path = dir.path().join("remote");
            let remote = Repo::create(&remote_path, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap();
            let first = commit_tree(&remote, dir.path(), "src", "test/main", None, FIXED_TS).await;

            // The destination gets the first commit as loose objects. The
            // remote holds no delta yet, so the superblock request gets a 404.
            let server = RepoServer::start(&remote_path, false).await;
            let dest = build_dest(dir.path(), mode, &server.url(), "").await;
            dest.pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();
            assert_eq!(
                dest.resolve_rev("origin:test/main", true).await.unwrap(),
                Some(first),
                "{mode:?}"
            );

            // The remote adds one commit, with one file edited and one file
            // added. It publishes the delta from the commit that the
            // destination holds to the new commit.
            bulk[128 * 1024..128 * 1024 + 4].copy_from_slice(b"edit");
            std::fs::write(src.join("bulk.bin"), &bulk).unwrap();
            std::fs::write(src.join("added.txt"), b"added\n").unwrap();
            let second = commit_tree(
                &remote,
                dir.path(),
                "src",
                "test/main",
                Some(first),
                FIXED_TS + 1,
            )
            .await;
            remote
                .generate_static_delta(
                    Some(&first),
                    &second,
                    &DeltaOptions {
                        timestamp: Some(FIXED_TS),
                        ..DeltaOptions::default()
                    },
                )
                .await
                .unwrap();

            server.forget();
            let stats = dest
                .pull(
                    "origin",
                    PullOptions {
                        refs: vec!["test/main".to_owned()],
                        ..PullOptions::default()
                    },
                )
                .await
                .unwrap();

            // The delta carries the content. The pull requests the superblock
            // and requests no content object.
            let seen = server.seen();
            assert!(
                seen.iter().any(|path| path.ends_with("/superblock")),
                "{mode:?}: the pull took the delta: {seen:?}"
            );
            assert!(
                !seen.iter().any(|path| path.ends_with(".filez")),
                "{mode:?}: a content object was fetched loose: {seen:?}"
            );
            // Each requested part file counts once. The content that the delta
            // writes counts as zero content written, as the `ostree` command
            // counts it.
            let part_files = seen
                .iter()
                .filter(|path| {
                    path.starts_with("deltas/")
                        && path
                            .rsplit('/')
                            .next()
                            .unwrap()
                            .bytes()
                            .all(|b| b.is_ascii_digit())
                })
                .count();
            assert_eq!(stats.delta_parts as usize, part_files, "{mode:?}");
            assert_eq!(stats.content_fetched, 0, "{mode:?}");
            assert_eq!(stats.content_bytes_unpacked, 0, "{mode:?}");

            assert_eq!(
                dest.resolve_rev("origin:test/main", true).await.unwrap(),
                Some(second),
                "{mode:?}"
            );
            assert_eq!(
                dest.commit_state(&second).await.unwrap(),
                CommitState::Normal,
                "{mode:?}"
            );
            let report = dest.fsck(&FsckOptions::default()).await.unwrap();
            assert!(report.is_ok(), "{mode:?}: {:?}", report.errors);

            // The tree holds the edited file and the added file.
            let (tree, _) = dest.read_commit(&second.to_hex()).await.unwrap();
            let mut names: Vec<String> = tree
                .read_dir()
                .await
                .unwrap()
                .into_iter()
                .map(|entry| match entry {
                    TreeEntry::File { name, .. } | TreeEntry::Dir { name, .. } => name,
                })
                .collect();
            names.sort();
            assert_eq!(
                names,
                [
                    "added.txt",
                    "bulk.bin",
                    "exec.sh",
                    "hello.txt",
                    "link",
                    "subdir"
                ],
                "{mode:?}"
            );
        }
    });
}

/// A remote with no summary advertises no delta, so the pull requests the
/// superblock by name.
///
/// First the ref resolves through `refs/heads/<ref>`. Then the pull requests,
/// by its path, the delta from the commit that the destination holds under the
/// ref. If the destination holds no commit under the ref, the pull requests the
/// from-scratch delta.
///
/// If the superblock request gets a 404, the pull fetches the commit as loose
/// objects. If the superblock is present, the commit arrives through its parts,
/// with no loose object.
#[test]
fn a_pull_with_no_summary_takes_a_delta_by_name() {
    block_on(async {
        let dir = TmpDir::new("pull-http-delta-no-summary");
        let src = dir.path().join("src");
        build_tree(&src, b"hello\n");
        let remote_path = dir.path().join("remote");
        let remote = Repo::create(&remote_path, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let first = commit_tree(&remote, dir.path(), "src", "test/main", None, FIXED_TS).await;
        assert!(!remote_path.join("summary").exists());
        assert!(!remote_path.join("summary.sig").exists());

        let server = RepoServer::start(&remote_path, false).await;
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;
        let opts = || PullOptions {
            refs: vec!["test/main".to_owned()],
            ..PullOptions::default()
        };
        let opening = ["summary.sig", "summary", "config", "refs/heads/test/main"];

        // The remote holds no delta yet. The pull requests the from-scratch
        // superblock by name and gets a 404. The commit arrives as loose
        // objects.
        dest.pull("origin", opts()).await.unwrap();
        let seen = server.seen();
        assert_eq!(&seen[..4], opening);
        assert_eq!(server.statuses_for("summary.sig"), [404]);
        assert_eq!(server.statuses_for("summary"), [404]);
        assert_eq!(server.statuses_for("refs/heads/test/main"), [200]);
        let scratch = format!("{}/superblock", static_delta_relative_dir(None, &first));
        assert_eq!(server.statuses_for(&scratch), [404], "{seen:?}");
        assert!(seen.contains(&meta_path(&first, "commit")), "{seen:?}");
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(first)
        );

        // The remote adds one commit and publishes the delta from the commit
        // that the destination holds. The remote still has no summary.
        std::fs::write(src.join("hello.txt"), b"hello again\n").unwrap();
        std::fs::write(src.join("added.txt"), b"added\n").unwrap();
        let second = commit_tree(
            &remote,
            dir.path(),
            "src",
            "test/main",
            Some(first),
            FIXED_TS + 1,
        )
        .await;
        remote
            .generate_static_delta(
                Some(&first),
                &second,
                &DeltaOptions {
                    timestamp: Some(FIXED_TS),
                    ..DeltaOptions::default()
                },
            )
            .await
            .unwrap();
        assert!(!remote_path.join("summary").exists());
        let delta_dir = static_delta_relative_dir(Some(&first), &second);
        let mut parts_on_disk: Vec<String> = std::fs::read_dir(remote_path.join(&delta_dir))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.parse::<usize>().is_ok())
            .map(|name| format!("{delta_dir}/{name}"))
            .collect();
        parts_on_disk.sort();
        assert!(!parts_on_disk.is_empty());

        server.forget();
        let stats = dest.pull("origin", opts()).await.unwrap();

        let seen = server.seen();
        assert_eq!(&seen[..4], opening);
        assert_eq!(server.statuses_for("summary.sig"), [404]);
        assert_eq!(server.statuses_for("summary"), [404]);
        assert_eq!(server.statuses_for("refs/heads/test/main"), [200]);
        let superblock = format!("{delta_dir}/superblock");
        assert_eq!(server.statuses_for(&superblock), [200], "{seen:?}");
        let mut parts = part_requests(&seen);
        parts.sort();
        assert_eq!(parts, parts_on_disk);
        assert_eq!(stats.delta_parts as usize, parts.len());
        // The delta carries the whole commit. The one object request is the
        // probe for the detached metadata of the commit. The pull requests
        // nothing more than the opening reads, the superblock, and the parts.
        let objects: Vec<&String> = seen
            .iter()
            .filter(|path| path.starts_with("objects/"))
            .collect();
        assert_eq!(objects, [&meta_path(&second, "commitmeta")], "{seen:?}");
        assert_eq!(seen.len(), opening.len() + 1 + parts.len() + 1, "{seen:?}");
        assert_eq!(stats.content_fetched, 0);

        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(second)
        );
        assert_eq!(
            dest.commit_state(&second).await.unwrap(),
            CommitState::Normal
        );
        let report = dest.fsck(&FsckOptions::default()).await.unwrap();
        assert!(report.is_ok(), "{:?}", report.errors);
    });
}

/// Returns the part requests in `seen`: each path under `deltas/` whose last
/// component is a part number.
fn part_requests(seen: &[String]) -> Vec<String> {
    seen.iter()
        .filter(|path| path.starts_with("deltas/"))
        .filter(|path| {
            path.rsplit('/')
                .next()
                .is_some_and(|name| name.parse::<usize>().is_ok())
        })
        .cloned()
        .collect()
}

/// A pull applies inline deltas from the `ostree` command with no part request.
/// The first is a from-scratch delta whose part is past the heap threshold. The
/// second is a from-to delta that the command writes under
/// `--set-endianness=B`. Each time, the superblock is the one delta request,
/// and the pull fetches no content object as a loose object.
#[test]
fn a_tool_inline_delta_is_pulled_without_a_part_request() {
    if !ostree_available() {
        eprintln!("skipping: the ostree tool is not installed");
        return;
    }
    block_on(async {
        let dir = TmpDir::new("pull-http-inline-tool");
        let src = dir.path().join("src");
        build_tree(&src, b"hello\n");
        let mut bulk = incompressible(256 * 1024);
        std::fs::write(src.join("bulk.bin"), &bulk).unwrap();
        let remote = dir.path().join("remote");
        let remote_arg = format!("--repo={}", remote.display());
        let tree_arg = format!("--tree=dir={}", src.display());
        ostree(&[&remote_arg, "init", "--mode=archive"]);
        let commit = |ts: &str| {
            String::from_utf8(ostree(&[
                &remote_arg,
                "commit",
                "-b",
                "test/main",
                &format!("--timestamp={ts}"),
                &tree_arg,
            ]))
            .unwrap()
            .trim()
            .to_owned()
        };
        let c1 = commit("2020-01-01 00:00:00 +0000");
        ostree(&[
            &remote_arg,
            "static-delta",
            "generate",
            "--inline",
            "--empty",
            &format!("--to={c1}"),
        ]);

        let server = RepoServer::start(&remote, false).await;
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;
        let pull = PullOptions {
            refs: vec!["test/main".to_owned()],
            ..PullOptions::default()
        };
        dest.pull("origin", pull.clone()).await.unwrap();
        let seen = server.seen();
        assert!(
            seen.iter().any(|path| path.ends_with("/superblock")),
            "the pull took the delta: {seen:?}"
        );
        assert_eq!(part_requests(&seen), Vec::<String>::new());
        assert!(
            !seen.iter().any(|path| path.ends_with(".filez")),
            "{seen:?}"
        );
        let c1 = Checksum::from_hex(&c1).unwrap();
        assert_eq!(dest.commit_state(&c1).await.unwrap(), CommitState::Normal);

        bulk[128 * 1024..128 * 1024 + 4].copy_from_slice(b"edit");
        std::fs::write(src.join("bulk.bin"), &bulk).unwrap();
        let c2 = commit("2020-01-02 00:00:00 +0000");
        ostree(&[
            &remote_arg,
            "static-delta",
            "generate",
            "--inline",
            "--set-endianness=B",
            &format!("--from={}", c1.to_hex()),
            &format!("--to={c2}"),
        ]);
        server.forget();
        dest.pull("origin", pull).await.unwrap();
        let seen = server.seen();
        assert!(
            seen.iter().any(|path| path.ends_with("/superblock")),
            "the pull took the delta: {seen:?}"
        );
        assert_eq!(part_requests(&seen), Vec::<String>::new());
        let c2 = Checksum::from_hex(&c2).unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(c2)
        );
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
        ostree(&[
            &format!("--repo={}", dir.path().join("dest").display()),
            "fsck",
        ]);
    });
}

/// A pull applies an inline delta from ostrya with big-endian size fields. The
/// pull makes no part request.
#[test]
fn a_big_endian_inline_delta_is_pulled() {
    block_on(async {
        let dir = TmpDir::new("pull-http-inline-big");
        let src = dir.path().join("src");
        build_tree(&src, b"hello\n");
        std::fs::write(src.join("bulk.bin"), incompressible(256 * 1024)).unwrap();
        let remote_path = dir.path().join("remote");
        let remote = Repo::create(&remote_path, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let tip = commit_tree(&remote, dir.path(), "src", "test/main", None, FIXED_TS).await;
        remote
            .generate_static_delta(
                None,
                &tip,
                &DeltaOptions {
                    timestamp: Some(FIXED_TS),
                    inline: true,
                    endianness: DeltaEndianness::Big,
                    ..DeltaOptions::default()
                },
            )
            .await
            .unwrap();
        let server = RepoServer::start(&remote_path, false).await;
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;
        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        let seen = server.seen();
        assert!(
            seen.iter().any(|path| path.ends_with("/superblock")),
            "the pull took the delta: {seen:?}"
        );
        assert_eq!(part_requests(&seen), Vec::<String>::new());
        assert!(
            !seen.iter().any(|path| path.ends_with(".filez")),
            "{seen:?}"
        );
        assert_eq!(dest.commit_state(&tip).await.unwrap(), CommitState::Normal);
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
    });
}

/// The superblock type string, for a test that rewrites a superblock.
const SUPERBLOCK_SIG: &str = "(a{sv}tayay(a{sv}aya(say)sstayay)aya(uayttay)a(yaytt))";

/// An inline part with changed bytes fails the pull at discovery, before any
/// part request. The pull publishes nothing.
///
/// The superblock holds its last part inline and the parts before it as files.
/// If the pull verifies the inline part when it applies the part, the
/// verification comes after the requests for the part files. Verification at
/// discovery comes before them. The remote serves no summary, so no advertised
/// digest catches the superblock first.
#[test]
fn a_tampered_inline_part_fails_discovery_before_any_part_request() {
    block_on(async {
        let dir = TmpDir::new("pull-http-inline-tamper");
        let src = dir.path().join("src");
        build_tree(&src, b"hello\n");
        std::fs::write(src.join("one.bin"), incompressible(64 * 1024)).unwrap();
        std::fs::write(src.join("two.bin"), incompressible(96 * 1024)).unwrap();
        let remote_path = dir.path().join("remote");
        let remote = Repo::create(&remote_path, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let tip = commit_tree(&remote, dir.path(), "src", "test/main", None, FIXED_TS).await;
        let relative = remote
            .generate_static_delta(
                None,
                &tip,
                &DeltaOptions {
                    timestamp: Some(FIXED_TS),
                    min_fallback_size: 0,
                    max_chunk_size: 48 * 1024,
                    ..DeltaOptions::default()
                },
            )
            .await
            .unwrap();
        let superblock_path = format!("{}/superblock", relative.display());
        let ty = Type::parse(SUPERBLOCK_SIG).unwrap();
        let Value::Tuple(mut fields) = ostrya::from_bytes(
            &ty,
            &std::fs::read(remote_path.join(&superblock_path)).unwrap(),
        )
        .unwrap() else {
            panic!("a superblock is a tuple");
        };
        let parts = fields[6].as_array().unwrap().len();
        assert!(parts >= 2, "{parts} parts");
        // The last part goes inline with one body byte changed. Its file stays
        // in place, and a reader takes the inline part.
        let last = parts - 1;
        let mut part = std::fs::read(remote_path.join(&relative).join(last.to_string())).unwrap();
        let middle = part.len() / 2;
        part[middle] ^= 0xff;
        let Value::Array(dict) = &mut fields[0] else {
            panic!("the superblock metadata is a dict");
        };
        dict.push(Value::Tuple(vec![
            Value::Str(format!("{}/{last}", relative.display())),
            Value::variant(
                Type::parse("(yay)").unwrap(),
                Value::Tuple(vec![Value::Byte(part[0]), Value::Bytes(part[1..].to_vec())]),
            ),
        ]));
        let superblock = ostrya_core::to_bytes(&ty, &Value::Tuple(fields)).unwrap();

        let server = RepoServer::start(&remote_path, false).await;
        server.tamper(&superblock_path, superblock);
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;
        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("part checksum mismatch"), "{err}");
        assert_nothing_published(&dest).await;
        let seen = server.seen();
        assert!(
            seen.iter().any(|path| path.ends_with("/superblock")),
            "the pull took the delta: {seen:?}"
        );
        assert_eq!(part_requests(&seen), Vec::<String>::new());
    });
}

// --- signature verification --------------------------------------------------

/// A fixed ed25519 keypair that the remotes sign with.
const SECRET_B64: &str =
    "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";
const PUBLIC_B64: &str = "wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=";
/// A second keypair. It stands for a key that a destination does not trust.
const OTHER_SECRET_B64: &str =
    "5ILWxT+l9G/u3h0BptRpmSi35C9uog7YDdD+Fp1Xk+Hz52p0NlYh6xBA73kJEJKhKbbnjcE0rsWA5XA/K5Sq5Q==";
const OTHER_PUBLIC_B64: &str = "8+dqdDZWIesQQO95CRCSoSm2543BNK7FgOVwPyuUquU=";

/// Returns `true` if this host has its own sign-api key store. Its keys join
/// each trusted set that a test builds.
fn system_sign_keys() -> bool {
    !ostrya::load_sign_keys("ed25519")
        .unwrap()
        .trusted
        .is_empty()
}

/// Builds a remote that holds `test/main`. The function signs the commit and
/// the summary with `secret`. If `secret` is `None`, both stay unsigned.
async fn build_signed_remote(dir: &Path, secret: Option<&str>) -> (Repo, Checksum) {
    let (remote, commit) = build_remote(dir).await;
    if let Some(secret) = secret {
        let signer = Ed25519Signer::from_base64(secret).unwrap();
        remote.sign_commit(&commit, &signer).await.unwrap();
        remote.sign_summary(&signer).await.unwrap();
    }
    (remote, commit)
}

/// Pulls `test/main` from `origin` with the options in `opts`.
async fn pull_main(dest: &Repo, opts: PullOptions) -> Result<PullStats, Error> {
    dest.pull(
        "origin",
        PullOptions {
            refs: vec!["test/main".to_owned()],
            ..opts
        },
    )
    .await
}

/// The default policy is the policy of the `ostree` command. `gpg-verify` is on
/// unless the remote turns it off, so a pull from a remote with unsigned
/// commits is refused. The pull publishes nothing.
///
/// A build without the GPG engine refuses the same pull, because no engine can
/// verify the signatures. This is the fail-closed side of the same rule.
#[test]
fn an_unsigned_commit_is_refused_under_the_default_policy() {
    block_on(async {
        let dir = TmpDir::new("pull-http-gpg-default");
        let (_remote, _commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(
            dir.path(),
            RepoMode::Archive,
            &server.url(),
            "gpg-verify=true\n",
        )
        .await;

        let err = pull_main(&dest, PullOptions::default()).await.unwrap_err();
        if cfg!(feature = "verify-gpg") {
            assert!(
                matches!(&err, Error::Signature(m) if m.contains("carries no signature")),
                "{err}"
            );
        } else {
            assert!(
                matches!(&err, Error::Unsupported(m) if m.contains("verify-gpg")),
                "{err}"
            );
        }
        assert_nothing_published(&dest).await;
    });
}

/// `sign-verify` with the key that signed the commit accepts the commit. The
/// same pull under another key is refused and publishes nothing.
#[test]
fn sign_verify_accepts_the_configured_key_and_refuses_another() {
    block_on(async {
        let dir = TmpDir::new("pull-http-sign-verify");
        let (_remote, commit) = build_signed_remote(dir.path(), Some(SECRET_B64)).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;

        let dest = build_dest(
            dir.path(),
            RepoMode::Archive,
            &server.url(),
            &format!("sign-verify=ed25519\nverification-ed25519-key={PUBLIC_B64}\n"),
        )
        .await;
        pull_main(&dest, PullOptions::default()).await.unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(commit)
        );
        drop(dest);

        std::fs::remove_dir_all(dir.path().join("dest")).unwrap();
        let dest = build_dest(
            dir.path(),
            RepoMode::Archive,
            &server.url(),
            &format!("sign-verify=ed25519\nverification-ed25519-key={OTHER_PUBLIC_B64}\n"),
        )
        .await;
        let err = pull_main(&dest, PullOptions::default()).await.unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("is from a trusted key")),
            "{err}"
        );
        assert_nothing_published(&dest).await;
    });
}

/// The trusted set of an engine comes from both key sources. A
/// `verification-ed25519-file` with several keys accepts a commit that any one
/// of the keys signed. If no source holds a key for an engine, the pull refuses
/// the engine before it reads a signature.
#[test]
fn a_key_file_supplies_the_trusted_keys() {
    block_on(async {
        let dir = TmpDir::new("pull-http-key-file");
        let (_remote, commit) = build_signed_remote(dir.path(), Some(SECRET_B64)).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;

        let keys = dir.path().join("keys.ed25519");
        std::fs::write(&keys, format!("{OTHER_PUBLIC_B64}\n\n{PUBLIC_B64}\n")).unwrap();
        let dest = build_dest(
            dir.path(),
            RepoMode::Archive,
            &server.url(),
            &format!(
                "sign-verify=ed25519\nverification-ed25519-file={}\n",
                keys.display()
            ),
        )
        .await;
        pull_main(&dest, PullOptions::default()).await.unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(commit)
        );
        drop(dest);

        if system_sign_keys() {
            eprintln!("skipping the keyless half: this host has a sign-api key store");
            return;
        }
        std::fs::remove_dir_all(dir.path().join("dest")).unwrap();
        let dest = build_dest(
            dir.path(),
            RepoMode::Archive,
            &server.url(),
            "sign-verify=ed25519\n",
        )
        .await;
        let err = pull_main(&dest, PullOptions::default()).await.unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("no trusted key")),
            "{err}"
        );
        assert_nothing_published(&dest).await;
    });
}

/// `sign-verify=true` names each engine that this build has. If no engine has a
/// given name, the pull refuses the name. It does not skip it silently.
#[test]
fn sign_verify_true_selects_every_engine_and_an_unknown_name_is_refused() {
    block_on(async {
        let dir = TmpDir::new("pull-http-sign-verify-true");
        let (_remote, commit) = build_signed_remote(dir.path(), Some(SECRET_B64)).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;

        let dest = build_dest(
            dir.path(),
            RepoMode::Archive,
            &server.url(),
            &format!("sign-verify=true\nverification-ed25519-key={PUBLIC_B64}\n"),
        )
        .await;
        pull_main(&dest, PullOptions::default()).await.unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(commit)
        );
        drop(dest);

        std::fs::remove_dir_all(dir.path().join("dest")).unwrap();
        let dest = build_dest(
            dir.path(),
            RepoMode::Archive,
            &server.url(),
            &format!("sign-verify=ed25519;bogus\nverification-ed25519-key={PUBLIC_B64}\n"),
        )
        .await;
        let err = pull_main(&dest, PullOptions::default()).await.unwrap_err();
        assert!(
            matches!(&err, Error::Unsupported(m) if m.contains("'bogus'")),
            "{err}"
        );
        assert_nothing_published(&dest).await;
    });
}

/// `sign-verify-summary` verifies the summary of the remote with the same keys.
/// If another key signed the summary, the pull refuses it before the first
/// object request. If the remote publishes no summary signature, the refusal
/// names `summary.sig`. The pull reads the switch on its own, so
/// `sign-verify=false` does not turn it off.
#[test]
fn the_summary_signature_is_checked_when_the_remote_asks_for_it() {
    block_on(async {
        let dir = TmpDir::new("pull-http-summary-sig");
        let (remote, commit) = build_signed_remote(dir.path(), Some(SECRET_B64)).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let extra = format!(
            "sign-verify=false\nsign-verify-summary=true\n\
             verification-ed25519-key={PUBLIC_B64}\n"
        );

        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), &extra).await;
        pull_main(&dest, PullOptions::default()).await.unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(commit)
        );
        drop(dest);

        // A key that the destination does not trust signs the same summary.
        // Regeneration drops the signature of the trusted key, so the file
        // holds only the signature of the other key. The refusal comes before
        // any other request to the remote.
        remote
            .regenerate_summary(&SummaryOptions {
                last_modified: Some(FIXED_TS),
                ..SummaryOptions::default()
            })
            .await
            .unwrap();
        remote
            .sign_summary(&Ed25519Signer::from_base64(OTHER_SECRET_B64).unwrap())
            .await
            .unwrap();
        std::fs::remove_dir_all(dir.path().join("dest")).unwrap();
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), &extra).await;
        server.forget();
        let err = pull_main(&dest, PullOptions::default()).await.unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("is from a trusted key")),
            "{err}"
        );
        assert_nothing_published(&dest).await;
        assert_eq!(
            server.seen_set(),
            HashSet::from(["summary.sig".to_owned(), "summary".to_owned()]),
            "the summary is checked before anything else is requested"
        );
        drop(dest);

        // If the remote publishes no signature, the refusal names
        // `summary.sig`.
        server.hide("summary.sig");
        std::fs::remove_dir_all(dir.path().join("dest")).unwrap();
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), &extra).await;
        let err = pull_main(&dest, PullOptions::default()).await.unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("no summary.sig")),
            "{err}"
        );
        assert_nothing_published(&dest).await;
    });
}

/// A pull verifies the tip and each parent that a depth pull follows. If the
/// tip is signed and its parent is not, the pull refuses the parent.
#[test]
fn a_parent_reached_under_depth_is_checked_too() {
    block_on(async {
        let dir = TmpDir::new("pull-http-depth-verify");
        let src = dir.path().join("src");
        build_tree(&src, b"hello\n");
        let remote = Repo::create(
            &dir.path().join("remote"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let parent = commit_tree(&remote, dir.path(), "src", "test/main", None, FIXED_TS).await;
        let tip = commit_tree(
            &remote,
            dir.path(),
            "src",
            "test/main",
            Some(parent),
            FIXED_TS + 1,
        )
        .await;
        let signer = Ed25519Signer::from_base64(SECRET_B64).unwrap();
        remote.sign_commit(&tip, &signer).await.unwrap();

        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let extra = format!("sign-verify=ed25519\nverification-ed25519-key={PUBLIC_B64}\n");
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), &extra).await;

        // The tip alone is signed, so a depth-0 pull passes.
        pull_main(&dest, PullOptions::default()).await.unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(tip)
        );
        drop(dest);

        std::fs::remove_dir_all(dir.path().join("dest")).unwrap();
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), &extra).await;
        let err = pull_main(
            &dest,
            PullOptions {
                depth: 1,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains(&parent.to_hex())),
            "{err}"
        );
        assert_nothing_published(&dest).await;
        // The tip passed the policy and got a marker before the pull refused
        // the parent. The failed pull published neither commit, so it removes
        // that marker.
        let marker = dir
            .path()
            .join("dest/state")
            .join(format!("{}.commitpartial", tip.to_hex()));
        assert!(!marker.exists(), "the tip's marker was left behind");
    });
}

/// A pull that verifies the commit signatures applies the switch of the
/// destination to the `.commitmeta` that the verification read. With the
/// default switch, the pull stores the bytes of the remote unchanged. With
/// `keep-detached-related=false`, it stores the other properties in normal
/// form, and the verification reads the whole metadata.
#[test]
fn a_verified_pull_applies_the_switch_to_the_detached_metadata() {
    block_on(async {
        let dir = TmpDir::new("pull-http-verify-switch");
        let (remote, commit) = build_remote(dir.path()).await;
        remote
            .write_commit_detached_metadata(&commit, Some(&detached_dict()))
            .await
            .unwrap();
        let signer = Ed25519Signer::from_base64(SECRET_B64).unwrap();
        remote.sign_commit(&commit, &signer).await.unwrap();
        remote
            .add_detached_related(&commit, "layer/base", &commit)
            .await
            .unwrap();
        let Some(Value::Array(entries)) =
            remote.read_commit_detached_metadata(&commit).await.unwrap()
        else {
            panic!("the remote holds a dict");
        };
        assert_eq!(
            entries.len(),
            3,
            "the property, the signature, and the related key"
        );
        let server = RepoServer::start(remote.path(), false).await;
        let extra = format!("sign-verify=ed25519\nverification-ed25519-key={PUBLIC_B64}\n");
        let commitmeta = |root: &Path| std::fs::read(root.join(meta_path(&commit, "commitmeta")));

        for switch in ["", DROP_RELATED] {
            let _ = std::fs::remove_dir_all(dir.path().join("dest"));
            let dest = build_dest(
                dir.path(),
                RepoMode::Archive,
                &server.url(),
                &format!("{extra}{switch}"),
            )
            .await;

            pull_main(&dest, PullOptions::default()).await.unwrap();

            if switch.is_empty() {
                assert_eq!(
                    commitmeta(&dir.path().join("dest")).unwrap(),
                    commitmeta(remote.path()).unwrap()
                );
            } else {
                // The read accepts normal form alone, so the stored bytes are
                // the normal form of the kept properties.
                let kept: Vec<Value> = entries
                    .iter()
                    .filter(|entry| {
                        entry.as_tuple().and_then(|fields| fields[0].as_str())
                            != Some("ostrya.related")
                    })
                    .cloned()
                    .collect();
                assert_eq!(kept.len(), 2);
                assert_eq!(
                    dest.read_commit_detached_metadata(&commit).await.unwrap(),
                    Some(Value::Array(kept))
                );
            }
        }
    });
}

/// A pull verifies again a commit that this repository already holds. The
/// policy of the current pull decides. The result of an earlier pull does not.
#[test]
fn a_commit_already_here_is_checked_again() {
    block_on(async {
        let dir = TmpDir::new("pull-http-recheck");
        let (_remote, commit) = build_signed_remote(dir.path(), Some(SECRET_B64)).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(
            dir.path(),
            RepoMode::Archive,
            &server.url(),
            &format!("sign-verify=ed25519\nverification-ed25519-key={PUBLIC_B64}\n"),
        )
        .await;
        pull_main(&dest, PullOptions::default()).await.unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(commit)
        );

        // The same repository now holds the commit. Its new policy names a key
        // that did not sign the commit.
        drop(dest);
        let dest = reconfigure_dest(
            dir.path(),
            &server.url(),
            &format!("sign-verify=ed25519\nverification-ed25519-key={OTHER_PUBLIC_B64}\n"),
        )
        .await;
        let err = pull_main(&dest, PullOptions::default()).await.unwrap_err();
        assert!(matches!(&err, Error::Signature(_)), "{err}");
    });
}

/// The switches of the pull override the configuration of the remote, in both
/// directions.
#[test]
fn the_options_override_the_configured_policy() {
    block_on(async {
        let dir = TmpDir::new("pull-http-verify-override");
        let (_remote, commit) = build_signed_remote(dir.path(), Some(SECRET_B64)).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;

        // The configuration names a key that did not sign the commit. The pull
        // turns verification off and writes the ref.
        let dest = build_dest(
            dir.path(),
            RepoMode::Archive,
            &server.url(),
            &format!("sign-verify=ed25519\nverification-ed25519-key={OTHER_PUBLIC_B64}\n"),
        )
        .await;
        pull_main(
            &dest,
            PullOptions {
                verify: PullVerify {
                    sign: Some(false),
                    ..PullVerify::default()
                },
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(commit)
        );

        // The configuration turns no verification on. The pull turns on each
        // engine, and the configuration names the wrong key.
        drop(dest);
        std::fs::remove_dir_all(dir.path().join("dest")).unwrap();
        let dest = build_dest(
            dir.path(),
            RepoMode::Archive,
            &server.url(),
            &format!("verification-ed25519-key={OTHER_PUBLIC_B64}\n"),
        )
        .await;
        let err = pull_main(
            &dest,
            PullOptions {
                verify: PullVerify {
                    sign: Some(true),
                    ..PullVerify::default()
                },
                ..PullOptions::default()
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(&err, Error::Signature(_)), "{err}");
        assert_nothing_published(&dest).await;
    });
}

/// A pull verifies a static delta with the sign-api engines that the commit
/// policy names. If a trusted key signed the delta, the pull applies it. If
/// another key signed it, the pull fails before it fetches a part.
#[test]
fn a_delta_is_held_to_the_pulls_signature_policy() {
    block_on(async {
        let dir = TmpDir::new("pull-http-delta-verify");
        let src = dir.path().join("src");
        build_tree(&src, b"hello\n");
        let remote_path = dir.path().join("remote");
        let remote = Repo::create(&remote_path, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let tip = commit_tree(&remote, dir.path(), "src", "test/main", None, FIXED_TS).await;
        let signer = Ed25519Signer::from_base64(SECRET_B64).unwrap();
        remote.sign_commit(&tip, &signer).await.unwrap();
        let delta = remote_path.join(
            remote
                .generate_static_delta(
                    None,
                    &tip,
                    &DeltaOptions {
                        timestamp: Some(FIXED_TS),
                        ..DeltaOptions::default()
                    },
                )
                .await
                .unwrap(),
        );
        // A key that the destination does not trust signs the delta. The
        // remote serves no summary, so the pull requests the superblock by
        // name.
        remote
            .sign_static_delta(
                &delta,
                &Ed25519Signer::from_base64(OTHER_SECRET_B64).unwrap(),
            )
            .await
            .unwrap();

        let server = RepoServer::start(&remote_path, false).await;
        let extra = format!("sign-verify=ed25519\nverification-ed25519-key={PUBLIC_B64}\n");
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), &extra).await;
        let err = pull_main(&dest, PullOptions::default()).await.unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("static delta")),
            "{err}"
        );
        assert_nothing_published(&dest).await;
        assert!(
            !server.seen().iter().any(|path| path.ends_with("/0")),
            "no part was fetched: {:?}",
            server.seen()
        );
        drop(dest);

        // The pull applies the same delta with a signature of the trusted key.
        // The commit that the delta delivers passes the commit policy with its
        // own signature.
        std::fs::remove_dir_all(&delta).unwrap();
        let delta = remote_path.join(
            remote
                .generate_static_delta(
                    None,
                    &tip,
                    &DeltaOptions {
                        timestamp: Some(FIXED_TS),
                        ..DeltaOptions::default()
                    },
                )
                .await
                .unwrap(),
        );
        remote.sign_static_delta(&delta, &signer).await.unwrap();
        std::fs::remove_dir_all(dir.path().join("dest")).unwrap();
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), &extra).await;
        server.forget();
        pull_main(&dest, PullOptions::default()).await.unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(tip)
        );
        assert!(
            server.seen().iter().any(|path| path.ends_with("/0")),
            "the delta's part was fetched: {:?}",
            server.seen()
        );
    });
}

/// Interop: a pull by ostrya verifies the signatures that the `ostree` command
/// writes. The command builds the remote and signs its commit and its summary
/// with ed25519. ostrya pulls the remote under a policy that names that key. It
/// refuses the same remote under another key.
#[test]
fn a_pull_verifies_what_the_tool_signed() {
    if !ostree_supports_ed25519() {
        eprintln!("skipping: the ostree tool has no ed25519 engine");
        return;
    }
    block_on(async {
        let dir = TmpDir::new("pull-http-tool-signed");
        let src = dir.path().join("src");
        build_tree(&src, b"hello\n");

        let remote = dir.path().join("remote");
        let remote_arg = format!("--repo={}", remote.display());
        ostree(&[&remote_arg, "init", "--mode=archive"]);
        let commit = String::from_utf8(ostree(&[
            &remote_arg,
            "commit",
            "-b",
            "test/main",
            "--timestamp=2020-01-01 00:00:00 +0000",
            &format!("--tree=dir={}", src.display()),
        ]))
        .unwrap()
        .trim()
        .to_owned();
        ostree(&[
            &remote_arg,
            "sign",
            "--sign-type=ed25519",
            &commit,
            SECRET_B64,
        ]);
        ostree(&[
            &remote_arg,
            "summary",
            "-u",
            "--sign-type=ed25519",
            &format!("--sign={SECRET_B64}"),
        ]);

        let server = RepoServer::start(&remote, false).await;
        let dest = build_dest(
            dir.path(),
            RepoMode::BareUser,
            &server.url(),
            &format!(
                "sign-verify=ed25519\nsign-verify-summary=true\n\
                 verification-ed25519-key={PUBLIC_B64}\n"
            ),
        )
        .await;
        pull_main(&dest, PullOptions::default()).await.unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true)
                .await
                .unwrap()
                .map(|c| c.to_hex()),
            Some(commit)
        );
        drop(dest);

        std::fs::remove_dir_all(dir.path().join("dest")).unwrap();
        let dest = build_dest(
            dir.path(),
            RepoMode::BareUser,
            &server.url(),
            &format!(
                "sign-verify=ed25519\nsign-verify-summary=true\n\
                 verification-ed25519-key={OTHER_PUBLIC_B64}\n"
            ),
        )
        .await;
        let err = pull_main(&dest, PullOptions::default()).await.unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("is from a trusted key")),
            "{err}"
        );
        assert_nothing_published(&dest).await;
    });
}

/// The durability options change the sync calls of an HTTP pull. They change no
/// byte that the pull writes.
///
/// The test pulls into an `archive` and a `bare-user` destination under each
/// combination of the two options. Each pull stores the same objects and refs
/// and reports the same statistics. A mirror pull of all refs copies the same
/// summary. The CLI tests read the sync calls under `strace`.
#[test]
fn http_pull_durability_options_change_no_byte() {
    block_on(async {
        let dir = TmpDir::new("pull-http-durability");
        build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let rows = [(false, false), (true, false), (false, true), (true, true)];
        for (mode, flags) in [
            (RepoMode::Archive, PullFlags::empty()),
            (RepoMode::BareUser, PullFlags::empty()),
            (RepoMode::Archive, PullFlags::MIRROR),
        ] {
            let mut answer = None;
            for (disable_fsync, per_object_fsync) in rows {
                let row = dir.path().join(format!(
                    "{mode:?}-{}-{disable_fsync}-{per_object_fsync}",
                    flags.bits()
                ));
                std::fs::create_dir(&row).unwrap();
                let dest = build_dest(&row, mode, &server.url(), "").await;
                let refs = if flags.contains(PullFlags::MIRROR) {
                    Vec::new()
                } else {
                    vec!["test/main".to_owned()]
                };
                let stats = dest
                    .pull(
                        "origin",
                        PullOptions {
                            refs,
                            flags,
                            disable_fsync,
                            per_object_fsync,
                            ..PullOptions::default()
                        },
                    )
                    .await
                    .unwrap();
                let root = row.join("dest");
                let mut files = file_inventory(&root, "objects");
                files.extend(file_inventory(&root, "refs"));
                if flags.contains(PullFlags::MIRROR) {
                    let summary = std::fs::read(root.join("summary")).unwrap();
                    files.push(("summary".to_owned(), summary));
                }
                // The elapsed time is the one figure that changes between runs.
                let stats = PullStats {
                    elapsed: std::time::Duration::ZERO,
                    ..stats
                };
                let seen = (files, stats);
                match &answer {
                    None => answer = Some(seen),
                    Some(first) => assert_eq!(
                        &seen, first,
                        "{mode:?} {flags:?} disable_fsync={disable_fsync} \
                         per_object_fsync={per_object_fsync} changed what the pull wrote",
                    ),
                }
            }
        }
    });
}

// --- trust groups ------------------------------------------------------------

/// Returns the keys of a trust group that trusts the ed25519 key
/// [`PUBLIC_B64`].
fn ed25519_group() -> String {
    format!("sign-verify=ed25519\nverification-ed25519-key={PUBLIC_B64}\n")
}

/// Creates a destination as [`build_dest`] does. The remote section holds
/// `trust=t` and the keys of `extra`. The trust group `[ex-ostrya trust "t"]`
/// holds the keys of `group`.
async fn dest_with_trust(dir: &Path, url: &str, extra: &str, group: &str) -> Repo {
    build_dest(
        dir,
        RepoMode::Archive,
        url,
        &format!("trust=t\n{extra}[ex-ostrya trust \"t\"]\n{group}"),
    )
    .await
}

/// Pulls `test/main` over HTTP into a destination whose remote names the
/// trust group `group`. `own` is a key that the group trusts, and `other` is
/// a key that it does not trust.
///
/// An unsigned commit and a commit of `other` are refused, and the pull
/// publishes nothing. A commit of `own` is pulled.
async fn assert_the_group_checks_the_commits(
    dir: &Path,
    group: &str,
    own: &dyn Signer,
    other: &dyn Signer,
) {
    let (remote, commit) = build_remote(dir).await;
    let server = RepoServer::start(&dir.join("remote"), false).await;
    let fresh_dest = || async {
        let _ = std::fs::remove_dir_all(dir.join("dest"));
        dest_with_trust(dir, &server.url(), "", group).await
    };

    let dest = fresh_dest().await;
    let err = pull_main(&dest, PullOptions::default()).await.unwrap_err();
    assert!(
        matches!(&err, Error::Signature(m)
            if m.contains("sign-api verification is enabled, but it carries no signature")),
        "{err}"
    );
    assert_nothing_published(&dest).await;

    remote.sign_commit(&commit, other).await.unwrap();
    let dest = fresh_dest().await;
    let err = pull_main(&dest, PullOptions::default()).await.unwrap_err();
    assert!(
        matches!(&err, Error::Signature(m) if m.contains("no sign-api signature is from a trusted key")),
        "{err}"
    );
    assert_nothing_published(&dest).await;

    remote
        .write_commit_detached_metadata(&commit, None)
        .await
        .unwrap();
    remote.sign_commit(&commit, own).await.unwrap();
    let dest = fresh_dest().await;
    pull_main(&dest, PullOptions::default()).await.unwrap();
    assert_eq!(
        dest.resolve_rev("origin:test/main", true).await.unwrap(),
        Some(commit)
    );
}

/// A remote with `trust=t` takes the keys of the commits of a pull over HTTP
/// from the trust group, with an ed25519 group and with an spki group.
#[test]
fn a_trust_group_checks_the_commits_of_a_pull_over_http() {
    block_on(async {
        let dir = TmpDir::new("pull-http-trust-commits");
        let own = Ed25519Signer::from_base64(SECRET_B64).unwrap();
        let other = Ed25519Signer::from_base64(OTHER_SECRET_B64).unwrap();
        assert_the_group_checks_the_commits(dir.path(), &ed25519_group(), &own, &other).await;
    });
    #[cfg(feature = "sign-spki-p256")]
    block_on(async {
        use ostrya::SpkiSigner;

        let dir = TmpDir::new("pull-http-trust-commits-spki");
        let own = SpkiSigner::from_base64(concat!(
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2L708EsnnzHER0SYasMNIUcG",
            "v63QapC/3kVsoPerzKGhRANCAATxfzfHKUPeJtyLTGMUoxHhvBS1NT9guWhUQPGiZRLZIcB8Wc3",
            "csdVU1iOiTRmbZGKJTtekOdEAbVRrx5HxIpst",
        ))
        .unwrap();
        let other = SpkiSigner::from_base64(concat!(
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgU5tYPz/hTTxfsSTPOxD/H9U+",
            "IkBj5qWV4/H3D1NBfRChRANCAAQPyTr9rh2d6WiYOi3oxNiE3ppTP2g5JP2xX9D7rEKnzixp",
            "MqVuqA9XnzQr5GlCYd71m/D7BnYIqS4MytNawYrR",
        ))
        .unwrap();
        let group = format!(
            "sign-verify=spki\nverification-spki-key={}\n",
            ostrya::base64::encode(&own.public_key_der())
        );
        assert_the_group_checks_the_commits(dir.path(), &group, &own, &other).await;
    });
}

/// Each refusal of a trust group comes before the first request of a pull
/// over HTTP:
///
/// - a `trust` value that names no group, the empty value, and a value with
///   a `"`;
/// - `Some(true)` in `gpg` or in `sign`;
/// - a remote key that turns on a commit check, and a key source of the
///   remote that no summary check reads.
#[test]
fn a_trust_group_refuses_before_the_first_request() {
    block_on(async {
        let dir = TmpDir::new("pull-http-trust-refusals");
        let _remote = build_signed_remote(dir.path(), Some(SECRET_B64)).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let group = format!("[ex-ostrya trust \"t\"]\n{}", ed25519_group());
        let malformed = "the value names a trust group, is not empty, and holds no '\"' and \
                         no control character";
        let head = "[remote \"origin\"] sets trust=t and";
        let commit_check = "the trust group sets the commit checks";
        let gpg_on = PullVerify {
            gpg: Some(true),
            ..PullVerify::default()
        };
        let sign_on = PullVerify {
            sign: Some(true),
            ..PullVerify::default()
        };
        let input = |check: &str| {
            format!(
                "invalid input: remote 'origin' takes its commit keys from \
                 [ex-ostrya trust \"t\"], so a pull cannot turn on {check} of the commits"
            )
        };
        let rows: Vec<(String, PullVerify, String)> = vec![
            (
                format!("trust=nope\n{group}"),
                PullVerify::default(),
                "invalid format: [remote \"origin\"] trust=nope names no \
                 [ex-ostrya trust \"nope\"] group"
                    .to_owned(),
            ),
            (
                format!("trust=\n{group}"),
                PullVerify::default(),
                format!(
                    "invalid format: malformed [remote \"origin\"] trust value '': {malformed}"
                ),
            ),
            (
                format!("trust=a\"b\n{group}"),
                PullVerify::default(),
                format!(
                    "invalid format: malformed [remote \"origin\"] trust value 'a\"b': {malformed}"
                ),
            ),
            (format!("trust=t\n{group}"), gpg_on, input("the GPG check")),
            (
                format!("trust=t\n{group}"),
                sign_on,
                input("the sign-api check"),
            ),
            (
                format!("trust=t\ngpg-verify=true\n{group}"),
                PullVerify::default(),
                format!(
                    "invalid format: {head} gpg-verify=true: {commit_check}, so set \
                     gpg-verify=false or remove the key"
                ),
            ),
            (
                format!("trust=t\nsign-verify=true\n{group}"),
                PullVerify::default(),
                format!(
                    "invalid format: {head} sign-verify=true: {commit_check}, so remove sign-verify"
                ),
            ),
            (
                format!("trust=t\nsign-verify=ed25519\n{group}"),
                PullVerify::default(),
                format!(
                    "invalid format: {head} sign-verify=ed25519: {commit_check}, so remove \
                     sign-verify"
                ),
            ),
            (
                format!("trust=t\ngpgkeypath=/nonexistent.gpg\n{group}"),
                PullVerify::default(),
                format!(
                    "invalid format: {head} gpgkeypath, and gpg-verify-summary is not true, \
                     so no check reads it"
                ),
            ),
            (
                format!("trust=t\nverification-ed25519-key={OTHER_PUBLIC_B64}\n{group}"),
                PullVerify::default(),
                format!(
                    "invalid format: {head} holds 'verification-ed25519-key', and \
                     sign-verify-summary does not select ed25519, so no check reads it"
                ),
            ),
        ];
        for (extra, verify, reason) in rows {
            let _ = std::fs::remove_dir_all(dir.path().join("dest"));
            let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), &extra).await;
            let err = pull_main(
                &dest,
                PullOptions {
                    verify,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
            assert_eq!(err.to_string(), reason, "{extra:?}");
            assert_nothing_published(&dest).await;
            assert!(server.seen().is_empty(), "{extra:?}: {:?}", server.seen());
        }
    });
}

/// With a trust group, `Some(false)` in `sign` turns the sign-api axis of the
/// group off, so a pull over HTTP takes an unsigned commit. `gpg-verify=false`,
/// which every destination of these tests holds, `sign-verify=false`, and an
/// empty `sign-verify` turn no commit check on.
#[test]
fn a_trust_group_axis_turns_off_for_one_pull_over_http() {
    block_on(async {
        let dir = TmpDir::new("pull-http-trust-off");
        let (_remote, commit) = build_signed_remote(dir.path(), None).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        for extra in ["", "sign-verify=false\n", "sign-verify=\n"] {
            let _ = std::fs::remove_dir_all(dir.path().join("dest"));
            let dest = dest_with_trust(dir.path(), &server.url(), extra, &ed25519_group()).await;
            let off = PullVerify {
                sign: Some(false),
                ..PullVerify::default()
            };
            pull_main(
                &dest,
                PullOptions {
                    verify: off,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();
            assert_eq!(
                dest.resolve_rev("origin:test/main", true).await.unwrap(),
                Some(commit),
                "{extra:?}"
            );
        }
    });
}

/// Beside `trust=t`, an absent `gpg-verify` key gives no GPG check of the
/// commits, so a pull over HTTP takes a commit with an ed25519 signature
/// alone. The same remote with no `trust` key makes the GPG check of the
/// default, which refuses the commit, or which a build with no GPG support
/// refuses.
#[test]
fn a_trust_group_makes_no_gpg_check_when_gpg_verify_is_absent() {
    block_on(async {
        let dir = TmpDir::new("pull-http-trust-no-gpg-key");
        let (remote, commit) = build_remote(dir.path()).await;
        remote
            .sign_commit(&commit, &Ed25519Signer::from_base64(SECRET_B64).unwrap())
            .await
            .unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest_path = dir.path().join("dest");
        let config = dest_path.join("config");
        // Removes the `gpg-verify=false` of the destination, and `trust=t` if
        // `trust` is false, and opens the destination again.
        let without_gpg_verify = |dest: Repo, trust: bool| {
            drop(dest);
            let text = std::fs::read_to_string(&config).unwrap();
            let mut text = text.replacen("gpg-verify=false\n", "", 1);
            if !trust {
                text = text.replacen("trust=t\n", "", 1);
            }
            assert!(!text.contains("gpg-verify"), "{text}");
            std::fs::write(&config, text).unwrap();
            Repo::open(&dest_path)
        };

        let dest = dest_with_trust(dir.path(), &server.url(), "", &ed25519_group()).await;
        let dest = without_gpg_verify(dest, false).await.unwrap();
        let err = pull_main(&dest, PullOptions::default()).await.unwrap_err();
        let refused = if cfg!(feature = "verify-gpg") {
            matches!(&err, Error::Signature(_))
        } else {
            matches!(&err, Error::Unsupported(_))
        };
        assert!(refused, "{err}");
        assert_nothing_published(&dest).await;

        std::fs::remove_dir_all(&dest_path).unwrap();
        let dest = dest_with_trust(dir.path(), &server.url(), "", &ed25519_group()).await;
        let dest = without_gpg_verify(dest, true).await.unwrap();
        pull_main(&dest, PullOptions::default()).await.unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(commit)
        );
    });
}

/// Beside `trust=t`, the summary keys of the remote set the summary check of
/// a pull over HTTP. The group trusts key A, and the remote trusts key B for
/// the summary. A summary of B is accepted, and a summary of A is refused.
/// `sign_summary: Some(false)` over `sign-verify-summary=true` and its key is
/// accepted, because the rule on the key sources of the remote reads the
/// config.
#[test]
fn a_trust_group_keeps_the_summary_check_of_a_pull_over_http() {
    block_on(async {
        let dir = TmpDir::new("pull-http-trust-summary");
        let (remote, commit) = build_remote(dir.path()).await;
        let own = Ed25519Signer::from_base64(SECRET_B64).unwrap();
        let other = Ed25519Signer::from_base64(OTHER_SECRET_B64).unwrap();
        remote.sign_commit(&commit, &own).await.unwrap();
        remote.sign_summary(&other).await.unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let summary_keys = |value: &str| {
            format!("sign-verify-summary={value}\nverification-ed25519-key={OTHER_PUBLIC_B64}\n")
        };

        let dest = dest_with_trust(
            dir.path(),
            &server.url(),
            &summary_keys("ed25519"),
            &ed25519_group(),
        )
        .await;
        pull_main(&dest, PullOptions::default()).await.unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(commit)
        );
        drop(dest);

        remote
            .regenerate_summary(&SummaryOptions {
                last_modified: Some(FIXED_TS),
                ..SummaryOptions::default()
            })
            .await
            .unwrap();
        remote.sign_summary(&own).await.unwrap();
        std::fs::remove_dir_all(dir.path().join("dest")).unwrap();
        let dest = dest_with_trust(
            dir.path(),
            &server.url(),
            &summary_keys("ed25519"),
            &ed25519_group(),
        )
        .await;
        let err = pull_main(&dest, PullOptions::default()).await.unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("no sign-api signature is from a trusted key")),
            "{err}"
        );
        assert_nothing_published(&dest).await;
        drop(dest);

        std::fs::remove_dir_all(dir.path().join("dest")).unwrap();
        let dest = dest_with_trust(
            dir.path(),
            &server.url(),
            &summary_keys("true"),
            &ed25519_group(),
        )
        .await;
        let off = PullVerify {
            sign_summary: Some(false),
            ..PullVerify::default()
        };
        pull_main(
            &dest,
            PullOptions {
                verify: off,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(commit)
        );
    });
}

/// Returns the options of a pull with the trust group option `group`.
fn group_options(group: &str) -> PullOptions {
    PullOptions {
        trust_group: Some(group.to_owned()),
        ..PullOptions::default()
    }
}

/// Pulls `test/main` over HTTP with the trust group option `t`. The remote
/// section holds no key `trust`, and the config holds the group with the keys
/// of `group`. `own` is a key that the group trusts, and `other` is a key
/// that it does not trust.
///
/// An unsigned commit and a commit of `other` are refused, and the pull
/// publishes nothing. A commit of `own` is pulled.
async fn assert_the_option_checks_the_commits(
    dir: &Path,
    group: &str,
    own: &dyn Signer,
    other: &dyn Signer,
) {
    let (remote, commit) = build_remote(dir).await;
    let server = RepoServer::start(&dir.join("remote"), false).await;
    let fresh_dest = || async {
        let _ = std::fs::remove_dir_all(dir.join("dest"));
        build_dest(
            dir,
            RepoMode::Archive,
            &server.url(),
            &format!("[ex-ostrya trust \"t\"]\n{group}"),
        )
        .await
    };

    let dest = fresh_dest().await;
    let err = pull_main(&dest, group_options("t")).await.unwrap_err();
    assert!(
        matches!(&err, Error::Signature(m)
            if m.contains("sign-api verification is enabled, but it carries no signature")),
        "{err}"
    );
    assert_nothing_published(&dest).await;

    remote.sign_commit(&commit, other).await.unwrap();
    let dest = fresh_dest().await;
    let err = pull_main(&dest, group_options("t")).await.unwrap_err();
    assert!(
        matches!(&err, Error::Signature(m) if m.contains("no sign-api signature is from a trusted key")),
        "{err}"
    );
    assert_nothing_published(&dest).await;

    remote
        .write_commit_detached_metadata(&commit, None)
        .await
        .unwrap();
    remote.sign_commit(&commit, own).await.unwrap();
    let dest = fresh_dest().await;
    pull_main(&dest, group_options("t")).await.unwrap();
    assert_eq!(
        dest.resolve_rev("origin:test/main", true).await.unwrap(),
        Some(commit)
    );
}

/// The trust group option of a pull over HTTP takes the keys of the commits
/// from the group, with an ed25519 group and with an spki group.
#[test]
fn the_trust_group_option_checks_the_commits_of_a_pull_over_http() {
    block_on(async {
        let dir = TmpDir::new("pull-http-trust-option-commits");
        let own = Ed25519Signer::from_base64(SECRET_B64).unwrap();
        let other = Ed25519Signer::from_base64(OTHER_SECRET_B64).unwrap();
        assert_the_option_checks_the_commits(dir.path(), &ed25519_group(), &own, &other).await;
    });
    #[cfg(feature = "sign-spki-p256")]
    block_on(async {
        use ostrya::SpkiSigner;

        let dir = TmpDir::new("pull-http-trust-option-commits-spki");
        let own = SpkiSigner::from_base64(concat!(
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2L708EsnnzHER0SYasMNIUcG",
            "v63QapC/3kVsoPerzKGhRANCAATxfzfHKUPeJtyLTGMUoxHhvBS1NT9guWhUQPGiZRLZIcB8Wc3",
            "csdVU1iOiTRmbZGKJTtekOdEAbVRrx5HxIpst",
        ))
        .unwrap();
        let other = SpkiSigner::from_base64(concat!(
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgU5tYPz/hTTxfsSTPOxD/H9U+",
            "IkBj5qWV4/H3D1NBfRChRANCAAQPyTr9rh2d6WiYOi3oxNiE3ppTP2g5JP2xX9D7rEKnzixp",
            "MqVuqA9XnzQr5GlCYd71m/D7BnYIqS4MytNawYrR",
        ))
        .unwrap();
        let group = format!(
            "sign-verify=spki\nverification-spki-key={}\n",
            ostrya::base64::encode(&own.public_key_der())
        );
        assert_the_option_checks_the_commits(dir.path(), &group, &own, &other).await;
    });
}

/// The trust group option of a pull over HTTP wins over the key `trust` of
/// the remote, and the pull does not read the key. A key that names no group
/// and an empty key are not read.
#[test]
fn the_trust_group_option_wins_over_the_remote_key_over_http() {
    block_on(async {
        let dir = TmpDir::new("pull-http-trust-option-wins");
        let (remote, commit) = build_remote(dir.path()).await;
        remote
            .sign_commit(&commit, &Ed25519Signer::from_base64(SECRET_B64).unwrap())
            .await
            .unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        for key in ["trust=nope\n", "trust=\n"] {
            let _ = std::fs::remove_dir_all(dir.path().join("dest"));
            let dest = build_dest(
                dir.path(),
                RepoMode::Archive,
                &server.url(),
                &format!("{key}[ex-ostrya trust \"t\"]\n{}", ed25519_group()),
            )
            .await;
            pull_main(&dest, group_options("t")).await.unwrap();
            assert_eq!(
                dest.resolve_rev("origin:test/main", true).await.unwrap(),
                Some(commit),
                "{key:?}"
            );
        }
    });
}

/// With the trust group option, an absent `gpg-verify` key of the remote
/// gives no GPG check of the commits, so a pull over HTTP takes a commit with
/// an ed25519 signature alone. The same pull without the option makes the
/// GPG check of the default, which refuses the commit, or which a build with
/// no GPG support refuses.
#[test]
fn the_trust_group_option_makes_no_gpg_check_when_gpg_verify_is_absent() {
    block_on(async {
        let dir = TmpDir::new("pull-http-trust-option-no-gpg-key");
        let (remote, commit) = build_remote(dir.path()).await;
        remote
            .sign_commit(&commit, &Ed25519Signer::from_base64(SECRET_B64).unwrap())
            .await
            .unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(
            dir.path(),
            RepoMode::Archive,
            &server.url(),
            &format!("[ex-ostrya trust \"t\"]\n{}", ed25519_group()),
        )
        .await;
        let dest_path = dir.path().join("dest");
        let config = dest_path.join("config");
        drop(dest);
        let text = std::fs::read_to_string(&config)
            .unwrap()
            .replacen("gpg-verify=false\n", "", 1);
        assert!(!text.contains("gpg-verify"), "{text}");
        std::fs::write(&config, text).unwrap();
        let dest = Repo::open(&dest_path).await.unwrap();

        let err = pull_main(&dest, PullOptions::default()).await.unwrap_err();
        let refused = if cfg!(feature = "verify-gpg") {
            matches!(&err, Error::Signature(_))
        } else {
            matches!(&err, Error::Unsupported(_))
        };
        assert!(refused, "{err}");
        assert_nothing_published(&dest).await;

        pull_main(&dest, group_options("t")).await.unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(commit)
        );
    });
}

/// Each refusal of the trust group option comes before the first request of
/// a pull over HTTP:
///
/// - a name that names no group, the empty name, and a name with a `"`;
/// - `Some(true)` in `gpg` or in `sign`;
/// - a remote key that turns on a commit check, and a key source of the
///   remote that no summary check reads.
#[test]
fn the_trust_group_option_refuses_before_the_first_request() {
    block_on(async {
        let dir = TmpDir::new("pull-http-trust-option-refusals");
        let _remote = build_signed_remote(dir.path(), Some(SECRET_B64)).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let group = format!("[ex-ostrya trust \"t\"]\n{}", ed25519_group());
        let malformed = |name: &str| {
            format!(
                "invalid input: malformed trust group name '{name}': the name is not empty, \
                 and holds no '\"' and no control character"
            )
        };
        let head = "invalid format: the pull takes its commit keys from \
                    [ex-ostrya trust \"t\"], and [remote \"origin\"]";
        let commit_check = "the trust group sets the commit checks";
        let gpg_on = PullVerify {
            gpg: Some(true),
            ..PullVerify::default()
        };
        let sign_on = PullVerify {
            sign: Some(true),
            ..PullVerify::default()
        };
        let input = |check: &str| {
            format!(
                "invalid input: the pull takes its commit keys from [ex-ostrya trust \"t\"], \
                 so it cannot turn on {check} of the commits"
            )
        };
        let rows: Vec<(&str, String, PullVerify, String)> = vec![
            (
                "nope",
                group.clone(),
                PullVerify::default(),
                "invalid input: the pull names the trust group 'nope', and the config has \
                 no [ex-ostrya trust \"nope\"] group"
                    .to_owned(),
            ),
            ("", group.clone(), PullVerify::default(), malformed("")),
            (
                "a\"b",
                group.clone(),
                PullVerify::default(),
                malformed("a\"b"),
            ),
            ("t", group.clone(), gpg_on, input("the GPG check")),
            ("t", group.clone(), sign_on, input("the sign-api check")),
            (
                "t",
                format!("gpg-verify=true\n{group}"),
                PullVerify::default(),
                format!(
                    "{head} sets gpg-verify=true: {commit_check}, so set gpg-verify=false or \
                     remove the key"
                ),
            ),
            (
                "t",
                format!("sign-verify=true\n{group}"),
                PullVerify::default(),
                format!("{head} sets sign-verify=true: {commit_check}, so remove sign-verify"),
            ),
            (
                "t",
                format!("sign-verify=ed25519\n{group}"),
                PullVerify::default(),
                format!("{head} sets sign-verify=ed25519: {commit_check}, so remove sign-verify"),
            ),
            (
                "t",
                format!("gpgkeypath=/nonexistent.gpg\n{group}"),
                PullVerify::default(),
                format!(
                    "{head} sets gpgkeypath, and gpg-verify-summary is not true, so no check \
                     reads it"
                ),
            ),
            (
                "t",
                format!("verification-ed25519-key={OTHER_PUBLIC_B64}\n{group}"),
                PullVerify::default(),
                format!(
                    "{head} holds 'verification-ed25519-key', and sign-verify-summary does \
                     not select ed25519, so no check reads it"
                ),
            ),
        ];
        for (name, extra, verify, reason) in rows {
            let _ = std::fs::remove_dir_all(dir.path().join("dest"));
            let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), &extra).await;
            let err = pull_main(
                &dest,
                PullOptions {
                    verify,
                    ..group_options(name)
                },
            )
            .await
            .unwrap_err();
            assert_eq!(err.to_string(), reason, "{name:?} {extra:?}");
            assert_nothing_published(&dest).await;
            assert!(server.seen().is_empty(), "{extra:?}: {:?}", server.seen());
        }
    });
}

// --- subpaths ----------------------------------------------------------------

/// Builds a source tree under `dir` with siblings of distinct content. The tree
/// holds the files `top`, `a`, `sub/f1`, `sub/deeper/f2`, and `other/g`. It
/// also holds one directory `x` with the same content under `sub` and `other`.
fn build_subpath_tree(dir: &Path) {
    for d in ["sub/deeper", "sub/x", "other/x"] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
    }
    for (path, bytes) in [
        ("top", &b"top\n"[..]),
        ("a", b"a\n"),
        ("sub/f1", b"f1\n"),
        ("sub/deeper/f2", b"f2\n"),
        ("other/g", b"g\n"),
        ("sub/x/s", b"same\n"),
        ("other/x/s", b"same\n"),
    ] {
        std::fs::write(dir.join(path), bytes).unwrap();
    }
}

/// Builds a remote under `dir/remote` that holds `test/main` over the subpath
/// tree. The remote has no summary, so a pull probes for a delta by name.
async fn build_subpath_remote(dir: &Path) -> (Repo, Checksum) {
    build_subpath_tree(&dir.join("src"));
    let repo = Repo::create(&dir.join("remote"), CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap();
    let commit = commit_tree(&repo, dir, "src", "test/main", None, FIXED_TS).await;
    (repo, commit)
}

/// Returns the objects of the entry at `path` in `commit`. For a file, this is
/// the file object. For a directory, it is the dirtree and the dirmeta.
async fn entry_objects(repo: &Repo, commit: &Checksum, path: &str) -> Vec<ostrya::ObjectName> {
    use ostrya::{ObjectName, ObjectType};
    let (commit, _) = repo.load_commit(commit).await.unwrap();
    let mut tree = commit.root_dirtree;
    let mut meta = commit.root_dirmeta;
    let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    for (i, name) in components.iter().enumerate() {
        let dirtree = repo.load_dirtree(&tree).await.unwrap();
        if let Some((_, file)) = dirtree.files.iter().find(|(n, _)| n == name) {
            assert_eq!(i + 1, components.len(), "{path}: a file mid-path");
            return vec![ObjectName::new(*file, ObjectType::File)];
        }
        let (_, t, m) = dirtree.dirs.iter().find(|(n, _, _)| n == name).unwrap();
        tree = *t;
        meta = *m;
    }
    vec![
        ObjectName::new(tree, ObjectType::DirTree),
        ObjectName::new(meta, ObjectType::DirMeta),
    ]
}

/// Returns each object under the directory at `path` in `commit`. The set
/// includes the dirtree and the dirmeta of the directory itself.
async fn whole_objects(repo: &Repo, commit: &Checksum, path: &str) -> HashSet<ostrya::ObjectName> {
    use ostrya::{ObjectName, ObjectType};
    let own = entry_objects(repo, commit, path).await;
    let mut out: HashSet<ObjectName> = own.iter().copied().collect();
    let mut stack = vec![own[0].checksum];
    while let Some(tree) = stack.pop() {
        let dirtree = repo.load_dirtree(&tree).await.unwrap();
        for (_, file) in &dirtree.files {
            out.insert(ObjectName::new(*file, ObjectType::File));
        }
        for (_, t, m) in &dirtree.dirs {
            out.insert(ObjectName::new(*t, ObjectType::DirTree));
            out.insert(ObjectName::new(*m, ObjectType::DirMeta));
            stack.push(*t);
        }
    }
    out
}

/// Returns the objects that each subpath pull of `commit` fetches. These are
/// the commit, the root dirtree, and the root dirmeta.
async fn subpath_base(repo: &Repo, commit: &Checksum) -> HashSet<ostrya::ObjectName> {
    use ostrya::{ObjectName, ObjectType};
    let mut out: HashSet<ObjectName> = entry_objects(repo, commit, "/").await.into_iter().collect();
    out.insert(ObjectName::new(*commit, ObjectType::Commit));
    out
}

fn subpath_opts(values: &[&str]) -> PullOptions {
    PullOptions {
        refs: vec!["test/main".to_owned()],
        subpaths: values.iter().map(|v| (*v).to_owned()).collect(),
        ..PullOptions::default()
    }
}

/// Asserts that the destination at `dest` holds the zero-length marker that a
/// subpath pull leaves on `commit`.
fn assert_partial_marker(dest: &Path, commit: &Checksum) {
    let marker = dest
        .join("state")
        .join(format!("{}.commitpartial", commit.to_hex()));
    assert_eq!(std::fs::metadata(&marker).unwrap().len(), 0, "{marker:?}");
}

/// Each subpath form fetches these objects and no others:
///
/// - the commit, the root dirtree, and the root dirmeta
/// - the directories on the path
/// - the whole entry that the path names.
///
/// The pull writes the ref. The commit stays partial, with a zero-length
/// marker.
#[test]
fn a_subpath_pull_fetches_the_path_and_leaves_the_commit_partial() {
    block_on(async {
        let dir = TmpDir::new("pull-http-subpath-forms");
        let (remote, commit) = build_subpath_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let base = subpath_base(&remote, &commit).await;
        let on_path = |paths: &[&str]| {
            let paths: Vec<String> = paths.iter().map(|p| (*p).to_owned()).collect();
            let remote = &remote;
            async move {
                let mut out = HashSet::new();
                for p in &paths {
                    out.extend(entry_objects(remote, &commit, p).await);
                }
                out
            }
        };
        let cases: Vec<(Vec<&str>, HashSet<ostrya::ObjectName>)> = vec![
            (vec!["/sub"], whole_objects(&remote, &commit, "/sub").await),
            (vec!["/a"], on_path(&["/a"]).await),
            (vec!["/nonexist"], HashSet::new()),
            (vec!["/"], HashSet::new()),
            (vec!["/sub/"], on_path(&["/sub"]).await),
            (vec!["/a/", "//sub", "/./sub"], HashSet::new()),
            (vec!["/sub/f1/x"], on_path(&["/sub"]).await),
            (vec!["/sub/deeper"], {
                let mut s = whole_objects(&remote, &commit, "/sub/deeper").await;
                s.extend(on_path(&["/sub"]).await);
                s
            }),
            (vec!["/sub/deeper", "/a"], {
                let mut s = whole_objects(&remote, &commit, "/sub/deeper").await;
                s.extend(on_path(&["/sub", "/a"]).await);
                s
            }),
        ];
        for (i, (values, extra)) in cases.into_iter().enumerate() {
            let case = dir.path().join(i.to_string());
            std::fs::create_dir(&case).unwrap();
            let dest = build_dest(&case, RepoMode::Archive, &server.url(), "").await;
            dest.pull("origin", subpath_opts(&values)).await.unwrap();
            let mut expected = base.clone();
            expected.extend(extra);
            assert_eq!(dest.list_objects().await.unwrap(), expected, "{values:?}");
            assert_eq!(
                dest.resolve_rev("origin:test/main", true).await.unwrap(),
                Some(commit),
                "{values:?}"
            );
            assert_eq!(
                dest.commit_state(&commit).await.unwrap(),
                CommitState::Partial,
                "{values:?}"
            );
            assert_partial_marker(&case.join("dest"), &commit);
        }
    });
}

/// A pull without subpaths completes a commit that a subpath pull left partial.
/// It removes the marker of the commit. A subpath pull of a commit that is
/// already complete here leaves it complete.
#[test]
fn a_full_pull_completes_a_subpath_pull() {
    block_on(async {
        let dir = TmpDir::new("pull-http-subpath-full");
        let (_remote, commit) = build_subpath_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;
        dest.pull("origin", subpath_opts(&["/sub"])).await.unwrap();
        assert_partial_marker(&dir.path().join("dest"), &commit);

        dest.pull("origin", subpath_opts(&[])).await.unwrap();
        assert_eq!(
            dest.commit_state(&commit).await.unwrap(),
            CommitState::Normal
        );
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());

        dest.pull("origin", subpath_opts(&["/sub"])).await.unwrap();
        assert_eq!(
            dest.commit_state(&commit).await.unwrap(),
            CommitState::Normal
        );
    });
}

/// If two subpath positions reach one dirtree, the pull walks it under both. If
/// a subpath names `x` whole under `other`, the pull fetches its file in either
/// order. If both subpaths name `x` as a directory alone, the pull fetches no
/// file.
#[test]
fn a_dirtree_at_two_subpath_positions_takes_the_union() {
    block_on(async {
        let dir = TmpDir::new("pull-http-subpath-shared");
        let (remote, commit) = build_subpath_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let shared = entry_objects(&remote, &commit, "/sub/x/s").await[0];
        for (i, (values, fetched)) in [
            (["/sub/x/", "/other/x"], true),
            (["/other/x", "/sub/x/"], true),
            (["/other/x/", "/sub/x/"], false),
        ]
        .into_iter()
        .enumerate()
        {
            let case = dir.path().join(i.to_string());
            std::fs::create_dir(&case).unwrap();
            let dest = build_dest(&case, RepoMode::Archive, &server.url(), "").await;
            dest.pull("origin", subpath_opts(&values)).await.unwrap();
            let objects = dest.list_objects().await.unwrap();
            assert_eq!(objects.contains(&shared), fetched, "{values:?}");
            for p in ["/sub/x", "/other/x"] {
                for name in entry_objects(&remote, &commit, p).await {
                    assert!(objects.contains(&name), "{values:?}: {p}");
                }
            }
        }
    });
}

/// Subpaths combine with other options:
///
/// - Under `depth`, the pull walks each commit that it reaches under the same
///   subpaths and leaves each one partial.
/// - Under `COMMIT_ONLY`, the pull fetches the commit alone.
/// - Under `MIRROR`, the pull writes the ref as a local ref.
#[test]
fn subpaths_combine_with_depth_commit_only_and_mirror() {
    block_on(async {
        let dir = TmpDir::new("pull-http-subpath-combined");
        let (remote, first) = build_subpath_remote(dir.path()).await;
        std::fs::write(dir.path().join("src/sub/f3"), b"f3\n").unwrap();
        let second = commit_tree(
            &remote,
            dir.path(),
            "src",
            "test/main",
            Some(first),
            FIXED_TS + 1,
        )
        .await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;

        let case = dir.path().join("depth");
        std::fs::create_dir(&case).unwrap();
        let dest = build_dest(&case, RepoMode::Archive, &server.url(), "").await;
        dest.pull(
            "origin",
            PullOptions {
                depth: 1,
                ..subpath_opts(&["/sub/deeper"])
            },
        )
        .await
        .unwrap();
        let objects = dest.list_objects().await.unwrap();
        for commit in [first, second] {
            assert_partial_marker(&case.join("dest"), &commit);
            for name in whole_objects(&remote, &commit, "/sub/deeper").await {
                assert!(objects.contains(&name));
            }
            for name in entry_objects(&remote, &commit, "/sub/f1").await {
                assert!(!objects.contains(&name));
            }
        }

        let case = dir.path().join("commit-only");
        std::fs::create_dir(&case).unwrap();
        let dest = build_dest(&case, RepoMode::Archive, &server.url(), "").await;
        dest.pull(
            "origin",
            PullOptions {
                flags: PullFlags::COMMIT_ONLY,
                ..subpath_opts(&["/sub"])
            },
        )
        .await
        .unwrap();
        assert_eq!(
            dest.list_objects().await.unwrap(),
            HashSet::from([ostrya::ObjectName::new(second, ostrya::ObjectType::Commit)])
        );
        assert_partial_marker(&case.join("dest"), &second);

        let case = dir.path().join("mirror");
        std::fs::create_dir(&case).unwrap();
        let dest = build_dest(&case, RepoMode::Archive, &server.url(), "").await;
        dest.pull(
            "origin",
            PullOptions {
                flags: PullFlags::MIRROR,
                ..subpath_opts(&["/sub"])
            },
        )
        .await
        .unwrap();
        assert_eq!(
            dest.resolve_rev("test/main", true).await.unwrap(),
            Some(second)
        );
        assert_partial_marker(&case.join("dest"), &second);
    });
}

/// A subpath pull applies a from-scratch delta whole, as the `ostree` command
/// does. The commit keeps its marker.
#[test]
fn a_subpath_pull_applies_a_delta_whole() {
    block_on(async {
        let dir = TmpDir::new("pull-http-subpath-delta");
        let (remote, commit) = build_subpath_remote(dir.path()).await;
        remote
            .generate_static_delta(
                None,
                &commit,
                &DeltaOptions {
                    timestamp: Some(FIXED_TS),
                    ..DeltaOptions::default()
                },
            )
            .await
            .unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;
        dest.pull("origin", subpath_opts(&["/sub/deeper"]))
            .await
            .unwrap();
        let everything = remote.traverse_commit(&commit, 0).await.unwrap();
        assert_eq!(dest.list_objects().await.unwrap(), everything);
        assert_partial_marker(&dir.path().join("dest"), &commit);
        assert!(
            !server.seen().iter().any(|p| p.ends_with(".filez")),
            "{:?}",
            server.seen()
        );
    });
}

/// A subpath pull into an `archive` destination takes no delta. It fetches the
/// subpath as loose objects and requests no part.
#[test]
fn a_subpath_pull_into_an_archive_takes_no_delta() {
    block_on(async {
        let dir = TmpDir::new("pull-http-subpath-delta-archive");
        let (remote, commit) = build_subpath_remote(dir.path()).await;
        remote
            .generate_static_delta(
                None,
                &commit,
                &DeltaOptions {
                    timestamp: Some(FIXED_TS),
                    ..DeltaOptions::default()
                },
            )
            .await
            .unwrap();
        remote
            .regenerate_summary(&SummaryOptions {
                last_modified: Some(FIXED_TS),
                ..SummaryOptions::default()
            })
            .await
            .unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        dest.pull("origin", subpath_opts(&["/sub/deeper"]))
            .await
            .unwrap();
        let mut expected = subpath_base(&remote, &commit).await;
        expected.extend(whole_objects(&remote, &commit, "/sub/deeper").await);
        expected.extend(entry_objects(&remote, &commit, "/sub").await);
        assert_eq!(dest.list_objects().await.unwrap(), expected);
        assert_partial_marker(&dir.path().join("dest"), &commit);
        assert!(
            !server.seen().iter().any(|p| p.contains("deltas/")),
            "{:?}",
            server.seen()
        );
        // A pull that requires static deltas takes the delta in this case too.
        let required = dir.path().join("required");
        std::fs::create_dir(&required).unwrap();
        let dest = build_dest(&required, RepoMode::Archive, &server.url(), "").await;
        dest.pull(
            "origin",
            PullOptions {
                require_static_deltas: true,
                ..subpath_opts(&["/sub/deeper"])
            },
        )
        .await
        .unwrap();
        assert!(
            server.seen().iter().any(|p| p.contains("deltas/")),
            "{:?}",
            server.seen()
        );
        assert_partial_marker(&required.join("dest"), &commit);
    });
}

/// The destination holds a commit object partial, under a ref that names it.
/// The pull looks for a delta for this commit.
///
/// With a summary, the pull leaves the from-scratch delta alone. A subpath pull
/// after a commit-only pull fetches the missing objects as loose objects. A
/// full pull after the subpath pull does the same.
///
/// With no summary, the subpath pull requests the from-scratch delta by name
/// and applies it whole. The commit keeps its marker.
#[test]
fn a_commit_held_partial_under_its_ref_takes_a_delta_only_by_name() {
    block_on(async {
        let tmp = TmpDir::new("pull-http-subpath-delta-partial");
        for summary in [true, false] {
            let dir = tmp.path().join(if summary { "summary" } else { "bare" });
            std::fs::create_dir(&dir).unwrap();
            let (remote, commit) = build_subpath_remote(&dir).await;
            remote
                .generate_static_delta(
                    None,
                    &commit,
                    &DeltaOptions {
                        timestamp: Some(FIXED_TS),
                        ..DeltaOptions::default()
                    },
                )
                .await
                .unwrap();
            if summary {
                remote
                    .regenerate_summary(&SummaryOptions {
                        last_modified: Some(FIXED_TS),
                        ..SummaryOptions::default()
                    })
                    .await
                    .unwrap();
            }
            let server = RepoServer::start(&dir.join("remote"), false).await;
            let dest = build_dest(&dir, RepoMode::BareUser, &server.url(), "").await;
            dest.pull(
                "origin",
                PullOptions {
                    flags: PullFlags::COMMIT_ONLY,
                    ..subpath_opts(&[])
                },
            )
            .await
            .unwrap();
            dest.pull("origin", subpath_opts(&["/sub/deeper"]))
                .await
                .unwrap();
            let everything = remote.traverse_commit(&commit, 0).await.unwrap();
            if summary {
                let mut expected = subpath_base(&remote, &commit).await;
                expected.extend(whole_objects(&remote, &commit, "/sub/deeper").await);
                expected.extend(entry_objects(&remote, &commit, "/sub").await);
                assert_eq!(dest.list_objects().await.unwrap(), expected);
            } else {
                assert_eq!(dest.list_objects().await.unwrap(), everything);
            }
            assert_partial_marker(&dir.join("dest"), &commit);
            let superblocks = server
                .seen()
                .iter()
                .filter(|p| p.ends_with("/superblock"))
                .count();
            assert_eq!(superblocks, usize::from(!summary), "{:?}", server.seen());
            dest.pull("origin", subpath_opts(&[])).await.unwrap();
            assert_eq!(dest.list_objects().await.unwrap(), everything);
            assert_eq!(
                dest.commit_state(&commit).await.unwrap(),
                CommitState::Normal
            );
            if summary {
                assert!(
                    !server.seen().iter().any(|p| p.ends_with("/superblock")),
                    "{:?}",
                    server.seen()
                );
            }
        }
    });
}

/// A relative or empty subpath is refused before the first request.
#[test]
fn a_relative_or_empty_subpath_is_refused() {
    block_on(async {
        let dir = TmpDir::new("pull-http-subpath-relative");
        build_subpath_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        for value in ["sub", ""] {
            let err = dest
                .pull("origin", subpath_opts(&[value]))
                .await
                .unwrap_err();
            assert!(matches!(err, Error::Pull(_)), "{value:?}: {err}");
        }
        assert!(server.seen().is_empty(), "{:?}", server.seen());
        assert_nothing_published(&dest).await;
        assert!(dest.list_objects().await.unwrap().is_empty());
    });
}

/// The pull refuses a depth less than -1 before the first request.
#[test]
fn a_depth_below_minus_one_is_refused() {
    block_on(async {
        let dir = TmpDir::new("pull-http-depth-refused");
        build_subpath_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        for depth in [-2, -3, i32::MIN] {
            let opts = PullOptions {
                depth,
                ..subpath_opts(&[])
            };
            let err = dest.pull("origin", opts).await.unwrap_err();
            match &err {
                Error::InvalidInput(msg) => {
                    assert!(msg.contains(&format!("depth {depth} is below -1")), "{msg}")
                }
                other => panic!("{depth}: {other:?}"),
            }
        }
        assert!(server.seen().is_empty(), "{:?}", server.seen());
        assert_nothing_published(&dest).await;
        assert!(dest.list_objects().await.unwrap().is_empty());
    });
}

/// The pull refuses a `static_deltas` list that it cannot take with
/// `InvalidInput`. Each refusal comes before the first request and before the
/// transaction opens, so the pull writes no object, no ref, and no staging
/// directory.
#[test]
fn a_static_delta_list_is_refused_before_the_first_request() {
    block_on(async {
        let dir = TmpDir::new("pull-http-static-delta-list-refused");
        build_subpath_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        let dest_dir = dir.path().join("dest");
        let before = repo_snapshot(&dest_dir);
        for (tag, opts, expected) in static_delta_list_cases(|| subpath_opts(&[])) {
            let err = dest.pull("origin", opts).await.unwrap_err();
            assert_list_refusal(tag, &err, &expected);
        }
        assert!(server.seen().is_empty(), "{:?}", server.seen());
        assert_nothing_published(&dest).await;
        assert!(dest.list_objects().await.unwrap().is_empty());
        assert_eq!(repo_snapshot(&dest_dir), before);
        let staging = std::fs::read_dir(dest_dir.join("tmp"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("staging-"))
            .collect::<Vec<_>>();
        assert!(staging.is_empty(), "{staging:?}");
    });
}

/// The pull refuses a `remote` option that is not a valid remote name, also
/// under `MIRROR`. The refusal comes before the pull resolves the remote, so
/// it sends no request and writes no object and no ref.
#[test]
fn an_invalid_remote_option_is_refused_before_the_first_request() {
    block_on(async {
        let dir = TmpDir::new("pull-http-remote-option-refused");
        build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        let dest_dir = dir.path().join("dest");
        let before = repo_snapshot(&dest_dir);
        for flags in [PullFlags::NONE, PullFlags::MIRROR] {
            for name in ["a:b", "a/b", ""] {
                let opts = PullOptions {
                    refs: vec!["test/main".to_owned()],
                    remote: Some(name.to_owned()),
                    flags,
                    ..PullOptions::default()
                };
                let err = dest.pull("origin", opts).await.unwrap_err();
                assert!(
                    matches!(&err, Error::InvalidInput(m) if *m == format!("invalid remote name: {name}")),
                    "{name:?}: {err:?}"
                );
            }
        }
        assert!(server.seen().is_empty(), "{:?}", server.seen());
        assert_eq!(repo_snapshot(&dest_dir), before);
    });
}

/// Builds a remote archive repository under `dir/remote` with two commits on
/// `test/main`. The second commit is a child of the first. Both commits hold
/// the small tree, each with a different marker. The remote holds no delta and
/// no summary.
///
/// Returns the remote and the two commits, the first commit first.
async fn build_remote_two_commits(dir: &Path) -> (Repo, Checksum, Checksum) {
    build_tree(&dir.join("one"), b"one\n");
    build_tree(&dir.join("two"), b"two\n");
    let repo = Repo::create(&dir.join("remote"), CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap();
    let first = commit_tree(&repo, dir, "one", "test/main", None, FIXED_TS).await;
    let second = commit_tree(&repo, dir, "two", "test/main", Some(first), FIXED_TS + 1).await;
    (repo, first, second)
}

/// Generates a delta in `repo` with a fixed timestamp, then the summary.
async fn publish_delta(repo: &Repo, from: Option<&Checksum>, to: &Checksum) {
    repo.generate_static_delta(
        from,
        to,
        &DeltaOptions {
            timestamp: Some(FIXED_TS),
            ..DeltaOptions::default()
        },
    )
    .await
    .unwrap();
    repo.regenerate_summary(&SummaryOptions {
        last_modified: Some(FIXED_TS),
        ..SummaryOptions::default()
    })
    .await
    .unwrap();
}

/// Returns the options of a pull of `test/main` that requires static deltas.
fn required_delta_opts() -> PullOptions {
    PullOptions {
        refs: vec!["test/main".to_owned()],
        require_static_deltas: true,
        ..PullOptions::default()
    }
}

/// Builds a destination under `dir/dest` that holds `commit` complete, with no
/// ref. The commit comes from `dir/remote`.
async fn dest_holding(dir: &Path, url: &str, commit: &Checksum) -> Repo {
    let dest = build_dest(dir, RepoMode::BareUser, url, "").await;
    let remote = Repo::open(&dir.join("remote")).await.unwrap();
    dest.pull_local(
        &remote,
        PullOptions {
            refs: vec![commit.to_hex()],
            flags: PullFlags::DISABLE_VERIFY_BINDINGS,
            ..PullOptions::default()
        },
    )
    .await
    .unwrap();
    // A local pull of a checksum writes a ref with that name. This destination
    // does not keep the ref.
    let txn = dest.transaction().await.unwrap();
    txn.set_ref(&commit.to_hex(), None);
    txn.commit().await.unwrap();
    assert!(dest.list_refs(None).await.unwrap().is_empty());
    dest
}

/// The pull requires static deltas, and the destination holds the source of no
/// advertised delta. The summary advertises a delta from another commit. The
/// pull is refused, publishes nothing, and requests no object.
#[test]
fn required_deltas_refuse_a_summary_naming_no_usable_delta() {
    block_on(async {
        let dir = TmpDir::new("pull-http-require-none-usable");
        let (remote, first, second) = build_remote_two_commits(dir.path()).await;
        publish_delta(&remote, Some(&first), &second).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;

        let err = dest
            .pull("origin", required_delta_opts())
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("pull: Static deltas required, but none found for test/main to {second}")
        );
        assert_nothing_published(&dest).await;
        assert!(dest.list_objects().await.unwrap().is_empty());
        assert!(
            !server
                .seen()
                .iter()
                .any(|p| p.starts_with("objects/") || p.ends_with("/superblock")),
            "{:?}",
            server.seen()
        );
    });
}

/// A pull that requires static deltas from a summary that lists no delta is
/// refused with the same message.
#[test]
fn required_deltas_refuse_a_summary_listing_no_delta() {
    block_on(async {
        let dir = TmpDir::new("pull-http-require-no-delta");
        let (_remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;

        let err = dest
            .pull("origin", required_delta_opts())
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("pull: Static deltas required, but none found for test/main to {commit}")
        );
        assert_nothing_published(&dest).await;
        assert!(dest.list_objects().await.unwrap().is_empty());
    });
}

/// A pull that requires static deltas from a remote with no summary is refused
/// before it requests a delta by name.
#[test]
fn required_deltas_refuse_a_remote_with_no_summary() {
    block_on(async {
        let dir = TmpDir::new("pull-http-require-no-summary");
        let (remote, _first, second) = build_remote_two_commits(dir.path()).await;
        remote
            .generate_static_delta(
                None,
                &second,
                &DeltaOptions {
                    timestamp: Some(FIXED_TS),
                    ..DeltaOptions::default()
                },
            )
            .await
            .unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;

        let err = dest
            .pull("origin", required_delta_opts())
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "pull: Fetch configured to require static deltas, but no summary deltas or \
             delta index found"
        );
        assert_nothing_published(&dest).await;
        assert!(
            !server.seen().iter().any(|p| p.contains("deltas/")),
            "{:?}",
            server.seen()
        );
    });
}

/// The summary advertises a superblock that the remote does not hold. A pull
/// that requires static deltas fails. A pull that does not require them fetches
/// the objects as loose objects.
#[test]
fn required_deltas_refuse_a_stale_advertisement() {
    block_on(async {
        let dir = TmpDir::new("pull-http-require-stale");
        let (remote, _first, second) = build_remote_two_commits(dir.path()).await;
        publish_delta(&remote, None, &second).await;
        std::fs::remove_dir_all(dir.path().join("remote/deltas")).unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;

        let err = dest
            .pull("origin", required_delta_opts())
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("pull: Static deltas required, but none found for test/main to {second}")
        );
        assert_nothing_published(&dest).await;
        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            dest.commit_state(&second).await.unwrap(),
            CommitState::Normal
        );
    });
}

/// A destination that holds the source of a from-to delta takes that delta, for
/// any value of its own ref. In this test, it holds the source commit under no
/// ref.
#[test]
fn a_from_to_delta_is_taken_from_any_commit_held_complete() {
    block_on(async {
        let dir = TmpDir::new("pull-http-delta-held-source");
        let (remote, first, second) = build_remote_two_commits(dir.path()).await;
        publish_delta(&remote, Some(&first), &second).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = dest_holding(dir.path(), &server.url(), &first).await;
        assert!(
            dest.list_refs(Some("refs/remotes"))
                .await
                .unwrap()
                .is_empty()
        );
        server.forget();

        dest.pull("origin", required_delta_opts()).await.unwrap();
        assert_eq!(
            dest.commit_state(&second).await.unwrap(),
            CommitState::Normal
        );
        let seen = server.seen();
        assert!(seen.iter().any(|p| p.ends_with("/superblock")), "{seen:?}");
        assert!(!seen.iter().any(|p| p.ends_with(".filez")), "{seen:?}");
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
    });
}

/// If the ref of a destination names a commit that it holds, the pull leaves an
/// advertised from-scratch delta alone. This is also true when static deltas
/// are required. That pull fetches the objects as loose objects and is not
/// refused.
#[test]
fn required_deltas_pass_a_declined_from_scratch_delta() {
    block_on(async {
        let dir = TmpDir::new("pull-http-require-declined-scratch");
        let (remote, first, second) = build_remote_two_commits(dir.path()).await;
        publish_delta(&remote, None, &second).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = dest_holding(dir.path(), &server.url(), &first).await;
        let txn = dest.transaction().await.unwrap();
        txn.set_ref("origin:test/main", Some(&first));
        txn.commit().await.unwrap();
        server.forget();

        dest.pull("origin", required_delta_opts()).await.unwrap();
        assert_eq!(
            dest.commit_state(&second).await.unwrap(),
            CommitState::Normal
        );
        let seen = server.seen();
        assert!(!seen.iter().any(|p| p.ends_with("/superblock")), "{seen:?}");
        assert!(seen.iter().any(|p| p.ends_with(".filez")), "{seen:?}");
    });
}

/// If a destination holds the commit object partial, the pull looks for a delta
/// for it. The test pulls with required static deltas.
///
/// If the summary advertises no delta, the pull is refused and fetches no
/// object. If the summary advertises the from-scratch delta, the ref names that
/// commit, so the pull requests the delta index and leaves the delta alone. It
/// fetches the objects as loose objects and is not refused.
#[test]
fn required_deltas_look_for_a_delta_for_a_commit_held_partial() {
    block_on(async {
        let dir = TmpDir::new("pull-http-require-partial");
        let (remote, _first, second) = build_remote_two_commits(dir.path()).await;
        remote
            .regenerate_summary(&SummaryOptions {
                last_modified: Some(FIXED_TS),
                ..SummaryOptions::default()
            })
            .await
            .unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let commit_only = PullOptions {
            refs: vec!["test/main".to_owned()],
            flags: PullFlags::COMMIT_ONLY,
            ..PullOptions::default()
        };
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;
        dest.pull("origin", commit_only.clone()).await.unwrap();
        let held = dest.list_objects().await.unwrap();
        server.forget();

        let err = dest
            .pull("origin", required_delta_opts())
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("pull: Static deltas required, but none found for test/main to {second}")
        );
        assert_eq!(dest.list_objects().await.unwrap(), held);
        assert_eq!(
            dest.commit_state(&second).await.unwrap(),
            CommitState::Partial
        );
        let seen = server.seen();
        assert!(!seen.iter().any(|p| p.starts_with("objects/")), "{seen:?}");

        drop(dest);
        std::fs::remove_dir_all(dir.path().join("dest")).unwrap();
        publish_delta(&remote, None, &second).await;
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;
        dest.pull("origin", commit_only).await.unwrap();
        server.forget();

        dest.pull("origin", required_delta_opts()).await.unwrap();
        assert_eq!(
            dest.commit_state(&second).await.unwrap(),
            CommitState::Normal
        );
        let seen = server.seen();
        assert!(seen.iter().any(|p| p.ends_with(".index")), "{seen:?}");
        assert!(!seen.iter().any(|p| p.ends_with("/superblock")), "{seen:?}");
        assert!(seen.iter().any(|p| p.ends_with(".filez")), "{seen:?}");
    });
}

// --- chains of static deltas -----------------------------------------------

/// Creates an empty archive repository under `dir/remote`.
async fn create_remote(dir: &Path) -> Repo {
    Repo::create(&dir.join("remote"), CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap()
}

/// Builds the small tree under `dir/<name>` with the marker `<name>`, and
/// commits it into `remote` on `branch`, with `parent` and the timestamp
/// `FIXED_TS + offset`.
async fn chain_commit(
    remote: &Repo,
    dir: &Path,
    name: &str,
    branch: &str,
    parent: Option<Checksum>,
    offset: u64,
) -> Checksum {
    build_tree(&dir.join(name), format!("{name}\n").as_bytes());
    commit_tree(remote, dir, name, branch, parent, FIXED_TS + offset).await
}

/// Builds a remote archive repository under `dir/remote` with the commits A,
/// B, C, and D on `test/main`. Each commit is a child of the commit before it,
/// and holds the small tree with its own marker. The remote holds no summary
/// and no delta.
///
/// Returns the remote and the four commits, A first.
async fn build_chain_remote(dir: &Path) -> (Repo, [Checksum; 4]) {
    let remote = create_remote(dir).await;
    let mut commits = Vec::new();
    let mut parent = None;
    for (offset, name) in ["a", "b", "c", "d"].into_iter().enumerate() {
        let commit = chain_commit(&remote, dir, name, "test/main", parent, offset as u64).await;
        commits.push(commit);
        parent = Some(commit);
    }
    (remote, commits.try_into().unwrap())
}

/// Signs each commit of `commits` in `remote` with the key of `SECRET_B64`.
async fn sign_commits(remote: &Repo, commits: &[Checksum]) {
    let signer = Ed25519Signer::from_base64(SECRET_B64).unwrap();
    for commit in commits {
        remote.sign_commit(commit, &signer).await.unwrap();
    }
}

/// Generates the delta from `from` to `to` in `remote` with `opts` and a fixed
/// timestamp. Returns the entry of the delta for a list, with the SHA-256 of
/// its superblock.
async fn listed(
    remote: &Repo,
    from: &Checksum,
    to: &Checksum,
    opts: DeltaOptions,
) -> AdvertisedDelta {
    let opts = DeltaOptions {
        timestamp: Some(FIXED_TS),
        ..opts
    };
    remote
        .generate_static_delta(Some(from), to, &opts)
        .await
        .unwrap();
    let bytes = std::fs::read(remote.path().join(superblock_path(from, to))).unwrap();
    AdvertisedDelta {
        from: Some(*from),
        to: *to,
        superblock: Checksum::sha256(&bytes),
    }
}

/// Returns the request path of the superblock of the delta from `from` to
/// `to`.
fn superblock_path(from: &Checksum, to: &Checksum) -> String {
    format!("{}/superblock", static_delta_relative_dir(Some(from), to))
}

/// Returns the request path of each part file of the delta from `from` to
/// `to` in `remote`, in part order. The delta holds no inline part.
fn part_paths(remote: &Repo, from: &Checksum, to: &Checksum) -> Vec<String> {
    let dir = static_delta_relative_dir(Some(from), to);
    let bytes = std::fs::read(remote.path().join(superblock_path(from, to))).unwrap();
    let parts = DeltaSuperblock::parse(bytes).unwrap().parts().len();
    assert!(parts > 0, "{dir} has no part");
    (0..parts).map(|index| format!("{dir}/{index}")).collect()
}

/// Returns the position in `seen` of each request for a path of `paths`, in
/// order.
fn positions(seen: &[String], paths: &[String]) -> Vec<usize> {
    seen.iter()
        .enumerate()
        .filter(|(_, path)| paths.contains(path))
        .map(|(index, _)| index)
        .collect()
}

/// Asserts that each path of `paths` is requested once in `seen`, and that
/// each of these requests comes before each request for a path of `later`.
fn assert_before(seen: &[String], paths: &[String], later: &[String]) {
    let first = positions(seen, paths);
    let second = positions(seen, later);
    assert_eq!(first.len(), paths.len(), "{paths:?}: {seen:?}");
    assert!(!second.is_empty(), "{later:?}: {seen:?}");
    assert!(
        first.iter().max() < second.iter().min(),
        "{paths:?} before {later:?}: {seen:?}"
    );
}

/// Asserts that the repository at `dest_dir` keeps no `.commitpartial`
/// marker.
fn assert_no_markers(dest_dir: &Path) {
    let markers: Vec<String> = std::fs::read_dir(dest_dir.join("state"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".commitpartial"))
        .collect();
    assert!(markers.is_empty(), "{markers:?}");
}

/// Returns the options of a pull of `test/main` with the list `list`.
fn chain_opts(list: Vec<AdvertisedDelta>) -> PullOptions {
    PullOptions {
        refs: vec!["test/main".to_owned()],
        static_deltas: Some(list),
        ..PullOptions::default()
    }
}

/// The policy keys that check each commit against the key of `PUBLIC_B64`.
fn signed_policy() -> String {
    format!("sign-verify=ed25519\nverification-ed25519-key={PUBLIC_B64}\n")
}

/// A pull applies a chain of three static deltas from the commit that the
/// destination holds. The remote serves no summary. The pull requests the
/// three superblocks and their parts, and no loose object of a tree, no
/// commit object, and no delta index. The parts of each step come after the
/// parts of the step before it. Each intermediate commit ends complete with
/// no marker.
#[test]
fn a_chain_of_three_steps_is_applied_with_no_loose_request() {
    block_on(async {
        let dir = TmpDir::new("pull-http-chain-three-steps");
        let (remote, [a, b, c, d]) = build_chain_remote(dir.path()).await;
        let steps = [(a, b), (b, c), (c, d)];
        let mut list = Vec::new();
        for (from, to) in &steps {
            list.push(listed(&remote, from, to, DeltaOptions::default()).await);
        }
        let server = RepoServer::start(remote.path(), false).await;
        let dest = dest_holding(dir.path(), &server.url(), &a).await;
        let dest_dir = dir.path().join("dest");
        server.forget();

        let stats = dest.pull("origin", chain_opts(list)).await.unwrap();

        let seen = server.seen();
        let superblocks: HashSet<String> = seen
            .iter()
            .filter(|path| path.ends_with("/superblock"))
            .cloned()
            .collect();
        let expected: HashSet<String> = steps
            .iter()
            .map(|(from, to)| superblock_path(from, to))
            .collect();
        assert_eq!(superblocks, expected);
        for ext in [".filez", ".dirtree", ".dirmeta", ".index", ".commit"] {
            assert!(
                !seen.iter().any(|path| path.ends_with(ext)),
                "{ext}: {seen:?}"
            );
        }
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(d)
        );
        for commit in [b, c, d] {
            assert_complete(&remote, &dest, &dest_dir, &commit).await;
        }
        assert_no_markers(&dest_dir);
        assert_eq!(stats.content_fetched, 0);
        let parts: Vec<Vec<String>> = steps
            .iter()
            .map(|(from, to)| part_paths(&remote, from, to))
            .collect();
        assert_eq!(
            stats.delta_parts as usize,
            parts.iter().map(Vec::len).sum::<usize>()
        );
        assert_eq!(part_requests(&seen).len(), stats.delta_parts as usize);
        for pair in parts.windows(2) {
            assert_before(&seen, &pair[0], &pair[1]);
        }
        let report = dest.fsck(&FsckOptions::default()).await.unwrap();
        assert!(report.is_ok(), "{:?}", report.errors);
    });
}

/// A later step of a chain patches against an object that an earlier step
/// hands over loose. The delta from A to B hands over the large file of B as
/// a fallback. The delta from B to C reads that file as the source of an
/// edit. The pull requests no part of the later step before each part and the
/// fallback of the earlier step arrive.
#[test]
fn a_later_step_reads_a_fallback_of_an_earlier_step() {
    block_on(async {
        let dir = TmpDir::new("pull-http-chain-fallback-barrier");
        let remote = create_remote(dir.path()).await;
        let big = incompressible(300_000);
        let mut edited = big.clone();
        edited[150_000..150_016].copy_from_slice(&[0x5a; 16]);
        build_tree(&dir.path().join("a"), b"a\n");
        build_tree(&dir.path().join("b"), b"a\n");
        std::fs::write(dir.path().join("b/big"), &big).unwrap();
        build_tree(&dir.path().join("c"), b"a\n");
        std::fs::write(dir.path().join("c/big"), &edited).unwrap();
        let a = commit_tree(&remote, dir.path(), "a", "test/main", None, FIXED_TS).await;
        let b = commit_tree(&remote, dir.path(), "b", "test/main", Some(a), FIXED_TS + 1).await;
        let c = commit_tree(&remote, dir.path(), "c", "test/main", Some(b), FIXED_TS + 2).await;
        let in_a = content_checksums(&remote, &a).await;
        let added: Vec<Checksum> = content_checksums(&remote, &b)
            .await
            .into_iter()
            .filter(|checksum| !in_a.contains(checksum))
            .collect();
        let [x1] = added[..] else {
            panic!("B adds {added:?}");
        };

        let ab = listed(
            &remote,
            &a,
            &b,
            DeltaOptions {
                min_fallback_size: 100_000,
                ..DeltaOptions::default()
            },
        )
        .await;
        let bc = listed(
            &remote,
            &b,
            &c,
            DeltaOptions {
                min_fallback_size: 0,
                ..DeltaOptions::default()
            },
        )
        .await;
        let ab_superblock = DeltaSuperblock::parse(
            std::fs::read(remote.path().join(superblock_path(&a, &b))).unwrap(),
        )
        .unwrap();
        let fallbacks: Vec<Checksum> = ab_superblock
            .fallbacks()
            .iter()
            .map(|fallback| *fallback.checksum())
            .collect();
        assert_eq!(fallbacks, [x1]);
        let bc_dir = remote.path().join(static_delta_relative_dir(Some(&b), &c));
        let bc_superblock =
            DeltaSuperblock::parse(std::fs::read(bc_dir.join("superblock")).unwrap()).unwrap();
        let mut reads = 0;
        for index in 0..bc_superblock.parts().len() {
            reads += bc_superblock
                .part_stats(index, &bc_dir)
                .await
                .unwrap()
                .ops
                .set_read_source;
        }
        assert!(reads > 0, "the delta from B to C reads no source object");

        let server = RepoServer::start(remote.path(), false).await;
        let dest = dest_holding(dir.path(), &server.url(), &a).await;
        let dest_dir = dir.path().join("dest");
        server.forget();

        dest.pull("origin", chain_opts(vec![ab, bc])).await.unwrap();

        for commit in [b, c] {
            assert_complete(&remote, &dest, &dest_dir, &commit).await;
        }
        assert_no_markers(&dest_dir);
        let seen = server.seen();
        let x1_path = filez_path(&x1.to_hex());
        assert_eq!(server.requests_for(&x1_path), 1, "{seen:?}");
        let mut earlier = part_paths(&remote, &a, &b);
        earlier.push(x1_path);
        assert_before(&seen, &earlier, &part_paths(&remote, &b, &c));
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(c)
        );
    });
}

/// A listed digest that the superblock of a step does not have fails the pull
/// before the transaction opens. The pull requests no part, publishes no ref,
/// writes no object, and leaves no marker.
#[test]
fn a_wrong_listed_digest_fails_before_the_transaction() {
    block_on(async {
        let dir = TmpDir::new("pull-http-chain-wrong-digest");
        let (remote, [a, b, c, d]) = build_chain_remote(dir.path()).await;
        let list = vec![
            listed(&remote, &a, &b, DeltaOptions::default()).await,
            AdvertisedDelta {
                superblock: Checksum::from_bytes([0xee; 32]),
                ..listed(&remote, &b, &c, DeltaOptions::default()).await
            },
            listed(&remote, &c, &d, DeltaOptions::default()).await,
        ];
        let server = RepoServer::start(remote.path(), false).await;
        let dest = dest_holding(dir.path(), &server.url(), &a).await;
        let dest_dir = dir.path().join("dest");
        let held = dest.list_objects().await.unwrap();
        server.forget();

        let err = dest.pull("origin", chain_opts(list)).await.unwrap_err();
        assert!(matches!(err, Error::ChecksumMismatch { .. }), "{err:?}");
        assert_nothing_published(&dest).await;
        assert_no_markers(&dest_dir);
        let seen = server.seen();
        assert!(part_requests(&seen).is_empty(), "{seen:?}");
        assert_eq!(dest.list_objects().await.unwrap(), held);
    });
}

/// The remote does not hold the superblock of the middle step of the one
/// chain of the list. Under `require_static_deltas`, the pull fails and
/// publishes nothing. Without it, the pull fetches the target loose and
/// requests no part.
#[test]
fn a_missing_superblock_in_the_middle_of_a_chain() {
    block_on(async {
        let dir = TmpDir::new("pull-http-chain-missing-superblock");
        let (remote, [a, b, c, d]) = build_chain_remote(dir.path()).await;
        let mut list = Vec::new();
        for (from, to) in [(a, b), (b, c), (c, d)] {
            list.push(listed(&remote, &from, &to, DeltaOptions::default()).await);
        }
        let server = RepoServer::start(remote.path(), false).await;
        server.hide(&superblock_path(&b, &c));
        let dest = dest_holding(dir.path(), &server.url(), &a).await;
        let dest_dir = dir.path().join("dest");
        server.forget();

        let required = PullOptions {
            require_static_deltas: true,
            ..chain_opts(list.clone())
        };
        let err = dest.pull("origin", required).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("pull: Static deltas required, but none found for test/main to {d}")
        );
        assert_nothing_published(&dest).await;
        assert_no_markers(&dest_dir);
        assert!(part_requests(&server.seen()).is_empty());

        server.forget();
        dest.pull("origin", chain_opts(list)).await.unwrap();
        let seen = server.seen();
        assert_complete(&remote, &dest, &dest_dir, &d).await;
        assert_no_markers(&dest_dir);
        assert!(seen.iter().any(|path| path.ends_with(".filez")), "{seen:?}");
        assert!(part_requests(&seen).is_empty(), "{seen:?}");
        assert_eq!(server.statuses_for(&superblock_path(&b, &c)), [404]);
        assert_eq!(server.requests_for(&superblock_path(&c, &d)), 0);
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(d)
        );
    });
}

/// A pull of depth 1 through a chain under a signature policy passes.
/// Discovery checks each commit of the chain with its `.commitmeta`, the
/// target included, and the pull requests neither file again: the step of the
/// parent under depth reads the commit that an earlier run made complete.
#[test]
fn depth_one_through_a_chain_under_verification() {
    block_on(async {
        let dir = TmpDir::new("pull-http-chain-depth-verify");
        let (remote, [a, b, c, d]) = build_chain_remote(dir.path()).await;
        sign_commits(&remote, &[a, b, c, d]).await;
        let mut list = Vec::new();
        for (from, to) in [(a, b), (b, c), (c, d)] {
            list.push(listed(&remote, &from, &to, DeltaOptions::default()).await);
        }
        let server = RepoServer::start(remote.path(), false).await;
        drop(dest_holding(dir.path(), &server.url(), &a).await);
        let dest = reconfigure_dest(dir.path(), &server.url(), &signed_policy()).await;
        let dest_dir = dir.path().join("dest");
        server.forget();

        let opts = PullOptions {
            depth: 1,
            ..chain_opts(list)
        };
        dest.pull("origin", opts).await.unwrap();

        let seen = server.seen();
        for commit in [b, c, d] {
            assert_eq!(server.requests_for(&meta_path(&commit, "commit")), 0);
            assert_eq!(
                server.requests_for(&meta_path(&commit, "commitmeta")),
                1,
                "{seen:?}"
            );
            assert_complete(&remote, &dest, &dest_dir, &commit).await;
        }
        assert_no_markers(&dest_dir);
        assert_eq!(
            dest.read_commit_detached_metadata(&c).await.unwrap(),
            remote.read_commit_detached_metadata(&c).await.unwrap()
        );
        assert!(
            dest.read_commit_detached_metadata(&c)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(d)
        );
    });
}

/// A requested target is also an intermediate commit of the chain of another
/// target. The pull passes under a signature policy, makes both refs, and
/// requests the `.commitmeta` of each intermediate commit once. The binding
/// check applies to the ref that names the intermediate commit: a ref that
/// the binding of that commit does not list fails the pull in discovery,
/// before the request of a part.
#[test]
fn a_target_that_is_an_intermediate_commit_of_another_target() {
    block_on(async {
        let dir = TmpDir::new("pull-http-chain-target-in-level");
        let remote = create_remote(dir.path()).await;
        let a = chain_commit(&remote, dir.path(), "a", "test/main", None, 0).await;
        let b = chain_commit(&remote, dir.path(), "b", "test/main", Some(a), 1).await;
        let c = chain_commit(&remote, dir.path(), "c", "test/mid", Some(b), 2).await;
        let d = chain_commit(&remote, dir.path(), "d", "test/main", Some(c), 3).await;
        let txn = remote.transaction().await.unwrap();
        txn.set_ref("test/alias", Some(&c));
        txn.commit().await.unwrap();
        sign_commits(&remote, &[a, b, c, d]).await;
        let mut list = Vec::new();
        for (from, to) in [(a, b), (b, c), (c, d)] {
            list.push(listed(&remote, &from, &to, DeltaOptions::default()).await);
        }
        let server = RepoServer::start(remote.path(), false).await;
        drop(dest_holding(dir.path(), &server.url(), &a).await);
        let dest = reconfigure_dest(dir.path(), &server.url(), &signed_policy()).await;
        let dest_dir = dir.path().join("dest");
        let held = dest.list_objects().await.unwrap();
        server.forget();

        let alias = PullOptions {
            refs: vec!["test/main".to_owned(), "test/alias".to_owned()],
            ..chain_opts(list.clone())
        };
        let err = dest.pull("origin", alias).await.unwrap_err();
        assert!(
            matches!(&err, Error::Pull(m) if m.contains("'test/alias'")),
            "{err:?}"
        );
        let seen = server.seen();
        assert!(part_requests(&seen).is_empty(), "{seen:?}");
        assert_nothing_published(&dest).await;
        assert_no_markers(&dest_dir);
        assert_eq!(dest.list_objects().await.unwrap(), held);

        server.forget();
        let opts = PullOptions {
            refs: vec!["test/main".to_owned(), "test/mid".to_owned()],
            ..chain_opts(list)
        };
        dest.pull("origin", opts).await.unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(d)
        );
        assert_eq!(
            dest.resolve_rev("origin:test/mid", true).await.unwrap(),
            Some(c)
        );
        let seen = server.seen();
        for commit in [b, c] {
            assert_eq!(
                server.requests_for(&meta_path(&commit, "commitmeta")),
                1,
                "{seen:?}"
            );
            assert_complete(&remote, &dest, &dest_dir, &commit).await;
        }
        assert!(
            !seen.iter().any(|path| path.ends_with(".commit")),
            "{seen:?}"
        );
        assert_complete(&remote, &dest, &dest_dir, &d).await;
        assert_no_markers(&dest_dir);
    });
}

/// Two targets share the first step of their chains. The pull fetches the
/// superblock and each part of the shared step once, and applies them before
/// each part of the two later steps.
#[test]
fn two_targets_share_a_step() {
    block_on(async {
        let dir = TmpDir::new("pull-http-chain-shared-step");
        let remote = create_remote(dir.path()).await;
        let a = chain_commit(&remote, dir.path(), "a", "test/main", None, 0).await;
        let b = chain_commit(&remote, dir.path(), "b", "test/main", Some(a), 1).await;
        let c = chain_commit(&remote, dir.path(), "c", "test/main", Some(b), 2).await;
        let d = chain_commit(&remote, dir.path(), "d", "test/other", Some(b), 3).await;
        let mut list = Vec::new();
        for (from, to) in [(a, b), (b, c), (b, d)] {
            list.push(listed(&remote, &from, &to, DeltaOptions::default()).await);
        }
        let server = RepoServer::start(remote.path(), false).await;
        let dest = dest_holding(dir.path(), &server.url(), &a).await;
        let dest_dir = dir.path().join("dest");
        server.forget();

        let opts = PullOptions {
            refs: vec!["test/main".to_owned(), "test/other".to_owned()],
            ..chain_opts(list)
        };
        dest.pull("origin", opts).await.unwrap();

        let seen = server.seen();
        assert_eq!(server.requests_for(&superblock_path(&a, &b)), 1);
        let mut later = part_paths(&remote, &b, &c);
        later.extend(part_paths(&remote, &b, &d));
        assert_before(&seen, &part_paths(&remote, &a, &b), &later);
        for commit in [b, c, d] {
            assert_complete(&remote, &dest, &dest_dir, &commit).await;
        }
        assert_no_markers(&dest_dir);
        assert!(
            !seen.iter().any(|path| path.ends_with(".filez")),
            "{seen:?}"
        );
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(c)
        );
        assert_eq!(
            dest.resolve_rev("origin:test/other", true).await.unwrap(),
            Some(d)
        );
    });
}

/// A `COMMIT_ONLY` pull ignores the list, also under `require_static_deltas`
/// from a remote with no summary. It requests no delta file, and fetches the
/// target commit object alone, which stays partial with its marker.
#[test]
fn a_commit_only_pull_ignores_the_list() {
    block_on(async {
        let dir = TmpDir::new("pull-http-chain-commit-only");
        let (remote, [a, b, c, d]) = build_chain_remote(dir.path()).await;
        let mut list = Vec::new();
        for (from, to) in [(a, b), (b, c), (c, d)] {
            list.push(listed(&remote, &from, &to, DeltaOptions::default()).await);
        }
        let server = RepoServer::start(remote.path(), false).await;
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;
        let dest_dir = dir.path().join("dest");

        let opts = PullOptions {
            flags: PullFlags::COMMIT_ONLY,
            require_static_deltas: true,
            ..chain_opts(list)
        };
        dest.pull("origin", opts).await.unwrap();

        let seen = server.seen();
        assert!(
            !seen.iter().any(|path| path.starts_with("deltas/")),
            "{seen:?}"
        );
        assert!(seen.contains(&meta_path(&d, "commit")), "{seen:?}");
        assert_eq!(dest.commit_state(&d).await.unwrap(), CommitState::Partial);
        assert!(
            dest_dir
                .join(format!("state/{}.commitpartial", d.to_hex()))
                .exists()
        );
    });
}

/// A pull with an empty list passes. It requests no delta file and no delta
/// index, and fetches the target loose.
#[test]
fn an_empty_list_fetches_loose() {
    block_on(async {
        let dir = TmpDir::new("pull-http-chain-empty-list");
        let (remote, [a, _, _, d]) = build_chain_remote(dir.path()).await;
        let server = RepoServer::start(remote.path(), false).await;
        let dest = dest_holding(dir.path(), &server.url(), &a).await;
        let dest_dir = dir.path().join("dest");
        server.forget();

        dest.pull("origin", chain_opts(Vec::new())).await.unwrap();

        let seen = server.seen();
        assert!(
            !seen
                .iter()
                .any(|path| path.starts_with("deltas/") || path.starts_with("delta-indexes/")),
            "{seen:?}"
        );
        assert!(seen.iter().any(|path| path.ends_with(".filez")), "{seen:?}");
        assert_complete(&remote, &dest, &dest_dir, &d).await;
        assert_no_markers(&dest_dir);
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(d)
        );
    });
}

/// A list that holds one entry twice passes. The pull applies the chain and
/// requests each superblock once.
#[test]
fn a_list_with_an_entry_twice_applies_the_chain() {
    block_on(async {
        let dir = TmpDir::new("pull-http-chain-equal-entry");
        let (remote, [a, b, c, d]) = build_chain_remote(dir.path()).await;
        let steps = [(a, b), (b, c), (c, d)];
        let mut list = Vec::new();
        for (from, to) in &steps {
            list.push(listed(&remote, from, to, DeltaOptions::default()).await);
        }
        list.push(list[1]);
        let server = RepoServer::start(remote.path(), false).await;
        let dest = dest_holding(dir.path(), &server.url(), &a).await;
        let dest_dir = dir.path().join("dest");
        server.forget();

        dest.pull("origin", chain_opts(list)).await.unwrap();

        let seen = server.seen();
        for (from, to) in &steps {
            assert_eq!(
                server.requests_for(&superblock_path(from, to)),
                1,
                "{seen:?}"
            );
        }
        assert!(
            !seen.iter().any(|path| path.ends_with(".filez")),
            "{seen:?}"
        );
        for commit in [b, c, d] {
            assert_complete(&remote, &dest, &dest_dir, &commit).await;
        }
        assert_no_markers(&dest_dir);
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(d)
        );
    });
}

/// A requested ref names an intermediate commit of the chain of another
/// target. The ref in the destination names a newer commit, so the timestamp
/// check refuses the intermediate commit in discovery. The pull fails before
/// it requests a part or the superblock of the next step, keeps the refs and
/// the objects of the destination, and leaves no marker.
#[test]
fn the_timestamp_check_refuses_an_older_intermediate_commit() {
    block_on(async {
        let dir = TmpDir::new("pull-http-chain-timestamp");
        let remote = create_remote(dir.path()).await;
        let a = chain_commit(&remote, dir.path(), "a", "test/main", None, 0).await;
        let b = chain_commit(&remote, dir.path(), "b", "test/main", Some(a), 1).await;
        let c = chain_commit(&remote, dir.path(), "c", "test/mid", Some(b), 2).await;
        let d = chain_commit(&remote, dir.path(), "d", "test/main", Some(c), 3).await;
        let mut list = Vec::new();
        for (from, to) in [(a, b), (b, c), (c, d)] {
            list.push(listed(&remote, &from, &to, DeltaOptions::default()).await);
        }
        let server = RepoServer::start(remote.path(), false).await;
        let dest = dest_holding(dir.path(), &server.url(), &a).await;
        let dest_dir = dir.path().join("dest");
        build_tree(&dir.path().join("newer"), b"newer\n");
        let newer = commit_tree(
            &dest,
            dir.path(),
            "newer",
            "origin:test/mid",
            None,
            FIXED_TS + 100,
        )
        .await;
        let held = dest.list_objects().await.unwrap();
        server.forget();

        let opts = PullOptions {
            refs: vec!["test/main".to_owned(), "test/mid".to_owned()],
            timestamp_check: TimestampCheck::CurrentRef,
            ..chain_opts(list)
        };
        let err = dest.pull("origin", opts).await.unwrap_err();

        assert!(matches!(err, Error::Pull(_)), "{err:?}");
        let message = err.to_string();
        assert!(message.contains(&c.to_hex()), "{message}");
        assert!(message.contains(&newer.to_hex()), "{message}");
        let seen = server.seen();
        assert!(part_requests(&seen).is_empty(), "{seen:?}");
        assert_eq!(server.requests_for(&superblock_path(&c, &d)), 0);
        assert!(!seen.contains(&meta_path(&c, "commit")), "{seen:?}");
        assert_eq!(
            dest.resolve_rev("origin:test/mid", true).await.unwrap(),
            Some(newer)
        );
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            None
        );
        assert_eq!(dest.list_objects().await.unwrap(), held);
        assert_no_markers(&dest_dir);
    });
}

/// The intermediate commits of a chain are signed, and the target is not.
/// The pull refuses the target in discovery, before the transaction opens. It
/// requests no part and no `.commit`, publishes no ref, writes no object, and
/// leaves no marker.
#[test]
fn a_target_refused_by_its_signature_requests_no_part() {
    block_on(async {
        let dir = TmpDir::new("pull-http-chain-unsigned-target");
        let (remote, [a, b, c, d]) = build_chain_remote(dir.path()).await;
        sign_commits(&remote, &[a, b, c]).await;
        let mut list = Vec::new();
        for (from, to) in [(a, b), (b, c), (c, d)] {
            list.push(listed(&remote, &from, &to, DeltaOptions::default()).await);
        }
        let server = RepoServer::start(remote.path(), false).await;
        drop(dest_holding(dir.path(), &server.url(), &a).await);
        let dest = reconfigure_dest(dir.path(), &server.url(), &signed_policy()).await;
        let dest_dir = dir.path().join("dest");
        let held = dest.list_objects().await.unwrap();
        server.forget();

        let err = dest.pull("origin", chain_opts(list)).await.unwrap_err();

        assert!(matches!(err, Error::Signature(_)), "{err:?}");
        let seen = server.seen();
        assert!(part_requests(&seen).is_empty(), "{seen:?}");
        assert!(
            !seen.iter().any(|path| path.ends_with(".commit")),
            "{seen:?}"
        );
        assert_eq!(server.requests_for(&meta_path(&d, "commitmeta")), 1);
        assert_nothing_published(&dest).await;
        assert_no_markers(&dest_dir);
        assert_eq!(dest.list_objects().await.unwrap(), held);
    });
}

/// The commits of a chain are signed, except the intermediate commit B. Under
/// sign-api verification, discovery refuses B after the superblock of its
/// step. The pull requests no later superblock, no part, and no `.commit`,
/// publishes no ref, writes no object, and leaves no marker. With
/// verification off, the same list passes.
#[test]
fn an_unsigned_intermediate_commit_fails_discovery_over_http() {
    block_on(async {
        let dir = TmpDir::new("pull-http-chain-unsigned-intermediate");
        let (remote, [a, b, c, d]) = build_chain_remote(dir.path()).await;
        sign_commits(&remote, &[a, c, d]).await;
        let mut list = Vec::new();
        for (from, to) in [(a, b), (b, c), (c, d)] {
            list.push(listed(&remote, &from, &to, DeltaOptions::default()).await);
        }
        let server = RepoServer::start(remote.path(), false).await;
        drop(dest_holding(dir.path(), &server.url(), &a).await);
        let dest = reconfigure_dest(dir.path(), &server.url(), &signed_policy()).await;
        let dest_dir = dir.path().join("dest");
        let held = dest.list_objects().await.unwrap();
        server.forget();

        let err = dest
            .pull("origin", chain_opts(list.clone()))
            .await
            .unwrap_err();

        assert!(
            matches!(&err, Error::Signature(m) if m.starts_with(&format!("commit {b}: "))
                && !m.contains("static delta")),
            "{err:?}"
        );
        let seen = server.seen();
        assert_eq!(server.requests_for(&superblock_path(&a, &b)), 1);
        assert_eq!(server.requests_for(&meta_path(&b, "commitmeta")), 1);
        assert_eq!(server.requests_for(&superblock_path(&b, &c)), 0);
        assert_eq!(server.requests_for(&superblock_path(&c, &d)), 0);
        assert!(part_requests(&seen).is_empty(), "{seen:?}");
        assert!(
            !seen.iter().any(|path| path.ends_with(".commit")),
            "{seen:?}"
        );
        assert_nothing_published(&dest).await;
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            None
        );
        assert_no_markers(&dest_dir);
        assert_eq!(dest.list_objects().await.unwrap(), held);
        drop(dest);

        let dest = reconfigure_dest(dir.path(), &server.url(), "").await;
        server.forget();
        dest.pull("origin", chain_opts(list)).await.unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(d)
        );
        for commit in [b, c, d] {
            assert_complete(&remote, &dest, &dest_dir, &commit).await;
        }
        assert_no_markers(&dest_dir);
        let seen = server.seen();
        assert!(!part_requests(&seen).is_empty(), "{seen:?}");
    });
}

/// The intermediate commit C has the ref binding `test/mid`, and the pull
/// requests `test/main` alone. Discovery checks only the signatures of C, so
/// the pull passes under sign-api verification. It writes no ref for C, and
/// requests no `.commit`.
#[test]
fn an_intermediate_commit_bound_to_another_ref_passes() {
    block_on(async {
        let dir = TmpDir::new("pull-http-chain-intermediate-binding");
        let remote = create_remote(dir.path()).await;
        let a = chain_commit(&remote, dir.path(), "a", "test/main", None, 0).await;
        let b = chain_commit(&remote, dir.path(), "b", "test/main", Some(a), 1).await;
        let c = chain_commit(&remote, dir.path(), "c", "test/mid", Some(b), 2).await;
        let d = chain_commit(&remote, dir.path(), "d", "test/main", Some(c), 3).await;
        sign_commits(&remote, &[a, b, c, d]).await;
        let mut list = Vec::new();
        for (from, to) in [(a, b), (b, c), (c, d)] {
            list.push(listed(&remote, &from, &to, DeltaOptions::default()).await);
        }
        let server = RepoServer::start(remote.path(), false).await;
        drop(dest_holding(dir.path(), &server.url(), &a).await);
        let dest = reconfigure_dest(dir.path(), &server.url(), &signed_policy()).await;
        let dest_dir = dir.path().join("dest");
        server.forget();

        dest.pull("origin", chain_opts(list)).await.unwrap();

        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(d)
        );
        assert_eq!(
            dest.resolve_rev("origin:test/mid", true).await.unwrap(),
            None
        );
        for commit in [b, c, d] {
            assert_complete(&remote, &dest, &dest_dir, &commit).await;
        }
        assert_no_markers(&dest_dir);
        let seen = server.seen();
        assert!(!part_requests(&seen).is_empty(), "{seen:?}");
        assert!(
            !seen.iter().any(|path| path.ends_with(".commit")),
            "{seen:?}"
        );
    });
}

/// Each commit of a chain is signed with the trusted key. The superblock of
/// the step B->C carries a signature of another key alone. Discovery refuses
/// the superblock before it checks C. The pull requests no later superblock,
/// no `.commitmeta` of C, and no part, publishes no ref, writes no object, and
/// leaves no marker.
#[test]
fn a_step_superblock_signed_by_an_untrusted_key_fails_discovery() {
    block_on(async {
        let dir = TmpDir::new("pull-http-chain-untrusted-superblock");
        let (remote, [a, b, c, d]) = build_chain_remote(dir.path()).await;
        sign_commits(&remote, &[a, b, c, d]).await;
        let mut list = Vec::new();
        for (from, to) in [(a, b), (b, c), (c, d)] {
            list.push(listed(&remote, &from, &to, DeltaOptions::default()).await);
        }
        let other = Ed25519Signer::from_base64(OTHER_SECRET_B64).unwrap();
        remote
            .sign_static_delta(
                &remote.path().join(static_delta_relative_dir(Some(&b), &c)),
                &other,
            )
            .await
            .unwrap();
        let bytes = std::fs::read(remote.path().join(superblock_path(&b, &c))).unwrap();
        list[1].superblock = Checksum::sha256(&bytes);
        let server = RepoServer::start(remote.path(), false).await;
        drop(dest_holding(dir.path(), &server.url(), &a).await);
        let dest = reconfigure_dest(dir.path(), &server.url(), &signed_policy()).await;
        let dest_dir = dir.path().join("dest");
        let held = dest.list_objects().await.unwrap();
        server.forget();

        let err = dest.pull("origin", chain_opts(list)).await.unwrap_err();

        assert!(
            matches!(&err, Error::Signature(m) if m.contains("static delta")
                && m.contains("trusted key")),
            "{err:?}"
        );
        let seen = server.seen();
        assert_eq!(server.requests_for(&superblock_path(&b, &c)), 1);
        assert_eq!(server.requests_for(&superblock_path(&c, &d)), 0);
        assert_eq!(server.requests_for(&meta_path(&b, "commitmeta")), 1);
        assert_eq!(server.requests_for(&meta_path(&c, "commitmeta")), 0);
        assert!(part_requests(&seen).is_empty(), "{seen:?}");
        assert_nothing_published(&dest).await;
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            None
        );
        assert_no_markers(&dest_dir);
        assert_eq!(dest.list_objects().await.unwrap(), held);
    });
}

/// The requested ref names the target of a chain, and the ref binding of the
/// target lists another ref. The pull refuses the target in discovery, after
/// the superblock of its step and before the request of a part. It publishes
/// no ref, writes no object, and leaves no marker.
#[test]
fn a_target_refused_by_its_ref_binding_requests_no_part() {
    block_on(async {
        let dir = TmpDir::new("pull-http-chain-target-binding");
        let (remote, [a, b, c, d]) = build_chain_remote(dir.path()).await;
        let txn = remote.transaction().await.unwrap();
        txn.set_ref("test/alias", Some(&d));
        txn.commit().await.unwrap();
        let mut list = Vec::new();
        for (from, to) in [(a, b), (b, c), (c, d)] {
            list.push(listed(&remote, &from, &to, DeltaOptions::default()).await);
        }
        let server = RepoServer::start(remote.path(), false).await;
        let dest = dest_holding(dir.path(), &server.url(), &a).await;
        let dest_dir = dir.path().join("dest");
        let held = dest.list_objects().await.unwrap();
        server.forget();

        let opts = PullOptions {
            refs: vec!["test/alias".to_owned()],
            ..chain_opts(list)
        };
        let err = dest.pull("origin", opts).await.unwrap_err();

        assert!(
            matches!(&err, Error::Pull(m) if m.contains("'test/alias'")),
            "{err:?}"
        );
        let seen = server.seen();
        assert_eq!(server.requests_for(&superblock_path(&c, &d)), 1);
        assert!(part_requests(&seen).is_empty(), "{seen:?}");
        assert_nothing_published(&dest).await;
        assert_no_markers(&dest_dir);
        assert_eq!(dest.list_objects().await.unwrap(), held);
    });
}

/// The ref binding of the target of a chain lists another ref, and the pull
/// sets `DISABLE_VERIFY_BINDINGS`. Discovery makes no ref-binding check, so
/// the pull requests the parts and writes the ref.
#[test]
fn a_target_with_another_ref_binding_pulls_with_the_check_disabled() {
    block_on(async {
        let dir = TmpDir::new("pull-http-chain-target-binding-off");
        let (remote, [a, b, c, d]) = build_chain_remote(dir.path()).await;
        let txn = remote.transaction().await.unwrap();
        txn.set_ref("test/alias", Some(&d));
        txn.commit().await.unwrap();
        let mut list = Vec::new();
        for (from, to) in [(a, b), (b, c), (c, d)] {
            list.push(listed(&remote, &from, &to, DeltaOptions::default()).await);
        }
        let server = RepoServer::start(remote.path(), false).await;
        let dest = dest_holding(dir.path(), &server.url(), &a).await;
        server.forget();

        let opts = PullOptions {
            refs: vec!["test/alias".to_owned()],
            flags: PullFlags::DISABLE_VERIFY_BINDINGS,
            ..chain_opts(list)
        };
        dest.pull("origin", opts).await.unwrap();

        let seen = server.seen();
        assert!(!part_requests(&seen).is_empty(), "{seen:?}");
        assert_eq!(
            dest.resolve_rev("origin:test/alias", false).await.unwrap(),
            Some(d)
        );
    });
}

/// The timestamp check compares the target of a chain with a newer commit of
/// the destination. The pull refuses the target in discovery, before the
/// request of a part and of the `.commit`. It writes no ref, keeps the
/// objects of the destination, and leaves no marker.
#[test]
fn a_target_refused_by_the_timestamp_check_requests_no_part() {
    block_on(async {
        let dir = TmpDir::new("pull-http-chain-target-timestamp");
        let (remote, [a, b, c, d]) = build_chain_remote(dir.path()).await;
        let mut list = Vec::new();
        for (from, to) in [(a, b), (b, c), (c, d)] {
            list.push(listed(&remote, &from, &to, DeltaOptions::default()).await);
        }
        let server = RepoServer::start(remote.path(), false).await;
        let dest = dest_holding(dir.path(), &server.url(), &a).await;
        let dest_dir = dir.path().join("dest");
        build_tree(&dir.path().join("newer"), b"newer\n");
        let newer = commit_tree(
            &dest,
            dir.path(),
            "newer",
            "local/newer",
            None,
            FIXED_TS + 100,
        )
        .await;
        let held = dest.list_objects().await.unwrap();
        server.forget();

        let opts = PullOptions {
            timestamp_check: TimestampCheck::Rev(newer),
            ..chain_opts(list)
        };
        let err = dest.pull("origin", opts).await.unwrap_err();

        assert!(matches!(err, Error::Pull(_)), "{err:?}");
        let message = err.to_string();
        assert!(message.contains(&d.to_hex()), "{message}");
        assert!(message.contains(&newer.to_hex()), "{message}");
        let seen = server.seen();
        assert!(part_requests(&seen).is_empty(), "{seen:?}");
        assert!(!seen.contains(&meta_path(&d, "commit")), "{seen:?}");
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            None
        );
        assert_eq!(dest.list_objects().await.unwrap(), held);
        assert_no_markers(&dest_dir);
    });
}

/// `TimestampCheck::Rev` names a commit that the destination does not hold.
/// The pull fails with `ObjectNotFound` for that commit before discovery: it
/// requests no superblock, no part, no `.commitmeta`, and no object. It
/// writes no ref, keeps the objects of the destination, and leaves no
/// marker.
#[test]
fn a_timestamp_commit_that_is_absent_stops_the_pull_before_discovery() {
    block_on(async {
        let dir = TmpDir::new("pull-http-timestamp-rev-absent");
        let (remote, [a, b, c, d]) = build_chain_remote(dir.path()).await;
        let mut list = Vec::new();
        for (from, to) in [(a, b), (b, c), (c, d)] {
            list.push(listed(&remote, &from, &to, DeltaOptions::default()).await);
        }
        let server = RepoServer::start(remote.path(), false).await;
        let dest = dest_holding(dir.path(), &server.url(), &a).await;
        let dest_dir = dir.path().join("dest");
        let absent = Checksum::sha256(b"a commit that no repository holds");
        let held = dest.list_objects().await.unwrap();
        server.forget();

        let opts = PullOptions {
            timestamp_check: TimestampCheck::Rev(absent),
            ..chain_opts(list)
        };
        let err = dest.pull("origin", opts).await.unwrap_err();

        assert!(
            matches!(
                err,
                Error::ObjectNotFound {
                    checksum,
                    ty: ostrya::ObjectType::Commit,
                } if checksum == absent
            ),
            "{err:?}"
        );
        let seen = server.seen();
        assert!(
            seen.iter()
                .all(|path| !path.starts_with("deltas/") && !path.starts_with("objects/")),
            "{seen:?}"
        );
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            None
        );
        assert_eq!(dest.list_objects().await.unwrap(), held);
        assert_no_markers(&dest_dir);
    });
}

/// A `MIRROR` pull with no named ref, from a summary that lists no ref, has
/// no target. `TimestampCheck::Rev` then reads no commit, so a commit that the
/// destination does not hold does not fail the pull. The pull writes no ref.
#[test]
fn a_pull_with_no_target_reads_no_timestamp_commit() {
    block_on(async {
        let dir = TmpDir::new("pull-http-timestamp-rev-no-target");
        let remote = Repo::create(
            &dir.path().join("remote"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        remote
            .regenerate_summary(&SummaryOptions {
                last_modified: Some(FIXED_TS),
                ..SummaryOptions::default()
            })
            .await
            .unwrap();
        let server = RepoServer::start(remote.path(), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        let absent = Checksum::sha256(b"a commit that no repository holds");

        dest.pull(
            "origin",
            PullOptions {
                flags: PullFlags::MIRROR,
                timestamp_check: TimestampCheck::Rev(absent),
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert_nothing_published(&dest).await;
    });
}

/// The switch of the destination applies to the `.commitmeta` of each commit
/// of a chain of static deltas, with and without a signature policy. A
/// verified pull applies it in discovery, and an unverified pull when it
/// fetches the commit. The pull stores each commit without `ostrya.related`.
#[test]
fn the_switch_applies_to_each_commit_of_a_chain() {
    for policy in [signed_policy(), String::new()] {
        block_on(async {
            let dir = TmpDir::new("pull-http-chain-keep-related");
            let (remote, [a, b, c, d]) = build_chain_remote(dir.path()).await;
            sign_commits(&remote, &[a, b, c, d]).await;
            for commit in [b, c, d] {
                remote
                    .add_detached_related(&commit, "layer/base", &a)
                    .await
                    .unwrap();
            }
            let mut list = Vec::new();
            for (from, to) in [(a, b), (b, c), (c, d)] {
                list.push(listed(&remote, &from, &to, DeltaOptions::default()).await);
            }
            let server = RepoServer::start(remote.path(), false).await;
            drop(dest_holding(dir.path(), &server.url(), &a).await);
            let extra = format!("{policy}{DROP_RELATED}");
            let dest = reconfigure_dest(dir.path(), &server.url(), &extra).await;
            let dest_dir = dir.path().join("dest");

            dest.pull("origin", chain_opts(list)).await.unwrap();

            for commit in [b, c, d] {
                assert_eq!(
                    detached_keys(&remote, &commit).await,
                    ["ostree.sign.ed25519", "ostrya.related"]
                );
                assert_eq!(
                    detached_keys(&dest, &commit).await,
                    ["ostree.sign.ed25519"],
                    "{policy:?}"
                );
                assert_complete(&remote, &dest, &dest_dir, &commit).await;
            }
            assert_no_markers(&dest_dir);
        });
    }
}

/// A verified pull of a chain applies the switch of the destination to the
/// `.commitmeta` of each commit of the chain. Discovery applies it, and the
/// commit step stores its result. With the default switch, the pull stores
/// the bytes of the remote unchanged. With `keep-detached-related=false`, it
/// stores the signature and drops `ostrya.related`. The pull requests each
/// `.commitmeta` once.
#[test]
fn a_verified_chain_pull_applies_the_switch_to_each_commitmeta() {
    block_on(async {
        let dir = TmpDir::new("pull-http-chain-switch-verified");
        let (remote, [a, b, c, d]) = build_chain_remote(dir.path()).await;
        sign_commits(&remote, &[a, b, c, d]).await;
        for commit in [b, c, d] {
            remote
                .add_detached_related(&commit, "layer/base", &a)
                .await
                .unwrap();
            assert_eq!(
                detached_keys(&remote, &commit).await,
                ["ostree.sign.ed25519", "ostrya.related"]
            );
        }
        let mut list = Vec::new();
        for (from, to) in [(a, b), (b, c), (c, d)] {
            list.push(listed(&remote, &from, &to, DeltaOptions::default()).await);
        }
        let server = RepoServer::start(remote.path(), false).await;
        let dest_dir = dir.path().join("dest");

        for switch in ["", DROP_RELATED] {
            let _ = std::fs::remove_dir_all(&dest_dir);
            drop(dest_holding(dir.path(), &server.url(), &a).await);
            let extra = format!("{}{switch}", signed_policy());
            let dest = reconfigure_dest(dir.path(), &server.url(), &extra).await;
            server.forget();

            dest.pull("origin", chain_opts(list.clone())).await.unwrap();

            let seen = server.seen();
            for commit in [b, c, d] {
                let path = meta_path(&commit, "commitmeta");
                assert_eq!(server.requests_for(&path), 1, "{switch:?}: {seen:?}");
                if switch.is_empty() {
                    assert_eq!(
                        std::fs::read(dest_dir.join(&path)).unwrap(),
                        std::fs::read(remote.path().join(&path)).unwrap(),
                        "{commit}"
                    );
                } else {
                    assert_eq!(
                        detached_keys(&dest, &commit).await,
                        ["ostree.sign.ed25519"],
                        "{commit}"
                    );
                    let stored = dest
                        .read_commit_detached_metadata(&commit)
                        .await
                        .unwrap()
                        .unwrap();
                    let held = remote
                        .read_commit_detached_metadata(&commit)
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(
                        stored.dict_get("ostree.sign.ed25519"),
                        held.dict_get("ostree.sign.ed25519"),
                        "{commit}"
                    );
                }
                assert_complete(&remote, &dest, &dest_dir, &commit).await;
            }
            assert_no_markers(&dest_dir);
        }
    });
}

/// With commit verification off, discovery does not parse the `.commitmeta`
/// of a commit of a chain. `keep-detached-related=false` in the destination,
/// and a `.commitmeta` of an intermediate commit that does not parse, do not
/// change the error of the pull: the timestamp check of the target in
/// discovery refuses the pull first.
#[test]
fn an_unverified_chain_pull_does_not_apply_the_switch_in_discovery() {
    block_on(async {
        let dir = TmpDir::new("pull-http-chain-switch-unverified-order");
        let (remote, [a, b, c, d]) = build_chain_remote(dir.path()).await;
        let mut list = Vec::new();
        for (from, to) in [(a, b), (b, c), (c, d)] {
            list.push(listed(&remote, &from, &to, DeltaOptions::default()).await);
        }
        let path = meta_path(&c, "commitmeta");
        std::fs::write(remote.path().join(&path), b"\x01\x02\x03\x04\x05").unwrap();
        let server = RepoServer::start(remote.path(), false).await;
        let dest = dest_holding(dir.path(), &server.url(), &a).await;
        build_tree(&dir.path().join("newer"), b"newer\n");
        let newer = commit_tree(
            &dest,
            dir.path(),
            "newer",
            "local/newer",
            None,
            FIXED_TS + 100,
        )
        .await;
        drop(dest);
        let dest = reconfigure_dest(dir.path(), &server.url(), DROP_RELATED).await;
        let opts = PullOptions {
            timestamp_check: TimestampCheck::Rev(newer),
            ..chain_opts(list)
        };
        match dest.pull("origin", opts).await {
            Err(Error::Pull(msg)) => {
                assert!(msg.contains("chronologically older"), "{msg}");
            }
            other => panic!("{other:?}"),
        }
    });
}

/// With commit verification off and `keep-detached-related=false` in the
/// destination, a `.commitmeta` that does not parse fails no pull for a
/// commit that discovery checks and a later plan drops. The list gives a->c
/// and c->d, and the remote lacks the superblock c->d, so the pull fetches d
/// loose and never fetches c.
#[test]
fn an_unverified_chain_pull_skips_the_commitmeta_of_a_dropped_commit() {
    block_on(async {
        let dir = TmpDir::new("pull-http-chain-switch-unverified-dropped");
        let (remote, [a, _b, c, d]) = build_chain_remote(dir.path()).await;
        let mut list = Vec::new();
        for (from, to) in [(a, c), (c, d)] {
            list.push(listed(&remote, &from, &to, DeltaOptions::default()).await);
        }
        std::fs::remove_file(remote.path().join(superblock_path(&c, &d))).unwrap();
        let path = meta_path(&c, "commitmeta");
        std::fs::write(remote.path().join(&path), b"\x01\x02\x03\x04\x05").unwrap();
        let server = RepoServer::start(remote.path(), false).await;
        let dest_dir = dir.path().join("dest");
        drop(dest_holding(dir.path(), &server.url(), &a).await);
        let dest = reconfigure_dest(dir.path(), &server.url(), DROP_RELATED).await;
        server.forget();
        dest.pull("origin", chain_opts(list)).await.unwrap();
        assert_eq!(server.requests_for(&path), 1, "{:?}", server.seen());
        assert_complete(&remote, &dest, &dest_dir, &d).await;
        assert_no_markers(&dest_dir);
    });
}

// --- writing no ref --------------------------------------------------------

/// Builds a remote archive repository under `dir/remote` with two commits on
/// `test/main` and a summary. The second commit is a child of the first.
async fn build_remote_chain(dir: &Path) -> (Repo, Checksum, Checksum) {
    let (remote, first, second) = build_remote_two_commits(dir).await;
    remote
        .regenerate_summary(&SummaryOptions {
            last_modified: Some(FIXED_TS),
            ..SummaryOptions::default()
        })
        .await
        .unwrap();
    (remote, first, second)
}

/// Asserts that `repo` holds no ref, local or under `refs/remotes`.
async fn assert_no_refs(repo: &Repo) {
    assert!(repo.list_refs(None).await.unwrap().is_empty());
    assert!(
        repo.list_refs(Some("refs/remotes"))
            .await
            .unwrap()
            .is_empty()
    );
}

/// Asserts that `commit` is complete in `dest`:
///
/// - its state is normal
/// - it keeps no `.commitpartial` marker
/// - each object that it reaches in `remote` is present.
async fn assert_complete(remote: &Repo, dest: &Repo, dest_dir: &Path, commit: &Checksum) {
    assert_eq!(
        dest.commit_state(commit).await.unwrap(),
        CommitState::Normal
    );
    let marker = format!("state/{}.commitpartial", commit.to_hex());
    assert!(!dest_dir.join(marker).exists());
    for name in &remote.traverse_commit(commit, 0).await.unwrap() {
        assert!(
            dest.has_object(name.ty, &name.checksum).await.unwrap(),
            "{name} missing from the destination"
        );
    }
}

/// A pull that writes no ref does not change the ref that the destination
/// holds. It stores the pulled commit complete, with its detached metadata.
#[test]
fn a_pull_with_no_ref_writes_keeps_the_ref_and_completes_the_commit() {
    block_on(async {
        let dir = TmpDir::new("pull-http-no-ref-writes");
        let (remote, first, second) = build_remote_chain(dir.path()).await;
        remote
            .write_commit_detached_metadata(&second, Some(&detached_dict()))
            .await
            .unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        let txn = dest.transaction().await.unwrap();
        txn.set_ref("origin:test/main", Some(&first));
        txn.commit().await.unwrap();
        let dest_dir = dir.path().join("dest");
        let refs = file_inventory(&dest_dir, "refs");

        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                no_ref_writes: true,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(file_inventory(&dest_dir, "refs"), refs);
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(first)
        );
        assert_complete(&remote, &dest, &dest_dir, &second).await;
        assert_eq!(
            dest.read_commit_detached_metadata(&second).await.unwrap(),
            Some(detached_dict())
        );
    });
}

/// A pull that writes no ref obeys `depth` and writes nothing under
/// `refs/remotes/origin`. It completes each commit of the chain.
#[test]
fn a_pull_with_no_ref_writes_completes_every_parent_under_depth() {
    block_on(async {
        let dir = TmpDir::new("pull-http-no-ref-writes-depth");
        let (remote, first, second) = build_remote_chain(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;
        let dest_dir = dir.path().join("dest");
        let refs = file_inventory(&dest_dir, "refs");

        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                depth: -1,
                no_ref_writes: true,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(file_inventory(&dest_dir, "refs"), refs);
        assert!(!dest_dir.join("refs/remotes/origin").exists());
        assert_no_refs(&dest).await;
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
        for commit in [&first, &second] {
            assert_complete(&remote, &dest, &dest_dir, commit).await;
        }
    });
}

/// A mirror pull of all refs that writes no ref copies no summary and no
/// summary signature.
#[test]
fn a_mirror_pull_with_no_ref_writes_copies_no_summary() {
    block_on(async {
        let dir = TmpDir::new("pull-http-no-ref-writes-mirror");
        let (remote, commit) = build_remote(dir.path()).await;
        std::fs::write(dir.path().join("remote/summary.sig"), SUMMARY_SIG).unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        let dest_dir = dir.path().join("dest");
        let refs = file_inventory(&dest_dir, "refs");

        dest.pull(
            "origin",
            PullOptions {
                flags: PullFlags::MIRROR,
                no_ref_writes: true,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(file_inventory(&dest_dir, "refs"), refs);
        assert_no_refs(&dest).await;
        assert!(!dest_dir.join("summary").exists());
        assert!(!dest_dir.join("summary.sig").exists());
        assert_complete(&remote, &dest, &dest_dir, &commit).await;
    });
}

// --- collection refs -------------------------------------------------------

/// An HTTP pull refuses a collection id before its first request and publishes
/// nothing. A pull from a remote with no section in the configuration gets the
/// same refusal.
#[test]
fn an_http_pull_refuses_a_collection_id() {
    block_on(async {
        let dir = TmpDir::new("pull-http-collection");
        build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        let dest_dir = dir.path().join("dest");
        let snapshot = || {
            let mut out = file_inventory(&dest_dir, "objects");
            out.extend(file_inventory(&dest_dir, "refs"));
            out.extend(file_inventory(&dest_dir, "state"));
            out
        };
        let before = snapshot();

        for remote in ["origin", "absent"] {
            let err = dest
                .pull(
                    remote,
                    PullOptions {
                        refs: vec!["test/main".to_owned()],
                        collection_id: Some("org.example.Os".to_owned()),
                        no_ref_writes: true,
                        ..PullOptions::default()
                    },
                )
                .await
                .unwrap_err();
            match err {
                Error::Unsupported(msg) => {
                    assert_eq!(msg, "only a local pull takes a collection id", "{remote}")
                }
                other => panic!("{remote}: {other:?}"),
            }
        }

        assert!(server.seen().is_empty(), "{:?}", server.seen());
        assert_eq!(snapshot(), before);
    });
}

// --- the proxy key of a remote ---------------------------------------------

/// The variables that the fetcher reads to find a proxy, in both spellings. A
/// child process that pulls through the environment starts with none of them.
const PROXY_VARIABLES: [&str; 8] = [
    "http_proxy",
    "HTTP_PROXY",
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "no_proxy",
    "NO_PROXY",
];

/// The prefix of a writer child argument that expects the pull to fail on
/// the `http_proxy` of the child.
const REFUSED: &str = "refused:";

/// The writer child pulls from `origin` the ref that its argument names. With
/// the [`REFUSED`] prefix, the pull must fail with a refusal that names
/// `http_proxy` and leaves out its credential.
#[test]
#[ignore = "helper process for the proxy environment tests"]
fn writer_child_subprocess() {
    writer_child_main(|path, arg| {
        block_on(async {
            let repo = Repo::open(path).await.unwrap();
            let (refused, rev) = match arg.strip_prefix(REFUSED) {
                Some(rev) => (true, rev),
                None => (false, arg),
            };
            let pulled = repo
                .pull(
                    "origin",
                    PullOptions {
                        refs: vec![rev.to_owned()],
                        ..PullOptions::default()
                    },
                )
                .await;
            if !refused {
                pulled.unwrap();
                return;
            }
            let err = pulled.unwrap_err();
            assert!(matches!(err, Error::Unsupported(_)), "{err:?}");
            let message = err.to_string();
            assert!(message.contains("http_proxy"), "{message}");
            assert!(!message.contains("s3cret"), "{message}");
        });
    });
}

/// A cleartext pull from a remote with a `proxy` key sends each request to that
/// proxy in absolute form. The suite runs with `no_proxy="*"`, which exempts
/// each origin from an environment proxy. The pull through the key also shows
/// that the key ignores `no_proxy`.
#[test]
fn a_pull_goes_through_the_proxy_key() {
    assert_eq!(
        std::env::var("no_proxy").as_deref(),
        Ok("*"),
        "the claim on no_proxy needs the suite's no_proxy=\"*\""
    );
    block_on(async {
        let dir = TmpDir::new("pull-http-proxy-key");
        let (_remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let proxy = TestProxy::start(Tunnel::Open).await;
        let dest = build_dest(
            dir.path(),
            RepoMode::Archive,
            &server.url(),
            &format!("proxy={}\n", proxy.url()),
        )
        .await;

        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(commit)
        );
        assert!(proxy.requests() > 0);
        assert_eq!(proxy.requests(), server.seen().len());
        let origin = format!("{}/", server.url());
        for seen in proxy.seen() {
            assert_eq!(seen.method, "GET");
            assert!(seen.target.starts_with(&origin), "{}", seen.target);
        }
    });
}

/// A pull from an `https://` remote with a `proxy` key opens a tunnel to the
/// remote through the proxy. The proxy sees no other request.
#[test]
fn a_tls_pull_tunnels_through_the_proxy_key() {
    block_on(async {
        let dir = TmpDir::new("pull-http-proxy-key-tls");
        let (_remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), true).await;
        let proxy = TestProxy::start(Tunnel::Open).await;
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, CA_PEM).unwrap();
        let dest = build_dest(
            dir.path(),
            RepoMode::Archive,
            &server.url(),
            &format!("tls-ca-path={}\nproxy={}\n", ca.display(), proxy.url()),
        )
        .await;

        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(commit)
        );
        let authority = server.url().strip_prefix("https://").unwrap().to_owned();
        let seen = proxy.seen();
        assert!(!seen.is_empty());
        for seen in seen {
            assert_eq!(seen.method, "CONNECT");
            assert_eq!(seen.target, authority);
        }
    });
}

/// `remote_fetch_summary` reaches the remote through its `proxy` key.
#[test]
fn remote_fetch_summary_goes_through_the_proxy_key() {
    block_on(async {
        let dir = TmpDir::new("pull-http-proxy-key-summary");
        build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let proxy = TestProxy::start(Tunnel::Open).await;
        let dest = build_dest(
            dir.path(),
            RepoMode::Archive,
            &server.url(),
            &format!("proxy={}\n", proxy.url()),
        )
        .await;

        let (summary, _) = dest.remote_fetch_summary("origin").await.unwrap();
        assert!(summary.is_some());
        let target = format!("{}/summary", server.url());
        assert!(
            proxy.seen().iter().any(|seen| seen.target == target),
            "{:?}",
            proxy.seen()
        );
    });
}

/// If the fetcher cannot connect through a `proxy` key, the pull fails before
/// its first request. The pull publishes nothing.
#[test]
fn a_pull_refuses_a_proxy_key_it_cannot_use() {
    block_on(async {
        let dir = TmpDir::new("pull-http-proxy-key-refused");
        build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(
            dir.path(),
            RepoMode::Archive,
            &server.url(),
            "proxy=https://127.0.0.1:1\n",
        )
        .await;

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "{err:?}");
        assert!(server.seen().is_empty(), "{:?}", server.seen());
        assert_nothing_published(&dest).await;
    });
}

/// A `proxy` key with white space at the end of its value fails the pull before
/// its first request. A value that the `\s` escape makes one space fails the
/// pull in the same way. The pull publishes nothing. The message leaves out the
/// credential.
#[test]
fn a_pull_refuses_a_proxy_key_with_white_space_around_it() {
    for (tag, value) in [
        ("trailing", "http://user:pw@127.0.0.1:1   "),
        ("escape", "\\s"),
    ] {
        block_on(async {
            let dir = TmpDir::new(&format!("pull-http-proxy-key-space-{tag}"));
            build_remote(dir.path()).await;
            let server = RepoServer::start(&dir.path().join("remote"), false).await;
            let dest = build_dest(
                dir.path(),
                RepoMode::Archive,
                &server.url(),
                &format!("proxy={value}\n"),
            )
            .await;

            let err = dest
                .pull(
                    "origin",
                    PullOptions {
                        refs: vec!["test/main".to_owned()],
                        ..PullOptions::default()
                    },
                )
                .await
                .unwrap_err();
            assert!(matches!(err, Error::Unsupported(_)), "{tag}: {err:?}");
            assert!(!err.to_string().contains("pw"), "{tag}: {err}");
            assert!(server.seen().is_empty(), "{tag}: {:?}", server.seen());
            assert_nothing_published(&dest).await;
        });
    }
}

/// Runs the pull of `test/main` in a child process, with the `[remote]` keys
/// `extra`. The environment of the child names the test proxy in `http_proxy`
/// alone. The pull goes through the proxy and writes the ref.
fn pull_through_the_environment_proxy(tag: &str, extra: &str) {
    block_on(async {
        let dir = TmpDir::new(tag);
        let (_remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let proxy = TestProxy::start(Tunnel::Open).await;
        drop(build_dest(dir.path(), RepoMode::Archive, &server.url(), extra).await);

        let path = dir.path().join("dest");
        let proxy_url = proxy.url();
        let child = writer_child_with(&path, "test/main", |command| {
            for name in PROXY_VARIABLES {
                command.env_remove(name);
            }
            command.env("http_proxy", proxy_url);
        });
        // The proxy and the server run on the runtime of this thread, so the
        // wait must not block it.
        ostrya_rt::unblock(move || child.wait()).await;

        assert!(proxy.requests() > 0);
        assert_eq!(proxy.requests(), server.seen().len());
        let dest = Repo::open(&path).await.unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(commit)
        );
    });
}

/// Runs the pull of `test/main` in a child process. The environment of the
/// child holds `http_proxy` alone. Its value is the test proxy URL with a
/// credential, and `around` adds white space to it. The pull fails before its
/// first request and publishes nothing.
fn pull_refuses_the_environment_proxy(tag: &str, around: impl Fn(&str) -> String) {
    block_on(async {
        let dir = TmpDir::new(tag);
        build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let proxy = TestProxy::start(Tunnel::Open).await;
        drop(build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await);

        let path = dir.path().join("dest");
        let value = around(&proxy.url_with("alice:s3cret"));
        let child = writer_child_with(&path, &format!("{REFUSED}test/main"), |command| {
            for name in PROXY_VARIABLES {
                command.env_remove(name);
            }
            command.env("http_proxy", value);
        });
        // The proxy and the server run on the runtime of this thread, so the
        // wait must not block it.
        ostrya_rt::unblock(move || child.wait()).await;

        assert_eq!(proxy.requests(), 0);
        assert!(server.seen().is_empty(), "{:?}", server.seen());
        assert_nothing_published(&Repo::open(&path).await.unwrap()).await;
    });
}

/// An `http_proxy` with white space at the end of its value fails the pull.
#[test]
fn a_pull_refuses_an_http_proxy_with_trailing_white_space() {
    pull_refuses_the_environment_proxy("pull-http-proxy-env-trailing", |url| format!("{url}  "));
}

/// An `http_proxy` with white space at the start of its value fails the pull.
#[test]
fn a_pull_refuses_an_http_proxy_with_leading_white_space() {
    pull_refuses_the_environment_proxy("pull-http-proxy-env-leading", |url| format!(" {url}"));
}

/// If the `proxy` key is empty, the pull reads the proxy from the environment.
#[test]
fn an_empty_proxy_key_reads_the_environment() {
    pull_through_the_environment_proxy("pull-http-proxy-key-empty", "proxy=\n");
}

/// If a remote has no `proxy` key, the pull reads the proxy from the
/// environment.
#[test]
fn no_proxy_key_reads_the_environment() {
    pull_through_the_environment_proxy("pull-http-proxy-key-absent", "");
}

// --- the transport of a pull ------------------------------------------------

/// The address of a remote that answers no request. A pull that read it would
/// fail.
const DEAD_URL: &str = "http://127.0.0.1:1/";

/// Pulls `test/main` through an HTTP session of the options `http`, with no
/// check of signatures, into refs under the remote name `origin`.
async fn pull_main_over(dest: &Repo, http: FetcherOptions) -> Result<PullStats, Error> {
    let session = PullSession::connect(Endpoint::Http(http), StreamSessionOptions::default())
        .await
        .unwrap();
    dest.pull_with_session(
        session,
        PullTrust::unverified(),
        PullOptions {
            refs: vec!["test/main".to_owned()],
            remote: Some("origin".to_owned()),
            ..PullOptions::default()
        },
    )
    .await
}

/// A session with the fixture authority as `TrustRoots::Pem` pulls over
/// HTTPS. The config of the remote holds no TLS key. The same options refuse
/// a leaf that another authority signed, and the pull publishes nothing.
#[test]
fn a_session_with_a_ca_certificate_pulls_over_https() {
    block_on(async {
        let dir = TmpDir::new("pull-http-session-ca");
        let (_remote, commit) = build_remote(dir.path()).await;
        let root = dir.path().join("remote");
        let dest = build_dest(dir.path(), RepoMode::Archive, DEAD_URL, "").await;

        let untrusted = RepoServer::start_with_leaf(&root, true, Leaf::Untrusted).await;
        let mut http = https_endpoint(&untrusted);
        // A failed handshake is retryable, so the test turns off the retry
        // rounds.
        http.max_retries = 0;
        let err = pull_main_over(&dest, http).await.unwrap_err();
        assert!(err.to_string().contains("UnknownIssuer"), "{err}");
        assert_nothing_published(&dest).await;

        let server = RepoServer::start(&root, true).await;
        pull_main_over(&dest, https_endpoint(&server))
            .await
            .unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(commit)
        );
    });
}

/// A session with a client identity pulls from a server that demands a client
/// certificate. With no identity, the same server refuses the pull, and the
/// pull publishes nothing.
#[test]
fn a_session_with_a_client_certificate_pulls_over_https() {
    block_on(async {
        let dir = TmpDir::new("pull-http-session-client");
        let (_remote, commit) = build_remote(dir.path()).await;
        let server =
            RepoServer::start_demanding_client_certificate(&dir.path().join("remote")).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, DEAD_URL, "").await;

        let mut http = https_endpoint(&server);
        http.max_retries = 0;
        let err = pull_main_over(&dest, http.clone()).await.unwrap_err();
        assert!(matches!(err, Error::Fetch(_)), "{err}");
        assert_nothing_published(&dest).await;

        http.tls.client_identity = Some(ClientIdentity {
            cert_chain_pem: CLIENT_CERT_PEM.to_vec(),
            key_pem: CLIENT_KEY_PEM.to_vec(),
            key_passphrase: None,
        });
        pull_main_over(&dest, http).await.unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(commit)
        );
    });
}

/// A session with a bearer token pulls from a server that demands the token.
/// With no token, the server answers 401, and the pull publishes nothing.
#[test]
fn a_session_with_a_bearer_token_pulls_over_https() {
    block_on(async {
        let dir = TmpDir::new("pull-http-session-bearer");
        let (_remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), true).await;
        server.require_bearer("pull-T0ken");
        let dest = build_dest(dir.path(), RepoMode::Archive, DEAD_URL, "").await;

        let mut http = https_endpoint(&server);
        http.max_retries = 0;
        let err = pull_main_over(&dest, http.clone()).await.unwrap_err();
        assert!(
            matches!(err, Error::HttpStatus { status: 401, .. }),
            "{err}"
        );
        assert_nothing_published(&dest).await;

        http.bearer_token = Some(BearerToken {
            token: "pull-T0ken".to_owned(),
        });
        pull_main_over(&dest, http).await.unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(commit)
        );
    });
}

/// A session pull under the trust of a named remote checks the commits
/// against the signature keys of that remote. The session replaces the
/// address, the TLS keys, and the `proxy` key of the remote. Each of these
/// keys would fail the pull.
#[test]
fn a_session_pull_under_the_trust_of_a_remote_reads_no_tls_key() {
    block_on(async {
        let dir = TmpDir::new("pull-http-session-remote-trust");
        let (_remote, commit) = build_signed_remote(dir.path(), Some(SECRET_B64)).await;
        let server = RepoServer::start(&dir.path().join("remote"), true).await;
        let keys = |public: &str| {
            format!(
                "tls-ca-path={}\ntls-permissive=maybe\nproxy={DEAD_URL}\n\
                 sign-verify=ed25519\nverification-ed25519-key={public}\n",
                dir.path().join("absent-ca.pem").display()
            )
        };
        let pull = |dest: Repo| {
            let server = &server;
            async move {
                let trust = PullTrust::from_remote(&dest, "origin", &PullVerify::default())
                    .await
                    .unwrap();
                let session = PullSession::connect(
                    Endpoint::Http(https_endpoint(server)),
                    StreamSessionOptions::default(),
                )
                .await
                .unwrap();
                let pulled = dest
                    .pull_with_session(
                        session,
                        trust,
                        PullOptions {
                            refs: vec!["test/main".to_owned()],
                            remote: Some("origin".to_owned()),
                            ..PullOptions::default()
                        },
                    )
                    .await;
                (dest, pulled)
            }
        };

        let dest = build_dest(
            dir.path(),
            RepoMode::Archive,
            DEAD_URL,
            &keys(OTHER_PUBLIC_B64),
        )
        .await;
        let (dest, pulled) = pull(dest).await;
        let err = pulled.unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("is from a trusted key")),
            "{err}"
        );
        assert_nothing_published(&dest).await;

        let dest = reconfigure_dest(dir.path(), DEAD_URL, &keys(PUBLIC_B64)).await;
        let (dest, pulled) = pull(dest).await;
        pulled.unwrap();
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(commit)
        );
    });
}

/// A `tls-ca-path` file over 1 MiB fails a pull before any request. The pull
/// publishes nothing.
#[test]
fn a_ca_file_over_one_mib_fails_the_pull_before_any_request() {
    block_on(async {
        let dir = TmpDir::new("pull-http-endpoint-ca-cap");
        build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), true).await;
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, vec![b'a'; (1 << 20) + 1]).unwrap();
        let dest = build_dest(
            dir.path(),
            RepoMode::Archive,
            &server.url(),
            &format!("tls-ca-path={}\n", ca.display()),
        )
        .await;

        let err = pull_main(&dest, PullOptions::default()).await.unwrap_err();
        assert!(
            matches!(&err, Error::InvalidInput(m) if m.contains("over 1 MiB")),
            "{err}"
        );
        assert!(server.seen().is_empty(), "{:?}", server.seen());
        assert_nothing_published(&dest).await;
    });
}

/// Builds an archive remote under `dir/remote` whose ref `test/main` names a
/// commit of one directory of 32 files, with a summary. The 32 content
/// objects give the pull 32 fetches that it can run at the same time.
async fn build_wide_remote(dir: &Path) -> std::path::PathBuf {
    let src = dir.join("src");
    std::fs::create_dir(&src).unwrap();
    for i in 0..32 {
        std::fs::write(src.join(format!("file-{i}")), format!("{i}\n")).unwrap();
    }
    let root = dir.join("remote");
    let remote = Repo::create(&root, CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap();
    commit_tree(&remote, dir, "src", "test/main", None, FIXED_TS).await;
    remote
        .regenerate_summary(&SummaryOptions {
            last_modified: Some(FIXED_TS),
            ..SummaryOptions::default()
        })
        .await
        .unwrap();
    root
}

/// The peak of requests in flight that the server sees follows
/// `max_outstanding_fetches` when it is set, and the limit of the resolved
/// endpoint, 8, when it is `None`. A value of 1 holds the peak at 1. A value
/// of 16 gives a peak above 8.
#[test]
fn max_outstanding_fetches_sets_the_limit_of_the_resolved_endpoint() {
    block_on(async {
        let dir = TmpDir::new("pull-http-endpoint-outstanding");
        let root = build_wide_remote(dir.path()).await;
        for (tag, max_outstanding_fetches) in
            [("serial", Some(1)), ("parallel", Some(16)), ("unset", None)]
        {
            let server = RepoServer::start(&root, false).await;
            let base = dir.path().join(tag);
            std::fs::create_dir(&base).unwrap();
            let dest = build_dest(&base, RepoMode::Archive, &server.url(), "").await;
            pull_main(
                &dest,
                PullOptions {
                    max_outstanding_fetches,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();
            let peak = server.peak_inflight();
            match max_outstanding_fetches {
                Some(1) => assert_eq!(peak, 1, "{tag}"),
                Some(_) => assert!(peak > 8, "{tag}: {peak}"),
                None => assert!(peak <= 8, "{tag}: {peak}"),
            }
        }
    });
}

// --- a pull through a session of the caller ----------------------------------

/// Creates an archive destination under `dir/dest` whose config has no remote
/// section.
async fn dest_with_no_remote(dir: &Path) -> Repo {
    Repo::create(&dir.join("dest"), CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap()
}

/// Returns the options of a fetcher for the cleartext `server`, with no proxy
/// and a request limit of `max_outstanding`.
///
/// The server sends no redirect. With no redirect to follow, the fetcher
/// reads no trust store.
fn session_options(server: &RepoServer, max_outstanding: usize) -> FetcherOptions {
    let mut http = FetcherOptions::new(server.url());
    http.proxy = Proxy::None;
    http.max_redirects = 0;
    http.max_outstanding = max_outstanding;
    http
}

/// Opens an HTTP session to the cleartext `server` with the default request
/// limit of the fetcher.
async fn http_session(server: &RepoServer) -> PullSession {
    let http = session_options(server, FetcherOptions::default().max_outstanding);
    PullSession::Http(Fetcher::new(http).await.unwrap())
}

/// Returns the trusted keys of the ed25519 public key `public`, in base64.
fn ed25519_keys(public: &str) -> TrustedKeys {
    let public = ostrya::base64::decode(public).unwrap();
    let verifier = Ed25519Verifier::new([public], Vec::<Vec<u8>>::new()).unwrap();
    TrustedKeys::new(vec![Arc::new(verifier)]).unwrap()
}

/// The objects, the refs, and the state files of the repository at `path`.
fn repo_snapshot(path: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = file_inventory(path, "objects");
    out.extend(file_inventory(path, "refs"));
    out.extend(file_inventory(path, "state"));
    out
}

/// A pull through a session checks each commit against the keys of its trust
/// alone. The destination has no remote section. A trust of another key
/// refuses the commit, and the pull publishes nothing. A trust of the signing
/// key, for the commits and the summary, accepts the pull.
#[test]
fn a_session_pull_checks_the_commits_against_the_keys_of_its_trust() {
    block_on(async {
        let dir = TmpDir::new("pull-http-session-trust");
        let (_remote, commit) = build_signed_remote(dir.path(), Some(SECRET_B64)).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = dest_with_no_remote(dir.path()).await;
        let dest_dir = dir.path().join("dest");
        let before = repo_snapshot(&dest_dir);
        let opts = || PullOptions {
            refs: vec!["test/main".to_owned()],
            ..PullOptions::default()
        };

        let trust = PullTrust::commits(ed25519_keys(OTHER_PUBLIC_B64));
        let err = dest
            .pull_with_session(http_session(&server).await, trust, opts())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("is from a trusted key")),
            "{err}"
        );
        assert_nothing_published(&dest).await;
        assert_eq!(repo_snapshot(&dest_dir), before);

        let trust =
            PullTrust::commits(ed25519_keys(PUBLIC_B64)).with_summary(ed25519_keys(PUBLIC_B64));
        dest.pull_with_session(http_session(&server).await, trust, opts())
            .await
            .unwrap();
        assert_eq!(
            dest.resolve_rev("test/main", true).await.unwrap(),
            Some(commit)
        );
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
    });
}

/// A pull through a session refuses each option that it cannot carry, and a
/// `remote` that is not a valid remote name, also under `MIRROR`. Each refusal
/// comes before the first request and writes no object and no ref. A refusal
/// of an option leaves the progress handle of the caller at its default.
#[test]
fn a_session_pull_refuses_its_options_before_the_first_request() {
    block_on(async {
        let dir = TmpDir::new("pull-http-session-refusals");
        build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = dest_with_no_remote(dir.path()).await;
        let dest_dir = dir.path().join("dest");
        let before = repo_snapshot(&dest_dir);
        let main = || PullOptions {
            refs: vec!["test/main".to_owned()],
            ..PullOptions::default()
        };

        let cases = [
            ("no refs", PullOptions::default()),
            (
                "no refs under mirror",
                PullOptions {
                    flags: PullFlags::MIRROR,
                    ..PullOptions::default()
                },
            ),
            (
                "verify",
                PullOptions {
                    verify: PullVerify {
                        gpg: Some(false),
                        ..PullVerify::default()
                    },
                    ..main()
                },
            ),
            (
                "trust_group",
                PullOptions {
                    trust_group: Some("t".to_owned()),
                    ..main()
                },
            ),
            (
                "max_outstanding_fetches",
                PullOptions {
                    max_outstanding_fetches: Some(1),
                    ..main()
                },
            ),
            (
                "overrides",
                PullOptions {
                    overrides: EndpointOverrides {
                        url: Some(DEAD_URL.to_owned()),
                        ..EndpointOverrides::default()
                    },
                    ..main()
                },
            ),
            (
                "depth",
                PullOptions {
                    depth: -2,
                    ..main()
                },
            ),
            (
                "subpath",
                PullOptions {
                    subpaths: vec!["relative".to_owned()],
                    ..main()
                },
            ),
            (
                "collection_id",
                PullOptions {
                    collection_id: Some("org.example.Os".to_owned()),
                    ..main()
                },
            ),
        ];
        for (tag, opts) in cases {
            let progress = ostrya::PullProgress::new();
            let opts = PullOptions {
                progress: Some(progress.clone()),
                ..opts
            };
            let err = dest
                .pull_with_session(http_session(&server).await, PullTrust::unverified(), opts)
                .await
                .unwrap_err();
            match (tag, &err) {
                ("collection_id", Error::Unsupported(m)) => {
                    assert_eq!(m, "only a local pull takes a collection id")
                }
                ("overrides", Error::InvalidInput(m)) => assert_eq!(
                    m,
                    "a pull with a session takes its server from the session, and takes \
                     no endpoint overrides"
                ),
                ("trust_group", Error::InvalidInput(m)) => assert_eq!(
                    m,
                    "a pull with a session takes its signature policy from its trust, and \
                     takes no trust group"
                ),
                ("subpath", Error::Pull(_)) => {}
                ("collection_id" | "subpath" | "overrides" | "trust_group", _) => {
                    panic!("{tag}: {err:?}")
                }
                (_, Error::InvalidInput(_)) => {}
                _ => panic!("{tag}: {err:?}"),
            }
            assert_eq!(
                progress.snapshot(),
                ostrya::PullProgressSnapshot::default(),
                "{tag}"
            );
        }
        for flags in [PullFlags::NONE, PullFlags::MIRROR] {
            for name in ["a:b", "a/b", ""] {
                let opts = PullOptions {
                    remote: Some(name.to_owned()),
                    flags,
                    ..main()
                };
                let err = dest
                    .pull_with_session(http_session(&server).await, PullTrust::unverified(), opts)
                    .await
                    .unwrap_err();
                assert!(
                    matches!(&err, Error::InvalidInput(m) if *m == format!("invalid remote name: {name}")),
                    "{name:?}: {err:?}"
                );
            }
        }
        // A pull with no ref names the missing refs, and not the list.
        let no_refs = (
            "no refs with a list",
            PullOptions {
                static_deltas: Some(vec![listed_delta(Some(1), 2, 3)]),
                ..PullOptions::default()
            },
            ListRefusal::InvalidInput(
                "a pull with a session needs at least one ref name".to_owned(),
            ),
        );
        for (tag, opts, expected) in static_delta_list_cases(main).into_iter().chain([no_refs]) {
            let progress = ostrya::PullProgress::new();
            let opts = PullOptions {
                progress: Some(progress.clone()),
                ..opts
            };
            let err = dest
                .pull_with_session(http_session(&server).await, PullTrust::unverified(), opts)
                .await
                .unwrap_err();
            assert_list_refusal(tag, &err, &expected);
            assert_eq!(
                progress.snapshot(),
                ostrya::PullProgressSnapshot::default(),
                "{tag}"
            );
        }

        assert!(server.seen().is_empty(), "{:?}", server.seen());
        assert_eq!(repo_snapshot(&dest_dir), before);
    });
}

/// `remote` selects the prefix of the refs that a pull through a session
/// writes. `None` writes a local ref, and `Some(name)` writes a ref under
/// `refs/remotes/<name>`. A `MIRROR` pull of a named ref with
/// `Some(name)` writes a local ref and leaves no summary.
#[test]
fn a_session_pull_names_its_refs_after_the_remote_option() {
    block_on(async {
        let dir = TmpDir::new("pull-http-session-refs");
        let (_remote, commit) = build_remote(dir.path()).await;
        std::fs::write(dir.path().join("remote/summary.sig"), SUMMARY_SIG).unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let pull = |tag: &'static str, remote: Option<&str>, flags: PullFlags| {
            let base = dir.path().join(tag);
            let remote = remote.map(str::to_owned);
            let server = &server;
            async move {
                std::fs::create_dir(&base).unwrap();
                let dest = dest_with_no_remote(&base).await;
                dest.pull_with_session(
                    http_session(server).await,
                    PullTrust::unverified(),
                    PullOptions {
                        refs: vec!["test/main".to_owned()],
                        remote,
                        flags,
                        ..PullOptions::default()
                    },
                )
                .await
                .unwrap();
                (dest, base.join("dest"))
            }
        };

        let (dest, _) = pull("to-local", None, PullFlags::NONE).await;
        assert_eq!(
            dest.resolve_rev("test/main", true).await.unwrap(),
            Some(commit)
        );
        assert!(
            dest.list_refs(Some("refs/remotes"))
                .await
                .unwrap()
                .is_empty()
        );

        let (dest, _) = pull("to-remote", Some("up"), PullFlags::NONE).await;
        assert_eq!(
            dest.resolve_rev("up:test/main", true).await.unwrap(),
            Some(commit)
        );
        assert!(dest.list_refs(None).await.unwrap().is_empty());

        let (dest, dest_dir) = pull("to-mirror", Some("up"), PullFlags::MIRROR).await;
        assert_eq!(
            dest.resolve_rev("test/main", true).await.unwrap(),
            Some(commit)
        );
        assert_eq!(dest.resolve_rev("up:test/main", true).await.unwrap(), None);
        assert!(!dest_dir.join("summary").exists());
        assert!(!dest_dir.join("summary.sig").exists());
    });
}

/// Under `no_ref_writes`, `remote` still selects the ref that a pull through
/// a session reads. `TimestampCheck::CurrentRef` compares the tip with the
/// local ref for `None`, and with the ref under `refs/remotes/<name>` for
/// `Some(name)`.
#[test]
fn a_session_pull_with_no_ref_writes_reads_the_selected_ref() {
    block_on(async {
        let dir = TmpDir::new("pull-http-session-current-ref");
        let (_remote, older) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = dest_with_no_remote(dir.path()).await;
        build_tree(&dir.path().join("newer"), b"newer\n");
        let newer = commit_tree(
            &dest,
            dir.path(),
            "newer",
            "test/main",
            None,
            FIXED_TS + 100,
        )
        .await;
        let opts = |remote: Option<&str>| PullOptions {
            refs: vec!["test/main".to_owned()],
            remote: remote.map(str::to_owned),
            no_ref_writes: true,
            timestamp_check: TimestampCheck::CurrentRef,
            ..PullOptions::default()
        };

        let err = dest
            .pull_with_session(
                http_session(&server).await,
                PullTrust::unverified(),
                opts(None),
            )
            .await
            .unwrap_err();
        assert!(matches!(&err, Error::Pull(_)), "{err}");
        assert!(err.to_string().contains(&newer.to_hex()), "{err}");

        dest.pull_with_session(
            http_session(&server).await,
            PullTrust::unverified(),
            opts(Some("up")),
        )
        .await
        .unwrap();
        assert_eq!(
            dest.resolve_rev("test/main", true).await.unwrap(),
            Some(newer)
        );
        assert_eq!(dest.resolve_rev("up:test/main", true).await.unwrap(), None);
        assert_eq!(
            dest.commit_state(&older).await.unwrap(),
            CommitState::Normal
        );
    });
}

/// A pull through a session counts as `Repo::pull` counts. The statistics,
/// less the run time, and the progress counters of the two pulls agree. A
/// counter that the caller attaches to its fetcher also counts the summary
/// and the config.
#[test]
fn a_session_pull_counts_as_a_pull_of_a_named_remote() {
    block_on(async {
        let dir = TmpDir::new("pull-http-session-counters");
        build_remote(dir.path()).await;
        let root = dir.path().join("remote");
        let server = RepoServer::start(&root, false).await;
        let opts = |progress: &ostrya::PullProgress| PullOptions {
            refs: vec!["test/main".to_owned()],
            progress: Some(progress.clone()),
            ..PullOptions::default()
        };

        let named_base = dir.path().join("named");
        std::fs::create_dir(&named_base).unwrap();
        let named = build_dest(&named_base, RepoMode::Archive, &server.url(), "").await;
        let named_progress = ostrya::PullProgress::new();
        let expected = named.pull("origin", opts(&named_progress)).await.unwrap();

        let session_base = dir.path().join("session");
        std::fs::create_dir(&session_base).unwrap();
        let dest = dest_with_no_remote(&session_base).await;
        let counted = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let fetcher = Fetcher::new(session_options(&server, 8))
            .await
            .unwrap()
            .counted(vec![Arc::clone(&counted)]);
        let progress = ostrya::PullProgress::new();
        let stats = dest
            .pull_with_session(
                PullSession::Http(fetcher),
                PullTrust::unverified(),
                opts(&progress),
            )
            .await
            .unwrap();

        let timeless = |stats: PullStats| PullStats {
            elapsed: Default::default(),
            ..stats
        };
        assert_eq!(timeless(stats), timeless(expected));
        assert_eq!(progress.snapshot(), named_progress.snapshot());
        assert!(stats.bytes_transferred > 0);
        let root_files = ["summary", "config"]
            .iter()
            .map(|file| std::fs::metadata(root.join(file)).unwrap().len())
            .sum::<u64>();
        assert_eq!(
            counted.load(std::sync::atomic::Ordering::Relaxed),
            stats.bytes_transferred + root_files
        );
    });
}

/// A pull through a session keeps as many requests in flight as its fetcher
/// admits. A limit of 1 holds the peak at 1. A limit of 16 gives a peak above
/// 8, the limit of a pull that names no limit.
#[test]
fn a_session_pull_takes_its_request_limit_from_the_session() {
    block_on(async {
        let dir = TmpDir::new("pull-http-session-limit");
        let root = build_wide_remote(dir.path()).await;
        for (tag, limit, serial) in [("serial", 1, true), ("parallel", 16, false)] {
            let server = RepoServer::start(&root, false).await;
            let base = dir.path().join(tag);
            std::fs::create_dir(&base).unwrap();
            let dest = dest_with_no_remote(&base).await;
            let fetcher = Fetcher::new(session_options(&server, limit)).await.unwrap();
            dest.pull_with_session(
                PullSession::Http(fetcher),
                PullTrust::unverified(),
                PullOptions {
                    refs: vec!["test/main".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();
            if serial {
                assert_eq!(server.peak_inflight(), 1, "{tag}");
            } else {
                assert!(
                    server.peak_inflight() > 8,
                    "{tag}: {}",
                    server.peak_inflight()
                );
            }
        }
    });
}

// --- dependencies ------------------------------------------------------------

/// Regenerates the summary of `repo` with a fixed timestamp.
async fn summarize(repo: &Repo) {
    repo.regenerate_summary(&SummaryOptions {
        last_modified: Some(FIXED_TS),
        ..SummaryOptions::default()
    })
    .await
    .unwrap();
}

/// Builds an archive remote under `dir/remote`, with a summary. `dep/uki`
/// names the dependency, and `test/main` names the tip, whose field 2 names
/// the dependency as `boot/uki`. Returns the remote, the tip, and the
/// dependency.
async fn build_dependency_remote(dir: &Path) -> (Repo, Checksum, Checksum) {
    build_tree(&dir.join("uki"), b"uki\n");
    build_tree(&dir.join("main"), b"main\n");
    let remote = Repo::create(&dir.join("remote"), CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap();
    let dep = commit_tree(&remote, dir, "uki", "dep/uki", None, FIXED_TS).await;
    let tip = commit_tree_related(
        &remote,
        dir,
        "main",
        "test/main",
        None,
        &[("boot/uki", dep)],
    )
    .await;
    summarize(&remote).await;
    (remote, tip, dep)
}

/// Sets the ref `name` of `repo` to `commit` and regenerates the summary.
async fn move_ref(repo: &Repo, name: &str, commit: &Checksum) {
    let txn = repo.transaction().await.unwrap();
    txn.set_ref(name, Some(commit));
    txn.commit().await.unwrap();
    summarize(repo).await;
}

/// Returns the number of distinct content objects of `commits` in `remote`.
async fn distinct_content(remote: &Repo, commits: &[Checksum]) -> usize {
    let mut all = HashSet::new();
    for commit in commits {
        all.extend(content_checksums(remote, commit).await);
    }
    all.len()
}

/// Asserts that a failed pull left nothing in `dest`: no object, no local
/// ref, no remote ref, and no file under `state/`.
async fn assert_left_nothing(dest: &Repo) {
    assert!(dest.list_objects().await.unwrap().is_empty());
    assert!(dest.list_refs(None).await.unwrap().is_empty());
    assert!(dest.list_remote_refs().await.unwrap().is_empty());
    assert_eq!(file_inventory(dest.path(), "state"), Vec::new());
}

/// A pull fetches the dependency that field 2 of the pulled commit names,
/// complete, and writes no ref for it. The content count of the pull holds
/// the content of the dependency. A repeat pull reads the detached metadata
/// of the tip alone again, and fetches no object.
#[test]
fn a_pull_fetches_the_dependency_of_the_commit() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency");
        let (remote, tip, dep) = build_dependency_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let stats = pull_main(&dest, PullOptions::default()).await.unwrap();

        assert_complete(&remote, &dest, dest.path(), &dep).await;
        assert_complete(&remote, &dest, dest.path(), &tip).await;
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
        assert_eq!(
            stats.content_fetched as usize,
            distinct_content(&remote, &[tip, dep]).await
        );
        assert!(dest.list_refs(None).await.unwrap().is_empty());
        assert_eq!(
            dest.list_remote_refs().await.unwrap(),
            [("origin:test/main".to_owned(), tip)]
        );

        server.forget();
        let repeated = pull_main(&dest, PullOptions::default()).await.unwrap();
        assert_eq!(
            (repeated.metadata_fetched, repeated.content_fetched),
            (0, 0)
        );
        assert_eq!(
            server.seen(),
            [
                "summary.sig".to_owned(),
                "summary".to_owned(),
                "config".to_owned(),
                meta_path(&tip, "commitmeta"),
            ]
        );
    });
}

/// A pull with depth follows the dependencies of each parent that it
/// moves. At depth 0 it moves no parent, so it fetches the dependency of the
/// tip alone.
#[test]
fn a_pull_with_depth_fetches_the_dependencies_of_the_parents() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-parent");
        let base = dir.path();
        for sub in ["d1", "d2", "p", "t"] {
            build_tree(&base.join(sub), sub.as_bytes());
        }
        let remote = Repo::create(&base.join("remote"), CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let d1 = commit_tree(&remote, base, "d1", "dep/d1", None, FIXED_TS).await;
        let d2 = commit_tree(&remote, base, "d2", "dep/d2", None, FIXED_TS).await;
        let parent =
            commit_tree_related(&remote, base, "p", "test/main", None, &[("boot/d1", d1)]).await;
        let tip = commit_tree_related(
            &remote,
            base,
            "t",
            "test/main",
            Some(parent),
            &[("boot/d2", d2)],
        )
        .await;
        summarize(&remote).await;
        let server = RepoServer::start(&base.join("remote"), false).await;

        for depth in [0, 1] {
            let path = base.join(format!("depth-{depth}"));
            std::fs::create_dir(&path).unwrap();
            let dest = build_dest(&path, RepoMode::Archive, &server.url(), "").await;
            pull_main(
                &dest,
                PullOptions {
                    depth,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();
            assert_complete(&remote, &dest, dest.path(), &tip).await;
            assert_complete(&remote, &dest, dest.path(), &d2).await;
            for commit in [parent, d1] {
                assert_eq!(
                    dest.has_object(ObjectType::Commit, &commit).await.unwrap(),
                    depth == 1,
                    "depth {depth}: {commit}"
                );
            }
            if depth == 1 {
                assert_complete(&remote, &dest, dest.path(), &d1).await;
            }
            assert_eq!(
                dest.list_remote_refs().await.unwrap(),
                [("origin:test/main".to_owned(), tip)]
            );
        }
    });
}

/// A dependency that two pulled commits name is fetched one time.
#[test]
fn a_dependency_that_two_commits_name_is_fetched_once() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-once");
        let base = dir.path();
        for sub in ["uki", "p", "t"] {
            build_tree(&base.join(sub), sub.as_bytes());
        }
        let remote = Repo::create(&base.join("remote"), CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let dep = commit_tree(&remote, base, "uki", "dep/uki", None, FIXED_TS).await;
        let parent =
            commit_tree_related(&remote, base, "p", "test/main", None, &[("boot/uki", dep)]).await;
        commit_tree_related(
            &remote,
            base,
            "t",
            "test/main",
            Some(parent),
            &[("boot/uki", dep)],
        )
        .await;
        summarize(&remote).await;
        let server = RepoServer::start(&base.join("remote"), false).await;
        let dest = build_dest(base, RepoMode::Archive, &server.url(), "").await;

        pull_main(
            &dest,
            PullOptions {
                depth: 1,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert_complete(&remote, &dest, dest.path(), &dep).await;
        assert_eq!(server.requests_for(&meta_path(&dep, "commit")), 1);
        assert_eq!(server.requests_for(&meta_path(&dep, "commitmeta")), 1);
    });
}

/// A pull fetches a dependency at depth 0, also under a pull of the whole
/// history. The parent of the dependency stays on the remote.
#[test]
fn a_dependency_is_fetched_at_depth_zero() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-depth");
        let base = dir.path();
        for sub in ["old", "uki", "main"] {
            build_tree(&base.join(sub), sub.as_bytes());
        }
        let remote = Repo::create(&base.join("remote"), CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let old = commit_tree(&remote, base, "old", "dep/uki", None, FIXED_TS).await;
        let dep = commit_tree(&remote, base, "uki", "dep/uki", Some(old), FIXED_TS + 1).await;
        let tip = commit_tree_related(
            &remote,
            base,
            "main",
            "test/main",
            None,
            &[("boot/uki", dep)],
        )
        .await;
        summarize(&remote).await;
        let server = RepoServer::start(&base.join("remote"), false).await;
        let dest = build_dest(base, RepoMode::Archive, &server.url(), "").await;

        pull_main(
            &dest,
            PullOptions {
                depth: -1,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        assert_complete(&remote, &dest, dest.path(), &tip).await;
        assert_complete(&remote, &dest, dest.path(), &dep).await;
        assert!(!dest.has_object(ObjectType::Commit, &old).await.unwrap());
        assert_eq!(server.requests_for(&meta_path(&old, "commit")), 0);
    });
}

/// A pull does not fetch a build source: the commit that `ostrya.related`
/// names.
#[test]
fn a_pull_does_not_fetch_a_build_source() {
    block_on(async {
        let dir = TmpDir::new("pull-http-build-source");
        let (remote, tip, _dep) = build_dependency_remote(dir.path()).await;
        build_tree(&dir.path().join("base"), b"base\n");
        let source = commit_tree(&remote, dir.path(), "base", "other/base", None, FIXED_TS).await;
        remote
            .add_detached_related(&tip, "layer/base", &source)
            .await
            .unwrap();
        summarize(&remote).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        pull_main(&dest, PullOptions::default()).await.unwrap();

        assert_eq!(
            dest.read_commit_related(&tip).await.unwrap().build_sources,
            [("layer/base".to_owned(), source)]
        );
        assert!(!dest.has_object(ObjectType::Commit, &source).await.unwrap());
        for ext in ["commit", "commitmeta"] {
            assert_eq!(server.requests_for(&meta_path(&source, ext)), 0, "{ext}");
        }
    });
}

/// A commit-only pull and a pull with subpaths fetch no dependency. A later
/// full pull fetches it.
#[test]
fn a_partial_pull_fetches_no_dependency() {
    for (tag, opts) in [
        (
            "commit-only",
            PullOptions {
                flags: PullFlags::COMMIT_ONLY,
                ..PullOptions::default()
            },
        ),
        (
            "subpaths",
            PullOptions {
                subpaths: vec!["/".to_owned()],
                ..PullOptions::default()
            },
        ),
    ] {
        block_on(async {
            let dir = TmpDir::new(&format!("pull-http-dependency-{tag}"));
            let (remote, tip, dep) = build_dependency_remote(dir.path()).await;
            let server = RepoServer::start(&dir.path().join("remote"), false).await;
            let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

            pull_main(&dest, opts).await.unwrap();
            assert!(dest.has_object(ObjectType::Commit, &tip).await.unwrap());
            assert!(!dest.has_object(ObjectType::Commit, &dep).await.unwrap());
            for ext in ["commit", "commitmeta"] {
                assert_eq!(server.requests_for(&meta_path(&dep, ext)), 0, "{tag} {ext}");
            }

            pull_main(&dest, PullOptions::default()).await.unwrap();
            assert_complete(&remote, &dest, dest.path(), &tip).await;
            assert_complete(&remote, &dest, dest.path(), &dep).await;
        });
    }
}

/// A dependency whose bytes do not hash to the checksum in field 2 of the tip
/// fails the pull with `Error::ChecksumMismatch` for that checksum, and the
/// pull leaves nothing. The served bytes are those of a different commit with
/// an empty field 2, so the format check of field 2 passes and the hash of the
/// stage finds the defect. The pull checks no signature of the dependency, so
/// under `sign-verify` with a signed tip the pull fails with the same error.
#[test]
fn a_dependency_with_wrong_bytes_fails_the_pull() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-wrong-bytes");
        let (remote, tip, dep) = build_dependency_remote(dir.path()).await;
        sign_commits(&remote, &[tip]).await;
        build_tree(&dir.path().join("other"), b"other\n");
        let donor = commit_tree(&remote, dir.path(), "other", "other/x", None, FIXED_TS).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let donor_bytes =
            std::fs::read(dir.path().join("remote").join(meta_path(&donor, "commit"))).unwrap();
        server.tamper(&meta_path(&dep, "commit"), donor_bytes);

        for (tag, extra) in [("unverified", String::new()), ("verified", signed_policy())] {
            let base = dir.path().join(tag);
            std::fs::create_dir(&base).unwrap();
            let dest = build_dest(&base, RepoMode::Archive, &server.url(), &extra).await;
            let err = pull_main(&dest, PullOptions::default()).await.unwrap_err();
            assert!(
                matches!(err, Error::ChecksumMismatch { expected, .. } if expected == dep),
                "{tag}: {err}"
            );
            assert_left_nothing(&dest).await;
        }
    });
}

/// The pull checks no signature of a dependency. Under `sign-verify` with a
/// signed tip, an unsigned dependency passes the pull, and the destination
/// holds no detached metadata for it. A dependency that a key signed that the
/// destination does not trust passes too, and the destination holds the
/// `.commitmeta` of the remote.
#[test]
fn a_dependency_with_no_trusted_signature_passes_the_pull() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-signature");
        let (remote, tip, dep) = build_dependency_remote(dir.path()).await;
        sign_commits(&remote, &[tip]).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let path = meta_path(&dep, "commitmeta");

        let unsigned = dir.path().join("unsigned");
        std::fs::create_dir(&unsigned).unwrap();
        let dest = build_dest(
            &unsigned,
            RepoMode::Archive,
            &server.url(),
            &signed_policy(),
        )
        .await;
        pull_main(&dest, PullOptions::default()).await.unwrap();
        assert_complete(&remote, &dest, dest.path(), &dep).await;
        assert!(!dest.path().join(&path).exists());

        remote
            .sign_commit(&dep, &Ed25519Signer::from_base64(OTHER_SECRET_B64).unwrap())
            .await
            .unwrap();
        let other = dir.path().join("other");
        std::fs::create_dir(&other).unwrap();
        let dest = build_dest(&other, RepoMode::Archive, &server.url(), &signed_policy()).await;
        pull_main(&dest, PullOptions::default()).await.unwrap();
        assert_complete(&remote, &dest, dest.path(), &dep).await;
        assert_eq!(
            std::fs::read(dest.path().join(&path)).unwrap(),
            std::fs::read(remote.path().join(&path)).unwrap()
        );
    });
}

/// A dependency that the pull also takes as a target gets the check of a
/// target. Under `sign-verify` with a signed tip, an unsigned dependency that a
/// requested ref names fails the pull, and the pull leaves nothing.
#[test]
fn a_dependency_that_is_also_a_target_is_checked() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-target-signature");
        let (remote, tip, dep) = build_dependency_remote(dir.path()).await;
        sign_commits(&remote, &[tip]).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(
            dir.path(),
            RepoMode::Archive,
            &server.url(),
            &signed_policy(),
        )
        .await;

        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned(), "dep/uki".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains(&format!("commit {dep}"))),
            "{err}"
        );
        assert_left_nothing(&dest).await;
    });
}

/// A parent that the depth of the pull takes gets the check of a parent, also
/// if field 2 of the tip names it. Under `sign-verify` with a signed tip and
/// an unsigned parent, a pull at depth 0 takes the parent as a dependency
/// alone and passes. A pull at depth 1 refuses the parent.
#[test]
fn a_dependency_that_is_also_a_parent_is_checked() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-parent-signature");
        let base = dir.path();
        for sub in ["p", "t"] {
            build_tree(&base.join(sub), sub.as_bytes());
        }
        let remote = Repo::create(&base.join("remote"), CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let parent = commit_tree(&remote, base, "p", "test/main", None, FIXED_TS).await;
        let tip = commit_tree_related(
            &remote,
            base,
            "t",
            "test/main",
            Some(parent),
            &[("boot/base", parent)],
        )
        .await;
        summarize(&remote).await;
        sign_commits(&remote, &[tip]).await;
        let server = RepoServer::start(&base.join("remote"), false).await;

        for depth in [0, 1] {
            let path = base.join(format!("depth-{depth}"));
            std::fs::create_dir(&path).unwrap();
            let dest = build_dest(&path, RepoMode::Archive, &server.url(), &signed_policy()).await;
            let pulled = pull_main(
                &dest,
                PullOptions {
                    depth,
                    ..PullOptions::default()
                },
            )
            .await;
            if depth == 0 {
                pulled.unwrap();
                assert_complete(&remote, &dest, dest.path(), &parent).await;
            } else {
                let err = pulled.unwrap_err();
                assert!(
                    matches!(&err, Error::Signature(m) if m.contains(&format!("commit {parent}"))),
                    "depth {depth}: {err}"
                );
                assert_left_nothing(&dest).await;
            }
        }
    });
}

/// The pull checks no signature of a dependency, so under `sign-verify` and
/// the default `keep-detached-related` it does not parse the `.commitmeta` of
/// a dependency. A `.commitmeta` that does not parse passes the pull, and the
/// destination holds its bytes. With `keep-detached-related=false`, the rule
/// parses the `.commitmeta`, and the pull fails with `Error::Core` and leaves
/// nothing.
#[test]
fn a_dependency_commitmeta_that_does_not_parse_is_stored() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-commitmeta-garbage");
        let (remote, tip, dep) = build_dependency_remote(dir.path()).await;
        sign_commits(&remote, &[tip]).await;
        let path = meta_path(&dep, "commitmeta");
        let garbage = b"\x01\x02\x03\x04\x05";
        std::fs::write(remote.path().join(&path), garbage).unwrap();
        let server = RepoServer::start(remote.path(), false).await;

        let kept = dir.path().join("kept");
        std::fs::create_dir(&kept).unwrap();
        let dest = build_dest(&kept, RepoMode::Archive, &server.url(), &signed_policy()).await;
        pull_main(&dest, PullOptions::default()).await.unwrap();
        assert_complete(&remote, &dest, dest.path(), &dep).await;
        assert_eq!(std::fs::read(dest.path().join(&path)).unwrap(), garbage);

        let dropped = dir.path().join("dropped");
        std::fs::create_dir(&dropped).unwrap();
        let extra = format!("{}{DROP_RELATED}", signed_policy());
        let dest = build_dest(&dropped, RepoMode::Archive, &server.url(), &extra).await;
        let err = pull_main(&dest, PullOptions::default()).await.unwrap_err();
        assert!(matches!(err, Error::Core(_)), "{err}");
        assert_left_nothing(&dest).await;
    });
}

/// A dependency that the remote does not hold fails the pull with
/// `Error::ObjectNotFound`, and the pull leaves nothing.
#[test]
fn a_missing_dependency_fails_the_pull() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-missing");
        let (_remote, _tip, dep) = build_dependency_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        server.hide(&meta_path(&dep, "commit"));
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let err = pull_main(&dest, PullOptions::default()).await.unwrap_err();
        assert!(
            matches!(
                err,
                Error::ObjectNotFound {
                    checksum,
                    ty: ObjectType::Commit,
                } if checksum == dep
            ),
            "{err:?}"
        );
        assert_left_nothing(&dest).await;
    });
}

/// A field 2 entry with an empty name or with a checksum that is not 32
/// bytes fails the pull with `Error::InvalidRelated`, and the pull leaves
/// nothing.
#[test]
fn a_defective_dependency_entry_fails_the_pull() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-defective");
        let (remote, tip, dep) = build_dependency_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let short: &[u8] = &dep.as_bytes()[..31];
        for (entry, reason) in [
            (
                ("boot/uki", short),
                "entry 0 (boot/uki) has a checksum of 31 bytes, not 32",
            ),
            (("", dep.as_bytes()), "entry 0 has an empty name"),
        ] {
            let defective = store_with_field2(&remote, &tip, &[entry]).await;
            move_ref(&remote, "test/main", &defective).await;
            let err = pull_main(&dest, PullOptions::default()).await.unwrap_err();
            assert_eq!(dependency_error(err), (Some(defective), reason.to_owned()));
            assert_left_nothing(&dest).await;
        }
    });
}

/// A dependency that names dependencies of its own fails the pull with
/// `Error::InvalidRelated`, whichever of the two commits the pull reads
/// first. The error names the commit that names the nested dependency. The
/// pull leaves nothing.
#[test]
fn a_nested_dependency_fails_the_pull() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-nested");
        let base = dir.path();
        let (remote, tip, dep) = build_dependency_remote(base).await;
        build_tree(&base.join("other"), b"other\n");
        let other = commit_tree(&remote, base, "other", "test/other", None, FIXED_TS).await;
        // `test/other` names a commit with a dependency, and `test/main` names
        // a commit whose dependency is that commit.
        let nested = store_with_field2(&remote, &other, &[("lib/c", dep.as_bytes())]).await;
        let head = store_with_field2(&remote, &tip, &[("lib/b", nested.as_bytes())]).await;
        move_ref(&remote, "test/other", &nested).await;
        move_ref(&remote, "test/main", &head).await;
        let server = RepoServer::start(&base.join("remote"), false).await;
        let dest = build_dest(base, RepoMode::Archive, &server.url(), "").await;

        let reason =
            format!("dependency lib/b names commit {nested}, which has dependencies of its own");
        for refs in [&["test/main"][..], &["test/main", "test/other"]] {
            let err = dest
                .pull(
                    "origin",
                    PullOptions {
                        refs: refs.iter().map(|r| (*r).to_owned()).collect(),
                        ..PullOptions::default()
                    },
                )
                .await
                .unwrap_err();
            assert_eq!(
                dependency_error(err),
                (Some(head), reason.clone()),
                "{refs:?}"
            );
            assert_left_nothing(&dest).await;
        }
    });
}

/// A parent that the remote does not hold ends its chain. If a pulled commit
/// names the parent as a dependency, the pull fails with
/// `Error::ObjectNotFound`. The tip names its own parent, so the plan queues
/// the parent first as an optional commit, and the dependency adds no item.
#[test]
fn an_absent_parent_that_is_a_dependency_fails_the_pull() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-absent-parent");
        let base = dir.path();
        for sub in ["p", "t"] {
            build_tree(&base.join(sub), sub.as_bytes());
        }
        let remote = Repo::create(&base.join("remote"), CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let parent = commit_tree(&remote, base, "p", "test/main", None, FIXED_TS).await;
        let plain = commit_tree(&remote, base, "t", "test/main", Some(parent), FIXED_TS + 1).await;
        let tip = store_with_field2(&remote, &plain, &[("boot/p", parent.as_bytes())]).await;
        move_ref(&remote, "test/main", &tip).await;
        let server = RepoServer::start(&base.join("remote"), false).await;
        server.hide(&meta_path(&parent, "commit"));
        let dest = build_dest(base, RepoMode::Archive, &server.url(), "").await;
        let opts = || PullOptions {
            depth: 1,
            ..PullOptions::default()
        };

        let err = pull_main(&dest, opts()).await.unwrap_err();
        assert!(
            matches!(
                err,
                Error::ObjectNotFound {
                    checksum,
                    ty: ObjectType::Commit,
                } if checksum == parent
            ),
            "{err:?}"
        );
        assert_left_nothing(&dest).await;

        // With no commit that names it, the absent parent ends its chain.
        move_ref(&remote, "test/main", &plain).await;
        pull_main(&dest, opts()).await.unwrap();
        assert!(!dest.has_object(ObjectType::Commit, &parent).await.unwrap());
    });
}

/// A pull that takes a static delta of the target fetches the dependency as
/// loose objects. The remote serves no summary, so the pull asks for the
/// from-scratch delta of the target by name, and then for the from-scratch
/// delta of the dependency, which the remote does not hold.
#[test]
fn a_pull_through_a_delta_fetches_the_dependency_loose() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-delta");
        let (remote, tip, dep) = build_dependency_remote(dir.path()).await;
        remote
            .generate_static_delta(
                None,
                &tip,
                &DeltaOptions {
                    timestamp: Some(FIXED_TS),
                    ..DeltaOptions::default()
                },
            )
            .await
            .unwrap();
        std::fs::remove_file(dir.path().join("remote/summary")).unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        pull_main(&dest, PullOptions::default()).await.unwrap();

        let seen = server.seen();
        assert!(
            seen.iter().any(|path| path.ends_with("/superblock")),
            "{seen:?}"
        );
        assert!(!seen.contains(&meta_path(&tip, "commit")), "{seen:?}");
        assert!(seen.contains(&meta_path(&dep, "commit")), "{seen:?}");
        assert_eq!(server.statuses_for(&scratch_superblock(&dep)), [404]);
        assert_complete(&remote, &dest, dest.path(), &tip).await;
        assert_complete(&remote, &dest, dest.path(), &dep).await;
    });
}

/// A pull through a chain of static deltas fetches a dependency one time, if
/// an intermediate commit and the target both name it.
#[test]
fn a_dependency_of_a_chain_is_fetched_once() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-chain");
        let base = dir.path();
        for sub in ["uki", "b", "c"] {
            build_tree(&base.join(sub), sub.as_bytes());
        }
        let remote = create_remote(base).await;
        let a = chain_commit(&remote, base, "a", "test/main", None, 0).await;
        let dep = commit_tree(&remote, base, "uki", "dep/uki", None, FIXED_TS).await;
        let b = commit_tree_related(
            &remote,
            base,
            "b",
            "test/main",
            Some(a),
            &[("boot/uki", dep)],
        )
        .await;
        let c = commit_tree_related(
            &remote,
            base,
            "c",
            "test/main",
            Some(b),
            &[("boot/uki", dep)],
        )
        .await;
        let list = vec![
            listed(&remote, &a, &b, DeltaOptions::default()).await,
            listed(&remote, &b, &c, DeltaOptions::default()).await,
        ];
        let server = RepoServer::start(remote.path(), false).await;
        let dest = dest_holding(base, &server.url(), &a).await;
        server.forget();

        dest.pull("origin", chain_opts(list)).await.unwrap();

        for (from, to) in [(a, b), (b, c)] {
            assert_eq!(server.requests_for(&superblock_path(&from, &to)), 1);
        }
        assert_eq!(server.requests_for(&meta_path(&dep, "commit")), 1);
        assert_eq!(server.requests_for(&meta_path(&dep, "commitmeta")), 1);
        for commit in [b, c, dep] {
            assert_complete(&remote, &dest, dest.path(), &commit).await;
        }
    });
}

/// A dependency that this repository holds partial is fetched whole, with a
/// request of its `.commitmeta`, and the pull removes its marker.
#[test]
fn a_dependency_held_partial_is_completed() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-partial");
        let (remote, _tip, dep) = build_dependency_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["dep/uki".to_owned()],
                flags: PullFlags::COMMIT_ONLY,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(dest.commit_state(&dep).await.unwrap(), CommitState::Partial);

        server.forget();
        pull_main(&dest, PullOptions::default()).await.unwrap();

        assert_complete(&remote, &dest, dest.path(), &dep).await;
        assert_eq!(server.requests_for(&meta_path(&dep, "commitmeta")), 1);
    });
}

// --- static deltas of dependencies ---------------------------------------

/// Builds an archive remote under `dir/remote` with two commits of a
/// dependency, D1 and D2, and two commits on `test/main`, T1 and T2. T1 names
/// D1 as `boot/uki`, and T2, a child of T1, names D2 as `boot/uki`. The ref
/// `test/main` names T1, and the remote holds a summary. Returns the remote
/// and `[T1, D1, T2, D2]`.
async fn build_dependency_generations(dir: &Path) -> (Repo, [Checksum; 4]) {
    for sub in ["uki1", "uki2", "main1", "main2"] {
        build_tree(&dir.join(sub), format!("{sub}\n").as_bytes());
    }
    let remote = create_remote(dir).await;
    let d1 = commit_tree(&remote, dir, "uki1", "dep/uki", None, FIXED_TS).await;
    let d2 = commit_tree(&remote, dir, "uki2", "dep/uki", Some(d1), FIXED_TS + 1).await;
    let t1 = commit_tree_related(
        &remote,
        dir,
        "main1",
        "test/main",
        None,
        &[("boot/uki", d1)],
    )
    .await;
    let t2 = commit_tree_related(
        &remote,
        dir,
        "main2",
        "test/main",
        Some(t1),
        &[("boot/uki", d2)],
    )
    .await;
    move_ref(&remote, "test/main", &t1).await;
    (remote, [t1, d1, t2, d2])
}

/// Returns the request path of the superblock of the from-scratch delta to
/// `to`.
fn scratch_superblock(to: &Checksum) -> String {
    format!("{}/superblock", static_delta_relative_dir(None, to))
}

/// The pull of T2 takes the delta of its dependency D2 from the paired entry
/// D1: the entry `boot/uki` of T1, which the local ref names before the pull.
/// The remote also publishes the from-scratch delta of D2, and the pull does
/// not request it. The commit of D2 comes from the superblock.
#[test]
fn the_delta_of_a_dependency_from_its_paired_entry_is_taken() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-delta-paired");
        let (remote, [_, d1, t2, d2]) = build_dependency_generations(dir.path()).await;
        let server = RepoServer::start(remote.path(), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        pull_main(&dest, PullOptions::default()).await.unwrap();
        publish_delta(&remote, Some(&d1), &d2).await;
        publish_delta(&remote, None, &d2).await;
        move_ref(&remote, "test/main", &t2).await;
        server.forget();

        pull_main(&dest, PullOptions::default()).await.unwrap();

        let seen = server.seen();
        assert_eq!(
            server.requests_for(&superblock_path(&d1, &d2)),
            1,
            "{seen:?}"
        );
        assert_eq!(server.requests_for(&scratch_superblock(&d2)), 0, "{seen:?}");
        assert_eq!(
            server.requests_for(&meta_path(&d2, "commit")),
            0,
            "{seen:?}"
        );
        assert_complete(&remote, &dest, dest.path(), &t2).await;
        assert_complete(&remote, &dest, dest.path(), &d2).await;
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
        assert_eq!(
            dest.list_remote_refs().await.unwrap(),
            [("origin:test/main".to_owned(), t2)]
        );
    });
}

/// The destination holds D1 complete under no ref, so no paired entry
/// exists. The pull takes the delta `<D1>-<D2>` from the commit that it
/// holds complete, before the from-scratch delta of D2.
#[test]
fn a_dependency_delta_from_another_held_commit_is_taken() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-delta-held");
        let (remote, [_, d1, t2, d2]) = build_dependency_generations(dir.path()).await;
        publish_delta(&remote, Some(&d1), &d2).await;
        publish_delta(&remote, None, &d2).await;
        move_ref(&remote, "test/main", &t2).await;
        let server = RepoServer::start(remote.path(), false).await;
        let dest = dest_holding(dir.path(), &server.url(), &d1).await;
        server.forget();

        pull_main(&dest, PullOptions::default()).await.unwrap();

        let seen = server.seen();
        assert_eq!(
            server.requests_for(&superblock_path(&d1, &d2)),
            1,
            "{seen:?}"
        );
        assert_eq!(server.requests_for(&scratch_superblock(&d2)), 0, "{seen:?}");
        assert_eq!(
            server.requests_for(&meta_path(&d2, "commit")),
            0,
            "{seen:?}"
        );
        assert_complete(&remote, &dest, dest.path(), &d2).await;
    });
}

/// The pull takes the from-scratch delta of a dependency if it holds no
/// paired entry complete: here the destination has no local ref. If the
/// paired entry is held complete, the pull does not take the from-scratch
/// delta and fetches the dependency loose. That delta counts as found, so a
/// pull that requires static deltas passes.
#[test]
fn the_from_scratch_delta_of_a_dependency_needs_no_paired_entry_held() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-delta-scratch");
        let base = dir.path();
        let (remote, [t1, _, t2, d2]) = build_dependency_generations(base).await;
        let server = RepoServer::start(remote.path(), false).await;
        let mut paired = Vec::new();
        for (name, opts) in [
            ("loose", PullOptions::default()),
            ("required", required_delta_opts()),
        ] {
            let path = base.join(name);
            std::fs::create_dir(&path).unwrap();
            let dest = build_dest(&path, RepoMode::Archive, &server.url(), "").await;
            pull_main(&dest, PullOptions::default()).await.unwrap();
            paired.push((dest, opts));
        }
        publish_delta(&remote, None, &d2).await;
        publish_delta(&remote, Some(&t1), &t2).await;
        move_ref(&remote, "test/main", &t2).await;

        let fresh = build_dest(base, RepoMode::Archive, &server.url(), "").await;
        server.forget();
        pull_main(&fresh, PullOptions::default()).await.unwrap();
        let seen = server.seen();
        assert_eq!(
            server.statuses_for(&scratch_superblock(&d2)),
            [200],
            "{seen:?}"
        );
        assert_eq!(
            server.requests_for(&meta_path(&d2, "commit")),
            0,
            "{seen:?}"
        );
        assert_complete(&remote, &fresh, fresh.path(), &d2).await;

        for (dest, opts) in paired {
            server.forget();
            pull_main(&dest, opts).await.unwrap();
            let seen = server.seen();
            assert_eq!(server.requests_for(&scratch_superblock(&d2)), 0, "{seen:?}");
            assert_eq!(
                server.requests_for(&meta_path(&d2, "commit")),
                1,
                "{seen:?}"
            );
            assert_complete(&remote, &dest, dest.path(), &d2).await;
        }
    });
}

/// Two targets name one dependency D, with the paired entries DA and DB.
/// With the delta `<DB>-<D>` alone, the pull of `[a, b]` finds it in the step
/// `<c>-<to>`. With both deltas, the paired entry of the first target is the
/// `from`: the pull of `[a, b]` takes `<DA>-<D>`, and the pull of `[b, a]`
/// takes `<DB>-<D>`.
#[test]
fn the_first_target_gives_the_from_of_a_dependency() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-delta-targets");
        let base = dir.path();
        for sub in ["da", "db", "d", "a1", "b1", "a2", "b2"] {
            build_tree(&base.join(sub), format!("{sub}\n").as_bytes());
        }
        let remote = create_remote(base).await;
        let da = commit_tree(&remote, base, "da", "dep/a", None, FIXED_TS).await;
        let db = commit_tree(&remote, base, "db", "dep/b", None, FIXED_TS).await;
        let d = commit_tree(&remote, base, "d", "dep/d", None, FIXED_TS).await;
        let a1 =
            commit_tree_related(&remote, base, "a1", "test/a", None, &[("boot/uki", da)]).await;
        let b1 =
            commit_tree_related(&remote, base, "b1", "test/b", None, &[("boot/uki", db)]).await;
        summarize(&remote).await;
        let server = RepoServer::start(remote.path(), false).await;
        let ab = || vec!["test/a".to_owned(), "test/b".to_owned()];
        let ba = || vec!["test/b".to_owned(), "test/a".to_owned()];
        let mut dests = Vec::new();
        for name in ["one", "two", "three"] {
            let path = base.join(name);
            std::fs::create_dir(&path).unwrap();
            let dest = build_dest(&path, RepoMode::Archive, &server.url(), "").await;
            dest.pull(
                "origin",
                PullOptions {
                    refs: ab(),
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();
            dests.push(dest);
        }
        let a2 =
            commit_tree_related(&remote, base, "a2", "test/a", Some(a1), &[("boot/uki", d)]).await;
        let b2 =
            commit_tree_related(&remote, base, "b2", "test/b", Some(b1), &[("boot/uki", d)]).await;
        publish_delta(&remote, Some(&db), &d).await;
        let pull = |dest: &Repo, refs: Vec<String>| {
            let dest = dest.clone();
            async move {
                dest.pull(
                    "origin",
                    PullOptions {
                        refs,
                        ..PullOptions::default()
                    },
                )
                .await
                .unwrap();
            }
        };

        server.forget();
        pull(&dests[0], ab()).await;
        assert_eq!(server.requests_for(&superblock_path(&db, &d)), 1);
        assert_eq!(server.requests_for(&meta_path(&d, "commit")), 0);

        publish_delta(&remote, Some(&da), &d).await;
        for (dest, refs, taken, other) in [(&dests[1], ab(), da, db), (&dests[2], ba(), db, da)] {
            server.forget();
            pull(dest, refs).await;
            let seen = server.seen();
            assert_eq!(
                server.requests_for(&superblock_path(&taken, &d)),
                1,
                "{seen:?}"
            );
            assert_eq!(
                server.requests_for(&superblock_path(&other, &d)),
                0,
                "{seen:?}"
            );
            assert_eq!(server.requests_for(&meta_path(&d, "commit")), 0, "{seen:?}");
        }
        for dest in &dests {
            for commit in [a2, b2, d] {
                assert_complete(&remote, dest, dest.path(), &commit).await;
            }
        }
    });
}

/// A pull that requires static deltas fails if a dependency has no delta.
/// The message names the entry, the ref of the target, and the dependency.
/// The pull moves no ref and leaves nothing.
#[test]
fn a_required_delta_pull_refuses_a_dependency_with_no_delta() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-delta-required");
        let (remote, tip, dep) = build_dependency_remote(dir.path()).await;
        publish_delta(&remote, None, &tip).await;
        let server = RepoServer::start(remote.path(), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let err = dest
            .pull("origin", required_delta_opts())
            .await
            .unwrap_err();

        match err {
            Error::Pull(message) => assert_eq!(
                message,
                format!(
                    "Static deltas required, but none found for boot/uki of test/main to {dep}"
                )
            ),
            other => panic!("{other:?}"),
        }
        assert_left_nothing(&dest).await;
    });
}

/// Under `disable_static_deltas`, the pull requests no delta and no delta
/// index for a dependency, and fetches it loose.
#[test]
fn a_pull_with_disabled_deltas_requests_no_dependency_delta() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-delta-disabled");
        let (remote, _tip, dep) = build_dependency_remote(dir.path()).await;
        publish_delta(&remote, None, &dep).await;
        let server = RepoServer::start(remote.path(), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        pull_main(
            &dest,
            PullOptions {
                disable_static_deltas: true,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        let seen = server.seen();
        assert!(
            !seen
                .iter()
                .any(|path| path.starts_with("deltas/") || path.starts_with("delta-indexes/")),
            "{seen:?}"
        );
        assert_eq!(server.requests_for(&meta_path(&dep, "commit")), 1);
        assert_complete(&remote, &dest, dest.path(), &dep).await;
    });
}

/// A remote with no summary advertises no delta. The pull requests the delta
/// of the dependency from its paired entry by name, and not the from-scratch
/// delta.
#[test]
fn a_pull_with_no_summary_requests_the_dependency_delta_by_name() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-delta-unlisted");
        let (remote, [_, d1, t2, d2]) = build_dependency_generations(dir.path()).await;
        let server = RepoServer::start(remote.path(), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        pull_main(&dest, PullOptions::default()).await.unwrap();
        publish_delta(&remote, Some(&d1), &d2).await;
        publish_delta(&remote, None, &d2).await;
        move_ref(&remote, "test/main", &t2).await;
        std::fs::remove_file(remote.path().join("summary")).unwrap();
        server.forget();

        pull_main(&dest, PullOptions::default()).await.unwrap();

        let seen = server.seen();
        assert_eq!(
            server.statuses_for(&superblock_path(&d1, &d2)),
            [200],
            "{seen:?}"
        );
        assert_eq!(server.requests_for(&scratch_superblock(&d2)), 0, "{seen:?}");
        assert_eq!(
            server.requests_for(&meta_path(&d2, "commit")),
            0,
            "{seen:?}"
        );
        assert_complete(&remote, &dest, dest.path(), &d2).await;
    });
}

/// A remote with no summary states no digest of a superblock. The target
/// names three dependencies, and the remote holds the from-scratch delta of
/// each. The pull requests each superblock one time: it parses the job of a
/// dependency from the bytes that discovery checked and kept, and sends no
/// second request.
#[test]
fn each_dependency_superblock_is_fetched_once_with_no_summary() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-delta-kept");
        let base = dir.path();
        for sub in ["uki", "initrd", "modules", "main"] {
            build_tree(&base.join(sub), format!("{sub}\n").as_bytes());
        }
        let remote = create_remote(base).await;
        let mut deps = Vec::new();
        for sub in ["uki", "initrd", "modules"] {
            let ref_name = format!("dep/{sub}");
            deps.push(commit_tree(&remote, base, sub, &ref_name, None, FIXED_TS).await);
        }
        let entries = [
            ("boot/uki", deps[0]),
            ("boot/initrd", deps[1]),
            ("lib/modules", deps[2]),
        ];
        let tip = commit_tree_related(&remote, base, "main", "test/main", None, &entries).await;
        for dep in &deps {
            publish_delta(&remote, None, dep).await;
        }
        std::fs::remove_file(remote.path().join("summary")).unwrap();
        let server = RepoServer::start(remote.path(), false).await;
        let dest = build_dest(base, RepoMode::Archive, &server.url(), "").await;

        pull_main(&dest, PullOptions::default()).await.unwrap();

        let seen = server.seen();
        for dep in &deps {
            assert_eq!(
                server.statuses_for(&scratch_superblock(dep)),
                [200],
                "{seen:?}"
            );
            assert_eq!(
                server.requests_for(&meta_path(dep, "commit")),
                0,
                "{seen:?}"
            );
            assert_complete(&remote, &dest, dest.path(), dep).await;
        }
        assert_complete(&remote, &dest, dest.path(), &tip).await;
        assert!(dest.fsck(&FsckOptions::default()).await.unwrap().is_ok());
    });
}

/// With a list of static deltas, the pull takes the list entry to a
/// dependency from its paired entry, in one step. Under
/// `require_static_deltas`, a list with no entry to the dependency fails the
/// pull with the message of a dependency, and the pull moves no ref.
#[test]
fn a_list_pull_takes_the_listed_delta_of_a_dependency() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-delta-list");
        let base = dir.path();
        let (remote, [t1, d1, t2, d2]) = build_dependency_generations(base).await;
        let server = RepoServer::start(remote.path(), false).await;
        let listed_dest = build_dest(base, RepoMode::Archive, &server.url(), "").await;
        pull_main(&listed_dest, PullOptions::default())
            .await
            .unwrap();
        let other = base.join("other");
        std::fs::create_dir(&other).unwrap();
        let refused = build_dest(&other, RepoMode::Archive, &server.url(), "").await;
        pull_main(&refused, PullOptions::default()).await.unwrap();
        move_ref(&remote, "test/main", &t2).await;
        let target = listed(&remote, &t1, &t2, DeltaOptions::default()).await;
        let dependency = listed(&remote, &d1, &d2, DeltaOptions::default()).await;
        server.forget();

        listed_dest
            .pull("origin", chain_opts(vec![target, dependency]))
            .await
            .unwrap();

        let seen = server.seen();
        assert_eq!(
            server.requests_for(&superblock_path(&d1, &d2)),
            1,
            "{seen:?}"
        );
        assert_eq!(
            server.requests_for(&meta_path(&d2, "commit")),
            0,
            "{seen:?}"
        );
        assert!(
            !seen.iter().any(|path| path.starts_with("delta-indexes/")),
            "{seen:?}"
        );
        assert_complete(&remote, &listed_dest, listed_dest.path(), &d2).await;

        let held = refused.list_objects().await.unwrap();
        let err = refused
            .pull(
                "origin",
                PullOptions {
                    require_static_deltas: true,
                    ..chain_opts(vec![target])
                },
            )
            .await
            .unwrap_err();
        match err {
            Error::Pull(message) => assert_eq!(
                message,
                format!("Static deltas required, but none found for boot/uki of test/main to {d2}")
            ),
            other => panic!("{other:?}"),
        }
        assert_eq!(refused.list_objects().await.unwrap(), held);
        assert_eq!(
            refused.list_remote_refs().await.unwrap(),
            [("origin:test/main".to_owned(), t1)]
        );
        assert_eq!(file_inventory(refused.path(), "state"), Vec::new());
    });
}

/// The pull checks no signature of a dependency whose commit comes from the
/// superblock of its delta. Under `sign-verify` with a signed tip, an unsigned
/// dependency and its unsigned delta pass the pull. The pull requests the
/// superblock and the `.commitmeta` of the dependency one time each, and no
/// `.commit` of the dependency.
#[test]
fn an_unsigned_dependency_from_its_delta_passes_the_pull() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-delta-signature");
        let (remote, tip, dep) = build_dependency_remote(dir.path()).await;
        publish_delta(&remote, None, &dep).await;
        sign_commits(&remote, &[tip]).await;
        let server = RepoServer::start(remote.path(), false).await;
        let dest = build_dest(
            dir.path(),
            RepoMode::Archive,
            &server.url(),
            &signed_policy(),
        )
        .await;

        pull_main(&dest, PullOptions::default()).await.unwrap();
        let seen = server.seen();
        assert_eq!(
            server.statuses_for(&scratch_superblock(&dep)),
            [200],
            "{seen:?}"
        );
        assert_eq!(
            server.requests_for(&meta_path(&dep, "commit")),
            0,
            "{seen:?}"
        );
        assert_eq!(
            server.requests_for(&meta_path(&dep, "commitmeta")),
            1,
            "{seen:?}"
        );
        assert_complete(&remote, &dest, dest.path(), &dep).await;
    });
}

/// The superblock of a dependency delta must give the commit that field 2
/// names. The remote serves two changed superblocks under the path of the
/// delta of the dependency:
///
/// - the superblock of the dependency, with the commit of another tree in
///   place of the dependency commit. The parse of the superblock finds that
///   the commit does not hash to the `to` of the superblock, and the pull
///   fails with [`Error::InvalidFormat`].
/// - the superblock of the delta of another commit. The `to` of the
///   superblock is not the dependency, and the pull fails with
///   [`Error::Pull`].
///
/// The remote serves no summary, so no advertised digest catches a changed
/// superblock first. Each pull fails with or without `sign-verify` and a
/// signed tip, requests no part, and leaves nothing.
#[test]
fn a_dependency_delta_that_gives_another_commit_fails_the_pull() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-delta-other-commit");
        let (remote, tip, dep) = build_dependency_remote(dir.path()).await;
        sign_commits(&remote, &[tip]).await;
        build_tree(&dir.path().join("other"), b"other\n");
        let donor = commit_tree(&remote, dir.path(), "other", "other/x", None, FIXED_TS).await;
        publish_delta(&remote, None, &dep).await;
        publish_delta(&remote, None, &donor).await;
        std::fs::remove_file(remote.path().join("summary")).unwrap();

        let ty = Type::parse(SUPERBLOCK_SIG).unwrap();
        let Value::Tuple(mut fields) = ostrya::from_bytes(
            &ty,
            &std::fs::read(remote.path().join(scratch_superblock(&dep))).unwrap(),
        )
        .unwrap() else {
            panic!("a superblock is a tuple");
        };
        fields[4] = ostrya::from_bytes(
            &Type::parse("(a{sv}aya(say)sstayay)").unwrap(),
            &std::fs::read(remote.path().join(meta_path(&donor, "commit"))).unwrap(),
        )
        .unwrap();
        let embedded = ostrya_core::to_bytes(&ty, &Value::Tuple(fields)).unwrap();
        let other = std::fs::read(remote.path().join(scratch_superblock(&donor))).unwrap();

        let server = RepoServer::start(remote.path(), false).await;
        for (case, bytes) in [("embedded", embedded), ("other", other)] {
            server.tamper(&scratch_superblock(&dep), bytes);
            for (tag, extra) in [("unverified", String::new()), ("verified", signed_policy())] {
                let base = dir.path().join(format!("{case}-{tag}"));
                std::fs::create_dir(&base).unwrap();
                let dest = build_dest(&base, RepoMode::Archive, &server.url(), &extra).await;
                server.forget();
                let err = pull_main(&dest, PullOptions::default()).await.unwrap_err();
                match (case, &err) {
                    ("embedded", Error::InvalidFormat(m)) => {
                        assert!(m.contains("embedded commit"), "{case} {tag}: {err}");
                    }
                    ("other", Error::Pull(m)) => {
                        assert!(m.contains(&donor.to_hex()), "{case} {tag}: {err}");
                    }
                    _ => panic!("{case} {tag}: {err:?}"),
                }
                let seen = server.seen();
                assert_eq!(
                    server.statuses_for(&scratch_superblock(&dep)),
                    [200],
                    "{case} {tag}: {seen:?}"
                );
                assert_eq!(part_requests(&seen), Vec::<String>::new());
                assert_left_nothing(&dest).await;
            }
        }
    });
}

/// The pull checks no signature of the superblock of a dependency delta. A
/// key that the destination does not trust signs the delta of the
/// dependency, and the pull under `sign-verify` with a signed tip takes the
/// delta. A pull that takes the dependency as a target too checks the
/// superblock, and fails with [`Error::Signature`].
#[test]
fn a_dependency_delta_signed_by_an_untrusted_key_passes_the_pull() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-delta-untrusted");
        let (remote, tip, dep) = build_dependency_remote(dir.path()).await;
        sign_commits(&remote, &[tip]).await;
        publish_delta(&remote, None, &dep).await;
        remote
            .sign_static_delta(
                &remote.path().join(static_delta_relative_dir(None, &dep)),
                &Ed25519Signer::from_base64(OTHER_SECRET_B64).unwrap(),
            )
            .await
            .unwrap();
        summarize(&remote).await;
        let server = RepoServer::start(remote.path(), false).await;

        let base = dir.path().join("dependency");
        std::fs::create_dir(&base).unwrap();
        let dest = build_dest(&base, RepoMode::Archive, &server.url(), &signed_policy()).await;
        pull_main(&dest, PullOptions::default()).await.unwrap();
        let seen = server.seen();
        assert_eq!(
            server.statuses_for(&scratch_superblock(&dep)),
            [200],
            "{seen:?}"
        );
        assert_eq!(
            server.requests_for(&meta_path(&dep, "commit")),
            0,
            "{seen:?}"
        );
        assert_complete(&remote, &dest, dest.path(), &dep).await;

        let base = dir.path().join("target");
        std::fs::create_dir(&base).unwrap();
        let dest = build_dest(&base, RepoMode::Archive, &server.url(), &signed_policy()).await;
        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test/main".to_owned(), "dep/uki".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("static delta")),
            "{err}"
        );
        assert_left_nothing(&dest).await;
    });
}

/// Returns the request path of the delta index of `to`.
fn index_path(to: &Checksum) -> String {
    let dir = static_delta_relative_dir(None, to);
    format!("{}.index", dir.replacen("deltas/", "delta-indexes/", 1))
}

/// A dependency that the run of the targets reaches gets no search for a
/// delta of its own. Here one dependency is the parent of the target, and the
/// other is the second target of the pull. The pull requests no delta index
/// for the parent, and one delta index for each target, the search of the
/// target. It requests no superblock.
#[test]
fn a_dependency_that_the_run_reaches_gets_no_delta_search() {
    block_on(async {
        let dir = TmpDir::new("pull-http-dependency-delta-reached");
        let base = dir.path();
        for sub in ["uki", "parent", "main"] {
            build_tree(&base.join(sub), format!("{sub}\n").as_bytes());
        }
        let remote = create_remote(base).await;
        let dep = commit_tree(&remote, base, "uki", "dep/uki", None, FIXED_TS).await;
        let parent = commit_tree(&remote, base, "parent", "test/main", None, FIXED_TS).await;
        let tip = commit_tree_related(
            &remote,
            base,
            "main",
            "test/main",
            Some(parent),
            &[("boot/uki", dep), ("boot/base", parent)],
        )
        .await;
        summarize(&remote).await;
        let server = RepoServer::start(remote.path(), false).await;
        let dest = build_dest(base, RepoMode::Archive, &server.url(), "").await;

        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned(), "dep/uki".to_owned()],
                depth: 1,
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        let seen = server.seen();
        assert_eq!(server.requests_for(&index_path(&tip)), 1, "{seen:?}");
        assert_eq!(server.requests_for(&index_path(&dep)), 1, "{seen:?}");
        assert_eq!(server.requests_for(&index_path(&parent)), 0, "{seen:?}");
        assert!(
            !seen.iter().any(|path| path.starts_with("deltas/")),
            "{seen:?}"
        );
        for commit in [tip, parent, dep] {
            assert_complete(&remote, &dest, dest.path(), &commit).await;
        }
    });
}
