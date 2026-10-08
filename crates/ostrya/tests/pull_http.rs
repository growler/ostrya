//! HTTP pull from a remote repository.
//!
//! Each test serves a repository directory from an in-process static file
//! server. The server uses cleartext HTTP/1.1. If the transport matters, it
//! uses TLS, and ALPN selects HTTP/2.
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
use std::path::Path;

use common::{
    TmpDir, file_inventory, ostree_available, ostree_supports_ed25519, wait_for_commit_under_guard,
    within, writer_child_main, writer_child_with,
};
use futures_lite::future::poll_once;
use ostrya::{
    Checksum, CommitModifierFlags, CommitState, CreateOptions, DeltaEndianness, DeltaOptions,
    DetachedMetadataFilter, Ed25519Signer, Error, FilterResult, FsckOptions, PullFlags,
    PullOptions, PullStats, PullVerify, Repo, RepoMode, SummaryOptions, TimestampCheck, TreeEntry,
    Type, Value, static_delta_relative_dir,
};
use ostrya_rt::{block_on, spawn};
use proxy::{TestProxy, Tunnel};
use pull::*;

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

/// The detached-metadata filter controls what an HTTP pull stores, as it does
/// for a local pull. The remote serves the whole `.commitmeta`, and the
/// destination keeps the properties that the filter allows.
#[test]
fn a_filter_shapes_the_detached_metadata_an_http_pull_stores() {
    block_on(async {
        let dir = TmpDir::new("pull-http-detached-filter");
        let (remote, commit) = build_remote(dir.path()).await;
        let meta = Value::Array(vec![
            Value::Tuple(vec![
                Value::Str("test.detached".to_owned()),
                Value::Variant(Box::new((
                    Type::parse("s").unwrap(),
                    Value::Str("present".to_owned()),
                ))),
            ]),
            Value::Tuple(vec![
                Value::Str("test.private".to_owned()),
                Value::Variant(Box::new((
                    Type::parse("s").unwrap(),
                    Value::Str("repository-local".to_owned()),
                ))),
            ]),
        ]);
        remote
            .write_commit_detached_metadata(&commit, Some(&meta))
            .await
            .unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        dest.pull(
            "origin",
            PullOptions {
                refs: vec!["test/main".to_owned()],
                detached_metadata_filter: DetachedMetadataFilter::new(|_, key, _| {
                    if key == "test.private" {
                        FilterResult::Skip
                    } else {
                        FilterResult::Allow
                    }
                }),
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();

        let stored = dest
            .read_commit_detached_metadata(&commit)
            .await
            .unwrap()
            .expect("the allowed property is stored");
        assert!(
            stored.dict_get("test.detached").is_some(),
            "an allowed property is stored"
        );
        assert!(
            stored.dict_get("test.private").is_none(),
            "a skipped property is not"
        );
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

        // Without encoding, `test%2fmain` asks a server that decodes its
        // request target for `refs/heads/test/main`. That ref exists under a
        // name that the test did not request.
        let err = dest
            .pull(
                "origin",
                PullOptions {
                    refs: vec!["test%2fmain".to_owned()],
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::RefNotFound(_)), "{err}");
        let seen = server.seen();
        assert!(
            seen.contains(&"refs/heads/test%252fmain".to_owned()),
            "the name reached the wire unencoded: {seen:?}"
        );
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
/// verification, so the pull copies the bytes and does not read them.
#[test]
fn a_mirror_pull_writes_local_refs_and_copies_the_summary() {
    block_on(async {
        let dir = TmpDir::new("pull-http-mirror");
        let (_remote, commit) = build_remote(dir.path()).await;
        std::fs::write(dir.path().join("remote/summary.sig"), SUMMARY_SIG).unwrap();
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

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
    block_on(async {
        const NAME: &[u8] = b"test/main";
        // The length stays the same, so the frame offsets of the summary stay
        // valid. The name gets a traversal component, which the ref store
        // refuses.
        const TRAVERSAL: &[u8] = b"test/../m";

        let dir = TmpDir::new("pull-http-mirror-bad-ref");
        build_remote(dir.path()).await;
        let published = std::fs::read(dir.path().join("remote/summary")).unwrap();
        let at = published
            .windows(NAME.len())
            .position(|window| window == NAME)
            .expect("the summary names the ref");
        let mut tampered = published.clone();
        tampered[at..at + NAME.len()].copy_from_slice(TRAVERSAL);

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
            matches!(&err, Error::InvalidRefspec(name) if name.as_bytes() == TRAVERSAL),
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
/// commit object, before it requests the tree.
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
                    n_network_retries: Some(0),
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
                    n_network_retries: Some(2),
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
/// authority of the destination signed. The unit test of `remote_tls` checks
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
                    n_network_retries: Some(0),
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
                url: Some(server.url()),
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

/// A pull verifies each commit that it carries, also the parents that a depth
/// pull follows. If the tip is signed and its parent is not, the pull refuses
/// the parent.
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
