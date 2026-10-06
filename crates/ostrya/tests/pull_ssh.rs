//! The pull through the ssh source: `Repo::pull_over_stream` as the client,
//! over two bounded in-process pipes, against `Repo::send` as the server.
//!
//! The oracle of each pull is the HTTP pull of the same remote into a second
//! destination of the same mode: the refs, the objects, the markers, and the
//! fetch statistics agree. The pipes are smaller than a large body, so the
//! server waits for the client to read.

mod common;
#[path = "common/pull.rs"]
mod pull;

use std::future::Future;
use std::path::Path;
use std::time::Duration;

use common::TmpDir;
use common::pipe::pipe;
use futures_lite::future;
use ostrya::{
    Checksum, CommitModifierFlags, CreateOptions, DeltaOptions, Error, FsckOptions, ObjectType,
    PullFlags, PullOptions, PullStats, Repo, RepoMode, SummaryOptions, loose_path,
};
use ostrya_rt::block_on;
use pull::{
    FIXED_TS, RepoServer, build_remote, build_tree, commit_tree, commit_tree_with,
    content_checksums, filez_path, incompressible,
};

/// The capacity of each pipe.
const PIPE_CAP: usize = 64 * 1024;

/// The time bound of each pull.
const LIMIT: Duration = Duration::from_secs(120);

/// Run `fut`, and fail the test when it takes longer than [`LIMIT`].
async fn within<T>(what: &str, fut: impl Future<Output = T>) -> T {
    future::or(fut, async {
        ostrya_rt::Timer::after(LIMIT).await;
        panic!("{what} took longer than {LIMIT:?}");
    })
    .await
}

/// A destination repository of `mode` at `path`, whose config names `origin`
/// at `url` with no signature check.
async fn dest_at(path: &Path, mode: RepoMode, url: Option<&str>) -> Repo {
    let keys = url.map(|url| format!("url={url}\n")).unwrap_or_default();
    dest_with_keys(path, mode, &keys).await
}

/// A destination repository of `mode` at `path`, whose config names `origin`
/// with the keys `keys` and no signature check.
async fn dest_with_keys(path: &Path, mode: RepoMode, keys: &str) -> Repo {
    drop(Repo::create(path, CreateOptions::new(mode)).await.unwrap());
    let config = path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str("\n[remote \"origin\"]\n");
    text.push_str(keys);
    text.push_str("gpg-verify=false\n");
    std::fs::write(&config, text).unwrap();
    Repo::open(path).await.unwrap()
}

/// Pull from `remote` into `dest` through the ssh source, with `Repo::send`
/// serving `remote`. Gives the result of the pull and the result of the
/// server.
async fn pull_ssh(
    dest: &Repo,
    remote: &Repo,
    opts: PullOptions,
) -> (Result<PullStats, Error>, Result<(), Error>) {
    let (to_server, server_in) = pipe(PIPE_CAP);
    let (server_out, from_server) = pipe(PIPE_CAP);
    within(
        "the pull over ssh",
        future::zip(
            dest.pull_over_stream("origin", from_server, to_server, opts),
            async move { remote.send(server_in, server_out).await },
        ),
    )
    .await
}

/// The objects, the refs, and the state files of the repository at `path`.
fn snapshot(path: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = common::file_inventory(path, "objects");
    out.extend(common::file_inventory(path, "refs"));
    out.extend(common::file_inventory(path, "state"));
    out
}

/// The statistics that both sources count the same way.
fn fetch_counts(stats: &PullStats) -> (u32, u32, u32, u32, u32, u64, u64) {
    (
        stats.metadata_imported,
        stats.content_imported,
        stats.metadata_fetched,
        stats.content_fetched,
        stats.delta_parts,
        stats.bytes_transferred,
        stats.content_bytes_unpacked,
    )
}

/// Pull from the archive repository at `remote_path` over HTTP and through
/// the ssh source, each into a new destination of `mode` under `dir`, with
/// the options `opts` gives, and assert that both give the same refs,
/// objects, markers, and fetch statistics, and that a complete pull passes
/// fsck. Gives the statistics.
async fn pull_both(
    dir: &Path,
    tag: &str,
    remote_path: &Path,
    mode: RepoMode,
    opts: impl Fn() -> PullOptions,
) -> PullStats {
    let remote = Repo::open(remote_path).await.unwrap();
    let server = RepoServer::start(remote_path, false).await;
    let http_path = dir.join(format!("{tag}-http"));
    let ssh_path = dir.join(format!("{tag}-ssh"));
    let http_dest = dest_at(&http_path, mode, Some(&server.url())).await;
    let ssh_dest = dest_at(&ssh_path, mode, None).await;

    let http = http_dest.pull("origin", opts()).await.unwrap();
    let (ssh, served) = pull_ssh(&ssh_dest, &remote, opts()).await;
    let ssh = ssh.unwrap();
    served.unwrap();

    assert_eq!(snapshot(&ssh_path), snapshot(&http_path), "{tag}");
    assert_eq!(fetch_counts(&ssh), fetch_counts(&http), "{tag}");
    // A commit-only pull and a subpath pull leave the commit partial.
    let opts = opts();
    if opts.subpaths.is_empty() && !opts.flags.contains(PullFlags::COMMIT_ONLY) {
        assert!(
            ssh_dest
                .fsck(&FsckOptions::default())
                .await
                .unwrap()
                .is_ok(),
            "{tag}"
        );
    }
    ssh
}

fn main_ref(depth: i32) -> PullOptions {
    PullOptions {
        refs: vec!["test/main".to_owned()],
        depth,
        ..PullOptions::default()
    }
}

/// A remote archive repository under `dir/remote` with two commits on
/// `test/main`, and a summary.
async fn build_remote_two_commits(dir: &Path) -> (Repo, Checksum, Checksum) {
    build_tree(&dir.join("one"), b"one\n");
    build_tree(&dir.join("two"), b"two\n");
    let repo = Repo::create(&dir.join("remote"), CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap();
    let first = commit_tree(&repo, dir, "one", "test/main", None, FIXED_TS).await;
    let second = commit_tree(&repo, dir, "two", "test/main", Some(first), FIXED_TS + 1).await;
    summarize(&repo).await;
    (repo, first, second)
}

async fn summarize(repo: &Repo) {
    repo.regenerate_summary(&SummaryOptions {
        last_modified: Some(FIXED_TS),
        ..SummaryOptions::default()
    })
    .await
    .unwrap();
}

/// The ssh source gives what the HTTP pull gives: the whole tree into an
/// archive and a bare-user destination, the history under `depth`, the
/// commit alone, and the subpaths.
#[test]
fn the_ssh_source_pulls_what_the_http_pull_pulls() {
    block_on(async {
        let dir = TmpDir::new("pull-ssh-same");
        let (_remote, first, second) = build_remote_two_commits(dir.path()).await;
        let remote_path = dir.path().join("remote");
        for mode in [RepoMode::Archive, RepoMode::BareUser] {
            let tag = mode.as_mode_str();
            let stats = pull_both(dir.path(), tag, &remote_path, mode, || main_ref(0)).await;
            assert!(stats.bytes_transferred > 0);
            assert_eq!(stats.content_fetched, 4);
        }

        let stats = pull_both(dir.path(), "depth", &remote_path, RepoMode::Archive, || {
            main_ref(-1)
        })
        .await;
        assert_eq!(stats.content_fetched, 5);
        let dest = Repo::open(&dir.path().join("depth-ssh")).await.unwrap();
        assert!(dest.has_object(ObjectType::Commit, &first).await.unwrap());
        assert_eq!(
            dest.resolve_rev("origin:test/main", true).await.unwrap(),
            Some(second)
        );

        let stats = pull_both(
            dir.path(),
            "commit-only",
            &remote_path,
            RepoMode::Archive,
            || PullOptions {
                flags: PullFlags::COMMIT_ONLY,
                ..main_ref(1)
            },
        )
        .await;
        assert_eq!(stats.content_fetched, 0);

        let stats = pull_both(
            dir.path(),
            "subpath",
            &remote_path,
            RepoMode::BareUser,
            || PullOptions {
                subpaths: vec!["/subdir".to_owned()],
                ..main_ref(0)
            },
        )
        .await;
        assert_eq!(stats.content_fetched, 1);
    });
}

/// A from-scratch static delta of an archive remote is taken over ssh as
/// over HTTP, with its parts fetched as files.
#[test]
fn the_ssh_source_takes_a_static_delta() {
    block_on(async {
        let dir = TmpDir::new("pull-ssh-delta");
        let (remote, commit) = build_remote(dir.path()).await;
        remote
            .generate_static_delta(
                None,
                &commit,
                &DeltaOptions {
                    timestamp: Some(FIXED_TS),
                    min_fallback_size: 0,
                    ..DeltaOptions::default()
                },
            )
            .await
            .unwrap();
        summarize(&remote).await;
        for mode in [RepoMode::Archive, RepoMode::BareUser] {
            let stats = pull_both(
                dir.path(),
                mode.as_mode_str(),
                &dir.path().join("remote"),
                mode,
                || main_ref(0),
            )
            .await;
            assert!(stats.delta_parts >= 1, "{stats:?}");
            assert_eq!(stats.content_fetched, 0, "{stats:?}");
        }
    });
}

/// An object larger than the buffers of the pipes, with small objects after
/// it in the pipeline, arrives whole, and the transferred count equals that
/// of the HTTP pull.
#[test]
fn a_large_object_with_small_objects_behind_it_arrives() {
    block_on(async {
        let dir = TmpDir::new("pull-ssh-large");
        let src = dir.path().join("src");
        build_tree(&src, b"hello\n");
        std::fs::write(src.join("aaa-large.bin"), incompressible(4 << 20)).unwrap();
        for i in 0..16 {
            std::fs::write(
                src.join(format!("small-{i:02}.txt")),
                format!("small {i}\n"),
            )
            .unwrap();
        }
        let remote = Repo::create(
            &dir.path().join("remote"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        commit_tree(&remote, dir.path(), "src", "test/main", None, FIXED_TS).await;
        summarize(&remote).await;
        for mode in [RepoMode::Archive, RepoMode::BareUser] {
            let stats = pull_both(
                dir.path(),
                mode.as_mode_str(),
                &dir.path().join("remote"),
                mode,
                || main_ref(0),
            )
            .await;
            assert!(stats.bytes_transferred > 4 << 20, "{stats:?}");
            assert_eq!(stats.content_fetched, 21);
        }
    });
}

/// A content object the remote does not hold fails the pull with the object
/// that is not found, and no ref is written.
#[test]
fn a_missing_object_fails_the_pull_and_writes_no_ref() {
    block_on(async {
        let dir = TmpDir::new("pull-ssh-missing");
        let (remote, commit) = build_remote(dir.path()).await;
        let lost = content_checksums(&remote, &commit).await[0];
        std::fs::remove_file(dir.path().join("remote").join(filez_path(&lost.to_hex()))).unwrap();
        let dest = dest_at(&dir.path().join("dest"), RepoMode::Archive, None).await;
        let (pulled, served) = pull_ssh(&dest, &remote, main_ref(0)).await;
        match pulled {
            Err(Error::ObjectNotFound { checksum, ty }) => {
                assert_eq!((checksum, ty), (lost, ObjectType::File));
            }
            other => panic!("{other:?}"),
        }
        // The server stopped: it read the end of its input, or it failed to
        // write a reply that was queued when the client failed.
        let _ = served;
        assert!(
            dest.list_refs(Some("refs/remotes"))
                .await
                .unwrap()
                .is_empty()
        );
        assert!(dest.list_refs(None).await.unwrap().is_empty());
    });
}

/// An `Error` of the server fails the pull with its code, and the session
/// ends: the server returns, and no ref is written. The server cannot load a
/// `bare-user` object whose `user.ostreemeta` does not parse.
#[test]
fn an_error_of_the_server_fails_the_pull_and_ends_the_session() {
    block_on(async {
        let dir = TmpDir::new("pull-ssh-server-error");
        build_tree(&dir.path().join("src"), b"hello\n");
        let remote_path = dir.path().join("remote");
        let remote = Repo::create(&remote_path, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let commit = commit_tree(&remote, dir.path(), "src", "test/main", None, FIXED_TS).await;
        summarize(&remote).await;
        let broken = content_checksums(&remote, &commit).await[0];
        rustix::fs::lsetxattr(
            remote_path.join("objects").join(loose_path(
                &broken,
                ObjectType::File,
                RepoMode::BareUser,
            )),
            "user.ostreemeta",
            b"\xff",
            rustix::fs::XattrFlags::REPLACE,
        )
        .unwrap();
        let dest = dest_at(&dir.path().join("dest"), RepoMode::Archive, None).await;
        let (pulled, served) = pull_ssh(&dest, &remote, main_ref(0)).await;
        match pulled {
            Err(Error::Push(e)) => {
                assert_eq!(e.code(), Some(ostrya::push::ErrorCode::Internal), "{e:?}")
            }
            other => panic!("{other:?}"),
        }
        assert!(served.is_err(), "the server reported no failure");
        assert!(
            dest.list_refs(Some("refs/remotes"))
                .await
                .unwrap()
                .is_empty()
        );
    });
}

/// A body that the client drops before its end, here a content object whose
/// mode the pull refuses after the head of the object, fails the pull with
/// that refusal and ends the session.
#[test]
fn a_dropped_body_fails_the_pull_and_ends_the_session() {
    block_on(async {
        use std::os::unix::fs::PermissionsExt;

        let dir = TmpDir::new("pull-ssh-dropped");
        let src = dir.path().join("src");
        build_tree(&src, b"hello\n");
        std::fs::write(src.join("exec.sh"), incompressible(1 << 20)).unwrap();
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
        summarize(&remote).await;
        let dest = dest_at(&dir.path().join("dest"), RepoMode::Archive, None).await;
        let (pulled, served) = pull_ssh(
            &dest,
            &remote,
            PullOptions {
                flags: PullFlags::BAREUSERONLY_FILES,
                ..main_ref(0)
            },
        )
        .await;
        let err = pulled.unwrap_err();
        assert!(err.to_string().contains("invalid mode"), "{err}");
        // The server stopped: it read the end of its input, or it failed to
        // write to a client that dropped its side.
        let _ = served;
        assert!(
            dest.list_refs(Some("refs/remotes"))
                .await
                .unwrap()
                .is_empty()
        );
    });
}

/// A stated length above the cap of the client ends the session before the
/// client reads the body: a ref file of a remote with no summary is capped
/// at 1 KiB.
#[test]
fn a_stated_length_above_the_cap_ends_the_session() {
    block_on(async {
        let dir = TmpDir::new("pull-ssh-cap");
        let (remote, commit) = build_remote(dir.path()).await;
        let remote_path = dir.path().join("remote");
        std::fs::remove_file(remote_path.join("summary")).unwrap();
        let mut long = format!("{}\n", commit.to_hex()).into_bytes();
        long.resize(2048, b'\n');
        std::fs::write(remote_path.join("refs/heads/test/main"), long).unwrap();
        let dest = dest_at(&dir.path().join("dest"), RepoMode::Archive, None).await;
        let (pulled, served) = pull_ssh(&dest, &remote, main_ref(0)).await;
        match pulled {
            Err(Error::Push(ostrya::push::Error::LimitExceeded(msg))) => {
                assert!(msg.contains("refs/heads/test/main"), "{msg}")
            }
            other => panic!("{other:?}"),
        }
        let _ = served;
        assert!(
            dest.list_refs(Some("refs/remotes"))
                .await
                .unwrap()
                .is_empty()
        );
    });
}

/// A pull over a pair of streams refuses a url and the ssh fields of the
/// connect options, and an HTTP pull refuses the ssh command and the send
/// command, each before any byte is written.
#[test]
fn the_fields_of_the_other_transport_are_refused() {
    block_on(async {
        let dir = TmpDir::new("pull-ssh-refusals");
        let (remote, _commit) = build_remote(dir.path()).await;
        let dest = dest_at(&dir.path().join("dest"), RepoMode::Archive, None).await;
        let ssh_command = || ostrya::push::PullConnectOptions {
            ssh_command: Some(vec!["ssh".to_owned()]),
            ..Default::default()
        };
        let send_command = || ostrya::push::PullConnectOptions {
            send_command: Some("ostrya send".to_owned()),
            ..Default::default()
        };
        for opts in [
            PullOptions {
                url: Some("http://127.0.0.1:1/".to_owned()),
                ..main_ref(0)
            },
            PullOptions {
                connect: ssh_command(),
                ..main_ref(0)
            },
            PullOptions {
                connect: send_command(),
                ..main_ref(0)
            },
        ] {
            let (pulled, served) = pull_ssh(&dest, &remote, opts).await;
            assert!(matches!(pulled, Err(Error::InvalidInput(_))), "{pulled:?}");
            // The server read the end of its input before any `PullHello`.
            served.unwrap();
        }
        for (connect, key) in [
            (ssh_command(), "ssh-command"),
            (send_command(), "send-command"),
        ] {
            let err = dest
                .pull(
                    "origin",
                    PullOptions {
                        url: Some("http://127.0.0.1:1/".to_owned()),
                        connect,
                        ..main_ref(0)
                    },
                )
                .await
                .unwrap_err();
            match err {
                Error::InvalidInput(msg) => assert!(msg.contains(key), "{msg}"),
                other => panic!("{other:?}"),
            }
        }
        // The remote ssh command is not read by an HTTP pull.
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        dest.pull(
            "origin",
            PullOptions {
                url: Some(server.url()),
                connect: ostrya::push::PullConnectOptions {
                    remote_ssh_command: Some("ssh -q".to_owned()),
                    ..Default::default()
                },
                ..main_ref(0)
            },
        )
        .await
        .unwrap();
    });
}

/// A stand-in ssh command that writes its arguments after the program, one
/// to a line, to `record`, and exits 0 without serving a session.
fn recording_ssh(record: &Path) -> ostrya::push::PullConnectOptions {
    ostrya::push::PullConnectOptions {
        ssh_command: Some(vec![
            "sh".to_owned(),
            "-c".to_owned(),
            r#"record=$1; shift; printf '%s\n' "$@" > "$record""#.to_owned(),
            "ssh".to_owned(),
            record.to_str().unwrap().to_owned(),
        ]),
        ..Default::default()
    }
}

/// The arguments the stand-in of [`recording_ssh`] got, or `None` when it
/// did not run.
fn recorded(record: &Path) -> Option<Vec<String>> {
    let text = std::fs::read_to_string(record).ok()?;
    Some(text.lines().map(str::to_owned).collect())
}

/// The ssh command and the send command of the caller win over the remote
/// keys, and the key of a field the caller leaves `None` fills it, also for
/// an address of the caller.
#[test]
fn the_commands_of_the_caller_win_over_the_remote_keys() {
    block_on(async {
        let dir = TmpDir::new("pull-ssh-commands");
        let dest = dest_with_keys(
            &dir.path().join("dest"),
            RepoMode::Archive,
            "pull-url=ssh://localhost/srv/repo\nssh-command=/nonexistent/ssh\n\
             send-command=/nonexistent/send\n",
        )
        .await;
        let both = dir.path().join("both");
        let pulled = dest
            .pull(
                "origin",
                PullOptions {
                    connect: ostrya::push::PullConnectOptions {
                        send_command: Some("my-send".to_owned()),
                        ..recording_ssh(&both)
                    },
                    ..main_ref(0)
                },
            )
            .await;
        // The stand-in serves no session.
        assert!(pulled.is_err());
        assert_eq!(
            recorded(&both).unwrap(),
            ["localhost", "my-send --repo='/srv/repo'"]
        );

        let key = dir.path().join("key");
        let pulled = dest
            .pull(
                "origin",
                PullOptions {
                    connect: recording_ssh(&key),
                    ..main_ref(0)
                },
            )
            .await;
        assert!(pulled.is_err());
        assert_eq!(
            recorded(&key).unwrap(),
            ["localhost", "/nonexistent/send --repo='/srv/repo'"]
        );

        let url = dir.path().join("url");
        let pulled = dest
            .pull(
                "origin",
                PullOptions {
                    url: Some("u@h:other".to_owned()),
                    connect: recording_ssh(&url),
                    ..main_ref(0)
                },
            )
            .await;
        assert!(pulled.is_err());
        assert_eq!(
            recorded(&url).unwrap(),
            ["u@h", "/nonexistent/send --repo='other'"]
        );
    });
}

/// An ssh address in `url` is refused in the `ssh://` form and in the scp
/// form, and the ssh client does not start.
#[test]
fn an_ssh_address_in_url_is_refused() {
    block_on(async {
        let dir = TmpDir::new("pull-ssh-url");
        for (tag, url) in [
            ("ssh", "ssh://localhost/srv/repo"),
            ("scp", "localhost:/srv/repo"),
        ] {
            let dest = dest_at(&dir.path().join(tag), RepoMode::Archive, Some(url)).await;
            let record = dir.path().join(format!("{tag}-record"));
            let err = dest
                .pull(
                    "origin",
                    PullOptions {
                        connect: recording_ssh(&record),
                        ..main_ref(0)
                    },
                )
                .await
                .unwrap_err();
            match err {
                Error::Pull(msg) => assert_eq!(
                    msg,
                    format!(
                        "remote 'origin': url '{url}' is an ssh address; the port reads an ssh \
                         address from pull-url alone"
                    )
                ),
                other => panic!("{tag}: {other:?}"),
            }
            assert_eq!(recorded(&record), None, "{tag}");
        }
    });
}

/// Each option of HTTP alone is refused with an ssh address before the ssh
/// client starts. A retry count of 0 is accepted, and the ssh client starts.
#[test]
fn the_options_of_http_alone_are_refused_before_the_ssh_client_starts() {
    block_on(async {
        let dir = TmpDir::new("pull-ssh-http-options");
        let dest = dest_at(&dir.path().join("dest"), RepoMode::Archive, None).await;
        let address = "ssh://localhost/srv/repo";
        let with = |opts: PullOptions| PullOptions {
            url: Some(address.to_owned()),
            connect: ostrya::push::PullConnectOptions {
                ssh_command: Some(vec!["/nonexistent/ssh".to_owned()]),
                ..Default::default()
            },
            ..opts
        };
        for (name, opts) in [
            (
                "http-header",
                PullOptions {
                    http_headers: vec![("A".to_owned(), "B".to_owned())],
                    ..main_ref(0)
                },
            ),
            (
                "network-retries",
                PullOptions {
                    n_network_retries: Some(1),
                    ..main_ref(0)
                },
            ),
            (
                "low-speed-limit-bytes",
                PullOptions {
                    low_speed_limit_bytes: Some(5),
                    ..main_ref(0)
                },
            ),
            (
                "low-speed-time-seconds",
                PullOptions {
                    low_speed_time: Some(Duration::ZERO),
                    ..main_ref(0)
                },
            ),
        ] {
            match dest.pull("origin", with(opts)).await {
                Err(Error::InvalidInput(msg)) => assert_eq!(
                    msg,
                    format!(
                        "{name} applies to a pull over HTTP, and '{address}' is an ssh address"
                    )
                ),
                other => panic!("{name}: {other:?}"),
            }
        }
        let err = dest
            .pull(
                "origin",
                with(PullOptions {
                    n_network_retries: Some(0),
                    ..main_ref(0)
                }),
            )
            .await
            .unwrap_err();
        match err {
            Error::Push(ostrya::push::Error::Transport(msg)) => {
                assert!(msg.contains("/nonexistent/ssh"), "{msg}")
            }
            other => panic!("{other:?}"),
        }
    });
}

/// A pull over ssh reads no remote key of HTTP alone: TLS keys that an HTTP
/// pull refuses do not stop it, and the ssh client starts.
#[test]
fn a_pull_over_ssh_reads_no_tls_key() {
    block_on(async {
        let dir = TmpDir::new("pull-ssh-no-tls");
        let tls = "tls-ca-path=/nonexistent/ca.pem\ntls-client-cert-path=/nonexistent/c.pem\n\
                   tls-permissive=maybe\ncontenturl=http://127.0.0.1:1/\n";
        let dest = dest_with_keys(
            &dir.path().join("dest"),
            RepoMode::Archive,
            &format!("pull-url=ssh://localhost/srv/repo\n{tls}"),
        )
        .await;
        let record = dir.path().join("record");
        let pulled = dest
            .pull(
                "origin",
                PullOptions {
                    connect: recording_ssh(&record),
                    ..main_ref(0)
                },
            )
            .await;
        assert!(pulled.is_err());
        assert_eq!(
            recorded(&record).unwrap(),
            ["localhost", "ostrya send --repo='/srv/repo'"]
        );

        // The same keys stop an HTTP pull before its first request.
        let err = dest
            .pull(
                "origin",
                PullOptions {
                    url: Some("http://127.0.0.1:1/".to_owned()),
                    ..main_ref(0)
                },
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("tls-permissive"), "{err}");
    });
}

/// A pull over ssh resolves its signature policy before the ssh client
/// starts, so a policy that cannot be built stops the pull with no ssh
/// client. The refusal of an option of HTTP alone comes before the policy.
#[test]
fn a_refused_policy_stops_the_pull_before_the_ssh_client_starts() {
    block_on(async {
        let dir = TmpDir::new("pull-ssh-policy-first");
        let keys = "/nonexistent/ostrya/keys.ed25519";
        let dest = dest_with_keys(
            &dir.path().join("dest"),
            RepoMode::Archive,
            &format!(
                "pull-url=ssh://localhost/srv/repo\nsign-verify=ed25519\n\
                 verification-ed25519-file={keys}\n"
            ),
        )
        .await;

        let policy = dir.path().join("policy");
        let err = dest
            .pull(
                "origin",
                PullOptions {
                    connect: recording_ssh(&policy),
                    ..main_ref(0)
                },
            )
            .await
            .unwrap_err();
        match err {
            Error::Signature(msg) => assert!(msg.contains(keys), "{msg}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(recorded(&policy), None);

        let header = dir.path().join("header");
        let err = dest
            .pull(
                "origin",
                PullOptions {
                    http_headers: vec![("A".to_owned(), "B".to_owned())],
                    connect: recording_ssh(&header),
                    ..main_ref(0)
                },
            )
            .await
            .unwrap_err();
        match err {
            Error::InvalidInput(msg) => assert_eq!(
                msg,
                "http-header applies to a pull over HTTP, and 'ssh://localhost/srv/repo' is \
                 an ssh address"
            ),
            other => panic!("{other:?}"),
        }
        assert_eq!(recorded(&header), None);
    });
}

/// A pull through the ssh source that writes no ref completes every commit
/// it pulls and writes no ref.
#[test]
fn the_ssh_source_with_no_ref_writes_writes_no_ref() {
    block_on(async {
        let dir = TmpDir::new("pull-ssh-no-ref-writes");
        let (remote, first, second) = build_remote_two_commits(dir.path()).await;
        let dest_path = dir.path().join("dest");
        let dest = dest_at(&dest_path, RepoMode::Archive, None).await;
        let refs = common::file_inventory(&dest_path, "refs");

        let (pulled, served) = pull_ssh(
            &dest,
            &remote,
            PullOptions {
                no_ref_writes: true,
                ..main_ref(1)
            },
        )
        .await;
        pulled.unwrap();
        served.unwrap();

        assert_eq!(common::file_inventory(&dest_path, "refs"), refs);
        assert!(!dest_path.join("refs/remotes/origin").exists());
        for commit in [&first, &second] {
            assert_eq!(
                dest.commit_state(commit).await.unwrap(),
                ostrya::CommitState::Normal
            );
            let marker = format!("state/{}.commitpartial", commit.to_hex());
            assert!(!dest_path.join(marker).exists());
            for name in &remote.traverse_commit(commit, 0).await.unwrap() {
                assert!(dest.has_object(name.ty, &name.checksum).await.unwrap());
            }
        }
    });
}
