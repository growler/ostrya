//! Tests of the pull through the stream source. `PullSession::over_stream`
//! with `Repo::pull_with_session` is the client and `Repo::send` is the
//! server, over two bounded in-process pipes.
//!
//! The oracle of each pull is the HTTP pull of the same remote into a second
//! destination of the same mode. The refs, the objects, the markers, and the
//! fetch statistics of the two destinations agree. The pipes are smaller than
//! a large body, so the server waits for the client to read.

mod common;
#[path = "common/pull.rs"]
mod pull;

use std::future::Future;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use common::TmpDir;
use common::pipe::{PipeReader, pipe};
use futures_lite::future;
use futures_lite::io::AsyncRead;
use ostrya::endpoint::{EndpointOverrides, resolve_pull};
use ostrya::remote::proto::{FrameReader, Message};
use ostrya::remote::{PullSession, StreamSessionOptions};
use ostrya::verify::PullTrust;
use ostrya::{
    Checksum, CommitModifierFlags, CreateOptions, DeltaOptions, Error, FsckOptions, ObjectType,
    PullFlags, PullOptions, PullProgress, PullStats, PullVerify, Repo, RepoMode, SummaryOptions,
    loose_path,
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

/// Runs `fut` and fails the test if `fut` takes longer than [`LIMIT`].
async fn within<T>(what: &str, fut: impl Future<Output = T>) -> T {
    future::or(fut, async {
        ostrya_rt::Timer::after(LIMIT).await;
        panic!("{what} took longer than {LIMIT:?}");
    })
    .await
}

/// A destination repository of `mode` at `path`, whose config names the
/// remote `origin` at `url`, with `gpg-verify=false`. If `url` is `None`, the
/// remote has no `url` key.
async fn dest_at(path: &Path, mode: RepoMode, url: Option<&str>) -> Repo {
    let keys = url.map(|url| format!("url={url}\n")).unwrap_or_default();
    dest_with_keys(path, mode, &keys).await
}

/// A destination repository of `mode` at `path`, whose config names the
/// remote `origin` with the keys `keys` and `gpg-verify=false`.
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

/// Pulls from `remote` into `dest` over a stream session with
/// `Repo::pull_with_session`, with `Repo::send` as the server of `remote`.
/// Returns the result of the pull and the result of the server.
///
/// The function takes the trust of the remote `origin` of `dest` with
/// `PullTrust::from_remote` under the policy of `opts`, and that trust must
/// build. The session takes the request limit of `opts`. If `opts` names no
/// remote, the refs go under `origin`.
async fn pull_ssh(
    dest: &Repo,
    remote: &Repo,
    opts: PullOptions,
) -> (Result<PullStats, Error>, Result<(), Error>) {
    let trust = PullTrust::from_remote(dest, "origin", &opts.verify)
        .await
        .unwrap();
    let stream = StreamSessionOptions {
        agent: None,
        max_outstanding: opts.max_outstanding_fetches,
    };
    let opts = PullOptions {
        verify: PullVerify::default(),
        max_outstanding_fetches: None,
        remote: opts.remote.or_else(|| Some("origin".to_owned())),
        ..opts
    };
    let (pulled, served, _) = pull_session_ssh(dest, remote, trust, stream, opts).await;
    (pulled, served)
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

/// Pulls from the archive repository at `remote_path` over HTTP and through
/// the stream source, each into a new destination of `mode` under `dir`.
///
/// Both pulls take the options that `opts` gives. The function asserts that
/// both pulls give the same refs, objects, markers, and fetch statistics. If
/// the pull is complete, it also asserts that the ssh destination passes
/// fsck. Returns the statistics of the pull through the stream source.
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

/// The stream source pulls the same data as the HTTP pull in each of these
/// cases:
///
/// - the whole tree, into an archive and into a bare-user destination
/// - the history under `depth`
/// - the commit alone
/// - the subpaths
#[test]
fn the_stream_source_pulls_what_the_http_pull_pulls() {
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

/// The stream source takes a from-scratch static delta of an archive remote as
/// the HTTP pull does. It fetches the parts of the delta as files.
#[test]
fn the_stream_source_takes_a_static_delta() {
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

/// An object larger than the buffers of the pipes arrives whole, also with
/// small objects after it in the pipeline. The count of transferred bytes
/// equals the count of the HTTP pull.
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

/// If the remote does not hold a content object, the pull fails with
/// `Error::ObjectNotFound` for that object. The pull writes no ref.
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
        // The test ignores the result of the server. The server reads the end
        // of its input, or it fails to write a reply that it queued before the
        // client failed.
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

/// An `Error` of the server fails the pull with the code of that error and
/// ends the session. The server returns, and the pull writes no ref. The
/// server fails because it cannot load a `bare-user` object whose
/// `user.ostreemeta` does not parse.
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
            Err(Error::Remote(e)) => {
                assert_eq!(e.code(), Some(ostrya::remote::ErrorCode::Internal), "{e:?}")
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

/// If the client drops a body before its end, the pull fails with the cause
/// of the drop, and the session ends. Here the body is a content object, and
/// the pull refuses its mode after it reads the head of the object.
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
        // The test ignores the result of the server. The server reads the end
        // of its input, or it fails to write to a client that dropped its side.
        let _ = served;
        assert!(
            dest.list_refs(Some("refs/remotes"))
                .await
                .unwrap()
                .is_empty()
        );
    });
}

/// If a stated length is more than the cap of the client, the session ends
/// before the client reads the body. The client caps a ref file of a remote
/// with no summary at 1 KiB.
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
            Err(Error::Remote(ostrya::remote::Error::LimitExceeded(msg))) => {
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

/// The resolution of an HTTP address refuses the ssh command and the send
/// command.
#[test]
fn the_resolution_of_an_http_address_refuses_the_ssh_commands() {
    block_on(async {
        let dir = TmpDir::new("pull-ssh-refusals");
        let dest = dest_at(&dir.path().join("dest"), RepoMode::Archive, None).await;
        for (o, key) in [
            (
                EndpointOverrides {
                    ssh_command: Some(vec!["ssh".to_owned()]),
                    ..EndpointOverrides::default()
                },
                "ssh-command",
            ),
            (
                EndpointOverrides {
                    remote_command: Some("ostrya send".to_owned()),
                    ..EndpointOverrides::default()
                },
                "send-command",
            ),
        ] {
            let o = EndpointOverrides {
                url: Some("http://127.0.0.1:1/".to_owned()),
                ..o
            };
            match resolve_pull(Some(dest.config()), "origin", o).await {
                Err(Error::InvalidInput(msg)) => assert!(msg.contains(key), "{msg}"),
                other => panic!("{other:?}"),
            }
        }
    });
}

/// A stand-in ssh command. It writes the arguments that the pull adds, one to
/// a line, to `record`, and exits 0. It serves no session.
fn recording_ssh(record: &Path) -> Vec<String> {
    vec![
        "sh".to_owned(),
        "-c".to_owned(),
        r#"record=$1; shift; printf '%s\n' "$@" > "$record""#.to_owned(),
        "ssh".to_owned(),
        record.to_str().unwrap().to_owned(),
    ]
}

/// Pulls from the remote `origin` of `dest` with the overrides `o`.
async fn pull_resolved(
    dest: &Repo,
    o: EndpointOverrides,
    opts: PullOptions,
) -> Result<PullStats, Error> {
    dest.pull(
        "origin",
        PullOptions {
            overrides: o,
            ..opts
        },
    )
    .await
}

/// The overrides that set the ssh command alone.
fn ssh_command(command: Vec<String>) -> EndpointOverrides {
    EndpointOverrides {
        ssh_command: Some(command),
        ..EndpointOverrides::default()
    }
}

/// The arguments that the stand-in of [`recording_ssh`] got. `None` if the
/// stand-in did not run.
fn recorded(record: &Path) -> Option<Vec<String>> {
    let text = std::fs::read_to_string(record).ok()?;
    Some(text.lines().map(str::to_owned).collect())
}

/// The ssh command and the send command of the caller take priority over the
/// remote keys. If the caller leaves a field `None`, the remote key fills it.
/// This rule also applies to an address that the caller gives.
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
        let pulled = pull_resolved(
            &dest,
            EndpointOverrides {
                remote_command: Some("my-send".to_owned()),
                ..ssh_command(recording_ssh(&both))
            },
            main_ref(0),
        )
        .await;
        // The stand-in serves no session.
        assert!(pulled.is_err());
        assert_eq!(
            recorded(&both).unwrap(),
            ["localhost", "my-send --repo='/srv/repo'"]
        );

        let key = dir.path().join("key");
        let pulled = pull_resolved(&dest, ssh_command(recording_ssh(&key)), main_ref(0)).await;
        assert!(pulled.is_err());
        assert_eq!(
            recorded(&key).unwrap(),
            ["localhost", "/nonexistent/send --repo='/srv/repo'"]
        );

        let url = dir.path().join("url");
        let pulled = pull_resolved(
            &dest,
            EndpointOverrides {
                url: Some("u@h:other".to_owned()),
                ..ssh_command(recording_ssh(&url))
            },
            main_ref(0),
        )
        .await;
        assert!(pulled.is_err());
        assert_eq!(
            recorded(&url).unwrap(),
            ["u@h", "/nonexistent/send --repo='other'"]
        );
    });
}

/// A destination at `dir/dest` whose remote `origin` has the ssh address
/// `ssh://localhost/srv/repo` in `pull-url`, a stand-in `ssh-command`, and
/// the keys `extra`. The stand-in writes its arguments, one to a line, to the
/// returned path, and serves no session.
async fn dest_with_standin_ssh(dir: &Path, extra: &str) -> (Repo, std::path::PathBuf) {
    // A key value splits at white space and cannot hold the script of
    // `recording_ssh`. The script goes in a file that `sh` reads.
    let standin = dir.join("standin.sh");
    std::fs::write(
        &standin,
        "record=$1; shift; printf '%s\\n' \"$@\" > \"$record\"\n",
    )
    .unwrap();
    let record = dir.join("record");
    let dest = dest_with_keys(
        &dir.join("dest"),
        RepoMode::Archive,
        &format!(
            "pull-url=ssh://localhost/srv/repo\nssh-command=sh {} {}\n{extra}",
            standin.display(),
            record.display()
        ),
    )
    .await;
    (dest, record)
}

/// A pull resolves the remote keys. It runs the `ssh-command` of the remote
/// with the address of `pull-url` and the `send-command` of the remote.
#[test]
fn a_pull_runs_the_ssh_keys_of_the_remote() {
    block_on(async {
        let dir = TmpDir::new("pull-ssh-remote-keys");
        let (dest, record) = dest_with_standin_ssh(dir.path(), "send-command=my-send\n").await;
        let pulled = dest.pull("origin", main_ref(0)).await;
        // The stand-in serves no session.
        assert!(pulled.is_err());
        assert_eq!(
            recorded(&record).unwrap(),
            ["localhost", "my-send --repo='/srv/repo'"]
        );
    });
}

/// `remote_fetch_summary` resolves the remote keys as a pull does. It runs
/// the `ssh-command` of the remote with the address of `pull-url` and the
/// `send-command` of the remote.
#[test]
fn remote_fetch_summary_runs_the_ssh_keys_of_the_remote() {
    block_on(async {
        let dir = TmpDir::new("pull-ssh-fetch-summary-keys");
        let (dest, record) = dest_with_standin_ssh(dir.path(), "send-command=my-send\n").await;
        let fetched = dest.remote_fetch_summary("origin").await;
        // The stand-in serves no session.
        assert!(fetched.is_err());
        assert_eq!(
            recorded(&record).unwrap(),
            ["localhost", "my-send --repo='/srv/repo'"]
        );
    });
}

/// `PullSession::fetch_summary` over a stream returns the summary of the
/// remote and its signature. A file that the remote does not serve is
/// `None`. One session serves each call, and it ends with `Ok`.
#[test]
fn a_pull_session_fetches_the_summary_over_a_stream() {
    block_on(async {
        let dir = TmpDir::new("pull-ssh-session-fetch-summary");
        let (remote, _commit) = build_remote(dir.path()).await;
        let root = dir.path().join("remote");
        let summary = std::fs::read(root.join("summary")).unwrap();
        let (to_server, server_in) = pipe(PIPE_CAP);
        let (server_out, from_server) = pipe(PIPE_CAP);
        let (fetched, served) = within(
            "the summary reads through a stream session",
            future::zip(
                async {
                    let session = PullSession::over_stream(
                        from_server,
                        to_server,
                        StreamSessionOptions::default(),
                    )
                    .await
                    .unwrap();
                    let mut fetched = vec![session.fetch_summary().await.unwrap()];
                    std::fs::write(root.join("summary.sig"), b"signature bytes").unwrap();
                    fetched.push(session.fetch_summary().await.unwrap());
                    std::fs::remove_file(root.join("summary")).unwrap();
                    fetched.push(session.fetch_summary().await.unwrap());
                    session.finish().await.unwrap();
                    fetched
                },
                async move { remote.send(server_in, server_out).await },
            ),
        )
        .await;
        served.unwrap();
        let signature = b"signature bytes".to_vec();
        assert_eq!(
            fetched,
            [
                (Some(summary.clone()), None),
                (Some(summary), Some(signature.clone())),
                (None, Some(signature)),
            ]
        );
    });
}

/// `PullSession::fetch_refs` over a stream returns the listing that
/// `Repo::build_ref_listing` builds on the server, for a prefix and for an
/// empty list. The session ends with `Ok`.
#[test]
fn a_pull_session_fetches_the_ref_listing_over_a_stream() {
    block_on(async {
        let dir = TmpDir::new("pull-ssh-session-fetch-refs");
        let (remote, _commit) = build_remote(dir.path()).await;
        let expected = [
            remote.build_ref_listing(&["test"]).await.unwrap(),
            remote.build_ref_listing(&[]).await.unwrap(),
        ];
        let (to_server, server_in) = pipe(PIPE_CAP);
        let (server_out, from_server) = pipe(PIPE_CAP);
        let (fetched, served) = within(
            "the ref listing reads through a stream session",
            future::zip(
                async {
                    let session = PullSession::over_stream(
                        from_server,
                        to_server,
                        StreamSessionOptions::default(),
                    )
                    .await
                    .unwrap();
                    let fetched = [
                        session.fetch_refs(&["test"]).await.unwrap(),
                        session.fetch_refs(&[]).await.unwrap(),
                    ];
                    session.finish().await.unwrap();
                    fetched
                },
                async move { remote.send(server_in, server_out).await },
            ),
        )
        .await;
        served.unwrap();
        let listing = ostrya::Summary::parse(&expected[0]).unwrap();
        assert_eq!(fetched, expected.map(Some));
        assert_eq!(listing.refs.len(), 1);
        assert_eq!(listing.refs[0].name, "test/main");
    });
}

/// The resolution of a pull refuses an ssh address in the `url` key, in the
/// `ssh://` form and in the scp form. The ssh client does not start.
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
            let err = pull_resolved(&dest, ssh_command(recording_ssh(&record)), main_ref(0))
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

/// If the address is an ssh address, the resolution of the pull refuses each
/// option of HTTP alone, so the ssh client does not start. The resolution
/// accepts a retry count of 0, and the ssh client starts.
#[test]
fn the_options_of_http_alone_are_refused_before_the_ssh_client_starts() {
    block_on(async {
        let dir = TmpDir::new("pull-ssh-http-options");
        let dest = dest_at(&dir.path().join("dest"), RepoMode::Archive, None).await;
        let address = "ssh://localhost/srv/repo";
        let with = |o: EndpointOverrides| EndpointOverrides {
            url: Some(address.to_owned()),
            ..EndpointOverrides {
                ssh_command: Some(vec!["/nonexistent/ssh".to_owned()]),
                ..o
            }
        };
        for (name, o) in [
            (
                "http-header",
                EndpointOverrides {
                    http_headers: vec![("A".to_owned(), "B".to_owned())],
                    ..EndpointOverrides::default()
                },
            ),
            (
                "network-retries",
                EndpointOverrides {
                    max_retries: Some(1),
                    ..EndpointOverrides::default()
                },
            ),
            (
                "low-speed-limit-bytes",
                EndpointOverrides {
                    low_speed_limit_bytes: Some(5),
                    ..EndpointOverrides::default()
                },
            ),
            (
                "low-speed-time-seconds",
                EndpointOverrides {
                    low_speed_time: Some(Duration::ZERO),
                    ..EndpointOverrides::default()
                },
            ),
        ] {
            match pull_resolved(&dest, with(o), main_ref(0)).await {
                Err(Error::InvalidInput(msg)) => assert_eq!(
                    msg,
                    format!(
                        "{name} applies to a pull over HTTP, and '{address}' is an ssh address"
                    )
                ),
                other => panic!("{name}: {other:?}"),
            }
        }
        let retries = EndpointOverrides {
            max_retries: Some(0),
            ..EndpointOverrides::default()
        };
        let err = pull_resolved(&dest, with(retries), main_ref(0))
            .await
            .unwrap_err();
        match err {
            Error::Remote(ostrya::remote::Error::Transport(msg)) => {
                assert!(msg.contains("/nonexistent/ssh"), "{msg}")
            }
            other => panic!("{other:?}"),
        }
    });
}

/// A pull over ssh reads no remote key of HTTP alone. TLS keys that an HTTP
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
        let pulled = pull_resolved(&dest, ssh_command(recording_ssh(&record)), main_ref(0)).await;
        assert!(pulled.is_err());
        assert_eq!(
            recorded(&record).unwrap(),
            ["localhost", "ostrya send --repo='/srv/repo'"]
        );

        // The same keys stop an HTTP pull before its first request.
        let err = pull_resolved(
            &dest,
            EndpointOverrides {
                url: Some("http://127.0.0.1:1/".to_owned()),
                ..EndpointOverrides::default()
            },
            main_ref(0),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("tls-permissive"), "{err}");
    });
}

/// A pull over ssh resolves its signature policy before the ssh client
/// starts. If the pull cannot build the policy, the pull stops, and the ssh
/// client does not start. The refusal of an option of HTTP alone comes
/// before the policy.
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
        let err = pull_resolved(&dest, ssh_command(recording_ssh(&policy)), main_ref(0))
            .await
            .unwrap_err();
        match err {
            Error::Signature(msg) => assert!(msg.contains(keys), "{msg}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(recorded(&policy), None);

        let header = dir.path().join("header");
        let err = pull_resolved(
            &dest,
            EndpointOverrides {
                http_headers: vec![("A".to_owned(), "B".to_owned())],
                ..ssh_command(recording_ssh(&header))
            },
            main_ref(0),
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

/// With `no_ref_writes`, a pull through the stream source completes each commit
/// that it pulls and writes no ref.
#[test]
fn the_stream_source_with_no_ref_writes_writes_no_ref() {
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

/// A pull over ssh refuses a collection id. The pull over a pair of streams
/// refuses it before its first `Get`. The pull from an ssh address refuses it
/// before the ssh client starts. Neither pull publishes anything.
#[test]
fn the_ssh_pull_refuses_a_collection_id() {
    block_on(async {
        let dir = TmpDir::new("pull-ssh-collection");
        let (remote, _commit) = build_remote(dir.path()).await;
        let dest_path = dir.path().join("dest");
        let (dest, record) = dest_with_standin_ssh(dir.path(), "").await;
        let before = snapshot(&dest_path);
        let collection = || PullOptions {
            collection_id: Some("org.example.Os".to_owned()),
            no_ref_writes: true,
            ..main_ref(0)
        };
        let expected = "only a local pull takes a collection id";

        let (pulled, served, messages) = pull_session_ssh(
            &dest,
            &remote,
            PullTrust::unverified(),
            StreamSessionOptions::default(),
            collection(),
        )
        .await;
        match pulled {
            Err(Error::Unsupported(msg)) => assert_eq!(msg, expected),
            other => panic!("{other:?}"),
        }
        assert!(
            matches!(messages.as_slice(), [Message::PullHello(_)]),
            "{messages:?}"
        );
        served.unwrap();

        let err = dest.pull("origin", collection()).await.unwrap_err();
        match err {
            Error::Unsupported(msg) => assert_eq!(msg, expected),
            other => panic!("{other:?}"),
        }
        assert_eq!(recorded(&record), None);
        assert_eq!(snapshot(&dest_path), before);
    });
}

/// The read half of the pipe into the server. It keeps a copy of each byte
/// that the server reads.
struct Tap {
    inner: PipeReader,
    read: Arc<Mutex<Vec<u8>>>,
}

impl AsyncRead for Tap {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(n)) = &polled {
            self.read.lock().unwrap().extend_from_slice(&buf[..*n]);
        }
        polled
    }
}

/// Pulls from `remote` into `dest` through a stream session that the test
/// opens with the options `stream`, with `Repo::send` as the server of
/// `remote`. Returns the result of the pull, the result of the server, and
/// the messages that the server read from the client.
async fn pull_session_ssh(
    dest: &Repo,
    remote: &Repo,
    trust: PullTrust,
    stream: StreamSessionOptions,
    opts: PullOptions,
) -> (Result<PullStats, Error>, Result<(), Error>, Vec<Message>) {
    let (to_server, server_in) = pipe(PIPE_CAP);
    let (server_out, from_server) = pipe(PIPE_CAP);
    let read = Arc::new(Mutex::new(Vec::new()));
    let server_in = Tap {
        inner: server_in,
        read: Arc::clone(&read),
    };
    let (pulled, served) = within(
        "the pull through a stream session",
        future::zip(
            async {
                let session = PullSession::over_stream(from_server, to_server, stream).await?;
                dest.pull_with_session(session, trust, opts).await
            },
            async move { remote.send(server_in, server_out).await },
        ),
    )
    .await;
    let read = read.lock().unwrap().clone();
    let mut reader = FrameReader::new(&read[..]);
    let mut messages = Vec::new();
    while let Some(message) = reader.read_message().await.unwrap() {
        messages.push(message);
    }
    (pulled, served, messages)
}

/// A stream pull with `Repo::pull_with_session` into a destination with no
/// remote section, under `PullTrust::unverified()`, writes the same objects,
/// refs, and state files as a stream pull under `PullTrust::from_remote` of the
/// remote `origin` with `gpg-verify=false`. The fetch statistics and the
/// progress counters agree, and the destination passes fsck.
#[test]
fn an_unverified_stream_pull_pulls_what_a_pull_under_the_remote_pulls() {
    block_on(async {
        let dir = TmpDir::new("pull-ssh-session-same");
        let (remote, _first, _second) = build_remote_two_commits(dir.path()).await;
        let opts = |progress: &PullProgress| PullOptions {
            remote: Some("origin".to_owned()),
            progress: Some(progress.clone()),
            ..main_ref(-1)
        };

        let stream_path = dir.path().join("stream");
        let stream_dest = dest_at(&stream_path, RepoMode::Archive, None).await;
        let stream_progress = PullProgress::new();
        let (pulled, served) = pull_ssh(&stream_dest, &remote, opts(&stream_progress)).await;
        let expected = pulled.unwrap();
        served.unwrap();

        let session_path = dir.path().join("session");
        drop(
            Repo::create(&session_path, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap(),
        );
        let session_dest = Repo::open(&session_path).await.unwrap();
        let progress = PullProgress::new();
        let (pulled, served, _) = pull_session_ssh(
            &session_dest,
            &remote,
            PullTrust::unverified(),
            StreamSessionOptions::default(),
            opts(&progress),
        )
        .await;
        let stats = pulled.unwrap();
        served.unwrap();

        assert_eq!(snapshot(&session_path), snapshot(&stream_path));
        assert_eq!(fetch_counts(&stats), fetch_counts(&expected));
        assert_eq!(progress.snapshot(), stream_progress.snapshot());
        assert!(
            session_dest
                .fsck(&FsckOptions::default())
                .await
                .unwrap()
                .is_ok()
        );
    });
}

/// A pull through a stream session refuses an option after the session
/// opens and before its first `Get`. The server reads the `PullHello` of the
/// session and no other message, and returns `Ok`. The pull publishes
/// nothing.
#[test]
fn a_session_pull_over_a_stream_refuses_before_the_first_get() {
    block_on(async {
        let dir = TmpDir::new("pull-ssh-session-refusal");
        let (remote, _commit) = build_remote(dir.path()).await;
        let dest_path = dir.path().join("dest");
        let dest = dest_at(&dest_path, RepoMode::Archive, None).await;
        let before = snapshot(&dest_path);

        let (pulled, served, messages) = pull_session_ssh(
            &dest,
            &remote,
            PullTrust::unverified(),
            StreamSessionOptions::default(),
            PullOptions::default(),
        )
        .await;
        assert!(matches!(pulled, Err(Error::InvalidInput(_))), "{pulled:?}");
        assert!(
            matches!(messages.as_slice(), [Message::PullHello(_)]),
            "{messages:?}"
        );
        served.unwrap();
        assert_eq!(snapshot(&dest_path), before);
    });
}
