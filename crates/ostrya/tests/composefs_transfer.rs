#![forbid(unsafe_code)]

//! Tests of the transfer of the composefs image object,
//! `objects/<xx>/<commit>.cfs`.
//!
//! The tests check these facts:
//!
//! - A local pull, an HTTP pull, a pull through a stream session, a push, and
//!   a one-way stream each copy the image byte for byte, and the copy passes
//!   [`Repo::check_composefs_image`]. A local pull never shares the inode of
//!   the source image.
//! - Each write path refuses an image whose digest is not the key of its
//!   commit, and publishes no ref.
//! - A pull from a source with no image of a commit with the key succeeds.
//!   A pull of a commit with no key, or with a malformed key, a commit-only
//!   pull, and a pull with a subpath request no `.cfs`.
//! - A pull and a push add the image of a commit that the destination holds
//!   with no image. An image that the destination holds is not sent again.
//! - An HTTP pull and a pull through a stream session request each image
//!   after each other object of the pull, also with several fetches in
//!   flight and through a chain of static deltas.
//! - After the first image that the remote does not serve, a pull requests
//!   no image of a held commit. A new commit gets its request all the same.
//! - The receiver refuses an image for a commit with no key, a second image
//!   for one commit, an image for a commit that it neither staged nor holds,
//!   and an image in a session with a server commit. It accepts an image for
//!   a commit that the repository holds. No object count holds an image.
//!
//! The tests of the seal skip if the file system has no fs-verity.

mod common;
#[path = "common/pull.rs"]
mod pull;

use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use common::composefs::{
    DIGEST_KEY, build_owned_source, commit_tree, dict, new_repo, verity_supported,
};
use common::pipe::pipe;
use common::{TmpDir, anyone, is_sealed};
use futures_io::AsyncRead;
use futures_lite::future;
use ostrya::remote::{PullSession, StreamSessionOptions};
use ostrya::verify::PullTrust;
use ostrya::{
    AdvertisedDelta, Checksum, CommitOptions, ComposefsImageState, DeltaOptions, Error,
    MutableTree, PullFlags, PullOptions, PullStats, Repo, RepoMode, SummaryOptions, Value,
    static_delta_relative_dir,
};
use ostrya_rt::block_on;
use pull::{RepoServer, build_dest, meta_path};

/// The capacity of each pipe of a stream session.
const PIPE_CAP: usize = 64 * 1024;

/// Creates a repository of `mode` under `dir/name` and commits the owned tree
/// of `dir/tree` onto `main`, with the key. If `image` is set, the repository
/// stores the image of the commit. A summary lists `main`.
async fn source(dir: &Path, name: &str, mode: RepoMode, image: bool) -> (Repo, Checksum) {
    let tree = dir.join("tree");
    if !tree.exists() {
        build_owned_source(&tree);
    }
    let repo = new_repo(&dir.join(name), mode, "").await;
    let (commit, _) = commit_tree(&repo, &tree, 1, image, Some("main")).await;
    repo.regenerate_summary(&SummaryOptions {
        last_modified: Some(1),
        ..SummaryOptions::default()
    })
    .await
    .unwrap();
    (repo, commit)
}

/// Commits the owned tree of `dir/tree` onto `main` of `repo`, with
/// `metadata` and no image, and writes a summary.
async fn commit_with(repo: &Repo, dir: &Path, metadata: Option<Value>) -> Checksum {
    let tree = dir.join("tree");
    if !tree.exists() {
        build_owned_source(&tree);
    }
    let txn = repo.transaction().await.unwrap();
    let mut mtree = MutableTree::new();
    let dfd = std::fs::File::open(&tree).unwrap();
    txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("src"), &mut mtree, None)
        .await
        .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let opts = CommitOptions {
        subject: Some("no image".to_owned()),
        timestamp: Some(2),
        metadata,
        ..CommitOptions::default()
    };
    let commit = txn.write_commit(opts, &root).await.unwrap();
    txn.set_ref("main", Some(&commit));
    txn.commit().await.unwrap();
    repo.regenerate_summary(&SummaryOptions {
        last_modified: Some(2),
        ..SummaryOptions::default()
    })
    .await
    .unwrap();
    commit
}

/// Returns the bytes of the stored image of `commit`, or `None`.
fn image_bytes(repo: &Repo, commit: &Checksum) -> Option<Vec<u8>> {
    std::fs::read(repo.composefs_image_path(commit)).ok()
}

/// Asserts that `dest` holds the image of `commit` that `src` holds, byte for
/// byte, and that the image passes the check against the key.
async fn assert_same_image(src: &Repo, dest: &Repo, commit: &Checksum) {
    let expected = image_bytes(src, commit).expect("the source holds the image");
    assert_eq!(image_bytes(dest, commit), Some(expected));
    assert_eq!(
        dest.check_composefs_image(commit).await.unwrap(),
        ComposefsImageState::Valid
    );
}

/// Returns the request path of the image of `commit`.
fn cfs_path(commit: &Checksum) -> String {
    meta_path(commit, "cfs")
}

/// Returns `bytes` with the byte in the middle flipped.
fn flipped(mut bytes: Vec<u8>) -> Vec<u8> {
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0xff;
    bytes
}

/// Writes `bytes` over the stored image of `commit` in `repo`.
fn replace_image(repo: &Repo, commit: &Checksum, bytes: &[u8]) {
    let path = repo.composefs_image_path(commit);
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, bytes).unwrap();
}

/// The options of a pull of `main`.
fn main_ref() -> PullOptions {
    PullOptions {
        refs: vec!["main".to_owned()],
        ..PullOptions::default()
    }
}

/// Pulls `opts` from `remote` into `dest` through a stream session, with
/// `Repo::send` as the server of `remote`. After a pull that succeeds, the
/// server must succeed too.
async fn stream_pull(dest: &Repo, remote: &Repo, opts: PullOptions) -> ostrya::Result<PullStats> {
    stream_pull_seen(dest, remote, opts).await.0
}

/// A reader that keeps a copy of each byte that it reads from `inner`.
struct Tap<R> {
    inner: R,
    seen: Arc<Mutex<Vec<u8>>>,
}

impl<R: AsyncRead + Unpin> AsyncRead for Tap<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(n)) = &polled {
            self.seen.lock().unwrap().extend_from_slice(&buf[..*n]);
        }
        polled
    }
}

/// Returns the paths under `objects/` that the client bytes `bytes` of a
/// stream session request, in order. A `Get` frame holds its path as a
/// string with a NUL at its end.
fn object_requests(bytes: &[u8]) -> Vec<String> {
    let needle = b"objects/";
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(start) = bytes[at..]
        .windows(needle.len())
        .position(|window| window == needle)
    {
        let start = at + start;
        let len = bytes[start..].iter().position(|&b| b == 0).unwrap();
        out.push(String::from_utf8(bytes[start..start + len].to_vec()).unwrap());
        at = start + len;
    }
    out
}

/// Pulls as [`stream_pull`] does, and returns the paths under `objects/`
/// that the pull requested, in order.
async fn stream_pull_seen(
    dest: &Repo,
    remote: &Repo,
    opts: PullOptions,
) -> (ostrya::Result<PullStats>, Vec<String>) {
    let (to_server, server_in) = pipe(PIPE_CAP);
    let (server_out, from_server) = pipe(PIPE_CAP);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let server_in = Tap {
        inner: server_in,
        seen: seen.clone(),
    };
    let (pulled, served) = future::zip(
        async {
            let session =
                PullSession::over_stream(from_server, to_server, StreamSessionOptions::default())
                    .await?;
            dest.pull_with_session(session, PullTrust::unverified(), opts)
                .await
        },
        async move { remote.send(server_in, server_out, &anyone()).await },
    )
    .await;
    // A pull that fails closes the session, and the server can fail on the
    // closed stream.
    if pulled.is_ok() {
        served.unwrap();
    }
    let seen = object_requests(&seen.lock().unwrap());
    (pulled, seen)
}

/// Asserts that `seen`, the object requests of a pull in order, holds a
/// request of each image of `commits`, each after each request of a tree
/// object or a content object. At least `min` tree and content requests go
/// first.
fn assert_images_last(seen: &[String], commits: &[Checksum], min: usize) {
    let images: Vec<usize> = commits
        .iter()
        .map(|commit| {
            seen.iter()
                .position(|path| *path == cfs_path(commit))
                .unwrap_or_else(|| panic!("no request of the image of {commit}: {seen:?}"))
        })
        .collect();
    let tree: Vec<usize> = seen
        .iter()
        .enumerate()
        .filter(|(_, path)| {
            [".filez", ".dirtree", ".dirmeta"]
                .iter()
                .any(|ext| path.ends_with(ext))
        })
        .map(|(at, _)| at)
        .collect();
    assert!(tree.len() >= min, "{seen:?}");
    assert!(
        tree.iter().max() < images.iter().min(),
        "an image before a tree object: {seen:?}"
    );
}

/// Commits the tree of `dir/tree` onto `branch` of `remote` at `timestamp`,
/// with the key and no image, and writes a summary.
async fn commit_keyed(remote: &Repo, dir: &Path, timestamp: u64, branch: &str) -> Checksum {
    let tree = dir.join("tree");
    if !tree.exists() {
        build_owned_source(&tree);
    }
    let (commit, _) = commit_tree(remote, &tree, timestamp, false, Some(branch)).await;
    remote
        .regenerate_summary(&SummaryOptions {
            last_modified: Some(timestamp),
            ..SummaryOptions::default()
        })
        .await
        .unwrap();
    commit
}

/// The options of a pull of `refs`.
fn refs_opts(refs: &[&str]) -> PullOptions {
    PullOptions {
        refs: refs.iter().map(|name| (*name).to_owned()).collect(),
        ..PullOptions::default()
    }
}

// ---------------------------------------------------------------------------
// The local pull.
// ---------------------------------------------------------------------------

/// A local pull copies the image byte for byte between modes, and the copy
/// is an inode of its own. A second pull copies nothing.
#[test]
fn a_local_pull_copies_the_image() {
    let dir = TmpDir::new("cfs-transfer-local");
    block_on(async {
        for (at, (src_mode, dest_mode)) in [
            (RepoMode::BareUser, RepoMode::Archive),
            (RepoMode::Archive, RepoMode::BareUser),
            (RepoMode::BareUser, RepoMode::BareUser),
        ]
        .into_iter()
        .enumerate()
        {
            let (src, commit) = source(dir.path(), &format!("src-{at}"), src_mode, true).await;
            let dest = new_repo(&dir.path().join(format!("dest-{at}")), dest_mode, "").await;
            dest.pull_local(&src, main_ref()).await.unwrap();
            assert_same_image(&src, &dest, &commit).await;
            let ino = |repo: &Repo| {
                std::fs::metadata(repo.composefs_image_path(&commit))
                    .unwrap()
                    .ino()
            };
            assert_ne!(ino(&src), ino(&dest), "{src_mode:?} -> {dest_mode:?}");

            let flags = PullFlags::FORCE_COPY | PullFlags::UNTRUSTED;
            let opts = PullOptions {
                flags,
                ..main_ref()
            };
            let before = ino(&dest);
            dest.pull_local(&src, opts).await.unwrap();
            assert_eq!(ino(&dest), before, "a held image is not copied again");
        }
    });
}

/// A local pull into a repository that seals its objects seals the image.
/// Skips if the file system has no fs-verity.
#[test]
fn a_local_pull_seals_the_image() {
    let dir = TmpDir::new("cfs-transfer-seal");
    if !verity_supported(dir.path()) {
        eprintln!("skipping: the file system has no fs-verity");
        return;
    }
    block_on(async {
        let (src, commit) = source(dir.path(), "src", RepoMode::BareUser, true).await;
        let config = "[ex-integrity]\nfsverity=maybe\n";
        let dest = new_repo(&dir.path().join("dest"), RepoMode::BareUser, config).await;
        dest.pull_local(&src, main_ref()).await.unwrap();
        assert_same_image(&src, &dest, &commit).await;
        assert!(is_sealed(&dest.composefs_image_path(&commit)));
    });
}

/// A local pull refuses a source image whose digest is not the key. It
/// writes no ref and no image.
#[test]
fn a_local_pull_refuses_an_image_that_is_not_the_key() {
    let dir = TmpDir::new("cfs-transfer-local-bad");
    block_on(async {
        let (src, commit) = source(dir.path(), "src", RepoMode::BareUser, true).await;
        let bytes = image_bytes(&src, &commit).unwrap();
        replace_image(&src, &commit, &flipped(bytes));
        let dest = new_repo(&dir.path().join("dest"), RepoMode::Archive, "").await;
        let err = dest.pull_local(&src, main_ref()).await.unwrap_err();
        assert!(
            matches!(err, Error::ComposefsDigestMismatch { commit: c, .. } if c == commit),
            "{err:?}"
        );
        assert!(dest.list_refs(None).await.unwrap().is_empty());
        assert_eq!(image_bytes(&dest, &commit), None);
    });
}

/// A local pull from a source with no image of a commit with the key
/// succeeds. A commit-only pull copies no image. A later pull adds the image
/// of a commit that the destination holds complete with no image.
#[test]
fn a_local_pull_adds_the_image_of_a_held_commit() {
    let dir = TmpDir::new("cfs-transfer-local-held");
    block_on(async {
        let (plain, commit) = source(dir.path(), "plain", RepoMode::BareUser, false).await;
        let (src, same) = source(dir.path(), "src", RepoMode::BareUser, true).await;
        assert_eq!(commit, same, "the image does not change the commit");
        let dest = new_repo(&dir.path().join("dest"), RepoMode::Archive, "").await;

        dest.pull_local(&plain, main_ref()).await.unwrap();
        assert_eq!(
            dest.check_composefs_image(&commit).await.unwrap(),
            ComposefsImageState::Absent
        );
        let commit_only = PullOptions {
            flags: PullFlags::COMMIT_ONLY,
            ..main_ref()
        };
        dest.pull_local(&src, commit_only).await.unwrap();
        assert_eq!(image_bytes(&dest, &commit), None);

        dest.pull_local(&src, main_ref()).await.unwrap();
        assert_same_image(&src, &dest, &commit).await;
    });
}

// ---------------------------------------------------------------------------
// The HTTP pull.
// ---------------------------------------------------------------------------

/// An HTTP pull requests the image after each other object, and copies it
/// byte for byte. A second pull requests no image. After the image is gone
/// from the destination, a pull of the held commit requests it again.
#[test]
fn an_http_pull_fetches_the_image_after_the_content() {
    let dir = TmpDir::new("cfs-transfer-http");
    block_on(async {
        let (remote, commit) = source(dir.path(), "remote", RepoMode::Archive, true).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;
        let opts = || PullOptions {
            max_outstanding_fetches: Some(1),
            ..main_ref()
        };

        let stats = dest.pull("origin", opts()).await.unwrap();
        assert_same_image(&remote, &dest, &commit).await;
        let objects: Vec<String> = server
            .seen()
            .into_iter()
            .filter(|path| path.starts_with("objects/"))
            .collect();
        assert_eq!(objects.last(), Some(&cfs_path(&commit)), "{objects:?}");
        assert_eq!(server.requests_for(&cfs_path(&commit)), 1);
        // The image adds its bytes alone.
        let size = image_bytes(&remote, &commit).unwrap().len() as u64;
        assert!(stats.bytes_transferred > size);

        server.forget();
        dest.pull("origin", opts()).await.unwrap();
        assert_eq!(server.requests_for(&cfs_path(&commit)), 0);

        std::fs::remove_file(dest.composefs_image_path(&commit)).unwrap();
        server.forget();
        dest.pull("origin", opts()).await.unwrap();
        assert_eq!(server.statuses_for(&cfs_path(&commit)), [200]);
        assert_same_image(&remote, &dest, &commit).await;
    });
}

/// With the default number of fetches in flight, an HTTP pull requests the
/// image after each dirtree, dirmeta, and content object of a tree with a
/// nested directory and several files.
#[test]
fn an_http_pull_with_several_fetches_requests_the_image_last() {
    let dir = TmpDir::new("cfs-transfer-http-order");
    block_on(async {
        let (remote, commit) = source(dir.path(), "remote", RepoMode::Archive, true).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;
        dest.pull("origin", main_ref()).await.unwrap();
        assert_same_image(&remote, &dest, &commit).await;
        // Two dirtrees, two dirmetas, and five content objects.
        assert_images_last(&server.seen(), &[commit], 9);
    });
}

/// A pull through a chain of static deltas requests the image of each
/// commit of the chain after each part of the last step and each object
/// of the tree walk.
#[test]
fn a_delta_chain_pull_requests_the_images_last() {
    let dir = TmpDir::new("cfs-transfer-http-chain");
    block_on(async {
        let remote = new_repo(&dir.path().join("remote"), RepoMode::Archive, "").await;
        let mut commits = Vec::new();
        for (at, marker) in [&b"a\n"[..], b"b\n", b"c\n"].into_iter().enumerate() {
            let base = dir.path().join(format!("tree-{at}"));
            build_owned_source(&base);
            std::fs::write(base.join("src/marker"), marker).unwrap();
            let (commit, _) = commit_tree(&remote, &base, at as u64 + 1, true, Some("main")).await;
            commits.push(commit);
        }
        let mut list = Vec::new();
        for pair in commits.windows(2) {
            let opts = DeltaOptions {
                timestamp: Some(1),
                ..DeltaOptions::default()
            };
            remote
                .generate_static_delta(Some(&pair[0]), &pair[1], &opts)
                .await
                .unwrap();
            let dir = static_delta_relative_dir(Some(&pair[0]), &pair[1]);
            let bytes = std::fs::read(remote.path().join(format!("{dir}/superblock"))).unwrap();
            list.push(AdvertisedDelta {
                from: Some(pair[0]),
                to: pair[1],
                superblock: Checksum::sha256(&bytes),
            });
        }
        let server = RepoServer::start(remote.path(), false).await;
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;
        let first = PullOptions {
            refs: vec![commits[0].to_hex()],
            ..PullOptions::default()
        };
        dest.pull_local(&remote, first).await.unwrap();

        let opts = PullOptions {
            static_deltas: Some(list),
            ..main_ref()
        };
        dest.pull("origin", opts).await.unwrap();
        let seen = server.seen();
        let last_part = seen
            .iter()
            .rposition(|path| path.starts_with("deltas/"))
            .unwrap_or_else(|| panic!("no delta request: {seen:?}"));
        let first_image = seen
            .iter()
            .position(|path| path.ends_with(".cfs"))
            .unwrap_or_else(|| panic!("no image request: {seen:?}"));
        assert!(last_part < first_image, "{seen:?}");
        let objects: Vec<String> = seen
            .into_iter()
            .filter(|path| path.starts_with("objects/"))
            .collect();
        assert_images_last(&objects, &commits[1..], 0);
        for commit in &commits[1..] {
            assert_same_image(&remote, &dest, commit).await;
        }
    });
}

/// A remote that serves no image answers 404 to the first image of a held
/// commit, and the pull requests no other image of a held commit. A new
/// commit gets its own request, and after its 404 the held commits get
/// none.
#[test]
fn an_http_pull_stops_the_held_images_after_a_404() {
    let dir = TmpDir::new("cfs-transfer-http-held-absent");
    block_on(async {
        let remote = new_repo(&dir.path().join("remote"), RepoMode::Archive, "").await;
        let a = commit_keyed(&remote, dir.path(), 1, "a").await;
        let b = commit_keyed(&remote, dir.path(), 2, "b").await;
        let server = RepoServer::start(remote.path(), false).await;
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;
        let held_requests = |server: &RepoServer| {
            server.requests_for(&cfs_path(&a)) + server.requests_for(&cfs_path(&b))
        };

        dest.pull("origin", refs_opts(&["a", "b"])).await.unwrap();
        assert_eq!(
            held_requests(&server),
            2,
            "new commits: {:?}",
            server.seen()
        );

        server.forget();
        dest.pull("origin", refs_opts(&["a", "b"])).await.unwrap();
        assert_eq!(held_requests(&server), 1, "{:?}", server.seen());

        let c = commit_keyed(&remote, dir.path(), 3, "c").await;
        server.forget();
        dest.pull("origin", refs_opts(&["a", "b", "c"]))
            .await
            .unwrap();
        assert_eq!(server.statuses_for(&cfs_path(&c)), [404]);
        assert_eq!(held_requests(&server), 0, "{:?}", server.seen());
        assert_eq!(dest.resolve_rev("origin:c", false).await.unwrap(), Some(c));
    });
}

/// An HTTP pull refuses an image whose digest is not the key, and fetches it
/// one time. It writes no ref and no image.
#[test]
fn an_http_pull_refuses_an_image_that_is_not_the_key() {
    let dir = TmpDir::new("cfs-transfer-http-bad");
    block_on(async {
        let (remote, commit) = source(dir.path(), "remote", RepoMode::Archive, true).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        server.tamper(
            &cfs_path(&commit),
            flipped(image_bytes(&remote, &commit).unwrap()),
        );
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;
        let err = dest.pull("origin", main_ref()).await.unwrap_err();
        assert!(
            matches!(err, Error::ComposefsDigestMismatch { .. }),
            "{err:?}"
        );
        assert_eq!(server.requests_for(&cfs_path(&commit)), 1);
        pull::assert_nothing_published(&dest).await;
        assert_eq!(image_bytes(&dest, &commit), None);
    });
}

/// A remote that serves no image of a commit with the key answers 404, and
/// the pull succeeds with no image.
#[test]
fn an_http_pull_from_a_remote_with_no_image_succeeds() {
    let dir = TmpDir::new("cfs-transfer-http-absent");
    block_on(async {
        let (remote, commit) = source(dir.path(), "remote", RepoMode::Archive, false).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::BareUser, &server.url(), "").await;
        dest.pull("origin", main_ref()).await.unwrap();
        assert_eq!(server.statuses_for(&cfs_path(&commit)), [404]);
        assert_eq!(
            dest.resolve_rev("origin:main", false).await.unwrap(),
            Some(commit)
        );
        assert_eq!(
            dest.check_composefs_image(&commit).await.unwrap(),
            ComposefsImageState::Absent
        );
        let _ = remote;
    });
}

/// A pull requests no `.cfs` for a commit with no key, for a commit with a
/// malformed key, in a commit-only pull, and in a pull with a subpath.
#[test]
fn an_http_pull_requests_no_image_without_a_key_or_a_whole_tree() {
    let dir = TmpDir::new("cfs-transfer-http-none");
    block_on(async {
        let (remote, commit) = source(dir.path(), "remote", RepoMode::Archive, true).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let any_cfs = |server: &RepoServer| server.seen().iter().any(|p| p.ends_with(".cfs"));

        for (at, opts) in [
            PullOptions {
                flags: PullFlags::COMMIT_ONLY,
                ..main_ref()
            },
            PullOptions {
                subpaths: vec!["/sub".to_owned()],
                ..main_ref()
            },
        ]
        .into_iter()
        .enumerate()
        {
            let base = dir.path().join(format!("partial-{at}"));
            std::fs::create_dir_all(&base).unwrap();
            let dest = build_dest(&base, RepoMode::BareUser, &server.url(), "").await;
            server.forget();
            dest.pull("origin", opts).await.unwrap();
            assert!(!any_cfs(&server), "{:?}", server.seen());
            assert_eq!(image_bytes(&dest, &commit), None);
        }

        for (at, metadata) in [None, Some(dict(DIGEST_KEY, "s", Value::Str("x".into())))]
            .into_iter()
            .enumerate()
        {
            let other = commit_with(&remote, dir.path(), metadata).await;
            let base = dir.path().join(format!("keyless-{at}"));
            std::fs::create_dir_all(&base).unwrap();
            let dest = build_dest(&base, RepoMode::BareUser, &server.url(), "").await;
            server.forget();
            dest.pull("origin", main_ref()).await.unwrap();
            assert_eq!(
                dest.resolve_rev("origin:main", false).await.unwrap(),
                Some(other)
            );
            assert!(!any_cfs(&server), "{:?}", server.seen());
        }
    });
}

// ---------------------------------------------------------------------------
// The pull through a stream session.
// ---------------------------------------------------------------------------

/// A pull through a stream session copies the image that the archive view of
/// a `bare-user` remote serves as stored. A remote with no image leaves the
/// commit with none, and the pull succeeds.
#[test]
fn a_stream_pull_copies_the_image() {
    let dir = TmpDir::new("cfs-transfer-stream");
    block_on(async {
        let (remote, commit) = source(dir.path(), "remote", RepoMode::BareUser, true).await;
        let dest = new_repo(&dir.path().join("dest"), RepoMode::Archive, "").await;
        stream_pull(&dest, &remote, main_ref()).await.unwrap();
        assert_same_image(&remote, &dest, &commit).await;

        let (plain, same) = source(dir.path(), "plain", RepoMode::BareUser, false).await;
        assert_eq!(same, commit);
        let empty = new_repo(&dir.path().join("empty"), RepoMode::Archive, "").await;
        stream_pull(&empty, &plain, main_ref()).await.unwrap();
        assert_eq!(image_bytes(&empty, &commit), None);
    });
}

/// A pull through a stream session requests the image after each dirtree,
/// dirmeta, and content object.
#[test]
fn a_stream_pull_requests_the_image_last() {
    let dir = TmpDir::new("cfs-transfer-stream-order");
    block_on(async {
        let (remote, commit) = source(dir.path(), "remote", RepoMode::BareUser, true).await;
        let dest = new_repo(&dir.path().join("dest"), RepoMode::Archive, "").await;
        let (pulled, seen) = stream_pull_seen(&dest, &remote, main_ref()).await;
        pulled.unwrap();
        assert_same_image(&remote, &dest, &commit).await;
        assert_images_last(&seen, &[commit], 9);
    });
}

/// A pull through a stream session from a remote with no image requests one
/// image for the held commits. A new commit gets its own request.
#[test]
fn a_stream_pull_stops_the_held_images_after_an_absent_image() {
    let dir = TmpDir::new("cfs-transfer-stream-held-absent");
    block_on(async {
        let remote = new_repo(&dir.path().join("remote"), RepoMode::BareUser, "").await;
        let a = commit_keyed(&remote, dir.path(), 1, "a").await;
        let b = commit_keyed(&remote, dir.path(), 2, "b").await;
        let dest = new_repo(&dir.path().join("dest"), RepoMode::Archive, "").await;
        let count = |seen: &[String], commits: &[Checksum]| {
            seen.iter()
                .filter(|path| commits.iter().any(|commit| **path == cfs_path(commit)))
                .count()
        };

        let (pulled, seen) = stream_pull_seen(&dest, &remote, refs_opts(&["a", "b"])).await;
        pulled.unwrap();
        assert_eq!(count(&seen, &[a, b]), 2, "{seen:?}");

        let (pulled, seen) = stream_pull_seen(&dest, &remote, refs_opts(&["a", "b"])).await;
        pulled.unwrap();
        assert_eq!(count(&seen, &[a, b]), 1, "{seen:?}");

        let c = commit_keyed(&remote, dir.path(), 3, "c").await;
        let (pulled, seen) = stream_pull_seen(&dest, &remote, refs_opts(&["a", "b", "c"])).await;
        pulled.unwrap();
        assert_eq!(count(&seen, &[c]), 1, "{seen:?}");
        assert_eq!(count(&seen, &[a, b]), 0, "{seen:?}");
    });
}

/// A pull through a stream session into a repository that seals its objects
/// seals the image that it streams. Skips if the file system has no
/// fs-verity.
#[test]
fn a_stream_pull_seals_the_image() {
    let dir = TmpDir::new("cfs-transfer-stream-seal");
    if !verity_supported(dir.path()) {
        eprintln!("skipping: the file system has no fs-verity");
        return;
    }
    block_on(async {
        let (remote, commit) = source(dir.path(), "remote", RepoMode::BareUser, true).await;
        let config = "[ex-integrity]\nfsverity=yes\n";
        let dest = new_repo(&dir.path().join("dest"), RepoMode::BareUser, config).await;
        stream_pull(&dest, &remote, main_ref()).await.unwrap();
        assert_same_image(&remote, &dest, &commit).await;
        assert!(is_sealed(&dest.composefs_image_path(&commit)));
    });
}

/// A pull through a stream session refuses an image whose digest is not the
/// key.
#[test]
fn a_stream_pull_refuses_an_image_that_is_not_the_key() {
    let dir = TmpDir::new("cfs-transfer-stream-bad");
    block_on(async {
        let (remote, commit) = source(dir.path(), "remote", RepoMode::BareUser, true).await;
        let bytes = image_bytes(&remote, &commit).unwrap();
        replace_image(&remote, &commit, &flipped(bytes));
        let dest = new_repo(&dir.path().join("dest"), RepoMode::Archive, "").await;
        let err = stream_pull(&dest, &remote, main_ref()).await.unwrap_err();
        assert!(
            matches!(err, Error::ComposefsDigestMismatch { .. }),
            "{err:?}"
        );
        assert!(dest.list_refs(None).await.unwrap().is_empty());
        assert_eq!(image_bytes(&dest, &commit), None);
    });
}

// ---------------------------------------------------------------------------
// The push, the one-way stream, and the receiver.
// ---------------------------------------------------------------------------

#[cfg(all(feature = "push", feature = "receive"))]
mod push {
    use futures_lite::future::zip;
    use ostrya::remote::proto::{Message, ServerCommit};
    use ostrya::remote::{Encoding, ErrorCode, Expected, PushOutcome, RefUpdate};
    use ostrya::{ExportStreamOptions, ObjectType, RepoPushOptions, StreamPolicy};

    use super::common::receive::{
        Obj, assert_nothing_published, commit_objects, policy_allowing, returned_code, session,
    };
    use super::common::{TmpDir, file_inventory};
    use super::*;

    /// Pushes `main` from `client` into `server` over two pipes, under a
    /// policy that allows each write.
    async fn push(client: &Repo, server: &Repo) -> PushOutcome {
        let (client_out, server_in) = pipe(PIPE_CAP);
        let (server_out, client_in) = pipe(PIPE_CAP);
        let policy = policy_allowing(&["w:**"]);
        let opts = RepoPushOptions {
            refspecs: vec!["main".to_owned()],
            ..RepoPushOptions::default()
        };
        let (received, pushed) = zip(
            server.receive(server_in, server_out, &policy),
            client.push_over_stream(client_in, client_out, opts),
        )
        .await;
        received.unwrap();
        pushed.unwrap()
    }

    fn update(name: &str, expected: Expected, new: Checksum) -> RefUpdate {
        RefUpdate {
            name: name.into(),
            expected,
            new: Some(new),
        }
    }

    /// A push sends the image with its commit, byte for byte. A second push
    /// sends no object. After the server loses the image, a push of the
    /// commit that the server holds sends the image alone, and no object
    /// count holds it.
    #[test]
    fn a_push_sends_the_image_once() {
        let dir = TmpDir::new("cfs-transfer-push");
        block_on(async {
            let (client, commit) = source(dir.path(), "client", RepoMode::BareUser, true).await;
            let server = new_repo(&dir.path().join("server"), RepoMode::Archive, "").await;
            let size = image_bytes(&client, &commit).unwrap().len() as u64;

            push(&client, &server).await;
            assert_same_image(&client, &server, &commit).await;

            let outcome = push(&client, &server).await;
            assert_eq!(outcome.stats.objects_needed, 0);
            assert_eq!(outcome.stats.objects_sent, 0);
            assert_eq!(outcome.stats.payload_bytes, 0);

            std::fs::remove_file(server.composefs_image_path(&commit)).unwrap();
            let outcome = push(&client, &server).await;
            assert_eq!(outcome.stats.objects_needed, 0);
            assert_eq!(outcome.stats.objects_sent, 0);
            assert_eq!(outcome.stats.payload_bytes, size);
            assert_same_image(&client, &server, &commit).await;
        });
    }

    /// A one-way stream carries the image of each new commit, and the
    /// receiver stores it byte for byte.
    #[test]
    fn a_one_way_stream_carries_the_image() {
        let dir = TmpDir::new("cfs-transfer-one-way");
        block_on(async {
            let (client, commit) = source(dir.path(), "client", RepoMode::BareUser, true).await;
            let server = new_repo(&dir.path().join("server"), RepoMode::Archive, "").await;
            let mut bytes = Vec::new();
            let opts = ExportStreamOptions {
                updates: vec![update("main", Expected::Absent, commit)],
                ..ExportStreamOptions::default()
            };
            let stats = client.export_stream(&mut bytes, opts).await.unwrap();
            let size = image_bytes(&client, &commit).unwrap().len() as u64;
            assert!(stats.payload_bytes > size);
            server
                .receive_stream(&bytes[..], &StreamPolicy::default())
                .await
                .unwrap();
            assert_same_image(&client, &server, &commit).await;
        });
    }

    /// The objects of `commit` in the archive repository `repo`, with the
    /// commit last, and the image of the commit after them if `image` is
    /// given.
    fn objects(repo: &Repo, commit: &Checksum, image: Option<Vec<u8>>) -> Vec<Obj> {
        let mut objects = commit_objects(repo.path(), commit, Encoding::Raw);
        if let Some(bytes) = image {
            objects.push(Obj {
                ty: ObjectType::ComposefsImage,
                checksum: *commit,
                encoding: Encoding::Raw,
                bytes,
            });
        }
        objects
    }

    /// Runs a push session that sends `objects` and a `Commit` of `main` to
    /// `new` into `server`, and returns the result of the server and the
    /// `ObjectsReply` counts.
    fn send_objects(
        server: &Repo,
        objects: &[Obj],
        expected: Expected,
        new: Checksum,
    ) -> (ostrya::Result<ostrya::ReceiveReport>, Option<(u32, u64)>) {
        session(
            server,
            &policy_allowing(&["w:**"]),
            |mut client| async move {
                client.hello_reply(&["main"]).await;
                for o in objects {
                    if client
                        .object(o.ty, o.checksum, o.encoding, &o.bytes)
                        .await
                        .is_err()
                    {
                        return None;
                    }
                }
                if client.send(&Message::ObjectsEnd).await.is_err() {
                    return None;
                }
                let reply = match client.recv().await {
                    Some(Message::ObjectsReply(reply)) => reply,
                    _ => return None,
                };
                let _ = client
                    .commit(vec![update("main", expected, new)], false)
                    .await;
                let _ = client.commit_reply().await;
                Some((reply.objects, reply.payload_bytes))
            },
        )
    }

    /// The receiver refuses an image whose digest is not the key with
    /// `checksum-mismatch`, and an image for a commit with no key with
    /// `protocol`. Each refusal publishes nothing.
    #[test]
    fn the_receiver_refuses_an_image_that_is_not_the_key() {
        let dir = TmpDir::new("cfs-transfer-receive-bad");
        let (src, commit) = block_on(source(dir.path(), "src", RepoMode::Archive, true));
        let image = image_bytes(&src, &commit).unwrap();
        let keyless = block_on(commit_with(&src, dir.path(), None));

        for (at, (target, bytes, code)) in [
            (commit, flipped(image.clone()), ErrorCode::ChecksumMismatch),
            (keyless, image, ErrorCode::Protocol),
        ]
        .into_iter()
        .enumerate()
        {
            let server = block_on(new_repo(
                &dir.path().join(format!("server-{at}")),
                RepoMode::Archive,
                "",
            ));
            let before = file_inventory(server.path(), "objects");
            let objects = objects(&src, &target, Some(bytes));
            let (result, _) = send_objects(&server, &objects, Expected::Absent, target);
            assert_eq!(returned_code(&result), Some(code), "{result:?}");
            assert_nothing_published(&server, &before);
        }
    }

    /// A second image for one commit is `protocol`, and the session
    /// publishes nothing.
    #[test]
    fn the_receiver_refuses_a_second_image() {
        let dir = TmpDir::new("cfs-transfer-receive-twice");
        let (src, commit) = block_on(source(dir.path(), "src", RepoMode::Archive, true));
        let image = image_bytes(&src, &commit).unwrap();
        let server = block_on(new_repo(&dir.path().join("server"), RepoMode::Archive, ""));
        let before = file_inventory(server.path(), "objects");
        let mut objects = objects(&src, &commit, Some(image));
        objects.push(objects.last().unwrap().clone());
        let (result, _) = send_objects(&server, &objects, Expected::Absent, commit);
        assert_eq!(
            returned_code(&result),
            Some(ErrorCode::Protocol),
            "{result:?}"
        );
        assert_nothing_published(&server, &before);
    }

    /// The receiver accepts an image for a commit that the repository holds
    /// with no image. The image adds its bytes to the `ObjectsReply`, and no
    /// object. An image for a commit that the session did not stage and the
    /// repository does not hold is `protocol`.
    #[test]
    fn the_receiver_takes_an_image_for_a_held_commit() {
        let dir = TmpDir::new("cfs-transfer-receive-held");
        let (src, commit) = block_on(source(dir.path(), "src", RepoMode::Archive, true));
        let image = image_bytes(&src, &commit).unwrap();
        let (plain, _) = block_on(source(dir.path(), "plain", RepoMode::Archive, false));
        let server = block_on(new_repo(&dir.path().join("server"), RepoMode::Archive, ""));
        block_on(push(&plain, &server));
        assert_eq!(image_bytes(&server, &commit), None);

        let stray = Obj {
            ty: ObjectType::ComposefsImage,
            checksum: Checksum::from_bytes([7; 32]),
            encoding: Encoding::Raw,
            bytes: image.clone(),
        };
        let (result, _) = send_objects(&server, &[stray], Expected::Commit(commit), commit);
        assert_eq!(
            returned_code(&result),
            Some(ErrorCode::Protocol),
            "{result:?}"
        );

        let all = objects(&src, &commit, Some(image.clone()));
        let only = &all[all.len() - 1..];
        let (result, counts) = send_objects(&server, only, Expected::Commit(commit), commit);
        result.unwrap();
        assert_eq!(counts, Some((0, image.len() as u64)));
        block_on(assert_same_image(&src, &server, &commit));
    }

    /// A session with a server commit refuses an image with `protocol`.
    #[test]
    fn a_server_commit_session_refuses_an_image() {
        let dir = TmpDir::new("cfs-transfer-receive-onto");
        let (src, commit) = block_on(source(dir.path(), "src", RepoMode::Archive, true));
        let image = image_bytes(&src, &commit).unwrap();
        let (plain, _) = block_on(source(dir.path(), "plain", RepoMode::Archive, false));
        let server = block_on(new_repo(&dir.path().join("server"), RepoMode::Archive, ""));
        block_on(push(&plain, &server));
        let (stored, _) = block_on(server.load_commit(&commit)).unwrap();
        let sc = ServerCommit {
            branch: "onto".into(),
            tags: Vec::new(),
            bind_refs: Vec::new(),
            root_dirtree: stored.root_dirtree,
            root_dirmeta: stored.root_dirmeta,
            subject: "onto".into(),
            body: String::new(),
            metadata: Vec::new(),
            timestamp: Some(1),
            orphan: true,
        };

        let policy = policy_allowing(&["c:**"]);
        let (result, ()) = session(&server, &policy, |mut client| async move {
            client.hello_reply(&["onto"]).await;
            let _ = client
                .object(ObjectType::ComposefsImage, commit, Encoding::Raw, &image)
                .await;
            let _ = client.objects_end().await;
            let _ = client.server_commit(sc).await;
            let _ = client.commit_reply().await;
        });
        assert_eq!(
            returned_code(&result),
            Some(ErrorCode::Protocol),
            "{result:?}"
        );
        assert_eq!(image_bytes(&server, &commit), None);
    }
}
