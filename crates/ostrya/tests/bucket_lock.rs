#![forbid(unsafe_code)]

//! Tests of the writer lock and of the object listing of a bucket
//! repository.
//!
//! Most tests run against the S3 stand-in of `common::s3`, which holds its
//! objects in memory. Other tests run against `weed mini` of SeaweedFS and
//! against `rclone serve s3`. A test on a real server skips when its program
//! is absent. `OSTRYA_REQUIRE_SEAWEEDFS` and `OSTRYA_REQUIRE_S3` turn each
//! skip into a failure.

#![cfg(feature = "s3")]

mod common;

use common::TmpDir;
use common::s3::{Rclone, Seaweed, StandIn, endpoint, rclone_available, seaweed_available};
use ostrya::bucket::{BucketRepo, LockHolder, LockOperation};
use ostrya::remote::s3::DeleteIfMatch;
use ostrya::{Checksum, Error, ObjectName, ObjectType};
use ostrya_rt::block_on;

/// The address of the repository in each test.
const ADDRESS: &str = "s3://bkt/repo";

/// The key of the lock in the bucket.
const LOCK: &str = "repo/extensions/ostrya/lock";

/// The id of the lock of a writer that a test writes into the bucket.
fn dead_id() -> String {
    "9".repeat(64)
}

/// The lock body of a writer that ended with no release.
fn dead_body() -> String {
    format!(
        "[lock]\nid={}\nhost=deadhost\npid=99\noperation=push\nstarted=1700000000\n",
        dead_id()
    )
}

/// Opens the repository at [`ADDRESS`] on the server at `url`.
async fn open(url: &str) -> BucketRepo {
    BucketRepo::open(&endpoint(url, ADDRESS)).await.unwrap()
}

/// Returns the holder that `err` names, if it is [`Error::BucketLocked`].
fn locked_by(err: &Error) -> Option<Option<&LockHolder>> {
    match err {
        Error::BucketLocked { holder, .. } => Some(holder.as_deref()),
        _ => None,
    }
}

/// Returns the holder that `err` names, if it is [`Error::BucketLockLost`].
fn lost_to(err: &Error) -> Option<Option<&LockHolder>> {
    match err {
        Error::BucketLockLost { holder, .. } => Some(holder.as_deref()),
        _ => None,
    }
}

/// Returns the method of each request that `server` got, in order.
fn methods(server: &StandIn) -> Vec<String> {
    server
        .state()
        .requests
        .iter()
        .map(|(method, _)| method.clone())
        .collect()
}

/// Returns a change that puts the lock of [`dead_body`] in place of the lock
/// that the key holds.
fn replace_lock() -> common::s3::Change {
    Box::new(|objects| {
        let stored = objects.get_mut(LOCK).unwrap();
        stored.bytes = dead_body().into_bytes();
        stored.etag = "\"replaced\"".into();
    })
}

#[test]
fn a_second_writer_fails_and_names_the_holder() {
    block_on(async {
        let server = StandIn::start();
        let repo = open(&server.endpoint()).await;
        let first = repo.lock(LockOperation::Push, false).await.unwrap();
        assert!(first.broken().is_none());
        let err = repo.lock(LockOperation::Prune, false).await.unwrap_err();
        let holder = locked_by(&err).flatten().expect("a lock with a holder");
        assert_eq!(holder.id.as_deref(), Some(first.id()));
        assert_eq!(holder.operation.as_deref(), Some("push"));
        assert_eq!(holder.pid, Some(std::process::id()));
        assert!(
            holder.host.is_some() && holder.started.is_some(),
            "{holder:?}"
        );
        let text = err.to_string();
        assert!(
            text.contains(ADDRESS) && text.contains(first.id()) && text.contains("push"),
            "{text}"
        );
        // The second take changed nothing.
        assert_eq!(
            repo.lock_holder().await.unwrap().and_then(|h| h.id),
            Some(first.id().to_owned())
        );
        first.check().await.unwrap();
        first.release().await.unwrap();
        assert!(!server.state().objects.contains_key(LOCK));
        assert_eq!(repo.lock_holder().await.unwrap(), None);
    });
}

#[test]
fn a_break_removes_the_lock_of_a_killed_writer() {
    block_on(async {
        let server = StandIn::start();
        server.state().store(LOCK, dead_body().as_bytes());
        let repo = open(&server.endpoint()).await;
        let err = repo.lock(LockOperation::Push, false).await.unwrap_err();
        let holder = locked_by(&err)
            .flatten()
            .expect("the lock of the killed writer");
        assert_eq!(holder.id, Some(dead_id()));
        assert_eq!(holder.host.as_deref(), Some("deadhost"));
        assert_eq!(holder.pid, Some(99));
        assert_eq!(holder.started, Some(1_700_000_000));

        let lock = repo.lock(LockOperation::Push, true).await.unwrap();
        assert_eq!(lock.broken().and_then(|h| h.id.clone()), Some(dead_id()));
        assert_eq!(
            repo.lock_holder().await.unwrap().and_then(|h| h.id),
            Some(lock.id().to_owned())
        );
        lock.release().await.unwrap();
    });
}

#[test]
fn a_lock_that_names_no_writer_is_held_and_a_break_removes_it() {
    block_on(async {
        let server = StandIn::start();
        server.state().store(LOCK, b"\xffnot a lock body");
        let repo = open(&server.endpoint()).await;
        let err = repo.lock(LockOperation::Fsck, false).await.unwrap_err();
        assert_eq!(locked_by(&err), Some(Some(&LockHolder::default())), "{err}");
        let lock = repo.lock(LockOperation::Fsck, true).await.unwrap();
        assert_eq!(lock.broken(), Some(&LockHolder::default()));
        lock.release().await.unwrap();
    });
}

#[test]
fn a_writer_whose_lock_is_broken_stops_at_its_check() {
    block_on(async {
        let server = StandIn::start();
        let repo = open(&server.endpoint()).await;
        let first = repo.lock(LockOperation::Prune, false).await.unwrap();
        let second = repo.lock(LockOperation::Push, true).await.unwrap();
        assert_eq!(
            second.broken().and_then(|h| h.id.as_deref()),
            Some(first.id())
        );
        let err = first.check().await.unwrap_err();
        let holder = lost_to(&err)
            .flatten()
            .expect("the lock of the second writer");
        assert_eq!(holder.id.as_deref(), Some(second.id()));
        let err = first.release().await.unwrap_err();
        assert!(lost_to(&err).is_some(), "{err}");
        // The release of the first writer leaves the lock of the second one.
        second.check().await.unwrap();
        second.release().await.unwrap();
        assert_eq!(repo.lock_holder().await.unwrap(), None);
    });
}

#[test]
fn a_check_and_a_release_with_no_lock_fail() {
    block_on(async {
        let server = StandIn::start();
        let repo = open(&server.endpoint()).await;
        let lock = repo.lock(LockOperation::Summary, false).await.unwrap();
        server.state().objects.remove(LOCK);
        let err = lock.check().await.unwrap_err();
        assert_eq!(lost_to(&err), Some(None), "{err}");
        let err = lock.release().await.unwrap_err();
        assert_eq!(lost_to(&err), Some(None), "{err}");
    });
}

#[test]
fn a_server_that_ignores_if_none_match_fails_the_probe() {
    block_on(async {
        let server = StandIn::start();
        server.state().honor_if_none_match = false;
        server.state().honor_if_match = false;
        let repo = open(&server.endpoint()).await;
        let err = repo.lock(LockOperation::Push, false).await.unwrap_err();
        assert!(matches!(err, Error::BucketNoExclusion { .. }), "{err}");
        assert!(err.to_string().contains(ADDRESS), "{err}");
        assert!(server.state().objects.is_empty());
        let methods: Vec<String> = server
            .state()
            .requests
            .iter()
            .map(|(method, _)| method.clone())
            .collect();
        assert_eq!(methods, ["PUT", "PUT", "GET", "DELETE"]);
    });
}

#[test]
fn an_interrupted_take_that_wrote_the_lock_holds_it() {
    block_on(async {
        let server = StandIn::start();
        server.state().close_after = Some(("PUT", 1));
        let repo = open(&server.endpoint()).await;
        let lock = repo.lock(LockOperation::Push, false).await.unwrap();
        lock.check().await.unwrap();
        // The read after the interrupted take, the probe, which gets 412,
        // the read after the probe, and the check.
        assert_eq!(methods(&server), ["PUT", "GET", "PUT", "GET", "GET"]);
        lock.release().await.unwrap();
    });
}

#[test]
fn an_interrupted_probe_removes_the_lock_and_fails() {
    block_on(async {
        let server = StandIn::start();
        server.state().close_after = Some(("PUT", 2));
        let repo = open(&server.endpoint()).await;
        let err = repo.lock(LockOperation::Push, false).await.unwrap_err();
        assert!(
            matches!(&err, Error::Remote(ostrya::remote::Error::Transport(text))
                if text.contains("probe") && text.contains("removed the lock of this run")),
            "{err}"
        );
        assert!(server.state().objects.is_empty());
    });
}

#[test]
fn a_probe_refused_after_a_slow_down_holds_the_lock() {
    block_on(async {
        let server = StandIn::start();
        server.state().slow_down = Some(("PUT", 2));
        let repo = open(&server.endpoint()).await;
        let lock = repo.lock(LockOperation::Push, false).await.unwrap();
        // The take, the probe, which gets 503, the probe again, which gets
        // 412, and the compare of the key, which finds the body of the take.
        assert_eq!(methods(&server), ["PUT", "PUT", "PUT", "GET"]);
        lock.check().await.unwrap();
        lock.release().await.unwrap();
        assert!(server.state().objects.is_empty());
    });
}

#[test]
fn a_probe_that_finds_another_lock_fails_and_names_the_holder() {
    block_on(async {
        let server = StandIn::start();
        // The probe gets no answer, and another writer breaks the lock and
        // takes its own before the read of the probe.
        server.state().close_after = Some(("PUT", 2));
        server.state().before = Some(("GET", replace_lock()));
        let repo = open(&server.endpoint()).await;
        let err = repo.lock(LockOperation::Push, false).await.unwrap_err();
        let holder = locked_by(&err).flatten().expect("the other lock");
        assert_eq!(holder.id, Some(dead_id()));
        assert_eq!(methods(&server), ["PUT", "PUT", "GET", "GET"]);
        // The call removes no lock of another writer.
        assert_eq!(server.state().objects[LOCK].bytes, dead_body().as_bytes());
    });
}

#[test]
fn a_probe_that_finds_another_lock_fails_on_a_server_that_ignores_the_headers() {
    block_on(async {
        let server = StandIn::start();
        server.state().honor_if_none_match = false;
        server.state().honor_if_match = false;
        // The server writes the probe and gives no answer. Another writer
        // writes its lock over it before the read of the probe.
        server.state().close_after = Some(("PUT", 2));
        server.state().before = Some(("GET", replace_lock()));
        let repo = open(&server.endpoint()).await;
        let err = repo.lock(LockOperation::Push, false).await.unwrap_err();
        let holder = locked_by(&err).flatten().expect("the other lock");
        assert_eq!(holder.id, Some(dead_id()));
        assert_eq!(methods(&server), ["PUT", "PUT", "GET", "GET"]);
        assert_eq!(server.state().objects[LOCK].bytes, dead_body().as_bytes());
    });
}

#[test]
fn a_lock_that_changes_before_the_delete_of_a_release_stays() {
    block_on(async {
        let server = StandIn::start();
        let repo = open(&server.endpoint()).await;
        let lock = repo.lock(LockOperation::Prune, false).await.unwrap();
        // Another writer breaks the lock and takes its own between the read
        // and the delete of the release.
        server.state().before = Some((
            "DELETE",
            Box::new(|objects| {
                objects.get_mut(LOCK).unwrap().bytes = dead_body().into_bytes();
                objects.get_mut(LOCK).unwrap().etag = "\"replaced\"".into();
            }),
        ));
        let err = lock.release().await.unwrap_err();
        let holder = lost_to(&err).flatten().expect("the new lock");
        assert_eq!(holder.id, Some(dead_id()));
        assert_eq!(server.state().objects[LOCK].bytes, dead_body().as_bytes());
    });
}

#[test]
fn a_lock_that_changes_before_the_delete_of_a_break_stays() {
    block_on(async {
        let server = StandIn::start();
        server.state().store(LOCK, b"[lock]\nid=old\n");
        server.state().before = Some((
            "DELETE",
            Box::new(|objects| {
                objects.get_mut(LOCK).unwrap().bytes = dead_body().into_bytes();
                objects.get_mut(LOCK).unwrap().etag = "\"replaced\"".into();
            }),
        ));
        let repo = open(&server.endpoint()).await;
        let err = repo.lock(LockOperation::Push, true).await.unwrap_err();
        let holder = locked_by(&err).flatten().expect("the new lock");
        assert_eq!(holder.id, Some(dead_id()));
        assert_eq!(server.state().objects[LOCK].bytes, dead_body().as_bytes());
    });
}

#[test]
fn a_break_of_a_lock_that_its_holder_removed_takes_the_lock() {
    block_on(async {
        let server = StandIn::start();
        server.state().store(LOCK, dead_body().as_bytes());
        // The holder releases its lock between the read and the delete of
        // the break.
        server.state().before = Some((
            "DELETE",
            Box::new(|objects| {
                objects.remove(LOCK);
            }),
        ));
        let repo = open(&server.endpoint()).await;
        let lock = repo.lock(LockOperation::Push, true).await.unwrap();
        assert_eq!(lock.broken(), None);
        assert_eq!(
            methods(&server),
            ["GET", "DELETE", "GET", "PUT", "PUT", "GET"]
        );
        lock.release().await.unwrap();
        assert!(server.state().objects.is_empty());
    });
}

#[test]
fn a_break_of_a_lock_whose_read_gives_no_etag_deletes_nothing() {
    block_on(async {
        let server = StandIn::start();
        server.state().store(LOCK, dead_body().as_bytes());
        server.state().etag_on_get = false;
        let repo = open(&server.endpoint()).await;
        let err = repo.lock(LockOperation::Push, true).await.unwrap_err();
        assert!(
            matches!(&err, Error::Remote(ostrya::remote::Error::Transport(text))
                if text.contains("ETag") && text.contains(ADDRESS)),
            "{err}"
        );
        assert_eq!(methods(&server), ["GET"]);
        assert_eq!(server.state().objects[LOCK].bytes, dead_body().as_bytes());
    });
}

#[test]
fn a_large_lock_is_read_once_unless_a_break_needs_its_etag() {
    block_on(async {
        let server = StandIn::start();
        server.state().store(LOCK, &vec![b'a'; 70 * 1024]);
        let repo = open(&server.endpoint()).await;
        assert_eq!(
            repo.lock_holder().await.unwrap(),
            Some(LockHolder::default())
        );
        assert_eq!(methods(&server), ["GET"]);
        let err = repo.lock(LockOperation::Fsck, false).await.unwrap_err();
        assert_eq!(locked_by(&err), Some(Some(&LockHolder::default())), "{err}");
        assert_eq!(methods(&server), ["GET", "PUT", "GET"]);
        // The break reads the `ETag` of the lock with a second `GET`.
        let lock = repo.lock(LockOperation::Fsck, true).await.unwrap();
        assert_eq!(lock.broken(), Some(&LockHolder::default()));
        assert_eq!(
            methods(&server)[3..],
            ["GET", "GET", "DELETE", "PUT", "PUT", "GET"]
        );
        lock.release().await.unwrap();
    });
}

/// The key of an object in the repository, with the checksum that `byte`
/// fills and the fan-out `fanout`.
fn object_key(fanout: &str, fill: &str, ext: &str) -> String {
    format!(
        "repo/objects/{fanout}/{}.{ext}",
        fill.repeat(62 / fill.len())
    )
}

/// Returns the object name of the key that [`object_key`] gives.
fn object_name(fanout: &str, fill: &str, ty: ObjectType) -> ObjectName {
    let hex = format!("{fanout}{}", fill.repeat(62 / fill.len()));
    ObjectName::new(Checksum::from_hex(&hex).unwrap(), ty)
}

#[test]
fn the_listing_keeps_each_object_and_each_stray() {
    block_on(async {
        let server = StandIn::start();
        {
            let mut state = server.state();
            state.store(&object_key("00", "1", "commit"), b"c");
            state.store(&object_key("7f", "2", "dirtree"), b"dt");
            state.store(&object_key("ff", "3", "filez"), b"fz!");
            state.store(&object_key("ab", "4", "file"), b"bare");
            state.store("repo/objects/ab/zz", b"stray");
            state.store("repo/objects/abc", b"outside");
            state.store("repo/config", b"[core]\n");
            state.store("repo2/objects/00/x", b"sibling");
            // More than one page of keys under one fan-out prefix.
            for n in 0..1100u32 {
                let hex = format!("{n:062x}");
                state.store(&format!("repo/objects/cd/{hex}.dirmeta"), b"dm");
            }
        }
        let repo = open(&server.endpoint()).await;
        let listing = repo.list_objects().await.unwrap();
        assert_eq!(listing.objects.len(), 1103);
        assert_eq!(
            listing.objects[&object_name("00", "1", ObjectType::Commit)],
            1
        );
        assert_eq!(
            listing.objects[&object_name("7f", "2", ObjectType::DirTree)],
            2
        );
        assert_eq!(
            listing.objects[&object_name("ff", "3", ObjectType::File)],
            3
        );
        let strays: Vec<(&str, u64)> = listing
            .strays
            .iter()
            .map(|listed| (listed.key.as_str(), listed.size))
            .collect();
        let bare = object_key("ab", "4", "file");
        assert_eq!(strays, [(&bare["repo/".len()..], 4), ("objects/ab/zz", 5)]);
        let lists = server
            .state()
            .requests
            .iter()
            .filter(|(method, target)| method == "GET" && target.contains("list-type=2"))
            .count();
        assert_eq!(lists, 257, "one list of each fan-out and a second page");
    });
}

#[test]
fn the_writer_lock_holds_on_seaweedfs() {
    if !seaweed_available("the_writer_lock_holds_on_seaweedfs") {
        return;
    }
    let scratch = TmpDir::new("bucket-lock-seaweed");
    let server = Seaweed::start(scratch.path(), "bkt");
    block_on(async {
        let repo = open(&server.endpoint()).await;
        let first = repo.lock(LockOperation::Push, false).await.unwrap();
        let err = repo.lock(LockOperation::Prune, false).await.unwrap_err();
        let holder = locked_by(&err)
            .flatten()
            .expect("the lock of the first writer");
        assert_eq!(holder.id.as_deref(), Some(first.id()));
        first.check().await.unwrap();

        // A delete with another `ETag` leaves the lock.
        let deleted = repo
            .bucket()
            .delete_if_match(
                "extensions/ostrya/lock",
                "\"0123456789abcdef0123456789abcdef\"",
            )
            .await
            .unwrap();
        assert_eq!(deleted, DeleteIfMatch::NotMatched);
        first.check().await.unwrap();

        let second = repo.lock(LockOperation::Push, true).await.unwrap();
        assert_eq!(
            second.broken().and_then(|h| h.id.as_deref()),
            Some(first.id())
        );
        let err = first.check().await.unwrap_err();
        assert!(lost_to(&err).flatten().is_some(), "{err}");
        let err = first.release().await.unwrap_err();
        assert!(lost_to(&err).is_some(), "{err}");
        second.check().await.unwrap();
        second.release().await.unwrap();
        assert_eq!(repo.lock_holder().await.unwrap(), None);
    });
}

#[test]
fn the_listing_reads_the_objects_on_seaweedfs() {
    if !seaweed_available("the_listing_reads_the_objects_on_seaweedfs") {
        return;
    }
    let scratch = TmpDir::new("bucket-list-seaweed");
    let server = Seaweed::start(scratch.path(), "bkt");
    block_on(async {
        let repo = open(&server.endpoint()).await;
        let commit = object_key("00", "1", "commit");
        let bucket = repo.bucket();
        bucket
            .put(&commit["repo/".len()..], b"c".to_vec())
            .await
            .unwrap();
        bucket
            .put(
                &object_key("ff", "3", "filez")["repo/".len()..],
                b"fz!".to_vec(),
            )
            .await
            .unwrap();
        let listing = repo.list_objects().await.unwrap();
        assert_eq!(listing.objects.len(), 2);
        assert_eq!(
            listing.objects[&object_name("ff", "3", ObjectType::File)],
            3
        );
        assert!(listing.strays.is_empty());
    });
}

#[test]
fn rclone_gives_no_exclusion_and_no_writer_runs() {
    if !rclone_available("rclone_gives_no_exclusion_and_no_writer_runs") {
        return;
    }
    let scratch = TmpDir::new("bucket-lock-rclone");
    let root = scratch.path().join("root");
    let repo_dir = root.join("bkt").join("repo");
    std::fs::create_dir_all(&repo_dir).unwrap();
    std::fs::write(
        repo_dir.join("config"),
        "[core]\nrepo_version=1\nmode=archive-z2\n",
    )
    .unwrap();
    let server = Rclone::start(scratch.path(), &root);
    block_on(async {
        let repo = open(&server.endpoint()).await;
        let err = repo.lock(LockOperation::Push, false).await.unwrap_err();
        assert!(matches!(err, Error::BucketNoExclusion { .. }), "{err}");
    });
    assert!(!repo_dir.join("extensions/ostrya/lock").exists());
}

#[test]
fn rclone_lists_the_objects_of_a_served_directory() {
    if !rclone_available("rclone_lists_the_objects_of_a_served_directory") {
        return;
    }
    let scratch = TmpDir::new("bucket-list-rclone");
    let root = scratch.path().join("root");
    let write = |key: &str, bytes: &[u8]| {
        let path = root.join("bkt").join(key);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    };
    write(&object_key("00", "1", "commit"), b"c");
    write(&object_key("7f", "2", "dirtree"), b"dt");
    write("repo/objects/ab/zz", b"stray");
    write("repo/objects/abc", b"outside");
    // Each file is in place before the server starts, which keeps each
    // listing for one hour.
    let server = Rclone::start(scratch.path(), &root);
    block_on(async {
        let repo = open(&server.endpoint()).await;
        let listing = repo.list_objects().await.unwrap();
        assert_eq!(listing.objects.len(), 2);
        assert_eq!(
            listing.objects[&object_name("7f", "2", ObjectType::DirTree)],
            2
        );
        let strays: Vec<(&str, u64)> = listing
            .strays
            .iter()
            .map(|listed| (listed.key.as_str(), listed.size))
            .collect();
        assert_eq!(strays, [("objects/ab/zz", 5)]);
    });
}
