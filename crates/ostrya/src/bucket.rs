//! Bucket repositories: repositories in `archive` form in an S3 bucket.
//!
//! A [`BucketRepo`] holds the [`Bucket`] client of one bucket repository.
//! Each file of the repository is one object of the bucket, under the prefix
//! of the address `s3://BUCKET[/PREFIX]`. A pull reads a bucket repository
//! through [`Repo::pull`](crate::Repo::pull). A `BucketRepo` adds the init,
//! the writer lock, and the listing of the objects. With the `push` feature,
//! `Repo::push_to_bucket` writes commits to a bucket repository.
//!
//! # Init
//!
//! [`BucketRepo::init`] writes the `config` of a new bucket repository under
//! the writer lock, with `If-None-Match: *`. The `config` holds the group
//! `[core]` with `repo_version=1` and `mode=archive-z2`, and
//! `collection-id=ID` when the caller gives an id. A bucket repository with
//! a collection id is the primary server of that collection. When the caller
//! gives a zlib level, the group `[archive]` with `zlib-level=LEVEL` follows.
//! The init refuses a bucket that holds a `config`, so the collection id of a
//! bucket repository never changes. A push needs the `config`.
//!
//! # The push
//!
//! A push writes the objects of its commits, and then the ref files, under
//! the writer lock. It writes no `summary` and no `summary.sig`, and leaves
//! the ones that the bucket holds as they are. A commit object goes up only
//! after each object of its tree, so a commit object in the bucket has its
//! whole tree in the bucket, also after a push that failed. For this reason,
//! a push walks no tree of a commit that the bucket holds. The refs of the
//! collection id of the bucket, or of a push with no collection, are under
//! `refs/heads/`. The refs of each other collection are under
//! `refs/mirrors/ID/`. A push builds each `.filez` that it uploads at the
//! `[archive] zlib-level` of the `config` of the bucket, 6 if the `config`
//! has none, clamped to 1 to 9.
//!
//! With the `push` feature, two writers push:
//!
//! - `Repo::push_to_bucket` writes the commits of a local repository.
//! - `BucketRepo::push_tree` writes a local directory as a new commit, which
//!   it makes on the client as the receive side of a tree push makes it.
//!
//! Each of the two states its steps, its namespaces, and its failure
//! states.
//!
//! # The writer lock
//!
//! S3 has no transaction over more than one object. So each writer of a
//! bucket repository holds the writer lock: one object at the key
//! `extensions/ostrya/lock`. [`BucketRepo::lock`] takes it, and
//! [`WriterLock::release`] removes it. A read takes no lock.
//!
//! - The take writes the lock with `If-None-Match: *`. If the key holds a
//!   lock, the take fails with
//!   [`Error::BucketLocked`](crate::Error::BucketLocked), which names the
//!   holder. On a server that honors the header, a take with no break of
//!   the lock then does not change the bucket.
//! - After the take, a probe writes the same body with `If-None-Match: *`
//!   again. A server that honors the header refuses the probe with 412.
//!   The writer then reads the lock, and the take holds the lock if the
//!   lock holds the id of the writer. A server that writes the probe gives
//!   no exclusion. The writer then removes its lock and fails with
//!   [`Error::BucketNoExclusion`](crate::Error::BucketNoExclusion). On such
//!   a server, the take writes over a lock that the key holds, so the lock
//!   of the other writer is gone after the call. `rclone serve s3` 1.75.1
//!   is such a server, and SeaweedFS 4.36 honors the header.
//! - [`WriterLock::check`] reads the lock and compares its id with the id of
//!   the writer. A writer checks before each change that the lock guards.
//!   A lock with another id, or no lock, gives
//!   [`Error::BucketLockLost`](crate::Error::BucketLockLost).
//! - [`WriterLock::release`] reads the lock, and deletes it with `If-Match`
//!   and the `ETag` of the read if it holds the id of the writer.
//! - With `break_lock`, [`BucketRepo::lock`] first deletes the lock that the
//!   key holds, with `If-Match` and the `ETag` of its read, and then takes
//!   its own. [`WriterLock::broken`] gives the holder of the deleted lock.
//!   If the take after the delete fails, the deleted lock stays deleted.
//!
//! The lock has no lease. A lock that a writer leaves when it ends with no
//! release stays until a break of the lock removes it. A dropped
//! [`WriterLock`] sends no request, so its lock stays too.
//!
//! The lock has two windows:
//!
//! - A writer that breaks the lock and takes its own after a check, and
//!   before the change that the check guards, does not stop that change.
//! - A server that does not honor `If-Match` deletes the lock whatever its
//!   `ETag` is. A writer that breaks the lock and takes its own between the
//!   read and the delete of a release or of a break then loses its lock.
//!   `rclone serve s3` 1.75.1 is such a server, and SeaweedFS 4.36 honors
//!   the header.
//!
//! # The listing
//!
//! [`BucketRepo::list_objects`] lists the objects of the repository with one
//! list of each of the 256 fan-out prefixes `objects/XX/`. At most
//! `max_outstanding` lists run at a time, as [`BucketRepo::new`] states.
//! The [`ObjectListing`] holds each object with its size, and each
//! stray key under a fan-out prefix. A key outside the fan-out prefixes,
//! for example `objects/abc`, is not in it.
//!
//! # Examples
//!
//! ```no_run
//! use ostrya::bucket::{BucketRepo, LockOperation};
//! use ostrya::remote::s3::{Environment, S3Endpoint, Settings};
//! # async fn run() -> ostrya::Result<()> {
//! let endpoint =
//!     S3Endpoint::resolve("s3://builds/exampleos", &Settings::default(), &Environment::Process)
//!         .await?;
//! let repo = BucketRepo::open(&endpoint).await?;
//! let lock = repo.lock(LockOperation::Prune, false).await?;
//! let listing = repo.list_objects().await?;
//! println!("{} objects", listing.objects.len());
//! lock.check().await?;
//! lock.release().await?;
//! # Ok(()) }
//! ```

use crate::error::Result;
use crate::remote::PushOutcome;
use crate::remote::s3::{Address, Bucket, PutIfAbsent, S3Endpoint};

mod listing;
mod lock;
mod state;
// No writer of this version writes the summary of a bucket repository. The
// build and the write of the summary stay for an explicit summary update.
#[allow(dead_code)]
mod summary;

pub use listing::ObjectListing;
pub use lock::{LockHolder, LockOperation, WriterLock};
pub(crate) use lock::{describe_locked, describe_lost};
#[cfg_attr(not(feature = "push"), allow(unused_imports))]
pub(crate) use state::check_prefixes;
#[cfg(test)]
pub(crate) use state::{BucketRefs, summary_refs};

/// The result of a push to a bucket repository: `Repo::push_to_bucket` or
/// `BucketRepo::push_tree`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BucketPushOutcome {
    /// The ref outcomes and the statistics of the push.
    ///
    /// Each ref outcome names the destination of its refspec, or the branch
    /// of a tree push. The namespace of the push decides its key:
    /// `refs/heads/DST` or `refs/mirrors/ID/DST`. The commit is `None` for
    /// `Repo::push_to_bucket`, and the new commit for `BucketRepo::push_tree`.
    pub outcome: PushOutcome,
    /// The holder of the lock that the break of the lock deleted, or `None`
    /// if the push deleted no lock.
    ///
    /// The holder is reported on success alone. A push that breaks the lock
    /// and then fails returns its error, and the holder of the deleted lock
    /// is not in it. [`BucketRepo::lock_holder`] reads the holder before the
    /// push.
    pub broken_lock: Option<LockHolder>,
}

/// The options of a writer of a bucket repository other than its own
/// inputs.
///
/// `BucketRepo::push_tree` takes them. A caller sets the fields of
/// [`default`](Default::default), because the struct is
/// `#[non_exhaustive]`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct BucketWriteOptions {
    /// Remove the writer lock of another writer before the writer takes its
    /// own, as [`BucketRepo::lock`] states.
    pub break_lock: bool,
    /// The part size of a multipart upload, at least 5 MiB, or `None` for
    /// the rule of [`part_size`](crate::remote::s3::part_size). For tests.
    #[doc(hidden)]
    pub part_size: Option<u64>,
}

/// A bucket repository: a repository in `archive` form in an S3 bucket.
///
/// The [module documentation](self) states the writer lock and the listing.
#[derive(Debug)]
pub struct BucketRepo {
    bucket: Bucket,
    /// The bound of the lists in flight.
    max_outstanding: usize,
}

impl BucketRepo {
    /// Opens the bucket repository of `endpoint`.
    ///
    /// The call builds the bucket client, as [`Bucket::new`] does. It sends
    /// no request and reads no object of the bucket. The
    /// [`max_outstanding`](crate::fetch::FetcherOptions::max_outstanding) of
    /// the HTTP options of `endpoint` bounds the lists in flight.
    ///
    /// # Errors
    ///
    /// [`Error::Remote`](crate::Error::Remote) with the error of
    /// [`Bucket::new`].
    pub async fn open(endpoint: &S3Endpoint) -> Result<BucketRepo> {
        Ok(BucketRepo::new(
            Bucket::new(endpoint).await?,
            endpoint.http.max_outstanding,
        ))
    }

    /// Returns the bucket repository of the client `bucket`. The call sends
    /// no request.
    ///
    /// At most `max_outstanding` lists of
    /// [`list_objects`](BucketRepo::list_objects) run at a time. A value of
    /// zero is one. The admission limit of the fetcher of `bucket` is the
    /// value to give.
    pub fn new(bucket: Bucket, max_outstanding: usize) -> BucketRepo {
        BucketRepo {
            bucket,
            max_outstanding,
        }
    }

    /// Returns the bucket client of the repository.
    pub fn bucket(&self) -> &Bucket {
        &self.bucket
    }

    /// Returns the address of the repository, `s3://BUCKET[/PREFIX]`.
    pub fn address(&self) -> &Address {
        self.bucket.location().address()
    }

    /// Takes the writer lock for `operation`.
    ///
    /// The take writes the lock body with `If-None-Match: *`, and a probe
    /// then writes the same body again. The [module
    /// documentation](self#the-writer-lock) states the rules. With
    /// `break_lock`, the call first reads the lock that the key holds and
    /// deletes it with `If-Match` and the `ETag` of the read.
    /// [`WriterLock::broken`] then gives its holder. If the delete gets 412
    /// and a read after it finds no lock, the call goes on to the take, and
    /// [`WriterLock::broken`] gives `None`.
    ///
    /// A take whose request has an unknown outcome reads the key. If the key
    /// holds the body of this take, the lock is taken: the body holds an id
    /// that no other run makes.
    ///
    /// A probe that gets 412 reads the lock. A probe whose request has an
    /// unknown outcome reads the key, and a read that finds other bytes
    /// gives the same result as a 412. The call then returns the lock only
    /// if the lock holds the id of this take. A probe whose request has an
    /// unknown outcome, and whose read finds the body of this take, holds
    /// the lock only if a later request of the probe gets 412: a 412 shows
    /// that the server honors the header.
    ///
    /// # Errors
    ///
    /// - [`Error::BucketLocked`](crate::Error::BucketLocked) if the key
    ///   holds a lock. The holder is `None` if the lock was gone at the read
    ///   after the take. Also if the read after a probe finds the lock of
    ///   another writer, or no lock. The lock of this take is then gone, and
    ///   the call removes no lock. A probe whose read after an interrupted
    ///   request finds other bytes gives this error also on a server that
    ///   does not honor the header. With `break_lock`, also if the lock
    ///   changed between the read and the delete, or if another writer took
    ///   the lock after the delete.
    /// - [`Error::BucketNoExclusion`](crate::Error::BucketNoExclusion) if the
    ///   server writes the probe. The call removes its lock first.
    /// - [`Error::Remote`](crate::Error::Remote) with
    ///   [`Transport`](crate::remote::Error::Transport) if the probe had an
    ///   unknown outcome and the key holds the body of this take, with no
    ///   412 after it. The call removes its lock first, and the message
    ///   states if the lock was removed. Also with `break_lock`, if the read
    ///   of the lock gives no `ETag`. The call then deletes no lock.
    /// - [`Error::Remote`](crate::Error::Remote) for an error of the bucket
    ///   client. After a failed probe, the call removes its lock first.
    pub async fn lock(&self, operation: LockOperation, break_lock: bool) -> Result<WriterLock<'_>> {
        self.take_lock(operation, break_lock).await
    }

    /// Reads the lock that the key holds, with no change to the bucket.
    ///
    /// Returns `None` if the key holds no lock.
    ///
    /// # Errors
    ///
    /// [`Error::Remote`](crate::Error::Remote) for an error of the bucket
    /// client.
    pub async fn lock_holder(&self) -> Result<Option<LockHolder>> {
        self.read_holder().await
    }

    /// Writes the `config` of a new bucket repository.
    ///
    /// The call takes the writer lock for [`LockOperation::Init`], writes
    /// `config` with `If-None-Match: *`, and releases the lock. The `config`
    /// holds the group `[core]` with `repo_version=1` and `mode=archive-z2`,
    /// each on one line, and `collection-id=ID` after them when
    /// `collection_id` is `Some`. The bucket repository is then the primary
    /// server of that collection. When `zlib_level` is `Some`, an empty line
    /// and the group `[archive]` with `zlib-level=LEVEL` follow. Without it,
    /// the `config` has no `[archive]` group, and a writer takes the level 6.
    /// The init writes no summary and no ref.
    ///
    /// With `break_lock`, the call removes the writer lock of another writer
    /// first, as [`lock`](BucketRepo::lock) states. It returns the holder of
    /// the deleted lock, or `None` if it deleted no lock. The holder is
    /// reported on success alone: an init that breaks the lock and then
    /// fails returns its error, and the holder of the deleted lock is not in
    /// it. [`lock_holder`](BucketRepo::lock_holder) reads the holder before
    /// the init.
    ///
    /// A failure before the write of `config` changes nothing but the lock,
    /// and the call releases the lock. A failure after the write leaves the
    /// `config`, and the bucket repository is ready for a push. A crash
    /// leaves the lock, as for each writer.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`](crate::Error::InvalidInput) if
    ///   `collection_id` fails [`is_collection_id`](crate::is_collection_id)
    ///   or is longer than 255 bytes, or if `zlib_level` is outside 1 to 9.
    ///   The call then sends no request.
    /// - [`Error::InvalidInput`](crate::Error::InvalidInput) if the bucket
    ///   holds a `config`. The call leaves it unchanged, so the collection id
    ///   of a bucket repository never changes.
    /// - The errors of [`lock`](BucketRepo::lock) and of
    ///   [`WriterLock::release`].
    /// - [`Error::Remote`](crate::Error::Remote) for an error of the bucket
    ///   client. The call releases the lock first, and drops an error of that
    ///   release.
    pub async fn init(
        &self,
        collection_id: Option<&str>,
        zlib_level: Option<u8>,
        break_lock: bool,
    ) -> Result<Option<LockHolder>> {
        if let Some(id) = collection_id
            && !state::is_namespace_id(id)
        {
            return Err(crate::Error::InvalidInput(format!(
                "the collection id '{}' of a bucket repository fails the collection id rule or \
                 is longer than 255 bytes",
                id.escape_debug()
            )));
        }
        if let Some(level) = zlib_level
            && !(1..=9).contains(&level)
        {
            return Err(crate::Error::InvalidInput(format!(
                "the zlib level {level} of a bucket repository is outside 1 to 9"
            )));
        }
        let lock = self.lock(LockOperation::Init, break_lock).await?;
        let broken = lock.broken().cloned();
        let present = match self
            .bucket
            .put_if_absent("config", config_bytes(collection_id, zlib_level))
            .await
        {
            Ok(PutIfAbsent::Created { .. })
            | Ok(PutIfAbsent::Matches { .. })
            | Ok(PutIfAbsent::Refused { .. }) => false,
            Ok(_) => true,
            Err(e) => {
                let _ = lock.release().await;
                return Err(e.into());
            }
        };
        if present {
            let _ = lock.release().await;
            return Err(crate::Error::InvalidInput(format!(
                "the bucket repository {} holds a config already; its collection id never \
                 changes",
                self.address()
            )));
        }
        lock.release().await?;
        Ok(broken)
    }

    /// Lists the objects of the repository.
    ///
    /// The call sends one list of each fan-out prefix `objects/XX/`. At
    /// most `max_outstanding` lists run at a time, as
    /// [`new`](BucketRepo::new) states. A key outside the fan-out prefixes,
    /// for example `objects/abc` or `objects/zz/x`, is not in the result.
    ///
    /// # Errors
    ///
    /// [`Error::Remote`](crate::Error::Remote) with the error of the first
    /// list that fails, as [`Bucket::list`](crate::remote::s3::Bucket::list)
    /// states. The call then drops the other lists.
    pub async fn list_objects(&self) -> Result<ObjectListing> {
        self.list_fanouts().await
    }

    /// Returns the bound of the requests in flight.
    #[cfg_attr(not(feature = "push"), allow(dead_code))]
    pub(crate) fn max_outstanding(&self) -> usize {
        self.max_outstanding
    }
}

/// Returns the bytes of the `config` of a new bucket repository, with the
/// collection id `collection_id` and the zlib level `zlib_level`.
fn config_bytes(collection_id: Option<&str>, zlib_level: Option<u8>) -> Vec<u8> {
    let mut text = String::from("[core]\nrepo_version=1\nmode=archive-z2\n");
    if let Some(id) = collection_id {
        text.push_str(&format!("collection-id={id}\n"));
    }
    if let Some(level) = zlib_level {
        text.push_str(&format!("\n[archive]\nzlib-level={level}\n"));
    }
    text.into_bytes()
}

/// Returns the error of a request of the caller that the bucket repository
/// refuses.
pub(crate) fn invalid(msg: impl Into<String>) -> crate::Error {
    crate::Error::Remote(crate::remote::Error::InvalidInput(msg.into()))
}

const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<BucketRepo>();
    assert_send_sync::<WriterLock<'_>>();
    assert_send_sync::<LockHolder>();
    assert_send_sync::<LockOperation>();
    assert_send_sync::<ObjectListing>();
    assert_send_sync::<BucketPushOutcome>();
    assert_send_sync::<BucketWriteOptions>();
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_config_of_a_new_bucket_repository_has_three_or_four_lines() {
        assert_eq!(
            config_bytes(None, None),
            b"[core]\nrepo_version=1\nmode=archive-z2\n"
        );
        assert_eq!(
            config_bytes(Some("org.example.Os"), None),
            b"[core]\nrepo_version=1\nmode=archive-z2\ncollection-id=org.example.Os\n"
        );
        let config = crate::config::RepoConfig::parse(
            std::str::from_utf8(&config_bytes(Some("org.example.Os"), None)).unwrap(),
        )
        .unwrap();
        assert_eq!(config.mode(), ostrya_core::RepoMode::Archive);
        assert_eq!(config.collection_id(), Some("org.example.Os"));
        assert_eq!(config.zlib_level().unwrap(), 6);
    }

    #[test]
    fn a_zlib_level_adds_the_archive_group() {
        let bytes = config_bytes(Some("org.example.Os"), Some(9));
        assert_eq!(
            bytes,
            b"[core]\nrepo_version=1\nmode=archive-z2\ncollection-id=org.example.Os\n\n\
              [archive]\nzlib-level=9\n"
        );
        let config =
            crate::config::RepoConfig::parse(std::str::from_utf8(&bytes).unwrap()).unwrap();
        assert_eq!(config.zlib_level().unwrap(), 9);
        assert_eq!(config.collection_id(), Some("org.example.Os"));
        assert_eq!(
            config_bytes(None, Some(1)),
            b"[core]\nrepo_version=1\nmode=archive-z2\n\n[archive]\nzlib-level=1\n"
        );
    }
}
