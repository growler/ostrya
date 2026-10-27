//! The reachability walk over a bucket repository.

use std::collections::HashSet;

use ostrya_core::{Checksum, ObjectName, ObjectType};

use super::{BucketRepo, object_key};
use crate::error::{Error, Result};
use crate::object::MAX_METADATA_SIZE;
use crate::traverse::{MetadataSource, walk_reachable};

/// Reads each object with
/// [`Bucket::get_strict`](crate::remote::s3::Bucket::get_strict). So only a
/// 404 with the code `NoSuchKey` gives `None`, and each other 404 is an
/// error. At most `max_outstanding` reads of dirtrees run at a time.
impl MetadataSource for BucketRepo {
    async fn load_metadata(&self, ty: ObjectType, checksum: Checksum) -> Result<Option<Vec<u8>>> {
        let key = object_key(&ObjectName::new(checksum, ty));
        match self.bucket.get_strict(&key, MAX_METADATA_SIZE).await {
            Ok(object) => Ok(object.map(|object| object.bytes)),
            Err(e) => Err(read_error(e, &key, |what| self.malformed(what))),
        }
    }

    fn max_reads(&self) -> usize {
        self.max_outstanding
    }
}

/// Returns the error of the failed read `e` of the metadata object `key`.
///
/// An object over [`MAX_METADATA_SIZE`] gives the error that `malformed`
/// makes from the reason. Each other error is [`Error::Remote`].
fn read_error(
    e: crate::remote::Error,
    key: &str,
    malformed: impl FnOnce(String) -> Error,
) -> Error {
    match e {
        crate::remote::Error::LimitExceeded(_) => malformed(format!(
            "the object {key} is larger than {MAX_METADATA_SIZE} bytes"
        )),
        e => e.into(),
    }
}

impl BucketRepo {
    /// Returns the name of each object that one of `roots` and its parents
    /// reach in the bucket repository.
    ///
    /// The walk is the walk of
    /// [`Repo::traverse_reachable`](crate::Repo::traverse_reachable) over the
    /// objects of the bucket, with the same depths. It reads the commits and
    /// the dirtrees that it reaches, and does not verify the checksum of the
    /// bytes. Each read is one `GET`. The walk reads the commits one at a
    /// time. It reads the dirtrees of the tree of one commit at most
    /// `max_outstanding` at a time, as [`new`](BucketRepo::new) gives it,
    /// before it reads the next commit. The walk reads each commit and each
    /// dirtree once. The call takes no writer lock.
    ///
    /// Each read holds the bytes of its object in memory, so the reads in
    /// flight hold at most `max_outstanding` objects, each at most
    /// [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE).
    ///
    /// An object is absent only if its `GET` gets a 404 with the code
    /// `NoSuchKey`. Each other 404 is an error. For a missing key, S3 gives
    /// 403 `AccessDenied` to credentials that cannot list the bucket. So with
    /// such credentials, an absent object stops the walk with an error, and
    /// the local walk adds its name.
    ///
    /// The function is not a stable API.
    ///
    /// # Errors
    ///
    /// - [`Error::Core`](crate::Error::Core) if a commit or a dirtree that
    ///   the walk reads does not parse.
    /// - [`Error::InvalidFormat`](crate::Error::InvalidFormat) if a commit or
    ///   a dirtree is larger than [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE).
    /// - [`Error::Remote`](crate::Error::Remote) for an error of the bucket
    ///   client, also for a 404 without the code `NoSuchKey` and for a 403.
    ///
    /// If more than one read fails, the error is the error of the first
    /// read that fails in time. The walk then drops the other reads in
    /// flight.
    #[doc(hidden)]
    pub async fn traverse_reachable(
        &self,
        roots: impl IntoIterator<Item = Checksum>,
        max_depth: i32,
    ) -> Result<HashSet<ObjectName>> {
        walk_reachable(self, roots, max_depth).await
    }
}

/// A compile-time check that the future of a walk over a bucket repository
/// is `Send`.
const _: fn() = || {
    fn assert_send<T: Send>(_: &T) {}
    let _ = |repo: &BucketRepo| assert_send(&repo.traverse_reachable(Vec::new(), -1));
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_object_over_the_limit_is_malformed_and_other_errors_stay_remote() {
        let key = "objects/ab/cdef.dirtree";
        let err = read_error(
            crate::remote::Error::LimitExceeded("too large".into()),
            key,
            Error::InvalidFormat,
        );
        assert!(
            matches!(&err, Error::InvalidFormat(m) if m.contains(key)
                && m.contains(&MAX_METADATA_SIZE.to_string())),
            "{err}"
        );
        let err = read_error(
            crate::remote::Error::InvalidInput("bad key".into()),
            key,
            Error::InvalidFormat,
        );
        assert!(
            matches!(&err, Error::Remote(crate::remote::Error::InvalidInput(m)) if m == "bad key"),
            "{err}"
        );
    }
}
