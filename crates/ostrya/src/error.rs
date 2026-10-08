//! The error type of this crate.
//!
//! [`Error`](enum@Error) is the error of each fallible operation of the
//! crate. [`Result`] is the result type with that error.

use ostrya_core::{Checksum, ObjectType};
use thiserror::Error;

/// The result type of this crate, with [`Error`](enum@Error) as the error.
pub type Result<T> = std::result::Result<T, Error>;

/// The error of each fallible operation of this crate.
///
/// The enum is `#[non_exhaustive]`, so a release can add a variant without a
/// breaking change. The signing engines and the fetcher have their own error
/// types, [`ostrya_sign::Error`] and [`fetch::Error`](crate::fetch::Error).
/// Each of the two converts into this type.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// An I/O error.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// An error from the format primitives: checksums, key files, and objects.
    #[error(transparent)]
    Core(#[from] ostrya_core::Error),
    /// An object that is not in the object store.
    #[error("object not found: {ty:?} {checksum}")]
    ObjectNotFound {
        /// The checksum of the object that the lookup asked for.
        checksum: Checksum,
        /// The type of the object that the lookup asked for.
        ty: ObjectType,
    },
    /// A refspec that does not resolve to a commit.
    #[error("ref not found: {0}")]
    RefNotFound(String),
    /// A remote with no `[remote "<name>"]` group in the configuration.
    ///
    /// The payload is the name of the remote.
    #[error("remote not found: {0}")]
    RemoteNotFound(String),
    /// A remote that already has a `[remote "<name>"]` group in the
    /// configuration.
    ///
    /// The payload is the name of the remote.
    #[error("remote already exists: {0}")]
    RemoteExists(String),
    /// A refspec that does not name a path in the `refs/` tree.
    ///
    /// The causes are:
    ///
    /// - an empty name
    /// - an empty, `.`, or `..` component
    /// - a remote element or a collection element that holds a `/`
    /// - an interior NUL
    ///
    /// The payload is the refspec as the caller gave it. If the refspec has a
    /// remote or a collection, the payload has the form `<remote>:<name>` or
    /// `<collection-id>:<name>`.
    #[error("invalid refspec: {0}")]
    InvalidRefspec(String),
    /// An abbreviated checksum that is the prefix of two or more commit
    /// objects.
    ///
    /// Such a checksum names no single commit. The payload is the revision as
    /// the caller gave it.
    #[error("refspec not unique: {0}")]
    AmbiguousRefspec(String),
    /// A `^` suffix of a revision that asks for the parent of a root commit.
    ///
    /// The payload is the checksum of the root commit.
    #[error("commit {0} has no parent")]
    NoParentCommit(Checksum),
    /// Data that does not match its expected format.
    #[error("invalid format: {0}")]
    InvalidFormat(String),
    /// An operation or a repository feature that this crate does not support.
    ///
    /// A [`fetch::Error::Unsupported`](crate::fetch::Error::Unsupported)
    /// converts to this variant.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// An argument outside the values that the operation accepts.
    ///
    /// An example is a pull depth less than `-1`.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// A wait for the repository lock or the update lock that passed its
    /// limit.
    ///
    /// The limit of the wait is the value of `[core] lock-timeout-secs`. With
    /// the value `-1`, a wait has no limit and does not give this error. The
    /// message names the repository lock for both locks.
    /// [`LockKind`](crate::LockKind) states the rules of the repository lock,
    /// and [`UpdateGuard`](crate::UpdateGuard) states the rules of the update
    /// lock.
    #[error("timed out acquiring repository lock after {secs}s")]
    LockTimeout {
        /// The limit of the wait, in seconds.
        secs: i64,
    },
    /// Data whose computed checksum is not the expected checksum.
    ///
    /// The expected checksum is the checksum that the caller of a write gives
    /// for the object. In a pull, it is also the advertised checksum of a
    /// static-delta superblock.
    #[error("checksum mismatch: expected {expected}, computed {actual}")]
    ChecksumMismatch {
        /// The checksum that the caller or the advertisement gave.
        expected: Checksum,
        /// The checksum that this crate computed.
        actual: Checksum,
    },
    /// A staged object that makes the free space less than the reserve.
    ///
    /// The keys `min-free-space-percent` and `min-free-space-size` of
    /// `[core]` set the reserve.
    #[error("insufficient free space: short by {shortfall} bytes")]
    InsufficientFreeSpace {
        /// The number of bytes of free space that the write needed in
        /// addition.
        shortfall: u64,
    },
    /// A failure to build or serialize an in-memory tree.
    ///
    /// The causes are:
    ///
    /// - an invalid entry name
    /// - a file name and a directory name that are the same
    /// - a directory with no dirmeta checksum
    /// - the removal of an absent entry
    /// - a committed subdirectory that is not loaded, with no repository to
    ///   read it from
    #[error("mutable tree: {0}")]
    MutableTree(String),
    /// An overlayfs feature in an upper directory that the merge cannot carry.
    ///
    /// An entry with `overlay.metacopy` or `overlay.redirect` is not
    /// self-contained. The merge needs an overlay that has the feature off:
    /// `metacopy=off` and `redirect_dir=off`.
    #[error("unsupported overlay feature: {0}")]
    UnsupportedOverlayFeature(String),
    /// A path with a component that is not present.
    #[error("path not found: {path}")]
    PathNotFound {
        /// The path of the absent component.
        ///
        /// If a caller has one name and no path, the field holds the bare
        /// entry name. [`MutableTree::subtree`](crate::MutableTree::subtree)
        /// is such a caller.
        path: String,
    },
    /// A path component that must be a directory and is a file.
    ///
    /// A symlink that resolves to a file also gives this error.
    #[error("not a directory: {path}")]
    NotADirectory {
        /// The path of the component that is not a directory.
        ///
        /// If a caller has one name and no path, the field holds the bare
        /// entry name. [`MutableTree::subtree`](crate::MutableTree::subtree)
        /// is such a caller.
        path: String,
    },
    /// A symlink whose target does not resolve.
    #[error("dangling symlink: {path} -> {target}")]
    DanglingSymlink {
        /// The path of the symlink.
        path: String,
        /// The target that the symlink names.
        target: String,
    },
    /// A path resolution that followed more symlinks than the depth cap.
    ///
    /// The cap is 40 symlinks.
    #[error("symlink chain too deep (possible loop): {path}")]
    SymlinkLoop {
        /// The path of the symlink where the resolution stopped.
        path: String,
    },
    /// An entry at a path where an operation must create a new entry.
    #[error("entry already exists: {path}")]
    EntryExists {
        /// The path of the entry.
        path: String,
    },
    /// A failure of a staging-tree operation that no other variant names.
    ///
    /// The causes are:
    ///
    /// - an outstanding file writer that blocks the operation, for example
    ///   [`StagingTree::close`](crate::StagingTree::close)
    /// - a read of a file at a path that holds a directory
    /// - a hardlink whose source resolves to a directory
    /// - a directory that a concurrent operation removed while the operation
    ///   held its path
    /// - a path with no final component, or a path that ends in `..`
    /// - a path component or a symlink target that is not valid UTF-8
    /// - a rename whose destination is under the moved entry
    /// - a load of a committed directory with no repository handle to read it
    #[error("staging tree: {0}")]
    Staging(String),
    /// A conflict of a staging-tree merge that the merge options do not permit.
    ///
    /// The conflicts are differing files, a file and a directory at one path,
    /// and differing directory metadata. Each one is a conflict only if
    /// [`allow_overwrite`](crate::MergeOptions::allow_overwrite) of the
    /// [`MergeOptions`](crate::MergeOptions) is off.
    #[error("merge conflict: {0}")]
    MergeConflict(String),
    /// A checkout that cannot proceed.
    ///
    /// The causes are:
    ///
    /// - a collision under [`OverwriteMode::None`](crate::OverwriteMode::None)
    /// - a mismatch under
    ///   [`UnionIdentical`](crate::OverwriteMode::UnionIdentical)
    /// - a combination of options that a checkout does not accept
    /// - a partial commit
    /// - a whiteout that names no entry
    /// - a destination name that is not valid UTF-8
    /// - a failure to set an extended attribute
    #[error("checkout: {0}")]
    Checkout(String),
    /// A checkout [`subpath`](crate::CheckoutOptions::subpath) that names no
    /// entry in the commit tree.
    ///
    /// The payload is the value as the caller wrote it.
    #[error("checkout: subpath not found: {}", .0.display())]
    SubpathNotFound(std::path::PathBuf),
    /// A checkout [`subpath`](crate::CheckoutOptions::subpath) that passes
    /// through an entry that is not a directory.
    ///
    /// The payload is the value as the caller wrote it.
    #[error("checkout: subpath is not a directory: {}", .0.display())]
    SubpathNotADirectory(std::path::PathBuf),
    /// An entry that a checkout under
    /// [`require_hardlinks`](crate::CheckoutOptions::require_hardlinks) must
    /// copy.
    ///
    /// The repository mode and the checkout mode give a copy of the entry.
    /// The payload is the name of the entry.
    #[error(
        "checkout: {0}: require-hardlinks is set and this repository mode and \
         checkout mode give a copy of this entry"
    )]
    RequireHardlinks(String),
    /// A hardlink checkout into a directory on another file system.
    ///
    /// A checkout under
    /// [`require_hardlinks`](crate::CheckoutOptions::require_hardlinks) cannot
    /// hardlink an entry into a directory on a file system other than the file
    /// system of the repository. The destination root gives this error, and
    /// so does each directory under it. A checkout of a
    /// single file or symlink does no such directory check. It gives this
    /// error if the link of that entry crosses a file system.
    ///
    /// The fields hold the device number of each side.
    #[error(
        "checkout: require-hardlinks: the destination is on another filesystem \
         than the repository (repository={src} destination={dst})"
    )]
    HardlinkAcrossDevices {
        /// The device number of the object store of the repository.
        src: u64,
        /// The device number of the destination.
        dst: u64,
    },
    /// A tar import or export that cannot proceed.
    ///
    /// The causes are:
    ///
    /// - an entry type that a repository cannot store: a device node or a
    ///   FIFO
    /// - an empty path, or a path with a `..` component
    /// - a hardlink with no target in the archive
    /// - an xattr name that is not valid UTF-8
    /// - an export subpath that is absent or is not a directory
    #[error("tar: {0}")]
    Tar(String),
    /// A tar member whose pathname is not valid UTF-8.
    ///
    /// This crate stores pathnames as text, so such a member has no name to
    /// import it under.
    #[error("Archive entry pathname is not valid UTF-8")]
    TarPathname,
    /// A failure to remove an entry of the source under
    /// [`CONSUME`](crate::CommitModifierFlags::CONSUME).
    ///
    /// The fields hold the name of the entry and the reason of the failure.
    #[error("unlinkat({name}): {reason}")]
    ConsumeUnlink {
        /// The name of the entry.
        name: String,
        /// The reason of the failure, as the text of the OS error.
        reason: String,
    },
    /// A file from a tree source at a path where an earlier source put a
    /// directory.
    ///
    /// The payload is the name of the entry.
    #[error("Can't replace directory with file: {0}")]
    ReplaceDirWithFile(String),
    /// A directory from a tree source at a path where an earlier source put a
    /// file.
    ///
    /// The payload is the name of the entry.
    #[error("Can't replace file with directory: {0}")]
    ReplaceFileWithDir(String),
    /// A tar member whose parent directory is not in the tree.
    ///
    /// A tar import gives this error if
    /// [`TarImportOptions::autocreate_parents`](crate::TarImportOptions::autocreate_parents)
    /// is off. The payload is the name of the first absent ancestor.
    #[error("No such file or directory: {0}")]
    TarMissingParent(String),
    /// A failure of a signing engine, a key source, or a signature
    /// verification.
    ///
    /// A signing engine gives this error for these inputs:
    ///
    /// - a key of the wrong length
    /// - a public key that is not a valid curve point
    /// - a malformed secret key
    /// - a signature blob that the engine refuses
    ///
    /// An [`ostrya_sign::Error::Signature`] converts to this variant with the
    /// same message. Each variant of `ostrya_sign::Error` that the conversion
    /// does not name also converts to this variant.
    ///
    /// This crate also builds this variant in these places:
    ///
    /// - the verification policy of a pull
    /// - the readers of keyrings and key files
    /// - the GPG key import and the `gpg` program that it runs
    /// - the signature verification of a static delta
    #[error("signature: {0}")]
    Signature(String),
    /// A pull that cannot proceed, or that refuses an object or a commit.
    ///
    /// The causes are:
    ///
    /// - a remote that is not in the configuration, or that has no `url` and
    ///   no `pull-url`
    /// - a pull of all refs with no configured branches, or in mirror mode
    ///   with no summary on the remote
    /// - a commit whose `ostree.ref-binding` does not name the ref of the pull
    /// - a commit that is older than the commit that its ref holds
    /// - a content object whose mode the destination repository cannot store
    /// - a required static delta that is absent, or a delta whose superblock
    ///   does not produce its target
    /// - a subpath that is not an absolute path, or too many subpaths
    /// - a signature verification with no remote to take the keys from
    /// - a client certificate with no client key, or a client key with no
    ///   client certificate
    #[error("pull: {0}")]
    Pull(String),
    /// A failure to set up or to carry out a fetch.
    ///
    /// The causes include a mirror URL, a header, or a TLS configuration that
    /// the fetcher cannot use. They also include a transport failure that
    /// outlived the retries.
    ///
    /// A [`fetch::Error::Fetch`](crate::fetch::Error::Fetch) converts to this
    /// variant with the same message. Each variant of `fetch::Error` that the
    /// conversion does not name also converts to this variant. A pull also
    /// builds this variant.
    #[error("fetch: {0}")]
    Fetch(String),
    /// An unsuccessful HTTP status that ended a fetch.
    ///
    /// A 404 means that the remote does not hold the object. A pull accepts a
    /// 404 as a normal answer for an optional object.
    ///
    /// A fetch with mirrors and rounds reports the first definitive failure
    /// that it received. If it received no definitive failure, it reports the
    /// first retryable failure. If the reported failure is a status, it is
    /// this variant.
    ///
    /// A [`fetch::Error::HttpStatus`](crate::fetch::Error::HttpStatus) converts
    /// to this variant.
    #[error("http status {status} for {url}")]
    HttpStatus {
        /// The status of the response.
        status: u16,
        /// The URL of the hop that answered with the status.
        url: String,
    },
    /// A redirect chain that reached the limit of
    /// [`max_redirects`](crate::FetcherOptions::max_redirects).
    ///
    /// The response at the end of the chain named another URL to follow. Each
    /// attempt against one destination counts its own hops, so a repeated
    /// round counts again from the destination that the route named.
    ///
    /// A [`fetch::Error::RedirectLimit`](crate::fetch::Error::RedirectLimit)
    /// converts to this variant.
    #[error("redirect from {url} exceeds the {hops}-redirect limit")]
    RedirectLimit {
        /// The URL of the last hop, whose `Location` the limit did not follow.
        url: String,
        /// The number of redirects that the attempt followed, which is the
        /// limit.
        hops: u32,
    },
    /// A response that declared more bytes than the cap of the caller.
    ///
    /// If a body grows past the cap while it streams, the read fails with the
    /// same [`FileTooLarge`](std::io::ErrorKind::FileTooLarge) kind. The
    /// payload of that I/O error is a message, and it does not downcast to an
    /// error of this crate.
    ///
    /// A [`fetch::Error::FetchTooLarge`](crate::fetch::Error::FetchTooLarge)
    /// converts to this variant.
    #[error("fetched object exceeds the {limit}-byte cap")]
    FetchTooLarge {
        /// The cap that the caller set on the request.
        limit: u64,
    },
    /// A response that declared a coding in `Content-Encoding` or
    /// `Transfer-Encoding`.
    ///
    /// The body of such a response holds bytes other than the bytes that the
    /// remote stores.
    ///
    /// A [`fetch::Error::ContentEncoded`](crate::fetch::Error::ContentEncoded)
    /// converts to this variant.
    #[error("response for {url} carries the coding {encoding}")]
    ContentEncoded {
        /// The URL that answered.
        url: String,
        /// The coding that the response declared.
        encoding: String,
    },
    /// An upload that failed after the fetcher gave its request to the
    /// connection.
    ///
    /// The server can have received the whole request and acted on it, so the
    /// outcome is unknown. The fetcher does not send the request again.
    ///
    /// A
    /// [`fetch::Error::UploadInterrupted`](crate::fetch::Error::UploadInterrupted)
    /// converts to this variant.
    #[error("upload to {url} interrupted: {message}")]
    UploadInterrupted {
        /// The URL that the request was sent to.
        url: String,
        /// The text that names what ended the upload.
        message: String,
    },
    /// A GC-root metadata key whose value is not a list of commit checksums.
    ///
    /// [`gc_root_metadata_keys`](crate::PruneOptions::gc_root_metadata_keys)
    /// names the keys. A value gives this error if its variant type is not
    /// `aay`, or if an element is not a 32-byte checksum.
    #[error("gc-root metadata key {metadata_key} on commit {commit}: {reason}")]
    InvalidGcRoot {
        /// The commit that holds the metadata key.
        commit: Checksum,
        /// The name of the metadata key, as configured.
        metadata_key: String,
        /// The text that names the defect of the value.
        reason: String,
    },
    /// A failure of a session of the wire protocol of [`push`](crate::push).
    ///
    /// The causes are:
    ///
    /// - an error that the server side sent to the peer with its wire code
    /// - an `Abort` from the client ([`Aborted`](crate::push::Error::Aborted))
    /// - an error of the session stream
    /// - on the client side, a push request that the client refuses
    ///   ([`InvalidInput`](crate::push::Error::InvalidInput))
    ///
    /// The variant is in every build.
    #[error(transparent)]
    Push(#[from] crate::push::Error),
    /// A static delta from `from` to `to` that the repository does not hold.
    ///
    /// No file resolves at its `deltas/<fanout>/<rest>` path. The message
    /// names the delta as the `ostree` command names it.
    #[error("Can't find delta {}", crate::delta::delta_hex_name(.from.as_ref(), .to))]
    StaticDeltaNotFound {
        /// The source commit, or `None` for a delta from scratch.
        from: Option<Checksum>,
        /// The target commit.
        to: Checksum,
    },
}

impl From<rustix::io::Errno> for Error {
    fn from(errno: rustix::io::Errno) -> Error {
        Error::Io(errno.into())
    }
}

impl From<ostrya_sign::Error> for Error {
    /// Maps a signing-engine error to the variant of the same name.
    ///
    /// A variant that this conversion does not name maps to
    /// [`Error::Signature`] with the message of the error.
    fn from(err: ostrya_sign::Error) -> Error {
        match err {
            ostrya_sign::Error::Signature(message) => Error::Signature(message),
            ostrya_sign::Error::InvalidFormat(message) => Error::InvalidFormat(message),
            ostrya_sign::Error::Core(e) => Error::Core(e),
            other => Error::Signature(other.to_string()),
        }
    }
}

impl From<crate::fetch::Error> for Error {
    /// Maps a fetcher error to the variant of the same name.
    ///
    /// The variant gets the same fields, so the message stays the same. A
    /// variant that this conversion does not name maps to [`Error::Fetch`]
    /// with the message of the error.
    fn from(err: crate::fetch::Error) -> Error {
        use crate::fetch::Error as F;

        match err {
            F::Fetch(message) => Error::Fetch(message),
            F::HttpStatus { status, url } => Error::HttpStatus { status, url },
            F::RedirectLimit { url, hops } => Error::RedirectLimit { url, hops },
            F::FetchTooLarge { limit } => Error::FetchTooLarge { limit },
            F::ContentEncoded { url, encoding } => Error::ContentEncoded { url, encoding },
            F::Unsupported(message) => Error::Unsupported(message),
            F::UploadInterrupted { url, message } => Error::UploadInterrupted { url, message },
            other => Error::Fetch(other.to_string()),
        }
    }
}

impl From<Error> for std::io::Error {
    /// Maps an error of this crate to the closest [`std::io::ErrorKind`].
    ///
    /// The I/O error holds the error as its payload, so its `Display` and its
    /// source chain stay. An [`Error::Io`] comes back unchanged.
    ///
    /// A variant gets a specific kind only if the standard set names the
    /// condition. A symlink loop maps to [`Other`](std::io::ErrorKind::Other),
    /// because `ErrorKind::FilesystemLoop` is unstable.
    ///
    /// Three fetch failures get their own kind:
    ///
    /// - An [`Error::HttpStatus`] of 404 maps to
    ///   [`NotFound`](std::io::ErrorKind::NotFound). A remote uses a 404 to
    ///   state that an object is absent.
    /// - A 401 and a 403 map to
    ///   [`PermissionDenied`](std::io::ErrorKind::PermissionDenied). Each
    ///   other status maps to [`Other`](std::io::ErrorKind::Other).
    /// - An [`Error::FetchTooLarge`] maps to
    ///   [`FileTooLarge`](std::io::ErrorKind::FileTooLarge).
    ///
    /// If a body grows past the cap while it streams, its read fails with the
    /// same `FileTooLarge` kind. The payload of that error is a message, so
    /// only the converted error downcasts to an error of this crate.
    fn from(err: Error) -> std::io::Error {
        use std::io::ErrorKind;

        let err = match err {
            Error::Io(e) => return e,
            other => other,
        };
        let kind = match &err {
            Error::PathNotFound { .. }
            | Error::DanglingSymlink { .. }
            | Error::ObjectNotFound { .. }
            | Error::RefNotFound(_)
            | Error::RemoteNotFound(_)
            | Error::StaticDeltaNotFound { .. }
            | Error::HttpStatus { status: 404, .. } => ErrorKind::NotFound,
            Error::HttpStatus {
                status: 401 | 403, ..
            } => ErrorKind::PermissionDenied,
            Error::FetchTooLarge { .. } => ErrorKind::FileTooLarge,
            Error::NotADirectory { .. } | Error::ReplaceFileWithDir(_) => ErrorKind::NotADirectory,
            Error::EntryExists { .. }
            | Error::MergeConflict(_)
            | Error::ReplaceDirWithFile(_)
            | Error::RemoteExists(_) => ErrorKind::AlreadyExists,
            Error::MutableTree(_) | Error::InvalidInput(_) => ErrorKind::InvalidInput,
            _ => ErrorKind::Other,
        };
        std::io::Error::new(kind, err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_error_converts_displays_and_chains() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let err: Error = io.into();
        assert!(matches!(err, Error::Io(_)));
        assert!(err.to_string().contains("i/o error"));
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn errors_convert_to_the_documented_io_kinds() {
        use std::io::ErrorKind;

        let path = || "usr/lib/modules".to_owned();
        let url = || "https://example.invalid/objects/ab.commit".to_owned();
        let cases: Vec<(Error, ErrorKind)> = vec![
            (Error::PathNotFound { path: path() }, ErrorKind::NotFound),
            (
                Error::DanglingSymlink {
                    path: path(),
                    target: "nowhere".into(),
                },
                ErrorKind::NotFound,
            ),
            (
                Error::ObjectNotFound {
                    checksum: Checksum::from_hex(&"ab".repeat(32)).unwrap(),
                    ty: ObjectType::Commit,
                },
                ErrorKind::NotFound,
            ),
            (Error::RefNotFound("x/y".into()), ErrorKind::NotFound),
            (Error::RemoteNotFound("origin".into()), ErrorKind::NotFound),
            (
                Error::StaticDeltaNotFound {
                    from: None,
                    to: Checksum::from_hex(&"ab".repeat(32)).unwrap(),
                },
                ErrorKind::NotFound,
            ),
            (
                Error::NotADirectory { path: path() },
                ErrorKind::NotADirectory,
            ),
            (
                Error::ReplaceFileWithDir("etc".into()),
                ErrorKind::NotADirectory,
            ),
            (
                Error::EntryExists { path: path() },
                ErrorKind::AlreadyExists,
            ),
            (
                Error::MergeConflict("file differs at a".into()),
                ErrorKind::AlreadyExists,
            ),
            (
                Error::ReplaceDirWithFile("etc".into()),
                ErrorKind::AlreadyExists,
            ),
            (
                Error::RemoteExists("origin".into()),
                ErrorKind::AlreadyExists,
            ),
            (
                Error::MutableTree("bad name".into()),
                ErrorKind::InvalidInput,
            ),
            (
                Error::InvalidInput("depth -2 is below -1".into()),
                ErrorKind::InvalidInput,
            ),
            (Error::SymlinkLoop { path: path() }, ErrorKind::Other),
            (Error::Staging("directory is gone".into()), ErrorKind::Other),
            (
                Error::HttpStatus {
                    status: 404,
                    url: url(),
                },
                ErrorKind::NotFound,
            ),
            (
                Error::HttpStatus {
                    status: 401,
                    url: url(),
                },
                ErrorKind::PermissionDenied,
            ),
            (
                Error::HttpStatus {
                    status: 403,
                    url: url(),
                },
                ErrorKind::PermissionDenied,
            ),
            (
                Error::HttpStatus {
                    status: 400,
                    url: url(),
                },
                ErrorKind::Other,
            ),
            (
                Error::HttpStatus {
                    status: 429,
                    url: url(),
                },
                ErrorKind::Other,
            ),
            (
                Error::HttpStatus {
                    status: 500,
                    url: url(),
                },
                ErrorKind::Other,
            ),
            (
                Error::HttpStatus {
                    status: 502,
                    url: url(),
                },
                ErrorKind::Other,
            ),
            (
                Error::FetchTooLarge { limit: 4096 },
                ErrorKind::FileTooLarge,
            ),
            (
                Error::ContentEncoded {
                    url: url(),
                    encoding: "gzip".into(),
                },
                ErrorKind::Other,
            ),
        ];

        for (err, expected) in cases {
            let rendered = err.to_string();
            let io: std::io::Error = err.into();
            assert_eq!(io.kind(), expected, "kind for {rendered}");
            assert_eq!(io.to_string(), rendered, "the message survives");
        }
    }

    #[test]
    fn an_io_error_converts_back_unchanged() {
        use std::io::ErrorKind;

        let err = Error::Io(std::io::Error::new(ErrorKind::PermissionDenied, "nope"));
        let io: std::io::Error = err.into();
        assert_eq!(io.kind(), ErrorKind::PermissionDenied);
        assert_eq!(io.to_string(), "nope");
    }

    #[test]
    fn a_signing_error_maps_to_its_namesake() {
        let err = Error::from(ostrya_sign::Error::Signature("refused".into()));
        assert!(
            matches!(&err, Error::Signature(m) if m == "refused"),
            "{err}"
        );
        assert_eq!(
            err.to_string(),
            ostrya_sign::Error::Signature("refused".into()).to_string()
        );

        let err = Error::from(ostrya_sign::Error::InvalidFormat("not a dict".into()));
        assert!(
            matches!(&err, Error::InvalidFormat(m) if m == "not a dict"),
            "{err}"
        );
        assert_eq!(
            err.to_string(),
            ostrya_sign::Error::InvalidFormat("not a dict".into()).to_string()
        );

        let core = ostrya_core::Error::InvalidBase64("truncated group");
        let err = Error::from(ostrya_sign::Error::Core(core.clone()));
        assert!(matches!(&err, Error::Core(e) if *e == core), "{err}");
        assert_eq!(err.to_string(), ostrya_sign::Error::Core(core).to_string());
    }

    #[test]
    fn a_fetch_error_maps_to_its_namesake() {
        use crate::fetch::Error as F;
        use std::io::ErrorKind;

        let url = || "https://example.invalid/objects/ab.commit".to_owned();
        let cases: Vec<(F, ErrorKind)> = vec![
            (F::Fetch("connection reset".into()), ErrorKind::Other),
            (
                F::HttpStatus {
                    status: 404,
                    url: url(),
                },
                ErrorKind::NotFound,
            ),
            (
                F::HttpStatus {
                    status: 401,
                    url: url(),
                },
                ErrorKind::PermissionDenied,
            ),
            (
                F::HttpStatus {
                    status: 403,
                    url: url(),
                },
                ErrorKind::PermissionDenied,
            ),
            (
                F::HttpStatus {
                    status: 500,
                    url: url(),
                },
                ErrorKind::Other,
            ),
            (
                F::RedirectLimit {
                    url: url(),
                    hops: 10,
                },
                ErrorKind::Other,
            ),
            (F::FetchTooLarge { limit: 4096 }, ErrorKind::FileTooLarge),
            (
                F::ContentEncoded {
                    url: url(),
                    encoding: "gzip".into(),
                },
                ErrorKind::Other,
            ),
            (F::Unsupported("proxy url".into()), ErrorKind::Other),
            (
                F::UploadInterrupted {
                    url: url(),
                    message: "connection reset".into(),
                },
                ErrorKind::Other,
            ),
        ];

        for (fetch, expected) in cases {
            let rendered = fetch.to_string();
            let namesake = match &fetch {
                F::Fetch(m) => Error::Fetch(m.clone()),
                F::HttpStatus { status, url } => Error::HttpStatus {
                    status: *status,
                    url: url.clone(),
                },
                F::RedirectLimit { url, hops } => Error::RedirectLimit {
                    url: url.clone(),
                    hops: *hops,
                },
                F::FetchTooLarge { limit } => Error::FetchTooLarge { limit: *limit },
                F::ContentEncoded { url, encoding } => Error::ContentEncoded {
                    url: url.clone(),
                    encoding: encoding.clone(),
                },
                F::Unsupported(m) => Error::Unsupported(m.clone()),
                F::UploadInterrupted { url, message } => Error::UploadInterrupted {
                    url: url.clone(),
                    message: message.clone(),
                },
                other => panic!("no namesake for {other:?}"),
            };
            let err = Error::from(fetch);
            assert_eq!(format!("{err:?}"), format!("{namesake:?}"));
            assert_eq!(err.to_string(), rendered);
            let io = std::io::Error::from(err);
            assert_eq!(io.kind(), expected, "kind for {rendered}");
            assert_eq!(io.to_string(), rendered);
        }
    }

    #[test]
    fn format_and_unsupported_have_no_source() {
        let err = Error::InvalidFormat("bad header".into());
        assert!(err.to_string().contains("invalid format"));
        assert!(std::error::Error::source(&err).is_none());

        let err = Error::Unsupported("mode".into());
        assert!(err.to_string().contains("unsupported"));
        assert!(std::error::Error::source(&err).is_none());
    }
}
