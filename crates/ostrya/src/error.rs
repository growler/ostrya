//! The library error type.
//!
//! One `Error` enum for the whole crate, deriving `Display` and
//! `std::error::Error` via `thiserror`. The enum is `#[non_exhaustive]` because
//! later phases add variants (object not-found, checksum mismatch, signature,
//! lock, and so on).

use ostrya_core::{Checksum, ObjectType};
use thiserror::Error;

/// Result alias used throughout the `ostrya` crate.
pub type Result<T> = std::result::Result<T, Error>;

/// The single error type for the library.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// An underlying I/O error.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// An error from the core format-primitive layer (checksums, keyfile
    /// parsing, object model).
    #[error(transparent)]
    Core(#[from] ostrya_core::Error),
    /// A referenced object is not present in the store.
    #[error("object not found: {ty:?} {checksum}")]
    ObjectNotFound {
        /// The object identity that was looked up.
        checksum: Checksum,
        /// The object type that was looked up.
        ty: ObjectType,
    },
    /// A refspec did not resolve to a commit.
    #[error("ref not found: {0}")]
    RefNotFound(String),
    /// A refspec does not name a path inside the `refs/` tree: an empty name,
    /// an empty, `.`, or `..` component, a remote or collection element holding
    /// a `/`, or an interior NUL. The payload is the refspec as given, spelled
    /// `<remote>:<name>` or `<collection-id>:<name>` where one is present.
    #[error("invalid refspec: {0}")]
    InvalidRefspec(String),
    /// An abbreviated checksum prefixes more than one of the commit objects
    /// present, so it names no single commit. The payload is the revision as
    /// given.
    #[error("refspec not unique: {0}")]
    AmbiguousRefspec(String),
    /// A revision's `^` ancestry suffix asked for the parent of a root commit.
    #[error("commit {0} has no parent")]
    NoParentCommit(Checksum),
    /// On-disk data did not match the expected format.
    #[error("invalid format: {0}")]
    InvalidFormat(String),
    /// A requested operation or repository feature is not supported.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// Acquiring the repository lock timed out under contention.
    #[error("timed out acquiring repository lock after {secs}s")]
    LockTimeout {
        /// The configured lock-acquisition timeout, in seconds.
        secs: i64,
    },
    /// A written object's computed checksum did not match the caller's
    /// expected value.
    #[error("checksum mismatch: expected {expected}, computed {actual}")]
    ChecksumMismatch {
        /// The checksum the caller asserted the object would have.
        expected: Checksum,
        /// The checksum the write path actually computed.
        actual: Checksum,
    },
    /// Staging an object would drop free space below the configured
    /// `min-free-space-percent` / `min-free-space-size` reserve.
    #[error("insufficient free space: short by {shortfall} bytes")]
    InsufficientFreeSpace {
        /// How many more bytes of free space the write would have needed.
        shortfall: u64,
    },
    /// An in-memory tree could not be built or serialized: an invalid entry
    /// name, a file/directory name collision, a directory missing its dirmeta
    /// checksum, or removing an absent entry.
    #[error("mutable tree: {0}")]
    MutableTree(String),
    /// An overlayfs upperdir uses a feature the merge cannot honor because the
    /// entry is not self-contained (`overlay.metacopy` or `overlay.redirect`);
    /// the overlay must be mounted with that feature disabled.
    #[error("unsupported overlay feature: {0}")]
    UnsupportedOverlayFeature(String),
    /// A path names a component that is not present.
    #[error("path not found: {path}")]
    PathNotFound {
        /// The path of the component that is absent. A caller that holds one
        /// name and no path, `MutableTree::subtree` among them, puts the bare
        /// entry name here.
        path: String,
    },
    /// A path component that had to be a directory is a file, or a symlink
    /// resolved to one.
    #[error("not a directory: {path}")]
    NotADirectory {
        /// The path of the component that is not a directory. A caller that
        /// holds one name and no path, `MutableTree::subtree` among them, puts
        /// the bare entry name here.
        path: String,
    },
    /// A symlink's target does not resolve.
    #[error("dangling symlink: {path} -> {target}")]
    DanglingSymlink {
        /// The path of the symlink.
        path: String,
        /// The target it names.
        target: String,
    },
    /// A path resolution followed more symlinks than the depth cap allows.
    #[error("symlink chain too deep (possible loop): {path}")]
    SymlinkLoop {
        /// The path of the symlink the walk gave up on.
        path: String,
    },
    /// An operation that requires a fresh entry found one already there.
    #[error("entry already exists: {path}")]
    EntryExists {
        /// The path the entry occupies.
        path: String,
    },
    /// A staging-tree operation could not proceed for a condition none of the
    /// variants above names: an outstanding file writer blocking
    /// [`StagingTree::close`](crate::StagingTree::close), a read that wanted a
    /// file where a directory sits, a hardlink whose source resolves to a
    /// directory, a directory that a concurrent operation removed while the
    /// operation held its path, a path with no final component or one ending
    /// in `..`, a non-UTF-8 path component or symlink target, or a hydration
    /// with no repository handle to read through.
    #[error("staging tree: {0}")]
    Staging(String),
    /// A staging-tree merge hit a conflict the [`MergeOptions`](crate::MergeOptions)
    /// did not permit: differing files, a file-versus-directory clash, or
    /// differing directory metadata, without `allow_overwrite`.
    #[error("merge conflict: {0}")]
    MergeConflict(String),
    /// A checkout could not proceed: a collision under
    /// [`OverwriteMode::None`](crate::OverwriteMode::None), a
    /// [`UnionIdentical`](crate::OverwriteMode::UnionIdentical) mismatch, or an
    /// unsupported combination of options.
    #[error("checkout: {0}")]
    Checkout(String),
    /// A checkout's [`subpath`](crate::CheckoutOptions::subpath) names no entry
    /// in the commit tree. The payload is the value as the caller spelled it.
    #[error("checkout: subpath not found: {}", .0.display())]
    SubpathNotFound(std::path::PathBuf),
    /// A checkout's [`subpath`](crate::CheckoutOptions::subpath) runs through an
    /// entry that is not a directory. The payload is the value as the caller
    /// spelled it.
    #[error("checkout: subpath is not a directory: {}", .0.display())]
    SubpathNotADirectory(std::path::PathBuf),
    /// A tar import or export could not proceed: an entry type ostree cannot
    /// store (a device node or FIFO), a path with a `..` component, a hardlink
    /// with no target in the archive, or a non-UTF-8 xattr name.
    #[error("tar: {0}")]
    Tar(String),
    /// A tar member's pathname is not valid UTF-8. The port stores pathnames as
    /// text, so such a member has no name to be imported under.
    #[error("Archive entry pathname is not valid UTF-8")]
    TarPathname,
    /// A consuming walk could not remove one entry of its source. The payload
    /// is the entry's own name and the reason the removal failed.
    #[error("unlinkat({name}): {reason}")]
    ConsumeUnlink {
        /// The name of the entry that could not be removed.
        name: String,
        /// Why the removal failed.
        reason: String,
    },
    /// A tree source names a file at a path an earlier source made a
    /// directory. The payload is the entry's own name.
    #[error("Can't replace directory with file: {0}")]
    ReplaceDirWithFile(String),
    /// A tree source names a directory at a path an earlier source made a
    /// file. The payload is the entry's own name.
    #[error("Can't replace file with directory: {0}")]
    ReplaceFileWithDir(String),
    /// A tar member names a parent directory the tree does not hold and
    /// [`TarImportOptions::autocreate_parents`](crate::TarImportOptions::autocreate_parents)
    /// is off. The payload is the name of the first ancestor that is absent.
    #[error("No such file or directory: {0}")]
    TarMissingParent(String),
    /// A signing engine rejected its key material or a signature blob: a
    /// wrong-length key, a public key that is not a valid curve point, or a
    /// malformed secret key.
    #[error("signature: {0}")]
    Signature(String),
    /// A pull refused an object or a commit: a commit whose
    /// `ostree.ref-binding` does not name the ref it is being pulled under, or
    /// a content object whose mode the destination repository may not store.
    #[error("pull: {0}")]
    Pull(String),
    /// A fetch could not be set up or carried out: an unusable mirror URL,
    /// header, or TLS configuration, or a transport failure that outlived its
    /// retries.
    #[error("fetch: {0}")]
    Fetch(String),
    /// Every mirror answered the request with an unsuccessful HTTP status. A
    /// 404 here means the object is absent from the remote, which pull treats
    /// as a normal answer for optional objects.
    ///
    /// One mirror's answer is reported: the first status received that is not
    /// retried, from whichever round it came, unless the rounds ran out with a
    /// retryable status outstanding, in which case the last mirror to give one.
    #[error("http status {status} for {url}")]
    HttpStatus {
        /// The status that mirror returned.
        status: u16,
        /// The URL requested of it.
        url: String,
    },
    /// A redirect chain reached the limit
    /// [`max_redirects`](crate::FetcherOptions::max_redirects) sets, and the
    /// response at the end of it named another URL to follow. One attempt
    /// against one destination counts its own hops, so a repeated round counts
    /// again from the destination the route named.
    #[error("redirect from {url} exceeds the {hops}-redirect limit")]
    RedirectLimit {
        /// The last hop the attempt reached, which is the URL whose `Location`
        /// the limit stopped it from following.
        url: String,
        /// How many redirects the attempt followed, which is the limit it was
        /// given.
        hops: u32,
    },
    /// A response declared more bytes than the caller's cap allows. A body that
    /// outgrows the cap while streaming fails the read with the same
    /// [`FileTooLarge`](std::io::ErrorKind::FileTooLarge) kind, under a
    /// message payload that downcasts to no library error.
    #[error("fetched object exceeds the {limit}-byte cap")]
    FetchTooLarge {
        /// The cap the caller set on the request.
        limit: u64,
    },
    /// A response declared a coding, in `Content-Encoding` or in
    /// `Transfer-Encoding`, so its body holds bytes other than the ones the
    /// remote stores.
    #[error("response for {url} carries the coding {encoding}")]
    ContentEncoded {
        /// The URL that answered.
        url: String,
        /// The coding the response declared.
        encoding: String,
    },
    /// A metadata key named in
    /// [`gc_root_metadata_keys`](crate::PruneOptions::gc_root_metadata_keys)
    /// holds a value that is not a list of commit checksums: its variant type
    /// is not `aay`, or one element is not a 32-byte checksum.
    #[error("gc-root metadata key {metadata_key} on commit {commit}: {reason}")]
    InvalidGcRoot {
        /// The commit the metadata key was read from.
        commit: Checksum,
        /// The metadata key name, as configured.
        metadata_key: String,
        /// What the value holds instead.
        reason: String,
    },
}

impl From<rustix::io::Errno> for Error {
    fn from(errno: rustix::io::Errno) -> Error {
        Error::Io(errno.into())
    }
}

impl From<Error> for std::io::Error {
    /// Map a library error onto the closest `std::io::ErrorKind`, keeping the
    /// error itself as the payload so its `Display` and its source chain
    /// survive. An [`Error::Io`] is handed back unchanged.
    ///
    /// A kind is given only where the standard set names the condition. A
    /// symlink loop falls to [`Other`](std::io::ErrorKind::Other), since
    /// `ErrorKind::FilesystemLoop` is unstable.
    ///
    /// Three fetch failures the standard set names carry their own kind. An
    /// [`Error::HttpStatus`] of 404 maps to
    /// [`NotFound`](std::io::ErrorKind::NotFound), which is how a remote
    /// states an object is absent; a 401 and a 403 map to
    /// [`PermissionDenied`](std::io::ErrorKind::PermissionDenied); every other
    /// status falls to [`Other`](std::io::ErrorKind::Other). An
    /// [`Error::FetchTooLarge`] maps to
    /// [`FileTooLarge`](std::io::ErrorKind::FileTooLarge). A body that
    /// outgrows the cap while streaming fails its read with that same kind,
    /// and its payload is a message, so only the converted error downcasts
    /// back to a library error.
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
            | Error::HttpStatus { status: 404, .. } => ErrorKind::NotFound,
            Error::HttpStatus {
                status: 401 | 403, ..
            } => ErrorKind::PermissionDenied,
            Error::FetchTooLarge { .. } => ErrorKind::FileTooLarge,
            Error::NotADirectory { .. } | Error::ReplaceFileWithDir(_) => ErrorKind::NotADirectory,
            Error::EntryExists { .. } | Error::MergeConflict(_) | Error::ReplaceDirWithFile(_) => {
                ErrorKind::AlreadyExists
            }
            Error::MutableTree(_) => ErrorKind::InvalidInput,
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
                Error::MutableTree("bad name".into()),
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
    fn format_and_unsupported_have_no_source() {
        let err = Error::InvalidFormat("bad header".into());
        assert!(err.to_string().contains("invalid format"));
        assert!(std::error::Error::source(&err).is_none());

        let err = Error::Unsupported("mode".into());
        assert!(err.to_string().contains("unsupported"));
        assert!(std::error::Error::source(&err).is_none());
    }
}
