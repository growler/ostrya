//! The library error type.
//!
//! One `Error` enum for the whole crate, deriving `Display` and
//! `std::error::Error` via `thiserror`. The enum is `#[non_exhaustive]` because
//! later phases add variants (object not-found, checksum mismatch, signature,
//! lock, and so on). The signing engines and the fetcher have their own error
//! types, [`ostrya_sign::Error`] and [`fetch::Error`](crate::fetch::Error),
//! which convert into this one.

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
    ///
    /// A [`fetch::Error::Unsupported`](crate::fetch::Error::Unsupported)
    /// converts to this variant.
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
    /// A checkout under
    /// [`require_hardlinks`](crate::CheckoutOptions::require_hardlinks) reached
    /// an entry the repository mode and the checkout mode in force give a copy.
    /// The payload is the entry's own name.
    #[error(
        "checkout: {0}: require-hardlinks is set and this repository mode and \
         checkout mode give a copy of this entry"
    )]
    RequireHardlinks(String),
    /// A checkout under
    /// [`require_hardlinks`](crate::CheckoutOptions::require_hardlinks) reached
    /// a destination directory on another filesystem than the repository, where
    /// no entry can be hardlinked. The destination root reaches this and so
    /// does every directory below it. A single file or symlink target takes no
    /// such check and reaches this where its own link crosses a filesystem. The
    /// payload is each side's device number.
    #[error(
        "checkout: require-hardlinks: the destination is on another filesystem \
         than the repository (repository={src} destination={dst})"
    )]
    HardlinkAcrossDevices {
        /// The device number of the repository's object store.
        src: u64,
        /// The device number of the destination.
        dst: u64,
    },
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
    ///
    /// An [`ostrya_sign::Error::Signature`] converts to this variant with the
    /// same message, and so does a variant of `ostrya_sign::Error` that this
    /// conversion does not name. The library also builds this variant itself:
    /// the verification policy of a pull, the keyring readers, and the
    /// signature check of a static delta.
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
    ///
    /// A [`fetch::Error::Fetch`](crate::fetch::Error::Fetch) converts to this
    /// variant with the same message, and so does a variant of
    /// `fetch::Error` that this conversion does not name. The pull also builds
    /// this variant itself.
    #[error("fetch: {0}")]
    Fetch(String),
    /// Every mirror answered the request with an unsuccessful HTTP status. A
    /// 404 here means the object is absent from the remote, which pull treats
    /// as a normal answer for optional objects.
    ///
    /// One mirror's answer is reported: the first status received that is not
    /// retried, from whichever round it came, unless the rounds ran out with a
    /// retryable status outstanding, in which case the last mirror to give one.
    ///
    /// A [`fetch::Error::HttpStatus`](crate::fetch::Error::HttpStatus) converts
    /// to this variant.
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
    ///
    /// A [`fetch::Error::RedirectLimit`](crate::fetch::Error::RedirectLimit)
    /// converts to this variant.
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
    ///
    /// A [`fetch::Error::FetchTooLarge`](crate::fetch::Error::FetchTooLarge)
    /// converts to this variant.
    #[error("fetched object exceeds the {limit}-byte cap")]
    FetchTooLarge {
        /// The cap the caller set on the request.
        limit: u64,
    },
    /// A response declared a coding, in `Content-Encoding` or in
    /// `Transfer-Encoding`, so its body holds bytes other than the ones the
    /// remote stores.
    ///
    /// A [`fetch::Error::ContentEncoded`](crate::fetch::Error::ContentEncoded)
    /// converts to this variant.
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
    /// A push session failed: the error the receive side sent to the peer
    /// with its wire code, an `Abort` of the client
    /// ([`Aborted`](crate::push::Error::Aborted)), or an error of the session
    /// stream.
    #[cfg(feature = "receive")]
    #[error(transparent)]
    Push(#[from] crate::push::Error),
    /// The repository holds no static delta from `from` to `to`: nothing
    /// resolves at its `deltas/<fanout>/<rest>` path. The message names the
    /// delta the way the tool names it.
    #[error("Can't find delta {}", crate::delta::delta_hex_name(.from.as_ref(), .to))]
    StaticDeltaNotFound {
        /// The source commit, `None` for a delta from scratch.
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
    /// Map a signing-engine error onto the variant of the same name. A variant
    /// this conversion does not name maps to [`Error::Signature`] with the
    /// message of the error.
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
    /// Map a fetcher error onto the variant of the same name, with the same
    /// fields and so the same message. A variant this conversion does not name
    /// maps to [`Error::Fetch`] with the message of the error.
    fn from(err: crate::fetch::Error) -> Error {
        use crate::fetch::Error as F;

        match err {
            F::Fetch(message) => Error::Fetch(message),
            F::HttpStatus { status, url } => Error::HttpStatus { status, url },
            F::RedirectLimit { url, hops } => Error::RedirectLimit { url, hops },
            F::FetchTooLarge { limit } => Error::FetchTooLarge { limit },
            F::ContentEncoded { url, encoding } => Error::ContentEncoded { url, encoding },
            F::Unsupported(message) => Error::Unsupported(message),
            other => Error::Fetch(other.to_string()),
        }
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
            | Error::StaticDeltaNotFound { .. }
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
