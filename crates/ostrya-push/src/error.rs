//! The error type of the push protocol and its wire codes.

use ostrya_core::{Checksum, ObjectName};

use crate::proto::{ErrorMessage, RefState};

/// Result alias used throughout the `ostrya-push` crate.
pub type Result<T> = std::result::Result<T, Error>;

/// The error a push session fails with.
///
/// Each variant except [`Error::Aborted`], [`Error::CommitOutcomeUnknown`],
/// [`Error::Source`], [`Error::InvalidInput`], [`Error::Transport`],
/// [`Error::Fetch`], [`Error::Io`], [`Error::Walk`], and [`Error::Sign`] is
/// one wire code of the `Error` message.
/// The enum is `#[non_exhaustive]`, so a match outside the crate needs a
/// wildcard arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The server does not speak the requested protocol version.
    #[error("version-unsupported: {0}")]
    VersionUnsupported(String),
    /// The server repository sets `[core] locking=false`.
    #[error("locking-disabled: {0}")]
    LockingDisabled(String),
    /// Over HTTP only. The transport answers 401 or 403 first.
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    /// A malformed frame, an unknown kind, or a message out of order.
    #[error("protocol: {0}")]
    Protocol(String),
    /// A frame, a batch, or a metadata object past a limit.
    #[error("limit-exceeded: {0}")]
    LimitExceeded(String),
    /// An object whose bytes do not hash to its name.
    #[error("checksum-mismatch: {0}")]
    ChecksumMismatch(String),
    /// Content the repository mode cannot store, or privileged content the
    /// policy does not allow.
    #[error("mode-refused: {0}")]
    ModeRefused(String),
    /// A commit of the session reaches objects that are neither in the
    /// repository nor staged in the session. `missing` lists them.
    #[error("missing-objects: {message}")]
    MissingObjects {
        /// The message for a human.
        message: String,
        /// The objects that are missing.
        missing: Vec<ObjectName>,
    },
    /// A ref is not in its expected state. `name` and `current` give the
    /// current state; `current` is `None` when the ref is absent.
    #[error("ref-mismatch: {message}")]
    RefMismatch {
        /// The message for a human.
        message: String,
        /// The name of the ref.
        name: String,
        /// The current commit of the ref.
        current: Option<Checksum>,
    },
    /// The new commit does not descend from the current tip, and the policy
    /// does not allow it.
    #[error("non-fast-forward: {0}")]
    NonFastForward(String),
    /// A ref delete the policy does not allow.
    #[error("delete-denied: {0}")]
    DeleteDenied(String),
    /// A ref name the port refuses.
    #[error("invalid-ref: {0}")]
    InvalidRef(String),
    /// A ref update that no rule of the policy accepts: the rule that
    /// matches it has `accept=false`, or it names a remote ref that no rule
    /// matches.
    #[error("ref-denied: {0}")]
    RefDenied(String),
    /// The policy requires a trusted signature, and the commit carries none
    /// that verifies.
    #[error("signature-required: {0}")]
    SignatureRequired(String),
    /// The `ostree.ref-binding` of the commit does not name a target ref, or
    /// its `ostree.collection-binding` does not name the server collection id.
    #[error("binding-mismatch: {0}")]
    BindingMismatch(String),
    /// A server-side failure, for example an I/O error.
    #[error("internal: {0}")]
    Internal(String),
    /// The client ended the session with `Abort`, or abandoned an object with
    /// the abandon marker. No wire code carries it, because the server sends
    /// no `Error` in reply.
    #[error("the client aborted the session")]
    Aborted,
    /// The client sent `Commit`, and the session ended with no reply the
    /// client could read. The server may have written the refs, or none of
    /// them. `refs` names the refs of the ref updates.
    #[error("the outcome of the commit of {refs:?} is unknown: {message}")]
    CommitOutcomeUnknown {
        /// The refs of the ref updates.
        refs: Vec<String>,
        /// What ended the session, for a human.
        message: String,
    },
    /// The object source of a client failed while the session sent its
    /// objects. The session ended with `Abort`.
    #[error("the object source failed: {0}")]
    Source(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// A call of the client that the session refuses: an argument or source
    /// data it cannot send, a call while another one runs, or a call on a
    /// broken session.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// The transport under the session failed. Over ssh: the ssh client
    /// could not be started, or it exited with a failure status while the
    /// session failed with an I/O error, and the message names the program.
    /// Over HTTP: the server answered with a status the receive endpoint does
    /// not give, a 3xx included, or with a body that is not one frame, and
    /// the message names the URL and the status. No wire code carries it.
    #[error("transport: {0}")]
    Transport(String),
    /// The HTTP client of the session failed: it could not be built, a
    /// request could not be sent, or a request failed after it was sent. No
    /// wire code carries it.
    #[error(transparent)]
    Fetch(ostrya_fetch::Error),
    /// An I/O error of the underlying stream. An end of file inside a frame
    /// or an object has the kind `UnexpectedEof`.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The walk or the hash of a local tree failed, or the send pass could
    /// not open a file of the tree again. `path` names the entry on the local
    /// filesystem, the walk root included. `source` keeps the
    /// `io::ErrorKind` of the failure: the kind of the call that failed, for
    /// example `PermissionDenied` or `NotFound`, `InvalidInput` for a walk
    /// root that is not a directory or that the entry filter skips, and
    /// `InvalidData` or `Unsupported` for a structure the walk refuses. No
    /// wire code carries it. The walk and the hash come before any session,
    /// and a session returns a failed open of the send pass inside
    /// [`Error::Source`].
    #[error("{}: {source}", .path.display())]
    Walk {
        /// The entry on the local filesystem.
        path: std::path::PathBuf,
        /// The failure.
        #[source]
        source: std::io::Error,
    },
    /// A signer of a tree push failed, or the detached metadata of the
    /// caller holds a value under the key of a signer that is not a
    /// signature array. No wire code carries it. The client signs before it
    /// offers an object, and it ends the session with `Abort`.
    #[error("signing: {0}")]
    Sign(#[source] ostrya_sign::Error),
}

/// The wire code of an `Error` message.
///
/// The enum is `#[non_exhaustive]`, because a later protocol use adds codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// `version-unsupported`.
    VersionUnsupported,
    /// `locking-disabled`.
    LockingDisabled,
    /// `unauthorized`.
    Unauthorized,
    /// `protocol`.
    Protocol,
    /// `limit-exceeded`.
    LimitExceeded,
    /// `checksum-mismatch`.
    ChecksumMismatch,
    /// `mode-refused`.
    ModeRefused,
    /// `missing-objects`.
    MissingObjects,
    /// `ref-mismatch`.
    RefMismatch,
    /// `non-fast-forward`.
    NonFastForward,
    /// `delete-denied`.
    DeleteDenied,
    /// `invalid-ref`.
    InvalidRef,
    /// `ref-denied`.
    RefDenied,
    /// `signature-required`.
    SignatureRequired,
    /// `binding-mismatch`.
    BindingMismatch,
    /// `internal`.
    Internal,
}

impl ErrorCode {
    /// Every code, in wire-list order.
    pub const ALL: [ErrorCode; 16] = [
        ErrorCode::VersionUnsupported,
        ErrorCode::LockingDisabled,
        ErrorCode::Unauthorized,
        ErrorCode::Protocol,
        ErrorCode::LimitExceeded,
        ErrorCode::ChecksumMismatch,
        ErrorCode::ModeRefused,
        ErrorCode::MissingObjects,
        ErrorCode::RefMismatch,
        ErrorCode::NonFastForward,
        ErrorCode::DeleteDenied,
        ErrorCode::InvalidRef,
        ErrorCode::RefDenied,
        ErrorCode::SignatureRequired,
        ErrorCode::BindingMismatch,
        ErrorCode::Internal,
    ];

    /// The wire name of the code.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::VersionUnsupported => "version-unsupported",
            ErrorCode::LockingDisabled => "locking-disabled",
            ErrorCode::Unauthorized => "unauthorized",
            ErrorCode::Protocol => "protocol",
            ErrorCode::LimitExceeded => "limit-exceeded",
            ErrorCode::ChecksumMismatch => "checksum-mismatch",
            ErrorCode::ModeRefused => "mode-refused",
            ErrorCode::MissingObjects => "missing-objects",
            ErrorCode::RefMismatch => "ref-mismatch",
            ErrorCode::NonFastForward => "non-fast-forward",
            ErrorCode::DeleteDenied => "delete-denied",
            ErrorCode::InvalidRef => "invalid-ref",
            ErrorCode::RefDenied => "ref-denied",
            ErrorCode::SignatureRequired => "signature-required",
            ErrorCode::BindingMismatch => "binding-mismatch",
            ErrorCode::Internal => "internal",
        }
    }

    /// The code of a wire name, or `None` for a name that is not a code.
    pub fn from_name(name: &str) -> Option<ErrorCode> {
        ErrorCode::ALL.into_iter().find(|c| c.as_str() == name)
    }
}

impl Error {
    /// The wire code of the error, or `None` for [`Error::Aborted`],
    /// [`Error::CommitOutcomeUnknown`], [`Error::Source`],
    /// [`Error::InvalidInput`], [`Error::Transport`], [`Error::Fetch`],
    /// [`Error::Io`], [`Error::Walk`], and [`Error::Sign`].
    pub fn code(&self) -> Option<ErrorCode> {
        Some(match self {
            Error::VersionUnsupported(_) => ErrorCode::VersionUnsupported,
            Error::LockingDisabled(_) => ErrorCode::LockingDisabled,
            Error::Unauthorized(_) => ErrorCode::Unauthorized,
            Error::Protocol(_) => ErrorCode::Protocol,
            Error::LimitExceeded(_) => ErrorCode::LimitExceeded,
            Error::ChecksumMismatch(_) => ErrorCode::ChecksumMismatch,
            Error::ModeRefused(_) => ErrorCode::ModeRefused,
            Error::MissingObjects { .. } => ErrorCode::MissingObjects,
            Error::RefMismatch { .. } => ErrorCode::RefMismatch,
            Error::NonFastForward(_) => ErrorCode::NonFastForward,
            Error::DeleteDenied(_) => ErrorCode::DeleteDenied,
            Error::InvalidRef(_) => ErrorCode::InvalidRef,
            Error::RefDenied(_) => ErrorCode::RefDenied,
            Error::SignatureRequired(_) => ErrorCode::SignatureRequired,
            Error::BindingMismatch(_) => ErrorCode::BindingMismatch,
            Error::Internal(_) => ErrorCode::Internal,
            Error::Aborted
            | Error::CommitOutcomeUnknown { .. }
            | Error::Source(_)
            | Error::InvalidInput(_)
            | Error::Transport(_)
            | Error::Fetch(_)
            | Error::Io(_)
            | Error::Walk { .. }
            | Error::Sign(_) => return None,
        })
    }

    /// The `Error` message that reports this error to the peer. An error with
    /// no wire code reports as `internal` with its display text.
    pub fn to_message(&self) -> ErrorMessage {
        let (code, message) = match self {
            Error::MissingObjects { message, missing } => {
                return ErrorMessage {
                    code: ErrorCode::MissingObjects,
                    message: message.clone(),
                    missing: missing.clone(),
                    current: None,
                };
            }
            Error::RefMismatch {
                message,
                name,
                current,
            } => {
                return ErrorMessage {
                    code: ErrorCode::RefMismatch,
                    message: message.clone(),
                    missing: Vec::new(),
                    current: Some(RefState {
                        name: name.clone(),
                        commit: *current,
                    }),
                };
            }
            Error::Aborted
            | Error::CommitOutcomeUnknown { .. }
            | Error::Source(_)
            | Error::InvalidInput(_)
            | Error::Transport(_)
            | Error::Fetch(_)
            | Error::Io(_)
            | Error::Walk { .. }
            | Error::Sign(_) => (ErrorCode::Internal, self.to_string()),
            Error::VersionUnsupported(m)
            | Error::LockingDisabled(m)
            | Error::Unauthorized(m)
            | Error::Protocol(m)
            | Error::LimitExceeded(m)
            | Error::ChecksumMismatch(m)
            | Error::ModeRefused(m)
            | Error::NonFastForward(m)
            | Error::DeleteDenied(m)
            | Error::InvalidRef(m)
            | Error::RefDenied(m)
            | Error::SignatureRequired(m)
            | Error::BindingMismatch(m)
            | Error::Internal(m) => (self.code().expect("not Io"), m.clone()),
        };
        ErrorMessage {
            code,
            message,
            missing: Vec::new(),
            current: None,
        }
    }
}

/// The error a client reads from the `Error` message of a server. A
/// `missing` list or a `current` state on a code that does not carry one is
/// dropped. A decoded `ref-mismatch` always carries its `current` state, so
/// the conversion back with [`Error::to_message`] gives the same message.
impl From<ErrorMessage> for Error {
    fn from(msg: ErrorMessage) -> Error {
        let m = msg.message;
        match msg.code {
            ErrorCode::VersionUnsupported => Error::VersionUnsupported(m),
            ErrorCode::LockingDisabled => Error::LockingDisabled(m),
            ErrorCode::Unauthorized => Error::Unauthorized(m),
            ErrorCode::Protocol => Error::Protocol(m),
            ErrorCode::LimitExceeded => Error::LimitExceeded(m),
            ErrorCode::ChecksumMismatch => Error::ChecksumMismatch(m),
            ErrorCode::ModeRefused => Error::ModeRefused(m),
            ErrorCode::MissingObjects => Error::MissingObjects {
                message: m,
                missing: msg.missing,
            },
            ErrorCode::RefMismatch => {
                let (name, current) = match msg.current {
                    Some(s) => (s.name, s.commit),
                    None => (String::new(), None),
                };
                Error::RefMismatch {
                    message: m,
                    name,
                    current,
                }
            }
            ErrorCode::NonFastForward => Error::NonFastForward(m),
            ErrorCode::DeleteDenied => Error::DeleteDenied(m),
            ErrorCode::InvalidRef => Error::InvalidRef(m),
            ErrorCode::RefDenied => Error::RefDenied(m),
            ErrorCode::SignatureRequired => Error::SignatureRequired(m),
            ErrorCode::BindingMismatch => Error::BindingMismatch(m),
            ErrorCode::Internal => Error::Internal(m),
        }
    }
}
