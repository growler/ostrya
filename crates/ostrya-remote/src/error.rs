//! The error type of this crate and its wire codes.

use ostrya_core::{Checksum, ObjectName};

use crate::proto::{ErrorMessage, RefState};

/// The result type of this crate, with [`Error`] as its error.
pub type Result<T> = std::result::Result<T, Error>;

/// The error of each fallible operation of this crate.
///
/// A variant with a wire code matches one code of an `Error` message, for
/// example [`Error::Protocol`] for the code `protocol`. [`ErrorCode`] names
/// the codes. [`code`](Error::code) returns the code of an error and lists the
/// variants that have no code.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The server does not support the requested protocol version.
    #[error("version-unsupported: {0}")]
    VersionUnsupported(String),
    /// The server repository sets `[core] locking=false`.
    #[error("locking-disabled: {0}")]
    LockingDisabled(String),
    /// A refusal of the credential of an HTTP push session.
    ///
    /// The client returns this variant for an `Error` message with the code
    /// `unauthorized`. An ostrya server sends that message over HTTP alone,
    /// with the status 401 or 403. A 401 or 403 whose body is not one frame
    /// is [`Error::Transport`].
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    /// A malformed frame, an unknown kind, or a message out of order.
    #[error("protocol: {0}")]
    Protocol(String),
    /// A frame, a batch, or a metadata object over its limit.
    #[error("limit-exceeded: {0}")]
    LimitExceeded(String),
    /// An object whose bytes do not hash to its name.
    #[error("checksum-mismatch: {0}")]
    ChecksumMismatch(String),
    /// Content that the server refuses to store.
    ///
    /// The repository mode cannot store the content, or the content is
    /// privileged and the policy does not allow it.
    #[error("mode-refused: {0}")]
    ModeRefused(String),
    /// A commit that reaches objects that the server does not hold.
    ///
    /// The objects are not in the repository and are not staged in the
    /// session. `missing` lists them.
    #[error("missing-objects: {message}")]
    MissingObjects {
        /// The message for a human.
        message: String,
        /// The objects that are missing.
        missing: Vec<ObjectName>,
    },
    /// A ref that is not in its expected state.
    ///
    /// `name` and `current` give the current state. `current` is `None` if
    /// the ref is absent.
    #[error("ref-mismatch: {message}")]
    RefMismatch {
        /// The message for a human.
        message: String,
        /// The name of the ref.
        name: String,
        /// The current commit of the ref.
        current: Option<Checksum>,
    },
    /// A ref update that is not a fast-forward.
    ///
    /// The new commit does not descend from the current tip, and the policy
    /// does not allow it.
    #[error("non-fast-forward: {0}")]
    NonFastForward(String),
    /// A ref delete that the policy does not allow.
    #[error("delete-denied: {0}")]
    DeleteDenied(String),
    /// A ref name that an ostrya server refuses.
    #[error("invalid-ref: {0}")]
    InvalidRef(String),
    /// A ref update that no rule of the policy accepts.
    ///
    /// The rule that matches the update has `accept=false`, or the update
    /// names a remote ref that no rule matches.
    #[error("ref-denied: {0}")]
    RefDenied(String),
    /// A commit with no trusted signature that verifies.
    ///
    /// The policy requires a trusted signature.
    #[error("signature-required: {0}")]
    SignatureRequired(String),
    /// A commit whose bindings do not match the session.
    ///
    /// The `ostree.ref-binding` of the commit does not name a target ref, or
    /// its `ostree.collection-binding` does not name the collection id of the
    /// server.
    #[error("binding-mismatch: {0}")]
    BindingMismatch(String),
    /// A server-side failure, for example an I/O error.
    #[error("internal: {0}")]
    Internal(String),
    /// The client ended the session with `Abort`, or abandoned an object.
    ///
    /// The client abandons an object with the abandon marker. No wire code
    /// carries this variant, because the server sends no `Error` message in
    /// reply.
    #[error("the client aborted the session")]
    Aborted,
    /// A `Commit` whose outcome is unknown.
    ///
    /// The client sent `Commit`, and the session ended with no reply that the
    /// client can read. The server can have written the refs, and the client
    /// cannot know if it did. `refs` names the refs of the ref updates.
    #[error("the outcome of the commit of {refs:?} is unknown: {message}")]
    CommitOutcomeUnknown {
        /// The refs of the ref updates.
        refs: Vec<String>,
        /// A message for a human that states what ended the session.
        message: String,
    },
    /// A failure of the object source while the session sends its objects.
    ///
    /// The session ends with `Abort`.
    #[error("the object source failed: {0}")]
    Source(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// A call of the client that the session refuses.
    ///
    /// The session refuses a call with an argument or source data that it
    /// cannot send. It also refuses a call while another call runs, and a
    /// call on a broken session.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// A failure of the transport under the session.
    ///
    /// - Over ssh, the ssh client cannot start, or it exits with a failure
    ///   status while the session fails with an I/O error. The message names
    ///   the program.
    /// - Over HTTP, the session cannot use the response of the server. The
    ///   message names the URL, and for the first three cases the status:
    ///   - a status that the receive endpoint does not give, a 3xx included
    ///   - a body that is not one frame
    ///   - a frame other than an `Error` message with an error status
    ///   - a `HelloReply` with no session id of 64 lowercase hex digits
    ///   - a frame other than an `Error` message in answer to `DELETE`
    ///
    /// No wire code carries this variant.
    #[error("transport: {0}")]
    Transport(String),
    /// A failure of the HTTP client of the session.
    ///
    /// The client cannot be built, a request cannot be sent, or a request
    /// fails after it is sent. No wire code carries this variant.
    #[error(transparent)]
    Fetch(ostrya_fetch::Error),
    /// An I/O error of the underlying stream.
    ///
    /// An end of file inside a frame or an object has the kind
    /// `UnexpectedEof`.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// A failure of the walk or of the hash pass of a local tree.
    ///
    /// If the send pass cannot open a file of the tree again, it also
    /// returns this variant. `path` names the entry on the local filesystem,
    /// the walk root included. `source` keeps the `io::ErrorKind` of the
    /// failure.
    /// [`TreeModel::scan`](crate::tree::TreeModel::scan) lists the kinds in
    /// its `# Errors` section.
    ///
    /// No wire code carries this variant. The walk and the hash pass come
    /// before any session. A session returns a failed open of the send pass
    /// inside [`Error::Source`].
    #[error("{}: {source}", .path.display())]
    Walk {
        /// The entry on the local filesystem.
        path: std::path::PathBuf,
        /// The I/O error, with the `io::ErrorKind` of the failure.
        #[source]
        source: std::io::Error,
    },
    /// A failure of a signer of a tree push.
    ///
    /// The detached metadata of the caller can hold a value under the key of
    /// a signer. If that value is not a signature array, the error is also
    /// this variant. No wire code carries this variant. The client signs before it offers an
    /// object, and it ends the session with `Abort`.
    #[error("signing: {0}")]
    Sign(#[source] ostrya_sign::Error),
}

/// The wire code of an `Error` message.
///
/// A later protocol version can add codes.
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
    /// All 16 codes, in the order that [`ErrorCode`] declares them.
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

    /// Returns the wire name of the code.
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

    /// Returns the code of a wire name, or `None` if the name is not a code.
    pub fn from_name(name: &str) -> Option<ErrorCode> {
        ErrorCode::ALL.into_iter().find(|c| c.as_str() == name)
    }
}

impl Error {
    /// Returns the wire code of the error, or `None` for a variant with no code.
    ///
    /// These variants have no wire code:
    ///
    /// - [`Error::Aborted`]
    /// - [`Error::CommitOutcomeUnknown`]
    /// - [`Error::Source`]
    /// - [`Error::InvalidInput`]
    /// - [`Error::Transport`]
    /// - [`Error::Fetch`]
    /// - [`Error::Io`]
    /// - [`Error::Walk`]
    /// - [`Error::Sign`]
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

    /// Returns the `Error` message that reports this error to the peer.
    ///
    /// An error with no wire code reports as the code `internal`, with its
    /// display text as the message.
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

/// Converts an `Error` message from a server to the [`Error`] variant of its
/// code.
///
/// The conversion drops a `missing` list or a `current` state on a code that
/// does not carry one. A decoded `ref-mismatch` always carries its `current`
/// state, so [`Error::to_message`] gives the same message back.
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
