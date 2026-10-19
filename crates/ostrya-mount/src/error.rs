//! The error type of the crate.

use std::path::PathBuf;

use ostrya::RepoMode;
use rustix::io::Errno;

/// The error of each fallible operation of the crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An error of the repository: a commit without the composefs key, an
    /// absent image, an image whose digest is not the key, a failed export,
    /// or a malformed config value.
    #[error(transparent)]
    Repo(#[from] ostrya::Error),
    /// A repository whose mode a composefs mount cannot read. Only `archive`
    /// gives this error.
    #[error("a repository of the mode {} cannot be mounted", .0.as_mode_str())]
    UnsupportedMode(RepoMode),
    /// A system call that failed.
    ///
    /// `op` names the call or the step. If the kernel logged a message for a
    /// failed file system configuration, `log` holds it.
    #[error("{}", sys_message(.op, .errno, .log.as_deref()))]
    Sys {
        /// The call or the step that failed.
        op: &'static str,
        /// The error number of the call.
        errno: Errno,
        /// The messages of the file system context, joined with `; `.
        log: Option<String>,
    },
    /// An image of the caller that a loop device cannot carry whole: an
    /// empty file, or a size that is not a multiple of 4096 bytes.
    #[error("invalid image: {0}")]
    InvalidImage(String),
    /// A target that is not the root of an overlay mount.
    #[error("{} is not the root of an overlay mount", .0.display())]
    NotOverlayMount(PathBuf),
    /// A request that the helper client refuses before it connects: a
    /// relative repository or target path, or a value longer than the
    /// protocol allows.
    #[error("invalid mount request: {0}")]
    InvalidRequest(String),
    /// A connect to the socket of the mount daemon that failed.
    #[error("{}", connect_message(.path, .errno))]
    Connect {
        /// The path of the socket.
        path: PathBuf,
        /// The error number of `connect`.
        errno: Errno,
    },
    /// A refusal or a failure that the mount daemon reports, or a reply of
    /// the daemon that breaks the protocol.
    #[error("mount daemon: {message} ({code})")]
    Helper {
        /// The class of the failure.
        code: HelperCode,
        /// The error number of the failed call, if a call failed.
        errno: Option<Errno>,
        /// The text of the failure.
        message: String,
    },
}

/// The class of an [`Error::Helper`].
///
/// The protocol of the mount daemon carries the class as one byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HelperCode {
    /// A message that breaks the protocol. The daemon and the client both
    /// use the class.
    Protocol,
    /// The client and the daemon speak different versions of the protocol.
    Version,
    /// The namespaces of the request fail a check of the daemon, for
    /// example a request from the initial user namespace.
    Namespace,
    /// The caller cannot open the repository, its `objects` directory, or
    /// the target, or the daemon refuses one of them: a target on FUSE, or
    /// an `objects` directory that is the root of a mount or that is on
    /// another mount than the repository directory.
    Access,
    /// The repository refuses the mount: a repository on FUSE, a mode that
    /// cannot be mounted, a commit without the composefs key, an absent
    /// image, an image whose digest is not the key, or a built image larger
    /// than the limit of the daemon.
    Repository,
    /// A system call of the mount failed.
    Mount,
    /// The daemon failed for another reason.
    Internal,
    /// The connection did not complete in its time: the daemon got no
    /// message of the client, or did not complete the request, in the 60
    /// seconds of the connection.
    Timeout,
    /// A class that this version of the crate does not know, with its byte.
    Other(u8),
}

impl HelperCode {
    /// Returns the byte of the class on the wire.
    #[cfg(any(feature = "server", test))]
    pub(crate) fn to_wire(self) -> u8 {
        match self {
            HelperCode::Protocol => 1,
            HelperCode::Version => 2,
            HelperCode::Namespace => 3,
            HelperCode::Access => 4,
            HelperCode::Repository => 5,
            HelperCode::Mount => 6,
            HelperCode::Internal => 7,
            HelperCode::Timeout => 8,
            HelperCode::Other(byte) => byte,
        }
    }

    /// Returns the class of the byte `byte` on the wire.
    pub(crate) fn from_wire(byte: u8) -> HelperCode {
        match byte {
            1 => HelperCode::Protocol,
            2 => HelperCode::Version,
            3 => HelperCode::Namespace,
            4 => HelperCode::Access,
            5 => HelperCode::Repository,
            6 => HelperCode::Mount,
            7 => HelperCode::Internal,
            8 => HelperCode::Timeout,
            other => HelperCode::Other(other),
        }
    }
}

impl std::fmt::Display for HelperCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HelperCode::Protocol => f.write_str("protocol"),
            HelperCode::Version => f.write_str("version"),
            HelperCode::Namespace => f.write_str("namespace"),
            HelperCode::Access => f.write_str("access"),
            HelperCode::Repository => f.write_str("repository"),
            HelperCode::Mount => f.write_str("mount"),
            HelperCode::Internal => f.write_str("internal"),
            HelperCode::Timeout => f.write_str("timeout"),
            HelperCode::Other(byte) => write!(f, "code {byte}"),
        }
    }
}

/// The result type of the crate.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Returns an [`Error::Sys`] with no log.
    pub(crate) fn sys(op: &'static str, errno: Errno) -> Error {
        Error::Sys {
            op,
            errno,
            log: None,
        }
    }

    /// Returns an [`Error::Sys`] for the I/O error `e` of a system call.
    pub(crate) fn io(op: &'static str, e: &std::io::Error) -> Error {
        Error::sys(op, Errno::from_io_error(e).unwrap_or(Errno::IO))
    }

    /// Returns an [`Error::Helper`] with no error number.
    pub(crate) fn helper(code: HelperCode, message: impl Into<String>) -> Error {
        Error::Helper {
            code,
            errno: None,
            message: message.into(),
        }
    }

    /// Returns the text of the error with no hint about the privilege of
    /// the process. The mount daemon reports this text, because its steps
    /// run with other privileges than a direct mount.
    #[cfg(feature = "server")]
    pub(crate) fn plain_text(&self) -> String {
        match self {
            Error::Sys { op, errno, log } => match log {
                Some(log) => format!("{op}: {errno}: {log}"),
                None => format!("{op}: {errno}"),
            },
            other => other.to_string(),
        }
    }
}

/// The steps of a direct mount whose `EPERM` comes from a missing
/// privilege in the initial user namespace, as prefixes of the step name.
const MOUNT_STEPS: [&str; 4] = ["fsopen", "fsconfig", "fsmount", "move_mount"];

/// The step that unmounts a target.
const UNMOUNT_STEP: &str = "unmount";

/// The step that attaches the loop device.
pub(crate) const ATTACH_STEP: &str = "attach loop device";

/// Formats an [`Error::Sys`]. An `EPERM` of a mount step names the privilege
/// that a direct mount needs, and an `EPERM` of the loop attach names the
/// device access it needs.
fn sys_message(op: &str, errno: &Errno, log: Option<&str>) -> String {
    let mut text = format!("{op}: {errno}");
    if *errno == Errno::PERM {
        if MOUNT_STEPS.iter().any(|step| op.starts_with(step)) {
            text.push_str(" (the call needs CAP_SYS_ADMIN in the initial user namespace)");
        } else if op == UNMOUNT_STEP {
            text.push_str(
                " (the call needs CAP_SYS_ADMIN in the user namespace that owns the mount \
                 namespace)",
            );
        } else if op == ATTACH_STEP {
            text.push_str(" (the call needs access to /dev/loop-control and the loop devices)");
        }
    }
    if let Some(log) = log {
        text.push_str(": ");
        text.push_str(log);
    }
    text
}

/// Formats an [`Error::Connect`]. The text names the likely cause of the
/// usual error numbers.
fn connect_message(path: &std::path::Path, errno: &Errno) -> String {
    let mut text = format!("connect to {}: {errno}", path.display());
    if *errno == Errno::ACCESS || *errno == Errno::PERM {
        text.push_str(" (the caller needs write access to the socket)");
    } else if *errno == Errno::NOENT || *errno == Errno::CONNREFUSED {
        text.push_str(" (no mount daemon listens at the socket)");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sys_error_names_the_step_the_privilege_and_the_log() {
        let err = Error::Sys {
            op: "fsopen erofs",
            errno: Errno::PERM,
            log: None,
        };
        let text = err.to_string();
        assert!(text.starts_with("fsopen erofs: "), "{text}");
        assert!(text.contains("CAP_SYS_ADMIN"), "{text}");

        let err = Error::Sys {
            op: "fsconfig overlay",
            errno: Errno::INVAL,
            log: Some("e overlay: Unknown parameter 'datadir+'".to_owned()),
        };
        let text = err.to_string();
        assert!(!text.contains("CAP_SYS_ADMIN"), "{text}");
        assert!(
            text.ends_with(": e overlay: Unknown parameter 'datadir+'"),
            "{text}"
        );

        let text = Error::sys(ATTACH_STEP, Errno::PERM).to_string();
        assert!(text.contains("/dev/loop-control"), "{text}");
        assert!(!text.contains("CAP_SYS_ADMIN"), "{text}");

        let text = Error::sys("seal memfd", Errno::PERM).to_string();
        assert_eq!(text, format!("seal memfd: {}", Errno::PERM));

        let text = Error::sys("unmount", Errno::PERM).to_string();
        assert!(text.contains("owns the mount namespace"), "{text}");
        assert!(!text.contains("initial user namespace"), "{text}");
    }

    #[test]
    fn a_connect_error_names_the_socket_and_the_cause() {
        let err = Error::Connect {
            path: PathBuf::from("/run/ostrya/mountd.sock"),
            errno: Errno::ACCESS,
        };
        let text = err.to_string();
        assert!(
            text.starts_with("connect to /run/ostrya/mountd.sock: "),
            "{text}"
        );
        assert!(text.contains("write access"), "{text}");
        let err = Error::Connect {
            path: PathBuf::from("/x"),
            errno: Errno::NOENT,
        };
        assert!(err.to_string().contains("no mount daemon"));
    }

    #[test]
    fn each_helper_code_round_trips_on_the_wire() {
        for byte in 0..=u8::MAX {
            assert_eq!(HelperCode::from_wire(byte).to_wire(), byte);
        }
        assert_eq!(HelperCode::from_wire(3), HelperCode::Namespace);
        assert_eq!(HelperCode::from_wire(8), HelperCode::Timeout);
        assert_eq!(HelperCode::Timeout.to_string(), "timeout");
        assert_eq!(HelperCode::from_wire(200), HelperCode::Other(200));
        let err = Error::helper(HelperCode::Namespace, "refused");
        assert_eq!(err.to_string(), "mount daemon: refused (namespace)");
    }

    #[test]
    fn archive_names_its_mode() {
        let text = Error::UnsupportedMode(RepoMode::Archive).to_string();
        assert_eq!(
            text,
            "a repository of the mode archive-z2 cannot be mounted"
        );
    }
}
