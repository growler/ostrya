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
}

/// The steps whose `EPERM` comes from a missing privilege of the process,
/// as prefixes of the step name.
const MOUNT_STEPS: [&str; 5] = ["fsopen", "fsconfig", "fsmount", "move_mount", "unmount"];

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
