//! The helper client, for a caller in its own user namespace.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};

use ostrya_core::Checksum;
use rustix::fs::{CWD, Mode, OFlags, openat};
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with};

use crate::error::{Error, HelperCode, Result};
use crate::options::MountOptions;
use crate::proto::{
    self, Failure, KIND_ERROR, KIND_HELLO, KIND_HELLO_REPLY, KIND_MOUNTED, MAX_ERROR, Op, Request,
    VERSION,
};
use crate::sys::unmount_overlay;

/// The path of the socket of the mount daemon.
pub const DEFAULT_SOCKET: &str = "/run/ostrya/mountd.sock";

/// The environment variable that gives another path of the socket.
pub const SOCKET_ENV: &str = "OSTRYA_MOUNTD_SOCKET";

/// The mounter that asks the mount daemon, `ostrya-mountd`, for each mount.
///
/// The client serves a caller without `CAP_SYS_ADMIN` in the initial user
/// namespace, for example a user in its own user namespace. The daemon runs
/// as root. It makes the mount for the caller and moves it onto the target
/// in the mount namespace that the client sends. The client sends a user
/// namespace and a mount namespace with each request. The daemon refuses the
/// initial user namespace, so a root caller on the host uses
/// [`Direct`](crate::Direct).
///
/// Each mount of the daemon has `nosuid` and `nodev`. The EROFS layer takes
/// the ID mapping of the user namespace of the request, so the files that
/// the image gives to user 0 show as the user 0 of that namespace. The
/// daemon mounts the top overlay inside the user namespace, as its user 0,
/// with the `userxattr` option. The top overlay is read-only, or for
/// [`Access::ReadWrite`](crate::Access) has the upper directory. For a
/// read-write mount, that user must be able to write `<target>`.
///
/// The daemon refuses a target or a repository on FUSE, and an `objects`
/// directory that is the root of a mount or that is on another mount than
/// the repository directory. A request has 60 seconds in the daemon.
///
/// If the target already carries the mount of a request, with the same
/// source label and the same access, the daemon mounts nothing and returns
/// the root of that mount.
///
/// The client opens no repository. A mount call blocks the calling thread
/// until the daemon replies, and the unmount blocks the calling thread too.
/// A caller on an async runtime runs these calls on the blocking pool of the
/// runtime.
///
/// # Socket
///
/// The socket is [`DEFAULT_SOCKET`]. The environment variable [`SOCKET_ENV`]
/// gives another path, except for a caller that is root in the initial user
/// namespace, and for a process whose real user or group id is not its
/// effective one, such as a setuid program. Each call connects again, sends
/// one request, and closes the connection.
#[derive(Debug)]
pub struct Helper {
    /// The path of the socket.
    socket: PathBuf,
    /// The user namespace that each request sends. The calls share the
    /// descriptor and duplicate it for no request.
    userns: OwnedFd,
    /// The mount namespace that each request sends.
    mntns: OwnedFd,
}

impl Helper {
    /// Returns a client that sends the user namespace and the mount
    /// namespace of the calling thread.
    ///
    /// The call opens `/proc/thread-self/ns/user` and
    /// `/proc/thread-self/ns/mnt`. It does not connect.
    ///
    /// # Errors
    ///
    /// [`Error::Sys`] if a namespace file does not open.
    pub fn new() -> Result<Helper> {
        let open = |name: &'static str| {
            openat(
                CWD,
                format!("/proc/thread-self/ns/{name}"),
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| Error::sys(name_op(name), e))
        };
        Ok(Helper::with_namespaces(open("user")?, open("mnt")?))
    }

    /// Returns a client that sends the user namespace `userns` and the mount
    /// namespace `mntns`, for example the namespaces of another process.
    ///
    /// The daemon checks that `userns` owns `mntns`, and that `userns` is not
    /// the initial user namespace. It does not check that the caller is a
    /// member of the two namespaces.
    pub fn with_namespaces(userns: OwnedFd, mntns: OwnedFd) -> Helper {
        Helper {
            socket: socket_path(),
            userns,
            mntns,
        }
    }

    /// Returns the path of the socket that the client connects to.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Mounts the stored composefs image of `commit` at `target` through the
    /// daemon.
    ///
    /// The daemon opens the image and compares its digest with the key
    /// `ostree.composefs.digest.v0` of the commit. It does not check a
    /// signature of the commit.
    ///
    /// `repo` is the path of the repository directory, and `target` is the
    /// path of the target directory. Both paths must be absolute, as the
    /// caller sees them. The client does not open the repository and does
    /// not read the commit. The daemon opens the repository directory and its
    /// `objects` directory with the user, the group, and the supplementary
    /// groups of the caller.
    ///
    /// Returns a descriptor of the root of the new mount. The descriptor
    /// keeps the mount in use, so close it before [`Helper::unmount`].
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidRequest`] if a path is relative, if a path is longer
    ///   than 4096 bytes, if the source label is longer than 255 bytes, or if
    ///   [`MountOptions::flags`] holds `noexec`. The daemon sets `nosuid` and
    ///   `nodev` on each mount and cannot set `noexec`.
    /// - [`Error::Connect`] if the client cannot connect to the socket.
    /// - [`Error::Helper`] with the refusal or the failure that the daemon
    ///   reports.
    /// - [`Error::Sys`] if a send or a receive on the socket fails.
    pub fn mount_stored(
        &self,
        repo: &Path,
        commit: &Checksum,
        target: &Path,
        opts: &MountOptions,
    ) -> Result<OwnedFd> {
        self.request(Op::Stored, repo, commit, target, opts)
    }

    /// Builds the composefs image of `commit` and mounts it at `target`
    /// through the daemon.
    ///
    /// The daemon needs no stored image and no key in the commit. It writes
    /// the image to a sealed memory file and attaches the file to the loop
    /// device. With `[ex-integrity] fsverity=yes`, the image carries the
    /// fs-verity digest that the kernel holds for each backing object, and a
    /// backing object with no fs-verity seal fails the request. The memory
    /// of the image counts against the memory cgroup of the daemon until
    /// the unmount.
    ///
    /// Returns a descriptor of the root of the new mount. The descriptor
    /// keeps the mount in use, so close it before [`Helper::unmount`].
    ///
    /// # Errors
    ///
    /// The errors of [`Helper::mount_stored`].
    pub fn mount_built(
        &self,
        repo: &Path,
        commit: &Checksum,
        target: &Path,
        opts: &MountOptions,
    ) -> Result<OwnedFd> {
        self.request(Op::Built, repo, commit, target, opts)
    }

    /// Unmounts the composefs mount at `target`.
    ///
    /// The unmount runs in the process of the caller, with no request to
    /// the daemon. The process needs `CAP_SYS_ADMIN` in the user namespace
    /// that owns its mount namespace. The call refuses a target that is not
    /// the root of an overlay mount, as [`Direct::unmount`](crate::Direct::unmount)
    /// does. The call blocks the calling thread.
    ///
    /// # Errors
    ///
    /// - [`Error::NotOverlayMount`] if `target` is not the root of an overlay
    ///   mount.
    /// - [`Error::Sys`] with `EBUSY` if a process still uses the mount, and
    ///   [`Error::Sys`] if another call fails.
    pub fn unmount(&self, target: &Path) -> Result<()> {
        unmount_overlay(target)
    }

    /// Runs the exchange of `request` on the connected socket `sock`: the
    /// hello, the request with the namespaces of the client, and the reply.
    ///
    /// `sock` is a `SOCK_SEQPACKET` socket whose peer speaks the protocol of
    /// the daemon. The call blocks the calling thread, and it does not close
    /// the socket. The mount calls of the client connect to [`Helper::socket`]
    /// and run this exchange.
    ///
    /// Returns the descriptor of the root of the mount that the peer sends.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidRequest`] if a path of `request` is longer than 4096
    ///   bytes, or if its source label is longer than 255 bytes.
    /// - [`Error::Helper`] with the refusal or the failure that the peer
    ///   reports, or if a reply breaks the protocol.
    /// - [`Error::Sys`] if a send or a receive on the socket fails.
    pub fn exchange(&self, sock: BorrowedFd<'_>, request: &Request) -> Result<OwnedFd> {
        let bytes = request.encode().map_err(Error::InvalidRequest)?;
        exchange(sock, &bytes, self.userns.as_fd(), self.mntns.as_fd())
    }

    /// Sends one request and returns the root of the mount.
    fn request(
        &self,
        op: Op,
        repo: &Path,
        commit: &Checksum,
        target: &Path,
        opts: &MountOptions,
    ) -> Result<OwnedFd> {
        if opts.flags.noexec {
            return Err(Error::InvalidRequest(
                "the mount daemon cannot set the mount flag noexec".to_owned(),
            ));
        }
        for (name, path) in [("repository", repo), ("target", target)] {
            if !path.is_absolute() {
                return Err(Error::InvalidRequest(format!(
                    "the {name} path {} is not absolute",
                    path.display()
                )));
            }
        }
        let request = Request {
            op,
            access: opts.access,
            commit: *commit,
            repo: repo.to_owned(),
            source: opts.source.clone().unwrap_or_default(),
            target: target.to_owned(),
        };
        let bytes = request.encode().map_err(Error::InvalidRequest)?;
        let sock = connect_to(&self.socket)?;
        exchange(
            sock.as_fd(),
            &bytes,
            self.userns.as_fd(),
            self.mntns.as_fd(),
        )
    }
}

/// Returns the name of the open of the namespace file `name`.
fn name_op(name: &str) -> &'static str {
    match name {
        "user" => "open user namespace",
        _ => "open mount namespace",
    }
}

/// Returns the path of the socket for the process: [`DEFAULT_SOCKET`], or
/// the value of [`SOCKET_ENV`].
///
/// The process reads the variable only if it is not root in the initial
/// user namespace and runs with its real ids as its effective ids. A setuid
/// or setgid program does not read it.
fn socket_path() -> PathBuf {
    let trusted = !crate::privilege::is_privileged() && crate::privilege::ids_match();
    let from_env = trusted
        .then(|| std::env::var_os(SOCKET_ENV))
        .flatten()
        .filter(|p| !p.is_empty());
    from_env.map_or_else(|| PathBuf::from(DEFAULT_SOCKET), PathBuf::from)
}

/// Connects a new `SOCK_SEQPACKET` socket to `path`.
fn connect_to(path: &Path) -> Result<OwnedFd> {
    let sock = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|e| Error::sys("socket", e))?;
    let addr = SocketAddrUnix::new(path).map_err(|errno| Error::Connect {
        path: path.to_owned(),
        errno,
    })?;
    connect(&sock, &addr).map_err(|errno| Error::Connect {
        path: path.to_owned(),
        errno,
    })?;
    Ok(sock)
}

/// Runs the exchange of one request on the connected socket `sock`: the
/// hello, the request `request` with the namespaces, and the reply.
fn exchange(
    sock: BorrowedFd<'_>,
    request: &[u8],
    userns: BorrowedFd<'_>,
    mntns: BorrowedFd<'_>,
) -> Result<OwnedFd> {
    let wire = |e: proto::WireError| e.into_error();
    proto::send(sock, &proto::encode_hello(KIND_HELLO, VERSION), &[]).map_err(wire)?;
    let reply = proto::recv(sock, MAX_ERROR, 0).map_err(wire)?;
    if reply.bytes.first() == Some(&KIND_ERROR) {
        return Err(failure(&reply.bytes));
    }
    let version = proto::decode_hello(KIND_HELLO_REPLY, &reply.bytes)
        .map_err(|text| Error::helper(HelperCode::Protocol, text))?;
    if version != VERSION {
        return Err(Error::helper(
            HelperCode::Version,
            format!("the daemon speaks version {version} of the protocol, the client {VERSION}"),
        ));
    }
    proto::send(sock, request, &[userns, mntns]).map_err(wire)?;
    let mut reply = proto::recv(sock, MAX_ERROR, 1).map_err(wire)?;
    match reply.bytes.first() {
        Some(&KIND_MOUNTED) if reply.bytes.len() == 1 && reply.fds.len() == 1 => {
            Ok(reply.fds.remove(0))
        }
        Some(&KIND_MOUNTED) => Err(Error::helper(
            HelperCode::Protocol,
            "the reply of the daemon is malformed",
        )),
        Some(&KIND_ERROR) if !reply.fds.is_empty() => Err(Error::helper(
            HelperCode::Protocol,
            "the error of the daemon carries descriptors",
        )),
        Some(&KIND_ERROR) => Err(failure(&reply.bytes)),
        _ => Err(Error::helper(
            HelperCode::Protocol,
            "the reply of the daemon has an unknown kind",
        )),
    }
}

/// Returns the error of the `Error` message `bytes`.
fn failure(bytes: &[u8]) -> Error {
    match Failure::decode(bytes) {
        Ok(failure) => failure.into_error(),
        Err(text) => Error::helper(HelperCode::Protocol, text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use std::path::PathBuf;

    use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};

    use crate::options::Access;
    use crate::proto::{KIND_REQUEST, MAX_REQUEST, REQUEST_FDS};

    fn pair() -> (OwnedFd, OwnedFd) {
        socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap()
    }

    fn own_ns(name: &str) -> OwnedFd {
        openat(
            CWD,
            format!("/proc/thread-self/ns/{name}"),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    fn request_bytes() -> Vec<u8> {
        Request {
            op: Op::Stored,
            access: Access::ReadOnly,
            commit: Checksum::from_bytes([1; 32]),
            repo: PathBuf::from("/srv/repo"),
            source: String::new(),
            target: PathBuf::from("/mnt"),
        }
        .encode()
        .unwrap()
    }

    /// Runs `server` on one end of a socket pair and the exchange on the
    /// other end.
    fn run(server: impl FnOnce(OwnedFd) + Send + 'static) -> Result<OwnedFd> {
        let (client, daemon) = pair();
        let thread = std::thread::spawn(move || server(daemon));
        let result = exchange(
            client.as_fd(),
            &request_bytes(),
            own_ns("user").as_fd(),
            own_ns("mnt").as_fd(),
        );
        drop(client);
        thread.join().unwrap();
        result
    }

    #[test]
    fn a_mounted_reply_gives_the_root() {
        let root = run(|sock| {
            let hello = proto::recv(sock.as_fd(), 2, 0).unwrap();
            assert_eq!(proto::decode_hello(KIND_HELLO, &hello.bytes), Ok(VERSION));
            proto::send(
                sock.as_fd(),
                &proto::encode_hello(KIND_HELLO_REPLY, VERSION),
                &[],
            )
            .unwrap();
            let req = proto::recv(sock.as_fd(), MAX_REQUEST, REQUEST_FDS).unwrap();
            assert_eq!(req.bytes[0], KIND_REQUEST);
            assert_eq!(req.fds.len(), 2);
            let dir = std::fs::File::open("/").unwrap();
            proto::send(sock.as_fd(), &[KIND_MOUNTED], &[dir.as_fd()]).unwrap();
            assert!(proto::recv(sock.as_fd(), 1, 0).is_err());
        })
        .unwrap();
        let st = rustix::fs::fstat(&root).unwrap();
        assert_eq!(st.st_ino, rustix::fs::stat("/").unwrap().st_ino);
    }

    #[test]
    fn a_daemon_of_another_version_is_refused() {
        let err = run(|sock| {
            proto::recv(sock.as_fd(), 2, 0).unwrap();
            proto::send(sock.as_fd(), &proto::encode_hello(KIND_HELLO_REPLY, 2), &[]).unwrap();
            let _ = proto::recv(sock.as_fd(), MAX_REQUEST, REQUEST_FDS);
        })
        .unwrap_err();
        assert!(
            matches!(
                err,
                Error::Helper {
                    code: HelperCode::Version,
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn a_refused_hello_gives_the_failure_of_the_daemon() {
        let err = run(|sock| {
            proto::recv(sock.as_fd(), 2, 0).unwrap();
            let failure = Failure::new(HelperCode::Version, "the daemon speaks version 1");
            proto::send(sock.as_fd(), &failure.encode(), &[]).unwrap();
        })
        .unwrap_err();
        match err {
            Error::Helper {
                code: HelperCode::Version,
                errno: None,
                message,
            } => assert_eq!(message, "the daemon speaks version 1"),
            other => panic!("{other}"),
        }
    }

    #[test]
    fn a_closed_connection_and_a_malformed_reply_are_protocol_errors() {
        let err = run(|sock| {
            proto::recv(sock.as_fd(), 2, 0).unwrap();
        })
        .unwrap_err();
        assert!(
            matches!(
                err,
                Error::Helper {
                    code: HelperCode::Protocol,
                    ..
                }
            ),
            "{err}"
        );

        let err = run(|sock| {
            proto::recv(sock.as_fd(), 2, 0).unwrap();
            proto::send(
                sock.as_fd(),
                &proto::encode_hello(KIND_HELLO_REPLY, VERSION),
                &[],
            )
            .unwrap();
            proto::recv(sock.as_fd(), MAX_REQUEST, REQUEST_FDS).unwrap();
            proto::send(sock.as_fd(), &[KIND_MOUNTED], &[]).unwrap();
        })
        .unwrap_err();
        assert!(
            matches!(
                err,
                Error::Helper {
                    code: HelperCode::Protocol,
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn an_error_with_a_descriptor_is_refused() {
        let err = run(|sock| {
            proto::recv(sock.as_fd(), 2, 0).unwrap();
            proto::send(
                sock.as_fd(),
                &proto::encode_hello(KIND_HELLO_REPLY, VERSION),
                &[],
            )
            .unwrap();
            proto::recv(sock.as_fd(), MAX_REQUEST, REQUEST_FDS).unwrap();
            let failure = Failure::new(HelperCode::Mount, "refused");
            let dir = std::fs::File::open("/").unwrap();
            proto::send(sock.as_fd(), &failure.encode(), &[dir.as_fd()]).unwrap();
        })
        .unwrap_err();
        match err {
            Error::Helper {
                code: HelperCode::Protocol,
                message,
                ..
            } => assert!(message.contains("carries descriptors"), "{message}"),
            other => panic!("{other}"),
        }
    }

    fn test_helper() -> Helper {
        Helper {
            socket: PathBuf::from("/nonexistent/socket"),
            userns: own_ns("user"),
            mntns: own_ns("mnt"),
        }
    }

    #[test]
    fn a_relative_path_is_refused_before_the_connect() {
        let helper = test_helper();
        let commit = Checksum::from_bytes([0; 32]);
        let opts = MountOptions::default();
        let repo = Path::new("/srv/repo");
        let err = helper
            .mount_stored(repo, &commit, Path::new("mnt"), &opts)
            .unwrap_err();
        assert!(matches!(err, Error::InvalidRequest(_)), "{err}");
        let err = helper
            .mount_built(Path::new("repo"), &commit, Path::new("/mnt"), &opts)
            .unwrap_err();
        assert!(
            matches!(&err, Error::InvalidRequest(text) if text.contains("repository")),
            "{err}"
        );
        let err = helper
            .mount_built(repo, &commit, Path::new("/mnt"), &opts)
            .unwrap_err();
        assert!(
            matches!(
                err,
                Error::Connect {
                    errno: rustix::io::Errno::NOENT,
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn noexec_is_refused_before_the_connect() {
        let helper = test_helper();
        let commit = Checksum::from_bytes([0; 32]);
        let repo = Path::new("/srv/repo");
        let target = Path::new("/mnt");

        let mut opts = MountOptions::default();
        opts.flags.noexec = true;
        let err = helper
            .mount_stored(repo, &commit, target, &opts)
            .unwrap_err();
        assert!(
            matches!(&err, Error::InvalidRequest(text) if text.contains("noexec")),
            "{err}"
        );
        let err = helper
            .mount_built(repo, &commit, target, &opts)
            .unwrap_err();
        assert!(
            matches!(&err, Error::InvalidRequest(text) if text.contains("noexec")),
            "{err}"
        );

        // The daemon sets these two flags itself, so the request goes to the
        // connect.
        let mut opts = MountOptions::default();
        opts.flags.nosuid = true;
        opts.flags.nodev = true;
        let err = helper
            .mount_stored(repo, &commit, target, &opts)
            .unwrap_err();
        assert!(
            matches!(
                err,
                Error::Connect {
                    errno: rustix::io::Errno::NOENT,
                    ..
                }
            ),
            "{err}"
        );
    }
}
