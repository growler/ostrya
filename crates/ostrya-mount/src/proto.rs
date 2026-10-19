//! The protocol between the helper client and the mount daemon.
//!
//! The protocol runs over a `SOCK_SEQPACKET` Unix socket, one message for
//! each packet. A connection carries one request:
//!
//! 1. The client sends `Hello`, `[0x01][version]`.
//! 2. The daemon sends `HelloReply`, `[0x02][version]`, or an `Error` if it
//!    does not speak the version of the client.
//! 3. The client sends `Request` with two descriptors in one `SCM_RIGHTS`
//!    message: the user namespace, then the mount namespace.
//! 4. The daemon sends `Mounted`, `[0x04]`, with the descriptor of the
//!    mounted root, or an `Error`.
//! 5. The client closes the connection.
//!
//! `Error` is `[0x05][code][errno: i32 big-endian][text]`. The text is UTF-8
//! and at most [`MAX_STRING`] bytes.
//!
//! The same framing carries the messages between the daemon and its worker
//! process.

use std::io::{IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use ostrya::Checksum;
use rustix::io::Errno;
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};

use crate::error::HelperCode;
use crate::options::Access;

/// The version of the protocol.
pub(crate) const VERSION: u8 = 1;

/// The largest length of a path in a request, and of the text of an error,
/// in bytes.
pub(crate) const MAX_STRING: usize = 4096;

/// The largest length of the source label of a request, in bytes. The kernel
/// takes a string option of a file system of at most this length.
pub(crate) const MAX_LABEL: usize = 255;

/// The kind byte of `Hello`.
pub(crate) const KIND_HELLO: u8 = 0x01;
/// The kind byte of `HelloReply`.
pub(crate) const KIND_HELLO_REPLY: u8 = 0x02;
/// The kind byte of `Request`.
pub(crate) const KIND_REQUEST: u8 = 0x03;
/// The kind byte of `Mounted`.
pub(crate) const KIND_MOUNTED: u8 = 0x04;
/// The kind byte of `Error`.
pub(crate) const KIND_ERROR: u8 = 0x05;

/// The length of the fixed part of a request: the kind, the operation, the
/// access, the commit, and three lengths.
const REQUEST_HEADER: usize = 1 + 1 + 1 + 32 + 2 + 2 + 2;

/// The largest length of a request.
#[cfg(any(feature = "server", test))]
pub(crate) const MAX_REQUEST: usize = REQUEST_HEADER + 2 * MAX_STRING + MAX_LABEL;

/// The length of the fixed part of an error: the kind, the code, and the
/// error number.
const ERROR_HEADER: usize = 1 + 1 + 4;

/// The largest length of an error.
pub(crate) const MAX_ERROR: usize = ERROR_HEADER + MAX_STRING;

/// The number of descriptors of a request.
#[cfg(any(feature = "server", test))]
pub(crate) const REQUEST_FDS: usize = 2;

/// The image that a request mounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Op {
    /// The stored image of the commit, `1`.
    Stored,
    /// An image that the daemon builds in memory, `2`.
    Built,
}

/// The fields of a request. The descriptors go beside the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Request {
    /// The image to mount.
    pub(crate) op: Op,
    /// Read-only or read-write.
    pub(crate) access: Access,
    /// The commit.
    pub(crate) commit: Checksum,
    /// The absolute path of the repository, as the caller sees it.
    pub(crate) repo: PathBuf,
    /// The source label of the mount. An empty label stands for the
    /// checksum of the commit.
    pub(crate) source: String,
    /// The absolute path of the target, as the caller sees it.
    pub(crate) target: PathBuf,
}

/// A failure that an `Error` message carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Failure {
    /// The class of the failure.
    pub(crate) code: HelperCode,
    /// The error number of the failed call, or `0`.
    pub(crate) errno: i32,
    /// The text of the failure.
    pub(crate) text: String,
}

impl Failure {
    /// Returns a failure with no error number.
    #[cfg(any(feature = "server", test))]
    pub(crate) fn new(code: HelperCode, text: impl Into<String>) -> Failure {
        Failure {
            code,
            errno: 0,
            text: text.into(),
        }
    }

    /// Returns a failure of the system call `op` with `errno`.
    #[cfg(feature = "server")]
    pub(crate) fn sys(code: HelperCode, op: &str, errno: Errno) -> Failure {
        Failure {
            code,
            errno: errno.raw_os_error(),
            text: format!("{op}: {errno}"),
        }
    }

    /// Returns the bytes of the `Error` message. A text longer than
    /// [`MAX_STRING`] bytes is cut at a character boundary.
    #[cfg(any(feature = "server", test))]
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut end = self.text.len().min(MAX_STRING);
        while !self.text.is_char_boundary(end) {
            end -= 1;
        }
        let mut out = Vec::with_capacity(ERROR_HEADER + end);
        out.push(KIND_ERROR);
        out.push(self.code.to_wire());
        out.extend_from_slice(&self.errno.to_be_bytes());
        out.extend_from_slice(&self.text.as_bytes()[..end]);
        out
    }

    /// Reads an `Error` message.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Failure, String> {
        if bytes.first() != Some(&KIND_ERROR) {
            return Err("the message is not an error".to_owned());
        }
        if bytes.len() < ERROR_HEADER {
            return Err("the error is shorter than its header".to_owned());
        }
        if bytes.len() > MAX_ERROR {
            return Err("the text of the error is too long".to_owned());
        }
        let errno = i32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        Ok(Failure {
            code: HelperCode::from_wire(bytes[1]),
            errno,
            text: String::from_utf8_lossy(&bytes[ERROR_HEADER..]).into_owned(),
        })
    }

    /// Returns the [`crate::Error::Helper`] of the failure.
    ///
    /// An error number outside the range from 1 to 4095 gives no error
    /// number. The range holds each error number of Linux.
    pub(crate) fn into_error(self) -> crate::Error {
        crate::Error::Helper {
            code: self.code,
            errno: (1..=4095)
                .contains(&self.errno)
                .then(|| Errno::from_raw_os_error(self.errno)),
            message: self.text,
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.text, self.code)
    }
}

/// Returns the bytes of `Hello` or `HelloReply`.
pub(crate) fn encode_hello(kind: u8, version: u8) -> [u8; 2] {
    [kind, version]
}

/// Reads the version of a `Hello` or a `HelloReply` of the kind `kind`.
pub(crate) fn decode_hello(kind: u8, bytes: &[u8]) -> Result<u8, String> {
    match bytes {
        [k, version] if *k == kind => Ok(*version),
        [k, ..] if *k == kind => Err("the hello has a wrong length".to_owned()),
        _ => Err("the message is not a hello".to_owned()),
    }
}

impl Request {
    /// Returns the bytes of the request.
    ///
    /// # Errors
    ///
    /// The text of the refusal if a path is longer than [`MAX_STRING`]
    /// bytes, or if the label is longer than [`MAX_LABEL`] bytes.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, String> {
        let repo = self.repo.as_os_str().as_bytes();
        let source = self.source.as_bytes();
        let target = self.target.as_os_str().as_bytes();
        let mut out = Vec::with_capacity(REQUEST_HEADER + repo.len() + source.len() + target.len());
        out.push(KIND_REQUEST);
        out.push(match self.op {
            Op::Stored => 1,
            Op::Built => 2,
        });
        out.push(match self.access {
            Access::ReadOnly => 0,
            Access::ReadWrite => 1,
        });
        out.extend_from_slice(self.commit.as_bytes());
        for (name, field, max) in [
            ("repository path", repo, MAX_STRING),
            ("source label", source, MAX_LABEL),
            ("target path", target, MAX_STRING),
        ] {
            if field.len() > max {
                return Err(format!("the {name} is longer than {max} bytes"));
            }
            out.extend_from_slice(&(field.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(repo);
        out.extend_from_slice(source);
        out.extend_from_slice(target);
        Ok(out)
    }

    /// Reads a request.
    ///
    /// The call refuses a message of another kind, an unknown operation or
    /// access byte, a path longer than [`MAX_STRING`] bytes, a label longer
    /// than [`MAX_LABEL`] bytes, lengths that do not sum to the length of the
    /// message, a NUL byte, an empty or relative path, and a label that is
    /// not UTF-8.
    #[cfg(any(feature = "server", test))]
    pub(crate) fn decode(bytes: &[u8]) -> Result<Request, String> {
        if bytes.first() != Some(&KIND_REQUEST) {
            return Err("the message is not a request".to_owned());
        }
        if bytes.len() < REQUEST_HEADER {
            return Err("the request is shorter than its header".to_owned());
        }
        let op = match bytes[1] {
            1 => Op::Stored,
            2 => Op::Built,
            other => return Err(format!("unknown operation {other}")),
        };
        let access = match bytes[2] {
            0 => Access::ReadOnly,
            1 => Access::ReadWrite,
            other => return Err(format!("unknown access {other}")),
        };
        let mut commit = [0u8; 32];
        commit.copy_from_slice(&bytes[3..35]);
        let len = |at: usize| usize::from(u16::from_be_bytes([bytes[at], bytes[at + 1]]));
        let (repo_len, source_len, target_len) = (len(35), len(37), len(39));
        if repo_len > MAX_STRING || target_len > MAX_STRING {
            return Err(format!("a path is longer than {MAX_STRING} bytes"));
        }
        if source_len > MAX_LABEL {
            return Err(format!("the source label is longer than {MAX_LABEL} bytes"));
        }
        if REQUEST_HEADER + repo_len + source_len + target_len != bytes.len() {
            return Err("the lengths of the fields do not match the request".to_owned());
        }
        let body = &bytes[REQUEST_HEADER..];
        let (repo, rest) = body.split_at(repo_len);
        let (source, target) = rest.split_at(source_len);
        if [repo, source, target].iter().any(|f| f.contains(&0)) {
            return Err("a field holds a NUL byte".to_owned());
        }
        let path = |name: &str, raw: &[u8]| -> Result<PathBuf, String> {
            let path = std::path::Path::new(std::ffi::OsStr::from_bytes(raw));
            if !path.is_absolute() {
                return Err(format!("the {name} is not an absolute path"));
            }
            Ok(path.to_owned())
        };
        Ok(Request {
            op,
            access,
            commit: Checksum::from_bytes(commit),
            repo: path("repository path", repo)?,
            source: String::from_utf8(source.to_vec())
                .map_err(|_| "the source label is not UTF-8".to_owned())?,
            target: path("target path", target)?,
        })
    }

    /// Returns the source label of the mount: the label of the request, or
    /// the checksum of the commit if the label is empty.
    #[cfg(any(feature = "server", test))]
    pub(crate) fn label(&self) -> String {
        if self.source.is_empty() {
            self.commit.to_hex()
        } else {
            self.source.clone()
        }
    }
}

/// A message that [`recv`] reads.
#[derive(Debug)]
pub(crate) struct Message {
    /// The bytes of the message.
    pub(crate) bytes: Vec<u8>,
    /// The descriptors that came with the message, in order.
    pub(crate) fds: Vec<OwnedFd>,
}

/// An error of [`send`] or [`recv`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WireError {
    /// The system call failed. `EAGAIN` is the end of a receive timeout.
    Sys(&'static str, Errno),
    /// The peer closed the connection.
    Closed,
    /// The message breaks the framing: it is longer than the reader
    /// allows, or it carries more descriptors.
    Protocol(String),
}

impl WireError {
    /// Returns the failure that the daemon reports for the error.
    #[cfg(feature = "server")]
    pub(crate) fn into_failure(self) -> Failure {
        match self {
            WireError::Sys(op, Errno::AGAIN) => {
                Failure::new(HelperCode::Timeout, format!("{op}: no message in time"))
            }
            WireError::Sys(op, errno) => Failure::sys(HelperCode::Internal, op, errno),
            WireError::Closed => {
                Failure::new(HelperCode::Protocol, "the peer closed the connection")
            }
            WireError::Protocol(text) => Failure::new(HelperCode::Protocol, text),
        }
    }

    /// Returns the error of the helper client for the error.
    pub(crate) fn into_error(self) -> crate::Error {
        match self {
            WireError::Sys(op, errno) => crate::Error::sys(op, errno),
            WireError::Closed => crate::Error::helper(
                HelperCode::Protocol,
                "the daemon closed the connection with no reply",
            ),
            WireError::Protocol(text) => crate::Error::helper(HelperCode::Protocol, text),
        }
    }
}

/// Sends `bytes` as one message on `sock`, with the descriptors `fds` in one
/// `SCM_RIGHTS` message.
pub(crate) fn send(
    sock: BorrowedFd<'_>,
    bytes: &[u8],
    fds: &[BorrowedFd<'_>],
) -> Result<(), WireError> {
    let mut space = vec![MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(fds.len()))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !fds.is_empty() && !ancillary.push(SendAncillaryMessage::ScmRights(fds)) {
        return Err(WireError::Sys("sendmsg", Errno::NOBUFS));
    }
    let sent = sendmsg(
        sock,
        &[IoSlice::new(bytes)],
        &mut ancillary,
        SendFlags::NOSIGNAL,
    )
    .map_err(|e| WireError::Sys("sendmsg", e))?;
    if sent != bytes.len() {
        return Err(WireError::Sys("sendmsg", Errno::MSGSIZE));
    }
    Ok(())
}

/// Receives one message of at most `max_len` bytes with at most `max_fds`
/// descriptors from `sock`.
///
/// Each received descriptor has the close-on-exec flag. The call refuses a
/// message that the kernel truncated, a longer message, and a message with
/// more descriptors. An end of file gives [`WireError::Closed`].
pub(crate) fn recv(
    sock: BorrowedFd<'_>,
    max_len: usize,
    max_fds: usize,
) -> Result<Message, WireError> {
    // One byte more than the largest message, and space for one descriptor
    // more, so that a longer message and an extra descriptor show.
    let mut buf = vec![0u8; max_len + 1];
    let mut space = vec![MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(max_fds + 1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let msg = recvmsg(
        sock,
        &mut [IoSliceMut::new(&mut buf)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )
    .map_err(|e| WireError::Sys("recvmsg", e))?;
    let fds: Vec<OwnedFd> = ancillary
        .drain()
        .filter_map(|m| match m {
            RecvAncillaryMessage::ScmRights(fds) => Some(fds),
            _ => None,
        })
        .flatten()
        .collect();
    if msg
        .flags
        .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
    {
        return Err(WireError::Protocol("the message was truncated".to_owned()));
    }
    if msg.bytes == 0 && fds.is_empty() {
        return Err(WireError::Closed);
    }
    if msg.bytes > max_len {
        return Err(WireError::Protocol("the message is too long".to_owned()));
    }
    if fds.len() > max_fds {
        return Err(WireError::Protocol(
            "the message carries too many descriptors".to_owned(),
        ));
    }
    buf.truncate(msg.bytes);
    Ok(Message { bytes: buf, fds })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};

    fn request() -> Request {
        Request {
            op: Op::Built,
            access: Access::ReadWrite,
            commit: Checksum::from_bytes([7; 32]),
            repo: PathBuf::from("/srv/repo"),
            source: "label".to_owned(),
            target: PathBuf::from("/mnt/os"),
        }
    }

    fn pair() -> (OwnedFd, OwnedFd) {
        socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap()
    }

    #[test]
    fn a_request_round_trips() {
        let req = request();
        let bytes = req.encode().unwrap();
        assert_eq!(bytes[0], KIND_REQUEST);
        assert_eq!(&bytes[1..3], &[2, 1]);
        assert_eq!(&bytes[35..41], &[0, 9, 0, 5, 0, 7]);
        assert_eq!(&bytes[41..], b"/srv/repolabel/mnt/os");
        assert_eq!(Request::decode(&bytes).unwrap(), req);

        let mut stored = request();
        stored.op = Op::Stored;
        stored.access = Access::ReadOnly;
        stored.source = String::new();
        let bytes = stored.encode().unwrap();
        assert_eq!(&bytes[1..3], &[1, 0]);
        let back = Request::decode(&bytes).unwrap();
        assert_eq!(back, stored);
        assert_eq!(back.label(), stored.commit.to_hex());
    }

    #[test]
    fn a_long_field_is_refused_on_both_sides() {
        let mut req = request();
        req.source = "x".repeat(MAX_LABEL);
        let bytes = req.encode().unwrap();
        assert_eq!(Request::decode(&bytes).unwrap(), req);
        req.source.push('x');
        assert!(req.encode().unwrap_err().contains("source label"));

        let mut req = request();
        req.target = PathBuf::from(format!("/{}", "t".repeat(MAX_STRING - 1)));
        let bytes = req.encode().unwrap();
        assert_eq!(bytes.len(), REQUEST_HEADER + 9 + 5 + MAX_STRING);
        req.target.as_mut_os_string().push("t");
        assert!(req.encode().unwrap_err().contains("target path"));

        let mut req = request();
        req.source = "x".repeat(MAX_LABEL + 1);
        let mut bytes = request().encode().unwrap();
        bytes.truncate(REQUEST_HEADER);
        bytes[37..39].copy_from_slice(&((MAX_LABEL + 1) as u16).to_be_bytes());
        bytes.extend_from_slice(b"/srv/repo");
        bytes.extend_from_slice(req.source.as_bytes());
        bytes.extend_from_slice(b"/mnt/os");
        assert!(
            Request::decode(&bytes)
                .unwrap_err()
                .contains("source label is longer than 255")
        );

        let mut bytes = request().encode().unwrap();
        bytes[35..37].copy_from_slice(&((MAX_STRING + 1) as u16).to_be_bytes());
        assert!(Request::decode(&bytes).unwrap_err().contains("longer than"));
    }

    #[test]
    fn an_error_number_out_of_range_gives_none() {
        for errno in [-1, 0, 4096, i32::MAX, i32::MIN] {
            let failure = Failure {
                code: HelperCode::Mount,
                errno,
                text: "x".to_owned(),
            };
            match failure.into_error() {
                crate::Error::Helper { errno: None, .. } => {}
                other => panic!("{errno}: {other:?}"),
            }
        }
        let failure = Failure {
            code: HelperCode::Mount,
            errno: 4095,
            text: "x".to_owned(),
        };
        assert!(matches!(
            failure.into_error(),
            crate::Error::Helper { errno: Some(_), .. }
        ));
    }

    #[test]
    fn each_malformed_request_is_refused() {
        let good = request().encode().unwrap();
        let refuse = |bytes: &[u8], what: &str| {
            let err = Request::decode(bytes).unwrap_err();
            assert!(err.contains(what), "{err}");
        };
        let mut b = good.clone();
        b[0] = KIND_HELLO;
        refuse(&b, "not a request");
        refuse(&good[..REQUEST_HEADER - 1], "shorter than its header");
        let mut b = good.clone();
        b[1] = 3;
        refuse(&b, "unknown operation");
        let mut b = good.clone();
        b[2] = 2;
        refuse(&b, "unknown access");
        refuse(&good[..good.len() - 1], "do not match");
        let mut b = good.clone();
        b.push(b'x');
        refuse(&b, "do not match");
        let mut b = good.clone();
        b[REQUEST_HEADER + 1] = 0;
        refuse(&b, "NUL");
        let mut b = good.clone();
        b[REQUEST_HEADER] = b'x';
        refuse(&b, "repository path is not an absolute path");
        let mut req = request();
        req.target = PathBuf::from("mnt");
        refuse(
            &req.encode().unwrap(),
            "target path is not an absolute path",
        );
        let mut b = good.clone();
        b[REQUEST_HEADER + 9] = 0xff;
        refuse(&b, "not UTF-8");
    }

    #[test]
    fn a_hello_round_trips_and_a_wrong_one_is_refused() {
        let hello = encode_hello(KIND_HELLO, VERSION);
        assert_eq!(hello, [0x01, 0x01]);
        assert_eq!(decode_hello(KIND_HELLO, &hello), Ok(VERSION));
        assert_eq!(decode_hello(KIND_HELLO_REPLY, &[0x02, 9]), Ok(9));
        assert!(decode_hello(KIND_HELLO, &[0x03, 1]).is_err());
        assert!(decode_hello(KIND_HELLO, &[0x01]).is_err());
        assert!(decode_hello(KIND_HELLO, &[0x01, 1, 1]).is_err());
        assert!(decode_hello(KIND_HELLO, &[]).is_err());
    }

    #[test]
    fn an_error_round_trips_and_a_long_text_is_cut() {
        let failure = Failure {
            code: HelperCode::Namespace,
            errno: Errno::PERM.raw_os_error(),
            text: "refused".to_owned(),
        };
        let bytes = failure.encode();
        assert_eq!(&bytes[..6], &[0x05, 3, 0, 0, 0, 1]);
        assert_eq!(Failure::decode(&bytes).unwrap(), failure);

        let long = Failure::new(HelperCode::Mount, "\u{e9}".repeat(MAX_STRING));
        let bytes = long.encode();
        assert!(bytes.len() <= MAX_ERROR);
        let back = Failure::decode(&bytes).unwrap();
        assert_eq!(back.text.len(), MAX_STRING);
        assert!(Failure::decode(&[0x05, 1, 0]).is_err());
        assert!(Failure::decode(&[0x04]).is_err());

        let err = failure.into_error();
        assert!(matches!(
            err,
            crate::Error::Helper {
                code: HelperCode::Namespace,
                errno: Some(Errno::PERM),
                ..
            }
        ));
    }

    #[test]
    fn descriptors_go_with_a_message() {
        let (a, b) = pair();
        let (x, _y) = pair();
        send(a.as_fd(), b"abc", &[x.as_fd(), b.as_fd()]).unwrap();
        let msg = recv(b.as_fd(), 16, 2).unwrap();
        assert_eq!(msg.bytes, b"abc");
        assert_eq!(msg.fds.len(), 2);
        let flags = rustix::io::fcntl_getfd(&msg.fds[0]).unwrap();
        assert!(flags.contains(rustix::io::FdFlags::CLOEXEC));
    }

    #[test]
    fn a_long_message_and_extra_descriptors_are_refused() {
        let (a, b) = pair();
        send(a.as_fd(), &[0u8; 17], &[]).unwrap();
        assert!(matches!(
            recv(b.as_fd(), 16, 0),
            Err(WireError::Protocol(_))
        ));

        let (x, _y) = pair();
        send(a.as_fd(), b"m", &[x.as_fd(), x.as_fd(), x.as_fd()]).unwrap();
        assert!(matches!(
            recv(b.as_fd(), 16, 2),
            Err(WireError::Protocol(_))
        ));

        drop(a);
        assert_eq!(recv(b.as_fd(), 16, 2).unwrap_err(), WireError::Closed);
    }
}
