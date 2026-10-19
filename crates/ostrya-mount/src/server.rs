//! The mount daemon: the handler of one connection, and the worker process
//! of one request.
//!
//! `ostrya-mountd` is the one user of this module. Its items are not a
//! stable API.
//!
//! The handler runs in the daemon process, on the runtime. It reads the
//! request, checks the namespaces, opens the repository, checks or builds
//! the image, and mounts the EROFS layer and the composefs overlay in the
//! mount namespace of the daemon. A worker process does each step that
//! changes the namespaces or the ids of a process: it enters the mount
//! namespace of the caller, opens the repository and the target as the
//! caller, enters the user namespace of the caller, mounts the top overlay
//! there, and moves it onto the target. The top overlay is read-only, or
//! read-write with an upper directory.
//!
//! One connection has 60 seconds, from the accept to the reply. At that
//! time the handler kills the worker and replies with an error.
//!
//! The worker is a process of its own, the daemon binary run again, because
//! the kernel refuses `setns(CLONE_NEWUSER)` in a process with more than one
//! thread, and a process that enters a user namespace cannot go back to its
//! parent namespace. The worker exits after one request.

use std::ffi::OsString;
use std::future::Future;
use std::io::{BufRead, BufReader, Read};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

use ostrya::Repo;
use rustix::fs::{
    AtFlags, CWD, Mode, OFlags, StatxAttributes, StatxFlags, fstat, fstatfs, openat, statx,
};
use rustix::io::Errno;
use rustix::mount::{MountAttrFlags, OpenTreeFlags, open_tree};
use rustix::net::sockopt::{Timeout, set_socket_timeout, socket_peercred};
use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};
use rustix::thread::{
    Gid, LinkNameSpaceType, Uid, move_into_link_name_space, set_thread_groups, set_thread_res_gid,
    set_thread_res_uid,
};

use crate::direct::{RepoPlan, build_image};
use crate::error::{Error, HelperCode};
use crate::options::Access;
use crate::proto::{
    self, Failure, KIND_ERROR, KIND_HELLO, KIND_HELLO_REPLY, KIND_MOUNTED, MAX_ERROR, MAX_REQUEST,
    Message, Op, REQUEST_FDS, Request, VERSION, WireError,
};
use crate::sys::{
    LayerRef, Layout, OVERLAYFS_SUPER_MAGIC, Plan, UpperOptions, build_composefs, move_onto,
    open_dir, top_overlay,
};

/// The time that one connection can take, from the accept to the reply. The
/// time covers the messages of the client, the worker process, and the work
/// on the repository.
const DEADLINE: Duration = Duration::from_secs(60);

/// The largest number of supplementary groups of a caller.
const MAX_GROUPS: usize = 4096;

/// The `f_type` that `statfs` reports for a FUSE file system.
const FUSE_SUPER_MAGIC: u64 = 0x6573_5546;

/// The longest line of `/proc/self/mountinfo` that the remount check reads,
/// in bytes. The check skips a longer line.
const MAX_MOUNTINFO_LINE: u64 = 64 * 1024;

/// The attribute flags of each mount of the daemon.
const DAEMON_ATTRS: MountAttrFlags =
    MountAttrFlags::MOUNT_ATTR_NOSUID.union(MountAttrFlags::MOUNT_ATTR_NODEV);

/// The kind byte of the job that the handler sends to the worker.
const KIND_JOB: u8 = 0x11;
/// The kind byte of the reply of the worker with the repository and its
/// `objects` directory.
const KIND_OPENED: u8 = 0x12;
/// The kind byte of the reply of the worker with the root of a mount that
/// the target already carries.
const KIND_EXISTING: u8 = 0x13;
/// The kind byte of the message of the handler with the composefs mount.
const KIND_MOUNT: u8 = 0x14;
/// The kind byte of the reply of the worker with the root of the new mount.
const KIND_ROOT: u8 = 0x15;

/// The length of the fixed part of a job: the kind, the user id, the group
/// id, and the count of groups.
const JOB_HEADER: usize = 1 + 4 + 4 + 2;

/// The largest length of a job.
const MAX_JOB: usize = JOB_HEADER + 4 * MAX_GROUPS + MAX_REQUEST;

/// The credentials of the caller, as the initial user namespace sees them.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Caller {
    /// The user id.
    uid: u32,
    /// The group id.
    gid: u32,
    /// The supplementary groups.
    groups: Vec<u32>,
}

/// The handler of the connections of the daemon.
#[derive(Debug)]
pub struct Server {
    /// The device and the inode of the user namespace of the daemon.
    own_userns: (u64, u64),
    /// The program of the worker process.
    program: PathBuf,
    /// The arguments of the worker process.
    args: Vec<OsString>,
    /// The largest size of a built image, in bytes.
    max_image_size: u64,
    /// The time that one connection can take.
    deadline: Duration,
}

impl Server {
    /// Returns a handler that starts the worker process as `program` with
    /// `args`. The worker process must call [`worker_main`] with its
    /// standard input. The handler refuses to build an image larger than
    /// `max_image_size` bytes.
    ///
    /// The call reads the user namespace of the process. The handler
    /// refuses a request from that namespace.
    ///
    /// # Errors
    ///
    /// The text of the error if `/proc/self/ns/user` does not open.
    pub fn new(
        program: PathBuf,
        args: Vec<OsString>,
        max_image_size: u64,
    ) -> Result<Server, String> {
        let ns = openat(
            CWD,
            "/proc/self/ns/user",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| format!("open /proc/self/ns/user: {e}"))?;
        let own_userns = dev_ino(&ns).map_err(|e| format!("fstat /proc/self/ns/user: {e}"))?;
        Ok(Server {
            own_userns,
            program,
            args,
            max_image_size,
            deadline: DEADLINE,
        })
    }

    /// Serves the one request of the connection `conn` and replies to it.
    ///
    /// The request and the reply must complete in 60 seconds. At that time
    /// the call kills the worker process and replies with an error. The call
    /// does not wait for the client to close the connection.
    ///
    /// # Errors
    ///
    /// The text of the failure that the call replied, or of a failed reply.
    pub async fn serve(&self, conn: OwnedFd) -> Result<(), String> {
        let deadline = Instant::now() + self.deadline;
        let conn = Arc::new(conn);
        let result = self.handle(conn.clone(), deadline).await;
        let failure = result.as_ref().err().map(ToString::to_string);
        let sent = ostrya_rt::unblock(move || match &result {
            Ok(root) => proto::send(conn.as_fd(), &[KIND_MOUNTED], &[root.as_fd()]),
            Err(failure) => proto::send(conn.as_fd(), &failure.encode(), &[]),
        })
        .await;
        match (failure, sent) {
            (Some(text), _) => Err(text),
            (None, Err(e)) => Err(format!("reply: {}", e.into_failure())),
            (None, Ok(())) => Ok(()),
        }
    }

    /// Runs the request of `conn` and returns the root of the mount.
    async fn handle(&self, conn: Arc<OwnedFd>, deadline: Instant) -> Result<OwnedFd, Failure> {
        let (caller, request, userns, mntns) =
            ostrya_rt::unblock(move || receive(conn.as_fd(), deadline)).await?;
        eprintln!(
            "ostrya-mountd: {} {} mount of {} at {} for uid {}",
            match request.op {
                Op::Stored => "stored",
                Op::Built => "built",
            },
            match request.access {
                Access::ReadOnly => "read-only",
                Access::ReadWrite => "read-write",
            },
            request.commit,
            request.target.display(),
            caller.uid,
        );
        self.check_namespaces(&userns, &mntns)?;
        let worker = WorkerProcess::spawn(&self.program, &self.args)?;
        let steps = mount(
            &worker,
            &caller,
            &request,
            (userns, mntns),
            deadline,
            self.max_image_size,
        );
        // The worker ends with the request. After the deadline, the call
        // kills it at once.
        match within(deadline, steps).await {
            Some(result) => {
                worker.end(deadline).await;
                result
            }
            None => {
                worker.end(Instant::now()).await;
                Err(late())
            }
        }
    }

    /// Checks the namespaces of a request: `userns` is a user namespace
    /// other than the one of the daemon, and it owns the mount namespace
    /// `mntns`.
    fn check_namespaces(&self, userns: &OwnedFd, mntns: &OwnedFd) -> Result<(), Failure> {
        let is = |fd: &OwnedFd, want: LinkNameSpaceType, name: &str| match ostrya_sys::ns_type(fd) {
            Ok(ty) if ty == want => Ok(()),
            _ => Err(Failure::new(
                HelperCode::Namespace,
                format!("the {name} namespace descriptor is not a {name} namespace"),
            )),
        };
        is(userns, LinkNameSpaceType::User, "user")?;
        is(mntns, LinkNameSpaceType::Mount, "mount")?;
        let user = dev_ino(userns).map_err(|e| Failure::sys(HelperCode::Internal, "fstat", e))?;
        if user == self.own_userns {
            return Err(Failure::new(
                HelperCode::Namespace,
                "the request names the initial user namespace; a root caller there mounts \
                 directly",
            ));
        }
        let owner = ostrya_sys::ns_owner_userns(mntns)
            .map_err(|e| Failure::sys(HelperCode::Namespace, "NS_GET_USERNS", e))?;
        let owner = dev_ino(&owner).map_err(|e| Failure::sys(HelperCode::Internal, "fstat", e))?;
        if owner != user {
            return Err(Failure::new(
                HelperCode::Namespace,
                "the user namespace of the request does not own its mount namespace",
            ));
        }
        Ok(())
    }
}

/// Runs `future` until it completes or until `deadline`. Returns `None` at
/// the deadline. The future then drops, and a blocking call that it started
/// on the blocking pool runs to its end.
async fn within<T>(deadline: Instant, future: impl Future<Output = T>) -> Option<T> {
    let mut future = pin!(future);
    let mut timer = pin!(ostrya_rt::Timer::after(
        deadline.saturating_duration_since(Instant::now())
    ));
    std::future::poll_fn(|cx| {
        if let Poll::Ready(value) = future.as_mut().poll(cx) {
            return Poll::Ready(Some(value));
        }
        match timer.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

/// Returns the failure of a request that did not complete before its
/// deadline.
fn late() -> Failure {
    Failure::new(
        HelperCode::Timeout,
        format!(
            "the request did not complete in {} seconds",
            DEADLINE.as_secs()
        ),
    )
}

/// Sets the receive timeout of `sock` to the time that is left until
/// `deadline`.
///
/// # Errors
///
/// [`late`] if less than one millisecond is left. The kernel reads a zero
/// timeout as no timeout.
fn arm(sock: BorrowedFd<'_>, deadline: Instant) -> Result<(), Failure> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left < Duration::from_millis(1) {
        return Err(late());
    }
    set_socket_timeout(sock, Timeout::Recv, Some(left))
        .map_err(|e| Failure::sys(HelperCode::Internal, "SO_RCVTIMEO", e))
}

/// Runs the steps of one request with the worker process `worker`.
///
/// `namespaces` holds the user namespace and the mount namespace of the
/// request. Each receive from the worker waits at most until `deadline`.
async fn mount(
    worker: &WorkerProcess,
    caller: &Caller,
    request: &Request,
    namespaces: (OwnedFd, OwnedFd),
    deadline: Instant,
    max_image_size: u64,
) -> Result<OwnedFd, Failure> {
    let (userns, mntns) = namespaces;
    let job = encode_job(caller, request)?;
    let idmap = userns
        .try_clone()
        .map_err(|e| Failure::sys(HelperCode::Internal, "dup", errno_of(&e)))?;
    let chan = worker.channel.clone();
    let mut reply = ostrya_rt::unblock(move || {
        ask(
            chan.as_fd(),
            &job,
            &[userns.as_fd(), mntns.as_fd()],
            2,
            deadline,
        )
    })
    .await?;
    match reply.bytes.as_slice() {
        [KIND_EXISTING] if reply.fds.len() == 1 => {
            eprintln!(
                "ostrya-mountd: {} already carries the mount",
                request.target.display()
            );
            return Ok(reply.fds.remove(0));
        }
        [KIND_OPENED] => {}
        [KIND_ERROR, ..] if reply.fds.is_empty() => return Err(decode_failure(&reply.bytes)),
        _ => return Err(protocol_failure()),
    }
    let [repo_fd, objects] = <[OwnedFd; 2]>::try_from(reply.fds).map_err(|_| protocol_failure())?;

    let composefs = build(request, repo_fd, objects, idmap, max_image_size).await?;
    let chan = worker.channel.clone();
    let mut reply = ostrya_rt::unblock(move || {
        ask(
            chan.as_fd(),
            &[KIND_MOUNT],
            &[composefs.as_fd()],
            1,
            deadline,
        )
    })
    .await?;
    match reply.bytes.as_slice() {
        [KIND_ROOT] if reply.fds.len() == 1 => Ok(reply.fds.remove(0)),
        [KIND_ERROR, ..] if reply.fds.is_empty() => Err(decode_failure(&reply.bytes)),
        _ => Err(protocol_failure()),
    }
}

/// Sends `bytes` with `fds` to the worker on `chan`, and receives its reply
/// with at most `max_fds` descriptors. The receive waits at most until
/// `deadline`.
fn ask(
    chan: BorrowedFd<'_>,
    bytes: &[u8],
    fds: &[BorrowedFd<'_>],
    max_fds: usize,
    deadline: Instant,
) -> Result<Message, Failure> {
    proto::send(chan, bytes, fds).map_err(worker_failure)?;
    arm(chan, deadline)?;
    proto::recv(chan, MAX_ERROR, max_fds).map_err(worker_failure)
}

/// Opens the repository at `repo_fd`, checks it, and mounts the EROFS layer
/// and the composefs overlay of the request. Returns the detached overlay.
///
/// `repo_fd` and `objects` are copies of the mounts of the repository
/// directory and of its `objects` directory, which the worker opened as the
/// caller. A copy holds no mount that is below it in the namespace of the
/// caller. The `objects` directory that the repository opens must be the
/// directory of `objects`, so a symlink or a rename cannot give the caller
/// the objects of another directory.
async fn build(
    request: &Request,
    repo_fd: OwnedFd,
    objects: OwnedFd,
    idmap: OwnedFd,
    max_image_size: u64,
) -> Result<OwnedFd, Failure> {
    // The reads of the repository are blocking calls on the blocking pool,
    // and the deadline of the connection cannot stop them. The worker
    // refused a repository on FUSE, and the copy of the repository mount
    // holds no mount of the caller below it. So no read waits on a file
    // system server of the caller. The strict open mode refuses a symlink, a
    // FIFO, and a device in place of a file that the daemon reads.
    let repo = Repo::open_at_strict(repo_fd.as_fd(), Path::new("."))
        .await
        .map_err(|e| failure_of(Error::Repo(e)))?;
    let same = dev_ino(repo.objects_dir())
        .and_then(|a| dev_ino(&objects).map(|b| a == b))
        .map_err(|e| Failure::sys(HelperCode::Internal, "fstat objects", e))?;
    if !same {
        return Err(Failure::new(
            HelperCode::Access,
            "the objects directory of the repository is not the directory that the caller \
             opened",
        ));
    }
    let repo_plan = RepoPlan::new(&repo).map_err(failure_of)?;
    let image: OwnedFd = match request.op {
        Op::Stored => repo
            .open_composefs_image_checked(&request.commit)
            .await
            .map_err(|e| failure_of(Error::Repo(e)))?
            .0
            .into(),
        Op::Built => build_image(&repo, &request.commit, &repo_plan, max_image_size)
            .await
            .map_err(failure_of)?,
    };
    let plan = Plan {
        verity: repo_plan.verity,
        access: request.access,
        source: request.label(),
        attrs: DAEMON_ATTRS,
        idmap: Some(idmap),
    };
    ostrya_rt::unblock(move || build_composefs(image, objects.as_fd(), &plan))
        .await
        .map_err(failure_of)
}

/// Reads the credentials of the peer of `conn`, the hello, and the request.
/// Returns the caller, the request, the user namespace, and the mount
/// namespace. Each receive waits at most until `deadline`.
fn receive(
    conn: BorrowedFd<'_>,
    deadline: Instant,
) -> Result<(Caller, Request, OwnedFd, OwnedFd), Failure> {
    // The timeouts come first, so that no later step waits with no limit.
    arm(conn, deadline)?;
    set_socket_timeout(conn, Timeout::Send, Some(DEADLINE))
        .map_err(|e| Failure::sys(HelperCode::Internal, "SO_SNDTIMEO", e))?;
    let cred =
        socket_peercred(conn).map_err(|e| Failure::sys(HelperCode::Internal, "SO_PEERCRED", e))?;
    let groups = ostrya_sys::peer_groups(conn, MAX_GROUPS).map_err(|e| match e {
        Errno::RANGE => Failure::new(
            HelperCode::Access,
            format!("the caller has more than {MAX_GROUPS} supplementary groups"),
        ),
        e => Failure::sys(HelperCode::Internal, "SO_PEERGROUPS", e),
    })?;
    let caller = Caller {
        uid: cred.uid.as_raw(),
        gid: cred.gid.as_raw(),
        groups,
    };

    // The first message is read with the limits of a request, so that a
    // request with no hello reads as a missing hello.
    let hello = proto::recv(conn, MAX_REQUEST, REQUEST_FDS).map_err(WireError::into_failure)?;
    let version = proto::decode_hello(KIND_HELLO, &hello.bytes)
        .map_err(|text| Failure::new(HelperCode::Protocol, text))?;
    if !hello.fds.is_empty() {
        return Err(Failure::new(
            HelperCode::Protocol,
            "the hello carries descriptors",
        ));
    }
    if version != VERSION {
        return Err(Failure::new(
            HelperCode::Version,
            format!("the daemon speaks version {VERSION} of the protocol, the client {version}"),
        ));
    }
    proto::send(conn, &proto::encode_hello(KIND_HELLO_REPLY, VERSION), &[])
        .map_err(WireError::into_failure)?;

    arm(conn, deadline)?;
    let msg = proto::recv(conn, MAX_REQUEST, REQUEST_FDS).map_err(WireError::into_failure)?;
    let request =
        Request::decode(&msg.bytes).map_err(|text| Failure::new(HelperCode::Protocol, text))?;
    let [userns, mntns] =
        take_fds(msg.fds).map_err(|text| Failure::new(HelperCode::Protocol, text))?;
    Ok((caller, request, userns, mntns))
}

/// A running worker process and the channel to it.
struct WorkerProcess {
    /// The channel to the worker.
    channel: Arc<OwnedFd>,
    /// The process.
    child: Child,
}

impl WorkerProcess {
    /// Starts `program` with `args`, with one end of a new socket pair as
    /// its standard input.
    fn spawn(program: &Path, args: &[OsString]) -> Result<WorkerProcess, Failure> {
        let (parent, child) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(|e| Failure::sys(HelperCode::Internal, "socketpair", e))?;
        let child = Command::new(program)
            .args(args)
            .stdin(Stdio::from(child))
            .env_remove("LISTEN_PID")
            .env_remove("LISTEN_FDS")
            .env_remove("LISTEN_FDNAMES")
            .spawn()
            .map_err(|e| Failure::sys(HelperCode::Internal, "start the worker", errno_of(&e)))?;
        Ok(WorkerProcess {
            channel: Arc::new(parent),
            child,
        })
    }

    /// Closes the channel and waits for the worker to exit. A worker that
    /// waits for a message sees the end of the channel and exits. At
    /// `deadline`, the call kills the worker and waits for it.
    async fn end(self, deadline: Instant) {
        let WorkerProcess { channel, mut child } = self;
        drop(channel);
        loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => return,
                Ok(Some(status)) => {
                    eprintln!("ostrya-mountd: the worker exited with {status}");
                    return;
                }
                Ok(None) if Instant::now() < deadline => {
                    ostrya_rt::Timer::after(Duration::from_millis(5)).await;
                }
                Ok(None) => {
                    eprintln!("ostrya-mountd: the worker is killed at the deadline");
                    let _ = child.kill();
                    if let Err(e) = ostrya_rt::unblock(move || child.wait()).await {
                        eprintln!("ostrya-mountd: wait for the worker: {e}");
                    }
                    return;
                }
                Err(e) => {
                    eprintln!("ostrya-mountd: wait for the worker: {e}");
                    return;
                }
            }
        }
    }
}

/// Returns the bytes of the job of `request` for `caller`.
fn encode_job(caller: &Caller, request: &Request) -> Result<Vec<u8>, Failure> {
    let req = request
        .encode()
        .map_err(|text| Failure::new(HelperCode::Internal, text))?;
    let mut out = Vec::with_capacity(JOB_HEADER + 4 * caller.groups.len() + req.len());
    out.push(KIND_JOB);
    out.extend_from_slice(&caller.uid.to_be_bytes());
    out.extend_from_slice(&caller.gid.to_be_bytes());
    let count = u16::try_from(caller.groups.len())
        .map_err(|_| Failure::new(HelperCode::Internal, "too many groups"))?;
    out.extend_from_slice(&count.to_be_bytes());
    for group in &caller.groups {
        out.extend_from_slice(&group.to_be_bytes());
    }
    out.extend_from_slice(&req);
    Ok(out)
}

/// Reads a job.
fn decode_job(bytes: &[u8]) -> Result<(Caller, Request), String> {
    if bytes.first() != Some(&KIND_JOB) || bytes.len() < JOB_HEADER {
        return Err("the job is malformed".to_owned());
    }
    let word =
        |at: usize| u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
    let count = usize::from(u16::from_be_bytes([bytes[9], bytes[10]]));
    let end = JOB_HEADER + 4 * count;
    if bytes.len() < end {
        return Err("the job is malformed".to_owned());
    }
    let caller = Caller {
        uid: word(1),
        gid: word(5),
        groups: (0..count).map(|i| word(JOB_HEADER + 4 * i)).collect(),
    };
    Ok((caller, Request::decode(&bytes[end..])?))
}

/// The entry of the worker process. `channel` is the socket that the
/// handler gave as standard input.
///
/// The worker must have one thread. It runs one job and returns.
///
/// # Errors
///
/// The text of the failure of the job. The worker also sends the failure to
/// the handler.
pub fn worker_main(channel: OwnedFd) -> Result<(), String> {
    match worker(channel.as_fd()) {
        Ok(()) => Ok(()),
        Err(WorkerExit::Aborted) => Err("the daemon closed the channel".to_owned()),
        Err(WorkerExit::Failed(failure)) => {
            let _ = proto::send(channel.as_fd(), &failure.encode(), &[]);
            Err(failure.to_string())
        }
    }
}

/// How a job of the worker ends without a mount.
enum WorkerExit {
    /// The handler closed the channel.
    Aborted,
    /// A step failed.
    Failed(Failure),
}

impl From<Failure> for WorkerExit {
    fn from(failure: Failure) -> WorkerExit {
        WorkerExit::Failed(failure)
    }
}

/// Runs one job of the worker on the channel `chan`.
fn worker(chan: BorrowedFd<'_>) -> Result<(), WorkerExit> {
    // The handler kills the worker at the deadline of the connection. The
    // receive timeout also ends each wait of the worker for the handler.
    set_socket_timeout(chan, Timeout::Recv, Some(DEADLINE))
        .map_err(|e| Failure::sys(HelperCode::Internal, "SO_RCVTIMEO", e))?;
    // The worker starts as root with no supplementary groups, so that each
    // switch back from the caller restores a known state.
    set_thread_groups(&[]).map_err(|e| Failure::sys(HelperCode::Internal, "setgroups", e))?;
    let job = proto::recv(chan, MAX_JOB, 2).map_err(abort_or_failure)?;
    let (caller, request) =
        decode_job(&job.bytes).map_err(|text| Failure::new(HelperCode::Internal, text))?;
    let [userns, mntns] =
        take_fds(job.fds).map_err(|text| Failure::new(HelperCode::Internal, text))?;
    let label = request.label();

    // The mount namespace of the caller can have another `/proc`, for
    // example one of another PID namespace, or none. The worker reads its
    // own entries through the `/proc` of the daemon, which it opens first.
    let proc =
        open_dir(CWD, "/proc").map_err(|e| Failure::sys(HelperCode::Internal, "open /proc", e))?;
    // The worker resolves each path of the request in the mount namespace
    // of the caller.
    move_into_link_name_space(mntns.as_fd(), Some(LinkNameSpaceType::Mount))
        .map_err(|e| Failure::sys(HelperCode::Namespace, "setns mount namespace", e))?;

    let opened = as_caller(&caller, || open_as_caller(proc.as_fd(), &request, &label))?;
    let (target, repo, objects) = match opened {
        Opened::Existing(root) => {
            proto::send(chan, &[KIND_EXISTING], &[root.as_fd()]).map_err(abort_or_failure)?;
            return Ok(());
        }
        Opened::Repo {
            target,
            repo,
            objects,
        } => (target, repo, objects),
    };
    // overlayfs takes a layer only from the mount namespace of the mounter
    // or from a detached mount. The handler mounts in its own namespace, so
    // the worker gives it a detached copy of the `objects` directory. The
    // copy has the device and the inode of the directory. The handler reads
    // the repository through a detached copy of its directory. A copy holds
    // no mount that is below the directory in the namespace of the caller.
    let repo = clone_tree(repo.as_fd(), "open_tree repository")?;
    let objects = clone_tree(objects.as_fd(), "open_tree objects")?;
    proto::send(chan, &[KIND_OPENED], &[repo.as_fd(), objects.as_fd()])
        .map_err(abort_or_failure)?;
    drop((repo, objects));

    let msg = proto::recv(chan, 1, 1).map_err(abort_or_failure)?;
    if msg.bytes != [KIND_MOUNT] {
        return Err(Failure::new(HelperCode::Internal, "the mount message is malformed").into());
    }
    let [composefs] = take_fds(msg.fds).map_err(|text| Failure::new(HelperCode::Internal, text))?;

    // overlayfs takes a detached layer only from a process with
    // CAP_SYS_ADMIN in the user namespace that owns the detached mount. The
    // handler made the composefs mount in the initial user namespace. A copy
    // that the worker makes here, in the mount namespace of the caller,
    // belongs to the user namespace of the caller.
    let composefs = clone_tree(composefs.as_fd(), "open_tree composefs")?;
    // The top overlay belongs to the user namespace of the caller, and its
    // user 0 owns each file that the overlay creates. The kernel gives a
    // superblock of that namespace no device access and no setuid effect
    // outside the namespace, also if the caller clears `nosuid` and `nodev`
    // on the mount.
    move_into_link_name_space(userns.as_fd(), Some(LinkNameSpaceType::User))
        .map_err(|e| Failure::sys(HelperCode::Namespace, "setns user namespace", e))?;
    let root_gid = Gid::from_raw(0);
    let root_uid = Uid::from_raw(0);
    set_thread_res_gid(root_gid, root_gid, root_gid).map_err(|e| {
        Failure::sys(
            HelperCode::Namespace,
            "setresgid to group 0 of the namespace",
            e,
        )
    })?;
    set_thread_res_uid(root_uid, root_uid, root_uid).map_err(|e| {
        Failure::sys(
            HelperCode::Namespace,
            "setresuid to user 0 of the namespace",
            e,
        )
    })?;
    let layout = match request.access {
        Access::ReadOnly => None,
        Access::ReadWrite => Some(Layout::ensure(target.as_fd()).map_err(failure_of)?),
    };
    let opts = UpperOptions {
        userxattr: true,
        attrs: DAEMON_ATTRS,
        layers: LayerRef::Fd,
    };
    let top = top_overlay(composefs.as_fd(), layout.as_ref(), &label, opts).map_err(failure_of)?;
    drop(composefs);
    // The descriptor of the root stays valid when the mount moves, so it is
    // opened before the move, and no step can fail after it.
    let root =
        open_dir(&top, ".").map_err(|e| Failure::sys(HelperCode::Mount, "open mount root", e))?;
    move_onto(top, target.as_fd()).map_err(failure_of)?;
    proto::send(chan, &[KIND_ROOT], &[root.as_fd()]).map_err(abort_or_failure)?;
    Ok(())
}

/// What the worker opens as the caller.
enum Opened {
    /// The target already carries the mount of the request. The value is
    /// the root of that mount.
    Existing(OwnedFd),
    /// The target, the repository directory, and its `objects` directory.
    Repo {
        target: OwnedFd,
        repo: OwnedFd,
        objects: OwnedFd,
    },
}

/// Opens the target and the repository of `request` with the credentials
/// of the caller. `proc` is the `/proc` of the daemon, and `label` is the
/// source label of the request.
///
/// The call refuses a target or a repository on FUSE, and an `objects`
/// directory that is a mount of its own or on another mount than the
/// repository directory.
fn open_as_caller(proc: BorrowedFd<'_>, request: &Request, label: &str) -> Result<Opened, Failure> {
    let target = open_dir(CWD, &request.target)
        .map_err(|e| Failure::sys(HelperCode::Access, "open target", e))?;
    refuse_fuse(target.as_fd(), HelperCode::Access, "the target")?;
    if already_mounted(proc, target.as_fd(), label, request.access)? {
        return Ok(Opened::Existing(target));
    }
    let repo = openat(
        CWD,
        &request.repo,
        OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|e| Failure::sys(HelperCode::Access, "open repository", e))?;
    refuse_fuse(repo.as_fd(), HelperCode::Repository, "the repository")?;
    let objects = openat(
        &repo,
        "objects",
        OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|e| Failure::sys(HelperCode::Access, "open objects", e))?;
    check_objects_mount(repo.as_fd(), objects.as_fd())?;
    Ok(Opened::Repo {
        target,
        repo,
        objects,
    })
}

/// Refuses a directory `dir` on a FUSE file system with the class `code`.
/// `what` names the directory in the text of the refusal.
fn refuse_fuse(dir: BorrowedFd<'_>, code: HelperCode, what: &str) -> Result<(), Failure> {
    let stat = fstatfs(dir).map_err(|e| Failure::sys(code, "statfs", e))?;
    if u64::try_from(stat.f_type).is_ok_and(|t| t == FUSE_SUPER_MAGIC) {
        return Err(Failure::new(
            code,
            format!("{what} is on a FUSE file system"),
        ));
    }
    Ok(())
}

/// Refuses an `objects` directory that is the root of a mount, or that is on
/// another mount than the repository directory `repo`.
fn check_objects_mount(repo: BorrowedFd<'_>, objects: BorrowedFd<'_>) -> Result<(), Failure> {
    let stx = |fd: BorrowedFd<'_>| {
        statx(fd, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)
            .map_err(|e| Failure::sys(HelperCode::Internal, "statx", e))
    };
    let (repo, objects) = (stx(repo)?, stx(objects)?);
    let mnt_id = StatxFlags::MNT_ID.bits();
    if repo.stx_mask & mnt_id == 0
        || objects.stx_mask & mnt_id == 0
        || !objects
            .stx_attributes_mask
            .contains(StatxAttributes::MOUNT_ROOT)
    {
        return Err(Failure::new(
            HelperCode::Internal,
            "statx gives no mount id or mount root attribute",
        ));
    }
    if objects.stx_attributes.contains(StatxAttributes::MOUNT_ROOT)
        || objects.stx_mnt_id != repo.stx_mnt_id
    {
        return Err(Failure::new(
            HelperCode::Access,
            "the objects directory of the repository is not on the mount of the repository \
             directory",
        ));
    }
    Ok(())
}

/// Returns a detached copy of the mount at `dir`, with no mount below it.
/// `op` names the call in an error.
fn clone_tree(dir: BorrowedFd<'_>, op: &str) -> Result<OwnedFd, Failure> {
    open_tree(
        dir,
        "",
        OpenTreeFlags::OPEN_TREE_CLONE
            | OpenTreeFlags::OPEN_TREE_CLOEXEC
            | OpenTreeFlags::AT_EMPTY_PATH,
    )
    .map_err(|e| Failure::sys(HelperCode::Mount, op, e))
}

/// Runs `f` with the user, the group, and the supplementary groups of
/// `caller`, then switches back to root.
///
/// The saved user id and the saved group id stay 0, so the switch back is
/// allowed. If the switch back fails, the call fails, and the worker does
/// no further step.
fn as_caller<T>(caller: &Caller, f: impl FnOnce() -> Result<T, Failure>) -> Result<T, Failure> {
    let internal = |op: &str, e: Errno| Failure::sys(HelperCode::Internal, op, e);
    let groups: Vec<Gid> = caller.groups.iter().map(|g| Gid::from_raw(*g)).collect();
    let (uid, gid) = (Uid::from_raw(caller.uid), Gid::from_raw(caller.gid));
    set_thread_groups(&groups).map_err(|e| internal("setgroups", e))?;
    set_thread_res_gid(gid, gid, None).map_err(|e| internal("setresgid", e))?;
    set_thread_res_uid(uid, uid, None).map_err(|e| internal("setresuid", e))?;
    let out = f();
    let root_uid = Uid::from_raw(0);
    let root_gid = Gid::from_raw(0);
    set_thread_res_uid(root_uid, root_uid, None).map_err(|e| internal("setresuid", e))?;
    set_thread_res_gid(root_gid, root_gid, None).map_err(|e| internal("setresgid", e))?;
    set_thread_groups(&[]).map_err(|e| internal("setgroups", e))?;
    out
}

/// Returns `true` if the mount whose root `target` opens is the mount of a
/// request with the source label `label` and the access `access`.
///
/// The target must be the root of an overlay mount. The call then reads the
/// line of that mount in `self/mountinfo` under `proc`, by the mount id
/// that `statx` gives. The mount is the mount of the request if its source
/// is `label`, and its superblock options hold `ro` for
/// [`Access::ReadOnly`] or `rw` for [`Access::ReadWrite`].
fn already_mounted(
    proc: BorrowedFd<'_>,
    target: BorrowedFd<'_>,
    label: &str,
    access: Access,
) -> Result<bool, Failure> {
    let stx = statx(target, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)
        .map_err(|e| Failure::sys(HelperCode::Internal, "statx target", e))?;
    if !stx.stx_attributes.contains(StatxAttributes::MOUNT_ROOT) {
        return Ok(false);
    }
    let fs = fstatfs(target).map_err(|e| Failure::sys(HelperCode::Internal, "statfs target", e))?;
    if !u64::try_from(fs.f_type).is_ok_and(|t| t == OVERLAYFS_SUPER_MAGIC) {
        return Ok(false);
    }
    let file = openat(
        proc,
        "self/mountinfo",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| Failure::sys(HelperCode::Internal, "open mountinfo", e))?;
    let line = find_mount_line(std::fs::File::from(file), stx.stx_mnt_id)
        .map_err(|e| Failure::sys(HelperCode::Internal, "read mountinfo", errno_of(&e)))?;
    Ok(line
        .as_deref()
        .and_then(parse_mountinfo)
        .is_some_and(|entry| entry.is_request(label, access)))
}

/// Reads the mountinfo text `reader` line by line and returns the line of
/// the mount id `mnt_id`, with no newline. Returns `None` if no line has
/// that id, or if the line is longer than [`MAX_MOUNTINFO_LINE`] bytes.
fn find_mount_line(reader: impl Read, mnt_id: u64) -> std::io::Result<Option<Vec<u8>>> {
    let id = mnt_id.to_string();
    let mut reader = BufReader::new(reader);
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = reader
            .by_ref()
            .take(MAX_MOUNTINFO_LINE)
            .read_until(b'\n', &mut line)?;
        if n == 0 {
            return Ok(None);
        }
        let ours = line.split(|b| *b == b' ').next() == Some(id.as_bytes());
        match line.last() {
            Some(b'\n') => {
                if ours {
                    line.pop();
                    return Ok(Some(line));
                }
            }
            // The line is longer than the limit, or the text ends with no
            // newline.
            _ => {
                if ours {
                    return Ok(None);
                }
                reader.skip_until(b'\n')?;
            }
        }
    }
}

/// The fields of one line of `/proc/<pid>/mountinfo` that the remount check
/// reads.
#[derive(Debug, PartialEq, Eq)]
struct MountEntry {
    /// The file system type.
    fstype: Vec<u8>,
    /// The source of the mount.
    source: Vec<u8>,
    /// The superblock options.
    super_options: Vec<u8>,
}

impl MountEntry {
    /// Returns `true` if the entry is the mount of a request with the source
    /// label `label` and the access `access`.
    fn is_request(&self, label: &str, access: Access) -> bool {
        let want: &[u8] = match access {
            Access::ReadOnly => b"ro",
            Access::ReadWrite => b"rw",
        };
        self.fstype == b"overlay"
            && self.source == label.as_bytes()
            && self
                .super_options
                .split(|b| *b == b',')
                .any(|opt| opt == want)
    }
}

/// Reads one line of `/proc/<pid>/mountinfo`.
///
/// The fields are the mount id, the parent id, the device, the root, the
/// mount point, the mount options, zero or more optional fields, a `-`, the
/// file system type, the source, and the superblock options. Returns `None`
/// for a line of another form.
fn parse_mountinfo(line: &[u8]) -> Option<MountEntry> {
    let fields: Vec<&[u8]> = line.split(|b| *b == b' ').collect();
    let dash = fields.iter().skip(6).position(|f| *f == b"-")? + 6;
    let after = fields.get(dash + 1..dash + 4)?;
    Some(MountEntry {
        fstype: unescape(after[0]),
        source: unescape(after[1]),
        super_options: unescape(after[2]),
    })
}

/// Decodes the octal escapes `\ooo` of a mountinfo field. The kernel writes
/// a space, a tab, a newline, and a backslash in this form.
fn unescape(field: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(field.len());
    let mut i = 0;
    while i < field.len() {
        let octal = field
            .get(i + 1..i + 4)
            .filter(|d| field[i] == b'\\' && d.iter().all(|c| (b'0'..=b'7').contains(c)));
        match octal {
            Some(d) => {
                let value = d.iter().fold(0u32, |n, c| n * 8 + u32::from(c - b'0'));
                out.push(u8::try_from(value).unwrap_or(b'?'));
                i += 4;
            }
            None => {
                out.push(field[i]);
                i += 1;
            }
        }
    }
    out
}

/// Returns the descriptors of a message as an array of `N`.
///
/// # Errors
///
/// The text of the refusal if the message carries another count.
fn take_fds<const N: usize>(fds: Vec<OwnedFd>) -> Result<[OwnedFd; N], String> {
    <[OwnedFd; N]>::try_from(fds)
        .map_err(|fds| format!("the message carries {} descriptors, not {N}", fds.len()))
}

/// Returns the device and the inode of `fd`.
fn dev_ino(fd: impl AsFd) -> rustix::io::Result<(u64, u64)> {
    let st = fstat(fd)?;
    Ok((st.st_dev, st.st_ino))
}

/// Returns the error number of an I/O error.
fn errno_of(e: &std::io::Error) -> Errno {
    Errno::from_io_error(e).unwrap_or(Errno::IO)
}

/// Returns the failure that the daemon reports for the error `e` of a
/// mount step or of the repository.
fn failure_of(e: Error) -> Failure {
    let code = match &e {
        Error::Repo(_) | Error::UnsupportedMode(_) | Error::InvalidImage(_) => {
            HelperCode::Repository
        }
        Error::Sys { .. } => HelperCode::Mount,
        _ => HelperCode::Internal,
    };
    let errno = match &e {
        Error::Sys { errno, .. } => errno.raw_os_error(),
        _ => 0,
    };
    Failure {
        code,
        errno,
        text: e.plain_text(),
    }
}

/// Returns the failure for an error of the channel to the worker.
fn worker_failure(e: WireError) -> Failure {
    match e {
        WireError::Closed => Failure::new(HelperCode::Internal, "the worker exited"),
        WireError::Sys(_, Errno::AGAIN) => late(),
        other => other.into_failure(),
    }
}

/// Returns the worker exit for an error of the channel to the handler.
fn abort_or_failure(e: WireError) -> WorkerExit {
    match e {
        WireError::Closed => WorkerExit::Aborted,
        other => WorkerExit::Failed(other.into_failure()),
    }
}

/// Returns the failure of the `Error` message `bytes` of the worker.
fn decode_failure(bytes: &[u8]) -> Failure {
    Failure::decode(bytes).unwrap_or_else(|text| Failure::new(HelperCode::Internal, text))
}

/// Returns the failure for a malformed reply of the worker.
fn protocol_failure() -> Failure {
    Failure::new(HelperCode::Internal, "the reply of the worker is malformed")
}

#[cfg(test)]
mod tests {
    use super::*;

    use rustix::fs::{CWD, Mode, OFlags, openat};

    use crate::helper::exchange;

    fn own_ns(name: &str) -> OwnedFd {
        openat(
            CWD,
            format!("/proc/thread-self/ns/{name}"),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
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

    fn request() -> Request {
        Request {
            op: Op::Built,
            access: Access::ReadWrite,
            commit: ostrya::Checksum::from_bytes([3; 32]),
            repo: PathBuf::from("/srv/repo"),
            source: "my label".to_owned(),
            target: PathBuf::from("/mnt/os"),
        }
    }

    /// Runs the handler on one end of a socket pair and `client` on the
    /// other end.
    fn with_server<T>(client: impl FnOnce(BorrowedFd<'_>) -> T) -> (T, Result<(), String>) {
        let (a, b) = pair();
        let server =
            Server::new(PathBuf::from("/nonexistent/worker"), Vec::new(), u64::MAX).unwrap();
        let thread = std::thread::spawn(move || ostrya_rt::block_on(server.serve(b)));
        let out = client(a.as_fd());
        drop(a);
        (out, thread.join().unwrap())
    }

    #[test]
    fn a_request_from_the_initial_user_namespace_is_refused() {
        let (result, served) = with_server(|sock| {
            exchange(
                sock,
                &request().encode().unwrap(),
                own_ns("user").as_fd(),
                own_ns("mnt").as_fd(),
            )
        });
        let err = result.unwrap_err();
        match &err {
            Error::Helper {
                code: HelperCode::Namespace,
                message,
                ..
            } => assert!(message.contains("initial user namespace"), "{message}"),
            other => panic!("{other}"),
        }
        assert!(served.unwrap_err().contains("initial user namespace"));
    }

    #[test]
    fn swapped_namespaces_are_refused() {
        let (result, _) = with_server(|sock| {
            exchange(
                sock,
                &request().encode().unwrap(),
                own_ns("mnt").as_fd(),
                own_ns("user").as_fd(),
            )
        });
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                Error::Helper {
                    code: HelperCode::Namespace,
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn a_hello_of_another_version_is_refused_with_the_version_code() {
        let (failure, served) = with_server(|sock| {
            proto::send(sock, &proto::encode_hello(KIND_HELLO, 9), &[]).unwrap();
            let reply = proto::recv(sock, MAX_ERROR, 0).unwrap();
            Failure::decode(&reply.bytes).unwrap()
        });
        assert_eq!(failure.code, HelperCode::Version);
        assert!(served.is_err());
    }

    #[test]
    fn a_request_without_a_hello_and_a_wrong_descriptor_count_are_refused() {
        let (failure, _) = with_server(|sock| {
            proto::send(sock, &request().encode().unwrap(), &[]).unwrap();
            let reply = proto::recv(sock, MAX_ERROR, 0).unwrap();
            Failure::decode(&reply.bytes).unwrap()
        });
        assert_eq!(failure.code, HelperCode::Protocol);
        assert!(failure.text.contains("not a hello"), "{}", failure.text);

        let (failure, _) = with_server(|sock| {
            proto::send(sock, &proto::encode_hello(KIND_HELLO, VERSION), &[]).unwrap();
            proto::recv(sock, 2, 0).unwrap();
            let ns = own_ns("user");
            proto::send(sock, &request().encode().unwrap(), &[ns.as_fd()]).unwrap();
            let reply = proto::recv(sock, MAX_ERROR, 0).unwrap();
            Failure::decode(&reply.bytes).unwrap()
        });
        assert_eq!(failure.code, HelperCode::Protocol);
        assert!(failure.text.contains("descriptors"), "{}", failure.text);

        let (failure, _) = with_server(|sock| {
            proto::send(sock, &proto::encode_hello(KIND_HELLO, VERSION), &[]).unwrap();
            proto::recv(sock, 2, 0).unwrap();
            proto::send(sock, &[0x42], &[]).unwrap();
            let reply = proto::recv(sock, MAX_ERROR, 0).unwrap();
            Failure::decode(&reply.bytes).unwrap()
        });
        assert_eq!(failure.code, HelperCode::Protocol);
    }

    #[test]
    fn a_job_round_trips() {
        let caller = Caller {
            uid: 1000,
            gid: 100,
            groups: vec![100, 10, 65534],
        };
        let bytes = encode_job(&caller, &request()).unwrap();
        assert_eq!(decode_job(&bytes).unwrap(), (caller, request()));
        assert!(decode_job(&bytes[..JOB_HEADER + 4]).is_err());
        assert!(decode_job(&[KIND_JOB]).is_err());
    }

    #[test]
    fn a_hello_with_a_descriptor_is_refused() {
        let (failure, _) = with_server(|sock| {
            let ns = own_ns("user");
            proto::send(
                sock,
                &proto::encode_hello(KIND_HELLO, VERSION),
                &[ns.as_fd()],
            )
            .unwrap();
            let reply = proto::recv(sock, MAX_ERROR, 0).unwrap();
            Failure::decode(&reply.bytes).unwrap()
        });
        assert_eq!(failure.code, HelperCode::Protocol);
        assert!(
            failure.text.contains("carries descriptors"),
            "{}",
            failure.text
        );
    }

    /// A client that stops after the hello gets an error at the deadline of
    /// the connection.
    #[test]
    fn a_silent_client_is_refused_at_the_deadline() {
        let (a, b) = pair();
        let mut server =
            Server::new(PathBuf::from("/nonexistent/worker"), Vec::new(), u64::MAX).unwrap();
        server.deadline = Duration::from_millis(300);
        let thread = std::thread::spawn(move || ostrya_rt::block_on(server.serve(b)));
        let started = Instant::now();
        proto::send(a.as_fd(), &proto::encode_hello(KIND_HELLO, VERSION), &[]).unwrap();
        proto::recv(a.as_fd(), 2, 0).unwrap();
        let reply = proto::recv(a.as_fd(), MAX_ERROR, 0).unwrap();
        let failure = Failure::decode(&reply.bytes).unwrap();
        assert_eq!(failure.code, HelperCode::Timeout);
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(thread.join().unwrap().is_err());
    }

    #[test]
    fn within_ends_a_future_at_the_deadline() {
        ostrya_rt::block_on(async {
            let soon = Instant::now() + Duration::from_millis(20);
            assert_eq!(within(soon, async { 7 }).await, Some(7));
            let never = std::future::pending::<()>();
            assert_eq!(within(soon, never).await, None);
        });
    }

    #[test]
    fn the_mount_line_is_found_by_its_id() {
        let text = b"20 1 0:1 / / rw - ext4 /dev/sda rw\n\
            36 20 0:50 / /mnt rw - overlay abc ro\n\
            361 20 0:51 / /mnt2 rw - overlay xyz rw\n";
        let line = find_mount_line(&text[..], 36).unwrap().unwrap();
        assert!(line.starts_with(b"36 20 "));
        assert!(!line.ends_with(b"\n"));
        assert!(find_mount_line(&text[..], 3).unwrap().is_none());
        assert!(find_mount_line(&text[..], 361).unwrap().is_some());

        let long = format!(
            "5 1 0:1 / /x rw - overlay {} ro\n36 1 0:2 / /y rw - overlay abc ro\n",
            "a".repeat(MAX_MOUNTINFO_LINE as usize)
        );
        assert!(find_mount_line(long.as_bytes(), 36).unwrap().is_some());
        assert!(find_mount_line(long.as_bytes(), 5).unwrap().is_none());
    }

    #[test]
    fn a_mountinfo_line_gives_its_fields() {
        let line = b"36 35 98:0 / /mnt/my\\040dir rw,nosuid master:1 shared:2 - overlay my\\040label ro,lowerdir+=/x";
        let entry = parse_mountinfo(line).unwrap();
        assert_eq!(entry.fstype, b"overlay");
        assert_eq!(entry.source, b"my label");
        assert!(entry.is_request("my label", Access::ReadOnly));
        assert!(!entry.is_request("my label", Access::ReadWrite));
        assert!(!entry.is_request("other", Access::ReadOnly));

        let line = b"40 1 0:50 / /mnt rw,relatime - overlay abc rw,userxattr";
        let entry = parse_mountinfo(line).unwrap();
        assert!(entry.is_request("abc", Access::ReadWrite));
        let line = b"40 1 0:50 / /mnt rw,relatime - tmpfs abc rw";
        assert!(
            !parse_mountinfo(line)
                .unwrap()
                .is_request("abc", Access::ReadWrite)
        );
        assert!(parse_mountinfo(b"").is_none());
        assert!(parse_mountinfo(b"1 2 3 4 5 6 7").is_none());
        assert_eq!(unescape(b"a\\134b\\011c\\9"), b"a\\b\tc\\9");
    }
}
