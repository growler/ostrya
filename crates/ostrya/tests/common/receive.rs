//! The test driver of the receive side: a client of `Repo::receive` over two
//! in-process pipes, with the frame codec of `ostrya::push::proto`, and the
//! helpers the receive tests share.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use futures_io::{AsyncRead, AsyncWrite};
use ostrya::push::proto::{
    CommitRequest, ErrorMessage, FrameReader, FrameWriter, Hello, HelloReply, Message,
    ObjectHeader, ObjectsReply,
};
use ostrya::push::{self, Encoding, ErrorCode, RefOutcome, RefUpdate};
use ostrya::{
    Checksum, CreateOptions, Error, ObjectName, ObjectType, ReceivePolicy, Repo, RepoMode, Xattrs,
};
use ostrya_core::DeflateSink;
use ostrya_core::FileHeader;
use ostrya_core::filehdr::frame;
use ostrya_rt::block_on;
use sha2::{Digest, Sha256};

use super::TmpDir;

// ---------------------------------------------------------------------------
// The in-process pipe.
// ---------------------------------------------------------------------------

pub struct PipeState {
    buf: VecDeque<u8>,
    cap: usize,
    writer_closed: bool,
    reader_closed: bool,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

/// The write half of a bounded in-process byte pipe. Dropping it gives the
/// reader end of file.
pub struct PipeWriter(Arc<Mutex<PipeState>>);

/// The read half of a bounded in-process byte pipe. Dropping it fails each
/// later write with `BrokenPipe`.
pub struct PipeReader(Arc<Mutex<PipeState>>);

pub fn pipe(cap: usize) -> (PipeWriter, PipeReader) {
    let state = Arc::new(Mutex::new(PipeState {
        buf: VecDeque::new(),
        cap,
        writer_closed: false,
        reader_closed: false,
        read_waker: None,
        write_waker: None,
    }));
    (PipeWriter(state.clone()), PipeReader(state))
}

impl AsyncWrite for PipeWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut st = self.0.lock().unwrap();
        if st.reader_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let room = st.cap - st.buf.len();
        if room == 0 {
            st.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = room.min(buf.len());
        st.buf.extend(&buf[..n]);
        if let Some(w) = st.read_waker.take() {
            w.wake();
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Drop for PipeWriter {
    fn drop(&mut self) {
        let mut st = self.0.lock().unwrap();
        st.writer_closed = true;
        if let Some(w) = st.read_waker.take() {
            w.wake();
        }
    }
}

impl AsyncRead for PipeReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut st = self.0.lock().unwrap();
        if st.buf.is_empty() {
            if st.writer_closed {
                return Poll::Ready(Ok(0));
            }
            st.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = buf.len().min(st.buf.len());
        for (dst, src) in buf[..n].iter_mut().zip(st.buf.drain(..n)) {
            *dst = src;
        }
        if let Some(w) = st.write_waker.take() {
            w.wake();
        }
        Poll::Ready(Ok(n))
    }
}

impl Drop for PipeReader {
    fn drop(&mut self) {
        let mut st = self.0.lock().unwrap();
        st.reader_closed = true;
        if let Some(w) = st.write_waker.take() {
            w.wake();
        }
    }
}

// ---------------------------------------------------------------------------
// The test client.
// ---------------------------------------------------------------------------

/// The capacity of each pipe. A small capacity makes each object of more than
/// a few chunks wait for the server to read.
pub const PIPE_CAP: usize = 64 * 1024;

/// The client end of a session.
pub struct Client {
    pub writer: FrameWriter<PipeWriter>,
    pub reader: FrameReader<PipeReader>,
}

impl Client {
    /// Send one message. A write error is returned, because the server can
    /// already be gone.
    pub async fn send(&mut self, msg: &Message) -> push::Result<()> {
        self.writer.write_message(msg).await?;
        self.writer.flush().await
    }

    pub async fn hello(&mut self, refs: &[&str]) -> push::Result<()> {
        self.send(&Message::Hello(Hello {
            version: 1,
            agent: None,
            refs: refs.iter().map(|r| r.to_string()).collect(),
        }))
        .await
    }

    pub async fn recv(&mut self) -> Option<Message> {
        self.reader
            .read_message()
            .await
            .expect("a well-formed frame")
    }

    pub async fn hello_reply(&mut self, refs: &[&str]) -> HelloReply {
        self.hello(refs).await.unwrap();
        match self.recv().await {
            Some(Message::HelloReply(reply)) => reply,
            other => panic!("expected HelloReply, got {other:?}"),
        }
    }

    /// Send one object: its header, its bytes in pieces of 40 KiB, and the end
    /// chunk.
    pub async fn object(
        &mut self,
        ty: ObjectType,
        checksum: Checksum,
        encoding: Encoding,
        bytes: &[u8],
    ) -> push::Result<()> {
        self.writer
            .write_message(&Message::ObjectHeader(ObjectHeader {
                name: ObjectName::new(checksum, ty),
                encoding,
            }))
            .await?;
        for piece in bytes.chunks(40 * 1024) {
            self.writer.write_object_data(piece).await?;
        }
        self.writer.end_object().await?;
        self.writer.flush().await
    }

    pub async fn objects_end(&mut self) -> ObjectsReply {
        self.send(&Message::ObjectsEnd).await.unwrap();
        match self.recv().await {
            Some(Message::ObjectsReply(reply)) => reply,
            other => panic!("expected ObjectsReply, got {other:?}"),
        }
    }

    /// Send `Commit` with `updates`.
    pub async fn commit(&mut self, updates: Vec<RefUpdate>, force: bool) -> push::Result<()> {
        self.send(&Message::Commit(CommitRequest { updates, force }))
            .await
    }

    /// Read the reply to `Commit`: the outcomes of `CommitReply`, or the
    /// `Error` that ended the session. Either is the last message of the
    /// session.
    pub async fn commit_reply(&mut self) -> Result<Vec<RefOutcome>, ErrorMessage> {
        let reply = match self.recv().await {
            Some(Message::CommitReply(refs)) => Ok(refs),
            Some(Message::Error(e)) => Err(e),
            other => panic!("expected CommitReply or Error, got {other:?}"),
        };
        assert_eq!(self.recv().await, None, "the session ends after the reply");
        reply
    }

    /// Read until the `Error` message, which is the last message of the
    /// session.
    pub async fn error(&mut self) -> ErrorMessage {
        loop {
            match self.recv().await {
                Some(Message::Error(e)) => {
                    assert_eq!(self.recv().await, None, "the session ends after Error");
                    return e;
                }
                Some(_) => continue,
                None => panic!("the session ended with no Error"),
            }
        }
    }
}

/// Run a session of `repo` under `policy` against the client `script`.
pub fn session<F, Fut, T>(
    repo: &Repo,
    policy: &ReceivePolicy,
    script: F,
) -> (ostrya::Result<ostrya::ReceiveReport>, T)
where
    F: FnOnce(Client) -> Fut,
    Fut: Future<Output = T>,
{
    let (client, server_in, server_out) = connect();
    block_on(futures_lite::future::zip(
        repo.receive(server_in, server_out, policy),
        script(client),
    ))
}

/// A client and the input and output of the server end of its session.
pub fn connect() -> (Client, PipeReader, PipeWriter) {
    let (client_out, server_in) = pipe(PIPE_CAP);
    let (server_out, client_in) = pipe(PIPE_CAP);
    let client = Client {
        writer: FrameWriter::new(client_out),
        reader: FrameReader::new(client_in),
    };
    (client, server_in, server_out)
}

/// The wire code a failed session returned to its caller.
pub fn returned_code(result: &ostrya::Result<ostrya::ReceiveReport>) -> Option<ErrorCode> {
    match result {
        Err(Error::Push(e)) => e.code(),
        other => panic!("expected a push error, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Objects.
// ---------------------------------------------------------------------------

pub fn sha(bytes: &[u8]) -> Checksum {
    Checksum::from_bytes(Sha256::digest(bytes).into())
}

pub fn header(uid: u32, gid: u32, mode: u32) -> FileHeader {
    FileHeader {
        uid,
        gid,
        mode,
        symlink_target: String::new(),
        xattrs: Xattrs::empty(),
    }
}

/// A content object in the `raw` encoding, and its checksum.
pub fn raw_object(header: &FileHeader, payload: &[u8]) -> (Checksum, Vec<u8>) {
    let mut bytes = frame(&header.serialize().unwrap()).unwrap();
    bytes.extend_from_slice(payload);
    (sha(&bytes), bytes)
}

/// A content object in the `deflate` encoding, and its checksum. A symlink
/// carries no payload, so its object is the framed header alone.
pub fn deflate_object(header: &FileHeader, payload: &[u8]) -> (Checksum, Vec<u8>) {
    let (checksum, _) = raw_object(header, payload);
    let mut bytes = frame(&header.serialize_archive(payload.len() as u64).unwrap()).unwrap();
    if header.is_symlink() {
        return (checksum, bytes);
    }
    let mut sink = DeflateSink::new(Vec::new(), 6);
    block_on(async {
        use futures_lite::io::AsyncWriteExt;
        sink.write_all(payload).await.unwrap();
        sink.close().await.unwrap();
    });
    bytes.extend(sink.into_inner());
    (checksum, bytes)
}

// ---------------------------------------------------------------------------
// Repositories.
// ---------------------------------------------------------------------------

/// A new repository of `mode` at `<tmp>/repo`, with `core` appended to its
/// config.
pub fn new_repo(tmp: &TmpDir, mode: RepoMode, core: &str) -> Repo {
    let root = tmp.path().join("repo");
    block_on(Repo::create(&root, CreateOptions::new(mode))).unwrap();
    if !core.is_empty() {
        let config = root.join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str(core);
        std::fs::write(&config, text).unwrap();
    }
    block_on(Repo::open(&root)).unwrap()
}

pub fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// The staging entries left under `tmp/`.
pub fn staging_entries(root: &Path) -> Vec<String> {
    std::fs::read_dir(root.join("tmp"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("staging-"))
        .collect()
}

// ---------------------------------------------------------------------------
// GnuPG.
// ---------------------------------------------------------------------------

/// A private GnuPG home holding one fresh, passphrase-free signing key.
/// Dropping it stops the GnuPG daemons of the home and removes their socket
/// directory.
#[cfg(feature = "verify-gpg")]
pub struct GnupgHome {
    pub dir: std::path::PathBuf,
}

#[cfg(feature = "verify-gpg")]
impl GnupgHome {
    pub fn new(dir: &Path, uid: &str) -> GnupgHome {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(dir).unwrap();
        let status = std::process::Command::new("gpg")
            .arg("--homedir")
            .arg(dir)
            .args(["--batch", "--pinentry-mode", "loopback", "--passphrase", ""])
            .args(["--quick-gen-key", uid, "ed25519", "sign", "never"])
            .status()
            .unwrap();
        assert!(status.success(), "gpg --quick-gen-key failed");
        GnupgHome {
            dir: dir.to_owned(),
        }
    }

    /// The public certificates of the home, as `gpg --export` writes them.
    pub fn export(&self) -> Vec<u8> {
        let out = std::process::Command::new("gpg")
            .arg("--homedir")
            .arg(&self.dir)
            .args(["--batch", "--export"])
            .output()
            .unwrap();
        assert!(
            out.status.success() && !out.stdout.is_empty(),
            "gpg --export failed"
        );
        out.stdout
    }
}

#[cfg(feature = "verify-gpg")]
impl Drop for GnupgHome {
    fn drop(&mut self) {
        super::remove_gnupg_sockets(&self.dir);
    }
}
