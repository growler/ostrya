//! The test driver of the receive side: a client of `Repo::receive` over two
//! in-process pipes, with the frame codec of `ostrya::push::proto`, and the
//! helpers the receive tests share.

use std::future::Future;
use std::path::Path;

use futures_lite::io::AsyncReadExt;
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

pub use super::pipe::{PipeReader, PipeWriter, pipe};
use super::{COMMIT, TmpDir, file_inventory, fixture_repo};

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
            one_way: false,
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

/// Write one object to `w`: its header, its bytes in pieces of 40 KiB, and
/// the end chunk.
pub async fn write_object<W>(w: &mut FrameWriter<W>, o: &Obj) -> push::Result<()>
where
    W: futures_io::AsyncWrite + Unpin,
{
    w.write_message(&Message::ObjectHeader(ObjectHeader {
        name: ObjectName::new(o.checksum, o.ty),
        encoding: o.encoding,
    }))
    .await?;
    for piece in o.bytes.chunks(40 * 1024) {
        w.write_object_data(piece).await?;
    }
    w.end_object().await
}

/// The body of one `objects` request of a `ReceiveService`: each object,
/// then `ObjectsEnd`.
pub fn body(objects: &[Obj]) -> Vec<u8> {
    block_on(async {
        let mut w = FrameWriter::new(Vec::new());
        for o in objects {
            write_object(&mut w, o).await.unwrap();
        }
        w.write_message(&Message::ObjectsEnd).await.unwrap();
        w.into_inner()
    })
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

/// One object a client sends.
#[derive(Clone)]
pub struct Obj {
    pub ty: ObjectType,
    pub checksum: Checksum,
    pub encoding: Encoding,
    pub bytes: Vec<u8>,
}

/// Every object of the fixture commit, content objects in `encoding`. The
/// `deflate` form of a content object is the `.filez` file of the archive
/// fixture, and the `raw` form is its header and payload.
pub fn fixture_objects(encoding: Encoding) -> Vec<Obj> {
    let root = fixture_repo("archive");
    let repo = block_on(Repo::open(&root)).unwrap();
    let commit = Checksum::from_hex(COMMIT).unwrap();
    let names = block_on(repo.traverse_commit(&commit, 0)).unwrap();
    let mut names: Vec<ObjectName> = names.into_iter().collect();
    names.sort_by_key(|n| (n.ty as u8, n.checksum));
    names
        .into_iter()
        .map(|name| {
            let bytes = match (name.ty, encoding) {
                (ObjectType::File, Encoding::Deflate) => std::fs::read(root.join("objects").join(
                    ostrya::loose_path(&name.checksum, ObjectType::File, RepoMode::Archive),
                ))
                .unwrap(),
                (ObjectType::File, _) => block_on(async {
                    let file = repo.load_file(&name.checksum).await.unwrap();
                    let mut bytes = frame(&file.header().serialize().unwrap()).unwrap();
                    file.reader()
                        .await
                        .unwrap()
                        .read_to_end(&mut bytes)
                        .await
                        .unwrap();
                    bytes
                }),
                (ty, _) => block_on(repo.load_object_bytes(ty, &name.checksum)).unwrap(),
            };
            let encoding = if name.ty == ObjectType::File {
                encoding
            } else {
                Encoding::Raw
            };
            Obj {
                ty: name.ty,
                checksum: name.checksum,
                encoding,
                bytes,
            }
        })
        .collect()
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

/// Wait until no staging directory is left under `root`. A session that
/// ends with no commit removes its staging directory in the background.
pub fn assert_staging_removed(root: &Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let left = staging_entries(root);
        if left.is_empty() {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "staging entries stay: {left:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// Assert that the session published nothing: the files under `objects/`,
/// the detached metadata included, are `before`, no ref is written, and no
/// staging entry is left.
pub fn assert_nothing_published(repo: &Repo, before: &[(String, Vec<u8>)]) {
    assert_eq!(
        file_inventory(repo.path(), "objects"),
        before,
        "no object published"
    );
    assert!(
        file_inventory(repo.path(), "refs").is_empty(),
        "no ref written"
    );
    assert!(
        staging_entries(repo.path()).is_empty(),
        "no staging entry left"
    );
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
