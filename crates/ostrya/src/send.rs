//! One pull session over a pair of streams: the serving side of the pull over
//! ssh.

use std::io;

use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::io::{AsyncReadExt, BufReader, BufWriter};

use crate::archive::{ArchiveAnswer, ArchiveView};
use crate::error::{Error, Result};
use crate::push;
use crate::push::proto::{
    FrameReader, FrameWriter, GetReply, Message, PULL_PROTOCOL_VERSION, PullHello, PullHelloReply,
};
use crate::repo::Repo;

/// The buffer size of each direction of the session stream.
const STREAM_BUFFER: usize = 64 * 1024;

/// The payload of each chunk of a body but the last. A full chunk and its
/// 4-byte length fill the output buffer, so each write to the output is at
/// most [`STREAM_BUFFER`] bytes, and no write holds a chunk length alone.
const CHUNK: usize = STREAM_BUFFER - 4;

/// How a session failed.
enum Failure {
    /// A failure with a wire code. The session sends it to the peer, and the
    /// caller gets it as [`Error::Push`].
    Wire(push::Error),
    /// A failure on the server side. The session sends it to the peer as
    /// `internal`, and the caller gets it as it is.
    Internal(Error),
    /// A body that failed after its reply. The session already wrote the
    /// abandon marker and the `Error` frame, and the caller gets the error as
    /// it is.
    Abandoned(Error),
    /// A failure of the output. The session sends nothing.
    Silent(Error),
}

/// A codec error of the reader. An end of file inside a frame is
/// `protocol`, and another error of the input stream is a failure of the
/// server. Every other error carries its wire code.
fn input(error: push::Error) -> Failure {
    match error {
        push::Error::Io(e) if e.kind() == io::ErrorKind::UnexpectedEof => Failure::Wire(
            push::Error::Protocol("the input ended inside a frame".to_owned()),
        ),
        push::Error::Io(e) => Failure::Internal(Error::Io(e)),
        other => Failure::Wire(other),
    }
}

/// An error of the writer. An error of the output stream is silent. A
/// message the codec refuses is a fault of the server, whatever code the
/// codec gives it.
fn output(error: push::Error) -> Failure {
    match error {
        push::Error::Io(e) => Failure::Silent(Error::Io(e)),
        other => Failure::Wire(push::Error::Internal(other.to_string())),
    }
}

fn out_of_order(msg: &Message) -> Failure {
    Failure::Wire(push::Error::Protocol(format!(
        "{:?} is out of order",
        msg.kind()
    )))
}

/// Whether `buf` starts with a whole frame: its 4-byte length and that
/// number of bytes.
fn complete_frame(buf: &[u8]) -> bool {
    match buf.first_chunk::<4>() {
        Some(prefix) => buf.len() - 4 >= u32::from_be_bytes(*prefix) as usize,
        None => false,
    }
}

impl Repo {
    /// Serve one pull session: read the `PullHello` and the `Get` messages of
    /// a client from `input`, and write the replies and the bodies to
    /// `output`.
    ///
    /// The session answers each `Get` through one [`ArchiveView`] of this
    /// repository, so the requests share the parsed `config` and the idle
    /// compressors of the view. A path the view does not find and a path it
    /// refuses get the same reply, `GetReply` with found false, and the
    /// session goes on. A served path gets `GetReply` with found true and the
    /// length when the view knows it, and then the body as chunks. The
    /// session reads one `Get`, answers it to the end of its body, and then
    /// reads the next. It opens no transaction and takes no lock. Read access
    /// to the repository is sufficient for an `archive`, `bare-user`,
    /// `bare-user-only`, or `bare-user-shared` repository. A `bare` or
    /// `bare-split-xattrs` repository needs an account that can read every
    /// object and its extended attributes.
    ///
    /// The frame limit is [`MIN_FRAME_LIMIT`](crate::push::proto::MIN_FRAME_LIMIT)
    /// in both directions. Each direction goes through a buffer of 64 KiB,
    /// and each chunk of a body but the last holds 64 KiB less 4 bytes. A
    /// body streams through one chunk buffer, so no content object is whole
    /// in memory. The session flushes `output` when its input buffer holds no
    /// whole frame, before a read that can wait, and after an `Error`.
    ///
    /// The call returns `Ok` at an end of file of `input` at a frame
    /// boundary, an empty `input` included. Each other end is an error:
    ///
    /// - A failure with a wire code goes to the peer as an `Error` message
    ///   and returns as [`Error::Push`]: `version-unsupported` for a
    ///   `PullHello` of version 0, `protocol` for a message out of order, a
    ///   kind of the push, a malformed frame, or an end of file inside a
    ///   frame, and `limit-exceeded` for a frame over the limit.
    /// - A failure of the view before the reply, for example a file that
    ///   cannot be read, goes to the peer as `internal` in place of the reply
    ///   and returns as the error it is. An error of `input` other than an
    ///   end of file does the same.
    /// - A body that fails after its reply ends with the abandon marker and
    ///   an `Error` with `internal`. The call returns the error of the read,
    ///   or an [`Error::Io`] of kind `UnexpectedEof` for a stored file that
    ///   ends before its stated length, or of kind `InvalidData` for one that
    ///   holds more. The session reads at most one byte past the stated
    ///   length.
    /// - A failed write of a reply or of a body to `output` sends nothing
    ///   more and returns as an [`Error::Io`]. A failure to deliver the
    ///   `Error` message does not change the returned error.
    ///
    /// The call does not close `output`.
    pub async fn send<R, W>(&self, input: R, output: W) -> Result<()>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        let mut session = Session {
            view: ArchiveView::new(self.clone()),
            reader: FrameReader::new(BufReader::with_capacity(STREAM_BUFFER, input)),
            writer: FrameWriter::new(BufWriter::with_capacity(STREAM_BUFFER, output)),
            chunk: Vec::new(),
        };
        let failure = match session.run().await {
            Ok(()) => return Ok(()),
            Err(failure) => failure,
        };
        Err(match failure {
            Failure::Wire(e) => {
                session.send_error(&e).await;
                Error::Push(e)
            }
            Failure::Internal(e) => {
                session
                    .send_error(&push::Error::Internal(e.to_string()))
                    .await;
                e
            }
            Failure::Abandoned(e) => {
                let _ = session.writer.flush().await;
                e
            }
            Failure::Silent(e) => e,
        })
    }
}

struct Session<R, W> {
    view: ArchiveView,
    reader: FrameReader<BufReader<R>>,
    writer: FrameWriter<BufWriter<W>>,
    /// The chunk buffer of the bodies, shared by every body of the session.
    chunk: Vec<u8>,
}

impl<R, W> Session<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    /// Run the session until the input ends or the session fails.
    async fn run(&mut self) -> std::result::Result<(), Failure> {
        match self.next().await? {
            Some(Message::PullHello(hello)) => self.hello(hello).await?,
            Some(other) => return Err(out_of_order(&other)),
            None => return Ok(()),
        }
        loop {
            // The futures of the reader are not cancel-safe, so the buffer
            // is inspected and no read is polled to learn whether the next
            // read can wait.
            if !complete_frame(self.reader.get_ref().buffer()) {
                self.writer.flush().await.map_err(output)?;
            }
            match self.next().await? {
                Some(Message::Get(path)) => self.get(&path).await?,
                Some(other) => return Err(out_of_order(&other)),
                None => return Ok(()),
            }
        }
    }

    async fn next(&mut self) -> std::result::Result<Option<Message>, Failure> {
        self.reader.read_message().await.map_err(input)
    }

    /// Write one message. The flush rule of the loop flushes it.
    async fn reply(&mut self, msg: &Message) -> std::result::Result<(), Failure> {
        self.writer.write_message(msg).await.map_err(output)
    }

    /// Send an `Error` message and flush. A failure to send it is ignored,
    /// because the peer can be gone.
    async fn send_error(&mut self, error: &push::Error) {
        let msg = Message::Error(error.to_message());
        if self.writer.write_message(&msg).await.is_ok() {
            let _ = self.writer.flush().await;
        }
    }

    /// Reply with the lower of the version of the client and the highest
    /// version of the server. The server speaks each version from 1 up.
    async fn hello(&mut self, hello: PullHello) -> std::result::Result<(), Failure> {
        if hello.version == 0 {
            return Err(Failure::Wire(push::Error::VersionUnsupported(format!(
                "pull protocol version 0: the server speaks versions 1 to {PULL_PROTOCOL_VERSION}"
            ))));
        }
        let version = hello.version.min(PULL_PROTOCOL_VERSION);
        self.reply(&Message::PullHelloReply(PullHelloReply { version }))
            .await
    }

    /// Answer one `Get`. The body is dropped before the next `Get`, so a
    /// built `.filez` gives its compressor back to the view first.
    async fn get(&mut self, path: &str) -> std::result::Result<(), Failure> {
        let answer = self.view.get(path).await.map_err(Failure::Internal)?;
        let found = |len| Message::GetReply(GetReply { found: true, len });
        match answer {
            ArchiveAnswer::Bytes(bytes) => {
                self.reply(&found(Some(bytes.len() as u64))).await?;
                write_bytes(&mut self.writer, &bytes).await
            }
            ArchiveAnswer::Stream { len, body } => {
                self.reply(&found(len)).await?;
                write_body(&mut self.writer, &mut self.chunk, len, body).await
            }
            ArchiveAnswer::NotFound | ArchiveAnswer::Refused => {
                let reply = GetReply {
                    found: false,
                    len: None,
                };
                self.reply(&Message::GetReply(reply)).await
            }
        }
    }
}

/// Write `bytes` as the chunks of a pull body, and end it. The chunks have
/// the shape that [`write_body`] gives.
async fn write_bytes<W: AsyncWrite + Unpin>(
    writer: &mut FrameWriter<W>,
    bytes: &[u8],
) -> std::result::Result<(), Failure> {
    for chunk in bytes.chunks(CHUNK) {
        writer.write_object_data(chunk).await.map_err(output)?;
    }
    writer.end_object().await.map_err(output)
}

/// Write `body` as the chunks of a pull body, and end it. Each chunk but the
/// last is full. With a stated `len`, at most `len + 1` bytes are read, and a
/// body that ends sooner or holds more is abandoned.
async fn write_body<W, B>(
    writer: &mut FrameWriter<W>,
    chunk: &mut Vec<u8>,
    len: Option<u64>,
    body: B,
) -> std::result::Result<(), Failure>
where
    W: AsyncWrite + Unpin,
    B: AsyncRead + Unpin,
{
    if chunk.is_empty() {
        chunk.resize(CHUNK, 0);
    }
    let mut body = body.take(len.map_or(u64::MAX, |len| len.saturating_add(1)));
    let mut total = 0u64;
    loop {
        let n = match fill(&mut body, chunk).await {
            Ok(n) => n,
            Err(e) => return abandon(writer, Error::Io(e)).await,
        };
        total += n as u64;
        if let Some(len) = len {
            if total > len {
                let e = io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the file holds more than its stated length",
                );
                return abandon(writer, Error::Io(e)).await;
            }
            if n < CHUNK && total < len {
                let e = io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the file ended before its stated length",
                );
                return abandon(writer, Error::Io(e)).await;
            }
        }
        if n > 0 {
            writer
                .write_object_data(&chunk[..n])
                .await
                .map_err(output)?;
        }
        if n < CHUNK {
            return writer.end_object().await.map_err(output);
        }
    }
}

/// Read from `body` until `chunk` is full or the body ends. A built `.filez`
/// gives its header alone in the first read, and the deflate stream gives its
/// output in bursts, so one read seldom fills the chunk.
async fn fill<B: AsyncRead + Unpin>(body: &mut B, chunk: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < chunk.len() {
        match body.read(&mut chunk[filled..]).await? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

/// Abandon the body with the abandon marker and an `Error` with `internal`.
async fn abandon<W: AsyncWrite + Unpin>(
    writer: &mut FrameWriter<W>,
    error: Error,
) -> std::result::Result<(), Failure> {
    let msg = push::Error::Internal(error.to_string()).to_message();
    writer.abandon_body(&msg).await.map_err(output)?;
    Err(Failure::Abandoned(error))
}

/// The future of a session can run on a thread pool.
const _: fn() = || {
    fn assert_send<T: Send>(_: T) {}
    let _ =
        |repo: &Repo| assert_send(repo.send(futures_lite::io::empty(), futures_lite::io::sink()));
};

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use futures_lite::future::block_on;

    use super::*;
    use crate::push::ErrorCode;
    use crate::push::proto::ObjectRead;

    /// A reader of `ok` bytes of `0x5a` that then fails, or with `ok` of
    /// `None` never ends. `read` counts the bytes it gave.
    struct Source {
        ok: Option<usize>,
        read: usize,
    }

    impl AsyncRead for Source {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let left = self.ok.map_or(usize::MAX, |ok| ok - self.read);
            if left == 0 {
                return Poll::Ready(Err(io::Error::other("the disk failed")));
            }
            // Short reads, as a pipe or a deflate stream gives them.
            let n = buf.len().min(left).min(10_000);
            buf[..n].fill(0x5a);
            self.read += n;
            Poll::Ready(Ok(n))
        }
    }

    /// Write one found reply of `len` and its body from `body` into a
    /// buffer, and return the result and the bytes written.
    fn serve<B: AsyncRead + Unpin>(
        len: Option<u64>,
        body: B,
    ) -> (std::result::Result<(), Failure>, Vec<u8>) {
        let mut writer = FrameWriter::new(Vec::new());
        let mut chunk = Vec::new();
        let result = block_on(async {
            let reply = GetReply { found: true, len };
            writer
                .write_message(&Message::GetReply(reply))
                .await
                .unwrap();
            write_body(&mut writer, &mut chunk, len, body).await
        });
        (result, writer.into_inner())
    }

    /// The chunk lengths after the reply frame at the start of `bytes`, up to
    /// the chunk of length 0 or the abandon marker, which is the last entry.
    fn chunk_lengths(bytes: &[u8]) -> Vec<u32> {
        let frame = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        let mut at = 4 + frame;
        let mut lengths = Vec::new();
        loop {
            let len = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap());
            lengths.push(len);
            if len == 0 || len == crate::push::proto::ABANDON {
                return lengths;
            }
            at += 4 + len as usize;
        }
    }

    /// A reader that fails partway ends the body with the abandon marker
    /// and an `Error` with `internal`. The full chunk before the failure is
    /// written, and the bytes after it are not.
    #[test]
    fn a_reader_that_fails_partway_abandons_the_body() {
        let (result, bytes) = serve(
            None,
            Source {
                ok: Some(100_000),
                read: 0,
            },
        );
        let Err(Failure::Abandoned(Error::Io(e))) = result else {
            panic!("the body was not abandoned");
        };
        assert_eq!(e.to_string(), "the disk failed");
        assert_eq!(
            chunk_lengths(&bytes),
            [CHUNK as u32, crate::push::proto::ABANDON]
        );

        let mut reader = FrameReader::new(&bytes[..]);
        block_on(async {
            let reply = reader.read_message().await.unwrap();
            assert_eq!(
                reply,
                Some(Message::GetReply(GetReply {
                    found: true,
                    len: None
                }))
            );
            let mut buf = vec![0u8; 200_000];
            let mut got = 0;
            let err = loop {
                match reader.read_object_data(&mut buf).await {
                    Ok(ObjectRead::Data(n)) => got += n,
                    Ok(other) => panic!("the body ended with {other:?}"),
                    Err(e) => break e,
                }
            };
            assert_eq!(got, CHUNK);
            assert_eq!(err.code(), Some(ErrorCode::Internal));
            assert_eq!(err.to_message().message, "i/o error: the disk failed");
            assert_eq!(reader.read_message().await.unwrap(), None);
        });
    }

    /// Each chunk but the last is full, and a body of a whole number of
    /// chunks ends with the chunk of length 0 alone.
    #[test]
    fn each_chunk_but_the_last_is_full() {
        for (size, expected) in [
            (0, vec![0]),
            (1, vec![1, 0]),
            (CHUNK, vec![CHUNK as u32, 0]),
            (2 * CHUNK + 1, vec![CHUNK as u32, CHUNK as u32, 1, 0]),
        ] {
            for len in [None, Some(size as u64)] {
                let (result, bytes) = serve(len, &vec![7u8; size][..]);
                assert!(result.is_ok(), "{size} {len:?}");
                assert_eq!(chunk_lengths(&bytes), expected, "{size} {len:?}");
            }
        }
    }

    /// Bytes in memory go out as the chunks that a body of the same bytes
    /// gives.
    #[test]
    fn bytes_take_the_chunks_of_a_body() {
        for size in [0, 1, CHUNK, CHUNK + 1, 2 * CHUNK + 1] {
            let data = vec![7u8; size];
            let len = Some(size as u64);
            let (result, expected) = serve(len, &data[..]);
            assert!(result.is_ok(), "{size}");
            let mut writer = FrameWriter::new(Vec::new());
            let result = block_on(async {
                let reply = GetReply { found: true, len };
                writer
                    .write_message(&Message::GetReply(reply))
                    .await
                    .unwrap();
                write_bytes(&mut writer, &data).await
            });
            assert!(result.is_ok(), "{size}");
            assert_eq!(writer.into_inner(), expected, "{size}");
        }
    }

    /// A stored length bounds the read to one byte past it. A body that ends
    /// sooner or holds more is abandoned with the error of its kind.
    #[test]
    fn a_stated_length_bounds_the_read() {
        let mut source = Source { ok: None, read: 0 };
        let (result, bytes) = serve(Some(10), &mut source);
        let Err(Failure::Abandoned(Error::Io(e))) = result else {
            panic!("a long body was not abandoned");
        };
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert_eq!(source.read, 11);
        assert_eq!(chunk_lengths(&bytes), [crate::push::proto::ABANDON]);

        let (result, bytes) = serve(Some(20), &[1u8; 10][..]);
        let Err(Failure::Abandoned(Error::Io(e))) = result else {
            panic!("a short body was not abandoned");
        };
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(chunk_lengths(&bytes), [crate::push::proto::ABANDON]);

        // A body that falls short at a chunk boundary is found at the next
        // read.
        let (result, bytes) = serve(Some(CHUNK as u64 + 1), &vec![1u8; CHUNK][..]);
        assert!(matches!(result, Err(Failure::Abandoned(_))));
        assert_eq!(
            chunk_lengths(&bytes),
            [CHUNK as u32, crate::push::proto::ABANDON]
        );
    }

    #[test]
    fn a_complete_frame_is_its_length_and_its_bytes() {
        assert!(!complete_frame(&[]));
        assert!(!complete_frame(&[0, 0, 0]));
        assert!(!complete_frame(&[0, 0, 0, 2, 14]));
        assert!(complete_frame(&[0, 0, 0, 2, 14, 0]));
        assert!(complete_frame(&[0, 0, 0, 2, 14, 0, 0]));
        assert!(!complete_frame(&[0xff, 0xff, 0xff, 0xff, 0]));
        // A frame of length 0 is whole. The reader refuses it.
        assert!(complete_frame(&[0, 0, 0, 0]));
    }

    /// The chunk payload equals that of the push, so both directions write
    /// the same shape.
    #[test]
    fn the_chunk_and_the_buffer_fill_one_write() {
        assert_eq!(CHUNK, 65_532);
        assert_eq!(CHUNK + 4, STREAM_BUFFER);
    }
}
