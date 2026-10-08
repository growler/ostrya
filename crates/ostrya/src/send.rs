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

/// The payload size of each chunk of a body, except the last chunk.
///
/// Each write to the output is at most [`STREAM_BUFFER`] bytes, because a
/// full chunk and its 4-byte length fill the output buffer. No write holds a
/// chunk length alone.
const CHUNK: usize = STREAM_BUFFER - 4;

/// The kind of failure that ends a session.
enum Failure {
    /// A failure with a wire code. The session sends it to the peer. The
    /// caller gets it as [`Error::Push`].
    Wire(push::Error),
    /// A failure on the server side. The session sends it to the peer as
    /// `internal`. The caller gets the error unchanged.
    Internal(Error),
    /// A body that failed after its reply. The session wrote the abandon
    /// marker and the `Error` frame before it made this value. The caller
    /// gets the error unchanged.
    Abandoned(Error),
    /// A failure of the output. The session sends nothing.
    Silent(Error),
}

/// Maps a codec error of the reader to a failure.
///
/// An end of file inside a frame is `protocol`. Another error of the input
/// stream is a failure of the server. Every other error keeps its wire code.
fn input(error: push::Error) -> Failure {
    match error {
        push::Error::Io(e) if e.kind() == io::ErrorKind::UnexpectedEof => Failure::Wire(
            push::Error::Protocol("the input ended inside a frame".to_owned()),
        ),
        push::Error::Io(e) => Failure::Internal(Error::Io(e)),
        other => Failure::Wire(other),
    }
}

/// Maps an error of the writer to a failure.
///
/// An error of the output stream is silent. If the codec refuses a message,
/// the failure is `internal`, whatever code the codec gives. The refusal is a
/// fault of the server.
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

/// Returns `true` if `buf` starts with a whole frame.
///
/// A whole frame is its 4-byte length and that number of bytes.
fn complete_frame(buf: &[u8]) -> bool {
    match buf.first_chunk::<4>() {
        Some(prefix) => buf.len() - 4 >= u32::from_be_bytes(*prefix) as usize,
        None => false,
    }
}

/// Methods that serve a pull session.
impl Repo {
    /// Serves one pull session over the streams `input` and `output`.
    ///
    /// The session reads a `PullHello` message and then `Get` messages of a
    /// client from `input`. It writes the replies and the bodies to `output`.
    /// This method is the serving side of a pull over ssh. It does not close
    /// `output`.
    ///
    /// # Requests
    ///
    /// The session answers each `Get` through one [`ArchiveView`] of this
    /// repository. All requests of the session share the parsed `config` and
    /// the idle compressors of the view. The session reads one `Get`, answers
    /// it to the end of its body, and then reads the next `Get`.
    ///
    /// - If the view does not find the path, or refuses it, the reply is a
    ///   `GetReply` with `found` set to `false`. The session continues.
    /// - If the view serves the path, the reply is a `GetReply` with `found`
    ///   set to `true`. The reply holds the length if the view knows it. The
    ///   body follows as chunks.
    ///
    /// # Access
    ///
    /// The session opens no transaction and takes no lock. For an `archive`,
    /// `bare-user`, `bare-user-only`, or `bare-user-shared` repository, read
    /// access to the repository is sufficient. For a `bare` or
    /// `bare-split-xattrs` repository, the account must be able to read every
    /// object and its extended attributes.
    ///
    /// # Framing and memory
    ///
    /// The frame limit is [`MIN_FRAME_LIMIT`](crate::push::proto::MIN_FRAME_LIMIT)
    /// in the two directions. Each direction goes through a buffer of 64 KiB.
    /// Each chunk of a body, except the last chunk, holds 64 KiB less 4 bytes.
    ///
    /// A body streams through one chunk buffer, so no content object is whole
    /// in memory. For a stored file, the session reads at most one byte past
    /// the stated length.
    ///
    /// If the input buffer holds no whole frame, the next read can wait. The
    /// session flushes `output` before that read. It also flushes `output`
    /// after each `Error` message.
    ///
    /// # End of a session
    ///
    /// At an end of file of `input` at a frame boundary, the method returns
    /// `Ok`. An empty `input` also gives `Ok`. Every other end of the session
    /// is an error. The session tells the peer about the failure:
    ///
    /// - If the failure has a wire code, the session sends an `Error` message
    ///   with that code.
    /// - If the view fails before the reply, the session sends an `Error`
    ///   message with the code `internal` in place of the reply. A file that
    ///   the process cannot read is an example.
    /// - If a read of `input` fails with an error other than an end of file,
    ///   the session sends an `Error` message with the code `internal`.
    /// - If a body fails after its reply, the session ends the body with the
    ///   abandon marker and an `Error` message with the code `internal`.
    /// - If a write of a reply or of a body to `output` fails, the session
    ///   sends nothing more.
    ///
    /// If the session cannot deliver the `Error` message, the returned error
    /// does not change.
    ///
    /// # Errors
    ///
    /// - [`Error::Push`] with the code `version-unsupported` if the
    ///   `PullHello` states version 0.
    /// - [`Error::Push`] with the code `protocol` if a message is out of
    ///   order or is a kind of the push.
    /// - [`Error::Push`] with the code `protocol` if a frame is malformed, or
    ///   if `input` ends inside a frame.
    /// - [`Error::Push`] with the code `limit-exceeded` if a frame is larger
    ///   than the limit.
    /// - [`Error::Push`] with the code `internal` if the codec refuses a
    ///   message that the session writes.
    /// - Each error of [`ArchiveView::get`] if the view fails before the
    ///   reply.
    /// - [`Error::Io`] if a read of `input` fails with an error other than an
    ///   end of file.
    /// - [`Error::Io`] with the error of the read if a body fails after its
    ///   reply. For a stored file that ends before its stated length, the
    ///   kind is `UnexpectedEof`. For a stored file that holds more, the kind
    ///   is `InvalidData`.
    /// - [`Error::Io`] if a write of a reply or of a body to `output` fails.
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
    /// The chunk buffer of the bodies. Every body of the session uses it.
    chunk: Vec<u8>,
}

impl<R, W> Session<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    /// Runs the session until the input ends or the session fails.
    async fn run(&mut self) -> std::result::Result<(), Failure> {
        match self.next().await? {
            Some(Message::PullHello(hello)) => self.hello(hello).await?,
            Some(other) => return Err(out_of_order(&other)),
            None => return Ok(()),
        }
        loop {
            // The futures of the reader are not cancel-safe. To learn if the
            // next read can wait, the loop reads the buffer and polls no read.
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

    /// Writes one message. The flush rule of the loop in `run` flushes it.
    async fn reply(&mut self, msg: &Message) -> std::result::Result<(), Failure> {
        self.writer.write_message(msg).await.map_err(output)
    }

    /// Sends an `Error` message and flushes the output.
    ///
    /// The method ignores a failure to send the message, because the peer can
    /// be gone.
    async fn send_error(&mut self, error: &push::Error) {
        let msg = Message::Error(error.to_message());
        if self.writer.write_message(&msg).await.is_ok() {
            let _ = self.writer.flush().await;
        }
    }

    /// Replies with the lower of the client version and the highest server
    /// version.
    ///
    /// The server speaks each version from 1 up.
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

    /// Answers one `Get`.
    ///
    /// The method drops the body before the next `Get`, so a built `.filez`
    /// gives its compressor back to the view first.
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

/// Writes `bytes` as the chunks of a pull body, and ends the body.
///
/// The chunks have the shape that [`write_body`] gives.
async fn write_bytes<W: AsyncWrite + Unpin>(
    writer: &mut FrameWriter<W>,
    bytes: &[u8],
) -> std::result::Result<(), Failure> {
    for chunk in bytes.chunks(CHUNK) {
        writer.write_object_data(chunk).await.map_err(output)?;
    }
    writer.end_object().await.map_err(output)
}

/// Writes `body` as the chunks of a pull body, and ends the body.
///
/// Each chunk except the last chunk is full. If `len` is set, the function
/// reads at most `len + 1` bytes. It abandons a body that ends sooner or
/// holds more.
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

/// Reads from `body` until `chunk` is full or the body ends.
///
/// A built `.filez` gives its header alone in the first read. Its deflate
/// stream gives the output in bursts. Because of this, one read seldom fills
/// the chunk.
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

/// Abandons the body with the abandon marker and an `Error` with `internal`.
async fn abandon<W: AsyncWrite + Unpin>(
    writer: &mut FrameWriter<W>,
    error: Error,
) -> std::result::Result<(), Failure> {
    let msg = push::Error::Internal(error.to_string()).to_message();
    writer.abandon_body(&msg).await.map_err(output)?;
    Err(Failure::Abandoned(error))
}

/// A compile-time check that the future of a session is `Send`.
///
/// The future can run on a thread pool.
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

    /// A reader that gives `ok` bytes of `0x5a` and then fails.
    ///
    /// If `ok` is `None`, the reader never ends. `read` counts the bytes that
    /// the reader gave.
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

    /// Writes one found reply of `len` and its body from `body` into a
    /// buffer.
    ///
    /// Returns the result and the bytes written.
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

    /// Returns the chunk lengths after the reply frame at the start of
    /// `bytes`.
    ///
    /// The list ends with the chunk of length 0 or the abandon marker.
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
    /// and an `Error` with `internal`. The session writes the full chunk
    /// before the failure and no byte after it.
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

    /// Each chunk except the last chunk is full. A body of a whole number of
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

    /// A stated length limits the read to one byte past it. The session
    /// abandons a body that ends sooner or holds more, with the error of its
    /// kind.
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

        // The next read finds a body that falls short at a chunk boundary.
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

    /// The chunk payload is equal to the chunk payload of the push, so the
    /// two directions write the same shape.
    #[test]
    fn the_chunk_and_the_buffer_fill_one_write() {
        assert_eq!(CHUNK, 65_532);
        assert_eq!(CHUNK + 4, STREAM_BUFFER);
    }
}
