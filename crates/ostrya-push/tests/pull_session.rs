//! The client session of the pull against scripted servers over a bounded
//! in-process pipe. The tests cover the hello and the version, the pipeline,
//! the reply bodies, the length checks, the end of the session, and the errors
//! that later calls repeat.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::future;
use futures_lite::io::AsyncReadExt;
use ostrya_push::proto::{
    ErrorMessage, FrameReader, FrameWriter, GetReply, Message, PULL_PROTOCOL_VERSION,
    PullHelloReply,
};
use ostrya_push::{Error, ErrorCode, PullBody, PullSession, PullSessionOptions};

/// The capacity of each pipe. It is smaller than a large body, so the server
/// waits for the client to read.
const PIPE_CAP: usize = 16 * 1024;

/// The time bound of each test.
const LIMIT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// A bounded pipe.
// ---------------------------------------------------------------------------

struct PipeState {
    buf: VecDeque<u8>,
    writer_closed: bool,
    reader_closed: bool,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

/// The write half of a bounded pipe. After a drop of this half, the reader
/// reads end of file.
struct PipeWriter(Arc<Mutex<PipeState>>);

/// The read half of a bounded pipe. After a drop of this half, each later
/// write fails with `BrokenPipe`.
struct PipeReader(Arc<Mutex<PipeState>>);

fn pipe() -> (PipeWriter, PipeReader) {
    let state = Arc::new(Mutex::new(PipeState {
        buf: VecDeque::new(),
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
        let room = PIPE_CAP - st.buf.len();
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
// The scripted server.
// ---------------------------------------------------------------------------

/// The server end of a session.
struct Server {
    reader: FrameReader<PipeReader>,
    writer: FrameWriter<PipeWriter>,
}

impl Server {
    async fn recv(&mut self) -> Option<Message> {
        self.reader.read_message().await.unwrap()
    }

    async fn send(&mut self, msg: &Message) {
        self.writer.write_message(msg).await.unwrap();
        self.writer.flush().await.unwrap();
    }

    /// Reads `PullHello` and replies with `version`.
    async fn hello(&mut self, version: u32) {
        match self.recv().await {
            Some(Message::PullHello(hello)) => assert_eq!(hello.version, PULL_PROTOCOL_VERSION),
            other => panic!("{other:?}"),
        }
        self.send(&Message::PullHelloReply(PullHelloReply { version }))
            .await;
    }

    /// Reads one `Get` and returns its path.
    async fn path(&mut self) -> String {
        match self.recv().await {
            Some(Message::Get(path)) => path,
            other => panic!("{other:?}"),
        }
    }

    /// Replies with `found` set to `true` and with `len`. Then sends `body` in
    /// chunks of `chunk` bytes, and then the end of the body.
    async fn body(&mut self, len: Option<u64>, body: &[u8], chunk: usize) {
        self.send(&Message::GetReply(GetReply { found: true, len }))
            .await;
        for piece in body.chunks(chunk) {
            self.writer.write_object_data(piece).await.unwrap();
        }
        self.writer.end_object().await.unwrap();
        self.writer.flush().await.unwrap();
    }

    async fn not_found(&mut self) {
        self.send(&Message::GetReply(GetReply {
            found: false,
            len: None,
        }))
        .await;
    }

    async fn error(&mut self, code: ErrorCode, message: &str) {
        self.send(&Message::Error(error_message(code, message)))
            .await;
    }
}

fn error_message(code: ErrorCode, message: &str) -> ErrorMessage {
    ErrorMessage {
        code,
        message: message.to_owned(),
        missing: Vec::new(),
        current: None,
    }
}

/// The two ends of a session: the streams of the client and the server.
fn ends() -> ((PipeReader, PipeWriter), Server) {
    let (to_server, server_in) = pipe();
    let (server_out, from_server) = pipe();
    (
        (from_server, to_server),
        Server {
            reader: FrameReader::new(server_in),
            writer: FrameWriter::new(server_out),
        },
    )
}

fn options(max_outstanding: Option<usize>) -> PullSessionOptions {
    PullSessionOptions {
        agent: Some("pull-session-test".to_owned()),
        max_outstanding,
    }
}

/// Runs the client and the server together within the time bound.
fn run<C, S, T>(client: C, server: S) -> T
where
    C: Future<Output = T>,
    S: Future<Output = ()>,
{
    ostrya_rt::block_on(future::or(
        async {
            let (out, ()) = future::zip(client, server).await;
            out
        },
        async {
            ostrya_rt::Timer::after(LIMIT).await;
            panic!("the session took longer than {LIMIT:?}");
        },
    ))
}

/// One call of a test client, as a boxed future.
type Call<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// Polls every future of `futures` until each is done, and returns their
/// outputs in order.
async fn join_all<T>(futures: Vec<Call<'_, T>>) -> Vec<T> {
    let mut futures: Vec<_> = futures.into_iter().map(Some).collect();
    let mut outputs: Vec<Option<T>> = futures.iter().map(|_| None).collect();
    future::poll_fn(|cx| {
        let mut pending = false;
        for (slot, out) in futures.iter_mut().zip(outputs.iter_mut()) {
            if let Some(fut) = slot {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(value) => {
                        *out = Some(value);
                        *slot = None;
                    }
                    Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await;
    outputs.into_iter().map(Option::unwrap).collect()
}

async fn read_all(mut body: PullBody) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    body.read_to_end(&mut out).await?;
    Ok(out)
}

/// The error of the session that a failed read of a body carries.
fn carried(e: io::Error) -> Error {
    *e.into_inner()
        .expect("the read error carries an error")
        .downcast::<Error>()
        .expect("the read error carries the error of the session")
}

fn body_of(path: &str) -> Vec<u8> {
    path.bytes().cycle().take(100 + path.len() * 1000).collect()
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

/// Eight concurrent calls keep eight `Get` frames in flight. The server reads
/// all eight before it answers one. Each reply goes to the call of its place,
/// also a not-found reply.
#[test]
fn concurrent_calls_share_the_pipeline_in_order() {
    let paths: Vec<String> = (0..8).map(|i| format!("objects/{i:02}/file")).collect();
    let ((input, output), mut server) = ends();
    let expected = paths.clone();
    let results = run(
        async {
            let session = PullSession::over_stream(input, output, options(None))
                .await
                .unwrap();
            let calls: Vec<Call<'_, Option<Vec<u8>>>> = paths
                .iter()
                .map(|path| {
                    let session = &session;
                    Box::pin(async move {
                        match session.get(path, u64::MAX).await.unwrap() {
                            Some(body) => Some(read_all(body).await.unwrap()),
                            None => None,
                        }
                    }) as Call<'_, _>
                })
                .collect();
            let results = join_all(calls).await;
            session.finish().await.unwrap();
            results
        },
        async {
            server.hello(1).await;
            let mut seen = Vec::new();
            for _ in 0..8 {
                seen.push(server.path().await);
            }
            // The frames went on the wire in some order of the places. Each
            // reply answers the frame of its turn.
            let mut sorted = seen.clone();
            sorted.sort();
            assert_eq!(sorted, expected);
            for path in &seen {
                if path.ends_with("03/file") {
                    server.not_found().await;
                } else {
                    let body = body_of(path);
                    server.body(Some(body.len() as u64), &body, 1000).await;
                }
            }
            assert!(server.recv().await.is_none());
        },
    );
    for (path, got) in paths.iter().zip(results) {
        if path.ends_with("03/file") {
            assert_eq!(got, None);
        } else {
            assert_eq!(got.unwrap(), body_of(path), "{path}");
        }
    }
}

/// When the session reads the chunk that ends a body, it moves to the next
/// reply, also while the caller still holds that body.
#[test]
fn a_later_reply_arrives_while_the_caller_holds_a_body_read_to_its_end() {
    let ((input, output), mut server) = ends();
    run(
        async {
            let session = PullSession::over_stream(input, output, options(None))
                .await
                .unwrap();
            let mut first = session.get("a", 100).await.unwrap().unwrap();
            let mut bytes = Vec::new();
            first.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, b"first");
            // `first` is still held.
            let second = session.get("b", 100).await.unwrap().unwrap();
            assert_eq!(second.len(), None);
            assert_eq!(read_all(second).await.unwrap(), b"second");
            drop(first);
            session.finish().await.unwrap();
        },
        async {
            server.hello(1).await;
            assert_eq!(server.path().await, "a");
            server.body(Some(5), b"first", 2).await;
            assert_eq!(server.path().await, "b");
            server.body(None, b"second", 4).await;
            assert!(server.recv().await.is_none());
        },
    );
}

/// A stated length that differs from the sum of the chunks is
/// `Error::Protocol` in both directions. It also ends the session.
#[test]
fn a_stated_length_that_differs_from_the_body_is_protocol() {
    for (stated, body) in [(10u64, &b"short"[..]), (3, &b"longer"[..])] {
        let ((input, output), mut server) = ends();
        run(
            async {
                let session = PullSession::over_stream(input, output, options(None))
                    .await
                    .unwrap();
                let body = session.get("x", 100).await.unwrap().unwrap();
                assert_eq!(body.len(), Some(stated));
                let e = carried(read_all(body).await.unwrap_err());
                assert!(matches!(e, Error::Protocol(_)), "{e:?}");
                let later = session.get("y", 100).await.unwrap_err();
                assert_eq!(later.to_string(), e.to_string());
                assert!(matches!(session.finish().await, Err(Error::Protocol(_))));
            },
            async {
                server.hello(1).await;
                server.path().await;
                server.body(Some(stated), body, 100).await;
            },
        );
    }
}

/// A stated length that is more than the cap of the call ends the session
/// before the client reads the body. A body with no stated length ends the
/// session at the chunk that passes the cap.
#[test]
fn a_body_over_the_cap_ends_the_session() {
    let ((input, output), mut server) = ends();
    run(
        async {
            let session = PullSession::over_stream(input, output, options(None))
                .await
                .unwrap();
            let e = session.get("big", 4).await.unwrap_err();
            assert!(
                matches!(&e, Error::LimitExceeded(m) if m.contains("big")),
                "{e:?}"
            );
            let later = session.get("other", 4).await.unwrap_err();
            assert!(matches!(later, Error::LimitExceeded(_)), "{later:?}");
            assert_eq!(later.to_string(), e.to_string());
        },
        async {
            server.hello(1).await;
            server.path().await;
            server
                .send(&Message::GetReply(GetReply {
                    found: true,
                    len: Some(5),
                }))
                .await;
            // The client reads no body and closes its output.
            assert!(server.recv_or_eof().await);
        },
    );

    let ((input, output), mut server) = ends();
    run(
        async {
            let session = PullSession::over_stream(input, output, options(None))
                .await
                .unwrap();
            let body = session.get("big", 4).await.unwrap().unwrap();
            let e = carried(read_all(body).await.unwrap_err());
            assert!(matches!(e, Error::LimitExceeded(_)), "{e:?}");
        },
        async {
            server.hello(1).await;
            server.path().await;
            // The writes after the client dropped its input fail.
            server
                .send(&Message::GetReply(GetReply {
                    found: true,
                    len: None,
                }))
                .await;
            let _ = server.writer.write_object_data(b"12345").await;
            let _ = server.writer.flush().await;
        },
    );
}

impl Server {
    /// Waits for the end of the input of the server, and returns `true` if it
    /// came. A read error also counts as the end.
    async fn recv_or_eof(&mut self) -> bool {
        matches!(self.reader.read_message().await, Ok(None) | Err(_))
    }
}

/// A `get` future that is dropped after it takes its place ends the session.
/// A body dropped before its end also ends the session. Later calls fail with
/// the same error.
#[test]
fn a_dropped_call_or_body_ends_the_session() {
    let ((input, output), mut server) = ends();
    run(
        async {
            let session = PullSession::over_stream(input, output, options(None))
                .await
                .unwrap();
            {
                let mut call = Box::pin(session.get("dropped", 100));
                // One poll takes the place and writes the frame.
                assert!(future::poll_once(&mut call).await.is_none());
            }
            let e = session.get("later", 100).await.unwrap_err();
            assert!(
                matches!(&e, Error::InvalidInput(m) if m.contains("dropped")),
                "{e:?}"
            );
            assert!(matches!(
                session.finish().await,
                Err(Error::InvalidInput(_))
            ));
        },
        async {
            server.hello(1).await;
            assert_eq!(server.path().await, "dropped");
            assert!(server.recv_or_eof().await);
        },
    );

    let ((input, output), mut server) = ends();
    run(
        async {
            let session = PullSession::over_stream(input, output, options(None))
                .await
                .unwrap();
            let mut body = session.get("held", 100).await.unwrap().unwrap();
            let mut two = [0u8; 2];
            body.read_exact(&mut two).await.unwrap();
            drop(body);
            let e = session.get("later", 100).await.unwrap_err();
            assert!(
                matches!(&e, Error::InvalidInput(m) if m.contains("body")),
                "{e:?}"
            );
        },
        async {
            server.hello(1).await;
            server.path().await;
            server.body(Some(6), b"abcdef", 2).await;
        },
    );
}

/// An `Error` message from the server is the error of the call. Each later
/// call repeats its code and its message. An I/O error repeats its kind and
/// its message.
#[test]
fn later_calls_repeat_the_first_error() {
    let ((input, output), mut server) = ends();
    run(
        async {
            let session = PullSession::over_stream(input, output, options(None))
                .await
                .unwrap();
            let (first, second) = future::zip(session.get("a", 100), session.get("b", 100)).await;
            assert!(matches!(&first, Err(Error::Internal(m)) if m == "cannot read a"));
            assert!(matches!(&second, Err(Error::Internal(m)) if m == "cannot read a"));
            let third = session.get("c", 100).await.unwrap_err();
            assert_eq!(third.code(), Some(ErrorCode::Internal));
            assert_eq!(third.to_string(), "internal: cannot read a");
            assert!(matches!(session.finish().await, Err(Error::Internal(_))));
        },
        async {
            server.hello(1).await;
            server.path().await;
            server.error(ErrorCode::Internal, "cannot read a").await;
        },
    );

    let ((input, output), mut server) = ends();
    run(
        async {
            let session = PullSession::over_stream(input, output, options(None))
                .await
                .unwrap();
            let first = session.get("a", 100).await.unwrap_err();
            let Error::Io(io) = &first else {
                panic!("{first:?}");
            };
            assert_eq!(io.kind(), io::ErrorKind::UnexpectedEof);
            let later = session.get("b", 100).await.unwrap_err();
            let Error::Io(again) = &later else {
                panic!("{later:?}");
            };
            assert_eq!(again.kind(), io::ErrorKind::UnexpectedEof);
            assert_eq!(again.to_string(), io.to_string());
        },
        async {
            server.hello(1).await;
            server.path().await;
            // The server ends its output with no reply.
            let Server { reader, writer } = server;
            drop(writer);
            drop(reader);
        },
    );
}

/// After the abandon marker, the session reads the `Error` message. The read
/// of the body fails with the code of that message.
#[test]
fn an_abandoned_body_gives_the_code_of_its_error() {
    let ((input, output), mut server) = ends();
    run(
        async {
            let session = PullSession::over_stream(input, output, options(None))
                .await
                .unwrap();
            let body = session.get("a", 100).await.unwrap().unwrap();
            let e = carried(read_all(body).await.unwrap_err());
            assert!(
                matches!(&e, Error::Internal(m) if m == "read failed"),
                "{e:?}"
            );
            let later = session.get("b", 100).await.unwrap_err();
            assert!(matches!(later, Error::Internal(_)), "{later:?}");
        },
        async {
            server.hello(1).await;
            server.path().await;
            server
                .send(&Message::GetReply(GetReply {
                    found: true,
                    len: Some(10),
                }))
                .await;
            server.writer.write_object_data(b"abc").await.unwrap();
            server
                .writer
                .abandon_body(&error_message(ErrorCode::Internal, "read failed"))
                .await
                .unwrap();
            server.writer.flush().await.unwrap();
        },
    );
}

/// The client continues after a reply of version 1. It refuses a reply of a
/// version that it does not speak. An `Error` message at the hello is
/// returned as the `Error` variant of its code.
#[test]
fn the_hello_reply_gives_the_version_of_the_session() {
    let ((input, output), mut server) = ends();
    run(
        async {
            let session = PullSession::over_stream(input, output, options(None))
                .await
                .unwrap();
            assert!(session.get("config", 100).await.unwrap().is_none());
            session.finish().await.unwrap();
        },
        async {
            server.hello(1).await;
            server.path().await;
            server.not_found().await;
            assert!(server.recv().await.is_none());
        },
    );

    for version in [0, PULL_PROTOCOL_VERSION + 1] {
        let ((input, output), mut server) = ends();
        run(
            async {
                match PullSession::over_stream(input, output, options(None)).await {
                    Err(Error::VersionUnsupported(m)) => assert!(m.contains("version"), "{m}"),
                    Err(other) => panic!("{other:?}"),
                    Ok(_) => panic!("version {version} accepted"),
                }
            },
            async {
                server.hello(version).await;
                // The client sends no `Get`, and closes its output.
                assert!(server.recv().await.is_none());
            },
        );
    }

    let ((input, output), mut server) = ends();
    run(
        async {
            match PullSession::over_stream(input, output, options(None)).await {
                Err(Error::VersionUnsupported(m)) => assert_eq!(m, "no such version"),
                Err(other) => panic!("{other:?}"),
                Ok(_) => panic!("accepted"),
            }
        },
        async {
            server.recv().await;
            server
                .error(ErrorCode::VersionUnsupported, "no such version")
                .await;
        },
    );
}

/// The session raises a pipeline depth of 0 to 1, so the server sees one
/// `Get` at a time.
#[test]
fn a_depth_of_zero_keeps_one_get_in_flight() {
    let ((input, output), mut server) = ends();
    run(
        async {
            let session = PullSession::over_stream(input, output, options(Some(0)))
                .await
                .unwrap();
            let calls: Vec<Call<'_, Vec<u8>>> = ["a", "b", "c"]
                .into_iter()
                .map(|path| {
                    let session = &session;
                    Box::pin(async move {
                        read_all(session.get(path, 100).await.unwrap().unwrap())
                            .await
                            .unwrap()
                    }) as Call<'_, _>
                })
                .collect();
            let bodies = join_all(calls).await;
            assert_eq!(bodies, [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
            session.finish().await.unwrap();
        },
        async {
            server.hello(1).await;
            for _ in 0..3 {
                let path = server.path().await;
                // No second `Get` waits while this one is in flight.
                let early = future::poll_once(server.reader.read_message()).await;
                assert!(early.is_none(), "a second Get came early: {early:?}");
                server.body(Some(1), path.as_bytes(), 1).await;
            }
            assert!(server.recv().await.is_none());
        },
    );
}

/// If the caller holds a body that it did not read to its end, `finish` ends
/// the session uncleanly and returns `InvalidInput`. The session drops its
/// input, and a later read of the held body repeats the error.
#[test]
fn finish_with_an_unread_body_is_an_unclean_end() {
    let ((input, output), mut server) = ends();
    let held = run(
        async {
            let session = PullSession::over_stream(input, output, options(None))
                .await
                .unwrap();
            let mut body = session.get("a", 100).await.unwrap().unwrap();
            let e = session.finish().await.unwrap_err();
            assert!(
                matches!(&e, Error::InvalidInput(m) if m.contains("unread")),
                "{e:?}"
            );
            let mut bytes = Vec::new();
            let later = carried(body.read_to_end(&mut bytes).await.unwrap_err());
            assert_eq!(later.to_string(), e.to_string());
            assert!(bytes.is_empty(), "{bytes:?}");
            // The caller still holds the body while the server writes.
            body
        },
        async {
            server.hello(1).await;
            server.path().await;
            server.body(Some(3), b"abc", 3).await;
            assert!(server.recv_or_eof().await);
            let write = server.writer.write_message(&Message::Abort).await;
            assert!(
                matches!(&write, Err(Error::Io(e)) if e.kind() == io::ErrorKind::BrokenPipe),
                "the client kept its input open: {write:?}"
            );
        },
    );
    drop(held);
}

/// After the session fails, a read of a body fails with a repeat of the first
/// error and reads no more of the body.
#[test]
fn a_body_read_after_a_failure_repeats_the_failure() {
    let ((input, output), mut server) = ends();
    run(
        async {
            let session = PullSession::over_stream(input, output, options(None))
                .await
                .unwrap();
            let mut body = session.get("a", 100).await.unwrap().unwrap();
            {
                let mut call = Box::pin(session.get("b", 100));
                // One poll takes the place and writes the frame.
                assert!(future::poll_once(&mut call).await.is_none());
            }
            let mut bytes = Vec::new();
            let e = carried(body.read_to_end(&mut bytes).await.unwrap_err());
            assert!(
                matches!(&e, Error::InvalidInput(m) if m.contains("dropped")),
                "{e:?}"
            );
            assert!(bytes.is_empty(), "{bytes:?}");
        },
        async {
            server.hello(1).await;
            assert_eq!(server.path().await, "a");
            server.body(Some(3), b"abc", 3).await;
            assert_eq!(server.path().await, "b");
        },
    );
}

/// A session dropped while the caller holds a body closes its output, so the
/// server reads the end of its input.
#[test]
fn a_dropped_session_closes_its_output_while_a_body_is_held() {
    let ((input, output), mut server) = ends();
    let held = run(
        async {
            let session = PullSession::over_stream(input, output, options(None))
                .await
                .unwrap();
            let body = session.get("a", 100).await.unwrap().unwrap();
            drop(session);
            body
        },
        async {
            server.hello(1).await;
            server.path().await;
            server.body(Some(3), b"abc", 3).await;
            assert!(server.recv().await.is_none());
        },
    );
    drop(held);
}
