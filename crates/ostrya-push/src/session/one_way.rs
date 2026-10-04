//! The sender of a one-way stream: the messages of a push session in one
//! direction, with no reply.

use std::collections::HashSet;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_io::AsyncWrite;
use futures_lite::io::BufWriter;
use ostrya_core::{Checksum, ObjectName};

use super::progress::Counters;
use super::stream::WRITE_BUFFER;
use super::writer::{Counting, HandOver, MetaClaims, ObjectWriter, Pass, Stop, Upload};
use super::{
    Compression, ObjectSource, PushPhase, PushStats, SessionOptions, deflate_level, invalid,
    refuse_off_wire,
};
use crate::error::{Error, Result};
use crate::proto::{
    CommitRequest, Expected, Hello, MIN_FRAME_LIMIT, Message, PROTOCOL_VERSION, RefUpdate,
    encode_frame,
};

/// The output of a one-way stream. Each byte it takes reaches the caller's
/// writer, so it is handed over at once.
struct Direct<W> {
    inner: W,
}

impl<W> HandOver for Direct<W> {
    fn is_handed_over(&self) -> bool {
        true
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Direct<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}

/// Write one one-way stream to `output`: one `Hello` with `one-way` true for
/// the refs of `updates`, one object stream with `names` from `source` and
/// the detached metadata of each commit in `commits` that has some, closed
/// by `ObjectsEnd`, and one `Commit` with `updates` and `force` false. The
/// stream has no object stream when it has no object to carry.
///
/// The receiver sends no reply, so the stream reads nothing, does no
/// negotiation, and sends each name of `names`. The frame limit and the
/// chunk limit are [`MIN_FRAME_LIMIT`]. The `deflate` encoding is used for
/// the content objects when `compression` asks for it: a one-way receiver
/// accepts it in every repository mode.
///
/// Before it writes a byte, the call refuses with [`Error::InvalidInput`]:
///
/// - empty `updates`, a ref named twice, and a ref name that fails the rule
///   of [`ostrya_core::is_refspec`];
/// - an update whose expected state is [`Expected::Commit`], and an update
///   with no new commit, because the sender cannot learn the current tips;
/// - a level outside 1 through 9;
/// - a name whose type is not a file, a dirtree, a dirmeta, or a commit;
/// - a `Hello` or a `Commit` frame over [`MIN_FRAME_LIMIT`].
///
/// A source that fails while the call writes the stream, for example on a
/// missing file object or a failed read, and data of the source that the
/// stream cannot carry, end the stream inside an object: the call writes the
/// header of the object when it did not write it yet, then the abandon
/// marker and `Abort`, flushes `output`, and returns the error of the source
/// as [`Error::Source`], or [`Error::InvalidInput`] for the data. A failed
/// write returns its error, and the call writes nothing more.
///
/// The call writes `output` in blocks of 64 KiB, so the caller need not give
/// a buffered writer. It flushes `output` after `Commit` and does not close
/// it. The caller closes it, and the close gives the end of file that ends
/// the stream. A caller that keeps its writer gives `&mut W`. `opts.agent` is
/// the `agent` of `Hello`, and `opts.progress` receives the counters. The
/// statistics count each name as offered and as needed, and the phases are
/// [`PushPhase::Uploading`] and then [`PushPhase::Committing`].
pub async fn export_stream<W>(
    output: W,
    source: &dyn ObjectSource,
    names: &[ObjectName],
    commits: &[Checksum],
    updates: &[RefUpdate],
    compression: Compression,
    opts: SessionOptions,
) -> Result<PushStats>
where
    W: AsyncWrite + Unpin + Send,
{
    check_updates(updates)?;
    let level = deflate_level(compression)?;
    refuse_off_wire(names)?;
    let agent = opts
        .agent
        .unwrap_or_else(|| format!("ostrya/{}", env!("CARGO_PKG_VERSION")));
    // Each frame is encoded once, before the first byte. The stream keeps
    // the bytes of `Commit` and no message.
    let hello = frame(
        &Message::Hello(Hello {
            version: PROTOCOL_VERSION,
            agent: Some(agent),
            refs: updates.iter().map(|u| u.name.clone()).collect(),
            one_way: true,
        }),
        "Hello",
    )?;
    let commit = frame(
        &Message::Commit(CommitRequest {
            updates: updates.to_vec(),
            force: false,
        }),
        "Commit",
    )?;

    let counters = Arc::new(Counters::new(opts.progress.as_ref()));
    counters.phase(PushPhase::Uploading);
    counters.offered(names.len() as u64);
    counters.needed(names.len() as u64);
    let counting = Counting::new(Direct { inner: output }, Arc::clone(&counters));
    let mut writer = ObjectWriter::new(
        BufWriter::with_capacity(WRITE_BUFFER, counting),
        Arc::clone(&counters),
    );
    writer.frames().write_frame(&hello).await?;
    drop(hello);

    let claims = MetaClaims::default();
    let up = Upload::new(source, names, commits, level, true, &claims);
    let mut started = false;
    let mut pass = Pass::default();
    match writer.write_items(&up, &mut pass, &mut started).await {
        Ok(()) => {}
        Err(Stop::Wire(e)) => return Err(e),
        Err(Stop::Abandon {
            error,
            in_object,
            next,
        }) => {
            // A one-way receiver reads `Abort` between two objects as
            // `protocol`, so the stream opens the object it was to send and
            // abandons it. A failed write ends the call with its error.
            let mut in_object = in_object;
            if let (false, Some(header)) = (in_object, next) {
                writer
                    .frames()
                    .write_message(&Message::ObjectHeader(header))
                    .await?;
                in_object = true;
            }
            writer.abandon(in_object).await?;
            writer.frames().flush().await?;
            return Err(error);
        }
    }
    if started {
        writer.frames().write_message(&Message::ObjectsEnd).await?;
    }
    counters.phase(PushPhase::Committing);
    let frames = writer.frames();
    frames.write_frame(&commit).await?;
    frames.flush().await?;
    Ok(counters.stats())
}

/// Refuse empty `updates`, a ref named twice, a ref name that is not a
/// refspec, an expected commit, and a delete.
fn check_updates(updates: &[RefUpdate]) -> Result<()> {
    if updates.is_empty() {
        return Err(invalid("a commit needs at least one ref update"));
    }
    let mut seen = HashSet::new();
    for u in updates {
        if !ostrya_core::is_refspec(&u.name) {
            return Err(invalid(format!("'{}' is not a valid ref name", u.name)));
        }
        if !seen.insert(u.name.as_str()) {
            return Err(invalid(format!("ref '{}' is updated twice", u.name)));
        }
        if let Expected::Commit(_) = u.expected {
            return Err(invalid(format!(
                "the update of '{}' expects a commit, which a one-way stream cannot state",
                u.name
            )));
        }
        if u.new.is_none() {
            return Err(invalid(format!(
                "the update of '{}' deletes the ref, which a one-way stream cannot do",
                u.name
            )));
        }
    }
    Ok(())
}

/// The frame of `msg`. A frame over [`MIN_FRAME_LIMIT`], the limit of a
/// one-way stream, is refused.
fn frame(msg: &Message, what: &str) -> Result<Vec<u8>> {
    match encode_frame(msg, MIN_FRAME_LIMIT) {
        Ok(frame) => Ok(frame),
        Err(Error::LimitExceeded(e)) => Err(invalid(format!(
            "the {what} frame of the one-way stream: {e}"
        ))),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use futures_lite::io::{AsyncReadExt, Cursor};
    use ostrya_core::ObjectType;
    use ostrya_gvariant::Value;

    use super::super::{BoxFuture, ObjectData};
    use super::*;
    use crate::proto::{ABANDON, Encoding, FrameReader, ObjectHeader, ObjectRead};

    /// A source of metadata objects whose bytes are their checksum, with one
    /// detached metadata dict for each commit. A name in `missing` fails to
    /// open.
    struct Source {
        missing: Option<ObjectName>,
    }

    impl ObjectSource for Source {
        fn objects<'a>(&'a self, _: &'a Checksum) -> BoxFuture<'a, Result<Vec<ObjectName>>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn open<'a>(
            &'a self,
            name: &'a ObjectName,
            _: Encoding,
        ) -> BoxFuture<'a, Result<ObjectData>> {
            Box::pin(async move {
                if self.missing == Some(*name) {
                    return Err(invalid("no such object"));
                }
                Ok(ObjectData::Encoded {
                    encoding: Encoding::Raw,
                    reader: Box::new(Cursor::new(name.checksum.as_bytes().to_vec())),
                })
            })
        }

        fn detached_metadata<'a>(
            &'a self,
            _: &'a Checksum,
        ) -> BoxFuture<'a, Result<Option<Value>>> {
            Box::pin(async {
                let mut dict = ostrya_gvariant::DictBuilder::new();
                dict.insert_str("k", "v");
                Ok(Some(dict.build()))
            })
        }
    }

    fn commit() -> Checksum {
        Checksum::from_bytes([1; 32])
    }

    fn names() -> Vec<ObjectName> {
        vec![
            ObjectName::new(commit(), ObjectType::Commit),
            ObjectName::new(Checksum::from_bytes([2; 32]), ObjectType::DirTree),
            ObjectName::new(Checksum::from_bytes([3; 32]), ObjectType::DirMeta),
        ]
    }

    fn update(name: &str, expected: Expected, new: Option<Checksum>) -> RefUpdate {
        RefUpdate {
            name: name.into(),
            expected,
            new,
        }
    }

    fn updates() -> Vec<RefUpdate> {
        vec![
            update("main", Expected::Absent, Some(commit())),
            update("origin:main", Expected::Any, Some(commit())),
        ]
    }

    fn export<W: AsyncWrite + Unpin + Send>(
        source: &Source,
        names: &[ObjectName],
        updates: &[RefUpdate],
        compression: Compression,
        out: W,
    ) -> Result<PushStats> {
        ostrya_rt::block_on(export_stream(
            out,
            source,
            names,
            &[commit()],
            updates,
            compression,
            SessionOptions::default(),
        ))
    }

    /// Read the body of the current object to its end.
    fn body(reader: &mut FrameReader<&[u8]>) -> Vec<u8> {
        let mut out = Vec::new();
        ostrya_rt::block_on(reader.object_body().read_to_end(&mut out)).unwrap();
        out
    }

    fn next(reader: &mut FrameReader<&[u8]>) -> Option<Message> {
        ostrya_rt::block_on(reader.read_message()).unwrap()
    }

    /// The stream is `Hello` with `one-way` true and the refs of the
    /// updates, each object, the detached metadata of the commit, then
    /// `ObjectsEnd`, `Commit` with `force` false, and the end. The
    /// statistics count each name as offered, needed, and sent.
    #[test]
    fn the_stream_is_hello_objects_metadata_objects_end_and_commit() {
        let source = Source { missing: None };
        let mut out = Vec::new();
        let stats = export(&source, &names(), &updates(), Compression::None, &mut out).unwrap();
        assert_eq!(stats.objects_total, 3);
        assert_eq!(stats.objects_needed, 3);
        assert_eq!(stats.objects_sent, 3);
        assert_eq!(stats.bytes_sent, out.len() as u64);

        let mut reader = FrameReader::new(&out[..]);
        match next(&mut reader) {
            Some(Message::Hello(hello)) => {
                assert!(hello.one_way);
                assert_eq!(hello.version, PROTOCOL_VERSION);
                assert_eq!(hello.refs, vec!["main", "origin:main"]);
            }
            other => panic!("{other:?}"),
        }
        for name in names() {
            assert_eq!(
                next(&mut reader),
                Some(Message::ObjectHeader(ObjectHeader {
                    name,
                    encoding: Encoding::Raw,
                }))
            );
            assert_eq!(body(&mut reader), name.checksum.as_bytes());
        }
        assert_eq!(
            next(&mut reader),
            Some(Message::ObjectHeader(ObjectHeader {
                name: ObjectName::new(commit(), ObjectType::CommitMeta),
                encoding: Encoding::Raw,
            }))
        );
        assert!(!body(&mut reader).is_empty());
        assert_eq!(next(&mut reader), Some(Message::ObjectsEnd));
        assert_eq!(
            next(&mut reader),
            Some(Message::Commit(CommitRequest {
                updates: updates(),
                force: false,
            }))
        );
        assert_eq!(next(&mut reader), None);
    }

    /// An output that takes each byte until `fail` is set. After that it
    /// fails each call of `poll_write`, `poll_flush`, and `poll_close`, and
    /// counts it in `failed`.
    struct Probe {
        fail: Arc<AtomicBool>,
        failed: usize,
    }

    impl Probe {
        fn new(fail: bool) -> Probe {
            Probe {
                fail: Arc::new(AtomicBool::new(fail)),
                failed: 0,
            }
        }

        fn call<T>(&mut self, ok: T) -> Poll<io::Result<T>> {
            if self.fail.load(Ordering::Relaxed) {
                self.failed += 1;
                return Poll::Ready(Err(io::Error::other("the output fails")));
            }
            Poll::Ready(Ok(ok))
        }
    }

    impl AsyncWrite for Probe {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.get_mut().call(buf.len())
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.get_mut().call(())
        }

        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.get_mut().call(())
        }
    }

    /// Each refusal comes before the first byte, as `InvalidInput`, and
    /// makes no call on the output.
    #[test]
    fn a_refusal_writes_nothing() {
        let source = Source { missing: None };
        let long = |n: usize, len: usize| {
            (0..n)
                .map(|i| update(&format!("{i:0len$}"), Expected::Any, Some(commit())))
                .collect::<Vec<_>>()
        };
        let cases: Vec<(&str, Vec<RefUpdate>, Compression, Vec<ObjectName>)> = vec![
            ("empty updates", vec![], Compression::None, names()),
            (
                "a ref named twice",
                vec![updates()[0].clone(), updates()[0].clone()],
                Compression::None,
                names(),
            ),
            (
                "an invalid ref name",
                vec![update("a/../b", Expected::Any, Some(commit()))],
                Compression::None,
                names(),
            ),
            (
                "an expected commit",
                vec![update("main", Expected::Commit(commit()), Some(commit()))],
                Compression::None,
                names(),
            ),
            (
                "a delete",
                vec![update("main", Expected::Any, None)],
                Compression::None,
                names(),
            ),
            (
                "level 0",
                updates(),
                Compression::Deflate { level: 0 },
                names(),
            ),
            (
                "level 10",
                updates(),
                Compression::Deflate { level: 10 },
                names(),
            ),
            (
                "a name off the wire",
                updates(),
                Compression::None,
                vec![ObjectName::new(commit(), ObjectType::CommitMeta)],
            ),
            (
                "a Hello frame over the limit",
                long(30_000, 40),
                Compression::None,
                names(),
            ),
            (
                "a Commit frame over the limit",
                long(20_000, 40),
                Compression::None,
                names(),
            ),
        ];
        for (case, updates, compression, names) in cases {
            let mut out = Probe::new(true);
            match export(&source, &names, &updates, compression, &mut out) {
                Err(Error::InvalidInput(_)) => {}
                other => panic!("{case}: {other:?}"),
            }
            assert_eq!(out.failed, 0, "{case}: calls on the output");
        }
        // The Commit frame is the one over the limit in the last case.
        let hello = Message::Hello(Hello {
            version: PROTOCOL_VERSION,
            agent: Some("ostrya".into()),
            refs: long(20_000, 40).into_iter().map(|u| u.name).collect(),
            one_way: true,
        });
        frame(&hello, "Hello").unwrap();
    }

    /// A source that fails to open an object ends the stream inside that
    /// object: its header, the abandon marker, and `Abort`. The call returns
    /// the error of the source.
    #[test]
    fn a_failed_source_abandons_the_object_it_was_to_send() {
        let missing = names()[1];
        let source = Source {
            missing: Some(missing),
        };
        let mut out = Vec::new();
        match export(&source, &names(), &updates(), Compression::None, &mut out) {
            Err(Error::Source(_)) => {}
            other => panic!("{other:?}"),
        }
        let mut reader = FrameReader::new(&out[..]);
        assert!(matches!(next(&mut reader), Some(Message::Hello(_))));
        assert!(matches!(next(&mut reader), Some(Message::ObjectHeader(_))));
        body(&mut reader);
        assert_eq!(
            next(&mut reader),
            Some(Message::ObjectHeader(ObjectHeader {
                name: missing,
                encoding: Encoding::Raw,
            }))
        );
        let mut buf = [0u8; 64];
        assert_eq!(
            ostrya_rt::block_on(reader.read_object_data(&mut buf)).unwrap(),
            ObjectRead::Abandoned
        );
        assert_eq!(next(&mut reader), None);
        let tail = [&ABANDON.to_be_bytes()[..], &[0, 0, 0, 2, 11, 0]].concat();
        assert!(out.ends_with(&tail));
    }

    /// A failed write of the header of the object that the source fails to
    /// open ends the call with the error of the write, and the call writes
    /// nothing more: no `Abort` and no flush.
    #[test]
    fn a_failed_header_write_ends_the_call() {
        /// A source whose first name has `len` bytes, and whose other names
        /// fail to open and make the output fail.
        struct Failing {
            len: usize,
            fail: Arc<AtomicBool>,
        }

        impl ObjectSource for Failing {
            fn objects<'a>(&'a self, _: &'a Checksum) -> BoxFuture<'a, Result<Vec<ObjectName>>> {
                Box::pin(async { Ok(Vec::new()) })
            }

            fn open<'a>(
                &'a self,
                name: &'a ObjectName,
                _: Encoding,
            ) -> BoxFuture<'a, Result<ObjectData>> {
                Box::pin(async move {
                    if *name != names()[0] {
                        self.fail.store(true, Ordering::Relaxed);
                        return Err(invalid("no such object"));
                    }
                    Ok(ObjectData::Encoded {
                        encoding: Encoding::Raw,
                        reader: Box::new(Cursor::new(vec![0; self.len])),
                    })
                })
            }

            fn detached_metadata<'a>(
                &'a self,
                _: &'a Checksum,
            ) -> BoxFuture<'a, Result<Option<Value>>> {
                Box::pin(async { Ok(None) })
            }
        }

        let header = |name: ObjectName| {
            encode_frame(
                &Message::ObjectHeader(ObjectHeader {
                    name,
                    encoding: Encoding::Raw,
                }),
                MIN_FRAME_LIMIT,
            )
            .unwrap()
            .len()
        };
        let hello = frame(
            &Message::Hello(Hello {
                version: PROTOCOL_VERSION,
                agent: Some("test".into()),
                refs: updates().into_iter().map(|u| u.name).collect(),
                one_way: true,
            }),
            "Hello",
        )
        .unwrap()
        .len();
        // The first object, its one chunk with its length, and its end
        // chunk leave one free byte in the output buffer, so the header of
        // the second object makes the buffer write to the output.
        let len = WRITE_BUFFER - 1 - hello - header(names()[0]) - 4 - 4;
        assert!(len <= super::super::writer::CHUNK_PAYLOAD);
        let mut out = Probe::new(false);
        let source = Failing {
            len,
            fail: Arc::clone(&out.fail),
        };
        let result = ostrya_rt::block_on(export_stream(
            &mut out,
            &source,
            &names(),
            &[commit()],
            &updates(),
            Compression::None,
            SessionOptions {
                agent: Some("test".into()),
                ..SessionOptions::default()
            },
        ));
        match result {
            Err(Error::Io(_)) => {}
            other => panic!("{other:?}"),
        }
        assert_eq!(out.failed, 1, "calls on the output after the failure");
    }
}
