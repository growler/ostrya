//! `PushSession` against `Repo::receive` over two in-process pipes: the
//! fixture commit, pushed from a source over the archive fixture.

#![cfg(feature = "receive")]

mod common;

use std::collections::HashSet;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};

use common::receive::{PipeWriter, connect, fixture_objects, new_repo};
use common::{COMMIT, TmpDir, fixture_repo};
use futures_io::AsyncWrite;
use futures_lite::future::zip;
use futures_lite::io::Cursor;
use ostrya::push::{
    BoxFuture, Compression, Encoding, Error, Expected, ObjectData, ObjectSource, PushOutcome,
    PushSession, RefUpdate, SessionOptions,
};
use ostrya::{
    Checksum, DictBuilder, FileKind, FsckOptions, ObjectName, ObjectType, ReceivePolicy,
    ReceiveReport, Repo, RepoMode, Value,
};
use ostrya_rt::block_on;

fn fixture_commit() -> Checksum {
    Checksum::from_hex(COMMIT).unwrap()
}

/// How the source gives a content object the session asks for in `deflate`.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Filez {
    /// As its header and payload, for the session to deflate.
    Encode,
    /// As the stored `.filez` bytes of the archive fixture.
    Stored,
}

/// A source over the archive fixture.
struct FixtureSource {
    repo: Repo,
    root: PathBuf,
    filez: Filez,
}

impl FixtureSource {
    fn new(filez: Filez) -> FixtureSource {
        let root = fixture_repo("archive");
        FixtureSource {
            repo: block_on(Repo::open(&root)).unwrap(),
            root,
            filez,
        }
    }

    async fn load(&self, name: &ObjectName, encoding: Encoding) -> ostrya::Result<ObjectData> {
        if name.ty != ObjectType::File {
            let bytes = self.repo.load_object_bytes(name.ty, &name.checksum).await?;
            return Ok(ObjectData::Encoded {
                encoding: Encoding::Raw,
                reader: Box::new(Cursor::new(bytes)),
            });
        }
        if encoding == Encoding::Deflate && self.filez == Filez::Stored {
            let path = self.root.join("objects").join(ostrya::loose_path(
                &name.checksum,
                ObjectType::File,
                RepoMode::Archive,
            ));
            return Ok(ObjectData::Encoded {
                encoding: Encoding::Deflate,
                reader: Box::new(Cursor::new(std::fs::read(path)?)),
            });
        }
        let file = self.repo.load_file(&name.checksum).await?;
        let (size, payload) = match file.kind {
            FileKind::Regular { size } => (size, Some(Box::new(file.reader().await?) as _)),
            FileKind::Symlink { .. } => (0, None),
        };
        Ok(ObjectData::Content {
            header: file.header(),
            size,
            payload,
        })
    }
}

fn source_error(e: ostrya::Error) -> Error {
    Error::Source(Box::new(e))
}

impl ObjectSource for FixtureSource {
    fn objects<'a>(
        &'a self,
        commit: &'a Checksum,
    ) -> BoxFuture<'a, ostrya::push::Result<Vec<ObjectName>>> {
        Box::pin(async move {
            let names = self
                .repo
                .traverse_commit(commit, 0)
                .await
                .map_err(source_error)?;
            let mut names: Vec<ObjectName> = names.into_iter().collect();
            names.sort_by_key(|n| (n.ty as u8, n.checksum));
            Ok(names)
        })
    }

    fn open<'a>(
        &'a self,
        name: &'a ObjectName,
        encoding: Encoding,
    ) -> BoxFuture<'a, ostrya::push::Result<ObjectData>> {
        Box::pin(async move { self.load(name, encoding).await.map_err(source_error) })
    }

    fn detached_metadata<'a>(
        &'a self,
        _commit: &'a Checksum,
    ) -> BoxFuture<'a, ostrya::push::Result<Option<Value>>> {
        Box::pin(async move {
            let mut dict = DictBuilder::new();
            dict.insert_str("xa.pushed-by", "push_session");
            Ok(Some(dict.build()))
        })
    }
}

fn update(expected: Expected) -> RefUpdate {
    RefUpdate {
        name: "test/main".into(),
        expected,
        new: Some(fixture_commit()),
    }
}

/// A writer that passes frames through until the `CommitReply` frame, and then
/// drops that frame and every later byte and closes the stream under it.
struct DropCommitReply {
    inner: Option<PipeWriter>,
    /// Bytes of a frame that is not complete yet.
    partial: Vec<u8>,
    /// Complete frames to pass through.
    forward: Vec<u8>,
    closing: bool,
}

impl DropCommitReply {
    fn new(inner: PipeWriter) -> DropCommitReply {
        DropCommitReply {
            inner: Some(inner),
            partial: Vec::new(),
            forward: Vec::new(),
            closing: false,
        }
    }

    fn poll_forward(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.forward.is_empty() {
            let Some(inner) = self.inner.as_mut() else {
                self.forward.clear();
                break;
            };
            let n = std::task::ready!(Pin::new(inner).poll_write(cx, &self.forward))?;
            self.forward.drain(..n);
        }
        if self.closing {
            // Dropping the pipe writer gives the client end of file.
            self.inner = None;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for DropCommitReply {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        std::task::ready!(me.poll_forward(cx))?;
        if me.closing {
            return Poll::Ready(Ok(buf.len()));
        }
        me.partial.extend_from_slice(buf);
        while me.partial.len() >= 5 {
            let len = u32::from_be_bytes(me.partial[..4].try_into().unwrap()) as usize;
            if me.partial.len() < 4 + len {
                break;
            }
            let frame: Vec<u8> = me.partial.drain(..4 + len).collect();
            if frame[4] == 9 {
                me.closing = true;
                me.partial.clear();
                break;
            }
            me.forward.extend(frame);
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        std::task::ready!(me.poll_forward(cx))?;
        match me.inner.as_mut() {
            Some(inner) => Pin::new(inner).poll_flush(cx),
            None => Poll::Ready(Ok(())),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

/// What the client of one session found: the names `missing` gave, and the
/// result of the commit.
type Client = ostrya::push::Result<(Vec<ObjectName>, PushOutcome)>;

/// One push of the fixture commit from `source` into `repo`. With
/// `drop_reply` set, the server's `CommitReply` does not reach the client.
fn push(
    repo: &Repo,
    source: &FixtureSource,
    compression: Compression,
    expected: Expected,
    drop_reply: bool,
) -> (ostrya::Result<ReceiveReport>, Client) {
    let (client, server_in, server_out) = connect();
    let output = client.writer.into_inner();
    let input = client.reader.into_inner();
    let policy = ReceivePolicy::default();
    let refs = vec!["test/main".to_string()];
    let commit = fixture_commit();
    let client = async {
        let session =
            PushSession::over_stream(input, output, &refs, SessionOptions::default()).await?;
        let names = source.objects(&commit).await?;
        let missing = session.missing(&names).await?;
        session
            .send(source, &missing, &[commit], compression)
            .await?;
        let outcome = session.commit(&[update(expected)], false).await?;
        Ok((missing, outcome))
    };
    if drop_reply {
        block_on(zip(
            repo.receive(server_in, DropCommitReply::new(server_out), &policy),
            client,
        ))
    } else {
        block_on(zip(repo.receive(server_in, server_out, &policy), client))
    }
}

fn ref_file(repo: &Repo) -> Option<String> {
    std::fs::read_to_string(repo.path().join("refs/heads/test/main")).ok()
}

fn fixture_names() -> HashSet<ObjectName> {
    fixture_objects(Encoding::Raw)
        .into_iter()
        .map(|o| ObjectName::new(o.checksum, o.ty))
        .collect()
}

#[test]
fn the_fixture_commit_lands_through_a_session() {
    let cases = [
        (Filez::Encode, Compression::None),
        (Filez::Encode, Compression::Deflate { level: 6 }),
        (Filez::Stored, Compression::Deflate { level: 6 }),
    ];
    for mode in [RepoMode::Archive, RepoMode::BareUser] {
        for (filez, compression) in cases {
            let what = format!("{mode:?}, {filez:?}, {compression:?}");
            let tmp = TmpDir::new("push-session");
            let repo = new_repo(&tmp, mode, "");
            let source = FixtureSource::new(filez);
            let (report, client) = push(&repo, &source, compression, Expected::Absent, false);
            let report = report.unwrap_or_else(|e| panic!("{what}: {e}"));
            let (missing, outcome) = client.unwrap_or_else(|e| panic!("{what}: {e}"));
            assert_eq!(
                missing.iter().copied().collect::<HashSet<_>>(),
                fixture_names(),
                "{what}: the server needs every object"
            );
            assert_eq!(outcome.refs, report.refs, "{what}");
            assert_eq!(outcome.refs[0].new, Some(fixture_commit()), "{what}");
            assert_eq!(outcome.stats.objects_sent, missing.len() as u64, "{what}");
            assert_eq!(ref_file(&repo), Some(format!("{COMMIT}\n")), "{what}");
            let meta = repo.path().join("objects").join(ostrya::loose_path(
                &fixture_commit(),
                ObjectType::CommitMeta,
                mode,
            ));
            assert!(meta.exists(), "{what}: the detached metadata is stored");
            let reopened = block_on(Repo::open(repo.path())).unwrap();
            let fsck = block_on(reopened.fsck(&FsckOptions::default())).unwrap();
            assert!(fsck.is_ok(), "{what}: {fsck:?}");

            // A second push finds every object present and sends none.
            let (report, client) = push(
                &repo,
                &source,
                compression,
                Expected::Commit(fixture_commit()),
                false,
            );
            report.unwrap_or_else(|e| panic!("{what}: second push: {e}"));
            let (missing, outcome) = client.unwrap_or_else(|e| panic!("{what}: {e}"));
            assert!(missing.is_empty(), "{what}: {missing:?}");
            assert_eq!(outcome.stats.objects_sent, 0, "{what}");
            assert_eq!(ref_file(&repo), Some(format!("{COMMIT}\n")), "{what}");
        }
    }
}

#[test]
fn a_lost_commit_reply_is_an_unknown_outcome() {
    let tmp = TmpDir::new("push-session-break");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let source = FixtureSource::new(Filez::Stored);
    let (_, client) = push(
        &repo,
        &source,
        Compression::Deflate { level: 6 },
        Expected::Absent,
        true,
    );
    match client {
        Err(Error::CommitOutcomeUnknown { refs, .. }) => {
            assert_eq!(refs, vec!["test/main".to_string()]);
        }
        other => panic!("expected CommitOutcomeUnknown, got {other:?}"),
    }
    assert_eq!(
        ref_file(&repo),
        Some(format!("{COMMIT}\n")),
        "the server wrote the ref"
    );
}

#[test]
fn a_ref_mismatch_at_commit_is_definite() {
    let tmp = TmpDir::new("push-session-mismatch");
    let repo = new_repo(&tmp, RepoMode::BareUser, "");
    let source = FixtureSource::new(Filez::Encode);
    let other = Checksum::from_bytes([7; 32]);
    let (report, client) = push(
        &repo,
        &source,
        Compression::None,
        Expected::Commit(other),
        false,
    );
    assert!(report.is_err());
    match client {
        Err(Error::RefMismatch { name, current, .. }) => {
            assert_eq!(name, "test/main");
            assert_eq!(current, None);
        }
        other => panic!("expected RefMismatch, got {other:?}"),
    }
    assert_eq!(ref_file(&repo), None, "no ref written");
}
