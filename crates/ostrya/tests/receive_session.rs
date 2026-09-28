//! `Repo::receive` through the object stream: `Hello`, `Have`, the ingest of
//! each object encoding, the content rules of each repository mode, the codes
//! each failure sends, and the repository lock the session holds.
//!
//! A test client drives the session over two in-process pipes with the frame
//! codec of `ostrya::push::proto`. No case sends `Commit`, so every session
//! ends in an error, and no case publishes an object. The tests of `Commit`
//! are in `receive_commit.rs`.

#![cfg(feature = "receive")]

mod common;

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::time::{Duration, Instant};

use common::receive::{
    Client, deflate_object, foreign_holder, header, is_root, lock_holder_main, new_repo,
    raw_object, returned_code, session, sha, staging_entries,
};
use common::{TmpDir, file_inventory};
use ostrya::push::proto::{
    ErrorMessage, FrameWriter, Hello, MAX_FRAME, MAX_HAVE, Message, ObjectHeader, ObjectsReply,
};
use ostrya::push::{self, Encoding, ErrorCode};
use ostrya::{
    Checksum, DirMeta, Error, ObjectName, ObjectType, ReceivePolicy, Repo, RepoMode, Xattrs,
};
use ostrya_core::filehdr::frame;
use ostrya_rt::block_on;

/// A payload of `len` bytes that does not compress to nothing.
fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + i / 251) as u8).collect()
}

fn dirmeta(xattrs: Xattrs) -> (Checksum, Vec<u8>) {
    let bytes = DirMeta {
        uid: 0,
        gid: 0,
        mode: 0o40755,
        xattrs,
    }
    .serialize()
    .unwrap();
    (sha(&bytes), bytes)
}

fn detached_meta() -> Vec<u8> {
    let mut dict = ostrya::DictBuilder::new();
    dict.insert_str("k", "v");
    ostrya_core::to_bytes(&ostrya::Type::parse("a{sv}").unwrap(), &dict.build()).unwrap()
}

// ---------------------------------------------------------------------------
// Repositories.
// ---------------------------------------------------------------------------

/// Assert that the session published nothing and left no staging entry.
fn assert_nothing_published(repo: &Repo, before: &[(String, Vec<u8>)]) {
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

fn policy() -> ReceivePolicy {
    ReceivePolicy::default()
}

// ---------------------------------------------------------------------------
// Hello.
// ---------------------------------------------------------------------------

#[test]
fn hello_reply_states_the_repository_and_its_refs() {
    let tmp = TmpDir::new("recv-hello");
    let repo = new_repo(&tmp, RepoMode::Archive, "collection-id=org.example.C\n");
    let tip = sha(b"tip");
    let heads = repo.path().join("refs/heads");
    std::fs::write(heads.join("main"), format!("{tip}\n")).unwrap();
    let remote = repo.path().join("refs/remotes/origin");
    std::fs::create_dir_all(&remote).unwrap();
    std::fs::write(remote.join("stable"), format!("{tip}\n")).unwrap();

    let (result, reply) = session(&repo, &policy(), |mut c| async move {
        let reply = c.hello_reply(&["main", "absent", "origin:stable"]).await;
        c.send(&Message::Abort).await.unwrap();
        reply
    });
    assert_eq!(reply.version, 1);
    assert_eq!(reply.mode, "archive-z2");
    assert_eq!(reply.collection_id.as_deref(), Some("org.example.C"));
    assert_eq!(reply.max_frame, MAX_FRAME);
    assert_eq!(reply.max_have, MAX_HAVE);
    assert_eq!(reply.encodings, vec![Encoding::Raw, Encoding::Deflate]);
    assert_eq!(reply.parallel_uploads, 1);
    let refs: Vec<_> = reply
        .refs
        .iter()
        .map(|r| (r.name.as_str(), r.commit))
        .collect();
    assert_eq!(
        refs,
        vec![
            ("main", Some(tip)),
            ("absent", None),
            ("origin:stable", Some(tip))
        ]
    );
    assert!(
        matches!(result, Err(Error::Push(push::Error::Aborted))),
        "{result:?}"
    );
}

#[test]
fn an_unknown_version_is_version_unsupported() {
    let tmp = TmpDir::new("recv-version");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let (result, error) = session(&repo, &policy(), |mut c| async move {
        c.send(&Message::Hello(Hello {
            version: 2,
            agent: None,
            refs: vec![],
        }))
        .await
        .unwrap();
        c.error().await
    });
    assert_eq!(error.code, ErrorCode::VersionUnsupported);
    assert_eq!(returned_code(&result), Some(ErrorCode::VersionUnsupported));
}

#[test]
fn locking_false_is_locking_disabled() {
    let tmp = TmpDir::new("recv-locking");
    let repo = new_repo(&tmp, RepoMode::Archive, "locking=false\n");
    let (result, error) = session(&repo, &policy(), |mut c| async move {
        c.hello(&[]).await.unwrap();
        c.error().await
    });
    assert_eq!(error.code, ErrorCode::LockingDisabled);
    assert_eq!(returned_code(&result), Some(ErrorCode::LockingDisabled));
}

#[test]
fn an_invalid_ref_name_is_invalid_ref() {
    let tmp = TmpDir::new("recv-badref");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let (result, error) = session(&repo, &policy(), |mut c| async move {
        c.hello(&["../escape"]).await.unwrap();
        c.error().await
    });
    assert_eq!(error.code, ErrorCode::InvalidRef);
    assert_eq!(returned_code(&result), Some(ErrorCode::InvalidRef));
    assert!(staging_entries(repo.path()).is_empty());
}

/// A ref path that names a directory, or passes through a file, holds no
/// ref, so the reply states the ref as absent.
#[test]
fn a_ref_path_through_a_directory_or_a_file_is_absent() {
    let tmp = TmpDir::new("recv-refdir");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let tip = sha(b"tip");
    let heads = repo.path().join("refs/heads");
    std::fs::create_dir_all(heads.join("a")).unwrap();
    std::fs::write(heads.join("a/b"), format!("{tip}\n")).unwrap();
    let (_, reply) = session(&repo, &policy(), |mut c| async move {
        let reply = c.hello_reply(&["a", "a/b", "a/b/c"]).await;
        c.send(&Message::Abort).await.unwrap();
        reply
    });
    let refs: Vec<_> = reply.refs.iter().map(|r| r.commit).collect();
    assert_eq!(refs, vec![None, Some(tip), None]);
}

/// A malformed setting of the write paths is a fault of the server: the
/// session refuses at Hello with `internal`.
#[test]
fn a_malformed_write_setting_is_internal_at_hello() {
    for (mode, extra) in [
        (RepoMode::Archive, "[archive]\nzlib-level=abc\n"),
        (RepoMode::BareUser, "[ex-integrity]\nfsverity=often\n"),
        (RepoMode::BareUser, "fsync=often\n"),
    ] {
        let tmp = TmpDir::new("recv-badcfg");
        let repo = new_repo(&tmp, mode, extra);
        let (result, error) = session(&repo, &policy(), |mut c| async move {
            c.hello(&[]).await.unwrap();
            c.error().await
        });
        assert_eq!(error.code, ErrorCode::Internal, "{extra}: {error:?}");
        assert!(
            !matches!(result, Err(Error::Push(_))),
            "{extra}: the caller gets the server error, {result:?}"
        );
        assert!(staging_entries(repo.path()).is_empty());
    }
}

/// A reply the codec refuses goes to the peer as `internal`, and the caller
/// gets the same code.
#[test]
fn a_reply_over_the_frame_limit_is_internal() {
    let tmp = TmpDir::new("recv-bigreply");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    std::fs::write(
        repo.path().join("refs/heads/m"),
        format!("{}\n", sha(b"tip")),
    )
    .unwrap();
    let refs = vec!["m"; 100_000];
    let (result, error) = session(&repo, &policy(), |mut c| async move {
        c.hello(&refs).await.unwrap();
        c.error().await
    });
    assert_eq!(error.code, ErrorCode::Internal);
    assert_eq!(returned_code(&result), Some(ErrorCode::Internal));
}

#[test]
fn bare_split_xattrs_is_mode_refused_at_hello() {
    let tmp = TmpDir::new("recv-bsx");
    let repo = new_repo(&tmp, RepoMode::BareSplitXattrs, "");
    let (result, error) = session(&repo, &policy(), |mut c| async move {
        c.hello(&[]).await.unwrap();
        c.error().await
    });
    assert_eq!(error.code, ErrorCode::ModeRefused);
    assert_eq!(returned_code(&result), Some(ErrorCode::ModeRefused));
}

#[test]
fn a_non_root_server_refuses_a_bare_repository() {
    if is_root() {
        eprintln!("skipping: the refusal of a bare repository applies to a non-root server");
        return;
    }
    let tmp = TmpDir::new("recv-bare-nonroot");
    let repo = new_repo(&tmp, RepoMode::Bare, "");
    let (result, error) = session(&repo, &policy(), |mut c| async move {
        c.hello(&[]).await.unwrap();
        c.error().await
    });
    assert_eq!(error.code, ErrorCode::ModeRefused);
    assert_eq!(returned_code(&result), Some(ErrorCode::ModeRefused));
    assert!(staging_entries(repo.path()).is_empty());
}

#[test]
fn end_of_file_before_hello_sends_nothing() {
    let tmp = TmpDir::new("recv-eof");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let (result, got) = session(&repo, &policy(), |c| async move {
        let Client { writer, mut reader } = c;
        drop(writer);
        reader.read_message().await.unwrap()
    });
    assert_eq!(got, None);
    match result {
        Err(Error::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof),
        other => panic!("expected an end of file, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Protocol and limits.
// ---------------------------------------------------------------------------

/// A client script that ends with the `Error` of the server.
type Script = fn(Client) -> Pin<Box<dyn Future<Output = ErrorMessage>>>;

#[test]
fn a_message_out_of_order_is_protocol() {
    let cases: Vec<(&str, Script)> = vec![
        ("Have before Hello", |mut c| {
            Box::pin(async move {
                c.send(&Message::Have(vec![])).await.unwrap();
                c.error().await
            })
        }),
        ("a second Hello", |mut c| {
            Box::pin(async move {
                c.hello_reply(&[]).await;
                c.hello(&[]).await.unwrap();
                c.error().await
            })
        }),
        ("Have inside an object stream", |mut c| {
            Box::pin(async move {
                c.hello_reply(&[]).await;
                let (sum, bytes) = raw_object(&header(0, 0, 0o100644), b"x");
                c.object(ObjectType::File, sum, Encoding::Raw, &bytes)
                    .await
                    .unwrap();
                c.send(&Message::Have(vec![])).await.unwrap();
                c.error().await
            })
        }),
        ("a server message from the client", |mut c| {
            Box::pin(async move {
                c.hello_reply(&[]).await;
                c.send(&Message::ObjectsReply(ObjectsReply {
                    objects: 0,
                    payload_bytes: 0,
                }))
                .await
                .unwrap();
                c.error().await
            })
        }),
    ];
    for (what, script) in cases {
        let tmp = TmpDir::new("recv-order");
        let repo = new_repo(&tmp, RepoMode::Archive, "");
        let before = file_inventory(repo.path(), "objects");
        let (result, error) = session(&repo, &policy(), script);
        assert_eq!(error.code, ErrorCode::Protocol, "{what}");
        assert_eq!(returned_code(&result), Some(ErrorCode::Protocol), "{what}");
        assert_nothing_published(&repo, &before);
    }
}

#[test]
fn a_have_past_max_have_is_limit_exceeded() {
    let tmp = TmpDir::new("recv-maxhave");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let names: Vec<_> = (0..=MAX_HAVE)
        .map(|i| ObjectName::new(sha(&i.to_le_bytes()), ObjectType::File))
        .collect();
    let (result, error) = session(&repo, &policy(), |mut c| async move {
        c.hello_reply(&[]).await;
        c.send(&Message::Have(names)).await.unwrap();
        c.error().await
    });
    assert_eq!(error.code, ErrorCode::LimitExceeded);
    assert_eq!(returned_code(&result), Some(ErrorCode::LimitExceeded));
}

#[test]
fn a_frame_or_a_chunk_past_the_limit_is_limit_exceeded() {
    use futures_lite::io::AsyncWriteExt;

    for chunk in [false, true] {
        let tmp = TmpDir::new("recv-limit");
        let repo = new_repo(&tmp, RepoMode::Archive, "");
        let before = file_inventory(repo.path(), "objects");
        let (result, error) = session(&repo, &policy(), |mut c| async move {
            c.hello_reply(&[]).await;
            if chunk {
                let (sum, _) = raw_object(&header(0, 0, 0o100644), b"x");
                c.send(&Message::ObjectHeader(ObjectHeader {
                    name: ObjectName::new(sum, ObjectType::File),
                    encoding: Encoding::Raw,
                }))
                .await
                .unwrap();
            }
            let Client { writer, reader } = c;
            let mut raw = writer.into_inner();
            raw.write_all(&(MAX_FRAME + 1).to_be_bytes()).await.unwrap();
            raw.write_all(&[1]).await.unwrap();
            let mut c = Client {
                writer: FrameWriter::new(raw),
                reader,
            };
            c.error().await
        });
        assert_eq!(error.code, ErrorCode::LimitExceeded, "chunk: {chunk}");
        assert_eq!(returned_code(&result), Some(ErrorCode::LimitExceeded));
        assert_nothing_published(&repo, &before);
    }
}

// ---------------------------------------------------------------------------
// Object ingest.
// ---------------------------------------------------------------------------

#[test]
fn bytes_that_do_not_hash_to_the_name_are_checksum_mismatch() {
    let (_, raw) = raw_object(&header(0, 0, 0o100644), b"payload");
    let (_, deflated) = deflate_object(&header(0, 0, 0o100644), &payload(5000));
    let (_, meta) = dirmeta(Xattrs::empty());
    let wrong = sha(b"another object");
    let cases = [
        (ObjectType::File, Encoding::Raw, raw),
        (ObjectType::File, Encoding::Deflate, deflated),
        (ObjectType::DirMeta, Encoding::Raw, meta),
    ];
    for mode in [RepoMode::Archive, RepoMode::BareUser] {
        for (ty, encoding, bytes) in &cases {
            let tmp = TmpDir::new("recv-mismatch");
            let repo = new_repo(&tmp, mode, "");
            let before = file_inventory(repo.path(), "objects");
            let (ty, encoding, bytes) = (*ty, *encoding, bytes.clone());
            let (result, error) = session(&repo, &policy(), |mut c| async move {
                c.hello_reply(&[]).await;
                let _ = c.object(ty, wrong, encoding, &bytes).await;
                c.error().await
            });
            assert_eq!(
                error.code,
                ErrorCode::ChecksumMismatch,
                "{mode:?} {ty:?} {encoding:?}"
            );
            assert_eq!(returned_code(&result), Some(ErrorCode::ChecksumMismatch));
            assert_nothing_published(&repo, &before);
        }
    }
}

#[test]
fn each_encoding_stages_and_a_held_object_is_dropped() {
    let file = header(0, 0, 0o100644);
    let big = payload(300 * 1024);
    let (raw_sum, raw) = raw_object(&file, &big);
    let (deflate_sum, deflated) = deflate_object(&file, &payload(200 * 1024 + 3));
    let mut link = header(0, 0, 0o120777);
    link.symlink_target = "target".into();
    let (link_sum, link_raw) = raw_object(&link, b"");
    let (_, link_deflated) = deflate_object(&link, b"");
    let (meta_sum, meta) = dirmeta(Xattrs::empty());
    for mode in [
        RepoMode::Archive,
        RepoMode::BareUser,
        RepoMode::BareUserOnly,
    ] {
        let tmp = TmpDir::new("recv-ingest");
        let repo = new_repo(&tmp, mode, "");
        let before = file_inventory(repo.path(), "objects");
        let wire = (raw.len() + deflated.len() + link_raw.len() + meta.len()) as u64;
        let (raw, deflated, link_raw, link_deflated, meta) = (
            raw.clone(),
            deflated.clone(),
            link_raw.clone(),
            link_deflated.clone(),
            meta.clone(),
        );
        let (result, (first, second, have)) = session(&repo, &policy(), |mut c| async move {
            c.hello_reply(&[]).await;
            c.object(ObjectType::File, raw_sum, Encoding::Raw, &raw)
                .await
                .unwrap();
            c.object(ObjectType::File, deflate_sum, Encoding::Deflate, &deflated)
                .await
                .unwrap();
            c.object(ObjectType::File, link_sum, Encoding::Raw, &link_raw)
                .await
                .unwrap();
            c.object(ObjectType::DirMeta, meta_sum, Encoding::Raw, &meta)
                .await
                .unwrap();
            let first = c.objects_end().await;
            // The same objects again, now staged in the session, in the other
            // encoding where there is one.
            c.object(ObjectType::File, raw_sum, Encoding::Raw, &raw)
                .await
                .unwrap();
            c.object(
                ObjectType::File,
                link_sum,
                Encoding::Deflate,
                &link_deflated,
            )
            .await
            .unwrap();
            c.object(ObjectType::DirMeta, meta_sum, Encoding::Raw, &meta)
                .await
                .unwrap();
            let second = c.objects_end().await;
            c.send(&Message::Have(vec![
                ObjectName::new(raw_sum, ObjectType::File),
                ObjectName::new(deflate_sum, ObjectType::File),
                ObjectName::new(sha(b"absent"), ObjectType::File),
            ]))
            .await
            .unwrap();
            let have = match c.recv().await {
                Some(Message::HaveReply(r)) => r,
                other => panic!("expected HaveReply, got {other:?}"),
            };
            c.send(&Message::Abort).await.unwrap();
            (first, second, have)
        });
        assert_eq!(
            first,
            ObjectsReply {
                objects: 4,
                payload_bytes: wire
            },
            "{mode:?}"
        );
        assert_eq!(
            second,
            ObjectsReply {
                objects: 0,
                payload_bytes: 0
            },
            "{mode:?}"
        );
        assert!(!have.is_missing(0) && !have.is_missing(1) && have.is_missing(2));
        have.check_len(3).unwrap();
        assert!(matches!(result, Err(Error::Push(push::Error::Aborted))));
        assert_nothing_published(&repo, &before);
    }
}

#[test]
fn a_held_object_is_checked_before_it_is_dropped() {
    let file = header(0, 0, 0o100644);
    let (sum, raw) = raw_object(&file, &payload(1000));
    let (_, deflated) = deflate_object(&file, &payload(1000));
    for mode in [RepoMode::Archive, RepoMode::BareUser] {
        let tmp = TmpDir::new("recv-held");
        let repo = new_repo(&tmp, mode, "");
        // Publish the object, so the repository holds it.
        block_on(async {
            let txn = repo.transaction().await.unwrap();
            let meta = ostrya::FileMeta::regular(0, 0, 0o644);
            txn.write_regfile_inline(Some(&sum), &meta, &payload(1000))
                .await
                .unwrap();
            txn.commit().await.unwrap();
        });
        let before = file_inventory(repo.path(), "objects");
        for (encoding, bytes) in [(Encoding::Raw, &raw), (Encoding::Deflate, &deflated)] {
            // A corrupt copy of the held object, for the second session.
            let mut corrupt = bytes.clone();
            let last = corrupt.len() - 1;
            corrupt[last] ^= 0xff;
            let bytes = bytes.clone();
            let (_, (have, reply)) = session(&repo, &policy(), |mut c| async move {
                c.hello_reply(&[]).await;
                c.send(&Message::Have(vec![ObjectName::new(sum, ObjectType::File)]))
                    .await
                    .unwrap();
                let have = match c.recv().await {
                    Some(Message::HaveReply(r)) => r,
                    other => panic!("expected HaveReply, got {other:?}"),
                };
                c.object(ObjectType::File, sum, encoding, &bytes)
                    .await
                    .unwrap();
                let reply = c.objects_end().await;
                c.send(&Message::Abort).await.unwrap();
                (have, reply)
            });
            assert!(!have.is_missing(0));
            assert_eq!(
                reply,
                ObjectsReply {
                    objects: 0,
                    payload_bytes: 0
                },
                "{mode:?} {encoding:?}"
            );
            // A corrupt copy of the held object still fails.
            let (result, error) = session(&repo, &policy(), |mut c| async move {
                c.hello_reply(&[]).await;
                let _ = c.object(ObjectType::File, sum, encoding, &corrupt).await;
                c.error().await
            });
            assert!(
                matches!(
                    error.code,
                    ErrorCode::ChecksumMismatch | ErrorCode::Protocol
                ),
                "{mode:?} {encoding:?}: {error:?}"
            );
            assert!(result.is_err());
            assert_eq!(file_inventory(repo.path(), "objects"), before);
        }
    }
}

#[test]
fn an_empty_object_stream_gets_a_zero_reply() {
    let tmp = TmpDir::new("recv-empty");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let (_, reply) = session(&repo, &policy(), |mut c| async move {
        c.hello_reply(&[]).await;
        let reply = c.objects_end().await;
        c.send(&Message::Abort).await.unwrap();
        reply
    });
    assert_eq!(
        reply,
        ObjectsReply {
            objects: 0,
            payload_bytes: 0
        }
    );
}

#[test]
fn malformed_content_is_protocol() {
    let file = header(0, 0, 0o100644);
    let (sum, raw) = raw_object(&file, b"abc");
    let (dsum, deflated) = deflate_object(&file, &payload(3000));
    let mut padding = raw.clone();
    padding[5] = 1;
    let mut link = header(0, 0, 0o120777);
    link.symlink_target = "t".into();
    let (lsum, mut link_payload) = raw_object(&link, b"");
    link_payload.push(b'x');
    let mut trailing = deflated.clone();
    trailing.extend_from_slice(b"junk");
    let truncated = deflated[..deflated.len() - 10].to_vec();
    // The header declares more bytes than the payload inflates to.
    let (_, short) = deflate_object(&file, &payload(3000));
    let long_header = frame(&file.serialize_archive(3100).unwrap()).unwrap();
    let mut overstated = long_header.clone();
    overstated
        .extend_from_slice(&short[frame(&file.serialize_archive(3000).unwrap()).unwrap().len()..]);
    let (ldsum, _) = deflate_object(&link, b"");
    let link_declares = frame(&link.serialize_archive(5).unwrap()).unwrap();
    let cases: Vec<(&str, Checksum, Encoding, Vec<u8>)> = vec![
        ("framing padding", sum, Encoding::Raw, padding),
        (
            "header",
            sum,
            Encoding::Raw,
            vec![0, 0, 0, 4, 0, 0, 0, 0, 1, 2, 3, 4],
        ),
        ("symlink payload", lsum, Encoding::Raw, link_payload),
        (
            "bytes after the DEFLATE end",
            dsum,
            Encoding::Deflate,
            trailing,
        ),
        ("truncated DEFLATE", dsum, Encoding::Deflate, truncated),
        (
            "overstated declared size",
            dsum,
            Encoding::Deflate,
            overstated,
        ),
        (
            "symlink that declares a payload",
            ldsum,
            Encoding::Deflate,
            link_declares,
        ),
        (
            "object that ends inside its header",
            sum,
            Encoding::Raw,
            vec![0, 0, 0, 16, 0, 0, 0, 0, 1, 2, 3],
        ),
    ];
    for mode in [RepoMode::Archive, RepoMode::BareUser] {
        for (what, sum, encoding, bytes) in &cases {
            let tmp = TmpDir::new("recv-malformed");
            let repo = new_repo(&tmp, mode, "");
            let (sum, encoding, bytes) = (*sum, *encoding, bytes.clone());
            let (result, error) = session(&repo, &policy(), |mut c| async move {
                c.hello_reply(&[]).await;
                let _ = c.object(ObjectType::File, sum, encoding, &bytes).await;
                // A server that took the object ends the session here with no
                // Error, and the test fails rather than waits.
                let _ = c.send(&Message::ObjectsEnd).await;
                let _ = c.send(&Message::Abort).await;
                c.error().await
            });
            assert_eq!(
                error.code,
                ErrorCode::Protocol,
                "{mode:?} {what}: {error:?}"
            );
            assert_eq!(returned_code(&result), Some(ErrorCode::Protocol));
        }
    }

    // A header length past the cap is limit-exceeded.
    let tmp = TmpDir::new("recv-bighdr");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let (result, error) = session(&repo, &policy(), |mut c| async move {
        c.hello_reply(&[]).await;
        let _ = c
            .object(
                ObjectType::File,
                sum,
                Encoding::Raw,
                &[0x7f, 0, 0, 0, 0, 0, 0, 0],
            )
            .await;
        c.error().await
    });
    assert_eq!(error.code, ErrorCode::LimitExceeded);
    assert_eq!(returned_code(&result), Some(ErrorCode::LimitExceeded));
}

// ---------------------------------------------------------------------------
// Mode rules.
// ---------------------------------------------------------------------------

#[test]
fn bare_user_only_refuses_content_it_cannot_store() {
    let mut xattr = header(0, 0, 0o100644);
    xattr.xattrs = Xattrs::new([(b"user.x\0".to_vec(), b"v".to_vec())]).unwrap();
    let cases = [header(1000, 0, 0o100644), header(0, 0, 0o100775), xattr];
    for h in cases {
        let tmp = TmpDir::new("recv-buo");
        let repo = new_repo(&tmp, RepoMode::BareUserOnly, "");
        let before = file_inventory(repo.path(), "objects");
        let (sum, bytes) = raw_object(&h, b"data");
        let (result, error) = session(&repo, &policy(), |mut c| async move {
            c.hello_reply(&[]).await;
            let _ = c.object(ObjectType::File, sum, Encoding::Raw, &bytes).await;
            c.error().await
        });
        assert_eq!(error.code, ErrorCode::ModeRefused, "{h:?}");
        assert_eq!(returned_code(&result), Some(ErrorCode::ModeRefused));
        assert_nothing_published(&repo, &before);
    }
}

#[test]
fn bare_refuses_privileged_content_unless_the_policy_allows_it() {
    if !is_root() {
        eprintln!("skipping: a session on a bare repository needs a server that runs as root");
        return;
    }
    let setuid = header(0, 0, 0o104755);
    let mut capability = header(0, 0, 0o100755);
    // A version 2 file capability with the effective flag: cap_net_bind_service
    // in the permitted set.
    let cap = [1, 0, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    capability.xattrs = Xattrs::new([(b"security.capability\0".to_vec(), cap.to_vec())]).unwrap();
    let (meta_sum, meta) =
        dirmeta(Xattrs::new([(b"security.selinux\0".to_vec(), b"x\0".to_vec())]).unwrap());
    let objects: Vec<(ObjectType, Checksum, Vec<u8>)> = vec![
        {
            let (s, b) = raw_object(&setuid, b"data");
            (ObjectType::File, s, b)
        },
        {
            let (s, b) = raw_object(&capability, b"data");
            (ObjectType::File, s, b)
        },
        (ObjectType::DirMeta, meta_sum, meta),
    ];
    for (ty, sum, bytes) in objects {
        let tmp = TmpDir::new("recv-priv");
        let repo = new_repo(&tmp, RepoMode::Bare, "");
        let before = file_inventory(repo.path(), "objects");
        let b = bytes.clone();
        let (result, error) = session(&repo, &policy(), |mut c| async move {
            c.hello_reply(&[]).await;
            let _ = c.object(ty, sum, Encoding::Raw, &b).await;
            c.error().await
        });
        assert_eq!(error.code, ErrorCode::ModeRefused, "{ty:?}");
        assert_eq!(returned_code(&result), Some(ErrorCode::ModeRefused));
        assert_nothing_published(&repo, &before);

        let mut allowing = policy();
        allowing.allow_privileged = true;
        let (_, reply) = session(&repo, &allowing, |mut c| async move {
            c.hello_reply(&[]).await;
            c.object(ty, sum, Encoding::Raw, &bytes).await.unwrap();
            let reply = c.objects_end().await;
            c.send(&Message::Abort).await.unwrap();
            reply
        });
        assert_eq!(reply.objects, 1, "{ty:?}");
    }
}

// ---------------------------------------------------------------------------
// Abandon, CommitMeta, and Commit.
// ---------------------------------------------------------------------------

#[test]
fn an_abandoned_object_aborts_and_publishes_nothing() {
    let (sum, raw) = raw_object(&header(0, 0, 0o100644), &payload(100 * 1024));
    let tmp = TmpDir::new("recv-abandon");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let before = file_inventory(repo.path(), "objects");
    let (result, got) = session(&repo, &policy(), |mut c| async move {
        c.hello_reply(&[]).await;
        c.object(ObjectType::File, sum, Encoding::Raw, &raw)
            .await
            .unwrap();
        let (other, _) = raw_object(&header(0, 0, 0o100644), b"changed");
        c.writer
            .write_message(&Message::ObjectHeader(ObjectHeader {
                name: ObjectName::new(other, ObjectType::File),
                encoding: Encoding::Raw,
            }))
            .await
            .unwrap();
        c.writer.write_object_data(&raw[..5000]).await.unwrap();
        c.writer.abandon_object().await.unwrap();
        c.writer.flush().await.unwrap();
        c.recv().await
    });
    assert_eq!(
        got, None,
        "the server sends nothing after an abandoned object"
    );
    assert!(
        matches!(result, Err(Error::Push(push::Error::Aborted))),
        "{result:?}"
    );
    assert_nothing_published(&repo, &before);

    // The abandon marker followed by any frame but Abort is protocol.
    let tmp = TmpDir::new("recv-abandon-bad");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let (result, error) = session(&repo, &policy(), |mut c| async move {
        use futures_lite::io::AsyncWriteExt;
        c.hello_reply(&[]).await;
        c.writer
            .write_message(&Message::ObjectHeader(ObjectHeader {
                name: ObjectName::new(sum, ObjectType::File),
                encoding: Encoding::Raw,
            }))
            .await
            .unwrap();
        let Client { writer, reader } = c;
        let mut raw = writer.into_inner();
        raw.write_all(&[0xff; 4]).await.unwrap();
        let mut c = Client {
            writer: FrameWriter::new(raw),
            reader,
        };
        c.send(&Message::ObjectsEnd).await.unwrap();
        c.error().await
    });
    assert_eq!(error.code, ErrorCode::Protocol);
    assert_eq!(returned_code(&result), Some(ErrorCode::Protocol));
}

#[test]
fn a_second_commit_meta_for_one_commit_is_protocol() {
    let tmp = TmpDir::new("recv-commitmeta");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let commit = sha(b"a commit");
    let dict = detached_meta();
    let (result, (reply, error)) = session(&repo, &policy(), |mut c| async move {
        c.hello_reply(&[]).await;
        c.object(ObjectType::CommitMeta, commit, Encoding::Raw, &dict)
            .await
            .unwrap();
        let reply = c.objects_end().await;
        let _ = c
            .object(ObjectType::CommitMeta, commit, Encoding::Raw, &dict)
            .await;
        (reply, c.error().await)
    });
    assert_eq!(
        reply,
        ObjectsReply {
            objects: 1,
            payload_bytes: detached_meta().len() as u64
        }
    );
    assert_eq!(error.code, ErrorCode::Protocol);
    assert_eq!(returned_code(&result), Some(ErrorCode::Protocol));

    // A detached metadata object that is not a dict is protocol.
    let tmp = TmpDir::new("recv-commitmeta-bad");
    let repo = new_repo(&tmp, RepoMode::Archive, "");
    let (result, error) = session(&repo, &policy(), |mut c| async move {
        c.hello_reply(&[]).await;
        let _ = c
            .object(ObjectType::CommitMeta, commit, Encoding::Raw, b"\x01")
            .await;
        c.error().await
    });
    assert_eq!(error.code, ErrorCode::Protocol);
    assert_eq!(returned_code(&result), Some(ErrorCode::Protocol));
}

// ---------------------------------------------------------------------------
// The repository lock.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "helper process for the receive lock tests"]
fn receive_lock_holder_subprocess() {
    lock_holder_main();
}

#[test]
fn hello_under_a_foreign_lock_times_out_as_internal() {
    let tmp = TmpDir::new("recv-lock-timeout");
    let repo = new_repo(&tmp, RepoMode::Archive, "lock-timeout-secs=1\n");
    let holder = foreign_holder(repo.path(), ".lock");
    let started = Instant::now();
    let (result, error) = session(&repo, &policy(), |mut c| async move {
        c.hello(&[]).await.unwrap();
        c.error().await
    });
    let waited = started.elapsed();
    drop(holder);
    assert_eq!(error.code, ErrorCode::Internal);
    assert!(
        error
            .message
            .contains("timed out acquiring repository lock after 1s"),
        "{error:?}"
    );
    assert!(
        matches!(result, Err(Error::LockTimeout { secs: 1 })),
        "{result:?}"
    );
    assert!(
        waited >= Duration::from_secs(1),
        "the Hello returned after {waited:?}"
    );
}

#[test]
fn hello_with_minus_one_waits_for_the_lock_with_no_limit() {
    let tmp = TmpDir::new("recv-lock-nolimit");
    let repo = new_repo(&tmp, RepoMode::Archive, "lock-timeout-secs=-1\n");
    let holder = foreign_holder(repo.path(), ".lock");
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(1500));
        drop(holder);
    });
    let started = Instant::now();
    let (result, reply) = session(&repo, &policy(), |mut c| async move {
        let reply = c.hello_reply(&[]).await;
        c.send(&Message::Abort).await.unwrap();
        reply
    });
    let waited = started.elapsed();
    release.join().unwrap();
    assert_eq!(reply.max_frame, MAX_FRAME);
    assert!(
        waited >= Duration::from_millis(1500),
        "the Hello returned after {waited:?}"
    );
    assert!(
        matches!(result, Err(Error::Push(push::Error::Aborted))),
        "{result:?}"
    );
}

#[test]
fn a_lock_timeout_below_minus_one_is_refused() {
    let tmp = TmpDir::new("recv-lock-refused");
    let repo = new_repo(&tmp, RepoMode::Archive, "lock-timeout-secs=-2\n");
    let (result, error) = session(&repo, &policy(), |mut c| async move {
        c.hello(&[]).await.unwrap();
        c.error().await
    });
    assert_eq!(error.code, ErrorCode::Internal);
    assert!(matches!(result, Err(Error::InvalidFormat(_))), "{result:?}");
}
