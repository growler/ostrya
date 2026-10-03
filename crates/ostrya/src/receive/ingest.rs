//! The ingest of one object of a push object stream, and the content checks of
//! the repository mode.
//!
//! Each ingest reads the bytes of its object to their end, checks them, and
//! either stages the object in the session transaction or drops it, where the
//! repository already holds it or the session already staged it. A metadata
//! object and a detached metadata object are read whole, under
//! [`MAX_METADATA_SIZE`]. Content streams through the transaction writers in
//! bounded chunks.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use futures_io::AsyncRead;
use futures_lite::io::{AsyncReadExt, AsyncWriteExt};
use ostrya_core::{Checksum, ContentHasher, DirMeta, FileHeader, ObjectType, RepoMode, Xattrs};
use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::object::{MAX_FILE_HEADER_SIZE, MAX_METADATA_SIZE};
use crate::pull::check_canonical;
use crate::pull::http::{
    BoundedInput, check_stream_end, compressed_bound, payload_refusal, store_filez_payload,
};
use crate::push;
use crate::transaction::Transaction;
use crate::write::{COPY_CHUNK, FileMeta, check_archive_payload};

use super::session::Failure;

/// The extended attributes a `bare` repository refuses unless the policy
/// allows privileged content. The names are in their stored form, with the
/// terminating NUL.
const PRIVILEGED_XATTRS: [&[u8]; 2] = [b"security.capability\0", b"security.selinux\0"];

/// The content checks of the repository mode, fixed when the session opens.
pub(super) struct ModeRules {
    mode: RepoMode,
    allow_privileged: bool,
}

impl ModeRules {
    pub(super) fn new(mode: RepoMode, allow_privileged: bool) -> ModeRules {
        ModeRules {
            mode,
            allow_privileged,
        }
    }

    /// Whether the privileged-content rule applies: a `bare` repository whose
    /// policy does not allow privileged content.
    fn guards_privileged(&self) -> bool {
        self.mode == RepoMode::Bare && !self.allow_privileged
    }

    /// Refuse a content object the repository mode cannot store, or
    /// privileged content the policy does not allow, with `mode-refused`.
    fn check_content(&self, checksum: &Checksum, meta: &FileMeta) -> Result<(), Failure> {
        if self.guards_privileged() {
            if meta.mode & 0o6000 != 0 {
                return Err(mode_refused(format!(
                    "content object {checksum}: mode 0{:o} carries the setuid or setgid bit, \
                     and the receive policy does not allow privileged content",
                    meta.mode
                )));
            }
            refuse_privileged_xattrs("content object", checksum, &meta.xattrs)?;
        }
        if self.mode == RepoMode::BareUserOnly {
            return check_canonical(checksum, meta).map_err(|e| match e {
                Error::Pull(message) => mode_refused(message),
                other => Failure::Internal(other),
            });
        }
        Ok(())
    }

    /// Refuse a dirmeta object with privileged extended attributes the policy
    /// does not allow, with `mode-refused`.
    fn check_dirmeta(&self, checksum: &Checksum, bytes: &[u8]) -> Result<(), Failure> {
        if !self.guards_privileged() {
            return Ok(());
        }
        let meta = DirMeta::parse(bytes)
            .map_err(|e| protocol(format!("dirmeta object {checksum} does not parse: {e}")))?;
        refuse_privileged_xattrs("dirmeta object", checksum, &meta.xattrs)
    }
}

fn refuse_privileged_xattrs(
    what: &str,
    checksum: &Checksum,
    xattrs: &Xattrs,
) -> Result<(), Failure> {
    match xattrs
        .iter()
        .find(|(name, _)| PRIVILEGED_XATTRS.contains(name))
    {
        Some((name, _)) => Err(mode_refused(format!(
            "{what} {checksum}: the extended attribute {} is privileged, and the receive \
             policy does not allow privileged content",
            String::from_utf8_lossy(name.strip_suffix(&[0]).unwrap_or(name))
        ))),
        None => Ok(()),
    }
}

fn mode_refused(message: String) -> Failure {
    Failure::Wire(push::Error::ModeRefused(message))
}

fn protocol(message: String) -> Failure {
    Failure::Wire(push::Error::Protocol(message))
}

pub(super) fn limit_exceeded(message: String) -> Failure {
    Failure::Wire(push::Error::LimitExceeded(message))
}

/// The code of a failure of a write path the ingest reuses. A payload that is
/// malformed -- a corrupt DEFLATE stream, a size that does not match its
/// header, bytes after the end -- is `protocol`. A digest that does not match
/// is `checksum-mismatch`. Every other failure is on the server side and is
/// `internal`. The session reads the settings of the write paths when it
/// opens, so a malformed setting fails there and not here.
///
/// An I/O error that carries an OS error code comes from the filesystem, so it
/// is `internal`. An I/O error with no OS error code comes from a decoder over
/// the object bytes, so it is `protocol`. The errors of the object stream
/// itself are read from the stream reader before this applies.
fn classify(error: Error) -> Failure {
    match error {
        Error::ChecksumMismatch { .. } => {
            Failure::Wire(push::Error::ChecksumMismatch(error.to_string()))
        }
        Error::InvalidFormat(message) => protocol(message),
        Error::Io(e) if e.raw_os_error().is_none() => protocol(e.to_string()),
        other => Failure::Internal(other),
    }
}

/// A reader that counts the bytes it passes.
pub(super) struct Counted<R> {
    pub(super) inner: R,
    pub(super) count: u64,
}

impl<R> Counted<R> {
    pub(super) fn new(inner: R) -> Counted<R> {
        Counted { inner, count: 0 }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Counted<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        let n = ready!(Pin::new(&mut me.inner).poll_read(cx, buf))?;
        me.count += n as u64;
        Poll::Ready(Ok(n))
    }
}

fn grow(buf: &mut Vec<u8>) {
    if buf.len() < COPY_CHUNK {
        buf.resize(COPY_CHUNK, 0);
    }
}

/// Read a metadata or detached metadata object whole. The first read that
/// takes it past [`MAX_METADATA_SIZE`] is `limit-exceeded`.
///
/// The bytes are read straight into the result. Its capacity doubles as it
/// fills, up to one byte over the cap: that byte is what shows an object over
/// the cap. Each read goes into a zeroed window of at most [`COPY_CHUNK`]
/// bytes past the bytes already read, so the memory the result touches
/// follows the bytes that arrived, and one read returns at most one window.
/// `reserve` gets the length of each read that returns bytes, before the next
/// read starts, and an error from it ends the read. The result is shrunk to
/// its length.
pub(super) async fn read_capped<R, F>(
    body: &mut R,
    what: &str,
    checksum: &Checksum,
    mut reserve: F,
) -> Result<Vec<u8>, Failure>
where
    R: AsyncRead + Unpin,
    F: FnMut(u64) -> Result<(), Failure>,
{
    let limit = MAX_METADATA_SIZE as usize + 1;
    let mut bytes = Vec::new();
    loop {
        let len = bytes.len();
        let end = len + COPY_CHUNK.min(limit - len);
        if end > bytes.capacity() {
            let target = (bytes.capacity() * 2).max(end).min(limit);
            bytes.reserve_exact(target - len);
        }
        bytes.resize(end, 0);
        let n = body
            .read(&mut bytes[len..])
            .await
            .map_err(|e| classify(e.into()))?;
        bytes.truncate(len + n);
        if n == 0 {
            bytes.shrink_to_fit();
            return Ok(bytes);
        }
        if bytes.len() as u64 > MAX_METADATA_SIZE {
            return Err(limit_exceeded(format!(
                "{what} {checksum} is larger than {MAX_METADATA_SIZE} bytes"
            )));
        }
        reserve(n as u64)?;
    }
}

/// Ingest a dirtree, dirmeta, or commit object. `Ok(true)` when the object was
/// staged, `Ok(false)` when it was dropped because `held` or because the
/// repository already holds it.
///
/// `reserve` gets the length of each read, as [`read_capped`] gives it. The
/// hash runs on the blocking pool.
pub(super) async fn metadata<R, F>(
    txn: &Transaction,
    rules: &ModeRules,
    ty: ObjectType,
    checksum: &Checksum,
    held: bool,
    body: &mut R,
    reserve: F,
) -> Result<bool, Failure>
where
    R: AsyncRead + Unpin,
    F: FnMut(u64) -> Result<(), Failure>,
{
    let what = format!("{ty:?} object").to_lowercase();
    let bytes = read_capped(body, &what, checksum, reserve).await?;
    let (bytes, actual) = ostrya_rt::unblock(move || {
        let actual = Checksum::from_bytes(Sha256::digest(&bytes).into());
        (bytes, actual)
    })
    .await;
    if actual != *checksum {
        return Err(Failure::Wire(push::Error::ChecksumMismatch(format!(
            "{what} {checksum}: the bytes hash to {actual}"
        ))));
    }
    if ty == ObjectType::DirMeta {
        rules.check_dirmeta(checksum, &bytes)?;
    }
    if held {
        return Ok(false);
    }
    let stored = txn
        .stage_metadata_outcome(*checksum, ty, bytes)
        .await
        .map_err(Failure::Internal)?;
    Ok(stored)
}

/// Read the framed header of a content object: a big-endian length, four zero
/// bytes, and the header variant. `archive` selects the archive form, which
/// also declares the uncompressed payload size. The framed bytes are returned
/// for the archive form, which an archive repository stores as they arrive.
async fn read_framed_header<R: AsyncRead + Unpin>(
    body: &mut R,
    checksum: &Checksum,
    archive: bool,
) -> Result<(FileHeader, u64, Vec<u8>), Failure> {
    let mut framed = vec![0u8; 8];
    body.read_exact(&mut framed)
        .await
        .map_err(|e| classify(e.into()))?;
    if framed[4..] != [0u8; 4] {
        return Err(protocol(format!(
            "content object {checksum}: the framing padding is not zero"
        )));
    }
    let len = u64::from(u32::from_be_bytes(
        framed[..4].try_into().expect("four bytes of a length"),
    ));
    if len > MAX_FILE_HEADER_SIZE {
        return Err(limit_exceeded(format!(
            "content object {checksum}: the header of {len} bytes is larger than \
             {MAX_FILE_HEADER_SIZE} bytes"
        )));
    }
    // The header grows with the bytes that arrive, not with the length the
    // framing declares.
    (&mut *body)
        .take(len)
        .read_to_end(&mut framed)
        .await
        .map_err(|e| classify(e.into()))?;
    if framed.len() as u64 != 8 + len {
        return Err(protocol(format!(
            "content object {checksum}: the object ends inside its header"
        )));
    }
    let parsed = if archive {
        FileHeader::parse_archive(&framed[8..])
    } else {
        FileHeader::parse(&framed[8..]).map(|h| (h, 0))
    };
    let (header, declared) = parsed.map_err(|e| {
        protocol(format!(
            "content object {checksum}: the header does not parse: {e}"
        ))
    })?;
    Ok((header, declared, framed))
}

fn file_meta(header: &FileHeader) -> FileMeta {
    FileMeta {
        uid: header.uid,
        gid: header.gid,
        mode: header.mode,
        xattrs: header.xattrs.clone(),
    }
}

/// A header the content hash cannot take is `protocol`.
fn unhashable(checksum: &Checksum, error: ostrya_core::Error) -> Failure {
    protocol(format!("content object {checksum}: {error}"))
}

fn check_digest(checksum: &Checksum, actual: Checksum) -> Result<(), Failure> {
    if actual == *checksum {
        return Ok(());
    }
    Err(Failure::Wire(push::Error::ChecksumMismatch(format!(
        "content object {checksum}: the bytes hash to {actual}"
    ))))
}

/// Ingest a content object in the `raw` encoding: the framed header and the
/// payload. `Ok(true)` when the object was staged, `Ok(false)` when it was
/// read, checked, and dropped because `held`.
pub(super) async fn raw_content<R: AsyncRead + Unpin>(
    txn: &Transaction,
    rules: &ModeRules,
    checksum: &Checksum,
    held: bool,
    body: &mut R,
    buf: &mut Vec<u8>,
) -> Result<bool, Failure> {
    let (header, _, _) = read_framed_header(body, checksum, false).await?;
    let meta = file_meta(&header);
    rules.check_content(checksum, &meta)?;
    if header.is_symlink() {
        check_stream_end(checksum, "symlink header", &mut *body)
            .await
            .map_err(classify)?;
        if held {
            let hasher = ContentHasher::new(&header).map_err(|e| unhashable(checksum, e))?;
            check_digest(checksum, hasher.finish())?;
            return Ok(false);
        }
        txn.write_symlink(&header.symlink_target, &meta, Some(checksum))
            .await
            .map_err(classify)?;
        return Ok(true);
    }
    grow(buf);
    if held {
        let mut hasher = ContentHasher::new(&header).map_err(|e| unhashable(checksum, e))?;
        loop {
            let n = body.read(buf).await.map_err(|e| classify(e.into()))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        check_digest(checksum, hasher.finish())?;
        return Ok(false);
    }
    let mut writer = txn
        .content_writer(Some(checksum), &meta)
        .await
        .map_err(classify)?;
    loop {
        let n = body.read(buf).await.map_err(|e| classify(e.into()))?;
        if n == 0 {
            break;
        }
        writer
            .write_all(&buf[..n])
            .await
            .map_err(|e| Failure::Internal(e.into()))?;
    }
    writer.finish().await.map_err(classify)?;
    Ok(true)
}

/// Ingest a content object in the `deflate` encoding: the bytes of an
/// archive-mode object. `Ok(true)` when the object was staged, `Ok(false)`
/// when it was read, checked, and dropped because `held`.
pub(super) async fn deflate_content<R: AsyncRead + Unpin>(
    txn: &Transaction,
    rules: &ModeRules,
    checksum: &Checksum,
    held: bool,
    body: &mut R,
    buf: &mut Vec<u8>,
) -> Result<bool, Failure> {
    let (header, declared, framed) = read_framed_header(body, checksum, true).await?;
    let meta = file_meta(&header);
    rules.check_content(checksum, &meta)?;
    if header.is_symlink() && declared != 0 {
        return Err(protocol(format!(
            "content object {checksum}: a symlink declares a payload of {declared} bytes"
        )));
    }
    if !held {
        store_filez_payload(txn, checksum, &header, &meta, declared, &framed, body, buf)
            .await
            .map_err(classify)?;
        return Ok(true);
    }
    if header.is_symlink() {
        check_stream_end(checksum, "symlink header", &mut *body)
            .await
            .map_err(classify)?;
        let hasher = ContentHasher::new(&header).map_err(|e| unhashable(checksum, e))?;
        check_digest(checksum, hasher.finish())?;
        return Ok(false);
    }
    let source = BoundedInput::new(body, *checksum, compressed_bound(declared));
    check_archive_payload(checksum, &header, declared, source, buf)
        .await
        .map_err(|e| classify(payload_refusal(e)))?;
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn csum() -> Checksum {
        Checksum::from_bytes([7; 32])
    }

    fn refused(r: Result<(), Failure>) -> bool {
        matches!(r, Err(Failure::Wire(push::Error::ModeRefused(_))))
    }

    fn with_xattr(mut meta: FileMeta, name: &[u8]) -> FileMeta {
        meta.xattrs = Xattrs::new([(name.to_vec(), b"v".to_vec())]).unwrap();
        meta
    }

    #[test]
    fn bare_refuses_privileged_content_unless_allowed() {
        let strict = ModeRules::new(RepoMode::Bare, false);
        let open = ModeRules::new(RepoMode::Bare, true);
        let plain = FileMeta::regular(1000, 1000, 0o755);
        assert!(strict.check_content(&csum(), &plain).is_ok());
        for perm in [0o4755, 0o2755] {
            let meta = FileMeta::regular(0, 0, perm);
            assert!(refused(strict.check_content(&csum(), &meta)));
            assert!(open.check_content(&csum(), &meta).is_ok());
        }
        for name in PRIVILEGED_XATTRS {
            let meta = with_xattr(plain.clone(), name);
            assert!(refused(strict.check_content(&csum(), &meta)));
            assert!(open.check_content(&csum(), &meta).is_ok());
        }
        let meta = with_xattr(plain, b"user.x\0");
        assert!(strict.check_content(&csum(), &meta).is_ok());
    }

    #[test]
    fn bare_refuses_privileged_dirmeta_unless_allowed() {
        let dir = |name: Option<&[u8]>| {
            DirMeta {
                uid: 0,
                gid: 0,
                mode: 0o40755,
                xattrs: match name {
                    Some(n) => Xattrs::new([(n.to_vec(), b"v".to_vec())]).unwrap(),
                    None => Xattrs::empty(),
                },
            }
            .serialize()
            .unwrap()
        };
        let strict = ModeRules::new(RepoMode::Bare, false);
        let open = ModeRules::new(RepoMode::Bare, true);
        assert!(strict.check_dirmeta(&csum(), &dir(None)).is_ok());
        assert!(refused(
            strict.check_dirmeta(&csum(), &dir(Some(b"security.selinux\0")))
        ));
        assert!(
            open.check_dirmeta(&csum(), &dir(Some(b"security.selinux\0")))
                .is_ok()
        );
        assert!(matches!(
            strict.check_dirmeta(&csum(), b"junk"),
            Err(Failure::Wire(push::Error::Protocol(_)))
        ));
    }

    #[test]
    fn other_modes_apply_their_own_rules() {
        let setuid = FileMeta::regular(0, 0, 0o4755);
        for mode in [
            RepoMode::Archive,
            RepoMode::BareUser,
            RepoMode::BareUserShared,
        ] {
            let rules = ModeRules::new(mode, false);
            assert!(rules.check_content(&csum(), &setuid).is_ok());
            let meta = with_xattr(FileMeta::regular(5, 5, 0o644), b"security.capability\0");
            assert!(rules.check_content(&csum(), &meta).is_ok());
        }
        let rules = ModeRules::new(RepoMode::BareUserOnly, true);
        assert!(
            rules
                .check_content(&csum(), &FileMeta::regular(0, 0, 0o755))
                .is_ok()
        );
        assert!(refused(
            rules.check_content(&csum(), &FileMeta::regular(1000, 0, 0o644))
        ));
        assert!(refused(
            rules.check_content(&csum(), &FileMeta::regular(0, 0, 0o775))
        ));
        let meta = with_xattr(FileMeta::regular(0, 0, 0o644), b"user.x\0");
        assert!(refused(rules.check_content(&csum(), &meta)));
    }

    #[test]
    fn metadata_past_the_cap_is_limit_exceeded() {
        struct Endless;
        impl AsyncRead for Endless {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut [u8],
            ) -> Poll<io::Result<usize>> {
                buf.fill(0);
                Poll::Ready(Ok(buf.len()))
            }
        }
        let mut body = Counted::new(Endless);
        let got = futures_lite::future::block_on(read_capped(
            &mut body,
            "commit object",
            &csum(),
            |_| Ok(()),
        ));
        assert!(matches!(
            got,
            Err(Failure::Wire(push::Error::LimitExceeded(_)))
        ));
        // The read stops at the first byte past the cap.
        assert_eq!(body.count, MAX_METADATA_SIZE + 1);
    }

    /// Each read gets a window of at most one chunk, and the result keeps no
    /// spare capacity.
    #[test]
    fn reads_go_through_a_bounded_window() {
        struct Widest<'a> {
            bytes: &'a [u8],
            widest: usize,
        }
        impl AsyncRead for Widest<'_> {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut [u8],
            ) -> Poll<io::Result<usize>> {
                self.widest = self.widest.max(buf.len());
                let n = buf.len().min(self.bytes.len());
                buf[..n].copy_from_slice(&self.bytes[..n]);
                self.bytes = &self.bytes[n..];
                Poll::Ready(Ok(n))
            }
        }
        let bytes: Vec<u8> = (0..5 * COPY_CHUNK + 7).map(|i| i as u8).collect();
        let mut body = Widest {
            bytes: &bytes,
            widest: 0,
        };
        let got = futures_lite::future::block_on(read_capped(
            &mut body,
            "commit object",
            &csum(),
            |_| Ok(()),
        ));
        let Ok(got) = got else {
            panic!("the read failed")
        };
        assert_eq!(got, bytes);
        assert_eq!(got.capacity(), got.len());
        assert_eq!(body.widest, COPY_CHUNK);
    }

    #[test]
    fn a_refused_reservation_ends_the_read() {
        let bytes = vec![1u8; 3 * COPY_CHUNK];
        let mut body = Counted::new(&bytes[..]);
        let mut reserved = 0;
        let got = futures_lite::future::block_on(read_capped(
            &mut body,
            "detached metadata of commit",
            &csum(),
            |n| {
                reserved += n;
                if reserved > COPY_CHUNK as u64 {
                    return Err(limit_exceeded("the session cap".into()));
                }
                Ok(())
            },
        ));
        assert!(matches!(
            got,
            Err(Failure::Wire(push::Error::LimitExceeded(m))) if m == "the session cap"
        ));
        // Each read that returns bytes is reserved before the next read.
        assert_eq!(reserved, body.count);
        assert!(body.count < bytes.len() as u64);
    }
}
