//! Key sets and the reader of key files.
//!
//! The reader is synchronous. An async caller runs it on the blocking pool.

use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::path::Path;

use crate::{Error, Result};

/// The trusted and revoked key sets loaded from a sign-api key store, as raw
/// decoded key bytes. The engine that consumes them validates their length.
#[derive(Debug, Clone, Default)]
pub struct SignKeys {
    /// Keys from the `trusted.<type>` files and directories.
    pub trusted: Vec<Vec<u8>>,
    /// Keys from the `revoked.<type>` files and directories.
    pub revoked: Vec<Vec<u8>>,
}

/// The ceiling on one key file, whose whole content is read into memory. A
/// mebibyte holds some twenty thousand base64 ed25519 keys.
pub const MAX_KEY_FILE: u64 = 1024 * 1024;

/// The most a read reserves before it reads, whatever length the source states.
/// A larger source grows the buffer as it is read.
const MAX_RESERVE: usize = 16 * 1024 * 1024;

/// Read the key source at `path` whole, up to `ceiling`, or `None` where no file
/// is there. `subject` is what a refusal names the source by, so an operator can
/// find the entry that named it.
pub fn read_key_file(path: &Path, subject: &str, ceiling: u64) -> Result<Option<Vec<u8>>> {
    let file = match open_key_file(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::Signature(format!("{subject} cannot be opened: {e}"))),
    };
    read_key_source(file, subject, ceiling).map(Some)
}

/// Open `path` for reading. On Unix the open carries `O_NONBLOCK`, so a fifo
/// answers the open rather than waiting for a writer. On a regular file the flag
/// has no effect on the read [`read_key_source`] makes.
fn open_key_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK);
    options.open(path)
}

/// Read an opened key source whole, holding it to its kind and to `ceiling`.
/// This is the reader every keyring and every key file reaches a trusted set
/// through, whichever source names it.
///
/// A source over the ceiling is refused by its own name: reading the part the
/// ceiling admits would leave the trusted set smaller than the one the operator
/// placed there, with nothing said about it. Only a regular file is read: what a
/// fifo answers a read with is what its writers sent, which for key material is
/// a trusted set of their own making, and an open fifo holds the reading thread
/// until a writer arrives.
pub fn read_key_source(file: File, subject: &str, ceiling: u64) -> Result<Vec<u8>> {
    let refuse = |what: &str| Error::Signature(format!("{subject} {what}"));
    let metadata = file
        .metadata()
        .map_err(|e| refuse(&format!("cannot be read: {e}")))?;
    if !metadata.file_type().is_file() {
        return Err(refuse("is not a regular file"));
    }
    // The length the handle states sizes the buffer, so the read and its probe
    // for the end fit with no growth. The take bound stays the limit.
    let hint = metadata.len().min(ceiling).saturating_add(1);
    let capacity = usize::try_from(hint).map_or(MAX_RESERVE, |n| n.min(MAX_RESERVE));
    let mut bytes = Vec::with_capacity(capacity);
    file.take(ceiling.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| refuse(&format!("cannot be read: {e}")))?;
    if bytes.len() as u64 > ceiling {
        return Err(refuse(&format!("is over the {ceiling}-byte ceiling")));
    }
    Ok(bytes)
}

/// The text of a key source read under [`read_key_source`], for a source whose
/// keys are base64 lines.
pub fn key_text(bytes: Vec<u8>, subject: &str) -> Result<String> {
    String::from_utf8(bytes).map_err(|_| Error::Signature(format!("{subject} is not valid UTF-8")))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    /// The ceiling the tests hold their key files to.
    const CEILING: u64 = 8;

    /// A process-unique scratch path, removed with everything under it when the
    /// guard drops.
    struct Scratch {
        path: PathBuf,
    }

    impl Scratch {
        fn new(label: &str) -> Scratch {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "ostrya-sign-{label}-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Scratch { path }
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// The signature message of `err`, which every reader refusal is.
    fn message(err: Error) -> String {
        match err {
            Error::Signature(m) => m,
            other => panic!("not a signature error: {other}"),
        }
    }

    #[test]
    fn an_absent_file_reads_as_none() {
        let dir = Scratch::new("absent");
        let read = read_key_file(&dir.path.join("absent"), "the key", CEILING).unwrap();
        assert!(read.is_none());
    }

    #[test]
    fn a_file_at_the_ceiling_is_read_whole() {
        let dir = Scratch::new("at-ceiling");
        let path = dir.path.join("key");
        std::fs::write(&path, b"12345678").unwrap();
        let read = read_key_file(&path, "the key", CEILING).unwrap();
        assert_eq!(read.as_deref(), Some(&b"12345678"[..]));
    }

    #[test]
    fn a_file_over_the_ceiling_is_refused() {
        let dir = Scratch::new("over-ceiling");
        let path = dir.path.join("key");
        std::fs::write(&path, b"123456789").unwrap();
        let err = read_key_file(&path, "the key", CEILING).unwrap_err();
        assert_eq!(message(err), "the key is over the 8-byte ceiling");
    }

    #[test]
    fn a_file_under_the_largest_ceiling_is_read_whole() {
        let dir = Scratch::new("max-ceiling");
        let path = dir.path.join("key");
        std::fs::write(&path, b"12345678").unwrap();
        let read = read_key_file(&path, "the key", u64::MAX).unwrap();
        assert_eq!(read.as_deref(), Some(&b"12345678"[..]));
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_is_refused() {
        let dir = Scratch::new("directory");
        let err = read_key_file(&dir.path, "the key", CEILING).unwrap_err();
        assert_eq!(message(err), "the key is not a regular file");
    }

    #[test]
    fn text_that_is_not_utf8_is_refused() {
        let err = key_text(vec![0xff, 0xfe], "the key").unwrap_err();
        assert_eq!(message(err), "the key is not valid UTF-8");
    }

    /// A fifo is refused, and the open does not wait for a writer. The read runs
    /// on a thread of its own, so an open that waits fails the test rather than
    /// holding it.
    #[cfg(unix)]
    #[test]
    fn a_fifo_is_refused_without_waiting_for_a_writer() {
        let dir = Scratch::new("fifo");
        let path = dir.path.join("key");
        match std::process::Command::new("mkfifo").arg(&path).status() {
            Ok(status) if status.success() => {}
            other => {
                eprintln!("skipping: mkfifo did not create a fifo: {other:?}");
                return;
            }
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let reader_path = path.clone();
        std::thread::spawn(move || {
            let _ = tx.send(read_key_file(&reader_path, "the key", CEILING));
        });
        let result = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the open of a fifo waited for a writer");
        assert_eq!(
            message(result.unwrap_err()),
            "the key is not a regular file"
        );
    }
}
