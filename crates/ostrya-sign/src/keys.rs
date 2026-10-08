//! Key sets and the reader of key files.

use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::path::Path;

use crate::{Error, Result};

/// The trusted keys and the revoked keys of a key store, as decoded bytes.
///
/// The key store holds the `trusted.<type>` and `revoked.<type>` files and
/// directories of the ed25519 and spki engines. A verifier trusts each key in
/// `trusted` that is not in `revoked`. The engine that uses the keys checks
/// their length.
#[derive(Debug, Clone, Default)]
pub struct SignKeys {
    /// Keys from the `trusted.<type>` files and directories.
    pub trusted: Vec<Vec<u8>>,
    /// Keys from the `revoked.<type>` files and directories.
    pub revoked: Vec<Vec<u8>>,
}

/// The ceiling for one key file, in bytes.
///
/// A key reader reads the whole file into memory. An ed25519 key is 44 base64
/// characters and a newline, so 1 MiB holds 23,301 keys.
pub const MAX_KEY_FILE: u64 = 1024 * 1024;

/// The largest capacity that a read reserves before it starts. The length that
/// the source states does not change this limit. For a larger source, the
/// buffer grows during the read.
const MAX_RESERVE: usize = 16 * 1024 * 1024;

/// Reads the whole key file at `path`, up to `ceiling` bytes.
///
/// If no file is at `path`, the function returns `None`. Each error message
/// names the source with `subject`, so that an operator can find the entry
/// that named the source. [`MAX_KEY_FILE`] is the ceiling for one key file.
///
/// On Unix, the open uses `O_NONBLOCK`. As a result, the open of a fifo does
/// not wait for a writer, and the function refuses the fifo at once.
/// [`read_key_source`] states the ceiling rule and the regular-file rule.
///
/// The read is synchronous, over `std::fs`. An async caller runs it on the
/// blocking pool.
///
/// # Errors
///
/// - [`Error::Signature`] with the message `<subject> cannot be opened: <e>`
///   if the open fails for a cause other than a missing file. `<e>` is the
///   I/O error.
/// - The errors of [`read_key_source`].
pub fn read_key_file(path: &Path, subject: &str, ceiling: u64) -> Result<Option<Vec<u8>>> {
    let file = match open_key_file(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::Signature(format!("{subject} cannot be opened: {e}"))),
    };
    read_key_source(file, subject, ceiling).map(Some)
}

/// Opens `path` for reading. On Unix the open uses `O_NONBLOCK`, so the open
/// of a fifo returns at once and does not wait for a writer. On a regular file,
/// the flag has no effect on the read of [`read_key_source`].
fn open_key_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK);
    options.open(path)
}

/// Reads the whole key source in `file`, up to `ceiling` bytes.
///
/// Each keyring and each key file goes through this function before its keys
/// get into a trusted set, whatever source names the file. Each error message
/// names the source with `subject`.
///
/// # Ceiling and file type
///
/// If the source holds more than `ceiling` bytes, the function refuses the
/// whole source by its name. A read of only the first `ceiling` bytes gives a
/// trusted set that is smaller than the set that the operator supplied. No
/// message tells the operator about this difference.
///
/// The function reads only a regular file. A fifo gives the bytes that its
/// writers send. For key material, the writers of a fifo can supply a trusted
/// set of their own. An open fifo also holds the reading thread until a writer
/// arrives.
///
/// The read is synchronous, over `std::fs`. An async caller runs it on the
/// blocking pool.
///
/// # Errors
///
/// - [`Error::Signature`] with the message `<subject> cannot be read: <e>` if
///   the metadata query or the read fails. `<e>` is the I/O error.
/// - [`Error::Signature`] with the message `<subject> is not a regular file`
///   if `file` is a directory, a fifo, or another file type.
/// - [`Error::Signature`] with the message
///   `<subject> is over the <ceiling>-byte ceiling` if the source holds more
///   than `ceiling` bytes.
pub fn read_key_source(file: File, subject: &str, ceiling: u64) -> Result<Vec<u8>> {
    let refuse = |what: &str| Error::Signature(format!("{subject} {what}"));
    let metadata = file
        .metadata()
        .map_err(|e| refuse(&format!("cannot be read: {e}")))?;
    if !metadata.file_type().is_file() {
        return Err(refuse("is not a regular file"));
    }
    // The length that the handle states sets the capacity of the buffer, so the
    // read and its probe for the end need no growth. The `take` bound stays the
    // limit.
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

/// Returns the text of a key source that [`read_key_source`] read.
///
/// The function is for a source that holds one base64 key on each line.
///
/// # Errors
///
/// - [`Error::Signature`] with the message `<subject> is not valid UTF-8` if
///   `bytes` is not valid UTF-8.
pub fn key_text(bytes: Vec<u8>, subject: &str) -> Result<String> {
    String::from_utf8(bytes).map_err(|_| Error::Signature(format!("{subject} is not valid UTF-8")))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    /// The ceiling of the key files in the tests.
    const CEILING: u64 = 8;

    /// A scratch path that is unique in the process. When the guard drops, it
    /// removes the path and all of its contents.
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

    /// Returns the message of `err`. Each refusal of a reader is an
    /// `Error::Signature`.
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
    /// on its own thread. If the open waits, the test fails after 10 seconds.
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
