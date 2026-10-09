//! The hash pass of a scan: a bounded set of jobs on the blocking pool, and
//! the stop flag that they share. Each job reads one regular file in chunks.

use std::collections::VecDeque;
use std::fs;
use std::future::{Future, poll_fn};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use ostrya_core::{ContentHasher, FileHeader};

use super::invalid_data;
use super::model::{Hashed, TreeModel};

/// The maximum number of bytes that a job reads from its file in one read.
const HASH_CHUNK: usize = 64 * 1024;

/// The Win32 open flag `FILE_FLAG_OPEN_REPARSE_POINT`, which opens a reparse
/// point itself.
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// The Win32 open flag `FILE_FLAG_BACKUP_SEMANTICS`, which lets the open of a
/// directory succeed, so that the type check after the open refuses it.
#[cfg(windows)]
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

/// The identity of a regular file at the time of the walk.
///
/// On Unix, it holds the device number and the inode number. On other
/// platforms, it holds nothing, and all identities are equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FileId {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
}

impl FileId {
    /// Returns the identity of the file that `md` describes.
    #[cfg(unix)]
    pub(super) fn of(md: &fs::Metadata) -> FileId {
        use std::os::unix::fs::MetadataExt;
        FileId {
            dev: md.dev(),
            ino: md.ino(),
        }
    }

    /// Returns the identity of the file that `md` describes.
    #[cfg(not(unix))]
    pub(super) fn of(_md: &fs::Metadata) -> FileId {
        FileId {}
    }
}

/// The marker of a stopped pass, whose error `Jobs` holds.
pub(super) struct Stopped;

/// The outcome of a job.
enum Outcome {
    /// The job read the file to its end.
    Done(Hashed),
    /// The job found the stop flag set.
    Stopped,
    /// The open or a read of the file failed.
    Failed(PathBuf, io::Error),
}

/// A job in flight, whose output is the index of its entry and its outcome.
type Job = Pin<Box<dyn Future<Output = (u32, Outcome)> + Send>>;

/// The jobs of the hash pass.
///
/// The walk queues each kept regular file with `push`. Each await of the walk
/// goes through `drive`, which also polls the jobs in flight. `drive` starts
/// the queued jobs in queue order, up to the limit.
///
/// The first error sets the stop flag. A dropped pass also sets it, so a job
/// that a dropped future left on the pool stops at its next chunk.
pub(super) struct Jobs {
    limit: usize,
    stop: Arc<AtomicBool>,
    pending: VecDeque<u32>,
    running: Vec<Job>,
    error: Option<(PathBuf, io::Error)>,
}

impl Jobs {
    /// Creates a pass with a limit of one job in flight. `set_limit` changes
    /// the limit.
    pub(super) fn new() -> Jobs {
        Jobs {
            limit: 1,
            stop: Arc::new(AtomicBool::new(false)),
            pending: VecDeque::new(),
            running: Vec::new(),
            error: None,
        }
    }

    /// Sets the maximum number of jobs that run at the same time to `limit`.
    /// `limit` must be at least 1.
    pub(super) fn set_limit(&mut self, limit: usize) {
        self.limit = limit;
    }

    /// Adds the regular file `index` to the queue.
    pub(super) fn push(&mut self, index: u32) {
        self.pending.push_back(index);
    }

    /// Records a failure of the pass at `path` and sets the stop flag. The pass
    /// keeps only the first failure.
    pub(super) fn fail(&mut self, path: PathBuf, error: io::Error) -> Stopped {
        if self.error.is_none() {
            self.error = Some((path, error));
        }
        self.stop.store(true, Ordering::Relaxed);
        Stopped
    }

    /// Returns `true` if the pass failed.
    pub(super) fn is_stopped(&self) -> bool {
        self.error.is_some()
    }

    /// Awaits `future` while the jobs run. Each job that ends records its hash
    /// in `model`.
    pub(super) async fn drive<F: Future>(&mut self, model: &mut TreeModel, future: F) -> F::Output {
        let mut future = pin!(future);
        poll_fn(|cx| {
            self.poll(model, cx);
            future.as_mut().poll(cx)
        })
        .await
    }

    /// Runs the queued jobs to their end and returns the first failure, if
    /// there is one. After a failure, it only waits until each job in flight
    /// stops.
    pub(super) async fn finish(
        &mut self,
        model: &mut TreeModel,
    ) -> Result<(), (PathBuf, io::Error)> {
        poll_fn(|cx| {
            self.poll(model, cx);
            if self.running.is_empty() && (self.pending.is_empty() || self.is_stopped()) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        match self.error.take() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Starts queued jobs up to the limit and polls each job in flight, until a
    /// round ends no job. Because a failed job sets the stop flag itself, no
    /// job starts after the failure, also before `poll` records it.
    fn poll(&mut self, model: &mut TreeModel, cx: &mut Context<'_>) {
        loop {
            while !self.is_stopped()
                && !self.stop.load(Ordering::Relaxed)
                && self.running.len() < self.limit
                && let Some(index) = self.pending.pop_front()
            {
                let job = self.start(model, index);
                self.running.push(job);
            }
            let before = self.running.len();
            let mut k = 0;
            while k < self.running.len() {
                match self.running[k].as_mut().poll(cx) {
                    Poll::Ready((index, outcome)) => {
                        drop(self.running.swap_remove(k));
                        match outcome {
                            Outcome::Done(hashed) => model.set_hashed(index, hashed),
                            Outcome::Stopped => {}
                            Outcome::Failed(path, error) => {
                                self.fail(path, error);
                            }
                        }
                    }
                    Poll::Pending => k += 1,
                }
            }
            if self.running.len() == before {
                return;
            }
        }
    }

    /// Returns the job that hashes the regular file `index`.
    fn start(&self, model: &TreeModel, index: u32) -> Job {
        let path = model.os_path(index);
        let header = model.header(index);
        let id = model.file_id(index);
        let stop = Arc::clone(&self.stop);
        Box::pin(async move {
            let outcome = ostrya_rt::unblock(move || hash_file(path, &header, &id, &stop)).await;
            (index, outcome)
        })
    }
}

impl Drop for Jobs {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Hashes `header` and the payload of the regular file at `path`, which the
/// walk read as `id`.
///
/// The job reads the payload in chunks of at most `HASH_CHUNK` bytes. It checks
/// `stop` before the open and before each chunk. If the job fails, it sets
/// `stop`.
fn hash_file(path: PathBuf, header: &FileHeader, id: &FileId, stop: &AtomicBool) -> Outcome {
    let outcome = read_file(path, header, id, stop);
    if matches!(outcome, Outcome::Failed(..)) {
        stop.store(true, Ordering::Relaxed);
    }
    outcome
}

/// Opens and reads the file for `hash_file`.
fn read_file(path: PathBuf, header: &FileHeader, id: &FileId, stop: &AtomicBool) -> Outcome {
    if stop.load(Ordering::Relaxed) {
        return Outcome::Stopped;
    }
    let mut hasher = match ContentHasher::new(header) {
        Ok(hasher) => hasher,
        Err(e) => return Outcome::Failed(path, invalid_data(e.to_string())),
    };
    let (mut file, len) = match open_regular(&path, id) {
        Ok(opened) => opened,
        Err(e) => return Outcome::Failed(path, e),
    };
    // A file of `len` bytes needs a buffer of `len + 1` bytes. After the data
    // of the file, the read that gives 0 bytes ends the loop. If the file grew
    // after the metadata read, the loop reads it to its end.
    let cap = usize::try_from(len).map_or(HASH_CHUNK, |len| len.saturating_add(1).min(HASH_CHUNK));
    let mut buf = vec![0u8; cap];
    let mut size = 0u64;
    loop {
        if stop.load(Ordering::Relaxed) {
            return Outcome::Stopped;
        }
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                hasher.update(&buf[..n]);
                size += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Outcome::Failed(path, e),
        }
    }
    Outcome::Done(Hashed {
        checksum: hasher.finish(),
        size,
    })
}

/// Returns the error for an entry that is no longer a regular file.
fn not_regular() -> io::Error {
    invalid_data("the entry is no longer a regular file")
}

/// Opens the regular file at `path`, which the walk read as `id`, for reading,
/// and returns it with its length.
///
/// On Unix, the open carries `O_NOFOLLOW | O_NONBLOCK`. With `O_NOFOLLOW`, a
/// symlink fails the open. With `O_NONBLOCK`, the open of a fifo returns with
/// no wait for a writer. If the open of a symlink (`ELOOP`) or of a socket
/// (`ENXIO`, and `EOPNOTSUPP` on macOS) fails, the function returns the
/// `not_regular` error.
///
/// On Windows, the open carries `FILE_FLAG_OPEN_REPARSE_POINT`, so it opens a
/// reparse point itself. It also carries `FILE_FLAG_BACKUP_SEMANTICS`, so it
/// opens a directory. The function refuses a file with the reparse point
/// attribute.
///
/// One metadata read of the open file must show a regular file with the
/// identity `id`. If a directory on the path to the file became a symlink,
/// the open follows it. On Unix, the identity check refuses the file that the
/// open reaches.
pub(super) fn open_regular(path: &Path, id: &FileId) -> io::Result<(fs::File, u64)> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(
        &mut options,
        libc::O_NOFOLLOW | libc::O_NONBLOCK,
    );
    #[cfg(windows)]
    std::os::windows::fs::OpenOptionsExt::custom_flags(
        &mut options,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
    );
    let file = match options.open(path) {
        Ok(file) => file,
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Err(not_regular()),
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(libc::ENXIO) => return Err(not_regular()),
        #[cfg(target_os = "macos")]
        Err(e) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => return Err(not_regular()),
        Err(e) => return Err(e),
    };
    let md = file.metadata()?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if md.file_attributes() & super::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(not_regular());
        }
    }
    if !md.file_type().is_file() {
        return Err(not_regular());
    }
    if FileId::of(&md) != *id {
        return Err(invalid_data(
            "the entry is no longer the file the walk read",
        ));
    }
    Ok((file, md.len()))
}
