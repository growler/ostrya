//! The archive view of a repository.
//!
//! The `ostree` command pulls over HTTP from a repository whose `config`
//! states the archive mode. It requests the files of the archive layout. An
//! [`ArchiveView`] answers these requests over a repository of any mode. For
//! a request path, it gives the bytes or a stream to serve, a not-found, or a
//! refusal. A server maps the answers onto its protocol.
//!
//! - [`ArchiveView::get`] gives the [`ArchiveAnswer`] for a `GET`.
//! - [`ArchiveView::head`] gives the [`ArchiveHead`] for a `HEAD`.
//! - [`ArchiveView`] states the [routing](ArchiveView#routing) of a path and
//!   the [file access](ArchiveView#file-access).

use std::fmt;
use std::future::Future;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};

use futures_io::AsyncRead;
use ostrya_core::{Checksum, DeflateReader, RepoMode};
use ostrya_fetch::Priority;
use ostrya_fetch::gate::{Acquire, Gate, Permit};
use ostrya_rt::FileReader;
use rustix::fs::{AtFlags, FileType, Mode, OFlags, Statx, StatxFlags};
use rustix::io::Errno;

use crate::config::RepoConfig;
use crate::error::{Error, Result};
use crate::file::{Contained, ContentReader, FileKind};
use crate::repo::Repo;
use crate::write::archive_level;

/// The maximum number of `.filez` objects that one view deflates at one time.
///
/// Each of these objects holds a compressor and two 64 KiB buffers.
pub const MAX_COMPRESSORS: usize = 16;

/// The archive view over one repository.
///
/// The view is `Send + Sync`, so one view serves every connection of a
/// server.
///
/// # Routing
///
/// - `config`: the view builds it for each request. It holds a `[core]`
///   group with `repo_version=1` and `mode=archive-z2`. Then come
///   `collection-id` and `indexed-deltas`, with the values of the repository,
///   if the repository sets them. The view serves no other key.
/// - `summary`, `summary.sig`, the files under `refs/` and `extensions/`, and
///   the `.commit`, `.dirtree`, `.dirmeta`, and `.commitmeta` objects: the
///   view serves them as stored.
/// - In an `archive` repository, the view also serves the `.filez` objects
///   and the files under `deltas/` and `delta-indexes/` as stored.
/// - In every other mode, the view builds a `.filez` object on request from
///   the stored content object. [`get`](ArchiveView::get) states the format
///   of the body. The files under `deltas/` and `delta-indexes/` are not
///   found in these modes.
/// - A `.file` path is not found. Every path outside these families is not
///   found.
/// - The view refuses a path with an empty component, or with a `.` at the
///   start of a component. It also refuses `tmp/` and `state/`.
///
/// The view refuses a path with a symlink on it, wherever the symlink leads.
/// One exception is a ref alias: a symlink at the last component of a path
/// under `refs/`. If the alias names a ref that is a regular file under
/// `refs/`, the view serves that ref. The view follows one link, so it
/// refuses an alias of an alias.
///
/// # File access
///
/// The view opens a stored file one component at a time, with `openat` and
/// `O_NOFOLLOW`. The walk starts at the descriptor of the repository or of
/// `objects/`, so it needs no `openat2`. The repository handle opened these
/// descriptors. Because of this, a symlink at `objects/` itself is part of
/// the layout of the repository. The handle follows it once, when it opens.
///
/// The view reads the repository `config` again if its inode number, size,
/// modification time, or change time differs from the last parse. The next
/// answer then shows the change. One request reads a changed file, and the
/// requests that see the same change wait for its parse.
pub struct ArchiveView {
    repo: Repo,
    /// The `config` of the last parse and the `statx` fields it was read
    /// under.
    config: Mutex<Option<ConfigSnapshot>>,
    /// One permit, held by the request that reads a changed `config`.
    refresh: Arc<Gate>,
    compressors: Arc<Compressors>,
    /// How many times the view read `config`, for the tests of the reuse.
    #[cfg(test)]
    config_reads: std::sync::atomic::AtomicUsize,
}

/// The answer of the view for one request path.
pub enum ArchiveAnswer {
    /// The built `config`.
    Bytes(Vec<u8>),
    /// A stream to serve: a stored file, or a `.filez` built on request.
    ///
    /// For a stored file, `len` comes from its `fstat`. For a built `.filez`,
    /// `len` is `None`. If the caller drops the stream before its first read,
    /// the stream reads no byte, and a built `.filez` does no deflate work.
    Stream {
        /// The number of bytes that the stream gives, if it is known.
        len: Option<u64>,
        /// The bytes to serve.
        body: Box<dyn AsyncRead + Unpin + Send>,
    },
    /// The answer for a path with nothing to serve.
    ///
    /// The view gives this answer for:
    ///
    /// - a `.file` path
    /// - a path under `deltas/` or `delta-indexes/` in a mode other than
    ///   `archive`
    /// - a path outside the served families
    /// - a served path with nothing at it.
    NotFound,
    /// The answer for a path that the view refuses.
    ///
    /// The view gives this answer for:
    ///
    /// - a path with an empty component, or with a `.` at the start of a
    ///   component
    /// - `tmp/` and `state/`
    /// - a path with a symlink on it that is no ref alias.
    Refused,
}

/// The answer of the view for one `HEAD` request path.
///
/// Each variant matches the [`ArchiveAnswer`] variant for the same path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveHead {
    /// The answer for a path that the view serves.
    ///
    /// `len` is the length that a `GET` gives. It is `None` for a `.filez`
    /// built on request.
    Found {
        /// The number of bytes that a `GET` gives, if it is known.
        len: Option<u64>,
    },
    /// The same answer as [`ArchiveAnswer::NotFound`].
    NotFound,
    /// The same answer as [`ArchiveAnswer::Refused`].
    Refused,
}

impl fmt::Debug for ArchiveAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArchiveAnswer::Bytes(bytes) => f.debug_tuple("Bytes").field(&bytes.len()).finish(),
            ArchiveAnswer::Stream { len, .. } => f
                .debug_struct("Stream")
                .field("len", len)
                .finish_non_exhaustive(),
            ArchiveAnswer::NotFound => f.write_str("NotFound"),
            ArchiveAnswer::Refused => f.write_str("Refused"),
        }
    }
}

impl ArchiveView {
    /// Creates the view over `repo`.
    ///
    /// The view reads nothing until a request needs it.
    pub fn new(repo: Repo) -> ArchiveView {
        ArchiveView {
            repo,
            config: Mutex::new(None),
            refresh: Arc::new(Gate::new(1)),
            #[cfg(test)]
            config_reads: std::sync::atomic::AtomicUsize::new(0),
            compressors: Arc::new(Compressors {
                gate: Arc::new(Gate::new(MAX_COMPRESSORS)),
                idle: Mutex::new(Vec::new()),
                #[cfg(test)]
                leases: std::sync::atomic::AtomicUsize::new(0),
            }),
        }
    }

    /// Returns the answer for one `GET` request path.
    ///
    /// The path is relative to the repository root and has no leading `/`.
    /// [`ArchiveView`](ArchiveView#routing) states the routing.
    ///
    /// # Built `.filez` objects
    ///
    /// In a mode other than `archive`, the view builds a `.filez` object on
    /// request from the stored content object. The body is the archive file
    /// header, then the payload in raw DEFLATE at `[archive] zlib-level`. The
    /// length of the stream is unknown.
    ///
    /// The body takes a compressor from a pool of at most [`MAX_COMPRESSORS`]
    /// when it first reads past the header. It gives the compressor back when
    /// it ends or when the caller drops it. While the body waits for a
    /// compressor, its read is pending. A body dropped before that read does
    /// no deflate work.
    ///
    /// The payload must hold the size that the header states. If the stored
    /// file ends sooner, the body fails with `io::ErrorKind::UnexpectedEof`.
    /// If it holds more, the body fails with `io::ErrorKind::InvalidData`. An
    /// error of the body is sticky, so a read after it fails too.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] if the `statx` or the read of `config` fails, for the
    ///   path `config` or a built `.filez`.
    /// - [`Error::InvalidFormat`] or [`Error::Core`] if `config` is not a
    ///   valid repository config, for the path `config` or a built `.filez`.
    /// - [`Error::Io`] if the walk to a stored file fails with an error that
    ///   gives no not-found and no refusal. A directory that the process
    ///   cannot search gives this error.
    /// - [`Error::Core`] if `[archive] zlib-level` is not an integer, for a
    ///   built `.filez`.
    /// - [`Error::Io`] if the load of the content object for a built `.filez`
    ///   fails with an error other than a missing object or a symlink.
    /// - [`Error::InvalidFormat`] or [`Error::Core`] if the content object
    ///   for a built `.filez` is not a valid object, or its archive header
    ///   cannot be written.
    pub async fn get(&self, path: &str) -> Result<ArchiveAnswer> {
        match classify(path, self.repo.mode()) {
            Route::Config => Ok(ArchiveAnswer::Bytes(built_config(
                &*self.current_config().await?,
            ))),
            Route::Stored {
                anchor,
                path,
                alias_ok,
            } => Ok(match self.stored(anchor, path, alias_ok).await? {
                Walked::File(file, len) => ArchiveAnswer::Stream {
                    len: Some(len),
                    body: Box::new(FileReader::with_len_hint(file, len)),
                },
                Walked::NotFound => ArchiveAnswer::NotFound,
                Walked::Refused | Walked::Alias(_) => ArchiveAnswer::Refused,
            }),
            Route::BuiltFilez(checksum) => self.built_filez(&checksum).await,
            Route::NotFound => Ok(ArchiveAnswer::NotFound),
            Route::Refused => Ok(ArchiveAnswer::Refused),
        }
    }

    /// Returns the answer for one `HEAD` request path.
    ///
    /// The answer matches the answer of [`get`](ArchiveView::get) for a `GET`
    /// of the same path. The view uses the same routing and the same walk. It
    /// opens a stored file and does not read it.
    ///
    /// For a `.filez` built on request, the view checks that the object is
    /// there. It reads no xattr and no byte of the object. Because of this, a
    /// `bare-split-xattrs` object is found even if a `GET` cannot read its
    /// xattrs.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] if the `statx` or the read of `config` fails, for the
    ///   path `config`.
    /// - [`Error::InvalidFormat`] or [`Error::Core`] if `config` is not a
    ///   valid repository config, for the path `config`.
    /// - [`Error::Io`] if the walk to a stored file fails with an error that
    ///   gives no not-found and no refusal.
    /// - [`Error::Io`] if the check of the content object for a built `.filez`
    ///   fails with an error other than a missing object or a symlink.
    /// - [`Error::InvalidFormat`] if the content object for a built `.filez`
    ///   is neither a regular file nor a symlink.
    /// - [`Error::InvalidFormat`] if the repository mode is `bare-split-xattrs`
    ///   and the object path has no `.file-xattrs-link` entry next to it. The
    ///   view checks this entry before the object, so a missing object in a
    ///   fan-out directory that exists also gives this error. For the same
    ///   path, [`get`](ArchiveView::get) gives [`ArchiveAnswer::NotFound`].
    pub async fn head(&self, path: &str) -> Result<ArchiveHead> {
        match classify(path, self.repo.mode()) {
            Route::Config => Ok(ArchiveHead::Found {
                len: Some(built_config(&*self.current_config().await?).len() as u64),
            }),
            Route::Stored {
                anchor,
                path,
                alias_ok,
            } => Ok(match self.stored(anchor, path, alias_ok).await? {
                Walked::File(_, len) => ArchiveHead::Found { len: Some(len) },
                Walked::NotFound => ArchiveHead::NotFound,
                Walked::Refused | Walked::Alias(_) => ArchiveHead::Refused,
            }),
            Route::BuiltFilez(checksum) => {
                let repo = self.repo.clone();
                let probed =
                    ostrya_rt::unblock(move || repo.probe_contained_blocking(&checksum)).await;
                Ok(match object_answer(probed)? {
                    Object::Found(()) => ArchiveHead::Found { len: None },
                    Object::NotFound => ArchiveHead::NotFound,
                    Object::Refused => ArchiveHead::Refused,
                })
            }
            Route::NotFound => Ok(ArchiveHead::NotFound),
            Route::Refused => Ok(ArchiveHead::Refused),
        }
    }

    /// Returns the parsed repository `config`.
    ///
    /// One `statx` shows if the file changed since the last parse. An
    /// unchanged file reuses that parse.
    async fn current_config(&self) -> Result<Arc<RepoConfig>> {
        let repo = self.repo.clone();
        let stat = ostrya_rt::unblock(move || config_statx(repo.repo_fd())).await?;
        self.config_for(&stat).await
    }

    /// Returns the parsed repository `config` for its `statx` fields `stat`.
    ///
    /// One request reads a change of the file. The requests that wait at the
    /// same time take its parse if they saw the same change.
    async fn config_for(&self, stat: &Statx) -> Result<Arc<RepoConfig>> {
        let key = ConfigKey::of(stat);
        if let Some(config) = self.cached_config(key) {
            return Ok(config);
        }
        let _refresh = self.refresh.acquire(Priority::Normal).await;
        if let Some(config) = self.cached_config(key) {
            return Ok(config);
        }
        #[cfg(test)]
        self.config_reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // The view reads the file after the `statx`, so the parse is at least
        // as new as its key. A later change gives another key.
        let config = Arc::new(self.repo.read_config_file().await?);
        *self.config.lock().expect("archive view config mutex") = Some(ConfigSnapshot {
            key,
            config: config.clone(),
        });
        Ok(config)
    }

    /// Returns the parse stored under `key`, if the last parse has that key.
    fn cached_config(&self, key: ConfigKey) -> Option<Arc<RepoConfig>> {
        let snapshot = self.config.lock().expect("archive view config mutex");
        snapshot
            .as_ref()
            .filter(|snapshot| snapshot.key == key)
            .map(|snapshot| snapshot.config.clone())
    }

    /// Opens a stored file through the safe walk.
    async fn stored(&self, anchor: Anchor, path: String, alias_ok: bool) -> Result<Walked> {
        let repo = self.repo.clone();
        let walked = ostrya_rt::unblock(move || {
            let root = match anchor {
                Anchor::Repo => repo.repo_fd(),
                Anchor::Objects => repo.objects_fd(),
            };
            match walk(root, &path, alias_ok)? {
                Walked::Alias(body) => {
                    let link_dir = path.rsplit_once('/').map_or("", |(dir, _)| dir);
                    match resolve_alias(link_dir, &body) {
                        Some(target) => walk(root, &target, false),
                        None => Ok(Walked::Refused),
                    }
                }
                walked => Ok(walked),
            }
        })
        .await?;
        Ok(walked)
    }

    /// Builds a `.filez` from the stored content object `checksum`.
    ///
    /// The `statx` of `config` and the load of the object share one call on
    /// the blocking pool.
    async fn built_filez(&self, checksum: &Checksum) -> Result<ArchiveAnswer> {
        let repo = self.repo.clone();
        let key = *checksum;
        let (stat, loaded) = ostrya_rt::unblock(move || {
            (
                config_statx(repo.repo_fd()),
                repo.load_contained_blocking(&key),
            )
        })
        .await;
        let level = archive_level(self.config_for(&stat?).await?.zlib_level()?);
        let contained: Contained = match object_answer(loaded)? {
            Object::Found(contained) => contained,
            Object::NotFound => return Ok(ArchiveAnswer::NotFound),
            Object::Refused => return Ok(ArchiveAnswer::Refused),
        };
        let (file, reader) = self.repo.contained_file(checksum, contained);
        let (size, payload) = match file.kind {
            FileKind::Regular { size } => (size, Some(reader)),
            // A symlink is the archive header alone.
            FileKind::Symlink { .. } => (0, None),
        };
        let mut header = Vec::new();
        file.header().write_framed_archive(size, &mut header)?;
        Ok(ArchiveAnswer::Stream {
            len: None,
            body: Box::new(BuiltFilez {
                header,
                pos: 0,
                payload: match payload {
                    Some(source) => Payload::Waiting {
                        source: Exact {
                            source,
                            remaining: size,
                        },
                        level,
                        acquire: None,
                    },
                    None => Payload::Done,
                },
                compressors: self.compressors.clone(),
            }),
        })
    }
}

/// The outcome of a load of a content object for a `.filez` built on
/// request.
enum Object<T> {
    Found(T),
    NotFound,
    /// A symlink on the object path.
    Refused,
}

/// Maps `loaded` to an outcome.
///
/// A missing object is not found. A symlink on its path (`ELOOP`) is refused.
/// Every other error stays an error.
fn object_answer<T>(loaded: Result<T>) -> Result<Object<T>> {
    match loaded {
        Ok(found) => Ok(Object::Found(found)),
        Err(Error::ObjectNotFound { .. }) => Ok(Object::NotFound),
        Err(Error::Io(e)) if e.raw_os_error() == Some(Errno::LOOP.raw_os_error()) => {
            Ok(Object::Refused)
        }
        Err(e) => Err(e),
    }
}

/// Returns the `statx` of `config` under `repo_fd`, with the fields of a
/// [`ConfigKey`].
fn config_statx(repo_fd: BorrowedFd<'_>) -> io::Result<Statx> {
    Ok(rustix::fs::statx(
        repo_fd,
        "config",
        AtFlags::empty(),
        StatxFlags::INO | StatxFlags::SIZE | StatxFlags::MTIME | StatxFlags::CTIME,
    )?)
}

/// The parsed `config` and the key it was parsed under.
struct ConfigSnapshot {
    key: ConfigKey,
    config: Arc<RepoConfig>,
}

/// The `statx` fields that show if `config` changed: the inode number,
/// the size, and the modification and change times in nanoseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConfigKey {
    ino: u64,
    size: u64,
    mtime: (i64, u32),
    ctime: (i64, u32),
}

impl ConfigKey {
    fn of(stat: &Statx) -> ConfigKey {
        ConfigKey {
            ino: stat.stx_ino,
            size: stat.stx_size,
            mtime: (stat.stx_mtime.tv_sec, stat.stx_mtime.tv_nsec),
            ctime: (stat.stx_ctime.tv_sec, stat.stx_ctime.tv_nsec),
        }
    }
}

/// Returns the `config` of an archive repository with the values of `config`.
fn built_config(config: &RepoConfig) -> Vec<u8> {
    let mut out = String::from("[core]\nrepo_version=1\nmode=archive-z2\n");
    for key in ["collection-id", "indexed-deltas"] {
        if let Some(value) = config.keyfile().get_value("core", key) {
            out.push_str(key);
            out.push('=');
            out.push_str(value);
            out.push('\n');
        }
    }
    out.into_bytes()
}

/// The directory a stored path walks from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Anchor {
    /// The repository root.
    Repo,
    /// `objects/`.
    Objects,
}

/// What a request path names.
#[derive(Debug, Eq, PartialEq)]
enum Route {
    Config,
    /// A stored file at `path` under `anchor`. `alias_ok` allows a ref alias
    /// at the last component.
    Stored {
        anchor: Anchor,
        path: String,
        alias_ok: bool,
    },
    /// A `.filez` built from the content object of this checksum.
    BuiltFilez(Checksum),
    NotFound,
    Refused,
}

/// Returns `true` if the router refuses a path component by its name alone.
///
/// The router refuses an empty component and a component that starts with
/// `.`. This covers `.`, `..`, `.lock`, and `.update.lock`.
fn refused_component(part: &str) -> bool {
    part.is_empty() || part.starts_with('.')
}

/// Classifies a request path. The function reads no file.
fn classify(path: &str, mode: RepoMode) -> Route {
    if path.is_empty() {
        return Route::NotFound;
    }
    if path.split('/').any(refused_component) {
        return Route::Refused;
    }
    let archive = mode.is_archive();
    let stored = |alias_ok| Route::Stored {
        anchor: Anchor::Repo,
        path: path.to_owned(),
        alias_ok,
    };
    // No component is empty here, so a `rest` holds one component or more.
    let (first, rest) = match path.split_once('/') {
        Some((first, rest)) => (first, Some(rest)),
        None => (path, None),
    };
    match (first, rest) {
        ("tmp" | "state", _) => Route::Refused,
        ("config", None) => Route::Config,
        ("summary" | "summary.sig", None) => stored(false),
        ("refs", Some(_)) => stored(true),
        ("extensions", Some(_)) => stored(false),
        ("deltas" | "delta-indexes", Some(_)) if archive => stored(false),
        ("objects", Some(rest)) => match rest.split_once('/') {
            Some((fanout, name)) if !name.contains('/') => object_route(fanout, name, archive),
            _ => Route::NotFound,
        },
        _ => Route::NotFound,
    }
}

/// Classifies `objects/<fanout>/<name>`.
fn object_route(fanout: &str, name: &str, archive: bool) -> Route {
    let Some((rest, ext)) = name.split_once('.') else {
        return Route::NotFound;
    };
    if fanout.len() != 2 || rest.len() != 62 {
        return Route::NotFound;
    }
    let Ok(checksum) = Checksum::from_hex_lower(&format!("{fanout}{rest}")) else {
        return Route::NotFound;
    };
    let stored = || Route::Stored {
        anchor: Anchor::Objects,
        path: format!("{fanout}/{name}"),
        alias_ok: false,
    };
    match ext {
        "commit" | "dirtree" | "dirmeta" | "commitmeta" => stored(),
        "filez" if archive => stored(),
        "filez" => Route::BuiltFilez(checksum),
        _ => Route::NotFound,
    }
}

/// The result of the safe walk.
enum Walked {
    /// A regular file and its size.
    File(std::fs::File, u64),
    NotFound,
    Refused,
    /// A symlink at the last component of a walk that allows a ref alias,
    /// with the bytes of its body.
    Alias(Vec<u8>),
}

/// Opens the file at `path` under `root` and follows no symlink.
///
/// The walk takes the components of `path` one at a time. Each intermediate
/// component opens with `O_PATH`, `O_DIRECTORY`, and `O_NOFOLLOW`. The last
/// one opens with `O_RDONLY` and `O_NOFOLLOW`.
///
/// `O_NONBLOCK` keeps the open of a FIFO from a wait for a writer. The
/// `fstat` then gives not-found for anything but a regular file. The flag
/// changes no read of a regular file.
///
/// With `alias_ok`, a symlink at the last component gives its body. A name
/// longer than the kernel accepts is not found, and so is a path with nothing
/// at it. A directory that the process cannot search fails the walk with its
/// error.
fn walk(root: BorrowedFd<'_>, path: &str, alias_ok: bool) -> io::Result<Walked> {
    let (dirs, last) = match path.rsplit_once('/') {
        Some((dirs, last)) => (Some(dirs), last),
        None => (None, path),
    };
    let mut held: Option<OwnedFd> = None;
    for part in dirs.into_iter().flat_map(|dirs| dirs.split('/')) {
        let dir = held.as_ref().map_or(root, |fd| fd.as_fd());
        match rustix::fs::openat(
            dir,
            part,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => held = Some(fd),
            Err(Errno::NOENT | Errno::NAMETOOLONG) => return Ok(Walked::NotFound),
            // A symlink gives `ENOTDIR` under `O_DIRECTORY`, and so does any
            // other entry that is no directory.
            Err(Errno::NOTDIR | Errno::LOOP) => return not_a_directory(dir, part),
            Err(e) => return Err(e.into()),
        }
    }
    let dir = held.as_ref().map_or(root, |fd| fd.as_fd());
    let fd = match rustix::fs::openat(
        dir,
        last,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT | Errno::NOTDIR | Errno::NXIO | Errno::NAMETOOLONG) => {
            return Ok(Walked::NotFound);
        }
        Err(Errno::LOOP) if alias_ok => {
            let body = rustix::fs::readlinkat(dir, last, Vec::new())?;
            return Ok(Walked::Alias(body.into_bytes()));
        }
        Err(Errno::LOOP) => return Ok(Walked::Refused),
        Err(e) => return Err(e.into()),
    };
    let stat = rustix::fs::fstat(&fd)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Ok(Walked::NotFound);
    }
    Ok(Walked::File(
        std::fs::File::from(fd),
        stat.st_size.max(0) as u64,
    ))
}

/// The answer for an intermediate component that did not open as a
/// directory: refused for a symlink, not found for anything else.
fn not_a_directory(dir: BorrowedFd<'_>, part: &str) -> io::Result<Walked> {
    match rustix::fs::statat(dir, part, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::Symlink => {
            Ok(Walked::Refused)
        }
        Ok(_) | Err(Errno::NOENT) => Ok(Walked::NotFound),
        Err(e) => Err(e.into()),
    }
}

/// Resolves the body of a ref alias in the directory `link_dir`, which
/// starts with `refs`.
///
/// The function resolves `.` and `..` by name. The result is `None` for:
///
/// - an absolute body
/// - a body that is not UTF-8
/// - an empty component, which a trailing `/` gives
/// - a `..` that leaves `refs/`
/// - a component that the router refuses by name
/// - a result with no component under `refs/`.
fn resolve_alias(link_dir: &str, body: &[u8]) -> Option<String> {
    let body = std::str::from_utf8(body).ok()?;
    if body.starts_with('/') {
        return None;
    }
    // No component of `link_dir` or of the result is empty, so each `/`
    // separates two components.
    let mut target = link_dir.to_owned();
    for part in body.split('/') {
        match part {
            "" => return None,
            "." => {}
            ".." => {
                let (dir, _) = target.rsplit_once('/')?;
                target.truncate(dir.len());
            }
            part if refused_component(part) => return None,
            part => {
                if !target.is_empty() {
                    target.push('/');
                }
                target.push_str(part);
            }
        }
    }
    let under_refs = target
        .split_once('/')
        .is_some_and(|(first, _)| first == "refs");
    under_refs.then_some(target)
}

/// The compressors of one view: a gate of [`MAX_COMPRESSORS`] permits, and the
/// compressors that no body holds.
struct Compressors {
    gate: Arc<Gate>,
    idle: Mutex<Vec<DeflateReader<Exact>>>,
    /// The number of leases that the view gave. The tests use it to prove
    /// that a body dropped unread takes no lease.
    #[cfg(test)]
    leases: std::sync::atomic::AtomicUsize,
}

impl Compressors {
    /// Leases a compressor over `source` at `level`.
    ///
    /// The lease reuses an idle compressor if one is there.
    fn lease(self: &Arc<Self>, source: Exact, level: u8, permit: Permit) -> Lease {
        #[cfg(test)]
        self.leases
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let idle = self
            .idle
            .lock()
            .expect("archive view compressor mutex")
            .pop();
        let reader = match idle {
            Some(mut reader) => {
                reader.reset(source, level);
                reader
            }
            None => DeflateReader::new(source, level),
        };
        Lease {
            reader: Some(reader),
            compressors: self.clone(),
            _permit: permit,
        }
    }
}

/// A compressor held by one body.
///
/// When the lease drops, the compressor goes back to the idle ones before the
/// lease releases the permit.
struct Lease {
    reader: Option<DeflateReader<Exact>>,
    compressors: Arc<Compressors>,
    _permit: Permit,
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(mut reader) = self.reader.take() {
            // The descriptor of the object closes now. The compressor and its
            // buffers stay for the next body.
            drop(std::mem::replace(reader.get_mut(), Exact::empty()));
            self.compressors
                .idle
                .lock()
                .expect("archive view compressor mutex")
                .push(reader);
        }
    }
}

/// The body of a `.filez` built on request: the framed archive header, then
/// the deflated payload.
struct BuiltFilez {
    header: Vec<u8>,
    /// The bytes of `header` already read.
    pos: usize,
    payload: Payload,
    compressors: Arc<Compressors>,
}

/// The payload half of a built `.filez`.
enum Payload {
    /// The payload source, which waits for a compressor. The wait starts on
    /// the first read past the header.
    Waiting {
        source: Exact,
        level: u8,
        acquire: Option<Acquire>,
    },
    Deflating(Lease),
    /// The payload is at its end, or a symlink has no payload.
    Done,
    /// A read failed with an error of this kind. Each later read fails too,
    /// so a reader that reads again does not see the end of the stream.
    Failed(io::ErrorKind),
}

/// The payload source of a built `.filez`: the content reader, held to the
/// size the header states. A source that ends sooner, or holds more, fails
/// the read, so the body never ends with a payload of another length.
struct Exact {
    source: ContentReader,
    /// The bytes the source still has to give.
    remaining: u64,
}

impl Exact {
    /// Returns a source of no bytes that holds no descriptor.
    fn empty() -> Exact {
        Exact {
            source: ContentReader::empty(),
            remaining: 0,
        }
    }
}

impl AsyncRead for Exact {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // The read asks for one byte past the size, so a longer source shows.
        let want =
            usize::try_from(me.remaining.saturating_add(1)).map_or(buf.len(), |n| n.min(buf.len()));
        let n = ready!(Pin::new(&mut me.source).poll_read(cx, &mut buf[..want]))?;
        if n as u64 > me.remaining {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the object holds more bytes than its size",
            )));
        }
        if n == 0 && me.remaining > 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the object ended before its size",
            )));
        }
        me.remaining -= n as u64;
        Poll::Ready(Ok(n))
    }
}

impl AsyncRead for BuiltFilez {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let BuiltFilez {
            header,
            pos,
            payload,
            compressors,
        } = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if *pos < header.len() {
            let n = buf.len().min(header.len() - *pos);
            buf[..n].copy_from_slice(&header[*pos..*pos + n]);
            *pos += n;
            return Poll::Ready(Ok(n));
        }
        loop {
            match payload {
                Payload::Done => return Poll::Ready(Ok(0)),
                Payload::Failed(kind) => {
                    return Poll::Ready(Err(io::Error::new(
                        *kind,
                        "the payload failed at an earlier read",
                    )));
                }
                Payload::Waiting { acquire, .. } => {
                    let acquire =
                        acquire.get_or_insert_with(|| compressors.gate.acquire(Priority::Normal));
                    let permit = ready!(Pin::new(acquire).poll(cx));
                    let Payload::Waiting { source, level, .. } =
                        std::mem::replace(payload, Payload::Done)
                    else {
                        unreachable!("the payload is waiting");
                    };
                    *payload = Payload::Deflating(compressors.lease(source, level, permit));
                }
                Payload::Deflating(lease) => {
                    let reader = lease
                        .reader
                        .as_mut()
                        .expect("a lease holds its compressor until it drops");
                    let read = ready!(Pin::new(reader).poll_read(cx, buf));
                    // The end of the stream and an error both give the
                    // compressor back.
                    match &read {
                        Ok(0) => *payload = Payload::Done,
                        Ok(_) => {}
                        Err(e) => *payload = Payload::Failed(e.kind()),
                    }
                    return Poll::Ready(read);
                }
            }
        }
    }
}

/// The view moves freely across tasks and threads, and so does the future of
/// a request.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_send<T: Send>(_: &T) {}
    assert_send_sync::<ArchiveView>();
    let _ = |view: &ArchiveView| assert_send(&view.get(""));
    let _ = |view: &ArchiveView| assert_send(&view.head(""));
};

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::Ordering;

    use futures_lite::AsyncReadExt;
    use ostrya_core::ObjectType;

    use super::*;
    use crate::repo::CreateOptions;
    use crate::write::FileMeta;

    fn route(path: &str, mode: RepoMode) -> Route {
        classify(path, mode)
    }

    fn stored(anchor: Anchor, path: &str, alias_ok: bool) -> Route {
        Route::Stored {
            anchor,
            path: path.to_owned(),
            alias_ok,
        }
    }

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn the_router_names_each_family() {
        let (fanout, rest) = HEX.split_at(2);
        let object = |ext: &str| format!("objects/{fanout}/{rest}.{ext}");
        for mode in [RepoMode::Archive, RepoMode::BareUser] {
            assert_eq!(route("config", mode), Route::Config);
            assert_eq!(
                route("summary", mode),
                stored(Anchor::Repo, "summary", false)
            );
            assert_eq!(
                route("summary.sig", mode),
                stored(Anchor::Repo, "summary.sig", false)
            );
            assert_eq!(
                route("refs/heads/a/b", mode),
                stored(Anchor::Repo, "refs/heads/a/b", true)
            );
            assert_eq!(
                route("extensions/x", mode),
                stored(Anchor::Repo, "extensions/x", false)
            );
            for ext in ["commit", "dirtree", "dirmeta", "commitmeta"] {
                assert_eq!(
                    route(&object(ext), mode),
                    stored(Anchor::Objects, &format!("{fanout}/{rest}.{ext}"), false)
                );
            }
            assert_eq!(route(&object("file"), mode), Route::NotFound);
            assert_eq!(route(&object("tombstone-commit"), mode), Route::NotFound);
            assert_eq!(route(&object("file-xattrs-link"), mode), Route::NotFound);
            assert_eq!(
                route(&format!("objects/{fanout}/{}.commit", &rest[1..]), mode),
                Route::NotFound
            );
            assert_eq!(
                route(&format!("objects/AB/{rest}.commit"), mode),
                Route::NotFound
            );
            for path in ["", "refs", "objects", "extensions", "deltas", "other"] {
                assert_eq!(route(path, mode), Route::NotFound, "{path}");
            }
            for path in [
                ".lock",
                ".update.lock",
                "tmp",
                "tmp/x",
                "state",
                "state/x",
                "a/../config",
                "./config",
                "refs//heads",
                "refs/heads/",
                "/config",
                "refs/heads/.hidden",
            ] {
                assert_eq!(route(path, mode), Route::Refused, "{path}");
            }
        }
        assert_eq!(
            route(&object("filez"), RepoMode::Archive),
            stored(Anchor::Objects, &format!("{fanout}/{rest}.filez"), false)
        );
        assert_eq!(
            route(&object("filez"), RepoMode::Bare),
            Route::BuiltFilez(Checksum::from_hex(HEX).unwrap())
        );
        for path in ["deltas/ab/cd/superblock", "delta-indexes/ab/cd.index"] {
            assert_eq!(
                route(path, RepoMode::Archive),
                stored(Anchor::Repo, path, false)
            );
            assert_eq!(route(path, RepoMode::BareUserOnly), Route::NotFound);
        }
    }

    /// A deep path routes by its first components and keeps the whole path.
    /// A refused component anywhere in it refuses the path, and so does an
    /// empty one.
    #[test]
    fn the_router_takes_a_deep_path_whole() {
        let deep = format!("refs/heads/{}b", "a/".repeat(100_000));
        for mode in [RepoMode::Archive, RepoMode::BareUser] {
            assert_eq!(route(&deep, mode), stored(Anchor::Repo, &deep, true));
            for tail in ["/..", "/.", "/", "//c", "/.lock"] {
                let path = format!("{deep}{tail}");
                assert_eq!(route(&path, mode), Route::Refused, "{tail}");
            }
            let path = format!("{}refs/heads/x", "a/".repeat(100_000));
            assert_eq!(route(&path, mode), Route::NotFound);
            let path = format!("objects/{}x", "a/".repeat(100_000));
            assert_eq!(route(&path, mode), Route::NotFound);
            assert_eq!(route("objects/ab/cd/ef.commit", mode), Route::NotFound);
            assert_eq!(route("config/x", mode), Route::NotFound);
            assert_eq!(route("summary/x", mode), Route::NotFound);
            assert_eq!(route("tmp/a/b", mode), Route::Refused);
        }
    }

    #[test]
    fn an_alias_resolves_inside_refs_alone() {
        let resolve = |dir: &str, body: &str| resolve_alias(dir, body.as_bytes());
        let target = |t: &str| Some(t.to_owned());
        assert_eq!(resolve("refs/heads", "main"), target("refs/heads/main"));
        assert_eq!(
            resolve("refs/heads/a", "../b/./c"),
            target("refs/heads/b/c")
        );
        assert_eq!(
            resolve("refs/heads", "../remotes/o/main"),
            target("refs/remotes/o/main")
        );
        assert_eq!(resolve("refs/heads", "./main"), target("refs/heads/main"));
        assert_eq!(resolve("refs/heads", "../x"), target("refs/x"));
        assert_eq!(resolve("refs/heads", "../.."), None);
        assert_eq!(resolve("refs/heads", "../../summary"), None);
        assert_eq!(resolve("refs/heads", "../../refs/heads/x"), None);
        assert_eq!(resolve("refs/heads", "/etc/passwd"), None);
        assert_eq!(resolve("refs/heads", ".."), None);
        assert_eq!(resolve("refs/heads", ".lock"), None);
        assert_eq!(resolve("refs/heads", "main/"), None);
        assert_eq!(resolve("refs/heads", "a//main"), None);
        assert_eq!(resolve_alias("refs/heads", b"\xff"), None);
    }

    fn config_of(text: &str) -> RepoConfig {
        RepoConfig::parse(text).unwrap()
    }

    #[test]
    fn the_built_config_copies_two_keys() {
        assert_eq!(
            built_config(&config_of(
                "[core]\nrepo_version=1\nmode=bare-user\n[remote \"o\"]\nurl=x\n"
            )),
            b"[core]\nrepo_version=1\nmode=archive-z2\n"
        );
        assert_eq!(
            built_config(&config_of(
                "[core]\nindexed-deltas=true\nmode=bare\nrepo_version=1\n\
                 collection-id=org.example.Repo\n[ex-ostrya]\nk=v\n"
            )),
            b"[core]\nrepo_version=1\nmode=archive-z2\ncollection-id=org.example.Repo\n\
              indexed-deltas=true\n"
        );
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ostrya-archive-view-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A `bare-user` repository with one regular content object.
    async fn repo_with_object(dir: &Path) -> (Repo, Checksum) {
        let repo = Repo::create(&dir.join("repo"), CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let meta = FileMeta {
            uid: 0,
            gid: 0,
            mode: 0o100644,
            xattrs: ostrya_core::Xattrs::empty(),
        };
        let checksum = txn
            .write_regfile_inline(None, &meta, &vec![7u8; 100_000])
            .await
            .unwrap();
        txn.commit().await.unwrap();
        (repo, checksum)
    }

    fn filez_path(checksum: &Checksum) -> String {
        format!(
            "objects/{}",
            ostrya_core::loose_path(checksum, ObjectType::File, RepoMode::Archive)
        )
    }

    /// A built `.filez` takes a compressor on its first read past the
    /// header, and one dropped unread takes none. A body that ends gives its
    /// compressor back, and the next body reuses it.
    #[test]
    fn a_compressor_is_taken_on_the_first_payload_read() {
        let dir = scratch("lazy");
        ostrya_rt::block_on(async {
            let (repo, checksum) = repo_with_object(&dir).await;
            let view = ArchiveView::new(repo);
            let leases = || view.compressors.leases.load(Ordering::Relaxed);
            let idle = || view.compressors.idle.lock().unwrap().len();

            let answer = view.get(&filez_path(&checksum)).await.unwrap();
            assert!(matches!(answer, ArchiveAnswer::Stream { len: None, .. }));
            drop(answer);
            assert_eq!(leases(), 0);

            let ArchiveAnswer::Stream { mut body, .. } =
                view.get(&filez_path(&checksum)).await.unwrap()
            else {
                panic!("a stream");
            };
            // A read inside the header takes no compressor.
            let mut byte = [0u8; 1];
            body.read_exact(&mut byte).await.unwrap();
            assert_eq!(leases(), 0);
            let mut rest = Vec::new();
            body.read_to_end(&mut rest).await.unwrap();
            assert_eq!(leases(), 1);
            assert_eq!(idle(), 1);

            let ArchiveAnswer::Stream { mut body, .. } =
                view.get(&filez_path(&checksum)).await.unwrap()
            else {
                panic!("a stream");
            };
            let mut again = Vec::new();
            body.read_to_end(&mut again).await.unwrap();
            assert_eq!([&byte[..], &rest[..]].concat(), again);
            assert_eq!((leases(), idle()), (2, 1));
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The path of the `bare-user` object of `checksum` under `dir`.
    fn bare_user_path(dir: &Path, checksum: &Checksum) -> PathBuf {
        dir.join("repo/objects").join(ostrya_core::loose_path(
            checksum,
            ObjectType::File,
            RepoMode::BareUser,
        ))
    }

    /// The body of a built `.filez` of `checksum` after its header.
    async fn past_header(
        view: &ArchiveView,
        checksum: &Checksum,
    ) -> Box<dyn AsyncRead + Unpin + Send> {
        let ArchiveAnswer::Stream { mut body, .. } = view.get(&filez_path(checksum)).await.unwrap()
        else {
            panic!("a stream");
        };
        let mut header = Vec::new();
        view.repo
            .load_file(checksum)
            .await
            .unwrap()
            .header()
            .write_framed_archive(100_000, &mut header)
            .unwrap();
        let mut head = vec![0u8; header.len()];
        body.read_exact(&mut head).await.unwrap();
        body
    }

    /// A stored file that ends before the size of the header fails the body,
    /// and so does one that holds more. The error is sticky: a read after it
    /// fails too and does not see the end of the stream.
    #[test]
    fn a_payload_of_another_size_fails_the_body() {
        let dir = scratch("size");
        ostrya_rt::block_on(async {
            let (repo, checksum) = repo_with_object(&dir).await;
            let view = ArchiveView::new(repo);
            let object = bare_user_path(&dir, &checksum);
            for (len, kind) in [
                (50_000, io::ErrorKind::UnexpectedEof),
                (150_000, io::ErrorKind::InvalidData),
            ] {
                let mut body = past_header(&view, &checksum).await;
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&object)
                    .unwrap()
                    .set_len(len)
                    .unwrap();
                let mut out = Vec::new();
                let err = body.read_to_end(&mut out).await.unwrap_err();
                assert_eq!(err.kind(), kind, "{len}");
                let mut more = [0u8; 16];
                let err = body.read(&mut more).await.unwrap_err();
                assert_eq!(err.kind(), kind, "{len}");
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&object)
                    .unwrap()
                    .set_len(100_000)
                    .unwrap();
            }
            // A body of the right size still ends cleanly, with the
            // compressor of the failed bodies back in the pool.
            let mut out = Vec::new();
            past_header(&view, &checksum)
                .await
                .read_to_end(&mut out)
                .await
                .unwrap();
            assert_eq!(view.compressors.idle.lock().unwrap().len(), 1);
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A FIFO at the path of a `bare-user` object fails the `GET` and the
    /// `HEAD` at once: neither open waits for a writer.
    #[test]
    fn a_fifo_at_an_object_path_answers_at_once() {
        let dir = scratch("fifo");
        let (repo, checksum) = ostrya_rt::block_on(repo_with_object(&dir));
        let object = bare_user_path(&dir, &checksum);
        std::fs::remove_file(&object).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &object,
            FileType::Fifo,
            Mode::from_raw_mode(0o644),
            0,
        )
        .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            ostrya_rt::block_on(async {
                let view = ArchiveView::new(repo);
                let get = view.get(&filez_path(&checksum)).await;
                let head = view.head(&filez_path(&checksum)).await;
                tx.send((get.is_err(), head.is_err())).unwrap();
            });
        });
        let answered = rx.recv_timeout(std::time::Duration::from_secs(10));
        assert_eq!(answered, Ok((true, true)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// After a change of `config`, requests that see the change at the same
    /// time read the file once.
    #[test]
    fn one_request_reads_a_changed_config() {
        let dir = scratch("single-flight");
        ostrya_rt::block_on(async {
            let (repo, checksum) = repo_with_object(&dir).await;
            let view = ArchiveView::new(repo);
            let reads = || view.config_reads.load(Ordering::Relaxed);
            view.get("config").await.unwrap();
            assert_eq!(reads(), 1);
            view.get("config").await.unwrap();
            assert_eq!(reads(), 1);

            let config = dir.join("repo/config");
            let mut text = std::fs::read_to_string(&config).unwrap();
            text.push_str("indexed-deltas=true\n");
            std::fs::write(&config, text).unwrap();
            let path = filez_path(&checksum);
            let mut requests: Vec<Pin<Box<dyn Future<Output = ()> + '_>>> = Vec::new();
            for i in 0..8 {
                let view = &view;
                let path = path.as_str();
                requests.push(Box::pin(async move {
                    if i % 2 == 0 {
                        view.get("config").await.unwrap();
                    } else {
                        view.get(path).await.unwrap();
                    }
                }));
            }
            std::future::poll_fn(|cx| {
                requests.retain_mut(|request| request.as_mut().poll(cx).is_pending());
                if requests.is_empty() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            assert_eq!(reads(), 2);
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// No more than the pool size of bodies deflate at once: one more waits
    /// for a compressor, and gets one when a body is dropped mid-stream.
    #[test]
    fn a_body_past_the_pool_size_waits_for_a_compressor() {
        let dir = scratch("gate");
        ostrya_rt::block_on(async {
            let (repo, checksum) = repo_with_object(&dir).await;
            let view = ArchiveView::new(repo);
            let mut header_len = Vec::new();
            {
                let file = view.repo.load_file(&checksum).await.unwrap();
                file.header()
                    .write_framed_archive(100_000, &mut header_len)
                    .unwrap();
            }
            let open = || async {
                let ArchiveAnswer::Stream { body, .. } =
                    view.get(&filez_path(&checksum)).await.unwrap()
                else {
                    panic!("a stream");
                };
                body
            };
            let mut held = Vec::new();
            for _ in 0..MAX_COMPRESSORS {
                let mut body = open().await;
                let mut head = vec![0u8; header_len.len() + 1];
                body.read_exact(&mut head).await.unwrap();
                held.push(body);
            }
            let mut waiting = open().await;
            let mut head = vec![0u8; header_len.len()];
            waiting.read_exact(&mut head).await.unwrap();
            let mut one = [0u8; 1];
            let mut read = Box::pin(waiting.read(&mut one));
            assert!(futures_lite::future::poll_once(&mut read).await.is_none());
            drop(held.pop());
            assert_eq!(read.await.unwrap(), 1);
        });
        let _ = std::fs::remove_dir_all(&dir);
    }
}
