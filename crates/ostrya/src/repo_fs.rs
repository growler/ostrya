//! The file system access of a repository: the directory kinds, the files at
//! the root, the handles, and the errors.
//!
//! A [`RepoDir`] is an open directory of a repository and its
//! [`RepoLayout`] kind. Each kind has a fixed set of [`LayoutRules`]: its
//! path, its modes, and the home of its temp files. A [`RootFile`] is a file
//! at the repository root.
//!
//! An operation gives an [`FsError`]. `From<FsError> for Error` converts it
//! into an [`Error`], so `?` passes it on. A caller that accepts an absent
//! entry calls [`FsResultExt::optional`]. A ref and an object have their own
//! conversions: [`FsResultExt::optional_ref`] and
//! [`FsError::into_object_error`].

#![allow(dead_code)]

use std::fmt;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::{Arc, OnceLock};

use ostrya_core::{Checksum, ObjectType, RepoMode};
use rustix::fs::{AtFlags, FileType, StatxAttributes, StatxFlags};
use rustix::io::Errno;

use crate::error::Error;

mod dir;
mod lock;
mod named;
mod read;
mod temp;
mod write;

pub(crate) use temp::{TempFile, TempLink};

/// The error of a file system operation in a repository.
///
/// The path in a kind is relative to the repository root. A path that the
/// caller names shows as the caller gives it.
///
/// `From<FsError> for Error` converts each kind with one rule:
///
/// - [`Io`](FsError::Io) gives [`Error::Io`] with the same error.
/// - [`Invalid`](FsError::Invalid) gives [`Error::InvalidFormat`] with the
///   text `{path} {reason}`, where `{reason}` is the `Display` text of the
///   [`Reason`].
/// - [`Absent`](FsError::Absent) gives [`Error::Io`] of kind
///   [`NotFound`](std::io::ErrorKind::NotFound) with the text
///   `{path} does not exist`. The error has no raw errno.
/// - [`Exists`](FsError::Exists) gives [`Error::Io`] with the raw errno
///   `EEXIST`.
#[derive(Debug)]
pub(crate) enum FsError {
    /// The entry does not exist.
    Absent {
        /// The path of the entry.
        path: String,
    },
    /// The entry exists, and the operation creates it exclusively.
    Exists,
    /// The entry is not in the form that the repository accepts.
    Invalid {
        /// The path of the entry.
        path: String,
        /// The cause.
        reason: Reason,
    },
    /// Each other I/O error.
    Io(std::io::Error),
}

/// The cause of an [`FsError::Invalid`].
///
/// The `Display` of a reason is the text that follows the path in a message,
/// for example `is not a directory`.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Reason {
    /// The path passes through a symlink.
    Symlink,
    /// The path resolves outside the repository.
    Escape,
    /// A component of the path is not a directory.
    NotDirectory,
    /// The entry is not a regular file. The payload is its file type.
    NotRegular(FileType),
    /// The entry is larger than its cap.
    TooLarge {
        /// The cap, in bytes.
        cap: u64,
    },
    /// A relative path has a `..` component.
    ParentDir,
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reason::Symlink => {
                f.write_str("passes through a symlink; ostrya refuses a symlink in the repository")
            }
            Reason::Escape => f.write_str("resolves outside the repository"),
            Reason::NotDirectory => f.write_str("is not a directory"),
            Reason::NotRegular(_) => f.write_str("is not a regular file"),
            Reason::TooLarge { cap } => write!(f, "is larger than its cap of {cap} bytes"),
            Reason::ParentDir => {
                f.write_str("has a `..` component, which a relative path in a config cannot have")
            }
        }
    }
}

impl FsError {
    /// Returns the error of `errno` from an operation on `path`. `path` is
    /// relative to the repository root.
    ///
    /// `ENOENT` gives [`Absent`](FsError::Absent), `EEXIST` gives
    /// [`Exists`](FsError::Exists), `ELOOP` gives [`Reason::Symlink`], `EXDEV`
    /// gives [`Reason::Escape`], and `ENOTDIR` gives [`Reason::NotDirectory`].
    /// Each other errno gives [`Io`](FsError::Io) with the same raw errno.
    pub(crate) fn at(errno: Errno, path: String) -> FsError {
        let reason = match errno {
            Errno::NOENT => return FsError::Absent { path },
            Errno::EXIST => return FsError::Exists,
            Errno::LOOP => Reason::Symlink,
            Errno::XDEV => Reason::Escape,
            Errno::NOTDIR => Reason::NotDirectory,
            other => return FsError::Io(other.into()),
        };
        FsError::Invalid { path, reason }
    }

    /// Converts the error of an operation on the loose object `checksum` of
    /// type `ty` into an [`Error`].
    ///
    /// [`Absent`](FsError::Absent) gives [`Error::ObjectNotFound`]. Each other
    /// kind gives the result of `From<FsError> for Error`.
    pub(crate) fn into_object_error(self, checksum: &Checksum, ty: ObjectType) -> Error {
        match self {
            FsError::Absent { .. } => Error::ObjectNotFound {
                checksum: *checksum,
                ty,
            },
            other => other.into(),
        }
    }
}

/// Converts each kind with one rule. The doc of `FsError` states the rules.
impl From<FsError> for Error {
    fn from(err: FsError) -> Error {
        match err {
            FsError::Io(e) => Error::Io(e),
            FsError::Invalid { path, reason } => Error::InvalidFormat(format!("{path} {reason}")),
            FsError::Absent { path } => Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{path} does not exist"),
            )),
            FsError::Exists => Error::Io(std::io::Error::from(Errno::EXIST)),
        }
    }
}

/// The conversions of a [`Result`] with an [`FsError`] that depend on the
/// call site.
pub(crate) trait FsResultExt<T> {
    /// Gives `Ok(None)` for an [`Absent`](FsError::Absent) entry and
    /// `Ok(Some(value))` for `Ok(value)`. Each other error stays the same.
    fn optional(self) -> Result<Option<T>, FsError>;

    /// Converts the result of an operation on the ref file of the ref `name`.
    /// `name` is the ref as text, as the caller gives it.
    ///
    /// - [`Absent`](FsError::Absent) gives `Ok(None)`.
    /// - [`Reason::NotDirectory`] gives `Ok(None)`: a name below a ref file is
    ///   no ref.
    /// - [`Reason::NotRegular`] gives [`Error::NotARef`] with the reason
    ///   `is not a regular file`.
    /// - Each other error gives the result of `From<FsError> for Error`.
    ///
    /// A caller that needs the ref gives [`Error::RefNotFound`] for `None`:
    ///
    /// ```text
    /// let value = result
    ///     .optional_ref(name)?
    ///     .ok_or_else(|| Error::RefNotFound(name.to_owned()))?;
    /// ```
    fn optional_ref(self, name: &str) -> Result<Option<T>, Error>;
}

impl<T> FsResultExt<T> for Result<T, FsError> {
    fn optional(self) -> Result<Option<T>, FsError> {
        match self {
            Ok(value) => Ok(Some(value)),
            Err(FsError::Absent { .. }) => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn optional_ref(self, name: &str) -> Result<Option<T>, Error> {
        match self {
            Ok(value) => Ok(Some(value)),
            Err(
                FsError::Absent { .. }
                | FsError::Invalid {
                    reason: Reason::NotDirectory,
                    ..
                },
            ) => Ok(None),
            Err(FsError::Invalid {
                reason: Reason::NotRegular(_),
                ..
            }) => Err(Error::NotARef {
                name: name.to_owned(),
                reason: "is not a regular file".to_owned(),
            }),
            Err(err) => Err(err.into()),
        }
    }
}

/// The kind of a directory of a repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RepoLayout {
    /// The repository root.
    Root,
    /// `objects/`, the object store.
    Objects,
    /// A staging directory of a transaction, below `tmp/`.
    Staging,
    /// `tmp/`, the directory of temp files and staging directories.
    Tmp,
    /// `refs/`, the ref store.
    Refs,
    /// `state/`, the markers of partial commits.
    State,
    /// `extensions/`, the files of the extensions, such as the image store.
    Extensions,
    /// `deltas/`, the static deltas.
    Deltas,
    /// `delta-indexes/`, the index files of the static deltas.
    DeltaIndexes,
}

/// The home of the temp files of a directory kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TempHome {
    /// The temp files go in `tmp/`.
    Tmp,
    /// The temp files go in the directory itself.
    OwnDir,
}

/// The rules of a directory kind.
///
/// When the repository is created, the create makes each directory with
/// `created_at_init` and each of its `init_children` with `dir_mode`.
/// `below_mode` is the mode of each directory that a later write makes below
/// the directory.
///
/// Outside a `bare-user-shared` repository, each directory mode is the mode of
/// the create request, and the umask reduces it. A write primitive, such as an
/// atomic write or a publish, forces the file mode with `fchmod`. A
/// create-exclusive open and a lock open give the file mode as the mode of the
/// create request, and the umask reduces it.
///
/// In a `bare-user-shared` repository, the shared modes replace the plain
/// modes. An `fchmod` after each create forces the shared mode on each
/// directory, each file, each create-exclusive file, and each lock file, so
/// the umask has no effect.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LayoutRules {
    /// The path relative to `base`, or `None` for a directory with no fixed
    /// name.
    pub(crate) path: Option<&'static str>,
    /// The kind of the parent directory, or `None` for the root.
    pub(crate) base: Option<RepoLayout>,
    /// The mode of the directory itself.
    pub(crate) dir_mode: u32,
    /// The mode of each directory that a later write makes below the
    /// directory, or `None` if no write makes one.
    pub(crate) below_mode: Option<u32>,
    /// The mode of each file in the directory, or `None` if the kind sets no
    /// file mode.
    pub(crate) file_mode: Option<u32>,
    /// The mode of each directory of the kind in a `bare-user-shared`
    /// repository.
    pub(crate) shared_dir_mode: u32,
    /// The mode of each file of the kind in a `bare-user-shared` repository,
    /// or `None` if the kind sets no file mode.
    pub(crate) shared_file_mode: Option<u32>,
    /// The home of the temp files of a write to the directory.
    pub(crate) temp_home: TempHome,
    /// The directories that the create of the repository makes in the
    /// directory.
    pub(crate) init_children: &'static [&'static str],
    /// `true` if the create of the repository makes the directory.
    pub(crate) created_at_init: bool,
}

impl RepoLayout {
    /// Returns the rules of the kind.
    pub(crate) const fn rules(self) -> LayoutRules {
        match self {
            RepoLayout::Root => LayoutRules {
                path: None,
                base: None,
                dir_mode: 0o775,
                below_mode: None,
                file_mode: None,
                shared_dir_mode: 0o2770,
                shared_file_mode: None,
                temp_home: TempHome::Tmp,
                init_children: &[],
                created_at_init: true,
            },
            RepoLayout::Objects => LayoutRules {
                path: Some("objects"),
                base: Some(RepoLayout::Root),
                dir_mode: 0o775,
                below_mode: Some(0o777),
                file_mode: None,
                shared_dir_mode: 0o2770,
                shared_file_mode: None,
                temp_home: TempHome::Tmp,
                init_children: &[],
                created_at_init: true,
            },
            RepoLayout::Staging => LayoutRules {
                path: None,
                base: Some(RepoLayout::Tmp),
                dir_mode: 0o775,
                below_mode: None,
                file_mode: None,
                shared_dir_mode: 0o2770,
                shared_file_mode: None,
                temp_home: TempHome::OwnDir,
                init_children: &[],
                created_at_init: false,
            },
            RepoLayout::Tmp => LayoutRules {
                path: Some("tmp"),
                base: Some(RepoLayout::Root),
                dir_mode: 0o775,
                below_mode: Some(0o775),
                file_mode: Some(0o600),
                shared_dir_mode: 0o2770,
                shared_file_mode: Some(0o660),
                temp_home: TempHome::OwnDir,
                init_children: &["cache"],
                created_at_init: true,
            },
            RepoLayout::Refs => LayoutRules {
                path: Some("refs"),
                base: Some(RepoLayout::Root),
                dir_mode: 0o775,
                below_mode: Some(0o777),
                file_mode: Some(0o644),
                shared_dir_mode: 0o2770,
                shared_file_mode: Some(0o644),
                temp_home: TempHome::Tmp,
                init_children: &["heads", "remotes", "mirrors"],
                created_at_init: true,
            },
            RepoLayout::State => LayoutRules {
                path: Some("state"),
                base: Some(RepoLayout::Root),
                dir_mode: 0o775,
                below_mode: None,
                file_mode: Some(0o644),
                shared_dir_mode: 0o2770,
                shared_file_mode: Some(0o644),
                temp_home: TempHome::Tmp,
                init_children: &[],
                created_at_init: true,
            },
            RepoLayout::Extensions => LayoutRules {
                path: Some("extensions"),
                base: Some(RepoLayout::Root),
                dir_mode: 0o775,
                below_mode: Some(0o775),
                file_mode: Some(0o644),
                shared_dir_mode: 0o2770,
                shared_file_mode: Some(0o644),
                temp_home: TempHome::Tmp,
                init_children: &[],
                created_at_init: true,
            },
            RepoLayout::Deltas => LayoutRules {
                path: Some("deltas"),
                base: Some(RepoLayout::Root),
                dir_mode: 0o755,
                below_mode: Some(0o755),
                file_mode: Some(0o644),
                shared_dir_mode: 0o2770,
                shared_file_mode: Some(0o640),
                temp_home: TempHome::Tmp,
                init_children: &[],
                created_at_init: false,
            },
            RepoLayout::DeltaIndexes => LayoutRules {
                path: Some("delta-indexes"),
                base: Some(RepoLayout::Root),
                dir_mode: 0o755,
                below_mode: Some(0o755),
                file_mode: Some(0o644),
                shared_dir_mode: 0o2770,
                shared_file_mode: Some(0o640),
                temp_home: TempHome::Tmp,
                init_children: &[],
                created_at_init: false,
            },
        }
    }
}

/// A file at the repository root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RootFile {
    /// `config`, the configuration of the repository.
    Config,
    /// `summary`, the summary of the repository.
    Summary,
    /// `summary.sig`, the signatures of the summary.
    SummarySig,
    /// `.lock`, the repository lock.
    Lock,
    /// `.update.lock`, the update lock.
    UpdateLock,
    /// A keyring file, such as `<remote>.trustedkeys.gpg` or `gpgkeys.gpg`.
    /// The payload is the file name, which is one path component.
    Keyring(String),
}

impl RootFile {
    /// Returns the file name.
    pub(crate) fn name(&self) -> &str {
        match self {
            RootFile::Config => "config",
            RootFile::Summary => "summary",
            RootFile::SummarySig => "summary.sig",
            RootFile::Lock => ".lock",
            RootFile::UpdateLock => ".update.lock",
            RootFile::Keyring(name) => {
                debug_assert!(
                    !name.is_empty() && !name.contains('/') && name != "." && name != "..",
                    "a keyring name is one path component: {name:?}"
                );
                name
            }
        }
    }

    /// Returns the mode of the file.
    pub(crate) fn file_mode(&self) -> u32 {
        match self {
            RootFile::Lock | RootFile::UpdateLock => 0o660,
            RootFile::Config | RootFile::Summary | RootFile::SummarySig | RootFile::Keyring(_) => {
                0o644
            }
        }
    }

    /// Returns the mode of the file in a `bare-user-shared` repository.
    pub(crate) fn shared_file_mode(&self) -> u32 {
        match self {
            RootFile::Lock | RootFile::UpdateLock => 0o660,
            RootFile::Config | RootFile::Summary | RootFile::SummarySig | RootFile::Keyring(_) => {
                0o644
            }
        }
    }

    /// Returns `true` if a read of the file follows a symlink at the file
    /// name. A keyring file can be a symlink. Each other root file cannot.
    pub(crate) fn follows_leaf_symlink(&self) -> bool {
        matches!(self, RootFile::Keyring(_))
    }
}

/// An open directory of a repository and its kind.
///
/// A clone shares the descriptor and the context of the repository.
///
/// A handle with no repository mode is not shared: its operations use the
/// plain modes and never force a shared mode.
#[derive(Debug, Clone)]
pub(crate) struct RepoDir {
    /// The descriptor of the directory.
    fd: Arc<OwnedFd>,
    /// The kind of the directory.
    kind: RepoLayout,
    /// The context of the repository.
    ctx: Arc<RepoContext>,
    /// The path of the directory, relative to the repository root. An error
    /// gives its path from this value.
    path: DirPath,
}

/// The path of a [`RepoDir`], relative to the repository root.
///
/// The root is the empty path. A primitive joins the parts of the path only
/// to make the path of an error.
#[derive(Debug, Clone)]
enum DirPath {
    /// The fixed path of the root or of a layout kind.
    Fixed(&'static str),
    /// The path of a directory below the root or a layout kind.
    Nested {
        /// The fixed path of the root or of the layout kind.
        base: &'static str,
        /// The path of the directory, relative to `base`.
        rel: Arc<str>,
    },
}

/// The state that the [`RepoDir`] handles of one repository share.
///
/// A clone of a handle shares its context. [`RepoDir::with_repo_mode`] sets the
/// mode in the context of a handle that is the sole owner of its context. It
/// gives each other handle a new context, and the clones made before the call
/// keep the old context.
#[derive(Debug)]
struct RepoContext {
    /// The descriptor of the repository root.
    root: Arc<OwnedFd>,
    /// The descriptor of `tmp/`, after its first open.
    tmp: OnceLock<Arc<OwnedFd>>,
    /// The mode of the repository, or `None` before the read of the config.
    mode: Option<RepoMode>,
}

impl RepoDir {
    /// Returns a handle of kind [`RepoLayout::Root`] on the open repository
    /// root `fd`. The handle has no repository mode.
    pub(crate) fn from_root_fd(fd: OwnedFd) -> RepoDir {
        let fd = Arc::new(fd);
        RepoDir {
            ctx: Arc::new(RepoContext {
                root: Arc::clone(&fd),
                tmp: OnceLock::new(),
                mode: None,
            }),
            fd,
            kind: RepoLayout::Root,
            path: DirPath::Fixed(""),
        }
    }

    /// Returns the handle with the repository mode `mode`. The handle keeps
    /// its descriptor, its kind, and the `tmp/` descriptor of its context.
    ///
    /// If the handle is the sole owner of its context, the function sets the
    /// mode in that context. If not, the function gives the handle a new
    /// context with the mode. Each other handle cloned before the call keeps
    /// the old context, which has no mode. Thus a caller opens the other
    /// handles after the call.
    pub(crate) fn with_repo_mode(mut self, mode: RepoMode) -> RepoDir {
        if let Some(ctx) = Arc::get_mut(&mut self.ctx) {
            ctx.mode = Some(mode);
            return self;
        }
        RepoDir {
            ctx: Arc::new(RepoContext {
                root: Arc::clone(&self.ctx.root),
                tmp: self.ctx.tmp.clone(),
                mode: Some(mode),
            }),
            fd: self.fd,
            kind: self.kind,
            path: self.path,
        }
    }

    /// Returns the kind of the directory.
    pub(crate) fn kind(&self) -> RepoLayout {
        self.kind
    }

    /// Returns the mode of the repository, or `None` if the handle has no
    /// mode.
    pub(crate) fn repo_mode(&self) -> Option<RepoMode> {
        self.ctx.mode
    }

    /// Returns the mode of each file of the kind of the directory, or `None`
    /// if the kind sets no file mode. In a `bare-user-shared` repository it
    /// is the shared file mode of the kind.
    pub(crate) fn file_mode(&self) -> Option<u32> {
        let rules = self.kind.rules();
        if self.ctx.is_shared() {
            rules.shared_file_mode
        } else {
            rules.file_mode
        }
    }
}

impl AsFd for RepoDir {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<RepoDir>();
    assert_send_sync::<FsError>();
    assert_send_sync::<Opened>();
    assert_send_sync::<ObjectEntry>();
    assert_send_sync::<TempFile>();
    assert_send_sync::<TempLink>();
    assert_send_sync::<Publish>();
    assert_send_sync::<Published>();
};

/// The status of an inode, from one `statx` call.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Stat {
    /// The file type.
    pub(crate) file_type: FileType,
    /// The full `stx_mode`: the file type bits and the permission bits.
    pub(crate) mode: u32,
    /// The owner.
    pub(crate) uid: u32,
    /// The group.
    pub(crate) gid: u32,
    /// The size, in bytes.
    pub(crate) size: u64,
    /// The device that holds the inode.
    pub(crate) dev: u64,
    /// The inode number.
    pub(crate) ino: u64,
    /// The seconds of the modification time.
    pub(crate) mtime_sec: i64,
    /// The nanoseconds of the modification time.
    pub(crate) mtime_nsec: u32,
    /// `true` if the inode is sealed with fs-verity.
    pub(crate) verity: bool,
}

/// One entry of a directory listing.
#[derive(Debug)]
pub(crate) struct Entry {
    /// The name of the entry.
    pub(crate) name: Vec<u8>,
    /// The file type of the entry.
    pub(crate) file_type: FileType,
}

/// An open regular file and its status.
#[derive(Debug)]
pub(crate) struct Opened {
    /// The open file. It is open read-only, with `O_NONBLOCK`.
    pub(crate) file: std::fs::File,
    /// The status of the file, from one `statx` on the open descriptor.
    pub(crate) stat: Stat,
}

/// A loose object that [`RepoDir::open_object`] opened: a regular file, or the
/// target of a symlink object.
#[derive(Debug)]
pub(crate) enum ObjectEntry {
    /// A regular file.
    Regular(Opened),
    /// A symlink. The payload is the target, as bytes.
    Symlink(Vec<u8>),
}

/// The rule of a publish for an entry that exists at the target path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Publish {
    /// The existing entry stays, and the publish gives
    /// [`Published::Existed`].
    KeepExisting,
    /// The new entry replaces the existing entry in one atomic step.
    Replace,
}

/// The result of a publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Published {
    /// The publish put the new entry at the target path.
    Created,
    /// An entry existed at the target path, and it stays. The publish does
    /// not examine the type or the content of that entry.
    Existed,
}

/// The `statx` fields that [`stat_fd`] reads.
const STAT_FIELDS: StatxFlags = StatxFlags::TYPE
    .union(StatxFlags::MODE)
    .union(StatxFlags::UID)
    .union(StatxFlags::GID)
    .union(StatxFlags::SIZE)
    .union(StatxFlags::INO)
    .union(StatxFlags::MTIME);

/// Returns the status of the inode open at `fd`, from one `statx` call.
///
/// The verity flag comes from the attributes word alone. The function does not
/// read the attribute mask, because btrfs sets the attribute and leaves it out
/// of the mask.
pub(crate) fn stat_fd(fd: BorrowedFd<'_>) -> Result<Stat, FsError> {
    let stx = rustix::fs::statx(fd, "", AtFlags::EMPTY_PATH, STAT_FIELDS)
        .map_err(|errno| FsError::Io(errno.into()))?;
    let mode = u32::from(stx.stx_mode);
    Ok(Stat {
        file_type: FileType::from_raw_mode(mode),
        mode,
        uid: stx.stx_uid,
        gid: stx.stx_gid,
        size: stx.stx_size,
        dev: rustix::fs::makedev(stx.stx_dev_major, stx.stx_dev_minor),
        ino: stx.stx_ino,
        mtime_sec: stx.stx_mtime.tv_sec,
        mtime_nsec: stx.stx_mtime.tv_nsec,
        verity: stx.stx_attributes.contains(StatxAttributes::VERITY),
    })
}

/// A temp directory that a test removes when it drops.
#[cfg(test)]
pub(crate) struct TestDir {
    /// The path of the directory.
    path: std::path::PathBuf,
    /// The descriptor of the directory.
    fd: OwnedFd,
}

#[cfg(test)]
impl TestDir {
    /// Creates a new directory `ostrya-repo-fs-<tag>-<pid>-<n>` in the temp
    /// directory of the system and opens it.
    pub(crate) fn new(tag: &str) -> TestDir {
        TestDir::new_in(&std::env::temp_dir(), tag)
    }

    /// Creates a new directory `ostrya-repo-fs-<tag>-<pid>-<n>` in `base` and
    /// opens it.
    pub(crate) fn new_in(base: &std::path::Path, tag: &str) -> TestDir {
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = base.join(format!("ostrya-repo-fs-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        let fd = rustix::fs::open(
            &path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        TestDir { path, fd }
    }

    /// Returns the path of the directory.
    pub(crate) fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Returns the descriptor of the directory.
    pub(crate) fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

#[cfg(test)]
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Returns a root handle on a duplicate of the descriptor of `dir`.
#[cfg(test)]
fn root(dir: &TestDir) -> RepoDir {
    RepoDir::from_root_fd(rustix::io::dup(dir.fd()).unwrap())
}

/// Returns the path and the reason of an `Invalid` error.
#[cfg(test)]
fn invalid<T: fmt::Debug>(result: Result<T, FsError>) -> (String, Reason) {
    match result {
        Err(FsError::Invalid { path, reason }) => (path, reason),
        other => panic!("{other:?}"),
    }
}

/// Returns the error of an `Io` error.
#[cfg(test)]
fn io_err<T: fmt::Debug>(result: Result<T, FsError>) -> std::io::Error {
    match result {
        Err(FsError::Io(e)) => e,
        other => panic!("{other:?}"),
    }
}

/// The step after a `mkdirat` that a test fault fails.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FaultStep {
    /// The open of a new temp directory, and the open for the `fchmod` of a
    /// new directory of `ensure_named_dir`.
    Open,
    /// The `fchmod` that forces the shared mode on each new directory and
    /// each new exclusive file in a `bare-user-shared` repository.
    Fchmod,
}

/// A point in a primitive where a test runs a hook.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HookPoint {
    /// After the read of each subdirectory of a tree removal. The hook gets
    /// the name of the subdirectory.
    Descend,
    /// In `ensure_dir`, after the open of the full path gives `ENOENT` and
    /// before the walk of the components. The hook gets the path.
    Walk,
    /// Before the first `getdents` of each read of a directory. The hook gets
    /// an empty name.
    Getdents,
    /// Before the typing of each entry of a directory read. The hook gets the
    /// name of the entry.
    Entry,
    /// Before the create of each temp file name and temp symlink name. The
    /// hook gets the name.
    TempName,
    /// In `open_lock`, after the create of a lock file gives `EEXIST` and
    /// before the open of the existing file. The hook gets the name.
    LockOpen,
    /// In `open_lock`, before each create of a lock file. The hook gets the
    /// name.
    LockCreate,
}

/// A hook that a test runs at a [`HookPoint`].
#[cfg(test)]
type Hook = Box<dyn FnMut(&[u8])>;

/// The faults that a test injects into the primitives of its own thread.
#[cfg(test)]
#[derive(Default)]
struct Faults {
    /// Fails the step after a `mkdirat` with the errno. The step
    /// [`FaultStep::Fchmod`] also fails after the create of an exclusive file.
    fail_after_mkdir: Option<(FaultStep, Errno)>,
    /// Gives `EEXIST` in place of each `mkdirat` of a temp directory and each
    /// create of a temp file name or a temp symlink name. The primitive makes
    /// no create call.
    force_eexist: bool,
    /// Gives `EOPNOTSUPP` in place of each `O_TMPFILE` open. The primitive
    /// makes no `openat` call.
    no_tmpfile: bool,
    /// Gives `EINVAL` in place of each `renameat2` with `RENAME_NOREPLACE`.
    /// The primitive makes no `renameat2` call.
    no_rename_noreplace: bool,
    /// Gives the errno in place of each `FICLONE` reflink. The primitive makes
    /// no `ioctl` call.
    reflink_error: Option<Errno>,
    /// The hooks, at most one for each point.
    hooks: Vec<(HookPoint, Hook)>,
    /// Gives the unknown type in place of the `getdents` type of each entry of
    /// a directory read.
    unknown_type: bool,
    /// The device and inode of each directory that a primitive syncs, in the
    /// order of the syncs. `None` records nothing.
    synced: Option<Vec<(u64, u64)>>,
}

#[cfg(test)]
thread_local! {
    /// The faults of the thread. Each test thread starts with no fault.
    static FAULTS: std::cell::RefCell<Faults> = std::cell::RefCell::default();
}

/// Clears the faults of the thread when it drops.
#[cfg(test)]
struct FaultReset;

#[cfg(test)]
impl Drop for FaultReset {
    fn drop(&mut self) {
        FAULTS.with(|f| *f.borrow_mut() = Faults::default());
    }
}

/// Changes the faults of the thread with `set`. The faults clear when the
/// returned value drops.
#[cfg(test)]
fn set_faults(set: impl FnOnce(&mut Faults)) -> FaultReset {
    FAULTS.with(|f| set(&mut f.borrow_mut()));
    FaultReset
}

/// Adds a hook at `point` to the faults of the thread.
#[cfg(test)]
fn set_hook(point: HookPoint, hook: impl FnMut(&[u8]) + 'static) -> FaultReset {
    set_faults(|f| f.hooks.push((point, Box::new(hook))))
}

/// Starts the record of the directory syncs of the thread.
#[cfg(test)]
fn record_syncs() -> FaultReset {
    set_faults(|f| f.synced = Some(Vec::new()))
}

/// Returns the directory syncs that the thread recorded, and empties the
/// record.
#[cfg(test)]
fn take_synced() -> Vec<(u64, u64)> {
    FAULTS.with(|f| {
        f.borrow_mut()
            .synced
            .as_mut()
            .map(std::mem::take)
            .expect("the thread records its syncs")
    })
}

/// Makes `refs/` and its children in `dir`, and returns a handle of it.
#[cfg(test)]
fn refs(dir: &TestDir) -> RepoDir {
    root(dir).ensure_layout(RepoLayout::Refs, false).unwrap()
}

/// Returns the names of the temp entries in `tmp/` of `dir`.
#[cfg(test)]
fn temp_names(dir: &TestDir) -> Vec<String> {
    names_with(&dir.path().join("tmp"), temp::TEMP_PREFIX)
}

/// Returns the names of the entries of `path` that start with `prefix`.
#[cfg(test)]
fn names_with(path: &std::path::Path, prefix: &str) -> Vec<String> {
    std::fs::read_dir(path)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(prefix))
        .collect()
}

/// Returns the permission bits and the special bits of `path`, with no
/// follow.
#[cfg(test)]
fn mode_of(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::MetadataExt;

    std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

/// Returns the device and inode of `path`, with no follow.
#[cfg(test)]
fn id_of(path: &std::path::Path) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;

    let meta = std::fs::symlink_metadata(path).unwrap();
    (meta.dev(), meta.ino())
}

/// Returns `true` if `path` is a symlink.
#[cfg(test)]
fn is_symlink(path: &std::path::Path) -> bool {
    std::fs::symlink_metadata(path)
        .unwrap()
        .file_type()
        .is_symlink()
}

/// Returns the mode of a directory that a `mkdir` with the mode `request`
/// makes in `parent`. The umask, a set-group-ID parent, and a default ACL
/// of `parent` change the mode as they change each other new directory.
#[cfg(test)]
fn reference_mode(parent: &std::path::Path, request: u32) -> u32 {
    use std::os::unix::fs::DirBuilderExt;

    let path = parent.join(".reference-mode");
    std::fs::DirBuilder::new()
        .mode(request)
        .create(&path)
        .unwrap();
    let mode = mode_of(&path);
    std::fs::remove_dir(&path).unwrap();
    mode
}

/// Returns the mode of a file that a create with the mode `request` makes in
/// `parent`. The umask and a default ACL of `parent` change the mode as they
/// change each other new file.
#[cfg(test)]
fn reference_file_mode(parent: &std::path::Path, request: u32) -> u32 {
    use std::os::unix::fs::OpenOptionsExt;

    let path = parent.join(".reference-file-mode");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(request)
        .open(&path)
        .unwrap();
    let mode = mode_of(&path);
    std::fs::remove_file(&path).unwrap();
    mode
}

/// Makes a FIFO at `path`.
#[cfg(test)]
fn mkfifo(path: &std::path::Path) {
    rustix::fs::mknodat(
        rustix::fs::CWD,
        path,
        FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
}

/// Runs `f` in a new thread, and gives its result. If `f` does not return in
/// 10 seconds, the function opens the FIFO `fifo` for write, which releases a
/// blocked open, and panics.
#[cfg(test)]
fn without_block<T: Send + 'static>(
    fifo: &std::path::Path,
    f: impl FnOnce() -> T + Send + 'static,
) -> T {
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::time::Duration;

    let (tx, rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(value) => {
            worker.join().unwrap();
            value
        }
        Err(RecvTimeoutError::Disconnected) => match worker.join() {
            Err(panic) => std::panic::resume_unwind(panic),
            Ok(()) => unreachable!("the worker sends a value before it ends"),
        },
        Err(RecvTimeoutError::Timeout) => {
            let _ = rustix::fs::open(
                fifo,
                rustix::fs::OFlags::WRONLY
                    | rustix::fs::OFlags::NONBLOCK
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            );
            panic!("a read of the FIFO {} blocked", fifo.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    use rustix::fs::{Mode, OFlags};

    use super::*;

    const ALL_LAYOUTS: [RepoLayout; 9] = [
        RepoLayout::Root,
        RepoLayout::Objects,
        RepoLayout::Staging,
        RepoLayout::Tmp,
        RepoLayout::Refs,
        RepoLayout::State,
        RepoLayout::Extensions,
        RepoLayout::Deltas,
        RepoLayout::DeltaIndexes,
    ];

    fn checksum() -> Checksum {
        Checksum::from_hex(&"ab".repeat(32)).unwrap()
    }

    fn has_errno(err: &Error, errno: Errno) -> bool {
        matches!(err, Error::Io(e) if e.raw_os_error() == Some(errno.raw_os_error()))
    }

    /// Returns each reason and its `Display` text.
    fn reason_cases() -> [(Reason, &'static str); 7] {
        [
            (
                Reason::Symlink,
                "passes through a symlink; ostrya refuses a symlink in the repository",
            ),
            (Reason::Escape, "resolves outside the repository"),
            (Reason::NotDirectory, "is not a directory"),
            (
                Reason::NotRegular(FileType::Directory),
                "is not a regular file",
            ),
            (
                Reason::TooLarge { cap: 1024 },
                "is larger than its cap of 1024 bytes",
            ),
            (
                Reason::TooLarge { cap: u64::MAX },
                "is larger than its cap of 18446744073709551615 bytes",
            ),
            (
                Reason::ParentDir,
                "has a `..` component, which a relative path in a config cannot have",
            ),
        ]
    }

    fn invalid(path: &str, reason: Reason) -> FsError {
        FsError::Invalid {
            path: path.to_owned(),
            reason,
        }
    }

    fn absent(path: &str) -> FsError {
        FsError::Absent {
            path: path.to_owned(),
        }
    }

    #[test]
    fn each_errno_maps_to_its_kind_and_keeps_the_path() {
        let path = "refs/heads/main";
        assert!(matches!(
            FsError::at(Errno::NOENT, path.to_owned()),
            FsError::Absent { path: p } if p == path
        ));
        assert!(matches!(
            FsError::at(Errno::EXIST, path.to_owned()),
            FsError::Exists
        ));
        assert!(matches!(
            FsError::at(Errno::LOOP, path.to_owned()),
            FsError::Invalid { path: p, reason: Reason::Symlink } if p == path
        ));
        assert!(matches!(
            FsError::at(Errno::XDEV, path.to_owned()),
            FsError::Invalid { path: p, reason: Reason::Escape } if p == path
        ));
        assert!(matches!(
            FsError::at(Errno::NOTDIR, path.to_owned()),
            FsError::Invalid { path: p, reason: Reason::NotDirectory } if p == path
        ));
        for errno in [Errno::NOSYS, Errno::PERM, Errno::ACCESS, Errno::NXIO] {
            match FsError::at(errno, path.to_owned()) {
                FsError::Io(e) => assert_eq!(e.raw_os_error(), Some(errno.raw_os_error())),
                other => panic!("{errno:?} gave {other:?}"),
            }
        }
    }

    #[test]
    fn layout_paths_and_bases() {
        let expected: [(RepoLayout, Option<&str>, Option<RepoLayout>); 9] = [
            (RepoLayout::Root, None, None),
            (RepoLayout::Objects, Some("objects"), Some(RepoLayout::Root)),
            (RepoLayout::Staging, None, Some(RepoLayout::Tmp)),
            (RepoLayout::Tmp, Some("tmp"), Some(RepoLayout::Root)),
            (RepoLayout::Refs, Some("refs"), Some(RepoLayout::Root)),
            (RepoLayout::State, Some("state"), Some(RepoLayout::Root)),
            (
                RepoLayout::Extensions,
                Some("extensions"),
                Some(RepoLayout::Root),
            ),
            (RepoLayout::Deltas, Some("deltas"), Some(RepoLayout::Root)),
            (
                RepoLayout::DeltaIndexes,
                Some("delta-indexes"),
                Some(RepoLayout::Root),
            ),
        ];
        for (kind, path, base) in expected {
            let rules = kind.rules();
            assert_eq!(rules.path, path, "path of {kind:?}");
            assert_eq!(rules.base, base, "base of {kind:?}");
        }
    }

    #[test]
    fn layout_modes() {
        let expected: [(RepoLayout, u32, Option<u32>, Option<u32>); 9] = [
            (RepoLayout::Root, 0o775, None, None),
            (RepoLayout::Objects, 0o775, Some(0o777), None),
            (RepoLayout::Staging, 0o775, None, None),
            (RepoLayout::Tmp, 0o775, Some(0o775), Some(0o600)),
            (RepoLayout::Refs, 0o775, Some(0o777), Some(0o644)),
            (RepoLayout::State, 0o775, None, Some(0o644)),
            (RepoLayout::Extensions, 0o775, Some(0o775), Some(0o644)),
            (RepoLayout::Deltas, 0o755, Some(0o755), Some(0o644)),
            (RepoLayout::DeltaIndexes, 0o755, Some(0o755), Some(0o644)),
        ];
        for (kind, dir, below, file) in expected {
            let rules = kind.rules();
            assert_eq!(rules.dir_mode, dir, "dir mode of {kind:?}");
            assert_eq!(rules.below_mode, below, "below mode of {kind:?}");
            assert_eq!(rules.file_mode, file, "file mode of {kind:?}");
        }
    }

    #[test]
    fn layout_shared_modes() {
        let expected: [(RepoLayout, Option<u32>); 9] = [
            (RepoLayout::Root, None),
            (RepoLayout::Objects, None),
            (RepoLayout::Staging, None),
            (RepoLayout::Tmp, Some(0o660)),
            (RepoLayout::Refs, Some(0o644)),
            (RepoLayout::State, Some(0o644)),
            (RepoLayout::Extensions, Some(0o644)),
            (RepoLayout::Deltas, Some(0o640)),
            (RepoLayout::DeltaIndexes, Some(0o640)),
        ];
        for (kind, file) in expected {
            let rules = kind.rules();
            assert_eq!(rules.shared_dir_mode, 0o2770, "shared dir mode of {kind:?}");
            assert_eq!(rules.shared_file_mode, file, "shared file mode of {kind:?}");
        }
    }

    #[test]
    fn layout_temp_homes() {
        for kind in ALL_LAYOUTS {
            let expected = match kind {
                RepoLayout::Staging | RepoLayout::Tmp => TempHome::OwnDir,
                _ => TempHome::Tmp,
            };
            assert_eq!(kind.rules().temp_home, expected, "temp home of {kind:?}");
        }
    }

    #[test]
    fn layout_init_children_and_created_at_init() {
        let expected: [(RepoLayout, &[&str], bool); 9] = [
            (RepoLayout::Root, &[], true),
            (RepoLayout::Objects, &[], true),
            (RepoLayout::Staging, &[], false),
            (RepoLayout::Tmp, &["cache"], true),
            (RepoLayout::Refs, &["heads", "remotes", "mirrors"], true),
            (RepoLayout::State, &[], true),
            (RepoLayout::Extensions, &[], true),
            (RepoLayout::Deltas, &[], false),
            (RepoLayout::DeltaIndexes, &[], false),
        ];
        for (kind, children, at_init) in expected {
            let rules = kind.rules();
            assert_eq!(rules.init_children, children, "init children of {kind:?}");
            assert_eq!(rules.created_at_init, at_init, "created at init: {kind:?}");
        }
    }

    #[test]
    fn root_files_have_their_names_modes_and_symlink_rule() {
        let expected: [(RootFile, &str, u32, u32, bool); 7] = [
            (RootFile::Config, "config", 0o644, 0o644, false),
            (RootFile::Summary, "summary", 0o644, 0o644, false),
            (RootFile::SummarySig, "summary.sig", 0o644, 0o644, false),
            (RootFile::Lock, ".lock", 0o660, 0o660, false),
            (RootFile::UpdateLock, ".update.lock", 0o660, 0o660, false),
            (
                RootFile::Keyring("origin.trustedkeys.gpg".into()),
                "origin.trustedkeys.gpg",
                0o644,
                0o644,
                true,
            ),
            (
                RootFile::Keyring("gpgkeys.gpg".into()),
                "gpgkeys.gpg",
                0o644,
                0o644,
                true,
            ),
        ];
        for (file, name, mode, shared, follows) in expected {
            assert_eq!(file.name(), name);
            assert_eq!(file.file_mode(), mode, "mode of {name}");
            assert_eq!(file.shared_file_mode(), shared, "shared mode of {name}");
            assert_eq!(
                file.follows_leaf_symlink(),
                follows,
                "symlink rule of {name}"
            );
        }
    }

    #[test]
    fn an_absent_entry_gives_not_found_with_the_path() {
        let err = Error::from(absent("state/x"));
        match &err {
            Error::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
                assert_eq!(e.raw_os_error(), None);
                assert_eq!(e.to_string(), "state/x does not exist");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_invalid_entry_gives_invalid_format_with_the_path_and_the_reason() {
        for (reason, text) in reason_cases() {
            assert_eq!(reason.to_string(), text);
            let err = Error::from(invalid("state/x", reason));
            let expected = format!("state/x {text}");
            assert!(
                matches!(&err, Error::InvalidFormat(m) if *m == expected),
                "{err:?}"
            );
        }
    }

    #[test]
    fn an_io_error_keeps_its_errno() {
        let err = Error::from(FsError::Io(Errno::ACCESS.into()));
        assert!(has_errno(&err, Errno::ACCESS), "{err:?}");
    }

    #[test]
    fn an_existing_entry_gives_eexist() {
        let err = Error::from(FsError::Exists);
        assert!(has_errno(&err, Errno::EXIST), "{err:?}");
    }

    #[test]
    fn optional_gives_none_for_an_absent_entry_alone() {
        assert!(matches!(Ok::<u8, FsError>(5).optional(), Ok(Some(5))));
        assert!(matches!(
            Err::<u8, _>(absent("state/x")).optional(),
            Ok(None)
        ));
        assert!(matches!(
            Err::<u8, _>(FsError::Exists).optional(),
            Err(FsError::Exists)
        ));
        for (reason, text) in reason_cases() {
            match Err::<u8, _>(invalid("state/x", reason)).optional() {
                Err(FsError::Invalid { path, reason }) => {
                    assert_eq!(path, "state/x");
                    assert_eq!(reason.to_string(), text);
                }
                other => panic!("{other:?}"),
            }
        }
        match Err::<u8, _>(FsError::Io(Errno::ACCESS.into())).optional() {
            Err(FsError::Io(e)) => assert_eq!(e.raw_os_error(), Some(Errno::ACCESS.raw_os_error())),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_absent_ref_or_a_ref_below_a_file_is_no_ref() {
        assert!(matches!(
            Ok::<u8, FsError>(5).optional_ref("main"),
            Ok(Some(5))
        ));
        let ok = Err::<u8, _>(absent("refs/heads/main"))
            .optional_ref("main")
            .unwrap();
        assert!(ok.is_none());
        let ok = Err::<u8, _>(invalid("refs/heads/main/sub", Reason::NotDirectory))
            .optional_ref("main/sub")
            .unwrap();
        assert!(ok.is_none());
    }

    #[test]
    fn a_ref_that_is_not_a_regular_file_gives_not_a_ref() {
        let err = Err::<u8, _>(invalid(
            "refs/heads/main",
            Reason::NotRegular(FileType::Fifo),
        ))
        .optional_ref("main")
        .unwrap_err();
        assert!(
            matches!(&err, Error::NotARef { name, reason }
                if name == "main" && reason == "is not a regular file"),
            "{err:?}"
        );
    }

    #[test]
    fn a_ref_through_a_symlink_or_an_escape_or_too_large_gives_invalid_format() {
        let cases = [
            (
                Reason::Symlink,
                "refs/heads/main passes through a symlink; ostrya refuses a symlink in the repository",
            ),
            (
                Reason::Escape,
                "refs/heads/main resolves outside the repository",
            ),
            (
                Reason::TooLarge { cap: 4096 },
                "refs/heads/main is larger than its cap of 4096 bytes",
            ),
        ];
        for (reason, expected) in cases {
            let err = Err::<u8, _>(invalid("refs/heads/main", reason))
                .optional_ref("main")
                .unwrap_err();
            assert!(
                matches!(&err, Error::InvalidFormat(m) if m == expected),
                "{err:?}"
            );
        }
    }

    #[test]
    fn a_ref_keeps_an_io_errno_and_gives_eexist_for_an_existing_entry() {
        let err = Err::<u8, _>(FsError::Io(Errno::ACCESS.into()))
            .optional_ref("main")
            .unwrap_err();
        assert!(has_errno(&err, Errno::ACCESS), "{err:?}");
        let err = Err::<u8, _>(FsError::Exists)
            .optional_ref("main")
            .unwrap_err();
        assert!(has_errno(&err, Errno::EXIST), "{err:?}");
    }

    #[test]
    fn an_absent_object_gives_object_not_found() {
        let sum = checksum();
        let err = absent("objects/ab/ab.commit").into_object_error(&sum, ObjectType::Commit);
        assert!(
            matches!(&err, Error::ObjectNotFound { checksum, ty: ObjectType::Commit } if *checksum == sum),
            "{err:?}"
        );
    }

    #[test]
    fn an_object_error_of_each_other_kind_gives_the_common_conversion() {
        let sum = checksum();
        for (reason, text) in reason_cases() {
            let err =
                invalid("objects/ab/ab.commit", reason).into_object_error(&sum, ObjectType::Commit);
            let expected = format!("objects/ab/ab.commit {text}");
            assert!(
                matches!(&err, Error::InvalidFormat(m) if *m == expected),
                "{err:?}"
            );
        }
        let err = FsError::Io(Errno::ACCESS.into()).into_object_error(&sum, ObjectType::Commit);
        assert!(has_errno(&err, Errno::ACCESS), "{err:?}");
        let err = FsError::Exists.into_object_error(&sum, ObjectType::Commit);
        assert!(has_errno(&err, Errno::EXIST), "{err:?}");
    }

    #[test]
    fn from_root_fd_gives_a_root_handle_with_no_mode() {
        let dir = TestDir::new("root-fd");
        let fd = rustix::io::dup(dir.fd()).unwrap();
        let raw = fd.as_raw_fd();
        let repo = RepoDir::from_root_fd(fd);
        assert_eq!(repo.kind(), RepoLayout::Root);
        assert_eq!(repo.repo_mode(), None);
        assert_eq!(repo.as_fd().as_raw_fd(), raw);
        assert_eq!(repo.ctx.root.as_raw_fd(), raw);
    }

    #[test]
    fn with_repo_mode_keeps_the_descriptor_and_sets_the_mode() {
        let dir = TestDir::new("repo-mode");
        let fd = rustix::io::dup(dir.fd()).unwrap();
        let raw = fd.as_raw_fd();
        let repo = RepoDir::from_root_fd(fd).with_repo_mode(RepoMode::BareUser);
        assert_eq!(repo.kind(), RepoLayout::Root);
        assert_eq!(repo.repo_mode(), Some(RepoMode::BareUser));
        assert_eq!(repo.as_fd().as_raw_fd(), raw);
        assert_eq!(repo.ctx.root.as_raw_fd(), raw);
    }

    /// Returns a root handle on a duplicate of the descriptor of `dir`, with
    /// the `tmp/` descriptor of its context set to another duplicate.
    fn root_with_tmp(dir: &TestDir) -> (RepoDir, Arc<OwnedFd>) {
        let repo = RepoDir::from_root_fd(rustix::io::dup(dir.fd()).unwrap());
        let tmp = Arc::new(rustix::io::dup(dir.fd()).unwrap());
        repo.ctx.tmp.set(Arc::clone(&tmp)).unwrap();
        (repo, tmp)
    }

    #[test]
    fn with_repo_mode_sets_the_mode_in_place_for_the_sole_owner() {
        let dir = TestDir::new("repo-mode-sole");
        let (repo, tmp) = root_with_tmp(&dir);
        let ctx = Arc::as_ptr(&repo.ctx);
        let repo = repo.with_repo_mode(RepoMode::BareUserShared);
        assert!(std::ptr::eq(Arc::as_ptr(&repo.ctx), ctx), "one context");
        assert_eq!(repo.repo_mode(), Some(RepoMode::BareUserShared));
        assert!(Arc::ptr_eq(repo.ctx.tmp.get().unwrap(), &tmp));
    }

    #[test]
    fn with_repo_mode_gives_a_shared_handle_a_new_context() {
        let dir = TestDir::new("repo-mode-shared");
        let (repo, tmp) = root_with_tmp(&dir);
        let other = repo.clone();
        let repo = repo.with_repo_mode(RepoMode::Archive);
        assert!(!Arc::ptr_eq(&repo.ctx, &other.ctx), "a new context");
        assert_eq!(repo.repo_mode(), Some(RepoMode::Archive));
        assert_eq!(other.repo_mode(), None);
        assert!(Arc::ptr_eq(&repo.fd, &other.fd));
        assert!(Arc::ptr_eq(&repo.ctx.root, &other.ctx.root));
        assert!(Arc::ptr_eq(repo.ctx.tmp.get().unwrap(), &tmp));
        assert!(Arc::ptr_eq(other.ctx.tmp.get().unwrap(), &tmp));
    }

    #[test]
    fn stat_fd_reads_a_regular_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TestDir::new("stat-file");
        let path = dir.path().join("file");
        std::fs::write(&path, b"twelve bytes").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let fd = rustix::fs::openat(
            dir.fd(),
            "file",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();

        let stat = stat_fd(fd.as_fd()).unwrap();
        let meta = std::fs::symlink_metadata(&path).unwrap();
        assert_eq!(stat.file_type, FileType::RegularFile);
        assert_eq!(stat.mode & 0o7777, 0o640);
        assert_eq!(stat.mode, meta.mode());
        assert_eq!(stat.uid, meta.uid());
        assert_eq!(stat.gid, meta.gid());
        assert_eq!(stat.size, 12);
        assert_eq!(stat.size, meta.size());
        assert_eq!(stat.dev, meta.dev());
        assert_eq!(stat.ino, meta.ino());
        assert_eq!(stat.mtime_sec, meta.mtime());
        assert_eq!(i64::from(stat.mtime_nsec), meta.mtime_nsec());
        assert!(!stat.verity);
    }

    #[test]
    fn stat_fd_reads_a_directory() {
        let dir = TestDir::new("stat-dir");
        let stat = stat_fd(dir.fd()).unwrap();
        let meta = std::fs::symlink_metadata(dir.path()).unwrap();
        assert_eq!(stat.file_type, FileType::Directory);
        assert_eq!(stat.mode, meta.mode());
        assert_eq!(stat.ino, meta.ino());
    }

    #[test]
    fn stat_fd_reads_a_symlink_opened_with_o_path() {
        let dir = TestDir::new("stat-link");
        std::os::unix::fs::symlink("nowhere", dir.path().join("link")).unwrap();
        let fd = rustix::fs::openat(
            dir.fd(),
            "link",
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let stat = stat_fd(fd.as_fd()).unwrap();
        assert_eq!(stat.file_type, FileType::Symlink);
    }

    #[test]
    fn test_dir_removes_its_tree_on_drop() {
        let dir = TestDir::new("drop");
        let path = dir.path().to_owned();
        std::fs::create_dir(path.join("sub")).unwrap();
        std::fs::write(path.join("sub/file"), b"x").unwrap();
        assert!(path.is_dir());
        drop(dir);
        assert!(!path.exists());
    }
}
