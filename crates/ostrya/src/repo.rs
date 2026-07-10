//! The repository handle: open, create, and the parsed config.
//!
//! [`Repo`] is a cheap-to-clone handle (an `Arc` inner) that owns the
//! file descriptors anchoring fd-relative I/O and the parsed [`RepoConfig`].
//! Opening resolves the repository directory and its `objects/` directory and
//! reads the config once; clones share that state so a handle moves freely
//! into a task.
//!
//! The public entry points are `async fn`. The filesystem work -- the
//! `openat`/`mkdirat` syscalls and the config read -- runs on the blocking
//! pool via [`ostrya_rt::unblock`], so a call does not stall the async
//! executor. The config parse that follows is CPU-only and runs inline.
//!
//! Directory-layout creation reproduces what the `ostree` tool writes: the
//! `config` file (mode `0644`, independent of umask), and the `objects`,
//! `refs/{heads,remotes,mirrors}`, `state`, `tmp`, `tmp/cache`, and
//! `extensions` directories (mode `0775`, reduced by the process umask, the
//! same as the tool). Creation is idempotent: an existing `config` is left
//! untouched, matching the tool's `init`.

use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;

use ostrya_core::RepoMode;
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

use crate::config::RepoConfig;
use crate::error::{Error, Result};

/// The path of the config file within a repository.
const CONFIG: &str = "config";

/// The mode requested for created directories, before the umask is applied.
const DIR_MODE: u32 = 0o775;

/// The mode forced on the config file, independent of the umask.
const CONFIG_MODE: u32 = 0o644;

/// The directories a repository holds, in an order that creates each parent
/// before its children.
const LAYOUT_DIRS: &[&str] = &[
    "objects",
    "tmp",
    "tmp/cache",
    "refs",
    "refs/heads",
    "refs/remotes",
    "refs/mirrors",
    "state",
    "extensions",
];

/// Options for creating a repository.
#[derive(Debug, Clone)]
pub struct CreateOptions {
    /// The storage mode written to `[core] mode`.
    pub mode: RepoMode,
    /// An optional collection id written to `[core] collection-id`.
    pub collection_id: Option<String>,
}

impl Default for CreateOptions {
    fn default() -> Self {
        CreateOptions {
            mode: RepoMode::Bare,
            collection_id: None,
        }
    }
}

impl CreateOptions {
    /// Options for a repository of the given mode with no collection id.
    pub fn new(mode: RepoMode) -> Self {
        CreateOptions {
            mode,
            collection_id: None,
        }
    }
}

/// A repository handle.
#[derive(Debug, Clone)]
pub struct Repo(Arc<RepoInner>);

#[derive(Debug)]
struct RepoInner {
    // The repository root and `objects/` directory fds anchor all fd-relative
    // I/O; they are opened once here and used by the reading path (Phase 5)
    // and, later, the write path (Phase 7).
    repo_fd: OwnedFd,
    objects_fd: OwnedFd,
    config: RepoConfig,
}

/// The filesystem-derived materials for a handle, produced on the blocking
/// pool and assembled into a [`Repo`] on the async side.
struct Materials {
    repo_fd: OwnedFd,
    objects_fd: OwnedFd,
    config: Vec<u8>,
}

impl Repo {
    /// Open an existing repository at `path`, resolved against the current
    /// working directory.
    pub async fn open(path: &Path) -> Result<Repo> {
        let path = path.to_owned();
        let materials = ostrya_rt::unblock(move || open_materials(rustix::fs::CWD, &path)).await?;
        Repo::assemble(materials)
    }

    /// Open an existing repository at `path`, resolved against `dir`.
    pub async fn open_at(dir: BorrowedFd<'_>, path: &Path) -> Result<Repo> {
        let dir = dir.try_clone_to_owned()?;
        let path = path.to_owned();
        let materials = ostrya_rt::unblock(move || open_materials(&dir, &path)).await?;
        Repo::assemble(materials)
    }

    /// Create a repository at `path`, resolved against the current working
    /// directory, then open it. Creation is idempotent.
    pub async fn create(path: &Path, opts: CreateOptions) -> Result<Repo> {
        let path = path.to_owned();
        let materials =
            ostrya_rt::unblock(move || create_materials(rustix::fs::CWD, &path, &opts)).await?;
        Repo::assemble(materials)
    }

    /// Create a repository at `path`, resolved against `dir`, then open it.
    /// Creation is idempotent.
    pub async fn create_at(dir: BorrowedFd<'_>, path: &Path, opts: CreateOptions) -> Result<Repo> {
        let dir = dir.try_clone_to_owned()?;
        let path = path.to_owned();
        let materials = ostrya_rt::unblock(move || create_materials(&dir, &path, &opts)).await?;
        Repo::assemble(materials)
    }

    /// The repository storage mode.
    pub fn mode(&self) -> RepoMode {
        self.0.config.mode()
    }

    /// The parsed repository configuration.
    pub fn config(&self) -> &RepoConfig {
        &self.0.config
    }

    /// The repository root directory fd, anchoring fd-relative access to
    /// `refs/`, `state/`, and the rest of the layout.
    pub(crate) fn repo_fd(&self) -> BorrowedFd<'_> {
        self.0.repo_fd.as_fd()
    }

    /// The `objects/` directory fd, anchoring loose-object access.
    pub(crate) fn objects_fd(&self) -> BorrowedFd<'_> {
        self.0.objects_fd.as_fd()
    }

    /// Parse the config bytes and assemble the handle. This step is CPU-only.
    fn assemble(materials: Materials) -> Result<Repo> {
        let text = std::str::from_utf8(&materials.config)
            .map_err(|_| Error::InvalidFormat("config is not valid UTF-8".into()))?;
        let config = RepoConfig::parse(text)?;
        Ok(Repo(Arc::new(RepoInner {
            repo_fd: materials.repo_fd,
            objects_fd: materials.objects_fd,
            config,
        })))
    }
}

/// Open an existing repository directory and gather its materials.
fn open_materials<Fd: AsFd>(dir: Fd, path: &Path) -> std::io::Result<Materials> {
    let repo_fd = open_dir(dir, path)?;
    materials_from_repo(repo_fd)
}

/// Ensure the repository layout and config exist, then gather its materials.
fn create_materials<Fd: AsFd>(
    dir: Fd,
    path: &Path,
    opts: &CreateOptions,
) -> std::io::Result<Materials> {
    mkdir_idempotent(&dir, path)?;
    let repo_fd = open_dir(&dir, path)?;
    for sub in LAYOUT_DIRS {
        mkdir_idempotent(&repo_fd, Path::new(sub))?;
    }
    write_initial_config(&repo_fd, opts)?;
    materials_from_repo(repo_fd)
}

/// Open the `objects/` directory and read the config, given the repo root fd.
fn materials_from_repo(repo_fd: OwnedFd) -> std::io::Result<Materials> {
    let objects_fd = open_dir(&repo_fd, Path::new("objects"))?;
    let config = read_file(&repo_fd, CONFIG)?;
    Ok(Materials {
        repo_fd,
        objects_fd,
        config,
    })
}

/// Open a directory relative to `dir` for fd-relative use.
fn open_dir<Fd: AsFd>(dir: Fd, path: &Path) -> std::io::Result<OwnedFd> {
    let fd = rustix::fs::openat(
        dir,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    Ok(fd)
}

/// Read a file's full contents relative to `dir`.
fn read_file<Fd: AsFd>(dir: Fd, path: &str) -> std::io::Result<Vec<u8>> {
    let fd = rustix::fs::openat(dir, path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())?;
    let mut buf = Vec::new();
    std::fs::File::from(fd).read_to_end(&mut buf)?;
    Ok(buf)
}

/// Create a directory, treating an existing entry as success.
fn mkdir_idempotent<Fd: AsFd>(dir: Fd, path: &Path) -> std::io::Result<()> {
    match rustix::fs::mkdirat(dir, path, Mode::from_raw_mode(DIR_MODE)) {
        Ok(()) | Err(Errno::EXIST) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Write the initial `config` if it does not already exist. The file is forced
/// to mode `0644` regardless of the umask, matching the tool.
fn write_initial_config<Fd: AsFd>(repo_fd: Fd, opts: &CreateOptions) -> std::io::Result<()> {
    let fd = match rustix::fs::openat(
        repo_fd,
        CONFIG,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::from_raw_mode(CONFIG_MODE),
    ) {
        Ok(fd) => fd,
        // An existing config means the repository is already initialized.
        Err(Errno::EXIST) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    rustix::fs::fchmod(&fd, Mode::from_raw_mode(CONFIG_MODE))?;
    std::fs::File::from(fd).write_all(initial_config_text(opts).as_bytes())
}

/// The exact config bytes a freshly created repository holds.
fn initial_config_text(opts: &CreateOptions) -> String {
    let mut text = String::from("[core]\nrepo_version=1\nmode=");
    text.push_str(opts.mode.as_mode_str());
    text.push('\n');
    if let Some(id) = &opts.collection_id {
        text.push_str("collection-id=");
        text.push_str(id);
        text.push('\n');
    }
    text
}

/// A repository handle is `Send + Sync`, so it moves freely across tasks and
/// threads.
#[allow(dead_code)]
fn assert_send_sync() {
    fn is_send_sync<T: Send + Sync>() {}
    is_send_sync::<Repo>();
}
