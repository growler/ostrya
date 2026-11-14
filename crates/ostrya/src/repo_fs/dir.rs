//! The directory primitives: the open and the create of a directory, the temp
//! directories, the listing, the removal of a tree, and the directory sync.
//!
//! Each open of a path below a [`RepoDir`] is one `openat2` with
//! `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS`. The kernel refuses a symlink at each
//! component with `ELOOP`. Each primitive refuses a `..`, `.`, or empty
//! component, and an absolute path, before the call.
//!
//! A primitive that changes the names in a directory takes `fsync`. With
//! `fsync`, it syncs the directory that it changed with `fsync` before it
//! returns. A caller that changes the names in many directories keeps their
//! paths, and syncs each one at the end with [`RepoDir::sync_dir`].

use std::ffi::{CStr, OsStr};
use std::io;
use std::mem::MaybeUninit;
use std::ops::ControlFlow;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;

use ostrya_core::RepoMode;
use rustix::fs::{AtFlags, FileType, Mode, OFlags, RawDir, ResolveFlags, StatxFlags};
use rustix::io::Errno;

use super::{DirPath, Entry, FsError, Reason, RepoContext, RepoDir, RepoLayout};

/// The flags of each directory open.
const DIR_OPEN: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);

/// The resolve flags of each open below a handle.
const BENEATH: ResolveFlags = ResolveFlags::BENEATH.union(ResolveFlags::NO_SYMLINKS);

/// The size of the `getdents` buffer of a listing or a tree removal.
const LIST_BUF_LEN: usize = 32 * 1024;

/// The size of the stack buffer that joins the path of a nested handle. A
/// longer path costs one more allocation.
const JOIN_BUF_LEN: usize = 512;

/// The character set of the random suffix of a temp directory name (the
/// alphabet of `mkdtemp`).
const SUFFIX_ALPHABET: &[u8; 62] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// The length of the random suffix of a temp directory name.
const SUFFIX_LEN: usize = 6;

/// The maximum number of names that [`RepoDir::make_temp_dir`] tries.
const TEMP_DIR_ATTEMPTS: u32 = 128;

/// The device and the inode of a directory.
type Identity = (u64, u64);

/// A directory on the path of a tree removal, from the top of the tree down
/// to the directory that the removal reads.
struct Level {
    /// The name of the directory in its parent.
    name: Vec<u8>,
    /// The device and inode of the directory. The removal reads them when it
    /// descends below the directory, and compares them when it goes up again.
    id: Option<Identity>,
    /// The names of the subdirectories that the removal did not remove yet.
    subdirs: Vec<Vec<u8>>,
}

/// The failure of the read of one directory in a tree removal: the errno, and
/// the name of the entry that failed, or `None` for the directory itself.
type ClearError = (Errno, Option<Vec<u8>>);

impl RepoDir {
    /// Opens the repository root at `path` relative to `base`, and returns a
    /// handle of kind [`RepoLayout::Root`] with no repository mode.
    ///
    /// The open is one `openat`. It follows a symlink at each component of
    /// `path`, because the caller names the root. An absolute `path` ignores
    /// `base`.
    ///
    /// `ENOENT` gives [`FsError::Absent`] and `ENOTDIR` gives
    /// [`Reason::NotDirectory`], each with `path` as the caller gives it. Each
    /// other errno gives [`FsError::Io`].
    pub(crate) fn open_root(base: impl AsFd, path: &Path) -> Result<RepoDir, FsError> {
        let fd = rustix::fs::openat(base, path, DIR_OPEN, Mode::empty())
            .map_err(|e| root_error(e, path))?;
        Ok(RepoDir::from_root_fd(fd))
    }

    /// Creates the repository root at `path` relative to `base` if it does
    /// not exist, opens it, and returns a handle of kind [`RepoLayout::Root`]
    /// with the repository mode `mode`.
    ///
    /// The `mkdirat` requests the directory mode of the root kind. In a
    /// `bare-user-shared` repository it requests the shared mode with no
    /// special bits, and an `fchmod` forces the shared mode when the function
    /// created the directory. If the `fchmod` fails, the function removes the
    /// directory that it created. An existing directory keeps its mode. The
    /// open and its errors are those of [`open_root`](RepoDir::open_root).
    pub(crate) fn create_root(
        base: impl AsFd,
        path: &Path,
        mode: RepoMode,
    ) -> Result<RepoDir, FsError> {
        let base = base.as_fd();
        let (request, force) = dir_modes(
            Some(mode),
            RepoLayout::Root,
            RepoLayout::Root.rules().dir_mode,
        );
        let created = match rustix::fs::mkdirat(base, path, Mode::from_raw_mode(request)) {
            Ok(()) => true,
            Err(Errno::EXIST) => false,
            Err(e) => return Err(root_error(e, path)),
        };
        let root = RepoDir::open_root(base, path)?.with_repo_mode(mode);
        if let Some(force) = force.filter(|_| created) {
            force_new_dir_mode(base, path, root.as_fd(), force).map_err(io_error)?;
        }
        Ok(root)
    }

    /// Opens the directory of the layout kind `kind` on the root handle, and
    /// returns a handle of that kind.
    ///
    /// The open is one `openat2` of the path of the kind. `kind` must be a kind
    /// with a fixed path, so not [`RepoLayout::Root`] and not
    /// [`RepoLayout::Staging`]. A call on a handle other than the root, or
    /// with such a kind, is a defect of the caller: it fails a debug assertion,
    /// and gives an `InvalidInput` error in a release build.
    pub(crate) fn open_layout(&self, kind: RepoLayout) -> Result<RepoDir, FsError> {
        let path = self.layout_path(kind)?;
        let fd = open_beneath(self.as_fd(), path).map_err(|e| FsError::at(e, path))?;
        Ok(self.handle(fd, kind, DirPath::Fixed(path)))
    }

    /// Opens the directory at `path` below this handle, and returns a handle
    /// of the same kind.
    ///
    /// `path` is relative to this directory. The open is one `openat2`. A
    /// symlink at a component gives [`Reason::Symlink`], a file at a
    /// component gives [`Reason::NotDirectory`], and a `..`, `.`, or empty
    /// component or an absolute path gives [`Reason::Escape`]. The path of an
    /// error is the full `path`, relative to the repository root.
    ///
    /// A call on the root handle is a defect of the caller, because the root
    /// has no kind for the directories below it. Use
    /// [`open_layout`](RepoDir::open_layout) there.
    pub(crate) fn open_dir(&self, path: &str) -> Result<RepoDir, FsError> {
        require(
            (self.kind != RepoLayout::Root).then_some(()),
            "open_dir needs a handle other than the root",
        )?;
        self.check_path(path)?;
        let fd =
            open_beneath(self.as_fd(), path).map_err(|e| FsError::at(e, &self.err_path(path)))?;
        Ok(self.nested(fd, path))
    }

    /// Makes the directory of the layout kind `kind` and its initial children
    /// if they do not exist, and returns a handle of that kind. The call is on
    /// the root handle, and `kind` is a kind with a fixed path.
    ///
    /// The directory of the kind gets the directory mode of the kind, and each
    /// child in `init_children` gets the same mode. The function makes each
    /// child that is missing, also when the directory of the kind exists. One
    /// `statx` with no follow checks each child that exists: a symlink gives
    /// [`Reason::Symlink`], and an entry that is not a directory gives
    /// [`Reason::NotDirectory`].
    ///
    /// The rules of [`ensure_dir`](RepoDir::ensure_dir) for the shared mode
    /// apply to each new directory. With `fsync`, the function syncs the root
    /// when it makes the directory of the kind, and syncs the directory of the
    /// kind one time when it makes one or more children.
    pub(crate) fn ensure_layout(&self, kind: RepoLayout, fsync: bool) -> Result<RepoDir, FsError> {
        let path = self.layout_path(kind)?;
        let rules = kind.rules();
        let (request, force) = dir_modes(self.ctx.mode, kind, rules.dir_mode);
        let (fd, _) = ensure_component(self.as_fd(), path, request, force, fsync)
            .map_err(|e| FsError::at(e, path))?;
        let dir = self.handle(fd, kind, DirPath::Fixed(path));
        let mut made = false;
        for child in rules.init_children {
            made |= ensure_child(dir.as_fd(), child, request, force)
                .map_err(|e| FsError::at(e, &dir.err_path(child)))?;
        }
        if made && fsync {
            fsync_dir(dir.as_fd()).map_err(io_error)?;
        }
        Ok(dir)
    }

    /// Makes the directory at `path` below this handle and each missing
    /// directory on the way, and returns a handle of the same kind.
    ///
    /// Each new directory gets the mode below the kind (`below_mode`). A call
    /// on a kind with no mode below is a defect of the caller.
    ///
    /// The function first opens the full path with one `openat2`. If a
    /// component is missing, it goes through the components. It opens each
    /// component before the first missing one. It makes the first missing
    /// component, each component below it, and the last component with
    /// `mkdirat`, and then opens each one. An entry that another process
    /// makes at the same time is used as it is. The path rules and the errors
    /// are those of [`open_dir`](RepoDir::open_dir). A file at a component,
    /// also at the last one, gives [`Reason::NotDirectory`]. An error in the
    /// walk gives the path up to the component that failed.
    ///
    /// In a `bare-user-shared` repository the `mkdirat` requests the shared
    /// mode of the kind with no special bits, and an `fchmod` forces the
    /// shared mode on each new directory. If the `fchmod` fails, the function
    /// removes that directory. An existing directory keeps its mode. Outside
    /// that mode, the umask reduces the mode of each new directory.
    ///
    /// With `fsync`, the function syncs the parent of each new directory at
    /// once. It syncs no other directory, so an existing path syncs nothing.
    pub(crate) fn ensure_dir(&self, path: &str, fsync: bool) -> Result<RepoDir, FsError> {
        let below = require(
            self.kind.rules().below_mode,
            "ensure_dir needs a kind with a mode below it",
        )?;
        self.check_path(path)?;
        match open_beneath(self.as_fd(), path) {
            Ok(fd) => return Ok(self.nested(fd, path)),
            Err(Errno::NOENT) => {}
            Err(e) => return Err(FsError::at(e, &self.err_path(path))),
        }
        #[cfg(test)]
        run_hook(super::HookPoint::Walk, path.as_bytes());
        let (request, force) = dir_modes(self.ctx.mode, self.kind, below);
        let mut parent: Option<OwnedFd> = None;
        let mut made = false;
        let mut end = 0;
        let mut components = path.split('/').peekable();
        while let Some(component) = components.next() {
            end += component.len();
            let at = parent.as_ref().map_or(self.as_fd(), AsFd::as_fd);
            // The open before the first missing component found that a
            // component is missing. Below a new directory, and at the last
            // component, `mkdirat` comes first.
            let result = if made || components.peek().is_none() {
                make_component(at, component, request, force, fsync)
            } else {
                ensure_component(at, component, request, force, fsync)
            };
            let (fd, created) = result.map_err(|e| FsError::at(e, &self.err_path(&path[..end])))?;
            made |= created;
            parent = Some(fd);
            end += 1;
        }
        let Some(fd) = parent else {
            unreachable!("a checked path has a component");
        };
        Ok(self.nested(fd, path))
    }

    /// Returns a handle of `tmp/`. The first call for a context makes `tmp/`
    /// and its initial children as [`ensure_layout`](RepoDir::ensure_layout)
    /// does, with `fsync`, and keeps the descriptor in the context. Each later
    /// call, from each handle of the context, gives a handle on the same
    /// descriptor and syncs nothing.
    pub(crate) fn tmp_dir(&self, fsync: bool) -> Result<RepoDir, FsError> {
        let fd = match self.ctx.tmp.get() {
            Some(fd) => Arc::clone(fd),
            None => {
                let root = RepoDir {
                    fd: Arc::clone(&self.ctx.root),
                    kind: RepoLayout::Root,
                    ctx: Arc::clone(&self.ctx),
                    path: DirPath::Fixed(""),
                };
                let tmp = root.ensure_layout(RepoLayout::Tmp, fsync)?;
                // A concurrent call can set the descriptor first. Its
                // descriptor is then the descriptor of the context.
                Arc::clone(self.ctx.tmp.get_or_init(|| tmp.fd))
            }
        };
        Ok(self.handle_on(fd, RepoLayout::Tmp, DirPath::Fixed("tmp")))
    }

    /// Makes a new directory with a unique name in this `tmp/` handle, and
    /// gives its name, a handle of kind [`RepoLayout::Staging`] on it, and the
    /// claim of the name.
    ///
    /// The name is `prefix` and a random suffix of six characters from
    /// `[A-Za-z0-9]`. Before the `mkdirat` of each name, the function calls
    /// `claim` with the name. `None` makes the function draw a new name. A
    /// name that exists also makes it draw a new name, and the claim of that
    /// name drops. The function tries 128 names at most, and then gives an
    /// `AlreadyExists` error.
    ///
    /// The `mkdirat` requests the directory mode of the staging kind. In a
    /// `bare-user-shared` repository it requests the shared mode with no
    /// special bits, and an `fchmod` forces the shared mode. If a step after
    /// the `mkdirat` fails, the function removes the new directory, then drops
    /// the claim, and gives the error of the step.
    ///
    /// The function syncs no directory. The sync of the file system at the
    /// commit of a transaction covers the content of a staging directory, and
    /// a staging directory that a crash loses does no harm.
    ///
    /// A call on a handle other than `tmp/` is a defect of the caller.
    pub(crate) fn make_temp_dir<G>(
        &self,
        prefix: &str,
        mut claim: impl FnMut(&str) -> Option<G>,
    ) -> Result<(String, RepoDir, G), FsError> {
        require(
            (self.kind == RepoLayout::Tmp).then_some(()),
            "make_temp_dir needs the tmp/ handle",
        )?;
        if prefix.contains('/') {
            return Err(FsError::Invalid {
                path: self.err_path(prefix),
                reason: Reason::Escape,
            });
        }
        let (request, force) = dir_modes(
            self.ctx.mode,
            RepoLayout::Staging,
            RepoLayout::Staging.rules().dir_mode,
        );
        let pid = std::process::id();
        for _ in 0..TEMP_DIR_ATTEMPTS {
            let mut name = String::with_capacity(prefix.len() + SUFFIX_LEN);
            name.push_str(prefix);
            push_random_suffix(&mut name, pid);
            let Some(guard) = claim(&name) else {
                continue;
            };
            match mkdir_temp(self.as_fd(), &name, request) {
                Ok(()) => {}
                Err(Errno::EXIST) => continue,
                Err(e) => return Err(FsError::at(e, &self.err_path(&name))),
            }
            match open_temp_dir(self.as_fd(), &name, force) {
                Ok(fd) => {
                    let dir = self.handle(fd, RepoLayout::Staging, self.child_path(&name));
                    return Ok((name, dir, guard));
                }
                Err(e) => {
                    let _ = rustix::fs::unlinkat(self, name.as_str(), AtFlags::REMOVEDIR);
                    return Err(FsError::at(e, &self.err_path(&name)));
                }
            }
        }
        Err(FsError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique temp directory",
        )))
    }

    /// Calls `visit` with the name and the type of each entry of the
    /// directory, with no `.` and no `..`, until `visit` gives
    /// [`ControlFlow::Break`].
    ///
    /// The function opens `.` of the directory again, so it needs search
    /// permission on the directory. A listing of a clone of the handle thus
    /// does not share the read position. It uses one `getdents` buffer of
    /// 32 KiB, and makes no allocation for each entry. A name stays as bytes,
    /// also a name that is not UTF-8. The type comes from `getdents`. For an
    /// entry of unknown type, one `statx` with no follow gives the type, and
    /// an entry that is gone at that `statx` is left out. A directory that is
    /// removed after its open gives no more entries.
    pub(crate) fn for_each_entry(
        &self,
        visit: impl FnMut(&CStr, FileType) -> ControlFlow<()>,
    ) -> Result<(), FsError> {
        reopen_and_visit(self.as_fd(), visit).map_err(|e| FsError::at(e, &self.err_path("")))
    }

    /// Returns the entries of the directory, with no `.` and no `..`.
    ///
    /// The rules of [`for_each_entry`](RepoDir::for_each_entry) apply. The
    /// listing thus needs search permission on the directory.
    pub(crate) fn list(&self) -> Result<Vec<Entry>, FsError> {
        let mut entries = Vec::new();
        self.for_each_entry(|name, file_type| push_entry(&mut entries, name, file_type))?;
        Ok(entries)
    }

    /// Removes the directory `name` of this directory and each entry below
    /// it. It gives `true` if the directory existed.
    ///
    /// `name` is one component. A `..`, `.`, empty, or multi-component name
    /// gives [`Reason::Escape`]. A symlink at `name` gives
    /// [`Reason::Symlink`], and a file at `name` gives
    /// [`Reason::NotDirectory`]. Each of them stays. An absent `name` gives
    /// `false`.
    ///
    /// The removal follows no symlink. It reads each directory with one
    /// `getdents` buffer for all levels, unlinks each entry that is not a
    /// directory at once, and keeps the names of the subdirectories alone. It
    /// unlinks a symlink as a link, so the target stays. It removes a
    /// subdirectory that has no subdirectory of its own from the parent that
    /// it holds. It descends into each other subdirectory, and holds two
    /// directory descriptors of its own at most. It goes up with an open of
    /// `..`, and compares the device and inode of that directory with the
    /// parent that it left. A difference means that a directory moved during
    /// the removal: the removal stops with an error, and does not follow the
    /// directory. An entry that is gone before the removal gets to it is
    /// skipped.
    ///
    /// With `fsync`, the function syncs this directory after it removes the
    /// directory `name`. It syncs nothing after an error.
    pub(crate) fn remove_tree(&self, name: &OsStr, fsync: bool) -> Result<bool, FsError> {
        let bytes = name.as_bytes();
        let err_path = || self.err_path(&String::from_utf8_lossy(bytes));
        if !is_component(bytes) {
            return Err(FsError::Invalid {
                path: err_path(),
                reason: Reason::Escape,
            });
        }
        let top = match open_beneath(self.as_fd(), name) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(false),
            Err(e) => return Err(FsError::at(e, &err_path())),
        };
        self.clear_tree(bytes, top)?;
        unlink_entry(self.as_fd(), name, AtFlags::REMOVEDIR)
            .map_err(|e| FsError::at(e, &err_path()))?;
        if fsync {
            fsync_dir(self.as_fd()).map_err(io_error)?;
        }
        Ok(true)
    }

    /// Removes each entry below the directory `name`, open at `top`. The
    /// directory `name` stays.
    fn clear_tree(&self, name: &[u8], top: OwnedFd) -> Result<(), FsError> {
        let mut buf: Box<[MaybeUninit<u8>]> = Box::new_uninit_slice(LIST_BUF_LEN);
        let mut levels = vec![Level {
            name: name.to_vec(),
            id: None,
            subdirs: Vec::new(),
        }];
        clear_level(top.as_fd(), &mut buf, &mut levels[0].subdirs)
            .map_err(|e| self.clear_error(&levels, None, e))?;
        // The descriptor of the last level.
        let mut level_fd = top;

        loop {
            let Some(level) = levels.last_mut() else {
                unreachable!("a level is in hand within the loop");
            };
            let Some(child) = level.subdirs.pop() else {
                // The level is clear. Go up, and remove it.
                let Some(cleared) = levels.pop() else {
                    unreachable!("a level is in hand within the loop");
                };
                let Some(parent) = levels.last() else {
                    return Ok(());
                };
                // `..` is never a symlink. The device and inode check below
                // guards the open.
                let up = rustix::fs::openat(level_fd.as_fd(), c"..", DIR_OPEN, Mode::empty())
                    .map_err(|e| {
                        FsError::at(e, &self.tree_path(&levels, &[cleared.name.as_slice()]))
                    })?;
                if Some(identity(up.as_fd())?) != parent.id {
                    return Err(FsError::Io(io::Error::other(
                        "a directory moved during the removal",
                    )));
                }
                level_fd = up;
                unlink_entry(
                    level_fd.as_fd(),
                    cleared.name.as_slice(),
                    AtFlags::REMOVEDIR,
                )
                .map_err(|e| {
                    FsError::at(e, &self.tree_path(&levels, &[cleared.name.as_slice()]))
                })?;
                continue;
            };
            let child_fd = match open_beneath(level_fd.as_fd(), child.as_slice()) {
                Ok(fd) => fd,
                Err(Errno::NOENT) => continue,
                Err(e) => {
                    return Err(FsError::at(
                        e,
                        &self.tree_path(&levels, &[child.as_slice()]),
                    ));
                }
            };
            let mut subdirs = Vec::new();
            clear_level(child_fd.as_fd(), &mut buf, &mut subdirs)
                .map_err(|e| self.clear_error(&levels, Some(child.as_slice()), e))?;
            #[cfg(test)]
            run_hook(super::HookPoint::Descend, &child);
            if subdirs.is_empty() {
                drop(child_fd);
                unlink_entry(level_fd.as_fd(), child.as_slice(), AtFlags::REMOVEDIR)
                    .map_err(|e| FsError::at(e, &self.tree_path(&levels, &[child.as_slice()])))?;
                continue;
            }
            // The removal descends, and drops the descriptor of this level.
            // The way up again compares the device and inode of `..` with this
            // level.
            if let Some(level) = levels.last_mut()
                && level.id.is_none()
            {
                level.id = Some(identity(level_fd.as_fd())?);
            }
            level_fd = child_fd;
            levels.push(Level {
                name: child,
                id: None,
                subdirs,
            });
        }
    }

    /// Syncs the directory at `path` below this handle with `fsync`.
    ///
    /// The open is one `openat2`. The path rules and the errors of the open
    /// are those of [`open_dir`](RepoDir::open_dir). An error of the `fsync`
    /// gives [`FsError::Io`]. The call is also correct on the root handle.
    pub(crate) fn sync_dir(&self, path: &str) -> Result<(), FsError> {
        self.check_path(path)?;
        let fd =
            open_beneath(self.as_fd(), path).map_err(|e| FsError::at(e, &self.err_path(path)))?;
        fsync_dir(fd.as_fd()).map_err(io_error)
    }

    /// Syncs the file system that holds the directory, with `syncfs`.
    pub(crate) fn syncfs(&self) -> Result<(), FsError> {
        rustix::fs::syncfs(self).map_err(io_error)
    }

    /// Returns the fixed path of `kind`, after the check that this is the root
    /// handle and that `kind` has a fixed path.
    fn layout_path(&self, kind: RepoLayout) -> Result<&'static str, FsError> {
        require(
            kind.rules().path.filter(|_| self.kind == RepoLayout::Root),
            "a layout kind opens on the root handle and has a fixed path",
        )
    }

    /// Refuses a `path` that is empty or absolute, or that has a `..`, `.`,
    /// or empty component, with [`Reason::Escape`].
    fn check_path(&self, path: &str) -> Result<(), FsError> {
        if path.split('/').all(|c| is_component(c.as_bytes())) {
            return Ok(());
        }
        Err(FsError::Invalid {
            path: self.err_path(path),
            reason: Reason::Escape,
        })
    }

    /// Returns a handle of the kind `kind` on `fd`, in the context of this
    /// handle.
    fn handle(&self, fd: OwnedFd, kind: RepoLayout, path: DirPath) -> RepoDir {
        self.handle_on(Arc::new(fd), kind, path)
    }

    /// Returns a handle of the kind `kind` on the shared descriptor `fd`, in
    /// the context of this handle.
    fn handle_on(&self, fd: Arc<OwnedFd>, kind: RepoLayout, path: DirPath) -> RepoDir {
        RepoDir {
            fd,
            kind,
            ctx: Arc::clone(&self.ctx),
            path,
        }
    }

    /// Returns a handle of the same kind on `fd`, the directory at `path`
    /// below this handle.
    fn nested(&self, fd: OwnedFd, path: &str) -> RepoDir {
        self.handle(fd, self.kind, self.child_path(path))
    }

    /// Returns the path of the directory `rel` below this handle. The path
    /// costs one allocation, or two for a joined path longer than 512 bytes.
    fn child_path(&self, rel: &str) -> DirPath {
        match &self.path {
            DirPath::Fixed(base) => DirPath::Nested {
                base,
                rel: Arc::from(rel),
            },
            DirPath::Nested { base, rel: head } => DirPath::Nested {
                base,
                rel: join_arc(head, rel),
            },
        }
    }

    /// Returns the path of an error at `rel`, relative to this directory, as
    /// a path relative to the repository root. An empty `rel` gives the path
    /// of this directory. The root itself shows as `.`.
    fn err_path(&self, rel: &str) -> String {
        let (base, mid) = match &self.path {
            DirPath::Fixed(base) => (*base, ""),
            DirPath::Nested { base, rel } => (*base, &**rel),
        };
        let parts = [base, mid, rel];
        let mut path = String::with_capacity(parts.iter().map(|p| p.len() + 1).sum());
        for part in parts.into_iter().filter(|p| !p.is_empty()) {
            if !path.is_empty() {
                path.push('/');
            }
            path.push_str(part);
        }
        if path.is_empty() {
            path.push('.');
        }
        path
    }

    /// Returns the path of an error at the names `tail` below the last level
    /// of `levels`. The first level is a directory of this handle.
    fn tree_path(&self, levels: &[Level], tail: &[&[u8]]) -> String {
        let mut rel = String::new();
        for name in levels
            .iter()
            .map(|level| level.name.as_slice())
            .chain(tail.iter().copied())
        {
            if !rel.is_empty() {
                rel.push('/');
            }
            rel.push_str(&String::from_utf8_lossy(name));
        }
        self.err_path(&rel)
    }

    /// Returns the error of the read of a directory in a tree removal. The
    /// directory is `child` of the last level of `levels`, or the last level
    /// itself for `None`.
    fn clear_error(
        &self,
        levels: &[Level],
        child: Option<&[u8]>,
        (errno, entry): ClearError,
    ) -> FsError {
        let tail: Vec<&[u8]> = child.into_iter().chain(entry.as_deref()).collect();
        FsError::at(errno, &self.tree_path(levels, &tail))
    }
}

impl RepoContext {
    /// Returns `true` if the repository mode is `bare-user-shared`.
    fn is_shared(&self) -> bool {
        self.mode == Some(RepoMode::BareUserShared)
    }
}

/// Calls `visit` with the name and the type of each entry of the directory
/// open at `dir`, with no `.` and no `..`. The rules of
/// [`RepoDir::for_each_entry`] apply.
///
/// The function lists a directory that is not a handle of a repository, for
/// example a directory that a config names. It opens `.` of `dir` again, so
/// it needs search permission on the directory, and the read position of
/// `dir` does not change. Each error gives [`FsError::Io`].
pub(crate) fn for_each_entry_fd(
    dir: BorrowedFd<'_>,
    visit: impl FnMut(&CStr, FileType) -> ControlFlow<()>,
) -> Result<(), FsError> {
    reopen_and_visit(dir, visit).map_err(io_error)
}

/// Returns the entries of the directory open at `dir`, with no `.` and no
/// `..`. The rules of [`for_each_entry_fd`] apply. The listing thus needs
/// search permission on the directory.
pub(crate) fn list_fd(dir: BorrowedFd<'_>) -> Result<Vec<Entry>, FsError> {
    let mut entries = Vec::new();
    for_each_entry_fd(dir, |name, file_type| {
        push_entry(&mut entries, name, file_type)
    })?;
    Ok(entries)
}

/// Adds the entry `name` of type `file_type` to `entries`, and continues the
/// listing.
fn push_entry(entries: &mut Vec<Entry>, name: &CStr, file_type: FileType) -> ControlFlow<()> {
    entries.push(Entry {
        name: name.to_bytes().to_vec(),
        file_type,
    });
    ControlFlow::Continue(())
}

/// Opens `.` of `dir`, and calls `visit` with each entry of it.
fn reopen_and_visit(
    dir: BorrowedFd<'_>,
    mut visit: impl FnMut(&CStr, FileType) -> ControlFlow<()>,
) -> Result<(), Errno> {
    let fd = rustix::fs::openat(dir, c".", DIR_OPEN, Mode::empty())?;
    let mut buf: Box<[MaybeUninit<u8>]> = Box::new_uninit_slice(LIST_BUF_LEN);
    read_entries(fd.as_fd(), &mut buf, |name, file_type| {
        Ok(visit(name, file_type))
    })
}

/// Reads the directory open at `dir` from its read position, with `buf` as the
/// `getdents` buffer, and calls `visit` with the name and the type of each
/// entry until `visit` gives [`ControlFlow::Break`] or an error.
///
/// The function skips `.` and `..`. [`entry_type`] gives the type, and the
/// function skips an entry that is gone at its `statx`. `ENOENT` from
/// `getdents` means that the directory was removed after its open, and ends
/// the read.
fn read_entries(
    dir: BorrowedFd<'_>,
    buf: &mut [MaybeUninit<u8>],
    mut visit: impl FnMut(&CStr, FileType) -> Result<ControlFlow<()>, Errno>,
) -> Result<(), Errno> {
    #[cfg(test)]
    let unknown_type = super::FAULTS.with(|faults| faults.borrow().unknown_type);
    #[cfg(test)]
    run_hook(super::HookPoint::Getdents, b"");
    let mut raw = RawDir::new(dir, buf);
    while let Some(entry) = raw.next() {
        let entry = match entry {
            Ok(entry) => entry,
            Err(Errno::NOENT) => break,
            Err(e) => return Err(e),
        };
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        let d_type = entry.file_type();
        #[cfg(test)]
        let d_type = if unknown_type {
            FileType::Unknown
        } else {
            d_type
        };
        #[cfg(test)]
        run_hook(super::HookPoint::Entry, name.to_bytes());
        let Some(file_type) = entry_type(dir, name, d_type)? else {
            continue;
        };
        if visit(name, file_type)?.is_break() {
            break;
        }
    }
    Ok(())
}

/// Reads the directory open at `dir` in a tree removal. The function unlinks
/// each entry that is not a directory, and adds the name of each
/// subdirectory to `subdirs`.
///
/// An `unlinkat` with no flag removes a symlink itself, and never follows
/// it. An entry that is gone at its unlink is skipped.
fn clear_level(
    dir: BorrowedFd<'_>,
    buf: &mut [MaybeUninit<u8>],
    subdirs: &mut Vec<Vec<u8>>,
) -> Result<(), ClearError> {
    let mut failed = None;
    read_entries(dir, buf, |name, file_type| {
        if file_type == FileType::Directory {
            subdirs.push(name.to_bytes().to_vec());
        } else if let Err(e) = unlink_entry(dir, name, AtFlags::empty()) {
            failed = Some(name.to_bytes().to_vec());
            return Err(e);
        }
        Ok(ControlFlow::Continue(()))
    })
    .map_err(|e| (e, failed.take()))
}

/// Returns the type of the entry `name` of `dir`, with the type `d_type` from
/// `getdents`.
///
/// A known `d_type` is the type, with no syscall. For
/// [`FileType::Unknown`], one `statx` with no follow gives the type. `None`
/// means that the entry is gone.
fn entry_type(
    dir: BorrowedFd<'_>,
    name: &CStr,
    d_type: FileType,
) -> Result<Option<FileType>, Errno> {
    if d_type != FileType::Unknown {
        return Ok(Some(d_type));
    }
    match rustix::fs::statx(dir, name, AtFlags::SYMLINK_NOFOLLOW, StatxFlags::TYPE) {
        Ok(stx) => Ok(Some(FileType::from_raw_mode(u32::from(stx.stx_mode)))),
        Err(Errno::NOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Opens the directory `path` below `dir` with one `openat2`. The open
/// refuses a symlink at each component, and a path that leaves `dir`.
fn open_beneath<P: rustix::path::Arg>(dir: BorrowedFd<'_>, path: P) -> Result<OwnedFd, Errno> {
    rustix::fs::openat2(dir, path, DIR_OPEN, Mode::empty(), BENEATH)
}

/// Opens the directory `name` of `parent`, and makes it if it is missing. It
/// gives the descriptor and `true` if the function made the directory.
///
/// The function makes a missing directory as [`make_component`] does.
fn ensure_component(
    parent: BorrowedFd<'_>,
    name: &str,
    request: u32,
    force: Option<u32>,
    fsync: bool,
) -> Result<(OwnedFd, bool), Errno> {
    match open_beneath(parent, name) {
        Ok(fd) => Ok((fd, false)),
        Err(Errno::NOENT) => make_component(parent, name, request, force, fsync),
        Err(e) => Err(e),
    }
}

/// Makes the directory `name` of `parent` with the mode `request`, and opens
/// it. It gives the descriptor and `true` if the function made the
/// directory.
///
/// A directory that exists, also one that another process makes at the same
/// time, is used as it is. On a new directory, an `fchmod` sets the mode
/// `force`, and the function removes the directory if the `fchmod` fails.
/// With `fsync`, the function then syncs `parent`.
fn make_component(
    parent: BorrowedFd<'_>,
    name: &str,
    request: u32,
    force: Option<u32>,
    fsync: bool,
) -> Result<(OwnedFd, bool), Errno> {
    let created = match rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(request)) {
        Ok(()) => true,
        Err(Errno::EXIST) => false,
        Err(e) => return Err(e),
    };
    let fd = open_beneath(parent, name)?;
    if created {
        if let Some(force) = force {
            force_new_dir_mode(parent, name, fd.as_fd(), force)?;
        }
        if fsync {
            fsync_dir(parent)?;
        }
    }
    Ok((fd, created))
}

/// Makes the initial child `name` of `parent` with the mode `request` if it is
/// missing. It gives `true` if the function made the directory.
///
/// One `statx` with no follow checks an existing child. The function opens
/// the child only to force the mode `force` on a directory that it made. If
/// the `fchmod` fails, the function removes the directory.
fn ensure_child(
    parent: BorrowedFd<'_>,
    name: &str,
    request: u32,
    force: Option<u32>,
) -> Result<bool, Errno> {
    match check_dir_entry(parent, name) {
        Ok(()) => return Ok(false),
        Err(Errno::NOENT) => {}
        Err(e) => return Err(e),
    }
    match rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(request)) {
        Ok(()) => {}
        Err(Errno::EXIST) => return check_dir_entry(parent, name).map(|()| false),
        Err(e) => return Err(e),
    }
    if let Some(force) = force {
        let fd = open_beneath(parent, name)?;
        force_new_dir_mode(parent, name, fd.as_fd(), force)?;
    }
    Ok(true)
}

/// Checks the entry `name` of `parent` with one `statx` with no follow. A
/// directory gives `Ok`, a symlink gives `ELOOP`, and each other type gives
/// `ENOTDIR`.
fn check_dir_entry(parent: BorrowedFd<'_>, name: &str) -> Result<(), Errno> {
    let stx = rustix::fs::statx(parent, name, AtFlags::SYMLINK_NOFOLLOW, StatxFlags::TYPE)?;
    match FileType::from_raw_mode(u32::from(stx.stx_mode)) {
        FileType::Directory => Ok(()),
        FileType::Symlink => Err(Errno::LOOP),
        _ => Err(Errno::NOTDIR),
    }
}

/// Forces the mode `force` on the new directory `name` of `parent`, open at
/// `fd`. If the `fchmod` fails, the function removes the directory, and gives
/// the error of the `fchmod`.
fn force_new_dir_mode<P: rustix::path::Arg + Copy>(
    parent: BorrowedFd<'_>,
    name: P,
    fd: BorrowedFd<'_>,
    force: u32,
) -> Result<(), Errno> {
    fchmod_new(fd, force).inspect_err(|_| {
        let _ = rustix::fs::unlinkat(parent, name, AtFlags::REMOVEDIR);
    })
}

/// Sets the mode `force` on the new directory open at `fd` with `fchmod`.
fn fchmod_new(fd: BorrowedFd<'_>, force: u32) -> Result<(), Errno> {
    #[cfg(test)]
    fault_after_mkdir(super::FaultStep::Fchmod)?;
    rustix::fs::fchmod(fd, Mode::from_raw_mode(force))
}

/// Syncs the directory open at `fd` with `fsync`.
fn fsync_dir(fd: BorrowedFd<'_>) -> Result<(), Errno> {
    #[cfg(test)]
    record_sync(fd);
    rustix::fs::fsync(fd)
}

/// Returns the mode that a `mkdirat` of a directory of `kind` requests, and
/// the mode that an `fchmod` forces after the create.
///
/// In a `bare-user-shared` repository the request is the shared mode of the
/// kind with no special bits, and the forced mode is the shared mode. In each
/// other mode, and with no mode, the request is `plain` and nothing is
/// forced.
fn dir_modes(mode: Option<RepoMode>, kind: RepoLayout, plain: u32) -> (u32, Option<u32>) {
    if mode == Some(RepoMode::BareUserShared) {
        let shared = kind.rules().shared_dir_mode;
        (shared & 0o777, Some(shared))
    } else {
        (plain, None)
    }
}

/// Makes the temp directory `name` of `tmp`.
fn mkdir_temp(tmp: BorrowedFd<'_>, name: &str, request: u32) -> Result<(), Errno> {
    #[cfg(test)]
    if super::FAULTS.with(|faults| faults.borrow().force_eexist) {
        return Err(Errno::EXIST);
    }
    rustix::fs::mkdirat(tmp, name, Mode::from_raw_mode(request))
}

/// Opens the new temp directory `name` of `tmp`, and forces the mode `force`
/// on it.
fn open_temp_dir(tmp: BorrowedFd<'_>, name: &str, force: Option<u32>) -> Result<OwnedFd, Errno> {
    #[cfg(test)]
    fault_after_mkdir(super::FaultStep::Open)?;
    let fd = open_beneath(tmp, name)?;
    if let Some(force) = force {
        fchmod_new(fd.as_fd(), force)?;
    }
    Ok(fd)
}

/// Gives the errno of a test fault at `step`.
#[cfg(test)]
fn fault_after_mkdir(step: super::FaultStep) -> Result<(), Errno> {
    match super::FAULTS.with(|faults| faults.borrow().fail_after_mkdir) {
        Some((at, errno)) if at == step => Err(errno),
        _ => Ok(()),
    }
}

/// Runs the test hook at `point`, if the thread has one, with `name`.
#[cfg(test)]
fn run_hook(point: super::HookPoint, name: &[u8]) {
    let taken = super::FAULTS.with(|faults| {
        let mut faults = faults.borrow_mut();
        let at = faults.hooks.iter().position(|(p, _)| *p == point)?;
        Some(faults.hooks.swap_remove(at))
    });
    if let Some((point, mut hook)) = taken {
        hook(name);
        super::FAULTS.with(|faults| faults.borrow_mut().hooks.push((point, hook)));
    }
}

/// Records the device and inode of the directory open at `fd`, if the test
/// records the syncs of its thread.
#[cfg(test)]
fn record_sync(fd: BorrowedFd<'_>) {
    super::FAULTS.with(|faults| {
        if let Some(synced) = faults.borrow_mut().synced.as_mut() {
            synced.push(identity(fd).expect("the identity of a synced directory"));
        }
    });
}

/// Appends a six-character `[A-Za-z0-9]` suffix to `name`, from a seed of the
/// time, the process id `pid`, and a counter of the process.
///
/// The name must be unique on the host only. A collision causes a new attempt.
fn push_random_suffix(name: &mut String, pid: u32) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut state = nanos ^ (u64::from(pid) << 32) ^ counter.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    for _ in 0..SUFFIX_LEN {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        name.push(SUFFIX_ALPHABET[(state % 62) as usize] as char);
    }
}

/// Unlinks `name` of `dir` with `flags`. An entry that is already gone is a
/// success.
fn unlink_entry<P: rustix::path::Arg>(
    dir: BorrowedFd<'_>,
    name: P,
    flags: AtFlags,
) -> Result<(), Errno> {
    match rustix::fs::unlinkat(dir, name, flags) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Returns `true` if `name` is one path component: not empty, not `.`, not
/// `..`, and with no `/`.
fn is_component(name: &[u8]) -> bool {
    !matches!(name, b"" | b"." | b"..") && !name.contains(&b'/')
}

/// Returns `head/tail` with one allocation when the joined path fits in a
/// stack buffer of 512 bytes.
fn join_arc(head: &str, tail: &str) -> Arc<str> {
    let len = head.len() + 1 + tail.len();
    let mut buf = [0u8; JOIN_BUF_LEN];
    if let Some(out) = buf.get_mut(..len) {
        let (left, right) = out.split_at_mut(head.len());
        left.copy_from_slice(head.as_bytes());
        right[0] = b'/';
        right[1..].copy_from_slice(tail.as_bytes());
        // The join of two strings is UTF-8, so the check always passes.
        if let Ok(joined) = std::str::from_utf8(out) {
            return Arc::from(joined);
        }
    }
    Arc::from(format!("{head}/{tail}"))
}

/// Returns the device and inode of the directory open at `fd`, from one
/// `statx`.
fn identity(fd: BorrowedFd<'_>) -> Result<Identity, FsError> {
    let stx = rustix::fs::statx(fd, c"", AtFlags::EMPTY_PATH, StatxFlags::INO).map_err(io_error)?;
    Ok((
        rustix::fs::makedev(stx.stx_dev_major, stx.stx_dev_minor),
        stx.stx_ino,
    ))
}

/// Maps the error of the open or the create of the root at `path`.
fn root_error(errno: Errno, path: &Path) -> FsError {
    match errno {
        Errno::NOENT => FsError::Absent {
            path: path.display().to_string(),
        },
        Errno::NOTDIR => FsError::Invalid {
            path: path.display().to_string(),
            reason: Reason::NotDirectory,
        },
        other => io_error(other),
    }
}

/// Returns an errno as [`FsError::Io`].
fn io_error(errno: Errno) -> FsError {
    FsError::Io(errno.into())
}

/// Gives the value of `value`, which a correct caller always supplies.
///
/// `None` is a defect of the caller, and `what` states the rule. It fails a
/// debug assertion, and gives an `InvalidInput` error in a release build.
fn require<T>(value: Option<T>, what: &'static str) -> Result<T, FsError> {
    debug_assert!(value.is_some(), "{what}");
    value.ok_or_else(|| FsError::Io(io::Error::new(io::ErrorKind::InvalidInput, what)))
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::fmt::Debug;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink};
    use std::path::PathBuf;
    use std::rc::Rc;

    use super::super::{FAULTS, FaultStep, Faults, HookPoint, TestDir};
    use super::*;

    /// Returns a root handle on a duplicate of the descriptor of `dir`.
    fn root(dir: &TestDir) -> RepoDir {
        RepoDir::from_root_fd(rustix::io::dup(dir.fd()).unwrap())
    }

    /// Returns the permission bits and the special bits of `path`.
    fn mode_of(path: &Path) -> u32 {
        std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
    }

    /// Returns the mode of a directory that a `mkdir` with the mode `request`
    /// makes in `parent`. The umask, a set-group-ID parent, and a default ACL
    /// of `parent` change the mode as they change each other new directory.
    fn reference_mode(parent: &Path, request: u32) -> u32 {
        let path = parent.join(".reference-mode");
        std::fs::DirBuilder::new()
            .mode(request)
            .create(&path)
            .unwrap();
        let mode = mode_of(&path);
        std::fs::remove_dir(&path).unwrap();
        mode
    }

    /// Returns the device and inode of `path`, with no follow.
    fn id_of(path: &Path) -> Identity {
        let meta = std::fs::symlink_metadata(path).unwrap();
        (meta.dev(), meta.ino())
    }

    fn is_symlink(path: &Path) -> bool {
        std::fs::symlink_metadata(path)
            .unwrap()
            .file_type()
            .is_symlink()
    }

    fn set_mode(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Returns the path and the reason of an `Invalid` error.
    fn invalid<T: Debug>(result: Result<T, FsError>) -> (String, Reason) {
        match result {
            Err(FsError::Invalid { path, reason }) => (path, reason),
            other => panic!("{other:?}"),
        }
    }

    /// Returns the error of an `Io` error.
    fn io_err<T: Debug>(result: Result<T, FsError>) -> io::Error {
        match result {
            Err(FsError::Io(e)) => e,
            other => panic!("{other:?}"),
        }
    }

    /// Returns the names of the entries of `path` that start with `prefix`.
    fn names_with(path: &Path, prefix: &str) -> Vec<String> {
        std::fs::read_dir(path)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(prefix))
            .collect()
    }

    /// Clears the faults of the thread when it drops.
    struct FaultReset;

    impl Drop for FaultReset {
        fn drop(&mut self) {
            FAULTS.with(|f| *f.borrow_mut() = Faults::default());
        }
    }

    fn set_faults(set: impl FnOnce(&mut Faults)) -> FaultReset {
        FAULTS.with(|f| set(&mut f.borrow_mut()));
        FaultReset
    }

    /// Adds a hook at `point` to the faults of the thread.
    fn set_hook(point: HookPoint, hook: impl FnMut(&[u8]) + 'static) -> FaultReset {
        set_faults(|f| f.hooks.push((point, Box::new(hook))))
    }

    /// Starts the record of the directory syncs of the thread.
    fn record_syncs() -> FaultReset {
        set_faults(|f| f.synced = Some(Vec::new()))
    }

    /// Returns the directory syncs that the thread recorded, and empties the
    /// record.
    fn take_synced() -> Vec<Identity> {
        FAULTS.with(|f| {
            f.borrow_mut()
                .synced
                .as_mut()
                .map(std::mem::take)
                .expect("the thread records its syncs")
        })
    }

    /// A claim of a temp directory name. Its drop records whether the
    /// directory existed at that time.
    #[derive(Debug)]
    struct Claim {
        path: PathBuf,
        existed_at_drop: Rc<Cell<Option<bool>>>,
    }

    impl Drop for Claim {
        fn drop(&mut self) {
            self.existed_at_drop.set(Some(self.path.exists()));
        }
    }

    #[test]
    fn open_layout_gives_symlink_for_a_symlinked_kind() {
        for dangling in [false, true] {
            let dir = TestDir::new("layout-link");
            std::fs::create_dir(dir.path().join("real")).unwrap();
            let target = if dangling { "nowhere" } else { "real" };
            symlink(target, dir.path().join("objects")).unwrap();
            let repo = root(&dir);
            let (path, reason) = invalid(repo.open_layout(RepoLayout::Objects));
            assert_eq!(path, "objects");
            assert!(matches!(reason, Reason::Symlink), "{reason:?}");
            let _reset = record_syncs();
            let (path, reason) = invalid(repo.ensure_layout(RepoLayout::Objects, true));
            assert_eq!(path, "objects");
            assert!(matches!(reason, Reason::Symlink), "{reason:?}");
            assert!(take_synced().is_empty());
            assert!(is_symlink(&dir.path().join("objects")));
        }
    }

    #[test]
    fn a_symlink_at_each_component_gives_symlink_with_the_full_path() {
        let components = ["a", "b", "c"];
        for at in 0..components.len() {
            for dangling in [false, true] {
                let dir = TestDir::new("component-link");
                let objects = dir.path().join("objects");
                std::fs::create_dir(&objects).unwrap();
                let mut path = objects.clone();
                for component in &components[..at] {
                    path.push(component);
                    std::fs::create_dir(&path).unwrap();
                }
                path.push(components[at]);
                // A real target holds the rest of the path, so a follow of
                // the link would succeed.
                let mut real = dir.path().join("real");
                std::fs::create_dir(&real).unwrap();
                for component in &components[at + 1..] {
                    real.push(component);
                    std::fs::create_dir(&real).unwrap();
                }
                let target = if dangling {
                    PathBuf::from("nowhere")
                } else {
                    dir.path().join("real")
                };
                symlink(&target, &path).unwrap();

                let objects_dir = root(&dir).open_layout(RepoLayout::Objects).unwrap();
                let case = format!("link at {at}, dangling {dangling}");
                let (err_path, reason) = invalid(objects_dir.open_dir("a/b/c"));
                assert_eq!(err_path, "objects/a/b/c", "{case}");
                assert!(matches!(reason, Reason::Symlink), "{case}: {reason:?}");
                let _reset = record_syncs();
                let (err_path, reason) = invalid(objects_dir.ensure_dir("a/b/c", true));
                assert_eq!(err_path, "objects/a/b/c", "{case}");
                assert!(matches!(reason, Reason::Symlink), "{case}: {reason:?}");
                assert!(take_synced().is_empty(), "{case}");
                let (err_path, reason) = invalid(objects_dir.sync_dir("a/b/c"));
                assert_eq!(err_path, "objects/a/b/c", "{case}");
                assert!(matches!(reason, Reason::Symlink), "{case}: {reason:?}");
                assert!(take_synced().is_empty(), "{case}");
                assert!(is_symlink(&path), "{case}");
            }
        }
    }

    #[test]
    fn a_dot_dot_an_absolute_path_or_an_empty_component_gives_escape() {
        let dir = TestDir::new("escape");
        std::fs::create_dir_all(dir.path().join("objects/a")).unwrap();
        let repo = root(&dir);
        let objects = repo.open_layout(RepoLayout::Objects).unwrap();
        let cases = [
            "..",
            "../x",
            "../objects",
            "a/../b",
            "a/..",
            "/etc",
            "/",
            "",
            "a//b",
            "./a",
            "a/.",
            "a/",
        ];
        let _reset = record_syncs();
        for path in cases {
            let (err_path, reason) = invalid(objects.open_dir(path));
            assert_eq!(err_path, objects.err_path(path), "{path}");
            assert!(matches!(reason, Reason::Escape), "{path}: {reason:?}");
            let (_, reason) = invalid(objects.ensure_dir(path, true));
            assert!(matches!(reason, Reason::Escape), "{path}: {reason:?}");
            let (err_path, reason) = invalid(objects.sync_dir(path));
            assert_eq!(err_path, objects.err_path(path), "{path}");
            assert!(matches!(reason, Reason::Escape), "{path}: {reason:?}");
            let (_, reason) = invalid(repo.sync_dir(path));
            assert!(matches!(reason, Reason::Escape), "{path}: {reason:?}");
        }
        assert!(take_synced().is_empty());
        assert_eq!(objects.err_path("../x"), "objects/../x");
        assert!(!dir.path().join("objects/b").exists());
        assert!(!dir.path().join("x").exists());
    }

    #[test]
    fn a_file_at_a_component_before_the_last_gives_not_directory() {
        let dir = TestDir::new("not-dir");
        std::fs::create_dir_all(dir.path().join("objects/a")).unwrap();
        std::fs::write(dir.path().join("objects/a/file"), b"x").unwrap();
        let objects = root(&dir).open_layout(RepoLayout::Objects).unwrap();
        let (path, reason) = invalid(objects.open_dir("a/file/c"));
        assert_eq!(path, "objects/a/file/c");
        assert!(matches!(reason, Reason::NotDirectory), "{reason:?}");
        let _reset = record_syncs();
        let (path, reason) = invalid(objects.ensure_dir("a/file/c", true));
        assert_eq!(path, "objects/a/file/c");
        assert!(matches!(reason, Reason::NotDirectory), "{reason:?}");
        let (path, reason) = invalid(objects.sync_dir("a/file/c"));
        assert_eq!(path, "objects/a/file/c");
        assert!(matches!(reason, Reason::NotDirectory), "{reason:?}");
        assert!(take_synced().is_empty());
        assert_eq!(
            std::fs::read(dir.path().join("objects/a/file")).unwrap(),
            b"x"
        );
    }

    #[test]
    fn ensure_dir_at_a_file_gives_not_directory_and_at_a_directory_gives_it() {
        let dir = TestDir::new("ensure-existing");
        let a = dir.path().join("objects/a");
        std::fs::create_dir_all(a.join("d")).unwrap();
        set_mode(&a.join("d"), 0o700);
        std::fs::write(a.join("f"), b"x").unwrap();
        let objects = root(&dir).open_layout(RepoLayout::Objects).unwrap();
        let _reset = record_syncs();

        let (path, reason) = invalid(objects.ensure_dir("a/f", true));
        assert_eq!(path, "objects/a/f");
        assert!(matches!(reason, Reason::NotDirectory), "{reason:?}");
        assert!(a.join("f").is_file());

        let d = objects.ensure_dir("a/d", true).unwrap();
        assert_eq!(identity(d.as_fd()).unwrap(), id_of(&a.join("d")));
        assert_eq!(d.kind(), RepoLayout::Objects);
        assert_eq!(d.err_path(""), "objects/a/d");
        assert!(take_synced().is_empty());
        assert_eq!(mode_of(&a.join("d")), 0o700);
    }

    #[test]
    fn ensure_dir_in_bare_user_shared_forces_the_shared_mode_on_new_directories_alone() {
        let dir = TestDir::new("ensure-shared");
        let heads = dir.path().join("refs/heads");
        std::fs::create_dir_all(&heads).unwrap();
        set_mode(&heads, 0o700);
        let repo = root(&dir).with_repo_mode(RepoMode::BareUserShared);
        let refs = repo.open_layout(RepoLayout::Refs).unwrap();
        let _reset = record_syncs();

        let y = refs.ensure_dir("heads/x/y", true).unwrap();
        assert_eq!(y.err_path(""), "refs/heads/x/y");
        assert_eq!(identity(y.as_fd()).unwrap(), id_of(&heads.join("x/y")));
        assert_eq!(mode_of(&heads), 0o700);
        assert_eq!(mode_of(&heads.join("x")), 0o2770);
        assert_eq!(mode_of(&heads.join("x/y")), 0o2770);
        assert_eq!(take_synced(), [id_of(&heads), id_of(&heads.join("x"))]);

        // An existing path syncs nothing.
        refs.ensure_dir("heads/x/y", true).unwrap();
        assert!(take_synced().is_empty());
    }

    #[test]
    fn ensure_dir_in_bare_user_requests_the_mode_below_the_kind() {
        let dir = TestDir::new("ensure-plain");
        let heads = dir.path().join("refs/heads");
        std::fs::create_dir_all(&heads).unwrap();
        let repo = root(&dir).with_repo_mode(RepoMode::BareUser);
        let refs = repo.open_layout(RepoLayout::Refs).unwrap();
        let _reset = record_syncs();

        refs.ensure_dir("heads/x/y", true).unwrap();
        assert_eq!(mode_of(&heads.join("x")), reference_mode(&heads, 0o777));
        let x = heads.join("x");
        assert_eq!(mode_of(&x.join("y")), reference_mode(&x, 0o777));
        assert_eq!(take_synced(), [id_of(&heads), id_of(&x)]);

        // With no `fsync`, a new path syncs nothing.
        refs.ensure_dir("heads/x/z/w", false).unwrap();
        assert!(x.join("z/w").is_dir());
        refs.ensure_dir("heads/v", false).unwrap();
        assert!(heads.join("v").is_dir());
        assert!(take_synced().is_empty());
    }

    #[test]
    fn ensure_dir_removes_a_new_directory_when_its_fchmod_fails() {
        let dir = TestDir::new("ensure-fchmod");
        let heads = dir.path().join("refs/heads");
        std::fs::create_dir_all(&heads).unwrap();
        let repo = root(&dir).with_repo_mode(RepoMode::BareUserShared);
        let refs = repo.open_layout(RepoLayout::Refs).unwrap();
        let _reset = set_faults(|f| f.fail_after_mkdir = Some((FaultStep::Fchmod, Errno::IO)));
        let _record = record_syncs();

        let err = io_err(refs.ensure_dir("heads/x/y", true));
        assert_eq!(err.raw_os_error(), Some(Errno::IO.raw_os_error()));
        assert!(!heads.join("x").exists());
        assert!(take_synced().is_empty());
    }

    #[test]
    fn ensure_dir_reports_an_error_of_the_walk_at_the_component_that_failed() {
        // Each case plants an entry after the first open of the full path,
        // so the walk meets it. The path names the component that failed.
        type Plant = fn(&Path);
        let symlink_to_real: Plant = |at| symlink("real", at).unwrap();
        let dangling: Plant = |at| symlink("nowhere", at).unwrap();
        let file: Plant = |at| std::fs::write(at, b"x").unwrap();
        let cases: [(&str, Plant, Reason); 6] = [
            // A component before the last: the walk opens it first.
            ("a/b", symlink_to_real, Reason::Symlink),
            ("a/b", dangling, Reason::Symlink),
            ("a/b", file, Reason::NotDirectory),
            // The last component: `mkdirat` gives `EEXIST`, and the open
            // gives the error.
            ("a", symlink_to_real, Reason::Symlink),
            ("a", dangling, Reason::Symlink),
            ("a", file, Reason::NotDirectory),
        ];
        for (path, plant, reason) in cases {
            let dir = TestDir::new("ensure-walk");
            let objects_path = dir.path().join("objects");
            std::fs::create_dir_all(objects_path.join("real")).unwrap();
            let objects = root(&dir).open_layout(RepoLayout::Objects).unwrap();
            let at = objects_path.join("a");
            let planted = at.clone();
            let _reset = set_hook(HookPoint::Walk, move |_| plant(&planted));
            let _record = record_syncs();
            let (err_path, got) = invalid(objects.ensure_dir(path, true));
            let case = format!("{path} {reason:?}");
            assert_eq!(err_path, "objects/a", "{case}");
            assert_eq!(got.to_string(), reason.to_string(), "{case}");
            assert!(take_synced().is_empty(), "{case}");
            assert!(!objects_path.join("nowhere").exists(), "{case}");
            assert!(!objects_path.join("real/b").exists(), "{case}");
        }
    }

    #[test]
    fn ensure_layout_makes_the_kind_and_its_children() {
        for mode in [None, Some(RepoMode::BareUserShared)] {
            let dir = TestDir::new("ensure-layout");
            let mut repo = root(&dir);
            if let Some(mode) = mode {
                repo = repo.with_repo_mode(mode);
            }
            let _reset = record_syncs();
            let refs = repo.ensure_layout(RepoLayout::Refs, true).unwrap();
            assert_eq!(refs.kind(), RepoLayout::Refs);
            assert_eq!(refs.err_path(""), "refs");
            let path = dir.path().join("refs");
            assert_eq!(identity(refs.as_fd()).unwrap(), id_of(&path));
            let (kind_mode, child_mode) = match mode {
                Some(_) => (0o2770, 0o2770),
                None => (
                    reference_mode(dir.path(), 0o775),
                    reference_mode(&path, 0o775),
                ),
            };
            assert_eq!(mode_of(&path), kind_mode, "{mode:?}");
            for child in ["heads", "remotes", "mirrors"] {
                assert_eq!(mode_of(&path.join(child)), child_mode, "{child} {mode:?}");
            }
            assert_eq!(take_synced(), [id_of(dir.path()), id_of(&path)]);

            // A missing child is made also when the kind exists.
            std::fs::remove_dir(path.join("mirrors")).unwrap();
            repo.ensure_layout(RepoLayout::Refs, true).unwrap();
            assert_eq!(mode_of(&path.join("mirrors")), child_mode);
            assert_eq!(take_synced(), [id_of(&path)]);

            repo.ensure_layout(RepoLayout::Refs, true).unwrap();
            assert!(take_synced().is_empty());

            // With no `fsync`, a new child syncs nothing.
            std::fs::remove_dir(path.join("heads")).unwrap();
            repo.ensure_layout(RepoLayout::Refs, false).unwrap();
            assert!(path.join("heads").is_dir());
            assert!(take_synced().is_empty());
        }
    }

    #[test]
    fn ensure_layout_refuses_a_child_that_is_a_symlink_or_a_file() {
        let dir = TestDir::new("ensure-layout-child");
        let refs = dir.path().join("refs");
        std::fs::create_dir_all(refs.join("real")).unwrap();
        symlink("real", refs.join("heads")).unwrap();
        let repo = root(&dir);
        let (path, reason) = invalid(repo.ensure_layout(RepoLayout::Refs, true));
        assert_eq!(path, "refs/heads");
        assert!(matches!(reason, Reason::Symlink), "{reason:?}");
        assert!(is_symlink(&refs.join("heads")));

        std::fs::remove_file(refs.join("heads")).unwrap();
        std::fs::write(refs.join("remotes"), b"x").unwrap();
        let (path, reason) = invalid(repo.ensure_layout(RepoLayout::Refs, true));
        assert_eq!(path, "refs/remotes");
        assert!(matches!(reason, Reason::NotDirectory), "{reason:?}");
        assert!(refs.join("remotes").is_file());
    }

    #[test]
    fn ensure_layout_removes_a_new_directory_when_its_fchmod_fails() {
        let dir = TestDir::new("layout-fchmod");
        let repo = root(&dir).with_repo_mode(RepoMode::BareUserShared);
        let _reset = set_faults(|f| f.fail_after_mkdir = Some((FaultStep::Fchmod, Errno::IO)));
        let _record = record_syncs();

        // The directory of the kind.
        let err = io_err(repo.ensure_layout(RepoLayout::Refs, true));
        assert_eq!(err.raw_os_error(), Some(Errno::IO.raw_os_error()));
        assert!(!dir.path().join("refs").exists());

        // An initial child.
        std::fs::create_dir(dir.path().join("refs")).unwrap();
        let err = io_err(repo.ensure_layout(RepoLayout::Refs, true));
        assert_eq!(err.raw_os_error(), Some(Errno::IO.raw_os_error()));
        assert_eq!(
            names_with(&dir.path().join("refs"), ""),
            Vec::<String>::new()
        );
        assert!(take_synced().is_empty());
    }

    #[test]
    fn sync_dir_syncs_the_directory_at_the_path() {
        let dir = TestDir::new("sync-dir");
        let ab = dir.path().join("objects/ab");
        std::fs::create_dir_all(&ab).unwrap();
        let repo = root(&dir);
        let objects = repo.open_layout(RepoLayout::Objects).unwrap();
        let _reset = record_syncs();
        objects.sync_dir("ab").unwrap();
        repo.sync_dir("objects/ab").unwrap();
        repo.sync_dir("objects").unwrap();
        assert_eq!(
            take_synced(),
            [id_of(&ab), id_of(&ab), id_of(&dir.path().join("objects"))]
        );
        match objects.sync_dir("cd") {
            Err(FsError::Absent { path }) => assert_eq!(path, "objects/cd"),
            other => panic!("{other:?}"),
        }
        assert!(take_synced().is_empty());
    }

    #[test]
    fn make_temp_dir_gives_a_staging_handle_with_a_unique_name() {
        for mode in [None, Some(RepoMode::BareUserShared)] {
            let dir = TestDir::new("temp-dir");
            let mut repo = root(&dir);
            if let Some(mode) = mode {
                repo = repo.with_repo_mode(mode);
            }
            let tmp = repo.tmp_dir(false).unwrap();
            let _reset = record_syncs();
            let (name, staging, ()) = tmp.make_temp_dir("staging-", |_| Some(())).unwrap();
            assert!(take_synced().is_empty());
            let suffix = name.strip_prefix("staging-").unwrap();
            assert_eq!(suffix.len(), SUFFIX_LEN, "{name}");
            assert!(
                suffix.bytes().all(|b| SUFFIX_ALPHABET.contains(&b)),
                "{name}"
            );
            assert_eq!(staging.kind(), RepoLayout::Staging);
            assert_eq!(staging.err_path(""), format!("tmp/{name}"));
            let tmp_path = dir.path().join("tmp");
            let path = tmp_path.join(&name);
            assert_eq!(identity(staging.as_fd()).unwrap(), id_of(&path));
            let expected = match mode {
                Some(_) => 0o2770,
                None => reference_mode(&tmp_path, 0o775),
            };
            assert_eq!(mode_of(&path), expected, "{mode:?}");
        }
    }

    #[test]
    fn make_temp_dir_removes_the_new_directory_when_a_later_step_fails() {
        let cases = [
            (None, FaultStep::Open),
            (Some(RepoMode::BareUserShared), FaultStep::Open),
            (Some(RepoMode::BareUserShared), FaultStep::Fchmod),
        ];
        for (mode, step) in cases {
            let dir = TestDir::new("temp-fault");
            let mut repo = root(&dir);
            if let Some(mode) = mode {
                repo = repo.with_repo_mode(mode);
            }
            let tmp = repo.tmp_dir(false).unwrap();
            let _reset = set_faults(|f| f.fail_after_mkdir = Some((step, Errno::IO)));
            let existed_at_drop = Rc::new(Cell::new(None));
            let tmp_path = dir.path().join("tmp");
            let result = tmp.make_temp_dir("pfx-", |name| {
                Some(Claim {
                    path: tmp_path.join(name),
                    existed_at_drop: Rc::clone(&existed_at_drop),
                })
            });
            let err = io_err(result);
            assert_eq!(
                err.raw_os_error(),
                Some(Errno::IO.raw_os_error()),
                "{step:?}"
            );
            assert_eq!(existed_at_drop.get(), Some(false), "{step:?}");
            assert!(names_with(&tmp_path, "pfx-").is_empty(), "{step:?}");
        }
    }

    #[test]
    fn make_temp_dir_gives_already_exists_after_128_names() {
        let dir = TestDir::new("temp-exhaust");
        let tmp = root(&dir).tmp_dir(false).unwrap();
        let _reset = set_faults(|f| f.force_eexist = true);
        let claims = Cell::new(0);
        let drops = Rc::new(Cell::new(None));
        let result = tmp.make_temp_dir("pfx-", |name| {
            claims.set(claims.get() + 1);
            Some(Claim {
                path: dir.path().join("tmp").join(name),
                existed_at_drop: Rc::clone(&drops),
            })
        });
        let err = io_err(result);
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            err.to_string(),
            "could not allocate a unique temp directory"
        );
        assert_eq!(claims.get(), TEMP_DIR_ATTEMPTS);
        assert_eq!(drops.get(), Some(false));
        assert!(names_with(&dir.path().join("tmp"), "pfx-").is_empty());
    }

    #[test]
    fn make_temp_dir_draws_a_new_name_when_the_claim_refuses() {
        let dir = TestDir::new("temp-claim");
        let tmp = root(&dir).tmp_dir(false).unwrap();
        let names = RefCell::new(Vec::new());
        let (name, _, guard) = tmp
            .make_temp_dir("pfx-", |name| {
                let mut names = names.borrow_mut();
                names.push(name.to_owned());
                (names.len() == 4).then_some(7u8)
            })
            .unwrap();
        let names = names.into_inner();
        assert_eq!(guard, 7);
        assert_eq!(names.len(), 4);
        assert_eq!(name, names[3]);
        let mut distinct = names.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(distinct.len(), 4, "{names:?}");
        assert_eq!(names_with(&dir.path().join("tmp"), "pfx-"), [name]);
    }

    /// Makes one entry of each type, and a name that is not UTF-8.
    fn make_entries(dir: &TestDir) -> Vec<(Vec<u8>, FileType)> {
        std::fs::write(dir.path().join("file"), b"x").unwrap();
        std::fs::create_dir(dir.path().join("dir")).unwrap();
        symlink("dir", dir.path().join("link")).unwrap();
        rustix::fs::mknodat(
            dir.fd(),
            "fifo",
            FileType::Fifo,
            Mode::from_raw_mode(0o644),
            0,
        )
        .unwrap();
        rustix::fs::mknodat(
            dir.fd(),
            "sock",
            FileType::Socket,
            Mode::from_raw_mode(0o644),
            0,
        )
        .unwrap();
        let raw = OsStr::from_bytes(b"\xff\xfe");
        std::fs::write(dir.path().join(raw), b"y").unwrap();
        let mut expected = vec![
            (b"file".to_vec(), FileType::RegularFile),
            (b"dir".to_vec(), FileType::Directory),
            (b"link".to_vec(), FileType::Symlink),
            (b"fifo".to_vec(), FileType::Fifo),
            (b"sock".to_vec(), FileType::Socket),
            (b"\xff\xfe".to_vec(), FileType::RegularFile),
        ];
        expected.sort_by(|a, b| a.0.cmp(&b.0));
        expected
    }

    fn sorted(entries: Vec<Entry>) -> Vec<(Vec<u8>, FileType)> {
        let mut entries: Vec<_> = entries.into_iter().map(|e| (e.name, e.file_type)).collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        entries
    }

    #[test]
    fn list_skips_dot_entries_keeps_raw_names_and_types_each_entry() {
        let dir = TestDir::new("list");
        let expected = make_entries(&dir);
        let repo = root(&dir);
        assert_eq!(sorted(repo.list().unwrap()), expected);
        assert_eq!(sorted(repo.list().unwrap()), expected);
        let clone = repo.clone();
        assert_eq!(sorted(clone.list().unwrap()), expected);
        assert_eq!(sorted(repo.list().unwrap()), expected);
        assert_eq!(sorted(list_fd(dir.fd()).unwrap()), expected);
        assert_eq!(sorted(list_fd(dir.fd()).unwrap()), expected);
    }

    #[test]
    fn list_reads_a_directory_larger_than_one_buffer() {
        let dir = TestDir::new("list-large");
        let mut expected = Vec::new();
        for n in 0..1000 {
            let name = format!("{n:04}-{}", "x".repeat(100));
            std::fs::write(dir.path().join(&name), b"").unwrap();
            expected.push((name.into_bytes(), FileType::RegularFile));
        }
        expected.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(sorted(root(&dir).list().unwrap()), expected);
    }

    #[test]
    fn list_types_unknown_entries_and_leaves_out_an_entry_gone_at_its_statx() {
        let dir = TestDir::new("list-unknown");
        let expected = make_entries(&dir);
        let gone = dir.path().join("gone");
        std::fs::write(&gone, b"x").unwrap();
        let _reset = set_faults(|f| f.unknown_type = true);
        // `getdents` reads each entry of the small directory with its first
        // call, so the entry is in the buffer when the hook removes it.
        let _hook = set_hook(HookPoint::Entry, move |_| {
            let _ = std::fs::remove_file(&gone);
        });
        assert_eq!(sorted(root(&dir).list().unwrap()), expected);
        std::fs::write(dir.path().join("gone"), b"x").unwrap();
        assert_eq!(sorted(list_fd(dir.fd()).unwrap()), expected);
    }

    #[test]
    fn list_of_a_directory_removed_after_its_open_is_empty() {
        let dir = TestDir::new("list-removed");
        let ab = dir.path().join("objects/ab");
        std::fs::create_dir_all(&ab).unwrap();
        let objects = root(&dir).open_layout(RepoLayout::Objects).unwrap();
        let handle = objects.open_dir("ab").unwrap();

        // `getdents` of a removed directory gives `ENOENT`.
        let removed = ab.clone();
        let _reset = set_hook(HookPoint::Getdents, move |_| {
            let _ = std::fs::remove_dir(&removed);
        });
        let mut buf: Box<[MaybeUninit<u8>]> = Box::new_uninit_slice(LIST_BUF_LEN);
        std::fs::remove_dir(&ab).unwrap();
        let mut raw = RawDir::new(handle.as_fd(), &mut buf);
        assert!(matches!(raw.next(), Some(Err(Errno::NOENT))));

        std::fs::create_dir(&ab).unwrap();
        let handle = objects.open_dir("ab").unwrap();
        assert!(handle.list().unwrap().is_empty());
        assert!(!ab.exists());
        std::fs::create_dir(&ab).unwrap();
        let fd = rustix::fs::open(&ab, DIR_OPEN, Mode::empty()).unwrap();
        assert!(list_fd(fd.as_fd()).unwrap().is_empty());
        assert!(!ab.exists());
    }

    #[test]
    fn for_each_entry_stops_when_the_visitor_breaks() {
        let dir = TestDir::new("visit-stop");
        for n in 0..5 {
            std::fs::write(dir.path().join(format!("f{n}")), b"").unwrap();
        }
        let repo = root(&dir);
        let mut seen = Vec::new();
        repo.for_each_entry(|name, file_type| {
            assert_eq!(file_type, FileType::RegularFile);
            seen.push(name.to_bytes().to_vec());
            if seen.len() == 2 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })
        .unwrap();
        assert_eq!(seen.len(), 2);

        let mut count = 0;
        for_each_entry_fd(dir.fd(), |_, _| {
            count += 1;
            ControlFlow::Break(())
        })
        .unwrap();
        assert_eq!(count, 1);

        let mut count = 0;
        repo.for_each_entry(|_, _| {
            count += 1;
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(count, 5);
    }

    #[test]
    fn entry_type_types_an_unknown_entry_with_statx() {
        let dir = TestDir::new("entry-type");
        make_entries(&dir);
        let cases = [
            (c"file", FileType::RegularFile),
            (c"dir", FileType::Directory),
            (c"link", FileType::Symlink),
            (c"fifo", FileType::Fifo),
            (c"sock", FileType::Socket),
        ];
        for (name, file_type) in cases {
            assert_eq!(
                entry_type(dir.fd(), name, FileType::Unknown).unwrap(),
                Some(file_type),
                "{name:?}"
            );
        }
        assert_eq!(
            entry_type(dir.fd(), c"gone", FileType::Unknown).unwrap(),
            None
        );
        // A known type costs no syscall, so a gone entry keeps it.
        assert_eq!(
            entry_type(dir.fd(), c"gone", FileType::RegularFile).unwrap(),
            Some(FileType::RegularFile)
        );
    }

    #[test]
    fn remove_tree_unlinks_symlinks_and_keeps_their_targets() {
        for unknown_type in [false, true] {
            let dir = TestDir::new("remove-tree");
            let victim = dir.path().join("victim");
            std::fs::create_dir_all(victim.join("a/b/c")).unwrap();
            std::fs::create_dir(victim.join("empty")).unwrap();
            std::fs::write(victim.join("a/b/file"), b"x").unwrap();
            std::fs::write(victim.join("a/b/c/file"), b"x").unwrap();
            std::fs::write(victim.join("a").join(OsStr::from_bytes(b"\xff")), b"x").unwrap();
            let outside = dir.path().join("outside");
            std::fs::create_dir(&outside).unwrap();
            std::fs::write(outside.join("kept"), b"x").unwrap();
            symlink(&outside, victim.join("link")).unwrap();
            symlink(&outside, victim.join("a/b/c/dlink")).unwrap();
            symlink(outside.join("kept"), victim.join("a/flink")).unwrap();
            // A directory with no search permission and no entries goes too.
            std::fs::create_dir(victim.join("a/closed")).unwrap();
            set_mode(&victim.join("a/closed"), 0o400);

            let _reset = set_faults(|f| f.unknown_type = unknown_type);
            let _record = record_syncs();
            let repo = root(&dir);
            assert!(repo.remove_tree(OsStr::new("victim"), true).unwrap());
            assert!(!victim.exists(), "{unknown_type}");
            assert!(outside.join("kept").is_file(), "{unknown_type}");
            assert_eq!(take_synced(), [id_of(dir.path())], "{unknown_type}");
        }
    }

    #[test]
    fn remove_tree_with_no_fsync_syncs_nothing() {
        let dir = TestDir::new("remove-no-sync");
        std::fs::create_dir_all(dir.path().join("victim/a")).unwrap();
        let _record = record_syncs();
        assert!(root(&dir).remove_tree(OsStr::new("victim"), false).unwrap());
        assert!(!dir.path().join("victim").exists());
        assert!(take_synced().is_empty());
    }

    #[test]
    fn remove_tree_of_an_absent_name_gives_false() {
        let dir = TestDir::new("remove-absent");
        let _record = record_syncs();
        assert!(!root(&dir).remove_tree(OsStr::new("gone"), true).unwrap());
        assert!(take_synced().is_empty());
    }

    #[test]
    fn remove_tree_refuses_a_file_a_symlink_and_a_bad_name() {
        let dir = TestDir::new("remove-refuse");
        std::fs::create_dir(dir.path().join("objects")).unwrap();
        std::fs::write(dir.path().join("objects/file"), b"x").unwrap();
        std::fs::create_dir(dir.path().join("objects/target")).unwrap();
        symlink("target", dir.path().join("objects/link")).unwrap();
        let objects = root(&dir).open_layout(RepoLayout::Objects).unwrap();
        let _record = record_syncs();

        let (path, reason) = invalid(objects.remove_tree(OsStr::new("file"), true));
        assert_eq!(path, "objects/file");
        assert!(matches!(reason, Reason::NotDirectory), "{reason:?}");
        let (path, reason) = invalid(objects.remove_tree(OsStr::new("link"), true));
        assert_eq!(path, "objects/link");
        assert!(matches!(reason, Reason::Symlink), "{reason:?}");
        for name in ["", ".", "..", "target/x", "/target"] {
            let (_, reason) = invalid(objects.remove_tree(OsStr::new(name), true));
            assert!(matches!(reason, Reason::Escape), "{name}: {reason:?}");
        }
        assert!(take_synced().is_empty());
        assert!(dir.path().join("objects/file").is_file());
        assert!(is_symlink(&dir.path().join("objects/link")));
        assert!(dir.path().join("objects/target").is_dir());
    }

    #[test]
    fn remove_tree_stops_when_a_directory_moves() {
        let dir = TestDir::new("remove-moved");
        let victim = dir.path().join("victim");
        std::fs::create_dir_all(victim.join("a/b")).unwrap();
        std::fs::write(victim.join("a/b/file"), b"x").unwrap();
        let elsewhere = dir.path().join("elsewhere");
        let (from, to) = (victim.join("a"), elsewhere.clone());
        let _reset = set_hook(HookPoint::Descend, move |name| {
            if name == b"a" {
                std::fs::rename(&from, &to).unwrap();
                std::fs::write(to.join("planted"), b"p").unwrap();
            }
        });
        let _record = record_syncs();

        let err = io_err(root(&dir).remove_tree(OsStr::new("victim"), true));
        assert_eq!(err.to_string(), "a directory moved during the removal");
        assert!(take_synced().is_empty());
        assert!(victim.is_dir());
        assert!(elsewhere.is_dir());
        assert_eq!(std::fs::read(elsewhere.join("planted")).unwrap(), b"p");
    }

    #[test]
    fn open_root_follows_a_symlink_and_maps_its_errors() {
        let dir = TestDir::new("open-root");
        std::fs::create_dir(dir.path().join("repo")).unwrap();
        symlink("repo", dir.path().join("link")).unwrap();
        std::fs::write(dir.path().join("file"), b"x").unwrap();

        let repo = RepoDir::open_root(dir.fd(), Path::new("link")).unwrap();
        assert_eq!(repo.kind(), RepoLayout::Root);
        assert_eq!(repo.repo_mode(), None);
        assert_eq!(
            identity(repo.as_fd()).unwrap(),
            id_of(&dir.path().join("repo"))
        );
        let repo = RepoDir::open_root(dir.fd(), &dir.path().join("repo")).unwrap();
        assert_eq!(
            identity(repo.as_fd()).unwrap(),
            id_of(&dir.path().join("repo"))
        );

        match RepoDir::open_root(dir.fd(), Path::new("missing/repo")) {
            Err(FsError::Absent { path }) => assert_eq!(path, "missing/repo"),
            other => panic!("{other:?}"),
        }
        let (path, reason) = invalid(RepoDir::open_root(dir.fd(), Path::new("file")));
        assert_eq!(path, "file");
        assert!(matches!(reason, Reason::NotDirectory), "{reason:?}");
    }

    #[test]
    fn create_root_makes_the_root_with_its_mode() {
        let dir = TestDir::new("create-root");
        let repo = RepoDir::create_root(dir.fd(), Path::new("plain"), RepoMode::BareUser).unwrap();
        assert_eq!(repo.kind(), RepoLayout::Root);
        assert_eq!(repo.repo_mode(), Some(RepoMode::BareUser));
        assert_eq!(
            mode_of(&dir.path().join("plain")),
            reference_mode(dir.path(), 0o775)
        );

        let repo =
            RepoDir::create_root(dir.fd(), Path::new("shared"), RepoMode::BareUserShared).unwrap();
        assert_eq!(repo.repo_mode(), Some(RepoMode::BareUserShared));
        assert_eq!(mode_of(&dir.path().join("shared")), 0o2770);

        // An existing root keeps its mode.
        std::fs::create_dir(dir.path().join("old")).unwrap();
        set_mode(&dir.path().join("old"), 0o700);
        let repo =
            RepoDir::create_root(dir.fd(), Path::new("old"), RepoMode::BareUserShared).unwrap();
        assert_eq!(
            identity(repo.as_fd()).unwrap(),
            id_of(&dir.path().join("old"))
        );
        assert_eq!(mode_of(&dir.path().join("old")), 0o700);

        match RepoDir::create_root(dir.fd(), Path::new("missing/repo"), RepoMode::Archive) {
            Err(FsError::Absent { path }) => assert_eq!(path, "missing/repo"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn create_root_removes_the_new_root_when_its_fchmod_fails() {
        let dir = TestDir::new("create-root-fchmod");
        let _reset = set_faults(|f| f.fail_after_mkdir = Some((FaultStep::Fchmod, Errno::IO)));
        let err = io_err(RepoDir::create_root(
            dir.fd(),
            Path::new("shared"),
            RepoMode::BareUserShared,
        ));
        assert_eq!(err.raw_os_error(), Some(Errno::IO.raw_os_error()));
        assert!(!dir.path().join("shared").exists());
    }

    #[test]
    fn a_nested_handle_keeps_its_kind_and_gives_the_full_path_in_an_error() {
        let dir = TestDir::new("nested");
        std::fs::create_dir_all(dir.path().join("objects/ab")).unwrap();
        let repo = root(&dir);
        assert_eq!(repo.err_path(""), ".");
        let objects = repo.open_layout(RepoLayout::Objects).unwrap();
        assert_eq!(objects.err_path(""), "objects");
        let ab = objects.open_dir("ab").unwrap();
        assert_eq!(ab.kind(), RepoLayout::Objects);
        assert_eq!(ab.err_path(""), "objects/ab");
        match ab.open_dir("cd") {
            Err(FsError::Absent { path }) => assert_eq!(path, "objects/ab/cd"),
            other => panic!("{other:?}"),
        }
        let _record = record_syncs();
        let ef = ab.ensure_dir("cd/ef", true).unwrap();
        assert_eq!(ef.kind(), RepoLayout::Objects);
        assert_eq!(ef.err_path(""), "objects/ab/cd/ef");
        assert_eq!(ef.err_path("gh"), "objects/ab/cd/ef/gh");
        assert_eq!(
            take_synced(),
            [
                id_of(&dir.path().join("objects/ab")),
                id_of(&dir.path().join("objects/ab/cd"))
            ]
        );
        assert_eq!(
            identity(ef.as_fd()).unwrap(),
            id_of(&dir.path().join("objects/ab/cd/ef"))
        );
    }

    #[test]
    fn a_nested_handle_keeps_a_long_path() {
        let dir = TestDir::new("nested-long");
        let names = ["a".repeat(250), "b".repeat(250), "c".repeat(250)];
        let mut path = dir.path().join("objects");
        for name in &names {
            path.push(name);
        }
        std::fs::create_dir_all(&path).unwrap();
        let objects = root(&dir).open_layout(RepoLayout::Objects).unwrap();
        let a = objects.open_dir(&names[0]).unwrap();
        let ab = a.open_dir(&names[1]).unwrap();
        let abc = ab.open_dir(&names[2]).unwrap();
        assert_eq!(
            ab.err_path(""),
            format!("objects/{}/{}", names[0], names[1])
        );
        assert_eq!(
            abc.err_path("d"),
            format!("objects/{}/{}/{}/d", names[0], names[1], names[2])
        );
        assert_eq!(identity(abc.as_fd()).unwrap(), id_of(&path));
        assert_eq!(&*join_arc("x", "y"), "x/y");
    }

    #[test]
    fn syncfs_syncs_the_file_system_of_a_handle() {
        let dir = TestDir::new("syncfs");
        root(&dir).syncfs().unwrap();
    }

    #[test]
    fn tmp_dir_makes_tmp_once_for_each_context() {
        let dir = TestDir::new("tmp-once");
        std::fs::create_dir(dir.path().join("objects")).unwrap();
        let repo = root(&dir);
        let _record = record_syncs();
        let tmp = repo.tmp_dir(true).unwrap();
        assert_eq!(tmp.kind(), RepoLayout::Tmp);
        assert_eq!(tmp.err_path(""), "tmp");
        assert!(dir.path().join("tmp/cache").is_dir());
        assert_eq!(
            take_synced(),
            [id_of(dir.path()), id_of(&dir.path().join("tmp"))]
        );

        let again = repo.tmp_dir(true).unwrap();
        assert!(Arc::ptr_eq(&tmp.fd, &again.fd));
        let objects = repo.open_layout(RepoLayout::Objects).unwrap();
        let from_objects = objects.tmp_dir(true).unwrap();
        assert!(Arc::ptr_eq(&tmp.fd, &from_objects.fd));
        assert!(take_synced().is_empty());
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "open_dir needs a handle other than the root")]
    fn open_dir_on_the_root_fails_a_debug_assertion() {
        let dir = TestDir::new("misuse-open-dir");
        std::fs::create_dir(dir.path().join("objects")).unwrap();
        let _ = root(&dir).open_dir("objects");
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "a layout kind opens on the root handle and has a fixed path")]
    fn open_layout_of_staging_fails_a_debug_assertion() {
        let dir = TestDir::new("misuse-layout");
        let _ = root(&dir).open_layout(RepoLayout::Staging);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "ensure_dir needs a kind with a mode below it")]
    fn ensure_dir_on_a_kind_with_no_mode_below_fails_a_debug_assertion() {
        let dir = TestDir::new("misuse-ensure");
        std::fs::create_dir(dir.path().join("state")).unwrap();
        let state = root(&dir).open_layout(RepoLayout::State).unwrap();
        let _ = state.ensure_dir("x", false);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "make_temp_dir needs the tmp/ handle")]
    fn make_temp_dir_on_another_handle_fails_a_debug_assertion() {
        let dir = TestDir::new("misuse-temp");
        let _ = root(&dir).make_temp_dir("pfx-", |_| Some(()));
    }
}
