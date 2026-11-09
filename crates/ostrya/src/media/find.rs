//! The media finder: the search for the one media repository on the mounted
//! volumes.

use std::ffi::OsStr;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ostrya_core::Value;
use rustix::fs::{AtFlags, Dir, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;

use super::MediaSkip;
use super::mountinfo::{self, Mount};
use crate::error::Result;
use crate::repo::Repo;
use crate::summary::{
    COLLECTION_ID_KEY, SUMMARY_FILE, Summary, collection_map_has_ref, parse_ref_list,
    read_root_file_with,
};

/// The directory of the repository entries of the tool on a volume.
const REPOS_D: &str = ".ostree/repos.d";

/// The paths that the finder probes on a volume after the entries of
/// [`REPOS_D`], in order.
const CANDIDATES: [&str; 3] = [".ostree/repo", "ostree/repo", "var/lib/flatpak/repo"];

/// The pseudo file systems, which hold no media.
const PSEUDO_TYPES: [&str; 18] = [
    "proc",
    "sysfs",
    "devtmpfs",
    "devpts",
    "cgroup",
    "cgroup2",
    "securityfs",
    "debugfs",
    "tracefs",
    "bpf",
    "pstore",
    "mqueue",
    "hugetlbfs",
    "configfs",
    "fusectl",
    "autofs",
    "binfmt_misc",
    "efivarfs",
];

/// The network file systems. The finder does not probe them, so that a dead
/// server cannot stop the scan.
const NETWORK_TYPES: [&str; 16] = [
    "nfs",
    "nfs4",
    "cifs",
    "smb3",
    "smbfs",
    "ceph",
    "9p",
    "virtiofs",
    "davfs",
    "afs",
    "glusterfs",
    "fuse.glusterfs",
    "fuse.sshfs",
    "fuse.rclone",
    "fuse.s3fs",
    "fuse.gvfsd-fuse",
];

/// The device and the inode of a directory.
type Identity = (u64, u64);

/// The media repository that the finder found.
pub(super) struct FoundMedia {
    /// The path of the repository: the mount point or the directory of the
    /// scan, joined with the probed path.
    pub(super) path: PathBuf,
    /// The repository, opened in the strict open mode.
    pub(super) repo: Repo,
    /// The bytes of the summary that the finder read.
    pub(super) summary: Vec<u8>,
}

/// The result of a scan.
pub(super) enum MediaChoice {
    /// No media repository. The list holds each candidate that exists and
    /// that the finder skipped, with the reason, in probe order.
    None(Vec<(PathBuf, MediaSkip)>),
    /// One media repository.
    One(FoundMedia),
    /// More than one media repository: the path of each, in the order of
    /// the mount table.
    Many(Vec<PathBuf>),
}

/// Scans the mounts of the mount table `table` for media, as the client
/// repository `client` reads them.
///
/// For each mount point, the call takes the last line of the table alone
/// (see [`mountinfo::parse`]). It skips the root mount, the pseudo file
/// systems, and the network file systems before a system call on their
/// path. It also skips a mount whose directory it cannot open. On each other
/// mount, it takes the first candidate whose summary lists a collection ref
/// (see `probe`). Candidates with the same device and inode are one media
/// repository, at the path of the first one in table order.
///
/// # Errors
///
/// - [`Error::Io`](crate::Error::Io) if the call cannot read the device
///   and the inode of the client repository.
pub(super) async fn find_media(client: &Repo, table: Vec<u8>) -> Result<MediaChoice> {
    let mut scan = Scan::new(client).await?;
    let points = ostrya_rt::unblock(move || probe_points(&table)).await;
    for point in points {
        // A mount whose directory the scan cannot open holds no media.
        let _ = scan.probe(&point).await;
    }
    Ok(scan.choice())
}

/// Scans the directory `dir` alone for media, as the client repository
/// `client` reads them. The call reads no mount table, and `dir` need not
/// be a mount point. The file system of each candidate must be the file
/// system of `dir`.
///
/// # Errors
///
/// - [`Error::Io`](crate::Error::Io) if the call cannot open `dir`, or
///   cannot read the device and the inode of the client repository.
pub(super) async fn find_media_in(client: &Repo, dir: &Path) -> Result<MediaChoice> {
    let mut scan = Scan::new(client).await?;
    scan.probe(dir).await?;
    Ok(scan.choice())
}

/// Returns the mount points of the mount table `table` that the finder
/// probes, in table order. The call tests the file system type of a mount
/// before it decodes the mount point.
fn probe_points(table: &[u8]) -> Vec<PathBuf> {
    mountinfo::parse(table)
        .iter()
        .filter(|mount| !is_excluded(mount))
        .map(Mount::point)
        .collect()
}

/// Returns `true` if the finder does not probe the mount `mount`: a pseudo
/// file system, a network file system, or the root mount.
fn is_excluded(mount: &Mount<'_>) -> bool {
    PSEUDO_TYPES
        .iter()
        .chain(&NETWORK_TYPES)
        .any(|ty| ty.as_bytes() == mount.fs_type)
        || mount.escaped_point == b"/"
}

/// The state of a scan.
struct Scan {
    /// The client repository.
    client: Identity,
    /// Each candidate that exists and that the scan skipped, with the reason.
    skipped: Vec<(PathBuf, MediaSkip)>,
    /// The device, the inode, and the path of each media repository, in the
    /// order of the mounts.
    found: Vec<(Identity, PathBuf)>,
    /// The repository and the summary of the media repository, while the
    /// scan has found one media repository alone.
    first: Option<(Repo, Vec<u8>)>,
}

/// A directory that the scan probes.
struct MountDir {
    /// The directory, open with `O_PATH`.
    fd: OwnedFd,
    /// The device of the directory.
    dev: u64,
    /// The names of the entries of `.ostree/repos.d`, in byte order, or the
    /// reason why the scan skips that directory.
    repos_d: std::result::Result<Vec<Vec<u8>>, MediaSkip>,
}

/// The result of the probe of one candidate.
enum Probe {
    /// The candidate does not exist.
    Missing,
    /// The candidate exists, and the finder skipped it.
    Skipped(MediaSkip),
    /// The candidate is a media repository that the scan found before.
    Found,
    /// The candidate is a media repository.
    Media(Identity, Repo, Vec<u8>),
}

impl Scan {
    /// Starts a scan for the client repository `client`.
    async fn new(client: &Repo) -> Result<Scan> {
        let repo = client.clone();
        let client = ostrya_rt::unblock(move || identity(repo.repo_fd())).await?;
        Ok(Scan {
            client,
            skipped: Vec::new(),
            found: Vec::new(),
            first: None,
        })
    }

    /// Probes the directory `dir`, and records its media repository.
    ///
    /// The probe order is each entry of `.ostree/repos.d/` in byte order of
    /// the names, then `.ostree/repo`, `ostree/repo`, and
    /// `var/lib/flatpak/repo`. The media repository of `dir` is the first
    /// candidate whose summary lists a collection ref, and the probe stops
    /// there. The probe also stops at a candidate with the device and the
    /// inode of an earlier media repository, and does not record it again.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`](crate::Error::Io) if the call cannot open `dir` or
    ///   read its device.
    async fn probe(&mut self, dir: &Path) -> Result<()> {
        let path = dir.to_owned();
        let mount = ostrya_rt::unblock(move || open_mount(&path)).await?;
        let names = mount.repos_d.unwrap_or_else(|skip| {
            self.skipped.push((dir.join(REPOS_D), skip));
            Vec::new()
        });
        let fd = Arc::new(mount.fd);
        let candidates = names
            .iter()
            .map(|name| Path::new(REPOS_D).join(OsStr::from_bytes(name)))
            .chain(CANDIDATES.iter().map(PathBuf::from));
        for relative in candidates {
            let path = dir.join(&relative);
            let fd = Arc::clone(&fd);
            let dev = mount.dev;
            let client = self.client;
            let found: Vec<Identity> = self.found.iter().map(|(id, _)| *id).collect();
            let repo_path = path.clone();
            let probe = ostrya_rt::unblock(move || {
                probe_candidate(fd.as_fd(), dev, &relative, client, &found, repo_path)
                    .unwrap_or_else(Probe::Skipped)
            })
            .await;
            match probe {
                Probe::Missing => {}
                Probe::Skipped(skip) => self.skipped.push((path, skip)),
                Probe::Found => return Ok(()),
                Probe::Media(id, repo, summary) => {
                    self.first = self.found.is_empty().then_some((repo, summary));
                    self.found.push((id, path));
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// Applies the one-media rule to the result of the scan.
    fn choice(self) -> MediaChoice {
        let mut paths: Vec<PathBuf> = self.found.into_iter().map(|(_, path)| path).collect();
        match (self.first, paths.len()) {
            (_, 0) => MediaChoice::None(self.skipped),
            (Some((repo, summary)), 1) => MediaChoice::One(FoundMedia {
                path: paths.remove(0),
                repo,
                summary,
            }),
            _ => MediaChoice::Many(paths),
        }
    }
}

/// Opens the directory `path` with `O_PATH`, and reads its device and the
/// names of the entries of its `.ostree/repos.d`. Blocks the calling thread.
fn open_mount(path: &Path) -> Result<MountDir> {
    let fd = rustix::fs::open(
        path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let dev = identity(fd.as_fd())?.0;
    let repos_d = repos_d_names(fd.as_fd());
    Ok(MountDir { fd, dev, repos_d })
}

/// Returns the names of the entries of `.ostree/repos.d` under the
/// directory `dir`, in byte order, or no name if the directory does not
/// exist. Blocks the calling thread.
fn repos_d_names(dir: BorrowedFd<'_>) -> std::result::Result<Vec<Vec<u8>>, MediaSkip> {
    let Some(fd) = open_in_mount(dir, Path::new(REPOS_D))? else {
        return Ok(Vec::new());
    };
    let unreadable = |e: Errno| MediaSkip::Unreadable(e.into());
    let mut names = Vec::new();
    for entry in Dir::new(fd).map_err(unreadable)? {
        let name = entry.map_err(unreadable)?.file_name().to_bytes().to_vec();
        if name != b"." && name != b".." {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// Probes the candidate `relative` under the directory `dir` on the device
/// `dev`, for the client repository `client` and the media repositories
/// `found` of the scan. The repository of a media candidate stores `path`.
/// Blocks the calling thread.
///
/// The call reads the summary before it opens the repository, so it reads
/// the `config` of a media candidate alone.
fn probe_candidate(
    dir: BorrowedFd<'_>,
    dev: u64,
    relative: &Path,
    client: Identity,
    found: &[Identity],
    path: PathBuf,
) -> std::result::Result<Probe, MediaSkip> {
    let Some(candidate) = open_in_mount(dir, relative)? else {
        return Ok(Probe::Missing);
    };
    let id = identity(candidate.as_fd()).map_err(|e| MediaSkip::Unreadable(e.into()))?;
    if id.0 != dev {
        return Err(MediaSkip::OtherFileSystem);
    }
    if id == client {
        return Err(MediaSkip::Client);
    }
    if found.contains(&id) {
        return Ok(Probe::Found);
    }
    let summary = read_root_file_with(candidate.as_fd(), SUMMARY_FILE, true)
        .map_err(MediaSkip::Unreadable)?
        .ok_or(MediaSkip::NoCollectionRef)?;
    if !lists_collection_ref(&summary).map_err(MediaSkip::Unreadable)? {
        return Err(MediaSkip::NoCollectionRef);
    }
    let repo = Repo::open_strict_blocking(candidate, path).map_err(MediaSkip::Unreadable)?;
    Ok(Probe::Media(id, repo, summary))
}

/// Opens the directory `relative` under the directory `dir`, or returns
/// `None` if it does not exist. Blocks the calling thread.
///
/// The open is an `openat2` with `RESOLVE_NO_XDEV`. It follows a symlink,
/// and the resolution of the path crosses no mount point. A path whose
/// resolution crosses a mount point is on another file system. A path with
/// a component before the last one that is not a directory does not exist.
fn open_in_mount(
    dir: BorrowedFd<'_>,
    relative: &Path,
) -> std::result::Result<Option<OwnedFd>, MediaSkip> {
    match rustix::fs::openat2(
        dir,
        relative,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_XDEV,
    ) {
        Ok(fd) => Ok(Some(fd)),
        Err(Errno::NOENT) => Ok(None),
        Err(Errno::NOTDIR) if rustix::fs::statat(dir, relative, AtFlags::empty()).is_err() => {
            Ok(None)
        }
        Err(Errno::XDEV) => Err(MediaSkip::OtherFileSystem),
        Err(e) => Err(MediaSkip::Unreadable(e.into())),
    }
}

/// Returns the device and the inode of the open file `fd`.
pub(super) fn identity(fd: impl AsFd) -> std::result::Result<Identity, Errno> {
    let stat = rustix::fs::fstat(fd)?;
    Ok((stat.st_dev, stat.st_ino))
}

/// Returns `true` if the summary `bytes` lists a collection ref: a ref in
/// the collection map, or a ref in field 0 when the summary states a
/// collection id. The call parses the global metadata dict, and parses the
/// refs of field 0 only when the summary states a collection id.
fn lists_collection_ref(bytes: &[u8]) -> Result<bool> {
    let metadata = Summary::parse_metadata(bytes)?;
    if collection_map_has_ref(&metadata)? {
        return Ok(true);
    }
    let own = metadata
        .dict_get(COLLECTION_ID_KEY)
        .and_then(Value::as_variant)
        .and_then(|(_, value)| value.as_str())
        .is_some();
    Ok(own && !parse_ref_list(bytes)?.is_empty())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};

    use ostrya_core::{Type, to_bytes};

    use super::*;
    use crate::{CreateOptions, Error, RepoMode};

    /// The collection of the test media.
    const ID: &str = "org.example.Os";
    /// The variable that names the scratch directory of the child of
    /// [`the_finder_finds_media_on_a_tmpfs_in_a_user_namespace`].
    const NAMESPACE_CHILD: &str = "OSTRYA_MEDIA_FIND_CHILD";

    /// A scratch directory that the value removes when it drops.
    struct Scratch {
        root: PathBuf,
    }

    impl Scratch {
        fn new(dir: &Path) -> Scratch {
            let root = dir.join(format!(
                "ostrya-media-find-{}-{}",
                std::process::id(),
                crate::write::unique()
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            Scratch { root }
        }

        /// Creates the empty directory `name` in the scratch directory, and
        /// returns its path.
        fn dir(&self, name: &str) -> PathBuf {
            let path = self.root.join(name);
            std::fs::create_dir_all(&path).unwrap();
            path
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// Returns the bytes of a summary with the refs `refs` in field 0, the
    /// collection id `own`, and the refs of each collection of `map`.
    fn summary(own: Option<&str>, refs: &[&str], map: &[(&str, &[&str])]) -> Vec<u8> {
        let entries = |names: &[&str]| {
            let entry = |name: &&str| {
                Value::Tuple(vec![
                    Value::Str((*name).to_owned()),
                    Value::Tuple(vec![
                        Value::U64(0),
                        Value::Bytes(vec![1; 32]),
                        Value::Array(Vec::new()),
                    ]),
                ])
            };
            Value::Array(names.iter().map(entry).collect())
        };
        let item = |key: &str, ty: &str, value: Value| {
            Value::Tuple(vec![
                Value::Str(key.to_owned()),
                Value::Variant(Box::new((Type::parse(ty).unwrap(), value))),
            ])
        };
        let mut metadata = Vec::new();
        if let Some(id) = own {
            metadata.push(item(COLLECTION_ID_KEY, "s", Value::Str(id.to_owned())));
        }
        if !map.is_empty() {
            let map = map
                .iter()
                .map(|(id, names)| Value::Tuple(vec![Value::Str((*id).to_owned()), entries(names)]))
                .collect();
            metadata.push(item(
                "ostree.summary.collection-map",
                "a{sa(s(taya{sv}))}",
                Value::Array(map),
            ));
        }
        let value = Value::Tuple(vec![entries(refs), Value::Array(metadata)]);
        to_bytes(&Type::parse("(a(s(taya{sv}))a{sv})").unwrap(), &value).unwrap()
    }

    /// The summary of media that hold the ref `os/stable` of [`ID`] in the
    /// collection map.
    fn media_summary() -> Vec<u8> {
        summary(None, &[], &[(ID, &["os/stable"])])
    }

    /// Creates an archive repository at `path`, and its parents, with the
    /// summary `summary`.
    async fn repo_at(path: &Path, summary: Option<&[u8]>) -> Repo {
        std::fs::create_dir_all(path).unwrap();
        let repo = Repo::create(path, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        if let Some(bytes) = summary {
            std::fs::write(path.join("summary"), bytes).unwrap();
        }
        repo
    }

    /// Returns a mount table with a mount of each `(point, type)`.
    fn table(mounts: &[(&Path, &str)]) -> Vec<u8> {
        let mut out = String::new();
        for (i, (point, ty)) in mounts.iter().enumerate() {
            out.push_str(&format!(
                "{} 1 0:{i} / {} rw,relatime shared:{i} - {ty} src rw\n",
                i + 100,
                point.display()
            ));
        }
        out.into_bytes()
    }

    /// Returns the media of `choice`, or panics.
    fn one(choice: MediaChoice) -> FoundMedia {
        match choice {
            MediaChoice::One(found) => found,
            MediaChoice::None(skipped) => panic!("no media: {skipped:?}"),
            MediaChoice::Many(paths) => panic!("more than one media: {paths:?}"),
        }
    }

    /// Returns the skipped candidates of `choice` with their reasons as
    /// text, or panics.
    fn skipped(choice: MediaChoice) -> Vec<(PathBuf, String)> {
        match choice {
            MediaChoice::None(skipped) => skipped
                .into_iter()
                .map(|(path, skip)| {
                    let reason = match skip {
                        MediaSkip::Unreadable(Error::Io(_)) => "unreadable".to_owned(),
                        other => format!("{other:?}"),
                    };
                    (path, reason)
                })
                .collect(),
            MediaChoice::One(found) => panic!("media at {}", found.path.display()),
            MediaChoice::Many(paths) => panic!("more than one media: {paths:?}"),
        }
    }

    /// A candidate repository on `/dev/shm`, on another file system than
    /// the scratch directory, or `None` with a printed reason.
    fn other_file_system(scratch: &Scratch) -> Option<Scratch> {
        let shm = Path::new("/dev/shm");
        let dev =
            |path: &Path| std::fs::metadata(path).map(|m| std::os::unix::fs::MetadataExt::dev(&m));
        match (dev(shm), dev(&scratch.root)) {
            (Ok(a), Ok(b)) if a != b => Some(Scratch::new(shm)),
            _ => {
                eprintln!(
                    "skipping the other file system: /dev/shm is missing or on the scratch file system"
                );
                None
            }
        }
    }

    /// A mount with no candidate holds no media. A mount with media gives
    /// one media, and two mounts with media give the path of each in table
    /// order. A mount directory that the client can search and cannot list
    /// is probed.
    #[test]
    fn the_finder_takes_one_media_and_reports_two() {
        ostrya_rt::block_on(async {
            let scratch = Scratch::new(&std::env::temp_dir());
            let client = repo_at(&scratch.root.join("client"), None).await;
            let empty = scratch.dir("empty");
            let a = scratch.dir("a");
            let b = scratch.dir("b");
            repo_at(&a.join(".ostree/repo"), Some(&media_summary())).await;
            repo_at(&b.join("ostree/repo"), Some(&media_summary())).await;

            let choice = find_media(&client, table(&[(&empty, "ext4")])).await;
            assert!(skipped(choice.unwrap()).is_empty());
            std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o311)).unwrap();
            let choice = find_media(&client, table(&[(&empty, "ext4"), (&a, "vfat")])).await;
            let _ = std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o755));
            let found = one(choice.unwrap());
            assert_eq!(found.path, a.join(".ostree/repo"));
            assert_eq!(found.summary, media_summary());
            assert!(found.repo.is_strict());
            assert_eq!(found.repo.path(), a.join(".ostree/repo"));
            let choice = find_media(&client, table(&[(&b, "exfat"), (&a, "vfat")])).await;
            let MediaChoice::Many(paths) = choice.unwrap() else {
                panic!("two mounts give two media");
            };
            assert_eq!(paths, [b.join("ostree/repo"), a.join(".ostree/repo")]);
        });
    }

    /// The entries of `.ostree/repos.d` come first, in name order, whatever
    /// the order of their creation. A candidate whose summary lists no
    /// collection ref, or that has no summary, is skipped, and the next
    /// candidate is the media. A summary with its own collection id lists
    /// the refs of that id in field 0. A later candidate of the mount is not
    /// used.
    #[test]
    fn the_first_candidate_with_a_collection_ref_is_the_media() {
        ostrya_rt::block_on(async {
            let scratch = Scratch::new(&std::env::temp_dir());
            let client = repo_at(&scratch.root.join("client"), None).await;
            let mount = scratch.dir("mount");
            let repos_d = mount.join(".ostree/repos.d");
            let local = summary(None, &["os/stable"], &[]);
            let own = summary(Some(ID), &["os/stable"], &[]);
            repo_at(&repos_d.join("b"), Some(&own)).await;
            repo_at(&repos_d.join("a"), Some(&media_summary())).await;
            repo_at(&repos_d.join("d"), None).await;
            repo_at(&repos_d.join("c"), Some(&local)).await;
            repo_at(&mount.join(".ostree/repo"), Some(&media_summary())).await;

            let choice = find_media(&client, table(&[(&mount, "ext4")])).await;
            assert_eq!(one(choice.unwrap()).path, repos_d.join("a"));

            std::fs::remove_dir_all(repos_d.join("a")).unwrap();
            let choice = find_media(&client, table(&[(&mount, "ext4")])).await;
            assert_eq!(one(choice.unwrap()).path, repos_d.join("b"));

            std::fs::remove_dir_all(repos_d.join("b")).unwrap();
            std::fs::remove_dir_all(mount.join(".ostree/repo")).unwrap();
            let choice = find_media(&client, table(&[(&mount, "ext4")])).await;
            assert_eq!(
                skipped(choice.unwrap()),
                [
                    (repos_d.join("c"), "NoCollectionRef".to_owned()),
                    (repos_d.join("d"), "NoCollectionRef".to_owned()),
                ]
            );
        });
    }

    /// The finder skips the client repository, a candidate it cannot read,
    /// and a candidate on another file system than the mount. A directory
    /// given in place of the mount table gets the same checks.
    #[test]
    fn the_finder_skips_the_client_and_candidates_it_cannot_take() {
        ostrya_rt::block_on(async {
            let scratch = Scratch::new(&std::env::temp_dir());
            let mount = scratch.dir("mount");
            let client = repo_at(&mount.join(".ostree/repo"), Some(&media_summary())).await;
            let mut expected = vec![(mount.join(".ostree/repo"), "Client".to_owned())];
            let unreadable = scratch.dir("mount/ostree/repo");
            std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
            if rustix::process::geteuid().is_root() {
                eprintln!("skipping the unreadable candidate: root reads each directory");
                std::fs::remove_dir(&unreadable).unwrap();
            } else {
                expected.push((unreadable.clone(), "unreadable".to_owned()));
            }
            let other = other_file_system(&scratch);
            if let Some(other) = &other {
                repo_at(&other.root.join("repo"), Some(&media_summary())).await;
                std::fs::create_dir_all(mount.join("var/lib/flatpak")).unwrap();
                std::os::unix::fs::symlink(
                    other.root.join("repo"),
                    mount.join("var/lib/flatpak/repo"),
                )
                .unwrap();
                expected.push((
                    mount.join("var/lib/flatpak/repo"),
                    "OtherFileSystem".to_owned(),
                ));
            }

            let found = skipped(
                find_media(&client, table(&[(&mount, "ext4")]))
                    .await
                    .unwrap(),
            );
            let given = skipped(find_media_in(&client, &mount).await.unwrap());
            let _ = std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o755));
            assert_eq!(found, expected);
            assert_eq!(given, expected);
            assert!(matches!(
                find_media_in(&client, &scratch.root.join("absent")).await,
                Err(Error::Io(_))
            ));
        });
    }

    /// A candidate under a component that is not a directory does not
    /// exist. A candidate that is not a directory is unreadable.
    #[test]
    fn a_path_through_a_file_is_no_candidate() {
        ostrya_rt::block_on(async {
            let scratch = Scratch::new(&std::env::temp_dir());
            let client = repo_at(&scratch.root.join("client"), None).await;
            let mount = scratch.dir("mount");
            std::fs::write(mount.join(".ostree"), b"").unwrap();
            std::fs::write(mount.join("ostree"), b"").unwrap();
            std::fs::create_dir_all(mount.join("var/lib/flatpak")).unwrap();
            std::fs::write(mount.join("var/lib/flatpak/repo"), b"").unwrap();

            let choice = find_media(&client, table(&[(&mount, "ext4")])).await;
            assert_eq!(
                skipped(choice.unwrap()),
                [(mount.join("var/lib/flatpak/repo"), "unreadable".to_owned())]
            );
        });
    }

    /// One repository at two mount points is one media, at the path of the
    /// first mount in table order.
    #[test]
    fn one_repository_at_two_mount_points_is_one_media() {
        ostrya_rt::block_on(async {
            let scratch = Scratch::new(&std::env::temp_dir());
            let client = repo_at(&scratch.root.join("client"), None).await;
            let a = scratch.dir("a");
            repo_at(&a.join(".ostree/repo"), Some(&media_summary())).await;
            let b = scratch.root.join("b");
            std::os::unix::fs::symlink("a", &b).unwrap();

            let choice = find_media(&client, table(&[(&b, "ext4"), (&a, "ext4")])).await;
            assert_eq!(one(choice.unwrap()).path, b.join(".ostree/repo"));
        });
    }

    /// The finder probes no root mount, no pseudo file system, and no
    /// network file system.
    #[test]
    fn the_finder_probes_no_excluded_mount() {
        let points: Vec<PathBuf> = PSEUDO_TYPES
            .iter()
            .chain(&NETWORK_TYPES)
            .map(|ty| PathBuf::from(format!("/mnt/{ty}")))
            .collect();
        let mut mounts = vec![(Path::new("/"), "ext4")];
        for (point, ty) in points.iter().zip(PSEUDO_TYPES.iter().chain(&NETWORK_TYPES)) {
            mounts.push((point, ty));
        }
        mounts.push((Path::new("/mnt/media"), "ext4"));
        assert_eq!(probe_points(&table(&mounts)), [Path::new("/mnt/media")]);
    }

    /// A mount of an excluded type over a mount with media hides the media.
    /// A mount of another type over an excluded mount is probed.
    #[test]
    fn the_last_mount_at_a_mount_point_counts() {
        ostrya_rt::block_on(async {
            let scratch = Scratch::new(&std::env::temp_dir());
            let client = repo_at(&scratch.root.join("client"), None).await;
            let mount = scratch.dir("mount");
            repo_at(&mount.join(".ostree/repo"), Some(&media_summary())).await;

            let choice = find_media(&client, table(&[(&mount, "ext4"), (&mount, "nfs")])).await;
            assert!(skipped(choice.unwrap()).is_empty());
            let choice = find_media(&client, table(&[(&mount, "nfs"), (&mount, "ext4")])).await;
            assert_eq!(one(choice.unwrap()).path, mount.join(".ostree/repo"));
        });
    }

    /// A directory given in place of the mount table skips a candidate on
    /// another file system than the directory, and takes the next one.
    #[test]
    fn a_given_directory_skips_a_candidate_on_another_file_system() {
        ostrya_rt::block_on(async {
            let scratch = Scratch::new(&std::env::temp_dir());
            let Some(other) = other_file_system(&scratch) else {
                return;
            };
            let client = repo_at(&scratch.root.join("client"), None).await;
            let dir = scratch.dir("dir/.ostree");
            repo_at(&other.root.join("repo"), Some(&media_summary())).await;
            std::os::unix::fs::symlink(other.root.join("repo"), dir.join("repo")).unwrap();
            let dir = scratch.root.join("dir");
            repo_at(&dir.join("ostree/repo"), Some(&media_summary())).await;

            let choice = find_media_in(&client, &dir).await;
            assert_eq!(one(choice.unwrap()).path, dir.join("ostree/repo"));
        });
    }

    /// The finder reads the mount table of the process and finds media on
    /// a `tmpfs`. The test runs the child half in a new mount namespace, in
    /// a user namespace when it does not run as root.
    #[test]
    fn the_finder_finds_media_on_a_tmpfs_in_a_user_namespace() {
        let scratch = Scratch::new(&std::env::temp_dir());
        let unshare = |args: &[&str]| {
            Command::new("unshare")
                .args(args)
                .arg("true")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
        };
        if unshare(&[]).is_err() {
            eprintln!("skipping: unshare is not available");
            return;
        }
        let root = rustix::process::geteuid().is_root();
        if !root && !unshare(&["--map-root-user"]).is_ok_and(|s| s.success()) {
            eprintln!("skipping: the host grants no user namespace");
            return;
        }
        let namespace: &[&str] = if root {
            &["-m", "--propagation", "private"]
        } else {
            &["--map-root-user", "-m", "--propagation", "private"]
        };
        if !unshare(namespace).is_ok_and(|s| s.success()) {
            eprintln!("skipping: the host grants no mount namespace");
            return;
        }
        let out = Command::new("unshare")
            .args(namespace)
            .arg(std::env::current_exe().unwrap())
            .args([
                "media::find::tests::tmpfs_media_subprocess",
                "--exact",
                "--ignored",
                "--nocapture",
            ])
            .env(NAMESPACE_CHILD, &scratch.root)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        if let Some(line) = stdout
            .lines()
            .find(|l| l.starts_with("tmpfs mount refused"))
        {
            eprintln!("skipping: {line}");
            return;
        }
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "the child reported {}:\n{stdout}{}",
            out.status,
            String::from_utf8_lossy(&out.stderr),
        );
    }

    /// The half of [`the_finder_finds_media_on_a_tmpfs_in_a_user_namespace`]
    /// that mounts a `tmpfs` with media and scans the mount table. It runs
    /// only if this test binary runs again with the environment set.
    #[test]
    #[ignore = "helper process for the_finder_finds_media_on_a_tmpfs_in_a_user_namespace"]
    fn tmpfs_media_subprocess() {
        let Some(dir) = std::env::var_os(NAMESPACE_CHILD).map(PathBuf::from) else {
            return;
        };
        let dir = std::fs::canonicalize(dir).unwrap();
        let mount = dir.join("mnt");
        std::fs::create_dir(&mount).unwrap();
        match Command::new("mount")
            .args(["-t", "tmpfs", "tmpfs"])
            .arg(&mount)
            .output()
        {
            Ok(out) if out.status.success() => {}
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                println!("tmpfs mount refused: {}", stderr.trim());
                return;
            }
            Err(e) => {
                println!("tmpfs mount refused: mount: {e}");
                return;
            }
        }
        let nested = mount.join("ostree");
        std::fs::create_dir(&nested).unwrap();
        let out = Command::new("mount")
            .args(["-t", "tmpfs", "tmpfs"])
            .arg(&nested)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        ostrya_rt::block_on(async {
            let client = repo_at(&dir.join("client"), None).await;
            repo_at(&mount.join(".ostree/repo"), Some(&media_summary())).await;
            repo_at(&nested.join("repo"), Some(&media_summary())).await;
            let table = mountinfo::read_table().await.unwrap();
            let paths = match find_media(&client, table).await.unwrap() {
                MediaChoice::One(found) => vec![found.path],
                MediaChoice::Many(paths) => paths,
                MediaChoice::None(skipped) => panic!("no media: {skipped:?}"),
            };
            assert!(paths.contains(&mount.join(".ostree/repo")), "{paths:?}");

            std::fs::remove_dir_all(mount.join(".ostree")).unwrap();
            let choice = find_media_in(&client, &mount).await.unwrap();
            assert_eq!(
                skipped(choice),
                [(nested.join("repo"), "OtherFileSystem".to_owned())]
            );
        });
    }
}
