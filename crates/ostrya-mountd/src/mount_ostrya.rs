#![forbid(unsafe_code)]

//! `mount.ostrya`, the mount helper of ostrya.
//!
//! mount(8) runs the helper for `mount -t ostrya -o ro <repo>:<rev> <dir>`.
//! The helper resolves the revision in the repository and mounts the commit
//! as a read-only composefs tree at the target directory.
//!
//! The helper selects one of two paths:
//!
//! - In-process: a caller that is root in the initial user namespace opens
//!   the repository, finds or builds the image, and mounts it with the
//!   `Direct` mounter of `ostrya-mount`.
//! - Daemon: each other caller resolves the revision, reads the relations of
//!   the commit, and asks the mount daemon `ostrya-mountd` for the mount with
//!   the `Helper` client of `ostrya-mount`.
//!
//! The image is the image of the attachment `composefs` of the commit, else
//! the image of its supplement `composefs`, else an image that is built in
//! memory.

use std::ffi::{OsStr, OsString};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use ostrya::{COMPOSEFS_RELATION, Checksum, ComposefsImageSource, Repo};
use ostrya_mount::sys::{Plan, mount_composefs, move_onto, open_dir};
use ostrya_mount::{Access, Direct, Helper, MountFlags, MountOptions, Verity};
use rustix::fs::{CWD, Mode, OFlags, openat};
use rustix::io::Errno;
use rustix::mount::MountAttrFlags;
use rustix::thread::{LinkNameSpaceType, move_into_link_name_space};

#[cfg(test)]
#[path = "man.rs"]
mod man;
#[path = "repo.rs"]
#[allow(dead_code)]
mod repo;

use repo::{DEFAULT_MAX_IMAGE_SIZE, RepoPlan, build_image, find_image};

/// The name of the helper in each message.
const NAME: &str = "mount.ostrya";

/// The file system type of the helper.
const FS_TYPE: &str = "ostrya";

/// The exit status of a usage error or of a refused argument.
const USAGE_ERROR: u8 = 1;

/// The exit status of a failure after the parse of the arguments.
const MOUNT_FAILURE: u8 = 32;

/// The refusal of the option `rw`.
const RW_REFUSED: &str = "the option rw is refused: each mount of the helper is read-only. \
     mount(8) gives rw if no option is given, so give -o ro or -r";

/// The refusal of a mount in the initial user namespace with no `-N`.
const INITIAL_USERNS_REFUSED: &str = "the mount daemon refuses the initial user namespace. \
     Run the mount in a user namespace of your own, for example with \
     `podman unshare mount -t ostrya -o ro <spec> <dir>`, or give the mount namespace of a \
     process in such a namespace with `mount.ostrya <spec> <dir> -N <pid>`";

/// The command line of `mount.ostrya`, in the form that mount(8) gives.
#[derive(Debug, Parser)]
#[command(
    name = "mount.ostrya",
    bin_name = "mount.ostrya",
    version,
    about = "Mount a commit of an ostrya repository as a read-only composefs tree",
    long_about = "Mount a commit of an ostrya repository as a read-only composefs tree.\n\n\
        mount(8) runs mount.ostrya for `mount -t ostrya -o ro REPO:REV DIR`. The helper \
        resolves the revision REV in the repository REPO and mounts the commit at DIR.\n\n\
        A caller that is root in the initial user namespace mounts in its own process. Each \
        other caller asks the mount daemon ostrya-mountd for the mount. Such a caller is in \
        a user namespace of its own, for example under `podman unshare`, or gives the mount \
        namespace of such a process with -N."
)]
struct Cli {
    /// The repository and the revision, in the form REPO:REV.
    ///
    /// The helper splits the value at the first colon. REPO is the path of
    /// the repository directory, and cannot hold a colon. With -N, REPO
    /// must be an absolute path. REV is a commit checksum, a ref,
    /// `remote:ref`, or `@ID:REF`, as `ostrya rev-parse` reads it.
    #[arg(value_name = "SPEC")]
    spec: OsString,
    /// The target directory of the mount.
    ///
    /// With -N, DIR must be an absolute path in the target mount namespace.
    #[arg(value_name = "DIR")]
    dir: PathBuf,
    /// Ignore each mount option that the helper does not know.
    ///
    /// The option does not make the helper accept a known option that it
    /// refuses, for example rw.
    #[arg(short = 's')]
    sloppy: bool,
    /// Do each check and the lookup of the image, and mount nothing.
    ///
    /// The helper builds no image. On the daemon path it does not connect to
    /// the daemon.
    #[arg(short = 'f')]
    fake: bool,
    /// Has no effect. The helper writes no mtab and no utab.
    #[arg(short = 'n')]
    no_mtab: bool,
    /// Write the commit, the source of the image, and the path of the mount
    /// to standard error.
    #[arg(short = 'v')]
    verbose: bool,
    /// Mount in the mount namespace NS.
    ///
    /// A value of digits alone is a process id, and the namespace is
    /// `/proc/NS/ns/mnt`. Each other value is the path of a mount namespace
    /// file.
    #[arg(short = 'N', value_name = "NS")]
    namespace: Option<OsString>,
    /// The mount options, as a list with commas.
    ///
    /// The helper accepts ro, nosuid, nodev, noexec, suid, dev, and exec. It
    /// refuses rw, because each mount is read-only. On the daemon path, it
    /// also refuses noexec, suid, and dev. The helper joins the values of
    /// more than one -o.
    #[arg(short = 'o', value_name = "OPTIONS")]
    options: Vec<String>,
    /// The file system type. The helper accepts `ostrya` alone.
    #[arg(short = 't', value_name = "TYPE")]
    fs_type: Option<String>,
}

/// The way the helper makes the mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    /// The helper mounts in its own process.
    InProcess,
    /// The helper asks the mount daemon.
    Daemon,
}

impl Route {
    /// Returns the name of the path in the line of `-v`.
    fn name(self) -> &'static str {
        match self {
            Route::InProcess => "in-process",
            Route::Daemon => "daemon",
        }
    }
}

/// How a run of the helper fails.
#[derive(Debug, PartialEq, Eq)]
enum Fail {
    /// A usage error or a refused argument.
    Usage(String),
    /// A failure after the parse of the arguments.
    Mount(String),
}

impl Fail {
    /// Returns the exit status of the failure.
    fn status(&self) -> u8 {
        match self {
            Fail::Usage(_) => USAGE_ERROR,
            Fail::Mount(_) => MOUNT_FAILURE,
        }
    }

    /// Returns the text of the failure.
    fn text(&self) -> &str {
        match self {
            Fail::Usage(text) | Fail::Mount(text) => text,
        }
    }
}

/// The arguments of one mount, after their checks.
#[derive(Debug)]
struct Args {
    /// The repository path, as the spec gives it.
    repo: PathBuf,
    /// The revision.
    rev: String,
    /// The attribute flags of the mount.
    flags: MountFlags,
    /// The mount namespace file of `-N`.
    namespace: Option<PathBuf>,
    /// The absolute path of the target directory.
    target: PathBuf,
}

impl Args {
    /// Checks the arguments of `cli` for the path `route`.
    fn new(cli: &Cli, route: Route) -> Result<Args, Fail> {
        let (repo, rev) = parse_spec(&cli.spec).map_err(Fail::Usage)?;
        check_type(cli.fs_type.as_deref()).map_err(Fail::Usage)?;
        let flags = parse_options(&cli.options, cli.sloppy, route).map_err(Fail::Usage)?;
        let namespace = cli
            .namespace
            .as_deref()
            .map(parse_namespace)
            .transpose()
            .map_err(Fail::Usage)?;
        check_repo_path(&repo, namespace.is_some()).map_err(Fail::Usage)?;
        let target = target_path(&cli.dir, namespace.is_some())?;
        Ok(Args {
            repo,
            rev,
            flags,
            namespace,
            target,
        })
    }
}

/// The image of a mount, and where it comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImageSource {
    /// The image of the image commit that a field of the commit names.
    Named(ComposefsImageSource, Checksum),
    /// An image that is built in memory.
    Built,
}

impl std::fmt::Display for ImageSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImageSource::Named(source, image) => write!(f, "{source} {image}"),
            ImageSource::Built => f.write_str("built"),
        }
    }
}

/// What the in-process path reads from the repository.
struct Opened {
    /// The commit of the revision.
    commit: Checksum,
    /// The `verity` option of the composefs overlay.
    verity: Verity,
    /// The `objects` directory of the repository.
    objects: OwnedFd,
    /// The image, or `None` for an image that `-f` does not build.
    image: Option<OwnedFd>,
    /// The source of the image.
    source: ImageSource,
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() {
                ExitCode::from(USAGE_ERROR)
            } else {
                ExitCode::SUCCESS
            };
        }
    };
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(fail) => {
            eprintln!("{NAME}: {}", fail.text());
            ExitCode::from(fail.status())
        }
    }
}

/// Selects the path, checks the arguments, and makes the mount.
fn run(cli: &Cli) -> Result<(), Fail> {
    let route = if ostrya_mount::is_privileged() {
        Route::InProcess
    } else {
        Route::Daemon
    };
    let args = Args::new(cli, route)?;
    match route {
        Route::InProcess => in_process(cli, &args),
        Route::Daemon => through_daemon(cli, &args),
    }
}

/// Splits the spec `REPO:REV` at the first colon.
fn parse_spec(spec: &OsStr) -> Result<(PathBuf, String), String> {
    let bytes = spec.as_bytes();
    let Some(at) = bytes.iter().position(|b| *b == b':') else {
        return Err(format!(
            "the spec {} has no colon: give REPO:REV",
            spec.display()
        ));
    };
    let (repo, rev) = (&bytes[..at], &bytes[at + 1..]);
    if repo.is_empty() {
        return Err(format!(
            "the spec {} has no repository path: give REPO:REV",
            spec.display()
        ));
    }
    if rev.is_empty() {
        return Err(format!(
            "the spec {} has no revision: give REPO:REV",
            spec.display()
        ));
    }
    let rev = std::str::from_utf8(rev)
        .map_err(|_| format!("the revision of the spec {} is not UTF-8", spec.display()))?;
    Ok((PathBuf::from(OsStr::from_bytes(repo)), rev.to_owned()))
}

/// Refuses each file system type other than `ostrya`.
fn check_type(fs_type: Option<&str>) -> Result<(), String> {
    match fs_type {
        None | Some(FS_TYPE) => Ok(()),
        Some(other) => Err(format!(
            "the file system type {other} is refused: the helper mounts the type {FS_TYPE} alone"
        )),
    }
}

/// Reads the mount options of each `-o` for the path `route`, and returns
/// the attribute flags of the mount.
///
/// For a name that more than one option sets, the last option wins, as in
/// the list that mount(8) merges. With `sloppy`, an option that the helper
/// does not know is ignored.
fn parse_options(lists: &[String], sloppy: bool, route: Route) -> Result<MountFlags, String> {
    let mut flags = MountFlags::default();
    for opt in lists.iter().flat_map(|l| l.split(',')) {
        match (opt, route) {
            ("" | "ro", _) => {}
            ("rw", _) => return Err(RW_REFUSED.to_owned()),
            ("nosuid", _) => flags.nosuid = true,
            ("nodev", _) => flags.nodev = true,
            ("exec", _) => flags.noexec = false,
            ("noexec", Route::InProcess) => flags.noexec = true,
            ("suid", Route::InProcess) => flags.nosuid = false,
            ("dev", Route::InProcess) => flags.nodev = false,
            ("noexec", Route::Daemon) => {
                return Err(
                    "the option noexec is refused: the mount daemon cannot set it".to_owned(),
                );
            }
            ("suid" | "dev", Route::Daemon) => {
                return Err(format!(
                    "the option {opt} is refused: the mount daemon sets nosuid and nodev on \
                     each mount"
                ));
            }
            _ if sloppy => {}
            _ => return Err(format!("the mount option {opt} is not known")),
        }
    }
    Ok(flags)
}

/// Returns the mount namespace file of the value of `-N`.
fn parse_namespace(value: &OsStr) -> Result<PathBuf, String> {
    if value.is_empty() {
        return Err("the value of -N is empty".to_owned());
    }
    if value.as_bytes().iter().all(u8::is_ascii_digit) {
        return Ok(PathBuf::from(format!("/proc/{}/ns/mnt", value.display())));
    }
    Ok(PathBuf::from(value))
}

/// Refuses a relative repository path with `-N`. With `-N`, mount(8) runs
/// the helper with its working directory at `/`, so a relative path resolves
/// against `/`.
fn check_repo_path(repo: &Path, with_namespace: bool) -> Result<(), String> {
    if with_namespace && !repo.is_absolute() {
        return Err(format!(
            "with -N, the repository path must be an absolute path: {}",
            repo.display()
        ));
    }
    Ok(())
}

/// Returns the absolute path of the target directory `dir`. With `-N`, a
/// relative path is refused, because the helper resolves the path in the
/// target namespace. Else a relative path is made absolute against the
/// working directory.
fn target_path(dir: &Path, with_namespace: bool) -> Result<PathBuf, Fail> {
    if with_namespace {
        if !dir.is_absolute() {
            return Err(Fail::Usage(format!(
                "with -N, the target directory must be an absolute path: {}",
                dir.display()
            )));
        }
        return Ok(dir.to_owned());
    }
    std::path::absolute(dir)
        .map_err(|e| Fail::Mount(format!("the target directory {}: {e}", dir.display())))
}

/// Opens the mount namespace file `path`, and refuses a file that is not a
/// mount namespace. The open does not block, so a FIFO with no writer gets
/// the refusal.
fn open_mount_namespace(path: &Path) -> Result<OwnedFd, Fail> {
    let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let fd = openat(CWD, path, flags, Mode::empty())
        .map_err(|e| Fail::Mount(format!("open the mount namespace {}: {e}", path.display())))?;
    match ostrya_sys::ns_type(&fd) {
        Ok(LinkNameSpaceType::Mount) => Ok(fd),
        Ok(_) => Err(Fail::Usage(format!(
            "{} is not a mount namespace",
            path.display()
        ))),
        Err(Errno::NOTTY) => Err(Fail::Usage(format!(
            "{} is not a namespace file",
            path.display()
        ))),
        Err(e) => Err(Fail::Mount(format!(
            "read the type of the namespace {}: {e}",
            path.display()
        ))),
    }
}

/// Resolves `rev` in `repo` to a commit checksum.
async fn resolve(repo: &Repo, rev: &str) -> Result<Checksum, Fail> {
    match repo.resolve_rev(rev, false).await {
        Ok(Some(commit)) => Ok(commit),
        Ok(None) => Err(Fail::Mount(format!("the revision {rev} names no commit"))),
        Err(e) => Err(Fail::Mount(format!("resolve {rev}: {e}"))),
    }
}

/// Returns the failure of a read of the repository.
fn repo_failure(e: repo::Error) -> Fail {
    Fail::Mount(e.to_string())
}

/// Writes the line of `-v`.
fn report(commit: &Checksum, source: ImageSource, route: Route) {
    eprintln!(
        "{NAME}: commit {commit}, image {source}, path {}",
        route.name()
    );
}

/// Returns the mount attributes of `flags`.
fn mount_attrs(flags: MountFlags) -> MountAttrFlags {
    let mut attrs = MountAttrFlags::empty();
    if flags.nosuid {
        attrs |= MountAttrFlags::MOUNT_ATTR_NOSUID;
    }
    if flags.nodev {
        attrs |= MountAttrFlags::MOUNT_ATTR_NODEV;
    }
    if flags.noexec {
        attrs |= MountAttrFlags::MOUNT_ATTR_NOEXEC;
    }
    attrs
}

/// The in-process path: opens the repository, finds or builds the image,
/// and mounts it in the mount namespace of the helper or of `-N`.
fn in_process(cli: &Cli, args: &Args) -> Result<(), Fail> {
    let mntns = args
        .namespace
        .as_deref()
        .map(open_mount_namespace)
        .transpose()?;
    let opened = ostrya_rt::block_on(open_in_process(&args.repo, &args.rev, cli.fake))?;
    if cli.verbose {
        report(&opened.commit, opened.source, Route::InProcess);
    }
    let Some(image) = opened.image.filter(|_| !cli.fake) else {
        return Ok(());
    };
    match mntns {
        None => {
            let mut opts = MountOptions::default();
            opts.flags = args.flags;
            opts.source = Some(opened.commit.to_hex());
            let root = Direct::new()
                .mount_image(
                    image.as_fd(),
                    opened.objects.as_fd(),
                    opened.verity,
                    &args.target,
                    &opts,
                )
                .map_err(|e| Fail::Mount(e.to_string()))?;
            drop(root);
        }
        Some(mntns) => {
            let plan = Plan {
                verity: opened.verity,
                access: Access::ReadOnly,
                source: opened.commit.to_hex(),
                attrs: mount_attrs(args.flags),
                idmap: None,
            };
            let top = mount_composefs(image, opened.objects.as_fd(), &plan)
                .map_err(|e| Fail::Mount(e.to_string()))?;
            // The blocking pool of the runtime shares the file system
            // attributes of the process, and the kernel refuses `setns` into
            // a mount namespace for a thread that shares them.
            ostrya_sys::unshare_fs().map_err(|e| Fail::Mount(format!("unshare CLONE_FS: {e}")))?;
            move_into_link_name_space(mntns.as_fd(), Some(LinkNameSpaceType::Mount))
                .map_err(|e| Fail::Mount(format!("setns mount namespace: {e}")))?;
            let target = open_dir(CWD, &args.target).map_err(|e| {
                Fail::Mount(format!("open the target {}: {e}", args.target.display()))
            })?;
            move_onto(top, target.as_fd()).map_err(|e| Fail::Mount(e.to_string()))?;
        }
    }
    Ok(())
}

/// Opens the repository at `path`, resolves `rev`, checks the mode, reads
/// the verity choice, and finds the image of the commit. With no image
/// commit, builds the image, except with `fake`.
async fn open_in_process(path: &Path, rev: &str, fake: bool) -> Result<Opened, Fail> {
    let open_failure = |e: &dyn std::fmt::Display| {
        Fail::Mount(format!("open the repository {}: {e}", path.display()))
    };
    // The strict open takes a directory descriptor and a path below it, and
    // duplicates the descriptor, so the helper opens the repository
    // directory first.
    let dir = open_dir(CWD, path).map_err(|e| open_failure(&e))?;
    let repo = Repo::open_at_strict(dir.as_fd(), Path::new("."))
        .await
        .map_err(|e| open_failure(&e))?;
    drop(dir);
    let commit = resolve(&repo, rev).await?;
    let plan = RepoPlan::new(&repo).map_err(repo_failure)?;
    let (image, source) = match find_image(&repo, &commit).await.map_err(repo_failure)? {
        Some((image, source, image_commit)) => {
            (Some(image), ImageSource::Named(source, image_commit))
        }
        None if fake => (None, ImageSource::Built),
        None => {
            let image = build_image(&repo, &commit, &plan, DEFAULT_MAX_IMAGE_SIZE)
                .await
                .map_err(repo_failure)?;
            (Some(image), ImageSource::Built)
        }
    };
    let objects = repo
        .objects_dir()
        .try_clone_to_owned()
        .map_err(|e| Fail::Mount(format!("dup objects: {e}")))?;
    Ok(Opened {
        commit,
        verity: plan.verity,
        objects,
        image,
        source,
    })
}

/// The daemon path: refuses the initial user namespace with no `-N`,
/// resolves the revision, selects the op from the relations of the commit,
/// and asks the daemon for the mount.
fn through_daemon(cli: &Cli, args: &Args) -> Result<(), Fail> {
    if args.namespace.is_none() && ostrya_mount::in_initial_user_namespace() {
        return Err(Fail::Usage(INITIAL_USERNS_REFUSED.to_owned()));
    }
    let helper = match &args.namespace {
        Some(path) => {
            let mntns = open_mount_namespace(path)?;
            let userns = ostrya_sys::ns_owner_userns(&mntns).map_err(|e| {
                Fail::Mount(format!(
                    "the user namespace that owns {}: {e}",
                    path.display()
                ))
            })?;
            Helper::with_namespaces(userns, mntns)
        }
        None => Helper::new().map_err(|e| Fail::Mount(e.to_string()))?,
    };
    let repo_path = std::path::absolute(&args.repo)
        .map_err(|e| Fail::Mount(format!("the repository path {}: {e}", args.repo.display())))?;
    let (commit, source) = ostrya_rt::block_on(read_for_daemon(&args.repo, &args.rev))?;
    if cli.verbose {
        report(&commit, source, Route::Daemon);
    }
    if cli.fake {
        return Ok(());
    }
    let mut opts = MountOptions::default();
    opts.flags = args.flags;
    opts.source = Some(commit.to_hex());
    let root = match source {
        ImageSource::Named(..) => helper.mount_stored(&repo_path, &commit, &args.target, &opts),
        ImageSource::Built => helper.mount_built(&repo_path, &commit, &args.target, &opts),
    }
    .map_err(|e| Fail::Mount(e.to_string()))?;
    drop(root);
    Ok(())
}

/// Opens the repository at `path` with the credentials of the caller,
/// resolves `rev`, and reads the relations of the commit. Returns the
/// commit and the source of its image: the image commit of the first entry
/// [`COMPOSEFS_RELATION`] of the attachments, else of the supplements, else
/// a built image.
async fn read_for_daemon(path: &Path, rev: &str) -> Result<(Checksum, ImageSource), Fail> {
    let repo = Repo::open(path)
        .await
        .map_err(|e| Fail::Mount(format!("open the repository {}: {e}", path.display())))?;
    let commit = resolve(&repo, rev).await?;
    let relations = repo
        .read_commit_relations(&commit)
        .await
        .map_err(|e| Fail::Mount(format!("read the relations of commit {commit}: {e}")))?;
    let named = |list: &[(String, Checksum)], source| {
        list.iter()
            .find(|(name, _)| name == COMPOSEFS_RELATION)
            .map(|(_, image)| ImageSource::Named(source, *image))
    };
    let source = named(&relations.attachments, ComposefsImageSource::Attachment)
        .or_else(|| named(&relations.supplements, ComposefsImageSource::Supplement))
        .unwrap_or(ImageSource::Built);
    Ok((commit, source))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_line_definition_is_valid() {
        Cli::command().debug_assert();
    }

    /// The committed page `mount.ostrya.8` is the page that the `clap`
    /// definition renders.
    #[test]
    fn man_page_matches_the_committed_file() {
        man::assert_page_matches(Cli::command(), NAME, "8");
    }

    /// The arguments in the form that mount(8) gives parse, and the values
    /// of more than one `-o` are kept in order.
    #[test]
    fn the_arguments_of_mount_parse() {
        let cli = Cli::try_parse_from([
            NAME,
            "/srv/repo:main",
            "/mnt",
            "-s",
            "-f",
            "-n",
            "-v",
            "-o",
            "ro,nosuid",
            "-N",
            "/proc/42/fd/4",
            "-o",
            "nodev",
            "-t",
            "ostrya",
        ])
        .unwrap();
        assert_eq!(cli.spec, "/srv/repo:main");
        assert_eq!(cli.dir, Path::new("/mnt"));
        assert!(cli.sloppy && cli.fake && cli.no_mtab && cli.verbose);
        assert_eq!(cli.namespace.as_deref(), Some(OsStr::new("/proc/42/fd/4")));
        assert_eq!(cli.options, ["ro,nosuid", "nodev"]);
        assert_eq!(cli.fs_type.as_deref(), Some("ostrya"));
        let cli = Cli::try_parse_from([NAME, "r:c", "d"]).unwrap();
        assert!(cli.options.is_empty() && cli.namespace.is_none() && cli.fs_type.is_none());
        let err = Cli::try_parse_from([NAME, "r:c"]).unwrap_err();
        assert!(err.use_stderr());
    }

    #[test]
    fn a_spec_splits_at_the_first_colon() {
        let split = |spec: &str| parse_spec(OsStr::new(spec)).unwrap();
        let commit = "a".repeat(64);
        assert_eq!(
            split(&format!("/srv/repo:{commit}")),
            (PathBuf::from("/srv/repo"), commit.clone())
        );
        assert_eq!(
            split("repo:main"),
            (PathBuf::from("repo"), "main".to_owned())
        );
        assert_eq!(
            split("/srv/repo:origin:os/x86_64"),
            (PathBuf::from("/srv/repo"), "origin:os/x86_64".to_owned())
        );
        assert_eq!(
            split("/srv/repo:@org.example.Os:os/stable"),
            (
                PathBuf::from("/srv/repo"),
                "@org.example.Os:os/stable".to_owned()
            )
        );
        assert_eq!(
            split("/srv/repo:a^"),
            (PathBuf::from("/srv/repo"), "a^".to_owned())
        );
    }

    #[test]
    fn a_spec_with_an_empty_part_or_no_colon_is_refused() {
        let refuse = |spec: &OsStr, what: &str| {
            let err = parse_spec(spec).unwrap_err();
            assert!(err.contains(what), "{err}");
        };
        refuse(OsStr::new("/srv/repo"), "has no colon");
        refuse(OsStr::new(":main"), "has no repository path");
        refuse(OsStr::new("/srv/repo:"), "has no revision");
        refuse(OsStr::new(":"), "has no repository path");
        refuse(OsStr::from_bytes(b"/srv/repo:\xff"), "is not UTF-8");
        let (repo, _) = parse_spec(OsStr::from_bytes(b"/srv/\xff:main")).unwrap();
        assert_eq!(repo.as_os_str().as_bytes(), b"/srv/\xff");
    }

    fn options(list: &[&str], sloppy: bool, route: Route) -> Result<MountFlags, String> {
        let lists: Vec<String> = list.iter().map(|s| (*s).to_owned()).collect();
        parse_options(&lists, sloppy, route)
    }

    fn flags(nosuid: bool, nodev: bool, noexec: bool) -> MountFlags {
        MountFlags {
            nosuid,
            nodev,
            noexec,
        }
    }

    #[test]
    fn ro_and_no_option_give_no_flag() {
        for route in [Route::InProcess, Route::Daemon] {
            assert_eq!(options(&[], false, route), Ok(MountFlags::default()));
            assert_eq!(options(&["ro"], false, route), Ok(MountFlags::default()));
            assert_eq!(
                options(&["ro,,exec"], false, route),
                Ok(MountFlags::default())
            );
        }
    }

    #[test]
    fn rw_is_refused_also_with_sloppy() {
        for route in [Route::InProcess, Route::Daemon] {
            for sloppy in [false, true] {
                let err = options(&["rw"], sloppy, route).unwrap_err();
                assert!(err.contains("-o ro") && err.contains("-r"), "{err}");
                assert!(options(&["ro", "rw"], sloppy, route).is_err());
            }
        }
    }

    #[test]
    fn an_unknown_option_is_refused_unless_sloppy() {
        for route in [Route::InProcess, Route::Daemon] {
            for opt in [
                "foo=bar", "nofail", "_netdev", "user", "users", "owner", "group",
            ] {
                let err = options(&["ro", opt], false, route).unwrap_err();
                assert!(err.contains(opt), "{err}");
                assert_eq!(
                    options(&["ro", opt], true, route),
                    Ok(MountFlags::default())
                );
            }
        }
    }

    #[test]
    fn the_in_process_path_takes_each_flag() {
        let route = Route::InProcess;
        assert_eq!(
            options(&["ro,nosuid,nodev,noexec"], false, route),
            Ok(flags(true, true, true))
        );
        assert_eq!(
            options(&["nosuid", "nodev"], false, route),
            Ok(flags(true, true, false))
        );
        assert_eq!(
            options(&["nosuid,nodev,noexec,suid,dev,exec"], false, route),
            Ok(MountFlags::default())
        );
        assert_eq!(
            options(&["suid,nosuid"], false, route),
            Ok(flags(true, false, false))
        );
    }

    #[test]
    fn the_daemon_path_refuses_noexec_suid_and_dev() {
        let route = Route::Daemon;
        assert_eq!(
            options(&["ro,nosuid,nodev"], false, route),
            Ok(flags(true, true, false))
        );
        assert_eq!(options(&["exec"], false, route), Ok(MountFlags::default()));
        for opt in ["noexec", "suid", "dev"] {
            for sloppy in [false, true] {
                let err = options(&[opt], sloppy, route).unwrap_err();
                assert!(err.contains(opt), "{err}");
            }
        }
    }

    #[test]
    fn only_the_type_ostrya_is_accepted() {
        assert_eq!(check_type(None), Ok(()));
        assert_eq!(check_type(Some("ostrya")), Ok(()));
        for other in ["ostrya.sub", "overlay", ""] {
            assert!(check_type(Some(other)).is_err(), "{other}");
        }
    }

    #[test]
    fn digits_name_a_process_and_each_other_value_a_file() {
        let ns = |v: &str| parse_namespace(OsStr::new(v));
        assert_eq!(ns("4242"), Ok(PathBuf::from("/proc/4242/ns/mnt")));
        assert_eq!(ns("/proc/7/fd/4"), Ok(PathBuf::from("/proc/7/fd/4")));
        assert_eq!(ns("ns/mnt"), Ok(PathBuf::from("ns/mnt")));
        assert_eq!(ns("42a"), Ok(PathBuf::from("42a")));
        assert!(ns("").is_err());
    }

    #[test]
    fn a_relative_target_is_refused_with_a_namespace_and_made_absolute_without() {
        assert!(matches!(
            target_path(Path::new("dir"), true),
            Err(Fail::Usage(_))
        ));
        assert_eq!(
            target_path(Path::new("/mnt/x"), true),
            Ok(PathBuf::from("/mnt/x"))
        );
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(target_path(Path::new("dir"), false), Ok(cwd.join("dir")));
        assert_eq!(
            target_path(Path::new("/mnt/x"), false),
            Ok(PathBuf::from("/mnt/x"))
        );
    }

    #[test]
    fn a_relative_repository_is_refused_with_a_namespace() {
        for repo in ["repo", "./repo", "../repo"] {
            let err = check_repo_path(Path::new(repo), true).unwrap_err();
            assert!(err.contains("-N") && err.contains(repo), "{err}");
            assert_eq!(check_repo_path(Path::new(repo), false), Ok(()));
        }
        assert_eq!(check_repo_path(Path::new("/srv/repo"), true), Ok(()));
        assert_eq!(check_repo_path(Path::new("/srv/repo"), false), Ok(()));
    }

    /// The check of the arguments refuses a relative repository with `-N` as
    /// a usage error, on each path, and accepts it with no `-N`.
    #[test]
    fn the_arguments_refuse_a_relative_repository_with_a_namespace() {
        for route in [Route::InProcess, Route::Daemon] {
            let cli =
                Cli::try_parse_from([NAME, "repo:main", "/mnt", "-o", "ro", "-N", "42"]).unwrap();
            let fail = Args::new(&cli, route).unwrap_err();
            assert_eq!(fail.status(), USAGE_ERROR, "{fail:?}");
            assert!(fail.text().contains("repository path"), "{fail:?}");
            let cli = Cli::try_parse_from([NAME, "repo:main", "/mnt", "-o", "ro"]).unwrap();
            let args = Args::new(&cli, route).unwrap();
            assert_eq!(args.repo, Path::new("repo"));
        }
    }

    /// A FIFO with no writer as the `-N` file is refused as a file that is
    /// not a namespace, and the open does not block.
    #[test]
    fn a_fifo_as_the_namespace_file_is_refused_with_no_block() {
        let dir = std::env::temp_dir().join(format!("mount-ostrya-fifo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let fifo = dir.join("fifo");
        rustix::fs::mknodat(
            CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let path = fifo.clone();
        std::thread::spawn(move || {
            let _ = tx.send(open_mount_namespace(&path).map(drop));
        });
        let result = rx.recv_timeout(std::time::Duration::from_secs(10));
        let _ = std::fs::remove_dir_all(&dir);
        let fail = result.expect("the open of the FIFO blocks").unwrap_err();
        assert_eq!(fail.status(), USAGE_ERROR, "{fail:?}");
        assert!(fail.text().contains("is not a namespace file"), "{fail:?}");
    }

    #[test]
    fn a_usage_failure_exits_1_and_each_other_failure_32() {
        assert_eq!(Fail::Usage(String::new()).status(), 1);
        assert_eq!(Fail::Mount(String::new()).status(), 32);
    }

    #[test]
    fn the_verbose_line_names_the_source_and_the_path() {
        let image: Checksum = "b".repeat(64).parse().unwrap();
        assert_eq!(
            ImageSource::Named(ComposefsImageSource::Attachment, image).to_string(),
            format!("attachment {image}")
        );
        assert_eq!(
            ImageSource::Named(ComposefsImageSource::Supplement, image).to_string(),
            format!("supplement {image}")
        );
        assert_eq!(ImageSource::Built.to_string(), "built");
        assert_eq!(Route::InProcess.name(), "in-process");
        assert_eq!(Route::Daemon.name(), "daemon");
    }

    #[test]
    fn the_mount_attributes_follow_the_flags() {
        assert_eq!(mount_attrs(MountFlags::default()), MountAttrFlags::empty());
        assert_eq!(
            mount_attrs(flags(true, true, true)),
            MountAttrFlags::MOUNT_ATTR_NOSUID
                | MountAttrFlags::MOUNT_ATTR_NODEV
                | MountAttrFlags::MOUNT_ATTR_NOEXEC
        );
    }
}
