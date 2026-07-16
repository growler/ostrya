#![forbid(unsafe_code)]

//! The `ostrya` command-line front-end.
//!
//! A thin binary over the ingest, checkout, and export paths of the `ostrya`
//! library (Phase 11 of `docs/port-plan.md`). Its command surface is its own; a
//! command-line-compatible `ostree` surface arrives in a later phase. Three
//! subcommands are implemented:
//!
//! - `commit` -- ingest a tree from a path, or a tar stream on stdin, into a
//!   commit and print its checksum.
//! - `checkout` -- materialize a commit's tree, or write its composefs image.
//! - `export` -- write a commit's tree to stdout as a tar stream.
//!
//! The binary is synchronous and drives the async library with
//! [`ostrya_rt::block_on`]. Tar streams to and from stdin/stdout flow through
//! [`ostrya_rt::File`] over a duplicated descriptor, so no unbounded stream is
//! buffered in memory.

use std::os::fd::AsFd;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use ostrya::{
    CheckoutMode, CheckoutOptions, Checksum, CommitModifier, CommitModifierFlags, CommitOptions,
    Error, MutableTree, Repo, Result, TarExportOptions, TarImportOptions, Type, Value,
};

/// A pure-Rust front-end over the ostrya repository library.
#[derive(Parser)]
#[command(name = "ostrya", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Commit a tree into the repository and print the new commit checksum.
    Commit(CommitArgs),
    /// Check a commit out onto the filesystem, or write its composefs image.
    Checkout(CheckoutArgs),
    /// Write a commit's tree to stdout as a tar stream.
    Export(ExportArgs),
}

#[derive(Args)]
struct CommitArgs {
    /// The repository to commit into.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// The parent commit (a checksum or a ref); none for a root commit.
    #[arg(long)]
    parent: Option<String>,
    /// Point this branch at the new commit and bind it into the commit.
    #[arg(short, long)]
    branch: Option<String>,
    /// The commit subject.
    #[arg(short, long)]
    subject: Option<String>,
    /// Force owner 0:0, canonicalize modes to `perm & 0755`, and drop xattrs,
    /// for an owner- and host-independent commit.
    #[arg(long)]
    canonical_permissions: bool,
    /// The tree to commit; with none, read a tar stream from stdin.
    path: Option<PathBuf>,
}

#[derive(Args)]
struct CheckoutArgs {
    /// The repository to check out from.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Prefer hardlinks where the repository mode allows (the default path).
    #[arg(short = 'H', long)]
    require_hardlinks: bool,
    /// Copy every object instead of hardlinking (the copy path still reflinks).
    #[arg(short = 'C', long, conflicts_with = "require_hardlinks")]
    force_copy: bool,
    /// Write the commit's composefs EROFS image to the destination instead of a
    /// tree (requires a bare-user or bare-user-shared repository).
    #[arg(long)]
    composefs: bool,
    /// The commit to check out (a checksum or a ref).
    commit: String,
    /// The destination path.
    destination: PathBuf,
}

#[derive(Args)]
struct ExportArgs {
    /// The repository to export from.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// The commit to export (a checksum or a ref).
    commit: String,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match ostrya_rt::block_on(run(cli)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("ostrya: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Commit(args) => commit(args).await,
        Command::Checkout(args) => checkout(args).await,
        Command::Export(args) => export(args).await,
    }
}

async fn commit(args: CommitArgs) -> Result<()> {
    let repo = Repo::open(&args.repo).await?;
    let txn = repo.transaction().await?;

    let parent = match args.parent.as_deref() {
        Some(rev) => repo.resolve_rev(rev, false).await?,
        None => None,
    };

    let root = match args.path.as_deref() {
        Some(path) => {
            let dfd = std::fs::File::open(path).map_err(Error::Io)?;
            let mut modifier = args.canonical_permissions.then(|| {
                CommitModifier::new(
                    CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::SKIP_XATTRS,
                )
            });
            let mut mtree = MutableTree::new();
            txn.write_dfd_to_mtree(
                dfd.as_fd(),
                std::path::Path::new("."),
                &mut mtree,
                modifier.as_mut(),
            )
            .await?;
            txn.write_mtree(&mut mtree).await?
        }
        None => {
            let stdin = stdin_file()?;
            let mut mtree = repo
                .import_tar(&txn, TarImportOptions::new(), stdin)
                .await?;
            txn.write_mtree(&mut mtree).await?
        }
    };

    let opts = CommitOptions {
        parent,
        subject: args.subject,
        body: None,
        timestamp: None,
        metadata: args.branch.as_deref().map(ref_binding),
    };
    let checksum = txn.write_commit(opts, &root).await?;
    if let Some(branch) = args.branch.as_deref() {
        txn.set_ref(branch, Some(&checksum));
    }
    txn.commit().await?;

    println!("{}", checksum.to_hex());
    Ok(())
}

async fn checkout(args: CheckoutArgs) -> Result<()> {
    let repo = Repo::open(&args.repo).await?;
    let commit = resolve(&repo, &args.commit).await?;

    if args.composefs {
        let image = repo.export_composefs(&commit).await?;
        std::fs::write(&args.destination, &image.bytes).map_err(Error::Io)?;
        return Ok(());
    }

    let mut opts = CheckoutOptions::new(CheckoutMode::None);
    opts.force_copy = args.force_copy;
    // -H and -C are mutually exclusive (enforced by clap); -C forces copies and
    // -H requests hardlinks, which is the default path when copies are not
    // forced. The minimal library surface exposes only force_copy.
    let _ = args.require_hardlinks;

    let dest_dir = std::fs::File::open(".").map_err(Error::Io)?;
    repo.checkout_at(&mut opts, dest_dir.as_fd(), &args.destination, &commit)
        .await
}

async fn export(args: ExportArgs) -> Result<()> {
    let repo = Repo::open(&args.repo).await?;
    let commit = resolve(&repo, &args.commit).await?;
    let stdout = stdout_file()?;
    repo.export_tar(&commit, TarExportOptions::new(), stdout)
        .await
}

/// Resolve a checksum or ref to a commit checksum. `resolve_rev` with
/// `allow_noent = false` returns `Some` or an error, never `None`.
async fn resolve(repo: &Repo, rev: &str) -> Result<Checksum> {
    Ok(repo
        .resolve_rev(rev, false)
        .await?
        .expect("resolve_rev with allow_noent=false returns Some or errors"))
}

/// The `ostree.ref-binding` metadata dict binding a commit to `branch`: a single
/// `as` entry, matching what the tool writes for a branch commit.
fn ref_binding(branch: &str) -> Value {
    Value::Array(vec![Value::Tuple(vec![
        Value::Str("ostree.ref-binding".to_owned()),
        Value::variant(
            Type::parse("as").expect("\"as\" is a valid gvariant type"),
            Value::Array(vec![Value::Str(branch.to_owned())]),
        ),
    ])])
}

/// An async streaming reader over stdin, backed by a duplicated descriptor so
/// dropping it leaves the real stdin open.
fn stdin_file() -> Result<ostrya_rt::File> {
    let fd = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map_err(Error::Io)?;
    Ok(ostrya_rt::File::from(fd))
}

/// An async streaming writer over stdout, backed by a duplicated descriptor.
fn stdout_file() -> Result<ostrya_rt::File> {
    let fd = std::io::stdout()
        .as_fd()
        .try_clone_to_owned()
        .map_err(Error::Io)?;
    Ok(ostrya_rt::File::from(fd))
}
