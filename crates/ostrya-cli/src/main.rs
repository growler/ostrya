#![forbid(unsafe_code)]

//! The `ostrya` command-line front-end.
//!
//! A thin binary over the ingest, checkout, and export paths of the `ostrya`
//! library (Phase 11 of `docs/port-plan.md`). Its command surface is its own; a
//! command-line-compatible `ostree` surface arrives in a later phase. The
//! subcommands are:
//!
//! - `commit` -- ingest a tree from a path, or a tar stream on stdin, into a
//!   commit and print its checksum.
//! - `checkout` -- materialize a commit's tree, or write its composefs image.
//! - `export` -- write a commit's tree to stdout as a tar stream.
//! - `prune` -- delete unreachable objects.
//! - `fsck` -- verify object integrity and completeness.
//! - `diff` -- report the paths that changed between two commits.
//! - `sign` -- add, verify, or delete commit signatures under one of the
//!   ed25519, spki, or gpg engines.
//! - `summary` -- regenerate, sign, or verify the repository summary.
//! - `static-delta` -- list the repository's static deltas, apply one offline,
//!   generate one, or rebuild the delta index cache.
//!
//! The binary is synchronous and drives the async library with
//! [`ostrya_rt::block_on`]. Tar streams to and from stdin/stdout flow through
//! [`ostrya_rt::File`] over a duplicated descriptor, so no unbounded stream is
//! buffered in memory.

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};
use ostrya::{
    CheckoutMode, CheckoutOptions, Checksum, CommitModifier, CommitModifierFlags, CommitOptions,
    DeltaOptions, DiffChange, Ed25519Signer, Ed25519Verifier, Error, FsckOptions, MutableTree,
    ObjectType, PruneOptions, Repo, Result, SummaryOptions, TarExportOptions, TarImportOptions,
    Type, Value, Verifier, VerifyOutcome, base64, load_sign_keys, load_sign_keys_from,
};
#[cfg(feature = "gpg")]
use ostrya::{GpgSigner, GpgVerifier};
#[cfg(feature = "spki")]
use ostrya::{SpkiSigner, SpkiVerifier};

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
    /// Delete objects unreachable from the repository's refs and commits.
    Prune(PruneArgs),
    /// Verify object integrity and completeness across every commit.
    Fsck(FsckArgs),
    /// Report the paths that changed between two commits.
    Diff(DiffArgs),
    /// Add, verify, or delete signatures on a commit.
    Sign(SignArgs),
    /// Regenerate, sign, or verify the repository summary.
    Summary(SummaryArgs),
    /// List, generate, apply, or index static deltas.
    #[command(name = "static-delta")]
    StaticDelta(StaticDeltaArgs),
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

#[derive(Args)]
struct PruneArgs {
    /// The repository to prune.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Keep only objects reachable from refs; also prune unreferenced commits.
    #[arg(long)]
    refs_only: bool,
    /// Parents of each ref to keep: -1 for all history, 0 for only the head.
    #[arg(long, default_value_t = -1, allow_negative_numbers = true)]
    depth: i32,
    /// Compute and print the statistics without deleting anything.
    #[arg(long)]
    no_prune: bool,
    /// Delete this specific, unreferenced commit before sweeping.
    #[arg(long)]
    delete_commit: Option<String>,
}

#[derive(Args)]
struct FsckArgs {
    /// The repository to check.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Do not mark commits partial when a referenced object is missing.
    #[arg(long)]
    no_mark_partial: bool,
}

#[derive(Args)]
struct DiffArgs {
    /// The repository to read from.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// The first revision. With no second revision, its parent is compared
    /// against it.
    from: String,
    /// The second revision; when omitted, `from` is compared against its
    /// parent.
    to: Option<String>,
}

/// The signature engine selected by `--sign-type`.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SignType {
    /// ed25519 detached signatures (the sign-api default).
    #[value(name = "ed25519")]
    Ed25519,
    /// spki: ECDSA over NIST P-256 with SHA-256.
    #[value(name = "spki")]
    Spki,
    /// GPG (OpenPGP) detached signatures.
    #[value(name = "gpg")]
    Gpg,
}

#[derive(Args)]
struct SignArgs {
    /// The repository holding the commit.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Delete stored signatures matching the given KEY-IDs.
    #[arg(short, long, conflicts_with = "verify")]
    delete: bool,
    /// Verify the commit's signatures instead of adding one.
    #[arg(long)]
    verify: bool,
    /// The signature engine to use.
    #[arg(short = 's', long = "sign-type", default_value = "ed25519")]
    sign_type: SignType,
    /// Read key(s) from a file; repeatable. For ed25519/spki: base64 secret
    /// keys (signing) or public keys (verify), one per line. For gpg: a
    /// keyring, binary or armored (verify and delete).
    #[arg(long)]
    keys_file: Vec<PathBuf>,
    /// Override the system trusted/revoked key directories for ed25519/spki
    /// verification; repeatable. Not used by the gpg engine.
    #[arg(long)]
    keys_dir: Vec<PathBuf>,
    /// The GnuPG home directory gpg resolves signing keys in (default: gpg's
    /// own resolution). Only for the gpg engine.
    #[arg(long)]
    gpg_homedir: Option<PathBuf>,
    /// The remote whose trusted keyring to add for gpg verify and delete:
    /// `<remote>.trustedkeys.gpg` in the repo and under
    /// `/etc/ostree/remotes.d/`, on top of the global trusted set. Only for
    /// the gpg engine.
    #[arg(long)]
    remote: Option<String>,
    /// The commit to operate on (a checksum or a ref).
    commit: String,
    /// Key identifiers: base64 keys for ed25519/spki. For gpg: the signing
    /// key gpg resolves (a fingerprint, key id, or user id), or, with
    /// --delete, the fingerprints to remove.
    key_id: Vec<String>,
}

#[derive(Args)]
struct SummaryArgs {
    /// The repository whose summary to operate on.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Regenerate the summary from the repository's refs.
    #[arg(short = 'u', long)]
    update: bool,
    /// Verify the summary's signatures instead of regenerating or signing.
    #[arg(long)]
    verify: bool,
    /// The signature engine to use for --verify or signing.
    #[arg(short = 's', long = "sign-type", default_value = "ed25519")]
    sign_type: SignType,
    /// Override `ostree.summary.last-modified` (seconds since the Unix epoch)
    /// for reproducible output; defaults to the current time.
    #[arg(long)]
    last_modified: Option<u64>,
    /// The timestamp of the collection anchor commit (seconds since the Unix
    /// epoch); defaults to SOURCE_DATE_EPOCH or the current time. Only used for
    /// a collection repository.
    #[arg(long)]
    metadata_commit_timestamp: Option<u64>,
    /// Read key(s) from a file; repeatable, same format as `ostrya sign`.
    #[arg(long)]
    keys_file: Vec<PathBuf>,
    /// Override the system trusted/revoked key directories for ed25519/spki
    /// verification; repeatable.
    #[arg(long)]
    keys_dir: Vec<PathBuf>,
    /// The GnuPG home directory gpg resolves signing keys in. Only for gpg.
    #[arg(long)]
    gpg_homedir: Option<PathBuf>,
    /// The remote whose trusted gpg keyring to add for verification. Only for
    /// the gpg engine.
    #[arg(long)]
    remote: Option<String>,
    /// Signing or verification key identifiers, same format as `ostrya sign`.
    key_id: Vec<String>,
}

#[derive(Args)]
struct StaticDeltaArgs {
    /// The repository to operate on.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    #[command(subcommand)]
    command: StaticDeltaCommand,
}

#[derive(Subcommand)]
enum StaticDeltaCommand {
    /// List the repository's static deltas.
    List,
    /// Apply a static delta from a directory offline, producing the target
    /// commit's objects, and print the target commit checksum.
    ApplyOffline {
        /// The delta directory (holding `superblock` and numbered part files).
        dir: PathBuf,
    },
    /// Generate a static delta and print the directory it was written to.
    ///
    /// The three size thresholds take a count of bytes. The same-named `ostree`
    /// options take decimal megabytes, so pass 4000000 where `ostree` takes 4.
    Generate(DeltaGenerateArgs),
    /// Rebuild the `delta-indexes/` cache from the deltas present.
    Reindex,
}

#[derive(Args)]
struct DeltaGenerateArgs {
    /// The source commit (a checksum or a ref); omit for a delta from scratch.
    #[arg(long)]
    from: Option<String>,
    /// The target commit (a checksum or a ref).
    #[arg(long)]
    to: String,
    /// Deliver an object whose stream reaches this many bytes as a loose
    /// fallback instead of packing it into a part.
    #[arg(long, default_value_t = 4_000_000)]
    min_fallback_size: u64,
    /// The largest content size a bspatch stream is attempted for.
    #[arg(long, default_value_t = 64_000_000)]
    max_bsdiff_size: u64,
    /// Close a part once its payload would pass this many bytes.
    #[arg(long, default_value_t = 32_000_000)]
    max_chunk_size: u64,
    /// Never emit bspatch streams; splice what chunking cannot express.
    #[arg(long)]
    disable_bsdiff: bool,
    /// Pin the superblock timestamp (seconds since the Unix epoch) for
    /// reproducible output; defaults to the current time.
    #[arg(long)]
    timestamp: Option<u64>,
    /// Write the delta's files here instead of into the repository's `deltas/`.
    /// The directory's other contents are left alone, so part files of a longer
    /// delta written here before stay behind.
    #[arg(long)]
    output_dir: Option<PathBuf>,
    /// Sign the generated delta with this key; repeatable. A base64 secret key
    /// for ed25519 and spki, a KEY-ID for gpg, as `ostrya sign` takes them.
    #[arg(long = "sign")]
    sign: Vec<String>,
    /// The signature engine used for --sign.
    #[arg(short = 's', long = "sign-type", default_value = "ed25519")]
    sign_type: SignType,
    /// Read signing key(s) from a file; repeatable, same format as
    /// `ostrya sign`.
    #[arg(long)]
    keys_file: Vec<PathBuf>,
    /// The GnuPG home directory gpg resolves signing keys in. Only for gpg.
    #[arg(long)]
    gpg_homedir: Option<PathBuf>,
    /// Rebuild the index cache after generating. Covers the deltas under the
    /// repository's `deltas/` tree, so it cannot be combined with --output-dir.
    #[arg(long)]
    reindex: bool,
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
        Command::Prune(args) => prune(args).await,
        Command::Fsck(args) => fsck(args).await,
        Command::Diff(args) => diff(args).await,
        Command::Sign(args) => sign(args).await,
        Command::Summary(args) => summary(args).await,
        Command::StaticDelta(args) => static_delta(args).await,
    }
}

/// List the repository's static deltas, apply one offline, generate one, or
/// rebuild the index cache.
async fn static_delta(args: StaticDeltaArgs) -> Result<()> {
    let repo = Repo::open(&args.repo).await?;
    match args.command {
        StaticDeltaCommand::List => {
            for name in repo.list_static_deltas().await? {
                println!("{name}");
            }
            Ok(())
        }
        StaticDeltaCommand::ApplyOffline { dir } => {
            let to = repo.apply_static_delta_offline(&dir).await?;
            println!("{}", to.to_hex());
            Ok(())
        }
        StaticDeltaCommand::Generate(generate) => delta_generate(&repo, &args.repo, generate).await,
        StaticDeltaCommand::Reindex => repo.reindex_static_deltas().await,
    }
}

/// Generate a static delta, optionally sign it, and print its directory.
async fn delta_generate(repo: &Repo, repo_path: &Path, args: DeltaGenerateArgs) -> Result<()> {
    // Indexing rebuilds the cache from the deltas present under the
    // repository's `deltas/` tree, which a delta written elsewhere is not part
    // of, so the pair would silently index nothing.
    if args.reindex && args.output_dir.is_some() {
        return Err(Error::InvalidFormat(
            "--reindex covers the deltas under the repository's deltas/ tree, so it \
             cannot be combined with --output-dir"
                .into(),
        ));
    }
    let from = match args.from.as_deref() {
        Some(rev) => Some(resolve(repo, rev).await?),
        None => None,
    };
    let to = resolve(repo, &args.to).await?;

    let opts = DeltaOptions {
        min_fallback_size: args.min_fallback_size,
        max_bsdiff_size: args.max_bsdiff_size,
        max_chunk_size: args.max_chunk_size,
        bsdiff: !args.disable_bsdiff,
        timestamp: args.timestamp,
        output_dir: args.output_dir.clone(),
    };
    let written = repo
        .generate_static_delta(from.as_ref(), &to, &opts)
        .await?;
    // The default location is repository-relative; an output directory is
    // already resolved against this process's working directory.
    let dir = match &args.output_dir {
        Some(dir) => dir.clone(),
        None => repo_path.join(written),
    };

    if !args.sign.is_empty() || !args.keys_file.is_empty() {
        delta_sign(repo, &dir, &args).await?;
    }
    if args.reindex {
        repo.reindex_static_deltas().await?;
    }
    println!("{}", dir.display());
    Ok(())
}

/// Sign a generated delta once per requested key, under the chosen engine.
async fn delta_sign(repo: &Repo, dir: &Path, args: &DeltaGenerateArgs) -> Result<()> {
    match args.sign_type {
        SignType::Ed25519 => {
            for key in delta_secret_keys(args)? {
                repo.sign_static_delta(dir, &Ed25519Signer::from_base64(&key)?)
                    .await?;
            }
            Ok(())
        }
        SignType::Spki => delta_sign_spki(repo, dir, args).await,
        SignType::Gpg => delta_sign_gpg(repo, dir, args).await,
    }
}

#[cfg(feature = "spki")]
async fn delta_sign_spki(repo: &Repo, dir: &Path, args: &DeltaGenerateArgs) -> Result<()> {
    for key in delta_secret_keys(args)? {
        repo.sign_static_delta(dir, &SpkiSigner::from_base64(&key)?)
            .await?;
    }
    Ok(())
}

#[cfg(not(feature = "spki"))]
async fn delta_sign_spki(_: &Repo, _: &Path, _: &DeltaGenerateArgs) -> Result<()> {
    Err(unsupported_type("spki"))
}

#[cfg(feature = "gpg")]
async fn delta_sign_gpg(repo: &Repo, dir: &Path, args: &DeltaGenerateArgs) -> Result<()> {
    if !args.keys_file.is_empty() {
        return Err(Error::Signature(
            "gpg signing takes --sign KEY-ID arguments; --keys-file serves the other engines"
                .into(),
        ));
    }
    for key in &args.sign {
        let mut signer = GpgSigner::new(key);
        if let Some(dir) = &args.gpg_homedir {
            signer = signer.with_homedir(dir);
        }
        repo.sign_static_delta(dir, &signer).await?;
    }
    Ok(())
}

#[cfg(not(feature = "gpg"))]
async fn delta_sign_gpg(_: &Repo, _: &Path, _: &DeltaGenerateArgs) -> Result<()> {
    Err(unsupported_type("gpg"))
}

/// The base64 secret keys for a delta signing run: the `--sign` values plus the
/// non-blank lines of each `--keys-file`.
fn delta_secret_keys(args: &DeltaGenerateArgs) -> Result<Vec<String>> {
    let mut keys = args.sign.clone();
    for path in &args.keys_file {
        keys.extend(read_key_lines(path)?);
    }
    if keys.is_empty() {
        return Err(Error::Signature(
            "no signing key given; pass --sign or --keys-file".into(),
        ));
    }
    Ok(keys)
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

async fn prune(args: PruneArgs) -> Result<()> {
    let repo = Repo::open(&args.repo).await?;
    let delete_commit = match args.delete_commit.as_deref() {
        Some(rev) => Some(resolve(&repo, rev).await?),
        None => None,
    };
    let opts = PruneOptions {
        refs_only: args.refs_only,
        depth: args.depth,
        no_prune: args.no_prune,
        delete_commit,
    };
    let stats = repo.prune(&opts).await?;
    println!("Total objects: {}", stats.total_objects);
    if stats.pruned_objects == 0 {
        println!("No unreachable objects");
    } else if args.no_prune {
        println!(
            "Would delete: {} objects, freeing {} bytes",
            stats.pruned_objects, stats.freed_bytes
        );
    } else {
        println!(
            "Deleted {} objects, {} bytes freed",
            stats.pruned_objects, stats.freed_bytes
        );
    }
    Ok(())
}

async fn fsck(args: FsckArgs) -> Result<()> {
    use std::io::Write;
    let repo = Repo::open(&args.repo).await?;
    let opts = FsckOptions {
        mark_partial: !args.no_mark_partial,
    };
    let report = repo.fsck(&opts).await?;
    for error in &report.errors {
        eprintln!("{error}");
    }
    println!(
        "fsck: {} commits, {} objects checked, {} error(s)",
        report.commits_checked,
        report.objects_checked,
        report.errors.len()
    );
    // Match the tool's convention: a repository with faults exits nonzero.
    std::io::stdout().flush().ok();
    if !report.is_ok() {
        std::process::exit(1);
    }
    Ok(())
}

async fn diff(args: DiffArgs) -> Result<()> {
    let repo = Repo::open(&args.repo).await?;
    let (from, to) = match args.to.as_deref() {
        Some(second) => (
            resolve(&repo, &args.from).await?,
            resolve(&repo, second).await?,
        ),
        None => {
            // With one revision, compare its parent against it.
            let rev = resolve(&repo, &args.from).await?;
            let (commit, _) = repo.load_commit(&rev).await?;
            let parent = commit.parent.ok_or_else(|| {
                Error::InvalidFormat("commit has no parent to diff against".into())
            })?;
            (parent, rev)
        }
    };
    for entry in repo.diff_commits(&from, &to).await? {
        let code = match entry.change {
            DiffChange::Added => 'A',
            DiffChange::Removed => 'D',
            DiffChange::Modified => 'M',
        };
        println!("{code}    {}", entry.path);
    }
    Ok(())
}

async fn sign(args: SignArgs) -> Result<()> {
    let repo = Repo::open(&args.repo).await?;
    let commit = resolve(&repo, &args.commit).await?;
    if args.sign_type == SignType::Gpg && !args.keys_dir.is_empty() {
        return Err(Error::Signature(
            "--keys-dir is not used by the gpg engine; supply keyrings with --keys-file".into(),
        ));
    }
    if args.sign_type != SignType::Gpg && args.gpg_homedir.is_some() {
        return Err(Error::Signature(
            "--gpg-homedir applies only to the gpg engine".into(),
        ));
    }
    if args.sign_type != SignType::Gpg && args.remote.is_some() {
        return Err(Error::Signature(
            "--remote applies only to the gpg engine".into(),
        ));
    }
    if args.verify {
        verify_signatures(&repo, &commit, &args).await
    } else if args.delete {
        delete_signatures(&repo, &commit, &args).await
    } else {
        add_signatures(&repo, &commit, &args).await
    }
}

async fn summary(args: SummaryArgs) -> Result<()> {
    let repo = Repo::open(&args.repo).await?;

    if args.verify {
        let verifier = summary_verifier(&args)?;
        let outcome = repo.verify_summary(&[verifier.as_ref()]).await?;
        report_verify(&outcome);
        if !outcome.valid {
            std::process::exit(1);
        }
        return Ok(());
    }

    if args.update {
        repo.regenerate_summary(&SummaryOptions {
            last_modified: args.last_modified,
            metadata_commit_timestamp: args.metadata_commit_timestamp,
        })
        .await?;
    }

    let signing = !args.key_id.is_empty() || !args.keys_file.is_empty();
    if signing {
        summary_sign(&repo, &args).await?;
    } else if !args.update {
        return Err(Error::InvalidFormat(
            "nothing to do: pass --update, --verify, or a signing key".into(),
        ));
    }
    Ok(())
}

/// Sign the summary once per supplied key, under the selected engine.
async fn summary_sign(repo: &Repo, args: &SummaryArgs) -> Result<()> {
    match args.sign_type {
        SignType::Ed25519 => {
            for key in summary_secret_keys(args)? {
                repo.sign_summary(&Ed25519Signer::from_base64(&key)?)
                    .await?;
            }
            Ok(())
        }
        SignType::Spki => summary_sign_spki(repo, args).await,
        SignType::Gpg => summary_sign_gpg(repo, args).await,
    }
}

#[cfg(feature = "spki")]
async fn summary_sign_spki(repo: &Repo, args: &SummaryArgs) -> Result<()> {
    for key in summary_secret_keys(args)? {
        repo.sign_summary(&SpkiSigner::from_base64(&key)?).await?;
    }
    Ok(())
}

#[cfg(not(feature = "spki"))]
async fn summary_sign_spki(_: &Repo, _: &SummaryArgs) -> Result<()> {
    Err(unsupported_type("spki"))
}

#[cfg(feature = "gpg")]
async fn summary_sign_gpg(repo: &Repo, args: &SummaryArgs) -> Result<()> {
    if !args.keys_file.is_empty() {
        return Err(Error::Signature(
            "gpg signing takes KEY-ID arguments; --keys-file keyrings serve verify".into(),
        ));
    }
    if args.key_id.is_empty() {
        return Err(Error::Signature(
            "gpg signing requires at least one KEY-ID (a fingerprint, key id, or user id)".into(),
        ));
    }
    for key in &args.key_id {
        let mut signer = GpgSigner::new(key);
        if let Some(dir) = &args.gpg_homedir {
            signer = signer.with_homedir(dir);
        }
        repo.sign_summary(&signer).await?;
    }
    Ok(())
}

#[cfg(not(feature = "gpg"))]
async fn summary_sign_gpg(_: &Repo, _: &SummaryArgs) -> Result<()> {
    Err(unsupported_type("gpg"))
}

/// The base64 secret keys for a summary signing run: the KEY-IDs plus the
/// non-blank lines of each `--keys-file`.
fn summary_secret_keys(args: &SummaryArgs) -> Result<Vec<String>> {
    let mut keys = args.key_id.clone();
    for path in &args.keys_file {
        keys.extend(read_key_lines(path)?);
    }
    if keys.is_empty() {
        return Err(Error::Signature(
            "no signing key given; pass a key argument or --keys-file".into(),
        ));
    }
    Ok(keys)
}

/// Build the verifier for `ostrya summary --verify`, mirroring `ostrya sign`.
fn summary_verifier(args: &SummaryArgs) -> Result<Box<dyn Verifier>> {
    match args.sign_type {
        SignType::Gpg => summary_gpg_verifier(args),
        engine => {
            let name = sign_type_name(engine);
            let mut trusted = Vec::new();
            for key in &args.key_id {
                trusted.push(base64::decode(key.trim())?);
            }
            for path in &args.keys_file {
                for line in read_key_lines(path)? {
                    trusted.push(base64::decode(&line)?);
                }
            }
            let mut revoked = Vec::new();
            if !args.keys_dir.is_empty() {
                let roots: Vec<&Path> = args.keys_dir.iter().map(PathBuf::as_path).collect();
                let keys = load_sign_keys_from(&roots, name)?;
                trusted.extend(keys.trusted);
                revoked.extend(keys.revoked);
            } else if trusted.is_empty() {
                let keys = load_sign_keys(name)?;
                trusted.extend(keys.trusted);
                revoked.extend(keys.revoked);
            }
            build_sign_api_verifier(engine, trusted, revoked)
        }
    }
}

#[cfg(feature = "gpg")]
fn summary_gpg_verifier(args: &SummaryArgs) -> Result<Box<dyn Verifier>> {
    let verifier = if !args.keys_file.is_empty() {
        GpgVerifier::from_keyring_files(&args.keys_file)?
    } else if let Some(remote) = &args.remote {
        GpgVerifier::for_remote(&args.repo, remote)?
    } else {
        GpgVerifier::from_system_trust()?
    };
    Ok(Box::new(verifier))
}

#[cfg(not(feature = "gpg"))]
fn summary_gpg_verifier(_: &SummaryArgs) -> Result<Box<dyn Verifier>> {
    Err(unsupported_type("gpg"))
}

/// Sign the commit once per supplied key.
async fn add_signatures(repo: &Repo, commit: &Checksum, args: &SignArgs) -> Result<()> {
    match args.sign_type {
        SignType::Ed25519 => {
            for key in secret_key_lines(args)? {
                repo.sign_commit(commit, &Ed25519Signer::from_base64(&key)?)
                    .await?;
            }
            Ok(())
        }
        SignType::Spki => sign_spki(repo, commit, args).await,
        SignType::Gpg => sign_gpg(repo, commit, args).await,
    }
}

#[cfg(feature = "spki")]
async fn sign_spki(repo: &Repo, commit: &Checksum, args: &SignArgs) -> Result<()> {
    for key in secret_key_lines(args)? {
        repo.sign_commit(commit, &SpkiSigner::from_base64(&key)?)
            .await?;
    }
    Ok(())
}

#[cfg(not(feature = "spki"))]
async fn sign_spki(_: &Repo, _: &Checksum, _: &SignArgs) -> Result<()> {
    Err(unsupported_type("spki"))
}

/// Sign with keys the `gpg` binary resolves: each KEY-ID is a fingerprint,
/// key id, or user id, looked up in the default GnuPG home directory or the
/// `--gpg-homedir` override. The private key stays with gpg and its agent,
/// including a key on a hardware token.
#[cfg(feature = "gpg")]
async fn sign_gpg(repo: &Repo, commit: &Checksum, args: &SignArgs) -> Result<()> {
    if !args.keys_file.is_empty() {
        return Err(Error::Signature(
            "gpg signing takes KEY-ID arguments; --keys-file keyrings serve verify and delete"
                .into(),
        ));
    }
    if args.key_id.is_empty() {
        return Err(Error::Signature(
            "gpg signing requires at least one KEY-ID (a fingerprint, key id, or user id)".into(),
        ));
    }
    for key in &args.key_id {
        let mut signer = GpgSigner::new(key);
        if let Some(dir) = &args.gpg_homedir {
            signer = signer.with_homedir(dir);
        }
        repo.sign_commit(commit, &signer).await?;
    }
    Ok(())
}

#[cfg(not(feature = "gpg"))]
async fn sign_gpg(_: &Repo, _: &Checksum, _: &SignArgs) -> Result<()> {
    Err(unsupported_type("gpg"))
}

/// Verify the commit under the selected engine, print each signature, and exit
/// nonzero when no signature is valid.
async fn verify_signatures(repo: &Repo, commit: &Checksum, args: &SignArgs) -> Result<()> {
    let verifier = match args.sign_type {
        SignType::Gpg => gpg_verifier(args)?,
        engine => sign_api_verifier(engine, args)?,
    };
    let outcome = repo.verify_commit(commit, &[verifier.as_ref()]).await?;
    report_verify(&outcome);
    if !outcome.valid {
        std::process::exit(1);
    }
    Ok(())
}

/// Delete signatures the given KEY-IDs match, and report the count removed.
async fn delete_signatures(repo: &Repo, commit: &Checksum, args: &SignArgs) -> Result<()> {
    if args.key_id.is_empty() {
        return Err(Error::Signature(
            "delete requires at least one KEY-ID".into(),
        ));
    }
    let removed = match args.sign_type {
        SignType::Gpg => gpg_delete(repo, commit, args).await?,
        engine => {
            // A sign-api blob belongs to a KEY-ID when it verifies under that
            // public key. Verification is async, so the blobs to remove are
            // decided up front and the predicate matches by bytes.
            let verifier = build_sign_api_verifier(engine, public_key_bytes(args)?, Vec::new())?;
            let key = sign_metadata_key(engine);
            let payload = repo.load_object_bytes(ObjectType::Commit, commit).await?;
            let mut doomed: Vec<Vec<u8>> = Vec::new();
            for blob in stored_signatures(repo, commit, key).await? {
                let valid = verifier
                    .verify(&payload, std::slice::from_ref(&blob))
                    .await
                    .map(|o| o.valid)
                    .unwrap_or(false);
                if valid {
                    doomed.push(blob);
                }
            }
            repo.delete_signatures(commit, key, |_, blob| doomed.iter().any(|d| d == blob))
                .await?
        }
    };
    println!("Deleted {removed} signature(s)");
    Ok(())
}

/// The signature blobs stored under `key` in the commit's detached metadata,
/// in stored order. Missing metadata, a missing key, or non-byte elements
/// yield an empty set.
async fn stored_signatures(repo: &Repo, commit: &Checksum, key: &str) -> Result<Vec<Vec<u8>>> {
    let Some(dict) = repo.read_commit_detached_metadata(commit).await? else {
        return Ok(Vec::new());
    };
    let Some(value) = dict.dict_get(key) else {
        return Ok(Vec::new());
    };
    let array = match value.as_variant() {
        Some((_, inner)) => inner,
        None => value,
    };
    Ok(array
        .as_array()
        .map(|blobs| {
            blobs
                .iter()
                .filter_map(|blob| blob.as_bytes().map(<[u8]>::to_vec))
                .collect()
        })
        .unwrap_or_default())
}

/// Delete GPG signatures whose issuer or primary-key fingerprint matches a
/// KEY-ID. The issuer fingerprint is reported even for a key absent from the
/// keyrings; a keyring in the trusted set (`--keys-file`, `--remote`, or the
/// default `trusted.gpg.d`) lets a match also consider the primary-key
/// fingerprint of a verified signature.
#[cfg(feature = "gpg")]
async fn gpg_delete(repo: &Repo, commit: &Checksum, args: &SignArgs) -> Result<usize> {
    let wanted: Vec<String> = args
        .key_id
        .iter()
        .map(|k| normalize_fingerprint(k))
        .collect();
    let verifier = gpg_trust(args)?;
    let payload = repo.load_object_bytes(ObjectType::Commit, commit).await?;
    let mut doomed: Vec<Vec<u8>> = Vec::new();
    for blob in stored_signatures(repo, commit, "ostree.gpgsigs").await? {
        let matches = match verifier.verify(&payload, std::slice::from_ref(&blob)).await {
            Ok(outcome) => outcome.signatures.iter().any(|s| {
                fingerprint_matches(s.fingerprint.as_deref(), &wanted)
                    || fingerprint_matches(s.primary_fingerprint.as_deref(), &wanted)
            }),
            Err(_) => false,
        };
        if matches {
            doomed.push(blob);
        }
    }
    repo.delete_signatures(commit, "ostree.gpgsigs", |_, blob| {
        doomed.iter().any(|d| d == blob)
    })
    .await
}

#[cfg(not(feature = "gpg"))]
async fn gpg_delete(_: &Repo, _: &Checksum, _: &SignArgs) -> Result<usize> {
    Err(unsupported_type("gpg"))
}

/// Build a sign-api (ed25519/spki) verifier from the KEY-IDs, the `--keys-file`
/// keys, and the trusted/revoked key directories: `--keys-dir` if given,
/// otherwise the system store when nothing was supplied inline.
fn sign_api_verifier(engine: SignType, args: &SignArgs) -> Result<Box<dyn Verifier>> {
    let name = sign_type_name(engine);
    let mut trusted = public_key_bytes(args)?;
    let mut revoked: Vec<Vec<u8>> = Vec::new();
    if !args.keys_dir.is_empty() {
        let roots: Vec<&Path> = args.keys_dir.iter().map(PathBuf::as_path).collect();
        let keys = load_sign_keys_from(&roots, name)?;
        trusted.extend(keys.trusted);
        revoked.extend(keys.revoked);
    } else if trusted.is_empty() {
        let keys = load_sign_keys(name)?;
        trusted.extend(keys.trusted);
        revoked.extend(keys.revoked);
    }
    build_sign_api_verifier(engine, trusted, revoked)
}

fn build_sign_api_verifier(
    engine: SignType,
    trusted: Vec<Vec<u8>>,
    revoked: Vec<Vec<u8>>,
) -> Result<Box<dyn Verifier>> {
    match engine {
        SignType::Ed25519 => Ok(Box::new(Ed25519Verifier::new(trusted, revoked)?)),
        #[cfg(feature = "spki")]
        SignType::Spki => Ok(Box::new(SpkiVerifier::new(trusted, revoked)?)),
        #[cfg(not(feature = "spki"))]
        SignType::Spki => Err(unsupported_type("spki")),
        SignType::Gpg => Err(Error::Signature("gpg is not a sign-api engine".into())),
    }
}

#[cfg(feature = "gpg")]
fn gpg_verifier(args: &SignArgs) -> Result<Box<dyn Verifier>> {
    Ok(Box::new(gpg_trust(args)?))
}

#[cfg(not(feature = "gpg"))]
fn gpg_verifier(_: &SignArgs) -> Result<Box<dyn Verifier>> {
    Err(unsupported_type("gpg"))
}

/// The gpg trusted keyring set for verify and delete: the `--keys-file`
/// keyrings when any are given, otherwise the default ostree trust -- the
/// global `trusted.gpg.d` directory (or `$OSTREE_GPG_HOME`) plus, when
/// `--remote` names a remote, that remote's `trustedkeys.gpg`.
#[cfg(feature = "gpg")]
fn gpg_trust(args: &SignArgs) -> Result<GpgVerifier> {
    if !args.keys_file.is_empty() {
        return GpgVerifier::from_keyring_files(&args.keys_file);
    }
    match &args.remote {
        Some(remote) => GpgVerifier::for_remote(&args.repo, remote),
        None => GpgVerifier::from_system_trust(),
    }
}

/// The base64 secret keys for a sign-api signing run: the KEY-IDs plus the
/// non-blank lines of each `--keys-file`. At least one key is required.
fn secret_key_lines(args: &SignArgs) -> Result<Vec<String>> {
    let mut keys = args.key_id.clone();
    for path in &args.keys_file {
        keys.extend(read_key_lines(path)?);
    }
    if keys.is_empty() {
        return Err(Error::Signature(
            "no signing key given; pass a key argument or --keys-file".into(),
        ));
    }
    Ok(keys)
}

/// The decoded public keys for sign-api verify/delete: the KEY-IDs and the
/// `--keys-file` lines, each a base64-encoded key.
fn public_key_bytes(args: &SignArgs) -> Result<Vec<Vec<u8>>> {
    let mut keys = Vec::new();
    for key in &args.key_id {
        keys.push(base64::decode(key.trim())?);
    }
    for path in &args.keys_file {
        for line in read_key_lines(path)? {
            keys.push(base64::decode(&line)?);
        }
    }
    Ok(keys)
}

/// The non-blank, trimmed lines of a key file.
fn read_key_lines(path: &Path) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path).map_err(Error::Io)?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect())
}

/// The engine's short name, used for the `trusted.<name>` / `revoked.<name>`
/// key-store files.
fn sign_type_name(engine: SignType) -> &'static str {
    match engine {
        SignType::Ed25519 => "ed25519",
        SignType::Spki => "spki",
        SignType::Gpg => "gpg",
    }
}

/// The detached-metadata dict key each engine's signatures accumulate under.
fn sign_metadata_key(engine: SignType) -> &'static str {
    match engine {
        SignType::Ed25519 => "ostree.sign.ed25519",
        SignType::Spki => "ostree.sign.spki",
        SignType::Gpg => "ostree.gpgsigs",
    }
}

/// Normalize a GPG fingerprint or key id for suffix matching: drop a `0x`
/// prefix and internal spaces, and upper-case the hex.
#[cfg(feature = "gpg")]
fn normalize_fingerprint(id: &str) -> String {
    id.trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .replace(' ', "")
        .to_uppercase()
}

/// Whether a stored fingerprint ends with any of the wanted key ids (so a short
/// key id matches the tail of a full fingerprint).
#[cfg(feature = "gpg")]
fn fingerprint_matches(stored: Option<&str>, wanted: &[String]) -> bool {
    match stored {
        Some(fpr) => {
            let fpr = fpr.to_uppercase();
            wanted
                .iter()
                .any(|w| !w.is_empty() && fpr.ends_with(w.as_str()))
        }
        None => false,
    }
}

/// An error reported when a sign-type's engine was compiled out of this binary.
#[cfg_attr(all(feature = "spki", feature = "gpg"), allow(dead_code))]
fn unsupported_type(name: &str) -> Error {
    Error::Unsupported(format!(
        "sign-type '{name}' requires building ostrya-cli with the '{name}' feature"
    ))
}

/// Print one line per examined signature and a final verdict.
fn report_verify(outcome: &VerifyOutcome) {
    if outcome.signatures.is_empty() {
        println!("no signatures found");
        return;
    }
    for (i, sig) in outcome.signatures.iter().enumerate() {
        let status = if sig.valid {
            "good"
        } else if sig.key_missing {
            "no public key"
        } else {
            "BAD"
        };
        let mut line = format!("signature {}: {status}", i + 1);
        if let Some(fpr) = &sig.fingerprint {
            line.push_str(&format!(" key {fpr}"));
        }
        match (&sig.user_name, &sig.user_email) {
            (Some(name), Some(email)) => line.push_str(&format!(" ({name} <{email}>)")),
            (Some(name), None) => line.push_str(&format!(" ({name})")),
            (None, Some(email)) => line.push_str(&format!(" (<{email}>)")),
            (None, None) => {}
        }
        println!("{line}");
    }
    println!(
        "{}",
        if outcome.valid {
            "verification OK"
        } else {
            "verification FAILED"
        }
    );
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
