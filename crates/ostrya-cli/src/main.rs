#![forbid(unsafe_code)]

//! The `ostrya` command-line front-end.
//!
//! A thin binary over the ingest, checkout, and export paths of the `ostrya`
//! library (Phase 11 of `docs/port-plan.md`), growing an `ostree`-compatible
//! surface since Phase 17. `--repo`, `-v`/`--verbose`, and `--version` are
//! global: each is accepted both before and after the subcommand name, the
//! subcommand-position value winning when both are given, matching the tool
//! (`docs/conformance/cli-surface.md`, "Global conventions"). With no `--repo`
//! given, the current directory is used when it opens as a repository,
//! otherwise `OSTREE_REPO`; with neither, the subcommand's usage text and
//! `error: Command requires a --repo argument` go to standard error and the
//! process exits 1. `init` shares this precedence: a cwd/`OSTREE_REPO` target
//! that already opens as a repository is reused (an idempotent re-init); a
//! target that does not never gets created by the fallback, only by an
//! explicit `--repo`. The subcommands are:
//!
//! - `init` -- create a repository in the given mode.
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
//! - `pull` -- fetch refs and their objects from an HTTP remote.
//! - `pull-local` -- import refs and their objects from another local
//!   repository.
//!
//! The binary is synchronous and drives the async library with
//! [`ostrya_rt::block_on`]. Tar streams to and from stdin/stdout flow through
//! [`ostrya_rt::File`] over a duplicated descriptor, so no unbounded stream is
//! buffered in memory.

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use ostrya::{
    CheckoutMode, CheckoutOptions, Checksum, CommitModifier, CommitModifierFlags, CommitOptions,
    CreateOptions, DeltaOptions, DiffChange, Ed25519Signer, Ed25519Verifier, Error, FsckOptions,
    MutableTree, ObjectType, PruneOptions, PullFlags, PullOptions, PullStats, PullVerify, Repo,
    RepoMode, Result, SummaryOptions, TarExportOptions, TarImportOptions, TimestampCheck, Type,
    Value, Verifier, VerifyOutcome, base64, load_sign_keys, load_sign_keys_from,
};
#[cfg(feature = "gpg")]
use ostrya::{GpgSigner, GpgVerifier};
#[cfg(feature = "spki")]
use ostrya::{SpkiSigner, SpkiVerifier};

/// A pure-Rust front-end over the ostrya repository library.
#[derive(Parser)]
#[command(name = "ostrya", about, long_about = None)]
struct Cli {
    /// The repository to operate on; accepted before or after the subcommand
    /// name, with the subcommand-position value winning when both are given.
    /// With neither, the current directory is used when it opens as a
    /// repository, else the `OSTREE_REPO` environment variable (`init`
    /// reuses an existing repository resolved this way, but never creates a
    /// new one without this option).
    #[arg(long, global = true)]
    repo: Option<PathBuf>,
    /// Print debug information during command processing.
    #[arg(short, long, global = true)]
    verbose: bool,
    /// Print version information and exit.
    #[arg(long, global = true)]
    version: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a new empty repository.
    Init(InitArgs),
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
    /// Fetch refs and their objects from an HTTP remote.
    Pull(PullArgs),
    /// Import refs and their objects from another local repository.
    #[command(name = "pull-local")]
    PullLocal(PullLocalArgs),
}

impl Command {
    /// Every name [`Command::name`] returns. The test at the end of this file
    /// holds this list and `clap`'s own subcommand set to each other, so a
    /// renamed or an added subcommand fails a test rather than the
    /// usage-text lookup on an error path.
    #[cfg(test)]
    const NAMES: &'static [&'static str] = &[
        "init",
        "commit",
        "checkout",
        "export",
        "prune",
        "fsck",
        "diff",
        "sign",
        "summary",
        "static-delta",
        "pull",
        "pull-local",
    ];

    /// The name `clap` registered this subcommand under, which the error paths
    /// use to render its usage text.
    fn name(&self) -> &'static str {
        match self {
            Command::Init(_) => "init",
            Command::Commit(_) => "commit",
            Command::Checkout(_) => "checkout",
            Command::Export(_) => "export",
            Command::Prune(_) => "prune",
            Command::Fsck(_) => "fsck",
            Command::Diff(_) => "diff",
            Command::Sign(_) => "sign",
            Command::Summary(_) => "summary",
            Command::StaticDelta(_) => "static-delta",
            Command::Pull(_) => "pull",
            Command::PullLocal(_) => "pull-local",
        }
    }
}

#[derive(Args)]
struct InitArgs {
    /// The repository mode: archive (an alias for archive-z2), archive-z2,
    /// bare, bare-user, bare-user-only, or the port extension
    /// bare-user-shared.
    #[arg(long, default_value = "bare")]
    mode: String,
    /// A globally unique id for this repository as a collection of refs.
    #[arg(long = "collection-id")]
    collection_id: Option<String>,
}

#[derive(Args)]
struct CommitArgs {
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
    /// The commit to export (a checksum or a ref). Required; checked after
    /// the repository resolves, matching the tool's error-ordering
    /// (`docs/conformance/cli-surface.md`, "Global conventions").
    commit: Option<String>,
}

#[derive(Args)]
struct PruneArgs {
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
    /// Do not mark commits partial when a referenced object is missing.
    #[arg(long)]
    no_mark_partial: bool,
}

#[derive(Args)]
struct DiffArgs {
    /// The first revision. With no second revision, its parent is compared
    /// against it. Required; checked after the repository resolves, matching
    /// the tool's error-ordering (`docs/conformance/cli-surface.md`, "Global
    /// conventions").
    from: Option<String>,
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
    /// The commit to operate on (a checksum or a ref). Required; checked
    /// after the repository resolves, matching the tool's error-ordering
    /// (`docs/conformance/cli-surface.md`, "Global conventions").
    commit: Option<String>,
    /// Key identifiers: base64 keys for ed25519/spki. For gpg: the signing
    /// key gpg resolves (a fingerprint, key id, or user id), or, with
    /// --delete, the fingerprints to remove.
    key_id: Vec<String>,
}

#[derive(Args)]
struct SummaryArgs {
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
    /// Optional at the argument-parsing layer so a missing one is reported
    /// with the tool's own text, before the repository resolves, matching the
    /// tool's error-ordering (`docs/conformance/cli-surface.md`, "Global
    /// conventions").
    #[command(subcommand)]
    command: Option<StaticDeltaCommand>,
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

#[derive(Args)]
struct PullArgs {
    /// Fetch from this URL instead of the remote's configured `url`. A remote
    /// the config does not describe can be pulled from this way; it supplies no
    /// keys, so such a pull states its own signature policy or is refused.
    #[arg(long)]
    url: Option<String>,
    /// Write the pulled refs as local refs, take every ref the remote's summary
    /// lists when none are named, and copy the remote's summary here.
    #[arg(long)]
    mirror: bool,
    /// Parents of each pulled commit to follow: 0 for the commit alone, -1 for
    /// the whole ancestry the remote holds.
    #[arg(long, default_value_t = 0, allow_negative_numbers = true)]
    depth: i32,
    /// Fetch only the commit objects, leaving each commit marked partial.
    #[arg(long)]
    commit_metadata_only: bool,
    /// Reject regular files whose mode has bits outside 0775.
    #[arg(long)]
    bareuseronly_files: bool,
    /// Do not check that a pulled commit's ostree.ref-binding names the ref it
    /// is pulled under.
    #[arg(long)]
    disable_verify_bindings: bool,
    /// Copy each object a localcache repository supplies instead of
    /// hardlinking it.
    #[arg(long)]
    force_copy: bool,
    /// Consult this repository for an object before the network; repeatable.
    #[arg(short = 'L', long = "localcache-repo")]
    localcache_repo: Vec<PathBuf>,
    /// Send NAME=VALUE as an HTTP header with every request; repeatable.
    #[arg(long = "http-header", value_name = "NAME=VALUE", value_parser = parse_http_header)]
    http_header: Vec<(String, String)>,
    /// How many fetches to keep in flight (default: 8).
    #[arg(long, value_name = "N")]
    max_outstanding_fetcher_requests: Option<usize>,
    /// How many times to repeat a round of mirrors after a retryable failure
    /// (default: 5).
    #[arg(long, value_name = "N")]
    network_retries: Option<u32>,
    /// Require each fetched tip to be no older than the commit its ref names in
    /// this repository.
    #[arg(short = 'T', long)]
    timestamp_check: bool,
    /// Require each fetched tip to be no older than this commit, which this
    /// repository must hold.
    #[arg(long, value_name = "REV", conflicts_with = "timestamp_check")]
    timestamp_check_from_rev: Option<String>,
    /// Fetch every object loose, ignoring any static delta the remote
    /// advertises. This wins over --require-static-deltas.
    #[arg(long)]
    disable_static_deltas: bool,
    /// Refuse a remote that advertises no static delta at all.
    #[arg(long)]
    require_static_deltas: bool,
    /// Require a GPG signature on every commit the pull carries. Absent, the
    /// remote's `gpg-verify` applies (default true); `--gpg-verify` requires
    /// one; `--gpg-verify=false` requires none.
    #[arg(long, require_equals = true, num_args = 0..=1, default_missing_value = "true", value_name = "BOOL")]
    gpg_verify: Option<bool>,
    /// Require a GPG signature on the remote's summary. Absent, the remote's
    /// `gpg-verify-summary` applies (default false); `--gpg-verify-summary`
    /// requires one; `--gpg-verify-summary=false` requires none.
    #[arg(long, require_equals = true, num_args = 0..=1, default_missing_value = "true", value_name = "BOOL")]
    gpg_verify_summary: Option<bool>,
    /// Require a sign-api signature on every commit the pull carries. Absent,
    /// the remote's `sign-verify` applies (default off); `--sign-verify`
    /// requires one, selecting every engine this build has;
    /// `--sign-verify=false` requires none.
    #[arg(long, require_equals = true, num_args = 0..=1, default_missing_value = "true", value_name = "BOOL")]
    sign_verify: Option<bool>,
    /// Require a sign-api signature on the remote's summary. Absent, the
    /// remote's `sign-verify-summary` applies (default off);
    /// `--sign-verify-summary` requires one; `--sign-verify-summary=false`
    /// requires none.
    #[arg(long, require_equals = true, num_args = 0..=1, default_missing_value = "true", value_name = "BOOL")]
    sign_verify_summary: Option<bool>,
    /// The remote to pull from: a `[remote "<name>"]` section of this
    /// repository's config, which also names the prefix the refs are written
    /// under. Required; checked after the repository resolves, matching the
    /// tool's error-ordering (`docs/conformance/cli-surface.md`, "Global
    /// conventions").
    remote: Option<String>,
    /// The refs to pull; with none, the remote's configured `branches`, or
    /// every ref its summary lists under --mirror.
    refs: Vec<String>,
}

#[derive(Args)]
struct PullLocalArgs {
    /// Write the pulled refs under this remote (`refs/remotes/<remote>/<ref>`)
    /// instead of as local refs.
    #[arg(long)]
    remote: Option<String>,
    /// Parents of each pulled commit to follow: 0 for the commit alone, -1 for
    /// the whole ancestry the source holds.
    #[arg(long, default_value_t = 0, allow_negative_numbers = true)]
    depth: i32,
    /// Import only the commit objects, leaving each commit marked partial.
    #[arg(long)]
    commit_metadata_only: bool,
    /// Verify every imported object's checksum against its name.
    #[arg(long)]
    untrusted: bool,
    /// Reject regular files whose mode has bits outside 0775.
    #[arg(long)]
    bareuseronly_files: bool,
    /// Do not check that a pulled commit's ostree.ref-binding names the ref it
    /// is pulled under.
    #[arg(long)]
    disable_verify_bindings: bool,
    /// Copy every object instead of hardlinking it.
    #[arg(long)]
    force_copy: bool,
    /// Consult this repository for objects the source does not hold;
    /// repeatable.
    #[arg(short = 'L', long = "localcache-repo")]
    localcache_repo: Vec<PathBuf>,
    /// The repository to pull from. Required; checked after the repository
    /// resolves, matching the tool's error-ordering
    /// (`docs/conformance/cli-surface.md`, "Global conventions").
    src_repo: Option<PathBuf>,
    /// The refs to pull; with none, every ref the source holds.
    refs: Vec<String>,
}

fn main() -> std::process::ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            err.print().ok();
            let code = match err.kind() {
                clap::error::ErrorKind::DisplayHelp => 0,
                _ => 1,
            };
            return std::process::ExitCode::from(code);
        }
    };
    if cli.version {
        println!("ostrya {}", env!("CARGO_PKG_VERSION"));
        return std::process::ExitCode::SUCCESS;
    }
    let Some(command) = cli.command else {
        exit_no_command();
    };
    match ostrya_rt::block_on(run(cli.repo.as_deref(), cli.verbose, command)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(repo: Option<&Path>, verbose: bool, command: Command) -> Result<()> {
    let name = command.name();
    match command {
        Command::Init(args) => init(repo, verbose, name, args).await,
        Command::Commit(args) => {
            let (repo, _) = resolve_repo(repo, verbose, name).await;
            commit(repo, args).await
        }
        Command::Checkout(args) => {
            let (repo, _) = resolve_repo(repo, verbose, name).await;
            checkout(repo, args).await
        }
        Command::Export(args) => {
            let (repo, _) = resolve_repo(repo, verbose, name).await;
            export(repo, name, args).await
        }
        Command::Prune(args) => {
            let (repo, _) = resolve_repo(repo, verbose, name).await;
            prune(repo, args).await
        }
        Command::Fsck(args) => {
            let (repo, _) = resolve_repo(repo, verbose, name).await;
            fsck(repo, args).await
        }
        Command::Diff(args) => {
            let (repo, _) = resolve_repo(repo, verbose, name).await;
            diff(repo, name, args).await
        }
        Command::Sign(args) => {
            let (repo, path) = resolve_repo(repo, verbose, name).await;
            sign(repo, path, name, args).await
        }
        Command::Summary(args) => {
            let (repo, path) = resolve_repo(repo, verbose, name).await;
            summary(repo, path, args).await
        }
        Command::StaticDelta(args) => {
            // The tool reports a missing nested subcommand before it resolves
            // the repository, so this check comes first.
            let Some(sub) = args.command else {
                exit_with_error(name, "No command specified");
            };
            let (repo, path) = resolve_repo(repo, verbose, name).await;
            static_delta(repo, path, sub).await
        }
        Command::Pull(args) => {
            let (repo, _) = resolve_repo(repo, verbose, name).await;
            pull(repo, name, args).await
        }
        Command::PullLocal(args) => {
            let (repo, _) = resolve_repo(repo, verbose, name).await;
            pull_local(repo, name, args).await
        }
    }
}

/// Print the top-level usage text and the tool's own error line for a bare
/// invocation, and exit like the tool does.
fn exit_no_command() -> ! {
    eprint!("{}", <Cli as CommandFactory>::command().render_help());
    eprintln!("error: No command specified");
    std::process::exit(1);
}

/// Print `subcommand`'s usage text and `error: {message}`, then exit 1,
/// matching the tool's own two-line error shape (usage block, then an
/// `error: ` line) for a missing repository, a missing required operand, and a
/// missing nested subcommand (`docs/conformance/cli-surface.md`, "Global
/// conventions").
fn exit_with_error(subcommand: &str, message: &str) -> ! {
    let mut top = <Cli as CommandFactory>::command();
    let sub = top
        .find_subcommand_mut(subcommand)
        .expect("subcommand name matches a defined command");
    eprint!("{}", sub.render_help());
    eprintln!("error: {message}");
    std::process::exit(1);
}

/// Print `subcommand`'s usage text and the tool's own "no repo" error line,
/// then exit 1, matching the tool's behavior when no repository can be
/// resolved (`docs/conformance/cli-surface.md`, "Global conventions").
fn exit_requires_repo(subcommand: &str) -> ! {
    exit_with_error(subcommand, "Command requires a --repo argument")
}

/// Resolve the repository a subcommand operates on and the filesystem path
/// used to reach it, applying the tool's precedence: an explicit `--repo`
/// (either position) first; then the current directory, if it opens as a
/// repository; then `OSTREE_REPO`. With none of those, print `subcommand`'s
/// usage text and the tool's error line and exit. `init` shares this
/// precedence too, through `resolve_init_path`, below, which resolves to a
/// path rather than an opened `Repo` since its explicit-`--repo` tier need
/// not already exist.
async fn resolve_repo(repo: Option<&Path>, verbose: bool, subcommand: &str) -> (Repo, PathBuf) {
    if let Some(path) = repo {
        match Repo::open(path).await {
            Ok(repo) => {
                if verbose {
                    eprintln!("ostrya: using repository {}", path.display());
                }
                return (repo, path.to_owned());
            }
            Err(err) => {
                eprintln!("error: opening repo: {err}");
                std::process::exit(1);
            }
        }
    }
    let cwd = Path::new(".");
    if let Ok(repo) = Repo::open(cwd).await {
        if verbose {
            eprintln!("ostrya: using repository {}", cwd.display());
        }
        return (repo, cwd.to_owned());
    }
    if let Ok(val) = std::env::var("OSTREE_REPO") {
        let path = PathBuf::from(val);
        if let Ok(repo) = Repo::open(&path).await {
            if verbose {
                eprintln!("ostrya: using repository {}", path.display());
            }
            return (repo, path);
        }
    }
    exit_requires_repo(subcommand);
}

/// Resolve the path `init` creates or reuses a repository at. The precedence
/// matches `resolve_repo`, but an explicit `--repo` is used as given, valid or
/// not, since a freshly created repository need not already exist there; only
/// the cwd and `OSTREE_REPO` fallbacks require the path to already open as a
/// repository (an idempotent re-init), since `init` never creates a
/// brand-new repository at a path it did not receive explicitly.
async fn resolve_init_path(repo: Option<&Path>, subcommand: &str) -> PathBuf {
    if let Some(path) = repo {
        return path.to_owned();
    }
    let cwd = Path::new(".");
    if Repo::open(cwd).await.is_ok() {
        return cwd.to_owned();
    }
    if let Ok(val) = std::env::var("OSTREE_REPO") {
        let path = PathBuf::from(val);
        if Repo::open(&path).await.is_ok() {
            return path;
        }
    }
    exit_requires_repo(subcommand);
}

/// Create a new empty repository, or idempotently reuse one that already
/// exists at the resolved path, matching `Repo::create`'s own idempotence.
async fn init(repo: Option<&Path>, verbose: bool, name: &str, args: InitArgs) -> Result<()> {
    let path = resolve_init_path(repo, name).await;
    let mode = parse_init_mode(&args.mode);
    Repo::create(
        &path,
        CreateOptions {
            mode,
            collection_id: args.collection_id,
        },
    )
    .await?;
    if verbose {
        eprintln!("ostrya: using repository {}", path.display());
    }
    Ok(())
}

/// The repository modes `ostrya init --mode` accepts, matching the tool's set
/// for the modes both implementations support. `bare-split-xattrs` is
/// excluded even though the tool's own `init --mode` accepts it: the port
/// reads that mode and does not write it (`format-reference.md`, "Repository
/// modes and on-disk storage"), so exposing it here would create a repository
/// nothing in the port could subsequently commit into.
fn parse_init_mode(mode: &str) -> RepoMode {
    match mode {
        "bare" => RepoMode::Bare,
        "bare-user" => RepoMode::BareUser,
        "bare-user-only" => RepoMode::BareUserOnly,
        "archive" | "archive-z2" => RepoMode::Archive,
        "bare-user-shared" => RepoMode::BareUserShared,
        _ => {
            eprintln!("error: Invalid mode '{mode}' in repository configuration");
            std::process::exit(1);
        }
    }
}

/// Fetch refs and their objects from an HTTP remote.
async fn pull(repo: Repo, name: &str, args: PullArgs) -> Result<()> {
    let Some(remote) = args.remote.as_deref() else {
        exit_with_error(name, "REMOTE must be specified");
    };
    let mut localcache_repos = Vec::with_capacity(args.localcache_repo.len());
    for path in &args.localcache_repo {
        localcache_repos.push(Repo::open(path).await?);
    }

    let mut flags = PullFlags::empty();
    if args.mirror {
        flags |= PullFlags::MIRROR;
    }
    if args.commit_metadata_only {
        flags |= PullFlags::COMMIT_ONLY;
    }
    if args.bareuseronly_files {
        flags |= PullFlags::BAREUSERONLY_FILES;
    }
    if args.disable_verify_bindings {
        flags |= PullFlags::DISABLE_VERIFY_BINDINGS;
    }
    if args.force_copy {
        flags |= PullFlags::FORCE_COPY;
    }

    let timestamp_check = match args.timestamp_check_from_rev.as_deref() {
        Some(rev) => TimestampCheck::Rev(resolve(&repo, rev).await?),
        None if args.timestamp_check => TimestampCheck::CurrentRef,
        None => TimestampCheck::Off,
    };

    let stats = repo
        .pull(
            remote,
            PullOptions {
                refs: args.refs,
                flags,
                depth: args.depth,
                localcache_repos,
                url: args.url,
                http_headers: args.http_header,
                max_outstanding_fetches: args.max_outstanding_fetcher_requests,
                n_network_retries: args.network_retries,
                timestamp_check,
                disable_static_deltas: args.disable_static_deltas,
                require_static_deltas: args.require_static_deltas,
                verify: PullVerify {
                    gpg: args.gpg_verify,
                    gpg_summary: args.gpg_verify_summary,
                    sign: args.sign_verify,
                    sign_summary: args.sign_verify_summary,
                },
                ..PullOptions::default()
            },
        )
        .await?;
    report_pull(&stats);
    Ok(())
}

/// Split a `NAME=VALUE` header argument at its first `=`.
fn parse_http_header(arg: &str) -> std::result::Result<(String, String), String> {
    match arg.split_once('=') {
        Some((name, value)) if !name.is_empty() => Ok((name.to_owned(), value.to_owned())),
        _ => Err("expected NAME=VALUE".to_owned()),
    }
}

/// Print what a pull imported.
fn report_pull(stats: &PullStats) {
    println!(
        "{} metadata, {} content objects imported; {} bytes content written",
        stats.metadata_imported, stats.content_imported, stats.content_bytes_written
    );
}

/// Import refs and their objects from another local repository.
async fn pull_local(repo: Repo, name: &str, args: PullLocalArgs) -> Result<()> {
    let Some(src_repo) = args.src_repo.as_deref() else {
        // The tool's own message names DESTINATION, not SRC_REPO, for this
        // case -- an observed quirk, not a transcription error here.
        exit_with_error(name, "DESTINATION must be specified");
    };
    let src = Repo::open(src_repo).await?;
    let mut localcache_repos = Vec::with_capacity(args.localcache_repo.len());
    for path in &args.localcache_repo {
        localcache_repos.push(Repo::open(path).await?);
    }

    let mut flags = PullFlags::empty();
    if args.commit_metadata_only {
        flags |= PullFlags::COMMIT_ONLY;
    }
    if args.untrusted {
        flags |= PullFlags::UNTRUSTED;
    }
    if args.bareuseronly_files {
        flags |= PullFlags::BAREUSERONLY_FILES;
    }
    if args.disable_verify_bindings {
        flags |= PullFlags::DISABLE_VERIFY_BINDINGS;
    }
    if args.force_copy {
        flags |= PullFlags::FORCE_COPY;
    }

    let stats = repo
        .pull_local(
            &src,
            PullOptions {
                refs: args.refs,
                remote: args.remote,
                flags,
                depth: args.depth,
                localcache_repos,
                ..PullOptions::default()
            },
        )
        .await?;
    report_pull(&stats);
    Ok(())
}

/// List the repository's static deltas, apply one offline, generate one, or
/// rebuild the index cache.
async fn static_delta(repo: Repo, repo_path: PathBuf, command: StaticDeltaCommand) -> Result<()> {
    match command {
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
        StaticDeltaCommand::Generate(generate) => delta_generate(&repo, &repo_path, generate).await,
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

async fn commit(repo: Repo, args: CommitArgs) -> Result<()> {
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

async fn checkout(repo: Repo, args: CheckoutArgs) -> Result<()> {
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

async fn export(repo: Repo, name: &str, args: ExportArgs) -> Result<()> {
    let Some(commit) = args.commit.as_deref() else {
        exit_with_error(name, "A COMMIT argument is required");
    };
    let commit = resolve(&repo, commit).await?;
    let stdout = stdout_file()?;
    repo.export_tar(&commit, TarExportOptions::new(), stdout)
        .await
}

async fn prune(repo: Repo, args: PruneArgs) -> Result<()> {
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

async fn fsck(repo: Repo, args: FsckArgs) -> Result<()> {
    use std::io::Write;
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

async fn diff(repo: Repo, name: &str, args: DiffArgs) -> Result<()> {
    let Some(from_rev) = args.from.as_deref() else {
        exit_with_error(name, "REV must be specified");
    };
    let (from, to) = match args.to.as_deref() {
        Some(second) => (
            resolve(&repo, from_rev).await?,
            resolve(&repo, second).await?,
        ),
        None => {
            // With one revision, compare its parent against it.
            let rev = resolve(&repo, from_rev).await?;
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

async fn sign(repo: Repo, repo_path: PathBuf, name: &str, args: SignArgs) -> Result<()> {
    let Some(commit_rev) = args.commit.as_deref() else {
        exit_with_error(name, "Need a COMMIT to sign or verify");
    };
    let commit = resolve(&repo, commit_rev).await?;
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
        verify_signatures(&repo, &commit, &repo_path, &args).await
    } else if args.delete {
        delete_signatures(&repo, &commit, &repo_path, &args).await
    } else {
        add_signatures(&repo, &commit, &args).await
    }
}

async fn summary(repo: Repo, repo_path: PathBuf, args: SummaryArgs) -> Result<()> {
    if args.verify {
        let verifier = summary_verifier(&repo_path, &args)?;
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
fn summary_verifier(repo_path: &Path, args: &SummaryArgs) -> Result<Box<dyn Verifier>> {
    match args.sign_type {
        SignType::Gpg => summary_gpg_verifier(repo_path, args),
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
fn summary_gpg_verifier(repo_path: &Path, args: &SummaryArgs) -> Result<Box<dyn Verifier>> {
    let verifier = if !args.keys_file.is_empty() {
        GpgVerifier::from_keyring_files(&args.keys_file)?
    } else if let Some(remote) = &args.remote {
        GpgVerifier::for_remote(repo_path, remote)?
    } else {
        GpgVerifier::from_system_trust()?
    };
    Ok(Box::new(verifier))
}

#[cfg(not(feature = "gpg"))]
fn summary_gpg_verifier(_: &Path, _: &SummaryArgs) -> Result<Box<dyn Verifier>> {
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
async fn verify_signatures(
    repo: &Repo,
    commit: &Checksum,
    repo_path: &Path,
    args: &SignArgs,
) -> Result<()> {
    let verifier = match args.sign_type {
        SignType::Gpg => gpg_verifier(repo_path, args)?,
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
async fn delete_signatures(
    repo: &Repo,
    commit: &Checksum,
    repo_path: &Path,
    args: &SignArgs,
) -> Result<()> {
    if args.key_id.is_empty() {
        return Err(Error::Signature(
            "delete requires at least one KEY-ID".into(),
        ));
    }
    let removed = match args.sign_type {
        SignType::Gpg => gpg_delete(repo, commit, repo_path, args).await?,
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
async fn gpg_delete(
    repo: &Repo,
    commit: &Checksum,
    repo_path: &Path,
    args: &SignArgs,
) -> Result<usize> {
    let wanted: Vec<String> = args
        .key_id
        .iter()
        .map(|k| normalize_fingerprint(k))
        .collect();
    let verifier = gpg_trust(repo_path, args)?;
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
async fn gpg_delete(_: &Repo, _: &Checksum, _: &Path, _: &SignArgs) -> Result<usize> {
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
fn gpg_verifier(repo_path: &Path, args: &SignArgs) -> Result<Box<dyn Verifier>> {
    Ok(Box::new(gpg_trust(repo_path, args)?))
}

#[cfg(not(feature = "gpg"))]
fn gpg_verifier(_: &Path, _: &SignArgs) -> Result<Box<dyn Verifier>> {
    Err(unsupported_type("gpg"))
}

/// The gpg trusted keyring set for verify and delete: the `--keys-file`
/// keyrings when any are given, otherwise the default ostree trust -- the
/// global `trusted.gpg.d` directory (or `$OSTREE_GPG_HOME`) plus, when
/// `--remote` names a remote, that remote's `trustedkeys.gpg`.
#[cfg(feature = "gpg")]
fn gpg_trust(repo_path: &Path, args: &SignArgs) -> Result<GpgVerifier> {
    if !args.keys_file.is_empty() {
        return GpgVerifier::from_keyring_files(&args.keys_file);
    }
    match &args.remote {
        Some(remote) => GpgVerifier::for_remote(repo_path, remote),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The error paths render a subcommand's usage text by name, so a name
    /// `clap` does not know would abort the process instead of printing. This
    /// holds [`Command::NAMES`] and `clap`'s own set to each other in both
    /// directions, so a renamed or an added subcommand fails here.
    #[test]
    fn every_subcommand_name_renders_its_usage_text() {
        let mut top = <Cli as CommandFactory>::command();
        let registered: Vec<String> = top
            .get_subcommands()
            .map(|sub| sub.get_name().to_owned())
            .filter(|name| name != "help")
            .collect();
        for name in Command::NAMES {
            assert!(
                top.find_subcommand_mut(name).is_some(),
                "`{name}` names no defined subcommand"
            );
        }
        for name in &registered {
            assert!(
                Command::NAMES.contains(&name.as_str()),
                "subcommand `{name}` is missing from Command::NAMES"
            );
        }
        assert_eq!(registered.len(), Command::NAMES.len());
    }
}
