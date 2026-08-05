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
//! - `refs` -- list, create, or delete refs, aliases, and collection refs.
//! - `rev-parse` -- print the commit a revision names.
//! - `cat` -- write a commit's files to stdout.
//! - `show` -- report a metadata object, a file object, or one metadata key.
//! - `log` -- walk a commit's parent chain.
//! - `ls` -- list a commit's file paths.
//! - `config` -- read a repository configuration value.
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
    CheckoutMode, CheckoutOptions, Checksum, CollectionRef, CommitModifier, CommitModifierFlags,
    CommitOptions, CreateOptions, DeltaOptions, DiffChange, Ed25519Signer, Ed25519Verifier, Error,
    FileKind, FileObject, FsckOptions, MutableTree, ObjectType, PruneOptions, PullFlags,
    PullOptions, PullStats, PullVerify, RefAlias, Repo, RepoMode, RepoTree, Result, SignatureInfo,
    SummaryOptions, TarExportOptions, TarImportOptions, TimestampCheck, TreeEntry, Type, Value,
    Verifier, VerifyOutcome, Xattrs, base64, from_bytes, load_sign_keys, load_sign_keys_from,
    to_text, validate_refspec,
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
    /// List, create, or delete refs.
    Refs(RefsArgs),
    /// Print the commit checksum a revision names.
    #[command(name = "rev-parse")]
    RevParse(RevParseArgs),
    /// Write the contents of a commit's files to stdout.
    Cat(CatArgs),
    /// Output a metadata object.
    Show(ShowArgs),
    /// Show the log starting at a commit or ref.
    Log(LogArgs),
    /// List a commit's file paths.
    Ls(LsArgs),
    /// Read a repository configuration value.
    Config(ConfigArgs),
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
        "refs",
        "rev-parse",
        "cat",
        "show",
        "log",
        "ls",
        "config",
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
            Command::Refs(_) => "refs",
            Command::RevParse(_) => "rev-parse",
            Command::Cat(_) => "cat",
            Command::Show(_) => "show",
            Command::Log(_) => "log",
            Command::Ls(_) => "ls",
            Command::Config(_) => "config",
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
    /// The parent commit (a checksum or a ref), or `none` for a root commit.
    /// Absent, the branch's current tip is the parent.
    #[arg(long)]
    parent: Option<String>,
    /// Point this branch at the new commit and bind it into the commit.
    #[arg(short, long)]
    branch: Option<String>,
    /// Commit with no parent, and permit a commit that names no branch.
    #[arg(long)]
    orphan: bool,
    /// The commit subject.
    #[arg(short, long)]
    subject: Option<String>,
    /// Force owner 0:0, canonicalize modes to `perm & 0755`, and drop xattrs,
    /// for an owner- and host-independent commit.
    #[arg(long)]
    canonical_permissions: bool,
    /// Set file ownership user id.
    #[arg(long, value_name = "UID", allow_hyphen_values = true)]
    owner_uid: Option<String>,
    /// Set file ownership group id.
    #[arg(long, value_name = "GID", allow_hyphen_values = true)]
    owner_gid: Option<String>,
    /// Do not import extended attributes.
    #[arg(long)]
    no_xattrs: bool,
    /// Override the timestamp of the commit: `@SECONDS` since the Unix epoch,
    /// or a date and time carrying a UTC offset (`2020-01-02T03:04:05Z`).
    #[arg(long, value_name = "TIMESTAMP")]
    timestamp: Option<String>,
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
    /// Do not change file ownership or initialize extended attributes.
    #[arg(short = 'U', long)]
    user_mode: bool,
    /// Check out this path within the commit instead of the whole tree.
    #[arg(long, value_name = "PATH")]
    subpath: Option<PathBuf>,
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
struct RefsArgs {
    /// Delete the refs each PREFIX matches instead of listing them.
    #[arg(long)]
    delete: bool,
    /// Print each ref under its whole name, leaving the matched PREFIX in
    /// place.
    #[arg(long)]
    list: bool,
    /// Print each ref's commit checksum after a tab.
    #[arg(short = 'r', long)]
    revision: bool,
    /// List the aliases alone; with --create, create an alias instead of a ref.
    #[arg(short = 'A', long)]
    alias: bool,
    /// Create this ref, pointing it at the commit the single PREFIX argument
    /// names.
    #[arg(long, value_name = "NEWREF")]
    create: Option<String>,
    /// List collection refs as `(collection-id, ref)` pairs, and read each
    /// PREFIX as a collection id rather than a ref-name prefix.
    #[arg(short = 'c', long)]
    collections: bool,
    /// Replace an existing ref when creating.
    #[arg(long)]
    force: bool,
    /// The ref-name prefixes to match, or the collection ids under
    /// --collections. With none, every ref is listed.
    prefix: Vec<String>,
}

#[derive(Args)]
struct RevParseArgs {
    /// Print the repository's one commit. An empty repository, and one holding
    /// more than one commit, are both errors.
    #[arg(short = 'S', long)]
    single: bool,
    /// The revisions to resolve: a checksum, a refspec, or either with a
    /// trailing `^` per generation of ancestry. Required unless --single;
    /// checked after the repository resolves, matching the tool's
    /// error-ordering (`docs/conformance/cli-surface.md`, "Global
    /// conventions").
    rev: Vec<String>,
}

#[derive(Args)]
struct CatArgs {
    /// The commit to read (a checksum or a ref). Required, with at least one
    /// PATH; both are checked after the repository resolves, matching the
    /// tool's error-ordering (`docs/conformance/cli-surface.md`, "Global
    /// conventions").
    commit: Option<String>,
    /// The paths to write, in order. A leading `/` is optional.
    path: Vec<String>,
}

#[derive(Args, Default)]
struct ShowArgs {
    /// Show the "related" commits.
    #[arg(long)]
    print_related: bool,
    /// Read OBJECT as a file holding a value of this GVariant type.
    #[arg(long, value_name = "TYPE")]
    print_variant_type: Option<String>,
    /// List the available metadata keys.
    #[arg(long)]
    list_metadata_keys: bool,
    /// Print the value of one metadata key.
    #[arg(long, value_name = "KEY")]
    print_metadata_key: Option<String>,
    /// For a byte-array valued key, print an unquoted hexadecimal string.
    #[arg(long)]
    print_hex: bool,
    /// List the available detached metadata keys.
    #[arg(long)]
    list_detached_metadata_keys: bool,
    /// Print the value of one detached metadata key.
    #[arg(long, value_name = "KEY")]
    print_detached_metadata_key: Option<String>,
    /// Show the commit size metadata.
    #[arg(long)]
    print_sizes: bool,
    /// Show the raw variant data.
    #[arg(long)]
    raw: bool,
    /// Do not convert the variant data from big endian. The raw variant is
    /// reported as stored, and a commit's own report follows it.
    #[arg(short = 'B', long)]
    no_byteswap: bool,
    /// GPG homedir to use when looking for keyrings.
    #[arg(long, value_name = "HOMEDIR")]
    gpg_homedir: Option<PathBuf>,
    /// Use this remote's GPG configuration when verifying signatures.
    #[arg(long, value_name = "REMOTE")]
    gpg_verify_remote: Option<String>,
    /// The object to report: a revision, a metadata or file object checksum,
    /// or, under --print-variant-type, a filename. Required; checked after the
    /// repository resolves, matching the tool's error-ordering
    /// (`docs/conformance/cli-surface.md`, "Global conventions").
    object: Option<String>,
}

#[derive(Args)]
struct LogArgs {
    /// Show the raw variant data.
    #[arg(long)]
    raw: bool,
    /// The revision to start at. Required; checked after the repository
    /// resolves, matching the tool's error-ordering
    /// (`docs/conformance/cli-surface.md`, "Global conventions").
    rev: Option<String>,
}

#[derive(Args)]
struct LsArgs {
    /// Do not recurse into directory arguments.
    #[arg(short = 'd', long)]
    dironly: bool,
    /// Print directories recursively.
    #[arg(short = 'R', long)]
    recursive: bool,
    /// Print each entry's checksum: the content checksum of a file, the dirtree
    /// and dirmeta checksums of a directory.
    #[arg(short = 'C', long)]
    checksum: bool,
    /// Print each entry's extended attributes.
    #[arg(short = 'X', long)]
    xattrs: bool,
    /// Print only the paths, NUL separated.
    #[arg(long)]
    nul_filenames_only: bool,
    /// The commit to list (a checksum or a ref). Required; checked after the
    /// repository resolves, matching the tool's error-ordering
    /// (`docs/conformance/cli-surface.md`, "Global conventions").
    commit: Option<String>,
    /// The paths within the commit to list, in order. With none, the tree root
    /// is listed.
    path: Vec<String>,
}

#[derive(Args)]
struct ConfigArgs {
    /// The group the KEY belongs to. With this, KEY is read as a bare key name
    /// rather than `section.key`.
    #[arg(long, value_name = "GROUP")]
    group: Option<String>,
    /// The operation: `get`. `set` and `unset` need a config write path the
    /// library does not have yet (`docs/port-plan.md`, Phase 17e).
    operation: Option<String>,
    /// The key to read: `section.key`, or a bare key name under --group.
    args: Vec<String>,
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
            eprintln!("error: {}", error_line(&err));
            std::process::ExitCode::FAILURE
        }
    }
}

/// The text a library error reaches standard error as. A refspec the ref rule
/// refuses is reported in the tool's own words, wherever a revision, a NEWREF,
/// or a branch name reaches the library, so one condition has one message
/// (`docs/format-reference.md`, "Ref name validation"). Every other error
/// carries the library's own `Display`.
fn error_line(err: &Error) -> String {
    match err {
        Error::InvalidRefspec(refspec) => format!("Invalid refspec {refspec}"),
        other => other.to_string(),
    }
}

async fn run(repo: Option<&Path>, verbose: bool, command: Command) -> Result<()> {
    let name = command.name();
    match command {
        Command::Init(args) => init(repo, verbose, name, args).await,
        Command::Commit(args) => {
            // The tool reads `--owner-uid` and `--owner-gid` while it parses its
            // options, so a value it cannot read is reported ahead of the
            // repository (`docs/format-reference.md`, "CLI output formats").
            let owner = commit_owner(&args);
            let (repo, _) = resolve_repo(repo, verbose, name).await;
            commit(repo, args, owner).await
        }
        Command::Checkout(args) => {
            let (repo, _) = resolve_repo(repo, verbose, name).await;
            checkout(repo, args).await
        }
        Command::Export(args) => {
            let (repo, _) = resolve_repo(repo, verbose, name).await;
            export(repo, name, args).await
        }
        Command::Refs(args) => {
            let (repo, _) = resolve_repo(repo, verbose, name).await;
            refs(repo, args).await
        }
        Command::RevParse(args) => {
            let (repo, _) = resolve_repo(repo, verbose, name).await;
            rev_parse(repo, name, args).await
        }
        Command::Cat(args) => {
            let (repo, _) = resolve_repo(repo, verbose, name).await;
            cat(repo, name, args).await
        }
        Command::Show(args) => {
            let (repo, path) = resolve_repo(repo, verbose, name).await;
            show(repo, path, name, args).await
        }
        Command::Log(args) => {
            let (repo, path) = resolve_repo(repo, verbose, name).await;
            log(repo, path, name, args).await
        }
        Command::Ls(args) => {
            let (repo, _) = resolve_repo(repo, verbose, name).await;
            ls(repo, name, args).await
        }
        Command::Config(args) => {
            let (repo, _) = resolve_repo(repo, verbose, name).await;
            config(repo, name, args).await
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

/// Print `error: {message}` with no usage text and exit 1, the shape the tool
/// uses once a subcommand is running and its arguments are in hand.
fn exit_error(message: &str) -> ! {
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
/// used to reach it, applying the port's precedence: an explicit `--repo`
/// (either position) first; then the current directory, if it opens as a
/// repository; then `OSTREE_REPO`. The chain ends there. The tool carries one
/// more source after `OSTREE_REPO`, the compiled-in `/sysroot/ostree/repo`;
/// the port leaves that step out, which keeps `ostrya` from acting on a live
/// system repository through an omitted `--repo`. With none of the three,
/// print `subcommand`'s usage text and the tool's error line and exit. `init`
/// shares this precedence too, through `resolve_init_path`, below, which
/// resolves to a path rather than an opened `Repo` since its explicit-`--repo`
/// tier need not already exist.
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

/// The one `--parent` value that is a literal rather than a revision, in
/// lowercase alone: it asks for a root commit.
const NO_PARENT: &str = "none";

async fn commit(repo: Repo, args: CommitArgs, owner: Owner) -> Result<()> {
    // A commit either names the branch it moves or states that it writes no ref.
    // The check stands ahead of `--parent`, ahead of the tree, and ahead of any
    // object publication, which is the order the tool reports it in
    // (`docs/format-reference.md`, "CLI output formats").
    if args.branch.is_none() && !args.orphan {
        exit_error("A branch must be specified with --branch, or use --orphan");
    }

    // Canonical ingest owns every object 0:0, so a declared non-zero id would
    // contradict it. The tool refuses the pair after the branch check and ahead
    // of the tree, and names the flag whose id it read, uid first.
    if args.canonical_permissions {
        for (id, flag) in [(owner.uid, "--owner-uid"), (owner.gid, "--owner-gid")] {
            if id.is_some_and(|id| id != 0) {
                exit_error(&format!(
                    "Cannot specify both --canonical-permissions and non-zero {flag}"
                ));
            }
        }
    }

    let txn = repo.transaction().await?;

    // `--parent` takes a revision, so it carries the resolution wording every
    // subcommand taking one gives (`docs/port-plan.md`, Phase 17b).
    // `report_resolution_failure` reports through `exit_error`, which runs no
    // destructor, so the staging directory is reaped ahead of it, the way the
    // branch-name guard below does it.
    let parent = match args.parent.as_deref() {
        Some(NO_PARENT) => None,
        Some(rev) => match repo.resolve_rev(rev, false).await {
            Ok(found) => found,
            Err(err) => {
                txn.abort().await?;
                return Err(report_resolution_failure(err));
            }
        },
        // `--orphan` suppresses the implicit parent alone, so an explicit
        // `--parent` alongside it still parents the commit.
        None if args.orphan => None,
        // The branch's current tip is the implicit parent. The tip is read from
        // the ref file and not loaded, so a branch that names no ref gives a
        // root commit and a ref over an absent object is inherited unread. A
        // name the guard below refuses is not read at all, which leaves that
        // refusal the message and the position it already has.
        None => match args.branch.as_deref() {
            Some(branch) if shadowed_branch_name(branch).is_none() => {
                match repo.resolve_rev(branch, true).await {
                    Ok(found) => found,
                    Err(err) => {
                        txn.abort().await?;
                        return Err(report_resolution_failure(err));
                    }
                }
            }
            _ => None,
        },
    };

    // The tool opens the tree ahead of reading `--timestamp`, so a tree path that
    // does not open is reported and a timestamp the reader refuses is not.
    let dfd = match args.path.as_deref() {
        Some(path) => Some(std::fs::File::open(path).map_err(Error::Io)?),
        None => None,
    };
    let timestamp = match args.timestamp.as_deref() {
        Some(text) => match parse_timestamp(text) {
            Some(seconds) => Some(seconds),
            None => {
                txn.abort().await?;
                exit_error(&format!("Could not parse '{text}'"));
            }
        },
        None => None,
    };

    let root = match dfd {
        Some(dfd) => {
            let mut modifier = commit_modifier(&args, owner);
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
            let mut opts = TarImportOptions::new();
            opts.owner_uid = owner.uid;
            opts.owner_gid = owner.gid;
            opts.skip_xattrs = args.no_xattrs;
            let mut mtree = repo.import_tar(&txn, opts, stdin).await?;
            txn.write_mtree(&mut mtree).await?
        }
    };

    let opts = CommitOptions {
        parent,
        subject: args.subject,
        body: None,
        timestamp,
        metadata: Some(ref_binding(args.branch.as_deref())),
    };
    let checksum = txn.write_commit(opts, &root).await?;
    if let Some(branch) = args.branch.as_deref() {
        // A branch name the revision syntax shadows is refused at the ref write,
        // after the commit is written. `exit_error` runs no destructor, so the
        // staging directory is reaped ahead of it.
        if let Some(message) = shadowed_branch_name(branch) {
            txn.abort().await?;
            exit_error(&message);
        }
        txn.set_ref(branch, Some(&checksum));
    }
    txn.commit().await?;

    println!("{}", checksum.to_hex());
    Ok(())
}

/// The ownership a `commit` invocation declares, read from `--owner-uid` and
/// `--owner-gid`. A field is `None` where the option was absent or carried a
/// negative id, which declares nothing: the tool's own default for both is
/// `-1`, so every negative value leaves the source's ownership in place.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Owner {
    uid: Option<u32>,
    gid: Option<u32>,
}

/// Read `--owner-uid` and `--owner-gid`, reporting a value neither can hold in
/// the tool's own words and at the tool's own step: while the options are read,
/// ahead of the repository and ahead of every check `commit` itself makes.
fn commit_owner(args: &CommitArgs) -> Owner {
    Owner {
        uid: owner_id(args.owner_uid.as_deref(), "--owner-uid"),
        gid: owner_id(args.owner_gid.as_deref(), "--owner-gid"),
    }
}

/// One `--owner-*` id, or `None` where the option is absent or its value is
/// negative. The value is read as a C `int` the way the tool's option parser
/// reads one, so the two accept and refuse the same text
/// (`docs/format-reference.md`, "CLI output formats").
fn owner_id(value: Option<&str>, flag: &str) -> Option<u32> {
    let text = value?;
    match parse_c_int(text) {
        Ok(id) if id >= 0 => Some(id as u32),
        Ok(_) => None,
        Err(IntError::Syntax) => exit_error(&format!(
            "Cannot parse integer value \u{201c}{text}\u{201d} for {flag}"
        )),
        Err(IntError::Range) => exit_error(&format!(
            "Integer value \u{201c}{text}\u{201d} for {flag} out of range"
        )),
    }
}

/// Why a C `int` value was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntError {
    /// The text is not an integer in any accepted base.
    Syntax,
    /// The text is an integer outside the range of a C `int`.
    Range,
}

/// Read `text` as a C `int` the way `strtol` with base 0 does: optional leading
/// whitespace, an optional sign, then a `0x`-prefixed hexadecimal, a
/// `0`-prefixed octal, or a decimal run. The whole text must be consumed, so a
/// trailing space or letter is refused, and the value must fit an `i32`.
fn parse_c_int(text: &str) -> std::result::Result<i32, IntError> {
    let body = text.trim_start_matches(|c: char| c.is_ascii_whitespace());
    let (negative, body) = match body.as_bytes().first() {
        Some(b'-') => (true, &body[1..]),
        Some(b'+') => (false, &body[1..]),
        _ => (false, body),
    };
    let (radix, digits) = match body.as_bytes() {
        [b'0', b'x' | b'X', ..] => (16, &body[2..]),
        [b'0', ..] => (8, &body[1..]),
        _ => (10, body),
    };
    // A lone `0` reaches here as an empty octal tail and is the value zero.
    if digits.is_empty() {
        return if radix == 8 {
            Ok(0)
        } else {
            Err(IntError::Syntax)
        };
    }
    let mut value: i64 = 0;
    for byte in digits.bytes() {
        let digit = (byte as char).to_digit(radix).ok_or(IntError::Syntax)?;
        value = value
            .checked_mul(i64::from(radix))
            .and_then(|v| v.checked_add(i64::from(digit)))
            .ok_or(IntError::Range)?;
        if value > i64::from(u32::MAX) {
            return Err(IntError::Range);
        }
    }
    let value = if negative { -value } else { value };
    i32::try_from(value).map_err(|_| IntError::Range)
}

/// The commit modifier the tree-shaping options ask for, or `None` where they
/// ask for nothing. `--canonical-permissions` implies the xattr skip, since
/// canonical ingest records no extended attributes.
fn commit_modifier(args: &CommitArgs, owner: Owner) -> Option<CommitModifier> {
    let mut flags = CommitModifierFlags::empty();
    if args.canonical_permissions {
        flags |= CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::SKIP_XATTRS;
    }
    if args.no_xattrs {
        flags |= CommitModifierFlags::SKIP_XATTRS;
    }
    if flags == CommitModifierFlags::empty() && owner == Owner::default() {
        return None;
    }
    let mut modifier = CommitModifier::new(flags);
    modifier.owner_uid = owner.uid;
    modifier.owner_gid = owner.gid;
    Some(modifier)
}

/// Read a `--timestamp` value: `@SECONDS` since the Unix epoch, or a date and
/// time carrying an explicit UTC offset. `None` for a value this reader does not
/// hold, which `commit` reports as the tool words it.
///
/// The tool reads a superset: a wall-clock time with no offset (its own local
/// time), a relative expression such as `now` or `yesterday`, and an empty value
/// (today's midnight). Those need a time-zone database or a natural-language
/// date reader, so the port refuses them and the difference is recorded in
/// `docs/conformance/cli-surface.md`, "P2".
fn parse_timestamp(text: &str) -> Option<u64> {
    let text = text.trim_matches(|c: char| c.is_ascii_whitespace());
    match text.strip_prefix('@') {
        Some(seconds) => parse_epoch(seconds),
        None => parse_datetime(text),
    }
}

/// The `@SECONDS` form: an optional sign, a decimal run, and an optional
/// fractional part, which names a sub-second the commit timestamp cannot hold
/// and is dropped. A pre-epoch value is recorded as the unsigned field's
/// two's-complement form, matching the tool.
fn parse_epoch(text: &str) -> Option<u64> {
    let text = text.trim_start_matches(|c: char| c.is_ascii_whitespace());
    let (negative, body) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let (whole, fraction) = match body.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (body, None),
    };
    if whole.is_empty() || !whole.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if let Some(fraction) = fraction
        && (fraction.is_empty() || !fraction.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    let seconds: i64 = whole.parse().ok()?;
    Some(if negative {
        seconds.checked_neg()? as u64
    } else {
        seconds as u64
    })
}

/// The absolute form: `YYYY-MM-DD`, a `T` or a space, `HH:MM[:SS]`, an optional
/// fractional second, and a UTC offset (`Z`, or `+HH`, `+HH:MM`, `+HHMM`, and
/// their negatives). The offset is required: without one the value names a
/// wall-clock time in a zone this reader does not resolve.
fn parse_datetime(text: &str) -> Option<u64> {
    let (year, rest) = take_digits(text, 4)?;
    let (month, rest) = take_digits(rest.strip_prefix('-')?, 2)?;
    let (day, rest) = take_digits(rest.strip_prefix('-')?, 2)?;
    let rest = rest
        .strip_prefix('T')
        .or_else(|| rest.strip_prefix('t'))
        .or_else(|| rest.strip_prefix(' '))?
        .trim_start_matches(' ');
    let (hour, rest) = take_digits(rest, 2)?;
    let (minute, rest) = take_digits(rest.strip_prefix(':')?, 2)?;
    let (second, rest) = match rest.strip_prefix(':') {
        Some(rest) => take_digits(rest, 2)?,
        None => (0, rest),
    };
    let rest = match rest.strip_prefix('.').or_else(|| rest.strip_prefix(',')) {
        Some(rest) => {
            let after = rest.trim_start_matches(|c: char| c.is_ascii_digit());
            if after.len() == rest.len() {
                return None;
            }
            after
        }
        None => rest,
    };
    let offset = parse_offset(rest.trim_start_matches(' '))?;

    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    // A leap second is stated as :60 and lands on the following second, which is
    // what an unsigned epoch count can hold.
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let seconds =
        days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second - offset;
    Some(seconds as u64)
}

/// A UTC offset in seconds, to subtract from the stated wall clock.
fn parse_offset(text: &str) -> Option<i64> {
    if text == "Z" || text == "z" {
        return Some(0);
    }
    let (negative, body) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => return None,
    };
    let (hours, rest) = take_digits(body, 2)?;
    let minutes = match rest {
        "" => 0,
        rest => {
            let rest = rest.strip_prefix(':').unwrap_or(rest);
            let (minutes, tail) = take_digits(rest, 2)?;
            if !tail.is_empty() {
                return None;
            }
            minutes
        }
    };
    if hours > 23 || minutes > 59 {
        return None;
    }
    let offset = hours * 3_600 + minutes * 60;
    Some(if negative { -offset } else { offset })
}

/// Exactly `count` decimal digits from the front of `text`, with the rest.
fn take_digits(text: &str, count: usize) -> Option<(i64, &str)> {
    let (head, rest) = text.split_at_checked(count)?;
    if !head.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((head.parse().ok()?, rest))
}

/// The number of days in `month` of `year`, under the proleptic Gregorian
/// calendar the epoch count follows.
fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// The days from `1970-01-01` to the given proleptic Gregorian date, negative
/// before the epoch. The era arithmetic counts 400-year cycles, whose length in
/// days is fixed at 146097, so no table and no iteration is needed.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

async fn checkout(repo: Repo, args: CheckoutArgs) -> Result<()> {
    let commit = resolve(&repo, &args.commit).await?;

    if args.composefs {
        let image = repo.export_composefs(&commit).await?;
        std::fs::write(&args.destination, &image.bytes).map_err(Error::Io)?;
        return Ok(());
    }

    // `-U` applies no ownership and no xattrs and reduces a regular file's mode
    // to `perm & 0777`; a `--subpath` directory's own metadata becomes the
    // destination root's, and a `--subpath` file or symlink is placed inside a
    // fresh destination directory (`docs/format-reference.md`, "Checkout").
    let mode = if args.user_mode {
        CheckoutMode::User
    } else {
        CheckoutMode::None
    };
    let mut opts = CheckoutOptions::new(mode);
    opts.subpath = args.subpath;
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

/// List, create, or delete refs. `--create` wins over `--delete`, and
/// `--collections` wins over `--alias`, matching the tool's own precedence
/// (`docs/format-reference.md`, "CLI output formats").
async fn refs(repo: Repo, args: RefsArgs) -> Result<()> {
    if let Some(newref) = args.create.as_deref() {
        refs_create(&repo, newref, &args).await
    } else if args.delete {
        refs_delete(&repo, &args).await
    } else if args.collections {
        refs_list_collections(&repo, &args).await
    } else if args.alias {
        refs_list_aliases(&repo, &args).await
    } else {
        refs_list(&repo, &args).await
    }
}

/// Point a new ref, a new collection ref, or a new alias, at what the single
/// PREFIX argument names. `-c` wins over `-A` here the way it does in a
/// listing.
async fn refs_create(repo: &Repo, newref: &str, args: &RefsArgs) -> Result<()> {
    let existing = match args.prefix.len() {
        1 => args.prefix[0].as_str(),
        0 => exit_error("You must specify a revision when creating a new ref"),
        _ => exit_error("You must specify only 1 existing ref when creating a new ref"),
    };
    // The existence check resolves NEWREF as a revision in every case; `--force`
    // suppresses the refusal a resolved NEWREF draws and not the resolution
    // itself (`format-reference.md`, "refs"). So `--create=NAME^ --force` where
    // NAME's base is a root commit stops here with `Commit <checksum> has no
    // parent`, the words `report_resolution_failure` gives that failure.
    let resolved = resolve_optional(repo, newref).await?;
    if !args.force && resolved.is_some() {
        exit_error(&format!(
            "--create specified but ref {newref} already exists"
        ));
    }
    // NEWREF is validated as a ref name here: after the existence check and
    // before the positional resolves, which is the order the tool takes it in
    // (`format-reference.md`, "refs"). A trailing `^` fails this step, since a
    // ref name carries no ancestry suffix -- it names a commit, and a ref written
    // under that name is one the existence check reads as a revision.
    if validate_refspec(newref).is_err() || newref.ends_with('^') {
        exit_error(&format!("Invalid refspec {newref}"));
    }
    if args.collections {
        return refs_create_collection(repo, newref, existing).await;
    }
    if args.alias {
        // An alias lives under `refs/heads`, so a NEWREF naming a remote is
        // refused, and the message names the remote half alone, whether or not
        // that remote exists. The step sits after the three NEWREF checks and
        // before the positional resolves, so `--create=origin:al nosuch`
        // reports the remote and not the positional, and `--force` leaves it in
        // place (`docs/format-reference.md`, "refs").
        if let Some((remote, _)) = newref.split_once(':') {
            exit_error(&format!("Cannot create alias to remote ref: {remote}"));
        }
        // An alias records a name, so its target has to be a ref: a checksum
        // and an ancestry suffix each name a commit and no ref file.
        if !names_a_ref(repo, existing).await? {
            exit_error(&format!(
                "Cannot create alias to non-existent ref: {existing}"
            ));
        }
        return repo.set_ref_alias_immediate(newref, existing).await;
    }
    let commit = resolve(repo, existing).await?;
    repo.set_ref_immediate(newref, Some(&commit)).await
}

/// Write a collection ref under `-c`, where NEWREF is a
/// `<collection-id>:<ref>` pair naming `refs/mirrors/<collection-id>/<ref>`.
///
/// The steps run in the tool's order (`docs/format-reference.md`, "refs"): the
/// pair shape, then the revision, then the collection id. An empty half is
/// refused a step earlier, by the ref-name check every NEWREF passes. A NEWREF
/// holding no `:` names no ref, so the whole argument is read as the collection
/// id and the missing name is reported once that id holds.
async fn refs_create_collection(repo: &Repo, newref: &str, existing: &str) -> Result<()> {
    let pair = match newref.split_once(':') {
        // A `^` is refused with the pair's own message here, and a trailing one
        // is the case the tool crashes on under `-c`
        // (`docs/conformance/cli-surface.md`, "P1").
        Some((_, ref_name)) if ref_name.contains(':') || newref.contains('^') => {
            exit_error(&format!("Invalid refspec {newref}"))
        }
        pair => pair,
    };
    let commit = resolve(repo, existing).await?;
    let Some((collection_id, ref_name)) = pair else {
        if !is_collection_id(newref) {
            exit_error(&format!("Invalid collection ID {newref}"));
        }
        exit_error("Invalid ref name (null)");
    };
    if !is_collection_id(collection_id) {
        exit_error(&format!("Invalid collection ID {collection_id}"));
    }
    let cref = CollectionRef::new(collection_id, ref_name);
    repo.set_collection_ref_immediate(&cref, Some(&commit))
        .await
}

/// Whether `id` is a collection id: two or more `.`-separated elements, each
/// starting with an ASCII letter or `_` and continuing with ASCII letters,
/// digits, or `_`.
///
/// Recovered by observation: the tool writes `a.b`, `A.b`, `_a.b`, `a._b`,
/// `a_b.c`, and `a.b.c.d`, and refuses `fresh`, `a..b`, `a.b.`, `1a.b`,
/// `a.1b`, `a-b.c`, and `a.b-c` with `error: Invalid collection ID <id>`. The
/// length is bounded by the filesystem alone, the id being one path component.
fn is_collection_id(id: &str) -> bool {
    id.split('.').count() >= 2
        && id.split('.').all(|element| {
            let mut chars = element.chars();
            chars
                .next()
                .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
}

/// The commit a ref name resolves to, or `None` when the name names no ref: a
/// bare checksum and an ancestry suffix each name a commit and no ref file, and
/// a name no ref file can carry names no ref either, which is the answer the
/// alias refusal reports, the way the tool reports it for `..` and for an empty
/// target. An i/o error reaching the ref file is returned, so the caller
/// decides whether a name that is a directory, or a path through a ref file, is
/// a refusal or a miss.
async fn resolve_ref_name(repo: &Repo, rev: &str) -> Result<Option<Checksum>> {
    // A 64-character name is a checksum in lowercase hex alone, the split
    // resolution takes, so an uppercase one is looked up as a ref name and an
    // alias to it is written (`docs/format-reference.md`, "Revision syntax").
    if rev.ends_with('^') || Checksum::from_hex_lower(rev).is_ok() {
        return Ok(None);
    }
    match repo.resolve_rev(rev, true).await {
        Ok(found) => Ok(found),
        Err(Error::InvalidRefspec(_)) => Ok(None),
        Err(err) => Err(err),
    }
}

/// Whether `rev` names a ref file rather than a commit.
async fn names_a_ref(repo: &Repo, rev: &str) -> Result<bool> {
    Ok(resolve_ref_name(repo, rev).await?.is_some())
}

/// Delete every ref the prefixes match. A prefix matching nothing is not an
/// error, and the parent directories a removal empties are left in place,
/// matching the tool.
///
/// A whole-remote prefix that matches at least one ref ends the invocation with
/// exit 1 and removes none of what it matched, which is the tool's outcome: the
/// tool names each ref it deletes by joining the prefix's ref half with the name
/// below it, and the `.` that join carries is a refspec its own rule then
/// refuses. The prefixes ahead of it keep their effect, and a whole-remote
/// prefix matching no ref exits 0. The two word the refusal differently
/// (`docs/conformance/cli-surface.md`, "P1").
///
/// A ref under `refs/heads` that an alias names is refused with exit 1, and the
/// prefix that matched it removes nothing. The guard runs per prefix, after the
/// whole-remote refusal, so `refs --delete deep test` removes what `deep`
/// matched and then reports the refusal for `test`. It is the ref set and the
/// alias set as the prefixes ahead left them that each prefix reads, so
/// `refs --delete alal test/al` removes the alias and then the ref it named. `-c`
/// takes no part in it (`docs/format-reference.md`, "refs").
///
/// Each prefix is matched against the ref set as the prefixes ahead of it left
/// it, so a prefix that removes a remote's last ref leaves a whole-remote prefix
/// behind it matching nothing, which exits 0 in both.
///
/// With `-A` the set each prefix selects is the one a `-A` listing prints: the
/// ref the prefix names exactly, or the aliases nested under it. `-c` wins over
/// `-A`, and the prefix rules, the whole-remote refusal, and the alias guard all
/// apply to whichever set the prefix selected (`docs/format-reference.md`,
/// "refs").
///
/// With `-c` the prefixes are collection ids, and the id equal to the
/// repository's own `collection-id` removes the refs under `refs/heads` alone,
/// keeping the mirror refs that carry that id.
async fn refs_delete(repo: &Repo, args: &RefsArgs) -> Result<()> {
    if args.prefix.is_empty() {
        exit_error("At least one PREFIX is required when deleting refs");
    }
    if args.collections {
        // An id equal to the repository's own `collection-id` removes the refs
        // under `refs/heads` alone: the mirror refs carrying that same id stand,
        // where a foreign id removes the mirror refs it names
        // (`docs/format-reference.md`, "refs").
        let own = repo.config().collection_id().map(str::to_owned);
        for entry in select_collection_refs(repo, &args.prefix).await? {
            if entry.local {
                repo.set_ref_immediate(&entry.name, None).await?;
            } else if own.as_deref() != Some(entry.collection.as_str()) {
                let cref = CollectionRef::new(entry.collection, entry.name);
                repo.set_collection_ref_immediate(&cref, None).await?;
            }
        }
        return Ok(());
    }
    let listed = repo.list_ref_aliases().await?;
    let mut aliases = active_aliases(&listed);
    // Every alias, local and remote alike, which is the set a `-A` prefix
    // filters and a `-A --delete` removes from.
    let mut alias_names: Vec<String> = listed.into_iter().map(|alias| alias.refspec).collect();
    let mut all = all_refs(repo).await?;
    for prefix in prefixes(&args.prefix) {
        check_prefix(repo, prefix).await?;
        let selected: Vec<String> = if args.alias {
            select_aliases(repo, &alias_names, prefix).await?
        } else {
            all.iter()
                .filter(|(name, _)| matches_prefix(name, prefix))
                .map(|(name, _)| name.clone())
                .collect()
        };
        if let Some(given) = prefix
            && whole_remote(given).is_some()
            && !selected.is_empty()
        {
            return Err(Error::InvalidRefspec(given.to_owned()));
        }
        for refspec in &selected {
            // A ref under `refs/remotes` is removed with an alias naming it, so
            // the guard reads the refs under `refs/heads` alone -- the ones a
            // refspec holding no `:` names. Where more than one guarded ref
            // matches, the port names the first in refspec order and the tool
            // names the first its own enumeration reaches
            // (`docs/conformance/cli-surface.md`, "P1").
            if refspec.contains(':') {
                continue;
            }
            if let Some((alias, _)) = aliases.iter().find(|(_, named)| named == refspec) {
                exit_error(&format!("Ref '{refspec}' has an active alias: '{alias}'"));
            }
        }
        for refspec in &selected {
            repo.set_ref_immediate(refspec, None).await?;
        }
        all.retain(|(name, _)| !selected.contains(name));
        aliases.retain(|(alias, _)| !selected.contains(alias));
        alias_names.retain(|alias| !selected.contains(alias));
    }
    Ok(())
}

/// The aliases one `-A --delete` prefix removes, which is the set a `-A` listing
/// prints for it: the ref the prefix names exactly, whether or not that ref is an
/// alias, or the aliases nested under it.
///
/// A remote alias is removed by a prefix naming it exactly and by no other, since
/// the tool deletes each nested alias by the name it prints for it, which for a
/// remote alias drops the remote and names no ref of that remote. The port
/// removes the alias its own listing names, so a remote prefix holding an alias
/// diverges (`docs/conformance/cli-surface.md`, "P1").
async fn select_aliases(
    repo: &Repo,
    aliases: &[String],
    prefix: Option<&str>,
) -> Result<Vec<String>> {
    if let Some(prefix) = prefix
        && alias_prefix_commit(repo, prefix).await?.is_some()
    {
        return Ok(vec![prefix.to_owned()]);
    }
    Ok(aliases
        .iter()
        .filter(|refspec| nested_under_prefix(refspec, prefix))
        .cloned()
        .collect())
}

/// The aliases that can name a local ref, as `(alias refspec, the ref name its
/// link body gives)` pairs sorted by alias refspec.
///
/// An alias names a ref under `refs/heads` by that ref's own name: the link body
/// with its leading `../` components removed, read from the `refs/heads` root and
/// not from the alias's own directory. So an alias at `refs/heads/test/al2` whose
/// body is `other` names the ref `other`, where the link itself resolves to
/// `refs/heads/test/other`. An alias under `refs/remotes` names nothing here, and
/// a body reaching outside `refs/heads` matches no local refspec, a local ref
/// name holding no `:` (`docs/format-reference.md`, "refs").
fn active_aliases(listed: &[RefAlias]) -> Vec<(String, String)> {
    listed
        .iter()
        .filter(|alias| !alias.refspec.contains(':'))
        .map(|alias| {
            let named = alias_body_name(&alias.target).to_owned();
            (alias.refspec.clone(), named)
        })
        .collect()
}

/// Print the local and remote refs the prefixes match, one per line, with the
/// commit checksum after a tab under `-r`. A ref two prefixes match is printed
/// once per match, and the name a row carries is stripped by the prefix that
/// selected it -- `refs test test/main` prints `main` and then `test/main`.
async fn refs_list(repo: &Repo, args: &RefsArgs) -> Result<()> {
    let all = all_refs(repo).await?;
    for prefix in prefixes(&args.prefix) {
        check_prefix(repo, prefix).await?;
        for (refspec, commit) in all.iter().filter(|(name, _)| matches_prefix(name, prefix)) {
            let name = if args.list {
                refspec.clone()
            } else {
                strip_prefix_from(refspec, prefix)
            };
            if args.revision {
                println!("{name}\t{}", commit.to_hex());
            } else {
                println!("{name}");
            }
        }
    }
    Ok(())
}

/// Print the aliases the prefixes match, as `name -> target`. A `PREFIX` that
/// names a ref is answered by that one ref, with the commit checksum in the
/// target position; every other prefix keeps the aliases nested under it. The
/// name is never stripped and `-r` adds nothing, matching the tool.
async fn refs_list_aliases(repo: &Repo, args: &RefsArgs) -> Result<()> {
    let aliases = repo.list_ref_aliases().await?;
    for prefix in prefixes(&args.prefix) {
        check_prefix(repo, prefix).await?;
        if let Some(prefix) = prefix
            && let Some(commit) = alias_prefix_commit(repo, prefix).await?
        {
            println!("{prefix} -> {}", commit.to_hex());
            continue;
        }
        for alias in &aliases {
            if nested_under_prefix(&alias.refspec, prefix) {
                println!(
                    "{} -> {}",
                    alias.refspec,
                    alias_target(&alias.refspec, &alias.target)
                );
            }
        }
    }
    Ok(())
}

/// The commit a `-A` PREFIX names as a ref, whether or not that ref is an
/// alias. A prefix reaching no ref file -- a directory holding refs, a path
/// through a ref file, an alias whose target ref is missing -- names no ref, so
/// it filters the alias listing instead. `EISDIR` and `ENOTDIR` are the two
/// errnos those paths draw; every other read failure is returned, so a
/// permission fault reaches the caller rather than reading as an empty listing.
async fn alias_prefix_commit(repo: &Repo, prefix: &str) -> Result<Option<Checksum>> {
    match resolve_ref_name(repo, prefix).await {
        Err(Error::Io(err))
            if matches!(
                err.kind(),
                std::io::ErrorKind::IsADirectory | std::io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(None)
        }
        other => other,
    }
}

/// Print the collection refs, as `(collection-id, ref)`, with the commit
/// checksum after a tab under `-r`.
async fn refs_list_collections(repo: &Repo, args: &RefsArgs) -> Result<()> {
    for entry in select_collection_refs(repo, &args.prefix).await? {
        let pair = format!("({}, {})", entry.collection, entry.name);
        if args.revision {
            println!("{pair}\t{}", entry.commit.to_hex());
        } else {
            println!("{pair}");
        }
    }
    Ok(())
}

/// One collection-qualified ref, as `refs -c` lists it.
#[derive(Clone)]
struct CollectionEntry {
    collection: String,
    /// The ref name, which for a local ref is its refspec.
    name: String,
    commit: Checksum,
    /// Whether the ref lives under `refs/heads`, qualified by the repository's
    /// own collection id, rather than under `refs/mirrors`.
    local: bool,
}

/// Every local and remote ref, sorted by refspec, which is the order a listing
/// prints and the set each prefix filters.
async fn all_refs(repo: &Repo) -> Result<Vec<(String, Checksum)>> {
    let mut all = repo.list_refs(None).await?;
    all.extend(repo.list_remote_refs().await?);
    all.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(all)
}

/// The collection refs the collection ids select, grouped the same way a
/// listing groups ref-name prefixes. The repository's own
/// `collection-id` qualifies its local refs; the mirror refs carry theirs in
/// the path.
async fn select_collection_refs(repo: &Repo, ids: &[String]) -> Result<Vec<CollectionEntry>> {
    let mut all = Vec::new();
    if let Some(collection) = repo.config().collection_id().map(str::to_owned) {
        for (name, commit) in repo.list_refs(None).await? {
            all.push(CollectionEntry {
                collection: collection.clone(),
                name,
                commit,
                local: true,
            });
        }
    }
    for (collection, name, commit) in repo.list_mirror_refs().await? {
        all.push(CollectionEntry {
            collection,
            name,
            commit,
            local: false,
        });
    }
    all.sort_by(|a, b| (&a.collection, &a.name).cmp(&(&b.collection, &b.name)));

    let mut out = Vec::new();
    for id in prefixes(ids) {
        out.extend(
            all.iter()
                .filter(|entry| id.is_none_or(|id| entry.collection == id))
                .cloned(),
        );
    }
    Ok(out)
}

/// The prefixes to iterate: each one given, or a single `None` standing for
/// "every ref" when none were.
fn prefixes(given: &[String]) -> Vec<Option<&str>> {
    if given.is_empty() {
        return vec![None];
    }
    given.iter().map(|prefix| Some(prefix.as_str())).collect()
}

/// Refuse a PREFIX that no ref name can hold, and a PREFIX whose path under
/// `refs/` runs through a ref file, both of which the tool refuses before the
/// prefix filters anything. The check runs where each prefix is taken, so the
/// rows an earlier prefix printed and the refs it deleted stand, matching the
/// tool: `refs test 'bad/'` prints the `test` rows and then reports the refusal.
///
/// The refspec rule comes first, so a prefix that breaks both rules -- `plain/x/`
/// over the ref file `plain` -- draws the refspec message in both
/// implementations.
///
/// The path probe reads the prefix as the directory a listing enumerates, the
/// path the tool itself reads: `ENOTDIR` ends the invocation, with the port's one
/// message for that condition where the tool names the path and the syscall. A
/// path naming nothing continues, since a prefix matching no ref exits 0 in both
/// (`docs/format-reference.md`, "refs"). The probe runs through
/// [`Repo::check_refs_path`], one fd-relative call inside the repository the
/// handle holds open.
async fn check_prefix(repo: &Repo, prefix: Option<&str>) -> Result<()> {
    let Some(prefix) = prefix else {
        return Ok(());
    };
    check_prefix_name(prefix)?;
    repo.check_refs_path(&prefix_path(prefix)).await
}

/// The refspec rule a PREFIX passes, reported with the prefix as given.
///
/// A whole-remote prefix passes the rule: the rule reads an empty ref name as a
/// refusal, so [`whole_remote`] hands it the remote name alone -- one component,
/// which the rule reads as a name holding no `/`.
///
/// The tool's ref-name character class is narrower than the port's rule, so a
/// prefix such as `tes~t` passes here and the tool refuses it
/// (`docs/conformance/cli-surface.md`, "P1").
fn check_prefix_name(prefix: &str) -> Result<()> {
    let checked = whole_remote(prefix).unwrap_or(prefix);
    validate_refspec(checked).map_err(|_| Error::InvalidRefspec(prefix.to_owned()))
}

/// The path a PREFIX names below `refs/`: the ref file or directory a listing
/// enumerates. A whole-remote prefix names the remote's own directory, its ref
/// half standing for the remote's root.
fn prefix_path(prefix: &str) -> String {
    match whole_remote(prefix) {
        Some(remote) => format!("remotes/{remote}"),
        None => ref_path(prefix).join("/"),
    }
}

/// The remote a whole-remote prefix names: a `<remote>:` prefix whose ref half
/// is empty or `.`, which names every ref of that remote. A remote name holds no
/// `/`, so a prefix such as `or/igin:` is not one and reaches the refspec rule
/// whole.
fn whole_remote(prefix: &str) -> Option<&str> {
    match prefix.split_once(':') {
        Some((remote, "" | ".")) if !remote.contains('/') => Some(remote),
        _ => None,
    }
}

/// Whether a refspec is the prefix itself or is nested under it. `None`
/// matches every refspec.
fn matches_prefix(refspec: &str, prefix: Option<&str>) -> bool {
    prefix == Some(refspec) || nested_under_prefix(refspec, prefix)
}

/// Whether a refspec is nested under the prefix, with an exact match excluded.
/// `None` matches every refspec. This is the `-A` filter: a prefix equal to an
/// alias's own name is answered by resolving that name, so the filter reads a
/// prefix as a directory alone. A whole-remote prefix keeps every ref of the
/// remote it names, since its ref half stands for the remote's root.
fn nested_under_prefix(refspec: &str, prefix: Option<&str>) -> bool {
    let Some(prefix) = prefix else {
        return true;
    };
    match whole_remote(prefix) {
        Some(remote) => refspec
            .strip_prefix(remote)
            .is_some_and(|rest| rest.starts_with(':')),
        None => refspec
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/')),
    }
}

/// The name a listing prints for a refspec the given prefix selected: the part
/// below the prefix, or the whole refspec when the match is exact, when the
/// prefix names a remote in whole, or when no prefix applied. A remote's refspec
/// keeps its `remote:` part, since the tool strips within the ref name and
/// renders the refspec again -- `refs origin:rr` prints `origin:x` for
/// `origin:rr/x`.
fn strip_prefix_from(refspec: &str, prefix: Option<&str>) -> String {
    let nested = prefix
        .and_then(|prefix| refspec.strip_prefix(prefix))
        .and_then(|rest| rest.strip_prefix('/'));
    match (prefix, nested) {
        (Some(prefix), Some(nested)) => match prefix.split_once(':') {
            Some((remote, _)) => format!("{remote}:{nested}"),
            None => nested.to_owned(),
        },
        _ => refspec.to_owned(),
    }
}

/// The target an alias listing prints: the symlink body with its leading `../`
/// components removed, which is the form the tool prints, or the target ref's
/// refspec where the link leaves the alias's own ref root -- `refs/heads` for a
/// local alias, `refs/remotes/<remote>` for a remote one.
/// `refs -A --create=xal origin:rr/x` writes `../remotes/origin/rr/x`, so the
/// listing prints `origin:rr/x`, a name the port resolves, in place of the path
/// below `refs/` (`docs/conformance/cli-surface.md`, "P1").
fn alias_target(refspec: &str, target: &str) -> String {
    let path = ref_path(refspec);
    let root = path_refspec(&path).map(|(root, _)| root);
    let crossed = link_path(&path[..path.len() - 1], target)
        .and_then(|path| path_refspec(&path))
        .filter(|(target_root, _)| Some(target_root) != root.as_ref())
        .map(|(_, refspec)| refspec);
    crossed.unwrap_or_else(|| alias_body_name(target).to_owned())
}

/// The ref name an alias's link body gives: the body with its leading `../`
/// components removed, which is the form an `-A` listing prints and the name the
/// `--delete` guard reads.
fn alias_body_name(target: &str) -> &str {
    let mut rest = target;
    while let Some(stripped) = rest.strip_prefix("../") {
        rest = stripped;
    }
    rest
}

/// The components below `refs/` of the file one refspec names: `heads` and the
/// ref name for a local refspec, `remotes`, the remote, and the ref name for a
/// remote one.
fn ref_path(refspec: &str) -> Vec<&str> {
    let (mut path, name) = match refspec.split_once(':') {
        Some((remote, name)) => (vec!["remotes", remote], name),
        None => (vec!["heads"], refspec),
    };
    path.extend(name.split('/'));
    path
}

/// The ref root one path below `refs/` lives in, and the refspec it names.
/// `None` where the path names no ref file: a root with no name below it, or a
/// path under neither `refs/heads` nor `refs/remotes`.
fn path_refspec(path: &[&str]) -> Option<(String, String)> {
    match path {
        ["heads", name @ ..] if !name.is_empty() => Some(("heads".to_owned(), name.join("/"))),
        ["remotes", remote, name @ ..] if !name.is_empty() => Some((
            format!("remotes/{remote}"),
            format!("{remote}:{}", name.join("/")),
        )),
        _ => None,
    }
}

/// The path below `refs/` a symlink body names, read from `dir`, the directory
/// holding the link: each `..` drops one component. `None` where the body
/// reaches above `refs/`.
fn link_path<'a>(dir: &[&'a str], body: &'a str) -> Option<Vec<&'a str>> {
    let mut path = dir.to_vec();
    for part in body.split('/') {
        match part {
            ".." => {
                path.pop()?;
            }
            "." | "" => {}
            name => path.push(name),
        }
    }
    Some(path)
}

/// Print the commit each revision names, or the repository's single commit
/// under `-S`.
async fn rev_parse(repo: Repo, name: &str, args: RevParseArgs) -> Result<()> {
    if args.single {
        if !args.rev.is_empty() {
            exit_with_error(name, "Cannot specify arguments with --single");
        }
        let mut commits: Vec<Checksum> = repo
            .list_objects()
            .await?
            .into_iter()
            .filter(|object| object.ty == ObjectType::Commit)
            .map(|object| object.checksum)
            .collect();
        match commits.len() {
            0 => exit_error("No commit objects found"),
            1 => {
                println!("{}", commits.pop().expect("one commit").to_hex());
                return Ok(());
            }
            _ => exit_error("Multiple commit objects found"),
        }
    }
    if args.rev.is_empty() {
        exit_with_error(name, "REV must be specified");
    }
    for rev in &args.rev {
        println!("{}", resolve(&repo, rev).await?.to_hex());
    }
    Ok(())
}

/// How many symlinks one `cat` path may follow before the port gives up: a
/// chain this deep resolves and one link deeper is refused. The tool bounds the
/// depth nowhere -- 20000 links resolve, and a self-referencing link recurses
/// until the process dies (`docs/conformance/cli-surface.md`, "P1 -- reading
/// and resolution").
const CAT_SYMLINK_LIMIT: usize = 256;

/// Why a `cat` path wrote nothing: a refusal the port reports in the tool's own
/// words and exits 1 on, or a library error the top-level renderer prints. Both
/// travel back to [`cat`] as values, so the stdout writer settles before the
/// process leaves the command.
enum CatFailure {
    Refused(String),
    Failed(Error),
}

impl From<Error> for CatFailure {
    fn from(err: Error) -> Self {
        Self::Failed(err)
    }
}

/// Write each named file's content to stdout, in order, streaming it.
async fn cat(repo: Repo, name: &str, args: CatArgs) -> Result<()> {
    let Some(rev) = args.commit.as_deref().filter(|_| !args.path.is_empty()) else {
        exit_with_error(name, "A COMMIT and at least one PATH argument are required");
    };
    let commit = resolve(&repo, rev).await?;
    let (root, _) = repo.read_commit(&commit.to_hex()).await?;
    let mut stdout = stdout_file()?;
    let written = cat_paths(&repo, &root, &args.path, &mut stdout).await;
    // The async writer over the duplicated stdout descriptor holds the bytes
    // its blocking worker has not taken, so the tail of a large payload is lost
    // unless the writes settle before the process exits. A refusal and an I/O
    // error leave the command through here as well, so each one settles the
    // bytes already written before it is reported.
    let settled = stdout.flush().await.map_err(Error::Io);
    // Where a path failed and the flush failed with it, the path failure is the
    // one reported: it names the condition the invocation is measured on. The
    // two failure branches therefore drop `settled`.
    match written {
        Ok(()) => settled,
        Err(CatFailure::Refused(message)) => exit_error(&message),
        Err(CatFailure::Failed(err)) => Err(err),
    }
}

/// Write each path's content to `out`, in order, stopping at the first failure.
async fn cat_paths(
    repo: &Repo,
    root: &RepoTree,
    paths: &[String],
    out: &mut ostrya_rt::File,
) -> std::result::Result<(), CatFailure> {
    for path in paths {
        let file = cat_lookup(repo, root, path).await?;
        file.write_to(out).await?;
    }
    Ok(())
}

/// Resolve one `cat` path to the regular file it names.
///
/// The path is split on `/` and each component looked up on its own, so `.`,
/// `..`, and an empty component each name nothing, which is what the tool does
/// with them. A symlink in the final position is followed, its target read
/// relative to the link's own directory; a symlink in any other position is
/// not followed, and reports `Not a directory` the way the tool does.
///
/// An empty argument reaches no component at all and reports the commit root as
/// absent, which is what the tool does with it; `/` reaches the root and is
/// refused as a directory.
async fn cat_lookup(
    repo: &Repo,
    root: &RepoTree,
    path: &str,
) -> std::result::Result<FileObject, CatFailure> {
    if path.is_empty() {
        return Err(cat_refusal("No such file or directory: /"));
    }
    let mut components = split_cat_path(path);
    // One iteration per link followed, plus the one that reads the file the
    // last link names.
    for _ in 0..=CAT_SYMLINK_LIMIT {
        let file = match lookup_components(root, &components).await? {
            TreeEntry::File { checksum, .. } => repo.load_file(&checksum).await?,
            TreeEntry::Dir { .. } => return Err(cat_refusal("Can't open directory")),
        };
        match &file.kind {
            FileKind::Symlink { target } => components = follow_link(&components, target),
            FileKind::Regular { .. } => return Ok(file),
        }
    }
    Err(cat_refusal("Too many levels of symbolic links"))
}

/// One `cat` refusal, held as a value until the stdout writer settles.
fn cat_refusal(message: &str) -> CatFailure {
    CatFailure::Refused(message.to_owned())
}

/// Walk `components` from `root`, one component at a time, to the entry they
/// name. An empty component list names the commit root, which is a directory
/// and so the same refusal a directory path gets.
async fn lookup_components(
    root: &RepoTree,
    components: &[String],
) -> std::result::Result<TreeEntry, CatFailure> {
    let mut current = root.clone();
    for (index, component) in components.iter().enumerate() {
        let last = index + 1 == components.len();
        match current.lookup(Path::new(component)).await? {
            Some(TreeEntry::Dir { name, tree }) => {
                if last {
                    return Ok(TreeEntry::Dir { name, tree });
                }
                current = tree;
            }
            Some(entry @ TreeEntry::File { .. }) => {
                if last {
                    return Ok(entry);
                }
                return Err(cat_refusal("Not a directory"));
            }
            None => {
                return Err(cat_refusal(&format!(
                    "No such file or directory: /{}",
                    components[..=index].join("/")
                )));
            }
        }
    }
    Err(cat_refusal("Can't open directory"))
}

/// Split a `cat` path into the components to look up: one optional leading `/`
/// is dropped and the rest split on `/`, keeping every other component
/// verbatim so `.`, `..`, and an empty one are looked up and not found.
fn split_cat_path(path: &str) -> Vec<String> {
    let rest = path.strip_prefix('/').unwrap_or(path);
    if rest.is_empty() {
        return Vec::new();
    }
    rest.split('/').map(str::to_owned).collect()
}

/// The components a symlink's target names: relative to the link's own
/// directory, or to the commit root for an absolute target.
fn follow_link(components: &[String], target: &str) -> Vec<String> {
    let mut out = if target.starts_with('/') {
        Vec::new()
    } else {
        components[..components.len() - 1].to_vec()
    };
    out.extend(split_cat_path(target));
    out
}

// --- show, log, ls, config ---------------------------------------------------

/// The commit object's GVariant signature, which the raw report parses against.
const COMMIT_SIGNATURE: &str = "(a{sv}aya(say)sstayay)";

/// Parse a GVariant type signature, carrying the codec's refusal as a format
/// error, so a signature the user typed is reported rather than panicking.
fn parse_type(signature: &str) -> Result<Type> {
    Type::parse(signature).map_err(|err| Error::InvalidFormat(err.to_string()))
}

/// Render a value in the GVariant text form, carrying a type mismatch as a
/// format error.
fn variant_text(ty: &Type, value: &Value) -> Result<String> {
    to_text(ty, value).map_err(|err| Error::InvalidFormat(err.to_string()))
}

/// Report one object.
///
/// The reporting modes are mutually exclusive and take a fixed precedence,
/// recovered by giving the tool each pair (`docs/format-reference.md`, "CLI
/// output formats", under `show`): the detached metadata key, the metadata key,
/// the detached key listing, the key listing, the related commits, the variant
/// file, the sizes, and last the object's own report.
async fn show(repo: Repo, repo_path: PathBuf, name: &str, args: ShowArgs) -> Result<()> {
    let Some(object) = args.object.as_deref() else {
        exit_with_error(name, "An object argument is required");
    };
    if let Some(key) = args.print_detached_metadata_key.as_deref() {
        return show_detached_key(&repo, object, key, &args).await;
    }
    if let Some(key) = args.print_metadata_key.as_deref() {
        return show_metadata_key(&repo, object, key, &args).await;
    }
    if args.list_detached_metadata_keys {
        return show_detached_keys(&repo, object).await;
    }
    if args.list_metadata_keys {
        return show_metadata_keys(&repo, object).await;
    }
    if args.print_related {
        return show_related(&repo, object).await;
    }
    if let Some(signature) = args.print_variant_type.as_deref() {
        return show_variant_file(signature, Path::new(object)).await;
    }
    if args.print_sizes {
        return show_sizes(&repo, object).await;
    }
    show_object(&repo, &repo_path, object, &args).await
}

/// The commit metadata dict of the revision `object` names, byte-order
/// converted unless `-B` was given. The dict is the commit's first member.
async fn commit_metadata(repo: &Repo, object: &str, args: &ShowArgs) -> Result<Value> {
    let checksum = resolve(repo, object).await?;
    let commit = repo.load_variant(ObjectType::Commit, &checksum).await?;
    let commit = maybe_byteswap(commit, args);
    commit
        .as_tuple()
        .and_then(|members| members.first())
        .cloned()
        .ok_or_else(|| Error::InvalidFormat("commit object is not a tuple".into()))
}

/// A loaded variant with the on-disk big-endian fields converted, which `-B`
/// suppresses so the numbers report as they are stored.
fn maybe_byteswap(value: Value, args: &ShowArgs) -> Value {
    if args.no_byteswap {
        value
    } else {
        value.byteswapped()
    }
}

/// Print one commit metadata key's value.
async fn show_metadata_key(repo: &Repo, object: &str, key: &str, args: &ShowArgs) -> Result<()> {
    let metadata = commit_metadata(repo, object, args).await?;
    let Some(value) = metadata.dict_get(key) else {
        exit_error(&format!("No such metadata key '{key}'"));
    };
    print_metadata_value(value, args.print_hex)
}

/// Print one detached metadata key's value.
async fn show_detached_key(repo: &Repo, object: &str, key: &str, args: &ShowArgs) -> Result<()> {
    let dict = detached_metadata(repo, object, args).await?;
    let Some(value) = dict.dict_get(key) else {
        exit_error(&format!("No such metadata key '{key}'"));
    };
    print_metadata_value(value, args.print_hex)
}

/// The commit's detached metadata dict, byte-order converted unless `-B` was
/// given. A commit with no `.commitmeta` is reported in the tool's own words.
async fn detached_metadata(repo: &Repo, object: &str, args: &ShowArgs) -> Result<Value> {
    let checksum = resolve(repo, object).await?;
    let Some(dict) = repo.read_commit_detached_metadata(&checksum).await? else {
        exit_error(&format!(
            "No detached metadata for commit {}",
            checksum.to_hex()
        ));
    };
    Ok(maybe_byteswap(dict, args))
}

/// Print a metadata value, which is a `v` holding the value proper. With
/// `--print-hex` a byte-array value prints as unquoted lowercase hex, and every
/// other type ignores the switch.
fn print_metadata_value(value: &Value, hex: bool) -> Result<()> {
    let (ty, inner) = match value.as_variant() {
        Some((ty, inner)) => (ty.clone(), inner),
        None => (Type::Str, value),
    };
    if hex && ty == Type::Array(Box::new(Type::Byte)) {
        let bytes = inner.as_bytes().unwrap_or_default();
        let mut text = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            text.push_str(&format!("{byte:02x}"));
        }
        println!("{text}");
        return Ok(());
    }
    println!("{}", variant_text(&ty, inner)?);
    Ok(())
}

/// Print the commit metadata keys, sorted.
async fn show_metadata_keys(repo: &Repo, object: &str) -> Result<()> {
    let checksum = resolve(repo, object).await?;
    let (commit, _) = repo.load_commit(&checksum).await?;
    print_sorted_keys(&commit.metadata);
    Ok(())
}

/// Print the detached metadata keys, sorted.
async fn show_detached_keys(repo: &Repo, object: &str) -> Result<()> {
    let checksum = resolve(repo, object).await?;
    let Some(dict) = repo.read_commit_detached_metadata(&checksum).await? else {
        exit_error(&format!(
            "No detached metadata for commit {}",
            checksum.to_hex()
        ));
    };
    print_sorted_keys(&dict);
    Ok(())
}

/// Print an `a{sv}` dict's keys, one per line, in sort order rather than the
/// order the dict stores them in.
fn print_sorted_keys(dict: &Value) {
    let mut keys: Vec<&str> = dict
        .as_array()
        .unwrap_or_default()
        .iter()
        .filter_map(|entry| entry.as_tuple()?.first()?.as_str())
        .collect();
    keys.sort_unstable();
    for key in keys {
        println!("{key}");
    }
}

/// Print the commit's related-objects array, one `ref checksum` pair per line.
/// The array is empty on every commit the tool writes, so a commit that carries
/// none prints nothing at exit 0.
async fn show_related(repo: &Repo, object: &str) -> Result<()> {
    let checksum = resolve(repo, object).await?;
    let (commit, _) = repo.load_commit(&checksum).await?;
    for (refspec, target) in &commit.related {
        let target = Checksum::from_ay(target)?;
        println!("{refspec} {}", target.to_hex());
    }
    Ok(())
}

/// The ceiling on a file read as a GVariant value by `--print-variant-type`.
/// A metadata object the format defines stays far below it, and the whole file
/// is parsed in memory, so a larger one is refused by name rather than read.
const MAX_VARIANT_FILE: u64 = 16 * 1024 * 1024;

/// Read `path` as a serialized value of the named type and print it. The
/// numeric fields are byte-order converted, which is what the tool does on this
/// path whether or not `-B` is given.
async fn show_variant_file(signature: &str, path: &Path) -> Result<()> {
    let ty = parse_type(signature)?;
    let owned = path.to_owned();
    let bytes = match ostrya_rt::unblock(move || read_bounded(&owned, MAX_VARIANT_FILE)).await {
        Ok(bytes) => bytes,
        Err(message) => exit_error(&message),
    };
    let value = from_bytes(&ty, &bytes).map_err(|err| Error::InvalidFormat(err.to_string()))?;
    println!("{}", variant_text(&ty, &value.byteswapped())?);
    Ok(())
}

/// Read a whole file, refusing one longer than `limit`. A refusal comes back as
/// the line it is reported on, in the tool's own `openat(<path>): <reason>`
/// shape for a path that does not open.
fn read_bounded(path: &Path, limit: u64) -> std::result::Result<Vec<u8>, String> {
    let opened = |err: &std::io::Error| format!("openat({}): {}", path.display(), io_reason(err));
    let meta = std::fs::metadata(path).map_err(|err| opened(&err))?;
    if meta.len() > limit {
        return Err(format!(
            "{} is {} bytes, over the {limit}-byte ceiling for a variant file",
            path.display(),
            meta.len()
        ));
    }
    std::fs::read(path).map_err(|err| opened(&err))
}

/// The system's own reason text for an I/O error, without the `(os error N)`
/// tail Rust appends, which is the form the tool's messages carry.
fn io_reason(err: &std::io::Error) -> String {
    let text = err.to_string();
    match text.find(" (os error ") {
        Some(cut) => text[..cut].to_owned(),
        None => text,
    }
}

/// Print the commit's recorded sizes and how much of them is absent locally.
async fn show_sizes(repo: &Repo, object: &str) -> Result<()> {
    let checksum = resolve(repo, object).await?;
    let Some(sizes) = repo.commit_sizes(&checksum).await? else {
        exit_error("No metadata key ostree.sizes in commit");
    };
    println!(
        "Compressed size (needed/total): {} bytes/{} bytes",
        sizes.compressed_needed, sizes.compressed_total
    );
    println!(
        "Unpacked size (needed/total): {} bytes/{} bytes",
        sizes.unpacked_needed, sizes.unpacked_total
    );
    println!(
        "Number of objects (needed/total): {}/{}",
        sizes.objects_needed, sizes.objects_total
    );
    Ok(())
}

/// Report the object `object` names: a metadata object by type and checksum, a
/// commit additionally by its own report, and a file object by its header.
///
/// The object type is recovered by probing the store, since a bare checksum
/// names no type: commit, then dirtree, then dirmeta, then a file object, whose
/// absence is the failure reported when nothing of that checksum is present.
async fn show_object(repo: &Repo, repo_path: &Path, object: &str, args: &ShowArgs) -> Result<()> {
    let checksum = resolve(repo, object).await?;
    for ty in [ObjectType::Commit, ObjectType::DirTree, ObjectType::DirMeta] {
        if !repo.has_object(ty, &checksum).await? {
            continue;
        }
        println!("{} {}", object_type_name(ty), checksum.to_hex());
        if args.raw || args.no_byteswap {
            let value = repo.load_variant(ty, &checksum).await?;
            let value = maybe_byteswap(value, args);
            let signature = parse_type(metadata_signature(ty))?;
            println!("{}", variant_text(&signature, &value)?);
        }
        // `--raw` alone reports the variant and stops; `-B` reports it and goes
        // on to the commit's own report.
        if ty == ObjectType::Commit && (!args.raw || args.no_byteswap) {
            report_commit(repo, repo_path, &checksum, args).await?;
        }
        return Ok(());
    }
    match repo.load_file(&checksum).await {
        Ok(file) => report_file(&checksum, &file),
        Err(Error::ObjectNotFound { .. }) => {
            // The absent-object line carries a prefix naming the open in every
            // mode that stores the payload in the object file itself, and not in
            // `archive`, whose header is read on its own
            // (`docs/format-reference.md`, "CLI output formats", under `show`).
            let hex = checksum.to_hex();
            let refusal = format!("Couldn't find file object '{hex}'");
            if repo.mode() == RepoMode::Archive {
                exit_error(&refusal);
            }
            exit_error(&format!("Opening content object {hex}: {refusal}"));
        }
        Err(err) => Err(err),
    }
}

/// The name the tool prints for an object type.
fn object_type_name(ty: ObjectType) -> &'static str {
    match ty {
        ObjectType::Commit => "commit",
        ObjectType::DirTree => "dirtree",
        ObjectType::DirMeta => "dirmeta",
        ObjectType::File => "file",
        ObjectType::CommitMeta => "commitmeta",
        ObjectType::FileXattrs => "file-xattrs",
        ObjectType::FileXattrsLink => "file-xattrs-link",
        ObjectType::PayloadLink => "payload-link",
        ObjectType::TombstoneCommit => "tombstone-commit",
    }
}

/// The GVariant signature of a metadata object type, for the raw report.
fn metadata_signature(ty: ObjectType) -> &'static str {
    match ty {
        ObjectType::DirTree => "(a(say)a(sayay))",
        ObjectType::DirMeta => "(uuua(ayay))",
        _ => COMMIT_SIGNATURE,
    }
}

/// Print a commit's own report: its parent, content checksum, date, the
/// `version` metadata key when it carries one, the subject and body, and the
/// signature report when it carries GPG signatures.
async fn report_commit(
    repo: &Repo,
    repo_path: &Path,
    checksum: &Checksum,
    args: &ShowArgs,
) -> Result<()> {
    let (commit, _) = repo.load_commit(checksum).await?;
    if let Some(parent) = &commit.parent {
        println!("Parent:  {}", parent.to_hex());
    }
    println!("ContentChecksum:  {}", commit.content_checksum().to_hex());
    println!("Date:  {}", format_utc(commit.timestamp));
    if let Some(version) =
        commit
            .metadata
            .dict_get("version")
            .and_then(|value| match value.as_variant() {
                Some((_, inner)) => inner.as_str(),
                None => value.as_str(),
            })
    {
        println!("Version: {version}");
    }
    if commit.subject.is_empty() {
        println!("(no subject)");
    } else {
        println!();
        print_indented(&commit.subject);
    }
    if !commit.body.is_empty() {
        println!();
        print_indented(&commit.body);
    }
    println!();
    report_commit_signatures(repo, repo_path, checksum, args).await
}

/// Print each line of `text` indented four spaces, the shape the commit report
/// gives a subject and a body.
fn print_indented(text: &str) {
    for line in text.split('\n') {
        println!("    {line}");
    }
}

/// Print the GPG signature report a commit's `ostree.gpgsigs` draws, or nothing
/// when it carries none.
#[cfg(feature = "gpg")]
async fn report_commit_signatures(
    repo: &Repo,
    repo_path: &Path,
    checksum: &Checksum,
    args: &ShowArgs,
) -> Result<()> {
    if stored_signatures(repo, checksum, "ostree.gpgsigs")
        .await?
        .is_empty()
    {
        return Ok(());
    }
    let verifier = show_gpg_verifier(repo_path, args)?;
    let outcome = repo
        .verify_commit(checksum, &[&verifier as &dyn Verifier])
        .await?;
    println!();
    let plural = if outcome.signatures.len() == 1 {
        ""
    } else {
        "s"
    };
    println!("Found {} signature{plural}:", outcome.signatures.len());
    for sig in &outcome.signatures {
        println!();
        let made = sig.created.map(format_utc).unwrap_or_default();
        let algorithm = sig.pubkey_algorithm.as_deref().unwrap_or("unknown");
        let key_id = sig
            .fingerprint
            .as_deref()
            .map(short_key_id)
            .unwrap_or_default();
        println!("  Signature made {made} using {algorithm} key ID {key_id}");
        if sig.key_missing {
            println!("  Can't check signature: public key not found");
        } else if sig.valid {
            println!("  Good signature from \"{}\"", signer_uid(sig));
        } else {
            println!("  BAD signature from \"{}\"", signer_uid(sig));
        }
    }
    Ok(())
}

/// Without the gpg engine compiled in there are no signatures to report, and
/// the two GPG options are accepted and unused.
#[cfg(not(feature = "gpg"))]
async fn report_commit_signatures(_: &Repo, _: &Path, _: &Checksum, _: &ShowArgs) -> Result<()> {
    Ok(())
}

/// The keyrings `show` verifies a commit's GPG signatures against: the
/// repository's own `gpgkeys.gpg`, every `*.gpg` file in a `--gpg-homedir`, or,
/// under `--gpg-verify-remote`, that remote's whole trusted set.
#[cfg(feature = "gpg")]
fn show_gpg_verifier(repo_path: &Path, args: &ShowArgs) -> Result<GpgVerifier> {
    if let Some(remote) = args.gpg_verify_remote.as_deref() {
        return GpgVerifier::for_remote(repo_path, remote);
    }
    let mut paths = vec![repo_path.join("gpgkeys.gpg")];
    if let Some(homedir) = args.gpg_homedir.as_deref() {
        let mut found: Vec<PathBuf> = std::fs::read_dir(homedir)
            .map_err(Error::Io)?
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                (path.extension()? == "gpg").then_some(path)
            })
            .collect();
        found.sort();
        paths.extend(found);
    }
    GpgVerifier::from_keyring_files(paths)
}

/// The trailing sixteen hex digits of a fingerprint, the form the signature
/// report names a key by.
#[cfg(feature = "gpg")]
fn short_key_id(fingerprint: &str) -> &str {
    let start = fingerprint.len().saturating_sub(16);
    &fingerprint[start..]
}

/// The signer's user id as one string, `Name <email>`, from the parts the
/// engine reported.
#[cfg(feature = "gpg")]
fn signer_uid(sig: &SignatureInfo) -> String {
    match (&sig.user_name, &sig.user_email) {
        (Some(name), Some(email)) => format!("{name} <{email}>"),
        (Some(name), None) => name.clone(),
        (None, Some(email)) => format!("<{email}>"),
        (None, None) => String::new(),
    }
}

/// Print a file object's header report.
fn report_file(checksum: &Checksum, file: &FileObject) -> Result<()> {
    println!("Object: {}", checksum.to_hex());
    println!("Type: file");
    match &file.kind {
        FileKind::Regular { size } => {
            println!("File Type: regular");
            println!("Size: {size}");
        }
        FileKind::Symlink { target } => {
            println!("File Type: symlink");
            println!("Target: {target}");
        }
    }
    println!("Mode: 0{:o}", file.mode);
    println!("Uid: {}", file.uid);
    println!("Gid: {}", file.gid);
    println!("Extended Attributes: {}", xattrs_text(&file.xattrs)?);
    Ok(())
}

/// The xattr set in the `{ <a(ayay) text> }` form the file report and `ls -X`
/// both print.
fn xattrs_text(xattrs: &Xattrs) -> Result<String> {
    let ty = parse_type("a(ayay)")?;
    let entries: Vec<Value> = xattrs
        .iter()
        .map(|(name, value)| {
            Value::Tuple(vec![
                Value::Bytes(name.to_vec()),
                Value::Bytes(value.to_vec()),
            ])
        })
        .collect();
    Ok(format!(
        "{{ {} }}",
        variant_text(&ty, &Value::Array(entries))?
    ))
}

/// Walk a commit's parent chain, newest first, reporting each commit.
///
/// A parent whose commit object is absent ends the walk with the tool's own
/// note, at exit 0, so a partial history reports what it holds. The starting
/// revision itself is held to the stricter rule every other reading command
/// uses: a checksum naming no commit is refused rather than read as an empty
/// history.
async fn log(repo: Repo, repo_path: PathBuf, name: &str, args: LogArgs) -> Result<()> {
    let Some(rev) = args.rev.as_deref() else {
        exit_with_error(name, "A rev argument is required");
    };
    let show = ShowArgs {
        raw: args.raw,
        ..ShowArgs::default()
    };
    let start = resolve(&repo, rev).await?;
    if !repo.has_object(ObjectType::Commit, &start).await? {
        return Err(Error::ObjectNotFound {
            checksum: start,
            ty: ObjectType::Commit,
        });
    }
    let mut current = Some(start);
    while let Some(checksum) = current {
        if !repo.has_object(ObjectType::Commit, &checksum).await? {
            println!("<< History beyond this commit not fetched >>");
            return Ok(());
        }
        println!("commit {}", checksum.to_hex());
        if args.raw {
            let value = repo.load_variant(ObjectType::Commit, &checksum).await?;
            let ty = parse_type(COMMIT_SIGNATURE)?;
            println!("{}", variant_text(&ty, &value.byteswapped())?);
        } else {
            report_commit(&repo, &repo_path, &checksum, &show).await?;
        }
        let (commit, _) = repo.load_commit(&checksum).await?;
        current = commit.parent;
    }
    Ok(())
}

/// One `ls` line's worth of entry facts, gathered before the line is written so
/// every column has a single source.
struct LsEntry {
    kind: char,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    checksums: Vec<Checksum>,
    xattrs: Xattrs,
    path: String,
    target: Option<String>,
}

/// List the paths a commit holds.
async fn ls(repo: Repo, name: &str, args: LsArgs) -> Result<()> {
    let Some(rev) = args.commit.as_deref() else {
        exit_with_error(name, "An COMMIT argument is required");
    };
    // The revision resolves through the shared reader, so a name no ref holds
    // is reported in the tool's own words here as it is at every other command.
    let checksum = resolve(&repo, rev).await?;
    let (root, _) = repo.read_commit(&checksum.to_hex()).await?;
    if args.path.is_empty() {
        return ls_directory(&repo, &root, "/", &args).await;
    }
    for given in &args.path {
        let path = normalize_ls_path(given);
        // An empty argument names the root and is still refused, which is what
        // the tool does with it.
        if path == "/" && !given.is_empty() {
            ls_directory(&repo, &root, "/", &args).await?;
            continue;
        }
        match root.lookup(Path::new(&path)).await? {
            Some(TreeEntry::Dir { tree, .. }) => {
                ls_directory(&repo, &tree, &path, &args).await?;
            }
            Some(TreeEntry::File { checksum, .. }) => {
                let entry = ls_file_entry(&repo, &checksum, &path).await?;
                print_ls_entry(&entry, &args);
            }
            None => exit_error(&format!(
                "Inspecting path '{given}': No such file or directory: {path}"
            )),
        }
    }
    Ok(())
}

/// The path an `ls` argument names, with one optional leading `/` supplied.
fn normalize_ls_path(given: &str) -> String {
    let trimmed = given.trim_start_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else {
        format!("/{trimmed}")
    }
}

/// Print a directory and, unless `-d` was given, its children; with `-R`, every
/// child directory's own contents follow it.
async fn ls_directory(repo: &Repo, tree: &RepoTree, path: &str, args: &LsArgs) -> Result<()> {
    let entry = ls_dir_entry(repo, tree, path).await?;
    print_ls_entry(&entry, args);
    if args.dironly {
        return Ok(());
    }
    ls_children(repo, tree, path, args).await
}

/// Print a directory's children, recursing where `-R` asks for it.
///
/// The stack holds individual entries rather than whole directories, so
/// printing a directory's line queues its own children right away, ahead of
/// whatever siblings are still pending: the next line popped is always that
/// directory's first child, which is what puts its contents immediately after
/// its own line rather than after every sibling's line at the same level.
async fn ls_children(repo: &Repo, tree: &RepoTree, path: &str, args: &LsArgs) -> Result<()> {
    // The recursion is a work list rather than recursive calls, so a deep tree
    // cannot grow the future's size with its depth.
    let mut pending: Vec<(TreeEntry, String)> = Vec::new();
    queue_children(&mut pending, tree, path).await?;
    while let Some((child, base)) = pending.pop() {
        match child {
            TreeEntry::File { name, checksum } => {
                let child_path = join_ls_path(&base, &name);
                let entry = ls_file_entry(repo, &checksum, &child_path).await?;
                print_ls_entry(&entry, args);
            }
            TreeEntry::Dir { name, tree } => {
                let child_path = join_ls_path(&base, &name);
                let entry = ls_dir_entry(repo, &tree, &child_path).await?;
                print_ls_entry(&entry, args);
                if args.recursive {
                    queue_children(&mut pending, &tree, &child_path).await?;
                }
            }
        }
    }
    Ok(())
}

/// Push `tree`'s entries onto `pending`, in reverse so the stack pops them
/// back in `read_dir`'s own order: files, then subdirectories, each in name
/// order.
async fn queue_children(
    pending: &mut Vec<(TreeEntry, String)>,
    tree: &RepoTree,
    base: &str,
) -> Result<()> {
    let mut children = tree.read_dir().await?;
    children.reverse();
    pending.extend(children.into_iter().map(|child| (child, base.to_owned())));
    Ok(())
}

/// The path of `name` inside the directory at `base`.
fn join_ls_path(base: &str, name: &str) -> String {
    if base == "/" {
        format!("/{name}")
    } else {
        format!("{base}/{name}")
    }
}

/// Gather a directory's `ls` facts from its dirmeta.
async fn ls_dir_entry(repo: &Repo, tree: &RepoTree, path: &str) -> Result<LsEntry> {
    let meta = repo.load_dirmeta(tree.dirmeta_checksum()).await?;
    Ok(LsEntry {
        kind: 'd',
        mode: meta.mode,
        uid: meta.uid,
        gid: meta.gid,
        size: 0,
        checksums: vec![*tree.dirtree_checksum(), *tree.dirmeta_checksum()],
        xattrs: meta.xattrs,
        path: path.to_owned(),
        target: None,
    })
}

/// Gather a file's `ls` facts from its object header.
async fn ls_file_entry(repo: &Repo, checksum: &Checksum, path: &str) -> Result<LsEntry> {
    let file = repo.load_file(checksum).await?;
    let (kind, size, target) = match &file.kind {
        FileKind::Regular { size } => ('-', *size, None),
        FileKind::Symlink { target } => ('l', 0, Some(target.clone())),
    };
    Ok(LsEntry {
        kind,
        mode: file.mode,
        uid: file.uid,
        gid: file.gid,
        size,
        checksums: vec![*checksum],
        xattrs: file.xattrs,
        path: path.to_owned(),
        target,
    })
}

/// Write one `ls` line, or the path alone under `--nul-filenames-only`.
fn print_ls_entry(entry: &LsEntry, args: &LsArgs) {
    use std::io::Write;
    if args.nul_filenames_only {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(entry.path.as_bytes());
        let _ = out.write_all(b"\0");
        return;
    }
    let mut line = format!(
        "{}{:05o} {} {} {:>6}",
        entry.kind,
        entry.mode & 0o7777,
        entry.uid,
        entry.gid,
        entry.size
    );
    if args.checksum {
        for checksum in &entry.checksums {
            line.push(' ');
            line.push_str(&checksum.to_hex());
        }
    }
    if args.xattrs {
        // The xattr set came out of a parsed object, so it renders; a printer
        // failure here would be a codec bug rather than input the user gave.
        let text = xattrs_text(&entry.xattrs).unwrap_or_else(|_| "{ }".to_owned());
        line.push(' ');
        line.push_str(&text);
    }
    line.push(' ');
    line.push_str(&entry.path);
    if let Some(target) = &entry.target {
        line.push_str(" -> ");
        line.push_str(target);
    }
    println!("{line}");
}

/// Read a repository configuration value.
async fn config(repo: Repo, name: &str, args: ConfigArgs) -> Result<()> {
    let Some(operation) = args.operation.as_deref() else {
        exit_with_error(name, "OPERATION must be specified");
    };
    // The operand count is checked ahead of the operation name: `set` takes a
    // key and a value, and every other operation, a name the tool does not know
    // included, takes a key alone (`docs/format-reference.md`, "CLI output
    // formats", under `config get`).
    let allowed = if operation == "set" { 2 } else { 1 };
    if args.args.len() > allowed {
        exit_with_error(name, "Too many arguments given");
    }
    match operation {
        "get" => config_get(&repo, &args),
        "set" | "unset" => exit_error(&format!("The {operation} operation is not implemented yet")),
        other => exit_error(&format!("Unknown operation {other}")),
    }
}

/// Print one configuration value. The key is `section.key`, split on its first
/// `.`, or a bare key name when `--group` names the section.
fn config_get(repo: &Repo, args: &ConfigArgs) -> Result<()> {
    let Some(key) = args.args.first() else {
        if args.group.is_some() {
            exit_error("Group name and key must be specified");
        }
        exit_error("KEY must be specified");
    };
    let (group, key) = match args.group.as_deref() {
        Some(group) => (group, key.as_str()),
        None => match key.split_once('.') {
            Some((group, key)) => (group, key),
            None => exit_error("Key must be of the form \"sectionname.keyname\""),
        },
    };
    let keyfile = repo.config().keyfile();
    if !keyfile.has_group(group) {
        exit_error(&format!(
            "Key file does not have group \u{201c}{group}\u{201d}"
        ));
    }
    match keyfile.get_string(group, key)? {
        Some(value) => println!("{value}"),
        None => exit_error(&format!(
            "Key file does not have key \u{201c}{key}\u{201d} in group \u{201c}{group}\u{201d}"
        )),
    }
    Ok(())
}

/// Render a timestamp as the commit report's `Date:` line does: UTC, in
/// `YYYY-MM-DD HH:MM:SS +0000`. The stored field is unsigned and a pre-epoch
/// instant is its two's-complement form, so it is read as a signed count of
/// seconds, matching the tool.
fn format_utc(timestamp: u64) -> String {
    let seconds = timestamp as i64;
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (rest / 3600, (rest % 3600) / 60, rest % 60);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} +0000")
}

/// The civil date `days` days after 1970-01-01, the inverse of
/// [`days_from_civil`].
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    (if month <= 2 { year + 1 } else { year }, month, day)
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

/// Resolve a revision -- a checksum, a refspec, or either with a trailing `^`
/// per generation of ancestry -- to a commit checksum, reporting the two
/// resolution failures in the tool's own words. `resolve_rev` with
/// `allow_noent = false` returns `Some` or an error, never `None`.
async fn resolve(repo: &Repo, rev: &str) -> Result<Checksum> {
    match repo.resolve_rev(rev, false).await {
        Ok(checksum) => {
            Ok(checksum.expect("resolve_rev with allow_noent=false returns Some or errors"))
        }
        Err(err) => Err(report_resolution_failure(err)),
    }
}

/// The same for a revision that may be absent: `None` states that nothing of
/// that name is in the repository, and a resolution failure carries the same
/// words [`resolve`] gives it.
async fn resolve_optional(repo: &Repo, rev: &str) -> Result<Option<Checksum>> {
    match repo.resolve_rev(rev, true).await {
        Ok(found) => Ok(found),
        Err(err) => Err(report_resolution_failure(err)),
    }
}

/// Report the two resolution failures in the tool's own words, so one condition
/// has one message wherever a revision is resolved, and hand every other error
/// back to the caller.
fn report_resolution_failure(err: Error) -> Error {
    match err {
        Error::RefNotFound(refspec) => exit_error(&format!("Refspec '{refspec}' not found")),
        Error::NoParentCommit(commit) => {
            exit_error(&format!("Commit {} has no parent", commit.to_hex()))
        }
        other => other,
    }
}

/// The `ostree.ref-binding` metadata dict a commit carries: the branch `-b`
/// named, or an empty `as` array where the commit names none, which is the value
/// the tool writes under `--orphan` alone
/// (`docs/format-reference.md`, "CLI output formats").
fn ref_binding(branch: Option<&str>) -> Value {
    let names = branch
        .map(|branch| Value::Str(branch.to_owned()))
        .into_iter()
        .collect();
    Value::Array(vec![Value::Tuple(vec![
        Value::Str("ostree.ref-binding".to_owned()),
        Value::variant(
            Type::parse("as").expect("\"as\" is a valid gvariant type"),
            Value::Array(names),
        ),
    ])])
}

/// The message a branch name the revision syntax shadows is refused with, and
/// `None` for a name a ref can carry. Resolution reads a trailing run of `^` as
/// ancestry and a name of 64 lowercase hex characters as a checksum, so a ref
/// carrying either is reachable by no revision
/// (`docs/format-reference.md`, "Revision syntax"). Each message is the wording
/// the port already gives that shape -- the ancestry name at `refs --create`, the
/// checksum name at the tool's own guard -- and the two shapes are disjoint, a
/// 64-character hex name holding no `^`.
fn shadowed_branch_name(branch: &str) -> Option<String> {
    if branch.ends_with('^') {
        return Some(format!("Invalid refspec {branch}"));
    }
    if Checksum::from_hex_lower(branch).is_ok() {
        return Some(format!("Rev name '{branch}' looks like a checksum"));
    }
    None
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

    /// An `--owner-uid`/`--owner-gid` value reads as a C `int` with the base
    /// taken from the text: `0x` hexadecimal, a leading `0` octal, decimal
    /// otherwise. Leading whitespace and a sign are accepted, a trailing byte is
    /// not, and the range is a C `int`'s. Each value here was checked against
    /// `ostree commit` (`docs/format-reference.md`, "CLI output formats").
    #[test]
    fn an_owner_id_reads_as_a_c_int() {
        for (text, value) in [
            ("0", 0),
            ("42", 42),
            ("+5", 5),
            ("-0", 0),
            (" 5", 5),
            ("\t7", 7),
            ("0x10", 16),
            ("0X10", 16),
            ("010", 8),
            ("07", 7),
            ("2147483647", 2147483647),
            ("-1", -1),
            ("-2147483648", -2147483648),
        ] {
            assert_eq!(parse_c_int(text), Ok(value), "`{text}`");
        }
        for text in ["abc", "", "5x", "5 ", "0x", "-", "--5", "5-", "0b1", "x5"] {
            assert_eq!(parse_c_int(text), Err(IntError::Syntax), "`{text}`");
        }
        for text in [
            "2147483648",
            "4294967295",
            "99999999999999999999",
            "-2147483649",
        ] {
            assert_eq!(parse_c_int(text), Err(IntError::Range), "`{text}`");
        }

        // A negative id declares nothing, so the source's ownership stands.
        let declared = |text: &str| owner_id(Some(text), "--owner-uid");
        assert_eq!(declared("0"), Some(0));
        assert_eq!(declared("42"), Some(42));
        assert_eq!(declared("-1"), None);
        assert_eq!(declared("-2"), None);
        assert_eq!(owner_id(None, "--owner-uid"), None);
    }

    /// A `--timestamp` value reads as `@SECONDS` or as a date and time carrying
    /// a UTC offset. The wall-clock forms without an offset and the relative
    /// forms the tool also takes are refused
    /// (`docs/conformance/cli-surface.md`, "P2").
    #[test]
    fn a_timestamp_reads_the_epoch_and_offset_forms() {
        for (text, seconds) in [
            ("@0", 0),
            ("@1234567890", 1234567890),
            ("@+5", 5),
            ("@ 7", 7),
            ("@0.5", 0),
            ("@1234567890.999", 1234567890),
            ("2009-02-13T23:31:30Z", 1234567890),
            ("2009-02-13t23:31:30z", 1234567890),
            ("2009-02-13 23:31:30+00", 1234567890),
            ("2009-02-13 23:31:30+00:00", 1234567890),
            ("2009-02-14 00:31:30+01:00", 1234567890),
            ("2009-02-13 22:31:30-0100", 1234567890),
            ("  2009-02-13T23:31:30Z  ", 1234567890),
            ("2009-02-13T23:31:30.250Z", 1234567890),
            ("2009-02-13T23:31Z", 1234567890 - 30),
            ("1970-01-01T00:00:00Z", 0),
            ("2000-02-29T00:00:00Z", 951782400),
            ("2038-01-19T03:14:08Z", 2147483648),
        ] {
            assert_eq!(parse_timestamp(text), Some(seconds), "`{text}`");
        }
        // A pre-epoch instant records the unsigned field's two's-complement
        // form, which is what the tool records for the same value.
        assert_eq!(parse_timestamp("@-1"), Some(u64::MAX));
        assert_eq!(
            parse_timestamp("1969-12-31T23:59:59Z"),
            Some(u64::MAX),
            "the same instant in the absolute form"
        );

        for text in [
            "",
            "@",
            "@1e3",
            "@abc",
            "1234567890",
            "now",
            "yesterday",
            "2009-02-13",
            // No offset: the value names a wall clock in a zone this reader does
            // not resolve.
            "2009-02-13T23:31:30",
            "2009-02-13 23:31:30",
            // Out of range for the field it names.
            "2009-13-01T00:00:00Z",
            "2009-02-30T00:00:00Z",
            "2009-02-13T24:00:00Z",
            "2009-02-13T23:60:00Z",
            "2009-02-13T23:31:30+24:00",
            "2009-02-13T23:31:30.Z",
            "2009-02-13T23:31:30ZZ",
        ] {
            assert_eq!(parse_timestamp(text), None, "`{text}`");
        }
    }

    /// The two prefix filters differ on the exact match alone: a listing keeps
    /// the ref a prefix names, and the `-A` filter leaves it to the resolution
    /// step, so an alias whose name a prefix gives exactly is filtered out.
    #[test]
    fn the_alias_filter_excludes_the_exact_match() {
        for prefix in [None, Some("grp"), Some("grp/deep")] {
            assert!(matches_prefix("grp/deep/z", prefix));
            assert!(nested_under_prefix("grp/deep/z", prefix));
        }
        assert!(matches_prefix("grp/deep/z", Some("grp/deep/z")));
        assert!(!nested_under_prefix("grp/deep/z", Some("grp/deep/z")));
        for prefix in [Some("grp/dee"), Some("other"), Some("grp/deep/z/x")] {
            assert!(!matches_prefix("grp/deep/z", prefix));
            assert!(!nested_under_prefix("grp/deep/z", prefix));
        }
    }

    /// A whole-remote prefix -- a `<remote>:` prefix whose ref half is empty or
    /// `.` -- selects every ref of that remote and no other, in a listing and in
    /// the `-A` filter alike, and the row keeps the whole refspec since there is
    /// no ref name to strip.
    #[test]
    fn a_whole_remote_prefix_selects_that_remote() {
        assert_eq!(whole_remote("origin:"), Some("origin"));
        assert_eq!(whole_remote("origin:."), Some("origin"));
        for prefix in ["origin:rr", "origin", "origin::", "origin:./x"] {
            assert_eq!(
                whole_remote(prefix),
                None,
                "`{prefix}` read as whole-remote"
            );
        }
        for prefix in [Some("origin:"), Some("origin:.")] {
            for refspec in ["origin:x", "origin:rr/x", "origin:rr/deep/y"] {
                assert!(matches_prefix(refspec, prefix));
                assert!(nested_under_prefix(refspec, prefix));
                assert_eq!(strip_prefix_from(refspec, prefix), refspec);
            }
            for refspec in ["test/main", "origin", "originx:rr/x", "other:rr/x"] {
                assert!(!matches_prefix(refspec, prefix));
                assert!(!nested_under_prefix(refspec, prefix));
            }
        }
    }

    /// A PREFIX is refused by the refspec rule, and is reported as given. The
    /// two whole-remote forms pass, since a `<remote>:` prefix whose ref half is
    /// empty or `.` names every ref of that remote.
    #[test]
    fn a_prefix_no_ref_name_can_hold_is_refused() {
        for prefix in [
            "test/",
            "/test",
            "a//b",
            ".",
            "..",
            "test/main/",
            "test/../main",
            "test/./main",
            "",
            ":",
            ":rr",
            "origin:rr/",
            "origin:..",
            "or/igin:rr",
            "or/igin:",
            ".:",
        ] {
            match check_prefix_name(prefix) {
                Err(Error::InvalidRefspec(name)) if name == prefix => {}
                other => panic!("`{prefix}` was not refused as given: {other:?}"),
            }
        }
        for prefix in [
            "test",
            "test/main",
            "origin:rr",
            "origin:",
            "origin:.",
            // The port's ref rule reads a second `:` as part of the ref name and
            // the tool refuses it, which is the character-class divergence
            // `docs/conformance/cli-surface.md`, "P1" records.
            "origin::rr",
        ] {
            check_prefix_name(prefix).expect("the prefix was refused");
        }
    }

    /// The path a PREFIX names below `refs/`: the ref name under `heads`, the ref
    /// name under `remotes/<remote>`, and the remote's own directory for a
    /// whole-remote prefix.
    #[test]
    fn a_prefix_names_its_path_under_refs() {
        for (prefix, path) in [
            ("plain", "heads/plain"),
            ("test/main", "heads/test/main"),
            ("deep/nest/ing", "heads/deep/nest/ing"),
            ("origin:rr", "remotes/origin/rr"),
            ("origin:rr/deep/y", "remotes/origin/rr/deep/y"),
            ("origin:", "remotes/origin"),
            ("origin:.", "remotes/origin"),
        ] {
            assert_eq!(prefix_path(prefix), path, "`{prefix}`");
        }
    }

    /// The `-A` target column: the link body with its leading `../` components
    /// removed while the link stays in the alias's own ref root, and the target
    /// ref's refspec once it leaves that root, which is the form the port's own
    /// resolver reads.
    #[test]
    fn a_cross_root_alias_target_prints_the_refspec() {
        for (refspec, body, printed) in [
            // Within one root, the stripped body is what both implementations
            // print.
            ("al", "test/main", "test/main"),
            ("nested/q", "../plain", "plain"),
            ("origin:rr/remal", "x", "x"),
            ("origin:rr/deep/remal", "../x", "x"),
            // Across roots, the stripped path below `refs/` names no ref.
            ("xal", "../remotes/origin/rr/x", "origin:rr/x"),
            ("origin:rr/toheads", "../../../heads/plain", "plain"),
            ("origin:rr/oal", "../../other/z/y", "other:z/y"),
            // A body naming no ref file keeps the stripped form: one reaching
            // above `refs/`, and one landing on a root itself.
            ("al", "../../objects/ab/cd", "objects/ab/cd"),
            ("al", "../remotes", "remotes"),
        ] {
            assert_eq!(
                alias_target(refspec, body),
                printed,
                "`{refspec} -> {body}` printed the wrong target",
            );
        }
    }
}
