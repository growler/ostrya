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
//! - `config` -- read a repository configuration value, or write one.
//! - `remote` -- add, delete, and list the configured remotes, read a live
//!   remote's refs and summary, and manage a remote's trusted GPG keys.
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

use std::collections::{HashMap, HashSet};
use std::os::fd::AsFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use ostrya::{
    CheckoutMode, CheckoutOptions, Checksum, CollectionRef, CommitModifier, CommitModifierFlags,
    CommitOptions, CreateOptions, DeltaOptions, DevInoCache, DiffChange, Ed25519Signer,
    Ed25519Verifier, Error, FileKind, FileObject, FilterResult, FsckOptions, MutableTree,
    ObjectType, PruneOptions, PullFlags, PullOptions, PullStats, PullVerify, RefAlias, Repo,
    RepoMode, RepoTree, Result, SignatureInfo, Signer, Summary, SummaryOptions, SummaryRef,
    TarExportOptions, TarImportOptions, TimestampCheck, Transaction, TransactionStats, TreeEntry,
    Type, Value, Verifier, VerifyOutcome, Xattrs, base64, from_bytes, load_sign_keys,
    load_sign_keys_from, to_text, to_text_unannotated, validate_refspec,
};
#[cfg(feature = "gpg")]
use ostrya::{GpgSigner, GpgVerifier};
#[cfg(feature = "spki")]
use ostrya::{SpkiSigner, SpkiVerifier};

use regex::{Captures, Regex};

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
// `commit` carries the largest option set of any subcommand, so its variant is
// the largest here. `clap`'s `Subcommand` derive reads the field type as the
// argument group itself, which a `Box` is not, so the indirection the lint asks
// for cannot be applied. One `Cli` value is parsed per process.
#[allow(clippy::large_enum_variant)]
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
    /// Read or write a repository configuration value.
    Config(ConfigArgs),
    /// Manage the configured remotes and their trusted GPG keys.
    Remote(RemoteArgs),
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
        "remote",
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
            Command::Remote(_) => "remote",
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
    /// The commit body. Given more than once, the last value wins.
    #[arg(short = 'm', long, value_name = "BODY", overrides_with = "body")]
    body: Option<String>,
    /// Read the commit body from this file, which wins over --body.
    #[arg(short = 'F', long, value_name = "FILE", overrides_with = "body_file")]
    body_file: Option<PathBuf>,
    /// Write the subject and the body in an editor, which replaces both.
    #[arg(short = 'e', long)]
    editor: bool,
    /// Do not write any ref bindings.
    #[arg(long)]
    no_bindings: bool,
    /// Bind this ref name into the commit beside the branch.
    #[arg(long = "bind-ref", value_name = "BRANCH")]
    bind_ref: Vec<String>,
    /// Add a string-valued key to the commit metadata.
    #[arg(long, value_name = "KEY=VALUE")]
    add_metadata_string: Vec<String>,
    /// Add a key to the commit metadata, its value in the GVariant text form.
    #[arg(long, value_name = "KEY=VALUE")]
    add_metadata: Vec<String>,
    /// Carry this metadata key over from the parent commit.
    #[arg(long, value_name = "KEY")]
    keep_metadata: Vec<String>,
    /// Add a string-valued key to the detached commit metadata.
    #[arg(long, value_name = "KEY=VALUE")]
    add_detached_metadata_string: Vec<String>,
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
    /// File holding the mode changes to make, one
    /// `[=]<decimal mode> <absolute in-tree path>` per line.
    #[arg(long, value_name = "PATH", overrides_with = "statoverride")]
    statoverride: Option<PathBuf>,
    /// File holding the paths to leave out, one absolute in-tree path per
    /// line. A listed directory prunes its whole subtree.
    #[arg(long, value_name = "PATH", overrides_with = "skip_list")]
    skip_list: Option<PathBuf>,
    /// Clear the write bits of every regular file that carries an execute bit.
    #[arg(long)]
    mode_ro_executables: bool,
    /// Print the parent's checksum and write nothing where the tree matches
    /// the parent commit.
    #[arg(long)]
    skip_if_unchanged: bool,
    /// Resolve a source file that is a hardlink to one of the repository's own
    /// content objects by its inode, instead of reading it.
    #[arg(long)]
    link_checkout_speedup: bool,
    /// Take an inode match as the file's whole identity, which skips the
    /// commit modifiers for it. Implies --link-checkout-speedup.
    #[arg(short = 'I', long)]
    devino_canonical: bool,
    /// Override the timestamp of the commit: `@SECONDS` since the Unix epoch,
    /// or a date and time carrying a UTC offset (`2020-01-02T03:04:05Z`).
    #[arg(long, value_name = "TIMESTAMP")]
    timestamp: Option<String>,
    /// Specify how to invoke fsync(): a boolean word from `true`, `yes`, `1`,
    /// `false`, `no`, or `0`, read without regard to case.
    #[arg(long, value_name = "POLICY", allow_hyphen_values = true)]
    fsync: Option<String>,
    /// Report the commit and the object counts in a `KEY: VALUE` block instead
    /// of the checksum alone.
    #[arg(long)]
    table_output: bool,
    /// Store the size of every object the commit reaches in `ostree.sizes`. An
    /// archive repository alone writes the key.
    #[arg(long)]
    generate_sizes: bool,
    /// Store `ostree.linux` and `ostree.bootable`, read from the one kernel
    /// directory under `/usr/lib/modules` in the committed tree.
    #[arg(long)]
    bootable: bool,
    /// Store the fs-verity digest of the tree's composefs image in
    /// `ostree.composefs.digest.v0`.
    #[arg(long)]
    generate_composefs_metadata: bool,
    /// Overlay the given argument as a tree, in command-line order. Repeatable.
    #[arg(long, value_name = "dir=PATH or tar=TARFILE or ref=COMMIT")]
    tree: Vec<String>,
    /// Start from the given commit as a base (no modifiers apply). Given more
    /// than once, the last value wins.
    #[arg(long, value_name = "REV", overrides_with = "base")]
    base: Option<String>,
    /// Consume (delete) content after commit (for local directories).
    #[arg(long)]
    consume: bool,
    /// When loading tar archives, automatically create parent directories as
    /// needed.
    #[arg(long)]
    tar_autocreate_parents: bool,
    /// When loading tar archives, use REGEX,REPLACEMENT against path names.
    /// Given more than once, the last value wins.
    #[arg(
        long,
        value_name = "REGEX,REPLACEMENT",
        overrides_with = "tar_pathname_filter"
    )]
    tar_pathname_filter: Option<String>,
    /// GPG Key ID to sign the commit with. Repeatable, and each occurrence adds
    /// one signature under `ostree.gpgsigs`, in command-line order.
    #[arg(long, value_name = "KEY-ID")]
    gpg_sign: Vec<String>,
    /// GPG Homedir to use when looking for keyrings. Read by --gpg-sign and,
    /// under --sign-type=gpg, by --sign and --sign-from-file. It wins over
    /// GNUPGHOME.
    #[arg(long, value_name = "HOMEDIR")]
    gpg_homedir: Option<PathBuf>,
    /// Sign the commit with this key: for ed25519 and spki, the base64 of the
    /// secret key. Repeatable, and each occurrence adds one signature.
    #[arg(long, value_name = "KEY_ID")]
    sign: Vec<String>,
    /// Sign the commit with the key on the first line of this file.
    /// Repeatable, and each occurrence adds one signature. An empty path
    /// carries its own refusal.
    #[arg(long, value_name = "PATH")]
    sign_from_file: Vec<std::ffi::OsString>,
    /// Signature type to use (defaults to 'ed25519'). Given more than once,
    /// the last value wins.
    #[arg(long, value_name = "NAME", overrides_with = "sign_type")]
    sign_type: Option<String>,
    /// The tree to commit. Ignored where any --tree is given, as is every
    /// argument after the first; with neither, read a tar stream from stdin.
    path: Vec<PathBuf>,
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
    /// The operation: `get`, `set`, or `unset`.
    operation: Option<String>,
    /// The key to read or write -- `section.key`, or a bare key name under
    /// --group -- and, for `set`, the value.
    args: Vec<String>,
}

#[derive(Args)]
struct RemoteArgs {
    #[command(subcommand)]
    command: Option<RemoteCommand>,
}

#[derive(Subcommand)]
enum RemoteCommand {
    /// Add a remote repository.
    Add(RemoteAddArgs),
    /// Delete a remote repository, and its trusted GPG keyring with it.
    Delete(RemoteDeleteArgs),
    /// List the configured remote names, sorted.
    List(RemoteListArgs),
    /// Print a remote's URL.
    #[command(name = "show-url")]
    ShowUrl(RemoteNameArgs),
    /// List the refs a remote publishes in its summary.
    Refs(RemoteRefsArgs),
    /// Report a remote's summary.
    Summary(RemoteSummaryArgs),
    /// Import GPG keys into a remote's trusted keyring.
    #[command(name = "gpg-import")]
    GpgImport(RemoteGpgImportArgs),
    /// List the GPG keys a remote's trusted keyring holds.
    #[command(name = "gpg-list-keys")]
    GpgListKeys(RemoteNameArgs),
}

impl RemoteCommand {
    /// The name `clap` registered this nested subcommand under, which the error
    /// paths use to render its usage text.
    fn name(&self) -> &'static str {
        match self {
            RemoteCommand::Add(_) => "add",
            RemoteCommand::Delete(_) => "delete",
            RemoteCommand::List(_) => "list",
            RemoteCommand::ShowUrl(_) => "show-url",
            RemoteCommand::Refs(_) => "refs",
            RemoteCommand::Summary(_) => "summary",
            RemoteCommand::GpgImport(_) => "gpg-import",
            RemoteCommand::GpgListKeys(_) => "gpg-list-keys",
        }
    }
}

#[derive(Args)]
struct RemoteAddArgs {
    /// Set this configuration key in the remote's section; repeatable, and
    /// applied before the options that write a fixed key.
    #[arg(long = "set", value_name = "KEY=VALUE")]
    set: Vec<String>,
    /// Do not require a GPG signature on the commits pulled from this remote.
    #[arg(long)]
    no_gpg_verify: bool,
    /// Do not require a sign-api signature, and do not require a GPG one
    /// either, which is what the tool writes for this switch.
    #[arg(long)]
    no_sign_verify: bool,
    /// Trust this key for one sign-api engine:
    /// KEYTYPE=inline:PUBKEY or KEYTYPE=file:PATH.
    #[arg(long, value_name = "KEYTYPE=[inline|file]:PUBKEY")]
    sign_verify: Vec<String>,
    /// Do nothing when the remote already exists.
    #[arg(long)]
    if_not_exists: bool,
    /// Replace the remote's section when it already exists.
    #[arg(long)]
    force: bool,
    /// Import the keys this keyring file holds into the remote's trusted
    /// keyring, as `remote gpg-import` does.
    #[arg(long, value_name = "FILE")]
    gpg_import: Option<PathBuf>,
    /// Record that this remote's content is fetched by something other than
    /// this implementation.
    #[arg(long, value_name = "NAME")]
    custom_backend: Option<String>,
    /// Fetch content objects from this URL instead of the remote's own.
    #[arg(long, value_name = "URL")]
    contenturl: Option<String>,
    /// A globally unique id for the remote as a collection of refs.
    #[arg(long, value_name = "COLLECTION-ID")]
    collection_id: Option<String>,
    /// The remote name. Required, with the URL; both are checked after the
    /// repository resolves, matching the tool's error-ordering
    /// (`docs/conformance/cli-surface.md`, "Global conventions").
    name: Option<String>,
    /// The remote's base URL, or `metalink=URL` for a metalink-described one.
    url: Option<String>,
    /// The refs a pull of this remote takes when it is asked for none.
    branches: Vec<String>,
}

#[derive(Args)]
struct RemoteDeleteArgs {
    /// Do nothing when the remote does not exist.
    #[arg(long)]
    if_exists: bool,
    /// The remote to delete. Required; checked after the repository resolves.
    name: Option<String>,
}

#[derive(Args)]
struct RemoteListArgs {
    /// Print each remote's URL after its name.
    #[arg(short = 'u', long)]
    show_urls: bool,
}

#[derive(Args)]
struct RemoteNameArgs {
    /// The remote to report. Required; checked after the repository resolves.
    name: Option<String>,
}

#[derive(Args)]
struct RemoteRefsArgs {
    /// Print each ref's commit checksum after a tab.
    #[arg(short = 'r', long)]
    revision: bool,
    /// The remote to list. Required; checked after the repository resolves.
    name: Option<String>,
}

#[derive(Args)]
struct RemoteSummaryArgs {
    /// List the available metadata keys.
    #[arg(long)]
    list_metadata_keys: bool,
    /// Print the value of one metadata key.
    #[arg(long, value_name = "KEY")]
    print_metadata_key: Option<String>,
    /// Show the raw variant data.
    #[arg(long)]
    raw: bool,
    /// The remote to report. Required; checked after the repository resolves.
    name: Option<String>,
}

#[derive(Args)]
struct RemoteGpgImportArgs {
    /// Import the keys this keyring file holds; repeatable.
    #[arg(short = 'k', long = "keyring", value_name = "FILE")]
    keyring: Vec<PathBuf>,
    /// Import the keys standard input holds.
    #[arg(long)]
    stdin: bool,
    /// The remote to import into. Required; checked after the repository
    /// resolves.
    name: Option<String>,
    /// The keys to import, named the way `gpg` names one; with none, every key
    /// the source holds.
    key_ids: Vec<String>,
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
            let fsync = fsync_policy(args.fsync.as_deref());
            let (repo, _) = resolve_repo(repo, verbose, name).await;
            commit(repo, args, owner, fsync).await
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
        Command::Remote(args) => {
            // The tool reports a missing nested subcommand before it resolves
            // the repository, the same order `static-delta` takes.
            let Some(sub) = args.command else {
                exit_with_error(name, "No \"remote\" subcommand specified");
            };
            let (repo, _) = resolve_repo(repo, verbose, name).await;
            remote(repo, sub).await
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

/// End the process with `code`, the one exit the CLI takes that does not return
/// through `main`.
///
/// `std::process::exit` runs no destructor, so a subcommand that exits while a
/// transaction is live would leave its staging directory under `tmp/`. The reap
/// runs first, which holds the rule for every subcommand and every exit site:
/// a refusal writes no object, moves no ref, and leaves `tmp/` as it found it
/// (`docs/conformance/cli-surface.md`, "Global conventions").
fn exit_process(code: i32) -> ! {
    ostrya::reap_process_staging();
    std::process::exit(code);
}

/// Print the top-level usage text and the tool's own error line for a bare
/// invocation, and exit like the tool does.
fn exit_no_command() -> ! {
    eprint!("{}", <Cli as CommandFactory>::command().render_help());
    eprintln!("error: No command specified");
    exit_process(1);
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
    exit_process(1);
}

/// Print a nested subcommand's usage text and `error: {message}`, then exit 1,
/// the shape the tool gives a `remote add` or `remote delete` missing an
/// operand.
fn exit_with_nested_error(subcommand: &str, nested: &str, message: &str) -> ! {
    let mut top = <Cli as CommandFactory>::command();
    let sub = top
        .find_subcommand_mut(subcommand)
        .and_then(|sub| sub.find_subcommand_mut(nested))
        .expect("the nested subcommand name matches a defined command");
    eprint!("{}", sub.render_help());
    eprintln!("error: {message}");
    exit_process(1);
}

/// Print `error: {message}` with no usage text and exit 1, the shape the tool
/// uses once a subcommand is running and its arguments are in hand.
fn exit_error(message: &str) -> ! {
    eprintln!("error: {message}");
    exit_process(1);
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
                exit_process(1);
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
            exit_process(1);
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

async fn commit(repo: Repo, args: CommitArgs, owner: Owner, fsync: Option<bool>) -> Result<()> {
    // The two walk-control files are read first: ahead of the missing-branch
    // check, ahead of `--parent`, ahead of the metadata options, ahead of the
    // tree, and ahead of the timestamp, which is where the tool reports a file
    // it cannot open or read (`docs/format-reference.md`, "CLI output
    // formats").
    let walk = match WalkOptions::read(&args) {
        Ok(walk) => walk,
        Err(message) => exit_error(&message),
    };

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

    // Every refusal from here to the transaction below stands ahead of the
    // repository lock, so there is no transaction to abort and no staging
    // directory to reap: the process exits having written no object and no ref.
    macro_rules! refuse_unlocked {
        ($result:expr) => {
            match $result {
                Ok(value) => value,
                Err(message) => exit_error(&message),
            }
        };
    }

    // The `[core]` keys the transaction reads are parsed here, ahead of the
    // edit, because the transaction opens once the editor has returned. The
    // tool reads them when it opens the repository, so a value their reader
    // refuses stands ahead of `--parent`, ahead of the metadata options, and
    // ahead of the editor on both sides (`docs/port-plan.md`, Phase 17f). The
    // first four are the set the transaction open reads; the fsync pair is the
    // set its write paths read, and it is parsed here too so that `--fsync`
    // does not move where a refusal lands (`docs/format-reference.md`, "The
    // fsync vocabulary").
    let config = repo.config();
    config.locking()?;
    config.lock_timeout_secs()?;
    config.tmp_expiry_secs()?;
    config.min_free_space()?;
    config.fsync()?;
    config.per_object_fsync()?;

    // `--parent` takes a revision, so it carries the resolution wording every
    // subcommand taking one gives (`docs/port-plan.md`, Phase 17b).
    let parent = match args.parent.as_deref() {
        Some(NO_PARENT) => None,
        Some(rev) => match repo.resolve_rev(rev, false).await {
            Ok(found) => found,
            Err(err) => return Err(report_resolution_failure(err)),
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
                    Err(err) => return Err(report_resolution_failure(err)),
                }
            }
            _ => None,
        },
    };

    // The metadata options are read next, each group in the order below, and a
    // group's refusal stands ahead of the body file, ahead of the editor, ahead
    // of the tree, and ahead of the timestamp (`docs/format-reference.md`,
    // "CLI output formats"). An empty key is refused where the dict is
    // assembled instead, so it stands after all four.
    if !args.keep_metadata.is_empty() && parent.is_none() {
        refuse_unlocked!(Err(
            "Either --branch or --parent must be specified when using --keep-metadata".to_owned()
        ));
    }
    let added_strings = refuse_unlocked!(metadata_pairs(&args.add_metadata_string));
    let added_variants = refuse_unlocked!(parse_added_metadata(&args.add_metadata));
    let detached_pairs = refuse_unlocked!(metadata_pairs(&args.add_detached_metadata_string));
    let kept = match parent.as_ref() {
        Some(parent) => refuse_unlocked!(kept_metadata(&repo, parent, &args.keep_metadata).await?),
        None => Vec::new(),
    };

    // `-e` replaces the subject and the body outright, so neither `-m` nor
    // `-F` is read when it is given; `-F` wins over `-m` in either order.
    let body = match (args.editor, args.body_file.as_deref()) {
        (true, _) => None,
        (false, Some(path)) => Some(refuse_unlocked!(read_body_file(path))),
        (false, None) => args.body.clone(),
    };

    // The editor runs after the metadata options are read and before the tree
    // opens, so a tree path that does not open and a timestamp the reader
    // refuses are both reported after the edit. Its result replaces both the
    // subject and the body.
    let (subject, body) = if args.editor {
        let edited = refuse_unlocked!(
            run_commit_editor(
                args.branch.as_deref().filter(|_| !args.orphan),
                args.subject.as_deref(),
            )
            .await
        );
        (Some(edited.0), Some(edited.1))
    } else {
        (args.subject.clone(), body)
    };

    // The message is settled, so the repository lock is taken now: an editing
    // session holds no lock, and an exclusive operation on the same repository
    // runs while the message is being written. The tool takes its lock at this
    // same point (`docs/port-plan.md`, Phase 17f).
    let mut txn = repo.transaction().await?;
    // The option narrows the configured policy and never widens it: a repository
    // holding `[core] fsync=false` syncs nothing under `--fsync=true`, so only
    // `false` reaches the transaction and `true` leaves the config in charge
    // (`docs/format-reference.md`, "CLI output formats", "The fsync
    // vocabulary").
    if fsync == Some(false) {
        txn.set_fsync(false);
    }
    // `--generate-sizes` covers both ingest paths, the tar stream included, so
    // the request goes to the transaction rather than to the walk's commit
    // modifier. Outside archive mode it changes nothing. A skip list naming the
    // walk root leaves every source unread, so no object is accounted and the
    // key is left out of the commit altogether
    // (`docs/format-reference.md`, "Metadata object formats").
    txn.set_generate_sizes(args.generate_sizes && !walk.root_pruned);

    // A refusal from here on has a transaction to abort first: `exit_error`
    // runs no destructor, so the staging directory is reaped ahead of it.
    macro_rules! refuse {
        ($result:expr) => {
            match $result {
                Ok(value) => value,
                Err(message) => {
                    txn.abort().await?;
                    exit_error(&message);
                }
            }
        };
    }

    // `--base` is the bottom layer of the source list whatever its position on
    // the command line, and it resolves ahead of the tree specifications, so an
    // unresolvable base is reported before a source that does not open and
    // before `--consume` removes anything
    // (`docs/format-reference.md`, "CLI output formats", `commit`).
    let base = match args.base.as_deref() {
        Some(rev) => match repo.resolve_rev(rev, false).await {
            Ok(found) => found,
            Err(err) => {
                txn.abort().await?;
                return Err(report_resolution_failure(err));
            }
        },
        None => None,
    };

    // The cache is built from this repository's own loose objects, so a source
    // tree checked out by any earlier process resolves through it. `-I` implies
    // `--link-checkout-speedup`.
    let devino = if args.link_checkout_speedup || args.devino_canonical {
        Some(repo.devino_cache().await?)
    } else {
        None
    };
    let mut modifier = commit_modifier(&args, owner, &walk, devino);
    let mut mtree = MutableTree::new();
    // The sources are read ahead of `--timestamp`, one at a time and in order,
    // so a source that does not open is reported where the tool reports it and
    // a source `--consume` already emptied stays gone when a later one fails
    // (`docs/format-reference.md`, "CLI output formats", `commit`).
    let specs = refuse!(tree_specs(&args));
    // The base is the bottom layer and no modifier reaches it, so every
    // entry a later source leaves alone keeps the mode, the ownership, and
    // the extended attributes the base recorded. A pruned walk root
    // contributes nothing over it, so the base alone is what the commit holds.
    if let Some(base) = base {
        let (commit, _) = repo.load_commit(&base).await?;
        txn.overlay_tree_to_mtree(&commit.root_dirtree, &commit.root_dirmeta, &mut mtree, None)
            .await?;
    }
    for spec in specs {
        let source = refuse!(open_tree_source(&repo, spec).await?);
        // A skip list naming the walk root prunes the walk itself: the source
        // is opened, so one that does not open is reported here, and no entry
        // below the root is offered to the filter, so every other entry of
        // either control file goes unmatched.
        if walk.root_pruned {
            continue;
        }
        // An OR-form `--statoverride` entry over a directory below the walk
        // root reaches an archive's member alone, and one modifier is shared by
        // every source, so the source kind is stated before the overlay reads
        // it (`docs/format-reference.md`, "CLI output formats", `commit`).
        walk.source_is_tar
            .store(matches!(source, OpenSource::Tar(_)), Ordering::Relaxed);
        // `ostree.sizes` covers the objects the last source contributed
        // together with the directory objects the serialization writes, so
        // each source opens its own accounting scope.
        txn.begin_tree_source();
        refuse!(overlay_source(&repo, &txn, &args, source, &mut mtree, modifier.as_mut()).await?);
    }
    // Both control files are checked once the sources have been read, the
    // statoverride file first. An entry inside a pruned directory is unmatched,
    // the walk never having reached it.
    refuse!(report_unmatched(
        "statoverride",
        &walk.unmatched_statoverride()
    ));
    refuse!(report_unmatched("skip-list", &walk.unmatched_skip_list()));
    // A source list that supplied no root directory -- an empty archive, one
    // naming no root member, or a walk the skip list pruned at the root --
    // leaves the tree with no metadata to write, `--base` having supplied none.
    if mtree.metadata_checksum().is_none() {
        refuse!(Err("Can't commit an empty tree".to_owned()));
    }
    let root = txn.write_mtree(&mut mtree).await?;

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

    let metadata = refuse!(commit_metadata_dict(
        &repo,
        &args,
        &added_strings,
        &added_variants,
        &kept,
    ));
    let detached = detached_metadata_dict(&detached_pairs);

    // `--skip-if-unchanged` compares the walked tree against the resolved
    // parent, root contents and root metadata both. The commit's own metadata
    // takes no part, so a new subject or a new metadata key over an unchanged
    // tree is still skipped. With no parent there is nothing to compare and the
    // commit is written.
    if args.skip_if_unchanged
        && let Some(parent) = parent
    {
        let (previous, _) = repo.load_commit(&parent).await?;
        if previous.root_dirtree == *root.dirtree_checksum()
            && previous.root_dirmeta == *root.dirmeta_checksum()
        {
            txn.abort().await?;
            if args.table_output {
                print_skipped_commit_table(&parent);
            } else {
                println!("{}", parent.to_hex());
            }
            return Ok(());
        }
    }

    // The two derived keys are read from the committed tree, so they stand
    // after the walk, after the control-file reports, after the empty-tree
    // refusal, and after `--skip-if-unchanged` has had its say
    // (`docs/format-reference.md`, "CLI output formats", `commit`).
    let mut metadata = metadata;
    if args.bootable {
        let version = refuse!(kernel_version(&txn, &root).await?);
        // The derived pair replaces a value supplied for either key: a commit
        // carrying `--add-metadata-string=ostree.linux=...` beside `--bootable`
        // reaches the same object as one carrying `--bootable` alone.
        drop_metadata_keys(&mut metadata, &[LINUX_KEY, BOOTABLE_KEY])?;
        prepend_metadata_entries(
            &mut metadata,
            vec![
                string_entry(LINUX_KEY, &version),
                Value::Tuple(vec![
                    Value::Str(BOOTABLE_KEY.to_owned()),
                    Value::variant(Type::Bool, Value::Bool(true)),
                ]),
            ],
        )?;
    }
    // The composefs digest stands after the binding keys, and the library
    // appends `ostree.sizes` after it. A value the command line supplied under
    // the same key -- through `--add-metadata-string`, `--add-metadata`, or
    // `--keep-metadata` -- takes the derived digest in the slot it already
    // holds, and a repeated key collapses to that one entry.
    if args.generate_composefs_metadata {
        let digest = txn.composefs_digest(&root).await?;
        let entry = Value::Tuple(vec![
            Value::Str(COMPOSEFS_DIGEST_KEY.to_owned()),
            Value::variant(
                Type::Array(Box::new(Type::Byte)),
                Value::Bytes(digest.to_vec()),
            ),
        ]);
        set_metadata_entry(&mut metadata, COMPOSEFS_DIGEST_KEY, entry)?;
    }

    let opts = CommitOptions {
        parent,
        subject,
        body,
        timestamp,
        metadata: Some(metadata),
    };
    let checksum = txn.write_commit(opts, &root).await?;
    // A branch name the revision syntax shadows, and one the refspec grammar
    // refuses, are both reported after the commit is written and ahead of the
    // signing step, which is the order the tool reports each of them against a
    // key it cannot use. The order is observable only over a name both
    // grammars refuse: `validate_refspec` covers path safety alone, so a name
    // the tool's wider ref-name grammar refuses and this one accepts -- one
    // holding a space or a caret -- reaches the signing step here and the
    // refspec refusal there (`docs/conformance/cli-surface.md`, "P2").
    // `exit_error` runs no destructor, so the staging directory is reaped ahead
    // of it.
    if let Some(branch) = args.branch.as_deref() {
        if let Some(message) = shadowed_branch_name(branch) {
            txn.abort().await?;
            exit_error(&message);
        }
        if validate_refspec(branch).is_err() {
            txn.abort().await?;
            exit_error(&format!("Invalid refspec {branch}"));
        }
    }
    // `--add-detached-metadata-string` replaces the whole stored detached
    // metadata and the signing engines append to what stands, so the dict is
    // queued ahead of the signatures: a run naming both writes the user keys
    // first and the signature keys after them, and it drops any signature an
    // earlier run left on the same checksum
    // (`docs/format-reference.md`, "CLI output formats", `commit`).
    if let Some(detached) = detached {
        txn.set_commit_detached_metadata(&checksum, detached);
    }
    // The signatures are produced before the ref is written and before the
    // transaction publishes, so a key that cannot sign leaves no object in
    // `objects/` and the ref where it stood.
    refuse!(sign_staged_commit(&txn, &checksum, &args).await?);
    if let Some(branch) = args.branch.as_deref() {
        txn.set_ref(branch, Some(&checksum));
    }
    let stats = txn.commit().await?;

    if args.table_output {
        print_commit_table(&checksum, &stats);
    } else {
        println!("{}", checksum.to_hex());
    }
    Ok(())
}

/// The `--sign-type` name in force when the option is absent, and the one name
/// the tool's own build carries.
const DEFAULT_SIGN_TYPE: &str = "ed25519";

/// The length of an ed25519 secret key: the 32-byte seed followed by the
/// 32-byte public key.
const ED25519_SECRET_LEN: usize = 64;

/// The largest first line `--sign-from-file` accepts. A base64 ed25519 secret
/// is 88 characters and a GPG key id shorter still, so this bounds the read well
/// above any key while barring an unbounded one (`CLAUDE.md`, "Working
/// conventions"). A longer first line is refused rather than cut.
const SIGN_KEY_FILE_LIMIT: u64 = 64 * 1024;

/// Sign the staged commit with every key the signing options name.
///
/// The step runs after the commit object is staged and before the ref write and
/// the publication, so a refusal here leaves no object in `objects/` and the ref
/// where it stood, and a run naming several keys is all or nothing
/// (`docs/format-reference.md`, "Signing details").
///
/// The order the signatures take is fixed and does not follow the command line:
/// every `--sign` key first, then every `--sign-from-file` key, then every
/// `--gpg-sign` key. `--sign-type` selects the engine of the first two groups
/// alone and is read only when one of them names a key, so a name no engine
/// carries passes unremarked through a run that signs nothing.
async fn sign_staged_commit(
    txn: &Transaction,
    checksum: &Checksum,
    args: &CommitArgs,
) -> Result<std::result::Result<(), String>> {
    macro_rules! refuse {
        ($result:expr) => {
            match $result {
                Ok(value) => value,
                Err(message) => return Ok(Err(message)),
            }
        };
    }
    if !args.sign.is_empty() || !args.sign_from_file.is_empty() {
        let engine = refuse!(commit_sign_type(
            args.sign_type.as_deref().unwrap_or(DEFAULT_SIGN_TYPE)
        ));
        for key in &args.sign {
            let signer = refuse!(commit_signer(engine, key.as_bytes(), args));
            txn.sign_commit(checksum, signer.as_ref()).await?;
        }
        for path in &args.sign_from_file {
            let key = refuse!(read_sign_key_file(Path::new(path)));
            let signer = refuse!(commit_signer(engine, &key, args));
            txn.sign_commit(checksum, signer.as_ref()).await?;
        }
    }
    refuse!(sign_staged_commit_gpg(txn, checksum, args).await?);
    Ok(Ok(()))
}

/// The shortest `--gpg-sign` selector the key lookup accepts, in bytes. A
/// shorter one is refused without a lookup
/// (`docs/format-reference.md`, "Signing details").
#[cfg(feature = "gpg")]
const GPG_SIGN_SELECTOR_MIN: usize = 8;

/// Add the `--gpg-sign` signatures, one per occurrence and in command-line
/// order.
///
/// Each selector is resolved in the GnuPG home directory `--gpg-homedir` names,
/// or the one gpg resolves for itself, and it must name exactly one secret key.
/// A selector under [`GPG_SIGN_SELECTOR_MIN`] bytes is refused without a lookup,
/// one that names no key and one that names several each carry their own
/// refusal, and the refusal comes before any signature is produced. The
/// signature is then made against the fingerprint the lookup returned, so the
/// key that signs is the key the lookup named.
#[cfg(feature = "gpg")]
async fn sign_staged_commit_gpg(
    txn: &Transaction,
    checksum: &Checksum,
    args: &CommitArgs,
) -> Result<std::result::Result<(), String>> {
    for key in &args.gpg_sign {
        if key.len() < GPG_SIGN_SELECTOR_MIN {
            return Ok(Err(format!(
                "Unable to lookup key ID {key}: GPGME: Invalid value"
            )));
        }
        let lookup = commit_gpg_signer(key, args);
        let homedir = gpg_homedir_text(&lookup);
        let found = lookup.secret_key_fingerprints().await?;
        let [fingerprint] = found.as_slice() else {
            return Ok(Err(if found.is_empty() {
                format!("No gpg key found with ID {key} (homedir: {homedir})")
            } else {
                format!(
                    "gpg key id {key} ambiguous (homedir: {homedir}). Try the fingerprint instead"
                )
            }));
        };
        let signer = commit_gpg_signer(fingerprint, args);
        txn.sign_commit(checksum, &signer).await?;
    }
    Ok(Ok(()))
}

#[cfg(not(feature = "gpg"))]
async fn sign_staged_commit_gpg(
    _: &Transaction,
    _: &Checksum,
    args: &CommitArgs,
) -> Result<std::result::Result<(), String>> {
    if args.gpg_sign.is_empty() {
        return Ok(Ok(()));
    }
    // A build without the engine refuses through the same channel as every
    // other signing refusal, so the line reads the same wherever it comes from.
    Ok(Err("Requested signature type is not implemented".to_owned()))
}

/// The `--gpg-sign` signer for one key selector.
#[cfg(feature = "gpg")]
fn commit_gpg_signer(key: &str, args: &CommitArgs) -> GpgSigner {
    let signer = GpgSigner::new(key);
    match &args.gpg_homedir {
        Some(dir) => signer.with_homedir(dir),
        None => signer,
    }
}

/// The GnuPG home directory a key-lookup refusal names: the signer's home
/// directory, or the literal `<default>` where the signer carries none and gpg
/// resolves the directory for itself.
#[cfg(feature = "gpg")]
fn gpg_homedir_text(signer: &GpgSigner) -> String {
    match signer.homedir() {
        Some(dir) => dir.display().to_string(),
        None => "<default>".to_owned(),
    }
}

/// Read `--sign-type` into the engine it names, refusing a name no engine
/// carries in the tool's own words. The match is exact and case sensitive with
/// no trimming, so `ED25519` and a whitespace-padded name each name no engine.
/// `dummy` is a registered engine the command line does not reach, and it
/// carries its own refusal.
fn commit_sign_type(name: &str) -> std::result::Result<SignType, String> {
    match name {
        "ed25519" => Ok(SignType::Ed25519),
        #[cfg(feature = "spki")]
        "spki" => Ok(SignType::Spki),
        #[cfg(feature = "gpg")]
        "gpg" => Ok(SignType::Gpg),
        "dummy" => Err("dummy signature type is only for ostree testing".to_owned()),
        _ => Err("Requested signature type is not implemented".to_owned()),
    }
}

/// The signer one `--sign` or `--sign-from-file` key names under `engine`.
///
/// The key arrives as bytes, since `--sign-from-file` reads a line of a file
/// and the tool places no encoding requirement on it. The ed25519 engine reads
/// the bytes directly; the engines whose key is a text selector read the same
/// bytes with every invalid UTF-8 sequence replaced.
fn commit_signer(
    engine: SignType,
    key: &[u8],
    args: &CommitArgs,
) -> std::result::Result<Box<dyn Signer>, String> {
    match engine {
        SignType::Ed25519 => {
            let secret = ed25519_secret_key(key)?;
            Ed25519Signer::from_secret_key(&secret)
                .map(|signer| Box::new(signer) as Box<dyn Signer>)
                .map_err(|err| err.to_string())
        }
        SignType::Spki => commit_signer_spki(&String::from_utf8_lossy(key)),
        SignType::Gpg => commit_signer_gpg(&String::from_utf8_lossy(key), args),
    }
}

#[cfg(feature = "spki")]
fn commit_signer_spki(key: &str) -> std::result::Result<Box<dyn Signer>, String> {
    SpkiSigner::from_base64(key)
        .map(|signer| Box::new(signer) as Box<dyn Signer>)
        .map_err(|err| err.to_string())
}

#[cfg(not(feature = "spki"))]
fn commit_signer_spki(_: &str) -> std::result::Result<Box<dyn Signer>, String> {
    Err("Requested signature type is not implemented".to_owned())
}

#[cfg(feature = "gpg")]
fn commit_signer_gpg(key: &str, args: &CommitArgs) -> std::result::Result<Box<dyn Signer>, String> {
    Ok(Box::new(commit_gpg_signer(key, args)))
}

#[cfg(not(feature = "gpg"))]
fn commit_signer_gpg(_: &str, _: &CommitArgs) -> std::result::Result<Box<dyn Signer>, String> {
    Err("Requested signature type is not implemented".to_owned())
}

/// Read an ed25519 secret key from its base64 text, refusing a value of any
/// other length in the tool's own words.
///
/// The decode is lenient: every byte outside the base64 alphabet is skipped, so
/// surrounding whitespace, an interior newline, and a line of prose all decode
/// to some byte count and the length check states the refusal. This is what
/// makes `--sign=not-base64!!!` report six bytes rather than a decoder error.
fn ed25519_secret_key(key: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let secret = lenient_base64(key);
    if secret.len() != ED25519_SECRET_LEN {
        return Err(format!(
            "Invalid ed25519 secret key: Ill-formed input: expected {ED25519_SECRET_LEN} bytes, \
             got {} bytes",
            secret.len()
        ));
    }
    Ok(secret)
}

/// Decode base64 text the way the tool's decoder does.
///
/// Every byte outside the alphabet is skipped, so whitespace and prose
/// characters contribute nothing. A padding character carries the value zero and
/// counts toward its group. Three bytes come out of every complete
/// four-character group, and each of that group's last two characters that is a
/// padding character removes one of them again. A trailing group short of four
/// characters contributes nothing at all.
///
/// Padding therefore acts per group and per position. `AAAA=` decodes to three
/// bytes, since the padding character opens an incomplete group; `AA=A` decodes
/// to two, since the padding character sits third in a complete group; and
/// `AA==AA==` decodes to two, one byte from each of its two groups. A
/// three-character argument decodes to zero bytes and a nine-character one to
/// six.
fn lenient_base64(text: &[u8]) -> Vec<u8> {
    let value = |c: u8| -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(0),
            _ => None,
        }
    };
    let mut out = Vec::new();
    let mut group: u32 = 0;
    let mut held = 0usize;
    let mut dropped = 0usize;
    for &byte in text {
        let Some(six) = value(byte) else { continue };
        if held >= 2 && byte == b'=' {
            dropped += 1;
        }
        group = (group << 6) | u32::from(six);
        held += 1;
        if held == 4 {
            out.push((group >> 16) as u8);
            out.push((group >> 8) as u8);
            out.push(group as u8);
            out.truncate(out.len() - dropped);
            group = 0;
            held = 0;
            dropped = 0;
        }
    }
    out
}

/// Read the key one `--sign-from-file` occurrence names: the first line of the
/// file alone, with the rest of the file ignored.
///
/// The line is read as bytes and carries no encoding requirement, so a file
/// holding a byte sequence that is not UTF-8 reaches the engine and its own
/// length check states the outcome. A NUL byte ends the line ahead of the
/// newline, so `AAAA\0BBBB` is the key `AAAA`.
///
/// A path that does not open is reported naming the path as the command line
/// spelled it, where the tool names the absolute path
/// (`docs/conformance/cli-surface.md`, "P2"). An empty path carries its own
/// refusal. A file whose first line is empty, and an empty file, both yield an
/// empty key, which the engine's own length check refuses; the tool dies on a
/// signal for each of the two (`docs/conformance/cli-surface.md`, "P2"). A
/// first line longer than [`SIGN_KEY_FILE_LIMIT`] is refused rather than cut,
/// so the length the engine reports is always the length the file holds; the
/// tool reads a line of any length (`docs/conformance/cli-surface.md`, "P2").
fn read_sign_key_file(path: &Path) -> std::result::Result<Vec<u8>, String> {
    if path.as_os_str().is_empty() {
        return Err("Operation not supported".to_owned());
    }
    let fail =
        |err: &std::io::Error| format!("Error opening file {}: {}", path.display(), io_reason(err));
    let file = std::fs::File::open(path).map_err(|err| fail(&err))?;
    // One byte over the cap distinguishes a line that fills it from one that
    // exceeds it.
    let mut reader = std::io::BufReader::new(std::io::Read::take(file, SIGN_KEY_FILE_LIMIT + 1));
    let mut line = Vec::new();
    std::io::BufRead::read_until(&mut reader, b'\n', &mut line).map_err(|err| fail(&err))?;
    let end = line
        .iter()
        .position(|&byte| byte == 0 || byte == b'\n')
        .unwrap_or(line.len());
    line.truncate(end);
    if line.len() as u64 > SIGN_KEY_FILE_LIMIT {
        return Err(format!(
            "Error reading file {}: the first line is longer than {SIGN_KEY_FILE_LIMIT} bytes",
            path.display()
        ));
    }
    Ok(line)
}

/// Print the `--table-output` block for a `--skip-if-unchanged` run that wrote
/// nothing: the parent's checksum, and zero for each of the six counters.
///
/// The tool prints uninitialized counter values here, which differ between two
/// identical runs, so the port states the counts of the work it did rather than
/// reproducing them (`docs/conformance/cli-surface.md`, "P2").
fn print_skipped_commit_table(parent: &Checksum) {
    print_commit_table(parent, &TransactionStats::default());
}

/// Print the `--table-output` block: seven `KEY: VALUE` lines in a fixed order,
/// one space after each colon and no padding
/// (`docs/format-reference.md`, "CLI output formats").
///
/// `Content Bytes Written` reports `content_bytes_unpacked`, the content byte
/// count of the regular files written, which is the number the tool prints.
/// `TransactionStats::content_bytes_written` in the same struct holds the size
/// the objects take in the repository, which for an `archive` repository is the
/// compressed size and is what `PullStats` reports; the two differ for every
/// compressed object.
fn print_commit_table(checksum: &Checksum, stats: &TransactionStats) {
    println!("Commit: {}", checksum.to_hex());
    println!("Metadata Total: {}", stats.metadata_total);
    println!("Metadata Written: {}", stats.metadata_written);
    println!("Content Total: {}", stats.content_total);
    println!("Content Written: {}", stats.content_written);
    println!("Content Cache Hits: {}", stats.devino_cache_hits);
    println!("Content Bytes Written: {}", stats.content_bytes_unpacked);
}

/// Read a `--fsync=POLICY` value into the policy it names, refusing anything
/// else in the tool's own words and at the tool's own step: while the options
/// are read, ahead of the repository and ahead of every check the subcommand
/// makes (`docs/format-reference.md`, "CLI output formats").
fn fsync_policy(value: Option<&str>) -> Option<bool> {
    let text = value?;
    match text.to_ascii_lowercase().as_str() {
        "true" | "yes" | "1" => Some(true),
        "false" | "no" | "0" => Some(false),
        _ => exit_error(&format!("Invalid boolean argument '{text}'")),
    }
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

/// The file-type mask of an `st_mode`, and the regular-file value in it.
const S_IFMT: u32 = 0o170000;
/// The regular-file type value of an `st_mode`.
const S_IFREG: u32 = 0o100000;
/// The directory type value of an `st_mode`.
const S_IFDIR: u32 = 0o040000;
/// The three execute bits, which `--mode-ro-executables` tests.
const EXEC_BITS: u32 = 0o111;
/// The three write bits, which `--mode-ro-executables` clears.
const WRITE_BITS: u32 = 0o222;

/// One `--statoverride` entry.
#[derive(Debug, Clone)]
struct StatOverride {
    /// Whether the value replaces the entry's permission bits (an `=` prefix)
    /// rather than being ORed into its mode.
    assign: bool,
    /// The mode value, read in base 10.
    value: u32,
    /// The text after the first space, which is the in-tree path the entry
    /// matches and the text an unmatched report names.
    path: String,
}

/// The `commit` options that reach the filesystem walk, read from the two
/// control files before anything else the subcommand does.
///
/// Each control file holds at most one entry per path, and the statoverride
/// file at most one per path per form: a path named more than once by one form
/// takes the value of the last line naming it, at the position the file first
/// names it.
#[derive(Debug, Default)]
struct WalkOptions {
    /// The OR-form `--statoverride` entries, one per path.
    statoverride_or: Vec<(String, u32)>,
    /// The `=`-form `--statoverride` entries, one per path.
    statoverride_assign: Vec<(String, u32)>,
    /// The `--skip-list` paths, one per path.
    skip_list: Vec<String>,
    /// Whether the skip list names the walk root, which prunes everything.
    root_pruned: bool,
    /// Which OR-form `--statoverride` path the walk reached, one flag per path.
    /// A path the skip list prunes is reached, the walk having offered the
    /// entry before the prune; a path below a pruned directory is not.
    statoverride_matched: Arc<Mutex<Vec<bool>>>,
    /// Which `--skip-list` path the walk reached, one flag per path.
    skip_list_matched: Arc<Mutex<Vec<bool>>>,
    /// Which OR-form `--statoverride` entry a source has already taken the
    /// value of, one flag per path. An entry reaches one entry of the tree per
    /// run, so the mode callback reads this and not
    /// [`statoverride_matched`](WalkOptions::statoverride_matched): a path the
    /// skip list prunes counts as reached without any source taking the value.
    statoverride_spent: Arc<Mutex<Vec<bool>>>,
    /// Whether the source being overlaid is an archive. One modifier is shared
    /// by every source of a run, and an OR-form `--statoverride` entry over a
    /// directory below the walk root reaches an archive's member where it
    /// leaves a filesystem walk and a `ref` source alone, so the caller states
    /// the source kind here before each source is read.
    source_is_tar: Arc<AtomicBool>,
}

/// The in-tree path of the walk root, which both control files spell `/`.
const WALK_ROOT: &str = "/";

impl WalkOptions {
    /// Read both control files, in the order the tool reads them.
    fn read(args: &CommitArgs) -> std::result::Result<WalkOptions, String> {
        let statoverride = match args.statoverride.as_deref() {
            Some(path) => read_statoverride(path)?,
            None => Vec::new(),
        };
        let skip_list = match args.skip_list.as_deref() {
            Some(path) => fold_paths(read_skip_list(path)?),
            None => Vec::new(),
        };
        // The walk root is never offered to the filter, so a skip list naming
        // it is answered here: the whole tree is pruned, every other entry of
        // either file goes unmatched, and the commit has nothing to write.
        let root_pruned = skip_list.iter().any(|path| path == WALK_ROOT);
        // One flag per path, with a root entry marked here since the filter
        // never sees it.
        let skip_seen: Vec<bool> = skip_list.iter().map(|path| path == WALK_ROOT).collect();
        let statoverride_or = fold_overrides(&statoverride, false);
        // The walk root counts as reached whether or not the skip list prunes
        // it, so an OR entry naming it is marked here too: with the root pruned
        // the walk runs over nothing and the mode callback never sees it.
        let override_seen: Vec<bool> = statoverride_or
            .iter()
            .map(|(path, _)| root_pruned && path == WALK_ROOT)
            .collect();
        let spent = vec![false; statoverride_or.len()];
        Ok(WalkOptions {
            statoverride_matched: Arc::new(Mutex::new(override_seen)),
            skip_list_matched: Arc::new(Mutex::new(skip_seen)),
            statoverride_spent: Arc::new(Mutex::new(spent)),
            statoverride_assign: fold_overrides(&statoverride, true),
            statoverride_or,
            skip_list,
            root_pruned,
            source_is_tar: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Whether any option here shapes a mode.
    fn shapes_modes(&self) -> bool {
        !self.statoverride_or.is_empty() || !self.statoverride_assign.is_empty()
    }

    /// The `--statoverride` paths the walk never reached, one entry per path.
    /// An `=` entry is not checked, so one matching nothing is ignored, and a
    /// path both forms name is checked once, through its OR-form entry. A path
    /// the skip list prunes is reached; a path below a pruned directory is not.
    fn unmatched_statoverride(&self) -> Vec<String> {
        let matched = self.statoverride_matched.lock().unwrap();
        self.statoverride_or
            .iter()
            .zip(matched.iter())
            .filter(|(_, hit)| !**hit)
            .map(|((path, _), _)| path.clone())
            .collect()
    }

    /// The `--skip-list` paths the walk never reached, one entry per path.
    /// Every path is checked.
    fn unmatched_skip_list(&self) -> Vec<String> {
        let matched = self.skip_list_matched.lock().unwrap();
        self.skip_list
            .iter()
            .zip(matched.iter())
            .filter(|(_, hit)| !**hit)
            .map(|(path, _)| path.clone())
            .collect()
    }
}

/// Print one `Unmatched <kind> path:` line per path of one control file the
/// walk never reached. The error is the summary line that follows them, which
/// the caller reports and exits 1 on; an empty list is `Ok`.
fn report_unmatched(kind: &str, unmatched: &[String]) -> std::result::Result<(), String> {
    if unmatched.is_empty() {
        return Ok(());
    }
    for path in unmatched {
        eprintln!("Unmatched {kind} path: {path}");
    }
    Err(format!("Unmatched {kind} paths"))
}

/// The largest control file `--statoverride` and `--skip-list` read, matching
/// the cap `-F/--body-file` takes (`CLAUDE.md`, "Working conventions", which
/// bars an unbounded read).
const CONTROL_FILE_LIMIT: u64 = 128 * 1024 * 1024;

/// Read a control file as text. A path that does not open is reported the way
/// the tool reports it, naming the path as the command line spelled it; a
/// directory is reported without one.
///
/// The bytes must be UTF-8 whole, and a NUL byte counts as invalid. A single
/// invalid byte anywhere in the file refuses the command with `Invalid UTF-8`,
/// which is what the tool does. An accepted file therefore holds text alone,
/// and the walk compares each entry's own bytes against the walk path's bytes,
/// so a spelled replacement character names that character and nothing else.
/// The read stops at [`CONTROL_FILE_LIMIT`].
fn read_control_file(path: &Path) -> std::result::Result<String, String> {
    let file = std::fs::File::open(path)
        .map_err(|err| format!("openat({}): {}", path.display(), io_reason(&err)))?;
    let mut bytes = Vec::new();
    let mut bounded = std::io::Read::take(file, CONTROL_FILE_LIMIT + 1);
    std::io::Read::read_to_end(&mut bounded, &mut bytes).map_err(|err| match err.kind() {
        std::io::ErrorKind::IsADirectory => "Is a directory".to_owned(),
        _ => io_reason(&err),
    })?;
    if bytes.len() as u64 > CONTROL_FILE_LIMIT {
        return Err(format!(
            "Control file larger than {CONTROL_FILE_LIMIT} bytes"
        ));
    }
    if bytes.contains(&0) {
        return Err("Invalid UTF-8".to_owned());
    }
    String::from_utf8(bytes).map_err(|_| "Invalid UTF-8".to_owned())
}

/// Read a `--statoverride` file: one `[=]<decimal mode> <path>` per line, with
/// blank lines ignored and everything after the first space taken as the path.
fn read_statoverride(path: &Path) -> std::result::Result<Vec<StatOverride>, String> {
    let text = read_control_file(path)?;
    let mut entries = Vec::new();
    for line in text.split('\n').filter(|line| !line.is_empty()) {
        let Some((mode, rest)) = line.split_once(' ') else {
            return Err("Malformed statoverride file (no space found)".to_owned());
        };
        let (assign, digits) = match mode.strip_prefix('=') {
            Some(digits) => (true, digits),
            None => (false, mode),
        };
        entries.push(StatOverride {
            assign,
            value: leading_u32(digits),
            path: rest.to_owned(),
        });
    }
    Ok(entries)
}

/// Read a `--skip-list` file: one path per line, blank lines ignored.
fn read_skip_list(path: &Path) -> std::result::Result<Vec<String>, String> {
    Ok(read_control_file(path)?
        .split('\n')
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect())
}

/// Reduce the `--statoverride` entries of one form to one entry per path: the
/// value of the last line naming a path, at the position the file first names
/// it. The two forms are folded apart, so a path named by both keeps a value
/// under each.
fn fold_overrides(entries: &[StatOverride], assign: bool) -> Vec<(String, u32)> {
    let mut at: HashMap<&str, usize> = HashMap::new();
    let mut folded: Vec<(String, u32)> = Vec::new();
    for entry in entries.iter().filter(|entry| entry.assign == assign) {
        match at.get(entry.path.as_str()) {
            Some(&index) => folded[index].1 = entry.value,
            None => {
                at.insert(entry.path.as_str(), folded.len());
                folded.push((entry.path.clone(), entry.value));
            }
        }
    }
    folded
}

/// Reduce the `--skip-list` paths to one entry per path, at the position the
/// file first names it.
fn fold_paths(paths: Vec<String>) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    paths
        .into_iter()
        .filter(|path| seen.insert(path.clone()))
        .collect()
}

/// Read the leading decimal run of a `--statoverride` mode field: an optional
/// sign, then digits, with the value truncated to 32 bits. Text holding no
/// digit is the value zero, so an entry with an unreadable mode changes nothing
/// under the OR form.
///
/// The tool reads the field as a C `double` and converts it, so it also takes a
/// hexadecimal literal, a decimal point, and an exponent, and turns a value
/// past the 32-bit range into `0x80000000`. Those forms are outside the
/// documented format, which is a mode in decimal, and their out-of-range
/// conversion is platform-defined; the port reads decimal alone and the
/// difference is recorded in `docs/conformance/cli-surface.md`, "P2".
fn leading_u32(text: &str) -> u32 {
    let (negative, body) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let digits: String = body.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return 0;
    }
    let value: u64 = digits.parse().unwrap_or(u64::MAX);
    (if negative {
        value.wrapping_neg()
    } else {
        value
    }) as u32
}

/// One tree source a `commit` invocation names.
enum TreeSpec {
    /// `--tree=dir=PATH`, and the positional `PATH`. The path is kept as it was
    /// spelled, which is what `--consume` reads.
    Dir(PathBuf),
    /// `--tree=tar=PATH`. The tool spells standard input `-`, and reaches it
    /// through `/dev/stdin` as well.
    Tar(PathBuf),
    /// `--tree=ref=REV`.
    Ref(String),
    /// The port's own default source: a tar stream on standard input, where
    /// the tool walks the current working directory
    /// (`docs/conformance/cli-surface.md`, "P2").
    Stdin,
}

/// One tree source, opened or resolved.
enum OpenSource {
    /// A directory, and the path it was named by.
    Dir(std::fs::File, PathBuf),
    /// A tar stream.
    Tar(ostrya_rt::File),
    /// A committed tree, by its root dirtree and dirmeta checksums.
    Ref(Checksum, Checksum),
}

/// The `ENOTDIR` a source that is not a directory is refused with. The port
/// reads the source's metadata no-follow and refuses what that read does not
/// state a directory, so a symlink naming a directory is refused too, as the
/// tool's own `opendir` refuses it.
const ENOTDIR: i32 = 20;

/// The source list a `commit` invocation states, in the order the sources are
/// overlaid. `--tree` values come in command-line order; with none, the
/// positional `PATH` is the one source, and with neither the port reads a tar
/// stream from standard input. A positional `PATH` beside any `--tree` is
/// ignored, at exit 0 and unread.
fn tree_specs(args: &CommitArgs) -> std::result::Result<Vec<TreeSpec>, String> {
    if args.tree.is_empty() {
        return Ok(vec![match args.path.first() {
            Some(path) => TreeSpec::Dir(path.clone()),
            None => TreeSpec::Stdin,
        }]);
    }
    args.tree
        .iter()
        .map(|value| match value.split_once('=') {
            Some(("dir", path)) => Ok(TreeSpec::Dir(PathBuf::from(path))),
            Some(("tar", path)) => Ok(TreeSpec::Tar(PathBuf::from(path))),
            Some(("ref", rev)) => Ok(TreeSpec::Ref(rev.to_owned())),
            Some((kind, _)) => Err(format!("Invalid tree type specification '{kind}'")),
            None => Err(format!("Missing type in tree specification '{value}'")),
        })
        .collect()
}

/// Open or resolve one source. The caller opens and overlays the sources one
/// at a time and in order, so a source that does not open is reported once
/// every earlier source is read and `--consume` has removed what those sources
/// named. The timestamp is read once the last source is overlaid, so a source
/// that does not open is reported ahead of a timestamp the reader refuses.
///
/// A `dir=` or a `tar=` source that does not open comes back as the message
/// rather than as an exit, because the caller holds an open transaction whose
/// staging directory has to be reaped first.
///
/// A `dir=` source is stated a directory by a no-follow metadata read and is
/// opened after that read, so the path can change between the two calls. The
/// walk reopens the descriptor with `OFlags::DIRECTORY | OFlags::NOFOLLOW`
/// (`ostrya::ingest::open_walk_root`), so a raced replacement that is not a
/// directory is refused there.
async fn open_tree_source(
    repo: &Repo,
    spec: TreeSpec,
) -> Result<std::result::Result<OpenSource, String>> {
    Ok(Ok(match spec {
        TreeSpec::Dir(path) => {
            let opened = std::fs::symlink_metadata(&path).and_then(|meta| {
                if meta.is_dir() {
                    std::fs::File::open(&path)
                } else {
                    Err(std::io::Error::from_raw_os_error(ENOTDIR))
                }
            });
            match opened {
                Ok(dfd) => OpenSource::Dir(dfd, path),
                Err(err) => {
                    return Ok(Err(format!(
                        "opendir({}): {}",
                        path.display(),
                        io_reason(&err)
                    )));
                }
            }
        }
        TreeSpec::Stdin => OpenSource::Tar(stdin_file()?),
        TreeSpec::Tar(path) if path == Path::new("-") || path == Path::new("/dev/stdin") => {
            OpenSource::Tar(stdin_file()?)
        }
        TreeSpec::Tar(path) => {
            let Ok(file) = std::fs::File::open(&path) else {
                return Ok(Err(format!(
                    "archive_read_open_filename: Failed to open '{}'",
                    path.display()
                )));
            };
            OpenSource::Tar(ostrya_rt::File::from(std::os::fd::OwnedFd::from(file)))
        }
        TreeSpec::Ref(rev) => {
            let checksum = match repo.resolve_rev(&rev, false).await {
                Ok(Some(checksum)) => checksum,
                Ok(None) => return Err(report_resolution_failure(Error::RefNotFound(rev))),
                Err(err) => return Err(report_resolution_failure(err)),
            };
            let (commit, _) = repo.load_commit(&checksum).await?;
            OpenSource::Ref(commit.root_dirtree, commit.root_dirmeta)
        }
    }))
}

/// Overlay one source onto `mtree`. A later source's directory metadata
/// replaces what an earlier one recorded, its files replace files of the same
/// name, and a name that is a directory on one side and a file on the other is
/// refused (`docs/format-reference.md`, "CLI output formats", `commit`).
///
/// A refusal comes back as the message rather than as an exit, because the
/// caller holds an open transaction whose staging directory has to be reaped
/// first.
async fn overlay_source(
    repo: &Repo,
    txn: &Transaction,
    args: &CommitArgs,
    source: OpenSource,
    mtree: &mut MutableTree,
    modifier: Option<&mut CommitModifier>,
) -> Result<std::result::Result<(), String>> {
    match source {
        OpenSource::Dir(dfd, path) => {
            txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("."), mtree, modifier)
                .await?;
            // `--consume` removes the source directory itself once its contents
            // are ingested, unless the path is spelled `.`. The test is on the
            // text, so an absolute path naming the working directory is removed
            // and `./` is not spared. A removal that fails aborts the commit and
            // names the path, which is what the tool does.
            // The test is on the text the value carries, which `Path` equality
            // would normalize away: `./` and `.` name one directory and only
            // the second is spared.
            if args.consume
                && path.as_os_str() != "."
                && let Err(err) = std::fs::remove_dir(&path)
            {
                return Ok(Err(format!(
                    "unlinkat({}): {}",
                    path.display(),
                    io_reason(&err)
                )));
            }
            Ok(Ok(()))
        }
        OpenSource::Ref(dirtree, dirmeta) => {
            txn.overlay_tree_to_mtree(&dirtree, &dirmeta, mtree, modifier)
                .await?;
            Ok(Ok(()))
        }
        OpenSource::Tar(input) => {
            let opts = match tar_import_options(args) {
                Ok(opts) => opts,
                Err(message) => return Ok(Err(message)),
            };
            repo.import_tar_into(txn, opts, input, mtree, modifier)
                .await?;
            Ok(Ok(()))
        }
    }
}

/// The tar import options a `commit` invocation states. The pathname filter is
/// read here, as a tar source is loaded, so a value the reader refuses is
/// reported only where an archive is read: a command line naming no tar source
/// carries a malformed filter at exit 0, which is what the tool does.
fn tar_import_options(args: &CommitArgs) -> std::result::Result<TarImportOptions, String> {
    let mut opts = TarImportOptions::new();
    opts.skip_xattrs = args.no_xattrs;
    opts.autocreate_parents = args.tar_autocreate_parents;

    let Some(value) = args.tar_pathname_filter.as_deref() else {
        return Ok(opts);
    };
    let Some((pattern, replacement)) = value.split_once(',') else {
        return Err("Missing ',' in --tar-pathname-filter".to_owned());
    };
    let regex = Regex::new(pattern).map_err(|err| {
        format!(
            "--tar-pathname-filter: Error while compiling regular expression \
             \u{2018}{pattern}\u{2019}: {err}"
        )
    })?;
    let replacement = parse_replacement(replacement).map_err(|reason| {
        format!(
            "--tar-pathname-filter: Error while reading the replacement \
             \u{2018}{replacement}\u{2019}: {reason}"
        )
    })?;
    // A member the filter empties names the tree root, which is what the tool
    // makes of it: a directory member mapped onto the empty string supplies the
    // root's metadata, so `^dir1/(.*)$,\1` strips a prefix. A file member mapped
    // onto the empty string names the root as a file, which the tar importer
    // refuses (`docs/conformance/cli-surface.md`, "P2").
    opts.rename = Some(Box::new(move |name: &str| {
        Ok(regex
            .replace_all(name, |caps: &Captures| {
                expand_replacement(&replacement, caps)
            })
            .into_owned())
    }));
    Ok(opts)
}

/// One piece of a parsed replacement template.
enum ReplacementPiece {
    /// Literal text.
    Text(String),
    /// The text a group matched, by number.
    Index(usize),
    /// The text a group matched, by name.
    Name(String),
}

/// Read the replacement half of `--tar-pathname-filter`.
///
/// The syntax is the one `g_regex_replace` states, which the port keeps because
/// it is the syntax an operator writes: `\0` to `\9` and `\g<name>` or
/// `\g<number>` name a group, `\\` is a backslash, `\n`, `\t`, `\r`, `\a`,
/// `\b`, `\f`, and `\v` are the control characters, any other escape is
/// refused, and `$` carries no meaning. A group that is unset, or that the
/// expression does not declare, contributes nothing.
fn parse_replacement(replacement: &str) -> std::result::Result<Vec<ReplacementPiece>, String> {
    let text: Vec<char> = replacement.chars().collect();
    let mut pieces = Vec::new();
    let mut literal = String::new();
    let mut at = 0;
    while at < text.len() {
        if text[at] != '\\' {
            literal.push(text[at]);
            at += 1;
            continue;
        }
        at += 1;
        let Some(c) = text.get(at).copied() else {
            return Err("trailing backslash".to_owned());
        };
        at += 1;
        let piece = match c {
            '0'..='9' => ReplacementPiece::Index(c as usize - '0' as usize),
            'g' => {
                if text.get(at) != Some(&'<') {
                    return Err("expected < after \\g".to_owned());
                }
                at += 1;
                let mut name = String::new();
                loop {
                    match text.get(at) {
                        Some('>') => {
                            at += 1;
                            break;
                        }
                        Some(c) => {
                            name.push(*c);
                            at += 1;
                        }
                        None => return Err("unterminated \\g<...>".to_owned()),
                    }
                }
                match name.parse::<usize>() {
                    Ok(index) => ReplacementPiece::Index(index),
                    Err(_) => ReplacementPiece::Name(name),
                }
            }
            '\\' => {
                literal.push('\\');
                continue;
            }
            'n' => {
                literal.push('\n');
                continue;
            }
            't' => {
                literal.push('\t');
                continue;
            }
            'r' => {
                literal.push('\r');
                continue;
            }
            'a' => {
                literal.push('\u{7}');
                continue;
            }
            'b' => {
                literal.push('\u{8}');
                continue;
            }
            'f' => {
                literal.push('\u{c}');
                continue;
            }
            'v' => {
                literal.push('\u{b}');
                continue;
            }
            other => return Err(format!("unknown replacement escape \\{other}")),
        };
        if !literal.is_empty() {
            pieces.push(ReplacementPiece::Text(std::mem::take(&mut literal)));
        }
        pieces.push(piece);
    }
    if !literal.is_empty() {
        pieces.push(ReplacementPiece::Text(literal));
    }
    Ok(pieces)
}

/// Build one match's replacement text.
fn expand_replacement(pieces: &[ReplacementPiece], caps: &Captures) -> String {
    let mut out = String::new();
    for piece in pieces {
        match piece {
            ReplacementPiece::Text(text) => out.push_str(text),
            ReplacementPiece::Index(index) => {
                if let Some(m) = caps.get(*index) {
                    out.push_str(m.as_str());
                }
            }
            ReplacementPiece::Name(name) => {
                if let Some(m) = caps.name(name) {
                    out.push_str(m.as_str());
                }
            }
        }
    }
    out
}

/// The commit modifier the tree-shaping options ask for, or `None` where they
/// ask for nothing. `--canonical-permissions` implies the xattr skip, since
/// canonical ingest records no extended attributes.
fn commit_modifier(
    args: &CommitArgs,
    owner: Owner,
    walk: &WalkOptions,
    devino: Option<DevInoCache>,
) -> Option<CommitModifier> {
    let mut flags = CommitModifierFlags::empty();
    if args.canonical_permissions {
        flags |= CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::SKIP_XATTRS;
    }
    if args.no_xattrs {
        flags |= CommitModifierFlags::SKIP_XATTRS;
    }
    if args.devino_canonical {
        flags |= CommitModifierFlags::DEVINO_CANONICAL;
    }
    // `--consume` empties each filesystem source as it is walked. The flag is
    // read by that walk alone, so a `tar` or a `ref` source ignores it.
    if args.consume {
        flags |= CommitModifierFlags::CONSUME;
    }
    let shapes_modes = args.mode_ro_executables || walk.shapes_modes();
    // A cache that came back empty resolves nothing, so it asks for no modifier
    // of its own. An `archive` repository stores every content object
    // compressed and contributes no entry, and a modifier attached over that
    // empty cache costs a `ref` source the checksum-copy overlay path for no
    // result (`docs/format-reference.md`, "Commit modifier: canonical
    // permissions, consume, and devino").
    if flags == CommitModifierFlags::empty()
        && owner == Owner::default()
        && !shapes_modes
        && walk.skip_list.is_empty()
        && devino.as_ref().is_none_or(DevInoCache::is_empty)
    {
        return None;
    }
    let mut modifier = CommitModifier::new(flags);
    modifier.owner_uid = owner.uid;
    modifier.owner_gid = owner.gid;
    modifier.devino_cache = devino;

    if !walk.skip_list.is_empty() {
        let entries = walk.skip_list.clone();
        let matched = walk.skip_list_matched.clone();
        // A pruned entry never reaches the mode callback, so the OR-form
        // `--statoverride` entry naming the same path is marked here: the walk
        // reached the path and pruned it there, which counts as reached. A path
        // below a pruned directory is never offered and stays unmatched.
        let or_entries: Vec<String> = walk
            .statoverride_or
            .iter()
            .map(|(entry, _)| entry.clone())
            .collect();
        let or_matched = walk.statoverride_matched.clone();
        modifier.filter = Some(Box::new(move |path, _meta| {
            let name = path.as_os_str().as_bytes();
            match entries.iter().position(|entry| entry.as_bytes() == name) {
                Some(index) => {
                    matched.lock().unwrap()[index] = true;
                    if let Some(index) = or_entries.iter().position(|e| e.as_bytes() == name) {
                        or_matched.lock().unwrap()[index] = true;
                    }
                    FilterResult::Skip
                }
                None => FilterResult::Allow,
            }
        }));
    }

    if shapes_modes {
        let or_entries = walk.statoverride_or.clone();
        let assign_entries = walk.statoverride_assign.clone();
        let matched = walk.statoverride_matched.clone();
        let spent_entries = walk.statoverride_spent.clone();
        let source_is_tar = walk.source_is_tar.clone();
        let ro_executables = args.mode_ro_executables;
        modifier.mode_callback = Some(Box::new(move |path, meta| {
            let mut mode = meta.mode;
            // `--mode-ro-executables` runs first, so a `--statoverride` entry
            // over the same path states the mode the entry ends with.
            if ro_executables && mode & S_IFMT == S_IFREG && mode & EXEC_BITS != 0 {
                mode &= !WRITE_BITS;
            }
            let name = path.as_os_str().as_bytes();
            // The OR form stands ahead of the `=` form: where a path carries an
            // entry of each, the OR value alone reaches the mode, whichever
            // order the file states the two lines in.
            if let Some(index) = or_entries.iter().position(|(e, _)| e.as_bytes() == name) {
                matched.lock().unwrap()[index] = true;
                // An OR entry reaches one tree entry per run: the first any
                // source offers under its path spends it, and a later source
                // under that path keeps the mode it brought.
                let spent = std::mem::replace(&mut spent_entries.lock().unwrap()[index], true);
                // A directory below the walk root spends the entry and takes no
                // value from it, leaving the mode to the `=` form or to the walk
                // where there is none. An archive's member is the exception: the
                // OR value reaches a directory there.
                if !spent
                    && (name == WALK_ROOT.as_bytes()
                        || mode & S_IFMT != S_IFDIR
                        || source_is_tar.load(Ordering::Relaxed))
                {
                    return mode | or_entries[index].1;
                }
            }
            // An `=` entry states the permission bits alone; the entry's own
            // file-type bits stay, so a value carrying type bits of its own
            // renames the type the mode holds.
            match assign_entries.iter().find(|(e, _)| e.as_bytes() == name) {
                Some((_, value)) => (mode & S_IFMT) | value,
                None => mode,
            }
        }));
    }
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
        "set" => config_set(&repo, &args).await,
        "unset" => config_unset(&repo, &args).await,
        other => exit_error(&format!("Unknown operation {other}")),
    }
}

/// The group and key one `config` operand names: `section.key`, split on its
/// first `.`, or a bare key name when `--group` names the section. A missing
/// operand is reported in the tool's own words, which name the group when
/// `--group` was given.
fn config_target(args: &ConfigArgs) -> (&str, &str) {
    let Some(key) = args.args.first() else {
        if args.group.is_some() {
            exit_error("Group name and key must be specified");
        }
        exit_error("KEY must be specified");
    };
    match args.group.as_deref() {
        Some(group) => (group, key.as_str()),
        None => match key.split_once('.') {
            Some((group, key)) => (group, key),
            None => exit_error("Key must be of the form \"sectionname.keyname\""),
        },
    }
}

/// Print one configuration value.
fn config_get(repo: &Repo, args: &ConfigArgs) -> Result<()> {
    let (group, key) = config_target(args);
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

/// Set one configuration value, creating the group when it is new, and write the
/// document back. The value is escaped the way the tool escapes one on write, so
/// a value carrying a newline or leading whitespace is stored in a form that
/// reads back whole.
async fn config_set(repo: &Repo, args: &ConfigArgs) -> Result<()> {
    if args.args.len() < 2 {
        if args.group.is_some() {
            exit_error("GROUP name, KEY and VALUE must be specified");
        }
        exit_error("KEY and VALUE must be specified");
    }
    let (group, key) = config_target(args);
    let value = &args.args[1];
    let mut keyfile = repo.config().keyfile().clone();
    keyfile.set_string(group, key, value)?;
    repo.write_config(&keyfile).await
}

/// Remove one configuration value and write the document back. A key the
/// document does not hold, and a group it does not hold, are both success and
/// leave the file untouched, matching the tool.
async fn config_unset(repo: &Repo, args: &ConfigArgs) -> Result<()> {
    let (group, key) = config_target(args);
    let mut keyfile = repo.config().keyfile().clone();
    if !keyfile.remove_key(group, key) {
        return Ok(());
    }
    repo.write_config(&keyfile).await
}

// --- remote ------------------------------------------------------------------

/// The summary's GVariant signature, which the raw report parses against.
const SUMMARY_SIGNATURE: &str = "(a(s(taya{sv}))a{sv})";

/// The summary metadata keys the report gives a label of their own
/// (`docs/format-reference.md`, "CLI output formats", under `remote summary`).
const SUMMARY_LABELS: &[(&str, &str)] = &[
    ("ostree.summary.mode", "Repository Mode"),
    ("ostree.summary.last-modified", "Last-Modified"),
    ("ostree.summary.tombstone-commits", "Has Tombstone Commits"),
    ("ostree.static-deltas", "Static Deltas"),
    ("ostree.summary.collection-map", "Collection Map"),
    ("ostree.summary.collection-id", "Collection ID"),
];

/// The per-ref metadata keys the report labels, with the same treatment.
const REF_LABELS: &[(&str, &str)] = &[
    ("ostree.commit.version", "Version"),
    ("ostree.commit.timestamp", "Timestamp"),
];

/// Run one `remote` subcommand.
async fn remote(repo: Repo, sub: RemoteCommand) -> Result<()> {
    let nested = sub.name();
    match sub {
        RemoteCommand::Add(args) => remote_add(&repo, nested, args).await,
        RemoteCommand::Delete(args) => remote_delete(&repo, nested, args).await,
        RemoteCommand::List(args) => remote_list(&repo, &args),
        RemoteCommand::ShowUrl(args) => remote_show_url(&repo, nested, &args),
        RemoteCommand::Refs(args) => remote_refs(&repo, nested, &args).await,
        RemoteCommand::Summary(args) => remote_summary(&repo, nested, &args).await,
        RemoteCommand::GpgImport(args) => remote_gpg_import(&repo, nested, args).await,
        RemoteCommand::GpgListKeys(args) => remote_gpg_list_keys(&repo, nested, &args).await,
    }
}

/// The key-file group one remote's configuration lives in.
fn remote_group(name: &str) -> String {
    format!("remote \"{name}\"")
}

/// Whether `name` is a name the tool accepts for a remote: at least one
/// character, every character alphanumeric or one of `-`, `_`, `.`, and the
/// first one alphanumeric or `_`. Recovered by offering the tool a set of names
/// (`docs/format-reference.md`, "CLI output formats", under `remote add`), which
/// is why `_` is a name and `-`, `.`, and `..` are not.
fn valid_remote_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_alphanumeric() || first == '_') {
        return false;
    }
    name.chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// The operand naming the remote, or the tool's own refusal for a missing one.
fn remote_operand<'a>(nested: &str, name: Option<&'a str>) -> &'a str {
    match name {
        Some(name) => name,
        None => exit_with_nested_error("remote", nested, "NAME must be specified"),
    }
}

/// The configuration section of a remote a reading subcommand names, or the
/// tool's own refusal. A read reaches no name rule: a name `add` would refuse
/// simply names no section.
fn remote_section<'a>(repo: &'a Repo, name: &str) -> ostrya::Remote<'a> {
    match repo.config().remote(name) {
        Some(section) => section,
        None => exit_error(&format!("Remote \"{name}\" not found")),
    }
}

/// Refuse a remote the configuration does not describe, for a subcommand that
/// reads nothing out of the section itself.
fn require_remote(repo: &Repo, name: &str) {
    remote_section(repo, name);
}

/// The URL a remote publishes, or the tool's own refusal for a section that
/// states none. A metalink-described remote states no `url`, so `show-url` and
/// `list -u` refuse it.
fn remote_url(section: &ostrya::Remote<'_>, name: &str) -> Result<String> {
    match section.url()? {
        Some(url) => Ok(url),
        None => exit_error(&format!("No \"url\" option in remote \"{name}\"")),
    }
}

/// Add a remote's configuration section, and import a keyring into its trusted
/// keys when `--gpg-import` names one.
///
/// The keys are written in the order the tool writes them: the URL (or the
/// metalink), the branch list, the content URL, the custom backend, the
/// `--set` pairs in the order they were given, the GPG switch, the sign-api
/// verification keys, and the collection id.
async fn remote_add(repo: &Repo, nested: &str, args: RemoteAddArgs) -> Result<()> {
    let (Some(name), Some(url)) = (args.name.as_deref(), args.url.as_deref()) else {
        exit_with_nested_error("remote", nested, "NAME and URL must be specified");
    };
    if args.if_not_exists && args.force {
        exit_with_nested_error(
            "remote",
            nested,
            "Can only specify one of --if-not-exists and --force",
        );
    }
    if !args.sign_verify.is_empty() && args.no_sign_verify {
        exit_error("Cannot specify both --sign-verify and --no-sign-verify");
    }
    if !valid_remote_name(name) {
        exit_error(&format!("Invalid remote name {name}"));
    }

    let group = remote_group(name);
    let mut keyfile = repo.config().keyfile().clone();
    if keyfile.has_group(&group) {
        if args.if_not_exists {
            return Ok(());
        }
        if !args.force {
            exit_error(&format!(
                "Remote configuration for \"{name}\" already exists: (in config)"
            ));
        }
        keyfile.remove_group(&group);
    }

    match url.strip_prefix("metalink=") {
        Some(metalink) => keyfile.set_string(&group, "metalink", metalink)?,
        None => keyfile.set_string(&group, "url", url)?,
    }
    if !args.branches.is_empty() {
        // Each branch is followed by the separator, the trailing one included,
        // which is the list form the tool writes.
        let mut list = String::new();
        for branch in &args.branches {
            list.push_str(branch);
            list.push(';');
        }
        keyfile.set_string(&group, "branches", &list)?;
    }
    if let Some(contenturl) = &args.contenturl {
        keyfile.set_string(&group, "contenturl", contenturl)?;
    }
    if let Some(backend) = &args.custom_backend {
        keyfile.set_string(&group, "custom-backend", backend)?;
    }
    for pair in &args.set {
        let Some((key, value)) = pair.split_once('=') else {
            exit_error("Missing '=' in KEY=VALUE for --set");
        };
        keyfile.set_string(&group, key, value)?;
    }
    // `--no-sign-verify` turns the GPG check off as well, which is what the tool
    // writes for it.
    if args.no_gpg_verify || args.no_sign_verify {
        keyfile.set_string(&group, "gpg-verify", "false")?;
    }
    if args.no_sign_verify {
        keyfile.set_string(&group, "sign-verify", "false")?;
    }
    if !args.sign_verify.is_empty() {
        let mut engines: Vec<&str> = Vec::new();
        for spec in &args.sign_verify {
            let (engine, key, from_file) = parse_sign_verify_spec(spec);
            let suffix = if from_file { "file" } else { "key" };
            keyfile.set_string(&group, &format!("verification-{engine}-{suffix}"), key)?;
            engines.push(engine);
        }
        keyfile.set_string(&group, "sign-verify", &engines.join(","))?;
    }
    if let Some(collection_id) = &args.collection_id {
        keyfile.set_string(&group, "collection-id", collection_id)?;
    }
    repo.write_config(&keyfile).await?;

    if let Some(path) = &args.gpg_import {
        let keys = read_keyring_file(path)?;
        report_gpg_import(gpg_import(repo, name, &keys, &[]).await?, name);
    }
    Ok(())
}

/// Read one `--sign-verify` or `--gpg-import` engine spec:
/// `KEYTYPE=inline:PUBKEY` or `KEYTYPE=file:PATH`, refused in the tool's own
/// words. The engine name is held to the ones this build carries, which is where
/// the tool reports a type it does not implement.
fn parse_sign_verify_spec(spec: &str) -> (&str, &str, bool) {
    let malformed = || {
        exit_error(&format!(
            "Failed to parse KEYTYPE=[inline|file]:DATA in {spec}"
        ))
    };
    let Some((engine, source)) = spec.split_once('=') else {
        malformed()
    };
    if engine.is_empty() {
        malformed()
    }
    let known = match engine {
        "ed25519" => true,
        #[cfg(feature = "spki")]
        "spki" => true,
        _ => false,
    };
    if !known {
        exit_error("Requested signature type is not implemented");
    }
    if let Some(key) = source.strip_prefix("inline:") {
        (engine, key, false)
    } else if let Some(path) = source.strip_prefix("file:") {
        (engine, path, true)
    } else {
        malformed()
    }
}

/// Delete a remote's configuration section and its trusted keyring.
async fn remote_delete(repo: &Repo, nested: &str, args: RemoteDeleteArgs) -> Result<()> {
    let name = remote_operand(nested, args.name.as_deref());
    if !valid_remote_name(name) {
        exit_error(&format!("Invalid remote name {name}"));
    }
    let mut keyfile = repo.config().keyfile().clone();
    if !keyfile.remove_group(&remote_group(name)) {
        if args.if_exists {
            return Ok(());
        }
        exit_error(&format!("Remote \"{name}\" not found"));
    }
    repo.write_config(&keyfile).await?;
    repo.remove_remote_keyring(name).await
}

/// List the configured remote names, sorted by name, with each URL after its
/// name under `-u`.
///
/// Under `-u` the names are padded to the longest name of the whole list plus
/// two, counted in bytes, so the URLs line up; a remote that states no `url`
/// stops the listing where its turn comes, the names before it already printed.
fn remote_list(repo: &Repo, args: &RemoteListArgs) -> Result<()> {
    let mut names: Vec<&str> = repo.config().remotes().collect();
    names.sort_unstable();
    let width = names.iter().map(|name| name.len()).max().unwrap_or(0) + 2;
    for name in names {
        if !args.show_urls {
            println!("{name}");
            continue;
        }
        let section = remote_section(repo, name);
        let padding = " ".repeat(width - name.len());
        println!("{name}{padding}{}", remote_url(&section, name)?);
    }
    Ok(())
}

/// Print one remote's URL.
fn remote_show_url(repo: &Repo, nested: &str, args: &RemoteNameArgs) -> Result<()> {
    let name = remote_operand(nested, args.name.as_deref());
    let section = remote_section(repo, name);
    println!("{}", remote_url(&section, name)?);
    Ok(())
}

/// The summary a remote publishes, or the tool's own refusal when it publishes
/// none. `absent` is the wording for the subcommand asking.
async fn fetch_remote_summary(repo: &Repo, name: &str, absent: &str) -> Result<Summary> {
    require_remote(repo, name);
    let (bytes, _signature) = repo.remote_fetch_summary(name).await?;
    let Some(bytes) = bytes else {
        exit_error(absent);
    };
    Summary::parse(&bytes)
}

/// List the refs a remote's summary publishes, each under the remote's prefix.
async fn remote_refs(repo: &Repo, nested: &str, args: &RemoteRefsArgs) -> Result<()> {
    let name = remote_operand(nested, args.name.as_deref());
    let summary = fetch_remote_summary(
        repo,
        name,
        "Remote refs not available; server has no summary file",
    )
    .await?;
    for entry in &summary.refs {
        if args.revision {
            println!("{name}:{}\t{}", entry.name, entry.commit.to_hex());
        } else {
            println!("{name}:{}", entry.name);
        }
    }
    Ok(())
}

/// Report a remote's summary: the raw variant, the metadata keys, one metadata
/// value, or the summary report itself.
async fn remote_summary(repo: &Repo, nested: &str, args: &RemoteSummaryArgs) -> Result<()> {
    let name = remote_operand(nested, args.name.as_deref());
    if args.raw {
        require_remote(repo, name);
        let (bytes, _) = repo.remote_fetch_summary(name).await?;
        let Some(bytes) = bytes else {
            exit_error("Remote server has no summary file");
        };
        let ty = parse_type(SUMMARY_SIGNATURE)?;
        let value = from_bytes(&ty, &bytes).map_err(|err| Error::InvalidFormat(err.to_string()))?;
        println!("{}", variant_text(&ty, &value.byteswapped())?);
        return Ok(());
    }
    let summary = fetch_remote_summary(repo, name, "Remote server has no summary file").await?;
    if args.list_metadata_keys {
        print_sorted_keys(&summary.metadata);
        return Ok(());
    }
    if let Some(key) = args.print_metadata_key.as_deref() {
        // The raw reports convert the stored big-endian fields, so a value read
        // by name reads as the number the field states.
        let metadata = summary.metadata.byteswapped();
        let Some(value) = metadata.dict_get(key) else {
            exit_error(&format!("No such metadata key '{key}'"));
        };
        return print_metadata_value(value, false);
    }
    print_summary_report(&summary)
}

/// Report a summary the way the tool reports one: each ref of field 0, then the
/// refs of every collection the collection map lists, then the global metadata
/// in the order the summary stores it.
fn print_summary_report(summary: &Summary) -> Result<()> {
    let collection_id = summary
        .metadata_value("ostree.summary.collection-id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    for entry in &summary.refs {
        print_summary_ref(collection_id.as_deref(), entry)?;
    }
    for (collection, refs) in summary.collection_map()? {
        for entry in &refs {
            print_summary_ref(Some(&collection), entry)?;
        }
    }
    for entry in summary.metadata.as_array().unwrap_or_default() {
        let Some((key, value)) = dict_entry(entry) else {
            continue;
        };
        print_summary_metadata(key, value)?;
    }
    Ok(())
}

/// Report one ref of a summary: its name, the size and checksum of the commit it
/// names, and the metadata the summary records for it. A repository that states
/// a collection id names each of its refs as a `(collection, ref)` pair.
fn print_summary_ref(collection_id: Option<&str>, entry: &SummaryRef) -> Result<()> {
    match collection_id {
        Some(collection) => println!("* ({collection}, {})", entry.name),
        None => println!("* {}", entry.name),
    }
    println!("    Latest Commit ({} bytes):", entry.commit_size);
    println!("      {}", entry.commit.to_hex());
    for member in entry.metadata.as_array().unwrap_or_default() {
        let Some((key, value)) = dict_entry(member) else {
            continue;
        };
        let label = label_for(REF_LABELS, key);
        match (key, value.as_variant()) {
            ("ostree.commit.timestamp", Some((_, inner))) => {
                let seconds = inner.as_u64().unwrap_or_default().swap_bytes();
                println!("    {label}: {}", format_iso_utc(seconds));
            }
            (_, Some((_, Value::Str(text)))) => println!("    {label}: {text}"),
            (_, Some((ty, inner))) => {
                println!("    {label}: {}", unannotated_text(ty, inner)?);
            }
            (_, None) => {}
        }
    }
    println!();
    Ok(())
}

/// Report one global metadata entry. The keys the format defines carry a label
/// and their own rendering; every other key prints its name and its value in the
/// text form, with no type annotation.
fn print_summary_metadata(key: &str, value: &Value) -> Result<()> {
    let label = label_for(SUMMARY_LABELS, key);
    let Some((ty, inner)) = value.as_variant() else {
        return Ok(());
    };
    match key {
        "ostree.summary.last-modified" => {
            let seconds = inner.as_u64().unwrap_or_default().swap_bytes();
            println!("{label}: {}", format_iso_utc(seconds));
        }
        "ostree.summary.tombstone-commits" => {
            let yes = inner.as_bool().unwrap_or(false);
            println!("{label}: {}", if yes { "Yes" } else { "No" });
        }
        // The map's refs are reported with the other refs, above.
        "ostree.summary.collection-map" => println!("{label}: (printed above)"),
        _ => match inner {
            Value::Str(text) => println!("{label}: {text}"),
            _ => println!("{label}: {}", unannotated_text(ty, inner)?),
        },
    }
    Ok(())
}

/// The label a report gives `key`, which is the key itself when the format does
/// not define one. A labeled key carries its name in parentheses.
fn label_for(labels: &[(&str, &str)], key: &str) -> String {
    match labels.iter().find(|(name, _)| *name == key) {
        Some((_, label)) => format!("{label} ({key})"),
        None => key.to_owned(),
    }
}

/// One `a{sv}` entry read as a key and the variant it holds.
fn dict_entry(entry: &Value) -> Option<(&str, &Value)> {
    let fields = entry.as_tuple()?;
    Some((fields.first()?.as_str()?, fields.get(1)?))
}

/// Render a value in the GVariant text form with no type annotation, the form a
/// report that names the value itself uses.
fn unannotated_text(ty: &Type, value: &Value) -> Result<String> {
    to_text_unannotated(ty, value).map_err(|err| Error::InvalidFormat(err.to_string()))
}

/// Render a timestamp the way a summary report does: UTC, in
/// `YYYY-MM-DDTHH:MM:SS+00`. The tool renders the same instant in the host's
/// time zone (`docs/conformance/cli-surface.md`, "P3").
fn format_iso_utc(timestamp: u64) -> String {
    let seconds = timestamp as i64;
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (rest / 3600, (rest % 3600) / 60, rest % 60);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}+00")
}

/// Read a keyring file whole, refusing what the tool refuses in its own words.
fn read_keyring_file(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|err| {
        exit_error(&format!(
            "Error opening file {}: {}",
            path.display(),
            io_reason(&err)
        ))
    })
}

/// Import keys into a remote's trusted keyring.
async fn remote_gpg_import(repo: &Repo, nested: &str, args: RemoteGpgImportArgs) -> Result<()> {
    let name = remote_operand(nested, args.name.as_deref());
    if !args.keyring.is_empty() && args.stdin {
        exit_with_nested_error(
            "remote",
            nested,
            "--keyring and --stdin are mutually exclusive",
        );
    }
    // The key sources are read before the remote is looked up, the order the
    // tool takes: a `--keyring` naming no file is reported even for a remote the
    // configuration does not describe.
    let mut keys = Vec::new();
    if args.stdin {
        use std::io::Read;
        std::io::stdin().read_to_end(&mut keys)?;
    } else {
        for path in &args.keyring {
            keys.extend_from_slice(&read_keyring_file(path)?);
        }
    }
    // This one subcommand prefixes its refusal of an unknown remote, which the
    // tool's own message does too.
    if repo.config().remote(name).is_none() {
        exit_error(&format!("GPG: Remote \"{name}\" not found"));
    }
    if keys.is_empty() {
        exit_error("No keys to import; pass --keyring or --stdin");
    }
    let imported = gpg_import(repo, name, &keys, &args.key_ids).await?;
    report_gpg_import(imported, name);
    Ok(())
}

/// Print what an import added, in the tool's own words, which count the keys the
/// keyring did not already hold.
fn report_gpg_import(imported: usize, remote: &str) {
    let keys = if imported == 1 { "key" } else { "keys" };
    println!("Imported {imported} GPG {keys} to remote \"{remote}\"");
}

/// List the keys a remote's trusted keyring holds.
async fn remote_gpg_list_keys(repo: &Repo, nested: &str, args: &RemoteNameArgs) -> Result<()> {
    let name = remote_operand(nested, args.name.as_deref());
    require_remote(repo, name);
    for key in gpg_list_keys(repo, name).await? {
        println!("Key: {}", key.fingerprint);
        if let Some(created) = key.created {
            println!("  Created: {}", format_utc(created));
        }
        for uid in &key.user_ids {
            println!("  UID: {uid}");
        }
    }
    Ok(())
}

#[cfg(feature = "gpg")]
async fn gpg_import(repo: &Repo, remote: &str, keys: &[u8], key_ids: &[String]) -> Result<usize> {
    repo.gpg_import_keys(remote, keys, key_ids).await
}

#[cfg(not(feature = "gpg"))]
async fn gpg_import(_: &Repo, _: &str, _: &[u8], _: &[String]) -> Result<usize> {
    Err(unsupported_type("gpg"))
}

#[cfg(feature = "gpg")]
async fn gpg_list_keys(repo: &Repo, remote: &str) -> Result<Vec<ostrya::GpgKey>> {
    repo.gpg_list_keys(remote).await
}

#[cfg(not(feature = "gpg"))]
async fn gpg_list_keys(_: &Repo, _: &str) -> Result<Vec<GpgKeyStub>> {
    Err(unsupported_type("gpg"))
}

/// Stands in for the GPG key record where the engine is not built, so the
/// listing's own code compiles under either feature set.
#[cfg(not(feature = "gpg"))]
struct GpgKeyStub {
    fingerprint: String,
    created: Option<u64>,
    user_ids: Vec<String>,
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
        exit_process(1);
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
            exit_process(1);
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
        exit_process(1);
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
            repo.delete_signatures(commit, key, move |_, blob| doomed.iter().any(|d| d == blob))
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
    repo.delete_signatures(commit, "ostree.gpgsigs", move |_, blob| {
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

/// The metadata key holding the ref names a commit is bound to.
const REF_BINDING_KEY: &str = "ostree.ref-binding";
/// The metadata key holding the collection id a commit is bound to.
const COLLECTION_BINDING_KEY: &str = "ostree.collection-binding";
/// The metadata key `--bootable` fills with the kernel directory's name.
const LINUX_KEY: &str = "ostree.linux";
/// The metadata key `--bootable` sets to true.
const BOOTABLE_KEY: &str = "ostree.bootable";
/// The metadata key `--generate-composefs-metadata` fills with the tree's
/// composefs image digest.
const COMPOSEFS_DIGEST_KEY: &str = "ostree.composefs.digest.v0";
/// The directory `--bootable` searches, one level deep, for the kernel.
const MODULES_DIR: &str = "/usr/lib/modules";
/// The entry name a kernel directory must hold. Its type is not read: a
/// regular file, a symlink, and a directory of that name all count.
const KERNEL_ENTRY: &str = "vmlinuz";

/// The kernel version `--bootable` stores in `ostree.linux`: the name of the
/// single directory under `/usr/lib/modules` in the committed tree that holds an
/// entry named `vmlinuz`. The search is one level deep, and an entry under
/// `/usr/lib/modules` that is not a directory takes no part
/// (`docs/format-reference.md`, "CLI output formats", `commit`).
///
/// The refusals carry the tool's own wording: the first component of the path
/// the tree does not hold, a component that is not a directory, and the two
/// counts that are not one.
async fn kernel_version(
    txn: &Transaction,
    root: &RepoTree,
) -> Result<std::result::Result<String, String>> {
    let mut dir = root.clone();
    let mut walked = String::new();
    for component in MODULES_DIR.split('/').filter(|part| !part.is_empty()) {
        walked.push('/');
        walked.push_str(component);
        let entry = txn
            .read_dir(&dir)
            .await?
            .into_iter()
            .find(|entry| entry_name(entry) == component);
        match entry {
            None => {
                return Ok(Err(format!("No such file or directory: {walked}")));
            }
            Some(TreeEntry::File { .. }) => return Ok(Err("Not a directory".to_owned())),
            Some(TreeEntry::Dir { tree, .. }) => dir = tree,
        }
    }
    let mut found = Vec::new();
    for entry in txn.read_dir(&dir).await? {
        if let TreeEntry::Dir { name, tree } = entry
            && txn
                .read_dir(&tree)
                .await?
                .iter()
                .any(|entry| entry_name(entry) == KERNEL_ENTRY)
        {
            found.push(name);
        }
    }
    match found.len() {
        0 => Ok(Err(format!("No kernel found in {MODULES_DIR}"))),
        1 => Ok(Ok(found.remove(0))),
        _ => Ok(Err(format!("Multiple kernels found in {MODULES_DIR}"))),
    }
}

/// The name of a directory entry, whichever kind it is.
fn entry_name(entry: &TreeEntry) -> &str {
    match entry {
        TreeEntry::File { name, .. } | TreeEntry::Dir { name, .. } => name,
    }
}

/// Insert entries at the head of an `a{sv}` metadata dict, the slot the keys a
/// tree walk derives take (`docs/format-reference.md`, "CLI output formats",
/// `commit`).
fn prepend_metadata_entries(metadata: &mut Value, entries: Vec<Value>) -> Result<()> {
    let Value::Array(existing) = metadata else {
        return Err(Error::InvalidFormat(
            "commit metadata must be an a{sv} dict".into(),
        ));
    };
    existing.splice(0..0, entries);
    Ok(())
}

/// Remove every entry of an `a{sv}` metadata dict holding one of these keys,
/// which is what a derived key does to a value the command line supplied for the
/// same name.
fn drop_metadata_keys(metadata: &mut Value, keys: &[&str]) -> Result<()> {
    let Value::Array(existing) = metadata else {
        return Err(Error::InvalidFormat(
            "commit metadata must be an a{sv} dict".into(),
        ));
    };
    existing.retain(|entry| match entry {
        Value::Tuple(fields) => match fields.first() {
            Some(Value::Str(key)) => !keys.contains(&key.as_str()),
            _ => true,
        },
        _ => true,
    });
    Ok(())
}

/// Store one entry in an `a{sv}` metadata dict under `key`. An entry the dict
/// already holds under that name takes the new value in the slot it stands in,
/// and every later entry under the same name is removed. A name the dict does
/// not hold is appended.
fn set_metadata_entry(metadata: &mut Value, key: &str, entry: Value) -> Result<()> {
    let Value::Array(existing) = metadata else {
        return Err(Error::InvalidFormat(
            "commit metadata must be an a{sv} dict".into(),
        ));
    };
    let holds_key = |value: &Value| match value {
        Value::Tuple(fields) => matches!(fields.first(), Some(Value::Str(name)) if name == key),
        _ => false,
    };
    let mut slot = None;
    let mut kept = 0;
    existing.retain(|value| {
        if holds_key(value) {
            if slot.is_none() {
                slot = Some(kept);
            }
            return false;
        }
        kept += 1;
        true
    });
    match slot {
        Some(at) => existing.insert(at, entry),
        None => existing.push(entry),
    }
    Ok(())
}

/// The `ostree.ref-binding` value: the branch `-b` named together with every
/// `--bind-ref` value, sorted byte-wise ascending with duplicates kept. A commit
/// that names neither carries the empty `as` array, which is the value the tool
/// writes under `--orphan` alone
/// (`docs/format-reference.md`, "CLI output formats").
fn ref_binding(branch: Option<&str>, bind_refs: &[String]) -> Value {
    let mut names: Vec<&str> = branch
        .into_iter()
        .chain(bind_refs.iter().map(String::as_str))
        .collect();
    names.sort_unstable();
    Value::variant(
        Type::parse("as").expect("\"as\" is a valid gvariant type"),
        Value::Array(
            names
                .into_iter()
                .map(|name| Value::Str(name.to_owned()))
                .collect(),
        ),
    )
}

/// A string-valued metadata entry, the form `--add-metadata-string` and
/// `--add-detached-metadata-string` write.
fn string_entry(key: &str, value: &str) -> Value {
    Value::Tuple(vec![
        Value::Str(key.to_owned()),
        Value::variant(Type::Str, Value::Str(value.to_owned())),
    ])
}

/// Split every `KEY=VALUE` metadata argument at its first `=`, so a value may
/// hold further ones. An empty key passes here and is refused where the dict is
/// assembled; a missing `=` is refused at once, in the tool's own words.
fn metadata_pairs(arguments: &[String]) -> std::result::Result<Vec<(&str, &str)>, String> {
    arguments
        .iter()
        .map(|argument| {
            argument
                .split_once('=')
                .ok_or_else(|| format!("Missing '=' in KEY=VALUE metadata '{argument}'"))
        })
        .collect()
}

/// Read every `--add-metadata` argument into the key it names and the variant
/// its value states. The value goes through the GVariant text form, and a
/// refusal names the whole argument and the reader's own offsets.
fn parse_added_metadata(arguments: &[String]) -> std::result::Result<Vec<(&str, Value)>, String> {
    let mut entries = Vec::with_capacity(arguments.len());
    for (key, text) in metadata_pairs(arguments)? {
        let argument = format!("{key}={text}");
        let (ty, value) =
            ostrya::from_text(text).map_err(|error| format!("Parsing {argument}: {error}"))?;
        entries.push((key, Value::variant(ty, value)));
    }
    Ok(entries)
}

/// Read every `--keep-metadata` key out of the resolved parent commit, keeping
/// each value's bytes as they stand. A key the parent does not hold is refused
/// naming the commit it was looked for in.
async fn kept_metadata(
    repo: &Repo,
    parent: &Checksum,
    keys: &[String],
) -> Result<std::result::Result<Vec<(String, Value)>, String>> {
    if keys.is_empty() {
        return Ok(Ok(Vec::new()));
    }
    let commit = repo.load_variant(ObjectType::Commit, parent).await?;
    let metadata = commit
        .as_tuple()
        .and_then(|members| members.first())
        .cloned()
        .ok_or_else(|| Error::InvalidFormat("commit object is not a tuple".into()))?;
    let mut entries = Vec::with_capacity(keys.len());
    for key in keys {
        let Some(value) = metadata.dict_get(key) else {
            return Ok(Err(format!(
                "Missing metadata key '{key}' from commit '{}'",
                parent.to_hex()
            )));
        };
        entries.push((key.clone(), value.clone()));
    }
    Ok(Ok(entries))
}

/// Assemble the commit metadata dict, whose entry order is part of the commit
/// checksum (`docs/format-reference.md`, "CLI output formats"): every
/// `--add-metadata-string` in command-line order, then every `--add-metadata`,
/// then every `--keep-metadata`, then the binding keys. Duplicate keys are kept
/// as duplicates. An empty key is refused here, after the tree and the
/// timestamp.
fn commit_metadata_dict(
    repo: &Repo,
    args: &CommitArgs,
    added_strings: &[(&str, &str)],
    added_variants: &[(&str, Value)],
    kept: &[(String, Value)],
) -> std::result::Result<Value, String> {
    let mut entries = Vec::new();
    for (key, value) in added_strings {
        if key.is_empty() {
            return Err("Empty metadata key".to_owned());
        }
        entries.push(string_entry(key, value));
    }
    for (key, value) in added_variants {
        if key.is_empty() {
            return Err("Empty metadata key".to_owned());
        }
        entries.push(Value::Tuple(vec![
            Value::Str((*key).to_owned()),
            value.clone(),
        ]));
    }
    for (key, value) in kept {
        entries.push(Value::Tuple(vec![Value::Str(key.clone()), value.clone()]));
    }
    // `--no-bindings` writes neither binding key, so the dict of a commit that
    // adds nothing of its own comes out empty.
    if !args.no_bindings {
        entries.push(Value::Tuple(vec![
            Value::Str(REF_BINDING_KEY.to_owned()),
            ref_binding(args.branch.as_deref(), &args.bind_ref),
        ]));
        if let Some(collection) = repo.config().collection_id() {
            entries.push(string_entry(COLLECTION_BINDING_KEY, collection));
        }
    }
    Ok(Value::Array(entries))
}

/// The detached metadata dict `--add-detached-metadata-string` writes, or `None`
/// where the option was not given. The entries keep command-line order, an empty
/// key is accepted here, and duplicates are kept as duplicates.
fn detached_metadata_dict(pairs: &[(&str, &str)]) -> Option<Value> {
    if pairs.is_empty() {
        return None;
    }
    Some(Value::Array(
        pairs
            .iter()
            .map(|(key, value)| string_entry(key, value))
            .collect(),
    ))
}

/// The most `-F/--body-file` reads, and the most the `-e/--editor` file reads
/// back. The body is a field of the commit object, and the port loads no
/// metadata object above this size, so a body past it names a commit the port
/// could never read back. The bound keeps the read off the file's own size
/// (`CLAUDE.md`, "Working conventions").
const MAX_BODY_BYTES: u64 = 128 * 1024 * 1024;

/// Read `-F/--body-file`: the whole file becomes the body, byte for byte.
fn read_body_file(path: &Path) -> std::result::Result<String, String> {
    read_message_file(path, "Commit body")
}

/// Read a file that carries commit message text. The file must be valid UTF-8,
/// hold no NUL, and stay within [`MAX_BODY_BYTES`]; `kind` names it in the
/// over-limit line.
///
/// The refusals carry the tool's own wording -- `openat(<path>): <reason>` for
/// a path that does not open, the reason alone for a read that fails, and
/// `Invalid UTF-8` for content neither implementation can hold.
fn read_message_file(path: &Path, kind: &str) -> std::result::Result<String, String> {
    let file = std::fs::File::open(path)
        .map_err(|err| format!("openat({}): {}", path.display(), io_reason(&err)))?;
    let mut bytes = Vec::new();
    let mut bounded = std::io::Read::take(file, MAX_BODY_BYTES + 1);
    std::io::Read::read_to_end(&mut bounded, &mut bytes).map_err(|err| io_reason(&err))?;
    if bytes.len() as u64 > MAX_BODY_BYTES {
        return Err(format!("{kind} larger than {MAX_BODY_BYTES} bytes"));
    }
    if bytes.contains(&0) {
        return Err("Invalid UTF-8".to_owned());
    }
    String::from_utf8(bytes).map_err(|_| "Invalid UTF-8".to_owned())
}

/// The environment variables that name the editor, in the order they are
/// consulted. The first one that is set wins, an empty value included; with
/// none set the built-in default below is used. `GIT_EDITOR` is not among them.
const EDITOR_VARIABLES: [&str; 3] = ["OSTREE_EDITOR", "VISUAL", "EDITOR"];
/// The editor used when no environment variable names one.
const DEFAULT_EDITOR: &str = "vi";

/// The commit-message template written into the editor's temporary file. The
/// branch block is appended for a commit that names one
/// (`docs/format-reference.md`, "CLI output formats").
const MESSAGE_TEMPLATE: &str = "\n\
     # Please enter the commit message for your changes. The first line will\n\
     # become the subject, and the remainder the body. Lines starting\n\
     # with '#' will be ignored, and an empty message aborts the commit.\n";

/// Run the editor over the commit-message template and read the subject and the
/// body back out of what it wrote.
///
/// The template carries the branch block when `branch` names one, and `subject`
/// is appended after the block as a prefill. The editor value is a shell command
/// line, the temporary file's path is appended to it shell-quoted, and a
/// non-zero exit discards the whole edit.
///
/// The wait for the editor leaves the executor free; see [`wait_for_editor`].
async fn run_commit_editor(
    branch: Option<&str>,
    subject: Option<&str>,
) -> std::result::Result<(String, String), String> {
    let mut template = MESSAGE_TEMPLATE.to_owned();
    if let Some(branch) = branch {
        template.push_str("#\n# Branch: ");
        template.push_str(branch);
        template.push('\n');
    }
    if let Some(subject) = subject {
        template.push_str(subject);
        template.push('\n');
    }

    let path = write_editor_file(template.as_bytes())?;
    let editor = editor_command();
    // The command line carries the editor value and the path as bytes, so an
    // editor variable that is not UTF-8, and a `TMPDIR` that is not UTF-8,
    // still name the editor to run and the file the port wrote.
    let mut command = editor.as_bytes().to_vec();
    command.push(b' ');
    command.extend_from_slice(&shell_quote(&path));
    let status = wait_for_editor(command).await;
    // The editor writes the file, so the read is bounded the way `-F` is and
    // refuses the same content: an editor is free to leave any bytes behind
    // (`CLAUDE.md`, "Working conventions", which bars an unbounded read).
    let edited = read_message_file(&path, "Commit message");
    let _ = std::fs::remove_file(&path);

    let status = status.map_err(|err| {
        format!(
            "There was a problem with the editor '{}'{}",
            Path::new(&editor).display(),
            io_reason(&err)
        )
    })?;
    if !status.success() {
        let reason = match status.code() {
            Some(code) => format!("Child process exited with code {code}"),
            None => format!(
                "Child process killed by signal {}",
                std::os::unix::process::ExitStatusExt::signal(&status).unwrap_or(0)
            ),
        };
        return Err(format!(
            "There was a problem with the editor '{}'{reason}",
            Path::new(&editor).display()
        ));
    }
    let edited = edited?;
    let (subject, body) = parse_commit_message(&edited);
    if subject.is_empty() {
        return Err("Aborting commit due to empty commit subject.".to_owned());
    }
    Ok((subject, body))
}

/// Run `command` under `/bin/sh -c` and wait for it to exit.
///
/// The editor takes over the terminal, so it inherits this process's three
/// standard streams, which [`std::process::Command`] gives it and
/// [`ostrya_rt::Command`] pipes. The wait itself runs on the blocking pool
/// through [`ostrya_rt::unblock`], so the executor thread stays free for the
/// length of the editing session.
async fn wait_for_editor(command: Vec<u8>) -> std::io::Result<std::process::ExitStatus> {
    ostrya_rt::unblock(move || {
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(std::ffi::OsString::from_vec(command))
            .status()
    })
    .await
}

/// The editor command line: the first of [`EDITOR_VARIABLES`] that is set, else
/// [`DEFAULT_EDITOR`]. The value is read as bytes, so a variable holding a value
/// that is not UTF-8 counts as set and names the editor to run.
fn editor_command() -> std::ffi::OsString {
    EDITOR_VARIABLES
        .iter()
        .find_map(std::env::var_os)
        .unwrap_or_else(|| std::ffi::OsString::from(DEFAULT_EDITOR))
}

/// Wrap a path so a shell reads it as one word: single quotes around it, with
/// each single quote it holds closed, escaped, and reopened. The bytes pass
/// through unchanged, so a path that is not UTF-8 survives.
fn shell_quote(path: &Path) -> Vec<u8> {
    let mut out = vec![b'\''];
    for &byte in path.as_os_str().as_bytes() {
        if byte == b'\'' {
            out.extend_from_slice(b"'\\''");
        } else {
            out.push(byte);
        }
    }
    out.push(b'\'');
    out
}

/// Write the template to a fresh file under `TMPDIR`, named `.` and six
/// characters, and return its path. The file is created readable and writable
/// by its owner alone, which is the mode the tool creates it with, so the
/// message cannot be read while it is being edited. It is removed once the
/// editor has run.
fn write_editor_file(contents: &[u8]) -> std::result::Result<PathBuf, String> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let dir = std::env::var_os("TMPDIR").map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
    let mut seed = std::process::id() as u64;
    for _ in 0..64 {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(nanos());
        let name: String = (0..6)
            .map(|i| {
                let digit = (seed >> (i * 6)) % 36;
                char::from_digit(digit as u32, 36)
                    .expect("a base-36 digit")
                    .to_ascii_uppercase()
            })
            .collect();
        let path = dir.join(format!(".{name}"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(contents).map_err(|err| io_reason(&err))?;
                return Ok(path);
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(format!("openat({}): {}", path.display(), io_reason(&err)));
            }
        }
    }
    Err(format!(
        "openat({}): could not name an unused temporary file",
        dir.display()
    ))
}

/// The nanosecond part of the current time, which seeds the temporary name.
fn nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| u64::from(since.subsec_nanos()))
}

/// Read the subject and the body out of an edited commit message.
///
/// Every line loses its trailing whitespace, a line whose first character is
/// `#` is dropped, and the leading blank lines go. The first line left is the
/// subject; the lines after it, less their own leading and trailing blank
/// lines, are the body, joined by newlines
/// (`docs/format-reference.md`, "CLI output formats").
fn parse_commit_message(text: &str) -> (String, String) {
    let lines: Vec<&str> = text
        .split('\n')
        .map(str::trim_end)
        .filter(|line| !line.starts_with('#'))
        .collect();
    let mut head = &lines[..];
    while head.first().is_some_and(|line| line.is_empty()) {
        head = &head[1..];
    }
    let Some(subject) = head.first().map(|line| (*line).to_owned()) else {
        return (String::new(), String::new());
    };
    let mut body = &head[1..];
    while body.first().is_some_and(|line| line.is_empty()) {
        body = &body[1..];
    }
    while body.last().is_some_and(|line| line.is_empty()) {
        body = &body[..body.len() - 1];
    }
    (subject, body.join("\n"))
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

    /// The editing session runs off the executor: the first poll of
    /// [`wait_for_editor`] over a command that is still running yields
    /// [`Poll::Pending`] at once, so the thread that drives the commit future is
    /// free while the editor holds the terminal. A wait performed on the
    /// executor thread would instead return [`Poll::Ready`] after the command
    /// exits.
    #[test]
    fn the_editor_wait_leaves_the_executor() {
        use std::future::Future as _;
        use std::task::Poll;
        use std::time::{Duration, Instant};

        // The command outlives the poll below and is reaped by the blocking
        // pool. Two seconds is long enough that a wait taken on this thread
        // cannot come back inside the window asserted below.
        let (pending, held) = ostrya_rt::block_on(async {
            let mut editor = std::pin::pin!(wait_for_editor(b"sleep 2".to_vec()));
            let started = Instant::now();
            let first = std::future::poll_fn(|cx| Poll::Ready(editor.as_mut().poll(cx))).await;
            (first.is_pending(), started.elapsed())
        });
        assert!(pending, "the first poll of the editor wait was ready");
        assert!(
            held < Duration::from_secs(1),
            "the poll held the thread for {held:?}"
        );
    }

    /// A `--skip-list` path and a `--statoverride` path are matched against the
    /// bytes of the walk path. A control file holds UTF-8 alone
    /// ([`read_control_file`]), so an entry spelling `U+FFFD` names that
    /// character and reaches no entry whose name holds a byte that is not
    /// UTF-8.
    ///
    /// Both ingest sources refuse such a name ahead of the callbacks, the
    /// filesystem walk while it reads the directory and the tar reader while it
    /// reads the header, so the two callbacks are driven here directly.
    #[test]
    fn a_control_file_path_matches_the_walk_path_by_bytes() {
        use ostrya::FileMeta;
        use std::ffi::OsStr;

        let cli = Cli::parse_from(["ostrya", "commit", "-b", "x", "/src"]);
        let Some(Command::Commit(args)) = cli.command else {
            panic!("`commit` parsed as another subcommand");
        };
        // One skip-list path and one statoverride path of each form, all four
        // spelling the replacement character.
        let spelled = "/bad\u{fffd}.txt";
        let options = || WalkOptions {
            statoverride_or: vec![(spelled.to_owned(), 0o4000)],
            statoverride_assign: vec![(spelled.to_owned(), 0o707)],
            skip_list: vec![spelled.to_owned()],
            root_pruned: false,
            statoverride_matched: Arc::new(Mutex::new(vec![false])),
            skip_list_matched: Arc::new(Mutex::new(vec![false])),
            statoverride_spent: Arc::new(Mutex::new(vec![false])),
            source_is_tar: Arc::new(AtomicBool::new(false)),
        };
        let meta = FileMeta::regular(0, 0, 0o644);

        // A walk path holding the raw byte `0xFF` is a different path.
        let walk = options();
        let mut modifier = commit_modifier(&args, Owner::default(), &walk, None)
            .expect("the walk options ask for a modifier");
        let raw = Path::new(OsStr::from_bytes(b"/bad\xff.txt"));
        let filter = modifier.filter.as_mut().expect("the skip list sets one");
        assert_eq!(filter(raw, &meta), FilterResult::Allow);
        let mode = modifier
            .mode_callback
            .as_mut()
            .expect("statoverride sets one");
        assert_eq!(mode(raw, &meta), meta.mode);
        assert_eq!(walk.unmatched_skip_list(), vec![spelled.to_owned()]);
        assert_eq!(walk.unmatched_statoverride(), vec![spelled.to_owned()]);

        // The path the entries do spell is matched, so the comparison is exact
        // and not merely refusing.
        let walk = options();
        let mut modifier = commit_modifier(&args, Owner::default(), &walk, None)
            .expect("the walk options ask for a modifier");
        let named = Path::new(spelled);
        let filter = modifier.filter.as_mut().expect("the skip list sets one");
        assert_eq!(filter(named, &meta), FilterResult::Skip);
        let mode = modifier
            .mode_callback
            .as_mut()
            .expect("statoverride sets one");
        assert_eq!(mode(named, &meta), meta.mode | 0o4000);
        assert!(walk.unmatched_skip_list().is_empty());
        assert!(walk.unmatched_statoverride().is_empty());
    }
}
