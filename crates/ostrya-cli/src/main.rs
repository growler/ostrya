#![forbid(unsafe_code)]

//! The `ostrya` command, a command-line front-end for the `ostrya` library.
//!
//! The `ostrya` binary creates, reads, and changes ostree repositories. A
//! subcommand that the `ostree` command also has takes the same option names
//! and values, and writes the same bytes into the repository. The binary is
//! synchronous and drives the async library with [`ostrya_rt::block_on`].
//!
//! # Subcommands
//!
//! [`Command`] has one variant for each subcommand, and [`Cli`] holds the
//! global options.
//!
//! - Repository: `init`, `config`, `remote`, `summary`, `prune`, `fsck`.
//! - Write: `commit`, `refs`, `sign`, `static-delta`.
//! - Read: `checkout`, `export`, `rev-parse`, `cat`, `show`, `log`, `ls`,
//!   `diff`.
//! - Pull: `pull`, `pull-local`.
//! - ostrya extensions: `composefs-image`, `push`, `push-tree`, `receive`,
//!   `send`, `serve`, `remote init`, `remote fsck`, `remote prune`.
//!
//! # Features
//!
//! - `smol` (default): the `smol` runtime backend.
//! - `tokio`: the `tokio` runtime backend.
//! - `spki` (default): the spki signature engine.
//! - `gpg` (default): the gpg signature engine.
//! - `receive` (default): `receive`, the server side of a push over ssh.
//! - `push` (default): `push` and `push-tree`.
//! - `serve` (default): `serve`, the HTTP server of a repository.
//! - `send` (default): `send`, the server side of a pull over ssh.
//! - `s3` (default): the pull from and the push to a bucket repository at an
//!   `s3://` address, `remote init`, `remote fsck`, `remote prune`, and the
//!   S3 options.
//! - `lzma-static` (default): a static liblzma, so the binary needs no
//!   liblzma at run time.
//!
//! # Usage
//!
//! ```text
//! ostrya --repo=repo init --mode=archive
//! ostrya --repo=repo commit -b main -s 'First commit' tree/
//! ostrya --repo=repo log main
//! ```

use std::collections::{HashMap, HashSet};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use ostrya::{
    BootableMetadata, BootableRefusal, CheckoutFilterFn, CheckoutMode, CheckoutOptions, Checksum,
    CollectionPullOptions, CollectionRef, CollectionRefEntry, CommitModifier, CommitModifierFlags,
    CommitOptions, ComposefsImageState, ComposefsOptions, CreateOptions, DeltaEndianness,
    DeltaOptions, DeltaSuperblock, DevInoCache, DictBuilder, DiffChange, DiffOptions, DiffSide,
    Ed25519Signer, Ed25519Verifier, Error, FileKind, FileMeta, FileObject, FilterResult,
    FsckBindingError, FsckBindingErrorKind, FsckError, FsckErrorKind, FsckFailure, FsckOptions,
    FsckPhase, MutableTree, ObjectType, OverwriteMode, PruneOptions, PullFlags, PullOptions,
    PullProgress, PullProgressSnapshot, PullStats, PullVerify, RefAlias, Repo, RepoConfig,
    RepoMode, RepoTree, Result, Signer, Summary, SummaryOptions, TarExportOptions,
    TarImportOptions, TimestampCheck, Transaction, TransactionStats, TreeEntry, Type, Value,
    Verifier, VerifyOutcome, VerityPolicy, Xattrs, base64, from_bytes, load_sign_keys,
    load_sign_keys_from, to_text, to_text_unannotated, validate_refspec,
};
#[cfg(feature = "gpg")]
use ostrya::{GpgSigner, GpgVerifier, SignatureInfo};
#[cfg(feature = "spki")]
use ostrya::{SpkiSigner, SpkiVerifier, spki_public_keys, spki_secret_key_lines, spki_secret_keys};

use pcre2::bytes::{CaptureLocations, RegexBuilder};

#[cfg(test)]
mod man;

/// The command line of the `ostrya` binary: the global options and the
/// subcommand.
///
/// # Global options
///
/// `--repo`, `-v`, and `--version` are global. Each one is accepted before
/// and after the subcommand name. If `--repo` is given in both positions, the
/// value after the subcommand name wins, as in the `ostree` command.
#[derive(Parser)]
#[command(
    name = "ostrya",
    about,
    long_about = concat!(
        env!("CARGO_PKG_DESCRIPTION"),
        ".\n\n",
        "ostrya reads and writes ostree repositories. A repository keeps file \
         trees as commits. Each file, directory, and commit is stored as \
         objects, and the SHA-256 checksum of an object is its name. A ref is \
         a name that points to a commit. The on-disk format is the format of \
         the `ostree` command.\n\n",
        "Each subcommand operates on one repository. The command finds the \
         repository in this order: the --repo option, the current directory, \
         and the `OSTREE_REPO` environment variable. Run `ostrya <COMMAND> \
         --help` to see the options of a subcommand."
    )
)]
struct Cli {
    /// The path of the repository to operate on.
    ///
    /// The option is accepted before and after the subcommand name. If both
    /// positions give a value, the value after the name wins. Without this
    /// option, the command opens the current directory if it is a repository.
    /// Else it opens the path in `OSTREE_REPO` if that path is a repository.
    /// If no source gives a repository, the command prints its usage text and
    /// `error: Command requires a --repo argument`, then exits 1.
    ///
    /// `init` creates a new repository only at an explicit --repo. Without the
    /// option, `init` reuses a repository that it finds in the current
    /// directory or at `OSTREE_REPO`. Each other subcommand exits 1 if an
    /// explicit --repo does not open as a repository.
    #[arg(long, global = true)]
    repo: Option<PathBuf>,
    /// Write extra information to standard error.
    ///
    /// Most subcommands write the line `ostrya: using repository PATH` when
    /// they open the repository. `push` and `push-tree` also write a
    /// statistics line after the push. `receive` and `send` write nothing
    /// more.
    #[arg(short, long, global = true)]
    verbose: bool,
    /// Print version information and exit.
    #[arg(long, global = true)]
    version: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
// `commit` has the largest option set of all subcommands, so its variant is
// the largest. The `Subcommand` derive of `clap` reads the field type as the
// argument group. A `Box` is not an argument group, so the indirection that
// the lint asks for is not possible. The process parses one `Cli` value.
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Initialize a new empty repository.
    ///
    /// The command creates the directory at the --repo path if it does not
    /// exist. The parent directory must exist. Then the command writes the
    /// directories of the repository layout and the `config` file. The
    /// `[core]` group of `config` holds `repo_version=1`, `mode`, and
    /// `collection-id` if --collection-id is given.
    ///
    /// The command is idempotent. It keeps each part of the layout that
    /// exists. If the `config` file exists, the command keeps it unchanged,
    /// and the repository keeps its mode and its collection id. Without
    /// --repo, the command reuses a repository in the current directory or at
    /// `OSTREE_REPO`. It prints nothing on success.
    Init(InitArgs),
    /// Commit a tree into the repository and print the new commit checksum.
    ///
    /// The command reads one or more tree sources: a directory, a tar
    /// archive, or a committed tree. With no --tree option and no PATH, it
    /// reads a tar stream from standard input. It writes the objects of the
    /// tree and the commit object. If signing options name keys, it signs the
    /// commit. Then it points the --branch ref at the new commit, and creates
    /// each --tag ref at the new commit.
    ///
    /// The command needs --branch or --orphan. Without --parent, the parent
    /// is the branch name resolved as a revision. On success, standard output
    /// carries the commit checksum, or the --table-output block. If the
    /// command refuses its input, it exits 1, moves no ref, and creates no
    /// ref.
    Commit(CommitArgs),
    /// Check a commit out onto the file system, or write its composefs image.
    ///
    /// The command writes the tree of COMMIT into DESTINATION. It applies the
    /// owner, the mode, and the extended attributes that the commit records.
    /// -U applies no owner and no extended attributes. A regular file is a
    /// hardlink to its loose object if the repository mode and the checkout
    /// mode permit it. Otherwise it is a copy. Without a union option, an
    /// existing entry at the path of a tree entry is an error.
    ///
    /// --composefs and --composefs-noverity write one EROFS image file at
    /// DESTINATION, and no tree. --from-stdin and --from-file read a stream of
    /// (REFSPEC, SUBPATH) pairs, and check out each pair into one destination.
    /// The command prints nothing.
    Checkout(CheckoutArgs),
    /// Write the tree of a commit as a tar stream, to stdout or to --output.
    ///
    /// The stream holds the files of the tree and no ostree objects. The root
    /// directory is the member `./`, and the other member names are relative
    /// paths. Ownership is numeric, and each timestamp is the commit
    /// timestamp. The extended attributes are `SCHILY.xattr.*` records, which
    /// --no-xattrs removes. The first regular file of a content object goes
    /// into the stream in full, and each later file of that object is a tar
    /// hardlink to it.
    Export(ExportArgs),
    /// List, create, or delete refs.
    ///
    /// Without an option, the command prints the local refs and the remote
    /// refs, one on each line, sorted by refspec. A remote ref prints as
    /// `remote:name`. Each PREFIX keeps the refs equal to it or below it, and
    /// the output groups the rows by PREFIX in the order given. -A lists the
    /// aliases, and -c lists the collection refs. --create and --delete write
    /// the refs and print nothing. --create wins over --delete.
    Refs(RefsArgs),
    /// Print the commit checksum that a revision names.
    ///
    /// The command prints one 64-character checksum on each line, one for each
    /// REV, in order. A revision that does not resolve is an error. --single
    /// prints the one commit object of the repository and takes no REV.
    #[command(name = "rev-parse")]
    RevParse(RevParseArgs),
    /// Write the content of files of a commit to stdout.
    ///
    /// The command writes the bytes of each PATH in order, with no separator.
    /// It follows a symlink in the last component of a PATH. A directory, or a
    /// PATH that names nothing, is an error.
    Cat(CatArgs),
    /// Print the report of an object, or one part of its commit metadata.
    ///
    /// For a commit, a dirtree, or a dirmeta, the command prints the object
    /// type and the checksum. A commit then gets its report: the parent, the
    /// content checksum, the date in UTC, the `version` metadata key if
    /// present, the subject, and the body. The GPG signatures of the commit
    /// follow, if it has any. For a file object, the command prints its
    /// header: the file type, the size or the symlink target, the mode, the
    /// owner, and the extended attributes.
    ///
    /// The report options exclude each other. If the command line holds more
    /// than one, the first in this order wins:
    /// --print-detached-metadata-key, --print-metadata-key,
    /// --list-detached-metadata-keys, --list-metadata-keys, --print-related,
    /// --print-variant-type, and --print-sizes.
    Show(ShowArgs),
    /// Show the log that starts at a commit or ref.
    ///
    /// The command walks the parent chain, newest first. For each commit, it
    /// prints `commit <checksum>` and the commit report of `show`. If the
    /// object of a parent commit is not in the repository, the command prints
    /// `<< History beyond this commit not fetched >>` and exits 0.
    Log(LogArgs),
    /// List the file paths of a commit.
    ///
    /// The command prints one line for each entry: the type and the permission
    /// bits, the uid, the gid, the size, and the path. A symlink adds
    /// ` -> <target>`. The type is `d` for a directory, `-` for a regular
    /// file, and `l` for a symlink. A directory prints its own line, then its
    /// files, then its subdirectories, each in name order.
    Ls(LsArgs),
    /// Read or write a repository configuration value.
    ///
    /// The command reads and writes the `config` file of the repository. `get`
    /// prints the value and a newline. `set` and `unset` print nothing. A
    /// missing group or key is an error for `get`.
    Config(ConfigArgs),
    /// Manage the configured remotes and their trusted GPG keys.
    ///
    /// Each remote is a `[remote "NAME"]` section in the `config` file of the
    /// repository. The trusted GPG keyring of a remote is the file
    /// `NAME.trustedkeys.gpg` at the root of the repository. A nested
    /// subcommand is necessary. Without one, the command fails before it
    /// opens the repository.
    Remote(RemoteArgs),
    /// Delete the objects that no ref or commit of the repository reaches.
    ///
    /// The walk starts from each ref and from each commit in the store. The
    /// command deletes each loose object that the walk does not reach.
    /// --refs-only, --only-branch, --retain-branch-depth, and
    /// --keep-younger-than start the walk from the refs alone. The depth and
    /// date options then limit the history of each ref.
    ///
    /// The related commits of each commit that the walk reaches are also
    /// roots, under the bound of --depth or --keep-younger-than. A related
    /// commit gets this bound also if --retain-branch-depth gives the commit
    /// that names it a different depth. Field 2 of a commit holds its
    /// dependencies, which `commit --related` writes. The detached metadata
    /// key `ostrya.related` holds its build sources. The walk reads the two
    /// fields of each related commit too. An entry that names a commit that
    /// is not in the store gives no error. The command then keeps the
    /// detached metadata and the composefs image of that commit if they are
    /// in the store. For each defective value, the command writes a warning
    /// on standard error, and the defective value roots nothing. A detached
    /// metadata file that does not parse fails the command.
    ///
    /// The command also deletes each static delta whose target commit it
    /// deleted. A run with neither --no-prune nor --static-deltas-only also
    /// deletes each static delta and each `state/<commit>.commitpartial`
    /// marker whose commit is not in the store. If `[core] tombstone-commits`
    /// is true, the command writes a `.tombstone-commit` for each deleted
    /// commit.
    ///
    /// The command prints the total number of objects. It then prints the
    /// number of deleted objects and the freed size, or
    /// `No unreachable objects`. If `[core] locking` is false, the command
    /// takes no repository lock and prints a warning on standard error.
    Prune(PruneArgs),
    /// Verify object integrity and completeness across every commit.
    ///
    /// The command loads the commit of each ref, lists each commit in the
    /// store, and reads each object that these commits reach. Each object must
    /// be present, and its checksum must equal its name. The command skips
    /// each commit that has a `state/<commit>.commitpartial` marker, and
    /// prints the number of these commits.
    ///
    /// The walk runs to its end and writes each finding on standard error. A
    /// ref to a missing commit, a missing dirtree, or a failed binding check
    /// ends the run early. If the command finds an error or skips a partial
    /// commit, it exits 1.
    ///
    /// After the walk, the command checks each composefs image object against
    /// the key `ostree.composefs.digest.v0` of its commit. A faulty image is
    /// an error, and --delete removes it: an image whose digest is not the
    /// key, an image that does not read, and an image whose commit has no key
    /// or a malformed key. If the commit of an image does not load, the
    /// command reports an error and keeps the image. An image whose commit is
    /// absent gets one line on standard output and is not an error.
    Fsck(FsckArgs),
    /// Report the paths that changed between two revisions or directories.
    ///
    /// The command prints one line for each changed path: `M`, `D`, or `A`,
    /// four spaces, and the path. The modified paths come first, then the
    /// deleted paths, then the added paths. An added directory also gives a
    /// line for each entry below it. A deleted directory gives one line. A
    /// path of a commit side starts with `/`, and a path of a directory side
    /// does not.
    ///
    /// With --stats, the command prints the object statistics of two commits
    /// in place of the path lines. With --stats and --fs-diff, it prints the
    /// path lines and then the statistics.
    Diff(DiffArgs),
    /// Add, verify, or delete signatures on a commit.
    ///
    /// The signatures are in the detached metadata of the commit. Without
    /// --verify or --delete, the command signs the commit once for each key and
    /// prints nothing. With --verify, it prints one line for each signature and
    /// a final verdict, and exits 1 if no signature is valid. With --delete, it
    /// removes the signatures that match the KEY-IDs and prints their count.
    /// An ed25519 or spki verify with no key source reads the system key
    /// directories `/etc/ostree` and `/usr/share/ostree`.
    Sign(SignArgs),
    /// Regenerate, sign, or verify the repository summary.
    ///
    /// With -u, the command writes the root summary `summary`, which holds
    /// each ref, and the summary of each auth item of the client groups, from
    /// the refs of the repository. It signs each one with the given keys.
    /// With -u -c, it writes the summaries of the auth items alone, and leaves
    /// `summary` and `summary.sig` as they are. With --verify, it verifies
    /// the signatures in `summary.sig`, and --verify takes precedence over
    /// -u. Without -u and --verify, a KEY-ID or a --keys-file signs each
    /// existing summary.
    /// The read options --raw, -v, --list-metadata-keys, and
    /// --print-metadata-key print the local summary, or with --auth-group the
    /// summary of the item of one client group. If no option gives an
    /// action, the command exits 1.
    Summary(SummaryArgs),
    /// List, generate, apply, or index static deltas.
    ///
    /// A static delta carries the objects that a target commit reaches and its
    /// source commit does not reach. A delta from scratch has no source commit.
    /// The `deltas/` tree of the repository holds the deltas. The
    /// `delta-indexes/` cache lists them for a pull. The nested subcommands
    /// also show, delete, and verify one delta. Without a nested subcommand,
    /// the command reports `No command specified` and exits 1.
    #[command(name = "static-delta")]
    StaticDelta(StaticDeltaArgs),
    /// Fetch refs and their objects from a remote over HTTP or ssh.
    ///
    /// The address is --url, else the `pull-url` key of the remote, else its
    /// `url` key. An address that starts with `ssh://`, or that holds no
    /// `://`, is an ssh address, and the pull runs the ssh client. The remote
    /// command is `ostrya send`, or the `send-command` key of the remote. Each
    /// other address goes to the HTTP fetcher, which takes `http` and `https`
    /// alone. The `url` key cannot hold an ssh address.
    ///
    /// The pull stores the objects in one transaction, and then writes each
    /// ref under `refs/remotes/<remote>/`, or under `refs/heads/` with
    /// --mirror. It verifies the signatures that the config of the remote or
    /// the verify options ask for. With `[ex-ostrya]
    /// keep-detached-related=false`, the pull drops `ostrya.related`.
    ///
    /// The pull also fetches the dependencies that field 2 of each pulled
    /// commit names, each with no parent and no ref, unless it takes
    /// --commit-metadata-only or --subpath.
    ///
    /// On success, the command prints one statistics line to standard output.
    /// If standard output is a terminal, a progress line shows while the pull
    /// runs, and the statistics line is drawn over it.
    Pull(PullArgs),
    /// Import refs and their objects from another local repository.
    ///
    /// The command opens SRC_REPO and imports each ref, the commits that
    /// --depth reaches, and the objects that these commits reach. When the
    /// link is possible, the pull hardlinks an object of the source into this
    /// repository. The pull writes local refs, or remote refs under --remote.
    /// With --remote, the verification keys of the remote apply to the pull.
    /// With `[ex-ostrya] keep-detached-related=false`, it drops
    /// `ostrya.related`.
    ///
    /// The pull also imports the dependencies that field 2 of each pulled
    /// commit names, each with no parent and no ref, unless it takes
    /// --commit-metadata-only.
    ///
    /// On success, the command prints one statistics line to standard output:
    /// `M metadata, C content objects imported; SIZE content written`. Under
    /// --require-static-deltas, the line has the form of a pull from a
    /// remote. The command writes no progress line.
    #[command(name = "pull-local")]
    PullLocal(PullLocalArgs),
    /// Store, locate, or check the composefs image of a commit.
    ///
    /// The image of a commit is the object `objects/<xx>/<commit>.cfs`. Its
    /// fs-verity digest is the value of `ostree.composefs.digest.v0` in the
    /// metadata of the commit. The command takes exactly one of --add,
    /// --get-path, and --check.
    ///
    /// --add and --check print nothing on success, and --get-path prints one
    /// line. If the action fails, the command writes one `error:` line to
    /// standard error and exits 1. This command is an extension of ostrya.
    #[command(name = "composefs-image")]
    ComposefsImage(ComposefsImageArgs),
    /// Receive one push session over standard input and standard output.
    ///
    /// By default, `ostrya push` runs this command on the server over ssh. The
    /// client name is --client, else the value of `LOGNAME`, which sshd sets
    /// from the password entry of the user. With neither, the command writes
    /// an error line and exits 1 before it opens the repository. At start,
    /// the command reads and checks the client groups, the server group, the
    /// trust groups, and the key groups of the repository config, and a bad
    /// group ends it with status 1. `Hello` names the namespace of the
    /// session: the local refs, or one collection. The session takes the
    /// policy of the client group of that namespace that carries the item
    /// `ssh:NAME`. For a collection, a group that names the collection wins
    /// over a group with `collection=*`. With no such group, `Hello` gets
    /// `ref-denied`. A session of a collection writes the refs under
    /// `refs/mirrors/ID/`. The session uses no `anonymous` and no `net:`
    /// item. With `[core] auto-update-summary=true`, a session that changes a
    /// ref writes each summary again, as `ostrya summary -u` does, signed
    /// with the key groups of `sign-summary`.
    /// Standard output carries the frames of the session alone. For each
    /// warning of the session, the command writes one `warning: STEP: MESSAGE`
    /// line to standard error. It writes nothing else, also under --verbose.
    /// The exit status is 0 after a committed session, also with warnings, and
    /// 1 otherwise.
    #[cfg(feature = "receive")]
    Receive(ReceiveArgs),
    /// Push commits to a remote over ssh or HTTP, or to a bucket repository.
    ///
    /// The command resolves REMOTE and sends the objects that the server does
    /// not have. The server then updates all the refs of the refspecs in one
    /// transaction. Over ssh, the push runs the ssh client with the receive
    /// command on the remote side. Over HTTP, the push sends its requests to
    /// the receive endpoint of `ostrya serve`. To an `s3://` address, the
    /// push reads `[ex-ostrya] keep-detached-related` from the `config` of the
    /// bucket, and with `false` drops `ostrya.related`.
    ///
    /// The collection bindings of the source commits, or --collection, give
    /// the namespace of the push on the server: the local refs or one
    /// collection. The server writes the refs of a collection other than its
    /// own collection id under `refs/mirrors/ID/`.
    ///
    /// To an `s3://` address, the push writes a bucket repository in an S3
    /// bucket with signed requests, and needs no server program. The bucket
    /// repository needs a `config`, which `remote init` writes. The push
    /// holds the writer lock of the bucket repository, uploads each object
    /// that the bucket does not hold, in archive form, and then writes the ref
    /// files. A commit object goes up after each object of its tree. The
    /// bucket gets the `.filez` bytes at the `[archive] zlib-level` of this
    /// repository. The `config` of the bucket takes the role of the server
    /// for --collection: its collection id gives `refs/heads/`, and each
    /// other collection gives `refs/mirrors/ID/`. The push writes no summary,
    /// and a summary of the bucket stays as it is. A pull of a ref that the
    /// summary lists takes the commit of the summary, so after the push moves
    /// that ref, the pull takes the old commit until `ostrya remote summary
    /// -u` writes the summary again. The push refuses --onto,
    /// --tag, --compress, a delete refspec, and the token and ssh options.
    ///
    /// With --onto, the push sends the tree of one local commit, and the
    /// server makes a new commit over it on the branch BRANCH. The server
    /// picks the parent, writes the bindings, and signs the commit.
    ///
    /// The push also sends the dependencies that field 2 of each pushed commit
    /// names, each with no parent and no ref, unless it takes --onto.
    ///
    /// On success, standard output carries one line for each ref, in the order
    /// of the refspecs and then of the tags. A line holds the DST name, the
    /// old state, and the new state. The old state is a full commit checksum,
    /// `(new)`, or `(absent)`. The new state is a full commit checksum,
    /// `(unchanged)`, or `(deleted)`. With --onto, standard output carries the
    /// checksum of the new commit alone.
    ///
    /// Under --verbose, one statistics line goes to standard error. If
    /// standard error is a terminal and `TERM` is set and is not `dumb`,
    /// standard error shows a progress bar while the push runs. A push to a
    /// bucket repository shows no bar while it lists the bucket and walks the
    /// commits. With --break-lock, a push that removed the writer lock of
    /// another writer writes one `warning: removed the writer lock of HOLDER`
    /// line to standard error. On failure, the command writes `error:
    /// MESSAGE` to standard error and nothing to standard output, and exits
    /// 1.
    #[cfg(feature = "push")]
    Push(PushArgs),
    /// Push a directory as a new commit to a server or a bucket repository.
    ///
    /// The command walks DIR and sends the objects of its tree that the server
    /// does not have. The server then makes one commit over the tree, moves
    /// the branch of --onto to it, and creates each --tag at it, in one
    /// transaction. The parent of the commit is the commit of the branch on
    /// the server. The server writes the bindings of its namespace and signs
    /// the commit with the keys of the client group. The tree holds no
    /// extended attributes. The option names and the value forms are those
    /// of `commit`.
    ///
    /// The client group needs `c` on the branch. A server whose receive hooks
    /// take no server commit answers ref-denied. The push sends the server
    /// commit in one frame, which an ostrya server limits to 1 MiB. The reply
    /// names the branch and each --tag, and must also fit in one frame. In a
    /// commit, an --add-metadata value can hold two levels of containers
    /// fewer than a variant. The push checks the two frames and the depth of
    /// each value before it sends an object.
    ///
    /// The command makes its checks before the ssh client starts or the first
    /// HTTP request goes. It resolves REMOTE before it reads --body-file. A
    /// refusal of the remote thus reads no body file. For an `s3://` push
    /// address, the command makes the commit itself and writes the bucket
    /// repository.
    ///
    /// On success, standard output carries the commit checksum alone. Under
    /// --verbose, one statistics line goes to standard error. On a terminal,
    /// standard error shows the progress bar of `push` while the push runs. On
    /// failure, the command writes `error: MESSAGE` to standard error and
    /// nothing to standard output, and exits 1.
    #[cfg(feature = "push")]
    #[command(name = "push-tree")]
    PushTree(PushTreeArgs),
    /// Serve the repository over HTTP as an archive repository for pull.
    ///
    /// The repository can be in any mode that ostrya reads. In a mode other
    /// than `archive`, the server builds each `.filez` object on request and
    /// serves no file under `deltas/` and `delta-indexes/`. The
    /// server also answers the ref listing at `/_ostrya/refs/v1`, and has
    /// the receive endpoint of a push. The client groups of the repository
    /// config give the read rights and the push rights. The server
    /// identifies the client of each request by the auth items of the client
    /// groups: a bearer token, a Basic credential, a client certificate, the
    /// client address, or `anonymous`. A request that identifies no item gets
    /// 401 or 403 and no file. A push session takes the policy of the client
    /// group that carries the item in the namespace of its `Hello`: the local
    /// refs, or one collection. With no such group, or with a group that
    /// opens no push session, the session request gets 403.
    ///
    /// A ref under `refs/heads/` or `refs/mirrors/ID/` is served when the
    /// client group of the item has `r` on its name. An alias needs `r` on
    /// its name and on its target. The ref listing holds the local refs that
    /// the client reads, and with a `collection` pair in its query the
    /// collection refs that the client reads. A directory under
    /// `refs/mirrors/` whose name is not a collection id is not served and
    /// not listed. `refs/remotes/`, each other path
    /// under `refs/`, and `extensions/ostrya/` get 404. Objects, deltas,
    /// `config`, and the other files under `extensions/` are served to each
    /// identified client. A denied path gets the 404 of an absent path. With
    /// no client group, each client reads each local ref and each mirror
    /// ref.
    ///
    /// `summary` and `summary.sig` give the summary of the auth item of the
    /// client, which `ostrya summary -u` writes. The summary of an item and
    /// the ref listing state the mode `archive-z2`. In a mode other than
    /// `archive`, they name no static delta. An item with no summary gets
    /// 404. When the summary of the item does not match the client groups,
    /// the request gets 404, and the command writes one `error:` line that
    /// names the item and tells the operator to run `ostrya summary -u`, one
    /// time for each item in each run. The responses of `summary` and
    /// `summary.sig` carry `Cache-Control: private`. The server never serves
    /// the root `summary`, which holds each ref, so a `summary` that
    /// `ostree summary -u` or a mirror pull writes is not served. Also with no
    /// client group, the server serves the summary of the `anonymous` item,
    /// which `ostrya summary -u` writes.
    ///
    /// The server takes its settings from `[ex-ostrya server]` of the
    /// repository config. Each option of the command with the name of a key
    /// has precedence over the key. A relative path in a key is relative to
    /// the repository directory, and a relative path in an option is
    /// relative to the current directory. `sign-summary` has no option. At
    /// start, the command reads and checks the client groups, the server
    /// group, the trust groups, and the key groups. A bad group, or a key group whose key the command cannot
    /// read, ends the command with status 1.
    ///
    /// When all listeners are bound, the command writes the URL of each
    /// listener to standard output, one line each, and writes nothing else
    /// to standard output. Then it serves until the process ends. Warnings
    /// and errors go to standard error. For each push session that commits,
    /// the command writes one `warning: STEP: MESSAGE` line to standard error
    /// for each warning of the session. When a ref listing finds a directory
    /// under `refs/mirrors/` whose name is not a collection id, the command
    /// writes one `warning:` line that names it, one time in each run. With
    /// `[core] auto-update-summary=true`, each push that changes a ref writes
    /// the root summary and each summary of an item again, signed with the
    /// key groups of `sign-summary`.
    #[cfg(feature = "serve")]
    Serve(ServeArgs),
    /// Serve one pull session over standard input and standard output.
    ///
    /// An ssh pull runs this command on the remote side. The command answers
    /// each `Get` path as the archive view of `ostrya serve` answers a `GET` of
    /// that path. It takes no lock and writes no file in the repository.
    ///
    /// The client name is --client, else the value of `LOGNAME`, which sshd
    /// sets from the password entry of the user. With neither, and with a
    /// name that the item `ssh:NAME` refuses, the command writes an error line
    /// and exits 1 before it opens the repository. At start, the command
    /// reads and checks the client groups and the server group of the
    /// repository config. It reads no key group. A bad group ends it with
    /// status 1.
    ///
    /// The session serves the refs that the client group of the item
    /// `ssh:NAME` reads, as `ostrya serve` serves them to that item. When the
    /// repository has client groups and none carries the item, the command
    /// writes an error line and exits 1 before it reads standard input. The
    /// session uses no
    /// `anonymous` and no `net:` item. In a repository with no client group,
    /// the session takes the item `anonymous`, so it serves each local ref and
    /// each mirror ref. `summary` and `summary.sig` give the summary of the
    /// item, as `ostrya serve` gives it.
    ///
    /// Standard output carries the frames of the session alone. On failure,
    /// the command writes `error: MESSAGE` to standard error. When a ref
    /// listing finds a directory under `refs/mirrors/` whose name is not a
    /// collection id, the command writes one `warning:` line that names it
    /// to standard error, one time in each session. When the summary of the
    /// item does not match the client groups, the session answers `summary`
    /// and `summary.sig` as absent paths, and the command writes one `error:`
    /// line to standard error, one time in each session. It exits 0 when
    /// standard input ends at a frame boundary, and 1 after an `Error` frame
    /// or a failed write.
    ///
    /// An `authorized_keys` entry with `command="ostrya send --repo=PATH"`
    /// limits an ssh key to a pull from one repository.
    #[cfg(feature = "send")]
    Send(SendArgs),
}

impl Command {
    /// Every name that [`Command::name`] returns.
    ///
    /// The test `tests::every_subcommand_name_renders_its_usage_text`
    /// compares this list with the subcommand set of `clap`. If a subcommand
    /// is renamed or added, that test fails before the change can break the
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
        "composefs-image",
        #[cfg(feature = "receive")]
        "receive",
        #[cfg(feature = "push")]
        "push",
        #[cfg(feature = "push")]
        "push-tree",
        #[cfg(feature = "serve")]
        "serve",
        #[cfg(feature = "send")]
        "send",
    ];

    /// Returns the name of this subcommand in `clap`. The error paths use it
    /// to print the usage text of the subcommand.
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
            Command::ComposefsImage(_) => "composefs-image",
            #[cfg(feature = "receive")]
            Command::Receive(_) => "receive",
            #[cfg(feature = "push")]
            Command::Push(_) => "push",
            #[cfg(feature = "push")]
            Command::PushTree(_) => "push-tree",
            #[cfg(feature = "serve")]
            Command::Serve(_) => "serve",
            #[cfg(feature = "send")]
            Command::Send(_) => "send",
        }
    }
}

#[derive(Args)]
struct InitArgs {
    /// The storage mode of the new repository.
    ///
    /// The values are `archive`, `archive-z2`, `bare`, `bare-user`,
    /// `bare-user-only`, and `bare-user-shared`. `archive` is an alias for
    /// `archive-z2`, and the `config` file records `archive-z2`.
    /// `bare-user-shared` is an ostrya extension. The command refuses any
    /// other value and exits 1. A repository that exists keeps its mode.
    #[arg(long, default_value = "bare")]
    mode: String,
    /// A globally unique id for this repository as a collection of refs.
    ///
    /// The command writes the value to `[core] collection-id` in the `config`
    /// file. A repository that exists keeps its `config` file unchanged.
    /// `commit` records this id in the `ostree.collection-binding` metadata
    /// key of each commit, unless --no-bindings is given.
    #[arg(long = "collection-id")]
    collection_id: Option<String>,
}

#[derive(Args)]
struct CommitArgs {
    /// The parent commit (a checksum or a ref), or `none` for a root commit.
    ///
    /// Without this option, the parent is the branch name resolved as a
    /// revision, unless --orphan is given: the commit that a short lowercase
    /// hexadecimal name abbreviates, or else the current tip of the branch.
    /// The command refuses a name that abbreviates more than one commit. A
    /// branch that names no ref and abbreviates no commit gives a root
    /// commit. Only the lowercase `none` asks for a root commit, and each
    /// other value is a revision.
    #[arg(long)]
    parent: Option<String>,
    /// Point this branch at the new commit and bind it into the commit.
    ///
    /// The command needs --branch or --orphan. The branch name goes into the
    /// `ostree.ref-binding` metadata key, unless --no-bindings is given. The
    /// command refuses a name that the ref-name rule refuses, and a name of
    /// 64 lowercase hexadecimal characters. It checks the name after it reads
    /// the tree. A refused name gives no new object and no ref.
    #[arg(short, long)]
    branch: Option<String>,
    /// Take no implicit parent, and permit a commit that names no branch.
    ///
    /// The commit has no parent unless --parent names one. Without --branch,
    /// the command moves no branch, but it creates each --tag ref. Without
    /// --branch, --tag, and --bind-ref, the `ostree.ref-binding` key holds an
    /// empty list.
    #[arg(long)]
    orphan: bool,
    /// The commit subject.
    ///
    /// Without this option and without --editor, the subject is empty. With
    /// --editor, the value goes into the editor file, and the edit replaces
    /// it.
    #[arg(short, long)]
    subject: Option<String>,
    /// The commit body.
    ///
    /// If the option occurs more than once, the last value wins. --body-file
    /// wins over this option, and --editor replaces both. Without --body,
    /// --body-file, and --editor, the body is empty.
    #[arg(short = 'm', long, value_name = "BODY", overrides_with = "body")]
    body: Option<String>,
    /// Read the commit body from this file.
    ///
    /// This option wins over --body in either order. The full file becomes
    /// the body, byte for byte. The file must be valid UTF-8 with no NUL
    /// byte, and 128 MiB or less. If the option occurs more than once, the
    /// last value wins. --editor replaces the body.
    #[arg(short = 'F', long, value_name = "FILE", overrides_with = "body_file")]
    body_file: Option<PathBuf>,
    /// Write the subject and the body in an editor.
    ///
    /// The editor text replaces both. The command runs the first of
    /// `OSTREE_EDITOR`, `VISUAL`, and `EDITOR` that is set, else `vi`, through
    /// `/bin/sh -c`. The command ignores each line that starts with `#`. The
    /// first line that is not blank is the subject, and the lines after it
    /// are the body. An empty subject, or a non-zero exit of the editor,
    /// stops the commit. The command runs the editor before it reads the
    /// tree, and holds no repository lock during the edit.
    #[arg(short = 'e', long)]
    editor: bool,
    /// Do not write any ref bindings.
    ///
    /// The commit then has no `ostree.ref-binding` key and no
    /// `ostree.collection-binding` key.
    #[arg(long)]
    no_bindings: bool,
    /// Bind this ref name into the commit beside the branch.
    ///
    /// The option can occur more than once. The `ostree.ref-binding` key holds
    /// the --branch name, each --tag name, and each --bind-ref name, sorted
    /// byte by byte. The command moves no ref for a --bind-ref name.
    #[arg(long = "bind-ref", value_name = "BRANCH")]
    bind_ref: Vec<String>,
    /// Create the local ref NAME at the new commit, and bind NAME into it.
    ///
    /// The option can occur more than once. Each NAME goes into the
    /// `ostree.ref-binding` key, as a --bind-ref name does. After the command
    /// publishes the objects, it writes the --branch ref and then each ref
    /// NAME under `refs/heads`, one ref at a time. A name that is also a
    /// --bind-ref name occurs two times in the key.
    ///
    /// NAME passes the ref-name rule, has no `:`, and is not 64 lowercase
    /// hexadecimal characters. NAME is not the --branch name, and each NAME
    /// occurs one time. No name of --branch and --tag is a path below another
    /// of these names. The command refuses a NAME that has an entry under
    /// `refs/heads`: a ref, an alias, or a directory of refs. It also refuses
    /// a NAME below a ref. A refused NAME gives no new object and no ref. The
    /// command reads the path of each NAME again before it publishes the
    /// objects. If another writer creates a ref at the path after this read,
    /// the command replaces that ref. The option conflicts with --no-bindings
    /// and --skip-if-unchanged.
    #[arg(
        long = "tag",
        value_name = "NAME",
        conflicts_with_all = ["no_bindings", "skip_if_unchanged"]
    )]
    tags: Vec<String>,
    /// Name a dependency of the commit in field 2 of the commit object.
    ///
    /// The argument splits at its last `=`, so NAME can hold `=`. CHECKSUM
    /// is 64 lowercase hexadecimal characters. By convention, NAME has the
    /// form `<class>/<name>`, for example `container/fe`. The option can
    /// occur more than once. The commit holds the entries sorted by name in
    /// byte order.
    ///
    /// The command refuses an argument with no `=` and a CHECKSUM of another
    /// form before it takes the repository lock. It refuses an empty NAME, a
    /// NAME that occurs two times, and a dependency that the repository does
    /// not hold complete or that has a dependency of its own before it reads
    /// the tree. A refusal gives no new object and no ref. The option
    /// conflicts with --skip-if-unchanged. This option is an extension of
    /// ostrya.
    #[arg(
        long = "related",
        value_name = "NAME=CHECKSUM",
        conflicts_with = "skip_if_unchanged"
    )]
    related: Vec<String>,
    /// Add a string-valued key to the commit metadata.
    ///
    /// The argument splits at its first `=`, so the value can hold `=`. The
    /// option can occur more than once, and a repeated key stays as a
    /// separate entry. The command refuses an argument with no `=` and an
    /// empty key. The metadata holds these entries first, then the
    /// --add-metadata entries, then the --keep-metadata entries.
    #[arg(long, value_name = "KEY=VALUE")]
    add_metadata_string: Vec<String>,
    /// Add a key to the commit metadata, with a value in GVariant text form.
    ///
    /// The argument splits at its first `=`. The type of the value comes from
    /// the text. The command refuses an argument with no `=`, a value that
    /// does not parse, and an empty key. A repeated key stays as a separate
    /// entry.
    #[arg(long, value_name = "KEY=VALUE")]
    add_metadata: Vec<String>,
    /// Carry this metadata key over from the parent commit.
    ///
    /// The value keeps its bytes. The option needs a parent, from --parent or
    /// from the tip of --branch. The command refuses a key that the parent
    /// does not hold.
    #[arg(long, value_name = "KEY")]
    keep_metadata: Vec<String>,
    /// Add a string-valued key to the detached commit metadata.
    ///
    /// The argument splits at its first `=`. These entries replace all
    /// detached metadata of the commit, so a signature that an earlier run
    /// left on the same commit checksum goes. The signatures of this run come
    /// after these entries.
    #[arg(long, value_name = "KEY=VALUE")]
    add_detached_metadata_string: Vec<String>,
    /// Record owner 0:0, modes of `perm & 0755`, and no extended attributes.
    ///
    /// The commit then does not depend on the owner or on the host. A symlink
    /// keeps its mode. The mode reduction applies after --mode-ro-executables
    /// and --statoverride. The command refuses a non-zero --owner-uid or
    /// --owner-gid with this switch.
    #[arg(long)]
    canonical_permissions: bool,
    /// Set the user id of the owner of the committed files.
    ///
    /// The value is a C `int` in decimal, in hexadecimal with `0x`, or in
    /// octal with a leading `0`. A negative value keeps the owner of the
    /// source. The command refuses a value that does not parse before it
    /// opens the repository.
    #[arg(long, value_name = "UID", allow_hyphen_values = true)]
    owner_uid: Option<String>,
    /// Set the group id of the owner of the committed files.
    ///
    /// The value is a C `int` in decimal, in hexadecimal with `0x`, or in
    /// octal with a leading `0`. A negative value keeps the group of the
    /// source. The command refuses a value that does not parse before it
    /// opens the repository.
    #[arg(long, value_name = "GID", allow_hyphen_values = true)]
    owner_gid: Option<String>,
    /// Do not import extended attributes.
    #[arg(long)]
    no_xattrs: bool,
    /// Change the modes of the paths that this file lists.
    ///
    /// Each line is `[=]<decimal mode> <absolute in-tree path>`. All text
    /// after the first space is the path, and the command ignores blank
    /// lines. Without the `=` prefix, the command ORs the value into the mode.
    /// With the `=` prefix, the value replaces the permission bits. If both
    /// forms name a path, only the OR value applies. An OR entry for a
    /// directory below the root applies to a member of a tar archive alone.
    ///
    /// The file must be valid UTF-8, and the command refuses a line with no
    /// space. After the command reads the tree, it refuses an OR entry whose
    /// path the walk did not reach. It names each such path on standard
    /// error. If the option occurs more than once, the last value wins.
    #[arg(long, value_name = "PATH", overrides_with = "statoverride")]
    statoverride: Option<PathBuf>,
    /// A file with the paths to leave out, one absolute in-tree path per line.
    ///
    /// A listed directory prunes its whole subtree. The command ignores blank
    /// lines, and the file must be valid UTF-8. After the command reads the
    /// tree, it refuses a listed path that the walk did not reach. It names
    /// each such path on standard error. A line `/` prunes every source, so
    /// the commit holds the --base tree alone, and without --base the command
    /// refuses the empty tree. If the option occurs more than once, the last
    /// value wins.
    #[arg(long, value_name = "PATH", overrides_with = "skip_list")]
    skip_list: Option<PathBuf>,
    /// Clear the write bits of every regular file that has an execute bit.
    ///
    /// The switch applies before --statoverride, so a --statoverride entry
    /// sets the final mode of its path.
    #[arg(long)]
    mode_ro_executables: bool,
    /// Skip the commit and print the parent checksum if the tree is unchanged.
    ///
    /// The command compares the root contents and the root metadata of the
    /// tree with the parent commit. It does not compare the commit metadata,
    /// so a new subject alone does not give a new commit. If the tree
    /// matches, the command writes no commit and moves no ref. With no
    /// parent, the command writes the commit. With --table-output, the block
    /// shows the parent checksum and a zero for each count.
    #[arg(long)]
    skip_if_unchanged: bool,
    /// Find a source file by its inode among the stored content objects.
    ///
    /// If a source file is a hardlink to a loose content object of this
    /// repository, the command does not read the file. It applies the commit
    /// modifiers to the metadata of the stored object. If the result differs,
    /// it writes a new object from the stored content. An `archive`
    /// repository stores each content object compressed, so the switch has
    /// no effect there.
    #[arg(long)]
    link_checkout_speedup: bool,
    /// Use an inode match as the whole identity of a file.
    ///
    /// The commit modifiers then do not apply to that file, and the stored
    /// object goes into the commit as it is. This switch implies
    /// --link-checkout-speedup.
    #[arg(short = 'I', long)]
    devino_canonical: bool,
    /// Set the timestamp of the commit.
    ///
    /// The value is `@SECONDS` since the Unix epoch, or a date and time with a
    /// UTC offset, for example `2020-01-02T03:04:05Z`. The offset is `Z`,
    /// `+HH`, `+HH:MM`, or `+HHMM`, or one of these forms with `-`. The
    /// command drops a fractional second, and refuses a value that it cannot
    /// read. Without this option, the commit uses `SOURCE_DATE_EPOCH` if it is
    /// set, else the current time.
    #[arg(long, value_name = "TIMESTAMP")]
    timestamp: Option<String>,
    /// Set the fsync policy of this commit with a boolean word.
    ///
    /// The words are `true`, `yes`, `1`, `false`, `no`, and `0`, in any letter
    /// case. A false word turns off fsync for this commit. A true word keeps
    /// the `[core] fsync` value of the repository config, so the option never
    /// turns on fsync that the config turns off. The command refuses any
    /// other word before it opens the repository.
    #[arg(long, value_name = "POLICY", allow_hyphen_values = true)]
    fsync: Option<String>,
    /// Report the commit and the object counts in a `KEY: VALUE` block.
    ///
    /// Without this switch, the command prints the checksum alone. The block
    /// has seven lines in this order: `Commit`, `Metadata Total`,
    /// `Metadata Written`, `Content Total`, `Content Written`,
    /// `Content Cache Hits`, and `Content Bytes Written`. The last count is
    /// the content size of the regular files that the commit wrote, before
    /// compression.
    #[arg(long)]
    table_output: bool,
    /// Store the sizes of the objects of the commit in `ostree.sizes`.
    ///
    /// Only an `archive` repository writes this key. The key holds the
    /// objects that the last tree source adds, and the directory objects of
    /// the tree. A content object from an earlier source or from --base is
    /// not in the key.
    #[arg(long)]
    generate_sizes: bool,
    /// Store `ostree.linux` and `ostree.bootable` in the commit metadata.
    ///
    /// The command reads the kernel version from the committed tree. The
    /// version is the name of the one directory under `/usr/lib/modules` that
    /// holds a `vmlinuz` entry. The command refuses a tree with no such
    /// directory, or with more than one. `ostree.bootable` is `true`. The two
    /// keys come first in the metadata, and replace a value that another
    /// option gives for the same key.
    #[arg(long)]
    bootable: bool,
    /// Store the composefs image digest of the tree in the commit metadata.
    ///
    /// The key is `ostree.composefs.digest.v0`, and the value is the fs-verity
    /// digest of the image as a byte array. The value depends on the
    /// committed tree alone. `archive`, `bare`, and `bare-user` commit the
    /// same tree and give the same digest. `bare-user-only` canonicalizes the
    /// tree, so it can give another digest. It replaces a
    /// value that --add-metadata-string, --add-metadata, or --keep-metadata
    /// gives for the same key.
    #[arg(long)]
    generate_composefs_metadata: bool,
    /// Store the composefs image of the tree with the commit.
    ///
    /// The option turns on --generate-composefs-metadata. The image is the
    /// object `objects/<xx>/<commit>.cfs` of the repository, and its
    /// fs-verity digest is the value of `ostree.composefs.digest.v0`. The
    /// command reads the tree one time for the digest and the image. This
    /// option is an extension of ostrya.
    #[arg(long)]
    generate_composefs: bool,
    /// Add a tree source: a directory, a tar archive, or a committed tree.
    ///
    /// The option can occur more than once. `tar=-` and `tar=/dev/stdin` read
    /// standard input. The command overlays the sources in command-line
    /// order. A later source replaces the files of the same name and the
    /// directory metadata of an earlier source. The command refuses a name
    /// that is a directory in one source and a file in another. With this
    /// option, the command ignores PATH.
    #[arg(long, value_name = "dir=PATH or tar=TARFILE or ref=COMMIT")]
    tree: Vec<String>,
    /// Start from the given commit as a base.
    ///
    /// No modifiers apply to the base. The base is the bottom layer at any
    /// position on the command line, and the tree sources go on top of it. An
    /// entry that no source changes keeps the mode, the owner, and the
    /// extended attributes of the base. If the option occurs more than once,
    /// the last value wins.
    #[arg(long, value_name = "REV", overrides_with = "base")]
    base: Option<String>,
    /// Delete the files of each directory source while the command reads it.
    ///
    /// The command removes each source entry after it records the entry. It
    /// also removes the entries that --skip-list prunes. Then it removes the
    /// source directory, unless the path is exactly `.`. A `tar` or `ref`
    /// source ignores this switch. If a later step fails, the removed files
    /// stay removed.
    #[arg(long)]
    consume: bool,
    /// Create the missing parent directories of the members of a tar archive.
    #[arg(long)]
    tar_autocreate_parents: bool,
    /// Rename the members of a tar archive with REGEX,REPLACEMENT.
    ///
    /// The value splits at its first comma. REGEX is a PCRE2 expression with
    /// UTF and Unicode properties on. The command replaces each match in the
    /// path name of each member. In REPLACEMENT, `\0` to `\9`, `\g<name>`,
    /// and `\g<number>` insert the text of a group, and `\\` inserts a
    /// backslash. The command reads the value only when it reads a tar
    /// source. If the option occurs more than once, the last value wins.
    #[arg(
        long,
        value_name = "REGEX,REPLACEMENT",
        overrides_with = "tar_pathname_filter"
    )]
    tar_pathname_filter: Option<String>,
    /// The GPG key ID to sign the commit with.
    ///
    /// Each occurrence adds one signature under `ostree.gpgsigs` in the
    /// detached metadata, in command-line order. The key ID must name exactly
    /// one secret key, and the command refuses a key ID of less than 8 bytes.
    /// These signatures come after the --sign and --sign-from-file
    /// signatures. If a key cannot sign, the command writes no object and
    /// moves no ref.
    #[arg(long, value_name = "KEY-ID")]
    gpg_sign: Vec<String>,
    /// The GPG home directory that holds the keyrings.
    ///
    /// --gpg-sign reads it, and so do --sign and --sign-from-file under
    /// --sign-type=gpg. It wins over `GNUPGHOME`. Without this option, gpg
    /// uses its own home directory.
    #[arg(long, value_name = "HOMEDIR")]
    gpg_homedir: Option<PathBuf>,
    /// Sign the commit with this key.
    ///
    /// For `ed25519` and `spki`, the key is the base64 of the secret key. An
    /// `ed25519` secret key is 64 bytes: the 32-byte seed, then the 32-byte
    /// public key. An `spki` secret key is a PKCS#8 DER, a SEC1 DER that names
    /// the P-256 or the P-384 curve, or a PKCS#1 DER of an RSA key, and its
    /// base64 can hold line breaks. For `gpg`, the key is a key ID. Each
    /// occurrence adds one signature. --sign-type selects the engine. The
    /// command reads every key before it makes the first signature, so a bad
    /// key gives no signature. The order is the --sign keys, then the
    /// --sign-from-file keys, then the --gpg-sign keys.
    #[arg(long, value_name = "KEY_ID")]
    sign: Vec<String>,
    /// Sign the commit with the key of this file.
    ///
    /// Each occurrence adds one signature. For ed25519 and gpg, the key is on
    /// the first line of the file, and the command ignores the rest of the
    /// file. A NUL byte ends the line, and the command refuses a first line of
    /// more than 65536 bytes. For spki, the file holds one PEM `PRIVATE KEY`
    /// block, a PKCS#8 DER, and the command ignores the text outside the
    /// block. The command refuses an spki file of more than one block. The
    /// spki file is a regular file of at most 1 MiB. The command refuses an
    /// empty path with a message of its own.
    #[arg(long, value_name = "PATH")]
    sign_from_file: Vec<std::ffi::OsString>,
    /// The signature engine of --sign and --sign-from-file.
    ///
    /// The names are `ed25519`, `spki`, and `gpg`, and the default is
    /// `ed25519`. The match is case sensitive, and the command refuses any
    /// other name. The command reads this option only if --sign or
    /// --sign-from-file names a key. If the option occurs more than once, the
    /// last value wins.
    #[arg(long, value_name = "NAME", overrides_with = "sign_type")]
    sign_type: Option<String>,
    /// The directory to commit.
    ///
    /// If a --tree option is present, the command ignores this argument. It
    /// also ignores each argument after the first. With no --tree option and
    /// no PATH, the command reads a tar stream from standard input. The
    /// command refuses a symlink to a directory.
    path: Vec<PathBuf>,
}

#[derive(Args)]
struct CheckoutArgs {
    /// Refuse each entry that the checkout must copy.
    ///
    /// Without this switch, the checkout falls back to a copy. A regular file
    /// of non-zero length needs a copy in an `archive` repository, in a `bare`
    /// repository under -U, and in a `bare-user` repository without -U. A
    /// symlink is refused in an `archive` repository, and in a `bare`
    /// repository under -U. A directory and a zero-length file never need a
    /// copy. The checkout also refuses a destination directory on a different
    /// file system than the repository. The refusal comes at the entry, so the
    /// entries that the checkout wrote before it stay in the destination.
    #[arg(short = 'H', long)]
    require_hardlinks: bool,
    /// Copy every object, and make no hardlink.
    ///
    /// Outside an `archive` repository, a copy first tries a reflink of the
    /// loose object. If the reflink fails, the copy writes the bytes. This
    /// switch conflicts with -H/--require-hardlinks.
    #[arg(short = 'C', long, conflicts_with = "require_hardlinks")]
    force_copy: bool,
    /// Reduce every directory that the checkout creates to `mode & 0775`.
    ///
    /// A directory that the checkout reuses under a union option keeps its own
    /// mode. The switch has no effect on regular files and symlinks.
    #[arg(short = 'M', long)]
    bareuseronly_dirs: bool,
    /// Do not update or use the uncompressed object cache (no effect).
    ///
    /// ostrya keeps no such cache, so this switch has no effect on the
    /// destination.
    #[arg(long)]
    disable_cache: bool,
    /// Do not change file ownership or initialize extended attributes.
    ///
    /// A regular file that the checkout copies loses its setuid and setgid
    /// bits, and keeps its sticky bit. A hardlinked file keeps the mode of the
    /// object inode. A directory keeps all its mode bits. In a `bare-user`
    /// repository, this switch lets the checkout hardlink regular files. A
    /// `bare-user-only` repository always gets this checkout mode.
    #[arg(short = 'U', long)]
    user_mode: bool,
    /// Check out only this path of the commit.
    ///
    /// If PATH names a directory, the destination root gets the metadata of
    /// that directory. If PATH names a file or a symlink, the checkout creates
    /// the destination directory and puts the entry in it under its own name.
    /// If PATH names nothing and --allow-noent is not given, the command
    /// fails. With --from-stdin or --from-file, the command ignores this
    /// option, and each record gives the subpath. A composefs image always
    /// holds the full commit tree.
    #[arg(long, value_name = "PATH")]
    subpath: Option<PathBuf>,
    /// Keep existing directories, overwrite existing files, add new entries.
    ///
    /// An existing entry that the tree does not hold stays in place. An
    /// existing directory where the tree holds a file or a symlink is an
    /// error, and so is an existing regular file where the tree holds a
    /// directory. With --whiteouts, the checkout removes such an entry
    /// and writes the tree entry in its place. Without a union option, an
    /// existing entry at the path of a tree entry is an error. If the command
    /// line holds two union options, the command fails.
    #[arg(long)]
    union: bool,
    /// Keep every existing entry, and add only the entries that do not exist.
    #[arg(long)]
    union_add: bool,
    /// Add new entries, and keep an existing entry that matches the tree.
    ///
    /// An existing entry that does not match is an error. A regular file
    /// matches if it is the inode of the loose object. It also matches if it
    /// has the file object checksum and the permission bits of the object. A
    /// symlink matches if its target is the same. An existing directory stays
    /// with no comparison. This switch requires `-H/--require-hardlinks`.
    #[arg(long)]
    union_identical: bool,
    /// Process Docker-style whiteout entries.
    ///
    /// A `.wh.<name>` entry removes `<name>` from the destination, and a
    /// `.wh..wh..opq` entry clears the destination directory. The checkout
    /// writes neither marker. Only a regular-file entry acts as a marker. A
    /// marker named `.wh.` alone is an error. With --union, this switch also
    /// lets the checkout replace an existing entry of a different type.
    #[arg(long)]
    whiteouts: bool,
    /// Turn a `.ostree-wh.<name>` entry into an overlayfs whiteout.
    ///
    /// The whiteout is a character device 0:0 at `<name>`, with the permission
    /// bits of the marker. The checkout does not write the marker under its
    /// own name. A marker named `.ostree-wh.` alone is an error.
    #[arg(long)]
    process_passthrough_whiteouts: bool,
    /// If `--subpath` names nothing, write nothing and exit 0.
    ///
    /// With --from-stdin or --from-file, the switch applies to the subpath of
    /// each record, and the stream continues. A subpath through an entry that
    /// is not a directory is still an error.
    #[arg(long)]
    allow_noent: bool,
    /// Write the composefs EROFS image of the commit to the destination.
    ///
    /// The destination is the image file, and the checkout writes no tree.
    /// The image holds the fs-verity digest of each backed file, unless
    /// --composefs-noverity is given. The command writes a temporary file in
    /// the directory of the destination. Then it renames the file over the
    /// destination, at mode 0644. If the export fails, an existing destination
    /// stays as it was.
    ///
    /// `--subpath` has no effect on the image. With --from-stdin or
    /// --from-file, each record writes the image of its revision to the
    /// destination. The command refuses this switch together with --whiteouts,
    /// --process-passthrough-whiteouts, --skip-list, -H, -C, -M, or
    /// --disable-cache.
    #[arg(long)]
    composefs: bool,
    /// Write the composefs EROFS image with no fs-verity digest in it.
    ///
    /// The two composefs switches are independent, and this switch applies in
    /// any position. This switch also writes the image without --composefs.
    /// The other rules of --composefs apply.
    #[arg(long)]
    composefs_noverity: bool,
    /// Read NUL-separated (REFSPEC, SUBPATH) records from standard input.
    ///
    /// The command checks out each pair into the destination that the first
    /// positional names, and ignores the second positional and --subpath. An
    /// empty REFSPEC record ends the stream. A REFSPEC with no record after it
    /// names the whole tree. Each pair writes with the overwrite mode of the
    /// command line, so the pairs layer under --union. If a pair fails, the
    /// run stops, and the pairs before it stay written. The command refuses a
    /// stream larger than 128 MiB.
    #[arg(long)]
    from_stdin: bool,
    /// Read NUL-separated (REFSPEC, SUBPATH) records from FILE.
    ///
    /// The records have the format of --from-stdin. If the option occurs more
    /// than once, the last value wins. --from-stdin wins over this option in
    /// any command-line order. The command refuses a file larger than 128 MiB.
    #[arg(long, value_name = "FILE", overrides_with = "from_file")]
    from_file: Option<PathBuf>,
    /// Specify how to invoke fsync() with a boolean word.
    ///
    /// POLICY is `true`, `yes`, `1`, `false`, `no`, or `0`. The letter case
    /// does not matter. The policy starts from `[core] fsync` of the
    /// repository configuration, which is on if the key is absent. `false`
    /// turns fsync off. `true` keeps the configured policy, so a repository
    /// with `[core] fsync=false` syncs nothing. With fsync on, the checkout
    /// syncs each directory and each new regular file. The command reads
    /// POLICY before it opens the repository, and refuses any other word.
    #[arg(long, value_name = "POLICY", allow_hyphen_values = true)]
    fsync: Option<String>,
    /// Prune each tree path that FILE names, one path per line.
    ///
    /// Each path starts with `/` at the checkout root, which is the `--subpath`
    /// root if one is given. Write a directory with a trailing slash. A
    /// directory matches only in that form. The path `/` prunes the whole
    /// tree. Blank lines are ignored, and the command reports no path that
    /// matches nothing. If the option occurs more than once, the last value
    /// wins. The command refuses a file larger than 128 MiB, and a file that
    /// is not UTF-8 or holds a NUL byte.
    #[arg(long, value_name = "FILE", overrides_with = "skip_list")]
    skip_list: Option<PathBuf>,
    /// The commit to check out (a checksum or a ref).
    ///
    /// With --from-stdin or --from-file, this positional is the destination,
    /// and each revision comes from the record stream.
    commit: String,
    // The `ostree` command has this arity.
    /// The destination directory, or the image file with --composefs.
    ///
    /// The parent directory of the destination must exist. With --from-stdin
    /// or --from-file, the first positional is the destination, and the
    /// command ignores this one.
    #[arg(required_unless_present_any = ["from_stdin", "from_file"])]
    destination: Option<PathBuf>,
}

#[derive(Args)]
struct ExportArgs {
    /// Emit no extended attributes.
    #[arg(long)]
    no_xattrs: bool,
    /// Export only this directory of the commit, as the archive root.
    ///
    /// PATH must name a directory. A file, a symlink, or a path that names
    /// nothing is an error. If the option occurs more than once, the last
    /// value wins.
    #[arg(long, value_name = "PATH", overrides_with = "subpath")]
    subpath: Option<PathBuf>,
    /// Put PATH in front of every member pathname.
    ///
    /// The command adds no separator after PATH, so a PATH that acts as a
    /// directory must end in `/`. The name of the root member is PATH with a
    /// `/` added if PATH does not end in one. The target of a symlink gets no
    /// prefix. If the option occurs more than once, the last value wins.
    #[arg(long, value_name = "PATH", overrides_with = "prefix")]
    prefix: Option<String>,
    /// Write the archive to PATH, and not to standard output.
    ///
    /// The command opens PATH before it resolves the commit. An existing file
    /// is truncated in place, and keeps its inode and its mode. A new file
    /// gets mode 0666, reduced by the umask. If the export fails after the
    /// open, PATH stays truncated. If the option occurs more than once, the
    /// last value wins.
    #[arg(short = 'o', long, value_name = "PATH", overrides_with = "output")]
    output: Option<PathBuf>,
    // ostrya checks this operand after the repository resolves, in the order
    // of the `ostree` command.
    /// The commit to export (a checksum or a ref). Required.
    commit: Option<String>,
}

#[derive(Args)]
struct RefsArgs {
    /// Delete the refs that each PREFIX matches.
    ///
    /// The command then lists no ref. At least one PREFIX is required. A
    /// PREFIX that matches nothing is not an error. With -A, each PREFIX
    /// selects the aliases that a -A listing prints for it. With -c, each
    /// PREFIX is a collection id. If an alias names a local ref that a PREFIX
    /// matches, the command fails, and that PREFIX deletes nothing.
    #[arg(long)]
    delete: bool,
    /// Print the whole name of each ref, with the matched PREFIX in it.
    ///
    /// Without this switch, the command prints the part of the name below the
    /// PREFIX. A ref whose name is equal to the PREFIX prints its whole name.
    #[arg(long)]
    list: bool,
    /// Print the commit checksum of each ref after a tab.
    ///
    /// With -A, this switch adds nothing.
    #[arg(short = 'r', long)]
    revision: bool,
    /// List the aliases alone, each as `name -> target`.
    ///
    /// If a PREFIX names a ref, the command prints that ref with its commit
    /// checksum as the target. Each other PREFIX selects the aliases below it.
    /// With --create, the new ref is an alias. Its target must be a ref, and
    /// NEWREF must not name a remote ref. -c wins over this switch.
    #[arg(short = 'A', long)]
    alias: bool,
    /// Create the ref NEWREF, and point it at the commit that PREFIX names.
    ///
    /// The command line must give exactly one PREFIX argument, which is a
    /// revision here. If NEWREF exists and --force is not given, the command
    /// fails. With -A, NEWREF is an alias of the ref that PREFIX names. With
    /// -c, NEWREF is `<collection-id>:<ref>`, and the command writes a
    /// collection ref. This option wins over --delete.
    #[arg(long, value_name = "NEWREF")]
    create: Option<String>,
    /// List collection refs as `(collection-id, ref)` pairs.
    ///
    /// Each PREFIX is then a collection id. The local refs carry the
    /// collection id of the repository. With --delete and the collection id
    /// of the repository, the command deletes only the local refs. The mirror
    /// refs with that id stay. This switch wins over -A.
    #[arg(short = 'c', long)]
    collections: bool,
    /// With --create, replace an existing ref.
    #[arg(long)]
    force: bool,
    /// The ref-name prefixes to match, or the collection ids with -c.
    ///
    /// A PREFIX matches the ref with that name and each ref below it.
    /// `<remote>:` matches each ref of the remote. With no PREFIX, the command
    /// lists every ref. With --create, the one PREFIX is the revision that the
    /// new ref points at.
    prefix: Vec<String>,
}

#[derive(Args)]
struct RevParseArgs {
    /// Print the one commit of the repository.
    ///
    /// An empty repository is an error, and so is a repository with more than
    /// one commit. The command refuses a REV argument with this switch.
    #[arg(short = 'S', long)]
    single: bool,
    // ostrya checks this operand after the repository resolves, in the order
    // of the `ostree` command.
    /// The revisions to resolve. Required, unless --single is given.
    ///
    /// A revision is a full checksum, an abbreviated checksum of 1 to 63
    /// lowercase hex characters, or a refspec. An abbreviated checksum must
    /// match exactly one commit. Each trailing `^` steps back one generation
    /// of ancestry. The command prints one commit checksum for each revision,
    /// in order.
    rev: Vec<String>,
}

#[derive(Args)]
struct CatArgs {
    // ostrya checks this operand and PATH after the repository resolves, in
    // the order of the `ostree` command.
    /// The commit to read (a checksum or a ref).
    ///
    /// COMMIT and at least one PATH are required.
    commit: Option<String>,
    /// The paths to write, in order. A leading `/` is optional.
    ///
    /// Each PATH must name a regular file, or a symlink that leads to one. The
    /// command follows a symlink in the last component, up to 256 links. A
    /// symlink in another component is an error. A `.` or `..` component
    /// names nothing. The command stops at the first PATH that fails, and the
    /// content of the paths before it stays written.
    path: Vec<String>,
}

#[derive(Args, Default)]
struct ShowArgs {
    /// Show the "related" commits.
    ///
    /// The command prints one `<name> <checksum>` line for each dependency of
    /// the commit, the entries of field 2 of the commit object, in the stored
    /// order. An empty field prints nothing.
    #[arg(long)]
    print_related: bool,
    /// Read OBJECT as a file that holds a value of this GVariant type.
    ///
    /// The command prints the value in the GVariant text form, with the byte
    /// order of its numbers converted. -B has no effect here. The command
    /// refuses a file larger than 16 MiB.
    #[arg(long, value_name = "TYPE")]
    print_variant_type: Option<String>,
    /// List the metadata keys of the commit, one on each line, sorted.
    #[arg(long)]
    list_metadata_keys: bool,
    /// Print the value of one metadata key.
    ///
    /// The value prints in the GVariant text form. A key that the commit
    /// metadata does not hold is an error.
    #[arg(long, value_name = "KEY")]
    print_metadata_key: Option<String>,
    /// Print a byte-array key value as an unquoted hexadecimal string.
    ///
    /// This switch applies to --print-metadata-key and
    /// --print-detached-metadata-key. The hex digits are lowercase. A value of
    /// another type ignores the switch.
    #[arg(long)]
    print_hex: bool,
    /// List the detached metadata keys of the commit, one on each line, sorted.
    ///
    /// A commit with no detached metadata is an error.
    #[arg(long)]
    list_detached_metadata_keys: bool,
    /// Print the value of one detached metadata key.
    ///
    /// The value prints in the GVariant text form. A commit with no detached
    /// metadata is an error, and so is a key that it does not hold.
    #[arg(long, value_name = "KEY")]
    print_detached_metadata_key: Option<String>,
    /// Print the sizes that the `ostree.sizes` metadata of the commit records.
    ///
    /// The command prints the compressed size, the unpacked size, and the
    /// object count. Each is a needed/total pair. The needed values cover the
    /// objects that the local store does not hold. A commit with no
    /// `ostree.sizes` key is an error.
    #[arg(long)]
    print_sizes: bool,
    /// Show the raw variant data.
    ///
    /// The command prints the value of the object in the GVariant text form,
    /// after the type line. For a commit, the commit report does not follow.
    /// For a file object, this switch has no effect.
    #[arg(long)]
    raw: bool,
    /// Do not convert the variant data from big endian.
    ///
    /// The command prints the raw variant as stored. For a commit, the report
    /// of the commit follows it, also with --raw. The switch also applies to
    /// the values of --print-metadata-key and --print-detached-metadata-key.
    #[arg(short = 'B', long)]
    no_byteswap: bool,
    /// The GPG home directory that holds the keyrings.
    ///
    /// The command reads each `*.gpg` file in HOMEDIR as a keyring, together
    /// with the `gpgkeys.gpg` file of the repository. It uses these keyrings
    /// to verify the GPG signatures in the commit report. --gpg-verify-remote
    /// wins over this option.
    #[arg(long, value_name = "HOMEDIR")]
    gpg_homedir: Option<PathBuf>,
    /// Use the GPG configuration of this remote to verify signatures.
    ///
    /// The keyrings are `<remote>.trustedkeys.gpg` in the repository and in
    /// `/etc/ostree/remotes.d/`, and the global trusted keyrings. The global
    /// keyrings are the `*.gpg` files in the directory that `OSTREE_GPG_HOME`
    /// names, or in `/usr/share/ostree/trusted.gpg.d/`.
    #[arg(long, value_name = "REMOTE")]
    gpg_verify_remote: Option<String>,
    // ostrya checks this operand after the repository resolves, in the order
    // of the `ostree` command.
    /// The object to report: a revision or an object checksum. Required.
    ///
    /// A full checksum can name a metadata object or a file object. The
    /// command looks for a commit, a dirtree, a dirmeta, and a file object, in
    /// that order. With --print-variant-type, OBJECT is a file name.
    object: Option<String>,
}

#[derive(Args)]
struct LogArgs {
    /// Show the raw variant data.
    ///
    /// For each commit, the command prints the commit value in the GVariant
    /// text form, in place of the commit report.
    #[arg(long)]
    raw: bool,
    // ostrya checks this operand after the repository resolves, in the order
    // of the `ostree` command.
    /// The revision to start at. Required.
    rev: Option<String>,
}

#[derive(Args)]
struct LsArgs {
    /// Print the line of each directory argument alone, without its entries.
    ///
    /// This switch wins over -R.
    #[arg(short = 'd', long)]
    dironly: bool,
    /// Print directories recursively.
    ///
    /// The entries of each subdirectory follow its own line. Without this
    /// switch, the command prints one level of entries.
    #[arg(short = 'R', long)]
    recursive: bool,
    /// Print the checksum of each entry.
    ///
    /// A file shows its content checksum. A directory shows its dirtree
    /// checksum and then its dirmeta checksum.
    #[arg(short = 'C', long)]
    checksum: bool,
    /// Print the extended attributes of each entry.
    ///
    /// The set prints after the checksums, in the GVariant text form between
    /// `{ ` and ` }`.
    #[arg(short = 'X', long)]
    xattrs: bool,
    /// Print only the paths, NUL separated.
    ///
    /// Each path ends with a NUL byte, and the output has no newline. This
    /// switch wins over -C and -X.
    #[arg(long)]
    nul_filenames_only: bool,
    // ostrya checks this operand after the repository resolves, in the order
    // of the `ostree` command.
    /// The commit to list (a checksum or a ref). Required.
    commit: Option<String>,
    /// The paths in the commit to list, in order.
    ///
    /// With no PATH, the command lists the tree root. A leading `/` is
    /// optional. A PATH that names a file prints one line. A PATH that names
    /// nothing is an error.
    path: Vec<String>,
}

#[derive(Args)]
struct ConfigArgs {
    /// The group of KEY. With this option, KEY is a bare key name.
    ///
    /// The key name can then hold `.` characters.
    #[arg(long, value_name = "GROUP")]
    group: Option<String>,
    /// The operation: `get`, `set`, or `unset`.
    ///
    /// `get` prints the value. `set` writes the value, and creates the group
    /// if it does not exist. `unset` removes the key. If the key or its group
    /// does not exist, `unset` changes nothing and exits 0. `set` and `unset`
    /// write the whole `config` file of the repository again. This write
    /// drops the comment lines and the blank lines of the file.
    operation: Option<String>,
    /// The key to read or write, and for `set` the value.
    ///
    /// The key is `section.key`, split on the first `.`, or a bare key name
    /// with --group. The command refuses more operands than the operation
    /// takes.
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
    ///
    /// The command writes the `[remote "NAME"]` section of the `config` file
    /// of the repository, and prints nothing. It refuses a name that is not a
    /// valid remote name. If the remote exists, the command fails, unless
    /// --if-not-exists or --force is given.
    Add(RemoteAddArgs),
    /// Create a bucket repository in an S3 bucket.
    ///
    /// The command writes the `config` of a new bucket repository at the
    /// `s3://` address of NAME, or at the address `s3://BUCKET[/PREFIX]`. The
    /// `config` holds the group `[core]` with `repo_version=1` and
    /// `mode=archive-z2`, and `collection-id=ID` with --collection-id. A bucket
    /// repository with a collection id is the primary server of that
    /// collection, and a push of the refs of another collection writes them
    /// under `refs/mirrors/ID/`. With --zlib-level, the group `[archive]`
    /// with `zlib-level=LEVEL` follows. The command writes no ref and no
    /// summary, and prints nothing on success.
    ///
    /// The command takes the writer lock of the bucket repository, writes the
    /// `config` only if the bucket repository holds none, and removes the
    /// lock. It refuses a bucket repository that holds a `config`, so the
    /// collection id of a bucket repository never changes. A push needs the
    /// `config`. The command needs the S3 permissions `s3:GetObject`,
    /// `s3:PutObject`, `s3:ListBucket`, and `s3:DeleteObject`.
    ///
    /// With an address, the command needs no repository and reads no
    /// `--repo`, current directory, or `OSTREE_REPO`. With a remote name, it
    /// reads the remote from the config of the repository. With
    /// --break-lock, an init that removed the writer lock of another writer
    /// writes one `warning: removed the writer lock of HOLDER` line to
    /// standard error.
    #[cfg(feature = "s3")]
    Init(RemoteInitArgs),
    /// Check a bucket repository in an S3 bucket.
    ///
    /// The command reads the bucket repository at the `s3://` address of NAME,
    /// or at the address `s3://BUCKET[/PREFIX]`, and checks the `config`, the
    /// ref files, the summary, the keys under `objects/`, each commit, each
    /// object of the tree of each commit, and each composefs image of a
    /// commit. It reads each object that a commit reaches, so its cost is the
    /// download of these objects.
    ///
    /// Unless -q is given, the command first prints the counts: `Listed N
    /// objects`, `Checked C commits and O objects, B bytes`, and `N objects
    /// not reached by a commit`, then `N composefs images with no commit` and
    /// `N partial commits` when the count is not zero. It writes one line for
    /// each finding to standard error, sorted by key: `KIND KEY: DETAIL`, and
    /// `; in commits C1, C2` when the finding names commits. A note starts
    /// with `note: `. A report with an error ends with `error: Bucket
    /// repository corruption encountered` on standard error, and the command
    /// exits 1. Else the command prints `fsck of the bucket repository
    /// ADDRESS: no errors found`, and exits 0. A stale summary, an absent
    /// summary, a marker of a commit whose tree is whole, an incomplete
    /// multipart upload, and a writer lock are notes. A failed write to
    /// standard output gives an error line and exit 1.
    ///
    /// With a remote name, the command verifies the signature of the summary
    /// with the summary keys of the remote, as a pull with
    /// `gpg-verify-summary` or `sign-verify-summary` does. With an address,
    /// it verifies no signature.
    ///
    /// A run without --delete takes no lock, so a writer can change the
    /// bucket during the run. Before the command reports an object that the
    /// listing does not hold, it reads the object again: an object that is
    /// in the bucket now gives a note, and an object whose commits are all
    /// gone now gives no line.
    ///
    /// With --delete, the command takes the writer lock, writes the marker
    /// `state/<checksum>.commitpartial` for each commit that reaches a bad or
    /// a missing object of a tree, deletes the marker of each commit whose
    /// tree is whole, and deletes each bad object. It prints `Marking commit
    /// as partial: COMMIT` with the refs of the commit, `Deleted the
    /// partial-commit marker of commit COMMIT`, `Deleted KEY` for each
    /// deleted object, and `Deleted the commit object of a ref: COMMIT` with
    /// the refs of each deleted commit that a ref names. A push of a ref
    /// whose commit has a marker uploads the missing objects of its tree,
    /// and removes the marker. The command refuses --delete for a bucket
    /// repository with no valid `config`, and then changes nothing.
    ///
    /// If the repair fails after its first change, the command prints the
    /// report with the changes that completed, then an error line that
    /// states that the repair is incomplete, and exits 1. Run the command
    /// with --delete again before a push: until then, a marker can be in the
    /// bucket while the bad objects of its commit stay, and a push of the
    /// commit then uploads no object for them and removes the marker.
    ///
    /// The command needs the S3 permissions `s3:GetObject`, `s3:ListBucket`,
    /// and `s3:ListBucketMultipartUploads`. With --delete, it also needs
    /// `s3:PutObject` and `s3:DeleteObject`.
    ///
    /// With an address, the command needs no repository and reads no
    /// `--repo`, current directory, or `OSTREE_REPO`. With a remote name, it
    /// reads the remote from the config of the repository.
    #[cfg(feature = "s3")]
    Fsck(RemoteFsckArgs),
    /// Delete the unreachable objects of a bucket repository in an S3 bucket.
    ///
    /// The command prunes the bucket repository at the `s3://` address of
    /// NAME, or at the address `s3://BUCKET[/PREFIX]`, as `ostrya prune`
    /// prunes a local repository with the same options. The commit of each
    /// ref is a root. Without --refs-only and --keep-younger-than, each
    /// commit of the bucket is a root too. The commits that the summary names
    /// are roots, and the command keeps them with no parent. A kept commit
    /// keeps its detached metadata and its composefs image.
    ///
    /// The dependencies in field 2 of each commit that the walk reaches are
    /// also roots, as in `ostrya prune`. With --refs-only or
    /// --keep-younger-than, a dependency gets the bound of --depth or
    /// --keep-younger-than, also a dependency of a commit that the summary
    /// names. Without them, each commit of the bucket is a root
    /// that keeps no parent, and a dependency keeps no parent too. The
    /// command reads field 2 from the commit object, with no other request.
    /// An entry that names a commit that is not in the bucket gives no error,
    /// and the command keeps the detached metadata and the composefs image of
    /// that commit if they are in the bucket. For each defective field 2
    /// entry, the command writes one
    /// `warning: related commits in field 2 of commit CHECKSUM: REASON` line
    /// to standard error before the lines on standard output, and the
    /// defective entry roots nothing.
    ///
    /// The command reads no detached metadata, so it reads no build source in
    /// the detached metadata key `ostrya.related`. It deletes a build source
    /// that no root reaches, which `ostrya prune` keeps. Without --refs-only
    /// and --keep-younger-than, the command also deletes the detached
    /// metadata and the composefs image of a parent commit that the bucket
    /// does not hold, which `ostrya prune` can keep.
    ///
    /// The command deletes each object that no root reaches, then each
    /// static delta and each `state/<commit>.commitpartial` marker whose
    /// commit is not in the bucket after the run, and aborts each incomplete
    /// multipart upload. It deletes the commit objects first, so a run that
    /// stops leaves a bucket repository that a reader can use, and the next
    /// run deletes the rest. It deletes no ref, no `.tombstone-commit`, and
    /// no key under `delta-indexes/`.
    ///
    /// The command reads each commit and dirtree that the walk reaches with
    /// one GET, and checks its checksum. It reads the commits one at a time,
    /// and at most 8 dirtrees of the tree of one commit at a time. A commit
    /// or a dirtree whose bytes do not match its name stops the command
    /// before its first delete. Run `ostrya remote fsck --delete` to repair
    /// such an object.
    ///
    /// The command writes no summary, and keeps each commit that the summary
    /// names. A summary that names a deleted static delta stays as it is
    /// until `ostrya remote summary -u` writes the summary again.
    ///
    /// The command prints the lines of `ostrya prune`: `Total objects: N`,
    /// then `Deleted N objects, SIZE freed`, or with --no-prune `Would
    /// delete: N objects, freeing SIZE`, or `No unreachable objects`. The
    /// counts leave out the detached metadata, the composefs images, and the
    /// static deltas. Then, for each count that is not zero, it prints
    /// `Deleted N static deltas`, `Deleted N partial-commit markers`, and
    /// `Aborted N incomplete multipart uploads`, or with --no-prune `Would
    /// delete N static deltas`, `Would delete N partial-commit markers`, and
    /// `Would abort N incomplete multipart uploads`.
    ///
    /// The command takes the writer lock of the bucket repository, also with
    /// --no-prune, and removes it at the end. It needs the S3 permissions of
    /// a push, `s3:GetObject`, `s3:PutObject`, `s3:ListBucket`,
    /// `s3:DeleteObject`, and `s3:AbortMultipartUpload`, and also
    /// `s3:ListBucketMultipartUploads`. It refuses a bucket repository whose
    /// `config` sets `[core] tombstone-commits` to true.
    ///
    /// With an address, the command needs no repository and reads no
    /// `--repo`, current directory, or `OSTREE_REPO`. With a remote name, it
    /// reads the remote from the config of the repository. With
    /// --break-lock, a prune that removed the writer lock of another writer
    /// writes one `warning: removed the writer lock of HOLDER` line to
    /// standard error, after the other lines.
    #[cfg(feature = "s3")]
    Prune(RemotePruneArgs),
    /// Delete a remote repository and its trusted GPG keyring.
    ///
    /// The command removes the keyring `NAME.trustedkeys.gpg` at the root of
    /// the repository, and then the `[remote "NAME"]` section of `config`. It
    /// prints nothing. If the remote does not exist, the command fails, unless
    /// --if-exists is given.
    Delete(RemoteDeleteArgs),
    /// List the configured remote names, sorted.
    ///
    /// The command prints one name on each line. With -u, the URL of each
    /// remote follows its name.
    List(RemoteListArgs),
    /// Print the URL of a remote.
    ///
    /// The command prints the value of the `url` key of the remote. It fails
    /// if the remote does not exist, or if the remote has no `url` key. A
    /// remote that a metalink describes has no `url` key.
    #[command(name = "show-url")]
    ShowUrl(RemoteNameArgs),
    /// List the refs that a remote publishes in its summary.
    ///
    /// The command fetches the summary of the remote over HTTP or ssh, as a
    /// pull does. From an `s3://` address in `pull-url`, it reads the summary
    /// of the bucket repository with signed requests. It prints one
    /// `NAME:REF` line for each ref, in the order of the summary. It does not
    /// verify the signature of the summary. If the remote has no summary
    /// file, the command fails. A push to a bucket repository writes no
    /// summary, and `ostrya remote summary -u` writes it.
    Refs(RemoteRefsArgs),
    /// Report the summary of a remote, or write the summary of a bucket
    /// repository.
    ///
    /// The command fetches the summary of the remote over HTTP or ssh, as a
    /// pull does. From an `s3://` address in `pull-url`, it reads the summary
    /// of the bucket repository with signed requests. It does not verify the
    /// signature of the summary. If the remote has no summary file, the
    /// command fails. A push to a bucket repository writes no summary, and
    /// -u writes it.
    ///
    /// The default report gives each ref with its commit size, its commit
    /// checksum, and its metadata. The global metadata of the summary follows
    /// the refs. The report shows each timestamp in UTC.
    ///
    /// With -u, the command writes the summary of the bucket repository at
    /// the `s3://` address of NAME, or at the address `s3://BUCKET[/PREFIX]`,
    /// and prints nothing. This is an ostrya extension, and a build without
    /// the feature `s3` does not have it. The summary lists each ref of
    /// `refs/heads/`, and the refs of each `refs/mirrors/ID/` in its
    /// collection map. It names each static delta with a superblock. Its bytes
    /// are the bytes of the root summary that `ostrya summary -u` writes for a
    /// local repository with the same refs, commits, deltas, and config, when
    /// that command writes no `ostree-metadata` anchor commit. The command
    /// reads the commit of each ref from the bucket, and checks its checksum.
    /// It refuses a ref whose commit the bucket does not hold, a key under
    /// `refs/` outside `refs/heads/` and `refs/mirrors/ID/`, and a ref name
    /// that is a directory of another ref name, as `a` is of `a/b`.
    ///
    /// Each --gpg-sign key, each --sign key, and each --keys-file key signs
    /// the summary, in this order. The command writes `summary`, and then
    /// `summary.sig` when it has a key. Between the two writes, a pull that
    /// verifies the summary refuses it. If the write of `summary.sig` fails
    /// after the write of `summary`, the command fails with an error that
    /// states that the two keys can fail to match, and a run again with the
    /// same keys writes a matching pair. The command never deletes
    /// `summary.sig`, so a bucket repository that holds one refuses an update
    /// with no signing key.
    ///
    /// The command takes the writer lock of the bucket repository, and
    /// removes it at the end. It needs the S3 permissions `s3:GetObject`,
    /// `s3:PutObject`, `s3:ListBucket`, and `s3:DeleteObject`. With an
    /// address, it needs no repository and reads no `--repo`, current
    /// directory, or `OSTREE_REPO`. With a remote name, it reads the remote
    /// from the config of the repository. With --break-lock, an update that
    /// removed the writer lock of another writer writes one `warning: removed
    /// the writer lock of HOLDER` line to standard error.
    Summary(RemoteSummaryArgs),
    /// Import GPG keys into the trusted keyring of a remote.
    ///
    /// The keyring is the file `NAME.trustedkeys.gpg` at the root of the
    /// repository. The keys come from the --keyring files or from standard
    /// input. A key source is a binary or an ASCII-armored public keyring. The
    /// command prints the number of keys that the keyring did not hold before.
    ///
    /// A key that the keyring holds stays as it is. The command replaces it
    /// only for a key revocation that it can verify, or for a later expiry
    /// time of the key.
    #[command(name = "gpg-import")]
    GpgImport(RemoteGpgImportArgs),
    /// List the GPG keys in the trusted keyring of a remote.
    ///
    /// The command reads the file `NAME.trustedkeys.gpg` at the root of the
    /// repository. For each key, it prints a `Key:` line with the fingerprint,
    /// a `Created:` line with the creation time in UTC, and one `UID:` line for
    /// each user id. If the keyring does not exist, the command prints nothing.
    #[command(name = "gpg-list-keys")]
    GpgListKeys(RemoteNameArgs),
}

impl RemoteCommand {
    /// Returns the name of this nested subcommand in `clap`. The error paths
    /// use it to print the usage text of the subcommand.
    fn name(&self) -> &'static str {
        match self {
            RemoteCommand::Add(_) => "add",
            #[cfg(feature = "s3")]
            RemoteCommand::Init(_) => "init",
            #[cfg(feature = "s3")]
            RemoteCommand::Fsck(_) => "fsck",
            #[cfg(feature = "s3")]
            RemoteCommand::Prune(_) => "prune",
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
    /// Set this configuration key in the section of the remote.
    ///
    /// The option can occur more than once. The command writes the pairs in
    /// the order of the command line. They come after the URL, the branches,
    /// --contenturl, and --custom-backend, and before the keys of
    /// --no-gpg-verify, --no-sign-verify, --sign-verify, and --collection-id.
    /// A later write of a key replaces the earlier value. The command refuses
    /// a value with no `=`.
    #[arg(long = "set", value_name = "KEY=VALUE")]
    set: Vec<String>,
    /// Do not require a GPG signature on the commits pulled from this remote.
    ///
    /// The command writes `gpg-verify=false`. Without this option, a pull from
    /// the remote verifies the GPG signature of each commit.
    #[arg(long)]
    no_gpg_verify: bool,
    // The `ostree` command writes both keys for this switch.
    /// Do not require an ed25519, spki, or GPG signature on pulled commits.
    ///
    /// The command writes `gpg-verify=false` and `sign-verify=false`. This
    /// option conflicts with --sign-verify.
    #[arg(long)]
    no_sign_verify: bool,
    /// Trust this public key for the ed25519 or the spki engine.
    ///
    /// The value is KEYTYPE=inline:PUBKEY or KEYTYPE=file:PATH. KEYTYPE is
    /// `ed25519`, or `spki` in a build with the `spki` feature. The command
    /// writes the key `verification-KEYTYPE-key` for an inline key, or
    /// `verification-KEYTYPE-file` for a file. It then writes `sign-verify`
    /// with the engine of each --sign-verify, separated by commas. The option
    /// can occur more than once, and it conflicts with --no-sign-verify. An
    /// spki PUBKEY is the base64 of a SubjectPublicKeyInfo DER.
    #[arg(long, value_name = "KEYTYPE=[inline|file]:PUBKEY")]
    sign_verify: Vec<String>,
    /// If the remote exists, do nothing.
    ///
    /// The command then also imports no keys for --gpg-import, and it exits
    /// 0. This option conflicts with --force.
    #[arg(long)]
    if_not_exists: bool,
    /// If the remote exists, replace its section.
    ///
    /// The command removes the full section and writes a new one. This option
    /// conflicts with --if-not-exists.
    #[arg(long)]
    force: bool,
    /// Import the keys of this keyring file into the trusted keyring.
    ///
    /// The import is the same as `remote gpg-import` with --keyring. The
    /// command imports the keys only after it writes the section of the
    /// remote, and then prints the number of imported keys.
    #[arg(long, value_name = "FILE")]
    gpg_import: Option<PathBuf>,
    /// Name a program other than ostrya that fetches this remote.
    ///
    /// The command writes NAME to the `custom-backend` key. ostrya does not
    /// read this key.
    #[arg(long, value_name = "NAME")]
    custom_backend: Option<String>,
    /// Write this URL to the `contenturl` key of the remote.
    ///
    /// The key names a different URL for the content objects. The pull of
    /// ostrya does not read this key. It fetches all objects from the
    /// `pull-url` or the `url` of the remote.
    #[arg(long, value_name = "URL")]
    contenturl: Option<String>,
    /// A globally unique id for the remote as a collection of refs.
    ///
    /// The command writes the value to the `collection-id` key of the remote.
    #[arg(long, value_name = "COLLECTION-ID")]
    collection_id: Option<String>,
    // ostrya checks this operand and URL after the repository resolves, in
    // the order of the `ostree` command.
    /// The remote name. Required, with the URL.
    ///
    /// A name has one or more characters. Each character is a letter, a digit,
    /// `-`, `_`, or `.`. The first character is a letter, a digit, or `_`.
    name: Option<String>,
    /// The base URL of the remote, or `metalink=URL` for a metalink remote.
    ///
    /// The command writes a base URL to the `url` key. For `metalink=URL`, it
    /// writes URL to the `metalink` key and writes no `url` key. The pull of
    /// ostrya does not read the `metalink` key.
    ///
    /// The command writes an `s3://BUCKET[/PREFIX]` address to the
    /// `pull-url` and `push-url` keys, after the branches, and writes no
    /// `url` key. It does not check the address. A pull or a push refuses a
    /// bad address when it uses the remote. --set writes the S3 keys
    /// `s3-region`, `s3-endpoint`, `s3-addressing`, and `s3-profile`.
    /// `show-url` and `list -u` refuse a remote with no `url` key.
    url: Option<String>,
    /// The refs that a pull of this remote takes if the pull names no ref.
    ///
    /// The command writes them to the `branches` key.
    branches: Vec<String>,
}

#[cfg(feature = "s3")]
#[derive(Args)]
struct RemoteInitArgs {
    /// Write `collection-id=ID` into the `config` of the bucket repository.
    ///
    /// The command refuses an ID that fails the collection-id rule or is
    /// longer than 255 bytes, before any request.
    #[arg(long, value_name = "ID")]
    collection_id: Option<String>,
    /// Write `[archive] zlib-level=LEVEL`, 1 to 9, into the `config` of the
    /// bucket repository.
    ///
    /// A push builds each `.filez` that it uploads at this level. Without
    /// this option, the `config` has no `[archive]` group, and a push takes
    /// the level 6. The command refuses a value outside 1 to 9 before any
    /// request.
    #[arg(
        long,
        value_name = "LEVEL",
        value_parser = clap::value_parser!(u8).range(1..=9)
    )]
    zlib_level: Option<u8>,
    /// Remove the writer lock of another writer of the bucket repository.
    ///
    /// The command reads the lock, deletes it, and then takes its own lock.
    /// It writes the holder of the removed lock to standard error after an
    /// init that succeeds. Use it only when the holder is gone, for example
    /// after a crash.
    #[arg(long)]
    break_lock: bool,
    #[command(flatten)]
    s3: S3AccessArgs,
    // ostrya checks this operand after the repository resolves, unless it is
    // an address.
    /// The remote name or the address `s3://BUCKET[/PREFIX]`. Required.
    ///
    /// The address of a remote is its `push-url` key if that key holds an
    /// `s3://` address, else its `pull-url` key if that key holds an `s3://`
    /// address. The command refuses a remote with neither, and never reads the
    /// `url` key.
    name: Option<String>,
}

#[cfg(feature = "s3")]
#[derive(Args)]
struct RemoteFsckArgs {
    /// Repair the bucket repository.
    ///
    /// The command takes the writer lock, writes a partial-commit marker for
    /// each commit that reaches a bad or a missing object of a tree, deletes
    /// the marker of each commit whose tree is whole, and then deletes each
    /// object whose bytes do not match its name or do not parse. It deletes
    /// no commit because of a bad object of its tree.
    #[arg(long)]
    delete: bool,
    /// Remove the writer lock of another writer of the bucket repository.
    ///
    /// The command reads the lock, deletes it, and then takes its own lock.
    /// It writes the holder of the removed lock to standard error after the
    /// report of the run. Use it only when the holder is gone, for example
    /// after a crash.
    #[arg(long, requires = "delete")]
    break_lock: bool,
    /// Do not print the counts.
    ///
    /// The command still prints the findings, the actions of --delete, and
    /// the final result line.
    #[arg(short, long)]
    quiet: bool,
    #[command(flatten)]
    s3: S3AccessArgs,
    // ostrya checks this operand after the repository resolves, unless it is
    // an address.
    /// The remote name or the address `s3://BUCKET[/PREFIX]`. Required.
    ///
    /// The address of a remote is its `push-url` key if that key holds an
    /// `s3://` address, else its `pull-url` key if that key holds an `s3://`
    /// address. The command refuses a remote with neither, and never reads the
    /// `url` key.
    name: Option<String>,
}

#[derive(Args)]
struct RemoteDeleteArgs {
    /// If the remote does not exist, do nothing.
    #[arg(long)]
    if_exists: bool,
    // ostrya checks this operand after the repository resolves.
    /// The remote to delete. Required.
    ///
    /// The command refuses a name that `remote add` refuses.
    name: Option<String>,
}

#[derive(Args)]
struct RemoteListArgs {
    /// Print the URL of each remote after its name.
    ///
    /// The command pads each name with spaces to the length of the longest
    /// name plus two, so the URLs align. A remote with no `url` key stops the
    /// listing with an error. The names before it stay printed.
    #[arg(short = 'u', long)]
    show_urls: bool,
}

#[derive(Args)]
struct RemoteNameArgs {
    // ostrya checks this operand after the repository resolves.
    /// The remote to report. Required.
    name: Option<String>,
}

#[derive(Args)]
struct RemoteRefsArgs {
    /// Print the commit checksum of each ref after a tab.
    #[arg(short = 'r', long)]
    revision: bool,
    #[cfg(feature = "s3")]
    #[command(flatten)]
    s3: S3AccessArgs,
    // ostrya checks this operand after the repository resolves.
    /// The remote to list. Required.
    name: Option<String>,
}

#[derive(Args)]
struct RemoteSummaryArgs {
    /// List the available metadata keys.
    ///
    /// The command prints the keys of the global metadata of the summary,
    /// sorted, one key on each line. --raw takes precedence over this option.
    #[arg(long)]
    list_metadata_keys: bool,
    /// Print the value of one metadata key.
    ///
    /// The command prints the value in the GVariant text form, with its type.
    /// If the global metadata has no such key, the command fails. --raw and
    /// --list-metadata-keys take precedence over this option.
    #[arg(long, value_name = "KEY")]
    print_metadata_key: Option<String>,
    /// Show the raw variant data.
    ///
    /// The command prints the full summary in the GVariant text form, with the
    /// big-endian fields converted.
    #[arg(long)]
    raw: bool,
    /// Write the summary of the bucket repository of NAME, or at the address
    /// NAME.
    ///
    /// This is an ostrya extension. The option conflicts with --raw,
    /// --list-metadata-keys, and --print-metadata-key. The command prints
    /// nothing.
    #[cfg(feature = "s3")]
    #[arg(
        short = 'u',
        long,
        conflicts_with_all = ["raw", "list_metadata_keys", "print_metadata_key"]
    )]
    update: bool,
    /// With -u, sign the summary with the GPG key that this selector names.
    ///
    /// The option uses the gpg engine for each --sign-type. Each occurrence
    /// adds one signature. The option needs -u.
    #[cfg(feature = "s3")]
    #[arg(long, value_name = "KEY-ID", requires = "update")]
    gpg_sign: Vec<String>,
    /// With -u, the GnuPG home directory where gpg resolves signing keys.
    ///
    /// Only the gpg engine reads it: for --gpg-sign, and for --sign under the
    /// gpg engine. The option needs -u.
    #[cfg(feature = "s3")]
    #[arg(long, value_name = "DIR", requires = "update")]
    gpg_homedir: Option<PathBuf>,
    /// With -u, sign the summary with this key.
    ///
    /// The --sign-type option selects the engine. For ed25519 and spki, the key
    /// is the base64 of the secret key. An spki secret key is a PKCS#8 DER, a
    /// SEC1 DER that names the P-256 or the P-384 curve, or a PKCS#1 DER of an
    /// RSA key, and its base64 can hold line breaks. For gpg, the key is a
    /// selector, as for --gpg-sign. Each
    /// occurrence adds one signature. The option needs -u.
    #[cfg(feature = "s3")]
    #[arg(long, value_name = "KEY-ID", requires = "update")]
    sign: Vec<String>,
    /// With -u, the signature engine for --sign and --keys-file.
    ///
    /// The names are `ed25519`, `spki`, and `gpg`, and the command refuses any
    /// other name. The default is `ed25519`. If the option occurs more than
    /// once, the last value wins. The option needs -u.
    #[cfg(feature = "s3")]
    #[arg(
        short = 's',
        long = "sign-type",
        value_name = "NAME",
        overrides_with = "sign_type",
        requires = "update"
    )]
    sign_type: Option<String>,
    /// With -u, sign the summary with the keys of this file, in the format of
    /// `ostrya sign`.
    ///
    /// For ed25519, the file has base64 secret keys, one per line. For spki,
    /// the file holds PEM `PRIVATE KEY` blocks, each a PKCS#8 DER of a P-256, a
    /// P-384, an Ed25519, or an RSA key. The command
    /// reads every file, and each key adds one signature after each --sign
    /// key. The gpg engine refuses this option. The option needs -u.
    #[cfg(feature = "s3")]
    #[arg(long, value_name = "PATH", requires = "update")]
    keys_file: Vec<std::ffi::OsString>,
    /// With -u, remove the writer lock of another writer of the bucket
    /// repository.
    ///
    /// The command reads the lock, deletes it, and then takes its own lock.
    /// It writes the holder of the removed lock to standard error after an
    /// update that succeeds. Use it only when the holder is gone, for example
    /// after a crash. The option needs -u.
    #[cfg(feature = "s3")]
    #[arg(long, requires = "update")]
    break_lock: bool,
    /// With -u, set `ostree.summary.last-modified`, in seconds since the Unix
    /// epoch.
    ///
    /// A fixed value makes the output reproducible. Without this option, the
    /// command uses the current time. `SOURCE_DATE_EPOCH` does not change this
    /// value. The option needs -u.
    #[cfg(feature = "s3")]
    #[arg(long, value_name = "SECONDS", requires = "update")]
    last_modified: Option<u64>,
    #[cfg(feature = "s3")]
    #[command(flatten)]
    s3: S3AccessArgs,
    // ostrya checks this operand after the repository resolves, unless -u is
    // given and the operand is an address.
    /// The remote to report. Required.
    ///
    /// With -u, the remote name or the address `s3://BUCKET[/PREFIX]`. The
    /// address of a remote is then its `push-url` key if that key holds an
    /// `s3://` address, else its `pull-url` key if that key holds an `s3://`
    /// address. The command refuses a remote with neither, and never reads
    /// the `url` key.
    name: Option<String>,
}

#[derive(Args)]
struct RemoteGpgImportArgs {
    /// Import the keys of this keyring file.
    ///
    /// The file is a binary or an ASCII-armored public keyring. The option can
    /// occur more than once, and it conflicts with --stdin.
    #[arg(short = 'k', long = "keyring", value_name = "FILE")]
    keyring: Vec<PathBuf>,
    /// Import the keys from standard input.
    ///
    /// This option conflicts with --keyring.
    #[arg(long)]
    stdin: bool,
    // ostrya checks this operand after the repository resolves.
    /// The remote to import into. Required.
    name: Option<String>,
    /// The keys to import, by fingerprint, key id, or user id.
    ///
    /// With no KEY_IDS, the command imports each key of the source. The
    /// command reads a key name as `gpg --export` reads it. A run of 8 or 16
    /// hex digits is a key id, and a run of 32, 40, or 64 hex digits is a
    /// fingerprint. Each other value matches a part of a user id, and the
    /// match ignores the case of ASCII letters. If a value names no key of the
    /// source, the command fails.
    key_ids: Vec<String>,
}

#[cfg(feature = "s3")]
#[derive(Args)]
struct RemotePruneArgs {
    /// Delete each commit and object that no ref reaches.
    ///
    /// Without this option, each commit of the bucket is a root of the walk.
    /// A commit that no ref names then stays, with the objects that it
    /// reaches.
    #[arg(long)]
    refs_only: bool,
    /// The number of parents of each ref to keep.
    ///
    /// The value -1 keeps all history. The value 0 keeps only the commit that
    /// the ref names, and so does each negative value other than -1. The bound
    /// deletes commits only if the walk starts from the refs alone: with
    /// --refs-only or --keep-younger-than.
    #[arg(long, default_value_t = -1, allow_negative_numbers = true, overrides_with = "depth")]
    depth: i32,
    /// Delete the history of each ref that is older than DATE.
    ///
    /// DATE is `@SECONDS` since the Unix epoch, or a date and time with a UTC
    /// offset, for example `2024-05-01T12:00:00Z` or `2024-05-01 12:00+02:00`.
    /// The command refuses each other form before any request. The commit
    /// that a ref names stays at all ages. The walk starts from the refs
    /// alone, as with --refs-only. This bound replaces --depth.
    #[arg(long, value_name = "DATE", overrides_with = "keep_younger_than")]
    keep_younger_than: Option<String>,
    /// Compute and print the statistics, and delete nothing.
    ///
    /// The command still takes and removes the writer lock, so it needs the
    /// permissions of a writer. This option conflicts with --break-lock.
    #[arg(long)]
    no_prune: bool,
    /// Remove the writer lock of another writer of the bucket repository.
    ///
    /// The command reads the lock, deletes it, and then takes its own lock.
    /// It writes the holder of the removed lock to standard error after a
    /// prune that succeeds. Use it only when the holder is gone, for example
    /// after a crash. This option conflicts with --no-prune.
    #[arg(long, conflicts_with = "no_prune")]
    break_lock: bool,
    #[command(flatten)]
    s3: S3AccessArgs,
    // ostrya checks this operand after the repository resolves, unless it is
    // an address.
    /// The remote name or the address `s3://BUCKET[/PREFIX]`. Required.
    ///
    /// The address of a remote is its `push-url` key if that key holds an
    /// `s3://` address, else its `pull-url` key if that key holds an `s3://`
    /// address. The command refuses a remote with neither, and never reads the
    /// `url` key.
    name: Option<String>,
}

#[derive(Args)]
struct PruneArgs {
    /// Delete each commit and object that no ref reaches, directly or through
    /// a related commit.
    ///
    /// Without this option, each commit in the store is a root of the walk. A
    /// commit that no ref names then stays, with the objects that it reaches.
    #[arg(long)]
    refs_only: bool,
    /// The number of parents of each ref to keep.
    ///
    /// The value -1 keeps all history. The value 0 keeps only the commit that
    /// the ref names, and so does each negative value other than -1. The bound
    /// deletes commits only if the walk starts from the refs alone: with
    /// --refs-only, --only-branch, --retain-branch-depth, or
    /// --keep-younger-than.
    #[arg(long, default_value_t = -1, allow_negative_numbers = true, overrides_with = "depth")]
    depth: i32,
    /// Compute and print the statistics, and delete nothing.
    ///
    /// The command prints the number of objects that a prune deletes and the
    /// size that it frees. This option conflicts with --delete-commit.
    #[arg(long)]
    no_prune: bool,
    /// Delete this specific, unreferenced commit before the sweep.
    ///
    /// The value is a revision. The command refuses a commit that a ref names.
    /// The sweep then deletes each object that only this commit reached. The
    /// command writes a `.tombstone-commit` for each commit that it deletes.
    /// This option conflicts with --no-prune.
    #[arg(long)]
    delete_commit: Option<String>,
    /// Delete the history of each ref that is older than DATE.
    ///
    /// DATE is `@SECONDS` since the Unix epoch, or a date and time with a UTC
    /// offset, for example `2024-05-01T12:00:00Z` or `2024-05-01 12:00+02:00`.
    /// The command refuses each other form. The commit that a ref names stays
    /// at all ages. The walk starts from the refs alone, as with --refs-only.
    /// For each branch that --retain-branch-depth does not set, this bound
    /// replaces --depth.
    #[arg(long, value_name = "DATE", overrides_with = "keep_younger_than")]
    keep_younger_than: Option<String>,
    /// Delete only the static deltas whose target commit is --delete-commit.
    ///
    /// The command deletes no loose object, so the commit stays. This option
    /// requires --delete-commit.
    #[arg(long)]
    static_deltas_only: bool,
    /// Keep DEPTH parents of BRANCH, in place of --depth for that branch.
    ///
    /// DEPTH is a decimal integer with an optional leading `-`. The option can
    /// occur more than once, and the last value for a branch applies. The
    /// value 0 keeps the branch at --depth. The walk starts from the refs
    /// alone, as with --refs-only.
    #[arg(long, value_name = "BRANCH=DEPTH")]
    retain_branch_depth: Vec<String>,
    /// Prune BRANCH alone. Every other branch keeps its whole ancestry.
    ///
    /// The option can occur more than once. A branch that
    /// --retain-branch-depth names is also pruned, to its own depth. The walk
    /// starts from the refs alone, as with --refs-only. The command reads each
    /// BRANCH as a revision, and it fails if a BRANCH names nothing.
    #[arg(long, value_name = "BRANCH")]
    only_branch: Vec<String>,
    /// Delete commit objects alone.
    ///
    /// The objects that a deleted commit reached stay. The totals count commit
    /// objects alone.
    #[arg(long)]
    commit_only: bool,
}

#[derive(Args)]
struct FsckArgs {
    /// If a referenced object is missing, do not mark the commit partial.
    ///
    /// Without this option, the command writes the marker
    /// `state/<commit>.commitpartial` for each commit that reaches a missing
    /// object, or an object that --delete removed.
    #[arg(long)]
    no_mark_partial: bool,
    /// Delete each commit whose parent commit is missing, and add a tombstone.
    ///
    /// This step comes after the object walk. It writes a `.tombstone-commit`
    /// for each deleted commit, and a ref to a deleted commit stays. One run
    /// deletes one generation of commits. After a walk that found a corrupt
    /// object, the step runs only with -a or --delete. This option also stops
    /// the count of partial commits on standard output.
    #[arg(long)]
    add_tombstones: bool,
    /// Do not print the lines that name each phase of the check.
    ///
    /// The command still prints the findings, the tombstone lines, the count
    /// of partial commits, and the final result line.
    #[arg(short, long)]
    quiet: bool,
    // The fsck walk of ostrya always runs to its end, with all switches. This
    // option selects one thing only: if `--add-tombstones` can act on a walk
    // that found a corrupt object.
    /// Let --add-tombstones run after a walk that found a corrupt object.
    ///
    /// The object walk always runs to its end and reports each error, with or
    /// without this option. --delete also gives this permission.
    #[arg(short, long)]
    all: bool,
    /// Delete each object whose checksum differs from its name.
    ///
    /// The command also marks each commit that reaches a deleted object as
    /// partial. A metadata object that does not parse stays, and the command
    /// reports it.
    #[arg(long)]
    delete: bool,
    /// Verify that the commit of each ref is bound to that ref.
    ///
    /// The `ostree.ref-binding` metadata of the commit of each ref must hold
    /// the name of the ref. For a collection ref, the
    /// `ostree.collection-binding` of the commit must be the collection id of
    /// the ref. A commit with no binding key passes. A failure ends the run.
    #[arg(long)]
    verify_bindings: bool,
    /// Verify that the ref bindings of each commit resolve to that commit.
    ///
    /// For each commit in the store, each name in its `ostree.ref-binding`
    /// must name a ref that resolves to the commit. If the commit has an
    /// `ostree.collection-binding`, the collection ref with that id and that
    /// name must also resolve to the commit. This option does not include
    /// --verify-bindings. A failure ends the run.
    #[arg(long)]
    verify_back_refs: bool,
}

#[derive(Args)]
struct DiffArgs {
    /// Print the object counts and the size of the common objects.
    ///
    /// The command reads both arguments as revisions. It prints the object
    /// count of each commit, the number of objects that both commits hold, and
    /// the size of these common objects on disk. Without --fs-diff, the
    /// command prints no path lines.
    #[arg(long)]
    stats: bool,
    /// Print the file system diff.
    ///
    /// The path lines are the default output. This option is necessary only
    /// with --stats, to print the path lines before the statistics.
    #[arg(long)]
    fs_diff: bool,
    /// Do not read the extended attributes of a directory side.
    ///
    /// A commit side keeps the extended attributes of its objects.
    #[arg(long)]
    no_xattrs: bool,
    /// Use this user id as the owner of each file of a directory side.
    ///
    /// The option applies only to the second side, and only if that side is a
    /// directory. A negative value keeps the user id from the file system. The
    /// value is a C integer: decimal, hexadecimal with `0x`, or octal with `0`.
    #[arg(
        long,
        value_name = "UID",
        allow_hyphen_values = true,
        overrides_with = "owner_uid"
    )]
    owner_uid: Option<String>,
    /// Use this group id as the owner group of each file of a directory side.
    ///
    /// The option applies only to the second side, and only if that side is a
    /// directory. A negative value keeps the group id from the file system.
    /// The value is a C integer: decimal, hexadecimal with `0x`, or octal with
    /// `0`.
    #[arg(
        long,
        value_name = "GID",
        allow_hyphen_values = true,
        overrides_with = "owner_gid"
    )]
    owner_gid: Option<String>,
    // ostrya checks this operand after the repository resolves, in the order
    // of the `ostree` command.
    /// The first revision or directory. Required.
    ///
    /// An argument that starts with `/` or `./` names a directory. Each other
    /// argument names a revision. If there is no second argument, the command
    /// compares FROM with `^` appended against FROM.
    from: Option<String>,
    /// The second revision or directory.
    to: Option<String>,
}

/// The signature engine that `--sign-type` selects.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SignType {
    /// ed25519 detached signatures (the sign-api default).
    #[value(name = "ed25519")]
    Ed25519,
    /// SubjectPublicKeyInfo keys: ECDSA over NIST P-256 or P-384 with SHA-256,
    /// Ed25519, or RSA PKCS#1 v1.5 with SHA-256.
    #[value(name = "spki")]
    Spki,
    /// GPG (OpenPGP) detached signatures.
    #[value(name = "gpg")]
    Gpg,
}

#[derive(Args)]
struct SignArgs {
    /// Delete the stored signatures that match the given KEY-IDs.
    ///
    /// The command needs at least one KEY-ID, and prints `Deleted <n>
    /// signature(s)`. For ed25519 and spki, a signature matches if it verifies
    /// under a public key from a KEY-ID or from a --keys-file. For gpg, a
    /// KEY-ID matches the end of the issuer fingerprint or of the primary-key
    /// fingerprint of a signature. This option conflicts with --verify.
    #[arg(short, long, conflicts_with = "verify")]
    delete: bool,
    /// Verify the signatures of the commit, and add no signature.
    ///
    /// The command prints one line for each signature, with `good`, `BAD`, or
    /// `no public key`. Then it prints `verification OK` or `verification
    /// FAILED`. If the commit has no signature for the engine, the command
    /// prints `no signatures found`. If no signature is valid, the command
    /// exits 1.
    #[arg(long)]
    verify: bool,
    /// The signature engine to use.
    ///
    /// The engine selects the key format and the detached-metadata key that
    /// holds the signatures: `ostree.sign.ed25519`, `ostree.sign.spki`, or
    /// `ostree.gpgsigs`.
    #[arg(short = 's', long = "sign-type", default_value = "ed25519")]
    sign_type: SignType,
    /// Read keys from a file.
    ///
    /// For ed25519, the file has base64 keys, one per line: secret keys to
    /// sign, public keys to verify and delete. For spki, the file holds PEM
    /// `PRIVATE KEY` blocks, each a PKCS#8 DER of a P-256, a P-384, an
    /// Ed25519, or an RSA key, to sign, and PEM `PUBLIC KEY`
    /// blocks to verify and delete. Each `PRIVATE KEY` block adds one
    /// signature. Signing and delete read every file. A signing or delete file
    /// is a regular file of at most 1 MiB. For an ed25519 or spki verify, the
    /// last value wins. With
    /// this option or a KEY-ID, that verify does not read --keys-dir or the
    /// system key directories.
    ///
    /// For gpg, the file is a binary or armored keyring for verify and delete,
    /// and every file is read. These keyrings then replace the global trusted
    /// set and the keyrings of --remote. A gpg signing run refuses this option.
    #[arg(long, value_name = "PATH")]
    keys_file: Vec<std::ffi::OsString>,
    /// Read the keys of an ed25519 or spki verify from this directory.
    ///
    /// The verify reads `trusted.<type>`, `revoked.<type>`, and the files in
    /// `trusted.<type>.d/` and `revoked.<type>.d/`. It then does not read the
    /// system key directories `/etc/ostree` and `/usr/share/ostree`. An
    /// ed25519 file has one base64 key per line, and an spki file has PEM
    /// `PUBLIC KEY` blocks. If the option occurs more than once, the last
    /// value wins. An empty value names the working directory. The gpg engine
    /// refuses this option.
    #[arg(long, value_name = "PATH", overrides_with = "keys_dir")]
    keys_dir: Option<std::ffi::OsString>,
    /// The GnuPG home directory where gpg resolves signing keys.
    ///
    /// Without this option, gpg uses its own resolution. Only the gpg engine
    /// reads it, and the ed25519 and spki engines refuse it.
    #[arg(long)]
    gpg_homedir: Option<PathBuf>,
    /// Add the trusted keyrings of this remote to a gpg verify and delete.
    ///
    /// The keyrings are `<remote>.trustedkeys.gpg` in the repository and in
    /// `/etc/ostree/remotes.d/`. The command adds them to the global trusted
    /// set: the `*.gpg` keyrings in `OSTREE_GPG_HOME`, or in
    /// `/usr/share/ostree/trusted.gpg.d/` if that variable is unset or empty.
    /// With --keys-file, the command does not read these keyrings. Only the gpg
    /// engine reads this option, and the ed25519 and spki engines refuse it.
    #[arg(long)]
    remote: Option<String>,
    // ostrya checks this operand after the repository resolves, in the order
    // of the `ostree` command.
    /// The commit to operate on (a checksum or a ref). Required.
    commit: Option<String>,
    /// Key identifiers: base64 keys, or gpg key selectors.
    ///
    /// For ed25519 and spki, each KEY-ID is a base64 key: a secret key to
    /// sign, or a public key to verify and delete. An spki secret key is a
    /// PKCS#8 DER, a SEC1 DER that names the P-256 or the P-384 curve, or a
    /// PKCS#1 DER of an RSA key. An spki public key is a SubjectPublicKeyInfo
    /// DER. The base64 of an spki key can hold line breaks. For gpg, each
    /// KEY-ID is a signing key that gpg resolves (a fingerprint, key id, or
    /// user id). A gpg signing run needs at least one KEY-ID. With --delete,
    /// the gpg KEY-IDs are the fingerprints to remove.
    key_id: Vec<String>,
}

#[derive(Args)]
struct SummaryArgs {
    /// Regenerate the root summary and the summary of each auth item from the
    /// refs of the repository.
    ///
    /// The root summary `summary` holds each ref, whatever the client groups.
    /// An auth item has a summary when one or more of its client groups has
    /// `summary=true`. With no client group, the `anonymous` item has a
    /// summary that holds each ref. The summary of an item holds the refs that
    /// the item reads in each namespace whose selected group has
    /// `summary=true`. A namespace whose selected group has `summary=false`
    /// adds no ref. The summary of each item, `anonymous` included, is under
    /// `extensions/ostrya/summary/`. The root summary states the mode of the
    /// repository. The summary of an item states `archive-z2`, the mode that
    /// `ostrya serve` serves. In a mode other than `archive`, the summary of
    /// an item names no static delta. The command writes each summary and
    /// replaces its signature file. Each summary gets a signature of each
    /// --gpg-sign key, each --sign key, and each KEY-ID and --keys-file key,
    /// in this order. The command writes the `.access` file of each item
    /// last, and removes the files of each item that has no summary.
    ///
    /// The command checks every -m value, every key, and the client groups
    /// before the regeneration, so a refusal leaves each summary as it was.
    /// For each directory under `refs/mirrors/` whose name is not a
    /// collection id, the command writes one `warning:` line to standard
    /// error. It prints nothing else. With -c, the command does not write the
    /// root summary.
    #[arg(short = 'u', long)]
    update: bool,
    /// With -u, write the summaries of the auth items alone.
    ///
    /// This is an ostrya extension. The command writes and signs the summary
    /// of each auth item under `extensions/ostrya/summary/`, and removes the
    /// files of each item that has no summary, as -u does. It leaves `summary`
    /// and `summary.sig` in the repository root as they are. In a repository
    /// with a collection id, it writes no `ostree-metadata` anchor commit.
    /// The option needs -u.
    #[arg(short = 'c', long, requires = "update")]
    client_groups: bool,
    /// View a report of the local summary file.
    ///
    /// The report holds each ref, the refs of each collection, and the global
    /// metadata. This option takes precedence over --list-metadata-keys and
    /// --print-metadata-key. If the repository has no `summary` file, the
    /// command exits 1.
    #[arg(short = 'v', long)]
    view: bool,
    /// Print debug information during command processing.
    // This subcommand declares the switch, so that `-v` stays bound to
    // `--view`. `clap` carries the value up to the global flag, and every
    // handler reads that flag. No code reads this field.
    #[arg(long)]
    #[allow(dead_code)]
    verbose: bool,
    /// View the local summary file in the GVariant text form.
    ///
    /// This option takes precedence over every other read option.
    #[arg(long)]
    raw: bool,
    /// List the available metadata keys.
    ///
    /// The command prints the keys of the global metadata, in sorted order.
    #[arg(long)]
    list_metadata_keys: bool,
    /// Print the value of one metadata key.
    ///
    /// If the global metadata has no such key, the command exits 1.
    #[arg(long, value_name = "KEY")]
    print_metadata_key: Option<String>,
    /// Add a metadata field to the summary, as KEY=VALUE.
    ///
    /// VALUE is in the GVariant text form. The option can occur more than once.
    /// Only -u reads it. If the summary writes KEY as one of its own entries,
    /// the summary keeps its own value. In a mode other than `archive`, the
    /// summary of an auth item drops `ostree.static-deltas` and
    /// `ostree.summary.indexed-deltas`. A repository with a collection id
    /// refuses this option.
    #[arg(short = 'm', long = "add-metadata", value_name = "KEY=VALUE")]
    add_metadata: Vec<String>,
    /// Sign the summary with this key.
    ///
    /// The --sign-type option selects the engine. For ed25519 and spki, the key
    /// is the base64 of the secret key. An spki secret key is a PKCS#8 DER, a
    /// SEC1 DER that names the P-256 or the P-384 curve, or a PKCS#1 DER of an
    /// RSA key, and its base64 can hold line breaks. For gpg, the key is a
    /// selector, as for --gpg-sign. Each
    /// occurrence adds one signature. Only -u reads it.
    #[arg(long, value_name = "KEY-ID")]
    sign: Vec<String>,
    /// Sign the summary with the GPG key that this selector names.
    ///
    /// The option uses the gpg engine for each --sign-type. Each occurrence
    /// adds one signature. Only -u reads it.
    #[arg(long, value_name = "KEY-ID")]
    gpg_sign: Vec<String>,
    /// Verify the signatures of the summary.
    ///
    /// The command then does not regenerate or sign the summary, also with -u.
    /// It prints one line for each signature and then `verification OK` or
    /// `verification FAILED`. If no signature is valid, the command exits 1.
    /// The ed25519 and spki engines read the key sources of `ostrya sign
    /// --verify`. The gpg engine reads each --keys-file keyring, or else the
    /// keyrings of --remote, or else the global trusted set.
    #[arg(long)]
    verify: bool,
    /// The signature engine for --verify, --sign, and the positional keys.
    ///
    /// The engine also applies to --keys-file. The names are `ed25519`,
    /// `spki`, and `gpg`, and the command refuses any other name. The default
    /// is `ed25519`. If the option occurs more than once, the last value wins.
    #[arg(
        short = 's',
        long = "sign-type",
        value_name = "NAME",
        overrides_with = "sign_type"
    )]
    sign_type: Option<String>,
    /// Set `ostree.summary.last-modified`, in seconds since the Unix epoch.
    ///
    /// A fixed value makes the output reproducible. Without this option, the
    /// command uses the current time. `SOURCE_DATE_EPOCH` does not change this
    /// value. Only -u reads it.
    #[arg(long)]
    last_modified: Option<u64>,
    /// The timestamp of the collection anchor commit, in Unix epoch seconds.
    ///
    /// The anchor commit is the `ostree-metadata` commit. Without this option,
    /// the timestamp is `SOURCE_DATE_EPOCH` if it is set, or else the current
    /// time. Only -u without -c reads it, and only a repository with a
    /// collection id uses it.
    #[arg(long)]
    metadata_commit_timestamp: Option<u64>,
    /// Read keys from a file, in the format of `ostrya sign`.
    ///
    /// For spki, a signing file holds PEM `PRIVATE KEY` blocks, and a verify
    /// file holds PEM `PUBLIC KEY` blocks. For an ed25519 or spki verify, the
    /// last value wins. With this option or a KEY-ID, that verify does not read
    /// --keys-dir or the system key directories. A signing run reads every
    /// file. A gpg verify reads every
    /// file as a keyring, and a gpg signing run refuses this option. Without -u
    /// and --verify, the keys sign the existing summary.
    #[arg(long, value_name = "PATH")]
    keys_file: Vec<std::ffi::OsString>,
    /// Read the keys of an ed25519 or spki verify from this directory.
    ///
    /// The verify reads `trusted.<type>`, `revoked.<type>`, and the files in
    /// `trusted.<type>.d/` and `revoked.<type>.d/`. It then does not read the
    /// system key directories `/etc/ostree` and `/usr/share/ostree`. An
    /// ed25519 file has one base64 key per line, and an spki file has PEM
    /// `PUBLIC KEY` blocks. If the option occurs more than once, the last
    /// value wins. An empty value names the working directory. A gpg verify
    /// refuses this option.
    #[arg(long, value_name = "PATH", overrides_with = "keys_dir")]
    keys_dir: Option<std::ffi::OsString>,
    /// The GnuPG home directory where gpg resolves signing keys.
    ///
    /// Only the gpg engine reads it: for --gpg-sign, and for --sign and the
    /// positional keys under the gpg engine.
    #[arg(long)]
    gpg_homedir: Option<PathBuf>,
    /// Add the trusted gpg keyrings of this remote to a gpg verify.
    ///
    /// The keyrings are `<remote>.trustedkeys.gpg` in the repository and in
    /// `/etc/ostree/remotes.d/`, in addition to the global trusted set. With
    /// --keys-file, the command does not read them. Only the gpg engine reads
    /// this option.
    #[arg(long)]
    remote: Option<String>,
    /// Read the summary of the auth item of the client group NAME.
    ///
    /// This is an ostrya extension. It applies to -v, --raw,
    /// --list-metadata-keys, and --print-metadata-key. The command reads the
    /// file of the summary of the item, and does not compare its `.access`
    /// file with the client groups. In a repository with no client group,
    /// NAME is `anonymous` or `anonymous-collections`, the implicit groups.
    /// The command refuses a group that does not exist, a group with
    /// `summary=false`, and a group whose `auth` list holds more than one
    /// item. It also refuses this option with -u, with --verify, with a
    /// signing key, and with no read option.
    #[arg(long, value_name = "NAME")]
    auth_group: Option<String>,
    /// Signing or verification keys, in the format of `ostrya sign`.
    ///
    /// This is an ostrya extension. With -u, the keys sign each summary after
    /// every --sign key. Without -u, they sign each existing summary, and the
    /// command then ignores every read option. With --verify, they are the
    /// trusted keys.
    key_id: Vec<String>,
}

#[derive(Args)]
struct StaticDeltaArgs {
    // The subcommand is optional for `clap`, so that ostrya reports a missing
    // subcommand with the text of the `ostree` command. The report comes
    // before the repository resolves, in the order of the `ostree` command.
    /// The `static-delta` subcommand to run.
    #[command(subcommand)]
    command: Option<StaticDeltaCommand>,
}

#[derive(Args)]
struct DeltaReindexArgs {
    /// Rewrite or remove only the index of the target REV.
    ///
    /// REV is a full lowercase commit checksum. If no delta to REV exists, the
    /// command removes the index file of REV. The other index files do not
    /// change. If the option occurs more than once, the last value wins.
    #[arg(long, value_name = "REV", overrides_with = "to")]
    to: Option<String>,
}

#[derive(Subcommand)]
enum StaticDeltaCommand {
    /// List the static deltas of the repository.
    ///
    /// The command prints one delta name on each line, in sorted order: `TO`
    /// for a delta from scratch, or `FROM-TO`. If the repository has no delta,
    /// the command prints `(No static deltas)`.
    List,
    /// Apply a static delta offline and write the objects of its target commit.
    ///
    /// The source is a superblock file or a directory that holds `superblock`.
    /// The command prints nothing and writes no ref. A key source is a KEY-ID,
    /// --keys-file, or --keys-dir. With a key source, the command verifies a
    /// signed delta before it writes an object, and applies an unsigned delta
    /// with no check. Without a key source, the command verifies no signature.
    ApplyOffline(DeltaApplyArgs),
    /// Generate a static delta and print what it is generated from and to.
    ///
    /// The command prints `Generating static delta:` and the `From:` and `To:`
    /// commits before it writes a file. Without --output-dir or --filename,
    /// the delta goes into the `deltas/` tree of the repository. With --sign
    /// or --keys-file, the command signs the superblock.
    Generate(DeltaGenerateArgs),
    /// Rebuild the `delta-indexes/` cache from the existing deltas.
    ///
    /// Each target commit gets one index file. The file lists each delta to
    /// that target with the SHA-256 of its superblock. The command removes the
    /// index file of a target that has no delta. With `--to`, the command
    /// rebuilds the index of one target alone.
    Reindex(DeltaReindexArgs),
    /// Print the superblock fields of a delta and what each part holds.
    ///
    /// The command prints the signed state, the source and target commits, the
    /// byte order, the timestamp, and the fallback objects. Then it prints the
    /// statistics of each part and the total sizes.
    Show {
        /// A delta name, or the path of a superblock file.
        ///
        /// A delta name is `TO` or `FROM-TO` in full lowercase hex. An
        /// argument with a `/` is a path. For a path, the command reads the
        /// parts from the directory of the superblock.
        delta: Option<String>,
    },
    /// Remove a static delta: its entry under `deltas/` and everything in it.
    ///
    /// The `delta-indexes/` cache and `summary` do not change, so they can
    /// still name the delta. `ostrya static-delta reindex` and `ostrya summary
    /// -u` update them.
    Delete {
        /// A delta name, `TO` or `FROM-TO` in full lowercase hex.
        ///
        /// The command reads a path as a name and refuses it.
        delta: Option<String>,
    },
    /// List the targets that the `delta-indexes/` cache has an index for.
    ///
    /// The command prints one checksum on each line, in sorted order. If the
    /// cache has no index, the command prints `(No static deltas indexes)`.
    /// The command reads no delta, so it lists a target also if no delta to it
    /// exists.
    Indexes,
    /// Verify the superblock signatures of a static delta.
    ///
    /// On success, the command prints `Verification OK`. After the keys load,
    /// each failure prints `Verification fails` on standard output and an
    /// error on standard error, and the command exits 1. An unsigned delta is
    /// a failure. Without --keys-file, --keys-dir, or a KEY-ID, the command
    /// reads the system key directories `/etc/ostree` and `/usr/share/ostree`.
    Verify(DeltaVerifyArgs),
}

#[derive(Args)]
struct DeltaVerifyArgs {
    /// The signature engine: `ed25519` or `spki`.
    ///
    /// The default is `ed25519`. The command refuses any other name, `gpg`
    /// included. If the option occurs more than once, the last value wins.
    #[arg(long = "sign-type", value_name = "NAME", overrides_with = "sign_type")]
    sign_type: Option<String>,
    /// Read public keys from a file.
    ///
    /// For ed25519, the file has one base64 key per line. For spki, it has PEM
    /// `PUBLIC KEY` blocks. If the option occurs more than once, the last value
    /// wins. With this option or a KEY-ID, the command does not read --keys-dir
    /// or the system key directories. The path must name a regular file of 1 MiB or less.
    /// The command takes an empty value as given, and refuses it because it is
    /// not a regular file.
    #[arg(long, value_name = "PATH", overrides_with = "keys_file")]
    keys_file: Option<std::ffi::OsString>,
    /// Read `trusted.<type>` and `revoked.<type>` from this directory.
    ///
    /// The command also reads the files in `trusted.<type>.d/` and
    /// `revoked.<type>.d/`. It then does not read the system key directories.
    /// An ed25519 file has one base64 key per line, and an spki file has PEM
    /// `PUBLIC KEY` blocks. If the option occurs more than once, the last value
    /// wins. An empty value names the working directory.
    #[arg(long, value_name = "PATH", overrides_with = "keys_dir")]
    keys_dir: Option<std::ffi::OsString>,
    // ostrya checks this operand after the repository resolves.
    /// A delta name, or the path of a superblock file. Required.
    ///
    /// A delta name is `TO` or `FROM-TO` in full lowercase hex. An argument
    /// with a `/` is a path. The command reads only the superblock.
    delta: Option<String>,
    /// Trusted public keys in base64.
    ///
    /// An ed25519 key must decode to 32 bytes. An spki key is a
    /// SubjectPublicKeyInfo DER, and its base64 can hold line breaks.
    key_id: Vec<String>,
}

#[derive(Args)]
struct DeltaApplyArgs {
    /// The signature engine: `ed25519` or `spki`.
    ///
    /// The default is `ed25519`. The command reads this option also with no
    /// key source, and refuses any other name, `gpg` included. If the option
    /// occurs more than once, the last value wins.
    #[arg(long = "sign-type", value_name = "NAME", overrides_with = "sign_type")]
    sign_type: Option<String>,
    /// Read public keys from a file.
    ///
    /// For ed25519, the file has one base64 key per line. For spki, it has PEM
    /// `PUBLIC KEY` blocks. If the option occurs more than once, the last value
    /// wins. With this option or a KEY-ID, the command does not read
    /// --keys-dir. The path must
    /// name a regular file of 1 MiB or less.
    #[arg(long, value_name = "PATH", overrides_with = "keys_file")]
    keys_file: Option<std::ffi::OsString>,
    /// Read `trusted.<type>` and `revoked.<type>` from this directory.
    ///
    /// The command also reads the files in `trusted.<type>.d/` and
    /// `revoked.<type>.d/`. An ed25519 file has one base64 key per line, and an
    /// spki file has PEM `PUBLIC KEY` blocks. If the option occurs more than
    /// once, the last value wins. An empty value names the working directory.
    #[arg(long, value_name = "PATH", overrides_with = "keys_dir")]
    keys_dir: Option<std::ffi::OsString>,
    // ostrya checks this operand after the repository resolves.
    /// A superblock file, or a directory with `superblock` and the parts.
    ///
    /// The superblock file can have any name. For a file, the command reads
    /// the parts from the directory of the file. The command applies each `..`
    /// component of PATH as text before it resolves the path. Required.
    path: Option<PathBuf>,
    /// Trusted public keys in base64.
    ///
    /// An ed25519 key must decode to 32 bytes. An spki key is a
    /// SubjectPublicKeyInfo DER, and its base64 can hold line breaks.
    key_id: Vec<String>,
}

#[derive(Args)]
struct DeltaGenerateArgs {
    /// Create the delta from revision REV.
    ///
    /// With neither --from nor --empty, the source is the parent of TO. The
    /// command refuses --from together with --empty.
    #[arg(long, value_name = "REV")]
    from: Option<String>,
    /// Create the delta from scratch, with no source commit.
    #[arg(long)]
    empty: bool,
    /// Create the delta to revision REV.
    ///
    /// This option wins over the positional TO. With neither, the command
    /// refuses the run.
    #[arg(long, value_name = "REV")]
    to: Option<String>,
    /// The target revision, if --to is absent.
    #[arg(value_name = "TO")]
    to_positional: Option<String>,
    /// Generate only if the repository has no superblock for the delta.
    ///
    /// If the superblock exists, the command prints `Delta <name> already
    /// exists.` and exits 0. The check reads the `deltas/` tree of the
    /// repository, also with --output-dir or --filename.
    #[arg(short = 'n', long)]
    if_not_exists: bool,
    /// Write the superblock to PATH and the parts to the directory of PATH.
    ///
    /// The command does not create the directory. It refuses a PATH that names
    /// a directory, or whose last component is empty, `.`, `..`, or a part
    /// file name such as `0`. This option conflicts with --output-dir.
    #[arg(long, value_name = "PATH", conflicts_with = "output_dir")]
    filename: Option<PathBuf>,
    /// Send an object of this many decimal megabytes or more as a fallback.
    ///
    /// The size is the size of the uncompressed stream of the object: the file
    /// header and the content. A loose fallback goes outside the parts, and
    /// the receiver fetches it whole. The value is a whole number. A value of
    /// `0` turns fallbacks off for content objects.
    ///
    /// The composefs image of the target commit goes in the delta if the
    /// commit carries a valid `ostree.composefs.digest.v0` and the repository
    /// stores the image. The image is a fallback if this value is not `0` and
    /// the image is this size or larger. It is also a fallback if it is
    /// larger than --max-chunk-size or 128 MiB, or with --inline.
    #[arg(long, value_name = "MB", default_value = "4", value_parser = parse_megabytes)]
    min_fallback_size: u64,
    /// The largest content size, in decimal megabytes, for a bspatch stream.
    ///
    /// A fixed limit of 64 KiB also applies, and the smaller limit decides.
    /// Both limits apply to the source object and to the target object.
    #[arg(long, value_name = "MB", default_value = "64", value_parser = parse_megabytes)]
    max_bsdiff_size: u64,
    /// Close a part before its payload passes this many decimal megabytes.
    ///
    /// A part that holds one large object can pass this size. A composefs
    /// image larger than this size is a fallback. The command refuses a value
    /// of `0`.
    #[arg(long, value_name = "MB", default_value = "32", value_parser = parse_megabytes)]
    max_chunk_size: u64,
    /// Emit no bspatch stream.
    ///
    /// The command splices the content that chunking cannot express.
    #[arg(long)]
    disable_bsdiff: bool,
    /// Set the superblock timestamp, in seconds since the Unix epoch.
    ///
    /// A fixed value makes the output reproducible. Without this option, the
    /// command uses the current time.
    #[arg(long)]
    timestamp: Option<u64>,
    /// Write the files of the delta to this directory.
    ///
    /// Without this option, the files go to `deltas/` of the repository. The
    /// command creates the directory if it is absent. The other content of the
    /// directory does not change, so part files of an earlier, longer delta
    /// stay.
    #[arg(long)]
    output_dir: Option<PathBuf>,
    /// Sign the generated delta with this key.
    ///
    /// The option can occur more than once. The key is a base64 secret key for
    /// ed25519 and spki, and a KEY-ID for gpg, as for `ostrya sign`. An spki
    /// secret key is a PKCS#8 DER, a SEC1 DER that names the P-256 or the P-384
    /// curve, or a PKCS#1 DER of an RSA key, and its base64 can hold line
    /// breaks.
    #[arg(long = "sign")]
    sign: Vec<String>,
    /// The signature engine for --sign and --keys-file.
    #[arg(short = 's', long = "sign-type", default_value = "ed25519")]
    sign_type: SignType,
    /// Read signing keys from a file.
    ///
    /// For ed25519, the file has base64 secret keys, one per line, as for
    /// `ostrya sign`. For spki, each line is the base64 of one secret key: a
    /// PKCS#8 DER, a SEC1 DER that names the P-256 or the P-384 curve, or a
    /// PKCS#1 DER of an RSA key. A line ends at LF
    /// or CRLF, and the last line can have no line end. The command refuses an
    /// empty spki file, an empty line, and a line with white space. Each key
    /// adds one signature. The option can occur more than once, and the
    /// command reads every file. The gpg engine refuses this option.
    #[arg(long)]
    keys_file: Vec<PathBuf>,
    /// The GnuPG home directory where gpg resolves signing keys.
    ///
    /// Only the gpg engine reads it.
    #[arg(long)]
    gpg_homedir: Option<PathBuf>,
    /// Rebuild the index cache after the delta is generated.
    ///
    /// The rebuild covers the deltas under the `deltas/` tree of the
    /// repository, so the command refuses this switch with --output-dir or
    /// --filename.
    #[arg(long)]
    reindex: bool,
    /// Carry the parts in the superblock and write no part file.
    ///
    /// The parts count toward the superblock limit of 128 MiB. If the
    /// superblock passes this limit, the command fails before it writes the
    /// superblock. With this switch, the composefs image of the target
    /// commit is a fallback, and no part carries it.
    #[arg(long)]
    inline: bool,
    /// The byte order of the superblock size fields: `l` or `B`.
    ///
    /// `l` is little-endian, and `B` is big-endian. Without this option, the
    /// byte order is the host order. The command refuses any other value. If
    /// the option occurs more than once, the last value wins.
    #[arg(
        long = "set-endianness",
        value_name = "ENDIAN",
        overrides_with = "set_endianness"
    )]
    set_endianness: Option<String>,
    /// Swap the byte order from the host order, or from --set-endianness.
    #[arg(long, overrides_with = "swap_endianness")]
    swap_endianness: bool,
}

/// The options of a command that reads or writes a bucket repository at an
/// `s3://` address.
///
/// Each option wins over the key of the remote with its name, and over the
/// environment and the shared AWS files. A command refuses each option for
/// an address that is not `s3://`.
#[cfg(feature = "s3")]
#[derive(Args, Default)]
struct S3Args {
    /// The region of the signature of each request to the S3 server.
    ///
    /// It wins over the `s3-region` key of the remote, over `AWS_REGION` and
    /// `AWS_DEFAULT_REGION`, and over the `region` of the AWS profile. The
    /// default is `us-east-1`. The command refuses this option for an
    /// address that is not `s3://`.
    #[arg(long, value_name = "REGION")]
    s3_region: Option<String>,
    /// The `http://` or `https://` URL of the S3 server, with no path.
    ///
    /// It wins over the `s3-endpoint` key of the remote, over
    /// `AWS_ENDPOINT_URL_S3` and `AWS_ENDPOINT_URL`, and over the endpoint of
    /// the AWS profile. Without each of them, the server is AWS. An `http://`
    /// URL needs --allow-cleartext-credentials. The command refuses this
    /// option for an address that is not `s3://`.
    #[arg(long, value_name = "URL")]
    s3_endpoint: Option<String>,
    /// The addressing style of the bucket: `path` or `virtual`.
    ///
    /// `path` puts the bucket in the path of each request, and `virtual` puts
    /// it in the host name. The option wins over the `s3-addressing` key of
    /// the remote and over the `addressing_style` of the AWS profile. The
    /// default is `virtual` for AWS and `path` for a set server. A bucket
    /// name that holds a `.` gets `path` by default. The command refuses this
    /// option for an address that is not `s3://`.
    #[arg(long, value_name = "STYLE", value_parser = ["path", "virtual"])]
    s3_addressing: Option<String>,
    /// The profile of the shared AWS files.
    ///
    /// It wins over the `s3-profile` key of the remote and over
    /// `AWS_PROFILE`. A profile that this option or the key names skips the
    /// key pair, the region, and the endpoint of the environment. The
    /// default profile is `default`. The command refuses this option for an
    /// address that is not `s3://`.
    #[arg(long, value_name = "PROFILE")]
    s3_profile: Option<String>,
}

#[cfg(feature = "s3")]
impl S3Args {
    /// Returns the name of the first option that is set, or `None` if no
    /// option is set.
    fn first_set(&self) -> Option<&'static str> {
        [
            ("--s3-region", self.s3_region.is_some()),
            ("--s3-endpoint", self.s3_endpoint.is_some()),
            ("--s3-addressing", self.s3_addressing.is_some()),
            ("--s3-profile", self.s3_profile.is_some()),
        ]
        .into_iter()
        .find(|(_, set)| *set)
        .map(|(name, _)| name)
    }

    /// Moves the options into the S3 fields of `overrides`.
    fn apply(self, overrides: &mut ostrya::endpoint::EndpointOverrides) {
        overrides.s3_region = self.s3_region;
        overrides.s3_endpoint = self.s3_endpoint;
        overrides.s3_addressing = self.s3_addressing;
        overrides.s3_profile = self.s3_profile;
    }
}

/// The S3 options of a command that has no other HTTP credential, with the
/// permission of an `http://` S3 server.
#[cfg(feature = "s3")]
#[derive(Args)]
struct S3AccessArgs {
    #[command(flatten)]
    s3: S3Args,
    /// Send the signature of each request to an `http://` S3 server.
    ///
    /// The signature is a credential. Without this switch, the command
    /// refuses an `http://` S3 server before any request. Use it for a
    /// server on a loopback address or behind a proxy that terminates TLS. No
    /// key of the remote sets this switch. The command refuses it for an
    /// address that is not `s3://`.
    #[arg(long)]
    allow_cleartext_credentials: bool,
}

#[cfg(feature = "s3")]
impl S3AccessArgs {
    /// Returns the name of the first option that is set, or `None` if no
    /// option is set.
    fn first_set(&self) -> Option<&'static str> {
        self.s3.first_set().or(self
            .allow_cleartext_credentials
            .then_some("--allow-cleartext-credentials"))
    }

    /// Returns the endpoint overrides of the options.
    fn into_overrides(self) -> ostrya::endpoint::EndpointOverrides {
        let mut overrides = ostrya::endpoint::EndpointOverrides {
            allow_cleartext_credentials: self.allow_cleartext_credentials,
            ..Default::default()
        };
        self.s3.apply(&mut overrides);
        overrides
    }

    /// Returns the endpoint overrides of the options for a pull of `remote`
    /// from the address `url` or from the address of the remote.
    ///
    /// If an option is set and the address of the pull is an HTTP or an ssh
    /// address, the process exits with an error that names the option. An
    /// address that the resolver refuses keeps the options, so that the
    /// resolver states its refusal.
    fn pull_overrides(
        self,
        repo: &Repo,
        remote: &str,
        url: Option<&str>,
    ) -> ostrya::endpoint::EndpointOverrides {
        if let Some(name) = self.first_set()
            && ostrya::endpoint::pull_address_is_s3(Some(repo.config()), remote, url) == Some(false)
        {
            exit_error(&format!(
                "{name} applies to an s3:// address, and the pull address of remote \
                 '{remote}' is not one"
            ));
        }
        self.into_overrides()
    }
}

#[derive(Args)]
struct PullArgs {
    /// Fetch from this address, an HTTP URL, an ssh address, or an `s3://`
    /// address.
    ///
    /// The address replaces the configured `pull-url` or `url` of the remote.
    /// An address that starts with `ssh://`, or that holds no `://`, is an
    /// ssh address. `s3://BUCKET[/PREFIX]` is the address of a bucket
    /// repository in an S3 bucket, which the pull reads with signed requests.
    /// A build without the feature `s3` refuses it. With this option, a pull
    /// can use a remote that the config
    /// does not describe. The config gives no keys for such a remote, and
    /// `gpg-verify` keeps its default of true. So the pull requires a GPG
    /// signature on each commit, unless the command line states its own
    /// signature policy, for example --gpg-verify=false.
    #[arg(long)]
    url: Option<String>,
    /// Pull refs of the collection ID from each remote that serves it.
    ///
    /// The candidates are the remotes whose `collection-id` key is ID. If no
    /// remote has the key, the command fails. The command reads the key of
    /// each remote, so a `collection-id` value with a malformed escape
    /// sequence in any remote fails the command. With this option, each
    /// operand is a ref of the collection, and the command takes no REMOTE.
    /// With no ref, the pull takes each ref of the collection that a
    /// candidate lists, and fails if no candidate lists a ref. The pull asks
    /// each candidate for the commit of each ref, through the ref listing of
    /// the server or else through its summary. Under `gpg-verify-summary` or
    /// `sign-verify-summary`, it reads the refs from the verified summary
    /// alone. A candidate at an `s3://` address is a bucket repository: the
    /// pull reads its refs from its summary alone, and skips it if it has no
    /// summary. A build without the feature `s3` refuses an `s3://`
    /// candidate, and the pull fails before its first request. The S3
    /// settings of each candidate come from the config, and the command
    /// refuses the `--s3-*` options. It refuses --allow-cleartext-credentials
    /// if the pull address of a candidate is an HTTP or an ssh address. For
    /// each ref, it selects the candidate with the newest commit, and a tie
    /// goes to the first candidate in the config. A candidate that fails to
    /// answer is skipped with a warning. The pull from each selected
    /// candidate is a pull of its own, so a failure of a later candidate
    /// keeps the refs of the earlier ones. The keys of the selected candidate
    /// apply.
    /// Each commit must be bound to ID. If a commit has a ref binding, the
    /// binding must hold the ref. The pull writes `refs/mirrors/ID/REF`, or
    /// `refs/heads/REF` if the `collection-id` of this repository is ID.
    #[arg(
        long,
        value_name = "ID",
        conflicts_with_all = ["url", "mirror", "disable_verify_bindings"]
    )]
    collection: Option<String>,
    /// Write the pulled refs as local refs under `refs/heads/`.
    ///
    /// If no ref is named, the pull takes every ref that the summary of the
    /// remote lists, and fails if the remote serves no summary. This pull also
    /// copies the `summary` and `summary.sig` of the remote to this
    /// repository. If the remote has no `summary.sig`, the `summary.sig` of
    /// this repository stays as it is. A pull of named refs copies no
    /// summary.
    #[arg(long)]
    mirror: bool,
    /// The number of parents of each pulled commit to follow.
    ///
    /// 0 takes the commit alone, and -1 takes the whole ancestry on the
    /// remote. The pull follows the chain of each ref separately. The command
    /// refuses a value less than -1.
    #[arg(long, default_value_t = 0, allow_negative_numbers = true)]
    depth: i32,
    /// Fetch only the commit objects, and mark each commit partial.
    ///
    /// The pull walks no tree and takes no static delta.
    #[arg(long)]
    commit_metadata_only: bool,
    /// Fetch only the part of the tree of each commit under this path.
    ///
    /// PATH is an absolute path, and the command refuses a value that does
    /// not start with `/`. The option can occur more than once, and the pull
    /// takes the union. The pull marks each commit partial, and a later pull
    /// without this option completes the commit. Into an `archive`
    /// repository, the pull takes no static delta, unless
    /// --require-static-deltas is given.
    #[arg(long = "subpath", value_name = "PATH")]
    subpath: Vec<String>,
    /// Verify the checksum of every object. A pull always does this.
    ///
    /// A pull over HTTP or over ssh hashes each object that it stores, and
    /// compares the result with the name of the object. So this switch changes
    /// nothing.
    #[arg(long)]
    untrusted: bool,
    /// A switch of the `ostree` command that this pull accepts and ignores.
    ///
    /// The pull still verifies the checksum of every fetched object, so a
    /// corrupt object fails the pull.
    #[arg(long)]
    http_trusted: bool,
    /// Refuse regular files with mode bits outside 0775.
    ///
    /// A world-writable, setuid, setgid, or sticky file fails the pull. A
    /// symlink passes. The check applies to the loose objects and to the
    /// objects that a static delta gives.
    #[arg(long)]
    bareuseronly_files: bool,
    /// Do not check the ostree.ref-binding list of each pulled commit.
    ///
    /// Without this switch, the list must name the ref that the commit is
    /// pulled under, or the pull fails. A commit with no ostree.ref-binding
    /// key passes.
    #[arg(long)]
    disable_verify_bindings: bool,
    /// Copy each object from a localcache repository, and make no hardlink.
    ///
    /// The pull copies an object from a repository on another file system
    /// also without this switch.
    #[arg(long)]
    force_copy: bool,
    /// Look in this repository for an object before the network.
    ///
    /// The option can occur more than once, and the pull reads the
    /// repositories in the order given. It verifies the checksum of each
    /// object that it takes from them. Each path must be a repository, or the
    /// command fails before the pull sends a request.
    #[arg(short = 'L', long = "localcache-repo")]
    localcache_repo: Vec<PathBuf>,
    /// Do not sync anything that this pull writes.
    ///
    /// This switch changes no byte that the pull writes. It wins over
    /// --per-object-fsync.
    #[arg(long)]
    disable_fsync: bool,
    /// Sync the file of each content object when the pull stages it.
    ///
    /// The switch applies whatever `[core] per-object-fsync` says. The pull
    /// does not sync metadata objects one by one. --disable-fsync and
    /// `[core] fsync=false` win over this switch.
    #[arg(long)]
    per_object_fsync: bool,
    /// Send NAME=VALUE as an HTTP header with every request.
    ///
    /// The option can occur more than once. The value splits at its first
    /// `=`, and the command refuses an empty NAME. A pull over ssh refuses
    /// this option.
    #[arg(long = "http-header", value_name = "NAME=VALUE", value_parser = parse_http_header)]
    http_header: Vec<(String, String)>,
    /// The number of fetches to keep in flight (default: 8).
    #[arg(long, value_name = "N")]
    max_outstanding_fetcher_requests: Option<usize>,
    /// The number of repeats after a retryable failure (default: 5).
    ///
    /// Each repeat goes through the round of mirrors again, from the first
    /// mirror. A 404 gets no repeat. If a body fails in transit, the pull
    /// fetches it again from the start, and each refetch uses one repeat. The
    /// pull waits 250 milliseconds before the first repeat, and doubles the
    /// wait up to 2 seconds. A pull over ssh refuses a value above 0.
    #[arg(long, value_name = "N")]
    network_retries: Option<u32>,
    /// Retry nothing, whatever the value of --network-retries.
    ///
    /// The switch wins in either order of the two options. A pull over ssh
    /// accepts it, because a pull over ssh never sends a request again.
    #[arg(long)]
    disable_retry_on_network_errors: bool,
    /// The lowest rate in bytes per second of a transfer (default: 1000).
    ///
    /// If the rate of a transfer stays at N bytes per second or less for
    /// --low-speed-time-seconds, the transfer fails as a retryable failure.
    /// The pull samples the rate once a second over the last five seconds. 0
    /// turns the check off, and a negative value keeps the default. The value
    /// is read as a C `int`, and a value that this reader refuses ends the
    /// command before the repository opens. A pull over ssh refuses a value
    /// of 0 or more.
    #[arg(long, value_name = "N", allow_hyphen_values = true)]
    low_speed_limit_bytes: Option<String>,
    /// The seconds that a transfer can stay at the lowest rate (default: 30).
    ///
    /// --low-speed-limit-bytes sets the lowest rate. 0 turns the check off,
    /// and a negative value keeps the default. The value is read as a C `int`,
    /// as the value of --low-speed-limit-bytes is. A pull over ssh refuses a
    /// value of 0 or more.
    #[arg(long, value_name = "N", allow_hyphen_values = true)]
    low_speed_time_seconds: Option<String>,
    /// The time between two redraws of the progress line (default: 1000 ms).
    ///
    /// FREQUENCY is in milliseconds. 0 and a negative value keep the default.
    /// The value is read as a C `int`, as the value of --low-speed-limit-bytes
    /// is. The progress line goes to standard output. If the output is not a
    /// terminal, the pull prints no progress line.
    #[arg(long, value_name = "FREQUENCY", allow_hyphen_values = true)]
    update_frequency: Option<String>,
    /// Refuse a fetched tip that is older than the current commit of its ref.
    ///
    /// The current commit is the commit that the ref names in this
    /// repository. A tip with an equal timestamp passes. A ref that this
    /// repository does not hold passes.
    #[arg(short = 'T', long)]
    timestamp_check: bool,
    /// Refuse a fetched tip that is older than the commit that REV names.
    ///
    /// The command resolves REV in this repository, so this repository must
    /// have the commit. A tip with an equal timestamp passes. The option
    /// conflicts with --timestamp-check.
    #[arg(long, value_name = "REV", conflicts_with = "timestamp_check")]
    timestamp_check_from_rev: Option<String>,
    /// Fetch every object loose, and ignore all static deltas of the remote.
    #[arg(long)]
    disable_static_deltas: bool,
    /// Refuse the pull if a missing commit has no static delta on the remote.
    ///
    /// A missing commit is a commit that this repository does not hold
    /// complete, a dependency of a pulled commit included. The pull also fails
    /// if the remote serves no summary. The option conflicts with
    /// --disable-static-deltas.
    #[arg(long, conflicts_with = "disable_static_deltas")]
    require_static_deltas: bool,
    /// Require a GPG signature on every commit that the pull carries.
    ///
    /// Without this option, the `gpg-verify` key of the remote applies, and
    /// its default is true. `--gpg-verify` requires a signature, and
    /// `--gpg-verify=false` requires none. The trusted keys are
    /// `<remote>.trustedkeys.gpg` of the repository, the system trusted set,
    /// and the keyrings that the `gpgkeypath` key of the remote names. If the
    /// remote has the key `trust`, the keys of the commits come from its trust
    /// group (see ostrya-config(1)). The command then refuses `--gpg-verify`,
    /// and `--gpg-verify=false` turns off the GPG check of the group.
    #[arg(long, require_equals = true, num_args = 0..=1, default_missing_value = "true", value_name = "BOOL")]
    gpg_verify: Option<bool>,
    /// Require a GPG signature on the summary of the remote.
    ///
    /// Without this option, the `gpg-verify-summary` key of the remote
    /// applies, and its default is false. `--gpg-verify-summary` requires a
    /// signature, and `--gpg-verify-summary=false` requires none. If a
    /// signature is required and the remote has no `summary` or no
    /// `summary.sig`, the pull fails.
    #[arg(long, require_equals = true, num_args = 0..=1, default_missing_value = "true", value_name = "BOOL")]
    gpg_verify_summary: Option<bool>,
    /// Require an ed25519 or spki signature on every pulled commit.
    ///
    /// Without this option, the `sign-verify` key of the remote applies, and
    /// its default is off. `--sign-verify` requires a signature and selects
    /// every engine of this build. `--sign-verify=false` requires none. A
    /// valid signature of one engine is sufficient. The trusted keys come from
    /// the `verification-<engine>-key` and `verification-<engine>-file` keys
    /// of the remote, and from the system key store. If the remote has the
    /// key `trust`, the keys of the commits come from its trust group (see
    /// ostrya-config(1)). The command then refuses `--sign-verify`, and
    /// `--sign-verify=false` turns off the sign-api check of the group.
    #[arg(long, require_equals = true, num_args = 0..=1, default_missing_value = "true", value_name = "BOOL")]
    sign_verify: Option<bool>,
    /// Require an ed25519 or spki signature on the summary of the remote.
    ///
    /// Without this option, the `sign-verify-summary` key of the remote
    /// applies, and its default is off. `--sign-verify-summary` requires a
    /// signature and selects every engine of this build.
    /// `--sign-verify-summary=false` requires none.
    #[arg(long, require_equals = true, num_args = 0..=1, default_missing_value = "true", value_name = "BOOL")]
    sign_verify_summary: Option<bool>,
    #[cfg(feature = "s3")]
    #[command(flatten)]
    s3: S3AccessArgs,
    // ostrya checks this operand after the repository resolves, in the order
    // of the `ostree` command.
    /// The remote to pull from, a `[remote "<name>"]` section of the config.
    ///
    /// The remote name is also the prefix of the written refs,
    /// `refs/remotes/<name>/`. Without --collection, the operand is required,
    /// and the command refuses a pull with no remote. With --collection, this
    /// operand is the first ref of the collection.
    remote: Option<String>,
    /// The refs to pull.
    ///
    /// With none, the pull takes the configured `branches` of the remote, or
    /// with --mirror every ref that its summary lists. The pull looks up each
    /// ref in the summary of the remote. If the summary does not list the ref,
    /// the pull reads `refs/heads/<ref>` of the remote. With --collection,
    /// these are the other refs of the collection.
    refs: Vec<String>,
}

#[cfg(feature = "receive")]
#[derive(Args)]
struct ReceiveArgs {
    /// The client name of the session, in place of `LOGNAME`.
    ///
    /// The session selects the client group that carries the item
    /// `ssh:NAME`. NAME is not empty, holds no control character, and does
    /// not start or end with white space. The option is safe only under a
    /// forced `command=` in `authorized_keys`, because a user with a shell
    /// can give any name.
    #[arg(long, value_name = "NAME")]
    client: Option<String>,
}

#[cfg(feature = "send")]
#[derive(Args)]
struct SendArgs {
    /// The client name of the session, in place of `LOGNAME`.
    ///
    /// The session serves the refs of the client group that carries the item
    /// `ssh:NAME`. NAME is not empty, holds no control character, and does
    /// not start or end with white space. The option is safe only under a
    /// forced `command=` in `authorized_keys`, because a user with a shell
    /// can give any name.
    #[arg(long, value_name = "NAME")]
    client: Option<String>,
}

#[cfg(feature = "serve")]
#[derive(Args)]
struct ServeArgs {
    /// Listen on ADDR:PORT, an IP address and a port.
    ///
    /// Give the option once for each address. The options replace the whole
    /// `listen` key. Without the option and the key, the server listens on
    /// `127.0.0.1:8080`. Port 0 lets the kernel choose a port. The command
    /// refuses a host name. When all listeners are bound, the command writes
    /// the URL of each listener to standard output, one line each.
    #[arg(long, value_name = "ADDR:PORT")]
    listen: Vec<std::net::SocketAddr>,
    /// Serve HTTPS with the certificate chain in FILE, in PEM.
    ///
    /// The certificate needs a key, from --tls-key or from the `tls-key`
    /// key. ALPN selects HTTP/2 or HTTP/1.1. The command reads FILE once, at
    /// start, and refuses a file larger than 1 MiB.
    #[arg(long, value_name = "FILE")]
    tls_cert: Option<PathBuf>,
    /// The private key of the server certificate, in PEM.
    ///
    /// The key needs a certificate, from --tls-cert or from the `tls-cert`
    /// key. The command refuses an encrypted key, because it has no option
    /// for a passphrase. It reads FILE once, at start, and refuses a file
    /// larger than 1 MiB.
    #[arg(long, value_name = "FILE")]
    tls_key: Option<PathBuf>,
    /// Verify client certificates against the CA certificates in FILE, in PEM.
    ///
    /// The CA needs a server certificate, from --tls-cert or from the
    /// `tls-cert` key, or a header of a forwarded certificate, from
    /// --trusted-proxy-client-cert or from the `trusted-proxy-client-cert`
    /// key. The CA verifies the certificate of the TLS handshake and the
    /// certificate that a trusted proxy forwards. A client that presents a
    /// certificate in the handshake must present one that the CA signed. A
    /// client that presents no certificate completes the handshake, and the
    /// other auth items identify it. A client certificate
    /// that the CA signed can match a `tls:*`, `tls:NAME`, or
    /// `tls-sha256:HEX` item of a client group. The command reads FILE once,
    /// at start, and refuses a file larger than 1 MiB.
    #[arg(long, value_name = "FILE")]
    tls_client_ca: Option<PathBuf>,
    /// Read the forwarding headers of a peer in the network CIDR.
    ///
    /// CIDR is ADDR/LEN or a bare ADDR. A network with host bits set is
    /// refused. Give the option once for each network. The options replace
    /// the whole `trusted-proxy` key. The option needs a header of the client
    /// address, from --trusted-proxy-header or from the
    /// `trusted-proxy-header` key. From a peer in such a network, the
    /// server reads the client address from that header, the
    /// scheme `https`, and a forwarded client certificate. It walks the hops
    /// of the header from the right, and skips each hop in a trusted network.
    /// The first other hop is the client address. A proxy in the list must
    /// set or remove these headers in each request. No option removes the
    /// key: to trust no peer, remove the key.
    #[arg(long, value_name = "CIDR", value_parser = parse_trusted_proxy)]
    trusted_proxy: Vec<ostrya::access::IpNet>,
    /// Read the client address of a request from a trusted proxy in HEADER.
    ///
    /// HEADER is `forwarded` for the `Forwarded` header of RFC 7239,
    /// `x-forwarded-for`, or `x-real-ip`. The server reads this one header.
    /// With `forwarded`, the `proto` of the client hop gives the scheme. With
    /// the other two, the rightmost value of `X-Forwarded-Proto` gives the
    /// scheme. The option needs a trusted network, from --trusted-proxy or
    /// from the `trusted-proxy` key. No option removes the key.
    #[arg(long, value_name = "HEADER", value_parser = parse_forwarded_header)]
    trusted_proxy_header: Option<ostrya::access::ForwardedHeader>,
    /// Read the client certificate of a request from a trusted proxy in the
    /// request header HEADER.
    ///
    /// HEADER is a header name: an HTTP token of RFC 9110, which is one or
    /// more ASCII letters, digits, and token characters. The value is a
    /// URL-escaped PEM
    /// certificate, as nginx `$ssl_client_escaped_cert` gives it, or a base64
    /// DER certificate, as HAProxy `ssl_c_der,base64` and Traefik
    /// `passTLSClientCert` give it. The client CA verifies the certificate,
    /// also on a plain HTTP listener. A value with more than one certificate,
    /// a value that does not parse, and a certificate that the CA does not
    /// verify get 403. The option needs a client CA and a trusted network,
    /// each from its option or its key. No option removes the key.
    #[arg(long, value_name = "HEADER", value_parser = parse_header_name)]
    trusted_proxy_client_cert: Option<String>,
    /// Read a PROXY protocol header, version 1 or 2, at the start of each
    /// connection.
    ///
    /// `--proxy-protocol` reads the header, and `--proxy-protocol=false`
    /// does not. The header comes before the TLS handshake, and its source
    /// address is the client address. The server closes a connection with
    /// no valid header, or with no header within 30 seconds, with no
    /// response. Each peer that can connect states its own client address
    /// in the header, so only the proxy must be able to reach the listener.
    #[arg(long, require_equals = true, num_args = 0..=1, default_missing_value = "true", value_name = "BOOL")]
    proxy_protocol: Option<bool>,
    /// Take a bearer or Basic credential over plain HTTP.
    ///
    /// `--allow-cleartext-credentials` takes such a credential, and
    /// `--allow-cleartext-credentials=false` refuses it. Without the option
    /// and the key, the server answers 403 to such a request, also
    /// when a client group has the `anonymous` item, unless a trusted proxy
    /// states the scheme `https` (see --trusted-proxy). Use it for a server
    /// on a loopback address, or behind a proxy that terminates TLS and is
    /// not a trusted proxy. A read of the files of a pull takes the same
    /// rule.
    #[arg(long, require_equals = true, num_args = 0..=1, default_missing_value = "true", value_name = "BOOL")]
    allow_cleartext_credentials: Option<bool>,
    /// Abort a push session that stays idle for SECONDS.
    ///
    /// A push session is idle when it has no request in progress, or when its
    /// request body delivers no byte. The value is a positive integer.
    /// Without the option and the key, the value is 300.
    #[arg(
        long,
        value_name = "SECONDS",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    session_timeout: Option<u64>,
    /// Serve at most N push sessions at the same time.
    ///
    /// The value is a positive integer. Without the option and the key, the
    /// value is 16. A request that opens a session past this limit gets the
    /// HTTP status 503.
    #[arg(
        long,
        value_name = "N",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    max_sessions: Option<u64>,
    /// Let a push session send N object streams at the same time.
    ///
    /// The value is 1 to 31. Without the option and the key, the value is 4.
    /// The `HelloReply` of a session announces it. Over HTTP/2, the receive
    /// window of a stream is 2 MiB, and the window of a connection is N
    /// times 2 MiB.
    #[arg(
        long,
        value_name = "N",
        value_parser = clap::value_parser!(u32).range(1..=31)
    )]
    parallel_uploads: Option<u32>,
    /// End a connection whose response waits more than SECONDS for the client.
    ///
    /// The response waits for the client to take its next bytes. If an HTTP/2
    /// client does not answer a ping within SECONDS, it also loses its
    /// connection. The value is a positive integer. Without the option and
    /// the key, the value is 60.
    #[arg(
        long,
        value_name = "SECONDS",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    body_timeout: Option<u64>,
}

#[cfg(feature = "serve")]
impl ServeArgs {
    /// Returns the options as the server settings that they replace. An
    /// option that is not given is `None`.
    fn settings(self) -> ostrya::access::ServerSettings {
        ostrya::access::ServerSettings {
            listen: (!self.listen.is_empty()).then_some(self.listen),
            tls_cert: self.tls_cert,
            tls_key: self.tls_key,
            tls_client_ca: self.tls_client_ca,
            trusted_proxy: (!self.trusted_proxy.is_empty()).then_some(self.trusted_proxy),
            trusted_proxy_header: self.trusted_proxy_header,
            trusted_proxy_client_cert: self.trusted_proxy_client_cert,
            proxy_protocol: self.proxy_protocol,
            allow_cleartext_credentials: self.allow_cleartext_credentials,
            session_timeout: self.session_timeout,
            max_sessions: self.max_sessions,
            parallel_uploads: self.parallel_uploads,
            body_timeout: self.body_timeout,
            ..ostrya::access::ServerSettings::default()
        }
    }
}

/// Reads a value of `--trusted-proxy`.
#[cfg(feature = "serve")]
fn parse_trusted_proxy(text: &str) -> std::result::Result<ostrya::access::IpNet, String> {
    ostrya::access::IpNet::parse(text).map_err(|err| err.to_string())
}

/// Reads a value of `--trusted-proxy-header`.
#[cfg(feature = "serve")]
fn parse_forwarded_header(
    text: &str,
) -> std::result::Result<ostrya::access::ForwardedHeader, String> {
    ostrya::access::ForwardedHeader::parse(text).map_err(|err| err.to_string())
}

/// Reads a value of `--trusted-proxy-client-cert`.
#[cfg(feature = "serve")]
fn parse_header_name(text: &str) -> std::result::Result<String, String> {
    if ostrya::access::is_header_name(text) {
        Ok(text.to_owned())
    } else {
        Err(format!(
            "'{text}' is not a header name: one or more ASCII letters, digits, and the \
             characters !#$%&'*+-.^_`|~"
        ))
    }
}

#[cfg(feature = "push")]
#[derive(Args)]
struct PushArgs {
    /// The number of parents of each source commit to send.
    ///
    /// 0 sends the commit alone, and -1 sends the whole chain that this
    /// repository holds. The command refuses a value less than -1.
    ///
    /// Without this option, the push sends the chain back to the commit of the
    /// ref on the server. If the server does not have the ref, or the local
    /// chain does not have that commit, the push sends the source commit
    /// alone.
    #[arg(long, value_name = "N", allow_negative_numbers = true)]
    depth: Option<i32>,
    /// Update each ref whatever its state on the server.
    ///
    /// The push also asks the server to allow an update that is not a
    /// fast-forward. The server still refuses such an update unless the
    /// client group of the push has `w` and `d` on the ref.
    #[arg(long)]
    force: bool,
    /// Write the refs of the collection ID on the server.
    ///
    /// The push reads the `ostree.collection-binding` of each source commit.
    /// Without this option, the bindings give the namespace on the server: a
    /// commit with no binding goes to the local refs, and a commit bound to
    /// ID goes to the refs of ID. The server writes the refs of its own
    /// collection id under `refs/heads/`, and the refs of each other
    /// collection under `refs/mirrors/ID/`. `commit` binds each commit of a
    /// repository with a collection id to that id. So a push of such a
    /// commit to a server with another collection id, or with none, writes
    /// `refs/mirrors/ID/NAME` on the server.
    ///
    /// The command refuses two source commits with different bindings, a
    /// binding that differs from ID, and a commit with no binding that goes
    /// to the refs of a collection. It refuses an ID or a binding that fails
    /// the collection-id rule or is longer than 255 bytes before it starts
    /// the transport.
    ///
    /// With --onto, ID alone names the namespace, and the bindings of the
    /// local commit do not apply. Without ID, the server commit goes to the
    /// local refs of the server.
    ///
    /// To a bucket repository, the `config` of the bucket takes the role of
    /// the server. No namespace, or the collection id of the bucket, writes
    /// `refs/heads/NAME`. Each other collection writes
    /// `refs/mirrors/ID/NAME`, also in a bucket with no collection id.
    #[arg(long, value_name = "ID")]
    collection: Option<String>,
    /// Create the ref NAME on the server at the source commit.
    ///
    /// The option can occur more than once. A tag is a ref update that
    /// expects no ref, also with --force. So a tag that exists gets
    /// ref-mismatch after the server reports its refs, and before the push
    /// sends an object. The refspecs that are not deletes must give one
    /// commit, and the `ostree.ref-binding` of that commit must hold NAME.
    /// NAME passes the ref-name rule, has no `:`, is not 64 lowercase hex
    /// characters, and is not a DST. The client group of the push needs `t`
    /// or `w` on NAME.
    ///
    /// With --onto, the server creates NAME at the new commit, and the
    /// `ostree.ref-binding` of that commit holds NAME. NAME is not BRANCH. A
    /// tag that exists also gets ref-mismatch before the push sends an
    /// object.
    #[arg(long = "tag", value_name = "NAME")]
    tags: Vec<String>,
    /// Ask the server to commit the tree of REF onto the branch BRANCH.
    ///
    /// The push sends the objects of the tree of the local commit that the
    /// server does not have. The server then makes a new commit over the
    /// tree, moves BRANCH to it, and creates each --tag at it, in one
    /// transaction. The parent of the new commit is the commit of BRANCH on
    /// the server. The new commit takes the subject, the body, the metadata,
    /// and the timestamp of the local commit. The push leaves out the local
    /// `ostree.ref-binding` and `ostree.collection-binding`, and the server
    /// writes the bindings of its namespace: BRANCH, each --tag, and each
    /// --bind-ref.
    ///
    /// The push sends no parent, no commit object, and no detached metadata,
    /// so no signature of the local commit reaches the server. The server
    /// signs the new commit with the keys of its own client group.
    ///
    /// The client group needs `c` on BRANCH. A server whose receive hooks
    /// take no server commit answers ref-denied. The push sends the server
    /// commit in one frame, which an ostrya server limits to 1 MiB. The reply
    /// names BRANCH and each --tag, and must also fit in one frame. The push
    /// checks the two frames against the limit of the server before it sends
    /// an object.
    ///
    /// BRANCH passes the ref-name rule, has no `:`, and is not 64 lowercase
    /// hex characters. With --onto, the command takes exactly one REF, a
    /// revision of this repository, and does not split it at `:`. The local
    /// commit must not be partial, and must have no related objects. --onto
    /// conflicts with --depth and --force.
    #[arg(long, value_name = "BRANCH", conflicts_with_all = ["depth", "force"])]
    onto: Option<String>,
    /// Bind the commit of --onto to NAME, and create no ref.
    ///
    /// The option can occur more than once. The `ostree.ref-binding` of the
    /// new commit holds each NAME. NAME passes the ref-name rule and has no
    /// `:`. The option needs --onto.
    #[arg(long = "bind-ref", value_name = "NAME", requires = "onto")]
    bind_refs: Vec<String>,
    /// Make the commit of --onto with no parent.
    ///
    /// If BRANCH exists on the server, the client group needs `c` and `d` on
    /// it, else the server answers non-fast-forward. The option needs --onto.
    #[arg(long, requires = "onto")]
    orphan: bool,
    /// Override the timestamp of the commit of --onto.
    ///
    /// The value is `@SECONDS` since the Unix epoch, or a date and time with
    /// a UTC offset (`2020-01-02T03:04:05Z`). Without this option, the new
    /// commit takes the timestamp of the local commit. The option needs
    /// --onto.
    #[arg(long, value_name = "TIMESTAMP", requires = "onto")]
    timestamp: Option<String>,
    /// Send the content objects deflated at LEVEL, 1 to 9.
    ///
    /// The value needs the `=` form, and --compress alone gives level 6.
    /// Without this option, the push sends the content objects raw. With it,
    /// if this repository is an archive repository, the push sends each stored
    /// content object as it is, whatever LEVEL is. The object keeps the zlib
    /// level that the repository wrote it with.
    #[arg(
        long,
        value_name = "LEVEL",
        require_equals = true,
        num_args = 0..=1,
        default_missing_value = "6",
        value_parser = clap::value_parser!(u8).range(1..=9)
    )]
    compress: Option<u8>,
    #[command(flatten)]
    connect: PushConnectArgs,
    #[cfg(feature = "s3")]
    #[command(flatten)]
    s3: S3Args,
    /// Remove the writer lock of another writer of a bucket repository.
    ///
    /// The push reads the lock, deletes it, and then takes its own lock. It
    /// writes the holder of the removed lock to standard error after a push
    /// that succeeds. Use it only when the holder is gone, for example after
    /// a crash: a writer whose lock is removed stops at its next check. The
    /// command refuses this option for an address that is not `s3://`, and
    /// with --onto.
    #[cfg(feature = "s3")]
    #[arg(long, conflicts_with = "onto")]
    break_lock: bool,
    // ostrya checks this operand after the repository resolves.
    /// The remote: a remote name, or an ssh, HTTP, or `s3://` address.
    /// Required.
    ///
    /// A value with a `:` or a `/` is an address:
    /// `ssh://[USER@]HOST[:PORT]/PATH`, `[USER@]HOST:PATH`, `http://`,
    /// `https://`, or `s3://BUCKET[/PREFIX]`. Each other value names a
    /// `[remote "<name>"]` section in the config of this repository. The push
    /// address of the section is its `push-url` key. If `push-url` is absent,
    /// a `url` key with an `http://` or `https://` address is the push
    /// address. The `url` key holds no `s3://` address.
    ///
    /// To an ssh address, the push runs the ssh client with the receive
    /// command on the remote side. To an HTTP address, the push sends its
    /// requests to the receive endpoint of `ostrya serve`. To an `s3://`
    /// address, the push writes the bucket repository at that address. A
    /// build without the feature `s3` refuses an `s3://` address.
    remote: Option<String>,
    /// The refspecs, each `SRC[:DST]`. At least one refspec is required.
    ///
    /// SRC is a revision of this repository, and DST is the ref of the server
    /// that takes its commit. The command splits each refspec at its last
    /// `:`. If SRC is a ref, DST defaults to SRC. A SRC that is a checksum, or
    /// that has a `^` suffix, needs a DST. `:DST` deletes the ref DST of the
    /// server.
    ///
    /// The command refuses a DST that the ref-name rule refuses, which
    /// includes a DST with `^`. It also refuses a DST of 64 lowercase hex
    /// characters after a SRC, because a revision reads such a name as a
    /// commit checksum. A delete of such a DST passes.
    ///
    /// With --onto, the operand is one REF, a revision of this repository.
    refspecs: Vec<String>,
}

/// The options of `push` and `push-tree` that say how the push reaches the
/// remote.
///
/// The ssh options apply to an ssh address, and the other options to an
/// `http://` or `https://` address. An option of the other transport is
/// refused. Each option wins over the key of the remote that has its name.
#[cfg(feature = "push")]
#[derive(Args, Default)]
struct PushConnectArgs {
    /// The ssh command, split at ASCII whitespace.
    ///
    /// It wins over the `OSTRYA_SSH_COMMAND` environment variable and over the
    /// `ssh-command` key of the remote. Without each of the three, the push
    /// runs `ssh`. The split has no quoting rule. The command refuses an empty
    /// value, and refuses this option for an HTTP address.
    #[arg(long, value_name = "CMD")]
    ssh_command: Option<String>,
    /// The command that the remote side runs over ssh.
    ///
    /// The remote shell parses the command. The push adds `--repo=` and the
    /// path of the address in single quotes. This option wins over the
    /// `receive-command` key of the remote. The default is `ostrya receive`.
    /// The command refuses an empty value, and refuses this option for an
    /// HTTP address.
    #[arg(long, value_name = "CMD")]
    receive_command: Option<String>,
    /// The file whose first line is the token of an HTTP push.
    ///
    /// It wins over the `push-token-file` key of the remote. Without
    /// --push-user, the push sends the token as a bearer token. The command
    /// refuses a first line that is empty or longer than 1 MiB. It refuses a
    /// token file for an `http://` address without
    /// --allow-cleartext-credentials, and for an ssh address.
    #[arg(long, value_name = "FILE")]
    push_token_file: Option<PathBuf>,
    /// Send the token as the password of a Basic credential with this name.
    ///
    /// Without this option, the token is a bearer token. The option needs a
    /// token file, from --push-token-file or from the `push-token-file` key of
    /// the remote. It wins over the `push-user` key of the remote. The command
    /// refuses an empty name and a name that holds `:`.
    #[arg(long, value_name = "NAME")]
    push_user: Option<String>,
    /// The PEM file of the client certificate of an HTTPS push.
    ///
    /// It needs a key file: --tls-client-key-path or the `tls-client-key-path`
    /// key of the remote. It wins over the `tls-client-cert-path` key of the
    /// remote. A push to an `http://` address reads no TLS file, and the
    /// command refuses this option for an ssh address.
    #[arg(long, value_name = "FILE")]
    tls_client_cert_path: Option<PathBuf>,
    /// The PEM file of the private key of the client certificate.
    ///
    /// The key must need no passphrase. It needs a certificate file:
    /// --tls-client-cert-path or the `tls-client-cert-path` key of the remote.
    /// It wins over the `tls-client-key-path` key of the remote. The command
    /// refuses this option for an ssh address.
    #[arg(long, value_name = "FILE")]
    tls_client_key_path: Option<PathBuf>,
    /// The PEM file of the CA certificates that verify the server.
    ///
    /// With it, the push does not use the trust store of the host. It wins
    /// over the `tls-ca-path` key of the remote. A push to an `http://`
    /// address reads no TLS file, and the command refuses this option for an
    /// ssh address.
    #[arg(long, value_name = "FILE")]
    tls_ca_path: Option<PathBuf>,
    /// Send the token to an `http://` address.
    ///
    /// Without this switch, the command refuses a token to such an address
    /// before any request. Use it for a server on a loopback address or behind
    /// a proxy that terminates TLS. No key of the remote sets this switch. The
    /// command refuses it for an ssh address. For a `push` or a `push-tree`
    /// to an `s3://` address, the switch permits an `http://` S3 server, to
    /// which the signature of each request goes in cleartext.
    #[arg(long)]
    allow_cleartext_credentials: bool,
}

#[cfg(feature = "push")]
#[derive(Args)]
struct PushTreeArgs {
    /// The branch of the server that the server commit moves. Required.
    ///
    /// The server makes the commit over the tree of DIR. Its parent is the
    /// commit of BRANCH on the server, or none if BRANCH is absent. The
    /// server moves BRANCH to the commit. The client group needs `c` on
    /// BRANCH. A server whose receive hooks take no server commit answers
    /// ref-denied.
    ///
    /// The command refuses a name that holds `:`, a name that the ref-name
    /// rule refuses, which includes a name with `^`, and a name of 64
    /// lowercase hex characters, because a revision reads such a name as a
    /// commit checksum.
    ///
    /// To a bucket repository, the push makes the commit itself, as the
    /// server makes it. The parent is the commit of BRANCH in the bucket,
    /// which the push reads under the writer lock, or none if BRANCH is
    /// absent. The push then writes the ref file of BRANCH. In a bucket
    /// repository with a collection id, the push refuses the BRANCH
    /// `ostree-metadata` in `refs/heads/`. The push signs no commit.
    #[arg(long, value_name = "BRANCH")]
    onto: Option<String>,
    /// Create the ref NAME on the server at the new commit.
    ///
    /// The option can occur more than once. The `ostree.ref-binding` of the
    /// commit holds NAME. A tag that exists on the server gets ref-mismatch
    /// before the push sends an object. NAME passes the rules of BRANCH, is
    /// not BRANCH, and occurs once. The client group needs `t` or `w` on
    /// NAME. A push to a bucket repository refuses this option.
    #[arg(long = "tag", value_name = "NAME")]
    tags: Vec<String>,
    /// Bind the commit to NAME, and create no ref.
    ///
    /// The option can occur more than once. The `ostree.ref-binding` of the
    /// commit holds BRANCH, each --tag, and each NAME, sorted. NAME passes
    /// the ref-name rule and has no `:`.
    #[arg(long = "bind-ref", value_name = "NAME")]
    bind_refs: Vec<String>,
    /// Make a commit with no parent.
    ///
    /// If BRANCH exists on the server, the client group needs `c` and `d` on
    /// it, else the server answers non-fast-forward. In a bucket repository,
    /// the new commit replaces the commit of BRANCH with no check.
    #[arg(long)]
    orphan: bool,
    /// Write the refs of the collection ID on the server.
    ///
    /// The server writes the refs of its own collection id under
    /// `refs/heads/`, and the refs of each other collection under
    /// `refs/mirrors/ID/`. `ostree.collection-binding` of the commit holds
    /// ID. Without this option, the push writes the local refs of the server,
    /// and the binding is the collection id of the server, if it has one.
    /// The command refuses an ID that fails the collection-id rule or is
    /// longer than 255 bytes before it starts the transport.
    ///
    /// To a bucket repository, the `config` of the bucket takes the role of
    /// the server: the collection id of the bucket, or no ID, writes
    /// `refs/heads/BRANCH`, and each other ID writes
    /// `refs/mirrors/ID/BRANCH`, also in a bucket with no collection id.
    #[arg(long, value_name = "ID")]
    collection: Option<String>,
    /// The commit subject.
    #[arg(short, long)]
    subject: Option<String>,
    /// The commit body.
    ///
    /// If the option occurs more than once, the last value wins.
    #[arg(short = 'm', long, value_name = "BODY", overrides_with = "body")]
    body: Option<String>,
    /// Read the commit body from this file. This option wins over --body.
    ///
    /// The whole file becomes the body, byte for byte. The command refuses a
    /// file that is larger than 128 MiB, is not UTF-8, or holds a NUL byte.
    #[arg(short = 'F', long, value_name = "FILE", overrides_with = "body_file")]
    body_file: Option<PathBuf>,
    /// Add a string-valued key to the commit metadata.
    ///
    /// The command splits KEY=VALUE at the first `=`, and refuses an empty
    /// key. Each occurrence adds one key. The command refuses the keys
    /// `ostree.ref-binding` and `ostree.collection-binding`, which the server
    /// writes.
    #[arg(long, value_name = "KEY=VALUE")]
    add_metadata_string: Vec<String>,
    /// Add a key to the commit metadata, with a value in GVariant text form.
    ///
    /// Each occurrence adds one key. The metadata holds each
    /// --add-metadata-string entry first, then each --add-metadata entry, and
    /// then the ref bindings that the server writes. The command refuses the
    /// keys `ostree.ref-binding` and `ostree.collection-binding`.
    #[arg(long, value_name = "KEY=VALUE")]
    add_metadata: Vec<String>,
    /// Set the timestamp of the commit.
    ///
    /// The value is `@SECONDS` since the Unix epoch, or a date and time with a
    /// UTC offset (`2020-01-02T03:04:05Z`). Without this option, the push
    /// sends the `SOURCE_DATE_EPOCH` environment variable. If that variable is
    /// not set, the push sends no timestamp, and the server takes its own
    /// clock. A push to a bucket repository then takes the clock of this
    /// host. The command refuses a `SOURCE_DATE_EPOCH` that is not a count of
    /// seconds.
    #[arg(long, value_name = "TIMESTAMP")]
    timestamp: Option<String>,
    /// Set the user id of the owner of the committed files.
    ///
    /// The value applies to the root directory too. A negative value keeps
    /// the user id of each file.
    #[arg(long, value_name = "UID", allow_hyphen_values = true)]
    owner_uid: Option<String>,
    /// Set the group id of the owner of the committed files.
    ///
    /// The value applies to the root directory too. A negative value keeps
    /// the group id of each file.
    #[arg(long, value_name = "GID", allow_hyphen_values = true)]
    owner_gid: Option<String>,
    /// Force owner 0:0, canonicalize modes to `perm & 0755`, and drop xattrs.
    ///
    /// The commit then does not depend on the owner or on the host. A symlink
    /// keeps its mode. The command refuses this switch with a non-zero
    /// --owner-uid or --owner-gid.
    #[arg(long)]
    canonical_permissions: bool,
    /// Send the content objects deflated at LEVEL, 1 to 9.
    ///
    /// The value needs the `=` form, and --compress alone gives level 6.
    /// Without this option, the push sends the content objects raw.
    ///
    /// A push to a bucket repository uploads each file as a `.filez`. It
    /// builds the `.filez` at LEVEL, else at the `[archive] zlib-level` of
    /// the `config` of the bucket, else at level 6.
    #[arg(
        long,
        value_name = "LEVEL",
        require_equals = true,
        num_args = 0..=1,
        default_missing_value = "6",
        value_parser = clap::value_parser!(u8).range(1..=9)
    )]
    compress: Option<u8>,
    #[command(flatten)]
    connect: PushConnectArgs,
    #[cfg(feature = "s3")]
    #[command(flatten)]
    s3: S3Args,
    /// Remove the writer lock of another writer of a bucket repository.
    ///
    /// The push reads the lock, deletes it, and then takes its own lock. It
    /// writes the holder of the removed lock to standard error after a push
    /// that succeeds. Use it only when the holder is gone, for example after
    /// a crash: a writer whose lock is removed stops at its next check. The
    /// command refuses this option for an address that is not `s3://`.
    #[cfg(feature = "s3")]
    #[arg(long)]
    break_lock: bool,
    /// The remote: a remote name, or an ssh, HTTP, or `s3://` address.
    /// Required.
    ///
    /// A value with a `:` or a `/` is an address: an ssh, `http://`,
    /// `https://`, or `s3://BUCKET[/PREFIX]` address. An address opens no
    /// repository, and the command ignores --repo for it. Each other value
    /// names a `[remote "<name>"]` section with a push address. The section
    /// is in the config of the repository that --repo, the current directory,
    /// or `OSTREE_REPO` names.
    ///
    /// To an `s3://` address, the push writes the bucket repository at that
    /// address, which `remote init` created. A build without the feature
    /// `s3` refuses an `s3://` address.
    remote: Option<String>,
    /// The directory to commit. Required.
    dir: Option<PathBuf>,
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct ComposefsImageArgs {
    /// Build and store the image of the commit REV.
    ///
    /// The commit must carry `ostree.composefs.digest.v0`. The command builds
    /// the image of the tree, checks its digest against the key, and stores
    /// it. If a valid image is present already, the command does nothing. An
    /// image whose digest is not the key, or an image that does not read, is
    /// replaced. The command does not refuse a partial commit, and the build
    /// fails if an object of the tree is absent.
    #[arg(long, value_name = "REV")]
    add: Option<String>,
    /// Print the absolute path of the image of the commit REV.
    ///
    /// The command does not read the image. If the image is absent, the
    /// command exits 1.
    #[arg(long, value_name = "REV")]
    get_path: Option<String>,
    /// Check the image of the commit REV against the key of the commit.
    ///
    /// The command reads the whole image and computes its fs-verity digest.
    /// It exits 0 if the digest is the value of `ostree.composefs.digest.v0`.
    /// It exits 1 if the image is absent, if the commit does not carry the
    /// key, or if the digests are different. The error line names the reason,
    /// and for different digests it names both digests.
    #[arg(long, value_name = "REV")]
    check: Option<String>,
}

#[derive(Args)]
#[command(group(
    clap::ArgGroup::new("key_source")
        .args(["remote", "trust"])
        .multiple(true)
))]
struct PullLocalArgs {
    /// Write the pulled refs under this remote name.
    ///
    /// The refs go to `refs/remotes/<remote>/<ref>`. Without this option, they
    /// are local refs. The verification keys of the `[remote "NAME"]` group
    /// apply to the pull, as they apply to `ostrya pull` (see
    /// ostrya-config(1)). If the config has no group for the name, the pull
    /// makes only the checks that its switches ask for. Each switch wins over
    /// its key: --gpg-verify, --gpg-verify-summary, --sign-verify, and
    /// --sign-verify-summary turn a check on, and --no-gpg-verify,
    /// --no-gpg-verify-summary, --no-sign-verify, and --no-sign-verify-summary
    /// turn a configured check off. If the remote has the key `trust`, or if
    /// --trust is given, the keys of the commits come from the trust group.
    /// The command then refuses --gpg-verify and --sign-verify, and
    /// --no-gpg-verify and --no-sign-verify turn off that check of the group.
    #[arg(long)]
    remote: Option<String>,
    /// Take the keys of the commits from the trust group
    /// `[ex-ostrya trust "NAME"]` (see ostrya-config(1)).
    ///
    /// The option wins over the key `trust` of the remote that --remote
    /// names. It needs no --remote, and --remote still names the refs. With
    /// --remote, the summary keys of the remote apply, and the command
    /// refuses a key of the remote that turns on a commit check. Without
    /// --remote, the pull checks no summary, and the command refuses
    /// --gpg-verify-summary. The command refuses --gpg-verify and
    /// --sign-verify, and --no-gpg-verify and --no-sign-verify turn off that
    /// check of the group.
    #[arg(long, value_name = "NAME")]
    trust: Option<String>,
    /// The number of parents of each pulled commit to follow.
    ///
    /// 0 takes the commit alone, and -1 takes the whole ancestry in the
    /// source. The command refuses a value less than -1 before it reads a ref
    /// or an object of the source.
    #[arg(long, default_value_t = 0, allow_negative_numbers = true)]
    depth: i32,
    /// Import only the commit objects, and mark each commit partial.
    #[arg(long)]
    commit_metadata_only: bool,
    /// Verify the checksum of every imported object against its name.
    ///
    /// Without this switch, the pull links or copies an object with no hash.
    /// An object that the pull writes again in another form always gets a
    /// hash. A mismatch fails the pull.
    #[arg(long)]
    untrusted: bool,
    /// Reject regular files with mode bits outside 0775.
    ///
    /// The switch refuses a world-writable, setuid, setgid, or sticky file. A
    /// symlink is exempt.
    #[arg(long)]
    bareuseronly_files: bool,
    /// Do not check the ref binding of a pulled commit.
    ///
    /// Without this switch, the pull checks that the `ostree.ref-binding` list
    /// of each pulled commit names the ref that it is pulled under. A commit
    /// with no binding key passes.
    #[arg(long)]
    disable_verify_bindings: bool,
    /// Copy every object, and make no hardlink.
    ///
    /// Without this switch, the pull hardlinks an object of the source into
    /// this repository when the link is possible.
    #[arg(long)]
    force_copy: bool,
    /// Look in this repository for the objects that the source does not have.
    ///
    /// The option can occur more than once. The pull reads the source first,
    /// and then each such repository in command-line order. It takes an object
    /// from the first repository that holds it.
    #[arg(short = 'L', long = "localcache-repo")]
    localcache_repo: Vec<PathBuf>,
    /// Do not sync anything that this pull writes.
    ///
    /// This switch changes no byte that the pull writes.
    #[arg(long)]
    disable_fsync: bool,
    /// Sync the file of each content object when the pull stages it.
    ///
    /// The pull does not sync metadata objects or hardlinked objects one by
    /// one. Without this switch, `[core] per-object-fsync` applies.
    /// --disable-fsync and `[core] fsync=false` win over this switch.
    #[arg(long)]
    per_object_fsync: bool,
    /// Require a GPG signature on every commit that the pull carries.
    ///
    /// The pull uses the keys of the remote that --remote names. Without
    /// --remote, the command refuses this switch. The switch takes no value.
    #[arg(long)]
    gpg_verify: bool,
    /// Require a GPG signature on the summary of the source.
    ///
    /// The pull uses the keys of the remote that --remote names. Without
    /// --remote, the command refuses this switch. The switch takes no value.
    #[arg(long)]
    gpg_verify_summary: bool,
    /// Require an ed25519 or spki signature on every commit that the pull
    /// carries.
    ///
    /// The switch selects every engine of this build, and a valid signature of
    /// one engine is sufficient. The trusted keys come from the
    /// `verification-<engine>-key` and `verification-<engine>-file` keys of
    /// the remote that --remote names, and from the system key store. The
    /// switch needs --remote and takes no value.
    #[arg(long, requires = "remote")]
    sign_verify: bool,
    /// Require an ed25519 or spki signature on the summary of the source.
    ///
    /// The switch selects every engine of this build, and takes the keys that
    /// --sign-verify takes. If the source has no `summary` or no
    /// `summary.sig`, the pull fails. The switch needs --remote and takes no
    /// value.
    #[arg(long, requires = "remote")]
    sign_verify_summary: bool,
    /// Do not require a GPG signature on the commits.
    ///
    /// The switch turns off the `gpg-verify` key of the remote that --remote
    /// names. With --trust, or if the remote has the key `trust`, the switch
    /// turns off the GPG check of the trust group. It needs --remote or
    /// --trust, and conflicts with --gpg-verify.
    #[arg(long, requires = "key_source", conflicts_with = "gpg_verify")]
    no_gpg_verify: bool,
    /// Do not require a GPG signature on the summary of the source.
    ///
    /// The switch turns off the `gpg-verify-summary` key of the remote that
    /// --remote names. It needs --remote and conflicts with
    /// --gpg-verify-summary.
    #[arg(long, requires = "remote", conflicts_with = "gpg_verify_summary")]
    no_gpg_verify_summary: bool,
    /// Do not require an ed25519 or spki signature on the commits.
    ///
    /// The switch turns off the `sign-verify` key of the remote that --remote
    /// names. With --trust, or if the remote has the key `trust`, the switch
    /// turns off the sign-api check of the trust group. It needs --remote or
    /// --trust, and conflicts with --sign-verify.
    #[arg(long, requires = "key_source", conflicts_with = "sign_verify")]
    no_sign_verify: bool,
    /// Do not require an ed25519 or spki signature on the summary of the
    /// source.
    ///
    /// The switch turns off the `sign-verify-summary` key of the remote that
    /// --remote names. It needs --remote and conflicts with
    /// --sign-verify-summary.
    #[arg(long, requires = "remote", conflicts_with = "sign_verify_summary")]
    no_sign_verify_summary: bool,
    /// Apply the static delta that the summary of the source advertises.
    ///
    /// If the source advertises no delta for a commit, the command refuses the
    /// pull. This includes each dependency that the pull imports and that this
    /// repository does not hold complete. The source must be an archive
    /// repository with a summary. The
    /// statistics line then has the form of a pull from a remote. This switch
    /// conflicts with --disable-static-deltas.
    #[arg(long, conflicts_with = "disable_static_deltas")]
    require_static_deltas: bool,
    /// Read no static delta.
    ///
    /// Without --require-static-deltas, the pull reads no static delta, so
    /// this switch changes nothing.
    #[arg(long)]
    disable_static_deltas: bool,
    // ostrya checks this operand after the repository resolves, in the order
    // of the `ostree` command.
    /// The repository to pull from. Required.
    src_repo: Option<PathBuf>,
    /// The refs to pull.
    ///
    /// With none, the pull takes every local ref of the source, under
    /// `refs/heads`.
    refs: Vec<String>,
}

/// Parses the command line, runs the subcommand, and returns the exit status.
///
/// A parse error prints the message of `clap` and exits 1, and `--help` exits
/// 0. `--version` prints `ostrya` and the version. With no subcommand,
/// [`exit_no_command`] ends the process. A library error prints the line of
/// [`error_line`] and exits 1.
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

/// Returns the text that [`main`] prints on standard error for a library error.
///
/// If the ref-name rule refuses a refspec, the text uses the words of the
/// `ostree` command. This applies wherever a revision, a NEWREF, or a branch
/// name reaches the library, so one condition has one message. An abbreviated
/// checksum that more than one commit carries gets its text here for the same
/// reason. This error occurs wherever a revision is taken, also at the sites
/// that read a revision through the library without [`resolve`].
///
/// Every other error gets the `Display` text of the `ostrya` library.
fn error_line(err: &Error) -> String {
    match err {
        Error::InvalidRefspec(refspec) => format!("Invalid refspec {refspec}"),
        Error::AmbiguousRefspec(refspec) => format!("Refspec {refspec} not unique"),
        other => other.to_string(),
    }
}

/// Runs one subcommand with the global options.
async fn run(repo: Option<&Path>, verbose: bool, command: Command) -> Result<()> {
    let name = command.name();
    match command {
        Command::Init(args) => init(repo, verbose, name, args).await,
        Command::Commit(args) => {
            // The `ostree` command reads `--owner-uid` and `--owner-gid` while
            // it parses its options, so an unreadable value is reported before
            // the repository resolves.
            let owner = commit_owner(&args);
            let fsync = fsync_policy(args.fsync.as_deref());
            let (repo, _) = resolve_repo(repo, verbose, name).await;
            commit(repo, args, owner, fsync).await
        }
        Command::Checkout(args) => {
            // `checkout` also reads `--fsync` with its options. The error for a
            // refused value comes before the repository, before the revision,
            // and before the `DESTINATION must be specified` refusal of a batch
            // option. `clap` counts the positionals before this step. If a
            // plain-path command line omits DESTINATION, ostrya reports the
            // missing positional, and `ostree` reports the value.
            let fsync = fsync_policy(args.fsync.as_deref());
            let (repo, _) = resolve_repo(repo, verbose, name).await;
            checkout(repo, args, fsync).await
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
            // The `ostree` command reports a missing nested subcommand before
            // it resolves the repository. `static-delta` has the same order.
            let Some(sub) = args.command else {
                exit_with_error(name, "No \"remote\" subcommand specified");
            };
            // An init at an address needs no repository. An address holds a
            // `:` or a `/`, and a remote name holds neither.
            #[cfg(feature = "s3")]
            if let RemoteCommand::Init(init) = &sub
                && init.name.as_deref().is_some_and(|n| n.contains([':', '/']))
            {
                let nested = sub.name();
                let RemoteCommand::Init(init) = sub else {
                    unreachable!("the subcommand is init");
                };
                return remote_init(None, nested, init).await;
            }
            // So does a fsck at an address.
            #[cfg(feature = "s3")]
            if let RemoteCommand::Fsck(fsck) = &sub
                && fsck.name.as_deref().is_some_and(|n| n.contains([':', '/']))
            {
                let nested = sub.name();
                let RemoteCommand::Fsck(fsck) = sub else {
                    unreachable!("the subcommand is fsck");
                };
                return remote_fsck(None, nested, fsck).await;
            }
            // So does a prune at an address.
            #[cfg(feature = "s3")]
            if let RemoteCommand::Prune(prune) = &sub
                && prune
                    .name
                    .as_deref()
                    .is_some_and(|n| n.contains([':', '/']))
            {
                let nested = sub.name();
                let RemoteCommand::Prune(prune) = sub else {
                    unreachable!("the subcommand is prune");
                };
                return remote_prune(None, nested, prune).await;
            }
            // So does a summary update at an address.
            #[cfg(feature = "s3")]
            if let RemoteCommand::Summary(summary) = &sub
                && summary.update
                && summary
                    .name
                    .as_deref()
                    .is_some_and(|n| n.contains([':', '/']))
            {
                let nested = sub.name();
                let RemoteCommand::Summary(summary) = sub else {
                    unreachable!("the subcommand is summary");
                };
                return remote_summary_update(None, nested, summary).await;
            }
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
            // `diff` also reads `--owner-uid` and `--owner-gid` with its
            // options, so the error for a refused value comes before the
            // repository resolves.
            let owner = Owner {
                uid: owner_id(args.owner_uid.as_deref(), "--owner-uid"),
                gid: owner_id(args.owner_gid.as_deref(), "--owner-gid"),
            };
            let (repo, _) = resolve_repo(repo, verbose, name).await;
            diff(repo, name, args, owner).await
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
            // The `ostree` command reports a missing nested subcommand before
            // it resolves the repository, so this check comes first.
            let Some(sub) = args.command else {
                exit_with_error(name, "No command specified");
            };
            let (repo, path) = resolve_repo(repo, verbose, name).await;
            static_delta(repo, path, sub).await
        }
        Command::Pull(args) => {
            // The low-speed values are read with the options, so the error for
            // a refused value comes before the repository resolves.
            let low_speed = LowSpeedArgs {
                limit: low_speed_value(
                    args.low_speed_limit_bytes.as_deref(),
                    "--low-speed-limit-bytes",
                ),
                seconds: low_speed_value(
                    args.low_speed_time_seconds.as_deref(),
                    "--low-speed-time-seconds",
                ),
            };
            // `--update-frequency` is read in the same way, at the same step.
            let redraw = update_interval(owner_id(
                args.update_frequency.as_deref(),
                "--update-frequency",
            ));
            let (repo, _) = resolve_repo(repo, verbose, name).await;
            pull(repo, name, args, low_speed, redraw).await
        }
        Command::PullLocal(args) => {
            let (repo, _) = resolve_repo(repo, verbose, name).await;
            pull_local(repo, name, args).await
        }
        Command::ComposefsImage(args) => {
            let (repo, _) = resolve_repo(repo, verbose, name).await;
            composefs_image(repo, args).await
        }
        #[cfg(feature = "receive")]
        Command::Receive(args) => {
            let client = ssh_client(args.client, name);
            // `receive` writes nothing on success, also under `--verbose`, so
            // `resolve_repo` does not write the repository line of `--verbose`.
            let (repo, _) = resolve_repo(repo, false, name).await;
            receive(repo, client).await
        }
        #[cfg(feature = "push")]
        Command::Push(args) => {
            let (repo, _) = resolve_repo(repo, verbose, name).await;
            push(repo, name, verbose, args).await
        }
        #[cfg(feature = "push")]
        Command::PushTree(args) => {
            // `push-tree` reads the owner ids first, as `commit` does, so the
            // error for a refused value comes before every other check.
            let owner = Owner {
                uid: owner_id(args.owner_uid.as_deref(), "--owner-uid"),
                gid: owner_id(args.owner_gid.as_deref(), "--owner-gid"),
            };
            push_tree(repo, verbose, name, args, owner).await
        }
        #[cfg(feature = "serve")]
        Command::Serve(args) => {
            let (repo, _) = resolve_repo(repo, verbose, name).await;
            serve(repo, args).await
        }
        #[cfg(feature = "send")]
        Command::Send(args) => {
            let client = ssh_client(args.client, name);
            // `send` writes nothing on success, also under `--verbose`, so
            // `resolve_repo` does not write the repository line of `--verbose`.
            let (repo, _) = resolve_repo(repo, false, name).await;
            send(repo, client).await
        }
    }
}

/// The maximum size in bytes of a file that `serve` reads.
///
/// The files are the PEM files.
#[cfg(feature = "serve")]
const MAX_SERVE_FILE_SIZE: u64 = 1024 * 1024;

/// Serves the repository with the options of `args` until the process ends.
///
/// When all listeners are bound, the URL of each listener goes to standard
/// output, one line for each listener.
///
/// `serve` reads and checks the client groups, the server group, the trust
/// groups, and the key groups of the repository config at start. Each option
/// of `args` replaces the key of `[ex-ostrya server]` with its name, and the
/// checks run on the result. The receive endpoint identifies each client by
/// the client groups. For each session that commits, each warning of its
/// report goes to standard error as one line.
#[cfg(feature = "serve")]
async fn serve(repo: Repo, args: ServeArgs) -> Result<()> {
    use std::io::Write;
    use std::time::Duration;

    let policies = Arc::new(ostrya::ReceivePolicies::from_config(&repo).await?);
    let settings = policies.access().server().overridden_by(&args.settings());
    policies.access().check_server(&settings)?;
    let mut opts = ostrya_server::ServeOptions::default();
    if let Some(listen) = settings.listen {
        opts.listen = listen;
    }
    if let Some(seconds) = settings.body_timeout {
        opts.body_timeout = Duration::from_secs(seconds);
    }
    if let Some(allow) = settings.allow_cleartext_credentials {
        opts.allow_cleartext_credentials = allow;
    }
    if let Some(seconds) = settings.session_timeout {
        opts.session_idle_timeout = Duration::from_secs(seconds);
    }
    if let Some(n) = settings.max_sessions {
        opts.max_sessions = usize::try_from(n).unwrap_or(usize::MAX);
    }
    if let Some(n) = settings.parallel_uploads {
        opts.parallel_uploads = n;
    }
    if let (Some(cert), Some(key)) = (&settings.tls_cert, &settings.tls_key) {
        opts.tls = Some(ostrya_server::ServerTls {
            cert_chain_pem: read_serve_file(cert),
            key_pem: read_serve_file(key),
            key_passphrase: None,
        });
    }
    opts.client_ca_pem = settings.tls_client_ca.as_deref().map(read_serve_file);
    opts.trusted_proxies = settings.trusted_proxy.unwrap_or_default();
    opts.trusted_proxy_header = settings.trusted_proxy_header;
    opts.trusted_proxy_client_cert = settings.trusted_proxy_client_cert;
    opts.proxy_protocol = settings.proxy_protocol.unwrap_or(false);
    opts.receive = Some(policies);
    opts.on_report = Some(Arc::new(|report: ostrya::ReceiveReport| {
        for warning in &report.warnings {
            eprintln!(
                "warning: {}: {}",
                receive_step(warning.step),
                warning.message
            );
        }
    }));
    opts.on_event = Some(Arc::new(|event: &ostrya_server::ServerEvent| {
        if event.is_warning() {
            eprintln!("warning: {event}");
        } else {
            eprintln!("error: {event}");
        }
    }));
    let scheme = if opts.tls.is_some() { "https" } else { "http" };
    let server = match ostrya_server::bind(repo, opts).await {
        Ok(server) => server,
        Err(err) => {
            eprintln!("error: {err}");
            exit_process(1);
        }
    };
    let mut stdout = std::io::stdout().lock();
    for addr in server.local_addrs() {
        writeln!(stdout, "{scheme}://{addr}/")?;
    }
    stdout.flush()?;
    drop(stdout);
    if let Err(err) = server.run().await {
        eprintln!("error: {err}");
        exit_process(1);
    }
    Ok(())
}

/// Reads a file of `serve` that has at most [`MAX_SERVE_FILE_SIZE`] bytes.
///
/// If the file cannot be read, or is larger, the process ends with an error.
#[cfg(feature = "serve")]
fn read_serve_file(path: &Path) -> Vec<u8> {
    use std::io::Read;

    let read = std::fs::File::open(path).and_then(|file| {
        let mut bytes = Vec::new();
        file.take(MAX_SERVE_FILE_SIZE + 1).read_to_end(&mut bytes)?;
        Ok(bytes)
    });
    match read {
        Ok(bytes) if bytes.len() as u64 <= MAX_SERVE_FILE_SIZE => bytes,
        Ok(_) => {
            eprintln!(
                "error: {}: the file exceeds the {MAX_SERVE_FILE_SIZE}-byte size cap",
                path.display()
            );
            exit_process(1);
        }
        Err(err) => {
            eprintln!("error: {}: {err}", path.display());
            exit_process(1);
        }
    }
}

/// Runs one push session of the client `client` over standard input and
/// standard output.
///
/// The command reads and checks the client groups, the server group, the
/// trust groups, and the key groups of the repository config at start. The
/// session runs under the policy of the client group that carries `client`
/// in the namespace of `Hello`. With no such group, `Hello` gets
/// `ref-denied`. Standard output carries the frames of the session alone.
/// Each warning of the report goes to standard error as one line. A failure
/// goes there as the error line of [`main`].
///
/// The command writes nothing else, also under `--verbose`.
#[cfg(feature = "receive")]
async fn receive(repo: Repo, client: ostrya::access::AuthItem) -> Result<()> {
    let policies = ostrya::ReceivePolicies::from_config(&repo).await?;
    let select = |namespace: &ostrya::access::Namespace| {
        policies
            .select(&client, namespace)
            .map(|(_, policy)| policy.as_ref())
    };
    // The input is read at most 256 KiB ahead of the session. Under the smol
    // backend, the output goes through a blocking-pool pipe of 8 MiB, so up
    // to 8 MiB that the session wrote can wait in the pipe.
    let report = repo
        .receive_selected(stdin_file()?, stdout_file()?, select)
        .await?;
    for warning in &report.warnings {
        eprintln!(
            "warning: {}: {}",
            receive_step(warning.step),
            warning.message
        );
    }
    Ok(())
}

/// Returns the client name of an ssh session of the command `name`.
///
/// The name is `client`, else the value of `LOGNAME`. An empty `LOGNAME` and
/// a value that is not UTF-8 count as absent. With no name, the process ends
/// with an error line and exit 1.
#[cfg(any(feature = "receive", feature = "send"))]
fn ssh_client_name(client: Option<String>, name: &str) -> String {
    let client = client.or_else(|| std::env::var("LOGNAME").ok().filter(|v| !v.is_empty()));
    let Some(client) = client else {
        eprintln!("error: {name} needs a client name: give --client, or set LOGNAME");
        exit_process(1);
    };
    client
}

/// Returns the `ssh:NAME` auth item of the client of an ssh session of the
/// command `name`.
///
/// [`ssh_client_name`] gives NAME. With a name that the item refuses, the
/// process ends with one error line and exit 1. The line shows the name in
/// escaped form, so a control character in the name does not split the line.
#[cfg(any(feature = "receive", feature = "send"))]
fn ssh_client(client: Option<String>, name: &str) -> ostrya::access::AuthItem {
    let client = ssh_client_name(client, name);
    match ostrya::access::AuthItem::parse(&format!("ssh:{client}")) {
        Ok(item) => item,
        Err(_) => {
            eprintln!(
                "error: malformed client name {client:?}: the name is not empty, holds no \
                 control character, and does not start or end with white space"
            );
            exit_process(1);
        }
    }
}

/// Serves one pull session of the client `client` over standard input and
/// standard output.
///
/// The command reads and checks the client groups and the server group of
/// the repository config at start. It reads no key group, because a pull
/// signs nothing. The session serves the refs that the client group of
/// `client` reads. In a config with no client group, the session takes the
/// item `anonymous` of the implicit groups. When no client group carries
/// `client`, the process ends with an error line and exit 1 before the
/// session reads its input.
///
/// Standard output carries the frames of the session alone. A failure goes to
/// standard error as the error line of [`main`]. Each
/// [`SendEvent`](ostrya::SendEvent) goes there as one `warning:` line, or as
/// one `error:` line for an event that is no warning. The command takes no
/// lock and writes no file in the repository.
#[cfg(feature = "send")]
async fn send(repo: Repo, client: ostrya::access::AuthItem) -> Result<()> {
    use ostrya::access::{AuthItem, ClientAccess, ReadAccess};

    let access = ClientAccess::from_config(repo.config(), repo.path())?;
    let item = if !access.has_client_groups() {
        AuthItem::Anonymous
    } else if access.groups_of(&client).next().is_none() {
        eprintln!("error: no client group carries the item {client}");
        exit_process(1);
    } else {
        client
    };
    let access = ReadAccess::new(Arc::new(access), item, None);
    // The input is read at most 256 KiB ahead of the session. Under the smol
    // backend, the output goes through a blocking-pool pipe of 8 MiB, and a
    // flush waits until each byte reaches the descriptor. For this reason,
    // the session flushes only if no whole `Get` frame waits in its input
    // buffer.
    let mut opts = ostrya::SendOptions::default();
    opts.on_event = Some(Arc::new(|event: &ostrya::SendEvent| {
        if event.is_warning() {
            eprintln!("warning: {event}");
        } else {
            eprintln!("error: {event}");
        }
    }));
    repo.send_with(stdin_file()?, stdout_file()?, &access, &opts)
        .await
}

/// Pushes the commits that the refspecs name to a remote over ssh or HTTP, or
/// to a bucket repository at an `s3://` address.
///
/// The push updates the refs of the remote in one transaction. Standard output
/// carries one line for each ref, in the order of the refspecs and then of
/// the tags, and nothing else. Under `--verbose`, one statistics line goes to
/// standard error. A failure writes nothing to standard output.
///
/// The S3 options and `--break-lock` are refused for a destination that is
/// not `s3://`, before the remote resolves. A push to a bucket repository
/// goes through `Repo::push_to_bucket`, and a writer lock that `--break-lock`
/// removed gives one warning line on standard error.
///
/// On a terminal, standard error shows the progress bar of [`PushBar`] while
/// the push runs.
#[cfg(feature = "push")]
async fn push(repo: Repo, name: &str, verbose: bool, mut args: PushArgs) -> Result<()> {
    let Some(remote) = args.remote.clone() else {
        exit_with_error(name, "REMOTE must be specified");
    };
    let remote = remote.as_str();
    if args.refspecs.is_empty() {
        exit_with_error(name, "REFSPEC must be specified");
    }
    // The id is one name under `refs/mirrors/` on the server, and a file
    // system takes a name of 255 bytes at most.
    if let Some(id) = &args.collection
        && (id.len() > 255 || !ostrya::is_collection_id(id))
    {
        exit_error(&format!("Invalid collection ID {id}"));
    }
    #[cfg(feature = "s3")]
    if push_destination_is_s3(&repo, remote) == Some(false) {
        let option = args
            .s3
            .first_set()
            .or(args.break_lock.then_some("--break-lock"));
        if let Some(option) = option {
            exit_error(&format!(
                "{option} applies to an s3:// address, and the push address of '{}' is not \
                 one",
                ostrya::remote::without_userinfo(remote)
            ));
        }
    }
    if args.onto.is_some() {
        return push_onto(repo, verbose, args).await;
    }
    let overrides = push_overrides(&mut args);
    let endpoint = ostrya::endpoint::resolve_push(Some(repo.config()), remote, overrides).await?;
    let (progress, bar) = PushBar::start();
    let opts = ostrya::RepoPushOptions {
        refspecs: args.refspecs,
        depth: args.depth,
        collection: args.collection,
        tags: args.tags,
        compression: push_compression(args.compress),
        force: args.force,
        progress,
        #[cfg(feature = "s3")]
        break_lock: args.break_lock,
        ..Default::default()
    };
    let outcome = match endpoint {
        #[cfg(feature = "s3")]
        ostrya::remote::Endpoint::S3(s3) => {
            let pushed = repo.push_to_bucket(s3, opts).await;
            // The bar is cleared before any line of the result or of the
            // error.
            bar.finish();
            let pushed = pushed?;
            if let Some(holder) = &pushed.broken_lock {
                eprintln!("warning: removed the writer lock of {holder}");
            }
            pushed.outcome
        }
        endpoint => {
            let pushed = repo.push(endpoint, opts).await;
            // The bar is cleared before any line of the result or of the
            // error.
            bar.finish();
            pushed?
        }
    };
    // The remote holds the new refs at this point. If the write to standard
    // output fails, for example on a full device or a closed pipe, `main`
    // prints the error line and exits 1.
    {
        use std::io::Write;
        let mut out = std::io::stdout().lock();
        for update in &outcome.refs {
            writeln!(out, "{}", ref_line(update)).map_err(Error::Io)?;
        }
        out.flush().map_err(Error::Io)?;
    }
    if verbose {
        eprintln!("{}", push_statistics_line(&outcome.stats));
    }
    Ok(())
}

/// Pushes the tree of the commit of one revision to a remote over ssh or
/// HTTP, and asks the server to commit it onto the branch of `--onto`.
///
/// The caller checked REMOTE, the presence of a REF, and `--collection`. The
/// command refuses a second REF and a bad `--timestamp` before it resolves
/// the remote. Standard output carries the checksum of the new commit alone.
/// Under `--verbose`, one statistics line goes to standard error. A failure
/// writes nothing to standard output.
#[cfg(feature = "push")]
async fn push_onto(repo: Repo, verbose: bool, mut args: PushArgs) -> Result<()> {
    let (Some(remote), Some(onto)) = (args.remote.take(), args.onto.take()) else {
        unreachable!("the caller checked REMOTE and --onto");
    };
    let remote = remote.as_str();
    let refspecs = std::mem::take(&mut args.refspecs);
    let [rev] = &refspecs[..] else {
        exit_error(&format!(
            "--onto takes one REF, and {} were given",
            refspecs.len()
        ));
    };
    let timestamp = args.timestamp.as_deref().map(|text| {
        parse_timestamp(text).unwrap_or_else(|| exit_error(&format!("Could not parse '{text}'")))
    });
    let overrides = push_overrides(&mut args);
    let endpoint = ostrya::endpoint::resolve_push(Some(repo.config()), remote, overrides).await?;
    let (progress, bar) = PushBar::start();
    let opts = ostrya::PushOntoOptions {
        rev: rev.clone(),
        onto,
        collection: args.collection,
        tags: args.tags,
        bind_refs: args.bind_refs,
        orphan: args.orphan,
        timestamp,
        compression: push_compression(args.compress),
        progress,
    };
    let pushed = repo.push_onto(endpoint, opts).await;
    // The bar is cleared before any line of the result or of the error.
    bar.finish();
    print_server_commit(verbose, pushed?)
}

/// Writes the commit of a server commit to standard output, and under
/// `verbose` the statistics line to standard error.
///
/// The remote holds the new refs at this point. If the write to standard
/// output fails, for example on a full device or a closed pipe, `main` prints
/// the error line and exits 1.
#[cfg(feature = "push")]
fn print_server_commit(verbose: bool, outcome: ostrya::remote::PushOutcome) -> Result<()> {
    use std::io::Write;
    let commit = outcome
        .commit
        .expect("the outcome of a server commit names its commit");
    let mut out = std::io::stdout().lock();
    writeln!(out, "{commit}").map_err(Error::Io)?;
    out.flush().map_err(Error::Io)?;
    drop(out);
    if verbose {
        eprintln!("{}", push_statistics_line(&outcome.stats));
    }
    Ok(())
}

/// Returns the encoding of the content objects that `--compress` selects.
///
/// The encoding is `deflate` at the given level, or `raw` if the option is
/// absent.
#[cfg(feature = "push")]
fn push_compression(level: Option<u8>) -> ostrya::remote::Compression {
    match level {
        Some(level) => ostrya::remote::Compression::Deflate { level },
        None => ostrya::remote::Compression::None,
    }
}

/// Returns `true` if the destination of `push` is an `s3://` address, or
/// `None` if the command cannot tell.
///
/// An address is the destination. For a remote name, the destination is the
/// push address of its section: `push-url`, else `url`. A remote that the
/// config does not describe, a section with neither key, and a key that does
/// not read give `None`, and the resolver then states the refusal.
#[cfg(all(feature = "push", feature = "s3"))]
fn push_destination_is_s3(repo: &Repo, remote: &str) -> Option<bool> {
    if ostrya::is_push_address(remote) {
        return Some(remote.starts_with("s3://"));
    }
    let section = repo.config().remote(remote)?;
    let address = match section.push_url().ok()? {
        Some(address) => address,
        None => section.url().ok()??,
    };
    Some(address.starts_with("s3://"))
}

/// Returns the endpoint overrides of the transport options of `push`.
///
/// The options are those of [`connect_overrides`], and the S3 options, which
/// the call takes out of `args`.
#[cfg(feature = "push")]
#[cfg_attr(not(feature = "s3"), allow(unused_mut))]
fn push_overrides(args: &mut PushArgs) -> ostrya::endpoint::EndpointOverrides {
    let mut overrides = connect_overrides(std::mem::take(&mut args.connect));
    #[cfg(feature = "s3")]
    std::mem::take(&mut args.s3).apply(&mut overrides);
    overrides
}

/// Returns the endpoint overrides of the ssh and HTTP options of a push.
///
/// The options are `--ssh-command`, `--receive-command`, and the HTTP options.
/// Each option goes in the field of its name, so the resolver refuses an
/// option of the other transport. The ssh command is split at ASCII
/// whitespace.
#[cfg(feature = "push")]
fn connect_overrides(args: PushConnectArgs) -> ostrya::endpoint::EndpointOverrides {
    let ssh_command = args.ssh_command.map(|command| {
        command
            .split_ascii_whitespace()
            .map(str::to_owned)
            .collect()
    });
    ostrya::endpoint::EndpointOverrides {
        ssh_command,
        remote_command: args.receive_command,
        push_token_file: args.push_token_file,
        push_user: args.push_user,
        tls_ca_path: args.tls_ca_path,
        tls_client_cert_path: args.tls_client_cert_path,
        tls_client_key_path: args.tls_client_key_path,
        allow_cleartext_credentials: args.allow_cleartext_credentials,
        ..Default::default()
    }
}

/// Pushes the directory DIR to a remote over ssh or HTTP, and asks the server
/// to commit it onto the branch of `--onto`, or pushes it to a bucket
/// repository as a new commit.
///
/// The server moves the branch to the new commit and creates each tag at it
/// in one transaction. A push to a bucket repository goes through
/// `BucketRepo::push_tree`, and a writer lock that `--break-lock` removed
/// gives one warning line on standard error.
///
/// # Check order
///
/// 1. [`run`] reads the owner ids.
/// 2. The command checks the operands in the order REMOTE, DIR, and
///    `--onto`, each with the usage text.
/// 3. The command checks the other options that it reads itself, before a
///    repository opens. The body file is not in this step. The timestamp is
///    `--timestamp`, else `SOURCE_DATE_EPOCH`, else none.
/// 4. The command refuses the S3 options and `--break-lock` for a push
///    address that is not an `s3://` address. It resolves the remote. It
///    refuses an option of the other transport and the bad HTTP options. It
///    reads the token file of an HTTP push, and the TLS files of an
///    `https://` push.
/// 5. The command makes the transport ready, or builds the client of the
///    bucket repository.
/// 6. The command reads the body file.
///
/// The push refuses the other bad names and options before the scan. All of
/// these steps come before the ssh client starts or the first HTTP request.
///
/// A remote name is looked up in the repository that `--repo`, the current
/// directory, or `OSTREE_REPO` gives. An address opens no repository, so the
/// command reads none of the three for it.
///
/// # Output
///
/// Standard output carries the commit checksum alone. Under `--verbose`, one
/// statistics line goes to standard error. A failure writes nothing to
/// standard output. On a terminal, standard error shows the progress bar of
/// [`PushBar`] while the push runs.
#[cfg(feature = "push")]
async fn push_tree(
    repo: Option<&Path>,
    verbose: bool,
    name: &str,
    args: PushTreeArgs,
    owner: Owner,
) -> Result<()> {
    let Some(remote) = args.remote.as_deref() else {
        exit_with_error(name, "REMOTE must be specified");
    };
    let Some(dir) = args.dir.as_deref() else {
        exit_with_error(name, "DIR must be specified");
    };
    let Some(onto) = args.onto else {
        exit_with_error(name, "A branch must be specified with --onto");
    };
    macro_rules! refuse {
        ($result:expr) => {
            match $result {
                Ok(value) => value,
                Err(message) => exit_error(&message),
            }
        };
    }
    if let Some(message) = canonical_owner_conflict(args.canonical_permissions, owner) {
        exit_error(&message);
    }
    // The name rule of the push refuses `:`, a name with `^`, and a bad name.
    // This loop refuses a name that a revision reads as a checksum, with the
    // words of `commit`.
    for branch in std::iter::once(&onto).chain(&args.tags) {
        if let Some(message) = shadowed_branch_name(branch) {
            exit_error(&message);
        }
    }
    let strings = refuse!(metadata_pairs(&args.add_metadata_string));
    let variants = refuse!(parse_added_metadata(&args.add_metadata));
    let metadata = refuse!(user_metadata_entries(&strings, &variants));
    let timestamp = match args.timestamp.as_deref() {
        Some(text) => match parse_timestamp(text) {
            Some(seconds) => Some(seconds),
            None => exit_error(&format!("Could not parse '{text}'")),
        },
        None => refuse!(ostrya::source_date_epoch().map_err(|e| e.to_string())),
    };
    // The transport is made ready before the body file is read. A refusal of
    // the remote or of its options then reads no body file.
    #[cfg(feature = "s3")]
    let s3_set = args
        .s3
        .first_set()
        .or(args.break_lock.then_some("--break-lock"));
    #[cfg_attr(not(feature = "s3"), allow(unused_mut))]
    let mut overrides = connect_overrides(args.connect);
    #[cfg(feature = "s3")]
    args.s3.apply(&mut overrides);
    let endpoint = if ostrya::is_push_address(remote) {
        #[cfg(feature = "s3")]
        refuse_s3_options(remote, Some(remote.starts_with("s3://")), &s3_set);
        ostrya::endpoint::resolve_push(None, remote, overrides).await?
    } else {
        let (repo, _) = resolve_repo(repo, verbose, name).await;
        #[cfg(feature = "s3")]
        refuse_s3_options(remote, push_destination_is_s3(&repo, remote), &s3_set);
        ostrya::endpoint::resolve_push(Some(repo.config()), remote, overrides).await?
    };
    let target = match endpoint {
        #[cfg(feature = "s3")]
        ostrya::remote::Endpoint::S3(s3) => {
            TreeTarget::Bucket(ostrya::bucket::BucketRepo::open(&s3).await?)
        }
        endpoint => TreeTarget::Session(ostrya::remote::PushSession::prepare(endpoint).await?),
    };
    // The body file can be large, so it is read after the other checks.
    let body = match args.body_file.as_deref() {
        Some(path) => Some(refuse!(read_body_file(path))),
        None => args.body,
    };
    let (progress, bar) = PushBar::start();
    let opts = ostrya::remote::TreePushOptions {
        onto,
        tags: args.tags,
        bind_refs: args.bind_refs,
        orphan: args.orphan,
        collection: args.collection,
        subject: args.subject,
        body,
        metadata,
        timestamp,
        compression: push_compression(args.compress),
        entry_filter: tree_push_filter(owner, args.canonical_permissions),
        hash_jobs: None,
        progress,
    };
    let outcome = match target {
        #[cfg(feature = "s3")]
        TreeTarget::Bucket(bucket) => {
            let write = {
                let mut write = ostrya::bucket::BucketWriteOptions::default();
                write.break_lock = args.break_lock;
                write
            };
            let pushed = bucket.push_tree(dir, opts, write).await;
            // The bar is cleared before any line of the result or of the
            // error.
            bar.finish();
            let pushed = pushed?;
            if let Some(holder) = &pushed.broken_lock {
                eprintln!("warning: removed the writer lock of {holder}");
            }
            pushed.outcome
        }
        TreeTarget::Session(transport) => {
            let pushed = ostrya::remote::push_tree_prepared(transport, dir, opts).await;
            // The bar is cleared before any line of the result or of the
            // error.
            bar.finish();
            pushed?
        }
    };
    print_server_commit(verbose, outcome)
}

/// The destination of `push-tree`: a transport that is ready, or a bucket
/// repository.
#[cfg(feature = "push")]
enum TreeTarget {
    Session(ostrya::remote::PreparedSession),
    #[cfg(feature = "s3")]
    Bucket(ostrya::bucket::BucketRepo),
}

/// Exits with the refusal of the first option of `set` when the push address
/// of `remote` is not an `s3://` address.
///
/// `s3` is `Some(true)` for an `s3://` push address, `Some(false)` for
/// another address, and `None` if the command cannot tell. For `None`, the
/// resolver states its refusal.
#[cfg(all(feature = "push", feature = "s3"))]
fn refuse_s3_options(remote: &str, s3: Option<bool>, set: &Option<&'static str>) {
    if s3 == Some(false)
        && let Some(option) = set
    {
        exit_error(&format!(
            "{option} applies to an s3:// address, and the push address of '{}' is not one",
            ostrya::remote::without_userinfo(remote)
        ));
    }
}

/// Returns the entry filter of the owner and permission options of `push-tree`.
///
/// The options are `--owner-uid`, `--owner-gid`, and
/// `--canonical-permissions`. If none of them is set, the result is `None`.
///
/// The filter keeps every entry, the root included, and applies the rule of
/// `commit` in this order:
///
/// 1. The canonical reduction. It sets the owner to 0:0 and empties the
///    extended attributes. It reduces the mode of each entry other than a
///    symlink to its file type and `perm & 0755`.
/// 2. Each declared id.
#[cfg(feature = "push")]
fn tree_push_filter(owner: Owner, canonical: bool) -> Option<ostrya::remote::tree::EntryFilter> {
    use ostrya::remote::tree::{EntryAction, EntryKind};
    if !canonical && owner == Owner::default() {
        return None;
    }
    Some(Box::new(move |_path, meta| {
        if canonical {
            meta.uid = 0;
            meta.gid = 0;
            meta.xattrs = Xattrs::empty();
            if meta.kind != EntryKind::Symlink {
                meta.mode = (meta.mode & S_IFMT) | (meta.mode & 0o755);
            }
        }
        if let Some(uid) = owner.uid {
            meta.uid = uid;
        }
        if let Some(gid) = owner.gid {
            meta.gid = gid;
        }
        EntryAction::Keep
    }))
}

/// Returns the line that `push` prints for one ref.
///
/// The line holds the name, the commit before the write or `(new)` or
/// `(absent)`, and the commit after the write or `(deleted)` or `(unchanged)`.
#[cfg(feature = "push")]
fn ref_line(outcome: &ostrya::remote::RefOutcome) -> String {
    let name = &outcome.name;
    match (outcome.old, outcome.new) {
        (None, Some(new)) => format!("{name} (new) {new}"),
        (Some(old), Some(new)) if old == new => format!("{name} {new} (unchanged)"),
        (Some(old), Some(new)) => format!("{name} {old} {new}"),
        (Some(old), None) => format!("{name} {old} (deleted)"),
        (None, None) => format!("{name} (absent) (unchanged)"),
    }
}

/// Returns the statistics line that `push --verbose` writes to standard error.
#[cfg(feature = "push")]
fn push_statistics_line(stats: &ostrya::remote::PushStats) -> String {
    format!(
        "{} objects offered, {} needed, {} sent; {} bytes sent in {:.3} seconds",
        stats.objects_total,
        stats.objects_needed,
        stats.objects_sent,
        stats.bytes_sent,
        stats.elapsed.as_secs_f64()
    )
}

/// The progress bar of `push` and `push-tree` on standard error.
///
/// The hook of a [`PushProgress`](ostrya::remote::PushProgress) drives the bar.
/// `indicatif` draws it at most 20 times a second.
///
/// If standard error is not a terminal, or `TERM` is unset or `dumb`, the bar
/// is hidden and the push gets no progress handle. The session then asks its
/// source for no byte total and calls no hook.
///
/// The bar shows these stages:
///
/// - Before the push reaches `Negotiating`, the bar shows nothing, so the
///   prompts of the ssh client and of a signer stay readable.
/// - While the session negotiates, the bar shows a spinner.
/// - While the session uploads, the bar shows the content bytes.
/// - When the push reaches `Committing`, the bar clears and shows nothing more.
///   A line that the server writes on standard error at the commit then starts
///   on a clean line.
#[cfg(feature = "push")]
struct PushBar {
    bar: indicatif::ProgressBar,
    /// The stage that the bar shows, one of the `STAGE_` constants. The stage
    /// only increases.
    stage: std::sync::atomic::AtomicU8,
    /// The object counts of the upload, which the bar reads when it draws.
    objects: Arc<ObjectCounts>,
}

/// The counts of the objects sent and needed in an upload.
///
/// The `{objects}` key of the upload templates writes these counts.
#[cfg(feature = "push")]
#[derive(Default)]
struct ObjectCounts {
    sent: std::sync::atomic::AtomicU64,
    needed: std::sync::atomic::AtomicU64,
}

/// The stage before the push reaches `Negotiating`, in which the bar shows
/// nothing.
#[cfg(feature = "push")]
const STAGE_HIDDEN: u8 = 0;
/// The stage of the negotiation, in which the bar shows a spinner.
#[cfg(feature = "push")]
const STAGE_NEGOTIATING: u8 = 1;
/// The stage of the upload, in which the bar shows the content bytes.
#[cfg(feature = "push")]
const STAGE_UPLOADING: u8 = 2;
/// The stage after the bar clears, in which the bar shows nothing more.
#[cfg(feature = "push")]
const STAGE_DONE: u8 = 3;

/// The bar template of the negotiation.
#[cfg(feature = "push")]
const NEGOTIATING_TEMPLATE: &str = "{spinner} Negotiating";
/// The bar template of the upload with a known byte total.
#[cfg(feature = "push")]
const BAR_TEMPLATE: &str =
    "{objects} [{wide_bar}] {percent:>3}% {bytes}/{total_bytes} {binary_bytes_per_sec} {eta}";
/// The bar template of the upload with no known byte total.
#[cfg(feature = "push")]
const BYTES_TEMPLATE: &str = "{spinner} {objects} {bytes} {binary_bytes_per_sec}";

#[cfg(feature = "push")]
impl PushBar {
    /// Creates a new bar and the progress handle whose hook drives the bar.
    ///
    /// If the bar is hidden, the handle is `None`.
    fn start() -> (Option<ostrya::remote::PushProgress>, Arc<PushBar>) {
        let bar = Arc::new(PushBar {
            bar: indicatif::ProgressBar::with_draw_target(
                None,
                indicatif::ProgressDrawTarget::stderr(),
            ),
            stage: std::sync::atomic::AtomicU8::new(STAGE_HIDDEN),
            objects: Arc::default(),
        });
        if bar.bar.is_hidden() {
            return (None, bar);
        }
        let hooked = Arc::clone(&bar);
        let progress = ostrya::remote::PushProgress::with_hook(Arc::new(move |snapshot| {
            hooked.update(snapshot)
        }));
        (Some(progress), bar)
    }

    /// Shows `snapshot` on the bar.
    ///
    /// The style changes only if the stage changes. A snapshot of an earlier
    /// stage changes nothing.
    fn update(&self, snapshot: &ostrya::remote::PushProgressSnapshot) {
        use ostrya::remote::PushPhase;
        let stage = match snapshot.phase {
            PushPhase::Negotiating => STAGE_NEGOTIATING,
            PushPhase::Uploading => STAGE_UPLOADING,
            PushPhase::Committing => STAGE_DONE,
            _ => return,
        };
        if stage == STAGE_UPLOADING {
            self.objects
                .sent
                .store(snapshot.objects_sent, Ordering::Relaxed);
            self.objects
                .needed
                .store(snapshot.objects_needed, Ordering::Relaxed);
        }
        let before = self.stage.fetch_max(stage, Ordering::Relaxed);
        if before > stage {
            return;
        }
        if before < stage {
            self.enter(before, stage, snapshot.bytes_total);
        }
        if stage == STAGE_UPLOADING {
            self.bar.set_position(snapshot.content_bytes);
        }
    }

    /// Changes the bar from the stage `before` to `stage`.
    fn enter(&self, before: u8, stage: u8, bytes_total: u64) {
        let style = |template: &str| {
            let objects = Arc::clone(&self.objects);
            indicatif::ProgressStyle::with_template(template)
                .expect("the template is valid")
                .with_key(
                    "objects",
                    move |_: &indicatif::ProgressState, w: &mut dyn std::fmt::Write| {
                        let _ = write!(
                            w,
                            "{}/{} objects",
                            objects.sent.load(Ordering::Relaxed),
                            objects.needed.load(Ordering::Relaxed)
                        );
                    },
                )
        };
        match stage {
            STAGE_NEGOTIATING => self.bar.set_style(style(NEGOTIATING_TEMPLATE)),
            STAGE_UPLOADING => {
                // The rate and the time left count from the first object.
                self.bar.reset_elapsed();
                if bytes_total > 0 {
                    self.bar.set_length(bytes_total);
                    self.bar.set_style(style(BAR_TEMPLATE));
                } else {
                    self.bar.unset_length();
                    self.bar.set_style(style(BYTES_TEMPLATE));
                }
            }
            _ => {
                self.clear(before);
                return;
            }
        }
        // The spinner turns between two updates. A hidden bar starts no
        // thread for it.
        if before == STAGE_HIDDEN && !self.bar.is_hidden() {
            self.bar
                .enable_steady_tick(std::time::Duration::from_millis(100));
        }
    }

    /// Clears the bar from the terminal if the stage `before` showed it.
    fn clear(&self, before: u8) {
        if before != STAGE_HIDDEN && before != STAGE_DONE {
            self.bar.disable_steady_tick();
            self.bar.finish_and_clear();
        }
    }

    /// Clears the bar if it shows, and stops all later drawing.
    fn finish(&self) {
        self.clear(self.stage.swap(STAGE_DONE, Ordering::Relaxed));
    }
}

/// Returns the name of a step of the receive report for its warning line.
#[cfg(any(feature = "receive", feature = "serve"))]
fn receive_step(step: ostrya::ReceiveStep) -> &'static str {
    match step {
        ostrya::ReceiveStep::SummaryBuild => "summary-build",
        ostrya::ReceiveStep::SummarySign => "summary-sign",
        ostrya::ReceiveStep::SummaryWrite => "summary-write",
        ostrya::ReceiveStep::PartialMarker => "partial-marker",
        ostrya::ReceiveStep::ReplyNotDelivered => "reply-not-delivered",
    }
}

/// Ends the process with `code`.
///
/// This is the one exit of the CLI that does not return through [`main`].
/// `std::process::exit` runs no destructor. If a subcommand exits while a
/// transaction is live, its staging directory under `tmp/` stays.
///
/// Before the exit, `ostrya::reap_process_staging` removes the staging
/// directory of each live transaction. A refusal at any exit site of any
/// subcommand then writes no object, moves no ref, and leaves `tmp/` as it
/// found it.
fn exit_process(code: i32) -> ! {
    ostrya::reap_process_staging();
    std::process::exit(code);
}

/// Prints the top-level usage text and an error line, then exits 1.
///
/// This is the result of a bare invocation. The error line and the exit are
/// the same as those of the `ostree` command.
fn exit_no_command() -> ! {
    eprint!("{}", <Cli as CommandFactory>::command().render_help());
    eprintln!("error: No command specified");
    exit_process(1);
}

/// Prints the usage text of `subcommand` and `error: {message}`, then exits 1.
///
/// This is the two-line error form of the `ostree` command: the usage block,
/// then an `error: ` line. It applies to a missing repository, a missing
/// required operand, and a missing nested subcommand.
fn exit_with_error(subcommand: &str, message: &str) -> ! {
    let mut top = <Cli as CommandFactory>::command();
    let sub = top
        .find_subcommand_mut(subcommand)
        .expect("subcommand name matches a defined command");
    eprint!("{}", sub.render_help());
    eprintln!("error: {message}");
    exit_process(1);
}

/// Prints the usage text of a nested subcommand and an error, then exits 1.
///
/// The error line is `error: {message}`. The `ostree` command gives this form
/// for a `remote add` or a `remote delete` with a missing operand.
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

/// Prints `error: {message}` with no usage text, then exits 1.
///
/// The `ostree` command uses this form after a subcommand starts and has its
/// arguments.
fn exit_error(message: &str) -> ! {
    eprintln!("error: {message}");
    exit_process(1);
}

/// Prints the usage text and the error for no repository, then exits 1.
///
/// The usage text is the text of `subcommand`. The `ostree` command gives the
/// same error line and exit if it cannot resolve a repository.
fn exit_requires_repo(subcommand: &str) -> ! {
    exit_with_error(subcommand, "Command requires a --repo argument")
}

/// Resolves the repository of a subcommand and the file system path to it.
///
/// # Precedence
///
/// 1. An explicit `--repo`, in either position. If this repository does not
///    open, the process ends with an error.
/// 2. The current directory, if it opens as a repository.
/// 3. `OSTREE_REPO`, if it opens as a repository.
///
/// The chain ends there. The `ostree` command has one more source after
/// `OSTREE_REPO`, the compiled-in `/sysroot/ostree/repo`. ostrya does not use
/// this source, so an omitted `--repo` never makes `ostrya` act on a live
/// system repository.
///
/// If no source gives a repository, the function prints the usage text of
/// `subcommand` and the error line of `ostree`, then exits.
///
/// `init` uses the same precedence through [`resolve_init_path`]. That function
/// returns a path, because the explicit `--repo` path of `init` does not need
/// to exist.
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

/// Resolves the path at which `init` creates or reuses a repository.
///
/// The precedence is the precedence of [`resolve_repo`], with these changes:
///
/// - An explicit `--repo` path is used as given, valid or not, because the new
///   repository does not need to exist there.
/// - The current directory and `OSTREE_REPO` apply only if the path opens as a
///   repository. Then the call is an idempotent re-init.
///
/// `init` never creates a new repository at a path that it did not get
/// explicitly. If no source gives a path, [`exit_requires_repo`] ends the
/// process.
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

/// Creates a new empty repository, or reuses one at the resolved path.
///
/// The reuse is idempotent, as in `Repo::create`.
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

/// Returns the repository mode for a value of `ostrya init --mode`.
///
/// The accepted set is the set of the `ostree` command for the modes that both
/// commands support. The set also holds `bare-user-shared`, an ostrya
/// extension. An unknown value ends the process with an error.
///
/// `bare-split-xattrs` is not in the set, although `init --mode` of `ostree`
/// accepts it. ostrya reads that mode and does not write it, so a repository in
/// that mode cannot take a commit from ostrya.
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

/// The low-speed rule that a `pull` command line names.
///
/// A field is `None` if its option is absent or negative.
struct LowSpeedArgs {
    limit: Option<u32>,
    seconds: Option<u32>,
}

/// Reads one `--low-speed-*` value.
///
/// If the option is absent or its value is negative, the result is `None`. The
/// `ostree` command also keeps the default in this case. The value is read as a
/// C `int` and refused in the words of `--owner-uid`. `ostree` reads and
/// refuses both values in the same way.
fn low_speed_value(value: Option<&str>, flag: &str) -> Option<u32> {
    owner_id(value, flag)
}

/// Returns the redraw interval of the progress line for `--update-frequency`.
///
/// `None` and 0 give the default of 1000 ms.
fn update_interval(frequency: Option<u32>) -> std::time::Duration {
    match frequency {
        None | Some(0) => std::time::Duration::from_millis(1000),
        Some(ms) => std::time::Duration::from_millis(ms.into()),
    }
}

/// Fetches refs and their objects from an HTTP remote, over ssh, or from a
/// bucket repository at an `s3://` address.
///
/// If standard output is a terminal, it carries a progress line that is
/// redrawn every `redraw`. The statistics line is then drawn over the progress
/// line. Other standard output carries the statistics line alone.
async fn pull(
    repo: Repo,
    name: &str,
    args: PullArgs,
    low_speed: LowSpeedArgs,
    redraw: std::time::Duration,
) -> Result<()> {
    // With `--collection`, each operand is a ref of the collection.
    let (from, refs) = match args.collection {
        Some(id) => {
            let remotes = collection_candidates(&repo, &id)?;
            let refs = args.remote.into_iter().chain(args.refs).collect();
            (PullFrom::Collection { id, remotes }, refs)
        }
        None => match args.remote {
            Some(remote) => (PullFrom::Remote(remote), args.refs),
            None => exit_with_error(name, "REMOTE must be specified"),
        },
    };
    // The S3 options apply to a pull from an `s3://` address alone.
    #[cfg(feature = "s3")]
    let base = match &from {
        PullFrom::Collection { remotes, .. } => {
            if let Some(option) = args.s3.s3.first_set() {
                exit_error(&format!(
                    "{option} applies to one remote, and a pull with --collection takes the S3 \
                     settings of each candidate from the config"
                ));
            }
            // A candidate whose address the resolver refuses passes this
            // check, so that the resolver states its refusal.
            let cleartext = args.s3.allow_cleartext_credentials;
            if cleartext
                && let Some(remote) = remotes.iter().find(|remote| {
                    ostrya::endpoint::pull_address_is_s3(Some(repo.config()), remote, None)
                        == Some(false)
                })
            {
                exit_error(&format!(
                    "--allow-cleartext-credentials applies to an s3:// address, and the pull \
                     address of remote '{remote}' is not one"
                ));
            }
            ostrya::endpoint::EndpointOverrides {
                allow_cleartext_credentials: cleartext,
                ..Default::default()
            }
        }
        PullFrom::Remote(remote) => args.s3.pull_overrides(&repo, remote, args.url.as_deref()),
    };
    #[cfg(not(feature = "s3"))]
    let base = ostrya::endpoint::EndpointOverrides::default();
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
    if args.untrusted {
        flags |= PullFlags::UNTRUSTED;
    }
    // `--http-trusted` asks the pull to store a fetched object with no
    // verification of its checksum. ostrya ignores the switch and verifies the
    // checksum of every object.
    let _ = args.http_trusted;
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

    let terminal = std::io::IsTerminal::is_terminal(&std::io::stdout());
    let progress = terminal.then(PullProgress::new);
    let overrides = ostrya::endpoint::EndpointOverrides {
        url: args.url,
        http_headers: args.http_header,
        // `--disable-retry-on-network-errors` wins over `--network-retries`,
        // in either order.
        max_retries: if args.disable_retry_on_network_errors {
            Some(0)
        } else {
            args.network_retries
        },
        low_speed_limit_bytes: low_speed.limit,
        low_speed_time: low_speed
            .seconds
            .map(|seconds| std::time::Duration::from_secs(seconds.into())),
        ..base
    };
    let line = progress
        .clone()
        .map(|progress| ProgressLine::start(progress, redraw));
    let opts = PullOptions {
        refs,
        flags,
        depth: args.depth,
        localcache_repos,
        disable_fsync: args.disable_fsync,
        per_object_fsync: args.per_object_fsync,
        subpaths: args.subpath,
        overrides,
        max_outstanding_fetches: args.max_outstanding_fetcher_requests,
        timestamp_check,
        disable_static_deltas: args.disable_static_deltas,
        require_static_deltas: args.require_static_deltas,
        verify: PullVerify {
            gpg: args.gpg_verify,
            gpg_summary: args.gpg_verify_summary,
            sign: args.sign_verify,
            sign_summary: args.sign_verify_summary,
        },
        progress,
        ..PullOptions::default()
    };
    let pulled = match from {
        PullFrom::Remote(remote) => repo.pull(&remote, opts).await,
        PullFrom::Collection { id, remotes } => {
            let remotes: Vec<&str> = remotes.iter().map(String::as_str).collect();
            let mut collection = CollectionPullOptions::default();
            collection.pull = opts;
            collection.on_event = Some(Box::new(|event| eprintln!("warning: {event}")));
            repo.pull_collection(&id, &remotes, collection)
                .await
                .map(|pulled| pulled.stats)
        }
    };
    let prefix = line.map_or("", ProgressLine::finish);
    let stats = match pulled {
        Ok(stats) => stats,
        Err(e) => {
            // The error goes to standard error, on a line of its own.
            if terminal {
                println!("{prefix}");
            }
            return Err(e);
        }
    };
    let mut text = statistics_line(&stats, PullSource::Http);
    if terminal {
        // The statistics line is drawn over the progress line and padded as
        // the progress line is.
        pad_line(&mut text, 0);
        println!("{prefix}\x1b8{text}");
    } else {
        println!("{text}");
    }
    Ok(())
}

/// What a pull reads from.
enum PullFrom {
    /// One remote, a section of the config.
    Remote(String),
    /// The remotes of the config whose `collection-id` is `id`, in the order
    /// of the config.
    Collection { id: String, remotes: Vec<String> },
}

/// Returns the remotes of the config of `repo` whose `collection-id` is `id`,
/// in the order of the config.
///
/// If no remote has the id, the command ends with an error. A refused id
/// goes on to the pull, which states the refusal. The function reads the key
/// of each remote, so a malformed value in any remote fails the command.
fn collection_candidates(repo: &Repo, id: &str) -> Result<Vec<String>> {
    let config = repo.config();
    let mut candidates = Vec::new();
    for name in config.remotes() {
        let Some(remote) = config.remote(name) else {
            continue;
        };
        if remote.collection_id()?.as_deref() == Some(id) {
            candidates.push(name.to_owned());
        }
    }
    if candidates.is_empty() && ostrya::is_collection_id(id) {
        exit_error(&format!("no remote has collection-id {id}"));
    }
    Ok(candidates)
}

/// The progress line of a pull on a terminal, redrawn on a thread of its own.
///
/// Each redraw restores the cursor position (`ESC 8`) and writes the line
/// padded to [`PROGRESS_COLUMNS`] bytes. The first redraw saves the position
/// (`ESC 7`) in the same write.
struct ProgressLine {
    /// The sender whose drop stops the thread.
    stop: std::sync::mpsc::Sender<()>,
    /// The thread. Its result is `true` if the thread wrote `ESC 7`.
    thread: std::thread::JoinHandle<bool>,
}

impl ProgressLine {
    /// Starts to redraw the counters of `progress` every `redraw`.
    fn start(progress: PullProgress, redraw: std::time::Duration) -> ProgressLine {
        use std::io::Write;
        let (stop, stopped) = std::sync::mpsc::channel::<()>();
        let started = std::time::Instant::now();
        let thread = std::thread::spawn(move || {
            let mut out = std::io::stdout();
            // One buffer serves every redraw.
            let mut line = String::new();
            let mut saved = false;
            while let Err(std::sync::mpsc::RecvTimeoutError::Timeout) = stopped.recv_timeout(redraw)
            {
                if !saved {
                    line.push_str("\x1b7");
                    saved = true;
                }
                line.push_str("\x1b8");
                let from = line.len();
                progress_text(&mut line, &progress.snapshot(), started.elapsed());
                pad_line(&mut line, from);
                let _ = out.write_all(line.as_bytes());
                let _ = out.flush();
                line.clear();
            }
            saved
        });
        ProgressLine { stop, thread }
    }

    /// Stops the redraw, waits for the thread, and returns the prefix of the
    /// last write.
    ///
    /// If no redraw saved the cursor position, the prefix is `ESC 7`, because
    /// the `ostree` command saves the position when the pull starts. Otherwise
    /// the prefix is empty.
    fn finish(self) -> &'static str {
        drop(self.stop);
        match self.thread.join() {
            Ok(true) => "",
            _ => "\x1b7",
        }
    }
}

/// The width in bytes to which a line on a terminal is padded with spaces.
///
/// The value is the width of a terminal of 80 columns. ostrya does not read the
/// width of the terminal. A longer line is written whole, and on a wider
/// terminal the padding still stops at 80 bytes.
const PROGRESS_COLUMNS: usize = 80;

/// Pads the text of `line` from byte `from` with spaces to
/// [`PROGRESS_COLUMNS`] bytes.
///
/// A longer text is not cut.
fn pad_line(line: &mut String, from: usize) {
    let width = line.len() - from;
    line.extend(std::iter::repeat_n(
        ' ',
        PROGRESS_COLUMNS.saturating_sub(width),
    ));
}

/// Appends the progress text of a pull to `line`.
///
/// The text comes from the counters of the pull, `elapsed` after it started.
/// It has three forms:
///
/// - the delta parts, while a delta part is still to arrive
/// - the metadata walk, while a commit or a dirtree is queued
/// - the objects, in all other cases
///
/// The rate is the bytes transferred over the whole elapsed time. It reads `-`
/// until a whole second passes.
fn progress_text(line: &mut String, s: &PullProgressSnapshot, elapsed: std::time::Duration) {
    use std::fmt::Write;
    let rate = (elapsed.as_secs() > 0)
        .then(|| (s.bytes_transferred as f64 / elapsed.as_secs_f64()) as u64);
    let rate_text = rate.map_or_else(|| "-".to_owned(), format_size);
    if s.delta_parts_fetched < s.delta_parts_total {
        let _ = write!(
            line,
            "Receiving delta parts: {}/{} {}/{} {rate_text}/s",
            s.delta_parts_fetched,
            s.delta_parts_total,
            format_size(s.delta_bytes_fetched),
            format_size(s.delta_bytes_total),
        );
        if let Some(rate) = rate.filter(|rate| *rate > 0) {
            let left = s.delta_bytes_total.saturating_sub(s.delta_bytes_fetched) / rate;
            let _ = write!(line, " {left} seconds remaining");
        }
        return;
    }
    if s.scanning {
        let _ = write!(
            line,
            "Receiving metadata objects: {}/(estimating) {rate_text}/s {}",
            s.metadata_fetched,
            format_size(s.bytes_transferred)
        );
        return;
    }
    let percent = if s.objects_total == 0 {
        0
    } else {
        u64::from(s.objects_done) * 100 / u64::from(s.objects_total)
    };
    let _ = write!(
        line,
        "Receiving objects: {percent}% ({}/{}) {rate_text}/s {}",
        s.objects_done,
        s.objects_total,
        format_size(s.bytes_transferred)
    );
}
/// Reads a size option in decimal megabytes into bytes.
///
/// The `ostree` command also reads the option in decimal megabytes. ostrya
/// accepts only ASCII digits. It refuses a value that `ostree` reads leniently
/// (`abc`, `1.5`, `-1`, ` 3`, `+3`, `3x`), and a value of more than
/// `u64::MAX` bytes.
fn parse_megabytes(text: &str) -> std::result::Result<u64, String> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err("expected a whole number of megabytes".to_owned());
    }
    text.parse::<u64>()
        .ok()
        .and_then(|mb| mb.checked_mul(1_000_000))
        .ok_or_else(|| "the size is past the largest byte count".to_owned())
}

/// Splits a `NAME=VALUE` header argument at its first `=`.
///
/// An empty NAME is refused.
fn parse_http_header(arg: &str) -> std::result::Result<(String, String), String> {
    match arg.split_once('=') {
        Some((name, value)) if !name.is_empty() => Ok((name.to_owned(), value.to_owned())),
        _ => Err("expected NAME=VALUE".to_owned()),
    }
}

/// The source of the objects of a pull, which selects the statistics line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PullSource {
    /// An HTTP or ssh remote, or another local repository that the pull reads
    /// as a fetch because it requires static deltas.
    Http,
    /// Another local repository.
    Local,
}

/// Returns the success line of a pull, in the words of the `ostree` command.
fn statistics_line(stats: &PullStats, source: PullSource) -> String {
    let written = format_size(stats.content_bytes_unpacked);
    if source == PullSource::Local {
        return format!(
            "{} metadata, {} content objects imported; {written} content written",
            stats.metadata_imported, stats.content_imported
        );
    }
    let fetched = if stats.delta_parts > 0 {
        format!(
            "{} delta parts, {} loose fetched",
            stats.delta_parts,
            stats.metadata_fetched + stats.content_fetched
        )
    } else {
        format!(
            "{} metadata, {} content objects fetched",
            stats.metadata_fetched, stats.content_fetched
        )
    };
    // If a pull read no body byte after the summary and the config, the line
    // states no transfer. The line of the `ostree` command does the same.
    if stats.bytes_transferred == 0 {
        return format!("{fetched}; {written} content written");
    }
    format!(
        "{fetched}; {} transferred in {} seconds; {written} content written",
        format_transferred(stats.bytes_transferred),
        stats.elapsed.as_secs()
    )
}

/// Returns a transferred byte count in the words of the `ostree` command.
///
/// A count of less than 1024 is `N B`. A count of 1024 or more is the whole
/// KiB, rounded down.
fn format_transferred(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else {
        format!("{} KiB", bytes / 1024)
    }
}

/// Runs the one action of `composefs-image` that `args` names.
async fn composefs_image(repo: Repo, args: ComposefsImageArgs) -> Result<()> {
    if let Some(rev) = args.add {
        let commit = resolve(&repo, &rev).await?;
        repo.add_composefs_image(&commit).await?;
        return Ok(());
    }
    if let Some(rev) = args.get_path {
        let commit = resolve(&repo, &rev).await?;
        if !repo.has_object(ObjectType::ComposefsImage, &commit).await? {
            exit_error(&format!("commit {commit} has no composefs image"));
        }
        let path = std::path::absolute(repo.composefs_image_path(&commit))?;
        println!("{}", path.display());
        return Ok(());
    }
    let rev = args.check.expect("clap requires one action");
    let commit = resolve(&repo, &rev).await?;
    match repo.check_composefs_image(&commit).await? {
        ComposefsImageState::Valid => Ok(()),
        ComposefsImageState::Absent => {
            exit_error(&format!("commit {commit} has no composefs image"))
        }
        ComposefsImageState::NoKey => exit_error(&format!(
            "commit {commit} does not carry {COMPOSEFS_DIGEST_KEY}"
        )),
        ComposefsImageState::Mismatch { expected, actual } => Err(Error::ComposefsDigestMismatch {
            commit,
            expected,
            actual,
        }),
    }
}

/// Imports refs and their objects from another local repository.
async fn pull_local(repo: Repo, name: &str, args: PullLocalArgs) -> Result<()> {
    let Some(src_repo) = args.src_repo.as_deref() else {
        // For this case, the message of the `ostree` command names
        // DESTINATION. This is an observed quirk of `ostree`, and ostrya
        // copies it on purpose.
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
                disable_fsync: args.disable_fsync,
                per_object_fsync: args.per_object_fsync,
                require_static_deltas: args.require_static_deltas,
                disable_static_deltas: args.disable_static_deltas,
                // `clap` refuses a switch together with its off switch, so
                // each pair gives one value or none.
                verify: PullVerify {
                    gpg: (args.gpg_verify || args.no_gpg_verify).then_some(args.gpg_verify),
                    gpg_summary: (args.gpg_verify_summary || args.no_gpg_verify_summary)
                        .then_some(args.gpg_verify_summary),
                    sign: (args.sign_verify || args.no_sign_verify).then_some(args.sign_verify),
                    sign_summary: (args.sign_verify_summary || args.no_sign_verify_summary)
                        .then_some(args.sign_verify_summary),
                },
                trust_group: args.trust,
                ..PullOptions::default()
            },
        )
        .await?;
    // A pull that requires static deltas reads the source as a fetch, and the
    // `ostree` command reports it in the words of a fetch.
    let source = if args.require_static_deltas {
        PullSource::Http
    } else {
        PullSource::Local
    };
    println!("{}", statistics_line(&stats, source));
    Ok(())
}

/// Runs one `static-delta` subcommand.
///
/// The subcommands do these operations:
///
/// - list the static deltas of the repository
/// - apply one delta offline
/// - generate one delta
/// - rebuild the index cache, or the index of one target
/// - show one delta
/// - delete one delta
/// - list the index cache
/// - verify the signatures of one delta
async fn static_delta(repo: Repo, repo_path: PathBuf, command: StaticDeltaCommand) -> Result<()> {
    match command {
        StaticDeltaCommand::List => {
            let names = repo.list_static_deltas().await?;
            if names.is_empty() {
                println!("(No static deltas)");
            }
            for name in names {
                println!("{name}");
            }
            Ok(())
        }
        StaticDeltaCommand::ApplyOffline(apply) => delta_apply_offline(&repo, apply).await,
        StaticDeltaCommand::Generate(generate) => delta_generate(&repo, &repo_path, generate).await,
        StaticDeltaCommand::Reindex(args) => match args.to {
            None => repo.reindex_static_deltas().await,
            Some(rev) => {
                let to = delta_name_half(&rev).unwrap_or_else(|text| exit_error(&text));
                repo.reindex_static_deltas_to(&to).await
            }
        },
        StaticDeltaCommand::Show { delta } => delta_show(&repo_path, delta).await,
        StaticDeltaCommand::Delete { delta } => delta_delete(&repo, delta).await,
        StaticDeltaCommand::Indexes => {
            let indexes = repo.list_static_delta_indexes().await?;
            if indexes.is_empty() {
                println!("(No static deltas indexes)");
            }
            for to in indexes {
                println!("{}", to.to_hex());
            }
            Ok(())
        }
        StaticDeltaCommand::Verify(args) => delta_verify(&repo_path, args).await,
    }
}

/// Reads one half of a delta name: 64 lowercase hex characters.
///
/// `Err` holds the refusal text of the `ostree` command. For a half of the
/// wrong length, the text names at most the first 64 bytes. For a half of the
/// right length, it names the decimal value of the first byte outside
/// `[0-9a-f]`.
fn delta_name_half(half: &str) -> std::result::Result<Checksum, String> {
    let bytes = half.as_bytes();
    if bytes.len() != 64 {
        let shown = String::from_utf8_lossy(&bytes[..bytes.len().min(64)]);
        return Err(format!("Invalid rev {shown}"));
    }
    if let Some(&bad) = bytes
        .iter()
        .find(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(format!("Invalid character '{bad}' in rev '{half}'"));
    }
    Checksum::from_hex_lower(half).map_err(|_| format!("Invalid rev {half}"))
}

/// Reads a delta name, `TO` or `FROM-TO`, split at the first `-`.
fn parse_delta_name(arg: &str) -> std::result::Result<(Option<Checksum>, Checksum), String> {
    match arg.split_once('-') {
        Some((from, to)) => Ok((Some(delta_name_half(from)?), delta_name_half(to)?)),
        None => Ok((None, delta_name_half(arg)?)),
    }
}

/// The files of a `static-delta` argument, and their names in the refusals.
struct DeltaFiles {
    superblock: PathBuf,
    superblock_shown: String,
    parts: PathBuf,
    parts_shown: String,
}

/// Resolves a `static-delta` argument to its files.
///
/// An argument that holds `/` is the path of a superblock file. Its parts are
/// read from the directory that holds it. Any other argument is a delta name,
/// read under the `deltas/` tree of the repository. If the parser refuses a
/// name, the result is `Err` with the text of the parser.
fn resolve_delta_arg(repo_path: &Path, arg: &str) -> std::result::Result<DeltaFiles, String> {
    if arg.contains('/') {
        let superblock = PathBuf::from(arg);
        let parts = superblock
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .to_owned();
        return Ok(DeltaFiles {
            superblock_shown: arg.to_owned(),
            parts_shown: parts.display().to_string(),
            superblock,
            parts,
        });
    }
    let (from, to) = parse_delta_name(arg)?;
    let relative = ostrya::static_delta_relative_dir(from.as_ref(), &to);
    Ok(DeltaFiles {
        superblock: repo_path.join(&relative).join("superblock"),
        superblock_shown: format!("{relative}/superblock"),
        parts: repo_path.join(&relative),
        parts_shown: relative,
    })
}

/// Returns the words of the `ostree` command for a failed delta file read.
///
/// For a system error, the text is `Is a directory` for a directory, and
/// `openat(<path>): <reason>` for every other system error. For any other
/// error, the result is `None`.
fn delta_read_text(err: &Error, shown: &str) -> Option<String> {
    match err {
        Error::Io(io) if io.kind() == std::io::ErrorKind::IsADirectory => {
            Some("Is a directory".to_owned())
        }
        Error::Io(io) if io.raw_os_error().is_some() => {
            Some(format!("openat({shown}): {}", io_reason(io)))
        }
        _ => None,
    }
}

/// Returns the error of a failed delta file read, or ends the process.
///
/// If [`delta_read_text`] gives a text, the process exits 1 with this text.
/// Any other error is returned.
fn delta_read_error(err: Error, shown: &str) -> Error {
    match delta_read_text(&err, shown) {
        Some(text) => exit_error(&text),
        None => err,
    }
}

/// Removes one static delta by name.
///
/// A path is read as a name, so the name parser refuses it. The `ostree`
/// command also refuses it.
async fn delta_delete(repo: &Repo, delta: Option<String>) -> Result<()> {
    let Some(arg) = delta else {
        exit_error("DELTA must be specified");
    };
    let (from, to) = parse_delta_name(&arg).unwrap_or_else(|text| exit_error(&text));
    repo.delete_static_delta(from.as_ref(), &to).await
}

/// Prints the superblock fields of a delta and the statistics of each part.
///
/// The command prints one line at a time, so the lines before a refusal reach
/// standard output.
async fn delta_show(repo_path: &Path, delta: Option<String>) -> Result<()> {
    let Some(arg) = delta else {
        exit_error("DELTA must be specified");
    };
    let files = resolve_delta_arg(repo_path, &arg).unwrap_or_else(|text| exit_error(&text));
    let sb = DeltaSuperblock::read(&files.superblock)
        .await
        .map_err(|err| delta_read_error(err, &files.superblock_shown))?;

    println!("Delta: {arg}");
    println!("Signed: {}", if sb.is_signed() { "yes" } else { "no" });
    match sb.from_commit() {
        Some(from) => println!("From: {}", from.to_hex()),
        None => println!("From <scratch>"),
    }
    println!("To: {}", sb.to_commit().to_hex());
    let endianness = match sb.endianness() {
        DeltaEndianness::Little => "little",
        DeltaEndianness::Big => "big",
    };
    println!("Endianness: {endianness}");
    println!("Timestamp: {}", sb.timestamp());
    println!("Number of parents: {}", sb.parent_count());
    println!("Number of fallback entries: {}", sb.fallbacks().len());
    // The sums wrap, as unsigned arithmetic does, if the sizes of a crafted
    // superblock overflow.
    let (mut fallback_size, mut fallback_usize) = (0u64, 0u64);
    for fallback in sb.fallbacks() {
        println!("  {}", fallback.checksum().to_hex());
        fallback_size = fallback_size.wrapping_add(fallback.size());
        fallback_usize = fallback_usize.wrapping_add(fallback.uncompressed_size());
    }
    print_delta_size("Total Fallback Size", fallback_size);
    print_delta_size("Total Fallback Uncompressed Size", fallback_usize);
    println!("Number of parts: {}", sb.parts().len());

    let (mut part_size, mut part_usize) = (0u64, 0u64);
    for (i, part) in sb.parts().iter().enumerate() {
        println!(
            "PartMeta{i}: nobjects={} size={} usize={}",
            part.objects().len(),
            part.size(),
            part.uncompressed_size()
        );
        let stats = sb
            .part_stats(i, &files.parts)
            .await
            .map_err(|err| delta_read_error(err, &format!("{}/{i}", files.parts_shown)))?;
        println!(
            "PartPayload{i}: nmodes={} nxattrs={} blobsize={} opsize={}",
            stats.modes, stats.xattrs, stats.blob_size, stats.ops_size
        );
        let ops = stats.ops;
        println!(
            "PartPayloadOps{i}: openspliceclose={} open={} write={} setread={} unsetread={} \
             close={} bspatch={}",
            ops.open_splice_close,
            ops.open,
            ops.write,
            ops.set_read_source,
            ops.unset_read_source,
            ops.close,
            ops.bspatch
        );
        part_size = part_size.wrapping_add(part.size());
        part_usize = part_usize.wrapping_add(part.uncompressed_size());
    }
    print_delta_size("Total Part Size", part_size);
    print_delta_size("Total Part Uncompressed Size", part_usize);
    print_delta_size("Total Size", part_size.wrapping_add(fallback_size));
    print_delta_size(
        "Total Uncompressed Size",
        part_usize.wrapping_add(fallback_usize),
    );
    Ok(())
}

/// The maximum size of a `--keys-file` for an ed25519 or spki verify.
///
/// The limit applies to `sign --verify`, `summary --verify`, and
/// `static-delta verify`. It is the limit that the key store of the `ostrya`
/// library applies to each of its files.
const VERIFY_KEYS_FILE_LIMIT: u64 = 1024 * 1024;

/// The keys of an ed25519 or spki verify.
///
/// The keys are the verifier, and the trusted and revoked keys in load order.
/// The failure line of `static-delta verify` names the keys from these lists.
struct VerifyKeys {
    verifier: Box<dyn Verifier>,
    trusted: Vec<Vec<u8>>,
    revoked: Vec<Vec<u8>>,
}

/// Prints `Verification fails` and `error: {text}`, then exits 1.
///
/// The first line goes to standard output, and the second line goes to
/// standard error. Every failure of `static-delta verify` after the keys load
/// has this form.
fn verification_fails(text: &str) -> ! {
    println!("Verification fails");
    exit_error(text)
}

/// Verifies the signatures of a static delta.
///
/// The checks come in the order of the `ostree` command:
///
/// 1. The argument is present.
/// 2. ostrya supports the sign type.
/// 3. The keys load.
/// 4. The argument resolves, and the superblock reads.
/// 5. The signatures verify.
///
/// Every failure from step 4 on prints `Verification fails` first.
async fn delta_verify(repo_path: &Path, args: DeltaVerifyArgs) -> Result<()> {
    let Some(arg) = args.delta else {
        exit_error("DELTA must be specified");
    };
    let engine = verify_sign_type(args.sign_type.as_deref().unwrap_or("ed25519"), true);
    let keys = load_verify_keys(
        engine,
        &args.key_id,
        args.keys_file.as_deref().map(Path::new),
        args.keys_dir.as_deref().map(Path::new),
    )?;
    let files = resolve_delta_arg(repo_path, &arg).unwrap_or_else(|text| verification_fails(&text));
    let sb = match DeltaSuperblock::read(&files.superblock).await {
        Ok(sb) => sb,
        Err(err) => match delta_read_text(&err, &files.superblock_shown) {
            Some(text) => verification_fails(&text),
            None => {
                println!("Verification fails");
                return Err(err);
            }
        },
    };
    if !sb.is_signed() {
        verification_fails("no signatures in static-delta");
    }
    let outcome = match sb.verify(&[keys.verifier.as_ref()]).await {
        Ok(outcome) => outcome,
        Err(err) => {
            println!("Verification fails");
            return Err(err);
        }
    };
    match delta_verify_failure(engine, &keys, &outcome) {
        None => {
            println!("Verification OK");
            Ok(())
        }
        Some(text) => verification_fails(&text),
    }
}

/// Returns the failure text of a verify of static-delta signatures.
///
/// The result is `None` if the outcome is valid.
fn delta_verify_failure(
    engine: SignType,
    keys: &VerifyKeys,
    outcome: &VerifyOutcome,
) -> Option<String> {
    if outcome.valid {
        return None;
    }
    let name = sign_type_name(engine);
    if outcome.signatures.is_empty() {
        return Some(format!(
            "no signature for '{}' in static-delta superblock",
            sign_metadata_key(engine)
        ));
    }
    // The failure line names each trusted key that is not revoked once, at
    // its first place, in reverse order.
    let revoked: HashSet<&[u8]> = keys.revoked.iter().map(Vec::as_slice).collect();
    let mut seen = HashSet::new();
    let effective: Vec<&[u8]> = keys
        .trusted
        .iter()
        .map(Vec::as_slice)
        .filter(|key| !revoked.contains(key) && seen.insert(*key))
        .collect();
    if effective.is_empty() {
        return Some(format!("{name}: no signatures found"));
    }
    let listed: Vec<String> = effective
        .iter()
        .rev()
        .map(|key| {
            let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
            format!("key '{hex}'")
        })
        .collect();
    Some(format!(
        "{name}: Signature couldn't be verified with: {}",
        listed.join("; ")
    ))
}

/// Reads the sign type of `static-delta verify` and `apply-offline`.
///
/// - `ed25519`, and `spki` in a build that supports it, proceed.
/// - `dummy` is refused in its own words, with nothing on standard output.
/// - Every other name, `gpg` included, is refused as not implemented, as the
///   `ostree` command does. With `report_unsupported`, `Sign-type not
///   supported` goes to standard output first, as `verify` prints it.
fn verify_sign_type(name: &str, report_unsupported: bool) -> SignType {
    match sign_type_from_name(name) {
        Ok(engine @ (SignType::Ed25519 | SignType::Spki)) => engine,
        Err(text) if name == "dummy" => exit_error(&text),
        Ok(SignType::Gpg) | Err(_) => {
            if report_unsupported {
                println!("Sign-type not supported");
            }
            exit_error("Requested signature type is not implemented")
        }
    }
}

/// Applies a static delta offline.
///
/// The steps come in the order of the `ostree` command:
///
/// 1. The path is present.
/// 2. ostrya supports the sign type.
/// 3. The keys load, if a key source is given.
/// 4. [`lexical_path`] applies the `..` components of the path. Then the path
///    resolves, and the superblock reads.
/// 5. The signatures of a signed delta verify.
/// 6. The delta applies.
///
/// The superblock is read once, so the verified bytes are the applied bytes.
/// Nothing is printed on success.
async fn delta_apply_offline(repo: &Repo, args: DeltaApplyArgs) -> Result<()> {
    let Some(path) = args.path else {
        exit_error("PATH must be specified");
    };
    let engine = verify_sign_type(args.sign_type.as_deref().unwrap_or("ed25519"), false);
    let keys = if !args.key_id.is_empty() || args.keys_file.is_some() || args.keys_dir.is_some() {
        Some(load_verify_keys(
            engine,
            &args.key_id,
            args.keys_file.as_deref().map(Path::new),
            args.keys_dir.as_deref().map(Path::new),
        )?)
    } else {
        None
    };
    let path = lexical_path(&path);
    let meta = std::fs::metadata(&path)
        .unwrap_or_else(|err| exit_error(&format!("openat(O_DIRECTORY): {}", io_reason(&err))));
    let (superblock, parts, shown) = if meta.is_dir() {
        (
            path.join("superblock"),
            path.clone(),
            "superblock".to_owned(),
        )
    } else {
        let parts = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .to_owned();
        let shown = path
            .file_name()
            .unwrap_or(path.as_os_str())
            .to_string_lossy()
            .into_owned();
        (path, parts, shown)
    };
    let sb = DeltaSuperblock::read(&superblock)
        .await
        .map_err(|err| delta_read_error(err, &shown))?;
    if let Some(keys) = keys.filter(|_| sb.is_signed()) {
        let outcome = sb.verify(&[keys.verifier.as_ref()]).await?;
        if let Some(text) = delta_verify_failure(engine, &keys, &outcome) {
            exit_error(&text);
        }
    }
    repo.apply_static_delta(sb, &parts).await?;
    Ok(())
}

/// Returns `path` with its `..` components applied as text.
///
/// This step comes before the kernel resolves the path. The `ostree` command
/// reads the `apply-offline` PATH in the same way. The rules:
///
/// - Empty and `.` components and a trailing `/` are dropped.
/// - Each `..` removes the component before it.
/// - A `..` at the start of a relative path stays.
/// - A `..` at the root of an absolute path stays at the root.
/// - A path that becomes empty is `.`.
fn lexical_path(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut kept: Vec<Component> = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => match kept.last() {
                Some(Component::Normal(_)) => {
                    kept.pop();
                }
                Some(Component::RootDir) => {}
                _ => kept.push(component),
            },
            _ => kept.push(component),
        }
    }
    if kept.is_empty() {
        PathBuf::from(".")
    } else {
        kept.iter().collect()
    }
}

/// Loads the keys of an ed25519 or spki verify.
///
/// The verify is `sign --verify`, `summary --verify`, `static-delta verify`,
/// or `static-delta apply-offline`. The trusted keys are each `key_ids` entry,
/// then each key of `keys_file`. If neither is given, the trusted and revoked
/// keys come from `keys_dir`, or from the system key directories if `keys_dir`
/// is absent.
///
/// If no trusted key is present before revocation, the error is
/// `{type}: no keys loaded`. A key that is not valid refuses the run. A build
/// without the `spki` feature refuses the spki engine before it reads a key.
fn load_verify_keys(
    engine: SignType,
    key_ids: &[String],
    keys_file: Option<&Path>,
    keys_dir: Option<&Path>,
) -> Result<VerifyKeys> {
    #[cfg(not(feature = "spki"))]
    if engine == SignType::Spki {
        return Err(unsupported_type("spki"));
    }
    let name = sign_type_name(engine);
    let mut trusted: Vec<Vec<u8>> = key_ids
        .iter()
        .map(|key| verify_key_bytes(engine, key.as_bytes()))
        .collect();
    let mut revoked = Vec::new();
    if let Some(path) = keys_file {
        trusted.extend(read_verify_keys_file(engine, path)?);
    } else if key_ids.is_empty() {
        let keys = match keys_dir {
            Some(root) => load_sign_keys_from(&[root], name)?,
            None => load_sign_keys(name)?,
        };
        trusted = keys.trusted;
        revoked = keys.revoked;
    }
    if trusted.is_empty() {
        return Err(Error::Signature(format!("{name}: no keys loaded")));
    }
    let verifier = build_sign_api_verifier(engine, &trusted, &revoked)?;
    Ok(VerifyKeys {
        verifier,
        trusted,
        revoked,
    })
}

/// Decodes one public key of an ed25519 or spki verify.
///
/// The decoder is [`lenient_base64`], the lenient base64 reader of the
/// `ostree` command. It skips each character outside the base64 alphabet, so
/// an spki key can hold the line breaks of a PEM body. Text that is not UTF-8
/// decodes to no byte. An ed25519 key with a length other than 32 bytes
/// refuses the run in the words of `ostree`. The spki engine checks its own
/// keys when the verifier is built: a key that is not a SubjectPublicKeyInfo
/// DER, for example a SEC1 point, refuses the run.
fn verify_key_bytes(engine: SignType, text: &[u8]) -> Vec<u8> {
    let key = match std::str::from_utf8(text) {
        Ok(_) => lenient_base64(text),
        Err(_) => Vec::new(),
    };
    if engine == SignType::Ed25519 && key.len() != 32 {
        exit_error(&format!(
            "Invalid ed25519 public key: Ill-formed input: expected 32 bytes, got {} bytes",
            key.len()
        ));
    }
    key
}

/// Reads the public keys of a `--keys-file` for an ed25519 or spki verify.
///
/// The rules for each engine:
///
/// - The path must name a regular file, with symlinks followed. This check
///   comes before the open, so the command refuses a FIFO and does not wait
///   on it.
/// - The file is read up to [`VERIFY_KEYS_FILE_LIMIT`] bytes. A larger file is
///   refused.
///
/// An spki file holds PEM `PUBLIC KEY` blocks, which `spki_public_keys` of
/// the `ostrya` crate reads. An empty file, or a file of white space only,
/// adds no keys.
///
/// An ed25519 file holds one key on each line:
///
/// - Each line is read as bytes, with a trailing `\r` removed.
/// - A line that is then empty is skipped. Every other line, also a line of
///   whitespace, is decoded as a key.
/// - A file with no key line is refused.
fn read_verify_keys_file(engine: SignType, path: &Path) -> Result<Vec<Vec<u8>>> {
    use std::io::Read;
    let shown = path.display();
    if !std::fs::metadata(path).is_ok_and(|meta| meta.is_file()) {
        exit_error(&format!("File object '{shown}' is not a regular file"));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(VERIFY_KEYS_FILE_LIMIT + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > VERIFY_KEYS_FILE_LIMIT {
        return Err(Error::Signature(format!(
            "the key file '{shown}' is over the {VERIFY_KEYS_FILE_LIMIT}-byte ceiling"
        )));
    }
    #[cfg(feature = "spki")]
    if engine == SignType::Spki {
        return Ok(spki_public_keys(
            &bytes,
            &format!("the key file '{shown}'"),
        )?);
    }
    let keys: Vec<Vec<u8>> = bytes
        .split(|&byte| byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .filter(|line| !line.is_empty())
        .map(|line| verify_key_bytes(engine, line))
        .collect();
    if keys.is_empty() {
        return Err(Error::Signature(format!(
            "{}: no valid keys in file '{shown}'",
            sign_type_name(engine)
        )));
    }
    Ok(keys)
}

/// Prints one `<label>: <n> (<size wording>)` line of `static-delta show`.
fn print_delta_size(label: &str, n: u64) {
    println!("{label}: {n} ({})", format_delta_size(n));
}

/// Returns a byte count in the words of the `ostree` command.
///
/// - A count of 1 is `1 byte`.
/// - Any other count of less than 1000 is `N bytes`.
/// - A count of 1000 or more is divided by the largest power of 1000 that it
///   reaches. The text is this value to one decimal place, with ties to even
///   on the exact double, then U+00A0 and the unit.
fn format_delta_size(n: u64) -> String {
    const UNITS: [(u64, &str); 6] = [
        (1_000_000_000_000_000_000, "EB"),
        (1_000_000_000_000_000, "PB"),
        (1_000_000_000_000, "TB"),
        (1_000_000_000, "GB"),
        (1_000_000, "MB"),
        (1_000, "kB"),
    ];
    match UNITS.iter().find(|(factor, _)| n >= *factor) {
        // Each factor is exact as a double, because 5^18 is less than 2^53.
        Some((factor, unit)) => format!("{:.1}\u{a0}{unit}", n as f64 / *factor as f64),
        None if n == 1 => "1 byte".to_owned(),
        None => format!("{n} bytes"),
    }
}

/// Generates a static delta and prints the commits that it goes from and to.
///
/// If signing keys are given, the delta is signed.
async fn delta_generate(repo: &Repo, repo_path: &Path, args: DeltaGenerateArgs) -> Result<()> {
    // The reindex rebuilds the cache from the deltas under the `deltas/` tree
    // of the repository. A delta written to another location is not in this
    // tree, so the combination indexes nothing and gives no message.
    if args.reindex && (args.output_dir.is_some() || args.filename.is_some()) {
        return Err(Error::InvalidFormat(
            "--reindex covers the deltas under the repository's deltas/ tree, so it \
             cannot be combined with --output-dir or --filename"
                .into(),
        ));
    }
    let Some(to_rev) = args.to.as_deref().or(args.to_positional.as_deref()) else {
        exit_error("TO revision must be specified");
    };
    if args.empty && args.from.is_some() {
        exit_error("Cannot specify both --empty and --from=REV");
    }
    let to = resolve(repo, to_rev).await?;
    let from = match (&args.from, args.empty) {
        (Some(rev), _) => Some(resolve(repo, rev).await?),
        (None, true) => None,
        (None, false) => Some(resolve(repo, &format!("{}^", to.to_hex())).await?),
    };

    // The `ostree` command reads the superblock of the delta in the
    // repository, at any output location of the run.
    if args.if_not_exists {
        let superblock = repo_path
            .join(ostrya::static_delta_relative_dir(from.as_ref(), &to))
            .join("superblock");
        if superblock.try_exists().map_err(Error::Io)? {
            let name = match &from {
                Some(from) => format!("{}-{}", from.to_hex(), to.to_hex()),
                None => to.to_hex(),
            };
            println!("Delta {name} already exists.");
            return Ok(());
        }
    }

    // The byte order starts from the host order, as the byte order of the
    // `ostree` command does. It is checked after `-n` and the default parent,
    // and before the block.
    let endianness = match args.set_endianness.as_deref() {
        None if cfg!(target_endian = "big") => DeltaEndianness::Big,
        None => DeltaEndianness::Little,
        Some("l") => DeltaEndianness::Little,
        Some("B") => DeltaEndianness::Big,
        Some(other) => exit_error(&format!("Invalid endianness '{other}'")),
    };
    let endianness = match (args.swap_endianness, endianness) {
        (false, endianness) => endianness,
        (true, DeltaEndianness::Little) => DeltaEndianness::Big,
        (true, DeltaEndianness::Big) => DeltaEndianness::Little,
    };

    // The block is printed before the keys are read and before any write, as
    // the `ostree` command prints it. A run that fails later also prints the
    // block.
    println!("Generating static delta:");
    println!(
        "  From: {}",
        from.as_ref()
            .map_or_else(|| "empty".to_owned(), Checksum::to_hex)
    );
    println!("  To:   {}", to.to_hex());

    let opts = DeltaOptions {
        min_fallback_size: args.min_fallback_size,
        max_bsdiff_size: args.max_bsdiff_size,
        max_chunk_size: args.max_chunk_size,
        bsdiff: !args.disable_bsdiff,
        timestamp: args.timestamp,
        output_dir: args.output_dir.clone(),
        superblock_file: args.filename.clone(),
        signers: delta_signers(&args)?,
        inline: args.inline,
        endianness,
    };
    repo.generate_static_delta(from.as_ref(), &to, &opts)
        .await?;
    if args.reindex {
        repo.reindex_static_deltas().await?;
    }
    Ok(())
}

/// Returns the signers of a `static-delta generate` run.
///
/// There is one signer for each `--sign` value and for each line of each
/// `--keys-file`, under `--sign-type`. If neither option is given, the list is
/// empty.
fn delta_signers(args: &DeltaGenerateArgs) -> Result<Vec<Arc<dyn Signer>>> {
    if args.sign.is_empty() && args.keys_file.is_empty() {
        return Ok(Vec::new());
    }
    if args.sign_type == SignType::Gpg && !args.keys_file.is_empty() {
        return Err(Error::Signature(
            "gpg signing takes --sign KEY-ID arguments; --keys-file serves the other engines"
                .into(),
        ));
    }
    #[cfg(feature = "spki")]
    if args.sign_type == SignType::Spki {
        return delta_spki_signers(args);
    }
    let mut keys = args.sign.clone();
    for path in &args.keys_file {
        keys.extend(read_key_lines(path)?);
    }
    if keys.is_empty() {
        return Err(Error::Signature(
            "no signing key given; pass --sign or --keys-file".into(),
        ));
    }
    keys.iter()
        .map(|key| {
            match sign_api_signer(args.sign_type, key.as_bytes(), args.gpg_homedir.as_deref()) {
                Ok(signer) => Ok(Arc::from(signer)),
                Err(message) => exit_error(&message),
            }
        })
        .collect()
}

/// Returns the signers of a `static-delta generate` run under spki.
///
/// There is one signer for each `--sign` value, then one for each line of
/// each `--keys-file`, as [`delta_spki_key_lines`] reads the file. The
/// command reads every file before it decodes a `--sign` value.
#[cfg(feature = "spki")]
fn delta_spki_signers(args: &DeltaGenerateArgs) -> Result<Vec<Arc<dyn Signer>>> {
    let mut from_files = Vec::new();
    for path in &args.keys_file {
        from_files.extend(delta_spki_key_lines(path)?);
    }
    let mut signers: Vec<Arc<dyn Signer>> = Vec::with_capacity(args.sign.len() + from_files.len());
    for key in &args.sign {
        match sign_api_signer(SignType::Spki, key.as_bytes(), None) {
            Ok(signer) => signers.push(Arc::from(signer)),
            Err(message) => exit_error(&message),
        }
    }
    signers.extend(
        from_files
            .into_iter()
            .map(|signer| Arc::new(signer) as Arc<dyn Signer>),
    );
    Ok(signers)
}

/// Returns one spki signer for each line of a `static-delta generate`
/// `--keys-file`.
///
/// The file is read as [`read_signing_key_file`] reads it.
/// `spki_secret_key_lines` of the `ostrya` crate reads the lines and states
/// the rules of the file.
#[cfg(feature = "spki")]
fn delta_spki_key_lines(path: &Path) -> Result<Vec<SpkiSigner>> {
    let bytes = read_signing_key_file(path)?;
    Ok(spki_secret_key_lines(bytes, &key_file_subject(path))?)
}

/// The literal `--parent` value that asks for a root commit.
///
/// It is the one `--parent` value that is not read as a revision. Only the
/// lowercase spelling has this meaning.
const NO_PARENT: &str = "none";

/// Writes one commit from the tree sources of a `commit` command line.
///
/// On success, the command prints the commit checksum, or the
/// `--table-output` block.
async fn commit(repo: Repo, args: CommitArgs, owner: Owner, fsync: Option<bool>) -> Result<()> {
    // The two walk-control files are read first. The `ostree` command reports a
    // file that it cannot open or read at this step. The step comes before the
    // missing-branch check, `--parent`, the metadata options, the tree, and the
    // timestamp.
    let walk = match WalkOptions::read(&args) {
        Ok(walk) => walk,
        Err(message) => exit_error(&message),
    };

    // A commit names the branch that it moves, or states that it writes no
    // ref. This check comes before `--parent`, the tree, and any object
    // publication, in the order of the `ostree` command.
    if args.branch.is_none() && !args.orphan {
        exit_error("A branch must be specified with --branch, or use --orphan");
    }

    // The names of `--tag` are checked before the repository lock. A tag
    // whose ref path has an entry is refused here, and again before the
    // transaction publishes.
    if let Some(message) = tag_name_refusal(args.branch.as_deref(), &args.tags) {
        exit_error(&message);
    }
    for tag in &args.tags {
        if let Some(message) = existing_tag_refusal(repo.path(), tag) {
            exit_error(&message);
        }
    }

    // The `ostree` command refuses `--canonical-permissions` with a non-zero
    // owner id after the branch check and before the tree.
    if let Some(message) = canonical_owner_conflict(args.canonical_permissions, owner) {
        exit_error(&message);
    }

    // Each refusal from this point to the transaction comes before the
    // repository lock. At that point, there is no transaction to abort and no
    // staging directory to reap. The process exits with no object and no ref
    // written.
    macro_rules! refuse_unlocked {
        ($result:expr) => {
            match $result {
                Ok(value) => value,
                Err(message) => exit_error(&message),
            }
        };
    }

    // The `[core]` keys that the transaction reads are parsed here, before the
    // edit, because the transaction opens after the editor returns. The
    // `ostree` command reads them when it opens the repository. In both
    // commands, the error for a refused value then comes before `--parent`, the
    // metadata options, and the editor. The first four keys are the set that
    // the transaction open reads. The fsync pair is the set that its write
    // paths read. It is also parsed here, so `--fsync` does not change the
    // place of a refusal.
    let config = repo.config();
    config.locking()?;
    config.lock_timeout_secs()?;
    config.tmp_expiry_secs()?;
    config.min_free_space()?;
    config.fsync()?;
    config.per_object_fsync()?;

    // `--parent` takes a revision, so its errors use the resolution words of
    // each subcommand that takes a revision.
    let parent = match args.parent.as_deref() {
        Some(NO_PARENT) => None,
        Some(rev) => match repo.resolve_rev(rev, false).await {
            Ok(found) => found,
            Err(err) => return Err(report_resolution_failure(err)),
        },
        // `--orphan` suppresses only the implicit parent, so an explicit
        // `--parent` with it still gives the commit a parent.
        None if args.orphan => None,
        // The implicit parent is the branch name resolved as a revision. A name
        // of lowercase hex that prefixes one commit gives that commit, and a
        // name that prefixes more than one commit is refused. Any other name
        // gives the tip from the ref file, and its commit object is not loaded.
        // A branch that names no ref and prefixes no commit then gives a root
        // commit, and the commit inherits a ref over an absent object with no
        // read. If the match guard refuses a name, its tip is not read. The
        // checksum guard and the ref-name rule refuse such a name after the
        // commit is written.
        None => match args.branch.as_deref() {
            Some(branch)
                if shadowed_branch_name(branch).is_none() && validate_refspec(branch).is_ok() =>
            {
                match repo.resolve_rev(branch, true).await {
                    Ok(found) => found,
                    Err(err) => return Err(report_resolution_failure(err)),
                }
            }
            _ => None,
        },
    };

    // The metadata options are read next, each group in the order of the
    // code. The refusal of a group comes before the body file, the editor, the
    // tree, and the timestamp. An empty key is refused when the dict is
    // assembled, so this refusal comes after all four.
    if !args.keep_metadata.is_empty() && parent.is_none() {
        refuse_unlocked!(Err(
            "Either --branch or --parent must be specified when using --keep-metadata".to_owned()
        ));
    }
    let added_strings = refuse_unlocked!(metadata_pairs(&args.add_metadata_string));
    let added_variants = refuse_unlocked!(parse_added_metadata(&args.add_metadata));
    let detached_pairs = refuse_unlocked!(metadata_pairs(&args.add_detached_metadata_string));
    let related = refuse_unlocked!(related_pairs(&args.related));
    let kept = match parent.as_ref() {
        Some(parent) => refuse_unlocked!(kept_metadata(&repo, parent, &args.keep_metadata).await?),
        None => Vec::new(),
    };

    // `-e` replaces the subject and the body, so if it is given, neither `-m`
    // nor `-F` is read. `-F` wins over `-m` in either order.
    let body = match (args.editor, args.body_file.as_deref()) {
        (true, _) => None,
        (false, Some(path)) => Some(refuse_unlocked!(read_body_file(path))),
        (false, None) => args.body.clone(),
    };

    // The editor runs after the metadata options are read and before the tree
    // opens. A tree path that does not open and a refused timestamp are then
    // both reported after the edit. The result of the editor replaces the
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

    // The message is final, so the repository lock is taken now. An edit
    // session holds no lock, so an exclusive operation on the same repository
    // can run while the user writes the message. The `ostree` command takes
    // its lock at the same point.
    let mut txn = repo.transaction().await?;
    // `--fsync` can narrow the configured policy and never widens it. A
    // repository with `[core] fsync=false` syncs nothing under `--fsync=true`.
    // Only `false` reaches the transaction, and with `true` the config applies.
    if fsync == Some(false) {
        txn.set_fsync(false);
    }
    // `--generate-sizes` covers both ingest paths, the tar stream included, so
    // the request goes to the transaction. The commit modifier of the walk
    // does not get it. Outside archive mode, the request changes nothing. If a
    // skip list names the walk root, no source is read. Then no object is
    // counted, and the commit has no `ostree.sizes` key.
    txn.set_generate_sizes(args.generate_sizes && !walk.root_pruned);
    // The dependencies are checked before the tree is read, so a refused
    // dependency stops the command before the ingest and the composefs build.
    if let Err(err) = txn.check_related(&related).await {
        txn.abort().await?;
        return Err(err);
    }

    // From this point, a refusal first aborts the transaction. `exit_error`
    // runs no destructor, so the abort reaps the staging directory before the
    // exit.
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

    // `--base` is the bottom layer of the source list at any position on the
    // command line. It resolves before the tree specifications. The error for a
    // base that does not resolve then comes before a source that does not open,
    // and before `--consume` removes anything.
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

    // The cache is built from the loose objects of this repository, so a
    // source tree that an earlier process checked out resolves through it.
    // `-I` implies `--link-checkout-speedup`.
    let devino = if args.link_checkout_speedup || args.devino_canonical {
        Some(repo.devino_cache().await?)
    } else {
        None
    };
    let mut modifier = commit_modifier(&args, owner, &walk, devino);
    let mut mtree = MutableTree::new();
    // The sources are read before `--timestamp`, one at a time and in order.
    // The error for a source that does not open then comes at the step of the
    // `ostree` command. If a later source fails, a source that `--consume`
    // emptied stays empty.
    let specs = refuse!(tree_specs(&args));
    // The base is the bottom layer, and no modifier applies to it. Each entry
    // that no later source changes keeps the mode, the owner, and the extended
    // attributes of the base. A pruned walk root adds nothing over the base, so
    // then the commit holds the base alone.
    if let Some(base) = base {
        let (commit, _) = repo.load_commit(&base).await?;
        txn.overlay_tree_to_mtree(&commit.root_dirtree, &commit.root_dirmeta, &mut mtree, None)
            .await?;
    }
    for spec in specs {
        let source = refuse!(open_tree_source(&repo, spec).await?);
        // If a skip list names the walk root, it prunes the whole walk. The
        // source is opened, so a source that does not open is reported here.
        // The filter gets no entry under the root, so every other entry of
        // each control file stays unmatched.
        if walk.root_pruned {
            continue;
        }
        // An OR-form `--statoverride` entry for a directory under the walk
        // root applies only to a member of an archive. All sources share one
        // modifier, so the source kind is set before the overlay reads it.
        walk.source_is_tar
            .store(matches!(source, OpenSource::Tar(_)), Ordering::Relaxed);
        // `ostree.sizes` covers the objects of the last source and the
        // directory objects that the serialization writes. For this reason,
        // each source opens its own scope for the count.
        txn.begin_tree_source();
        refuse!(overlay_source(&repo, &txn, &args, source, &mut mtree, modifier.as_mut()).await?);
    }
    // Both control files are checked after all sources are read, the
    // statoverride file first. An entry in a pruned directory is unmatched,
    // because the walk did not reach it.
    refuse!(report_unmatched(
        "statoverride",
        &walk.unmatched_statoverride()
    ));
    refuse!(report_unmatched("skip-list", &walk.unmatched_skip_list()));
    // If the source list gives no root directory, and `--base` gives none,
    // the tree has no metadata to write. This occurs for an empty archive, an
    // archive with no root member, or a walk that the skip list pruned at the
    // root.
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

    // `--skip-if-unchanged` compares the walked tree with the resolved
    // parent, both the root contents and the root metadata. The metadata of
    // the commit is not compared, so a new subject or a new metadata key over
    // an unchanged tree is still skipped. With no parent, there is nothing to
    // compare, and the commit is written.
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

    // The two derived keys come from the committed tree, so they come after the
    // walk, the control-file reports, the empty-tree refusal, and
    // `--skip-if-unchanged`.
    let mut metadata = metadata;
    if args.bootable {
        let version = refuse!(kernel_version(&txn, &root).await?);
        // The derived pair replaces a given value for each of the two keys. As
        // a result, a commit with `--add-metadata-string=ostree.linux=...` and
        // `--bootable` gives the same object as a commit with `--bootable`
        // alone.
        drop_metadata_keys(&mut metadata, &[LINUX_KEY, BOOTABLE_KEY])?;
        let mut pair = DictBuilder::new();
        pair.insert_bootable(&version);
        let Value::Array(entries) = pair.build() else {
            unreachable!("DictBuilder builds an a{{sv}} array")
        };
        prepend_metadata_entries(&mut metadata, entries)?;
    }
    // The composefs digest comes after the binding keys, and the library
    // appends `ostree.sizes` after the digest. A value of the command line
    // under the same key gets the derived digest in its slot. This applies to
    // `--add-metadata-string`, `--add-metadata`, and `--keep-metadata`. A
    // repeated key becomes that one entry.
    //
    // Under `--generate-composefs`, the one build of the image gives the
    // digest, and the image goes in with the commit. The image borrows the
    // transaction, so it lives in this block alone.
    let checksum = {
        let mut image = None;
        if args.generate_composefs_metadata || args.generate_composefs {
            let digest = if args.generate_composefs {
                let staged = txn.build_composefs_image(&root).await?;
                let digest = *staged.digest();
                image = Some(staged);
                digest
            } else {
                txn.composefs_digest(&root).await?
            };
            let entry = Value::Tuple(vec![
                Value::Str(COMPOSEFS_DIGEST_KEY.to_owned()),
                Value::variant(Type::array(Type::Byte), Value::Bytes(digest.to_vec())),
            ]);
            set_metadata_entry(&mut metadata, COMPOSEFS_DIGEST_KEY, entry)?;
        }

        let opts = CommitOptions {
            parent,
            subject,
            body,
            timestamp,
            metadata: Some(metadata),
            related,
        };
        let checksum = txn.write_commit(opts, &root).await?;
        if let Some(image) = image {
            txn.attach_composefs_image(&checksum, image).await?;
        }
        checksum
    };
    // A branch name that the revision syntax shadows is reported after the
    // commit is written and before the signing step. A name that the refspec
    // grammar refuses is reported at the same step. The `ostree` command
    // reports each of them in this order, before a key that it cannot use. The
    // refspec grammar is the ref-name rule of `ostree`, so a name with a space
    // or a caret gets `Invalid refspec <name>`.
    //
    // The refusal comes at the ref write, after the tree is read, so an error
    // of the tree can come first. `exit_error` runs no destructor, so the
    // abort reaps the staging directory before the exit.
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
    // `--add-detached-metadata-string` replaces all stored detached metadata,
    // and the signing engines append to the current metadata. For this reason,
    // the dict is queued before the signatures. A run with both writes the user
    // keys first and the signature keys after them. It also drops each
    // signature that an earlier run left on the same checksum.
    if let Some(detached) = detached {
        txn.set_commit_detached_metadata(&checksum, detached);
    }
    // The signatures are made before the ref is written and before the
    // transaction publishes. If a key cannot sign, `objects/` then gets no
    // object and the ref does not move.
    refuse!(sign_staged_commit(&txn, &checksum, &args).await?);
    // A ref can appear at the path of a tag while the command reads the tree.
    // The second check refuses it, and the abort publishes no staged object.
    // `txn.commit` publishes the objects before it writes the refs, so a ref
    // that another writer creates in that step is replaced.
    for tag in &args.tags {
        if let Some(message) = existing_tag_refusal(repo.path(), tag) {
            txn.abort().await?;
            exit_error(&message);
        }
    }
    if let Some(branch) = args.branch.as_deref() {
        txn.set_ref(branch, Some(&checksum));
    }
    for tag in &args.tags {
        txn.set_ref(tag, Some(&checksum));
    }
    let stats = txn.commit().await?;

    if args.table_output {
        print_commit_table(&checksum, &stats);
    } else {
        println!("{}", checksum.to_hex());
    }
    Ok(())
}

/// Returns the refusal of the `--tag` names of a commit, or `None` if each
/// name is good.
///
/// A tag is a local ref, so a name with `:` is refused. A name that the
/// ref-name rule refuses, and a name of 64 lowercase hex characters, are
/// refused with the words of a refused branch. A tag that is the branch, and
/// a tag named twice, are also refused.
///
/// After these checks, a name that is a path below another name is refused,
/// because the ref file of the outer name blocks the directory of the inner
/// name. The check covers each tag and the branch. It skips a branch with `:`,
/// which is a ref under `refs/remotes`, and a branch that the ref write
/// refuses with its own message.
fn tag_name_refusal(branch: Option<&str>, tags: &[String]) -> Option<String> {
    let mut seen = HashSet::new();
    for tag in tags {
        if tag.contains(':') {
            return Some(format!("--tag {tag} holds ':', and a tag is a local ref"));
        }
        if validate_refspec(tag).is_err() {
            return Some(format!("Invalid refspec {tag}"));
        }
        if let Some(message) = shadowed_branch_name(tag) {
            return Some(message);
        }
        if branch == Some(tag.as_str()) {
            return Some(format!("--tag {tag} is also the --branch name"));
        }
        if !seen.insert(tag.as_str()) {
            return Some(format!("--tag {tag} is given more than once"));
        }
    }
    let local_branch = branch.filter(|branch| {
        !branch.contains(':')
            && shadowed_branch_name(branch).is_none()
            && validate_refspec(branch).is_ok()
    });
    let names: Vec<(&str, &str)> = local_branch
        .map(|branch| ("--branch", branch))
        .into_iter()
        .chain(tags.iter().map(|tag| ("--tag", tag.as_str())))
        .collect();
    for &(inner_option, inner) in &names {
        for &(outer_option, outer) in &names {
            if inner.starts_with(&format!("{outer}/")) {
                return Some(format!(
                    "{inner_option} {inner} names a path below {outer_option} {outer}"
                ));
            }
        }
    }
    None
}

/// Returns the refusal of a `--tag` name that has an entry at its ref path,
/// or `None` if the path is absent.
///
/// The path is `refs/heads/<tag>` in the repository at `repo_path`. The
/// lookup reads each component with no symlink follow. Each component before
/// the last must be a directory. The check refuses a regular file, a
/// symlink (also a dangling one), and a directory at the last component. It
/// also refuses a component before the last that is not a directory. Only a
/// component that is absent gives `None`. A lookup error other than an
/// absent entry is also a refusal.
fn existing_tag_refusal(repo_path: &Path, tag: &str) -> Option<String> {
    let exists = || format!("--tag specified but ref {tag} already exists");
    let mut path = repo_path.join("refs/heads");
    let mut components = tag.split('/').peekable();
    while let Some(component) = components.next() {
        path.push(component);
        match std::fs::symlink_metadata(&path) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
            Err(err) => return Some(format!("Cannot read ref {tag}: {err}")),
            Ok(meta) if meta.is_dir() && components.peek().is_some() => {}
            Ok(_) => return Some(exists()),
        }
    }
    Some(exists())
}

/// Returns the refusal of `--canonical-permissions` with a non-zero owner id.
///
/// The result is `None` if the options agree. Canonical ingest gives every
/// object the owner 0:0, so a declared non-zero id contradicts it. The refusal
/// names the option whose id was read, uid first.
fn canonical_owner_conflict(canonical: bool, owner: Owner) -> Option<String> {
    if !canonical {
        return None;
    }
    [(owner.uid, "--owner-uid"), (owner.gid, "--owner-gid")]
        .into_iter()
        .find(|(id, _)| id.is_some_and(|id| id != 0))
        .map(|(_, flag)| format!("Cannot specify both --canonical-permissions and non-zero {flag}"))
}

/// The `--sign-type` name that applies if the option is absent.
///
/// It is also the one name that the build of the `ostree` command supports.
const DEFAULT_SIGN_TYPE: &str = "ed25519";

/// The length in bytes of an ed25519 secret key.
///
/// The key is the 32-byte seed, then the 32-byte public key.
const ED25519_SECRET_LEN: usize = 64;

/// The maximum length in bytes of the first line that `--sign-from-file` reads.
///
/// A base64 ed25519 secret is 88 characters, and a GPG key id is shorter. The
/// limit is far more than any key, and it bars an unbounded read. A longer
/// first line is refused. The line is never cut.
const SIGN_KEY_FILE_LIMIT: u64 = 64 * 1024;

/// Signs the staged commit with each key that the signing options name.
///
/// The order is the order of [`collect_signers`]. The step runs after the
/// commit object is staged, and before the ref write and the publication. A
/// refusal at this step leaves no object in `objects/` and does not move the
/// ref. A run with several keys is all or nothing.
async fn sign_staged_commit(
    txn: &Transaction,
    checksum: &Checksum,
    args: &CommitArgs,
) -> Result<std::result::Result<(), String>> {
    let signers = match collect_signers(
        &args.sign,
        &args.sign_from_file,
        args.sign_type.as_deref(),
        &args.gpg_sign,
        args.gpg_homedir.as_deref(),
    )
    .await?
    {
        Ok(signers) => signers,
        Err(message) => return Ok(Err(message)),
    };
    for signer in &signers {
        txn.sign_commit(checksum, signer.as_ref()).await?;
    }
    Ok(Ok(()))
}

/// Returns one signer for each key that the signing options name.
///
/// All signers are built before the first signature.
///
/// # Order
///
/// The order is fixed and does not follow the command line:
///
/// 1. every `--sign` key
/// 2. every `--sign-from-file` key
/// 3. every `--gpg-sign` key
///
/// `sign_type` selects the engine of the first two groups alone. It is read
/// only if one of these groups names a key. A run that signs nothing then
/// accepts an engine name that no engine has, with no message.
///
/// # Refusals
///
/// The function refuses these inputs, so each refusal comes before the first
/// signature:
///
/// - a key that does not decode
/// - a key file that does not read
/// - an spki key file of more than one `PRIVATE KEY` block
/// - a gpg selector that does not name exactly one secret key
///
/// A gpg selector is a `--gpg-sign` key, or a `--sign` or `--sign-from-file`
/// key under `--sign-type=gpg`.
async fn collect_signers(
    sign: &[String],
    sign_from_file: &[std::ffi::OsString],
    sign_type: Option<&str>,
    gpg_sign: &[String],
    gpg_homedir: Option<&Path>,
) -> Result<std::result::Result<Vec<Box<dyn Signer>>, String>> {
    macro_rules! refuse {
        ($result:expr) => {
            match $result {
                Ok(value) => value,
                Err(message) => return Ok(Err(message)),
            }
        };
    }
    let mut signers = Vec::with_capacity(sign.len() + sign_from_file.len() + gpg_sign.len());
    if !sign.is_empty() || !sign_from_file.is_empty() {
        let engine = refuse!(sign_type_from_name(sign_type.unwrap_or(DEFAULT_SIGN_TYPE)));
        if engine == SignType::Gpg {
            signers.extend(refuse!(resolve_gpg_selectors(sign, gpg_homedir).await?));
            for path in sign_from_file {
                let key = refuse!(read_sign_key_file(Path::new(path)));
                let key = [String::from_utf8_lossy(&key).into_owned()];
                signers.extend(refuse!(resolve_gpg_selectors(&key, gpg_homedir).await?));
            }
        } else {
            for key in sign {
                signers.push(refuse!(sign_api_signer(
                    engine,
                    key.as_bytes(),
                    gpg_homedir
                )));
            }
            for path in sign_from_file {
                if engine == SignType::Spki {
                    signers.push(refuse!(sign_from_file_spki(Path::new(path))));
                    continue;
                }
                let key = refuse!(read_sign_key_file(Path::new(path)));
                signers.push(refuse!(sign_api_signer(engine, &key, gpg_homedir)));
            }
        }
    }
    signers.extend(refuse!(resolve_gpg_selectors(gpg_sign, gpg_homedir).await?));
    Ok(Ok(signers))
}

/// The minimum length in bytes of a `--gpg-sign` selector for the key lookup.
///
/// A shorter selector is refused with no lookup.
#[cfg(feature = "gpg")]
const GPG_SIGN_SELECTOR_MIN: usize = 8;

/// Resolves the `--gpg-sign` selectors to signers, in command-line order.
///
/// There is one signer for each selector. Each selector is resolved in the
/// GnuPG home directory that `homedir` names, or in the directory that gpg
/// resolves for itself. It must name exactly one secret key.
///
/// - A selector of less than [`GPG_SIGN_SELECTOR_MIN`] bytes is refused with
///   no lookup.
/// - A selector that names no key, and a selector that names several keys,
///   each get a refusal of their own.
///
/// Every selector is resolved before the caller makes a signature. Each signer
/// is bound to the fingerprint from the lookup, so the key that signs is the
/// key that the lookup named.
#[cfg(feature = "gpg")]
async fn resolve_gpg_selectors(
    selectors: &[String],
    homedir: Option<&Path>,
) -> Result<std::result::Result<Vec<Box<dyn Signer>>, String>> {
    let mut signers: Vec<Box<dyn Signer>> = Vec::with_capacity(selectors.len());
    for key in selectors {
        if key.len() < GPG_SIGN_SELECTOR_MIN {
            return Ok(Err(format!(
                "Unable to lookup key ID {key}: GPGME: Invalid value"
            )));
        }
        let lookup = gpg_signer(key, homedir);
        let homedir_text = gpg_homedir_text(&lookup);
        let found = lookup.secret_key_fingerprints().await?;
        let [fingerprint] = found.as_slice() else {
            return Ok(Err(if found.is_empty() {
                format!("No gpg key found with ID {key} (homedir: {homedir_text})")
            } else {
                format!(
                    "gpg key id {key} ambiguous (homedir: {homedir_text}). Try the fingerprint \
                     instead"
                )
            }));
        };
        signers.push(Box::new(gpg_signer(fingerprint, homedir)));
    }
    Ok(Ok(signers))
}

/// Refuses each `--gpg-sign` selector, because this build has no gpg engine.
///
/// An empty selector list gives no signer and no refusal.
#[cfg(not(feature = "gpg"))]
async fn resolve_gpg_selectors(
    selectors: &[String],
    _: Option<&Path>,
) -> Result<std::result::Result<Vec<Box<dyn Signer>>, String>> {
    if selectors.is_empty() {
        return Ok(Ok(Vec::new()));
    }
    // A build without the engine refuses through the same channel as every
    // other signing refusal, so the line is the same at every site.
    Ok(Err("Requested signature type is not implemented".to_owned()))
}

/// Returns the gpg signer for one key selector, bound to `homedir` if given.
#[cfg(feature = "gpg")]
fn gpg_signer(key: &str, homedir: Option<&Path>) -> GpgSigner {
    let signer = GpgSigner::new(key);
    match homedir {
        Some(dir) => signer.with_homedir(dir),
        None => signer,
    }
}

/// Returns the GnuPG home directory that a key-lookup refusal names.
///
/// This is the home directory of the signer, or the literal `<default>` if
/// the signer has none and gpg resolves the directory for itself.
#[cfg(feature = "gpg")]
fn gpg_homedir_text(signer: &GpgSigner) -> String {
    match signer.homedir() {
        Some(dir) => dir.display().to_string(),
        None => "<default>".to_owned(),
    }
}

/// Reads `--sign-type` into the engine that it names.
///
/// A name that no engine has is refused in the words of the `ostree` command.
/// The match is exact and case sensitive, with no trim, so `ED25519` and a name
/// with whitespace around it each name no engine. `dummy` is a registered
/// engine that the command line does not reach, and it has a refusal of its
/// own.
fn sign_type_from_name(name: &str) -> std::result::Result<SignType, String> {
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

/// Returns the signer of one `--sign` or `--sign-from-file` key under `engine`.
///
/// The key arrives as bytes, because `--sign-from-file` reads a line of a
/// file, and the `ostree` command sets no encoding requirement on it. The
/// ed25519 engine reads the bytes directly. The engines whose key is a text
/// selector read the same bytes, with each invalid UTF-8 sequence replaced.
///
/// `gpg_homedir` applies to the gpg engine alone.
fn sign_api_signer(
    engine: SignType,
    key: &[u8],
    gpg_homedir: Option<&Path>,
) -> std::result::Result<Box<dyn Signer>, String> {
    match engine {
        SignType::Ed25519 => {
            let secret = ed25519_secret_key(key)?;
            Ed25519Signer::from_secret_key(&secret)
                .map(|signer| Box::new(signer) as Box<dyn Signer>)
                .map_err(|err| err.to_string())
        }
        SignType::Spki => sign_api_signer_spki(&String::from_utf8_lossy(key)),
        SignType::Gpg => sign_api_signer_gpg(&String::from_utf8_lossy(key), gpg_homedir),
    }
}

/// Returns the spki signer of one base64 secret key.
#[cfg(feature = "spki")]
fn sign_api_signer_spki(key: &str) -> std::result::Result<Box<dyn Signer>, String> {
    SpkiSigner::from_base64(key)
        .map(|signer| Box::new(signer) as Box<dyn Signer>)
        .map_err(|err| err.to_string())
}

/// Returns an error, because this build has no spki engine.
#[cfg(not(feature = "spki"))]
fn sign_api_signer_spki(_: &str) -> std::result::Result<Box<dyn Signer>, String> {
    Err("Requested signature type is not implemented".to_owned())
}

/// Returns the spki signer of one `--sign-from-file` file, which holds one
/// `PRIVATE KEY` block.
///
/// The command reads the whole file, as [`read_signing_key_file`] reads it.
/// An empty path, and a missing file, give the refusals of
/// [`read_sign_key_file`]. A file of more than one block is refused.
#[cfg(feature = "spki")]
fn sign_from_file_spki(path: &Path) -> std::result::Result<Box<dyn Signer>, String> {
    if path.as_os_str().is_empty() {
        return Err("Operation not supported".to_owned());
    }
    let mut signers = match spki_key_file_signers(path) {
        Ok(signers) => signers,
        Err(Error::Io(err)) => {
            return Err(format!(
                "Error opening file {}: {}",
                path.display(),
                io_reason(&err)
            ));
        }
        Err(err) => return Err(err.to_string()),
    };
    match (signers.pop(), signers.is_empty()) {
        (Some(signer), true) => Ok(Box::new(signer)),
        _ => Err(Error::Signature(format!(
            "{} holds more than one PEM PRIVATE KEY block",
            key_file_subject(path)
        ))
        .to_string()),
    }
}

/// Returns an error, because this build has no spki engine.
#[cfg(not(feature = "spki"))]
fn sign_from_file_spki(_: &Path) -> std::result::Result<Box<dyn Signer>, String> {
    Err("Requested signature type is not implemented".to_owned())
}

/// Returns the gpg signer of one key selector, bound to `homedir` if given.
#[cfg(feature = "gpg")]
fn sign_api_signer_gpg(
    key: &str,
    homedir: Option<&Path>,
) -> std::result::Result<Box<dyn Signer>, String> {
    Ok(Box::new(gpg_signer(key, homedir)))
}

/// Returns an error, because this build has no gpg engine.
#[cfg(not(feature = "gpg"))]
fn sign_api_signer_gpg(_: &str, _: Option<&Path>) -> std::result::Result<Box<dyn Signer>, String> {
    Err("Requested signature type is not implemented".to_owned())
}

/// Reads an ed25519 secret key from its base64 text.
///
/// A value with a length other than [`ED25519_SECRET_LEN`] is refused in the
/// words of the `ostree` command.
///
/// The decode ([`lenient_base64`]) is lenient: each byte outside the base64
/// alphabet is skipped. Whitespace around the key, a newline in it, and a line
/// of prose then all decode to some byte count. The length check gives the
/// refusal. For this reason, `--sign=not-base64!!!` reports six bytes and no
/// decoder error.
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

/// Decodes base64 text in the same way as the decoder of the `ostree` command.
///
/// # Rules
///
/// - Each byte outside the alphabet is skipped, so whitespace and prose
///   characters add nothing.
/// - A padding character has the value zero and counts toward its group.
/// - Each complete group of four characters gives three bytes. Each of the
///   last two characters of the group that is a padding character removes one
///   of these bytes.
/// - A trailing group of less than four characters adds nothing.
///
/// # Padding
///
/// Padding acts for each group and each position:
///
/// - `AAAA=` decodes to three bytes, because the padding character starts an
///   incomplete group.
/// - `AA=A` decodes to two bytes, because the padding character is third in a
///   complete group.
/// - `AA==AA==` decodes to two bytes, one byte from each of its two groups.
/// - An argument of three characters decodes to zero bytes, and an argument of
///   nine characters decodes to six bytes.
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

/// Reads the key that one `--sign-from-file` occurrence names.
///
/// The key is the first line of the file. The rest of the file is ignored. An
/// empty path gets a refusal of its own.
///
/// The line is read as bytes with no encoding requirement. A byte sequence that
/// is not UTF-8 then reaches the engine, and the length check of the engine
/// gives the outcome. A NUL byte ends the line before the newline, so
/// `AAAA\0BBBB` is the key `AAAA`.
///
/// # Divergences
///
/// Each item is a recorded divergence from the `ostree` command:
///
/// - If a path does not open, the message names the path as the command line
///   gives it. `ostree` names the absolute path.
/// - An empty file, and a file whose first line is empty, give an empty key.
///   The length check of the engine refuses it. `ostree` dies on a signal for
///   each of the two.
/// - A first line longer than [`SIGN_KEY_FILE_LIMIT`] is refused, never cut.
///   The length that the engine reports is then always the length in the file.
///   `ostree` reads a line of any length.
fn read_sign_key_file(path: &Path) -> std::result::Result<Vec<u8>, String> {
    if path.as_os_str().is_empty() {
        return Err("Operation not supported".to_owned());
    }
    let fail =
        |err: &std::io::Error| format!("Error opening file {}: {}", path.display(), io_reason(err));
    let file = std::fs::File::open(path).map_err(|err| fail(&err))?;
    // One byte more than the limit tells a line that fills the limit from a
    // longer line.
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

/// Prints the `--table-output` block for a skipped `--skip-if-unchanged` run.
///
/// The block holds the checksum of the parent, and zero for each of the six
/// counters.
///
/// The `ostree` command prints uninitialized counter values here, which differ
/// between two identical runs. ostrya prints the counts of the work that it
/// did. This is a recorded divergence.
fn print_skipped_commit_table(parent: &Checksum) {
    print_commit_table(parent, &TransactionStats::default());
}

/// Prints the `--table-output` block.
///
/// The block is seven `KEY: VALUE` lines in a fixed order, with one space after
/// each colon and no padding.
///
/// `Content Bytes Written` reports `content_bytes_unpacked`, the content byte
/// count of the regular files written. The `ostree` command prints this
/// number. `TransactionStats::content_bytes_written` holds the size of the
/// objects in the repository.
///
/// For an `archive` repository, `content_bytes_written` is the compressed
/// size, which `PullStats` reports. The two values differ for every
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

/// Reads a `--fsync=POLICY` value into the policy that it names.
///
/// The accepted values are `true`, `yes`, `1`, `false`, `no`, and `0`, in any
/// case. Any other value is refused in the words of the `ostree` command, at
/// the same step as `ostree`. This step is the read of the options, before the
/// repository and before every check of the subcommand.
fn fsync_policy(value: Option<&str>) -> Option<bool> {
    let text = value?;
    match text.to_ascii_lowercase().as_str() {
        "true" | "yes" | "1" => Some(true),
        "false" | "no" | "0" => Some(false),
        _ => exit_error(&format!("Invalid boolean argument '{text}'")),
    }
}

/// The owner that a `commit` command line declares with its owner options.
///
/// The options are `--owner-uid` and `--owner-gid`. A field is `None` if the
/// option is absent or has a negative id, which declares nothing. The default
/// of the `ostree` command for both options is `-1`, so every negative value
/// keeps the owner of the source.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Owner {
    uid: Option<u32>,
    gid: Option<u32>,
}

/// Reads `--owner-uid` and `--owner-gid` of `commit`.
///
/// A value that neither option can hold is reported in the words of the
/// `ostree` command, at the same step as `ostree`. This step is the read of
/// the options, before the repository and before every check of `commit`.
fn commit_owner(args: &CommitArgs) -> Owner {
    Owner {
        uid: owner_id(args.owner_uid.as_deref(), "--owner-uid"),
        gid: owner_id(args.owner_gid.as_deref(), "--owner-gid"),
    }
}

/// Reads one `--owner-*` id.
///
/// If the option is absent or its value is negative, the result is `None`. The
/// value is read as a C `int` ([`parse_c_int`]), as the option parser of the
/// `ostree` command reads it. Both commands then accept and refuse the same
/// text.
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

/// The reason for the refusal of a C `int` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntError {
    /// The text is not an integer in any accepted base.
    Syntax,
    /// The text is an integer outside the range of a C `int`.
    Range,
}

/// Reads `text` as a C `int`, as `strtol` with base 0 does.
///
/// The text is optional leading whitespace, an optional sign, then a
/// `0x`-prefixed hexadecimal, a `0`-prefixed octal, or a decimal run. The whole
/// text must be read, so a trailing space or letter is refused. The value must
/// fit an `i32`.
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

/// The file-type mask of an `st_mode`.
const S_IFMT: u32 = 0o170000;
/// The regular-file type value of an `st_mode`.
const S_IFREG: u32 = 0o100000;
/// The directory type value of an `st_mode`.
const S_IFDIR: u32 = 0o040000;
/// The three execute bits, which `--mode-ro-executables` checks.
const EXEC_BITS: u32 = 0o111;
/// The three write bits, which `--mode-ro-executables` clears.
const WRITE_BITS: u32 = 0o222;

/// One `--statoverride` entry.
#[derive(Debug, Clone)]
struct StatOverride {
    /// `true` if the value replaces the permission bits of the entry (an `=`
    /// prefix). If `false`, the value is ORed into the mode of the entry.
    assign: bool,
    /// The mode value, read in base 10.
    value: u32,
    /// The text after the first space. It is the in-tree path that the entry
    /// matches, and the text that an unmatched report names.
    path: String,
}

/// The `commit` options that reach the file system walk.
///
/// They come from the two control files, before any other step of the
/// subcommand. Each control file holds at most one entry for each path. The
/// statoverride file holds at most one entry for each path and form.
///
/// If one form names a path more than once, the path takes the value of the
/// last line that names it. The entry keeps the position of the first line that
/// names it.
#[derive(Debug, Default)]
struct WalkOptions {
    /// The OR-form `--statoverride` entries, one for each path.
    statoverride_or: Vec<(String, u32)>,
    /// The `=`-form `--statoverride` entries, one for each path.
    statoverride_assign: Vec<(String, u32)>,
    /// The `--skip-list` paths, each path once.
    skip_list: Vec<String>,
    /// `true` if the skip list names the walk root, which prunes everything.
    root_pruned: bool,
    /// The OR-form `--statoverride` paths that the walk reached, one flag for
    /// each path. A path that the skip list prunes is reached, because the
    /// walk offers the entry before the prune. A path under a pruned directory
    /// is not reached.
    statoverride_matched: Arc<Mutex<Vec<bool>>>,
    /// The `--skip-list` paths that the walk reached, one flag for each path.
    skip_list_matched: Arc<Mutex<Vec<bool>>>,
    /// The OR-form `--statoverride` entries whose value a source took, one
    /// flag for each path. An entry applies to one entry of the tree in each
    /// run, so the mode callback reads this field. It does not read
    /// [`statoverride_matched`](WalkOptions::statoverride_matched), because a
    /// path that the skip list prunes counts as reached with no source that
    /// takes the value.
    statoverride_spent: Arc<Mutex<Vec<bool>>>,
    /// `true` if the source of the current overlay is an archive.
    ///
    /// All sources of a run share one modifier. An OR-form `--statoverride`
    /// entry for a directory under the walk root applies to a member of an
    /// archive. It does not apply to a file system walk or a `ref` source. For
    /// this reason, the caller sets the source kind in this field before each
    /// source is read.
    source_is_tar: Arc<AtomicBool>,
}

/// The in-tree path of the walk root, which both control files write as `/`.
const WALK_ROOT: &str = "/";

impl WalkOptions {
    /// Reads both control files, in the order of the `ostree` command.
    fn read(args: &CommitArgs) -> std::result::Result<WalkOptions, String> {
        let statoverride = match args.statoverride.as_deref() {
            Some(path) => read_statoverride(path)?,
            None => Vec::new(),
        };
        let skip_list = match args.skip_list.as_deref() {
            Some(path) => fold_paths(read_skip_list(path)?),
            None => Vec::new(),
        };
        // The filter never gets the walk root, so this step handles a skip
        // list that names it. Then the whole tree is pruned, every other entry
        // of each file stays unmatched, and the commit has nothing to write.
        let root_pruned = skip_list.iter().any(|path| path == WALK_ROOT);
        // One flag for each path. A root entry is marked here, because the
        // filter never gets it.
        let skip_seen: Vec<bool> = skip_list.iter().map(|path| path == WALK_ROOT).collect();
        let statoverride_or = fold_overrides(&statoverride, false);
        // The walk root counts as reached, also if the skip list prunes it. If
        // the root is pruned, the walk runs over nothing and the mode callback
        // never gets the root. For this reason, an OR entry that names the root
        // is also marked here.
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

    /// Returns `true` if an option of this set changes a mode.
    fn shapes_modes(&self) -> bool {
        !self.statoverride_or.is_empty() || !self.statoverride_assign.is_empty()
    }

    /// Returns the `--statoverride` paths that the walk did not reach.
    ///
    /// The list has one entry for each path. An `=` entry is not checked, so
    /// an `=` entry that matches nothing is ignored. A path that both forms
    /// name is checked once, through its OR-form entry. A path that the skip
    /// list prunes is reached, and a path under a pruned directory is not
    /// reached.
    fn unmatched_statoverride(&self) -> Vec<String> {
        let matched = self.statoverride_matched.lock().unwrap();
        self.statoverride_or
            .iter()
            .zip(matched.iter())
            .filter(|(_, hit)| !**hit)
            .map(|((path, _), _)| path.clone())
            .collect()
    }

    /// Returns the `--skip-list` paths that the walk did not reach.
    ///
    /// The list has one entry for each path. Every path is checked.
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

/// Prints the `Unmatched <kind> path:` lines of one control file.
///
/// The lines go to standard error, one line for each path that the walk did
/// not reach. The error is the summary line after these lines. The caller
/// reports it and exits 1. An empty list gives `Ok`.
fn report_unmatched(kind: &str, unmatched: &[String]) -> std::result::Result<(), String> {
    if unmatched.is_empty() {
        return Ok(());
    }
    for path in unmatched {
        eprintln!("Unmatched {kind} path: {path}");
    }
    Err(format!("Unmatched {kind} paths"))
}

/// The maximum size in bytes of a `--statoverride` or `--skip-list` file.
///
/// It is the same limit as the limit of `-F/--body-file`, and it bars an
/// unbounded read.
const CONTROL_FILE_LIMIT: u64 = 128 * 1024 * 1024;

/// Reads a control file as bytes.
///
/// If a path does not open, the error has the form of the `ostree` command and
/// names the path as the command line gives it. A directory gets an error with
/// no path. The read stops at [`CONTROL_FILE_LIMIT`], and a larger file is
/// refused.
fn read_control_bytes(path: &Path) -> std::result::Result<Vec<u8>, String> {
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
    Ok(bytes)
}

/// Reads a control file as text.
///
/// All bytes must be UTF-8, and a NUL byte counts as invalid. One invalid byte
/// at any position refuses the command with `Invalid UTF-8`, as the `ostree`
/// command does. An accepted file holds text alone.
///
/// The walk compares the bytes of each entry with the bytes of the walk path. A
/// replacement character in the file then names that character and nothing
/// else.
fn read_control_file(path: &Path) -> std::result::Result<String, String> {
    let bytes = read_control_bytes(path)?;
    if bytes.contains(&0) {
        return Err("Invalid UTF-8".to_owned());
    }
    String::from_utf8(bytes).map_err(|_| "Invalid UTF-8".to_owned())
}

/// Reads a `--statoverride` file.
///
/// Each line is `[=]<decimal mode> <path>`. Blank lines are ignored, and all
/// text after the first space is the path. A line with no space is refused.
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

/// Reads a `--skip-list` file: one path on each line, blank lines ignored.
fn read_skip_list(path: &Path) -> std::result::Result<Vec<String>, String> {
    Ok(read_control_file(path)?
        .split('\n')
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect())
}

/// Reduces the `--statoverride` entries of one form to one entry per path.
///
/// The entry has the value of the last line that names the path, at the
/// position of the first line that names it. The two forms are reduced
/// separately, so a path that both forms name keeps a value under each form.
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

/// Reduces the `--skip-list` paths to one entry for each path.
///
/// Each entry stays at the position of the first line that names it.
fn fold_paths(paths: Vec<String>) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    paths
        .into_iter()
        .filter(|path| seen.insert(path.clone()))
        .collect()
}

/// Reads the leading decimal run of a `--statoverride` mode field.
///
/// The field is an optional sign, then digits. The value is truncated to 32
/// bits. Text with no digit is the value zero, so under the OR form, an entry
/// with a mode that cannot be read changes nothing.
///
/// # Divergence
///
/// The `ostree` command reads the field as a C `double` and converts it. As a
/// result, `ostree` also accepts a hexadecimal literal, a decimal point, and an
/// exponent. It turns a value out of the 32-bit range into `0x80000000`.
///
/// These forms are outside the documented format, which is a mode in decimal.
/// Their conversion out of range depends on the platform. ostrya reads decimal
/// alone. This is a recorded divergence.
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

/// One tree source that a `commit` command line names.
enum TreeSpec {
    /// `--tree=dir=PATH`, and the positional `PATH`. The path is kept as the
    /// command line gives it, because `--consume` reads that text.
    Dir(PathBuf),
    /// `--tree=tar=PATH`. The `ostree` command writes standard input as `-`,
    /// and also reaches it through `/dev/stdin`.
    Tar(PathBuf),
    /// `--tree=ref=REV`.
    Ref(String),
    /// The default source of ostrya: a tar stream on standard input. The
    /// `ostree` command walks the current working directory. This is a
    /// recorded divergence.
    Stdin,
}

/// One tree source, opened or resolved.
enum OpenSource {
    /// A directory, and the path that named it.
    Dir(std::fs::File, PathBuf),
    /// A tar stream.
    Tar(ostrya_rt::FileReader),
    /// A committed tree, by its root dirtree and dirmeta checksums.
    Ref(Checksum, Checksum),
}

/// The `ENOTDIR` error number for a source that is not a directory.
///
/// ostrya reads the metadata of the source with no symlink follow. It refuses
/// each source that this read does not show as a directory. A symlink that
/// names a directory is then also refused, as `opendir` of the `ostree` command
/// refuses it.
const ENOTDIR: i32 = 20;

/// Returns the source list of a `commit` command line, in overlay order.
///
/// The `--tree` values come in command-line order. With no `--tree`, the
/// positional `PATH` is the one source. With neither, ostrya reads a tar stream
/// from standard input. A positional `PATH` with any `--tree` is ignored and
/// not read, and the exit status stays 0.
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

/// Opens or resolves one tree source.
///
/// The caller opens and overlays the sources one at a time and in order. The
/// error for a source that does not open then comes after every earlier source
/// is read. It also comes after `--consume` removed the paths of those sources.
/// The timestamp is read after the last source is overlaid, so this error comes
/// before the error for a refused timestamp.
///
/// If a `dir=` or a `tar=` source does not open, the function returns the
/// message and does not exit. The caller holds an open transaction, and its
/// staging directory must be reaped first.
///
/// A metadata read with no symlink follow shows that a `dir=` source is a
/// directory, and the open comes after that read. The path can change between
/// the two calls. For this reason, the walk opens the descriptor again with
/// `OFlags::DIRECTORY | OFlags::NOFOLLOW` (`ostrya::ingest::open_walk_root`).
/// The walk then refuses a replacement from a race that is not a directory.
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
            OpenSource::Tar(ostrya_rt::FileReader::from(file))
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

/// Overlays one tree source onto `mtree`.
///
/// The directory metadata of a later source replaces the metadata of an
/// earlier source. Its files replace files of the same name. A name that is a
/// directory in one source and a file in the other source is refused.
///
/// A refusal comes back as the message, with no exit, because the caller
/// holds an open transaction. Its staging directory must be reaped first.
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
            // After the contents are ingested, `--consume` removes the source
            // directory itself, unless the path is `.`. The test is on the
            // text, so an absolute path that names the working directory is
            // removed, and `./` is also removed. A comparison with `Path`
            // equality loses this difference, because `./` and `.` name one
            // directory. If the removal fails, the commit aborts and the
            // message names the path, as the `ostree` command does.
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

/// The PCRE2 start-of-pattern option for the `any` newline convention.
///
/// GLib `GRegex` compiles under this convention.
const NEWLINE_ANY: &str = "(*ANY)";

/// Returns the tar import options of a `commit` command line.
///
/// The pathname filter is read when a tar source loads, so a refused value is
/// reported only where an archive is read. A command line that names no tar
/// source accepts a malformed filter with exit 0, as the `ostree` command does.
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
    // The `ostree` command compiles this value as a PCRE2 pattern through GLib
    // `GRegex`, with UTF and UCP on and every other compile option at its
    // default. Probes of `ostree` show these options. The JIT stays off. The
    // interpreter and the JIT differ in how they count the match limits, and
    // they match the same text.
    //
    // `GRegex` also sets the newline convention to `any`. Under this
    // convention, each of these ends a line: a carriage return, a line feed,
    // and the pair. A vertical tab, a form feed, `U+0085`, `U+2028`, and
    // `U+2029` also end a line. The convention sets where `$`, `\Z`, and
    // `(?m)^` match, and which characters `.` and `\N` exclude. The rename of a
    // name that holds one of these characters then follows the convention.
    //
    // The `pcre2` crate has no option for the convention. For this reason, the
    // compiled pattern has the PCRE2 start-of-pattern option `(*ANY)` before
    // the value. If the value states a convention itself, that convention
    // follows `(*ANY)` and wins, in both commands.
    let regex = RegexBuilder::new()
        .utf(true)
        .ucp(true)
        .build(&format!("{NEWLINE_ANY}{pattern}"))
        .map_err(|err| {
            // PCRE2 counts the offset in the compiled pattern, and the line of
            // the `ostree` command counts it in the value that the caller
            // wrote. Both counts are in code units, so the result of the
            // subtraction is a byte count. `ostree` writes a character offset
            // here. This is a recorded divergence.
            let at = match err.offset() {
                Some(offset) => {
                    format!(" at char {}", offset.saturating_sub(NEWLINE_ANY.len()))
                }
                None => String::new(),
            };
            format!(
                "--tar-pathname-filter: Error while compiling regular expression \
                 \u{2018}{pattern}\u{2019}{at}: {}",
                pcre2_reason(&err)
            )
        })?;
    let replacement = parse_replacement(replacement).map_err(|reason| {
        format!(
            "--tar-pathname-filter: Error while reading the replacement \
             \u{2018}{replacement}\u{2019}: {reason}"
        )
    })?;
    // If the filter makes the name of a member empty, the member names the
    // tree root, as in the `ostree` command. A directory member mapped to the
    // empty string gives the metadata of the root, so `^dir1/(.*)$,\1`
    // removes a prefix. A file member mapped to the empty string names the
    // root as a file, which the tar importer refuses. This is a recorded
    // divergence.
    let pattern = pattern.to_owned();
    let mut locs = regex.capture_locations();
    opts.rename = Some(Box::new(move |name: &str| {
        let subject = name.as_bytes();
        let mut out = Vec::with_capacity(subject.len());
        // The replacement is global, so the loop splices one match at a time.
        // `held` is the start of the unchanged tail, and `search` is the start
        // of the next attempt. The two differ after an empty match. The search
        // then moves past one whole character, and that character stays in the
        // tail. A move of one byte can start an attempt inside a character, and
        // PCRE2 gives no meaning to such an attempt.
        let mut held = 0;
        let mut search = 0;
        while search <= subject.len() {
            let found = regex
                .captures_read_at(&mut locs, subject, search)
                .map_err(|err| {
                    Error::Tar(format!(
                        "--tar-pathname-filter: Error while matching regular expression \
                         \u{2018}{pattern}\u{2019}: {}",
                        pcre2_reason(&err)
                    ))
                })?;
            let Some(found) = found else { break };
            out.extend_from_slice(&subject[held..found.start()]);
            expand_replacement(
                &replacement,
                subject,
                regex.capture_names(),
                &locs,
                &mut out,
            );
            held = found.end();
            search = if found.end() > found.start() {
                found.end()
            } else {
                next_character(name, found.end())
            };
        }
        out.extend_from_slice(&subject[held..]);
        // `\C` matches one byte, so a rewrite can split a character. ostrya
        // stores a pathname as text and refuses such a result. The `ostree`
        // command ends the run on a GLib assertion in the same case. This is a
        // recorded divergence.
        String::from_utf8(out).map_err(|_| {
            Error::Tar(format!(
                "--tar-pathname-filter: the rewritten name of \u{2018}{name}\u{2019} is \
                 not valid UTF-8"
            ))
        })
    }));
    Ok(opts)
}

/// Returns the reason of a PCRE2 error, without the prefix text of the crate.
///
/// Each refusal line names the operation and the character offset at the
/// positions of the line of the `ostree` command. For this reason, the text of
/// the crate is dropped. The kind of the error gives the form of that text:
///
/// - A compile error names the operation, and an offset clause that the crate
///   writes for some errors only.
/// - Every other kind names the operation up to the first `": "`.
///
/// Text of another form is returned whole.
fn pcre2_reason(err: &pcre2::Error) -> String {
    let text = err.to_string();
    let reason = match err.kind() {
        pcre2::ErrorKind::Compile => text
            .strip_prefix("PCRE2: error compiling pattern")
            .map(|rest| match rest.strip_prefix(" at offset ") {
                Some(after) => after.trim_start_matches(|c: char| c.is_ascii_digit()),
                None => rest,
            })
            .and_then(|rest| rest.strip_prefix(": ")),
        _ => text
            .strip_prefix("PCRE2: error ")
            .and_then(|rest| rest.split_once(": "))
            .map(|(_, reason)| reason),
    };
    reason.unwrap_or(text.as_str()).to_owned()
}

/// Returns the offset of the character after the character at `at`.
///
/// An empty match moves the search in this way, so no attempt starts inside a
/// character. For an offset at the end of the name, the result is one past the
/// end, which ends the loop.
fn next_character(name: &str, at: usize) -> usize {
    let mut next = at + 1;
    while next < name.len() && !name.is_char_boundary(next) {
        next += 1;
    }
    next
}

/// One piece of a parsed replacement template.
enum ReplacementPiece {
    /// Literal text.
    Text(String),
    /// The text that a group matched, by number.
    Index(usize),
    /// The text that a group matched, by name.
    Name(String),
}

/// Reads the replacement half of `--tar-pathname-filter`.
///
/// The syntax is the syntax of `g_regex_replace`. ostrya keeps it because an
/// operator writes this syntax:
///
/// - `\0` to `\9`, `\g<name>`, and `\g<number>` name a group.
/// - `\\` is a backslash.
/// - `\n`, `\t`, `\r`, `\a`, `\b`, `\f`, and `\v` are the control characters.
/// - Any other escape is refused.
/// - `$` has no meaning.
///
/// A group that is unset, or that the expression does not declare, adds
/// nothing.
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

/// Appends the replacement text of one match.
///
/// `names` holds the capture names of the expression by group number. A
/// `\g<name>` reference reaches its group through this list. `(?J)` lets
/// several groups have one name. The reference then resolves to the first
/// group, by number, that has the name and that the match set.
///
/// A reference that reaches no set group, and a name that the expression does
/// not declare, add nothing.
fn expand_replacement(
    pieces: &[ReplacementPiece],
    subject: &[u8],
    names: &[Option<String>],
    locs: &CaptureLocations,
    out: &mut Vec<u8>,
) {
    for piece in pieces {
        match piece {
            ReplacementPiece::Text(text) => out.extend_from_slice(text.as_bytes()),
            ReplacementPiece::Index(index) => push_group(subject, locs, *index, out),
            ReplacementPiece::Name(name) => {
                let group = names.iter().enumerate().find_map(|(group, held)| {
                    (held.as_deref() == Some(name.as_str()) && locs.get(group).is_some())
                        .then_some(group)
                });
                if let Some(group) = group {
                    push_group(subject, locs, group, out);
                }
            }
        }
    }
}

/// Appends the text that one capture group matched.
fn push_group(subject: &[u8], locs: &CaptureLocations, group: usize, out: &mut Vec<u8>) {
    if let Some((start, end)) = locs.get(group) {
        out.extend_from_slice(&subject[start..end]);
    }
}

/// Returns the commit modifier that the tree-shaping options ask for.
///
/// The result is `None` if they ask for nothing. `--canonical-permissions`
/// implies the xattr skip, because canonical ingest records no extended
/// attributes.
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
    // `--consume` empties each file system source during its walk. Only that
    // walk reads the flag, so a `tar` or a `ref` source ignores it.
    if args.consume {
        flags |= CommitModifierFlags::CONSUME;
    }
    let shapes_modes = args.mode_ro_executables || walk.shapes_modes();
    // An empty cache resolves nothing, so it asks for no modifier of its own.
    // An `archive` repository stores every content object compressed and adds
    // no entry to the cache. A modifier over that empty cache makes a `ref`
    // source lose the checksum-copy overlay path, with no gain.
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
        // `--statoverride` entry for the same path is marked here. The walk
        // reached the path and pruned it there, which counts as reached. A path
        // under a pruned directory is never offered and stays unmatched.
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
            // `--mode-ro-executables` applies first, so a `--statoverride`
            // entry for the same path sets the final mode of the entry.
            if ro_executables && mode & S_IFMT == S_IFREG && mode & EXEC_BITS != 0 {
                mode &= !WRITE_BITS;
            }
            let name = path.as_os_str().as_bytes();
            // The OR form comes before the `=` form. If a path has an entry of
            // each form, only the OR value reaches the mode. The order of the
            // two lines in the file does not change this.
            if let Some(index) = or_entries.iter().position(|(e, _)| e.as_bytes() == name) {
                matched.lock().unwrap()[index] = true;
                // An OR entry applies to one tree entry in each run. The first
                // entry that a source offers at its path spends it. A later
                // source at that path keeps its own mode.
                let spent = std::mem::replace(&mut spent_entries.lock().unwrap()[index], true);
                // A directory under the walk root spends the entry and takes no
                // value from it. Its mode then comes from the `=` form, or from
                // the walk if there is no `=` entry. A member of an archive is
                // the exception, because there the OR value applies to a
                // directory.
                if !spent
                    && (name == WALK_ROOT.as_bytes()
                        || mode & S_IFMT != S_IFDIR
                        || source_is_tar.load(Ordering::Relaxed))
                {
                    return mode | or_entries[index].1;
                }
            }
            // An `=` entry sets only the permission bits. The file-type bits of
            // the entry stay, so a value with type bits of its own changes the
            // type in the mode.
            match assign_entries.iter().find(|(e, _)| e.as_bytes() == name) {
                Some((_, value)) => (mode & S_IFMT) | value,
                None => mode,
            }
        }));
    }
    Some(modifier)
}

/// Reads a `--timestamp` value.
///
/// The value is `@SECONDS` since the Unix epoch, or a date and time with an
/// explicit UTC offset. Whitespace around the value is ignored. For a value
/// that this reader does not accept, the result is `None`. `commit` then
/// reports it in the words of the `ostree` command.
///
/// # Divergence
///
/// `ostree` reads a superset:
///
/// - a wall-clock time with no offset, in the local time of `ostree`
/// - a relative expression, for example `now` or `yesterday`
/// - an empty value, which is midnight of the current day
///
/// These forms need a time-zone database or a natural-language date reader.
/// ostrya refuses them. This is a recorded divergence.
fn parse_timestamp(text: &str) -> Option<u64> {
    let text = text.trim_matches(|c: char| c.is_ascii_whitespace());
    match text.strip_prefix('@') {
        Some(seconds) => parse_epoch(seconds),
        None => parse_datetime(text),
    }
}

/// Reads the `@SECONDS` form of a `--timestamp` value.
///
/// The form is an optional sign, a decimal run, and an optional fractional
/// part. The fractional part names a sub-second that the commit timestamp
/// cannot hold, so it is dropped. A value before the epoch is recorded as the
/// two's-complement form of the unsigned field, as the `ostree` command
/// records it.
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

/// Reads the absolute form of a `--timestamp` value.
///
/// The form is `YYYY-MM-DD`, a `T` or a space, `HH:MM[:SS]`, an optional
/// fractional second, and a UTC offset. The offset is `Z`, or `+HH`,
/// `+HH:MM`, `+HHMM`, and their negatives. The offset is required. Without an
/// offset, the value names a wall-clock time in a zone that this reader does
/// not resolve.
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
    // A leap second is written as :60 and becomes the next second, which an
    // unsigned epoch count can hold.
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let seconds =
        days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second - offset;
    Some(seconds as u64)
}

/// Reads a UTC offset in seconds, to subtract from the stated wall clock.
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

/// Reads exactly `count` decimal digits from the front of `text`.
///
/// The result is the value and the rest of the text.
fn take_digits(text: &str, count: usize) -> Option<(i64, &str)> {
    let (head, rest) = text.split_at_checked(count)?;
    if !head.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((head.parse().ok()?, rest))
}

/// Returns the number of days in `month` of `year`.
///
/// The calendar is the proleptic Gregorian calendar of the epoch count.
fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Returns the days from `1970-01-01` to a proleptic Gregorian date.
///
/// The value is negative before the epoch. The era arithmetic counts 400-year
/// cycles of 146097 days each, so the function needs no table and no loop.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Returns a refspec record without its line terminator.
///
/// One trailing `\n` is dropped, then one trailing `\r`. A subpath record
/// keeps all its bytes.
fn batch_refspec(record: &[u8]) -> &[u8] {
    let record = record.strip_suffix(b"\n").unwrap_or(record);
    record.strip_suffix(b"\r").unwrap_or(record)
}

/// Returns the `(refspec, subpath)` pairs of a batch stream.
///
/// The records are separated by NUL, and they are read two at a time:
///
/// - An empty record in the refspec position ends the stream.
/// - A trailing refspec with no record after it has no subpath, which names
///   the whole tree.
/// - An empty record in the subpath position is a subpath value of its own.
///
/// A final record with no terminator counts. An empty segment with nothing
/// after it is then the terminator of the record before it. A stream that ends
/// in NUL has no trailing empty record.
///
/// The scan stops at the record that ends the stream, so the segments after it
/// cost nothing. The walk holds only the pairs of the stream.
fn batch_pairs(bytes: &[u8]) -> Vec<(&[u8], Option<&[u8]>)> {
    let mut records = bytes.split(|byte| *byte == 0).peekable();
    let mut pairs = Vec::new();
    while let Some(refspec) = records.next() {
        if refspec.is_empty() {
            break;
        }
        let subpath = match records.next() {
            Some(record) if !(record.is_empty() && records.peek().is_none()) => Some(record),
            _ => None,
        };
        pairs.push((batch_refspec(refspec), subpath));
    }
    pairs
}

/// Returns one batch refspec record as text.
///
/// A record that is not UTF-8 names no revision that ostrya resolves, so the
/// record is refused. It is not read with a replacement character.
fn batch_refspec_str(record: &[u8]) -> &str {
    match std::str::from_utf8(record) {
        Ok(refspec) => refspec,
        Err(_) => exit_error(&format!(
            "Invalid refspec {}",
            String::from_utf8_lossy(record)
        )),
    }
}

/// Reads the batch stream of a `checkout` command line.
///
/// If the command line names neither source, the result is `None`. Standard
/// input wins over a file, in any command-line order.
fn read_batch(args: &CheckoutArgs) -> std::result::Result<Option<Vec<u8>>, String> {
    if args.from_stdin {
        return read_batch_stdin().map(Some);
    }
    match args.from_file.as_deref() {
        Some(path) => read_control_bytes(path).map(Some),
        None => Ok(None),
    }
}

/// Reads the batch stream from standard input.
///
/// A batch of checkouts is control input, so the read is bounded by
/// [`CONTROL_FILE_LIMIT`], as every other control input is.
fn read_batch_stdin() -> std::result::Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut bounded = std::io::Read::take(std::io::stdin().lock(), CONTROL_FILE_LIMIT + 1);
    std::io::Read::read_to_end(&mut bounded, &mut bytes).map_err(|err| io_reason(&err))?;
    if bytes.len() as u64 > CONTROL_FILE_LIMIT {
        return Err(format!(
            "Control file larger than {CONTROL_FILE_LIMIT} bytes"
        ));
    }
    Ok(bytes)
}

/// The `--skip-list` paths, split by the form of each line in the file.
///
/// The library calls the filter with the path of the entry from the checkout
/// root, with no trailing slash, and with the root as `/`. The file writes a
/// directory under the root with a trailing slash.
///
/// A line with a trailing slash is kept under the name without the slash. Every
/// other line is kept as the file writes it. The filter looks up both sets with
/// the path from the library, which allocates nothing for each entry.
struct SkipPaths {
    /// The lines that name a directory under the root, each without its
    /// trailing slash.
    dirs: HashSet<String>,
    /// Every other line, the `/` of the root among them.
    files: HashSet<String>,
}

/// Reads the `--skip-list` paths for all checkouts of the command line.
///
/// If the command line names no list, nothing is read. `checkout` reports no
/// unmatched entry, so the sets have no order, and a duplicate line changes
/// nothing.
fn read_skip_paths(path: Option<&Path>) -> Option<Arc<SkipPaths>> {
    let path = path?;
    let lines = match read_skip_list(path) {
        Ok(lines) => lines,
        Err(message) => exit_error(&message),
    };
    let mut paths = SkipPaths {
        dirs: HashSet::new(),
        files: HashSet::new(),
    };
    for line in lines {
        // The root is written `/`, and the strip of its slash leaves nothing.
        // For this reason, the root stays with the lines that the path itself
        // matches.
        match line.strip_suffix('/') {
            Some(dir) if !dir.is_empty() => paths.dirs.insert(dir.to_owned()),
            _ => paths.files.insert(line),
        };
    }
    Some(Arc::new(paths))
}

/// Returns the checkout filter of a `--skip-list`.
fn skip_list_filter(paths: Arc<SkipPaths>) -> CheckoutFilterFn {
    Box::new(move |path: &Path, meta: &FileMeta| {
        let path = path.to_string_lossy();
        let skipped = if meta.mode & S_IFMT == S_IFDIR && path != "/" {
            paths.dirs.contains(path.as_ref())
        } else {
            paths.files.contains(path.as_ref())
        };
        if skipped {
            FilterResult::Skip
        } else {
            FilterResult::Allow
        }
    })
}

/// Returns the library options of one checkout of a `checkout` command line.
///
/// Each checkout of a batch takes its own options, because the filter is a
/// callback that the options own.
///
/// `-U` applies no owner and no xattrs, and reduces the mode of a regular file
/// to `perm & 0777`. The metadata of a `--subpath` directory becomes the
/// metadata of the destination root. A `--subpath` file or symlink goes inside
/// a new destination directory.
///
/// `enable_fsync` is the policy that the caller resolved from `[core] fsync`
/// of the repository and `--fsync`. Every checkout of a batch uses this one
/// value.
fn checkout_options(
    args: &CheckoutArgs,
    filter: Option<CheckoutFilterFn>,
    enable_fsync: bool,
) -> CheckoutOptions {
    let mode = if args.user_mode {
        CheckoutMode::User
    } else {
        CheckoutMode::None
    };
    let mut opts = CheckoutOptions::new(mode);
    opts.force_copy = args.force_copy;
    opts.require_hardlinks = args.require_hardlinks;
    opts.bareuseronly_dirs = args.bareuseronly_dirs;
    opts.process_whiteouts = args.whiteouts;
    opts.process_passthrough_whiteouts = args.process_passthrough_whiteouts;
    opts.enable_fsync = enable_fsync;
    opts.overwrite = if args.union {
        OverwriteMode::UnionFiles
    } else if args.union_add {
        OverwriteMode::AddFiles
    } else if args.union_identical {
        OverwriteMode::UnionIdentical
    } else {
        OverwriteMode::None
    };
    opts.filter = filter;
    opts
}

/// Writes the composefs image of one commit to `destination`.
///
/// The library serializes the image while it builds it, so a refusal or a
/// failed write comes after part of the file is on disk. The export writes to
/// a temporary file in the directory of the destination. When the image is
/// complete, a rename moves the temporary file over the destination.
///
/// If the export does not complete, it writes no destination, and a
/// destination that already exists stays as it was. If the export completes,
/// it replaces the destination in one step. The temporary file is in the
/// directory of the destination, so the rename stays in one file system for
/// each destination name.
async fn export_composefs(
    repo: &Repo,
    opts: &ComposefsOptions,
    commit: &Checksum,
    destination: &Path,
) -> Result<()> {
    let dir = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let temp = dir.join(format!(".ostrya-composefs-{}.tmp", std::process::id()));
    let out = std::fs::File::create(&temp).map_err(Error::Io)?;
    // The `ostree` command writes the image with mode 0644 for each umask.
    // `File::create` opens with 0666 reduced by the umask, so the code sets
    // the mode on the open descriptor. `fchmod` ignores the umask, and the
    // rename keeps the mode on the destination.
    if let Err(err) = out.set_permissions(std::fs::Permissions::from_mode(0o644)) {
        let _ = std::fs::remove_file(&temp);
        return Err(Error::Io(err));
    }
    let written = repo
        .export_composefs_to(commit, opts, out.as_fd())
        .await
        .and_then(|_| std::fs::rename(&temp, destination).map_err(Error::Io));
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    written
}

/// Checks out a commit, or each pair of a batch, into the destination.
async fn checkout(repo: Repo, args: CheckoutArgs, fsync: Option<bool>) -> Result<()> {
    // The `ostree` command opens a `--from-file` before each other check of
    // the subcommand. If the file does not open, that error comes before the
    // union pair, the composefs incompatibility, and the revision.
    let batch = match read_batch(&args) {
        Ok(batch) => batch,
        Err(message) => exit_error(&message),
    };

    let pairs = batch.as_deref().map(batch_pairs);

    // The `ostree` command makes each command-line refusal of `checkout` in
    // the scope of one checkout. The prefix of each refusal under a batch
    // option shows this. A stream with no pair enters no such scope and
    // reaches none of the refusals, so it exits 0 for each command line. Each
    // refusal reads only the command line, which no pair changes, so one pass
    // over the refusals covers all pairs of the stream.
    let in_scope = pairs.as_ref().is_none_or(|pairs| !pairs.is_empty());

    // The plain path resolves its own COMMIT. Under a batch option, the first
    // positional is the destination and each revision comes from the record
    // stream, so this code resolves no revision.
    let commit = if batch.is_some() {
        None
    } else {
        Some(resolve(&repo, &args.commit).await?)
    };

    // The three union options are mutually exclusive. If the command line holds
    // more than one pair, ostrya reports the first pair in this order. The
    // check is in this function because the `ostree` command makes it after the
    // repository opens and the revision resolves. A rule of the `clap`
    // definition runs before both steps. The check also comes before the
    // composefs export, so ostrya refuses such a pair whatever else the command
    // line holds.
    if in_scope {
        if args.union && args.union_add {
            exit_error("Cannot specify both --union and --union-add");
        }
        if args.union && args.union_identical {
            exit_error("Cannot specify both --union and --union-identical");
        }
        if args.union_add && args.union_identical {
            exit_error("Cannot specify both --union-add and --union-identical");
        }
    }

    // Under a batch option, the destination is the first positional and the
    // second positional is ignored. This is the arity of the `ostree` command.
    // A destination value of no bytes names no path, so ostrya refuses it. It
    // does not stand for the working directory. `clap` refuses the same value
    // on the plain path.
    let destination = match &batch {
        Some(_) => {
            if in_scope && args.commit.is_empty() {
                exit_error("DESTINATION must be specified");
            }
            PathBuf::from(&args.commit)
        }
        None => args
            .destination
            .clone()
            .expect("clap requires DESTINATION where no batch option is given"),
    };

    if args.composefs || args.composefs_noverity {
        // A whiteout switch changes the tree that a checkout writes, and a
        // skip list removes paths from it. `--require-hardlinks`,
        // `--force-copy`, `--bareuseronly-dirs`, and `--disable-cache` decide
        // how a checkout writes an entry. A composefs export writes an image
        // of the commit tree, so none of these options applies to it. The
        // `ostree` command refuses each combination and writes no image.
        // ostrya refuses it with the same words. The two batch options are
        // not refused: `ostree` exports one image for each pair, from the
        // revision of the pair.
        if in_scope
            && (args.whiteouts
                || args.process_passthrough_whiteouts
                || args.skip_list.is_some()
                || args.require_hardlinks
                || args.force_copy
                || args.bareuseronly_dirs
                || args.disable_cache)
        {
            exit_error("Specified options are incompatible with --composefs");
        }
        let opts = ComposefsOptions {
            verity: if args.composefs_noverity {
                VerityPolicy::Disabled
            } else {
                VerityPolicy::Computed
            },
        };
        let Some(pairs) = pairs else {
            let commit = commit.expect("the plain path resolved its own COMMIT");
            return export_composefs(&repo, &opts, &commit, &destination).await;
        };
        // The subpath of a pair has no effect, as `--subpath` has no effect on
        // the plain path. A composefs export writes the image of the full
        // commit tree.
        for (refspec, _) in pairs {
            let commit = resolve(&repo, batch_refspec_str(refspec)).await?;
            export_composefs(&repo, &opts, &commit, &destination).await?;
        }
        return Ok(());
    }

    // The `-H` check comes after the composefs export, which makes no
    // hardlink and has no use for the switch.
    //
    // The hardlink establishes identity, so the `ostree` command accepts
    // `--union-identical` only with `-H`, for each repository mode. The
    // library has the same pairing as its own guard. The library decides at
    // the entry which mode pairs can hardlink.
    if in_scope && args.union_identical && !args.require_hardlinks {
        exit_error("--union-identical requires --require-hardlinks");
    }

    // ostrya keeps no uncompressed object cache, so a checkout writes none
    // and reads none. The switch asks for the behavior that ostrya already
    // has, so ostrya accepts it and it has no effect.
    let _ = args.disable_cache;

    // The checkout path takes the fsync policy as a plain value, so the code
    // reads the configured `[core] fsync` here, where it is used. The option
    // narrows the policy and never widens it. A repository with
    // `[core] fsync=false` syncs nothing under `--fsync=true`. The read comes
    // after the composefs export, which applies no such policy, and before
    // each checkout. One read covers the plain path and each pair of a batch.
    let enable_fsync = repo.config().fsync()? && fsync != Some(false);

    let dest_dir = std::fs::File::open(".").map_err(Error::Io)?;
    let Some(pairs) = pairs else {
        let commit = commit.expect("the plain path resolved its own COMMIT");
        let mut opts = checkout_options(
            &args,
            read_skip_paths(args.skip_list.as_deref()).map(skip_list_filter),
            enable_fsync,
        );
        opts.subpath = args.subpath.clone();
        return match repo
            .checkout_at(&mut opts, dest_dir.as_fd(), &destination, &commit)
            .await
        {
            // `--allow-noent` suppresses exactly one refusal: a `--subpath`
            // that names nothing. An unresolvable COMMIT is refused before
            // this call. A subpath through an entry that is not a directory
            // keeps its refusal. The `ostree` command does both of these.
            Err(Error::SubpathNotFound(_)) if args.allow_noent => Ok(()),
            other => other,
        };
    };

    // Each pair writes into the one destination with the overwrite mode of
    // the command line. `--subpath` is dropped, and the second record of the
    // pair gives the subpath. The `ostree` command opens the skip list in the
    // scope of each pair, so a stream with no pair never reads the file.
    let skip = if pairs.is_empty() {
        None
    } else {
        read_skip_paths(args.skip_list.as_deref())
    };
    for (refspec, subpath) in pairs {
        let commit = resolve(&repo, batch_refspec_str(refspec)).await?;
        let mut opts = checkout_options(&args, skip.clone().map(skip_list_filter), enable_fsync);
        opts.subpath = subpath.map(|bytes| PathBuf::from(std::ffi::OsStr::from_bytes(bytes)));
        match repo
            .checkout_at(&mut opts, dest_dir.as_fd(), &destination, &commit)
            .await
        {
            // `--allow-noent` acts on each pair, and the stream continues.
            // Each other refusal ends the run. The pairs that are already
            // written stay in place.
            Err(Error::SubpathNotFound(_)) if args.allow_noent => {}
            Err(err) => return Err(err),
            Ok(()) => {}
        }
    }
    Ok(())
}

/// Writes the tree of a commit as a tar stream to standard output or to
/// `--output`.
///
/// The destination opens before the revision resolves, in the order of the
/// `ostree` command. An existing destination is truncated in place, so it
/// keeps its inode and its mode. A refusal after the open leaves it
/// truncated. A destination that the open creates gets mode `0o666` reduced
/// by the umask.
async fn export(repo: Repo, name: &str, args: ExportArgs) -> Result<()> {
    let Some(rev) = args.commit.as_deref() else {
        exit_with_error(name, "A COMMIT argument is required");
    };
    let out = match &args.output {
        Some(path) => {
            let file = std::fs::File::create(path).map_err(Error::Io)?;
            ostrya_rt::File::from(OwnedFd::from(file))
        }
        None => stdout_file()?,
    };
    let commit = resolve(&repo, rev).await?;
    let opts = TarExportOptions {
        subpath: args.subpath,
        prefix: args.prefix,
        skip_xattrs: args.no_xattrs,
    };
    repo.export_tar(&commit, opts, out).await
}

/// Lists, creates, or deletes refs.
///
/// `--create` wins over `--delete`, and `--collections` wins over `--alias`.
/// This is the precedence of the `ostree` command.
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

/// Points a new ref, collection ref, or alias at the revision of PREFIX.
///
/// The command line must give exactly one PREFIX. `-c` wins over `-A`, as in
/// a listing.
async fn refs_create(repo: &Repo, newref: &str, args: &RefsArgs) -> Result<()> {
    let existing = match args.prefix.len() {
        1 => args.prefix[0].as_str(),
        0 => exit_error("You must specify a revision when creating a new ref"),
        _ => exit_error("You must specify only 1 existing ref when creating a new ref"),
    };
    // The existence check resolves NEWREF as a revision in each case.
    // `--force` suppresses only the refusal for a NEWREF that resolves. The
    // resolution itself still runs. If the base of NAME is a root commit,
    // `--create=NAME^ --force` stops at this point with `Commit <checksum> has
    // no parent`. These are the words that `report_resolution_failure` gives
    // for that failure.
    let resolved = resolve_optional(repo, newref).await?;
    if !args.force && resolved.is_some() {
        exit_error(&format!(
            "--create specified but ref {newref} already exists"
        ));
    }
    // ostrya checks NEWREF as a ref name after the existence check and before
    // the positional resolves. This is the order of the `ostree` command. A
    // `^` fails the ref-name rule, so a name with an ancestry suffix is
    // refused at this step.
    if validate_refspec(newref).is_err() {
        exit_error(&format!("Invalid refspec {newref}"));
    }
    if args.collections {
        return refs_create_collection(repo, newref, existing).await;
    }
    if args.alias {
        // An alias is under `refs/heads`, so a NEWREF that names a remote is
        // refused. The message names only the remote half, for a remote that
        // exists and for one that does not. This step comes after the three
        // NEWREF checks and before the positional resolves. As a result,
        // `--create=origin:al nosuch` reports the remote and not the
        // positional, and `--force` keeps the refusal.
        if let Some((remote, _)) = newref.split_once(':') {
            exit_error(&format!("Cannot create alias to remote ref: {remote}"));
        }
        // An alias records a name, so its target must be a ref. A checksum and
        // an ancestry suffix each name a commit and no ref file.
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

/// Writes a collection ref for `-c` from a `<collection-id>:<ref>` NEWREF.
///
/// The pair names `refs/mirrors/<collection-id>/<ref>`. The steps run in the
/// order of the `ostree` command:
///
/// 1. the shape of the pair
/// 2. the revision
/// 3. the collection id
///
/// The ref-name check of each NEWREF refuses an empty half one step earlier.
/// If NEWREF holds no `:`, it names no ref. The full argument is then read as
/// the collection id, and if that id is valid, the missing name is reported.
async fn refs_create_collection(repo: &Repo, newref: &str, existing: &str) -> Result<()> {
    let pair = match newref.split_once(':') {
        // A second `:` gets the message for the pair at this step. A `^` never
        // reaches this step, because the ref-name rule refuses it earlier.
        Some((_, ref_name)) if ref_name.contains(':') => {
            exit_error(&format!("Invalid refspec {newref}"))
        }
        pair => pair,
    };
    let commit = resolve(repo, existing).await?;
    let Some((collection_id, ref_name)) = pair else {
        if !ostrya::is_collection_id(newref) {
            exit_error(&format!("Invalid collection ID {newref}"));
        }
        exit_error("Invalid ref name (null)");
    };
    if !ostrya::is_collection_id(collection_id) {
        exit_error(&format!("Invalid collection ID {collection_id}"));
    }
    let cref = CollectionRef::new(collection_id, ref_name);
    repo.set_collection_ref_immediate(&cref, Some(&commit))
        .await
}

/// Returns the commit of a ref name, or `None` if the name names no ref.
///
/// These names name no ref:
///
/// - A full checksum and a name with an ancestry suffix. Each names a commit
///   and no ref file.
/// - A name that no ref file can carry. The alias refusal reports this
///   answer, as the `ostree` command does for `..` and for an empty target.
///
/// An abbreviated checksum, a run of 1 to 63 lowercase hex characters, is
/// also revision syntax. `refs -A --create` and the prefix selection of
/// `refs -A` take the name as written and match it against no commit. A
/// prefix with no ref in the ref store names no ref. An ambiguous prefix and
/// a unique prefix are the same here, because neither names a ref.
///
/// If an I/O error occurs on the ref file, the function returns it. The
/// caller decides if a name that is a directory, or a path through a ref
/// file, is a refusal or a miss.
///
/// The lookup reads only the ref store ([`Repo::resolve_ref_tip`]), so no
/// revision syntax applies here.
async fn resolve_ref_name(repo: &Repo, rev: &str) -> Result<Option<Checksum>> {
    // A 64-character name is a checksum only in lowercase hex, as the split
    // resolution reads it. An uppercase one is looked up as a ref name, and an
    // alias to it is written.
    if rev.ends_with('^') || Checksum::from_hex_lower(rev).is_ok() {
        return Ok(None);
    }
    match repo.resolve_ref_tip(rev).await {
        Ok(found) => Ok(found),
        Err(Error::InvalidRefspec(_)) => Ok(None),
        Err(err) => Err(err),
    }
}

/// Returns `true` if `rev` names a ref file, by the rules of
/// [`resolve_ref_name`].
async fn names_a_ref(repo: &Repo, rev: &str) -> Result<bool> {
    Ok(resolve_ref_name(repo, rev).await?.is_some())
}

/// Deletes each ref that the prefixes match.
///
/// A prefix that matches nothing is not an error. The parent directories that
/// a removal empties stay in place, as in the `ostree` command.
///
/// # Whole-remote prefixes
///
/// If a whole-remote prefix matches one or more refs, the command ends with
/// exit 1, and the prefix removes none of its matches. This is the outcome of
/// `ostree`. `ostree` names each ref that it deletes as the ref half of the
/// prefix joined with the name under it. The `.` in that join gives a refspec
/// that the rule of `ostree` refuses.
///
/// The prefixes before it keep their effect. A whole-remote prefix that
/// matches no ref exits 0. The two commands use different words for the
/// refusal. This is a recorded divergence.
///
/// # Alias guard
///
/// If an alias names a ref under `refs/heads`, the deletion of that ref is
/// refused with exit 1, and the prefix that matched it removes nothing. The
/// guard runs for each prefix, after the whole-remote refusal.
/// `refs --delete deep test` removes the matches of `deep` and then reports
/// the refusal for `test`. `-c` has no alias guard.
///
/// # Prefix order
///
/// Each prefix reads the ref set and the alias set as the prior prefixes left
/// them. `refs --delete alal test/al` removes the alias and then the ref that
/// it named. If a prefix removes the last ref of a remote, a later
/// whole-remote prefix matches nothing, and both commands exit 0.
///
/// # Aliases (`-A`)
///
/// With `-A`, each prefix selects the set that a `-A` listing prints: the ref
/// that the prefix names exactly, or the aliases under it. `-c` wins over
/// `-A`. The prefix rules, the whole-remote refusal, and the alias guard apply
/// to the set that the prefix selected.
///
/// # Collection ids (`-c`)
///
/// With `-c`, the prefixes are collection ids. The id that is equal to the
/// `collection-id` of the repository removes only the refs under
/// `refs/heads`. The mirror refs with that id stay.
async fn refs_delete(repo: &Repo, args: &RefsArgs) -> Result<()> {
    if args.prefix.is_empty() {
        exit_error("At least one PREFIX is required when deleting refs");
    }
    if args.collections {
        // An id that is equal to the `collection-id` of the repository removes
        // only the refs under `refs/heads`, and the mirror refs with the same
        // id stay. A foreign id removes the mirror refs that it names.
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
    // All aliases, local and remote. A `-A` prefix filters this set, and a
    // `-A --delete` removes from it.
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
            // A ref under `refs/remotes` is removed also if an alias names it,
            // so the guard reads only the refs under `refs/heads`. These are
            // the refspecs with no `:`. If more than one guarded ref matches,
            // ostrya names the first in refspec order. The `ostree` command
            // names the first that its enumeration reaches. This is a recorded
            // divergence.
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

/// Returns the aliases that one `-A --delete` prefix removes.
///
/// This is the set that a `-A` listing prints for the prefix. The set is the
/// ref that the prefix names exactly, alias or not, or the aliases under it.
///
/// # Divergence
///
/// In the `ostree` command, only a prefix that names a remote alias exactly
/// removes it. `ostree` deletes each nested alias by the name that it prints
/// for it. For a remote alias, this name drops the remote and names no ref of
/// that remote. ostrya removes each alias that its listing names, so the
/// result for a remote prefix that holds an alias is a recorded divergence.
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

/// Returns the aliases that can name a local ref, sorted by alias refspec.
///
/// Each pair is `(alias refspec, the ref name of its link body)`.
///
/// An alias names a ref under `refs/heads` by the name of that ref. This name
/// is the link body with its leading `../` components removed. The name is
/// relative to the `refs/heads` root, also for an alias in a subdirectory.
///
/// For example, an alias at `refs/heads/test/al2` with the body `other` names
/// the ref `other`. The link itself resolves to `refs/heads/test/other`.
///
/// An alias under `refs/remotes` names no ref here. A body that reaches
/// outside `refs/heads` matches no local refspec, which is a local ref name
/// with no `:`.
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

/// Prints the local and remote refs that the prefixes match, one on each line.
///
/// Under `-r`, a tab and the commit checksum follow the name. If two prefixes
/// match a ref, the ref is printed once for each match. The prefix that
/// selected a row strips the name of that row: `refs test test/main` prints
/// `main` and then `test/main`.
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

/// Prints the aliases that the prefixes match, as `name -> target`.
///
/// If a `PREFIX` names a ref, the output is that one ref, with the commit
/// checksum as the target. Each other prefix keeps the aliases under it. The
/// name is never stripped, and `-r` adds nothing, as in the `ostree` command.
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

/// Returns the commit of the ref that a `-A` PREFIX names, alias or not.
///
/// Some prefixes reach no ref file: a directory that holds refs, a path
/// through a ref file, and an alias with a missing target ref. Such a prefix
/// names no ref, so it filters the alias listing. These paths give `EISDIR`
/// and `ENOTDIR`. Each other read failure is returned, so a permission fault
/// reaches the caller and does not show as an empty listing.
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

/// Prints the collection refs as `(collection-id, ref)`.
///
/// Under `-r`, a tab and the commit checksum follow the pair.
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

/// Returns each local and remote ref, sorted by refspec.
///
/// This is the order of a listing and the set that each prefix filters.
async fn all_refs(repo: &Repo) -> Result<Vec<(String, Checksum)>> {
    let mut all = repo.list_refs(None).await?;
    all.extend(repo.list_remote_refs().await?);
    all.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(all)
}

/// Returns the collection refs that the collection ids select.
///
/// The ids group the refs as a listing groups ref-name prefixes. The
/// `collection-id` of the repository qualifies its local refs. The mirror
/// refs carry their id in the path.
async fn select_collection_refs(repo: &Repo, ids: &[String]) -> Result<Vec<CollectionRefEntry>> {
    let all = repo.list_collection_refs().await?;
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

/// Returns the prefixes to iterate: each given prefix, or one `None` for all
/// refs.
fn prefixes(given: &[String]) -> Vec<Option<&str>> {
    if given.is_empty() {
        return vec![None];
    }
    given.iter().map(|prefix| Some(prefix.as_str())).collect()
}

/// Refuses a PREFIX that no ref name can hold or that goes through a ref file.
///
/// The `ostree` command refuses both before the prefix filters anything. The
/// check runs when each prefix is taken. The rows that an earlier prefix
/// printed and the refs that it deleted stay, as in `ostree`.
/// `refs test 'bad/'` prints the `test` rows and then reports the refusal.
///
/// The refspec rule comes first. If a prefix breaks both rules, for example
/// `plain/x/` over the ref file `plain`, both commands give the refspec
/// message.
///
/// The path probe reads the prefix under `refs/` as the directory that a
/// listing enumerates. `ostree` reads the same path. `ENOTDIR` ends the
/// command. ostrya gives one message for that condition, and `ostree` names the
/// path and the syscall. This is a recorded divergence.
///
/// A path that names nothing continues, because a prefix that matches no ref
/// exits 0 in both commands. The probe is [`Repo::check_refs_path`], one
/// fd-relative call inside the repository that the handle holds open.
async fn check_prefix(repo: &Repo, prefix: Option<&str>) -> Result<()> {
    let Some(prefix) = prefix else {
        return Ok(());
    };
    check_prefix_name(prefix)?;
    repo.check_refs_path(&prefix_path(prefix)).await
}

/// Checks a PREFIX against the refspec rule, and reports it as given.
///
/// A whole-remote prefix passes the rule. The rule refuses an empty ref name,
/// so [`whole_remote`] gives it only the remote name. This is one component,
/// which the rule reads as a name with no `/`.
///
/// Each component of a prefix, and the remote of a prefix, obeys the ref-name
/// rule. It is not empty and does not start with `-` or `.`. It holds ASCII
/// alphanumerics, `-`, `.`, `_`, and alphanumeric characters that are not
/// ASCII.
fn check_prefix_name(prefix: &str) -> Result<()> {
    let checked = whole_remote(prefix).unwrap_or(prefix);
    validate_refspec(checked).map_err(|_| Error::InvalidRefspec(prefix.to_owned()))
}

/// Returns the path under `refs/` that a PREFIX names.
///
/// This is the ref file or directory that a listing enumerates. A whole-remote
/// prefix names the directory of the remote, and its ref half stands for the
/// root of the remote.
fn prefix_path(prefix: &str) -> String {
    match whole_remote(prefix) {
        Some(remote) => format!("remotes/{remote}"),
        None => ref_path(prefix).join("/"),
    }
}

/// Returns the remote that a whole-remote prefix names.
///
/// A whole-remote prefix is a `<remote>:` prefix with an empty ref half or the
/// ref half `.`, and it names each ref of that remote. A remote name holds no
/// `/`, so a prefix such as `or/igin:` is not a whole-remote prefix. The full
/// prefix goes to the refspec rule.
fn whole_remote(prefix: &str) -> Option<&str> {
    match prefix.split_once(':') {
        Some((remote, "" | ".")) if !remote.contains('/') => Some(remote),
        _ => None,
    }
}

/// Returns `true` if a refspec is the prefix or is nested under it.
///
/// The prefix `None` matches each refspec.
fn matches_prefix(refspec: &str, prefix: Option<&str>) -> bool {
    prefix == Some(refspec) || nested_under_prefix(refspec, prefix)
}

/// Returns `true` if a refspec is nested under the prefix and is not equal to
/// it.
///
/// The prefix `None` matches each refspec. This is the `-A` filter. A prefix
/// that is equal to the name of an alias resolves that name, so the filter
/// reads a prefix only as a directory. A whole-remote prefix keeps each ref of
/// its remote, because its ref half stands for the root of the remote.
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

/// Returns the name that a listing prints for a refspec that a prefix selected.
///
/// The name is the part under the prefix. The name is the full refspec if the
/// match is exact, if the prefix names a full remote, or if no prefix applies.
/// The refspec of a remote keeps its `remote:` part, because the `ostree`
/// command strips in the ref name and then writes the refspec again.
/// `refs origin:rr` prints `origin:x` for `origin:rr/x`.
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

/// Returns the target that an alias listing prints.
///
/// The target is the symlink body with its leading `../` components removed,
/// which is the form that the `ostree` command prints. If the link leaves the
/// ref root of the alias, the target is the refspec of the target ref. The
/// ref root is `refs/heads` for a local alias and `refs/remotes/<remote>` for
/// a remote alias.
///
/// # Divergence
///
/// `refs -A --create=xal origin:rr/x` writes `../remotes/origin/rr/x`. The
/// listing prints `origin:rr/x`, a name that ostrya resolves, in place of the
/// path under `refs/`. This is a recorded divergence.
fn alias_target(refspec: &str, target: &str) -> String {
    let path = ref_path(refspec);
    let root = path_refspec(&path).map(|(root, _)| root);
    let crossed = link_path(&path[..path.len() - 1], target)
        .and_then(|path| path_refspec(&path))
        .filter(|(target_root, _)| Some(target_root) != root.as_ref())
        .map(|(_, refspec)| refspec);
    crossed.unwrap_or_else(|| alias_body_name(target).to_owned())
}

/// Returns the ref name that the link body of an alias gives.
///
/// This is the body with its leading `../` components removed. An `-A`
/// listing prints this form, and the `--delete` guard reads this name.
fn alias_body_name(target: &str) -> &str {
    let mut rest = target;
    while let Some(stripped) = rest.strip_prefix("../") {
        rest = stripped;
    }
    rest
}

/// Returns the components under `refs/` of the file that one refspec names.
///
/// For a local refspec, these are `heads` and the ref name. For a remote
/// refspec, these are `remotes`, the remote, and the ref name.
fn ref_path(refspec: &str) -> Vec<&str> {
    let (mut path, name) = match refspec.split_once(':') {
        Some((remote, name)) => (vec!["remotes", remote], name),
        None => (vec!["heads"], refspec),
    };
    path.extend(name.split('/'));
    path
}

/// Returns the ref root of a path under `refs/` and the refspec of the path.
///
/// If the path names no ref file, the result is `None`. This is the case for a
/// root with no name under it and for a path under neither `refs/heads` nor
/// `refs/remotes`.
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

/// Returns the path under `refs/` that a symlink body names, read from `dir`.
///
/// `dir` is the directory that holds the link, and each `..` drops one
/// component. If the body reaches out of `refs/`, the result is `None`.
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

/// Prints the commit of each revision, or under `-S`, the single commit.
///
/// Under `-S`, the repository must hold exactly one commit object.
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

/// The maximum number of symlinks that one `cat` path follows.
///
/// A chain of this length resolves, and a chain with one more link is
/// refused. The `ostree` command has no such limit. 20000 links resolve, and
/// a link that names itself recurses until the process dies. This is a
/// recorded divergence.
const CAT_SYMLINK_LIMIT: usize = 256;

/// The reason that a `cat` path wrote nothing.
///
/// The reason is a refusal or a library error. ostrya reports a refusal in
/// the words of the `ostree` command and exits 1. The top-level renderer
/// prints a library error. Both go back to [`cat`] as values, so the stdout
/// writer settles before the process leaves the command.
enum CatFailure {
    Refused(String),
    Failed(Error),
}

impl From<Error> for CatFailure {
    fn from(err: Error) -> Self {
        Self::Failed(err)
    }
}

/// Writes the content of each named file to stdout, in order, as a stream.
async fn cat(repo: Repo, name: &str, args: CatArgs) -> Result<()> {
    let Some(rev) = args.commit.as_deref().filter(|_| !args.path.is_empty()) else {
        exit_with_error(name, "A COMMIT and at least one PATH argument are required");
    };
    let commit = resolve(&repo, rev).await?;
    let (root, _) = repo.read_commit(&commit.to_hex()).await?;
    let mut stdout = stdout_file()?;
    let written = cat_paths(&repo, &root, &args.path, &mut stdout).await;
    // The async writer over the duplicated stdout descriptor holds the bytes
    // that its blocking worker has not taken. If the writes do not settle
    // before the process exits, the tail of a large payload is lost. A refusal
    // and an I/O error also leave the command through this point, so each one
    // settles the bytes already written before it is reported.
    let settled = stdout.flush().await.map_err(Error::Io);
    // If a path failed and the flush also failed, the path failure is the one
    // reported. It names the condition that the command is measured on. For
    // this reason, the two failure branches drop `settled`.
    match written {
        Ok(()) => settled,
        Err(CatFailure::Refused(message)) => exit_error(&message),
        Err(CatFailure::Failed(err)) => Err(err),
    }
}

/// Writes the content of each path to `out` in order, up to the first failure.
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

/// Resolves one `cat` path to the regular file that it names.
///
/// The path is split on `/`, and each component is looked up separately. As a
/// result, `.`, `..`, and an empty component each name nothing, as in the
/// `ostree` command.
///
/// A symlink in the final position is followed, and its target is read
/// relative to the directory of the link. A symlink in each other position is
/// not followed. It reports `Not a directory`, as `ostree` does.
///
/// An empty argument reaches no component and reports the commit root as
/// absent, as `ostree` does. `/` reaches the root and is refused as a
/// directory.
async fn cat_lookup(
    repo: &Repo,
    root: &RepoTree,
    path: &str,
) -> std::result::Result<FileObject, CatFailure> {
    if path.is_empty() {
        return Err(cat_refusal("No such file or directory: /"));
    }
    let mut components = split_cat_path(path);
    // One iteration for each link that is followed, plus the iteration that
    // reads the file that the last link names.
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

/// Returns one `cat` refusal as a value, held until the stdout writer settles.
fn cat_refusal(message: &str) -> CatFailure {
    CatFailure::Refused(message.to_owned())
}

/// Walks `components` from `root` one at a time to the entry that they name.
///
/// An empty component list names the commit root. The root is a directory, so
/// it gets the refusal of a directory path.
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

/// Splits a `cat` path into the components to look up.
///
/// One optional leading `/` is dropped, and the rest is split on `/`. Each
/// other component stays as written, so `.`, `..`, and an empty component are
/// looked up and not found.
fn split_cat_path(path: &str) -> Vec<String> {
    let rest = path.strip_prefix('/').unwrap_or(path);
    if rest.is_empty() {
        return Vec::new();
    }
    rest.split('/').map(str::to_owned).collect()
}

/// Returns the components that the target of a symlink names.
///
/// A relative target is relative to the directory of the link. An absolute
/// target is relative to the commit root.
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

/// The GVariant signature of a commit object, for the parse of the raw report.
const COMMIT_SIGNATURE: &str = "(a{sv}aya(say)sstayay)";

/// Parses a GVariant type signature, with a codec refusal as a format error.
///
/// If the user types a bad signature, ostrya reports it and does not panic.
fn parse_type(signature: &str) -> Result<Type> {
    Type::parse(signature).map_err(|err| Error::InvalidFormat(err.to_string()))
}

/// Formats a value as GVariant text, with a type mismatch as a format error.
fn variant_text(ty: &Type, value: &Value) -> Result<String> {
    to_text(ty, value).map_err(|err| Error::InvalidFormat(err.to_string()))
}

/// Reports one object.
///
/// The report modes are mutually exclusive. Each pair given to the `ostree`
/// command showed this fixed precedence:
///
/// 1. the detached metadata key
/// 2. the metadata key
/// 3. the detached key listing
/// 4. the key listing
/// 5. the related commits
/// 6. the variant file
/// 7. the sizes
/// 8. the report of the object itself
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

/// Returns the commit metadata dict of the revision that `object` names.
///
/// The dict is the first member of the commit. If `-B` is not given, its byte
/// order is converted.
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

/// Returns a loaded variant with the big-endian fields on disk converted.
///
/// `-B` suppresses the conversion, so the numbers show as they are stored.
fn maybe_byteswap(value: Value, args: &ShowArgs) -> Value {
    if args.no_byteswap {
        value
    } else {
        value.byteswapped()
    }
}

/// Prints the value of one commit metadata key.
async fn show_metadata_key(repo: &Repo, object: &str, key: &str, args: &ShowArgs) -> Result<()> {
    let metadata = commit_metadata(repo, object, args).await?;
    let Some(value) = metadata.dict_get(key) else {
        exit_error(&format!("No such metadata key '{key}'"));
    };
    print_metadata_value(value, args.print_hex)
}

/// Prints the value of one detached metadata key.
async fn show_detached_key(repo: &Repo, object: &str, key: &str, args: &ShowArgs) -> Result<()> {
    let dict = detached_metadata(repo, object, args).await?;
    let Some(value) = dict.dict_get(key) else {
        exit_error(&format!("No such metadata key '{key}'"));
    };
    print_metadata_value(value, args.print_hex)
}

/// Returns the detached metadata dict of the commit.
///
/// If `-B` is not given, its byte order is converted. A commit with no
/// `.commitmeta` is reported in the words of the `ostree` command.
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

/// Prints a metadata value, which is a `v` that holds the value itself.
///
/// With `--print-hex`, a byte-array value prints as unquoted lowercase hex.
/// Each other type ignores the switch.
fn print_metadata_value(value: &Value, hex: bool) -> Result<()> {
    let (ty, inner) = match value.as_variant() {
        Some((ty, inner)) => (ty.clone(), inner),
        None => (Type::Str, value),
    };
    if hex && ty == Type::array(Type::Byte) {
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

/// Prints the commit metadata keys in sort order.
async fn show_metadata_keys(repo: &Repo, object: &str) -> Result<()> {
    let checksum = resolve(repo, object).await?;
    let (commit, _) = repo.load_commit(&checksum).await?;
    print_sorted_keys(&commit.metadata);
    Ok(())
}

/// Prints the detached metadata keys in sort order.
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

/// Prints the keys of an `a{sv}` dict in sort order, one on each line.
///
/// The output order does not depend on the order in which the dict stores
/// the keys.
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

/// Prints the related-objects array of the commit as `name checksum` lines.
///
/// The array is empty on each commit that the `ostree` command writes.
/// `ostrya commit --related` writes entries into it. A commit with no related
/// objects prints nothing and exits 0.
async fn show_related(repo: &Repo, object: &str) -> Result<()> {
    let checksum = resolve(repo, object).await?;
    let (commit, _) = repo.load_commit(&checksum).await?;
    for (refspec, target) in &commit.related {
        let target = Checksum::from_ay(target)?;
        println!("{refspec} {}", target.to_hex());
    }
    Ok(())
}

/// The maximum size of a GVariant file that `--print-variant-type` reads.
///
/// A metadata object of the format is much smaller. The full file is parsed
/// in memory, so a larger file is refused by name and is not read.
const MAX_VARIANT_FILE: u64 = 16 * 1024 * 1024;

/// Reads `path` as a serialized value of the named type and prints it.
///
/// The numeric fields are byte-order converted. The `ostree` command does this
/// on this path, with `-B` and without it.
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

/// Reads a full file, and refuses a file longer than `limit`.
///
/// A refusal comes back as the line that reports it. For a path that does not
/// open, the line has the `openat(<path>): <reason>` shape of the `ostree`
/// command.
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

/// Returns the reason text of the system for an I/O error.
///
/// The `(os error N)` tail that Rust adds is removed, because the messages of
/// the `ostree` command carry this form.
fn io_reason(err: &std::io::Error) -> String {
    let text = err.to_string();
    match text.find(" (os error ") {
        Some(cut) => text[..cut].to_owned(),
        None => text,
    }
}

/// Prints the recorded sizes of the commit and the part that is absent locally.
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

/// Reports the object that `object` names.
///
/// A metadata object reports its type and checksum. A commit also gets its own
/// report, and a file object reports its header.
///
/// A bare checksum names no type. The code probes the store for the object type
/// in this order: commit, dirtree, dirmeta, and a file object. If no object of
/// that checksum is present, the failure for the absent file object is
/// reported.
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
        // `--raw` alone reports the variant and stops. `-B` reports the variant
        // and then gives the report of the commit itself.
        if ty == ObjectType::Commit && (!args.raw || args.no_byteswap) {
            report_commit(repo, repo_path, &checksum, args).await?;
        }
        return Ok(());
    }
    match repo.load_file(&checksum).await {
        Ok(file) => report_file(&checksum, &file),
        Err(Error::ObjectNotFound { .. }) => {
            // In each mode that stores the payload in the object file itself,
            // the line for an absent object has a prefix that names the open.
            // In `archive` mode, the header is read separately, so the line has
            // no prefix.
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

/// Returns the name that the `ostree` command prints for an object type.
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
        ObjectType::ComposefsImage => "composefs-image",
        _ => ty.type_str(),
    }
}

/// Returns the GVariant signature of a metadata object type, for the raw
/// report.
fn metadata_signature(ty: ObjectType) -> &'static str {
    match ty {
        ObjectType::DirTree => "(a(say)a(sayay))",
        ObjectType::DirMeta => "(uuua(ayay))",
        _ => COMMIT_SIGNATURE,
    }
}

/// Prints the report of a commit.
///
/// The report holds the parent, the content checksum, and the date. Then come
/// the `version` metadata key if the commit has one, the subject, and the
/// body. If the commit has GPG signatures, the signature report follows.
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

/// Prints each line of `text` indented by four spaces.
///
/// This is the shape that the commit report gives a subject and a body.
fn print_indented(text: &str) {
    for line in text.split('\n') {
        println!("    {line}");
    }
}

/// Prints the GPG signature report for the `ostree.gpgsigs` of a commit.
///
/// If the commit has no GPG signatures, the function prints nothing.
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

/// Prints nothing, because a build without the gpg engine has no signatures.
///
/// The two GPG options are accepted and have no effect.
#[cfg(not(feature = "gpg"))]
async fn report_commit_signatures(_: &Repo, _: &Path, _: &Checksum, _: &ShowArgs) -> Result<()> {
    Ok(())
}

/// Returns the GPG verifier with the keyrings that `show` uses.
///
/// Under `--gpg-verify-remote`, the keyrings are the full trusted set of that
/// remote. Otherwise, the keyrings are the `gpgkeys.gpg` of the repository and
/// each `*.gpg` file in a `--gpg-homedir`.
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

/// Returns the last 16 hex digits of a fingerprint.
///
/// The signature report names a key in this form.
#[cfg(feature = "gpg")]
fn short_key_id(fingerprint: &str) -> &str {
    let start = fingerprint.len().saturating_sub(16);
    &fingerprint[start..]
}

/// Returns the user id of the signer as one string, `Name <email>`.
///
/// The parts come from the report of the engine.
#[cfg(feature = "gpg")]
fn signer_uid(sig: &SignatureInfo) -> String {
    match (&sig.user_name, &sig.user_email) {
        (Some(name), Some(email)) => format!("{name} <{email}>"),
        (Some(name), None) => name.clone(),
        (None, Some(email)) => format!("<{email}>"),
        (None, None) => String::new(),
    }
}

/// Prints the header report of a file object.
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

/// Returns the xattr set in the `{ <a(ayay) text> }` form.
///
/// The file report and `ls -X` both print this form.
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

/// Walks the parent chain of a commit, newest first, and reports each commit.
///
/// If the commit object of a parent is absent, the walk ends with the note of
/// the `ostree` command and exits 0. As a result, a partial history reports
/// what it holds.
///
/// The start revision obeys the stricter rule of each other read command. A
/// checksum that names no commit is refused, and does not count as an empty
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

/// The facts of one `ls` line, collected before the line is written.
///
/// Each column of the line has one source.
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

/// Lists the paths of a commit.
async fn ls(repo: Repo, name: &str, args: LsArgs) -> Result<()> {
    let Some(rev) = args.commit.as_deref() else {
        exit_with_error(name, "An COMMIT argument is required");
    };
    // The revision resolves through the shared reader. A name that no ref
    // holds is reported in the words of the `ostree` command, as in each other
    // command.
    let checksum = resolve(&repo, rev).await?;
    let (root, _) = repo.read_commit(&checksum.to_hex()).await?;
    if args.path.is_empty() {
        return ls_directory(&repo, &root, "/", &args).await;
    }
    for given in &args.path {
        let path = normalize_ls_path(given);
        // An empty argument names the root and is still refused, as in the
        // `ostree` command.
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

/// Returns the path that an `ls` argument names, with exactly one leading `/`.
fn normalize_ls_path(given: &str) -> String {
    let trimmed = given.trim_start_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else {
        format!("/{trimmed}")
    }
}

/// Prints a directory and, if `-d` is not given, its children.
///
/// With `-R`, the contents of each child directory follow its line.
async fn ls_directory(repo: &Repo, tree: &RepoTree, path: &str, args: &LsArgs) -> Result<()> {
    let entry = ls_dir_entry(repo, tree, path).await?;
    print_ls_entry(&entry, args);
    if args.dironly {
        return Ok(());
    }
    ls_children(repo, tree, path, args).await
}

/// Prints the children of a directory, and recurses if `-R` is given.
///
/// The stack holds single entries. When the line of a directory is printed,
/// its children go on the stack at once, before the siblings that are still
/// pending. The next line popped is always the first child of that directory.
/// As a result, the contents of a directory come directly after its own line,
/// before the lines of its later siblings at the same level.
async fn ls_children(repo: &Repo, tree: &RepoTree, path: &str, args: &LsArgs) -> Result<()> {
    // The recursion is a work list with no recursive calls, so a deep tree
    // cannot make the future larger with its depth.
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

/// Pushes the entries of `tree` onto `pending` in reverse order.
///
/// The stack then pops them in the order of `read_dir`: files, then
/// subdirectories, each in name order.
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

/// Returns the path of `name` in the directory at `base`.
fn join_ls_path(base: &str, name: &str) -> String {
    if base == "/" {
        format!("/{name}")
    } else {
        format!("{base}/{name}")
    }
}

/// Collects the `ls` facts of a directory from its dirmeta.
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

/// Collects the `ls` facts of a file from its object header.
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

/// Writes one `ls` line, or under `--nul-filenames-only`, only the path.
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
        // The xattr set comes from a parsed object, so it renders. A printer
        // failure here is a codec bug, and not an error in the input of the
        // user.
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

/// Reads, sets, or removes a repository configuration value.
async fn config(repo: Repo, name: &str, args: ConfigArgs) -> Result<()> {
    let Some(operation) = args.operation.as_deref() else {
        exit_with_error(name, "OPERATION must be specified");
    };
    // The operand count is checked before the operation name. `set` takes a
    // key and a value. Each other operation takes only a key. This includes a
    // name that the `ostree` command does not know.
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

/// Returns the group and the key that one `config` operand names.
///
/// The operand is `section.key`, split on its first `.`. If `--group` names
/// the section, the operand is a bare key name. A missing operand is reported
/// in the words of the `ostree` command. If `--group` is given, the message
/// names the group.
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

/// Prints one configuration value.
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

/// Sets one configuration value and writes the document back.
///
/// If the group is new, the command creates it. The value is escaped as the
/// `ostree` command escapes a value on write. As a result, a value with a
/// newline or leading whitespace is stored in a form that reads back
/// complete.
///
/// The edit is made first on the configuration read at open, so a refusal
/// takes no lock. The command then takes one update guard, reads the document
/// from disk, makes the edit again, and writes the document. As a result, an
/// edit that another writer made before the guard is kept.
async fn config_set(repo: &Repo, args: &ConfigArgs) -> Result<()> {
    if args.args.len() < 2 {
        if args.group.is_some() {
            exit_error("GROUP name, KEY and VALUE must be specified");
        }
        exit_error("KEY and VALUE must be specified");
    }
    let (group, key) = config_target(args);
    let value = &args.args[1];
    let edit = |config: &RepoConfig| -> Result<_> {
        let mut keyfile = config.keyfile().clone();
        keyfile.set_string(group, key, value)?;
        Ok(keyfile)
    };
    edit(repo.config())?;
    let guard = repo.begin_update().await?;
    let edited = async {
        let keyfile = edit(&guard.read_config().await?)?;
        guard.write_config(&keyfile).await
    }
    .await;
    let finished = guard.finish().await;
    edited.and(finished)
}

/// Removes one configuration value and writes the document back.
///
/// If the document does not hold the key or the group, the result is success
/// and the file does not change. The `ostree` command does the same.
///
/// The key is looked up first in the configuration read at open, so an absent
/// key takes no lock. Otherwise, the document is read from disk, edited, and
/// written under one update guard, as in [`config_set`]. If the key is not in
/// the document on disk, the result is success with no write.
async fn config_unset(repo: &Repo, args: &ConfigArgs) -> Result<()> {
    let (group, key) = config_target(args);
    let edit = |config: &RepoConfig| {
        let mut keyfile = config.keyfile().clone();
        keyfile.remove_key(group, key).then_some(keyfile)
    };
    if edit(repo.config()).is_none() {
        return Ok(());
    }
    let guard = repo.begin_update().await?;
    let edited = async {
        match edit(&guard.read_config().await?) {
            Some(keyfile) => guard.write_config(&keyfile).await,
            None => Ok(()),
        }
    }
    .await;
    let finished = guard.finish().await;
    edited.and(finished)
}

// --- remote ------------------------------------------------------------------

/// The GVariant signature of the summary, for the parse of the raw report.
const SUMMARY_SIGNATURE: &str = "(a(s(taya{sv}))a{sv})";

/// The summary metadata keys that get their own label in the report.
const SUMMARY_LABELS: &[(&str, &str)] = &[
    ("ostree.summary.mode", "Repository Mode"),
    ("ostree.summary.last-modified", "Last-Modified"),
    ("ostree.summary.tombstone-commits", "Has Tombstone Commits"),
    ("ostree.static-deltas", "Static Deltas"),
    ("ostree.summary.collection-map", "Collection Map"),
    ("ostree.summary.collection-id", "Collection ID"),
    ("ostree.summary.expires", "Expires"),
];

/// The metadata keys of each ref that the report labels in the same way.
const REF_LABELS: &[(&str, &str)] = &[
    ("ostree.commit.version", "Version"),
    ("ostree.commit.timestamp", "Timestamp"),
];

/// Runs one `remote` subcommand.
async fn remote(repo: Repo, sub: RemoteCommand) -> Result<()> {
    let nested = sub.name();
    match sub {
        RemoteCommand::Add(args) => remote_add(&repo, nested, args).await,
        #[cfg(feature = "s3")]
        RemoteCommand::Init(args) => remote_init(Some(&repo), nested, args).await,
        #[cfg(feature = "s3")]
        RemoteCommand::Fsck(args) => remote_fsck(Some(&repo), nested, args).await,
        #[cfg(feature = "s3")]
        RemoteCommand::Prune(args) => remote_prune(Some(&repo), nested, args).await,
        RemoteCommand::Delete(args) => remote_delete(&repo, nested, args).await,
        RemoteCommand::List(args) => remote_list(&repo, &args),
        RemoteCommand::ShowUrl(args) => remote_show_url(&repo, nested, &args),
        RemoteCommand::Refs(args) => remote_refs(&repo, nested, args).await,
        #[cfg(feature = "s3")]
        RemoteCommand::Summary(args) if args.update => {
            remote_summary_update(Some(&repo), nested, args).await
        }
        RemoteCommand::Summary(args) => remote_summary(&repo, nested, args).await,
        RemoteCommand::GpgImport(args) => remote_gpg_import(&repo, nested, args).await,
        RemoteCommand::GpgListKeys(args) => remote_gpg_list_keys(&repo, nested, &args).await,
    }
}

/// Returns the key-file group that holds the configuration of one remote.
fn remote_group(name: &str) -> String {
    format!("remote \"{name}\"")
}

/// Returns the operand that names the remote.
///
/// If the operand is missing, the process exits with the refusal of the
/// `ostree` command.
fn remote_operand<'a>(nested: &str, name: Option<&'a str>) -> &'a str {
    match name {
        Some(name) => name,
        None => exit_with_nested_error("remote", nested, "NAME must be specified"),
    }
}

/// Returns the configuration section of the remote that a read subcommand
/// names.
///
/// If the section does not exist, the process exits with the refusal of the
/// `ostree` command. A read applies no name rule: a name that `add` refuses
/// names no section.
fn remote_section<'a>(repo: &'a Repo, name: &str) -> ostrya::Remote<'a> {
    match repo.config().remote(name) {
        Some(section) => section,
        None => exit_error(&format!("Remote \"{name}\" not found")),
    }
}

/// Refuses a remote that the configuration does not describe.
///
/// This is for a subcommand that reads nothing from the section itself.
fn require_remote(repo: &Repo, name: &str) {
    remote_section(repo, name);
}

/// Returns the URL that a remote publishes.
///
/// If the section states no `url`, the process exits with the refusal of the
/// `ostree` command. A remote that a metalink describes states no `url`, so
/// `show-url` and `list -u` refuse it.
fn remote_url(section: &ostrya::Remote<'_>, name: &str) -> Result<String> {
    match section.url()? {
        Some(url) => Ok(url),
        None => exit_error(&format!("No \"url\" option in remote \"{name}\"")),
    }
}

/// Adds the configuration section of a remote.
///
/// If `--gpg-import` names a keyring, the command imports it into the trusted
/// keys of the remote. The keys are written in the order of the `ostree`
/// command:
///
/// 1. the URL or the metalink
/// 2. the branch list
/// 3. for an `s3://` address, `pull-url` and `push-url` in place of the URL
/// 4. the content URL
/// 5. the custom backend
/// 6. the `--set` pairs, in the order of the command line
/// 7. the GPG switch
/// 8. the verification keys of the ed25519 and spki engines
/// 9. the collection id
///
/// # Locks
///
/// The edit is made first on the configuration read at open. As a result, no
/// refusal takes a lock, and a remote that `--if-not-exists` leaves as it is
/// takes no lock. The command then takes one update guard, reads the document
/// from disk, makes the edit again, and writes the document. As a result, an
/// edit that another writer made before the guard is kept.
///
/// The command imports the keyring of `--gpg-import` only if it wrote the
/// remote. The import comes after the guard is finished, because the import
/// takes the locks itself.
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
    if !ostrya::valid_remote_name(name) {
        exit_error(&format!("Invalid remote name {name}"));
    }

    let group = remote_group(name);
    // The edited document, or `None` for a remote that `--if-not-exists` leaves
    // as it is.
    let edit = |config: &RepoConfig| -> Result<Option<_>> {
        let mut keyfile = config.keyfile().clone();
        if keyfile.has_group(&group) {
            if args.if_not_exists {
                return Ok(None);
            }
            if !args.force {
                exit_error(&format!(
                    "Remote configuration for \"{name}\" already exists: (in config)"
                ));
            }
            keyfile.remove_group(&group);
        }

        // The `ostree` command also reads `url`, and it reads no `s3://`
        // address, so an `s3://` address goes to the keys of the port alone.
        let s3 = url.starts_with("s3://");
        match url.strip_prefix("metalink=") {
            Some(metalink) => keyfile.set_string(&group, "metalink", metalink)?,
            None if s3 => {}
            None => keyfile.set_string(&group, "url", url)?,
        }
        if !args.branches.is_empty() {
            // The separator follows each branch, also the last one. This is
            // the list form that the `ostree` command writes.
            let mut list = String::new();
            for branch in &args.branches {
                list.push_str(branch);
                list.push(';');
            }
            keyfile.set_string(&group, "branches", &list)?;
        }
        if s3 {
            keyfile.set_string(&group, "pull-url", url)?;
            keyfile.set_string(&group, "push-url", url)?;
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
        // `--no-sign-verify` also turns the GPG check off. The `ostree`
        // command writes the same for it.
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
        Ok(Some(keyfile))
    };
    if edit(repo.config())?.is_none() {
        return Ok(());
    }
    let guard = repo.begin_update().await?;
    let edited = async {
        match edit(&guard.read_config().await?)? {
            Some(keyfile) => guard.write_config(&keyfile).await.map(|()| true),
            None => Ok(false),
        }
    }
    .await;
    let finished = guard.finish().await;
    let written = edited?;
    finished?;
    if !written {
        return Ok(());
    }

    if let Some(path) = &args.gpg_import {
        let keys = read_keyring_file(path)?;
        report_gpg_import(gpg_import(repo, name, &keys, &[]).await?, name);
    }
    Ok(())
}

/// Reads one `--sign-verify` engine spec.
///
/// The spec is `KEYTYPE=inline:PUBKEY` or `KEYTYPE=file:PATH`. A malformed
/// spec is refused in the words of the `ostree` command. The engine name must
/// be one that this build supports. At this step, `ostree` reports a type
/// that it does not implement.
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

/// Writes the `config` of a new bucket repository.
///
/// The operand is a remote of the config of `repo`, or an `s3://` address,
/// for which `repo` can be `None`. The endpoint comes from
/// `ostrya::endpoint::resolve_bucket`, and the init from
/// `BucketRepo::init`. A writer lock that `--break-lock` removed gives one
/// warning line on standard error.
#[cfg(feature = "s3")]
async fn remote_init(repo: Option<&Repo>, nested: &str, args: RemoteInitArgs) -> Result<()> {
    let target = remote_operand(nested, args.name.as_deref());
    let config = repo.map(Repo::config);
    let endpoint =
        ostrya::endpoint::resolve_bucket(config, target, args.s3.into_overrides()).await?;
    let bucket = ostrya::bucket::BucketRepo::open(&endpoint).await?;
    let broken = bucket
        .init(
            args.collection_id.as_deref(),
            args.zlib_level,
            args.break_lock,
        )
        .await?;
    if let Some(holder) = broken {
        eprintln!("warning: removed the writer lock of {holder}");
    }
    Ok(())
}

/// Checks the bucket repository of a remote or of an address, and with
/// `--delete` repairs it, for `ostrya remote fsck`.
///
/// `repo` is `None` for an address. With a remote name, the summary keys
/// come from `PullTrust::from_remote` with the commit checks off, so the
/// command reads no commit keyring. The report goes to standard output and
/// standard error as the help text states, and a report with an error exits
/// 1.
#[cfg(feature = "s3")]
async fn remote_fsck(repo: Option<&Repo>, nested: &str, args: RemoteFsckArgs) -> Result<()> {
    use std::io::Write;
    let target = remote_operand(nested, args.name.as_deref());
    let config = repo.map(Repo::config);
    let endpoint =
        ostrya::endpoint::resolve_bucket(config, target, args.s3.into_overrides()).await?;
    let mut opts = ostrya::bucket::BucketFsckOptions::default();
    opts.delete = args.delete;
    opts.break_lock = args.break_lock;
    if let Some(repo) = repo {
        let verify = ostrya::PullVerify {
            gpg: Some(false),
            sign: Some(false),
            ..ostrya::PullVerify::default()
        };
        let trust = ostrya::verify::PullTrust::from_remote(repo, target, &verify).await?;
        opts.summary_keys = trust.summary_keys().cloned();
    }
    let bucket = ostrya::bucket::BucketRepo::open(&endpoint).await?;
    // A repair that failed after its first change gives the report of the
    // markers and the deletes that completed, then the error line.
    let report = match bucket.fsck(&opts).await {
        Ok(report) => report,
        Err(e) => {
            if let Error::BucketRepairIncomplete { report, .. } = &e {
                print_bucket_fsck(report, args.quiet)?;
            }
            return Err(e);
        }
    };
    print_bucket_fsck(&report, args.quiet)?;
    if report.has_errors() {
        eprintln!("error: Bucket repository corruption encountered");
        exit_process(1);
    }
    let mut out = std::io::stdout().lock();
    writeln!(
        out,
        "fsck of the bucket repository {}: no errors found",
        bucket.address()
    )
    .and_then(|()| out.flush())
    .map_err(Error::Io)?;
    Ok(())
}

/// Prunes the bucket repository of a remote or of an address, for `ostrya
/// remote prune`.
///
/// `repo` is `None` for an address. The `--keep-younger-than` value is read
/// before any request. Each defective field 2 entry that the walk read gives
/// one warning line on standard error before the lines on standard output.
/// The lines go to standard output as the help text states, and a writer
/// lock that `--break-lock` removed gives one warning line on standard error
/// after them.
#[cfg(feature = "s3")]
async fn remote_prune(repo: Option<&Repo>, nested: &str, args: RemotePruneArgs) -> Result<()> {
    use std::io::Write;
    let target = remote_operand(nested, args.name.as_deref());
    let keep_younger_than = match args.keep_younger_than.as_deref() {
        Some(text) => match parse_timestamp(text) {
            Some(seconds) => Some(seconds),
            None => exit_error(&format!("Could not parse '{text}'")),
        },
        None => None,
    };
    let config = repo.map(Repo::config);
    let endpoint =
        ostrya::endpoint::resolve_bucket(config, target, args.s3.into_overrides()).await?;
    let opts = PruneOptions {
        refs_only: args.refs_only,
        depth: args.depth,
        no_prune: args.no_prune,
        keep_younger_than,
        ..PruneOptions::default()
    };
    let mut bucket_opts = ostrya::bucket::BucketPruneOptions::default();
    bucket_opts.break_lock = args.break_lock;
    let bucket = ostrya::bucket::BucketRepo::open(&endpoint).await?;
    let report = bucket.prune(&opts, &bucket_opts).await?;
    for warning in &report.stats.warnings {
        eprintln!("warning: {warning}");
    }
    let stats = &report.stats;
    let mut out = std::io::stdout().lock();
    writeln!(out, "Total objects: {}", stats.total_objects).map_err(Error::Io)?;
    if stats.pruned_objects == 0 {
        writeln!(out, "No unreachable objects")
    } else if args.no_prune {
        writeln!(
            out,
            "Would delete: {} objects, freeing {}",
            stats.pruned_objects,
            format_size(stats.freed_bytes)
        )
    } else {
        writeln!(
            out,
            "Deleted {} objects, {} freed",
            stats.pruned_objects,
            format_size(stats.freed_bytes)
        )
    }
    .map_err(Error::Io)?;
    let (delete, abort) = if args.no_prune {
        ("Would delete", "Would abort")
    } else {
        ("Deleted", "Aborted")
    };
    for (verb, count, what) in [
        (delete, report.deleted_deltas.len(), "static deltas"),
        (
            delete,
            report.deleted_markers.len(),
            "partial-commit markers",
        ),
        (
            abort,
            report.aborted_uploads.len(),
            "incomplete multipart uploads",
        ),
    ] {
        if count != 0 {
            writeln!(out, "{verb} {count} {what}").map_err(Error::Io)?;
        }
    }
    out.flush().map_err(Error::Io)?;
    if let Some(holder) = &report.broken_lock {
        eprintln!("warning: removed the writer lock of {holder}");
    }
    Ok(())
}

/// Prints the report of a fsck of a bucket repository: the counts unless
/// `quiet` is set, and each action of the repair, on standard output, and
/// each finding on standard error.
///
/// A failed write, for example on a full device, gives [`Error::Io`], and
/// `main` prints the error line and exits 1.
#[cfg(feature = "s3")]
fn print_bucket_fsck(report: &ostrya::bucket::BucketFsckReport, quiet: bool) -> Result<()> {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    if !quiet {
        writeln!(out, "Listed {} objects", report.objects_listed).map_err(Error::Io)?;
        writeln!(
            out,
            "Checked {} commits and {} objects, {} bytes",
            report.commits_checked, report.objects_checked, report.bytes_read
        )
        .map_err(Error::Io)?;
        writeln!(
            out,
            "{} objects not reached by a commit",
            report.objects_unreached
        )
        .map_err(Error::Io)?;
        if !report.orphan_images.is_empty() {
            writeln!(
                out,
                "{} composefs images with no commit",
                report.orphan_images.len()
            )
            .map_err(Error::Io)?;
        }
        if !report.commits_partial.is_empty() {
            writeln!(out, "{} partial commits", report.commits_partial.len()).map_err(Error::Io)?;
        }
    }
    out.flush().map_err(Error::Io)?;
    {
        // One buffer for all the lines: standard error has no buffer of its
        // own.
        let mut err = std::io::BufWriter::new(std::io::stderr().lock());
        for finding in &report.findings {
            if finding.error {
                writeln!(err, "{finding}")
            } else {
                writeln!(err, "note: {finding}")
            }
            .map_err(Error::Io)?;
        }
        err.flush().map_err(Error::Io)?;
    }
    let with_refs = |commit: &ostrya::Checksum, refs: &[String]| {
        if refs.is_empty() {
            commit.to_string()
        } else {
            format!("{commit} ({})", refs.join(", "))
        }
    };
    for (commit, refs) in &report.marked_partial {
        writeln!(
            out,
            "Marking commit as partial: {}",
            with_refs(commit, refs)
        )
        .map_err(Error::Io)?;
    }
    for commit in &report.cleared_partial {
        writeln!(out, "Deleted the partial-commit marker of commit {commit}").map_err(Error::Io)?;
    }
    for key in &report.deleted {
        writeln!(out, "Deleted {key}").map_err(Error::Io)?;
    }
    for (commit, refs) in &report.deleted_ref_targets {
        writeln!(
            out,
            "Deleted the commit object of a ref: {}",
            with_refs(commit, refs)
        )
        .map_err(Error::Io)?;
    }
    out.flush().map_err(Error::Io)?;
    if let Some(holder) = &report.broken_lock {
        eprintln!("warning: removed the writer lock of {holder}");
    }
    Ok(())
}

/// Deletes the trusted keyring and then the configuration section of a remote.
///
/// Both steps run under one update guard. The section is looked up first in
/// the configuration read at open, so an absent section takes no lock. When
/// the guard is taken, the section is looked up again in `config` as it is on
/// disk. A failure between the two steps leaves the section with no keyring,
/// and never a keyring with no section.
async fn remote_delete(repo: &Repo, nested: &str, args: RemoteDeleteArgs) -> Result<()> {
    let name = remote_operand(nested, args.name.as_deref());
    if !ostrya::valid_remote_name(name) {
        exit_error(&format!("Invalid remote name {name}"));
    }
    let absent = || -> Result<()> {
        if args.if_exists {
            return Ok(());
        }
        exit_error(&format!("Remote \"{name}\" not found"));
    };
    if !repo.config().keyfile().has_group(&remote_group(name)) {
        return absent();
    }
    let guard = repo.begin_update().await?;
    let deleted = guard.delete_remote(name).await;
    let finished = guard.finish().await;
    match deleted {
        Err(Error::RemoteNotFound(_)) => {
            finished?;
            absent()
        }
        deleted => deleted.and(finished),
    }
}

/// Lists the configured remote names, sorted by name.
///
/// Under `-u`, the URL follows each name. The names are padded to the length
/// of the longest name in the list plus two, counted in bytes, so the URLs
/// line up. A remote that states no `url` stops the listing at its turn. The
/// names before it stay printed.
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

/// Prints the URL of one remote.
fn remote_show_url(repo: &Repo, nested: &str, args: &RemoteNameArgs) -> Result<()> {
    let name = remote_operand(nested, args.name.as_deref());
    let section = remote_section(repo, name);
    println!("{}", remote_url(&section, name)?);
    Ok(())
}

/// Returns the summary that a remote publishes, with the endpoint overrides
/// `overrides`.
///
/// The caller checked that the remote exists. If the remote publishes no
/// summary, the process exits with the refusal of the `ostree` command.
/// `absent` is the message for the subcommand that asks.
async fn fetch_remote_summary(
    repo: &Repo,
    name: &str,
    absent: &str,
    overrides: ostrya::endpoint::EndpointOverrides,
) -> Result<Summary> {
    let (bytes, _signature) = repo.remote_fetch_summary_with(name, overrides).await?;
    let Some(bytes) = bytes else {
        exit_error(absent);
    };
    Summary::parse(&bytes)
}

/// Lists the refs in the summary of a remote, each with the prefix of the
/// remote.
async fn remote_refs(repo: &Repo, nested: &str, args: RemoteRefsArgs) -> Result<()> {
    let name = remote_operand(nested, args.name.as_deref());
    require_remote(repo, name);
    #[cfg(feature = "s3")]
    let overrides = args.s3.pull_overrides(repo, name, None);
    #[cfg(not(feature = "s3"))]
    let overrides = ostrya::endpoint::EndpointOverrides::default();
    let summary = fetch_remote_summary(
        repo,
        name,
        "Remote refs not available; server has no summary file",
        overrides,
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

/// Writes the summary of the bucket repository of a remote or of an address,
/// for `ostrya remote summary -u`.
///
/// `repo` is `None` for an address. The signers come from the signing
/// options, with the checks of `ostrya summary -u`, before any request. The
/// refusal of `--keys-file` under the gpg engine and the refusal of a key
/// file with no key name the options of this command. A writer lock that `--break-lock` removed gives one warning
/// line on standard error, also before the error of a signed update whose
/// `summary` and `summary.sig` can fail to match.
#[cfg(feature = "s3")]
async fn remote_summary_update(
    repo: Option<&Repo>,
    nested: &str,
    args: RemoteSummaryArgs,
) -> Result<()> {
    let target = remote_operand(nested, args.name.as_deref());
    let signers = summary_signers(&SummarySigning {
        gpg_sign: &args.gpg_sign,
        sign: &args.sign,
        sign_type: args.sign_type.as_deref(),
        keys_file: &args.keys_file,
        key_id: &[],
        gpg_homedir: args.gpg_homedir.as_deref(),
        remote: true,
    })
    .await?;
    let config = repo.map(Repo::config);
    let endpoint =
        ostrya::endpoint::resolve_bucket(config, target, args.s3.into_overrides()).await?;
    let mut opts = ostrya::bucket::BucketSummaryOptions::default();
    opts.summary_signers = signers.into_iter().map(Arc::from).collect();
    opts.last_modified = args.last_modified;
    opts.break_lock = args.break_lock;
    let bucket = ostrya::bucket::BucketRepo::open(&endpoint).await?;
    // A signed update whose summary and summary.sig can fail to match gives
    // the warning of a removed lock, then the error line.
    let report = match bucket.update_summary(&opts).await {
        Ok(report) => report,
        Err(e) => {
            if let Error::BucketSummaryIncomplete { report, .. } = &e
                && let Some(holder) = &report.broken_lock
            {
                eprintln!("warning: removed the writer lock of {holder}");
            }
            return Err(e);
        }
    };
    if let Some(holder) = &report.broken_lock {
        eprintln!("warning: removed the writer lock of {holder}");
    }
    Ok(())
}

/// Reports the summary of a remote.
///
/// The output is the raw variant, the metadata keys, one metadata value, or
/// the summary report.
async fn remote_summary(repo: &Repo, nested: &str, args: RemoteSummaryArgs) -> Result<()> {
    let name = remote_operand(nested, args.name.as_deref());
    require_remote(repo, name);
    #[cfg(feature = "s3")]
    let overrides = args.s3.pull_overrides(repo, name, None);
    #[cfg(not(feature = "s3"))]
    let overrides = ostrya::endpoint::EndpointOverrides::default();
    let (bytes, _) = repo.remote_fetch_summary_with(name, overrides).await?;
    let Some(bytes) = bytes else {
        exit_error("Remote server has no summary file");
    };
    print_summary_document(
        &bytes,
        args.raw,
        // `remote summary` has no view switch, and the report is its fallback.
        false,
        args.list_metadata_keys,
        args.print_metadata_key.as_deref(),
    )
}

/// Reports one summary document under the read options.
///
/// The options take the precedence of the `ostree` command: the raw variant,
/// the report, the metadata keys, and then one metadata value. With none of
/// them, the command writes the report.
fn print_summary_document(
    bytes: &[u8],
    raw: bool,
    view: bool,
    list_metadata_keys: bool,
    print_metadata_key: Option<&str>,
) -> Result<()> {
    if raw {
        let ty = parse_type(SUMMARY_SIGNATURE)?;
        let value = from_bytes(&ty, bytes).map_err(|err| Error::InvalidFormat(err.to_string()))?;
        // The text form renders the converted tree, so the code drops the
        // source tree before it builds the text.
        let converted = value.byteswapped();
        drop(value);
        println!("{}", variant_text(&ty, &converted)?);
        return Ok(());
    }
    if !view {
        // The key listing and one value by name report only the metadata
        // dict, so the ref list stays undecoded.
        if list_metadata_keys {
            print_sorted_keys(&Summary::parse_metadata(bytes)?);
            return Ok(());
        }
        if let Some(key) = print_metadata_key {
            let metadata = Summary::parse_metadata(bytes)?;
            let Some(value) = metadata.dict_get(key) else {
                exit_error(&format!("No such metadata key '{key}'"));
            };
            // The raw reports convert the big-endian fields as stored, so a
            // value read by name shows the number that the field states. The
            // lookup comes before the conversion, so only one value is
            // converted, and not the full dict.
            return print_metadata_value(&value.byteswapped(), false);
        }
    }
    print_summary_report(&Summary::parse(bytes)?)
}

/// Reports a summary as the `ostree` command does.
///
/// The report holds:
///
/// 1. each ref of field 0
/// 2. the refs of each collection in the collection map
/// 3. the global metadata, in the order of the summary
fn print_summary_report(summary: &Summary) -> Result<()> {
    let collection_id = summary
        .metadata_value("ostree.summary.collection-id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    for entry in &summary.refs {
        print_summary_ref(
            collection_id.as_deref(),
            &entry.name,
            entry.commit_size,
            &entry.commit.to_hex(),
            &entry.metadata,
        )?;
    }
    print_collection_map_refs(summary)?;
    for entry in summary.metadata.as_array().unwrap_or_default() {
        let Some((key, value)) = dict_entry(entry) else {
            continue;
        };
        print_summary_metadata(key, value)?;
    }
    Ok(())
}

/// The type of the `ostree.summary.collection-map` value.
const COLLECTION_MAP_TYPE: &str = "a{sa(s(taya{sv}))}";

/// Reports the refs that `ostree.summary.collection-map` lists.
///
/// The report reads the map as the `ostree` command reads it for its report.
/// A value of a different type lists no refs. If a commit checksum is not 32
/// bytes, the report names its length in place of the hex. The map reaches a
/// summary through `summary -m` in both commands, so the report does not
/// refuse a map of a different shape.
fn print_collection_map_refs(summary: &Summary) -> Result<()> {
    let Some((ty, map)) = summary
        .metadata
        .dict_get("ostree.summary.collection-map")
        .and_then(Value::as_variant)
    else {
        return Ok(());
    };
    if *ty != parse_type(COLLECTION_MAP_TYPE)? {
        return Ok(());
    }
    for collection in map.as_array().unwrap_or_default() {
        let Some([Value::Str(id), Value::Array(refs)]) = collection.as_tuple() else {
            continue;
        };
        for entry in refs {
            let Some([Value::Str(name), Value::Tuple(inner)]) = entry.as_tuple() else {
                continue;
            };
            let [Value::U64(size), Value::Bytes(checksum), metadata] = inner.as_slice() else {
                continue;
            };
            let commit = match <[u8; 32]>::try_from(checksum.as_slice()) {
                Ok(raw) => Checksum::from_bytes(raw).to_hex(),
                Err(_) => format!("Invalid checksum of length {} expected 32", checksum.len()),
            };
            print_summary_ref(Some(id), name, *size, &commit, metadata)?;
        }
    }
    Ok(())
}

/// Reports one ref of a summary.
///
/// The report gives the name, the commit size, the commit checksum, and the
/// metadata of the ref in the summary. If a repository states a collection id,
/// each of its refs shows as a `(collection, ref)` pair.
fn print_summary_ref(
    collection_id: Option<&str>,
    name: &str,
    commit_size: u64,
    commit: &str,
    metadata: &Value,
) -> Result<()> {
    match collection_id {
        Some(collection) => println!("* ({collection}, {name})"),
        None => println!("* {name}"),
    }
    println!("    Latest Commit ({commit_size} bytes):");
    println!("      {commit}");
    for member in metadata.as_array().unwrap_or_default() {
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

/// Reports one global metadata entry.
///
/// Each key that the format defines has a label and its own form. Each other
/// key prints its name and its value in the text form, with no type
/// annotation.
fn print_summary_metadata(key: &str, value: &Value) -> Result<()> {
    let labeled = SUMMARY_LABELS.iter().any(|(name, _)| *name == key);
    let label = label_for(SUMMARY_LABELS, key);
    let Some((ty, inner)) = value.as_variant() else {
        return Ok(());
    };
    match key {
        "ostree.summary.last-modified" | "ostree.summary.expires" => {
            let seconds = inner.as_u64().unwrap_or_default().swap_bytes();
            println!("{label}: {}", format_iso_utc(seconds));
        }
        "ostree.summary.tombstone-commits" => {
            let yes = inner.as_bool().unwrap_or(false);
            println!("{label}: {}", if yes { "Yes" } else { "No" });
        }
        // The refs of the map come earlier in the report, with the other refs.
        "ostree.summary.collection-map" => println!("{label}: (printed above)"),
        _ => match inner {
            // A labeled string prints bare. An unlabeled string keeps the
            // quotes of the text form. The delta map is read as a full value,
            // so a string stored under its key also keeps the quotes.
            Value::Str(text) if labeled && key != "ostree.static-deltas" => {
                println!("{label}: {text}")
            }
            _ => println!("{label}: {}", unannotated_text(ty, inner)?),
        },
    }
    Ok(())
}

/// Returns the label that a report gives `key`.
///
/// If the format defines no label, the label is the key itself. A labeled key
/// has its name in parentheses after the label.
fn label_for(labels: &[(&str, &str)], key: &str) -> String {
    match labels.iter().find(|(name, _)| *name == key) {
        Some((_, label)) => format!("{label} ({key})"),
        None => key.to_owned(),
    }
}

/// Returns one `a{sv}` entry as a key and the variant that it holds.
fn dict_entry(entry: &Value) -> Option<(&str, &Value)> {
    let fields = entry.as_tuple()?;
    Some((fields.first()?.as_str()?, fields.get(1)?))
}

/// Formats a value in the GVariant text form with no type annotation.
///
/// A report that names the value itself uses this form.
fn unannotated_text(ty: &Type, value: &Value) -> Result<String> {
    to_text_unannotated(ty, value).map_err(|err| Error::InvalidFormat(err.to_string()))
}

/// The first and the last second that a summary report shows as a date.
///
/// These are the start of year 1 and the end of year 9999, in seconds from
/// the Unix epoch.
const REPORT_INSTANT_RANGE: std::ops::RangeInclusive<i64> = -62_135_596_800..=253_402_300_799;

/// Formats a timestamp as a summary report shows it.
///
/// The form is UTC, `YYYY-MM-DDTHH:MM:SS+00`, with no padding on the year.
/// The field is read as a signed count of seconds. An instant outside the
/// years 1 to 9999 shows as `invalid`.
///
/// # Divergence
///
/// The `ostree` command shows the same instant in the time zone of the host.
/// This is a recorded divergence.
fn format_iso_utc(timestamp: u64) -> String {
    let seconds = timestamp as i64;
    if !REPORT_INSTANT_RANGE.contains(&seconds) {
        return "invalid".to_owned();
    }
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (rest / 3600, (rest % 3600) / 60, rest % 60);
    format!("{year}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}+00")
}

/// Reads a full keyring file.
///
/// A file that does not open is refused in the words of the `ostree` command.
fn read_keyring_file(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|err| {
        exit_error(&format!(
            "Error opening file {}: {}",
            path.display(),
            io_reason(&err)
        ))
    })
}

/// Imports keys into the trusted keyring of a remote.
async fn remote_gpg_import(repo: &Repo, nested: &str, args: RemoteGpgImportArgs) -> Result<()> {
    let name = remote_operand(nested, args.name.as_deref());
    if !args.keyring.is_empty() && args.stdin {
        exit_with_nested_error(
            "remote",
            nested,
            "--keyring and --stdin are mutually exclusive",
        );
    }
    // The key sources are read before the remote is looked up, in the order
    // of the `ostree` command. A `--keyring` that names no file is reported
    // also for a remote that the configuration does not describe.
    let mut keys = Vec::new();
    if args.stdin {
        use std::io::Read;
        std::io::stdin().read_to_end(&mut keys)?;
    } else {
        for path in &args.keyring {
            keys.extend_from_slice(&read_keyring_file(path)?);
        }
    }
    // Only this subcommand prefixes its refusal of an unknown remote. The
    // message of the `ostree` command has the same prefix.
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

/// Prints what an import added, in the words of the `ostree` command.
///
/// The count is the number of keys that the keyring did not already hold.
fn report_gpg_import(imported: usize, remote: &str) {
    let keys = if imported == 1 { "key" } else { "keys" };
    println!("Imported {imported} GPG {keys} to remote \"{remote}\"");
}

/// Lists the keys in the trusted keyring of a remote.
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

/// Imports `keys` into the trusted keyring of `remote`.
///
/// The result is the number of new keys.
#[cfg(feature = "gpg")]
async fn gpg_import(repo: &Repo, remote: &str, keys: &[u8], key_ids: &[String]) -> Result<usize> {
    repo.gpg_import_keys(remote, keys, key_ids).await
}

/// Returns an error, because this build has no gpg engine.
#[cfg(not(feature = "gpg"))]
async fn gpg_import(_: &Repo, _: &str, _: &[u8], _: &[String]) -> Result<usize> {
    Err(unsupported_type("gpg"))
}

/// Returns the keys in the trusted keyring of `remote`.
#[cfg(feature = "gpg")]
async fn gpg_list_keys(repo: &Repo, remote: &str) -> Result<Vec<ostrya::GpgKey>> {
    repo.gpg_list_keys(remote).await
}

/// Returns an error, because this build has no gpg engine.
#[cfg(not(feature = "gpg"))]
async fn gpg_list_keys(_: &Repo, _: &str) -> Result<Vec<GpgKeyStub>> {
    Err(unsupported_type("gpg"))
}

/// A stand-in for the GPG key record in a build without the gpg engine.
///
/// With it, the code of the listing compiles under each feature set.
#[cfg(not(feature = "gpg"))]
struct GpgKeyStub {
    fingerprint: String,
    created: Option<u64>,
    user_ids: Vec<String>,
}

/// Formats a timestamp as the `Date:` line of the commit report shows it.
///
/// The form is UTC, `YYYY-MM-DD HH:MM:SS +0000`. The stored field is
/// unsigned, and a pre-epoch instant is in its two's-complement form. As a
/// result, the field is read as a signed count of seconds, as in the `ostree`
/// command.
fn format_utc(timestamp: u64) -> String {
    let seconds = timestamp as i64;
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (rest / 3600, (rest % 3600) / 60, rest % 60);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} +0000")
}

/// Returns the civil date `days` days after 1970-01-01.
///
/// This is the inverse of [`days_from_civil`].
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

/// Reads one `--retain-branch-depth` value: a branch name, `=`, and a depth.
///
/// The value splits at its first `=`, so a branch name with a `=` cannot be
/// given. The `ostree` command does the same. The depth is a decimal integer
/// with an optional leading `-`.
///
/// # Divergence
///
/// `ostree` reads a leading run of digits and drops the rest of the string.
/// ostrya refuses a value that its reader does not accept. This is a recorded
/// divergence.
fn parse_retain_branch_depth(value: &str) -> std::result::Result<(String, i32), String> {
    let Some((branch, depth)) = value.split_once('=') else {
        return Err(format!("Invalid value {value}, must specify BRANCH=DEPTH"));
    };
    let body = depth.strip_prefix('-').unwrap_or(depth);
    let held = !body.is_empty() && body.bytes().all(|b| b.is_ascii_digit());
    match held.then(|| depth.parse::<i32>().ok()).flatten() {
        Some(depth) => Ok((branch.to_owned(), depth)),
        None => Err(format!("Invalid depth {depth}")),
    }
}

/// The units for a byte count of 1000 or more in a prune totals line.
const SIZE_UNITS: [&str; 6] = ["kB", "MB", "GB", "TB", "PB", "EB"];

/// The character between a quantity and its unit in the totals line.
///
/// This is U+00A0 NO-BREAK SPACE.
const NO_BREAK_SPACE: char = '\u{a0}';

/// Formats a byte count as the totals line shows it.
///
/// - Less than 1000 bytes: the count, a space, and the word `byte` or
///   `bytes`.
/// - 1000 bytes or more: a decimal (SI) quantity with one fractional digit, a
///   no-break space, and the unit.
///
/// The byte count selects the unit, and the rounded value does not. As a
/// result, 999999 shows as `1000.0 kB`.
fn format_size(bytes: u64) -> String {
    if bytes < 1000 {
        let word = if bytes == 1 { "byte" } else { "bytes" };
        return format!("{bytes} {word}");
    }
    let count = bytes as f64;
    let mut value = count / 1000.0;
    let mut unit = SIZE_UNITS[0];
    for (index, name) in SIZE_UNITS.iter().enumerate() {
        let divisor = 1000f64.powi(index as i32 + 1);
        if count / divisor < 1.0 {
            break;
        }
        value = count / divisor;
        unit = name;
    }
    format!("{value:.1}{NO_BREAK_SPACE}{unit}")
}

/// Prunes the objects that no ref reaches, and prints the totals.
async fn prune(repo: Repo, args: PruneArgs) -> Result<()> {
    // The refusals that follow come in the order of the `ostree` command. The
    // order is the option pair, the `--static-deltas-only` requirement, the
    // date, each `--retain-branch-depth` value, and then the revisions.
    // `Repo::prune` resolves the revisions last. No refusal writes, so a
    // refusal leaves the repository as it was.
    if args.no_prune && args.delete_commit.is_some() {
        exit_error("Cannot specify both --delete-commit and --no-prune");
    }
    if args.static_deltas_only && args.delete_commit.is_none() {
        exit_error("--static-deltas-only requires --delete-commit");
    }
    let keep_younger_than = match args.keep_younger_than.as_deref() {
        Some(text) => match parse_timestamp(text) {
            Some(seconds) => Some(seconds),
            None => exit_error(&format!("Could not parse '{text}'")),
        },
        None => None,
    };
    let mut retain_branch_depth = Vec::new();
    for value in &args.retain_branch_depth {
        match parse_retain_branch_depth(value) {
            Ok(entry) => retain_branch_depth.push(entry),
            Err(message) => exit_error(&message),
        }
    }
    let delete_commit = match args.delete_commit.as_deref() {
        Some(rev) => Some(resolve(&repo, rev).await?),
        None => None,
    };
    let opts = PruneOptions {
        refs_only: args.refs_only,
        depth: args.depth,
        no_prune: args.no_prune,
        delete_commit,
        keep_younger_than,
        only_branch: args.only_branch.clone(),
        retain_branch_depth,
        commit_only: args.commit_only,
        static_deltas_only: args.static_deltas_only,
        ..PruneOptions::default()
    };
    // If the config of a repository sets `[core] locking` to false, the prune
    // takes no lock. The run then shares the repository with each other
    // writer. The `ostree` command writes nothing at this point, so this line
    // is a recorded divergence.
    //
    // The config reads of a prune come in this order:
    //
    // 1. `[core] locking`, here, for the warning line.
    // 2. `[core] locking` and `[core] lock-timeout-secs`, at the lock.
    // 3. `[core] tombstone-commits` and `[core] fsync`, in the run.
    //
    // The read is here, after the options are assembled.
    // `commit` reads the four `[core]` keys of its transaction at the top of
    // its function. If this read moves to the top of this function, a
    // `locking=bogus` refusal comes before the `--keep-younger-than`,
    // `--retain-branch-depth`, and `--delete-commit` refusals. That order
    // contradicts the conformance record: each config read of `prune` comes
    // after each option refusal. `Repo::prune` reads the same key again when
    // it takes the lock. This is a lookup in the config that the handle
    // already parsed, and it reads no file.
    if !repo.config().locking()? {
        eprintln!(
            "ostrya: [core] locking is false, so this prune holds no repository \
             lock. Another writer can change the repository while the prune runs."
        );
    }
    let stats = repo.prune(&opts).await.map_err(report_resolution_failure)?;
    for warning in &stats.warnings {
        eprintln!("warning: {warning}");
    }
    if args.commit_only {
        println!("Total (commit only) objects: {}", stats.total_objects);
    } else {
        println!("Total objects: {}", stats.total_objects);
    }
    if stats.pruned_objects == 0 {
        println!("No unreachable objects");
    } else if args.no_prune {
        println!(
            "Would delete: {} objects, freeing {}",
            stats.pruned_objects,
            format_size(stats.freed_bytes)
        );
    } else {
        println!(
            "Deleted {} objects, {} freed",
            stats.pruned_objects,
            format_size(stats.freed_bytes)
        );
    }
    Ok(())
}

/// The opening quote of a ref name or a collection id, U+2018.
///
/// The `ostree` command writes this quote.
const OPEN_QUOTE: char = '\u{2018}';
/// The closing quote of a ref name or a collection id, U+2019.
///
/// The `ostree` command writes this quote.
const CLOSE_QUOTE: char = '\u{2019}';
/// The word for a collection ref in a back-reference finding.
///
/// The `ostree` command writes this word. The dash is U+2013 EN DASH.
const COLLECTION_REF: &str = "Collection\u{2013}ref";

/// Checks the objects of the repository and reports the findings.
async fn fsck(repo: Repo, args: FsckArgs) -> Result<()> {
    use std::io::Write;
    let opts = FsckOptions {
        mark_partial: !args.no_mark_partial,
        delete: args.delete,
        all: args.all,
        add_tombstones: args.add_tombstones,
        verify_bindings: args.verify_bindings,
        // The help text of the `ostree` command says that `--verify-back-refs`
        // implies `--verify-bindings`. `ostree` runs the two checks
        // separately, so only a command line with both runs both.
        verify_back_refs: args.verify_back_refs,
    };
    let report = match repo.fsck(&opts).await {
        Ok(report) => report,
        Err(e) => exit_error(&fsck_error_text(&e)),
    };

    if !args.quiet {
        println!("Validating refs...");
        if report.reached >= FsckPhase::ValidateCollectionRefs {
            println!("Validating refs in collections...");
        }
        if report.reached >= FsckPhase::EnumerateCommits {
            println!("Enumerating commits...");
        }
        if report.reached >= FsckPhase::VerifyObjects {
            println!(
                "Verifying content integrity of {} commit objects...",
                report.commits_checked
            );
        }
    }
    // The walk runs to its end, so each finding is written plain, and the run
    // ends with one `error: ` line of its own.
    for error in &report.errors {
        eprintln!("{}", fsck_finding_line(error));
    }
    for commit in &report.marked_partial {
        eprintln!("Marking commit as partial: {commit}");
    }
    // If the ref, collection, or enumerate phase ended the run, the run writes
    // that condition and nothing of the object walk.
    if let Some(failure) = &report.failure {
        std::io::stdout().flush().ok();
        fsck_report_failure(failure);
    }
    // A repository with no composefs image gets none of these lines.
    for error in &report.image_errors {
        eprintln!("{error}");
    }
    for commit in &report.orphan_images {
        println!("Composefs image with no commit: {commit}");
    }
    for commit in &report.tombstoned {
        println!("Adding tombstone for commit {commit}");
    }
    // `--add-tombstones` suppresses the standard-output count and keeps the
    // error line.
    if report.commits_partial > 0 && !args.add_tombstones {
        println!("{} partial commits not verified", report.commits_partial);
    }

    std::io::stdout().flush().ok();
    if !report.errors.is_empty() || !report.image_errors.is_empty() {
        eprintln!("error: Repository corruption encountered");
        exit_process(1);
    }
    if report.commits_partial > 0 {
        eprintln!(
            "error: {} partial commits from fsck-detected corruption",
            report.commits_partial
        );
        exit_process(1);
    }
    println!(
        "object fsck of {} commits completed successfully - no errors found.",
        report.commits_checked
    );
    std::io::stdout().flush().ok();
    Ok(())
}

/// Returns the text of one finding, in the words of the `ostree` command.
///
/// A content object is named by its checksum alone, and a metadata object by
/// its `<checksum>.<type>` form. Each finding names the commits that reach the
/// object.
fn fsck_finding_line(error: &FsckError) -> String {
    let object = error.object;
    let subject = if object.ty == ObjectType::File {
        format!("content object {}", object.checksum)
    } else {
        format!("{}.{}", object.checksum, object.ty.type_str())
    };
    let detail = match &error.kind {
        FsckErrorKind::Missing => {
            return format!(
                "Object missing in commits {}: {}.{}",
                fsck_commit_list(&error.in_commits),
                object.checksum,
                object.ty.type_str(),
            );
        }
        FsckErrorKind::ChecksumMismatch { actual } => format!(
            "Corrupted {} object; checksum expected='{}' actual='{actual}'",
            object.ty.type_str(),
            object.checksum,
        ),
        FsckErrorKind::Corrupt(detail) => detail.clone(),
    };
    if error.in_commits.is_empty() {
        return format!("fsck {subject}: {detail}");
    }
    format!(
        "In commits {}: fsck {subject}: {detail}",
        fsck_commit_list(&error.in_commits)
    )
}

/// Returns the commits that a finding names, separated by a comma and a space.
///
/// The library gives the commits sorted, and ostrya writes them in that order.
/// The `ostree` command writes them in the order of its hash container. This
/// is a recorded divergence.
fn fsck_commit_list(commits: &[Checksum]) -> String {
    commits
        .iter()
        .map(|c| c.to_hex())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Writes the condition that ended the run, and exits 1.
fn fsck_report_failure(failure: &FsckFailure) -> ! {
    match failure {
        FsckFailure::RefTarget {
            ref_name,
            commit,
            removed,
        } => {
            if !removed {
                eprintln!("Object missing: {commit}.commit");
            }
            exit_error(&format!(
                "Loading commit for ref {ref_name}: No such metadata object {commit}.commit"
            ));
        }
        FsckFailure::MissingDirTree(checksum) => {
            exit_error(&format!("No such metadata object {checksum}.dirtree"))
        }
        FsckFailure::Binding(binding) => exit_error(&fsck_binding_text(binding)),
    }
}

/// Returns the text of one binding finding, in the words of the `ostree`
/// command.
///
/// The quotes are U+2018 and U+2019, and the dash in `Collection-ref` is
/// U+2013, as `ostree` writes them.
fn fsck_binding_text(error: &FsckBindingError) -> String {
    let commit = error.commit;
    match &error.kind {
        FsckBindingErrorKind::RefNotBound { ref_name, bindings } => {
            let listed = if bindings.is_empty() {
                "no refs".to_owned()
            } else {
                bindings
                    .iter()
                    .map(|name| format!("{OPEN_QUOTE}{name}{CLOSE_QUOTE}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let named = format!("{OPEN_QUOTE}{ref_name}{CLOSE_QUOTE}");
            format!(
                "Commit {commit}: Commit has no requested ref {named} in ref binding metadata ({listed})"
            )
        }
        FsckBindingErrorKind::CollectionMismatch { bound, found_under } => {
            let bound = format!("{OPEN_QUOTE}{bound}{CLOSE_QUOTE}");
            let under = format!("{OPEN_QUOTE}{found_under}{CLOSE_QUOTE}");
            format!(
                "Commit {commit}: Commit has collection ID {bound} in collection binding metadata, while the remote it came from has collection ID {under}"
            )
        }
        FsckBindingErrorKind::BackRefMissing { ref_name } => {
            let named = format!("{OPEN_QUOTE}{ref_name}{CLOSE_QUOTE}");
            format!("Ref {named} in bindings for commit {commit} does not exist")
        }
        FsckBindingErrorKind::BackRefMismatch { ref_name } => {
            let named = format!("{OPEN_QUOTE}{ref_name}{CLOSE_QUOTE}");
            format!("Ref {named} in bindings for commit {commit} does not resolve to that commit")
        }
        FsckBindingErrorKind::BackCollectionRefMissing {
            collection_id,
            ref_name,
        } => format!(
            "{COLLECTION_REF} ({collection_id}, {ref_name}) in bindings for commit {commit} does not exist"
        ),
        FsckBindingErrorKind::BackCollectionRefMismatch {
            collection_id,
            ref_name,
        } => format!(
            "{COLLECTION_REF} ({collection_id}, {ref_name}) in bindings for commit {commit} does not resolve to that commit"
        ),
    }
}

/// Returns the text of an error that ends the command.
///
/// If the condition is the same in both commands, the text uses the words of
/// the `ostree` command. A referenced object that the store cannot supply
/// gets the `No such metadata object` sentence of `ostree`.
fn fsck_error_text(error: &Error) -> String {
    match error {
        Error::ObjectNotFound { checksum, ty } => {
            format!("No such metadata object {checksum}.{}", ty.type_str())
        }
        other => other.to_string(),
    }
}

/// One `REV_OR_DIR` argument, read by the rule of [`diff_side_is_directory`].
enum DiffArgSide {
    /// A commit that the argument resolved to.
    Commit(Checksum),
    /// A directory on the file system.
    Directory(PathBuf),
}

impl DiffArgSide {
    /// Returns the library side that this argument names.
    fn as_side(&self) -> DiffSide<'_> {
        match self {
            DiffArgSide::Commit(checksum) => DiffSide::Commit(checksum),
            DiffArgSide::Directory(path) => DiffSide::Directory(path),
        }
    }

    /// Returns `true` if the argument names a directory.
    ///
    /// This decides how a path of this side prints.
    fn is_directory(&self) -> bool {
        matches!(self, DiffArgSide::Directory(_))
    }
}

/// Returns `true` if a `REV_OR_DIR` argument names a directory.
///
/// An argument that starts with `/` or with `./` names a directory. Each
/// other argument names a revision. The rule reads only the spelling, so an
/// existing directory given as a relative path without `./` is read as a
/// revision.
fn diff_side_is_directory(argument: &str) -> bool {
    argument.starts_with('/') || argument.starts_with("./")
}

/// Reads one `REV_OR_DIR` argument.
async fn diff_arg_side(repo: &Repo, argument: &str) -> Result<DiffArgSide> {
    if diff_side_is_directory(argument) {
        Ok(DiffArgSide::Directory(PathBuf::from(argument)))
    } else {
        Ok(DiffArgSide::Commit(resolve(repo, argument).await?))
    }
}

/// Returns the character that a change prints.
fn diff_prefix(change: DiffChange) -> char {
    match change {
        DiffChange::Added => 'A',
        DiffChange::Removed => 'D',
        DiffChange::Modified => 'M',
    }
}

/// Prints the differences between two revisions or directories.
///
/// With `--stats`, the command prints the object statistics of two commits. It
/// prints the path block before them, and only with `--fs-diff`.
async fn diff(repo: Repo, name: &str, args: DiffArgs, owner: Owner) -> Result<()> {
    let Some(first) = args.from.as_deref() else {
        exit_with_error(name, "REV must be specified");
    };
    // With one argument, the first side is that argument with `^` appended.
    // As a result, the parent condition has the resolution words that each
    // subcommand with a revision gives.
    let (from_text, to_text) = match args.to.as_deref() {
        Some(second) => (first.to_owned(), second.to_owned()),
        None => (format!("{first}^"), first.to_owned()),
    };

    // The block for each path is written in full before the stats pass runs.
    // A run with both writes the block and then the refusal of the stats
    // pass.
    if args.fs_diff || !args.stats {
        let options = DiffOptions {
            skip_xattrs: args.no_xattrs,
            owner_uid: owner.uid,
            owner_gid: owner.gid,
        };
        let from = diff_arg_side(&repo, &from_text).await?;
        let to = diff_arg_side(&repo, &to_text).await?;
        for entry in repo.diff(from.as_side(), to.as_side(), &options).await? {
            let owning_side = match entry.change {
                DiffChange::Added => &to,
                DiffChange::Removed | DiffChange::Modified => &from,
            };
            let rendered = if owning_side.is_directory() {
                entry.path.strip_prefix('/').unwrap_or(&entry.path)
            } else {
                entry.path.as_str()
            };
            println!("{}    {rendered}", diff_prefix(entry.change));
        }
    }

    // `--stats` reads both arguments as revisions, whatever their spelling.
    if args.stats {
        let from = resolve(&repo, &from_text).await?;
        let to = resolve(&repo, &to_text).await?;
        let stats = repo.diff_stats(&from, &to).await?;
        println!("[A] Object Count: {}", stats.from_objects);
        println!("[B] Object Count: {}", stats.to_objects);
        println!("Common Object Count: {}", stats.common_objects);
        println!("Common Object Size: {}", format_size(stats.common_bytes));
    }
    Ok(())
}

/// Returns the refusal of `--keys-dir` under the gpg engine.
///
/// The gpg engine reads keyrings only from `--keys-file`.
fn gpg_keys_dir_refusal() -> Error {
    Error::Signature(
        "--keys-dir is not used by the gpg engine; supply keyrings with --keys-file".into(),
    )
}

/// Signs a commit, or verifies or deletes its signatures.
async fn sign(repo: Repo, repo_path: PathBuf, name: &str, args: SignArgs) -> Result<()> {
    let Some(commit_rev) = args.commit.as_deref() else {
        exit_with_error(name, "Need a COMMIT to sign or verify");
    };
    let commit = resolve(&repo, commit_rev).await?;
    if args.sign_type == SignType::Gpg && args.keys_dir.is_some() {
        return Err(gpg_keys_dir_refusal());
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

/// Updates, verifies, signs, or reads the summary of the repository.
async fn summary(repo: Repo, repo_path: PathBuf, args: SummaryArgs) -> Result<()> {
    let item = match &args.auth_group {
        Some(name) => Some(summary_auth_item(&repo, name, &args)?),
        None => None,
    };
    if args.verify {
        let engine = summary_sign_type(&args.signing());
        let verifier = summary_verifier(&repo_path, engine, &args)?;
        let outcome = repo.verify_summary(&[verifier.as_ref()]).await?;
        report_verify(&outcome, engine);
        if !outcome.valid {
            exit_process(1);
        }
        return Ok(());
    }

    if args.update {
        // An update does its work and returns. The `ostree` command writes no
        // report with it.
        return summary_update(&repo, &args).await;
    }

    // Without `-u`, nothing reads the write options. With a read option, they
    // have no effect. Alone, they cause the no-option refusal, before a
    // positional key is read.
    let reading =
        args.raw || args.view || args.list_metadata_keys || args.print_metadata_key.is_some();
    let writing =
        !args.sign.is_empty() || !args.gpg_sign.is_empty() || !args.add_metadata.is_empty();
    if !reading && writing {
        return Err(summary_nothing_to_do());
    }
    // A positional key or a `--keys-file` signs the current summary. This is
    // an ostrya extension. Signing comes before each read option. Each signer
    // is built before the first signature is written.
    if !args.key_id.is_empty() || !args.keys_file.is_empty() {
        let signing = args.signing();
        let signers = summary_extension_signers(&signing, summary_sign_type(&signing)).await?;
        return repo.sign_summary_all(&signer_refs(&signers)).await;
    }
    if !reading {
        return Err(summary_nothing_to_do());
    }
    summary_read(&repo, &args, item.as_ref()).await
}

/// Returns the auth item of the client group `name` for `--auth-group`.
///
/// The checks of the options come first: the command refuses
/// `--auth-group` with `--verify`, with `-u`, with a signing key, and with no
/// read option. Then it reads the client groups, and refuses a group that
/// does not exist, a group with `summary=false`, and a group with more than
/// one auth item.
fn summary_auth_item(
    repo: &Repo,
    name: &str,
    args: &SummaryArgs,
) -> Result<ostrya::access::AuthItem> {
    let refuse = |why: &str| Err(Error::InvalidFormat(format!("--auth-group {why}")));
    let reading =
        args.raw || args.view || args.list_metadata_keys || args.print_metadata_key.is_some();
    let signing = !args.sign.is_empty()
        || !args.gpg_sign.is_empty()
        || !args.key_id.is_empty()
        || !args.keys_file.is_empty();
    if args.verify {
        return refuse("does not apply to --verify, which verifies `summary.sig`");
    }
    if args.update {
        return refuse("does not apply to -u, which writes the summary of each item");
    }
    if signing {
        return refuse("does not apply to a signing key");
    }
    if !reading {
        return refuse(
            "needs a read option: -v, --raw, --list-metadata-keys, or --print-metadata-key",
        );
    }
    let access = ostrya::access::ClientAccess::from_config(repo.config(), repo.path())?;
    let Some(group) = access.groups().iter().find(|group| group.name() == name) else {
        return refuse(&format!("names no client group '{name}'"));
    };
    if !group.summary() {
        return refuse(&format!(
            "names the client group '{name}', which has summary=false"
        ));
    }
    match group.auth() {
        [item] => Ok(item.clone()),
        items => {
            let items: Vec<String> = items.iter().map(ToString::to_string).collect();
            refuse(&format!(
                "names the client group '{name}', whose auth list holds more than one item: \
                 {}",
                items.join(";")
            ))
        }
    }
}

/// Returns the refusal for a `summary` command line that names nothing to do.
///
/// The `ostree` command uses different words for this refusal. This is a
/// recorded divergence.
fn summary_nothing_to_do() -> Error {
    Error::InvalidFormat(
        "nothing to do: pass --update, --verify, a reading option, or a signing key".into(),
    )
}

/// The signing options of a summary update: of `ostrya summary -u`, and of
/// `ostrya remote summary -u`, which has no KEY-ID.
struct SummarySigning<'a> {
    /// The `--gpg-sign` selectors.
    gpg_sign: &'a [String],
    /// The `--sign` keys.
    sign: &'a [String],
    /// The `--sign-type` value.
    sign_type: Option<&'a str>,
    /// The `--keys-file` paths.
    keys_file: &'a [std::ffi::OsString],
    /// The positional KEY-IDs.
    key_id: &'a [String],
    /// The `--gpg-homedir` directory.
    gpg_homedir: Option<&'a Path>,
    /// `true` for `ostrya remote summary -u`, whose refusals name its own
    /// options.
    remote: bool,
}

impl SummaryArgs {
    /// Returns the signing options of the command line.
    fn signing(&self) -> SummarySigning<'_> {
        SummarySigning {
            gpg_sign: &self.gpg_sign,
            sign: &self.sign,
            sign_type: self.sign_type.as_deref(),
            keys_file: &self.keys_file,
            key_id: &self.key_id,
            gpg_homedir: self.gpg_homedir.as_deref(),
            remote: false,
        }
    }
}

/// Returns the engine that `--sign-type` names.
///
/// If no engine has the name, the process exits with the refusal of the
/// `ostree` command.
fn summary_sign_type(args: &SummarySigning<'_>) -> SignType {
    match sign_type_from_name(args.sign_type.unwrap_or(DEFAULT_SIGN_TYPE)) {
        Ok(engine) => engine,
        Err(message) => exit_error(&message),
    }
}

/// Regenerates the summary of each auth item and signs each one with each key
/// that the options name.
///
/// Each argument is checked before the regeneration, so a refusal leaves
/// each summary and its signature file as they were. The client groups are
/// checked after the arguments. The checks of the arguments run in the order
/// of the `ostree` command:
///
/// 1. each `-m` argument, in command-line order
/// 2. each `--gpg-sign` lookup
/// 3. `--sign-type`, if a key needs an engine
/// 4. each `--sign` key
/// 5. the positional and `--keys-file` keys
///
/// Under the gpg engine, a `--sign` key and a positional key are looked up as
/// a `--gpg-sign` selector is. The GPG signatures are written first, and the
/// `--sign` signatures after them, in one write of each signature file. Each
/// directory under `refs/mirrors/` whose name is not a collection id gets one
/// `warning:` line on standard error.
async fn summary_update(repo: &Repo, args: &SummaryArgs) -> Result<()> {
    let additional_metadata = match summary_added_metadata(&args.add_metadata) {
        Ok(entries) => entries,
        Err(message) => exit_error(&message),
    };
    let signers = summary_signers(&args.signing()).await?;

    let opts = SummaryOptions {
        last_modified: args.last_modified,
        metadata_commit_timestamp: args.metadata_commit_timestamp,
        additional_metadata,
        auth_items_only: args.client_groups,
    };
    let report = repo
        .regenerate_summaries(&opts, &signer_refs(&signers))
        .await?;
    for name in &report.invalid_collection_dirs {
        let name: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_control() {
                    c.escape_default().to_string()
                } else {
                    c.to_string()
                }
            })
            .collect();
        eprintln!(
            "warning: refs/mirrors/{name}: the directory name is not a collection id, and no \
             summary holds its refs"
        );
    }
    Ok(())
}

/// Returns the signers of a summary update, in the order of the signatures:
/// each `--gpg-sign` key, each `--sign` key, and then the positional and
/// `--keys-file` keys.
///
/// The steps 2 to 5 of the checks of [`summary_update`] run here, in that
/// order. Under the gpg engine, a `--sign` key and a positional key are looked
/// up as a `--gpg-sign` selector is.
async fn summary_signers(args: &SummarySigning<'_>) -> Result<Vec<Box<dyn Signer>>> {
    let homedir = args.gpg_homedir;
    let mut signers = match resolve_gpg_selectors(args.gpg_sign, homedir).await? {
        Ok(signers) => signers,
        Err(message) => exit_error(&message),
    };
    let extension = !args.key_id.is_empty() || !args.keys_file.is_empty();
    if !args.sign.is_empty() || extension {
        let engine = summary_sign_type(args);
        if engine == SignType::Gpg {
            match resolve_gpg_selectors(args.sign, homedir).await? {
                Ok(resolved) => signers.extend(resolved),
                Err(message) => exit_error(&message),
            }
        } else {
            for key in args.sign {
                match sign_api_signer(engine, key.as_bytes(), homedir) {
                    Ok(signer) => signers.push(signer),
                    Err(message) => exit_error(&message),
                }
            }
        }
        if extension {
            signers.extend(summary_extension_signers(args, engine).await?);
        }
    }
    Ok(signers)
}

/// Returns a borrow of each boxed signer, in order, for a batch signing call.
fn signer_refs(signers: &[Box<dyn Signer>]) -> Vec<&dyn Signer> {
    signers.iter().map(|signer| signer.as_ref()).collect()
}

/// The refusal of a read option if the repository has no `summary` file.
///
/// The `ostree` command gives `openat(summary): No such file or directory`, in
/// the form of its errno wrapper. Both commands exit 1 and write nothing to
/// standard output. This is a recorded divergence.
const SUMMARY_ABSENT: &str = "opening summary: No such file or directory";

/// Reports the local summary, or the summary of `item`.
///
/// The output is the raw variant, the report, the metadata keys, or one
/// metadata value. The precedence is that of the `ostree` command.
async fn summary_read(
    repo: &Repo,
    args: &SummaryArgs,
    item: Option<&ostrya::access::AuthItem>,
) -> Result<()> {
    let read = match item {
        Some(item) => repo.read_summary_of(item).await?,
        None => repo.read_summary().await?,
    };
    let Some(bytes) = read else {
        match item {
            Some(item) => exit_error(&format!(
                "the summary of the auth item {item} does not exist; run `ostrya summary -u`"
            )),
            None => exit_error(SUMMARY_ABSENT),
        }
    };
    print_summary_document(
        &bytes,
        args.raw,
        args.view,
        args.list_metadata_keys,
        args.print_metadata_key.as_deref(),
    )
}

/// Returns the signers of the positional keys and `--keys-file` under `engine`.
///
/// This is an ostrya extension. The keys are read strictly, as `ostrya sign`
/// reads them. A gpg selector is looked up before the signer is returned.
async fn summary_extension_signers(
    args: &SummarySigning<'_>,
    engine: SignType,
) -> Result<Vec<Box<dyn Signer>>> {
    match engine {
        SignType::Ed25519 => summary_secret_keys(args)?
            .iter()
            .map(|key| {
                Ed25519Signer::from_base64(key)
                    .map(|signer| Box::new(signer) as Box<dyn Signer>)
                    .map_err(Error::from)
            })
            .collect(),
        SignType::Spki => summary_signers_spki(args),
        SignType::Gpg => summary_signers_gpg(args).await,
    }
}

/// Returns an spki signer for each positional summary secret key, then for
/// each `PRIVATE KEY` block of each `--keys-file`, in order.
#[cfg(feature = "spki")]
fn summary_signers_spki(args: &SummarySigning<'_>) -> Result<Vec<Box<dyn Signer>>> {
    let signers = spki_signers(args.key_id, args.keys_file, no_summary_key(args.remote))?;
    Ok(signers
        .into_iter()
        .map(|signer| Box::new(signer) as Box<dyn Signer>)
        .collect())
}

/// Returns an error, because this build has no spki engine.
#[cfg(not(feature = "spki"))]
fn summary_signers_spki(_: &SummarySigning<'_>) -> Result<Vec<Box<dyn Signer>>> {
    Err(unsupported_type("spki"))
}

/// Returns a gpg signer for each positional KEY-ID of `summary`.
#[cfg(feature = "gpg")]
async fn summary_signers_gpg(args: &SummarySigning<'_>) -> Result<Vec<Box<dyn Signer>>> {
    if !args.keys_file.is_empty() {
        let message = if args.remote {
            "gpg signing takes --gpg-sign and --sign KEY-ID arguments; --keys-file serves the \
             other engines"
        } else {
            "gpg signing takes KEY-ID arguments; --keys-file keyrings serve verify"
        };
        return Err(Error::Signature(message.into()));
    }
    match resolve_gpg_selectors(args.key_id, args.gpg_homedir).await? {
        Ok(signers) => Ok(signers),
        Err(message) => exit_error(&message),
    }
}

/// Returns an error, because this build has no gpg engine.
#[cfg(not(feature = "gpg"))]
async fn summary_signers_gpg(_: &SummarySigning<'_>) -> Result<Vec<Box<dyn Signer>>> {
    Err(unsupported_type("gpg"))
}

/// Returns the base64 secret keys for a summary signing run.
///
/// These are the KEY-IDs and the non-blank lines of each `--keys-file`. At
/// least one key is required.
fn summary_secret_keys(args: &SummarySigning<'_>) -> Result<Vec<String>> {
    let mut keys = args.key_id.to_vec();
    for path in args.keys_file {
        keys.extend(read_key_lines(Path::new(path))?);
    }
    if keys.is_empty() {
        return Err(Error::Signature(no_summary_key(args.remote).into()));
    }
    Ok(keys)
}

/// Returns the refusal of a summary signing run with no key.
///
/// `remote` is `true` for `ostrya remote summary -u`, whose refusal names its
/// own options.
fn no_summary_key(remote: bool) -> &'static str {
    if remote {
        "no signing key given; pass --sign or --keys-file"
    } else {
        "no signing key given; pass a key argument or --keys-file"
    }
}

/// Returns the verifier for `ostrya summary --verify`.
///
/// The ed25519 and spki engines read the key sources of `ostrya sign
/// --verify`. The gpg engine reads each `--keys-file` keyring and refuses
/// `--keys-dir`.
fn summary_verifier(
    repo_path: &Path,
    engine: SignType,
    args: &SummaryArgs,
) -> Result<Box<dyn Verifier>> {
    match engine {
        SignType::Gpg if args.keys_dir.is_some() => Err(gpg_keys_dir_refusal()),
        SignType::Gpg => summary_gpg_verifier(repo_path, args),
        engine => Ok(load_verify_keys(
            engine,
            &args.key_id,
            args.keys_file.last().map(Path::new),
            args.keys_dir.as_deref().map(Path::new),
        )?
        .verifier),
    }
}

/// Returns the gpg verifier for `summary --verify`.
///
/// The keyrings are each `--keys-file`, or else the trusted keys of
/// `--remote`, or else the system trust.
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

/// Returns an error, because this build has no gpg engine.
#[cfg(not(feature = "gpg"))]
fn summary_gpg_verifier(_: &Path, _: &SummaryArgs) -> Result<Box<dyn Verifier>> {
    Err(unsupported_type("gpg"))
}

/// Signs the commit once for each given key.
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

/// Signs the commit with each spki secret key.
///
/// The signers are the positional keys, then the `PRIVATE KEY` blocks of each
/// `--keys-file`. The command reads every key before the first signature, so
/// a refused key writes no signature.
#[cfg(feature = "spki")]
async fn sign_spki(repo: &Repo, commit: &Checksum, args: &SignArgs) -> Result<()> {
    let signers = spki_signers(
        &args.key_id,
        &args.keys_file,
        "no signing key given; pass a key argument or --keys-file",
    )?;
    for signer in &signers {
        repo.sign_commit(commit, signer).await?;
    }
    Ok(())
}

/// Returns the spki signers of a signing run: one for each positional secret
/// key, then one for each `PRIVATE KEY` block of each key file, in order.
///
/// `none` is the refusal if no key is given.
#[cfg(feature = "spki")]
fn spki_signers(
    key_id: &[String],
    keys_file: &[std::ffi::OsString],
    none: &str,
) -> Result<Vec<SpkiSigner>> {
    let mut signers = Vec::new();
    for key in key_id {
        signers.push(SpkiSigner::from_base64(key)?);
    }
    for path in keys_file {
        signers.extend(spki_key_file_signers(Path::new(path))?);
    }
    if signers.is_empty() {
        return Err(Error::Signature(none.into()));
    }
    Ok(signers)
}

/// Returns one spki signer for each `PRIVATE KEY` block of the secret key
/// file at `path`, in the order of the file.
///
/// The file is read as [`read_signing_key_file`] reads it. `spki_secret_keys`
/// of the `ostrya` crate reads the blocks and states the rules of the file.
#[cfg(feature = "spki")]
fn spki_key_file_signers(path: &Path) -> Result<Vec<SpkiSigner>> {
    let bytes = read_signing_key_file(path)?;
    Ok(spki_secret_keys(bytes, &key_file_subject(path))?)
}

/// Returns an error, because this build has no spki engine.
#[cfg(not(feature = "spki"))]
async fn sign_spki(_: &Repo, _: &Checksum, _: &SignArgs) -> Result<()> {
    Err(unsupported_type("spki"))
}

/// Signs the commit with keys that the `gpg` binary resolves.
///
/// Each KEY-ID is a fingerprint, a key id, or a user id. The lookup uses the
/// default GnuPG home directory or the `--gpg-homedir` override. The private
/// key stays with gpg and its agent, also a key on a hardware token.
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

/// Returns an error, because this build has no gpg engine.
#[cfg(not(feature = "gpg"))]
async fn sign_gpg(_: &Repo, _: &Checksum, _: &SignArgs) -> Result<()> {
    Err(unsupported_type("gpg"))
}

/// Verifies the commit under the selected engine and prints each signature.
///
/// If no signature is valid, the process exits 1.
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
    report_verify(&outcome, args.sign_type);
    if !outcome.valid {
        exit_process(1);
    }
    Ok(())
}

/// Deletes the signatures that the KEY-IDs match, and prints the count.
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
            // An ed25519 or spki blob belongs to a KEY-ID if it verifies under
            // that public key. Verification is async, so the code selects the
            // blobs to remove first, and the predicate matches them by bytes.
            let verifier = build_sign_api_verifier(engine, &public_key_bytes(args)?, &[])?;
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

/// Returns the signature blobs stored under `key` in the detached metadata.
///
/// The blobs come in stored order. If the metadata or the key is missing, or
/// the value is not an array, the result is empty. Elements that are not
/// bytes are skipped.
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

/// Deletes the GPG signatures that match a KEY-ID by fingerprint.
///
/// A signature matches by its issuer fingerprint or by its primary-key
/// fingerprint. The issuer fingerprint is reported also for a key that is not
/// in the keyrings. If a keyring of the trusted set (`--keys-file`,
/// `--remote`, or the default `trusted.gpg.d`) holds the key, a match can
/// also use the primary-key fingerprint of a verified signature.
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

/// Returns an error, because this build has no gpg engine.
#[cfg(not(feature = "gpg"))]
async fn gpg_delete(_: &Repo, _: &Checksum, _: &Path, _: &SignArgs) -> Result<usize> {
    Err(unsupported_type("gpg"))
}

/// Returns the ed25519 or spki verifier of `sign --verify`.
///
/// [`load_verify_keys`] reads the KEY-IDs and the last `--keys-file`. With
/// neither, it reads the last `--keys-dir`, or the system key directories if
/// `--keys-dir` is absent. If no trusted key is loaded before revocation, the
/// error is `{type}: no keys loaded`.
fn sign_api_verifier(engine: SignType, args: &SignArgs) -> Result<Box<dyn Verifier>> {
    let keys = load_verify_keys(
        engine,
        &args.key_id,
        args.keys_file.last().map(Path::new),
        args.keys_dir.as_deref().map(Path::new),
    )?;
    Ok(keys.verifier)
}

/// Returns an ed25519 or spki verifier for the trusted and revoked public
/// keys.
fn build_sign_api_verifier(
    engine: SignType,
    trusted: &[Vec<u8>],
    revoked: &[Vec<u8>],
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

/// Returns the gpg verifier of `sign --verify`, with the keyrings of
/// [`gpg_trust`].
#[cfg(feature = "gpg")]
fn gpg_verifier(repo_path: &Path, args: &SignArgs) -> Result<Box<dyn Verifier>> {
    Ok(Box::new(gpg_trust(repo_path, args)?))
}

/// Returns an error, because this build has no gpg engine.
#[cfg(not(feature = "gpg"))]
fn gpg_verifier(_: &Path, _: &SignArgs) -> Result<Box<dyn Verifier>> {
    Err(unsupported_type("gpg"))
}

/// Returns the trusted gpg keyring set for verify and delete.
///
/// If `--keys-file` gives keyrings, the set is these keyrings. Otherwise, the
/// set is the default ostree trust: the global `trusted.gpg.d` directory (or
/// `$OSTREE_GPG_HOME`). If `--remote` names a remote, the set also holds the
/// `trustedkeys.gpg` of that remote.
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

/// Returns the base64 secret keys for an ed25519 signing run.
///
/// These are the KEY-IDs and the non-blank lines of each `--keys-file`. At
/// least one key is required.
fn secret_key_lines(args: &SignArgs) -> Result<Vec<String>> {
    let mut keys = args.key_id.clone();
    for path in &args.keys_file {
        keys.extend(read_key_lines(Path::new(path))?);
    }
    if keys.is_empty() {
        return Err(Error::Signature(
            "no signing key given; pass a key argument or --keys-file".into(),
        ));
    }
    Ok(keys)
}

/// Returns the decoded public keys for an ed25519 or spki verify or delete.
///
/// These are the KEY-IDs and the keys of each `--keys-file`. An spki KEY-ID
/// decodes as [`verify_key_bytes`] decodes it, so it can hold the line breaks
/// of a PEM body. An spki `--keys-file` holds PEM `PUBLIC KEY` blocks, and
/// [`spki_delete_keys`] reads it. The other KEY-IDs and the lines of an
/// ed25519 `--keys-file` decode strictly.
fn public_key_bytes(args: &SignArgs) -> Result<Vec<Vec<u8>>> {
    let mut keys = Vec::new();
    for key in &args.key_id {
        keys.push(match args.sign_type {
            SignType::Spki => verify_key_bytes(SignType::Spki, key.as_bytes()),
            _ => base64::decode(key.trim())?,
        });
    }
    for path in &args.keys_file {
        if args.sign_type == SignType::Spki {
            keys.extend(spki_delete_keys(Path::new(path))?);
            continue;
        }
        for line in read_key_lines(Path::new(path))? {
            keys.push(base64::decode(&line)?);
        }
    }
    Ok(keys)
}

/// Returns the public keys of an spki `-d` `--keys-file`.
///
/// The file is read as [`read_signing_key_file`] reads it. `spki_public_keys`
/// of the `ostrya` crate reads its PEM `PUBLIC KEY` blocks, by the rules of a
/// verify `--keys-file`.
#[cfg(feature = "spki")]
fn spki_delete_keys(path: &Path) -> Result<Vec<Vec<u8>>> {
    let bytes = read_signing_key_file(path)?;
    Ok(spki_public_keys(&bytes, &key_file_subject(path))?)
}

/// Returns an error, because this build has no spki engine.
#[cfg(not(feature = "spki"))]
fn spki_delete_keys(_: &Path) -> Result<Vec<Vec<u8>>> {
    Err(unsupported_type("spki"))
}

/// Returns the non-blank lines of a key file, trimmed.
///
/// The file is read as [`read_signing_key_file`] reads it.
fn read_key_lines(path: &Path) -> Result<Vec<String>> {
    let content = String::from_utf8(read_signing_key_file(path)?).map_err(|_| {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "stream did not contain valid UTF-8",
        ))
    })?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect())
}

/// Reads the whole key file at `path` for a signing run or a delete.
///
/// The read takes a regular file alone, of at most `MAX_KEY_FILE` bytes. It
/// does not wait on a fifo. A missing file gives the I/O error of a missing
/// file.
///
/// # Errors
///
/// - [`Error::Io`] if no file is at `path`.
/// - [`Error::Signature`] if the file cannot be opened or read, is not a
///   regular file, or is over the ceiling. The message names the file as
///   [`key_file_subject`] does.
fn read_signing_key_file(path: &Path) -> Result<Vec<u8>> {
    let subject = key_file_subject(path);
    match ostrya::sign::read_key_file(path, &subject, ostrya::sign::MAX_KEY_FILE)? {
        Some(bytes) => Ok(bytes),
        // ENOENT, so the message is the message of a failed open.
        None => Err(Error::Io(std::io::Error::from_raw_os_error(2))),
    }
}

/// Returns the name of the key file at `path` in a message.
fn key_file_subject(path: &Path) -> String {
    format!("the key file '{}'", path.display())
}

/// Returns the short name of an engine.
///
/// The `trusted.<name>` and `revoked.<name>` key-store files use this name.
fn sign_type_name(engine: SignType) -> &'static str {
    match engine {
        SignType::Ed25519 => "ed25519",
        SignType::Spki => "spki",
        SignType::Gpg => "gpg",
    }
}

/// Returns the detached-metadata dict key that holds the signatures of an
/// engine.
fn sign_metadata_key(engine: SignType) -> &'static str {
    match engine {
        SignType::Ed25519 => "ostree.sign.ed25519",
        SignType::Spki => "ostree.sign.spki",
        SignType::Gpg => "ostree.gpgsigs",
    }
}

/// Normalizes a GPG fingerprint or key id for a suffix match.
///
/// The function drops a `0x` prefix and all spaces, and changes the hex to
/// uppercase.
#[cfg(feature = "gpg")]
fn normalize_fingerprint(id: &str) -> String {
    id.trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .replace(' ', "")
        .to_uppercase()
}

/// Returns `true` if a stored fingerprint ends with one of the wanted key ids.
///
/// A short key id matches the tail of a full fingerprint.
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

/// Returns the error for a sign type whose engine this binary does not have.
#[cfg_attr(all(feature = "spki", feature = "gpg"), allow(dead_code))]
fn unsupported_type(name: &str) -> Error {
    Error::Unsupported(format!(
        "sign-type '{name}' requires building ostrya-cli with the '{name}' feature"
    ))
}

/// Prints one line for each examined signature, and a final verdict.
///
/// A line gives the fingerprint of the key under the gpg engine alone.
fn report_verify(outcome: &VerifyOutcome, engine: SignType) {
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
        if let Some(fpr) = sig.fingerprint.as_ref().filter(|_| engine == SignType::Gpg) {
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

/// Resolves a revision to a commit checksum.
///
/// A revision is a checksum or a refspec, each with an optional trailing `^`
/// for each generation of ancestry. The two resolution failures are reported
/// in the words of the `ostree` command. `resolve_rev` with
/// `allow_noent = false` returns `Some` or an error, and never `None`.
async fn resolve(repo: &Repo, rev: &str) -> Result<Checksum> {
    match repo.resolve_rev(rev, false).await {
        Ok(checksum) => {
            Ok(checksum.expect("resolve_rev with allow_noent=false returns Some or errors"))
        }
        Err(err) => Err(report_resolution_failure(err)),
    }
}

/// Resolves a revision that can be absent.
///
/// `None` states that nothing of that name is in the repository. A resolution
/// failure gets the same words that [`resolve`] gives it.
async fn resolve_optional(repo: &Repo, rev: &str) -> Result<Option<Checksum>> {
    match repo.resolve_rev(rev, true).await {
        Ok(found) => Ok(found),
        Err(err) => Err(report_resolution_failure(err)),
    }
}

/// Reports a resolution failure in the words of the `ostree` command.
///
/// This applies to two failures: a missing refspec and a commit with no
/// parent. As a result, one condition has one message wherever a revision is
/// resolved. Each other error goes back to the caller.
fn report_resolution_failure(err: Error) -> Error {
    match err {
        Error::RefNotFound(refspec) => exit_error(&format!("Refspec '{refspec}' not found")),
        Error::NoParentCommit(commit) => {
            exit_error(&format!("Commit {} has no parent", commit.to_hex()))
        }
        other => other,
    }
}

/// The metadata key that `--bootable` fills with the name of the kernel
/// directory.
const LINUX_KEY: &str = "ostree.linux";
/// The metadata key that `--bootable` sets to true.
const BOOTABLE_KEY: &str = "ostree.bootable";
/// The metadata key for the composefs image digest of the tree.
///
/// `--generate-composefs-metadata` fills this key.
const COMPOSEFS_DIGEST_KEY: &str = "ostree.composefs.digest.v0";
/// The directory that two of the `--bootable` refusals name.
const MODULES_DIR: &str = "/usr/lib/modules";

/// Returns the kernel version that `--bootable` stores in `ostree.linux`.
///
/// The version comes from the tree that the transaction staged. The refusals
/// use the words of the `ostree` command:
///
/// - the first component of the path that the tree does not hold
/// - a component that is not a directory
/// - the two counts that are not one: no kernel, and more than one kernel
///
/// The `Not a directory` message of `ostree` names no path, so this function
/// drops the path of that refusal.
async fn kernel_version(
    txn: &Transaction,
    root: &RepoTree,
) -> Result<std::result::Result<String, String>> {
    let found = txn.kernel_version(root).await?;
    Ok(found.map_err(|refusal| match refusal {
        BootableRefusal::MissingComponent { path } => {
            format!("No such file or directory: {path}")
        }
        BootableRefusal::NotADirectory { .. } => "Not a directory".to_owned(),
        BootableRefusal::NoKernel => format!("No kernel found in {MODULES_DIR}"),
        BootableRefusal::MultipleKernels => format!("Multiple kernels found in {MODULES_DIR}"),
    }))
}

/// Inserts entries at the head of an `a{sv}` metadata dict.
///
/// This is the slot of the keys that a tree walk derives.
fn prepend_metadata_entries(metadata: &mut Value, entries: Vec<Value>) -> Result<()> {
    let Value::Array(existing) = metadata else {
        return Err(Error::InvalidFormat(
            "commit metadata must be an a{sv} dict".into(),
        ));
    };
    existing.splice(0..0, entries);
    Ok(())
}

/// Removes each entry of an `a{sv}` metadata dict that holds one of `keys`.
///
/// A derived key does this to a value that the command line gave for the same
/// name.
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

/// Stores one entry in an `a{sv}` metadata dict under `key`.
///
/// If the dict already holds an entry with that name, the new value goes in
/// the slot of the first such entry. Each later entry with that name is
/// removed. If the dict does not hold the name, the entry is appended.
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

/// Returns a string-valued metadata entry.
///
/// `--add-metadata-string` and `--add-detached-metadata-string` write this
/// form.
fn string_entry(key: &str, value: &str) -> Value {
    Value::Tuple(vec![
        Value::Str(key.to_owned()),
        Value::variant(Type::Str, Value::Str(value.to_owned())),
    ])
}

/// Splits each `KEY=VALUE` metadata argument at its first `=`.
///
/// A value can hold more `=` characters. An empty key passes here and is
/// refused where the dict is assembled. A missing `=` is refused at once, in
/// the words of the `ostree` command.
fn metadata_pairs(arguments: &[String]) -> std::result::Result<Vec<(&str, &str)>, String> {
    arguments
        .iter()
        .map(|argument| metadata_pair(argument))
        .collect()
}

/// Splits one `KEY=VALUE` metadata argument at its first `=`.
///
/// A missing `=` is refused in the words of the `ostree` command.
fn metadata_pair(argument: &str) -> std::result::Result<(&str, &str), String> {
    argument
        .split_once('=')
        .ok_or_else(|| format!("Missing '=' in KEY=VALUE metadata '{argument}'"))
}

/// Splits each `--related` argument at its last `=` into a name and a
/// checksum.
///
/// The checksum is 64 lowercase hexadecimal characters. An empty name and a
/// name that occurs two times pass here, and the commit write refuses them.
fn related_pairs(arguments: &[String]) -> std::result::Result<Vec<(String, Checksum)>, String> {
    arguments
        .iter()
        .map(|argument| {
            let (name, hex) = argument
                .rsplit_once('=')
                .ok_or_else(|| format!("Missing '=' in NAME=CHECKSUM argument '{argument}'"))?;
            let checksum = Checksum::from_hex_lower(hex).map_err(|_| {
                format!(
                    "Checksum '{hex}' in '{argument}' is not 64 lowercase hexadecimal characters"
                )
            })?;
            Ok((name.to_owned(), checksum))
        })
        .collect()
}

/// Reads each `--add-metadata` argument into its key and the variant of its
/// value.
///
/// The value goes through the GVariant text form. A refusal names the full
/// argument and the offsets of the reader. Each argument is split and parsed
/// before the next one is read, so the refusal names the first bad argument
/// in command-line order.
fn parse_added_metadata(arguments: &[String]) -> std::result::Result<Vec<(&str, Value)>, String> {
    let mut entries = Vec::with_capacity(arguments.len());
    for argument in arguments {
        let (key, text) = metadata_pair(argument)?;
        let (ty, value) =
            ostrya::from_text(text).map_err(|error| format!("Parsing {argument}: {error}"))?;
        entries.push((key, Value::variant(ty, value)));
    }
    Ok(entries)
}

/// Reads each `summary -m` argument into its key and the variant of its
/// value.
///
/// The arguments are read one at a time, in command-line order. The empty key
/// is accepted. The refusals use the words of the `ostree` command for this
/// command. They name only the value, and `commit` names the full argument.
fn summary_added_metadata(
    arguments: &[String],
) -> std::result::Result<Vec<(String, Value)>, String> {
    let mut entries = Vec::with_capacity(arguments.len());
    for argument in arguments {
        let (key, text) = metadata_pair(argument)?;
        let (ty, value) = ostrya::from_text(text)
            .map_err(|error| format!("Error parsing variant \u{2018}{text}\u{2019}: : {error}"))?;
        entries.push((key.to_owned(), Value::variant(ty, value)));
    }
    Ok(entries)
}

/// Reads each `--keep-metadata` key from the resolved parent commit.
///
/// The bytes of each value stay as they are. If the parent does not hold a
/// key, the refusal names the commit.
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

/// Assembles the commit metadata dict.
///
/// The entry order is part of the commit checksum:
///
/// 1. each `--add-metadata-string`, in command-line order
/// 2. each `--add-metadata`
/// 3. each `--keep-metadata`
/// 4. the binding keys
///
/// Duplicate keys stay as duplicates. An empty key is refused here, after the
/// tree and the timestamp.
///
/// The order and the binding keys come from `ostrya::commit::commit_metadata`,
/// which `ostrya-core` defines. The binding keys name the branch of `-b`, each
/// `--tag` value, and each `--bind-ref` value. A commit that names none of
/// them has the empty `as` array. The `ostree` command writes this value under
/// `--orphan` alone.
fn commit_metadata_dict(
    repo: &Repo,
    args: &CommitArgs,
    added_strings: &[(&str, &str)],
    added_variants: &[(&str, Value)],
    kept: &[(String, Value)],
) -> std::result::Result<Value, String> {
    let mut entries = user_metadata_entries(added_strings, added_variants)?;
    entries.extend(kept.iter().cloned());
    let refs: Vec<&str> = args
        .branch
        .as_deref()
        .into_iter()
        .chain(args.tags.iter().map(String::as_str))
        .chain(args.bind_ref.iter().map(String::as_str))
        .collect();
    // `--no-bindings` writes neither binding key, so the dict of a commit that
    // adds no entries of its own is empty.
    Ok(ostrya::commit::commit_metadata(
        entries,
        (!args.no_bindings).then_some(refs.as_slice()),
        repo.config().collection_id(),
    ))
}

/// Returns the metadata entries of `--add-metadata-string` and
/// `--add-metadata`.
///
/// The entries form two groups for each command-line order: each string
/// entry in command-line order, then each variant entry. Each value is a
/// variant, and duplicate keys stay as duplicates. An empty key is refused.
fn user_metadata_entries(
    strings: &[(&str, &str)],
    variants: &[(&str, Value)],
) -> std::result::Result<Vec<(String, Value)>, String> {
    let mut entries = Vec::with_capacity(strings.len() + variants.len());
    let strings = strings.iter().map(|(key, value)| {
        (
            *key,
            Value::variant(Type::Str, Value::Str((*value).to_owned())),
        )
    });
    let variants = variants.iter().map(|(key, value)| (*key, value.clone()));
    for (key, value) in strings.chain(variants) {
        if key.is_empty() {
            return Err("Empty metadata key".to_owned());
        }
        entries.push((key.to_owned(), value));
    }
    Ok(entries)
}

/// Returns the detached metadata dict that `--add-detached-metadata-string`
/// writes.
///
/// If the option is not given, the result is `None`. The entries keep
/// command-line order, an empty key is accepted here, and duplicates stay as
/// duplicates.
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

/// The maximum size in bytes of a `-F/--body-file` file or an `-e/--editor`
/// file.
///
/// The body is a field of the commit object, and ostrya loads no metadata
/// object larger than this size. A larger body names a commit that ostrya can
/// never read back. The limit also bars an unbounded read of the file.
const MAX_BODY_BYTES: u64 = 128 * 1024 * 1024;

/// Reads `-F/--body-file`: the full file becomes the body, byte for byte.
fn read_body_file(path: &Path) -> std::result::Result<String, String> {
    read_message_file(path, "Commit body")
}

/// Reads a file that holds commit message text.
///
/// The file must be valid UTF-8, hold no NUL, and be no larger than
/// [`MAX_BODY_BYTES`]. `kind` names the file in the over-limit line. The
/// refusals use the words of the `ostree` command:
///
/// - `openat(<path>): <reason>` for a path that does not open
/// - the reason alone for a read that fails
/// - `Invalid UTF-8` for content that neither command can hold
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

/// The environment variables that name the editor, in lookup order.
///
/// The first one that is set wins, also with an empty value. If none is set,
/// [`DEFAULT_EDITOR`] applies. `GIT_EDITOR` is not one of them.
const EDITOR_VARIABLES: [&str; 3] = ["OSTREE_EDITOR", "VISUAL", "EDITOR"];
/// The editor if no environment variable names one.
const DEFAULT_EDITOR: &str = "vi";

/// The commit-message template that goes into the temporary file of the
/// editor.
///
/// For a commit that names a branch, the branch block is appended.
const MESSAGE_TEMPLATE: &str = "\n\
     # Please enter the commit message for your changes. The first line will\n\
     # become the subject, and the remainder the body. Lines starting\n\
     # with '#' will be ignored, and an empty message aborts the commit.\n";

/// Runs the editor on the message template and returns the subject and body.
///
/// The template holds the branch block if `branch` names one. `subject` comes
/// after the block as a prefill. The editor value is a shell command line, and
/// the path of the temporary file is appended to it, shell-quoted. A non-zero
/// exit discards the full edit.
///
/// The executor stays free while the editor runs. See [`wait_for_editor`].
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
    // The command line holds the editor value and the path as bytes. As a
    // result, an editor variable that is not UTF-8 still names the editor to
    // run. A `TMPDIR` that is not UTF-8 still names the file that ostrya wrote.
    let mut command = editor.as_bytes().to_vec();
    command.push(b' ');
    command.extend_from_slice(&shell_quote(&path));
    let status = wait_for_editor(command).await;
    // The editor writes the file, so the read has the same limit as `-F` and
    // refuses the same content. An editor can leave any bytes in the file, and
    // the limit bars an unbounded read.
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

/// Runs `command` under `/bin/sh -c` and waits for it to exit.
///
/// The editor takes control of the terminal, so it inherits the three
/// standard streams of this process. [`std::process::Command`] gives it these
/// streams, and [`ostrya_rt::Command`] pipes them. The wait runs on the
/// blocking pool through [`ostrya_rt::unblock`], so the executor thread stays
/// free for the full editing session.
async fn wait_for_editor(command: Vec<u8>) -> std::io::Result<std::process::ExitStatus> {
    ostrya_rt::unblock(move || {
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(std::ffi::OsString::from_vec(command))
            .status()
    })
    .await
}

/// Returns the editor command line.
///
/// This is the first of [`EDITOR_VARIABLES`] that is set, or else
/// [`DEFAULT_EDITOR`]. The value is read as bytes, so a variable with a value
/// that is not UTF-8 counts as set and names the editor to run.
fn editor_command() -> std::ffi::OsString {
    EDITOR_VARIABLES
        .iter()
        .find_map(std::env::var_os)
        .unwrap_or_else(|| std::ffi::OsString::from(DEFAULT_EDITOR))
}

/// Quotes a path so that a shell reads it as one word.
///
/// The path goes in single quotes. Each single quote in the path is closed,
/// escaped, and opened again. The bytes pass through unchanged, so a path
/// that is not UTF-8 stays intact.
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

/// Writes the template to a new file in `TMPDIR` and returns its path.
///
/// If `TMPDIR` is not set, the directory is `/tmp`. The name is `.` and six
/// characters.
///
/// Only the owner can read and write the file, which is the mode of the
/// `ostree` command. As a result, no other user can read the message during the
/// edit. The file is removed after the editor runs.
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

/// Returns the nanoseconds of the current time, which seed the temporary name.
fn nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| u64::from(since.subsec_nanos()))
}

/// Reads the subject and the body from an edited commit message.
///
/// Each line loses its trailing whitespace. A line whose first character is
/// `#` is dropped, and the leading blank lines go. The first remaining line is
/// the subject. The lines after it, without their leading and trailing blank
/// lines, are the body, joined by newlines.
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

/// Returns the refusal for a branch name that the revision syntax shadows.
///
/// For each other name, the result is `None`. Resolution reads a name of 64
/// lowercase hex characters as a checksum, so no revision can reach a ref
/// with such a name. The message uses the words of the guard of the `ostree`
/// command. This function does not cover a name with `^`, because the
/// ref-name rule refuses it.
fn shadowed_branch_name(branch: &str) -> Option<String> {
    if ostrya::is_checksum_shaped(branch) {
        return Some(format!("Rev name '{branch}' looks like a checksum"));
    }
    None
}

/// Returns an async streaming reader over stdin, on a duplicated descriptor.
///
/// When the reader drops, the real stdin stays open. A tar stream on standard
/// input flows through this reader, so no unbounded stream is held in memory.
fn stdin_file() -> Result<ostrya_rt::FileReader> {
    let fd = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map_err(Error::Io)?;
    Ok(ostrya_rt::FileReader::from(fd))
}

/// Returns an async streaming writer over stdout, on a duplicated descriptor.
///
/// A stream to standard output flows through this writer, so no unbounded
/// stream is held in memory.
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

    /// The `apply-offline` PATH is reduced lexically, as the `ostree` command
    /// reduces it. `.`, empty components, and a trailing `/` go. Each `..`
    /// removes the component before it. A leading `..` stays, and `..` at the
    /// root stays at the root.
    #[test]
    fn an_apply_offline_path_folds_lexically() {
        for (given, folded) in [
            (".", "."),
            ("./", "."),
            ("..", ".."),
            ("a/..", "."),
            ("a/b/../..", "."),
            ("lnk/../x", "x"),
            ("lnk/../x/superblock", "x/superblock"),
            ("d/superblock/..", "d"),
            ("d/superblock/", "d/superblock"),
            ("d/superblock/.", "d/superblock"),
            ("./d/./superblock", "d/superblock"),
            ("d//superblock", "d/superblock"),
            ("../x", "../x"),
            ("../../x/..", "../.."),
            ("a/../../x", "../x"),
            ("/", "/"),
            ("//", "/"),
            ("/..", "/"),
            ("/../../a/lnk/../x", "/a/x"),
        ] {
            assert_eq!(lexical_path(Path::new(given)), Path::new(folded), "{given}");
        }
    }

    /// The size words for less than 1000 bytes, and the U+00A0 before a unit.
    /// The raw count selects the unit, and the rounding is ties to even on the
    /// exact double.
    #[test]
    fn a_delta_size_is_worded_as_the_tool_words_it() {
        for (n, text) in [
            (0, "0 bytes"),
            (1, "1 byte"),
            (2, "2 bytes"),
            (999, "999 bytes"),
            (1_000, "1.0\u{a0}kB"),
            (1_250, "1.2\u{a0}kB"),
            (1_750, "1.8\u{a0}kB"),
            (999_950, "1000.0\u{a0}kB"),
            (999_999, "1000.0\u{a0}kB"),
            (1_000_000, "1.0\u{a0}MB"),
            (u64::MAX, "18.4\u{a0}EB"),
        ] {
            assert_eq!(format_delta_size(n), text, "{n}");
        }
    }

    /// Each half of a delta name is 64 lowercase hex characters. The two
    /// refusals name what the `ostree` command names.
    #[test]
    fn a_delta_name_is_read_as_the_tool_reads_it() {
        let hex = "ab".repeat(32);
        assert_eq!(parse_delta_name(&hex).unwrap().1.to_hex(), hex);
        let pair = parse_delta_name(&format!("{hex}-{hex}")).unwrap();
        assert_eq!(pair.0.unwrap().to_hex(), hex);
        assert_eq!(parse_delta_name("ABC").unwrap_err(), "Invalid rev ABC");
        assert_eq!(
            parse_delta_name(&format!("{hex}-")).unwrap_err(),
            "Invalid rev "
        );
        assert_eq!(
            parse_delta_name(&format!("{hex}-{hex}-{hex}")).unwrap_err(),
            format!("Invalid rev {hex}")
        );
        let upper = hex.to_uppercase();
        assert_eq!(
            parse_delta_name(&upper).unwrap_err(),
            format!("Invalid character '65' in rev '{upper}'")
        );
    }

    /// The error paths render the usage text of a subcommand by name. If
    /// `clap` does not know a name, the process aborts and does not print
    /// the usage text.
    /// This test compares [`Command::NAMES`] and the set of `clap` in both
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

    /// An `--owner-uid`/`--owner-gid` value reads as a C `int`, with the base
    /// from the text. `0x` is hexadecimal, a leading `0` is octal, and each
    /// other value is decimal.
    ///
    /// Leading whitespace and a sign are accepted, and a trailing byte is not.
    /// The range is the range of a C `int`. Each value here was compared with
    /// `ostree commit`.
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

        // A negative id declares nothing, so the ownership of the source stays.
        let declared = |text: &str| owner_id(Some(text), "--owner-uid");
        assert_eq!(declared("0"), Some(0));
        assert_eq!(declared("42"), Some(42));
        assert_eq!(declared("-1"), None);
        assert_eq!(declared("-2"), None);
        assert_eq!(owner_id(None, "--owner-uid"), None);
    }

    /// A `--timestamp` value reads as `@SECONDS` or as a date and time with a
    /// UTC offset. The `ostree` command also accepts the wall-clock forms with
    /// no offset and the relative forms. ostrya refuses them. This is a
    /// recorded divergence.
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
        // A pre-epoch instant records the two's-complement form of the
        // unsigned field. The `ostree` command records the same for this value.
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
            // No offset: the value names a wall clock in a zone that this
            // reader does not resolve.
            "2009-02-13T23:31:30",
            "2009-02-13 23:31:30",
            // Out of range for the field that it names.
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

    /// The two prefix filters differ only on the exact match. A listing keeps
    /// the ref that a prefix names, and the `-A` filter leaves it to the
    /// resolution step. As a result, the filter drops an alias whose name a
    /// prefix gives exactly.
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

    /// A whole-remote prefix is a `<remote>:` prefix with an empty ref half or
    /// the ref half `.`. It selects each ref of that remote and no other ref,
    /// in a listing and in the `-A` filter. The row keeps the full refspec,
    /// because there is no ref name to strip.
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

    /// The refspec rule refuses a PREFIX, and the report gives the prefix as
    /// written. The two whole-remote forms pass, because a `<remote>:` prefix
    /// with an empty ref half or the ref half `.` names each ref of that
    /// remote.
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
            "origin::rr",
            "tes~t",
            "te st",
            ".test",
        ] {
            match check_prefix_name(prefix) {
                Err(Error::InvalidRefspec(name)) if name == prefix => {}
                other => panic!("`{prefix}` was not refused as given: {other:?}"),
            }
        }
        for prefix in ["test", "test/main", "origin:rr", "origin:", "origin:."] {
            check_prefix_name(prefix).expect("the prefix was refused");
        }
    }

    /// The path under `refs/` that a PREFIX names. It is the ref name under
    /// `heads`, the ref name under `remotes/<remote>`, or the directory of the
    /// remote for a whole-remote prefix.
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

    /// The `-A` target column. While the link stays in the ref root of the
    /// alias, the column shows the link body with its leading `../` components
    /// removed. When the link leaves that root, the column shows the refspec of
    /// the target ref, which is the form that the resolver of ostrya reads.
    #[test]
    fn a_cross_root_alias_target_prints_the_refspec() {
        for (refspec, body, printed) in [
            // In one root, both commands print the stripped body.
            ("al", "test/main", "test/main"),
            ("nested/q", "../plain", "plain"),
            ("origin:rr/remal", "x", "x"),
            ("origin:rr/deep/remal", "../x", "x"),
            // Across roots, the stripped path under `refs/` names no ref.
            ("xal", "../remotes/origin/rr/x", "origin:rr/x"),
            ("origin:rr/toheads", "../../../heads/plain", "plain"),
            ("origin:rr/oal", "../../other/z/y", "other:z/y"),
            // A body that names no ref file keeps the stripped form: one that
            // reaches out of `refs/`, and one that ends on a root itself.
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

    /// The editing session runs off the executor. The first poll of
    /// [`wait_for_editor`] on a command that still runs gives
    /// [`Poll::Pending`] at once. As a result, the thread that drives the
    /// commit future is free while the editor holds the terminal. A wait on
    /// the executor thread returns [`Poll::Ready`] only after the command
    /// exits.
    #[test]
    fn the_editor_wait_leaves_the_executor() {
        use std::future::Future as _;
        use std::task::Poll;
        use std::time::{Duration, Instant};

        // The command runs longer than the poll, and the blocking pool reaps
        // it. A wait on this thread cannot return in the asserted window,
        // because the command runs for two seconds.
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

    /// A `--skip-list` path and a `--statoverride` path are matched against
    /// the bytes of the walk path. A control file holds only UTF-8
    /// ([`read_control_file`]). An entry that spells `U+FFFD` names that
    /// character, and it reaches no entry whose name holds a byte that is not
    /// UTF-8.
    ///
    /// Both ingest sources refuse such a name before the callbacks. The file
    /// system walk refuses it while it reads the directory, and the tar reader
    /// while it reads the header. For this reason, the test calls the two
    /// callbacks directly.
    #[test]
    fn a_control_file_path_matches_the_walk_path_by_bytes() {
        use ostrya::FileMeta;
        use std::ffi::OsStr;

        let cli = Cli::parse_from(["ostrya", "commit", "-b", "x", "/src"]);
        let Some(Command::Commit(args)) = cli.command else {
            panic!("`commit` parsed as another subcommand");
        };
        // One skip-list path and one statoverride path of each form. All four
        // spell the replacement character.
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

        // A walk path that holds the raw byte `0xFF` is a different path.
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

        // The path that the entries spell is matched, so the comparison is
        // exact and does not only refuse.
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

    /// For 1000 bytes or more, the totals line shows a byte count as a decimal
    /// (SI) quantity, with a no-break space before the unit. The byte count
    /// selects the unit, and the rounded value does not. Each pair here was
    /// compared with `ostree prune` under `LC_ALL=C.UTF-8`.
    #[test]
    fn a_freed_byte_count_renders_the_way_the_totals_line_does() {
        for (bytes, rendered) in [
            (0u64, "0 bytes"),
            (1, "1 byte"),
            (2, "2 bytes"),
            (673, "673 bytes"),
            (999, "999 bytes"),
            (1000, "1.0\u{a0}kB"),
            (1073, "1.1\u{a0}kB"),
            (1172, "1.2\u{a0}kB"),
            (10172, "10.2\u{a0}kB"),
            (100172, "100.2\u{a0}kB"),
            (999999, "1000.0\u{a0}kB"),
            (1000000, "1.0\u{a0}MB"),
            (1048749, "1.0\u{a0}MB"),
            (1500173, "1.5\u{a0}MB"),
            (1000000173, "1.0\u{a0}GB"),
            (1100000172, "1.1\u{a0}GB"),
        ] {
            assert_eq!(format_size(bytes), rendered, "{bytes} rendered wrongly");
        }
        assert!(format_size(u64::MAX).ends_with("\u{a0}EB"));
    }

    /// A `--retain-branch-depth` value splits at its first `=`, and its depth
    /// is a decimal integer with an optional leading `-`. The `ostree` command
    /// reads a leading run of digits and drops the rest of the string. ostrya
    /// refuses a value that its reader does not accept. This is a recorded
    /// divergence.
    #[test]
    fn a_retain_branch_depth_value_reads_strictly() {
        assert_eq!(
            parse_retain_branch_depth("main=1"),
            Ok(("main".to_owned(), 1))
        );
        assert_eq!(
            parse_retain_branch_depth("main=-1"),
            Ok(("main".to_owned(), -1))
        );
        assert_eq!(
            parse_retain_branch_depth("main=0"),
            Ok(("main".to_owned(), 0))
        );
        assert_eq!(parse_retain_branch_depth("=0"), Ok((String::new(), 0)));
        assert_eq!(
            parse_retain_branch_depth("a/b/c=2"),
            Ok(("a/b/c".to_owned(), 2))
        );
        for value in ["main", ""] {
            assert_eq!(
                parse_retain_branch_depth(value),
                Err(format!("Invalid value {value}, must specify BRANCH=DEPTH"))
            );
        }
        for (value, depth) in [
            ("main=", ""),
            ("main=abc", "abc"),
            ("main==0", "=0"),
            ("main=0=1", "0=1"),
            ("main=0x1", "0x1"),
            ("main=+1", "+1"),
            ("main= 1", " 1"),
            ("main=1 ", "1 "),
            ("main=99999999999999999999", "99999999999999999999"),
        ] {
            assert_eq!(
                parse_retain_branch_depth(value),
                Err(format!("Invalid depth {depth}"))
            );
        }
    }

    /// The transferred figure is `N B` for less than 1024 bytes, and the full
    /// KiB, rounded down, from 1024 bytes. The `ostree` command prints 3842
    /// bytes as `3 KiB`.
    #[test]
    fn the_transferred_figure_rounds_down_to_whole_kib() {
        for (bytes, text) in [
            (0, "0 B"),
            (1023, "1023 B"),
            (1024, "1 KiB"),
            (1535, "1 KiB"),
            (3842, "3 KiB"),
            (3_409_920, "3330 KiB"),
        ] {
            assert_eq!(format_transferred(bytes), text, "{bytes}");
        }
    }

    /// The three statistics lines: a local pull, an HTTP pull with no delta
    /// part, and an HTTP pull with a delta part. Its loose count adds the
    /// metadata and the content fetched. The written figure uses the size
    /// words of the `ostree` command.
    #[test]
    fn the_statistics_line_takes_the_tool_forms() {
        let stats = PullStats {
            metadata_imported: 4,
            content_imported: 4,
            content_bytes_written: 999,
            content_bytes_unpacked: 3_400_000,
            metadata_fetched: 6,
            content_fetched: 4,
            delta_parts: 0,
            bytes_transferred: 1500,
            elapsed: std::time::Duration::from_millis(10_900),
        };
        assert_eq!(
            statistics_line(&stats, PullSource::Local),
            "4 metadata, 4 content objects imported; 3.4\u{a0}MB content written"
        );
        assert_eq!(
            statistics_line(&stats, PullSource::Http),
            "6 metadata, 4 content objects fetched; 1 KiB transferred in 10 seconds; \
             3.4\u{a0}MB content written"
        );
        let delta = PullStats {
            delta_parts: 1,
            metadata_fetched: 2,
            content_fetched: 0,
            content_bytes_unpacked: 0,
            bytes_transferred: 3_409_920,
            ..stats
        };
        assert_eq!(
            statistics_line(&delta, PullSource::Http),
            "1 delta parts, 2 loose fetched; 3330 KiB transferred in 10 seconds; \
             0 bytes content written"
        );
        let one = PullStats {
            content_bytes_unpacked: 1,
            ..PullStats::default()
        };
        assert_eq!(
            statistics_line(&one, PullSource::Local),
            "0 metadata, 0 content objects imported; 1 byte content written"
        );
        // If no byte is transferred, the transfer clause goes.
        assert_eq!(
            statistics_line(&PullStats::default(), PullSource::Http),
            "0 metadata, 0 content objects fetched; 0 bytes content written"
        );
    }

    /// The progress text appended to an empty line.
    fn progress(s: &PullProgressSnapshot, elapsed: std::time::Duration) -> String {
        let mut line = String::new();
        progress_text(&mut line, s, elapsed);
        line
    }

    /// The three progress forms, selected by the delta parts that are still to
    /// arrive, then by the scan, then by the objects. The rate shows `-` until
    /// one full second passes. The `ostree` command writes the same before its
    /// first sample.
    #[test]
    fn the_progress_text_takes_three_forms() {
        let second = std::time::Duration::from_secs(1);
        let delta = PullProgressSnapshot {
            delta_parts_total: 1,
            delta_bytes_total: 3_400_000,
            bytes_transferred: 356_200,
            ..PullProgressSnapshot::default()
        };
        assert_eq!(
            progress(&delta, second),
            "Receiving delta parts: 0/1 0 bytes/3.4\u{a0}MB 356.2\u{a0}kB/s 9 seconds remaining"
        );
        assert_eq!(
            progress(&delta, std::time::Duration::from_millis(900)),
            "Receiving delta parts: 0/1 0 bytes/3.4\u{a0}MB -/s"
        );
        let idle = PullProgressSnapshot {
            delta_parts_total: 1,
            ..PullProgressSnapshot::default()
        };
        assert_eq!(
            progress(&idle, second),
            "Receiving delta parts: 0/1 0 bytes/0 bytes 0 bytes/s"
        );
        let scan = PullProgressSnapshot {
            metadata_fetched: 5,
            bytes_transferred: 948,
            scanning: true,
            ..PullProgressSnapshot::default()
        };
        assert_eq!(
            progress(&scan, std::time::Duration::from_secs(4)),
            "Receiving metadata objects: 5/(estimating) 237 bytes/s 948 bytes"
        );
        assert_eq!(
            progress(&scan, std::time::Duration::ZERO),
            "Receiving metadata objects: 5/(estimating) -/s 948 bytes"
        );
        let objects = PullProgressSnapshot {
            objects_done: 59,
            objects_total: 155,
            bytes_transferred: 1_400_000,
            ..PullProgressSnapshot::default()
        };
        assert_eq!(
            progress(&objects, std::time::Duration::from_secs(2)),
            "Receiving objects: 38% (59/155) 700.0\u{a0}kB/s 1.4\u{a0}MB"
        );
    }

    /// A line on a terminal is padded to 80 bytes. The `ostree` command pads
    /// it to the terminal width counted in bytes, so U+00A0 counts as two. The
    /// padding starts at the given byte, and a longer text is written in full.
    #[test]
    fn a_terminal_line_is_padded_to_80_bytes() {
        let mut line = String::from("\x1b8Receiving objects: 1.4\u{a0}MB");
        pad_line(&mut line, 2);
        assert_eq!(line.len(), 2 + PROGRESS_COLUMNS);
        assert_eq!(line.chars().count(), 2 + PROGRESS_COLUMNS - 1);
        assert!(line.starts_with("\x1b8Receiving objects: 1.4\u{a0}MB "));
        let long = "x".repeat(100);
        let mut padded = long.clone();
        pad_line(&mut padded, 0);
        assert_eq!(padded, long);
    }

    /// An `--update-frequency` of 0, a negative value, and no value each keep
    /// the 1000 ms default.
    #[test]
    fn the_update_frequency_defaults_to_a_second() {
        let second = std::time::Duration::from_millis(1000);
        assert_eq!(update_interval(None), second);
        assert_eq!(update_interval(Some(0)), second);
        assert_eq!(
            update_interval(Some(250)),
            std::time::Duration::from_millis(250)
        );
    }

    /// Each ref line of `push`. The lines are a new ref, a moved ref, a ref
    /// already at the commit, a deleted ref, and a delete of an absent ref.
    #[cfg(feature = "push")]
    #[test]
    fn a_push_ref_line_names_the_old_and_the_new_state() {
        let c1 = Checksum::from_bytes([0x11; 32]);
        let c2 = Checksum::from_bytes([0x22; 32]);
        let line = |old, new| {
            ref_line(&ostrya::remote::RefOutcome {
                name: "main".into(),
                old,
                new,
            })
        };
        assert_eq!(line(None, Some(c1)), format!("main (new) {c1}"));
        assert_eq!(line(Some(c1), Some(c2)), format!("main {c1} {c2}"));
        assert_eq!(line(Some(c2), Some(c2)), format!("main {c2} (unchanged)"));
        assert_eq!(line(Some(c2), None), format!("main {c2} (deleted)"));
        assert_eq!(line(None, None), "main (absent) (unchanged)");
        // A literal line, so that an abbreviated checksum fails the test.
        assert_eq!(
            line(Some(c1), Some(c2)),
            "main 1111111111111111111111111111111111111111111111111111111111111111 \
             2222222222222222222222222222222222222222222222222222222222222222"
        );
    }

    /// The statistics line of `push --verbose` gives each counter and the
    /// elapsed time in seconds.
    #[cfg(feature = "push")]
    #[test]
    fn the_push_statistics_line_gives_each_counter() {
        let stats = ostrya::remote::PushStats {
            objects_total: 12,
            objects_needed: 5,
            objects_sent: 4,
            bytes_sent: 2048,
            payload_bytes: 1900,
            elapsed: std::time::Duration::from_millis(1250),
        };
        assert_eq!(
            push_statistics_line(&stats),
            "12 objects offered, 5 needed, 4 sent; 2048 bytes sent in 1.250 seconds"
        );
    }

    /// The metadata entries of `push-tree` keep the two groups of `commit`:
    /// each `--add-metadata-string` before each `--add-metadata`, for each
    /// command-line order. An empty key is refused in each group.
    #[cfg(feature = "push")]
    #[test]
    fn the_tree_push_metadata_puts_the_strings_before_the_variants() {
        let cli = Cli::try_parse_from([
            "ostrya",
            "push-tree",
            "--add-metadata=n=uint32 1",
            "--add-metadata-string=a=x",
            "--add-metadata=m='y'",
            "--add-metadata-string=b=z",
            "host:repo",
            "dir",
            "--onto",
            "main",
        ])
        .unwrap();
        let Some(Command::PushTree(args)) = cli.command else {
            panic!("not push-tree")
        };
        let strings = metadata_pairs(&args.add_metadata_string).unwrap();
        let variants = parse_added_metadata(&args.add_metadata).unwrap();
        let entries = user_metadata_entries(&strings, &variants).unwrap();
        let keys: Vec<&str> = entries.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(keys, ["a", "b", "n", "m"]);
        assert_eq!(
            entries[0].1,
            Value::variant(Type::Str, Value::Str("x".into()))
        );
        assert_eq!(entries[2].1, Value::variant(Type::U32, Value::U32(1)));

        let variant = Value::variant(Type::Str, Value::Str("v".into()));
        for (strings, variants) in [
            (vec![("", "v")], vec![]),
            (vec![("k", "v")], vec![("", variant.clone())]),
        ] {
            assert_eq!(
                user_metadata_entries(&strings, &variants).unwrap_err(),
                "Empty metadata key"
            );
        }
        assert!(user_metadata_entries(&[], &[]).unwrap().is_empty());
    }

    /// `--tag` of `commit` conflicts with `--no-bindings` and with
    /// `--skip-if-unchanged`.
    #[test]
    fn the_tag_of_commit_conflicts_with_no_bindings_and_skip_if_unchanged() {
        let parse = |extra: &[&str]| {
            let mut all = vec!["ostrya", "commit", "-b", "main", "--tag=t"];
            all.extend_from_slice(extra);
            Cli::try_parse_from(all).map(|_| ())
        };
        use clap::error::ErrorKind;
        for extra in ["--no-bindings", "--skip-if-unchanged"] {
            assert_eq!(
                parse(&[extra]).unwrap_err().kind(),
                ErrorKind::ArgumentConflict,
                "{extra}"
            );
        }
        parse(&["--tag=u", "--bind-ref=t", "--orphan"]).unwrap();
    }

    /// `--related` of `commit` conflicts with `--skip-if-unchanged`.
    #[test]
    fn the_related_of_commit_conflicts_with_skip_if_unchanged() {
        let parse = |extra: &[&str]| {
            let mut all = vec!["ostrya", "commit", "-b", "main"];
            all.extend_from_slice(extra);
            Cli::try_parse_from(all).map(|_| ())
        };
        let related = format!("--related=a/x={}", "ab".repeat(32));
        assert_eq!(
            parse(&[&related, "--skip-if-unchanged"])
                .unwrap_err()
                .kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
        parse(&[&related, &related]).unwrap();
    }

    /// `tag_name_refusal` refuses a name with `:`, a name that the ref-name
    /// rule refuses, a checksum-shaped name, the branch name, a repeated
    /// name, and a name that is a path below another name.
    #[test]
    fn tag_names_follow_the_ref_rules() {
        let tags = |names: &[&str]| names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>();
        let hex = "0123456789abcdef".repeat(4);
        for (branch, names, message) in [
            (
                Some("main"),
                tags(&["a:b"]),
                "--tag a:b holds ':', and a tag is a local ref".to_owned(),
            ),
            (
                Some("main"),
                tags(&["bad name"]),
                "Invalid refspec bad name".to_owned(),
            ),
            (
                Some("main"),
                tags(&[&hex]),
                format!("Rev name '{hex}' looks like a checksum"),
            ),
            (
                Some("main"),
                tags(&["main"]),
                "--tag main is also the --branch name".to_owned(),
            ),
            (
                None,
                tags(&["x", "y", "x"]),
                "--tag x is given more than once".to_owned(),
            ),
            (
                Some("a"),
                tags(&["a/b"]),
                "--tag a/b names a path below --branch a".to_owned(),
            ),
            (
                None,
                tags(&["x", "x/y"]),
                "--tag x/y names a path below --tag x".to_owned(),
            ),
            (
                None,
                tags(&["x/y/z", "x"]),
                "--tag x/y/z names a path below --tag x".to_owned(),
            ),
            (
                Some("p/q"),
                tags(&["p"]),
                "--branch p/q names a path below --tag p".to_owned(),
            ),
            // The checks of each name come before the check of the paths.
            (
                Some("a"),
                tags(&["a/b", "a/b"]),
                "--tag a/b is given more than once".to_owned(),
            ),
        ] {
            assert_eq!(tag_name_refusal(branch, &names), Some(message));
        }
        assert_eq!(tag_name_refusal(Some("main"), &tags(&["a", "b/c"])), None);
        // A name that only starts with the other name is not below it.
        assert_eq!(tag_name_refusal(Some("ab"), &tags(&["a", "a-b/c"])), None);
        // A remote branch is a ref under `refs/remotes`, and the ref write
        // refuses a bad branch with its own message.
        assert_eq!(tag_name_refusal(Some("origin:a"), &tags(&["a/b"])), None);
        assert_eq!(
            tag_name_refusal(Some(&hex), &tags(&[&format!("{hex}/x")])),
            None
        );
        assert_eq!(tag_name_refusal(None, &[]), None);
    }

    /// `--onto` conflicts with `--depth` and `--force`, and `--bind-ref`,
    /// `--orphan`, and `--timestamp` of `push` need `--onto`. `push-tree`
    /// takes none of the options of a commit that the client builds.
    #[cfg(feature = "push")]
    #[test]
    fn the_server_commit_options_of_push_need_onto() {
        let parse = |args: &[&str]| {
            let mut all = vec!["ostrya", "push"];
            all.extend_from_slice(args);
            Cli::try_parse_from(all).map(|_| ())
        };
        let kind = |args: &[&str]| parse(args).unwrap_err().kind();
        use clap::error::ErrorKind;
        for extra in [&["--depth=1"][..], &["--force"]] {
            let mut args = vec!["--onto=main", "origin", "main"];
            args.extend_from_slice(extra);
            assert_eq!(kind(&args), ErrorKind::ArgumentConflict, "{extra:?}");
        }
        for extra in ["--bind-ref=x", "--orphan", "--timestamp=@1"] {
            assert_eq!(
                kind(&[extra, "origin", "main"]),
                ErrorKind::MissingRequiredArgument,
                "{extra}"
            );
        }
        parse(&[
            "--onto=main",
            "--tag=t",
            "--bind-ref=x",
            "--bind-ref=y",
            "--orphan",
            "--timestamp=@1",
            "--collection=org.example.C",
            "origin",
            "main",
        ])
        .unwrap();

        for removed in [
            "-b",
            "--branch=main",
            "--parent=none",
            "--sign=k",
            "--sign-from-file=f",
            "--sign-type=ed25519",
            "--gpg-sign=k",
            "--gpg-homedir=d",
            "--add-detached-metadata-string=k=v",
            "--force",
            "--no-bindings",
        ] {
            let args = [
                "ostrya",
                "push-tree",
                "--onto=main",
                removed,
                "host:repo",
                "dir",
            ];
            assert!(Cli::try_parse_from(args).is_err(), "{removed}");
        }
    }

    /// `-c` and `--client-groups` of `summary` need `-u`.
    #[test]
    fn the_client_groups_of_summary_need_update() {
        use clap::error::ErrorKind;
        for args in [
            &["ostrya", "summary", "-c"][..],
            &["ostrya", "summary", "--client-groups", "-v"],
        ] {
            let err = Cli::try_parse_from(args).map(|_| ()).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument, "{args:?}");
        }
        for args in [
            &["ostrya", "summary", "-u", "-c"][..],
            &["ostrya", "summary", "--update", "--client-groups"],
        ] {
            Cli::try_parse_from(args).map(|_| ()).unwrap();
        }
    }

    /// Each template of the push progress bar parses. The bar shows no stage
    /// before `Negotiating`, then the stage of each phase, and clears at
    /// `Committing`. A snapshot of an earlier phase after that changes
    /// nothing. A hidden bar gives no progress handle.
    #[cfg(feature = "push")]
    #[test]
    fn the_push_bar_templates_parse_and_the_bar_clears_at_committing() {
        use ostrya::remote::PushPhase;
        for template in [NEGOTIATING_TEMPLATE, BAR_TEMPLATE, BYTES_TEMPLATE] {
            assert!(
                indicatif::ProgressStyle::with_template(template).is_ok(),
                "{template}"
            );
        }
        let (progress, started) = PushBar::start();
        assert_eq!(progress.is_none(), started.bar.is_hidden());

        let hidden = || PushBar {
            bar: indicatif::ProgressBar::hidden(),
            stage: std::sync::atomic::AtomicU8::new(STAGE_HIDDEN),
            objects: Arc::default(),
        };
        let bar = hidden();
        let mut snapshot = ostrya::remote::PushProgressSnapshot::default();
        snapshot.bytes_total = 10;
        snapshot.objects_needed = 2;
        snapshot.objects_sent = 1;
        for (phase, stage) in [
            (PushPhase::Connecting, STAGE_HIDDEN),
            (PushPhase::Negotiating, STAGE_NEGOTIATING),
            (PushPhase::Uploading, STAGE_UPLOADING),
            (PushPhase::Committing, STAGE_DONE),
            (PushPhase::Uploading, STAGE_DONE),
            (PushPhase::Negotiating, STAGE_DONE),
        ] {
            snapshot.phase = phase;
            bar.update(&snapshot);
            assert_eq!(bar.stage.load(Ordering::Relaxed), stage, "{phase:?}");
        }
        assert_eq!(bar.objects.sent.load(Ordering::Relaxed), 1);
        assert_eq!(bar.objects.needed.load(Ordering::Relaxed), 2);
        assert!(bar.bar.is_finished());
        bar.finish();
        assert_eq!(bar.stage.load(Ordering::Relaxed), STAGE_DONE);

        // A push that fails in the upload clears the bar at its end.
        let bar = hidden();
        snapshot.phase = PushPhase::Uploading;
        bar.update(&snapshot);
        assert!(!bar.bar.is_finished());
        bar.finish();
        assert!(bar.bar.is_finished());
        assert_eq!(bar.stage.load(Ordering::Relaxed), STAGE_DONE);
    }

    /// Under `--canonical-permissions`, the filter of `push-tree` reduces the
    /// mode of a file and of a directory to `perm & 0755`. It keeps the mode
    /// of a symlink, sets the owner to 0:0, and then applies each declared id.
    /// The filter also applies to the root. With no option set, there is no
    /// filter.
    #[cfg(feature = "push")]
    #[test]
    fn the_tree_push_filter_applies_the_canonical_rule_then_the_owner() {
        use ostrya::remote::tree::{EntryAction, EntryFilter, EntryMeta, ScanOptions, TreeModel};

        assert!(tree_push_filter(Owner::default(), false).is_none());
        let root = std::env::temp_dir().join(format!(
            "ostrya-cli-tree-push-filter-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("dir")).unwrap();
        std::fs::write(root.join("file"), b"file").unwrap();
        std::os::unix::fs::symlink("file", root.join("link")).unwrap();
        let mode = |path: &Path, mode: u32| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap()
        };
        mode(&root.join("file"), 0o664);
        mode(&root.join("dir"), 0o2775);
        mode(&root, 0o775);

        let scan = |owner: Owner, canonical: bool| -> Vec<(String, EntryMeta)> {
            let seen = Arc::new(Mutex::new(Vec::new()));
            let record = seen.clone();
            let mut inner = tree_push_filter(owner, canonical).unwrap();
            let filter: EntryFilter = Box::new(move |path, meta| {
                let action = inner(path, meta);
                assert_eq!(action, EntryAction::Keep);
                record
                    .lock()
                    .unwrap()
                    .push((path.to_string(), meta.clone()));
                action
            });
            let options = ScanOptions {
                entry_filter: Some(filter),
                hash_jobs: None,
            };
            ostrya_rt::block_on(TreeModel::scan(&root, options)).unwrap();
            let mut seen = seen.lock().unwrap().clone();
            seen.sort_by(|a, b| a.0.cmp(&b.0));
            seen
        };

        let seen = scan(Owner::default(), true);
        let modes: Vec<(&str, u32)> = seen.iter().map(|(p, m)| (p.as_str(), m.mode)).collect();
        assert_eq!(
            modes,
            [
                ("", 0o40755),
                ("dir", 0o40755),
                ("file", 0o100644),
                ("link", 0o120777)
            ]
        );
        assert!(seen.iter().all(|(_, m)| m.uid == 0 && m.gid == 0));
        assert!(seen.iter().all(|(_, m)| m.xattrs.is_empty()));

        let seen = scan(
            Owner {
                uid: Some(7),
                gid: Some(9),
            },
            true,
        );
        assert!(
            seen.iter().all(|(_, m)| m.uid == 7 && m.gid == 9),
            "{seen:?}"
        );
        assert_eq!(seen[2].1.mode, 0o100644);

        // The owner options alone leave the mode and an undeclared id as the
        // walk read them.
        let gid = std::os::unix::fs::MetadataExt::gid(&std::fs::metadata(&root).unwrap());
        let seen = scan(
            Owner {
                uid: Some(0),
                gid: None,
            },
            false,
        );
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(seen[2].1.mode, 0o100664);
        assert_eq!(seen[1].1.mode, 0o42775);
        assert!(seen.iter().all(|(_, m)| m.uid == 0), "{seen:?}");
        assert_eq!(seen[0].1.gid, gid);
    }
}
