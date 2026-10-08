#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! An async, pure-Rust library that reads and writes ostree repositories.
//!
//! A user opens a repository, writes commits in transactions, reads and checks
//! out trees, and pulls, pushes, signs, and prunes. The bytes on disk are the
//! bytes that the `ostree` command writes. Many [`Transaction`]s can write to
//! one repository at once in one process.
//!
//! As an extension, the crate also has a push protocol over HTTP and over ssh.
//! With the `push` feature, `Repo::push` sends commits to a remote. With the
//! `receive` feature, the `receive` module takes a push on the server side.
//!
//! # Entry points
//! - [`Repo::open`] and [`Repo::create`] give a [`Repo`], the handle of a repository.
//! - [`Repo::transaction`] begins a [`Transaction`], which publishes objects and refs at commit.
//! - [`StagingTree`] and [`MutableTree`] build the tree of a new commit.
//! - [`Repo::checkout_at`] writes the tree of a commit into a directory.
//! - [`Repo::pull`] copies commits from a remote, and [`Repo::pull_local`] from a local repository.
//! - [`Error`] is the error of each fallible operation of the crate.
//!
//! # Modules
//! - Read: [`read`], [`file`](mod@file), [`tree`], [`refs`], and [`traverse`].
//! - Write: [`transaction`], [`mtree`], [`staging_tree`], [`commit`], [`modifier`], [`bootable`].
//! - Checkout and export: [`checkout`], [`composefs`], [`tar`], and [`archive`].
//! - Pull: [`pull`], [`summary`], and [`fetch`], the HTTP client of `ostrya-fetch`.
//! - Push and receive: [`push`], the wire protocol of `ostrya-push`, and `receive`.
//! - Signing: [`sign`], `gpg`, and `spki`.
//! - Maintenance: [`prune`], [`fsck`], [`diff`], [`update`], and [`config`].
//! - Static deltas: [`DeltaSuperblock`], [`DeltaOptions`], and [`Repo::generate_static_delta`].
//!
//! # Features
//! - `smol` (default): the `smol` backend of `ostrya-rt`.
//! - `tokio`: the `tokio` backend of `ostrya-rt`.
//! - `sign-spki`: the `spki` module, the spki signing engine.
//! - `verify-gpg`: the `gpg` module, GPG verification and keyring management.
//! - `sign-gpg`: `GpgSigner`, which signs with the `gpg` command. It turns on `verify-gpg`.
//! - `receive`: the `receive` module, the receive side of a push.
//! - `push`: `Repo::push` and `Repo::export_stream`, the push from a repository.
//! - `lzma-static`: xz built from source and linked statically, with no runtime liblzma.
//!
//! # Examples
//! ```no_run
//! # async fn run() -> ostrya::Result<()> {
//! let repo = ostrya::Repo::open("/srv/repo".as_ref()).await?;
//! let tip = repo.resolve_rev("exampleos/stable", false).await?;
//! # Ok(()) }
//! ```

pub mod repo;
pub mod transaction;

pub mod archive;
pub mod bootable;
mod bspatch;
pub mod checkout;
pub mod commit;
pub mod composefs;
pub mod config;
mod delta;
mod deltagen;
pub mod diff;
pub mod error;
pub use ostrya_fetch as fetch;
pub use ostrya_push as push;
pub mod file;
pub mod fsck;
#[cfg(feature = "verify-gpg")]
pub mod gpg;
mod hashing;
mod inflate;
mod ingest;
mod lock;
pub mod modifier;
pub mod mtree;
mod object;
mod overlay;
mod perm;
pub mod prune;
pub mod pull;
#[cfg(feature = "push")]
mod push_repo;
pub mod read;
#[cfg(feature = "receive")]
pub mod receive;
pub mod refs;
mod rollsum;
mod send;
pub mod sign;
#[cfg(feature = "sign-spki")]
pub mod spki {
    //! The spki signing engine: ECDSA signatures on P-256 with SPKI public keys.
    pub use ostrya_sign::{SpkiSigner, SpkiVerifier};
}
mod staging;
pub mod staging_tree;
pub mod summary;
pub mod tar;
mod tombstone;
pub mod traverse;
pub mod tree;
pub mod update;
mod verify;
mod write;

#[doc(hidden)]
pub use archive::{ArchiveAnswer, ArchiveHead, ArchiveView};
#[doc(hidden)]
pub use bootable::{BootableMetadata, BootableRefusal};
#[doc(hidden)]
pub use checkout::{CheckoutFilterFn, CheckoutMode, CheckoutOptions, OverwriteMode};
#[doc(hidden)]
pub use commit::CommitOptions;
#[doc(hidden)]
pub use composefs::{ComposefsOptions, VerityPolicy};
#[doc(hidden)]
pub use config::{
    MinFreeSpace, Remote, RepoConfig, SignVerify, SizeSpec, SizeUnit, Tristate, valid_remote_name,
};
pub use delta::{
    DeltaEndianness, DeltaFallback, DeltaOpCounts, DeltaPart, DeltaPartStats, DeltaSuperblock,
};
pub use deltagen::{DeltaOptions, static_delta_relative_dir};
#[doc(hidden)]
pub use diff::{DiffChange, DiffEntry, DiffOptions, DiffSide, DiffStats};
#[doc(hidden)]
pub use error::{Error, Result};
#[doc(hidden)]
pub use fetch::{
    BasicAuth, BearerToken, Body, ClientIdentity, FetchRequest, Fetched, Fetcher, FetcherOptions,
    LowSpeed, Priority, Protocol, Proxy, Target, TlsOptions, TrustRoots, UploadBody, UploadMethod,
    UploadRequest, UploadWriter, Uploaded, Validators,
};
#[doc(hidden)]
pub use file::{ContentReader, FileKind, FileObject};
#[doc(hidden)]
pub use fsck::{
    FsckBindingError, FsckBindingErrorKind, FsckError, FsckErrorKind, FsckFailure, FsckOptions,
    FsckPhase, FsckReport,
};
#[cfg(feature = "sign-gpg")]
#[doc(hidden)]
pub use gpg::GpgSigner;
#[cfg(feature = "verify-gpg")]
#[doc(hidden)]
pub use gpg::{GpgKey, GpgVerifier};
pub use hashing::{HashingReader, HashingWriter, VerifyingReader};
pub use lock::LockKind;
#[doc(hidden)]
pub use modifier::{
    CommitModifier, CommitModifierFlags, DevInoCache, FilterFn, FilterResult, LabelFn, ModeFn,
    XattrFn,
};
#[doc(hidden)]
pub use mtree::MutableTree;
pub use object::MAX_METADATA_SIZE;
pub use ostrya_composefs::Image;
pub use ostrya_core::base64;
pub use ostrya_core::{
    Checksum, Commit, DictBuilder, DirMeta, DirTree, ObjectName, ObjectType, RepoMode, Span,
    TextError, Type, Value, Xattrs, from_bytes, from_text, is_checksum_shaped, loose_path, to_text,
    to_text_unannotated,
};
#[doc(hidden)]
pub use prune::{PruneOptions, PruneStats, WeakRefFilter, WeakRefFilterFn};
#[doc(hidden)]
pub use pull::{
    DetachedMetadataFilter, DetachedMetadataFilterFn, PullFlags, PullOptions, PullProgress,
    PullProgressSnapshot, PullStats, PullVerify, TimestampCheck,
};
#[cfg(feature = "push")]
pub use push_repo::{ExportStreamOptions, RepoPushOptions, is_push_address, resolve_push_remote};
#[doc(hidden)]
pub use read::{CommitSizes, CommitState, MetadataReader};
#[cfg(feature = "receive")]
#[doc(hidden)]
pub use receive::{
    HookFuture, HookRefusal, HostEntry, ReceiveHooks, ReceivePolicy, ReceiveReport, ReceiveRule,
    ReceiveService, ReceiveStep, ReceiveVerify, ReceiveWarning, RefPattern, ServerSigner,
    TrustedKeys, UpdatePlan,
};
#[doc(hidden)]
pub use refs::{CollectionRef, CollectionRefEntry, RefAlias, validate_refspec};
#[doc(hidden)]
pub use repo::{CreateOptions, Repo};
#[doc(hidden)]
pub use sign::{
    DummySigner, DummyVerifier, Ed25519Signer, Ed25519Verifier, FromSystemKeys, SignFuture,
    SignKeys, SignatureInfo, Signer, Verifier, VerifyFuture, VerifyOutcome, load_sign_keys,
    load_sign_keys_from,
};
#[cfg(feature = "sign-spki")]
#[doc(hidden)]
pub use spki::{SpkiSigner, SpkiVerifier};
#[doc(hidden)]
pub use staging_tree::{
    MergeOptions, RootDirmeta, StagedFileWriter, StagingEntry, StagingLookup, StagingTree,
};
#[doc(hidden)]
pub use summary::{Summary, SummaryOptions, SummaryRef};
#[doc(hidden)]
pub use tar::{TarExportOptions, TarImportOptions, TarRename};
#[doc(hidden)]
pub use transaction::{ContentWriter, FileMeta, Transaction, TransactionStats};
#[doc(hidden)]
pub use tree::{RepoTree, TreeEntry};
#[doc(hidden)]
pub use update::UpdateGuard;

/// Removes the staging directories of the live transactions of this process.
///
/// A [`Transaction`] removes its staging directory when it commits, aborts, or
/// drops. [`std::process::exit`] runs no destructor. If a process ends that way
/// with a live transaction, its `tmp/staging-<boot-id>-XXXXXX` directory and
/// the sibling lock file stay. The reaper of a later transaction removes them.
///
/// A caller that ends the process with no unwind calls this function
/// immediately before the end. `tmp/` is then in the state that a return with
/// an unwind leaves.
///
/// The call removes the staging directory and the sibling lock file of each
/// live transaction in the process. A transaction that runs after the call
/// finds its staged objects gone, so the call is correct only when the
/// process is about to end. [`Transaction`] describes the staging directory
/// and the reaper.
pub fn reap_process_staging() {
    staging::reap_owned();
}
