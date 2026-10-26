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
//! With the `push` feature, `Repo::push` sends commits to a remote, and
//! `Repo::push_onto` asks a remote to commit the tree of a local commit. With
//! the `receive` feature, the `receive` module takes a push on the server side.
//! With the `push` and `s3` features, `Repo::push_to_bucket` writes commits to
//! a bucket repository in an S3 bucket, `BucketRepo::push_tree` writes a local
//! directory to one as a new commit, and `BucketRepo::init` creates one.
//!
//! # Entry points
//! - [`Repo::open`] and [`Repo::create`] give a [`Repo`], the handle of a repository.
//! - [`Repo::transaction`] begins a [`Transaction`], which publishes objects and refs at commit.
//! - [`StagingTree`] and [`MutableTree`] build the tree of a new commit.
//! - [`Repo::checkout_at`] writes the tree of a commit into a directory.
//! - [`Repo::pull`] copies commits from a remote, and [`Repo::pull_local`] from a local repository.
//! - [`Repo::pull_with_session`] copies commits from a remote through a session of the caller.
//! - [`Repo::pull_collection`] copies the refs of a collection from the remotes that serve it.
//! - [`Error`] is the error of each fallible operation of the crate.
//!
//! # Modules
//! - Read: [`read`], [`file`](mod@file), [`tree`], [`refs`], and [`traverse`].
//! - Write: [`transaction`], [`mtree`], [`staging_tree`], [`commit`], [`modifier`], [`bootable`].
//! - Checkout and export: [`checkout`], [`composefs`], [`tar`], and [`archive`].
//! - Pull: [`pull`], [`summary`], [`fetch`], the HTTP client of `ostrya-fetch`, and [`remote`], which holds the session of a pull over HTTP, over ssh, or over a pair of byte streams.
//! - Push and receive: [`remote`], the wire protocol of `ostrya-remote`, and `receive`.
//! - Client access: [`access`], the client groups and the server settings of the config, the claims of a client certificate, and the read rights of a client.
//! - Remote resolution: [`endpoint`], which reads the keys and files of a remote for a pull or a push.
//! - Bucket repositories: `bucket`, a repository in an S3 bucket, with the init, the writer lock, the listing of the objects, the fsck, the prune, and the summary update.
//! - Signing: [`sign`], `gpg`, and `spki`.
//! - Signature trust: [`verify`], the trusted keys and the trust of one pull.
//! - Maintenance: [`prune`], [`fsck`], [`diff`], [`update`], and [`config`].
//! - Static deltas: [`DeltaSuperblock`], [`DeltaOptions`], [`AdvertisedDelta`], and [`Repo::generate_static_delta`].
//!
//! # Features
//! - `smol` (default): the `smol` backend of `ostrya-rt`.
//! - `tokio`: the `tokio` backend of `ostrya-rt`.
//! - `sign-spki`: the `spki` module, the spki signing engine with each of its key types. It turns on `sign-spki-p256` and `sign-spki-rsa`.
//! - `sign-spki-p256`: the `spki` module with the ECDSA P-256 key type.
//! - `sign-spki-rsa`: the `spki` module with the RSA key type. A build with one of the two key features refuses a key of the other type.
//! - `verify-gpg`: the `gpg` module, GPG verification and keyring management.
//! - `sign-gpg`: `GpgSigner`, which signs with the `gpg` command. It turns on `verify-gpg`.
//! - `receive`: the `receive` module, the receive side of a push.
//! - `push`: `Repo::push`, `Repo::push_onto`, and `Repo::export_stream`, the push from a repository.
//! - `s3`: the pull from a bucket repository at an `s3://` address and the pull of collection refs from one, the `bucket` module with the fsck, the prune, and the summary update of a bucket repository, the `s3` module of `ostrya-remote`, and with `push`, the push of commits and of a local directory to a bucket repository.
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

pub mod access;
pub mod archive;
pub mod bootable;
mod bspatch;
#[cfg(feature = "s3")]
pub mod bucket;
pub mod checkout;
pub mod commit;
pub mod composefs;
pub mod config;
mod delta;
mod deltagen;
pub mod diff;
pub mod endpoint;
pub mod error;
pub use ostrya_fetch as fetch;
pub use ostrya_remote as remote;
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
#[cfg(any(feature = "receive", all(feature = "push", feature = "s3")))]
mod server_commit;
pub mod sign;
#[cfg(any(feature = "sign-spki-p256", feature = "sign-spki-rsa"))]
pub mod spki {
    //! The spki signing engine: ECDSA P-256 and RSA PKCS#1 v1.5 signatures,
    //! with SPKI public keys.
    pub use ostrya_sign::{
        SpkiSigner, SpkiVerifier, spki_public_keys, spki_secret_key_lines, spki_secret_keys,
    };
}
mod staging;
pub mod staging_tree;
pub mod summary;
pub mod tar;
mod tombstone;
pub mod traverse;
pub mod tree;
pub mod update;
pub mod verify;
mod write;

#[doc(hidden)]
pub use archive::{ArchiveAnswer, ArchiveHead, ArchiveView};
#[doc(hidden)]
pub use bootable::{BootableMetadata, BootableRefusal};
#[cfg(feature = "s3")]
#[doc(hidden)]
pub use bucket::{
    BucketFinding, BucketFindingKind, BucketFsckOptions, BucketFsckReport, BucketPruneOptions,
    BucketPruneReport, BucketPushOutcome, BucketRepo, BucketSummaryOptions, BucketSummaryReport,
    BucketWriteOptions, LockHolder, LockOperation, ObjectListing, WriterLock,
};
#[doc(hidden)]
pub use checkout::{CheckoutFilterFn, CheckoutMode, CheckoutOptions, OverwriteMode};
#[doc(hidden)]
pub use commit::CommitOptions;
#[doc(hidden)]
pub use composefs::{
    ComposefsImageAdd, ComposefsImageState, ComposefsOptions, StagedComposefsImage, VerityPolicy,
};
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
    FsckBindingError, FsckBindingErrorKind, FsckError, FsckErrorKind, FsckFailure, FsckImageError,
    FsckImageErrorKind, FsckOptions, FsckPhase, FsckReport,
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
    Checksum, Commit, DictBuilder, DirMeta, DirTree, ObjectName, ObjectType, RefPattern,
    RefSelector, RepoMode, Span, TextError, Type, Value, Xattrs, from_bytes, from_text,
    is_checksum_shaped, is_collection_id, loose_path, source_date_epoch, to_text,
    to_text_unannotated,
};
pub use ostrya_remote::proto::{
    MAX_REF_ENTRY_LEN, MAX_REF_ENTRY_PARTS, MAX_REF_LISTING, MAX_REF_PATTERNS,
};
#[doc(hidden)]
pub use prune::{PruneOptions, PruneStats, WeakRefFilter, WeakRefFilterFn};
#[doc(hidden)]
pub use pull::{
    CollectionPullEvent, CollectionPullOptions, CollectionPullRef, CollectionPullStats,
    DetachedMetadataFilter, DetachedMetadataFilterFn, PullFlags, PullOptions, PullProgress,
    PullProgressSnapshot, PullStats, PullVerify, TimestampCheck,
};
#[cfg(feature = "push")]
pub use push_repo::{ExportStreamOptions, PushOntoOptions, RepoPushOptions, is_push_address};
#[doc(hidden)]
pub use read::{CommitSizes, CommitState, MetadataReader};
#[cfg(feature = "receive")]
#[doc(hidden)]
pub use receive::{
    HookFuture, HookRefusal, HostEntry, ReceiveHooks, ReceivePattern, ReceivePolicies,
    ReceivePolicy, ReceiveReport, ReceiveService, ReceiveStep, ReceiveVerify, ReceiveWarning,
    ServerSigner, StreamPolicy, StreamRule, UpdatePlan,
};
#[doc(hidden)]
pub use refs::{CollectionRef, CollectionRefEntry, RefAlias, validate_refspec};
#[doc(hidden)]
pub use repo::{CreateOptions, Repo};
pub use send::{SendEvent, SendEventFn, SendOptions};
#[doc(hidden)]
pub use sign::{
    DummySigner, DummyVerifier, Ed25519Signer, Ed25519Verifier, FromSystemKeys, SignFuture,
    SignKeys, SignatureInfo, Signer, Verifier, VerifyFuture, VerifyOutcome, load_sign_keys,
    load_sign_keys_from,
};
#[cfg(any(feature = "sign-spki-p256", feature = "sign-spki-rsa"))]
#[doc(hidden)]
pub use spki::{
    SpkiSigner, SpkiVerifier, spki_public_keys, spki_secret_key_lines, spki_secret_keys,
};
#[doc(hidden)]
pub use staging_tree::{
    MergeOptions, RootDirmeta, StagedFileWriter, StagingEntry, StagingLookup, StagingTree,
};
#[doc(hidden)]
pub use summary::{
    AdvertisedDelta, RefListing, Summary, SummaryOptions, SummaryRef, SummaryReport,
};
#[doc(hidden)]
pub use tar::{TarExportOptions, TarImportOptions, TarRename};
#[doc(hidden)]
pub use transaction::{ContentWriter, FileMeta, Transaction, TransactionStats};
#[doc(hidden)]
pub use tree::{RepoTree, TreeEntry};
#[doc(hidden)]
pub use update::UpdateGuard;
#[doc(hidden)]
pub use verify::{PullTrust, TrustedKeys};

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
