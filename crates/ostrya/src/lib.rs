#![forbid(unsafe_code)]

//! Pure-Rust, async reimplementation of the ostree repository library.
//!
//! This crate exposes the repository, transaction, reading, writing, checkout,
//! and maintenance APIs. The async runtime backend is selected behind the
//! internal `ostrya-rt` crate: `smol` by default, `tokio` under the `tokio`
//! feature. The crate is designed to hold multiple concurrent transactions
//! within a single process.
//!
//! So far the crate covers repository open/create and config parsing (Phase 4
//! of `docs/port-plan.md`), the reading path (Phase 5): loading objects,
//! commits, and file content, resolving and listing refs, and traversing a
//! commit's tree, and the runtime backend and streaming primitives (Phase 5a):
//! the [`HashingReader`]/[`HashingWriter`] streams and a [`ContentReader`] that
//! streams from `rt::File` and inflates archive objects on the fly. It also
//! covers transactions and locking (Phase 6): the owned [`Transaction`] handle,
//! boot-id-keyed staging directories, and the two-layer repository lock, and the
//! object-store write layer (Phase 7a): streaming content ingestion through
//! [`ContentWriter`], metadata and symlink writers, per-mode on-disk
//! application, dedup, free-space accounting, and publication of staged objects
//! into `objects/` at commit. It also covers in-memory tree assembly (Phase
//! 7b): the [`MutableTree`] with lazy hydration and dirty tracking, and
//! [`Transaction::write_mtree`], which serializes dirty subtrees into dirtree
//! objects. It also covers filesystem ingest (Phase 7c):
//! [`Transaction::write_dfd_to_mtree`], which walks an on-disk tree into a
//! [`MutableTree`] under a [`CommitModifier`] that shapes what is committed
//! (canonical permissions, an include/prune filter, xattr and SELinux label
//! callbacks, a [`DevInoCache`], and source consumption). It also covers commit
//! assembly and durable publication (Phase 7d): [`Transaction::write_commit`]
//! and [`CommitOptions`] (with `ostree.sizes` emission), detached commit
//! metadata on [`Repo`], the ref queue ([`Transaction::set_ref`],
//! [`Transaction::set_collection_ref`]) and immediate ref writes
//! ([`Repo::set_ref_immediate`]), and the completed transaction commit
//! sequence -- objects published, then refs written. It also covers overlay
//! changeset import (Phase 7e): [`Transaction::merge_overlay_dfd_to_mtree`],
//! which merges an overlayfs upperdir into a [`MutableTree`] holding the lower
//! layer, applying whiteouts and opaque directories as it walks. It also covers
//! path-addressed tree construction (Phase 7f): the [`StagingTree`] built over a
//! transaction, with file, symlink, directory, and hardlink operations that
//! resolve paths through symlinks, tree [`merge`](StagingTree::merge) with
//! symlink resolution, and staged-first [`read_file`](StagingTree::read_file) /
//! [`read_dir`](StagingTree::read_dir) that see objects staged in the current
//! transaction before they publish. It also covers the checkout path (Phase 8):
//! [`Repo::checkout_at`], which materializes a commit's tree onto a filesystem
//! under a [`CheckoutOptions`] -- the [`CheckoutMode`] (faithful or
//! unprivileged), the [`OverwriteMode`] over an existing destination, an
//! optional subpath, hardlink-versus-copy with a `FICLONE` reflink on the copy
//! path, Docker-style whiteouts, a populated [`DevInoCache`], and an optional
//! filter. It also covers composefs export (Phase 9d):
//! [`Repo::export_composefs`], which builds the EROFS/composefs image for a
//! commit over the [`ostrya_composefs`] writer -- the tree model comes from the
//! commit's [`RepoTree`], the five top-level directories are injected, and each
//! regular file redirects to its `.file` loose object and carries that object's
//! fs-verity digest -- and [`Repo::commit_add_composefs_metadata`], which stores
//! the image digest in a commit's `ostree.composefs.digest.v0` metadata. It
//! also covers tar import and export (Phase 10): [`Repo::export_tar`], which
//! writes a commit's tree as a filesystem tar stream (numeric ownership,
//! commit-timestamp mtimes, `SCHILY.xattr.*` PAX records, content-checksum
//! hardlink coalescing), and [`Repo::import_tar`], which reads a filesystem tar
//! into a [`MutableTree`] with deferred hardlink resolution and an optional
//! `/etc` -> `/usr/etc` remap. It also covers maintenance (Phase 12):
//! [`Repo::list_objects`] and the reachability walks
//! [`Repo::traverse_commit`]/[`Repo::traverse_reachable`], [`Repo::prune`]
//! ([`PruneOptions`]/[`PruneStats`]) which deletes objects unreachable from the
//! chosen roots (refs, optionally every commit, to a depth, with an optional
//! `delete_commit`), [`Repo::fsck`] ([`FsckOptions`]/[`FsckReport`]) which
//! verifies object integrity and completeness and marks incomplete commits
//! partial, and [`Repo::diff_commits`] ([`DiffEntry`]/[`DiffChange`]) which
//! reports the paths that changed between two commits. It also covers
//! repository fs-verity (Phase pre13): with `[ex-integrity] fsverity` set to
//! `maybe` or `yes` (see [`RepoConfig::fsverity`] and [`Tristate`]), each loose
//! object stored as a regular file is sealed with fs-verity as it is staged,
//! through the audited `ostrya-sys` ioctl wrappers. It also covers the signing
//! framework (Phase 13a): the [`Signer`]/[`Verifier`] engine surface,
//! [`Repo::sign_commit`] and [`Repo::verify_commit`], which sign and verify a
//! commit's canonical bytes and accumulate signatures in the per-engine `aay`
//! array of the commit's detached metadata, [`Repo::delete_signatures`], which
//! removes stored blobs from an engine's array, and the test-only
//! [`DummySigner`] / [`DummyVerifier`] engine. It also covers the ed25519 engine and the sign-api
//! key store (Phase 13b): [`Ed25519Signer`] / [`Ed25519Verifier`] over
//! deterministic ed25519 signatures, and [`load_sign_keys`], which reads the
//! `trusted.<type>` / `revoked.<type>` files and `.d` directories (a verifier
//! trusts the loaded set minus the revoked set). Under the `sign-spki` feature
//! it also covers the spki engine (Phase 13c): [`SpkiSigner`] / [`SpkiVerifier`]
//! over ECDSA on NIST P-256 with SHA-256, DER-encoded signatures, and
//! SubjectPublicKeyInfo public keys, reusing the sign-api key store as
//! `trusted.spki` / `revoked.spki`. Under the `sign-gpg` feature it also covers
//! the GPG engine (Phase 13d): [`GpgSigner`] / [`GpgVerifier`] over the system
//! GnuPG binaries -- signing runs `gpg --detach-sign` with the key resolved by
//! fingerprint, key id, or user id in an optional GnuPG home directory
//! (agent-held and hardware-token keys included), verification runs `gpgv`
//! over binary or armored keyrings, and detached OpenPGP signatures accumulate
//! under `ostree.gpgsigs` with per-signature metadata parsed from the
//! `--status-fd` stream. It also covers static deltas in both directions
//! (Phase 15): [`Repo::apply_static_delta_offline`] reads a delta -- the
//! superblock, the xz-compressed parts, and the operation stream (splice,
//! open/close, set-read-source, rollsum write, and bspatch) -- and produces the
//! target commit's objects, asserting each checksum as written, while
//! [`Repo::generate_static_delta`] writes one, choosing per object between a
//! splice, a rollsum copy-from-source stream, a bspatch stream, and a loose
//! fallback. [`Repo::sign_static_delta`] wraps a superblock in the signed
//! envelope, [`Repo::verify_static_delta`] checks those signatures with the
//! signing engines over the raw superblock bytes, and
//! [`Repo::reindex_static_deltas`] rebuilds the `delta-indexes/` cache.

mod bspatch;
pub mod checkout;
pub mod commit;
pub mod composefs;
pub mod config;
mod delta;
mod deltagen;
pub mod diff;
pub mod error;
pub mod file;
pub mod fsck;
#[cfg(feature = "sign-gpg")]
pub mod gpg;
mod hashing;
mod inflate;
mod ingest;
mod lock;
pub mod modifier;
pub mod mtree;
mod object;
mod overlay;
pub mod prune;
pub mod read;
pub mod refs;
pub mod repo;
mod rollsum;
pub mod sign;
#[cfg(feature = "sign-spki")]
pub mod spki;
mod staging;
pub mod staging_tree;
pub mod summary;
pub mod tar;
pub mod transaction;
pub mod traverse;
pub mod tree;
mod write;

pub use checkout::{CheckoutFilterFn, CheckoutMode, CheckoutOptions, OverwriteMode};
pub use commit::CommitOptions;
pub use config::{MinFreeSpace, Remote, RepoConfig, SizeSpec, SizeUnit, Tristate};
pub use deltagen::DeltaOptions;
pub use diff::{DiffChange, DiffEntry};
pub use error::{Error, Result};
pub use file::{ContentReader, FileKind, FileObject};
pub use fsck::{FsckError, FsckErrorKind, FsckOptions, FsckReport};
#[cfg(feature = "sign-gpg")]
pub use gpg::{GpgSigner, GpgVerifier};
pub use hashing::{HashingReader, HashingWriter};
pub use lock::LockKind;
pub use modifier::{
    CommitModifier, CommitModifierFlags, DevInoCache, FilterFn, FilterResult, LabelFn, XattrFn,
};
pub use mtree::MutableTree;
pub use ostrya_composefs::Image;
pub use ostrya_core::base64;
pub use ostrya_core::{
    Checksum, Commit, DirMeta, DirTree, ObjectName, ObjectType, RepoMode, Type, Value,
};
pub use prune::{PruneOptions, PruneStats};
pub use read::CommitState;
pub use refs::CollectionRef;
pub use repo::{CreateOptions, Repo};
pub use sign::{
    DummySigner, DummyVerifier, Ed25519Signer, Ed25519Verifier, SignFuture, SignKeys,
    SignatureInfo, Signer, Verifier, VerifyFuture, VerifyOutcome, load_sign_keys,
    load_sign_keys_from,
};
#[cfg(feature = "sign-spki")]
pub use spki::{SpkiSigner, SpkiVerifier};
pub use staging_tree::{MergeOptions, StagedFileWriter, StagingEntry, StagingTree};
pub use summary::SummaryOptions;
pub use tar::{TarExportOptions, TarImportOptions};
pub use transaction::{ContentWriter, FileMeta, Transaction, TransactionStats};
pub use tree::{RepoTree, TreeEntry};
