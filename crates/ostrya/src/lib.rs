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
//! regular file redirects to its `.file` loose object and, under the default
//! [`ComposefsOptions`] verity policy, carries the fs-verity digest of that
//! file's content -- [`Repo::export_composefs_to`], which writes that image
//! through a file descriptor and returns its fs-verity digest without holding
//! the image, [`Repo::commit_add_composefs_metadata`],
//! which stores the image digest in a commit's `ostree.composefs.digest.v0`
//! metadata, and [`Transaction::composefs_digest`], which computes the digest
//! over a tree the transaction has staged, for a commit that carries the key in
//! its own metadata. It
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
//! `trusted.spki` / `revoked.spki`. Under the `verify-gpg` feature it also
//! covers the GPG engine (Phase 13d): [`GpgVerifier`] holds binary or armored
//! keyrings, parses each into certificates as it loads it, and answers the
//! verdict in the process over the `pgp` crate (rPGP); detached OpenPGP
//! signatures accumulate under `ostree.gpgsigs` with per-signature metadata
//! read from the certificate and the signature packet. The `sign-gpg` feature
//! adds [`GpgSigner`], which runs `gpg --detach-sign` with the key resolved by
//! fingerprint, key id, or user id in an optional GnuPG home directory
//! (agent-held and hardware-token keys included), and turns on `verify-gpg`
//! with it. It also covers static deltas
//! in both directions (Phase 15): [`Repo::apply_static_delta_offline`] reads a
//! delta -- the superblock, the xz-compressed parts, and the operation stream
//! (splice, open/close, set-read-source, rollsum write, and bspatch) -- and
//! produces the target commit's objects, asserting each checksum as written,
//! while [`Repo::generate_static_delta`] writes one, choosing per object
//! between a splice, a rollsum copy-from-source stream, a bspatch stream, and
//! a loose fallback. [`Repo::sign_static_delta`] wraps a superblock in the
//! signed envelope, [`Repo::verify_static_delta`] checks those signatures with
//! the signing engines over the raw superblock bytes, and
//! [`Repo::reindex_static_deltas`] rebuilds the `delta-indexes/` cache. It also
//! covers the fetcher pull is built on (Phase 16a): [`Fetcher`] serves
//! [`FetchRequest`]s for paths under a remote's mirrors over HTTP/1.1 and
//! HTTP/2 -- ALPN picks the version, connections are pooled per origin,
//! requests carry a [`Priority`] the fetcher's admission queue honors,
//! conditional requests resolve to [`Fetched::NotModified`], retryable
//! failures are repeated across mirrors, and a response arrives as a streaming
//! [`Body`] under an optional size cap -- and [`VerifyingReader`], the stream
//! that checks a payload against its expected digest at EOF. It also covers
//! local pull (Phase 16b): [`Repo::pull_local`] imports refs, their commit
//! chains, and every object those commits reach out of another local
//! repository under a [`PullOptions`] -- an object the two repositories store
//! identically, inode included, is hardlinked where the source inode already
//! carries the ownership a write here produces; a refused link takes a metadata
//! object to a reflink-then-copy and a content object to its logical header; a
//! content object crossing modes within the bare family has its payload cloned
//! under this repository's own inode policy; one crossing the archive boundary
//! is re-ingested through the ordinary write path; [`PullFlags`] selects
//! checksum verification, commit-metadata-only pulls, copying instead of
//! linking, and the mode and binding checks; and
//! [`localcache_repos`](PullOptions::localcache_repos) adds further local
//! repositories to source objects from. It also covers HTTP pull (Phase 16c):
//! [`Repo::pull`] fetches refs, their commit chains, and every object those
//! commits reach from an archive remote named in this repository's config --
//! `summary.sig`, `summary`, and `config` first, then the objects, with a
//! content object always requested in the `.filez` form an HTTP client can read
//! and a non-archive remote refused on its config mode. Up to
//! [`max_outstanding_fetches`](PullOptions::max_outstanding_fetches) objects are
//! in flight over a plan drained commits first, then the metadata the scan is
//! blocked on, then the content; a commit object is staged where it arrives,
//! behind its own `.commitpartial` marker and ahead of its tree, and the marker
//! is removed after the transaction publishes; three write permits bound the
//! concurrent writers on the destination; every object is stored under the name
//! it was requested by, which is what verifies it;
//! [`MIRROR`](PullFlags::MIRROR) writes local refs and copies the remote's
//! summary and its signature; and [`TimestampCheck`] refuses a tip older than
//! what the ref already names. [`Repo::remote_fetch_summary`] reads a remote's
//! `summary` and `summary.sig` on their own, and [`Summary`] parses one. A pull
//! also takes a static delta where the remote publishes one (Phase 16d): the
//! delta index, or the summary's `ostree.static-deltas` map, names the delta from
//! the commit the ref holds here (or from scratch), its superblock is checked
//! against the advertised digest, its parts are fetched two at a time and applied
//! into the pull's transaction, and the objects it hands over loose are fetched as
//! ordinary content objects;
//! [`disable_static_deltas`](PullOptions::disable_static_deltas) and
//! [`require_static_deltas`](PullOptions::require_static_deltas) control it, and
//! [`Repo::regenerate_summary`] writes the map that advertises this repository's
//! own deltas. Either pull checks signatures (Phase 16e): the remote's
//! `gpg-verify`, `gpg-verify-summary`, `sign-verify`, and `sign-verify-summary`
//! keys state the policy, [`PullVerify`] overrides it, and the keys come from
//! that remote's trusted keyrings and its `verification-<engine>-*` entries.
//! It also covers the configuration write side (Phase 17e):
//! [`Repo::write_config`] replaces `config` atomically with a document edited
//! through [`KeyFile`](ostrya_core::KeyFile), which is how a remote's section is
//! added or removed, and [`Repo::remove_remote_keyring`] deletes the keyring that
//! section owns. Under the `verify-gpg` feature, `Repo::gpg_import_keys` and
//! `Repo::gpg_list_keys` add certificates to a remote's
//! `<remote>.trustedkeys.gpg` and read back the key records it holds (see the
//! [`gpg`] module). It also covers the bootable commit metadata (Phase 21):
//! [`Transaction::kernel_version`] and [`RepoTree::kernel_version`] derive the
//! value `ostree.linux` holds from a tree, staged and published respectively,
//! answering the shapes that name no kernel with a [`BootableRefusal`], and
//! [`BootableMetadata`] adds `ostree.linux` and `ostree.bootable` to a
//! [`DictBuilder`] in the order they hold on disk (see the [`bootable`]
//! module).

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
pub mod fetch;
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
pub mod prune;
pub mod pull;
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

pub use bootable::{BootableMetadata, BootableRefusal};
pub use checkout::{CheckoutFilterFn, CheckoutMode, CheckoutOptions, OverwriteMode};
pub use commit::CommitOptions;
pub use composefs::{ComposefsOptions, VerityPolicy};
pub use config::{MinFreeSpace, Remote, RepoConfig, SignVerify, SizeSpec, SizeUnit, Tristate};
pub use deltagen::DeltaOptions;
pub use diff::{DiffChange, DiffEntry};
pub use error::{Error, Result};
pub use fetch::{
    BasicAuth, Body, ClientIdentity, FetchRequest, Fetched, Fetcher, FetcherOptions, Priority,
    Protocol, TlsOptions, TrustRoots, Validators,
};
pub use file::{ContentReader, FileKind, FileObject};
pub use fsck::{FsckError, FsckErrorKind, FsckOptions, FsckReport};
#[cfg(feature = "sign-gpg")]
pub use gpg::GpgSigner;
#[cfg(feature = "verify-gpg")]
pub use gpg::{GpgKey, GpgVerifier};
pub use hashing::{HashingReader, HashingWriter, VerifyingReader};
pub use lock::LockKind;
pub use modifier::{
    CommitModifier, CommitModifierFlags, DevInoCache, FilterFn, FilterResult, LabelFn, ModeFn,
    XattrFn,
};
pub use mtree::MutableTree;
pub use ostrya_composefs::Image;
pub use ostrya_core::base64;
pub use ostrya_core::{
    Checksum, Commit, DictBuilder, DirMeta, DirTree, ObjectName, ObjectType, RepoMode, Span,
    TextError, Type, Value, Xattrs, from_bytes, from_text, loose_path, to_text,
    to_text_unannotated,
};
pub use prune::{PruneOptions, PruneStats};
pub use pull::{PullFlags, PullOptions, PullStats, PullVerify, TimestampCheck};
pub use read::{CommitSizes, CommitState};
pub use refs::{CollectionRef, RefAlias, validate_refspec};
pub use repo::{CreateOptions, Repo};
pub use sign::{
    DummySigner, DummyVerifier, Ed25519Signer, Ed25519Verifier, SignFuture, SignKeys,
    SignatureInfo, Signer, Verifier, VerifyFuture, VerifyOutcome, load_sign_keys,
    load_sign_keys_from,
};
#[cfg(feature = "sign-spki")]
pub use spki::{SpkiSigner, SpkiVerifier};
pub use staging_tree::{
    MergeOptions, RootDirmeta, StagedFileWriter, StagingEntry, StagingLookup, StagingTree,
};
pub use summary::{Summary, SummaryOptions, SummaryRef};
pub use tar::{TarExportOptions, TarImportOptions, TarRename};
pub use transaction::{ContentWriter, FileMeta, Transaction, TransactionStats};
pub use tree::{RepoTree, TreeEntry};

/// Remove the staging directories the live transactions of this process own.
///
/// A [`Transaction`] removes its staging directory when it commits, when it
/// aborts, and when it drops, so an unwound return leaves `tmp/` clean on its
/// own. [`std::process::exit`] runs no destructor: a process that ends that way
/// with a transaction still live leaves its `tmp/staging-<boot-id>-XXXXXX`
/// directory and the sibling lock file behind, for a later transaction's
/// stale-directory reaper to collect. A caller that ends the process without
/// unwinding calls this immediately before it, and `tmp/` is left as an unwound
/// return would leave it.
///
/// Call it only when the process is about to end. It removes the staging
/// directory of every live transaction in the process, so a transaction that
/// keeps running afterward finds its staged objects gone.
pub fn reap_process_staging() {
    staging::reap_owned();
}
