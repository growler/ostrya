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
//! transaction before they publish. Checkout and maintenance land in later
//! phases.

pub mod commit;
pub mod config;
pub mod error;
pub mod file;
mod hashing;
mod inflate;
mod ingest;
mod lock;
pub mod modifier;
pub mod mtree;
mod object;
mod overlay;
pub mod read;
pub mod refs;
pub mod repo;
mod staging;
pub mod staging_tree;
pub mod transaction;
pub mod tree;
mod write;

pub use commit::CommitOptions;
pub use config::{MinFreeSpace, Remote, RepoConfig, SizeSpec, SizeUnit};
pub use error::{Error, Result};
pub use file::{ContentReader, FileKind, FileObject};
pub use hashing::{HashingReader, HashingWriter};
pub use lock::LockKind;
pub use modifier::{
    CommitModifier, CommitModifierFlags, DevInoCache, FilterFn, FilterResult, LabelFn, XattrFn,
};
pub use mtree::MutableTree;
pub use ostrya_core::{Checksum, Commit, DirMeta, DirTree, ObjectType, RepoMode, Type, Value};
pub use read::CommitState;
pub use refs::CollectionRef;
pub use repo::{CreateOptions, Repo};
pub use staging_tree::{MergeOptions, StagedFileWriter, StagingEntry, StagingTree};
pub use transaction::{ContentWriter, FileMeta, Transaction, TransactionStats};
pub use tree::{RepoTree, TreeEntry};
