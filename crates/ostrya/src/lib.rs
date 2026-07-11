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
//! boot-id-keyed staging directories, and the two-layer repository lock. The
//! writing, checkout, and maintenance subsystems land in later phases.

pub mod config;
pub mod error;
pub mod file;
mod hashing;
mod inflate;
mod lock;
mod object;
pub mod read;
pub mod refs;
pub mod repo;
mod staging;
pub mod transaction;
pub mod tree;

pub use config::{MinFreeSpace, Remote, RepoConfig, SizeSpec, SizeUnit};
pub use error::{Error, Result};
pub use file::{ContentReader, FileKind, FileObject};
pub use hashing::{HashingReader, HashingWriter};
pub use lock::LockKind;
pub use ostrya_core::{Checksum, ObjectType, RepoMode};
pub use read::CommitState;
pub use repo::{CreateOptions, Repo};
pub use transaction::Transaction;
pub use tree::{RepoTree, TreeEntry};
