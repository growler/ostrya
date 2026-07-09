#![forbid(unsafe_code)]

//! Pure-Rust, async reimplementation of the ostree repository library.
//!
//! This crate exposes the repository, transaction, reading, writing, checkout,
//! and maintenance APIs. It is async on the `smol` runtime and is designed to
//! hold multiple concurrent transactions within a single process.
//!
//! So far the crate covers repository open/create and config parsing (Phase 4
//! of `docs/port-plan.md`); the reading, writing, checkout, and maintenance
//! subsystems land in later phases.

pub mod config;
pub mod error;
pub mod repo;

pub use config::{MinFreeSpace, Remote, RepoConfig, SizeSpec, SizeUnit};
pub use error::{Error, Result};
pub use ostrya_core::RepoMode;
pub use repo::{CreateOptions, Repo};
