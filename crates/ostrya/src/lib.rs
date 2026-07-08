#![forbid(unsafe_code)]

//! Pure-Rust, async reimplementation of the ostree repository library.
//!
//! This crate exposes the repository, transaction, reading, writing, checkout,
//! and maintenance APIs. It is async on the `smol` runtime and is designed to
//! hold multiple concurrent transactions within a single process.
//!
//! So far only the error types exist; the functional subsystems land in later
//! phases (see `docs/port-plan.md`).

pub mod error;

pub use error::{Error, Result};
