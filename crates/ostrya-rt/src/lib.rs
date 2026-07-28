#![forbid(unsafe_code)]

//! The runtime abstraction the rest of ostrya is written against.
//!
//! This crate is the only place that knows which async backend is compiled.
//! It exposes [`unblock`] (the sole entry to the blocking pool), [`File`]
//! (an async file over an already-open descriptor), [`Timer`] (a one-shot
//! async delay for retry loops) with [`Deadline`] (a restartable window a
//! `poll_*` method can check), [`Command`] (a short-lived helper process
//! with piped standard streams), [`spawn`] (concurrent tasks, with the
//! [`JoinHandle`] they return), [`TcpStream`] and [`TcpListener`] (async TCP),
//! and [`block_on`] (a convenience driver used by tests and doctests). The
//! wider library is written against these plus the `futures-io` traits, so it
//! stays runtime-neutral.
//!
//! Backend selection is feature-gated and additive-safe:
//!
//! - `smol` (default) selects the `smol` backend.
//! - `tokio` selects the `tokio` backend and takes precedence when both
//!   features are enabled, so Cargo feature unification cannot break a build.
//! - enabling neither is a compile error.

#[cfg(not(any(feature = "smol", feature = "tokio")))]
compile_error!(
    "ostrya-rt requires an async backend: enable the `smol` feature (default) or `tokio`"
);

mod file;
mod net;
mod pool;
mod process;
mod task;
mod timer;

pub use file::File;
pub use net::{TcpListener, TcpStream};
pub use pool::{block_on, unblock};
pub use process::Command;
pub use task::{JoinHandle, spawn};
pub use timer::{Deadline, Timer};

/// The tokio I/O trait surface the public stream types in `ostrya` implement
/// under the `tokio` feature. Re-exported here so `ostrya` needs no direct
/// tokio dependency to name these traits.
#[cfg(feature = "tokio")]
pub mod tokio_io {
    pub use tokio::io::{AsyncBufRead, AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};
}
