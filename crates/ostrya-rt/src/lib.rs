#![forbid(unsafe_code)]

//! The async runtime layer of ostrya, over a `smol` or a `tokio` backend.
//!
//! The other ostrya crates run tasks, blocking work, file I/O, TCP, timers,
//! and helper processes through this crate. It is the only ostrya crate that
//! names the backend. Its stream types implement the `futures-io` traits with
//! each backend, so the code of a caller does not change with the backend.
//! The crate compiles on Unix and Windows.
//!
//! # Entry points
//!
//! - [`spawn`] starts a task and returns a [`JoinHandle`].
//! - [`unblock`] and [`unblock_detached`] run a closure on the blocking pool.
//! - [`File`] and [`FileReader`] stream over an open file descriptor.
//! - [`TcpStream`] and [`TcpListener`] carry async TCP.
//! - [`Command`] runs a helper process.
//! - [`Timer`] and [`Deadline`] measure a time window.
//! - [`block_on`] runs a future to completion on the current thread.
//!
//! # Features
//!
//! - `smol` (default): the `smol` backend.
//! - `tokio`: the `tokio` backend. It adds the `tokio_io` module, and
//!   [`File`] and [`TcpStream`] also implement the tokio I/O traits.
//!
//! If both features are on, `tokio` selects the backend, so a build in which
//! Cargo unifies the two features still compiles. If neither feature is on,
//! the build stops with a compile error. With the `tokio` feature, the I/O,
//! the timers, and the tasks of this crate need a tokio runtime context.
//! [`block_on`] gives one.
//!
//! # Examples
//!
//! ```
//! let total = ostrya_rt::block_on(async {
//!     let task = ostrya_rt::spawn(async { 6 * 7 });
//!     let sum = ostrya_rt::unblock(|| (1..=4).sum::<u32>()).await;
//!     task.await + sum
//! });
//! assert_eq!(total, 52);
//! ```

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

pub use file::{File, FileReader};
pub use net::{TcpListener, TcpStream};
pub use pool::{block_on, blocking_threads, unblock, unblock_detached};
pub use process::{Child, ChildStdin, ChildStdout, Command};
pub use task::{JoinHandle, spawn};
pub use timer::{Deadline, Timer};

/// The tokio I/O traits, for a crate with no direct `tokio` dependency.
///
/// [`File`] implements `AsyncRead`, `AsyncWrite`, and `AsyncSeek`.
/// [`TcpStream`] implements `AsyncRead` and `AsyncWrite`.
#[cfg(feature = "tokio")]
pub mod tokio_io {
    #[doc(no_inline)]
    pub use tokio::io::{AsyncBufRead, AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};
}
