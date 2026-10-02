#![forbid(unsafe_code)]

//! The HTTP server of ostrya.
//!
//! [`bind`] opens the listeners of a [`ServeOptions`], and [`Server::run`]
//! serves the archive view of one repository on them until its future is
//! dropped. [`serve`] does both. A pull of the `ostree` tool, or of the port,
//! reads the repository through it as an `archive` repository, whatever the
//! mode of the repository (see [`ostrya::ArchiveView`]).
//!
//! - `GET` and `HEAD` are served. Another method gets 405 with
//!   `Allow: GET, HEAD`.
//! - The request path is percent-decoded. A path that does not decode to
//!   UTF-8, or holds a NUL, gets 404. The query is ignored.
//! - A path the view does not find and a path it refuses both get 404 with an
//!   empty body, so a client cannot tell a private path from an absent one.
//!   An error of the view gets 500 with an empty body.
//! - A response with a known length carries `Content-Length`, and a `.filez`
//!   built on request carries none. The body is read in frames of at most
//!   64 KiB and is never collected whole. A `HEAD` takes the answer of
//!   [`ostrya::ArchiveView::head`]: it reads no byte of the file, and for a
//!   `.filez` built on request it reads no xattr and does no deflate work.
//! - Plain HTTP serves HTTP/1.1. Over TLS, ALPN selects HTTP/2 or HTTP/1.1.
//!   An HTTP/2 connection carries at most 32 streams at the same time. The
//!   TLS handshake of a connection has 30 seconds, and an HTTP/1.1
//!   connection has 30 seconds for the headers of each request.
//! - A response body that waits longer than
//!   [`ServeOptions::body_timeout`] for the client to take its next bytes
//!   ends its connection, so a client that stops reading does not hold a
//!   file or a compressor. An HTTP/2 peer that does not answer a ping within
//!   that time loses its connection.
//! - A body that streams gives at most 256 KiB before it yields to the
//!   executor.
//! - With a client CA, a client certificate is verified against it, and a
//!   client that presents none is served.
//!
//! The crate builds on Linux alone. The `smol` and `tokio` features select
//! the runtime backend of `ostrya-rt`.

mod body;
mod error;
mod options;
mod router;
mod server;
mod shutdown;
mod stall;

pub use error::{Error, Result};
pub use options::{ServeOptions, ServerTls};
pub use server::{Server, bind, serve};
