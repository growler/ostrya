//! The error type of the server.

use std::io;
use std::net::SocketAddr;

/// The result type of the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// The error of [`bind`](crate::bind) and of
/// [`ReceiveEndpoint::new`](crate::ReceiveEndpoint::new).
///
/// Each error occurs before the server or the host accepts a connection. An
/// error on one connection ends that connection and no other.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A listen address that cannot be bound, or whose local address cannot
    /// be read.
    #[error("bind {addr}: {source}")]
    Bind {
        /// The listen address from the options.
        addr: SocketAddr,
        /// The I/O error of the bind or of the read of the local address.
        #[source]
        source: io::Error,
    },
    /// TLS files that give no server configuration.
    #[error("server tls: {0}")]
    Tls(String),
    /// Options that the server refuses. The text states the reason.
    #[error("invalid serve options: {0}")]
    Options(String),
    /// A malformed line of the push credential file.
    ///
    /// The error names the line by its number and holds no byte of it.
    #[error("push credentials: line {line}: {message}")]
    Credentials {
        /// The number of the line, from 1.
        line: usize,
        /// The defect of the line.
        message: String,
    },
    /// An error of the repository.
    #[error(transparent)]
    Repo(#[from] ostrya::Error),
    /// An I/O error.
    #[error(transparent)]
    Io(#[from] io::Error),
}
