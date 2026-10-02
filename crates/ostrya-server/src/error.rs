//! The error type of the server.

use std::io;
use std::net::SocketAddr;

/// Result alias of the server.
pub type Result<T> = std::result::Result<T, Error>;

/// The error the server fails with. Each one arises before the server
/// accepts a connection. An error on one connection ends that connection and
/// no other.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A listen address could not be bound.
    #[error("bind {addr}: {source}")]
    Bind {
        /// The address of the options.
        addr: SocketAddr,
        /// The error of the bind.
        #[source]
        source: io::Error,
    },
    /// The TLS files do not give a server configuration.
    #[error("server tls: {0}")]
    Tls(String),
    /// The options cannot be served.
    #[error("invalid serve options: {0}")]
    Options(String),
    /// An error of the repository.
    #[error(transparent)]
    Repo(#[from] ostrya::Error),
    /// An I/O error.
    #[error(transparent)]
    Io(#[from] io::Error),
}
