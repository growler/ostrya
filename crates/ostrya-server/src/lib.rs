#![forbid(unsafe_code)]

//! The HTTP server of ostrya, for the pull and the push of one repository.
//!
//! A [`Server`] serves one repository to the pull of the `ostree` command and
//! of ostrya. The pull reads it as an `archive` repository, whatever its mode
//! (see [`ostrya::ArchiveView`]). With a receive policy, the server also runs
//! the receive endpoint of a push. A host with its own HTTP router mounts
//! that endpoint as a [`ReceiveEndpoint`] and authenticates the requests
//! itself. The crate builds on Linux alone.
//!
//! # Entry points
//!
//! - [`serve`] binds the listeners of a [`ServeOptions`] and runs the server.
//! - [`bind`] binds the listeners and returns a [`Server`] to run with [`Server::run`].
//! - [`ServeOptions`] holds the addresses, the TLS files, and the options of a push.
//! - [`ReceiveEndpoint::new`] creates the receive endpoint for the router of a host.
//! - [`ReceiveEndpoint::handle`] answers one request of the endpoint.
//! - [`ReceiveAuth`] is the authentication of the endpoint by its host.
//! - [`Error`] is the error of each fallible operation of the crate.
//!
//! # Features
//!
//! - `smol` (default): the `smol` backend of `ostrya-rt`.
//! - `tokio`: the `tokio` backend of `ostrya-rt`, for a host on tokio.
//!
//! # Examples
//!
//! ```no_run
//! use ostrya::Repo;
//! use ostrya_server::{ServeOptions, bind};
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let repo = Repo::open("/srv/repo".as_ref()).await?;
//! let mut opts = ServeOptions::default();
//! opts.listen = vec!["0.0.0.0:8080".parse()?];
//! let server = bind(repo, opts).await?;
//! println!("listening on {:?}", server.local_addrs());
//! server.run().await?;
//! # Ok(())
//! # }
//! ```

mod auth;
mod body;
mod endpoint;
mod error;
mod options;
mod receive;
mod receive_auth;
mod request;
mod router;
mod server;
mod session;
mod shutdown;
mod stall;

pub use body::ReceiveBody;
pub use endpoint::{EndpointOptions, ReceiveEndpoint};
pub use error::{Error, Result};
pub use options::{ServeOptions, ServerTls};
pub use receive_auth::{ReceiveAuth, Refusal, RequestKind, SessionSetup};
pub use server::{Server, bind, serve};
