//! S3 request signing, and the settings and credentials of an S3 endpoint.
//!
//! - [`SigV4`] is a [`RequestSigner`](ostrya_fetch::RequestSigner) that signs
//!   each request of a fetcher with AWS Signature Version 4, for the service
//!   `s3`.
//! - [`Credentials`] is the key pair of a signature.
//! - [`resolve`] gives the region, the endpoint, the addressing style, and the
//!   key pair of an endpoint, from the [`Settings`] of the caller, from the
//!   [`Environment`], and from the shared AWS config file and credentials
//!   file. Each value has its [`Origin`].
//!
//! The module reads static key pairs alone. It does not assume a role, run a
//! credential process, or read an SSO token.
//!
//! # Examples
//!
//! ```no_run
//! use std::sync::Arc;
//! use ostrya_fetch::FetcherOptions;
//! use ostrya_remote::s3::{Environment, Settings, SigV4, resolve};
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let resolved = resolve(&Settings::default(), &Environment::Process).await?;
//! let signer = SigV4::new(resolved.credentials, &resolved.region.value)?;
//! let mut options = FetcherOptions::new("https://bucket.s3.eu-central-1.amazonaws.com/");
//! options.signer = Some(Arc::new(signer));
//! # Ok(()) }
//! ```

mod chain;
mod credentials;
mod ini;
mod sigv4;

pub use chain::{Addressing, Environment, Origin, Resolved, Setting, Settings, resolve};
pub use credentials::Credentials;
pub use sigv4::SigV4;

/// The region of a profile that no source gives a region: `us-east-1`.
pub const DEFAULT_REGION: &str = "us-east-1";
