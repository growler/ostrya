//! The location, the credentials, and the HTTP options of a bucket
//! repository.

use std::fmt;

use super::{Address, Credentials, Environment, Location, Settings, resolve};
use crate::Result;

/// A bucket repository with the credentials and the HTTP options of its
/// client.
///
/// [`Bucket::new`](super::Bucket::new) opens a bucket client from it, and
/// [`Endpoint::S3`](crate::transport::Endpoint::S3) carries it.
///
/// The bucket client takes the TLS settings, the proxy, the headers, the
/// time limits, the retry count, the request limit, and
/// [`allow_cleartext_credentials`](ostrya_fetch::FetcherOptions::allow_cleartext_credentials)
/// from [`http`](S3Endpoint::http). It replaces three fields:
///
/// - [`mirrors`](ostrya_fetch::FetcherOptions::mirrors) with the
///   [`bucket_url`](Location::bucket_url) of the location
/// - [`signer`](ostrya_fetch::FetcherOptions::signer) with a
///   [`SigV4`](super::SigV4) of the credentials and the region
/// - [`max_redirects`](ostrya_fetch::FetcherOptions::max_redirects) with 0.
///
/// The [`Debug`] output shows the credentials as the [`Debug`] output of
/// [`Credentials`] shows them, and the HTTP options as the [`Debug`] output
/// of [`FetcherOptions`](ostrya_fetch::FetcherOptions) shows them. It holds
/// no secret access key and no session token.
#[derive(Clone)]
#[non_exhaustive]
pub struct S3Endpoint {
    /// The address, the region, the endpoint, and the addressing style.
    pub location: Location,
    /// The key pair that signs each request.
    pub credentials: Credentials,
    /// The options of the HTTP client.
    pub http: ostrya_fetch::FetcherOptions,
}

impl S3Endpoint {
    /// Returns the endpoint of `location` with `credentials` and the default
    /// HTTP options.
    pub fn new(location: Location, credentials: Credentials) -> S3Endpoint {
        S3Endpoint {
            location,
            credentials,
            http: ostrya_fetch::FetcherOptions::default(),
        }
    }

    /// Returns the endpoint of the address `address`, with the settings and
    /// the credentials that [`resolve`] gives from `settings`, from
    /// `environment`, and from the shared AWS files.
    ///
    /// The call is [`Address::parse`], [`resolve`], and
    /// [`Location::from_resolved`]. The HTTP options are the default.
    ///
    /// # Errors
    ///
    /// The errors of [`Address::parse`], [`resolve`], and
    /// [`Location::from_resolved`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use ostrya_remote::s3::{Environment, S3Endpoint, Settings};
    /// # async fn run() -> ostrya_remote::Result<()> {
    /// let endpoint =
    ///     S3Endpoint::resolve("s3://builds/exampleos", &Settings::default(), &Environment::Process)
    ///         .await?;
    /// println!("{}", endpoint.location.repository_url());
    /// # Ok(()) }
    /// ```
    pub async fn resolve(
        address: &str,
        settings: &Settings,
        environment: &Environment,
    ) -> Result<S3Endpoint> {
        let address = Address::parse(address)?;
        let resolved = resolve(settings, environment).await?;
        let location = Location::from_resolved(address, &resolved)?;
        Ok(S3Endpoint::new(location, resolved.credentials))
    }
}

impl fmt::Debug for S3Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Endpoint")
            .field("location", &self.location)
            .field("credentials", &self.credentials)
            .field("http", &self.http)
            .finish()
    }
}
