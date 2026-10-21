//! The location, the credentials, and the HTTP options of a bucket
//! repository.

use std::fmt;
use std::sync::Arc;

use ostrya_fetch::FetcherOptions;

use super::{Address, Credentials, Environment, Location, Settings, SigV4, resolve};
use crate::Result;

/// A bucket repository with the credentials and the HTTP options of its
/// client.
///
/// [`Bucket::new`](super::Bucket::new) opens a bucket client from it,
/// [`Bucket::from_fetcher`](super::Bucket::from_fetcher) opens one over the
/// fetcher of a pull, and
/// [`Endpoint::S3`](crate::transport::Endpoint::S3) carries it.
/// [`PullSession::connect`](crate::session::PullSession::connect) opens the
/// session of a pull to it, with the fetcher options that
/// [`pull_options`](S3Endpoint::pull_options) gives.
///
/// The bucket client and the fetcher of a pull take the TLS settings, the
/// proxy, the headers, the time limits, the retry count, the request limit,
/// and
/// [`allow_cleartext_credentials`](ostrya_fetch::FetcherOptions::allow_cleartext_credentials)
/// from [`http`](S3Endpoint::http). They replace three fields:
///
/// - [`mirrors`](ostrya_fetch::FetcherOptions::mirrors) with the
///   [`bucket_url`](Location::bucket_url) of the location for the bucket
///   client, and with the [`repository_url`](Location::repository_url) for a
///   pull
/// - [`signer`](ostrya_fetch::FetcherOptions::signer) with a
///   [`SigV4`](super::SigV4) of the credentials and the region
/// - [`max_redirects`](ostrya_fetch::FetcherOptions::max_redirects) with 0.
///   A redirect to another origin carries no signature, so the fetcher
///   follows no redirect.
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

    /// Returns the options of the fetcher of a pull from the bucket
    /// repository.
    ///
    /// The options are [`http`](S3Endpoint::http) with the one mirror
    /// [`repository_url`](Location::repository_url), a
    /// [`SigV4`](super::SigV4) signer of the credentials and the region, and
    /// no redirect. The pull asks for each file of the repository under that
    /// mirror, and the signer signs each request.
    ///
    /// An `http://` endpoint needs
    /// [`allow_cleartext_credentials`](ostrya_fetch::FetcherOptions::allow_cleartext_credentials)
    /// in [`http`](S3Endpoint::http), or
    /// [`Fetcher::new`](ostrya_fetch::Fetcher::new) refuses the options,
    /// because the signer is a credential.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInput`](crate::Error::InvalidInput) if
    /// [`SigV4::new`](super::SigV4::new) refuses the region.
    ///
    /// # Examples
    ///
    /// ```
    /// use ostrya_remote::s3::{Address, Credentials, Location, S3Endpoint};
    /// # fn main() -> ostrya_remote::Result<()> {
    /// let location = Location::new(
    ///     Address::parse("s3://builds/exampleos")?,
    ///     "us-east-1",
    ///     Some("https://s3.example.com"),
    ///     None,
    /// )?;
    /// let credentials = Credentials::new("AKIDEXAMPLE".into(), "SECRETEXAMPLE".into(), None)?;
    /// let options = S3Endpoint::new(location, credentials).pull_options()?;
    /// assert_eq!(options.mirrors, ["https://s3.example.com/builds/exampleos"]);
    /// assert_eq!(options.max_redirects, 0);
    /// assert!(options.signer.is_some());
    /// # Ok(()) }
    /// ```
    pub fn pull_options(&self) -> Result<FetcherOptions> {
        self.signed_options(self.location.repository_url())
    }

    /// Returns [`http`](S3Endpoint::http) with `mirror` as the one mirror, a
    /// [`SigV4`] signer of the credentials and the region, and
    /// `max_redirects` set to 0.
    pub(super) fn signed_options(&self, mirror: String) -> Result<FetcherOptions> {
        let signer = SigV4::new(self.credentials.clone(), self.location.region())?;
        Ok(FetcherOptions {
            mirrors: vec![mirror],
            signer: Some(Arc::new(signer)),
            max_redirects: 0,
            ..self.http.clone()
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s3::Addressing;

    fn endpoint(
        address: &str,
        endpoint: Option<&str>,
        addressing: Option<Addressing>,
    ) -> S3Endpoint {
        let location = Location::new(
            Address::parse(address).unwrap(),
            "eu-central-1",
            endpoint,
            addressing,
        )
        .unwrap();
        let credentials =
            Credentials::new("AKIDEXAMPLE".into(), "SECRETEXAMPLE".into(), None).unwrap();
        S3Endpoint::new(location, credentials)
    }

    /// The options of a pull have the repository URL as the one mirror, a
    /// signer, and no redirect. They keep each other field of the HTTP
    /// options.
    #[test]
    fn the_pull_options_sign_each_request_to_the_repository_url() {
        let mut s3 = endpoint("s3://builds/exampleos/x86_64", None, None);
        s3.http.max_retries = 2;
        s3.http.max_outstanding = 3;
        s3.http.headers = vec![("X-A".into(), "b".into())];
        s3.http.allow_cleartext_credentials = true;
        let options = s3.pull_options().unwrap();
        assert_eq!(
            options.mirrors,
            ["https://builds.s3.eu-central-1.amazonaws.com/exampleos/x86_64"]
        );
        assert!(options.signer.is_some());
        assert_eq!(options.max_redirects, 0);
        assert_eq!(options.max_retries, 2);
        assert_eq!(options.max_outstanding, 3);
        assert_eq!(options.headers, [("X-A".to_owned(), "b".to_owned())]);
        assert!(options.allow_cleartext_credentials);
        assert!(!format!("{options:?}").contains("SECRETEXAMPLE"));

        let s3 = endpoint("s3://builds", Some("http://127.0.0.1:9000"), None);
        let options = s3.pull_options().unwrap();
        assert_eq!(options.mirrors, ["http://127.0.0.1:9000/builds"]);
        let s3 = endpoint(
            "s3://builds/repo",
            Some("https://s3.example.com"),
            Some(Addressing::Path),
        );
        assert_eq!(
            s3.pull_options().unwrap().mirrors,
            ["https://s3.example.com/builds/repo"]
        );
    }
}
