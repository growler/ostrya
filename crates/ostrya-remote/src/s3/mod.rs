//! S3 request signing, the settings and credentials of an S3 endpoint, the
//! address of a bucket repository, and the bucket client.
//!
//! - [`SigV4`] is a [`RequestSigner`](ostrya_fetch::RequestSigner) that signs
//!   each request of a fetcher with AWS Signature Version 4, for the service
//!   `s3`.
//! - [`Credentials`] is the key pair of a signature.
//! - [`resolve`] gives the region, the endpoint, the addressing style, and the
//!   key pair of an endpoint, from the [`Settings`] of the caller, from the
//!   [`Environment`], and from the shared AWS config file and credentials
//!   file. Each value has its [`Origin`].
//! - [`Address`] is the address of a bucket repository,
//!   `s3://BUCKET[/PREFIX]`.
//! - [`Location`] adds the region, the endpoint, and the addressing style to
//!   an address, and gives the URL of the bucket.
//! - [`S3Endpoint`] holds a location, the credentials, and the HTTP options.
//!   [`S3Endpoint::resolve`] builds one from an address with [`resolve`].
//! - [`Bucket`] is the client of a bucket repository: it gets, puts, and
//!   deletes the objects of the keys of a repository, and lists them. Its
//!   results are [`Object`], [`ObjectStream`], [`PutIfAbsent`], [`Listing`]
//!   with each [`Listed`] object, and [`Upload`].
//!
//! The module reads static key pairs alone. It does not assume a role, run a
//! credential process, or read an SSO token.
//!
//! # Examples
//!
//! ```no_run
//! use ostrya_remote::s3::{Bucket, Environment, S3Endpoint, Settings};
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let endpoint =
//!     S3Endpoint::resolve("s3://builds/exampleos", &Settings::default(), &Environment::Process)
//!         .await?;
//! let bucket = Bucket::new(&endpoint).await?;
//! if let Some(config) = bucket.get("config", 1 << 20).await? {
//!     println!("{}", String::from_utf8_lossy(&config.bytes));
//! }
//! # Ok(()) }
//! ```

mod address;
mod bucket;
mod chain;
mod credentials;
mod endpoint;
mod ini;
mod key;
mod location;
mod sigv4;
mod xml;

pub use address::Address;
pub use bucket::{Bucket, Listed, Listing, Object, ObjectStream, PutIfAbsent, Upload};
pub use chain::{Addressing, Environment, Origin, Resolved, Setting, Settings, resolve};
pub use credentials::Credentials;
pub use endpoint::S3Endpoint;
pub use location::Location;
pub use sigv4::SigV4;

/// The region of a profile that no source gives a region: `us-east-1`.
pub const DEFAULT_REGION: &str = "us-east-1";

/// Returns the message of [`Error::S3`](crate::Error::S3).
///
/// The code `RequestTimeTooSkewed` adds that the clock of the host is not in
/// step with the clock of the server.
pub(crate) fn describe_status(
    status: u16,
    code: Option<&str>,
    message: Option<&str>,
    key: Option<&str>,
) -> String {
    let mut text = format!("S3 status {status}");
    if let Some(code) = code {
        text.push(' ');
        text.push_str(code);
    }
    match key {
        Some(key) => {
            text.push_str(" for the key ");
            text.push_str(key);
        }
        None => text.push_str(" for a request on the bucket"),
    }
    if let Some(message) = message {
        text.push_str(": ");
        text.push_str(message);
    }
    if code == Some("RequestTimeTooSkewed") {
        text.push_str(": the clock of this host is not in step with the clock of the server");
    }
    text
}

#[cfg(test)]
mod tests {
    use crate::Error;

    #[test]
    fn an_s3_error_names_the_status_the_code_the_key_and_the_message() {
        let error = Error::S3 {
            status: 403,
            code: Some("SignatureDoesNotMatch".into()),
            message: Some("The request signature does not match".into()),
            key: Some("repo/config".into()),
        };
        assert_eq!(
            error.to_string(),
            "S3 status 403 SignatureDoesNotMatch for the key repo/config: The request \
             signature does not match"
        );
        let bare = Error::S3 {
            status: 503,
            code: None,
            message: None,
            key: None,
        };
        assert_eq!(
            bare.to_string(),
            "S3 status 503 for a request on the bucket"
        );
        assert_eq!(bare.code(), None);
        assert_eq!(bare.to_message().code, crate::ErrorCode::Internal, "{bare}");
    }

    #[test]
    fn a_skewed_clock_names_the_clock_of_the_host() {
        let error = Error::S3 {
            status: 403,
            code: Some("RequestTimeTooSkewed".into()),
            message: None,
            key: Some("config".into()),
        };
        assert!(
            error.to_string().contains("the clock of this host"),
            "{error}"
        );
    }

    #[test]
    fn a_region_error_names_both_regions() {
        let error = Error::S3Region {
            bucket: "builds".into(),
            region: "us-east-1".into(),
            bucket_region: "eu-central-1".into(),
        };
        let text = error.to_string();
        assert!(text.contains("builds"), "{text}");
        assert!(text.contains("us-east-1"), "{text}");
        assert!(text.contains("set the region to eu-central-1"), "{text}");
        assert_eq!(error.code(), None);
        assert_eq!(error.to_message().message, text);
    }
}
