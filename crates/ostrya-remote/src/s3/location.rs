//! The endpoint, the region, and the addressing style of a bucket
//! repository.

use std::net::Ipv4Addr;

use super::sigv4::{region_refusal, valid_region};
use super::{Address, Addressing, Resolved};
use crate::{Error, Result};

/// The place of a bucket repository: its address, the region of the
/// signature, the endpoint, and the addressing style.
///
/// [`Location::new`] applies these rules:
///
/// - With no endpoint, the endpoint is AWS: `https://s3.REGION.amazonaws.com`.
/// - An endpoint is an `http://` or an `https://` URL with no path, no
///   query, no fragment, and no userinfo. One trailing `/` is allowed.
/// - Path style puts the bucket in the path: `ENDPOINT/BUCKET/PREFIX/...`.
///   Virtual-host style puts the bucket in the host:
///   `https://BUCKET.HOST/PREFIX/...`.
/// - The default style is virtual-host for AWS, and path for an endpoint of
///   the caller. A bucket name that holds a `.` gets path style by default.
///   A style that the caller sets wins.
/// - Virtual-host style is refused for a bucket name that holds a `.` over
///   `https`, because the certificate of the endpoint does not match such a
///   host. It is also refused for an endpoint whose host is an IP address.
///
/// An `http://` endpoint needs
/// [`allow_cleartext_credentials`](ostrya_fetch::FetcherOptions::allow_cleartext_credentials)
/// in the options of the bucket client, because the signature is a
/// credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Location {
    address: Address,
    region: String,
    /// The endpoint in use, with no trailing `/`.
    endpoint: String,
    addressing: Addressing,
}

impl Location {
    /// Returns the location of `address` with the region `region`, the
    /// endpoint `endpoint`, and the addressing style `addressing`.
    ///
    /// `None` for `endpoint` is AWS, and `None` for `addressing` is the
    /// default style. [`Location`] states the rules.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInput`] in these cases:
    ///
    /// - `region` is refused by [`SigV4::new`](super::SigV4::new)
    /// - [`check_base_url`](ostrya_fetch::check_base_url) refuses `endpoint`,
    ///   or `endpoint` has a path. The message holds no userinfo.
    /// - virtual-host style with a bucket name that holds a `.` over `https`
    /// - virtual-host style with an endpoint whose host is an IP address.
    pub fn new(
        address: Address,
        region: &str,
        endpoint: Option<&str>,
        addressing: Option<Addressing>,
    ) -> Result<Location> {
        if !valid_region(region) {
            return Err(Error::InvalidInput(region_refusal(region, "S3 location")));
        }
        let aws = endpoint.is_none();
        let endpoint = match endpoint {
            Some(endpoint) => checked_endpoint(endpoint)?,
            None => format!("https://s3.{region}.amazonaws.com"),
        };
        let addressing = addressing.unwrap_or(if aws && !address.bucket().contains('.') {
            Addressing::Virtual
        } else {
            Addressing::Path
        });
        let location = Location {
            address,
            region: region.to_owned(),
            endpoint,
            addressing,
        };
        if location.addressing == Addressing::Virtual {
            location.check_virtual()?;
        }
        Ok(location)
    }

    /// Returns the location of `address` with the region, the endpoint, and
    /// the addressing style of `resolved`.
    ///
    /// # Errors
    ///
    /// The errors of [`Location::new`]. A refused endpoint names the source
    /// of the endpoint.
    pub fn from_resolved(address: Address, resolved: &Resolved) -> Result<Location> {
        let endpoint = resolved.endpoint.as_ref();
        Location::new(
            address,
            &resolved.region.value,
            endpoint.map(|endpoint| endpoint.value.as_str()),
            resolved.addressing.as_ref().map(|style| style.value),
        )
        .map_err(|e| match (e, endpoint) {
            (Error::InvalidInput(message), Some(endpoint)) if message.contains("endpoint") => {
                Error::InvalidInput(format!("{message} (from {})", endpoint.origin))
            }
            (e, _) => e,
        })
    }

    /// Returns the address of the bucket repository.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Returns the region of the signature.
    pub fn region(&self) -> &str {
        &self.region
    }

    /// Returns the addressing style in use.
    pub fn addressing(&self) -> Addressing {
        self.addressing
    }

    /// Returns the endpoint in use, with no trailing `/`: the endpoint of the
    /// caller, or `https://s3.REGION.amazonaws.com`.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Returns the URL of the bucket: `ENDPOINT/BUCKET` for path style, and
    /// `SCHEME://BUCKET.HOST[:PORT]` for virtual-host style.
    ///
    /// The bucket client sends each request under this URL.
    pub fn bucket_url(&self) -> String {
        let bucket = self.address.bucket();
        match self.addressing {
            Addressing::Path => format!("{}/{bucket}", self.endpoint),
            Addressing::Virtual => {
                let (scheme, authority) = split_scheme(&self.endpoint);
                format!("{scheme}://{bucket}.{authority}")
            }
        }
    }

    /// Returns the base URL of the repository: the URL of the bucket, then
    /// `/` and the prefix if the address has one.
    pub fn repository_url(&self) -> String {
        let prefix = self.address.prefix();
        if prefix.is_empty() {
            self.bucket_url()
        } else {
            format!("{}/{prefix}", self.bucket_url())
        }
    }

    /// Refuses virtual-host style where the host of the bucket cannot carry
    /// it.
    fn check_virtual(&self) -> Result<()> {
        let (scheme, authority) = split_scheme(&self.endpoint);
        if scheme.eq_ignore_ascii_case("https") && self.address.bucket().contains('.') {
            return Err(Error::InvalidInput(format!(
                "S3 location: the bucket name {:?} holds a '.', so virtual-host style over \
                 https names a host that the certificate of the endpoint does not match: use \
                 path style",
                self.address.bucket()
            )));
        }
        let host = match authority.rfind(':') {
            Some(at) if !authority.ends_with(']') => &authority[..at],
            _ => authority,
        };
        if host.starts_with('[') || host.parse::<Ipv4Addr>().is_ok() {
            return Err(Error::InvalidInput(format!(
                "S3 location: the endpoint host {host} is an IP address, so it cannot carry the \
                 bucket name in virtual-host style: use path style"
            )));
        }
        Ok(())
    }
}

/// Checks the endpoint URL `endpoint` and returns it with no trailing `/`.
fn checked_endpoint(endpoint: &str) -> Result<String> {
    ostrya_fetch::check_base_url(endpoint)
        .map_err(|e| Error::InvalidInput(format!("S3 endpoint: {e}")))?;
    let (_, rest) = endpoint
        .split_once("://")
        .expect("a checked base URL has a scheme");
    let path = rest.find('/').map_or("", |at| &rest[at..]);
    if !path.is_empty() && path != "/" {
        return Err(Error::InvalidInput(format!(
            "S3 endpoint: the endpoint {endpoint} has the path {path}: an endpoint has no path"
        )));
    }
    Ok(endpoint.strip_suffix('/').unwrap_or(endpoint).to_owned())
}

/// Splits `url` into its scheme and the rest after `://`.
fn split_scheme(url: &str) -> (&str, &str) {
    url.split_once("://").unwrap_or(("https", url))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn location(
        address: &str,
        endpoint: Option<&str>,
        addressing: Option<Addressing>,
    ) -> Result<Location> {
        Location::new(
            Address::parse(address).unwrap(),
            "eu-central-1",
            endpoint,
            addressing,
        )
    }

    fn refusal(address: &str, endpoint: Option<&str>, addressing: Option<Addressing>) -> String {
        match location(address, endpoint, addressing) {
            Ok(found) => panic!("{address} {endpoint:?}: {found:?}"),
            Err(Error::InvalidInput(message)) => message,
            Err(other) => panic!("{other}"),
        }
    }

    #[test]
    fn aws_is_the_endpoint_when_none_is_set() {
        let aws = location("s3://bucket/repo", None, None).unwrap();
        assert_eq!(aws.endpoint(), "https://s3.eu-central-1.amazonaws.com");
        assert_eq!(aws.addressing(), Addressing::Virtual);
        assert_eq!(
            aws.bucket_url(),
            "https://bucket.s3.eu-central-1.amazonaws.com"
        );
        assert_eq!(
            aws.repository_url(),
            "https://bucket.s3.eu-central-1.amazonaws.com/repo"
        );

        let path = location("s3://bucket/repo", None, Some(Addressing::Path)).unwrap();
        assert_eq!(
            path.bucket_url(),
            "https://s3.eu-central-1.amazonaws.com/bucket"
        );
        assert_eq!(
            path.repository_url(),
            "https://s3.eu-central-1.amazonaws.com/bucket/repo"
        );
    }

    #[test]
    fn the_default_style_follows_the_endpoint_and_the_bucket_name() {
        let cases = [
            ("s3://bucket", None, None, Addressing::Virtual),
            ("s3://my.bucket", None, None, Addressing::Path),
            (
                "s3://bucket",
                Some("http://127.0.0.1:9000"),
                None,
                Addressing::Path,
            ),
            (
                "s3://bucket",
                Some("https://s3.example.com/"),
                None,
                Addressing::Path,
            ),
            (
                "s3://bucket",
                Some("https://s3.example.com"),
                Some(Addressing::Virtual),
                Addressing::Virtual,
            ),
            (
                "s3://bucket",
                None,
                Some(Addressing::Path),
                Addressing::Path,
            ),
            (
                "s3://my.bucket",
                Some("http://s3.example.com"),
                Some(Addressing::Virtual),
                Addressing::Virtual,
            ),
        ];
        for (address, endpoint, set, style) in cases {
            let found = location(address, endpoint, set).unwrap();
            assert_eq!(found.addressing(), style, "{address} {endpoint:?} {set:?}");
        }
    }

    #[test]
    fn the_urls_of_an_endpoint_of_the_caller() {
        let path = location("s3://b-1", Some("http://127.0.0.1:9000/"), None).unwrap();
        assert_eq!(path.endpoint(), "http://127.0.0.1:9000");
        assert_eq!(path.bucket_url(), "http://127.0.0.1:9000/b-1");
        assert_eq!(path.repository_url(), "http://127.0.0.1:9000/b-1");

        let virtual_host = location(
            "s3://b-1/a/b",
            Some("https://s3.example.com:8443"),
            Some(Addressing::Virtual),
        )
        .unwrap();
        assert_eq!(virtual_host.bucket_url(), "https://b-1.s3.example.com:8443");
        assert_eq!(
            virtual_host.repository_url(),
            "https://b-1.s3.example.com:8443/a/b"
        );
    }

    #[test]
    fn an_endpoint_out_of_the_rule_is_refused() {
        for endpoint in [
            "ftp://s3.example.com",
            "https://s3.example.com/path",
            "https://s3.example.com/?x=1",
            "https://key:secret@s3.example.com",
            "https://s3.example.com/#f",
            "https://",
            "s3.example.com",
        ] {
            let message = refusal("s3://bucket", Some(endpoint), None);
            assert!(message.contains("S3 endpoint"), "{endpoint}: {message}");
            assert!(!message.contains("secret"), "{message}");
        }
    }

    #[test]
    fn virtual_host_style_is_refused_where_the_host_cannot_carry_it() {
        let dotted = refusal(
            "s3://my.bucket",
            Some("https://s3.example.com"),
            Some(Addressing::Virtual),
        );
        assert!(dotted.contains("certificate"), "{dotted}");
        let dotted_aws = refusal("s3://my.bucket", None, Some(Addressing::Virtual));
        assert!(dotted_aws.contains("certificate"), "{dotted_aws}");
        for endpoint in [
            "http://127.0.0.1:9000",
            "http://[::1]:9000",
            "http://10.0.0.1",
        ] {
            let message = refusal("s3://bucket", Some(endpoint), Some(Addressing::Virtual));
            assert!(message.contains("IP address"), "{endpoint}: {message}");
        }
    }

    #[test]
    fn a_region_out_of_the_rule_is_refused() {
        let address = Address::parse("s3://bucket").unwrap();
        for region in ["", "eu central", "eu/central"] {
            let err = Location::new(address.clone(), region, None, None).unwrap_err();
            assert!(matches!(err, Error::InvalidInput(_)), "{err}");
        }
    }
}
