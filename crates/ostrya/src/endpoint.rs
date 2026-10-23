//! The resolution of a remote to an [`Endpoint`].
//!
//! [`resolve_pull`] and `resolve_push` read the keys of a remote section of
//! the repository config, read the files that the keys name, and give an
//! [`Endpoint`] that holds all values in memory. The `push` feature gates
//! `resolve_push`. [`EndpointOverrides`] holds the values of the caller. A
//! value of the caller wins over its remote key.
//!
//! With the `s3` feature, [`resolve_pull`] also gives the endpoint of a pull
//! from an `s3://` address, and `resolve_push` the endpoint of a push to an
//! `s3://` address. `resolve_bucket` gives the endpoint of each other writer
//! of a bucket repository, for example the init. They read the AWS
//! credentials and settings from the environment of the process and from the
//! shared AWS files. A build without the feature refuses an `s3://` address.
//! [`pull_address_is_s3`] tells if the address of a pull is an `s3://`
//! address, with no file and no environment.
//!
//! [`Repo::pull`](crate::Repo::pull) calls [`resolve_pull`] with
//! [`PullOptions::overrides`](crate::PullOptions::overrides).
//! [`Repo::remote_fetch_summary_with`](crate::Repo::remote_fetch_summary_with)
//! calls it with the overrides of the caller, and
//! [`Repo::remote_fetch_summary`](crate::Repo::remote_fetch_summary) with
//! the default overrides. A caller that selects its own server opens a
//! [`PullSession`](crate::remote::PullSession) and calls
//! [`Repo::pull_with_session`](crate::Repo::pull_with_session).
//!
//! [`read_token_file`] and [`read_pem_file`] read a token file and a PEM file.
//! [`read_pem_file`] reads at most 1 MiB and one byte. [`read_token_file`]
//! stops at the first LF, and reads at most 1 MiB and one byte. Each error
//! names the key and the path.
//!
//! The trust policy of the remote keys is in the resolvers. [`resolve_pull`]
//! maps `tls-permissive=true` to [`TrustRoots::DangerousAcceptAnyChain`], for
//! an HTTP address and for an `s3://` address. `resolve_push` refuses
//! `tls-permissive=true` for an `https://` address and for an `s3://`
//! address, and `resolve_bucket` refuses it.
//! A caller that builds an [`Endpoint`] itself sets the trust policy of its
//! own.

use std::fmt;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::{Remote, RepoConfig};
use crate::error::{Error, Result};
#[cfg(feature = "push")]
use crate::fetch::{BasicAuth, BearerToken};
use crate::fetch::{ClientIdentity, FetcherOptions, LowSpeed, Proxy, TrustRoots};
use crate::remote::{self, Endpoint, SshAddress, SshOptions};

/// The largest first line of a token file, and the largest PEM file: 1 MiB.
const FILE_CAP: u64 = 1 << 20;

/// The retry count of a pull if the caller names no count.
const PULL_RETRIES: u32 = 5;
/// The number of requests of a pull in flight.
const PULL_OUTSTANDING: usize = 8;
/// The rate in bytes per second at or below which the fetcher stops a
/// transfer, if the caller names no rate.
const DEFAULT_LOW_SPEED_LIMIT: u32 = 1000;
/// The time that the rate can stay at or below the limit, if the caller names
/// no time.
const DEFAULT_LOW_SPEED_TIME: Duration = Duration::from_secs(30);

/// The values of the caller for [`resolve_pull`] and `resolve_push`.
///
/// A field that is `None`, `false`, or empty sets nothing. A field that a
/// remote key backs wins over that key. Each field resolves on its own.
///
/// A resolver refuses a field that applies to the other direction or to the
/// other transport. The refusal names the field by its remote key, or by the
/// option of the `ostrya` command that sets it.
///
/// The [`Debug`] output shows `url` and `s3_endpoint` without their
/// userinfo, and shows `<redacted>` in place of each header value.
///
/// The struct carries no `#[non_exhaustive]`. A caller builds it with
/// `..Default::default()`.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct EndpointOverrides {
    /// The address of a pull. It wins over the keys `pull-url` and `url`.
    ///
    /// `resolve_push` refuses it.
    pub url: Option<String>,
    /// The token file of a push. It wins over the key `push-token-file`.
    ///
    /// [`resolve_pull`] refuses it. `resolve_push` refuses it for an
    /// `s3://` address.
    pub push_token_file: Option<PathBuf>,
    /// The user name of a Basic credential of a push. It wins over the key
    /// `push-user`. The token is the password.
    ///
    /// [`resolve_pull`] refuses it. `resolve_push` refuses it for an
    /// `s3://` address.
    pub push_user: Option<String>,
    /// The PEM file of the trust anchors. It wins over the key `tls-ca-path`.
    pub tls_ca_path: Option<PathBuf>,
    /// The PEM file of the client certificate chain. It wins over the key
    /// `tls-client-cert-path`.
    pub tls_client_cert_path: Option<PathBuf>,
    /// The PEM file of the client key. It wins over the key
    /// `tls-client-key-path`. The key must need no passphrase.
    pub tls_client_key_path: Option<PathBuf>,
    /// The ssh program and its arguments. It goes to
    /// [`SshOptions::command`].
    pub ssh_command: Option<Vec<String>>,
    /// The command that the remote side runs over ssh. For a push, it wins
    /// over the key `receive-command`. For a pull, it wins over the key
    /// `send-command`. It goes to [`SshOptions::remote_command`].
    pub remote_command: Option<String>,
    /// The permission for a credential to go to an `http://` address. No
    /// remote key sets it.
    pub allow_cleartext_credentials: bool,
    /// The extra headers of each HTTP request, as name and value pairs.
    pub http_headers: Vec<(String, String)>,
    /// The number of times that the HTTP client repeats a round after a
    /// retryable failure. A value of 0 turns the retries off.
    pub max_retries: Option<u32>,
    /// The lowest transfer rate in bytes per second. A value of 0 turns the
    /// low-speed check off.
    pub low_speed_limit_bytes: Option<u32>,
    /// The longest time that the rate can stay at the limit or less. A value
    /// of zero turns the low-speed check off.
    pub low_speed_time: Option<Duration>,
    /// The region of the signature of each request to an `s3://` address. It
    /// wins over the key `s3-region`.
    ///
    /// [`resolve_pull`] and `resolve_push` refuse it for another address.
    pub s3_region: Option<String>,
    /// The `http://` or `https://` URL of the S3 server of an `s3://` address.
    /// It wins over the key `s3-endpoint`.
    ///
    /// [`resolve_pull`] and `resolve_push` refuse it for another address.
    pub s3_endpoint: Option<String>,
    /// The addressing style of the bucket of an `s3://` address: `path` or
    /// `virtual`. It wins over the key `s3-addressing`.
    ///
    /// [`resolve_pull`] and `resolve_push` refuse it for another address.
    pub s3_addressing: Option<String>,
    /// The profile of the shared AWS files for an `s3://` address. It wins
    /// over the key `s3-profile`.
    ///
    /// [`resolve_pull`] and `resolve_push` refuse it for another address.
    pub s3_profile: Option<String>,
}

impl fmt::Debug for EndpointOverrides {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let EndpointOverrides {
            url,
            push_token_file,
            push_user,
            tls_ca_path,
            tls_client_cert_path,
            tls_client_key_path,
            ssh_command,
            remote_command,
            allow_cleartext_credentials,
            http_headers,
            max_retries,
            low_speed_limit_bytes,
            low_speed_time,
            s3_region,
            s3_endpoint,
            s3_addressing,
            s3_profile,
        } = self;
        // A url can hold a password, and a header value can be a credential.
        let headers: Vec<(&str, &str)> = http_headers
            .iter()
            .map(|(name, _)| (name.as_str(), "<redacted>"))
            .collect();
        f.debug_struct("EndpointOverrides")
            .field("url", &url.as_deref().map(remote::without_userinfo))
            .field("push_token_file", push_token_file)
            .field("push_user", push_user)
            .field("tls_ca_path", tls_ca_path)
            .field("tls_client_cert_path", tls_client_cert_path)
            .field("tls_client_key_path", tls_client_key_path)
            .field("ssh_command", ssh_command)
            .field("remote_command", remote_command)
            .field("allow_cleartext_credentials", allow_cleartext_credentials)
            .field("http_headers", &headers)
            .field("max_retries", max_retries)
            .field("low_speed_limit_bytes", low_speed_limit_bytes)
            .field("low_speed_time", low_speed_time)
            .field("s3_region", s3_region)
            .field(
                "s3_endpoint",
                &s3_endpoint.as_deref().map(remote::without_userinfo),
            )
            .field("s3_addressing", s3_addressing)
            .field("s3_profile", s3_profile)
            .finish()
    }
}

/// Returns the refusal of an endpoint that is neither ssh nor HTTP, for
/// example an S3 endpoint, by `operation`.
pub(crate) fn neither_ssh_nor_http(operation: &str) -> Error {
    Error::Unsupported(format!(
        "{operation} takes an ssh or an HTTP endpoint, and this endpoint is neither"
    ))
}

/// The environment that the resolution of an `s3://` address reads.
///
/// With the `s3` feature, it is the environment of
/// `ostrya_remote::s3::resolve`. A build without the feature reads no
/// environment for an `s3://` address, because it refuses the address.
#[cfg(feature = "s3")]
pub(crate) type S3Environment = remote::s3::Environment;
/// The environment that the resolution of an `s3://` address reads.
///
/// A build without the `s3` feature refuses an `s3://` address, so it reads
/// no environment for it.
#[cfg(not(feature = "s3"))]
pub(crate) type S3Environment = ();

/// Resolves the remote `remote` to the endpoint of a pull.
///
/// # Address
///
/// The address is the first of these that is set: [`EndpointOverrides::url`],
/// the key `pull-url`, and the key `url`. An address that starts with
/// `s3://` is the address of a bucket repository. An address that starts with
/// `ssh://`, or that holds no `://`, is an ssh address, and
/// [`SshAddress::parse`] reads it. Each other address is an HTTP address, and
/// goes to the fetcher as written. The key `url` cannot hold an ssh address
/// or an `s3://` address, because the `ostree` command also reads it. The
/// function ignores the keys `contenturl` and `metalink`.
///
/// A `url` of the caller replaces the address alone. The TLS keys, the key
/// `proxy`, the ssh keys, and the S3 keys of the section still apply.
///
/// The S3 keys are `s3-region`, `s3-endpoint`, `s3-addressing`, and
/// `s3-profile`. The function refuses a section that sets one of them if
/// neither `pull-url` nor `push-url` of the section holds an `s3://` address.
/// It makes this check for each address.
///
/// # HTTP address
///
/// The function gives [`Endpoint::Http`] with these values:
///
/// - The trust anchors are the PEM file of `tls_ca_path` or of the key
///   `tls-ca-path`. If the caller gives no `tls_ca_path` and the section sets
///   `tls-permissive=true`, the trust setting is
///   [`TrustRoots::DangerousAcceptAnyChain`], and the function does not read
///   the key `tls-ca-path`. With neither, the trust setting is
///   [`TrustRoots::System`].
/// - The client certificate and its key come from `tls_client_cert_path` and
///   `tls_client_key_path`, or from their keys. The key must need no
///   passphrase.
/// - The proxy is the key `proxy`. An empty or absent key, or no section,
///   gives [`Proxy::Environment`].
/// - The headers and the cleartext permission are the values of the caller.
/// - The retry count is `max_retries`, or 5. A value of 0 turns the retries
///   off.
/// - The number of requests in flight is 8.
/// - The low-speed rule takes 1000 bytes per second for 30 seconds in place
///   of a field left `None`. A zero in either field turns the rule off.
///
/// No field of [`EndpointOverrides`] sets the other fields of
/// [`FetcherOptions`], for example the timeouts or the number of requests in
/// flight. A caller changes them in the returned endpoint.
///
/// # ssh address
///
/// The function gives [`Endpoint::Ssh`]. `ssh_command` gives
/// [`SshOptions::command`], and the key `ssh-command` gives
/// [`SshOptions::config_command`]. `remote_command`, or else the key
/// `send-command`, gives [`SshOptions::remote_command`].
///
/// # S3 address
///
/// The address `s3://BUCKET[/PREFIX]` names a bucket repository. A build
/// with the `s3` feature gives `Endpoint::S3` with these values:
///
/// - The region, the endpoint, the addressing style, and the profile are the
///   fields `s3_region`, `s3_endpoint`, `s3_addressing`, and `s3_profile` of
///   the caller, else the keys of the same names. `S3Endpoint::resolve` of
///   `ostrya_remote::s3` gives each setting that neither one sets, and the
///   key pair, from the environment of the process, from the shared AWS
///   files, and from the defaults. `ostrya_remote::s3::resolve` states the
///   order of these sources.
/// - The HTTP options are the options of an HTTP address in the list
///   above. `S3Endpoint::pull_options` adds the mirror of the bucket
///   repository, the signer, and no redirect when the pull opens its
///   session.
///
/// The function ignores the keys `ssh-command` and `send-command` for an
/// `s3://` address.
///
/// # Errors
///
/// The function makes each refusal that needs no file before it reads a file.
///
/// - [`Error::InvalidInput`] if the caller sets `push_token_file` or
///   `push_user`.
/// - [`Error::Pull`] if `config` holds no section for `remote` and the caller
///   gives no `url`, or if the section has neither `pull-url` nor `url`.
/// - [`Error::Pull`] if the key `url` holds an ssh address or an `s3://`
///   address. The message shows the value without the text up to its last
///   `@`.
/// - [`Error::Pull`] if the section sets an S3 key, and neither `pull-url`
///   nor `push-url` holds an `s3://` address. The message names the key.
/// - [`Error::InvalidInput`] with the text of the parser if an ssh address is
///   malformed.
/// - [`Error::InvalidInput`] for an HTTP address or an ssh address if the
///   caller sets `s3_region`, `s3_endpoint`, `s3_addressing`, or
///   `s3_profile`. The message names the first such field by its key.
/// - [`Error::InvalidInput`] for an HTTP address or an `s3://` address if the
///   caller sets `ssh_command` or `remote_command`.
/// - [`Error::Pull`] for an HTTP address or an `s3://` address if a client
///   certificate has no key, or a key has no certificate.
/// - [`Error::Unsupported`] if the key `proxy` has white space at its start
///   or its end.
/// - [`Error::InvalidInput`] for an ssh address if the caller sets a field of
///   an HTTP address: a TLS path, `allow_cleartext_credentials`,
///   `http_headers`, a `max_retries` above 0, or a low-speed field. The
///   message names the first such field and shows the address without its
///   user.
/// - [`Error::Unsupported`] for an `s3://` address in a build without the
///   `s3` feature. The message names the feature.
/// - [`Error::InvalidInput`] for an `s3://` address if the addressing style
///   is neither `path` nor `virtual`.
/// - For an `s3://` address, the errors of `S3Endpoint::resolve`. A refused
///   address, a refused setting, and no key pair are
///   [`Error::InvalidInput`]. A shared AWS file that exists and cannot be
///   read is [`Error::Io`].
/// - [`Error::InvalidInput`] for an `s3://` address if the endpoint is
///   `http://`, and the caller does not set `allow_cleartext_credentials`.
///   The signature of each request would go to the server in cleartext. The
///   check comes after the read of the shared AWS files, because the
///   endpoint can come from them.
/// - The errors of [`read_pem_file`].
/// - [`Error::Core`] if a key that the function reads holds a malformed
///   escape sequence, or if `tls-permissive` is not a boolean.
pub async fn resolve_pull(
    config: Option<&RepoConfig>,
    remote: &str,
    overrides: EndpointOverrides,
) -> Result<Endpoint> {
    resolve_pull_in(config, remote, overrides, &S3Environment::default()).await
}

/// Resolves the remote `remote` to the endpoint of a pull, as
/// [`resolve_pull`] does, with `env` as the environment of an `s3://`
/// address.
#[cfg_attr(not(feature = "s3"), allow(unused_variables))]
pub(crate) async fn resolve_pull_in(
    config: Option<&RepoConfig>,
    remote: &str,
    overrides: EndpointOverrides,
    env: &S3Environment,
) -> Result<Endpoint> {
    let mut o = overrides;
    let section = config.and_then(|config| config.remote(remote));
    let push_fields = [
        ("push-token-file", o.push_token_file.is_some()),
        ("push-user", o.push_user.is_some()),
    ];
    if let Some((name, _)) = push_fields.iter().find(|(_, set)| *set) {
        return Err(Error::InvalidInput(format!(
            "{name} applies to a push, and this is a pull"
        )));
    }
    let address = pull_address(section.as_ref(), remote, o.url.take())?;
    check_s3_keys(remote, section.as_ref())?;
    let endpoint = match address {
        PullAddress::Endpoint(endpoint) => endpoint,
        PullAddress::S3(address) => {
            #[cfg(feature = "s3")]
            return Box::pin(pull_s3(remote, section.as_ref(), &address, o, env)).await;
            #[cfg(not(feature = "s3"))]
            return Err(Error::Unsupported(format!(
                "the pull address '{}' is an s3:// address, and this build of ostrya has no S3 \
                 support: turn on the feature s3 of ostrya",
                remote::without_userinfo(&address)
            )));
        }
    };
    match endpoint {
        Endpoint::Http(http) => pull_http(remote, section.as_ref(), http, o).await,
        Endpoint::Ssh { address, .. } => {
            if let Some(name) = s3_field(&o) {
                return Err(Error::InvalidInput(format!(
                    "{name} applies to a pull from an s3:// address, and '{}' is an ssh address",
                    address.without_user()
                )));
            }
            if let Some(name) = http_field(&o) {
                return Err(Error::InvalidInput(format!(
                    "{name} applies to a pull over HTTP, and '{}' is an ssh address",
                    address.without_user()
                )));
            }
            let (config_command, remote_command) = match &section {
                Some(section) => (
                    section.ssh_command()?,
                    match o.remote_command {
                        Some(command) => Some(command),
                        None => section.send_command()?,
                    },
                ),
                None => (None, o.remote_command),
            };
            Ok(Endpoint::Ssh {
                address,
                options: SshOptions {
                    command: o.ssh_command,
                    config_command,
                    remote_command,
                },
            })
        }
        _ => Err(neither_ssh_nor_http("a pull")),
    }
}

/// The address of a pull.
// The endpoint variant is much larger than the S3 variant. A pull resolves
// one address, so a box saves no work, and the variant stays inline.
#[allow(clippy::large_enum_variant)]
enum PullAddress {
    /// An ssh or an HTTP address, as an endpoint with default options.
    Endpoint(Endpoint),
    /// An `s3://` address, as written.
    S3(String),
}

/// Returns the address of a pull of `remote`, from `url` of the caller, or
/// else from `section`.
fn pull_address(
    section: Option<&Remote<'_>>,
    remote: &str,
    url: Option<String>,
) -> Result<PullAddress> {
    if let Some(url) = url {
        return parse_pull_address(&url);
    }
    let section =
        section.ok_or_else(|| Error::Pull(format!("no remote '{remote}' is configured")))?;
    if let Some(pull_url) = section.pull_url()? {
        return parse_pull_address(&pull_url);
    }
    match section.url()? {
        Some(url) if is_s3(&url) => Err(Error::Pull(format!(
            "remote '{remote}': url '{}' is an s3:// address; the port reads an s3:// \
             address from pull-url alone",
            remote::without_userinfo(&url)
        ))),
        Some(url) if is_ssh(&url) && is_ssh_address(&url) => Err(Error::Pull(format!(
            "remote '{remote}': url '{}' is an ssh address; the port reads an ssh \
             address from pull-url alone",
            remote::without_userinfo(&url)
        ))),
        Some(url) => Ok(PullAddress::Endpoint(Endpoint::Http(FetcherOptions::new(
            url,
        )))),
        None => Err(Error::Pull(format!(
            "remote '{remote}' has no pull-url and no url"
        ))),
    }
}

/// Returns `Some(true)` if the address of a pull of `remote` is an `s3://`
/// address, `Some(false)` if it is an HTTP or an ssh address, and `None` if
/// [`resolve_pull`] refuses the address.
///
/// The address is the one that [`resolve_pull`] reads: `url`, else the key
/// `pull-url` of the section of `remote` in `config`, else the key `url` of
/// the section. A caller gives the value of [`EndpointOverrides::url`] in
/// `url`. A caller can so refuse an option that applies to an `s3://`
/// address alone before it resolves the endpoint. With `None`, the caller
/// lets [`resolve_pull`] report the refusal.
///
/// The function reads `config` alone, and it reads no file and no
/// environment. [`resolve_pull`] refuses no section and no `url`, a section
/// with neither `pull-url` nor `url`, an `s3://` address in the key `url`, an
/// address that does not parse, and a key that holds a malformed escape
/// sequence. The result does not depend on the `s3` feature.
pub fn pull_address_is_s3(
    config: Option<&RepoConfig>,
    remote: &str,
    url: Option<&str>,
) -> Option<bool> {
    let section = config.and_then(|config| config.remote(remote));
    match pull_address(section.as_ref(), remote, url.map(str::to_owned)) {
        Ok(PullAddress::S3(_)) => Some(true),
        Ok(PullAddress::Endpoint(_)) => Some(false),
        Err(_) => None,
    }
}

/// Returns `true` if `value` is an `s3://` address.
fn is_s3(value: &str) -> bool {
    value.starts_with("s3://")
}

/// Returns `true` if a pull reads `value` as an ssh address: it starts with
/// `ssh://`, or it holds no `://`.
fn is_ssh(value: &str) -> bool {
    value.starts_with("ssh://") || !value.contains("://")
}

/// Returns `true` if `value` in the key `url` is an ssh address.
///
/// The caller gives a `value` for which [`is_ssh`] returns `true`. The value is
/// an ssh address if it starts with `ssh://` or if the parser accepts it.
fn is_ssh_address(value: &str) -> bool {
    value.starts_with("ssh://") || SshAddress::parse(value).is_ok()
}

/// Parses the address `value` of the caller or of `pull-url`.
///
/// # Errors
///
/// - [`Error::InvalidInput`] with the text of the parser if `value` is a
///   malformed ssh address.
fn parse_pull_address(value: &str) -> Result<PullAddress> {
    if is_s3(value) {
        return Ok(PullAddress::S3(value.to_owned()));
    }
    if !is_ssh(value) {
        return Ok(PullAddress::Endpoint(Endpoint::Http(FetcherOptions::new(
            value,
        ))));
    }
    let address = SshAddress::parse(value).map_err(|e| match e {
        remote::Error::InvalidInput(msg) => Error::InvalidInput(msg),
        other => Error::Remote(other),
    })?;
    Ok(PullAddress::Endpoint(Endpoint::Ssh {
        address,
        options: SshOptions::default(),
    }))
}

/// Refuses an S3 key of `section`, the section of `remote`, if neither
/// `pull-url` nor `push-url` of the section holds an `s3://` address.
fn check_s3_keys(remote: &str, section: Option<&Remote<'_>>) -> Result<()> {
    let Some(section) = section else {
        return Ok(());
    };
    let keys = [
        ("s3-region", section.s3_region()?),
        ("s3-endpoint", section.s3_endpoint()?),
        ("s3-addressing", section.s3_addressing()?),
        ("s3-profile", section.s3_profile()?),
    ];
    let Some((name, _)) = keys.iter().find(|(_, value)| value.is_some()) else {
        return Ok(());
    };
    let s3 = |value: Option<String>| value.is_some_and(|value| is_s3(&value));
    if s3(section.pull_url()?) || s3(section.push_url()?) {
        return Ok(());
    }
    Err(Error::Pull(format!(
        "remote '{remote}': {name} applies to an s3:// address, and neither pull-url nor \
         push-url holds one"
    )))
}

/// Returns the name of the first field of `o` that applies to an `s3://`
/// address alone, or `None` if `o` sets no such field. Each name is the
/// remote key of the field.
fn s3_field(o: &EndpointOverrides) -> Option<&'static str> {
    let set = [
        ("s3-region", o.s3_region.is_some()),
        ("s3-endpoint", o.s3_endpoint.is_some()),
        ("s3-addressing", o.s3_addressing.is_some()),
        ("s3-profile", o.s3_profile.is_some()),
    ];
    set.iter().find(|(_, set)| *set).map(|(name, _)| *name)
}

/// Completes `http`, the options of an HTTP pull of `remote`, from `o` and
/// the keys of `section`.
async fn pull_http(
    remote: &str,
    section: Option<&Remote<'_>>,
    mut http: FetcherOptions,
    o: EndpointOverrides,
) -> Result<Endpoint> {
    // Each name is the remote key of the field.
    let ssh_fields = [
        ("ssh-command", o.ssh_command.is_some()),
        ("send-command", o.remote_command.is_some()),
    ];
    if let Some((name, _)) = ssh_fields.iter().find(|(_, set)| *set) {
        return Err(Error::InvalidInput(format!(
            "{name} applies to a pull over ssh, and this pull runs over HTTP"
        )));
    }
    if let Some(name) = s3_field(&o) {
        return Err(Error::InvalidInput(format!(
            "{name} applies to a pull from an s3:// address, and this pull runs over HTTP"
        )));
    }
    PullHttp::read(remote, section, o)?.apply(&mut http).await?;
    Ok(Endpoint::Http(http))
}

/// Completes the endpoint of a pull of `remote` from the `s3://` address
/// `address`, from `o`, the keys of `section`, and `env`.
#[cfg(feature = "s3")]
async fn pull_s3(
    remote: &str,
    section: Option<&Remote<'_>>,
    address: &str,
    o: EndpointOverrides,
    env: &S3Environment,
) -> Result<Endpoint> {
    // Each name is the remote key of the field.
    let ssh_fields = [
        ("ssh-command", o.ssh_command.is_some()),
        ("send-command", o.remote_command.is_some()),
    ];
    if let Some((name, _)) = ssh_fields.iter().find(|(_, set)| *set) {
        return Err(Error::InvalidInput(format!(
            "{name} applies to a pull over ssh, and this pull reads an s3:// address"
        )));
    }
    let refusals = S3Refusals {
        invalid: Error::InvalidInput,
        remote: Error::Pull,
    };
    s3_endpoint(remote, section, address, o, env, refusals).await
}

/// The errors of the refusals of [`s3_endpoint`].
#[cfg(feature = "s3")]
struct S3Refusals {
    /// The error of a value that the caller or a key gives.
    invalid: fn(String) -> Error,
    /// The error of a remote whose keys do not go together.
    remote: fn(String) -> Error,
}

/// Completes the S3 endpoint of the `s3://` address `address` of `remote`,
/// from the S3 fields and the HTTP fields of `o`, the keys of `section`, and
/// `env`.
///
/// The call reads no ssh field of `o`. It refuses an addressing style other
/// than `path` and `virtual`, and an `http://` endpoint with no
/// `allow_cleartext_credentials`.
#[cfg(feature = "s3")]
async fn s3_endpoint(
    remote: &str,
    section: Option<&Remote<'_>>,
    address: &str,
    mut o: EndpointOverrides,
    env: &S3Environment,
    refusals: S3Refusals,
) -> Result<Endpoint> {
    use remote::s3::{Addressing, S3Endpoint, Settings};

    let region = or_key(o.s3_region.take(), section, |s| s.s3_region())?;
    let endpoint = or_key(o.s3_endpoint.take(), section, |s| s.s3_endpoint())?;
    let addressing = or_key(o.s3_addressing.take(), section, |s| s.s3_addressing())?;
    let profile = or_key(o.s3_profile.take(), section, |s| s.s3_profile())?;
    let addressing = match addressing {
        Some(name) => Some(Addressing::from_name(&name).ok_or_else(|| {
            (refusals.invalid)(format!(
                "s3-addressing '{name}' is neither path nor virtual"
            ))
        })?),
        None => None,
    };
    let settings = Settings {
        region,
        endpoint,
        addressing,
        profile,
    };
    let http = PullHttp::read(remote, section, o).map_err(|e| match e {
        Error::Pull(msg) => (refusals.remote)(msg),
        other => other,
    })?;
    let mut endpoint = S3Endpoint::resolve(address, &settings, env)
        .await
        .map_err(|e| match e {
            remote::Error::InvalidInput(msg) => (refusals.invalid)(msg),
            remote::Error::Io(e) => Error::Io(e),
            other => Error::Remote(other),
        })?;
    let url = endpoint.location.endpoint();
    let cleartext = url
        .get(..7)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http://"));
    if cleartext && !http.allow_cleartext_credentials {
        return Err((refusals.invalid)(format!(
            "the S3 endpoint '{url}' is http://, so the signature of each request would \
             travel in cleartext: use https, or set allow-cleartext-credentials"
        )));
    }
    http.apply(&mut endpoint.http).await?;
    Ok(Endpoint::S3(endpoint))
}

/// Returns `value` of the caller if it is set, else the key that `read`
/// reads from `section`.
#[cfg(feature = "s3")]
fn or_key(
    value: Option<String>,
    section: Option<&Remote<'_>>,
    read: impl FnOnce(&Remote<'_>) -> Result<Option<String>>,
) -> Result<Option<String>> {
    match (value, section) {
        (Some(value), _) => Ok(Some(value)),
        (None, Some(section)) => read(section),
        (None, None) => Ok(None),
    }
}

/// The HTTP options of a pull that the fields of the caller and the keys of
/// a remote give, before the pull reads a PEM file.
///
/// An HTTP address and an `s3://` address take the same options.
struct PullHttp {
    /// `true` if the section sets `tls-permissive=true` and the caller gives
    /// no CA path.
    any_chain: bool,
    /// The PEM file of the trust anchors.
    ca_path: Option<PathBuf>,
    /// The PEM files of the client certificate chain and of its key.
    client_files: Option<(PathBuf, PathBuf)>,
    proxy: Proxy,
    headers: Vec<(String, String)>,
    allow_cleartext_credentials: bool,
    max_retries: Option<u32>,
    low_speed_limit_bytes: Option<u32>,
    low_speed_time: Option<Duration>,
}

impl PullHttp {
    /// Reads the HTTP fields of `o` and the HTTP keys of `section`, the
    /// section of `remote`.
    ///
    /// The call reads no file. It refuses a client certificate with no key, a
    /// key with no certificate, and a key `proxy` with white space at its
    /// start or its end.
    fn read(
        remote: &str,
        section: Option<&Remote<'_>>,
        mut o: EndpointOverrides,
    ) -> Result<PullHttp> {
        // `tls-permissive` keeps the host name check and ignores
        // `tls-ca-path`. Both facts are observed on the `ostree` command: a
        // CA that signed nothing in the chain works, and a path that names an
        // absent file works too. So the function does not read the path, and
        // an absent file is no failure. `DangerousAcceptAnyChain` keeps the
        // name check and takes the chain as presented. A CA path of the
        // caller wins over the key.
        //
        // `DangerousAcceptAnyChain` also drops the expiry check. That part is
        // a reading of ostrya, with no observation behind it. A peer
        // verification that ignores the CA path is libcurl peer verification
        // turned off, and that setting also drops the validity dates.
        let mut any_chain = false;
        let ca_path = match (o.tls_ca_path, section) {
            (Some(path), _) => Some(path),
            (None, Some(section)) if section.tls_permissive()? => {
                any_chain = true;
                None
            }
            (None, Some(section)) => section.tls_ca_path()?.map(PathBuf::from),
            (None, None) => None,
        };
        if let Some(section) = section {
            if o.tls_client_cert_path.is_none() {
                o.tls_client_cert_path = section.tls_client_cert_path()?.map(PathBuf::from);
            }
            if o.tls_client_key_path.is_none() {
                o.tls_client_key_path = section.tls_client_key_path()?.map(PathBuf::from);
            }
        }
        let client_files = match (o.tls_client_cert_path, o.tls_client_key_path) {
            (Some(cert), Some(key)) => Some((cert, key)),
            (None, None) => None,
            _ => {
                return Err(Error::Pull(format!(
                    "remote '{remote}': a client certificate needs both \
                     tls-client-cert-path and tls-client-key-path"
                )));
            }
        };
        let proxy = match section {
            Some(section) => remote_proxy(remote, section)?,
            None => Proxy::Environment,
        };
        Ok(PullHttp {
            any_chain,
            ca_path,
            client_files,
            proxy,
            headers: o.http_headers,
            allow_cleartext_credentials: o.allow_cleartext_credentials,
            max_retries: o.max_retries,
            low_speed_limit_bytes: o.low_speed_limit_bytes,
            low_speed_time: o.low_speed_time,
        })
    }

    /// Reads the PEM files, and sets the options in `http`.
    async fn apply(self, http: &mut FetcherOptions) -> Result<()> {
        if self.any_chain {
            http.tls.roots = TrustRoots::DangerousAcceptAnyChain;
        }
        if let Some(path) = self.ca_path {
            http.tls.roots = TrustRoots::Pem(read_pem_file("tls-ca-path", &path).await?);
        }
        http.tls.client_identity = match self.client_files {
            Some((cert, key)) => Some(client_identity(&cert, &key).await?),
            None => None,
        };
        http.headers = self.headers;
        http.allow_cleartext_credentials = self.allow_cleartext_credentials;
        http.proxy = self.proxy;
        http.max_retries = self.max_retries.unwrap_or(PULL_RETRIES);
        http.max_outstanding = PULL_OUTSTANDING;
        http.low_speed = low_speed(self.low_speed_limit_bytes, self.low_speed_time);
        Ok(())
    }
}

/// Resolves `remote_or_address` to the endpoint of a push.
///
/// # Address
///
/// A value with a `:` or a `/` is an address, by the rule of
/// [`is_push_address`](crate::is_push_address). An address that starts with
/// `s3://` is the address of a bucket repository. [`Endpoint::parse`] reads
/// each other address. The function reads no configuration for an address.
/// Each other value is the name of a remote section of `config`. The address
/// of the section is its key `push-url`. If `push-url` is absent, a key `url`
/// that starts with `http://` or `https://` is the address. The function
/// reads `url` only if `push-url` is absent. The key `url` cannot hold an
/// `s3://` address, because the `ostree` command also reads it.
///
/// The S3 keys are `s3-region`, `s3-endpoint`, `s3-addressing`, and
/// `s3-profile`. For a remote name, the function refuses a section that sets
/// one of them if neither `pull-url` nor `push-url` of the section holds an
/// `s3://` address.
///
/// # HTTP address
///
/// The function gives [`Endpoint::Http`] with these values:
///
/// - The keys `push-token-file`, `push-user`, `tls-ca-path`,
///   `tls-client-cert-path`, and `tls-client-key-path` fill each field of
///   `overrides` that is `None`. A relative path stays relative to the
///   current directory of the process.
/// - The token of the token file and a `push_user` give
///   [`basic_auth`](FetcherOptions::basic_auth). The token alone gives
///   [`bearer_token`](FetcherOptions::bearer_token).
/// - The trust anchors and the client identity are the PEM files. The client
///   key must need no passphrase. For an `http://` address, the function
///   reads no PEM file, because the push uses no TLS.
/// - The proxy is the key `proxy`. An empty or absent key, or no section,
///   gives [`Proxy::Environment`].
/// - The headers, the cleartext permission, and the retry count are the
///   values of the caller. A retry count of `None` keeps the default of
///   [`FetcherOptions`]. The function does not refuse an `Authorization`
///   header beside the token.
///   [`PushSession::prepare`](crate::remote::PushSession::prepare) refuses
///   the pair when it builds the HTTP client.
/// - With no low-speed field, the push has no low-speed rule. With one
///   field, the other field takes 1000 bytes per second or 30 seconds. A zero
///   in either field turns the rule off.
///
/// No field of [`EndpointOverrides`] sets the other fields of
/// [`FetcherOptions`], for example the timeouts or the number of requests in
/// flight. A caller changes them in the returned endpoint.
///
/// # ssh address
///
/// The function gives [`Endpoint::Ssh`]. `ssh_command` gives
/// [`SshOptions::command`], and the key `ssh-command` gives
/// [`SshOptions::config_command`]. `remote_command`, or else the key
/// `receive-command`, gives [`SshOptions::remote_command`]. The function does
/// not read the HTTP keys of the section.
///
/// # S3 address
///
/// The address `s3://BUCKET[/PREFIX]` names a bucket repository. A build
/// with the `s3` feature gives `Endpoint::S3` with the values that
/// [`resolve_pull`] gives for the same address: the region, the endpoint,
/// the addressing style, and the profile of the fields and the keys, the
/// settings and the key pair of the environment and of the shared AWS
/// files, and the HTTP options of the TLS keys, the key `proxy`, and the
/// HTTP fields. The push takes the retry count, the number of requests in
/// flight, and the low-speed rule of a pull. [`Repo::push`](crate::Repo::push)
/// writes the bucket repository through the bucket client of the endpoint.
///
/// The signer gives the credential of each request, so the function refuses
/// the fields and the keys `push-token-file` and `push-user`. It ignores the
/// keys `ssh-command`, `send-command`, and `receive-command`.
///
/// # Errors
///
/// The function makes each refusal that needs no file before it reads a file.
/// Each refusal of the list is [`Error::Remote`] with
/// [`InvalidInput`](crate::remote::Error::InvalidInput):
///
/// - The caller sets `url`.
/// - `config` holds no section for the name, or the section has no push
///   address. The message shows a `url` that is no push address without the
///   text up to its last `@`. A `url` that holds an `s3://` address is no
///   push address.
/// - The section sets an S3 key, and neither `pull-url` nor `push-url` holds
///   an `s3://` address. The message names the key.
/// - The address is HTTP or ssh, and the caller sets `s3_region`,
///   `s3_endpoint`, `s3_addressing`, or `s3_profile`. The message names the
///   first such field by its key.
/// - The address is `https://` or `s3://`, and the section sets
///   `tls-permissive=true`, because a push verifies the certificate chain of
///   the server.
/// - The address is HTTP or `s3://`, and the caller sets `ssh_command` or
///   `remote_command`.
/// - The address is `s3://`, and the caller or the section sets
///   `push-token-file` or `push-user`.
/// - A client certificate has no key, or a key has no certificate.
/// - A `push_user` has no token file, or is empty, or holds `:`.
/// - The address is `http://`, the push has a token file, and the caller
///   does not set `allow_cleartext_credentials`. The token would go to the
///   server in cleartext. This refusal comes before the read of the key
///   `proxy`.
/// - The address is ssh, and the caller sets a field of an HTTP address. The
///   message names the first such field and shows the address without its
///   user.
/// - The address is `s3://`, and its addressing style is neither `path` nor
///   `virtual`.
/// - The address is `s3://`, the endpoint is `http://`, and the caller does
///   not set `allow_cleartext_credentials`. The signature of each request
///   would go to the server in cleartext. The check comes after the read of
///   the shared AWS files, because the endpoint can come from them.
/// - For an `s3://` address, a refusal of `S3Endpoint::resolve` of
///   `ostrya_remote::s3`: a refused address, a refused setting, or no key
///   pair.
///
/// These errors are also possible:
///
/// - [`Error::Remote`] with the error of [`Endpoint::parse`] if the address
///   does not parse.
/// - [`Error::Unsupported`] if the key `proxy` has white space at its start
///   or its end.
/// - [`Error::Unsupported`] for an `s3://` address in a build without the
///   `s3` feature. The message names the feature.
/// - [`Error::Io`] for an `s3://` address if a shared AWS file exists and
///   cannot be read.
/// - The errors of [`read_token_file`] and [`read_pem_file`].
/// - [`Error::Core`] if a key that the function reads holds a malformed
///   escape sequence, or if `tls-permissive` is not a boolean.
#[cfg(feature = "push")]
pub async fn resolve_push(
    config: Option<&RepoConfig>,
    remote_or_address: &str,
    overrides: EndpointOverrides,
) -> Result<Endpoint> {
    resolve_push_in(
        config,
        remote_or_address,
        overrides,
        &S3Environment::default(),
    )
    .await
}

/// Resolves `remote_or_address` to the endpoint of a push, as
/// [`resolve_push`] does, with `env` as the environment of an `s3://`
/// address.
#[cfg(feature = "push")]
#[cfg_attr(not(feature = "s3"), allow(unused_variables))]
pub(crate) async fn resolve_push_in(
    config: Option<&RepoConfig>,
    remote_or_address: &str,
    overrides: EndpointOverrides,
    env: &S3Environment,
) -> Result<Endpoint> {
    let remote = remote_or_address;
    if overrides.url.is_some() {
        return Err(push_invalid("url applies to a pull, and this is a push"));
    }
    let (section, address) = if crate::is_push_address(remote) {
        (None, remote.to_owned())
    } else {
        let section = config
            .and_then(|config| config.remote(remote))
            .ok_or_else(|| push_invalid(format!("no remote '{remote}' is configured")))?;
        check_s3_keys(remote, Some(&section)).map_err(|e| match e {
            Error::Pull(msg) => push_invalid(msg),
            other => other,
        })?;
        let address = match section.push_url()? {
            Some(push_url) => push_url,
            None => match section.url()? {
                Some(url) if url.starts_with("http://") || url.starts_with("https://") => url,
                Some(url) if is_s3(&url) => {
                    return Err(push_invalid(format!(
                        "remote '{remote}' has no push-url, and its url '{}' is an s3:// \
                         address; the port reads an s3:// address from push-url alone",
                        remote::without_userinfo(&url)
                    )));
                }
                Some(url) => {
                    return Err(push_invalid(format!(
                        "remote '{remote}' has no push-url, and its url '{}' is no push address",
                        remote::without_userinfo(&url)
                    )));
                }
                None => {
                    return Err(push_invalid(format!(
                        "remote '{remote}' has no push-url and no url"
                    )));
                }
            },
        };
        (Some(section), address)
    };
    if is_s3(&address) {
        // The name of an address in a message is the address without its
        // userinfo, which can hold a key pair.
        #[cfg(feature = "s3")]
        let name = match section {
            Some(_) => std::borrow::Cow::Borrowed(remote),
            None => remote::without_userinfo(remote),
        };
        #[cfg(feature = "s3")]
        return Box::pin(push_s3(&name, section.as_ref(), &address, overrides, env)).await;
        #[cfg(not(feature = "s3"))]
        return Err(Error::Unsupported(format!(
            "the push address '{}' is an s3:// address, and this build of ostrya has no S3 \
             support: turn on the feature s3 of ostrya",
            remote::without_userinfo(&address)
        )));
    }
    match Endpoint::parse(&address)? {
        Endpoint::Http(http) => {
            if let Some(name) = s3_field(&overrides) {
                return Err(push_invalid(format!(
                    "{name} applies to an s3:// address, and '{}' is an HTTP address",
                    remote::without_userinfo(&address)
                )));
            }
            push_http(remote, section.as_ref(), &address, http, overrides).await
        }
        Endpoint::Ssh { address, .. } => {
            if let Some(name) = s3_field(&overrides) {
                return Err(push_invalid(format!(
                    "{name} applies to an s3:// address, and '{}' is an ssh address",
                    address.without_user()
                )));
            }
            push_ssh(section.as_ref(), address, overrides)
        }
        _ => Err(neither_ssh_nor_http("a push")),
    }
}

/// Completes the endpoint of a push of `remote` to the `s3://` address
/// `address`, from `o`, the keys of `section`, and `env`.
///
/// [`resolve_bucket`] gives the endpoint of each other writer of a bucket
/// repository through this function, so each writer makes the refusals of a
/// push.
#[cfg(feature = "s3")]
async fn push_s3(
    remote: &str,
    section: Option<&Remote<'_>>,
    address: &str,
    o: EndpointOverrides,
    env: &S3Environment,
) -> Result<Endpoint> {
    let shown = remote::without_userinfo(address);
    let (token_key, user_key) = match section {
        Some(section) => (
            section.push_token_file()?.is_some(),
            section.push_user()?.is_some(),
        ),
        None => (false, false),
    };
    let http_fields = [
        ("push-token-file", o.push_token_file.is_some() || token_key),
        ("push-user", o.push_user.is_some() || user_key),
    ];
    if let Some((name, _)) = http_fields.iter().find(|(_, set)| *set) {
        return Err(push_invalid(format!(
            "{name} applies to an HTTP address, and '{shown}' is an s3:// address"
        )));
    }
    let ssh_fields = [
        ("ssh-command", o.ssh_command.is_some()),
        ("receive-command", o.remote_command.is_some()),
    ];
    if let Some((name, _)) = ssh_fields.iter().find(|(_, set)| *set) {
        return Err(push_invalid(format!(
            "{name} applies to an ssh address, and '{shown}' is an s3:// address"
        )));
    }
    if let Some(section) = section
        && section.tls_permissive()?
    {
        return Err(push_invalid(format!(
            "remote '{remote}' sets tls-permissive=true, which a writer of a bucket \
             repository refuses: the writer verifies the certificate chain of the server"
        )));
    }
    let refusals = S3Refusals {
        invalid: |msg| push_invalid(msg),
        remote: |msg| push_invalid(msg),
    };
    s3_endpoint(remote, section, address, o, env, refusals).await
}

/// Resolves a remote name or an `s3://` address to the endpoint of a writer
/// of a bucket repository other than a push.
///
/// [`BucketRepo::init`](crate::bucket::BucketRepo::init) is such a writer.
/// `resolve_push` gives the endpoint of a push.
///
/// # Address
///
/// A value that starts with `s3://` is the address, and the function reads
/// no configuration for it. Each other value is the name of a remote section
/// of `config`. The address of the section is its key `push-url` if that key
/// holds an `s3://` address, else its key `pull-url` if that key holds an
/// `s3://` address. The function never reads the key `url`.
///
/// # Endpoint
///
/// The function gives the S3 endpoint that `resolve_push` gives for the
/// same `s3://` address and the same section, and makes the same refusals.
/// The signer gives the credential of each request, so the function refuses
/// the fields and the keys `push-token-file` and `push-user`, and the ssh
/// fields. It refuses `tls-permissive=true`, because a writer verifies the
/// certificate chain of the server. It ignores the keys `ssh-command`,
/// `send-command`, and `receive-command`.
///
/// # Errors
///
/// The function makes each refusal that needs no file before it reads a file.
/// Each refusal of the list is [`Error::Remote`] with
/// [`InvalidInput`](crate::remote::Error::InvalidInput):
///
/// - The caller sets `url`.
/// - The value holds a `:` or a `/`, and does not start with `s3://`.
/// - `config` holds no section for the name, or neither `push-url` nor
///   `pull-url` of the section holds an `s3://` address.
/// - The caller or the section sets `push-token-file` or `push-user`.
/// - The caller sets `ssh_command` or `remote_command`.
/// - The section sets `tls-permissive=true`.
/// - A client certificate has no key, or a key has no certificate.
/// - The addressing style is neither `path` nor `virtual`.
/// - The endpoint is `http://`, and the caller does not set
///   `allow_cleartext_credentials`. The signature of each request would go
///   to the server in cleartext. The check comes after the read of the
///   shared AWS files, because the endpoint can come from them.
/// - A refusal of `S3Endpoint::resolve` of `ostrya_remote::s3`: a refused
///   address, a refused setting, or no key pair.
///
/// These errors are also possible:
///
/// - [`Error::Unsupported`] if the key `proxy` has white space at its start
///   or its end.
/// - [`Error::Io`] if a shared AWS file exists and cannot be read.
/// - The errors of [`read_pem_file`].
/// - [`Error::Core`] if a key that the function reads holds a malformed
///   escape sequence, or if `tls-permissive` is not a boolean.
#[cfg(feature = "s3")]
pub async fn resolve_bucket(
    config: Option<&RepoConfig>,
    name_or_address: &str,
    overrides: EndpointOverrides,
) -> Result<remote::s3::S3Endpoint> {
    resolve_bucket_in(
        config,
        name_or_address,
        overrides,
        &S3Environment::default(),
    )
    .await
}

/// Resolves `name_or_address` to the endpoint of a writer of a bucket
/// repository, as [`resolve_bucket`] does, with `env` as the environment of
/// the `s3://` address.
#[cfg(feature = "s3")]
pub(crate) async fn resolve_bucket_in(
    config: Option<&RepoConfig>,
    name_or_address: &str,
    overrides: EndpointOverrides,
    env: &S3Environment,
) -> Result<remote::s3::S3Endpoint> {
    let value = name_or_address;
    if overrides.url.is_some() {
        return Err(push_invalid(
            "url applies to a pull, and this is a write to a bucket repository",
        ));
    }
    let (section, address) = if is_s3(value) {
        (None, value.to_owned())
    } else if value.contains([':', '/']) {
        return Err(push_invalid(format!(
            "'{}' is no s3:// address",
            remote::without_userinfo(value)
        )));
    } else {
        let section = config
            .and_then(|config| config.remote(value))
            .ok_or_else(|| push_invalid(format!("no remote '{value}' is configured")))?;
        let s3 = |address: Option<String>| address.filter(|address| is_s3(address));
        let address = match s3(section.push_url()?) {
            Some(address) => address,
            None => s3(section.pull_url()?).ok_or_else(|| {
                push_invalid(format!(
                    "remote '{value}' holds no s3:// address in push-url or pull-url"
                ))
            })?,
        };
        (Some(section), address)
    };
    // The name of an address in a message is the address without its
    // userinfo, which can hold a key pair.
    let name = match section {
        Some(_) => std::borrow::Cow::Borrowed(value),
        None => remote::without_userinfo(value),
    };
    let endpoint = Box::pin(push_s3(&name, section.as_ref(), &address, overrides, env)).await?;
    let Endpoint::S3(endpoint) = endpoint else {
        unreachable!("the endpoint of an s3:// address is an S3 endpoint");
    };
    Ok(endpoint)
}

/// Completes `http`, the options of an HTTP push to `address`, from `o` and
/// the keys of `section`, the section of `remote`.
#[cfg(feature = "push")]
async fn push_http(
    remote: &str,
    section: Option<&Remote<'_>>,
    address: &str,
    mut http: FetcherOptions,
    mut o: EndpointOverrides,
) -> Result<Endpoint> {
    if let Some(section) = section
        && address.starts_with("https://")
        && section.tls_permissive()?
    {
        return Err(push_invalid(format!(
            "remote '{remote}' sets tls-permissive=true, which a push refuses: a \
             push verifies the certificate chain of the server"
        )));
    }
    let not_http = |name: &str| {
        push_invalid(format!(
            "{name} applies to an ssh address, and '{address}' is an HTTP address"
        ))
    };
    if o.ssh_command.is_some() {
        return Err(not_http("ssh-command"));
    }
    if o.remote_command.is_some() {
        return Err(not_http("receive-command"));
    }
    if let Some(section) = section {
        let path = |key: Option<String>| key.map(PathBuf::from);
        if o.push_token_file.is_none() {
            o.push_token_file = path(section.push_token_file()?);
        }
        if o.push_user.is_none() {
            o.push_user = section.push_user()?;
        }
        if o.tls_ca_path.is_none() {
            o.tls_ca_path = path(section.tls_ca_path()?);
        }
        if o.tls_client_cert_path.is_none() {
            o.tls_client_cert_path = path(section.tls_client_cert_path()?);
        }
        if o.tls_client_key_path.is_none() {
            o.tls_client_key_path = path(section.tls_client_key_path()?);
        }
    }
    let client_files = match (o.tls_client_cert_path, o.tls_client_key_path) {
        (Some(cert), Some(key)) => Some((cert, key)),
        (None, None) => None,
        _ => {
            return Err(push_invalid(
                "a client certificate needs both tls-client-cert-path and tls-client-key-path",
            ));
        }
    };
    match (&o.push_user, &o.push_token_file) {
        (Some(_), None) => {
            return Err(push_invalid("push-user needs push-token-file"));
        }
        (Some(user), Some(_)) if user.is_empty() || user.contains(':') => {
            return Err(push_invalid(
                "push-user is empty or holds ':', which a Basic credential cannot carry",
            ));
        }
        _ => {}
    }
    let cleartext = address
        .get(..7)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http://"));
    if o.push_token_file.is_some() && cleartext && !o.allow_cleartext_credentials {
        return Err(push_invalid(format!(
            "the push address '{address}' is http://, so the token would travel in cleartext: \
             use https, or set allow-cleartext-credentials"
        )));
    }
    http.proxy = match section {
        Some(section) => remote_proxy(remote, section)?,
        None => Proxy::Environment,
    };
    if let Some(path) = &o.push_token_file {
        let token = read_token_file(path).await?;
        match o.push_user {
            Some(user) => {
                http.basic_auth = Some(BasicAuth {
                    user,
                    password: token,
                })
            }
            None => http.bearer_token = Some(BearerToken { token }),
        }
    }
    // The HTTP client of a push session follows no redirect, so an `http://`
    // address uses no TLS, and the push reads no TLS file.
    if !cleartext && let Some(path) = &o.tls_ca_path {
        http.tls.roots = TrustRoots::Pem(read_pem_file("tls-ca-path", path).await?);
    }
    if !cleartext && let Some((cert, key)) = client_files {
        http.tls.client_identity = Some(client_identity(&cert, &key).await?);
    }
    http.headers = o.http_headers;
    http.allow_cleartext_credentials = o.allow_cleartext_credentials;
    if let Some(retries) = o.max_retries {
        http.max_retries = retries;
    }
    if o.low_speed_limit_bytes.is_some() || o.low_speed_time.is_some() {
        http.low_speed = low_speed(o.low_speed_limit_bytes, o.low_speed_time);
    }
    Ok(Endpoint::Http(http))
}

/// Gives the endpoint of a push to the ssh address `address`, with `o` and
/// the ssh keys of `section`.
#[cfg(feature = "push")]
fn push_ssh(
    section: Option<&Remote<'_>>,
    address: SshAddress,
    o: EndpointOverrides,
) -> Result<Endpoint> {
    let set = [
        ("push-token-file", o.push_token_file.is_some()),
        ("push-user", o.push_user.is_some()),
    ];
    let name = match set.iter().find(|(_, set)| *set) {
        Some((name, _)) => Some(*name),
        None => http_field(&o),
    };
    if let Some(name) = name {
        return Err(push_invalid(format!(
            "{name} applies to an HTTP address, and '{}' is an ssh address",
            address.without_user()
        )));
    }
    let (config_command, remote_command) = match section {
        Some(section) => (
            section.ssh_command()?,
            match o.remote_command {
                Some(command) => Some(command),
                None => section.receive_command()?,
            },
        ),
        None => (None, o.remote_command),
    };
    Ok(Endpoint::Ssh {
        address,
        options: SshOptions {
            command: o.ssh_command,
            config_command,
            remote_command,
        },
    })
}

/// Returns the error of a push request that the resolver refuses.
#[cfg(any(feature = "push", feature = "s3"))]
fn push_invalid(msg: impl Into<String>) -> Error {
    Error::Remote(remote::Error::InvalidInput(msg.into()))
}

/// Returns the name of the first field of `o` that applies to an HTTP
/// address alone, or `None` if `o` sets no such field.
///
/// A field that a remote key backs gets the name of the key. Each other field
/// gets the name of the option of `ostrya pull` that sets it. A retry count
/// of 0 is no refusal, because a session over ssh never sends a request
/// again.
fn http_field(o: &EndpointOverrides) -> Option<&'static str> {
    let set = [
        ("tls-ca-path", o.tls_ca_path.is_some()),
        ("tls-client-cert-path", o.tls_client_cert_path.is_some()),
        ("tls-client-key-path", o.tls_client_key_path.is_some()),
        ("allow-cleartext-credentials", o.allow_cleartext_credentials),
        ("http-header", !o.http_headers.is_empty()),
        ("network-retries", o.max_retries.is_some_and(|n| n > 0)),
        ("low-speed-limit-bytes", o.low_speed_limit_bytes.is_some()),
        ("low-speed-time-seconds", o.low_speed_time.is_some()),
    ];
    set.iter().find(|(_, set)| *set).map(|(name, _)| *name)
}

/// Returns the low-speed rule of `limit` and `time`. A value left `None`
/// takes its default, and a zero in either value turns the rule off.
fn low_speed(limit: Option<u32>, time: Option<Duration>) -> Option<LowSpeed> {
    let limit = limit.unwrap_or(DEFAULT_LOW_SPEED_LIMIT);
    let time = time.unwrap_or(DEFAULT_LOW_SPEED_TIME);
    (limit != 0 && !time.is_zero()).then_some(LowSpeed { limit, time })
}

/// Reads the proxy that the `proxy` key of a remote names. An empty or absent
/// key leaves the proxy to the environment variables.
///
/// The function refuses a value with white space at its start or end, as the
/// `ostree` command refuses it. The fetcher trims a proxy URL, so without this
/// check it connects through such a value. The message leaves out the value,
/// because the userinfo of the value can hold a password.
fn remote_proxy(remote: &str, section: &Remote<'_>) -> Result<Proxy> {
    Ok(match section.proxy()? {
        Some(url) if url.trim() != url => {
            return Err(Error::Unsupported(format!(
                "remote '{remote}': the proxy key has white space at the start or \
                 the end of its value"
            )));
        }
        Some(url) if !url.is_empty() => Proxy::Url(url),
        _ => Proxy::Environment,
    })
}

/// Reads the client certificate chain at `cert` and the client key at `key`.
async fn client_identity(cert: &Path, key: &Path) -> Result<ClientIdentity> {
    Ok(ClientIdentity {
        cert_chain_pem: read_pem_file("tls-client-cert-path", cert).await?,
        key_pem: read_pem_file("tls-client-key-path", key).await?,
        // A remote has no config key for a passphrase, so the key must need
        // no passphrase.
        key_passphrase: None,
    })
}

/// Returns the token of the token file at `path`.
///
/// The token is the first line of the file: the bytes up to the first LF, or
/// the whole file if it holds no LF. The function stops at the first LF, and
/// reads at most 1 MiB and one byte of the file. The token
/// must have the token68 syntax: one or more ASCII letters, digits, `-`,
/// `.`, `_`, `~`, `+`, or `/`, then zero or more `=`.
///
/// No error holds a part of the token. The function checks no permission of
/// the file.
///
/// # Errors
///
/// - [`Error::Io`] if the file cannot be read. The message names the key
///   `push-token-file` and the path.
/// - [`Error::InvalidInput`] if the first line is longer than 1 MiB, or if it
///   is empty, holds a CR, is not UTF-8, or is not token68. The message names
///   the key `push-token-file` and the path.
pub async fn read_token_file(path: &Path) -> Result<String> {
    let owned = path.to_owned();
    let read = ostrya_rt::unblock(move || {
        let mut bytes = Vec::new();
        let file = std::fs::File::open(&owned)?;
        BufReader::new(file.take(FILE_CAP + 1)).read_until(b'\n', &mut bytes)?;
        Ok::<_, std::io::Error>(bytes)
    })
    .await;
    let bytes = read.map_err(|e| io_error("push-token-file", path, e))?;
    let line = match bytes.split_last() {
        Some((b'\n', line)) => line,
        _ if bytes.len() as u64 > FILE_CAP => {
            return Err(Error::InvalidInput(format!(
                "the first line of push-token-file '{}' is over 1 MiB",
                path.display()
            )));
        }
        _ => &bytes[..],
    };
    token_of(line)
        .map_err(|why| Error::InvalidInput(format!("push-token-file '{}': {why}", path.display())))
}

/// Returns the bytes of the PEM file at `path`, which the remote key `key`
/// names.
///
/// The function reads at most 1 MiB and one byte of the file. It does not
/// check the PEM syntax. The fetcher reads the bytes.
///
/// # Errors
///
/// - [`Error::Io`] if the file cannot be read. The message names `key` and
///   the path, and holds no byte of the file.
/// - [`Error::InvalidInput`] if the file is larger than 1 MiB. The message
///   names `key` and the path.
pub async fn read_pem_file(key: &str, path: &Path) -> Result<Vec<u8>> {
    let bytes = read_capped(path, key).await?;
    if bytes.len() as u64 > FILE_CAP {
        return Err(Error::InvalidInput(format!(
            "{key} '{}' is over 1 MiB",
            path.display()
        )));
    }
    Ok(bytes)
}

/// Reads at most [`FILE_CAP`] + 1 bytes of the file at `path`, on the
/// blocking pool.
///
/// The key `key` names the file. A failure is an [`Error::Io`] that names
/// the key and the path, and holds no byte of the file.
async fn read_capped(path: &Path, key: &str) -> Result<Vec<u8>> {
    let owned = path.to_owned();
    let read = ostrya_rt::unblock(move || {
        let mut bytes = Vec::new();
        std::fs::File::open(&owned)?
            .take(FILE_CAP + 1)
            .read_to_end(&mut bytes)?;
        Ok::<_, std::io::Error>(bytes)
    })
    .await;
    read.map_err(|e| io_error(key, path, e))
}

/// Returns the [`Error::Io`] of the failure `e` to read the file at `path`,
/// which the key `key` names. The message names the key and the path.
fn io_error(key: &str, path: &Path, e: std::io::Error) -> Error {
    Error::Io(std::io::Error::new(
        e.kind(),
        format!("{key} '{}': {e}", path.display()),
    ))
}

/// Returns the token of `line`, the first line of a token file, or the
/// reason of its refusal.
fn token_of(line: &[u8]) -> std::result::Result<String, &'static str> {
    if line.contains(&b'\r') {
        return Err("the first line holds a carriage return");
    }
    if line.is_empty() {
        return Err("the first line is empty");
    }
    let token = std::str::from_utf8(line).map_err(|_| "the first line is not UTF-8")?;
    if !is_token68(token) {
        return Err(
            "the token is not token68: it holds letters, digits, -, ., _, ~, +, or /, \
                    then any number of =",
        );
    }
    Ok(token.to_owned())
}

/// Returns `true` if `token` has the token68 syntax of HTTP authentication.
/// The syntax is one or more ASCII letters, digits, `-`, `.`, `_`, `~`, `+`,
/// or `/`, then any number of `=`.
fn is_token68(token: &str) -> bool {
    let body = token.trim_end_matches('=');
    !body.is_empty()
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(&b))
}

// The overrides move freely across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<EndpointOverrides>();
};

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;
    use crate::fetch::TlsOptions;

    struct Dir(PathBuf);

    impl Dir {
        fn new() -> Dir {
            static N: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "ostrya-endpoint-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Dir(path)
        }

        fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, bytes).unwrap();
            path
        }

        /// Returns the path of `name` in the directory, with no file at it.
        fn absent(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Returns the config of the remote sections `sections`.
    fn config(sections: &str) -> RepoConfig {
        RepoConfig::parse(&format!(
            "[core]\nrepo_version=1\nmode=archive-z2\n\n{sections}"
        ))
        .unwrap()
    }

    fn pull(config: Option<&RepoConfig>, remote: &str, o: EndpointOverrides) -> Result<Endpoint> {
        ostrya_rt::block_on(resolve_pull(config, remote, o))
    }

    fn http_of(endpoint: Result<Endpoint>) -> FetcherOptions {
        match endpoint {
            Ok(Endpoint::Http(http)) => http,
            other => panic!("{other:?}"),
        }
    }

    fn ssh(endpoint: Result<Endpoint>) -> (SshAddress, SshOptions) {
        match endpoint {
            Ok(Endpoint::Ssh { address, options }) => (address, options),
            other => panic!("{other:?}"),
        }
    }

    fn invalid_input<T: fmt::Debug>(result: Result<T>) -> String {
        match result {
            Err(Error::InvalidInput(msg)) => msg,
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    fn pull_error<T: fmt::Debug>(result: Result<T>) -> String {
        match result {
            Err(Error::Pull(msg)) => msg,
            other => panic!("expected Pull, got {other:?}"),
        }
    }

    /// Returns the message of an [`Error::Io`], and checks its kind.
    fn not_found<T: fmt::Debug>(result: Result<T>) -> String {
        match result {
            Err(Error::Io(e)) => {
                assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
                e.to_string()
            }
            other => panic!("expected Io, got {other:?}"),
        }
    }

    fn token(path: &Path) -> Result<String> {
        ostrya_rt::block_on(read_token_file(path))
    }

    fn pem(key: &str, path: &Path) -> Result<Vec<u8>> {
        ostrya_rt::block_on(read_pem_file(key, path))
    }

    /// The token is the first line of the file. A file with no line end holds
    /// the token alone.
    #[test]
    fn the_token_is_the_first_line_of_the_file() {
        let dir = Dir::new();
        let file = dir.file("token", b"s3cr3t-T0ken==\nsecond line\n");
        assert_eq!(token(&file).unwrap(), "s3cr3t-T0ken==");
        assert_eq!(token(&dir.file("bare", b"abc")).unwrap(), "abc");
        assert_eq!(
            token(&dir.file("all", b"aZ0-._~+/==")).unwrap(),
            "aZ0-._~+/=="
        );
    }

    /// A token that is empty, holds a carriage return, is not UTF-8, or is
    /// not token68 is refused, and the refusal holds no part of it.
    #[test]
    fn a_bad_token_is_refused_without_the_token() {
        let dir = Dir::new();
        for (bytes, part) in [
            (&b"\nQXZ"[..], "is empty"),
            (b"", "is empty"),
            (b"QXZ\r\n", "carriage return"),
            (b"QX\rZ", "carriage return"),
            (b"QXZ\xff\n", "not UTF-8"),
            (b"QX Z\n", "not token68"),
            (b"QXZ:x\n", "not token68"),
            (b"==\n", "not token68"),
            (b"QX=Z\n", "not token68"),
        ] {
            let path = dir.file("t", bytes);
            let m = invalid_input(token(&path));
            assert!(m.contains(part), "{bytes:?}: {m}");
            assert!(!m.contains("QX"), "{m}");
            assert!(
                m.starts_with(&format!("push-token-file '{}': ", path.display())),
                "{m}"
            );
        }
    }

    /// A first line over 1 MiB and a PEM file over 1 MiB are refused, and the
    /// message names the key and the path. A token file whose first line is
    /// short can be longer.
    #[test]
    fn a_file_over_the_cap_is_refused() {
        let dir = Dir::new();
        let long = vec![b'a'; FILE_CAP as usize + 1];
        let path = dir.file("long", &long);
        let m = invalid_input(token(&path));
        assert_eq!(
            m,
            format!(
                "the first line of push-token-file '{}' is over 1 MiB",
                path.display()
            )
        );
        let mut short = b"abc\n".to_vec();
        short.extend_from_slice(&long);
        assert_eq!(token(&dir.file("short", &short)).unwrap(), "abc");
        let mut at_cap = vec![b'a'; FILE_CAP as usize];
        at_cap.push(b'\n');
        assert_eq!(token(&dir.file("at-cap", &at_cap)).unwrap().len(), 1 << 20);

        let m = invalid_input(pem("tls-ca-path", &path));
        assert_eq!(m, format!("tls-ca-path '{}' is over 1 MiB", path.display()));
        let at_cap = dir.file("pem-at-cap", &vec![b'a'; FILE_CAP as usize]);
        assert_eq!(pem("tls-ca-path", &at_cap).unwrap().len(), 1 << 20);
    }

    /// A file that cannot be read is an I/O error that names the key and the
    /// path.
    #[test]
    fn an_absent_file_is_an_io_error_that_names_the_key_and_the_path() {
        let dir = Dir::new();
        let absent = dir.absent("absent");
        let m = not_found(token(&absent));
        assert!(
            m.starts_with(&format!("push-token-file '{}': ", absent.display())),
            "{m}"
        );
        for key in ["tls-ca-path", "tls-client-cert-path", "tls-client-key-path"] {
            let m = not_found(pem(key, &absent));
            assert!(
                m.starts_with(&format!("{key} '{}': ", absent.display())),
                "{m}"
            );
        }
    }

    /// The `Debug` output shows no password of the url and no header value.
    /// It shows the header names and the paths.
    #[test]
    fn the_debug_output_shows_no_secret() {
        let o = EndpointOverrides {
            url: Some("https://user-QXZ:pw-QXZ@ex.com/repo".into()),
            push_token_file: Some("/etc/ostrya/token".into()),
            tls_ca_path: Some("/etc/ostrya/ca.pem".into()),
            http_headers: vec![
                ("Authorization".into(), "Bearer QXZ".into()),
                ("Cookie".into(), "id=QXZ".into()),
            ],
            ..EndpointOverrides::default()
        };
        let text = format!("{o:?}");
        assert!(!text.contains("QXZ"), "{text}");
        for part in [
            "https://ex.com/repo",
            "/etc/ostrya/token",
            "/etc/ostrya/ca.pem",
            "Authorization",
            "Cookie",
            "<redacted>",
        ] {
            assert!(text.contains(part), "{part}: {text}");
        }
    }

    const PULL_SECTIONS: &str = "[remote \"both\"]\nurl=https://ex.com/pull\n\
                                 pull-url=ssh://puller@ex.com/srv/repo\n\
                                 ssh-command=ssh -o BatchMode=yes\n\
                                 send-command=/opt/bin/ostrya send\n\
                                 tls-ca-path=/nonexistent/ca.pem\n\
                                 tls-permissive=maybe\n\n\
                                 [remote \"http-pull-url\"]\nurl=ssh://h/dead\n\
                                 pull-url=http://pull.ex.com/repo\n\
                                 ssh-command=ssh -q\n\
                                 send-command=ostrya send\n\n\
                                 [remote \"upper\"]\npull-url=HTTP://ex.com/repo\n\n\
                                 [remote \"file\"]\npull-url=file:///srv/repo\n\n\
                                 [remote \"scp\"]\npull-url=h:srv/repo\n\n\
                                 [remote \"bad-pull-url\"]\npull-url=ssh://h\n\n\
                                 [remote \"local-path\"]\npull-url=/srv/repo\n\n\
                                 [remote \"url\"]\nurl=https://ex.com/repo\n\
                                 contenturl=https://content.ex.com/repo\n\
                                 metalink=https://ex.com/metalink.xml\n\
                                 ssh-command=ssh -q\n\n\
                                 [remote \"ssh-url\"]\nurl=ssh://h/srv/repo\n\n\
                                 [remote \"scp-url\"]\nurl=u@h:/srv/repo\n\n\
                                 [remote \"file-url\"]\nurl=file:///srv/repo\n\n\
                                 [remote \"path-url\"]\nurl=/srv/repo\n\n\
                                 [remote \"none\"]\ngpg-verify=false\n";

    fn pull_url(name: &str, url: Option<&str>) -> Result<Endpoint> {
        let o = EndpointOverrides {
            url: url.map(str::to_owned),
            ..EndpointOverrides::default()
        };
        pull(Some(&config(PULL_SECTIONS)), name, o)
    }

    fn mirror(endpoint: Result<Endpoint>) -> String {
        let http = http_of(endpoint);
        assert_eq!(http.mirrors.len(), 1);
        http.mirrors[0].clone()
    }

    /// The url of the caller has precedence over `pull-url`, and `pull-url`
    /// has precedence over `url`.
    #[test]
    fn the_pull_takes_the_url_override_then_pull_url_then_url() {
        assert_eq!(
            mirror(pull_url("http-pull-url", Some("https://other.ex.com/"))),
            "https://other.ex.com/"
        );
        assert_eq!(
            ssh(pull_url("both", None)).0,
            SshAddress::parse("ssh://puller@ex.com/srv/repo").unwrap()
        );
        assert_eq!(
            ssh(pull_url("http-pull-url", Some("u@h:x"))).0,
            SshAddress::parse("u@h:x").unwrap()
        );
        // If `pull-url` is set, the pull does not read a dead ssh `url`.
        assert_eq!(
            mirror(pull_url("http-pull-url", None)),
            "http://pull.ex.com/repo"
        );
        assert_eq!(mirror(pull_url("url", None)), "https://ex.com/repo");
        assert_eq!(
            ssh(pull_url("scp", None)).0,
            SshAddress::parse("h:srv/repo").unwrap()
        );
    }

    /// A value with `://` and a scheme other than `ssh` goes to the fetcher
    /// as written.
    #[test]
    fn another_scheme_goes_to_the_fetcher() {
        assert_eq!(mirror(pull_url("upper", None)), "HTTP://ex.com/repo");
        assert_eq!(mirror(pull_url("file", None)), "file:///srv/repo");
        assert_eq!(mirror(pull_url("file-url", None)), "file:///srv/repo");
        assert_eq!(
            mirror(pull_url("none", Some("file:///srv/repo"))),
            "file:///srv/repo"
        );
    }

    /// A malformed ssh address of the caller or in `pull-url` gives
    /// `InvalidInput` with the text of the parser.
    #[test]
    fn a_malformed_ssh_address_is_invalid_input() {
        for (name, url, value) in [
            ("bad-pull-url", None, "ssh://h"),
            ("local-path", None, "/srv/repo"),
            ("none", Some("ssh://h"), "ssh://h"),
            ("none", Some("/srv/repo"), "/srv/repo"),
        ] {
            let msg = invalid_input(pull_url(name, url));
            assert!(msg.starts_with(&format!("address '{value}': ")), "{msg}");
        }
    }

    /// The pull refuses an ssh address in `url`, in the `ssh://` form and in
    /// the scp form. A `url` that is not an ssh address goes to the fetcher.
    #[test]
    fn an_ssh_address_in_url_is_refused() {
        for (name, value) in [("ssh-url", "ssh://h/srv/repo"), ("scp-url", "h:/srv/repo")] {
            assert_eq!(
                pull_error(pull_url(name, None)),
                format!(
                    "remote '{name}': url '{value}' is an ssh address; the port reads an ssh \
                     address from pull-url alone"
                )
            );
        }
        assert_eq!(mirror(pull_url("path-url", None)), "/srv/repo");
    }

    /// The refusal of an ssh address in `url` shows no user name and no
    /// password.
    #[test]
    fn the_refusal_of_an_ssh_url_shows_no_userinfo() {
        let config = config(
            "[remote \"ssh-userinfo\"]\nurl=ssh://user-QXZ:pw-QXZ@ex.com/srv/repo\n\n\
             [remote \"scp-user\"]\nurl=user-QXZ@ex.com:/srv/repo\n",
        );
        for (name, shown) in [
            ("ssh-userinfo", "ssh://ex.com/srv/repo"),
            ("scp-user", "ex.com:/srv/repo"),
        ] {
            let msg = pull_error(pull(Some(&config), name, EndpointOverrides::default()));
            assert!(!msg.contains("QXZ"), "{name}: {msg}");
            assert_eq!(
                msg,
                format!(
                    "remote '{name}': url '{shown}' is an ssh address; the port reads an ssh \
                     address from pull-url alone"
                )
            );
        }
    }

    /// The pull refuses a remote with no section and no url of the caller.
    /// It also refuses a section with neither key.
    #[test]
    fn a_pull_remote_with_no_address_is_refused() {
        assert_eq!(
            pull_error(pull_url("absent", None)),
            "no remote 'absent' is configured"
        );
        assert_eq!(
            pull_error(pull(None, "absent", EndpointOverrides::default())),
            "no remote 'absent' is configured"
        );
        assert_eq!(
            pull_error(pull_url("none", None)),
            "remote 'none' has no pull-url and no url"
        );
        assert_eq!(
            ssh(pull_url("absent", Some("ssh://h/x"))).0,
            SshAddress::parse("ssh://h/x").unwrap()
        );
    }

    /// An HTTP pull with no override gets the defaults of a pull, and the
    /// keys `contenturl` and `metalink` change nothing.
    #[test]
    fn an_http_pull_gets_the_defaults_of_a_pull() {
        for http in [
            http_of(pull_url("url", None)),
            http_of(pull(
                None,
                "absent",
                EndpointOverrides {
                    url: Some("https://ex.com/repo".into()),
                    ..EndpointOverrides::default()
                },
            )),
        ] {
            assert_eq!(http.mirrors, ["https://ex.com/repo"]);
            assert_eq!(http.max_retries, 5);
            assert_eq!(http.max_outstanding, 8);
            assert_eq!(
                http.low_speed,
                Some(LowSpeed {
                    limit: 1000,
                    time: Duration::from_secs(30)
                })
            );
            assert_eq!(http.tls, TlsOptions::default());
            assert!(matches!(http.proxy, Proxy::Environment));
            assert!(http.headers.is_empty());
            assert!(http.basic_auth.is_none());
            assert!(http.bearer_token.is_none());
            assert!(!http.allow_cleartext_credentials);
            let d = FetcherOptions::default();
            assert_eq!(http.max_redirects, d.max_redirects);
            assert_eq!(http.fetch_timeout, d.fetch_timeout);
        }
    }

    /// A low-speed value left `None` takes its default, and a zero in either
    /// value turns the rule off. A retry count of 0 turns the retries off.
    #[test]
    fn the_pull_applies_the_http_overrides() {
        let secs = Duration::from_secs;
        for (limit, time, expected) in [
            (None, None, Some((1000, secs(30)))),
            (Some(5), None, Some((5, secs(30)))),
            (None, Some(secs(10)), Some((1000, secs(10)))),
            (Some(5), Some(secs(10)), Some((5, secs(10)))),
            (Some(0), None, None),
            (None, Some(Duration::ZERO), None),
            (Some(0), Some(secs(10)), None),
        ] {
            let o = EndpointOverrides {
                low_speed_limit_bytes: limit,
                low_speed_time: time,
                ..EndpointOverrides::default()
            };
            let http = http_of(pull(Some(&config(PULL_SECTIONS)), "url", o));
            let expected = expected.map(|(limit, time)| LowSpeed { limit, time });
            assert_eq!(http.low_speed, expected, "{limit:?} {time:?}");
        }
        let o = EndpointOverrides {
            http_headers: vec![("X-A".into(), "b".into())],
            allow_cleartext_credentials: true,
            max_retries: Some(0),
            ..EndpointOverrides::default()
        };
        let http = http_of(pull(Some(&config(PULL_SECTIONS)), "url", o));
        assert_eq!(http.headers, [("X-A".to_owned(), "b".to_owned())]);
        assert!(http.allow_cleartext_credentials);
        assert_eq!(http.max_retries, 0);
    }

    /// `tls-permissive=true` gives `DangerousAcceptAnyChain`, and the pull
    /// does not read `tls-ca-path`. A CA path of the caller wins over the key.
    #[test]
    fn the_pull_maps_tls_permissive_to_any_chain() {
        let dir = Dir::new();
        let ca = dir.file("ca.pem", b"CA");
        let config = config(&format!(
            "[remote \"permissive\"]\nurl=https://ex.com/repo\n\
             tls-ca-path={}\ntls-permissive=true\n\n\
             [remote \"bad\"]\nurl=http://ex.com/repo\ntls-permissive=maybe\n",
            dir.absent("absent.pem").display()
        ));
        let http = http_of(pull(
            Some(&config),
            "permissive",
            EndpointOverrides::default(),
        ));
        assert_eq!(http.tls.roots, TrustRoots::DangerousAcceptAnyChain);
        let o = EndpointOverrides {
            tls_ca_path: Some(ca),
            ..EndpointOverrides::default()
        };
        let http = http_of(pull(Some(&config), "permissive", o));
        assert_eq!(http.tls.roots, TrustRoots::Pem(b"CA".to_vec()));
        // The pull reads the key for an `http://` address too.
        assert!(matches!(
            pull(Some(&config), "bad", EndpointOverrides::default()),
            Err(Error::Core(_))
        ));
    }

    /// Returns the PEM files of a CA and of a client, and a config whose
    /// remote `keys` names them.
    fn tls_keys(dir: &Dir, url: &str) -> RepoConfig {
        let ca = dir.file("key-ca.pem", b"KEY-CA");
        let cert = dir.file("key-cert.pem", b"KEY-CERT");
        let key = dir.file("key-key.pem", b"KEY-KEY");
        let token = dir.file("key-token", b"KEY-TOKEN\n");
        config(&format!(
            "[remote \"keys\"]\nurl={url}\n\
             push-token-file={}\npush-user=alice\n\
             tls-ca-path={}\ntls-client-cert-path={}\ntls-client-key-path={}\n\
             proxy=http://proxy.ex.com:3128\n\
             ssh-command=ssh -o BatchMode=yes\n\
             receive-command=/opt/bin/ostrya receive\n\
             send-command=/opt/bin/ostrya send\n",
            token.display(),
            ca.display(),
            cert.display(),
            key.display()
        ))
    }

    /// The paths that a caller gives in place of the keys.
    fn given(dir: &Dir) -> [PathBuf; 4] {
        [
            dir.file("given-ca.pem", b"GIVEN-CA"),
            dir.file("given-cert.pem", b"GIVEN-CERT"),
            dir.file("given-key.pem", b"GIVEN-KEY"),
            dir.file("given-token", b"GIVEN-TOKEN\n"),
        ]
    }

    fn identity(http: &FetcherOptions) -> (Vec<u8>, Vec<u8>) {
        let identity = http.tls.client_identity.as_ref().unwrap();
        assert_eq!(identity.key_passphrase, None);
        (identity.cert_chain_pem.clone(), identity.key_pem.clone())
    }

    /// The pull reads the TLS keys and the `proxy` key, and an override wins
    /// over each TLS key on its own.
    #[test]
    fn an_override_wins_over_each_tls_key_of_the_pull() {
        let dir = Dir::new();
        let config = tls_keys(&dir, "https://ex.com/repo");
        let http = http_of(pull(Some(&config), "keys", EndpointOverrides::default()));
        assert_eq!(http.tls.roots, TrustRoots::Pem(b"KEY-CA".to_vec()));
        assert_eq!(identity(&http), (b"KEY-CERT".to_vec(), b"KEY-KEY".to_vec()));
        assert!(matches!(&http.proxy, Proxy::Url(url) if url == "http://proxy.ex.com:3128"));

        let [ca, cert, key, _] = given(&dir);
        let o = EndpointOverrides {
            tls_ca_path: Some(ca.clone()),
            ..EndpointOverrides::default()
        };
        let http = http_of(pull(Some(&config), "keys", o));
        assert_eq!(http.tls.roots, TrustRoots::Pem(b"GIVEN-CA".to_vec()));
        assert_eq!(identity(&http), (b"KEY-CERT".to_vec(), b"KEY-KEY".to_vec()));
        let o = EndpointOverrides {
            tls_client_cert_path: Some(cert.clone()),
            ..EndpointOverrides::default()
        };
        let http = http_of(pull(Some(&config), "keys", o));
        assert_eq!(http.tls.roots, TrustRoots::Pem(b"KEY-CA".to_vec()));
        assert_eq!(
            identity(&http),
            (b"GIVEN-CERT".to_vec(), b"KEY-KEY".to_vec())
        );
        let o = EndpointOverrides {
            tls_client_key_path: Some(key.clone()),
            ..EndpointOverrides::default()
        };
        let http = http_of(pull(Some(&config), "keys", o));
        assert_eq!(
            identity(&http),
            (b"KEY-CERT".to_vec(), b"GIVEN-KEY".to_vec())
        );
        // With no section, the paths of the caller apply alone.
        let o = EndpointOverrides {
            url: Some("https://ex.com/repo".into()),
            tls_ca_path: Some(ca),
            tls_client_cert_path: Some(cert),
            tls_client_key_path: Some(key),
            ..EndpointOverrides::default()
        };
        let http = http_of(pull(None, "absent", o));
        assert_eq!(http.tls.roots, TrustRoots::Pem(b"GIVEN-CA".to_vec()));
        assert_eq!(
            identity(&http),
            (b"GIVEN-CERT".to_vec(), b"GIVEN-KEY".to_vec())
        );
        assert!(matches!(http.proxy, Proxy::Environment));
    }

    /// A lone certificate or a lone key is refused before the pull reads a
    /// file.
    #[test]
    fn a_lone_certificate_or_key_is_refused_by_the_pull() {
        let dir = Dir::new();
        let pem = dir.file("pem", b"");
        let config = config(&format!(
            "[remote \"cert\"]\nurl=https://ex.com/repo\ntls-ca-path={}\n\
             tls-client-cert-path={}\n",
            dir.absent("absent.pem").display(),
            pem.display()
        ));
        let expected = "remote 'cert': a client certificate needs both tls-client-cert-path \
                        and tls-client-key-path";
        assert_eq!(
            pull_error(pull(Some(&config), "cert", EndpointOverrides::default())),
            expected
        );
        let o = EndpointOverrides {
            url: Some("https://ex.com/repo".into()),
            tls_client_key_path: Some(pem),
            ..EndpointOverrides::default()
        };
        assert_eq!(pull_error(pull(None, "cert", o)), expected);
    }

    /// A proxy value with white space at its start or end is refused before
    /// the pull reads a file.
    #[test]
    fn the_pull_refuses_a_proxy_with_white_space() {
        let dir = Dir::new();
        let config = config(&format!(
            "[remote \"proxy\"]\nurl=https://ex.com/repo\nproxy=http://user-QXZ:pw@p:1   \n\
             tls-ca-path={}\n",
            dir.absent("absent.pem").display()
        ));
        match pull(Some(&config), "proxy", EndpointOverrides::default()) {
            Err(Error::Unsupported(msg)) => {
                assert!(msg.contains("white space") && !msg.contains("QXZ"), "{msg}")
            }
            other => panic!("{other:?}"),
        }
    }

    /// A TLS file over 1 MiB and an absent TLS file fail the pull, and the
    /// error names the key and the path.
    #[test]
    fn a_tls_file_over_the_cap_fails_the_pull() {
        let dir = Dir::new();
        let long = dir.file("long", &vec![b'a'; FILE_CAP as usize + 1]);
        let absent = dir.absent("absent");
        let pem = dir.file("pem", b"");
        for (key, path) in [
            ("tls-ca-path", &long),
            ("tls-client-cert-path", &long),
            ("tls-client-key-path", &long),
        ] {
            let mut o = EndpointOverrides {
                url: Some("https://ex.com/repo".into()),
                tls_client_cert_path: Some(pem.clone()),
                tls_client_key_path: Some(pem.clone()),
                ..EndpointOverrides::default()
            };
            match key {
                "tls-ca-path" => o.tls_ca_path = Some(path.clone()),
                "tls-client-cert-path" => o.tls_client_cert_path = Some(path.clone()),
                _ => o.tls_client_key_path = Some(path.clone()),
            }
            assert_eq!(
                invalid_input(pull(None, "r", o.clone())),
                format!("{key} '{}' is over 1 MiB", path.display())
            );
            match key {
                "tls-ca-path" => o.tls_ca_path = Some(absent.clone()),
                "tls-client-cert-path" => o.tls_client_cert_path = Some(absent.clone()),
                _ => o.tls_client_key_path = Some(absent.clone()),
            }
            let m = not_found(pull(None, "r", o));
            assert!(
                m.starts_with(&format!("{key} '{}': ", absent.display())),
                "{m}"
            );
        }
    }

    /// The pull refuses the fields of a push for each transport, before it
    /// resolves the address.
    #[test]
    fn the_pull_refuses_the_fields_of_a_push() {
        for (name, o) in [
            (
                "push-token-file",
                EndpointOverrides {
                    push_token_file: Some("/t".into()),
                    push_user: Some("alice".into()),
                    ..EndpointOverrides::default()
                },
            ),
            (
                "push-user",
                EndpointOverrides {
                    push_user: Some("alice".into()),
                    ..EndpointOverrides::default()
                },
            ),
        ] {
            for url in ["https://ex.com/repo", "ssh://h/r"] {
                let o = EndpointOverrides {
                    url: Some(url.into()),
                    ..o.clone()
                };
                assert_eq!(
                    invalid_input(pull(None, "r", o)),
                    format!("{name} applies to a push, and this is a pull")
                );
            }
            assert_eq!(
                invalid_input(pull(None, "absent", o)),
                format!("{name} applies to a push, and this is a pull")
            );
        }
    }

    /// An HTTP pull refuses the ssh fields, and names them by their keys.
    #[test]
    fn the_pull_refuses_the_ssh_fields_for_an_http_address() {
        for (name, o) in [
            (
                "ssh-command",
                EndpointOverrides {
                    ssh_command: Some(vec!["ssh".into()]),
                    remote_command: Some("ostrya send".into()),
                    ..EndpointOverrides::default()
                },
            ),
            (
                "send-command",
                EndpointOverrides {
                    remote_command: Some("ostrya send".into()),
                    ..EndpointOverrides::default()
                },
            ),
        ] {
            assert_eq!(
                invalid_input(pull(Some(&config(PULL_SECTIONS)), "url", o)),
                format!("{name} applies to a pull over ssh, and this pull runs over HTTP")
            );
        }
    }

    /// The keys fill the ssh options that the caller leaves `None`. A field
    /// that the caller sets has precedence over its key.
    #[test]
    fn the_pull_fills_the_ssh_options_from_the_keys() {
        let config = config(PULL_SECTIONS);
        let (_, options) = ssh(pull(Some(&config), "both", EndpointOverrides::default()));
        assert_eq!(
            options,
            SshOptions {
                command: None,
                config_command: Some("ssh -o BatchMode=yes".into()),
                remote_command: Some("/opt/bin/ostrya send".into()),
            }
        );
        let o = EndpointOverrides {
            ssh_command: Some(vec!["my-ssh".into()]),
            remote_command: Some("my send".into()),
            ..EndpointOverrides::default()
        };
        let (_, options) = ssh(pull(Some(&config), "both", o.clone()));
        assert_eq!(
            options,
            SshOptions {
                command: Some(vec!["my-ssh".into()]),
                config_command: Some("ssh -o BatchMode=yes".into()),
                remote_command: Some("my send".into()),
            }
        );
        let o = EndpointOverrides {
            url: Some("ssh://h/r".into()),
            ..o
        };
        let (_, options) = ssh(pull(None, "absent", o));
        assert_eq!(options.config_command, None);
        assert_eq!(options.remote_command.as_deref(), Some("my send"));
        let (_, options) = ssh(pull_url("none", Some("ssh://h/r")));
        assert_eq!(options, SshOptions::default());
    }

    /// Returns each field of an HTTP address alone, in the order of the
    /// check, with its name.
    fn http_fields() -> Vec<(&'static str, EndpointOverrides)> {
        let d = EndpointOverrides::default;
        vec![
            (
                "tls-ca-path",
                EndpointOverrides {
                    tls_ca_path: Some("/c".into()),
                    ..d()
                },
            ),
            (
                "tls-client-cert-path",
                EndpointOverrides {
                    tls_client_cert_path: Some("/c".into()),
                    ..d()
                },
            ),
            (
                "tls-client-key-path",
                EndpointOverrides {
                    tls_client_key_path: Some("/k".into()),
                    ..d()
                },
            ),
            (
                "allow-cleartext-credentials",
                EndpointOverrides {
                    allow_cleartext_credentials: true,
                    ..d()
                },
            ),
            (
                "http-header",
                EndpointOverrides {
                    http_headers: vec![("A".into(), "B".into())],
                    ..d()
                },
            ),
            (
                "network-retries",
                EndpointOverrides {
                    max_retries: Some(1),
                    ..d()
                },
            ),
            (
                "low-speed-limit-bytes",
                EndpointOverrides {
                    low_speed_limit_bytes: Some(0),
                    ..d()
                },
            ),
            (
                "low-speed-time-seconds",
                EndpointOverrides {
                    low_speed_time: Some(Duration::ZERO),
                    ..d()
                },
            ),
        ]
    }

    /// Returns the overrides that set each field of `fields` from `first` on.
    fn from_field(fields: &[(&str, EndpointOverrides)], first: usize) -> EndpointOverrides {
        let mut o = EndpointOverrides::default();
        for (_, f) in &fields[first..] {
            o.tls_ca_path = o.tls_ca_path.or(f.tls_ca_path.clone());
            o.tls_client_cert_path = o.tls_client_cert_path.or(f.tls_client_cert_path.clone());
            o.tls_client_key_path = o.tls_client_key_path.or(f.tls_client_key_path.clone());
            o.allow_cleartext_credentials |= f.allow_cleartext_credentials;
            o.http_headers.extend(f.http_headers.iter().cloned());
            o.max_retries = o.max_retries.or(f.max_retries);
            o.low_speed_limit_bytes = o.low_speed_limit_bytes.or(f.low_speed_limit_bytes);
            o.low_speed_time = o.low_speed_time.or(f.low_speed_time);
            o.push_token_file = o.push_token_file.or(f.push_token_file.clone());
            o.push_user = o.push_user.or(f.push_user.clone());
        }
        o
    }

    /// For an ssh address, the pull refuses each field of an HTTP address
    /// alone, and names the first one that is set. The message shows the
    /// address with no user. A retry count of 0 is accepted.
    #[test]
    fn the_pull_refuses_each_http_field_for_an_ssh_address() {
        let fields = http_fields();
        for (first, (name, _)) in fields.iter().enumerate() {
            let o = EndpointOverrides {
                url: Some("user-QXZ@h:x".into()),
                ..from_field(&fields, first)
            };
            assert_eq!(
                invalid_input(pull(None, "r", o)),
                format!("{name} applies to a pull over HTTP, and 'ssh://h/~/x' is an ssh address")
            );
        }
        let o = EndpointOverrides {
            url: Some("ssh://h/x".into()),
            max_retries: Some(0),
            ..EndpointOverrides::default()
        };
        ssh(pull(None, "r", o));
    }

    /// The refusal of a field of an HTTP address shows no user name of the
    /// ssh address. It shows the address in the `ssh://` form with no user, so
    /// an `@` in the path stays.
    #[test]
    fn the_refusal_of_an_http_field_shows_no_user_name() {
        for (written, shown) in [
            ("ssh://user-QXZ@ex.com/srv/repo", "ssh://ex.com/srv/repo"),
            ("user-QXZ@ex.com:srv/repo", "ssh://ex.com/~/srv/repo"),
            ("ssh://user-QXZ@ex.com/srv/a@b", "ssh://ex.com/srv/a@b"),
        ] {
            let o = EndpointOverrides {
                url: Some(written.into()),
                http_headers: vec![("A".into(), "B".into())],
                ..EndpointOverrides::default()
            };
            let msg = invalid_input(pull(None, "r", o));
            assert!(!msg.contains("QXZ"), "{written}: {msg}");
            assert_eq!(
                msg,
                format!("http-header applies to a pull over HTTP, and '{shown}' is an ssh address")
            );
        }
    }

    /// A url of the caller replaces the address alone. The pull still reads
    /// the TLS keys and the `proxy` key of the named section.
    #[test]
    fn a_url_override_keeps_the_tls_and_proxy_keys_of_the_section() {
        let dir = Dir::new();
        let config = tls_keys(&dir, "https://ex.com/repo");
        let o = EndpointOverrides {
            url: Some("https://other.ex.com/".into()),
            ..EndpointOverrides::default()
        };
        let http = http_of(pull(Some(&config), "keys", o));
        assert_eq!(http.mirrors, ["https://other.ex.com/"]);
        assert_eq!(http.tls.roots, TrustRoots::Pem(b"KEY-CA".to_vec()));
        assert_eq!(identity(&http), (b"KEY-CERT".to_vec(), b"KEY-KEY".to_vec()));
        assert!(matches!(&http.proxy, Proxy::Url(url) if url == "http://proxy.ex.com:3128"));
    }

    #[cfg(feature = "push")]
    mod push {
        use super::*;

        const CONFIG: &str = "[remote \"both\"]\nurl=https://ex.com/pull\n\
                              push-url=ssh://pusher@ex.com/srv/repo\n\
                              ssh-command=ssh -o BatchMode=yes\n\
                              receive-command=/opt/bin/ostrya receive\n\
                              push-token-file=/etc/ostrya/ssh-token\n\
                              push-user=ssh-user\n\
                              tls-ca-path=/etc/ostrya/ssh-ca.pem\n\
                              tls-client-cert-path=/etc/ostrya/ssh-client.pem\n\
                              tls-client-key-path=/etc/ostrya/ssh-client.key\n\
                              tls-permissive=true\n\n\
                              [remote \"https\"]\nurl=https://ex.com/repo\n\n\
                              [remote \"http-push-url\"]\nurl=https://pull.ex.com/repo\n\
                              push-url=http://push.ex.com/\n\n\
                              [remote \"permissive\"]\nurl=https://ex.com/repo\n\
                              tls-permissive=true\n\n\
                              [remote \"permissive-push-url\"]\nurl=https://ex.com/repo\n\
                              push-url=https://push.ex.com/\n\
                              tls-permissive=true\n\n\
                              [remote \"permissive-http\"]\nurl=https://ex.com/repo\n\
                              push-url=http://push.ex.com/\n\
                              tls-permissive=true\n\n\
                              [remote \"permissive-bad\"]\nurl=http://ex.com/repo\n\
                              tls-permissive=maybe\n\n\
                              [remote \"http\"]\nurl=http://ex.com/repo\n\n\
                              [remote \"file\"]\nurl=file:///srv/repo\n\n\
                              [remote \"metalink\"]\nurl=metalink=https://ex.com/metalink.xml\n\n\
                              [remote \"mirrorlist\"]\nurl=mirrorlist=https://ex.com/mirrors\n\n\
                              [remote \"none\"]\ngpg-verify=false\n\n\
                              [remote \"file-push\"]\nurl=file:///srv/repo\n\
                              push-url=host:srv/repo\n\n\
                              [remote \"bad-url\"]\nurl=a\\zb\n\
                              push-url=ssh://h/p\n";

        fn push(
            config: Option<&RepoConfig>,
            remote: &str,
            o: EndpointOverrides,
        ) -> Result<Endpoint> {
            ostrya_rt::block_on(resolve_push(config, remote, o))
        }

        fn push_named(name: &str) -> Result<Endpoint> {
            push(Some(&config(CONFIG)), name, EndpointOverrides::default())
        }

        fn refused<T: fmt::Debug>(result: Result<T>) -> String {
            match result {
                Err(Error::Remote(remote::Error::InvalidInput(msg))) => msg,
                other => panic!("expected InvalidInput, got {other:?}"),
            }
        }

        /// Returns the address of an endpoint as a string.
        fn address(endpoint: Result<Endpoint>) -> String {
            match endpoint {
                Ok(Endpoint::Http(http)) => {
                    assert_eq!(http.mirrors.len(), 1);
                    http.mirrors[0].clone()
                }
                Ok(Endpoint::Ssh { address, .. }) => address.to_string(),
                other => panic!("{other:?}"),
            }
        }

        fn parsed(value: &str) -> String {
            address(Endpoint::parse(value).map_err(Error::Remote))
        }

        #[test]
        fn a_value_with_a_colon_or_a_slash_is_an_address() {
            let cfg = config(CONFIG);
            for value in [
                "host:srv/repo",
                "host:repo",
                "ssh://host/srv/repo",
                "https://ex.com/r",
            ] {
                let endpoint = push(Some(&cfg), value, EndpointOverrides::default());
                assert_eq!(address(endpoint), parsed(value));
            }
            // No configuration is read for an address.
            let (address, options) = ssh(push(None, "host:srv/repo", EndpointOverrides::default()));
            assert_eq!(address, SshAddress::parse("host:srv/repo").unwrap());
            assert_eq!(options, SshOptions::default());
            let http = http_of(push(None, "https://ex.com/r", EndpointOverrides::default()));
            assert!(matches!(http.proxy, Proxy::Environment));
            assert_eq!(http.tls, TlsOptions::default());
            // An address that does not parse keeps the error of the parser,
            // also when it holds a `/` alone.
            for value in ["ftp://host/r", "srv/repo"] {
                let expected = match Endpoint::parse(value) {
                    Err(remote::Error::InvalidInput(msg)) => msg,
                    other => panic!("{value}: {other:?}"),
                };
                assert_eq!(
                    refused(push(Some(&cfg), value, EndpointOverrides::default())),
                    expected
                );
            }
        }

        #[test]
        fn push_url_wins_over_url() {
            assert_eq!(
                address(push_named("both")),
                parsed("ssh://pusher@ex.com/srv/repo")
            );
            // The push-url is the address also when the url is not a push
            // address.
            assert_eq!(address(push_named("file-push")), parsed("host:srv/repo"));
            // The keyfile cannot read the escape `\z` of this url, and the
            // push does not read it.
            assert!(config(CONFIG).remote("bad-url").unwrap().url().is_err());
            assert_eq!(address(push_named("bad-url")), parsed("ssh://h/p"));
        }

        #[test]
        fn an_http_url_is_the_address_when_push_url_is_absent() {
            assert_eq!(address(push_named("https")), "https://ex.com/repo");
            assert_eq!(address(push_named("http")), "http://ex.com/repo");
            assert_eq!(address(push_named("http-push-url")), "http://push.ex.com/");
        }

        #[test]
        fn a_url_of_another_form_is_no_push_address() {
            for name in ["file", "metalink", "mirrorlist"] {
                let msg = refused(push_named(name));
                assert!(msg.contains("is no push address"), "{msg}");
            }
            assert_eq!(
                refused(push_named("none")),
                "remote 'none' has no push-url and no url"
            );
            let cfg = config(
                "[remote \"upper\"]\nurl=HTTPS://user-QXZ:pw-QXZ@ex.com/repo\n\n\
                 [remote \"ftp\"]\nurl=ftp://user-QXZ:pw-QXZ@ex.com/repo\n",
            );
            for (name, shown) in [
                ("upper", "HTTPS://ex.com/repo"),
                ("ftp", "ftp://ex.com/repo"),
            ] {
                let msg = refused(push(Some(&cfg), name, EndpointOverrides::default()));
                assert!(!msg.contains("QXZ"), "{name}: {msg}");
                assert_eq!(
                    msg,
                    format!(
                        "remote '{name}' has no push-url, and its url '{shown}' is no push \
                         address"
                    )
                );
            }
        }

        #[test]
        fn an_unknown_remote_is_refused_by_the_push() {
            assert_eq!(
                refused(push_named("absent")),
                "no remote 'absent' is configured"
            );
            assert_eq!(
                refused(push(None, "both", EndpointOverrides::default())),
                "no remote 'both' is configured"
            );
        }

        #[test]
        fn the_push_refuses_a_url_override() {
            for remote in ["https", "host:srv/repo", "absent"] {
                let o = EndpointOverrides {
                    url: Some("https://ex.com/repo".into()),
                    ..EndpointOverrides::default()
                };
                assert_eq!(
                    refused(push(Some(&config(CONFIG)), remote, o)),
                    "url applies to a pull, and this is a push"
                );
            }
        }

        #[test]
        fn the_push_refuses_tls_permissive_for_https() {
            for name in ["permissive", "permissive-push-url"] {
                assert_eq!(
                    refused(push_named(name)),
                    format!(
                        "remote '{name}' sets tls-permissive=true, which a push refuses: a \
                         push verifies the certificate chain of the server"
                    )
                );
            }
            // An `http://` push address uses no TLS, so the push does not read
            // the key. A value that is not a boolean causes no error.
            assert_eq!(
                address(push_named("permissive-http")),
                "http://push.ex.com/"
            );
            assert_eq!(address(push_named("permissive-bad")), "http://ex.com/repo");
            // An address reads no section, so no key refuses it.
            push(
                Some(&config(CONFIG)),
                "https://ex.com/repo",
                EndpointOverrides::default(),
            )
            .unwrap();
        }

        /// The push reads the `proxy` key of the section. It refuses a value
        /// with white space before it reads a file.
        #[test]
        fn the_push_reads_the_proxy_key() {
            let dir = Dir::new();
            let cfg = tls_keys(&dir, "https://ex.com/repo");
            let http = http_of(push(Some(&cfg), "keys", EndpointOverrides::default()));
            assert!(matches!(&http.proxy, Proxy::Url(url) if url == "http://proxy.ex.com:3128"));
            let http = http_of(push_named("https"));
            assert!(matches!(http.proxy, Proxy::Environment));
            let cfg = config(&format!(
                "[remote \"p\"]\nurl=https://ex.com/repo\nproxy=\\s\npush-token-file={}\n",
                dir.absent("absent").display()
            ));
            match push(Some(&cfg), "p", EndpointOverrides::default()) {
                Err(Error::Unsupported(msg)) => assert!(msg.contains("white space"), "{msg}"),
                other => panic!("{other:?}"),
            }
        }

        /// A token with `push-user` gives `basic_auth`. A token alone gives
        /// `bearer_token`.
        #[test]
        fn a_push_token_gives_a_bearer_token_or_a_basic_credential() {
            let dir = Dir::new();
            let cfg = tls_keys(&dir, "https://ex.com/repo");
            let http = http_of(push(Some(&cfg), "keys", EndpointOverrides::default()));
            assert_eq!(
                http.basic_auth,
                Some(BasicAuth {
                    user: "alice".into(),
                    password: "KEY-TOKEN".into()
                })
            );
            assert_eq!(http.bearer_token, None);
            assert_eq!(http.tls.roots, TrustRoots::Pem(b"KEY-CA".to_vec()));
            assert_eq!(identity(&http), (b"KEY-CERT".to_vec(), b"KEY-KEY".to_vec()));

            let token = dir.file("t", b"s3cr3t==\n");
            let o = EndpointOverrides {
                push_token_file: Some(token),
                ..EndpointOverrides::default()
            };
            let http = http_of(push(None, "https://ex.com/r", o));
            assert_eq!(
                http.bearer_token,
                Some(BearerToken {
                    token: "s3cr3t==".into()
                })
            );
            assert_eq!(http.basic_auth, None);
            // With no token, the push has no credential.
            let http = http_of(push_named("https"));
            assert_eq!(http.bearer_token, None);
            assert_eq!(http.basic_auth, None);
        }

        /// An override wins over each key of the push on its own.
        #[test]
        fn an_override_wins_over_each_key_of_the_push() {
            let dir = Dir::new();
            let cfg = tls_keys(&dir, "https://ex.com/repo");
            let [ca, cert, key, token] = given(&dir);
            let resolve = |o: EndpointOverrides| http_of(push(Some(&cfg), "keys", o));
            let d = EndpointOverrides::default;

            let http = resolve(EndpointOverrides {
                push_token_file: Some(token),
                ..d()
            });
            assert_eq!(http.basic_auth.unwrap().password, "GIVEN-TOKEN");
            let http = resolve(EndpointOverrides {
                push_user: Some("bob".into()),
                ..d()
            });
            let auth = http.basic_auth.unwrap();
            assert_eq!(
                (auth.user.as_str(), auth.password.as_str()),
                ("bob", "KEY-TOKEN")
            );
            let http = resolve(EndpointOverrides {
                tls_ca_path: Some(ca),
                ..d()
            });
            assert_eq!(http.tls.roots, TrustRoots::Pem(b"GIVEN-CA".to_vec()));
            assert_eq!(identity(&http), (b"KEY-CERT".to_vec(), b"KEY-KEY".to_vec()));
            let http = resolve(EndpointOverrides {
                tls_client_cert_path: Some(cert),
                ..d()
            });
            assert_eq!(http.tls.roots, TrustRoots::Pem(b"KEY-CA".to_vec()));
            assert_eq!(
                identity(&http),
                (b"GIVEN-CERT".to_vec(), b"KEY-KEY".to_vec())
            );
            let http = resolve(EndpointOverrides {
                tls_client_key_path: Some(key),
                ..d()
            });
            assert_eq!(
                identity(&http),
                (b"KEY-CERT".to_vec(), b"GIVEN-KEY".to_vec())
            );
        }

        /// The push applies the headers, the cleartext permission, the retry
        /// count, and the low-speed rule of the caller.
        #[test]
        fn the_push_applies_the_http_overrides() {
            let defaults = FetcherOptions::default();
            let http = http_of(push_named("https"));
            assert_eq!(http.max_retries, defaults.max_retries);
            assert_eq!(http.max_outstanding, defaults.max_outstanding);
            assert_eq!(http.low_speed, None);
            assert!(http.headers.is_empty());
            assert!(!http.allow_cleartext_credentials);

            let o = EndpointOverrides {
                http_headers: vec![("X-A".into(), "b".into())],
                allow_cleartext_credentials: true,
                max_retries: Some(0),
                ..EndpointOverrides::default()
            };
            let http = http_of(push(Some(&config(CONFIG)), "https", o));
            assert_eq!(http.headers, [("X-A".to_owned(), "b".to_owned())]);
            assert!(http.allow_cleartext_credentials);
            assert_eq!(http.max_retries, 0);

            let secs = Duration::from_secs;
            for (limit, time, expected) in [
                (Some(5), None, Some((5, secs(30)))),
                (None, Some(secs(10)), Some((1000, secs(10)))),
                (Some(5), Some(secs(10)), Some((5, secs(10)))),
                (Some(0), None, None),
                (None, Some(Duration::ZERO), None),
            ] {
                let o = EndpointOverrides {
                    low_speed_limit_bytes: limit,
                    low_speed_time: time,
                    ..EndpointOverrides::default()
                };
                let http = http_of(push(Some(&config(CONFIG)), "https", o));
                let expected = expected.map(|(limit, time)| LowSpeed { limit, time });
                assert_eq!(http.low_speed, expected, "{limit:?} {time:?}");
            }
        }

        /// `push_user` needs a token file. It cannot be empty or hold `:`.
        /// The refusals come before the push reads a file.
        #[test]
        fn push_user_needs_a_token_file() {
            let dir = Dir::new();
            let o = EndpointOverrides {
                push_user: Some("alice".into()),
                ..EndpointOverrides::default()
            };
            assert_eq!(
                refused(push(None, "https://h/", o)),
                "push-user needs push-token-file"
            );
            for user in ["", "a:b"] {
                let o = EndpointOverrides {
                    push_user: Some(user.into()),
                    push_token_file: Some(dir.absent("absent")),
                    ..EndpointOverrides::default()
                };
                assert_eq!(
                    refused(push(None, "https://h/", o)),
                    "push-user is empty or holds ':', which a Basic credential cannot carry"
                );
            }
        }

        /// A token to an `http://` address without the cleartext permission
        /// is refused before the push reads a file. The token file and the
        /// CA file are absent, so a read gives an I/O error in place of the
        /// refusal.
        #[test]
        fn the_push_refuses_a_cleartext_token_before_it_reads_a_file() {
            let dir = Dir::new();
            let absent = dir.absent("absent");
            let expected = |address: &str| {
                format!(
                    "the push address '{address}' is http://, so the token would travel in \
                     cleartext: use https, or set allow-cleartext-credentials"
                )
            };
            let o = EndpointOverrides {
                push_token_file: Some(absent.clone()),
                tls_ca_path: Some(absent.clone()),
                ..EndpointOverrides::default()
            };
            assert_eq!(refused(push(None, "http://h/", o)), expected("http://h/"));
            let cfg = config(&format!(
                "[remote \"keys\"]\nurl=http://ex.com/repo\n\
                 push-token-file={0}\ntls-ca-path={0}\n",
                absent.display()
            ));
            assert_eq!(
                refused(push(Some(&cfg), "keys", EndpointOverrides::default())),
                expected("http://ex.com/repo")
            );
        }

        /// With `allow_cleartext_credentials`, a token goes to an `http://`
        /// address.
        #[test]
        fn the_cleartext_permission_lets_a_token_go_to_an_http_address() {
            let dir = Dir::new();
            let cfg = tls_keys(&dir, "http://ex.com/repo");
            let o = EndpointOverrides {
                allow_cleartext_credentials: true,
                ..EndpointOverrides::default()
            };
            let http = http_of(push(Some(&cfg), "keys", o));
            assert!(http.allow_cleartext_credentials);
            assert_eq!(
                http.basic_auth,
                Some(BasicAuth {
                    user: "alice".into(),
                    password: "KEY-TOKEN".into()
                })
            );
            assert_eq!(http.tls, TlsOptions::default());

            let o = EndpointOverrides {
                push_token_file: Some(dir.file("t", b"s3cr3t==\n")),
                allow_cleartext_credentials: true,
                ..EndpointOverrides::default()
            };
            let http = http_of(push(None, "http://h/", o));
            assert_eq!(
                http.bearer_token,
                Some(BearerToken {
                    token: "s3cr3t==".into()
                })
            );
        }

        /// An `http://` push address uses no TLS, so the push reads no TLS
        /// file of the caller or of the keys. The files are absent, so a read
        /// gives an I/O error.
        #[test]
        fn a_cleartext_push_reads_no_tls_file() {
            let dir = Dir::new();
            let absent = dir.absent("absent");
            let o = EndpointOverrides {
                tls_ca_path: Some(absent.clone()),
                tls_client_cert_path: Some(absent.clone()),
                tls_client_key_path: Some(absent.clone()),
                ..EndpointOverrides::default()
            };
            let http = http_of(push(None, "http://h/", o));
            assert_eq!(http.tls, TlsOptions::default());
            let cfg = config(&format!(
                "[remote \"keys\"]\nurl=http://ex.com/repo\n\
                 tls-ca-path={0}\ntls-client-cert-path={0}\ntls-client-key-path={0}\n",
                absent.display()
            ));
            let http = http_of(push(Some(&cfg), "keys", EndpointOverrides::default()));
            assert_eq!(http.tls, TlsOptions::default());
        }

        /// The push gives an `Authorization` header of the caller beside the
        /// token. The HTTP client of the push session refuses the pair, so
        /// the session does not send one of the two in place of the other.
        #[test]
        fn the_push_session_refuses_an_authorization_header_beside_a_token() {
            let dir = Dir::new();
            let token = dir.file("t", b"s3cr3t==\n");
            for (user, part) in [
                (None, "a bearer token and an authorization header"),
                (
                    Some("alice"),
                    "basic-auth credentials and an authorization header",
                ),
            ] {
                let o = EndpointOverrides {
                    push_token_file: Some(token.clone()),
                    push_user: user.map(str::to_owned),
                    http_headers: vec![("Authorization".into(), "Bearer other".into())],
                    ..EndpointOverrides::default()
                };
                let endpoint = push(None, "https://h/", o).unwrap();
                match ostrya_rt::block_on(remote::PushSession::prepare(endpoint)) {
                    Err(remote::Error::Fetch(e)) => {
                        let msg = e.to_string();
                        assert!(msg.contains(part), "{msg}");
                        assert!(!msg.contains("s3cr3t"), "{msg}");
                    }
                    other => panic!("{user:?}: {other:?}"),
                }
            }
        }

        /// A lone certificate or a lone key is refused before the push reads
        /// a file.
        #[test]
        fn a_lone_certificate_or_key_is_refused_by_the_push() {
            let dir = Dir::new();
            let absent = dir.absent("absent");
            for (cert, key) in [(Some(absent.clone()), None), (None, Some(absent.clone()))] {
                // An `http://` address reads no TLS file, and the refusal
                // stays.
                for address in ["https://h/", "http://h/"] {
                    let o = EndpointOverrides {
                        push_token_file: Some(absent.clone()),
                        tls_ca_path: Some(absent.clone()),
                        tls_client_cert_path: cert.clone(),
                        tls_client_key_path: key.clone(),
                        ..EndpointOverrides::default()
                    };
                    assert_eq!(
                        refused(push(None, address, o)),
                        "a client certificate needs both tls-client-cert-path and \
                         tls-client-key-path"
                    );
                }
            }
        }

        /// A file over 1 MiB and an absent file fail the push, and the error
        /// names the key and the path.
        #[test]
        fn a_file_over_the_cap_fails_the_push() {
            let dir = Dir::new();
            let long = dir.file("long", &vec![b'a'; FILE_CAP as usize + 1]);
            let absent = dir.absent("absent");
            let pem = dir.file("pem", b"");
            type Field = fn(&mut EndpointOverrides) -> &mut Option<PathBuf>;
            let cases: [(&str, Field); 4] = [
                ("push-token-file", |o| &mut o.push_token_file),
                ("tls-ca-path", |o| &mut o.tls_ca_path),
                ("tls-client-cert-path", |o| &mut o.tls_client_cert_path),
                ("tls-client-key-path", |o| &mut o.tls_client_key_path),
            ];
            for (key, field) in cases {
                let mut o = EndpointOverrides {
                    tls_client_cert_path: Some(pem.clone()),
                    tls_client_key_path: Some(pem.clone()),
                    ..EndpointOverrides::default()
                };
                *field(&mut o) = Some(long.clone());
                let msg = invalid_input(push(None, "https://h/", o.clone()));
                assert!(
                    msg.contains(&format!("{key} '{}'", long.display())),
                    "{msg}"
                );
                assert!(msg.ends_with("over 1 MiB"), "{msg}");
                *field(&mut o) = Some(absent.clone());
                let m = not_found(push(None, "https://h/", o));
                assert!(
                    m.starts_with(&format!("{key} '{}': ", absent.display())),
                    "{m}"
                );
            }
        }

        /// An HTTP push refuses the ssh fields of the caller, and it does not
        /// read the ssh keys of the section.
        #[test]
        fn the_push_refuses_the_ssh_fields_for_an_http_address() {
            for (name, o) in [
                (
                    "ssh-command",
                    EndpointOverrides {
                        ssh_command: Some(vec!["ssh".into()]),
                        remote_command: Some("ostrya receive".into()),
                        ..EndpointOverrides::default()
                    },
                ),
                (
                    "receive-command",
                    EndpointOverrides {
                        remote_command: Some("ostrya receive".into()),
                        ..EndpointOverrides::default()
                    },
                ),
            ] {
                assert_eq!(
                    refused(push(None, "https://h/", o)),
                    format!(
                        "{name} applies to an ssh address, and 'https://h/' is an HTTP address"
                    )
                );
            }
            // The keyfile cannot read the escape `\z` of these keys, and the
            // push does not read them.
            let cfg = config(
                "[remote \"bad-ssh\"]\nurl=https://ex.com/repo\n\
                 ssh-command=a\\zb\nreceive-command=a\\zb\n",
            );
            let section = cfg.remote("bad-ssh").unwrap();
            assert!(section.ssh_command().is_err());
            assert!(section.receive_command().is_err());
            assert_eq!(
                address(push(Some(&cfg), "bad-ssh", EndpointOverrides::default())),
                "https://ex.com/repo"
            );
        }

        /// The keys fill the ssh options that the caller leaves `None`. The
        /// push does not read the HTTP keys of the section.
        #[test]
        fn the_push_fills_the_ssh_options_from_the_keys() {
            let (_, options) = ssh(push_named("both"));
            assert_eq!(
                options,
                SshOptions {
                    command: None,
                    config_command: Some("ssh -o BatchMode=yes".into()),
                    remote_command: Some("/opt/bin/ostrya receive".into()),
                }
            );
            let o = EndpointOverrides {
                ssh_command: Some(vec!["my-ssh".into()]),
                remote_command: Some("receiver".into()),
                ..EndpointOverrides::default()
            };
            let (_, options) = ssh(push(Some(&config(CONFIG)), "both", o.clone()));
            assert_eq!(
                options,
                SshOptions {
                    command: Some(vec!["my-ssh".into()]),
                    config_command: Some("ssh -o BatchMode=yes".into()),
                    remote_command: Some("receiver".into()),
                }
            );
            let (_, options) = ssh(push(None, "h:r", o));
            assert_eq!(options.config_command, None);
            assert_eq!(options.remote_command.as_deref(), Some("receiver"));
        }

        /// For an ssh address, the push refuses each field of an HTTP address
        /// alone, and names the first one that is set. The message shows the
        /// address with no user. A retry count of 0 is accepted.
        #[test]
        fn the_push_refuses_each_http_field_for_an_ssh_address() {
            let d = EndpointOverrides::default;
            let mut fields = vec![
                (
                    "push-token-file",
                    EndpointOverrides {
                        push_token_file: Some("/t".into()),
                        ..d()
                    },
                ),
                (
                    "push-user",
                    EndpointOverrides {
                        push_user: Some("u".into()),
                        ..d()
                    },
                ),
            ];
            fields.extend(http_fields());
            for (first, (name, _)) in fields.iter().enumerate() {
                let o = from_field(&fields, first);
                assert_eq!(
                    refused(push(None, "user-QXZ@h:x", o)),
                    format!(
                        "{name} applies to an HTTP address, and 'ssh://h/~/x' is an ssh address"
                    )
                );
            }
            // The message shows the `ssh://` form with no user. An `@` in the
            // path stays.
            for (value, shown) in [
                ("ssh://user-QXZ@ex.com/srv/repo", "ssh://ex.com/srv/repo"),
                ("user-QXZ@ex.com:srv/a@b", "ssh://ex.com/~/srv/a@b"),
            ] {
                let o = EndpointOverrides {
                    push_user: Some("u".into()),
                    ..d()
                };
                assert_eq!(
                    refused(push(None, value, o)),
                    format!(
                        "push-user applies to an HTTP address, and '{shown}' is an ssh address"
                    )
                );
            }
            let o = EndpointOverrides {
                max_retries: Some(0),
                ..d()
            };
            ssh(push(None, "h:x", o));
        }

        /// The push refuses each S3 field for an HTTP address and for an
        /// ssh address, for a remote name and for an address.
        #[test]
        fn the_push_refuses_the_s3_fields_for_another_address() {
            for (name, o) in s3_fields() {
                for (remote, shown) in [
                    ("https", "'https://ex.com/repo' is an HTTP address"),
                    ("https://ex.com/r", "'https://ex.com/r' is an HTTP address"),
                    ("ssh://u-QXZ@h/r", "'ssh://h/r' is an ssh address"),
                ] {
                    assert_eq!(
                        refused(push(Some(&config(CONFIG)), remote, o.clone())),
                        format!("{name} applies to an s3:// address, and {shown}")
                    );
                }
            }
        }

        /// A `url` with an `s3://` address is no push address, and the
        /// message names the `s3://` form with no userinfo.
        #[test]
        fn an_s3_address_in_url_is_no_push_address() {
            let config = config(S3_SECTIONS);
            for name in ["s3-url", "s3-url-user"] {
                assert_eq!(
                    refused(push(Some(&config), name, EndpointOverrides::default())),
                    format!(
                        "remote '{name}' has no push-url, and its url 's3://bkt/repo' is an \
                         s3:// address; the port reads an s3:// address from push-url alone"
                    )
                );
            }
        }

        /// An S3 key in a remote with no `s3://` address is refused for a
        /// push too.
        #[test]
        fn an_s3_key_with_no_s3_address_is_refused_by_the_push() {
            let config = config(S3_SECTIONS);
            assert_eq!(
                refused(push(
                    Some(&config),
                    "stray-key",
                    EndpointOverrides::default()
                )),
                "remote 'stray-key': s3-profile applies to an s3:// address, and neither \
                 pull-url nor push-url holds one"
            );
        }

        /// A build without the `s3` feature refuses an `s3://` push address,
        /// and the message names the feature and shows no userinfo.
        #[cfg(not(feature = "s3"))]
        #[test]
        fn a_build_without_s3_refuses_an_s3_push_address() {
            let config = config(S3_SECTIONS);
            for result in [
                push(Some(&config), "push", EndpointOverrides::default()),
                push(
                    None,
                    "s3://AKID-QXZ:s@bkt/repo",
                    EndpointOverrides::default(),
                ),
            ] {
                match result {
                    Err(Error::Unsupported(msg)) => {
                        assert!(msg.contains("the feature s3 of ostrya"), "{msg}");
                        assert!(msg.contains("'s3://bkt/repo'"), "{msg}");
                        assert!(!msg.contains("QXZ"), "{msg}");
                    }
                    other => panic!("{other:?}"),
                }
            }
        }
    }

    /// Returns each S3 field alone, with the name of its key.
    fn s3_fields() -> Vec<(&'static str, EndpointOverrides)> {
        let d = EndpointOverrides::default;
        vec![
            (
                "s3-region",
                EndpointOverrides {
                    s3_region: Some("eu-west-1".into()),
                    ..d()
                },
            ),
            (
                "s3-endpoint",
                EndpointOverrides {
                    s3_endpoint: Some("https://s3.ex.com".into()),
                    ..d()
                },
            ),
            (
                "s3-addressing",
                EndpointOverrides {
                    s3_addressing: Some("path".into()),
                    ..d()
                },
            ),
            (
                "s3-profile",
                EndpointOverrides {
                    s3_profile: Some("p".into()),
                    ..d()
                },
            ),
        ]
    }

    const S3_SECTIONS: &str = "[remote \"s3-url\"]\nurl=s3://bkt/repo\n\n\
                               [remote \"s3-url-user\"]\nurl=s3://u-QXZ:p-QXZ@bkt/repo\n\n\
                               [remote \"pull\"]\npull-url=s3://bkt/repo\n\n\
                               [remote \"push\"]\nurl=https://ex.com/repo\n\
                               push-url=s3://bkt/repo\ns3-region=eu-west-1\n\n\
                               [remote \"stray-key\"]\nurl=https://ex.com/repo\n\
                               push-url=ssh://h/srv/repo\ns3-profile=p\n\n\
                               [remote \"stray-region\"]\npull-url=https://ex.com/repo\n\
                               s3-region=eu-west-1\ns3-endpoint=https://s3.ex.com\n";

    /// The pull refuses an `s3://` address in `url`, in each build, and
    /// shows no userinfo.
    #[test]
    fn an_s3_address_in_url_is_refused() {
        let config = config(S3_SECTIONS);
        for name in ["s3-url", "s3-url-user"] {
            let msg = pull_error(pull(Some(&config), name, EndpointOverrides::default()));
            assert_eq!(
                msg,
                format!(
                    "remote '{name}': url 's3://bkt/repo' is an s3:// address; the port reads \
                     an s3:// address from pull-url alone"
                )
            );
        }
    }

    /// The address of a pull is `s3://` by the order of the pull: the url of
    /// the caller, then `pull-url`, then `url`. An `s3://` address in `url`
    /// and an absent remote give `None`, the refusal of the resolver.
    #[test]
    fn the_s3_test_of_a_pull_address_follows_the_order_of_the_pull() {
        let config = config(S3_SECTIONS);
        let is_s3 = |remote, url| pull_address_is_s3(Some(&config), remote, url);
        assert_eq!(is_s3("pull", None), Some(true));
        assert_eq!(is_s3("push", None), Some(false));
        assert_eq!(is_s3("s3-url", None), None);
        assert_eq!(is_s3("absent", None), None);
        assert_eq!(is_s3("push", Some("s3://b/x")), Some(true));
        assert_eq!(is_s3("pull", Some("https://ex.com/r")), Some(false));
        assert_eq!(is_s3("pull", Some("h:/srv/r")), Some(false));
        assert_eq!(pull_address_is_s3(None, "r", Some("s3://b/x")), Some(true));
        assert_eq!(pull_address_is_s3(None, "r", None), None);
    }

    /// An S3 key in a remote whose `pull-url` and `push-url` hold no `s3://`
    /// address is refused, also with an `s3://` url of the caller. A remote
    /// with an `s3://` `push-url` keeps its HTTP pull with the S3 keys.
    #[test]
    fn an_s3_key_with_no_s3_address_is_refused() {
        let config = config(S3_SECTIONS);
        for (name, key, url) in [
            ("stray-key", "s3-profile", None),
            ("stray-region", "s3-region", None),
            ("stray-region", "s3-region", Some("s3://bkt/repo")),
        ] {
            let o = EndpointOverrides {
                url: url.map(str::to_owned),
                ..EndpointOverrides::default()
            };
            assert_eq!(
                pull_error(pull(Some(&config), name, o)),
                format!(
                    "remote '{name}': {key} applies to an s3:// address, and neither \
                     pull-url nor push-url holds one"
                )
            );
        }
        assert_eq!(
            mirror(pull(Some(&config), "push", EndpointOverrides::default())),
            "https://ex.com/repo"
        );
    }

    /// The pull refuses each S3 field for an HTTP address and for an ssh
    /// address, and names it by its key.
    #[test]
    fn the_pull_refuses_the_s3_fields_for_another_address() {
        for (name, o) in s3_fields() {
            let http = EndpointOverrides {
                url: Some("https://ex.com/repo".into()),
                ..o.clone()
            };
            assert_eq!(
                invalid_input(pull(None, "r", http)),
                format!(
                    "{name} applies to a pull from an s3:// address, and this pull runs over \
                     HTTP"
                )
            );
            let ssh = EndpointOverrides {
                url: Some("user-QXZ@h:x".into()),
                ..o
            };
            assert_eq!(
                invalid_input(pull(None, "r", ssh)),
                format!(
                    "{name} applies to a pull from an s3:// address, and 'ssh://h/~/x' is an \
                     ssh address"
                )
            );
        }
    }

    /// The pull refuses the fields of a push for an `s3://` address, in each
    /// build.
    #[test]
    fn the_pull_refuses_the_fields_of_a_push_for_an_s3_address() {
        for (name, o) in [
            (
                "push-token-file",
                EndpointOverrides {
                    push_token_file: Some("/t".into()),
                    ..EndpointOverrides::default()
                },
            ),
            (
                "push-user",
                EndpointOverrides {
                    push_user: Some("alice".into()),
                    ..EndpointOverrides::default()
                },
            ),
        ] {
            let o = EndpointOverrides {
                url: Some("s3://bkt/repo".into()),
                ..o
            };
            assert_eq!(
                invalid_input(pull(None, "r", o)),
                format!("{name} applies to a push, and this is a pull")
            );
        }
    }

    /// The `Debug` output shows the S3 endpoint with no userinfo.
    #[test]
    fn the_debug_output_shows_no_userinfo_of_the_s3_endpoint() {
        let o = EndpointOverrides {
            s3_endpoint: Some("https://user-QXZ:pw-QXZ@s3.ex.com".into()),
            s3_profile: Some("prod".into()),
            ..EndpointOverrides::default()
        };
        let text = format!("{o:?}");
        assert!(!text.contains("QXZ"), "{text}");
        assert!(text.contains("https://s3.ex.com"), "{text}");
        assert!(text.contains("prod"), "{text}");
    }

    /// A build without the `s3` feature refuses an `s3://` address, and the
    /// message names the feature.
    #[cfg(not(feature = "s3"))]
    #[test]
    fn a_build_without_s3_refuses_an_s3_address() {
        let config = config(S3_SECTIONS);
        let o = EndpointOverrides {
            url: Some("s3://bkt/repo".into()),
            ..EndpointOverrides::default()
        };
        for result in [
            pull(Some(&config), "pull", EndpointOverrides::default()),
            pull(None, "r", o),
        ] {
            match result {
                Err(Error::Unsupported(msg)) => {
                    assert!(msg.contains("the feature s3 of ostrya"), "{msg}")
                }
                other => panic!("{other:?}"),
            }
        }
    }

    /// The refusal of an `s3://` address by a build without the `s3`
    /// feature shows no userinfo of the address.
    #[cfg(not(feature = "s3"))]
    #[test]
    fn the_refusal_of_an_s3_address_shows_no_userinfo() {
        let config = config("[remote \"keyed\"]\npull-url=s3://AKID-QXZ:secret-QXZ@bkt/repo\n");
        let o = EndpointOverrides {
            url: Some("s3://AKID-QXZ:secret-QXZ@bkt/repo".into()),
            ..EndpointOverrides::default()
        };
        for result in [
            pull(Some(&config), "keyed", EndpointOverrides::default()),
            pull(None, "r", o),
        ] {
            match result {
                Err(Error::Unsupported(msg)) => {
                    assert!(!msg.contains("QXZ"), "{msg}");
                    assert!(msg.contains("'s3://bkt/repo'"), "{msg}");
                }
                other => panic!("{other:?}"),
            }
        }
    }

    #[cfg(feature = "s3")]
    mod s3 {
        use super::*;
        use crate::remote::s3::{Addressing, Environment, S3Endpoint};

        /// Returns the environment of a test: a key pair, the two shared
        /// files at absent paths under `dir`, and then `extra`.
        fn env(dir: &Dir, extra: &[(&str, &str)]) -> Environment {
            let mut variables = vec![
                ("AWS_ACCESS_KEY_ID".to_owned(), "AKIDEXAMPLE".to_owned()),
                ("AWS_SECRET_ACCESS_KEY".to_owned(), "SECRET-QXZ".to_owned()),
                (
                    "AWS_CONFIG_FILE".to_owned(),
                    dir.absent("aws-config").display().to_string(),
                ),
                (
                    "AWS_SHARED_CREDENTIALS_FILE".to_owned(),
                    dir.absent("aws-credentials").display().to_string(),
                ),
            ];
            variables.extend(
                extra
                    .iter()
                    .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
            );
            Environment::Variables(variables)
        }

        fn pull_in(
            config: Option<&RepoConfig>,
            remote: &str,
            o: EndpointOverrides,
            env: &Environment,
        ) -> Result<Endpoint> {
            ostrya_rt::block_on(resolve_pull_in(config, remote, o, env))
        }

        fn s3_of(endpoint: Result<Endpoint>) -> S3Endpoint {
            match endpoint {
                Ok(Endpoint::S3(s3)) => s3,
                other => panic!("{other:?}"),
            }
        }

        /// An `s3://` address of `pull-url` or of the caller gives an S3
        /// endpoint with the defaults of a pull.
        #[test]
        fn an_s3_address_gives_an_s3_endpoint() {
            let dir = Dir::new();
            let config = config(S3_SECTIONS);
            let other = EndpointOverrides {
                url: Some("s3://other/x".into()),
                ..EndpointOverrides::default()
            };
            for (name, o, repository) in [
                (
                    "pull",
                    EndpointOverrides::default(),
                    "https://bkt.s3.us-east-1.amazonaws.com/repo",
                ),
                (
                    "absent",
                    other,
                    "https://other.s3.us-east-1.amazonaws.com/x",
                ),
            ] {
                let s3 = s3_of(pull_in(Some(&config), name, o, &env(&dir, &[])));
                assert_eq!(s3.location.repository_url(), repository);
                assert_eq!(s3.location.region(), "us-east-1");
                assert_eq!(s3.credentials.access_key_id(), "AKIDEXAMPLE");
                assert_eq!(s3.http.max_retries, 5);
                assert_eq!(s3.http.max_outstanding, 8);
                assert_eq!(
                    s3.http.low_speed,
                    Some(LowSpeed {
                        limit: 1000,
                        time: Duration::from_secs(30)
                    })
                );
                assert_eq!(s3.http.tls, TlsOptions::default());
                assert!(matches!(s3.http.proxy, Proxy::Environment));
                assert!(!s3.http.allow_cleartext_credentials);
                assert!(s3.http.mirrors.is_empty());
                assert!(s3.http.signer.is_none());
            }
        }

        /// A field of the caller wins over its key, and a key wins over the
        /// environment.
        #[test]
        fn an_override_wins_over_the_key_and_the_key_over_the_environment() {
            let dir = Dir::new();
            let config = config(
                "[remote \"keys\"]\npull-url=s3://bkt/repo\ns3-region=eu-west-1\n\
                 s3-endpoint=https://keys.ex.com\ns3-addressing=virtual\n\n\
                 [remote \"bare\"]\npull-url=s3://bkt/repo\n",
            );
            let env = env(
                &dir,
                &[
                    ("AWS_REGION", "us-west-2"),
                    ("AWS_ENDPOINT_URL_S3", "https://env.ex.com"),
                ],
            );
            let s3 = s3_of(pull_in(
                Some(&config),
                "keys",
                EndpointOverrides::default(),
                &env,
            ));
            assert_eq!(s3.location.region(), "eu-west-1");
            assert_eq!(s3.location.endpoint(), "https://keys.ex.com");
            assert_eq!(s3.location.addressing(), Addressing::Virtual);
            assert_eq!(s3.location.repository_url(), "https://bkt.keys.ex.com/repo");
            let o = EndpointOverrides {
                s3_region: Some("ap-south-1".into()),
                s3_endpoint: Some("https://given.ex.com".into()),
                s3_addressing: Some("path".into()),
                ..EndpointOverrides::default()
            };
            let s3 = s3_of(pull_in(Some(&config), "keys", o, &env));
            assert_eq!(s3.location.region(), "ap-south-1");
            assert_eq!(s3.location.endpoint(), "https://given.ex.com");
            assert_eq!(
                s3.location.repository_url(),
                "https://given.ex.com/bkt/repo"
            );
            // With no key and no field, the environment gives the values.
            let s3 = s3_of(pull_in(
                Some(&config),
                "bare",
                EndpointOverrides::default(),
                &env,
            ));
            assert_eq!(s3.location.region(), "us-west-2");
            assert_eq!(s3.location.endpoint(), "https://env.ex.com");
        }

        /// A profile that the key `s3-profile` names turns off the key pair
        /// of the environment.
        #[test]
        fn a_profile_of_the_key_turns_off_the_keys_of_the_environment() {
            let dir = Dir::new();
            let credentials = dir.file(
                "credentials",
                b"[keyed]\naws_access_key_id = AKIDPROFILE\naws_secret_access_key = S\n",
            );
            let config = config("[remote \"p\"]\npull-url=s3://bkt/repo\ns3-profile=keyed\n");
            let env = Environment::Variables(vec![
                ("AWS_ACCESS_KEY_ID".into(), "AKIDEXAMPLE".into()),
                ("AWS_SECRET_ACCESS_KEY".into(), "SECRET-QXZ".into()),
                (
                    "AWS_CONFIG_FILE".into(),
                    dir.absent("config").display().to_string(),
                ),
                (
                    "AWS_SHARED_CREDENTIALS_FILE".into(),
                    credentials.display().to_string(),
                ),
            ]);
            let s3 = s3_of(pull_in(
                Some(&config),
                "p",
                EndpointOverrides::default(),
                &env,
            ));
            assert_eq!(s3.credentials.access_key_id(), "AKIDPROFILE");
        }

        /// A style other than `path` and `virtual` is refused, from the key
        /// and from a field.
        #[test]
        fn a_bad_addressing_style_is_refused() {
            let dir = Dir::new();
            let config = config("[remote \"auto\"]\npull-url=s3://bkt/repo\ns3-addressing=auto\n");
            assert_eq!(
                invalid_input(pull_in(
                    Some(&config),
                    "auto",
                    EndpointOverrides::default(),
                    &env(&dir, &[])
                )),
                "s3-addressing 'auto' is neither path nor virtual"
            );
            let o = EndpointOverrides {
                url: Some("s3://bkt/repo".into()),
                s3_addressing: Some("Path".into()),
                ..EndpointOverrides::default()
            };
            assert_eq!(
                invalid_input(pull_in(None, "r", o, &env(&dir, &[]))),
                "s3-addressing 'Path' is neither path nor virtual"
            );
        }

        /// The pull refuses the ssh fields for an `s3://` address.
        #[test]
        fn the_pull_refuses_the_ssh_fields_for_an_s3_address() {
            let dir = Dir::new();
            for (name, o) in [
                (
                    "ssh-command",
                    EndpointOverrides {
                        ssh_command: Some(vec!["ssh".into()]),
                        ..EndpointOverrides::default()
                    },
                ),
                (
                    "send-command",
                    EndpointOverrides {
                        remote_command: Some("ostrya send".into()),
                        ..EndpointOverrides::default()
                    },
                ),
            ] {
                let o = EndpointOverrides {
                    url: Some("s3://bkt/repo".into()),
                    ..o
                };
                assert_eq!(
                    invalid_input(pull_in(None, "r", o, &env(&dir, &[]))),
                    format!(
                        "{name} applies to a pull over ssh, and this pull reads an s3:// \
                         address"
                    )
                );
            }
        }

        /// An `http://` endpoint needs the cleartext permission. The endpoint
        /// can come from the environment, so the check comes after the
        /// resolution.
        #[test]
        fn an_http_endpoint_needs_the_cleartext_permission() {
            let dir = Dir::new();
            let config = config(S3_SECTIONS);
            let env = env(&dir, &[("AWS_ENDPOINT_URL", "http://127.0.0.1:9000")]);
            assert_eq!(
                invalid_input(pull_in(
                    Some(&config),
                    "pull",
                    EndpointOverrides::default(),
                    &env,
                )),
                "the S3 endpoint 'http://127.0.0.1:9000' is http://, so the signature of each \
                 request would travel in cleartext: use https, or set \
                 allow-cleartext-credentials"
            );
            let o = EndpointOverrides {
                allow_cleartext_credentials: true,
                ..EndpointOverrides::default()
            };
            let s3 = s3_of(pull_in(Some(&config), "pull", o, &env));
            assert!(s3.http.allow_cleartext_credentials);
            assert_eq!(
                s3.location.repository_url(),
                "http://127.0.0.1:9000/bkt/repo"
            );
        }

        /// The TLS keys, the proxy key, and the HTTP fields of the caller go
        /// into the HTTP options of the S3 endpoint. The pull ignores the ssh
        /// keys and `push-token-file` of the section.
        #[test]
        fn the_http_options_go_into_the_s3_endpoint() {
            let dir = Dir::new();
            let config = tls_keys(&dir, "https://ex.com/repo");
            let o = EndpointOverrides {
                url: Some("s3://bkt/repo".into()),
                http_headers: vec![("X-A".into(), "b".into())],
                max_retries: Some(2),
                low_speed_limit_bytes: Some(0),
                ..EndpointOverrides::default()
            };
            let s3 = s3_of(pull_in(Some(&config), "keys", o, &env(&dir, &[])));
            assert_eq!(s3.http.tls.roots, TrustRoots::Pem(b"KEY-CA".to_vec()));
            assert_eq!(
                identity(&s3.http),
                (b"KEY-CERT".to_vec(), b"KEY-KEY".to_vec())
            );
            assert!(matches!(&s3.http.proxy, Proxy::Url(url) if url == "http://proxy.ex.com:3128"));
            assert_eq!(s3.http.headers, [("X-A".to_owned(), "b".to_owned())]);
            assert_eq!(s3.http.max_retries, 2);
            assert_eq!(s3.http.low_speed, None);
            let config = super::config(
                "[remote \"permissive\"]\npull-url=s3://bkt/repo\ntls-permissive=true\n\
                 tls-ca-path=/nonexistent/ca.pem\n",
            );
            let s3 = s3_of(pull_in(
                Some(&config),
                "permissive",
                EndpointOverrides::default(),
                &env(&dir, &[]),
            ));
            assert_eq!(s3.http.tls.roots, TrustRoots::DangerousAcceptAnyChain);
        }

        /// A refusal that needs no file comes before the read of the shared
        /// files: a credentials file that cannot be read gives no error.
        #[test]
        fn a_refusal_comes_before_the_read_of_the_shared_files() {
            let dir = Dir::new();
            // A directory at the path of the credentials file cannot be read
            // as a file.
            let credentials = dir.absent("aws-credentials");
            std::fs::create_dir(&credentials).unwrap();
            let env = Environment::Variables(vec![(
                "AWS_SHARED_CREDENTIALS_FILE".into(),
                credentials.display().to_string(),
            )]);
            let o = EndpointOverrides {
                url: Some("s3://bkt/repo".into()),
                tls_client_cert_path: Some("/c".into()),
                ..EndpointOverrides::default()
            };
            assert_eq!(
                pull_error(pull_in(None, "r", o, &env)),
                "remote 'r': a client certificate needs both tls-client-cert-path and \
                 tls-client-key-path"
            );
            let o = EndpointOverrides {
                url: Some("s3://bkt/repo".into()),
                ..EndpointOverrides::default()
            };
            assert!(matches!(pull_in(None, "r", o, &env), Err(Error::Io(_))));
        }

        #[cfg(feature = "push")]
        fn push_in(
            config: Option<&RepoConfig>,
            remote: &str,
            o: EndpointOverrides,
            env: &Environment,
        ) -> Result<Endpoint> {
            ostrya_rt::block_on(resolve_push_in(config, remote, o, env))
        }

        #[cfg(feature = "push")]
        fn push_refused<T: fmt::Debug>(result: Result<T>) -> String {
            match result {
                Err(Error::Remote(remote::Error::InvalidInput(msg))) => msg,
                other => panic!("expected InvalidInput, got {other:?}"),
            }
        }

        /// An `s3://` address and an `s3://` `push-url` give an S3 endpoint
        /// with the keys of the remote.
        #[cfg(feature = "push")]
        #[test]
        fn an_s3_push_address_gives_an_s3_endpoint() {
            let dir = Dir::new();
            let config = config(S3_SECTIONS);
            let s3 = s3_of(push_in(
                Some(&config),
                "push",
                EndpointOverrides::default(),
                &env(&dir, &[]),
            ));
            assert_eq!(
                s3.location.repository_url(),
                "https://bkt.s3.eu-west-1.amazonaws.com/repo"
            );
            assert_eq!(s3.credentials.access_key_id(), "AKIDEXAMPLE");
            assert_eq!(s3.http.max_retries, 5);
            assert_eq!(s3.http.max_outstanding, 8);
            let o = EndpointOverrides {
                s3_endpoint: Some("http://127.0.0.1:9000".into()),
                allow_cleartext_credentials: true,
                ..EndpointOverrides::default()
            };
            let s3 = s3_of(push_in(None, "s3://bkt/x", o, &env(&dir, &[])));
            assert_eq!(s3.location.repository_url(), "http://127.0.0.1:9000/bkt/x");
            assert!(s3.http.allow_cleartext_credentials);
        }

        /// A push to an `s3://` address refuses the token file and the user
        /// of an HTTP push, as fields and as keys, and the ssh fields.
        #[cfg(feature = "push")]
        #[test]
        fn an_s3_push_refuses_the_fields_of_another_transport() {
            let dir = Dir::new();
            let d = EndpointOverrides::default;
            for (name, o) in [
                (
                    "push-token-file",
                    EndpointOverrides {
                        push_token_file: Some("/t".into()),
                        ..d()
                    },
                ),
                (
                    "push-user",
                    EndpointOverrides {
                        push_user: Some("u".into()),
                        ..d()
                    },
                ),
            ] {
                assert_eq!(
                    push_refused(push_in(None, "s3://u-QXZ@bkt/r", o, &env(&dir, &[]))),
                    format!(
                        "{name} applies to an HTTP address, and 's3://bkt/r' is an s3:// \
                         address"
                    )
                );
            }
            for (key, name) in [
                ("push-token-file=/t", "push-token-file"),
                ("push-user=u", "push-user"),
            ] {
                let config = config(&format!("[remote \"r\"]\npush-url=s3://bkt/r\n{key}\n"));
                assert_eq!(
                    push_refused(push_in(Some(&config), "r", d(), &env(&dir, &[]))),
                    format!(
                        "{name} applies to an HTTP address, and 's3://bkt/r' is an s3:// \
                         address"
                    )
                );
            }
            for (name, o) in [
                (
                    "ssh-command",
                    EndpointOverrides {
                        ssh_command: Some(vec!["ssh".into()]),
                        ..d()
                    },
                ),
                (
                    "receive-command",
                    EndpointOverrides {
                        remote_command: Some("ostrya receive".into()),
                        ..d()
                    },
                ),
            ] {
                assert_eq!(
                    push_refused(push_in(None, "s3://bkt/r", o, &env(&dir, &[]))),
                    format!(
                        "{name} applies to an ssh address, and 's3://bkt/r' is an s3:// address"
                    )
                );
            }
            // The ssh keys of the section do not apply, and pass.
            let config = config(
                "[remote \"r\"]\npush-url=s3://bkt/r\nssh-command=ssh\n\
                 receive-command=x\nsend-command=y\n",
            );
            s3_of(push_in(Some(&config), "r", d(), &env(&dir, &[])));
        }

        /// A push refuses `tls-permissive=true` for an `s3://` address, and
        /// an `http://` endpoint with no cleartext permission.
        #[cfg(feature = "push")]
        #[test]
        fn an_s3_push_verifies_the_chain_and_refuses_cleartext() {
            let dir = Dir::new();
            let config =
                config("[remote \"permissive\"]\npush-url=s3://bkt/repo\ntls-permissive=true\n");
            assert_eq!(
                push_refused(push_in(
                    Some(&config),
                    "permissive",
                    EndpointOverrides::default(),
                    &env(&dir, &[])
                )),
                "remote 'permissive' sets tls-permissive=true, which a writer of a bucket \
                 repository refuses: the writer verifies the certificate chain of the server"
            );
            let env = env(&dir, &[("AWS_ENDPOINT_URL", "http://127.0.0.1:9000")]);
            assert!(
                push_refused(push_in(
                    None,
                    "s3://bkt/r",
                    EndpointOverrides::default(),
                    &env
                ))
                .contains("is http://, so the signature of each request would travel")
            );
            let o = EndpointOverrides {
                url: None,
                tls_client_cert_path: Some("/c".into()),
                ..EndpointOverrides::default()
            };
            assert_eq!(
                push_refused(push_in(None, "s3://bkt/r", o, &env)),
                "remote 's3://bkt/r': a client certificate needs both tls-client-cert-path \
                 and tls-client-key-path"
            );
        }

        /// A refusal of an `s3://` push address names the address without
        /// its userinfo.
        #[cfg(feature = "push")]
        #[test]
        fn a_refusal_of_an_s3_push_address_shows_no_userinfo() {
            let dir = Dir::new();
            let env = env(&dir, &[("AWS_ENDPOINT_URL", "http://127.0.0.1:9000")]);
            let o = EndpointOverrides {
                url: None,
                tls_client_cert_path: Some("/c".into()),
                ..EndpointOverrides::default()
            };
            let message = push_refused(push_in(None, "s3://AKID:SECRET@bkt/r", o, &env));
            assert!(!message.contains("AKID"), "{message}");
            assert!(!message.contains("SECRET"), "{message}");
            assert_eq!(
                message,
                "remote 's3://bkt/r': a client certificate needs both tls-client-cert-path \
                 and tls-client-key-path"
            );
        }

        fn bucket_in(
            config: Option<&RepoConfig>,
            value: &str,
            o: EndpointOverrides,
            env: &Environment,
        ) -> Result<S3Endpoint> {
            ostrya_rt::block_on(resolve_bucket_in(config, value, o, env))
        }

        fn bucket_refused(result: Result<S3Endpoint>) -> String {
            match result {
                Err(Error::Remote(remote::Error::InvalidInput(msg))) => msg,
                other => panic!("expected InvalidInput, got {other:?}"),
            }
        }

        /// A writer of a bucket repository takes an `s3://` address, else the
        /// `s3://` address of `push-url`, else that of `pull-url`, and never
        /// `url`.
        #[test]
        fn a_bucket_writer_takes_push_url_then_pull_url() {
            let dir = Dir::new();
            let config = config(
                "[remote \"both\"]\npull-url=s3://pull/a\npush-url=s3://push/b\n\n\
                 [remote \"pull\"]\nurl=https://ex.com/r\npull-url=s3://pull/a\n\
                 push-url=https://ex.com/p\ns3-region=eu-west-1\n\n\
                 [remote \"url\"]\nurl=s3://bkt/repo\n\n\
                 [remote \"http\"]\npull-url=https://ex.com/r\npush-url=ssh://h/r\n",
            );
            let d = EndpointOverrides::default;
            let url_of = |value: &str| {
                bucket_in(Some(&config), value, d(), &env(&dir, &[]))
                    .unwrap()
                    .location
                    .repository_url()
                    .to_owned()
            };
            assert_eq!(url_of("both"), "https://push.s3.us-east-1.amazonaws.com/b");
            assert_eq!(url_of("pull"), "https://pull.s3.eu-west-1.amazonaws.com/a");
            assert_eq!(
                url_of("s3://bkt/x"),
                "https://bkt.s3.us-east-1.amazonaws.com/x"
            );
            for (value, message) in [
                (
                    "url",
                    "remote 'url' holds no s3:// address in push-url or pull-url",
                ),
                (
                    "http",
                    "remote 'http' holds no s3:// address in push-url or pull-url",
                ),
                ("absent", "no remote 'absent' is configured"),
                (
                    "https://u:p@ex.com/r",
                    "'https://ex.com/r' is no s3:// address",
                ),
                ("h:/srv/r", "'h:/srv/r' is no s3:// address"),
            ] {
                assert_eq!(
                    bucket_refused(bucket_in(Some(&config), value, d(), &env(&dir, &[]))),
                    message
                );
            }
            let o = EndpointOverrides {
                url: Some("s3://bkt/x".into()),
                ..d()
            };
            assert_eq!(
                bucket_refused(bucket_in(None, "s3://bkt/x", o, &env(&dir, &[]))),
                "url applies to a pull, and this is a write to a bucket repository"
            );
        }

        /// A writer of a bucket repository makes the refusals of a push to an
        /// `s3://` address, and takes the S3 fields and the cleartext
        /// permission of the caller.
        #[test]
        fn a_bucket_writer_makes_the_refusals_of_a_push() {
            let dir = Dir::new();
            let d = EndpointOverrides::default;
            let config = config(
                "[remote \"token\"]\npush-url=s3://bkt/r\npush-token-file=/t\n\n\
                 [remote \"permissive\"]\npull-url=s3://bkt/r\ntls-permissive=true\n",
            );
            assert_eq!(
                bucket_refused(bucket_in(Some(&config), "token", d(), &env(&dir, &[]))),
                "push-token-file applies to an HTTP address, and 's3://bkt/r' is an s3:// \
                 address"
            );
            assert_eq!(
                bucket_refused(bucket_in(Some(&config), "permissive", d(), &env(&dir, &[]))),
                "remote 'permissive' sets tls-permissive=true, which a writer of a bucket \
                 repository refuses: the writer verifies the certificate chain of the server"
            );
            let o = EndpointOverrides {
                push_user: Some("u".into()),
                ..d()
            };
            assert_eq!(
                bucket_refused(bucket_in(None, "s3://bkt/r", o, &env(&dir, &[]))),
                "push-user applies to an HTTP address, and 's3://bkt/r' is an s3:// address"
            );
            let o = EndpointOverrides {
                ssh_command: Some(vec!["ssh".into()]),
                ..d()
            };
            assert_eq!(
                bucket_refused(bucket_in(None, "s3://bkt/r", o, &env(&dir, &[]))),
                "ssh-command applies to an ssh address, and 's3://bkt/r' is an s3:// address"
            );
            let o = EndpointOverrides {
                s3_endpoint: Some("http://127.0.0.1:9000".into()),
                ..d()
            };
            assert!(
                bucket_refused(bucket_in(None, "s3://bkt/r", o.clone(), &env(&dir, &[])))
                    .contains("is http://, so the signature of each request would travel")
            );
            let o = EndpointOverrides {
                allow_cleartext_credentials: true,
                s3_region: Some("eu-north-1".into()),
                ..o
            };
            let s3 = bucket_in(None, "s3://bkt/r", o, &env(&dir, &[])).unwrap();
            assert_eq!(s3.location.repository_url(), "http://127.0.0.1:9000/bkt/r");
            assert_eq!(s3.location.region(), "eu-north-1");
            assert!(s3.http.allow_cleartext_credentials);
        }

        /// The `Debug` output of the S3 endpoint shows no secret.
        #[test]
        fn the_s3_endpoint_shows_no_secret() {
            let dir = Dir::new();
            let o = EndpointOverrides {
                url: Some("s3://bkt/repo".into()),
                ..EndpointOverrides::default()
            };
            let endpoint = pull_in(None, "r", o, &env(&dir, &[])).unwrap();
            let text = format!("{endpoint:?}");
            assert!(!text.contains("QXZ"), "{text}");
            assert!(text.contains("AKIDEXAMPLE"), "{text}");
        }
    }
}
