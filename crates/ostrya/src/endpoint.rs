//! The resolution of a remote to an [`Endpoint`].
//!
//! [`resolve_pull`] and `resolve_push` read the keys of a remote section of
//! the repository config, read the files that the keys name, and give an
//! [`Endpoint`] that holds all values in memory. The `push` feature gates
//! `resolve_push`. [`EndpointOverrides`] holds the values of the caller. A
//! value of the caller wins over its remote key.
//!
//! [`read_token_file`] and [`read_pem_file`] read a token file and a PEM file.
//! [`read_pem_file`] reads at most 1 MiB and one byte. [`read_token_file`]
//! stops at the first LF, and reads at most 1 MiB and one byte. Each error
//! names the key and the path.
//!
//! The trust policy of the remote keys is in the resolvers. [`resolve_pull`]
//! maps `tls-permissive=true` to [`TrustRoots::DangerousAcceptAnyChain`].
//! `resolve_push` refuses `tls-permissive=true` for an `https://` address.
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
/// The [`Debug`] output shows `url` without its userinfo, and shows
/// `<redacted>` in place of each header value.
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
    /// [`resolve_pull`] refuses it.
    pub push_token_file: Option<PathBuf>,
    /// The user name of a Basic credential of a push. It wins over the key
    /// `push-user`. The token is the password.
    ///
    /// [`resolve_pull`] refuses it.
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
            .finish()
    }
}

/// Resolves the remote `remote` to the endpoint of a pull.
///
/// # Address
///
/// The address is the first of these that is set: [`EndpointOverrides::url`],
/// the key `pull-url`, and the key `url`. An address that starts with
/// `ssh://`, or that holds no `://`, is an ssh address, and
/// [`SshAddress::parse`] reads it. Each other address is an HTTP address, and
/// goes to the fetcher as written. The key `url` cannot hold an ssh address,
/// because the `ostree` command also reads it. The function ignores the keys
/// `contenturl` and `metalink`.
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
/// # Errors
///
/// The function makes each refusal that needs no file before it reads a file.
///
/// - [`Error::InvalidInput`] if the caller sets `push_token_file` or
///   `push_user`.
/// - [`Error::Pull`] if `config` holds no section for `remote` and the caller
///   gives no `url`, or if the section has neither `pull-url` nor `url`.
/// - [`Error::Pull`] if the key `url` holds an ssh address. The message shows
///   the value without the text up to its last `@`.
/// - [`Error::InvalidInput`] with the text of the parser if an ssh address is
///   malformed.
/// - [`Error::InvalidInput`] for an HTTP address if the caller sets
///   `ssh_command` or `remote_command`.
/// - [`Error::Pull`] for an HTTP address if a client certificate has no key,
///   or a key has no certificate.
/// - [`Error::Unsupported`] if the key `proxy` has white space at its start
///   or its end.
/// - [`Error::InvalidInput`] for an ssh address if the caller sets a field of
///   an HTTP address: a TLS path, `allow_cleartext_credentials`,
///   `http_headers`, a `max_retries` above 0, or a low-speed field. The
///   message names the first such field and shows the address without its
///   user.
/// - The errors of [`read_pem_file`].
/// - [`Error::Core`] if a key that the function reads holds a malformed
///   escape sequence, or if `tls-permissive` is not a boolean.
pub async fn resolve_pull(
    config: Option<&RepoConfig>,
    remote: &str,
    overrides: EndpointOverrides,
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
    match pull_address(section.as_ref(), remote, o.url.take())? {
        Endpoint::Http(http) => pull_http(remote, section.as_ref(), http, o).await,
        Endpoint::Ssh { address, .. } => {
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
    }
}

/// Returns the endpoint of the address of a pull of `remote`, with default
/// options, from `url` of the caller, or else from `section`.
fn pull_address(
    section: Option<&Remote<'_>>,
    remote: &str,
    url: Option<String>,
) -> Result<Endpoint> {
    if let Some(url) = url {
        return parse_pull_address(&url);
    }
    let section =
        section.ok_or_else(|| Error::Pull(format!("no remote '{remote}' is configured")))?;
    if let Some(pull_url) = section.pull_url()? {
        return parse_pull_address(&pull_url);
    }
    match section.url()? {
        Some(url) if is_ssh(&url) && is_ssh_address(&url) => Err(Error::Pull(format!(
            "remote '{remote}': url '{}' is an ssh address; the port reads an ssh \
             address from pull-url alone",
            remote::without_userinfo(&url)
        ))),
        Some(url) => Ok(Endpoint::Http(FetcherOptions::new(url))),
        None => Err(Error::Pull(format!(
            "remote '{remote}' has no pull-url and no url"
        ))),
    }
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
fn parse_pull_address(value: &str) -> Result<Endpoint> {
    if !is_ssh(value) {
        return Ok(Endpoint::Http(FetcherOptions::new(value)));
    }
    let address = SshAddress::parse(value).map_err(|e| match e {
        remote::Error::InvalidInput(msg) => Error::InvalidInput(msg),
        other => Error::Remote(other),
    })?;
    Ok(Endpoint::Ssh {
        address,
        options: SshOptions::default(),
    })
}

/// Completes `http`, the options of an HTTP pull of `remote`, from `o` and
/// the keys of `section`.
async fn pull_http(
    remote: &str,
    section: Option<&Remote<'_>>,
    mut http: FetcherOptions,
    mut o: EndpointOverrides,
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
    // `tls-permissive` keeps the host name check and ignores `tls-ca-path`.
    // Both facts are observed on the `ostree` command: a CA that signed
    // nothing in the chain works, and a path that names an absent file works
    // too. So the function does not read the path, and an absent file is no
    // failure. `DangerousAcceptAnyChain` keeps the name check and takes the
    // chain as presented. A CA path of the caller wins over the key.
    let ca_path = match (o.tls_ca_path, section) {
        (Some(path), _) => Some(path),
        (None, Some(section)) if section.tls_permissive()? => {
            http.tls.roots = TrustRoots::DangerousAcceptAnyChain;
            None
        }
        (None, Some(section)) => section.tls_ca_path()?.map(PathBuf::from),
        (None, None) => None,
    };
    if let Some(path) = ca_path {
        http.tls.roots = TrustRoots::Pem(read_pem_file("tls-ca-path", &path).await?);
    }
    http.tls.client_identity = match client_files {
        Some((cert, key)) => Some(client_identity(&cert, &key).await?),
        None => None,
    };
    http.headers = o.http_headers;
    http.allow_cleartext_credentials = o.allow_cleartext_credentials;
    http.proxy = proxy;
    http.max_retries = o.max_retries.unwrap_or(PULL_RETRIES);
    http.max_outstanding = PULL_OUTSTANDING;
    http.low_speed = low_speed(o.low_speed_limit_bytes, o.low_speed_time);
    Ok(Endpoint::Http(http))
}

/// Resolves `remote_or_address` to the endpoint of a push.
///
/// # Address
///
/// A value with a `:` or a `/` is an address, by the rule of
/// [`is_push_address`](crate::is_push_address). [`Endpoint::parse`] reads
/// it, and the function reads no configuration. Each other value is the name
/// of a remote section of `config`. The address of the section is its key
/// `push-url`. If `push-url` is absent, a key `url` that starts with
/// `http://` or `https://` is the address. The function reads `url` only if
/// `push-url` is absent.
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
///   key must need no passphrase.
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
/// # Errors
///
/// The function makes each refusal that needs no file before it reads a file.
/// Each refusal of the list is [`Error::Remote`] with
/// [`InvalidInput`](crate::remote::Error::InvalidInput):
///
/// - The caller sets `url`.
/// - `config` holds no section for the name, or the section has no push
///   address. The message shows a `url` that is no push address without the
///   text up to its last `@`.
/// - The address is `https://`, and the section sets `tls-permissive=true`,
///   because a push verifies the certificate chain of the server.
/// - The address is HTTP, and the caller sets `ssh_command` or
///   `remote_command`.
/// - A client certificate has no key, or a key has no certificate.
/// - A `push_user` has no token file, or is empty, or holds `:`.
/// - The address is `http://`, the push has a token file, and the caller
///   does not set `allow_cleartext_credentials`. The token would go to the
///   server in cleartext.
/// - The address is ssh, and the caller sets a field of an HTTP address. The
///   message names the first such field and shows the address without its
///   user.
///
/// These errors are also possible:
///
/// - [`Error::Remote`] with the error of [`Endpoint::parse`] if the address
///   does not parse.
/// - [`Error::Unsupported`] if the key `proxy` has white space at its start
///   or its end.
/// - The errors of [`read_token_file`] and [`read_pem_file`].
/// - [`Error::Core`] if a key that the function reads holds a malformed
///   escape sequence, or if `tls-permissive` is not a boolean.
#[cfg(feature = "push")]
pub async fn resolve_push(
    config: Option<&RepoConfig>,
    remote_or_address: &str,
    overrides: EndpointOverrides,
) -> Result<Endpoint> {
    let remote = remote_or_address;
    if overrides.url.is_some() {
        return Err(push_invalid("url applies to a pull, and this is a push"));
    }
    if crate::is_push_address(remote) {
        return match Endpoint::parse(remote)? {
            Endpoint::Http(http) => push_http(remote, None, remote, http, overrides).await,
            Endpoint::Ssh { address, .. } => push_ssh(None, address, overrides),
        };
    }
    let section = config
        .and_then(|config| config.remote(remote))
        .ok_or_else(|| push_invalid(format!("no remote '{remote}' is configured")))?;
    let address = match section.push_url()? {
        Some(push_url) => push_url,
        None => match section.url()? {
            Some(url) if url.starts_with("http://") || url.starts_with("https://") => url,
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
    match Endpoint::parse(&address)? {
        Endpoint::Http(http) => push_http(remote, Some(&section), &address, http, overrides).await,
        Endpoint::Ssh { address, .. } => push_ssh(Some(&section), address, overrides),
    }
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
    if let Some(path) = &o.tls_ca_path {
        http.tls.roots = TrustRoots::Pem(read_pem_file("tls-ca-path", path).await?);
    }
    if let Some((cert, key)) = client_files {
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
#[cfg(feature = "push")]
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
            assert_eq!(http.tls.roots, TrustRoots::Pem(b"KEY-CA".to_vec()));

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
                let o = EndpointOverrides {
                    push_token_file: Some(absent.clone()),
                    tls_ca_path: Some(absent.clone()),
                    tls_client_cert_path: cert,
                    tls_client_key_path: key,
                    ..EndpointOverrides::default()
                };
                assert_eq!(
                    refused(push(None, "https://h/", o)),
                    "a client certificate needs both tls-client-cert-path and \
                     tls-client-key-path"
                );
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
    }
}
