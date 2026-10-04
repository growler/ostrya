//! The address a pull from a remote reads, and the options each transport
//! takes.
//!
//! The address comes from [`PullOptions::url`], then from the remote key
//! `pull-url`, then from the remote key `url`. A value that starts with
//! `ssh://`, or that holds no `://`, is an ssh address, parsed by
//! [`PushRemote::parse`]. Any other value goes to the HTTP fetcher as
//! written, so the fetcher gives its own refusal of a scheme it does not
//! fetch. An ssh address in `url` is refused: the tool reads `url` too, and
//! it does not pull over ssh.
//!
//! A pull over ssh takes its ssh command and its send command from the
//! remote keys `ssh-command` and `send-command`, each only where the caller
//! leaves the field of [`PullOptions::connect`] `None`, as a push takes them.
//! It refuses a field of [`PullOptions`] that applies to HTTP alone, and it
//! reads no remote key of HTTP alone: `contenturl`, `metalink`, and the
//! `tls-*` keys.

use crate::config::Remote;
use crate::error::{Error, Result};
use crate::push::{self, PullConnectOptions, PushRemote};

use super::PullOptions;

/// Where a pull reads the remote.
#[derive(Debug)]
pub(super) enum PullAddress {
    /// The base URL of an HTTP remote, as written.
    Http(String),
    /// An ssh address.
    Ssh(SshAddress),
}

/// An ssh address, parsed, and as written.
#[derive(Debug)]
pub(super) struct SshAddress {
    pub(super) remote: PushRemote,
    pub(super) written: String,
}

/// The address of a pull of `remote`, whose section of the config is
/// `section`, with `url` as the address of the caller.
///
/// A malformed ssh address in `url` or in `pull-url` is
/// [`Error::InvalidInput`] with the text of the parser. A remote with no
/// section and no `url` of the caller, a section with neither `pull-url` nor
/// `url`, and an ssh address in `url` are [`Error::Pull`].
pub(super) fn resolve_pull_address(
    section: Option<&Remote<'_>>,
    remote: &str,
    url: Option<&str>,
) -> Result<PullAddress> {
    if let Some(url) = url {
        return parse_address(url);
    }
    let section =
        section.ok_or_else(|| Error::Pull(format!("no remote '{remote}' is configured")))?;
    if let Some(pull_url) = section.pull_url()? {
        return parse_address(&pull_url);
    }
    match section.url()? {
        Some(url) if is_ssh(&url) && is_ssh_address(&url) => Err(Error::Pull(format!(
            "remote '{remote}': url '{url}' is an ssh address; the port reads an ssh \
             address from pull-url alone"
        ))),
        Some(url) => Ok(PullAddress::Http(url)),
        None => Err(Error::Pull(format!(
            "remote '{remote}' has no pull-url and no url"
        ))),
    }
}

/// `connect` with the remote keys of `section` in the fields it leaves
/// `None`: `ssh-command` fills
/// [`remote_ssh_command`](PullConnectOptions::remote_ssh_command), and
/// `send-command` fills [`send_command`](PullConnectOptions::send_command).
/// No section leaves `connect` as it is.
pub(super) fn fill_pull_connect(
    section: Option<&Remote<'_>>,
    mut connect: PullConnectOptions,
) -> Result<PullConnectOptions> {
    let Some(section) = section else {
        return Ok(connect);
    };
    if connect.remote_ssh_command.is_none() {
        connect.remote_ssh_command = section.ssh_command()?;
    }
    if connect.send_command.is_none() {
        connect.send_command = section.send_command()?;
    }
    Ok(connect)
}

/// Refuse a field of `opts` that applies to a pull over HTTP alone, for a
/// pull from the ssh address `address`. A retry count of 0 is accepted: a
/// pull over ssh never sends a request again.
pub(super) fn refuse_http_fields(opts: &PullOptions, address: &SshAddress) -> Result<()> {
    // Each name is the option of `ostrya pull` that sets the field.
    let set = [
        ("http-header", !opts.http_headers.is_empty()),
        (
            "network-retries",
            opts.n_network_retries.is_some_and(|n| n > 0),
        ),
        (
            "low-speed-limit-bytes",
            opts.low_speed_limit_bytes.is_some(),
        ),
        ("low-speed-time-seconds", opts.low_speed_time.is_some()),
    ];
    match set.iter().find(|(_, set)| *set) {
        Some((name, _)) => Err(Error::InvalidInput(format!(
            "{name} applies to a pull over HTTP, and '{}' is an ssh address",
            address.written
        ))),
        None => Ok(()),
    }
}

/// Whether `value` is read as an ssh address: it starts with `ssh://`, or it
/// holds no `://`.
fn is_ssh(value: &str) -> bool {
    value.starts_with("ssh://") || !value.contains("://")
}

/// Whether `value`, which [`is_ssh`] holds for, is an ssh address in `url`:
/// an `ssh://` value, or a value that the parser accepts.
fn is_ssh_address(value: &str) -> bool {
    value.starts_with("ssh://") || PushRemote::parse(value).is_ok()
}

/// The address `value` of the caller or of `pull-url`.
fn parse_address(value: &str) -> Result<PullAddress> {
    if !is_ssh(value) {
        return Ok(PullAddress::Http(value.to_owned()));
    }
    let remote = PushRemote::parse(value).map_err(|e| match e {
        push::Error::InvalidInput(msg) => Error::InvalidInput(msg),
        other => Error::Push(other),
    })?;
    Ok(PullAddress::Ssh(SshAddress {
        remote,
        written: value.to_owned(),
    }))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::config::RepoConfig;

    const CONFIG: &str = "[core]\nrepo_version=1\nmode=archive-z2\n\n\
                          [remote \"both\"]\nurl=https://ex.com/pull\n\
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
                          ssh-command=ssh -q\n\n\
                          [remote \"ssh-url\"]\nurl=ssh://h/srv/repo\n\n\
                          [remote \"scp-url\"]\nurl=u@h:/srv/repo\n\n\
                          [remote \"file-url\"]\nurl=file:///srv/repo\n\n\
                          [remote \"path-url\"]\nurl=/srv/repo\n\n\
                          [remote \"none\"]\ngpg-verify=false\n";

    fn config() -> RepoConfig {
        RepoConfig::parse(CONFIG).unwrap()
    }

    fn resolve(name: &str, url: Option<&str>) -> Result<PullAddress> {
        let config = config();
        let section = config.remote(name);
        resolve_pull_address(section.as_ref(), name, url)
    }

    fn http(address: Result<PullAddress>) -> String {
        match address {
            Ok(PullAddress::Http(url)) => url,
            other => panic!("{other:?}"),
        }
    }

    fn ssh(address: Result<PullAddress>) -> SshAddress {
        match address {
            Ok(PullAddress::Ssh(addr)) => addr,
            other => panic!("{other:?}"),
        }
    }

    /// The address of the caller wins over `pull-url`, and `pull-url` wins
    /// over `url`.
    #[test]
    fn the_address_of_the_caller_then_pull_url_then_url() {
        assert_eq!(
            http(resolve("both", Some("https://other.ex.com/"))),
            "https://other.ex.com/"
        );
        let addr = ssh(resolve("both", None));
        assert_eq!(addr.written, "ssh://puller@ex.com/srv/repo");
        assert_eq!(
            addr.remote,
            PushRemote::parse("ssh://puller@ex.com/srv/repo").unwrap()
        );
        assert_eq!(
            ssh(resolve("http-pull-url", Some("u@h:x"))).written,
            "u@h:x"
        );
        // A dead ssh `url` is not read when `pull-url` is set.
        assert_eq!(
            http(resolve("http-pull-url", None)),
            "http://pull.ex.com/repo"
        );
        assert_eq!(http(resolve("url", None)), "https://ex.com/repo");
        assert_eq!(ssh(resolve("scp", None)).written, "h:srv/repo");
    }

    /// A value with `://` and a scheme other than `ssh` goes to the fetcher
    /// as written.
    #[test]
    fn another_scheme_goes_to_the_fetcher() {
        assert_eq!(http(resolve("upper", None)), "HTTP://ex.com/repo");
        assert_eq!(http(resolve("file", None)), "file:///srv/repo");
        assert_eq!(http(resolve("file-url", None)), "file:///srv/repo");
        assert_eq!(
            http(resolve("none", Some("file:///srv/repo"))),
            "file:///srv/repo"
        );
    }

    /// A malformed ssh address of the caller or in `pull-url` is
    /// `InvalidInput` with the text of the parser.
    #[test]
    fn a_malformed_ssh_address_is_invalid_input() {
        for (name, url, value) in [
            ("bad-pull-url", None, "ssh://h"),
            ("local-path", None, "/srv/repo"),
            ("none", Some("ssh://h"), "ssh://h"),
            ("none", Some("/srv/repo"), "/srv/repo"),
        ] {
            match resolve(name, url) {
                Err(Error::InvalidInput(msg)) => {
                    assert!(msg.starts_with(&format!("address '{value}': ")), "{msg}")
                }
                other => panic!("{name}: {other:?}"),
            }
        }
    }

    /// An ssh address in `url` is refused, in the `ssh://` form and in the
    /// scp form. A `url` that is no ssh address goes to the fetcher.
    #[test]
    fn an_ssh_address_in_url_is_refused() {
        for (name, value) in [
            ("ssh-url", "ssh://h/srv/repo"),
            ("scp-url", "u@h:/srv/repo"),
        ] {
            match resolve(name, None) {
                Err(Error::Pull(msg)) => assert_eq!(
                    msg,
                    format!(
                        "remote '{name}': url '{value}' is an ssh address; the port reads an \
                         ssh address from pull-url alone"
                    )
                ),
                other => panic!("{name}: {other:?}"),
            }
        }
        assert_eq!(http(resolve("path-url", None)), "/srv/repo");
    }

    /// No section with no address of the caller, and a section with neither
    /// key, are refused.
    #[test]
    fn a_remote_with_no_address_is_refused() {
        match resolve("absent", None) {
            Err(Error::Pull(msg)) => assert_eq!(msg, "no remote 'absent' is configured"),
            other => panic!("{other:?}"),
        }
        match resolve("none", None) {
            Err(Error::Pull(msg)) => assert_eq!(msg, "remote 'none' has no pull-url and no url"),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            ssh(resolve("absent", Some("ssh://h/x"))).written,
            "ssh://h/x"
        );
    }

    /// The keys fill the fields left `None`, and a field the caller set wins
    /// over its key. No section changes nothing.
    #[test]
    fn the_keys_fill_the_fields_left_none() {
        let config = config();
        let section = config.remote("both");
        let filled = fill_pull_connect(section.as_ref(), PullConnectOptions::default()).unwrap();
        assert_eq!(filled.ssh_command, None);
        assert_eq!(
            filled.remote_ssh_command.as_deref(),
            Some("ssh -o BatchMode=yes")
        );
        assert_eq!(filled.send_command.as_deref(), Some("/opt/bin/ostrya send"));

        let set = PullConnectOptions {
            ssh_command: Some(vec!["my-ssh".to_owned()]),
            send_command: Some("my send".to_owned()),
            remote_ssh_command: Some("their-ssh".to_owned()),
        };
        let kept = fill_pull_connect(section.as_ref(), set).unwrap();
        assert_eq!(kept.ssh_command, Some(vec!["my-ssh".to_owned()]));
        assert_eq!(kept.send_command.as_deref(), Some("my send"));
        assert_eq!(kept.remote_ssh_command.as_deref(), Some("their-ssh"));

        let none = fill_pull_connect(None, PullConnectOptions::default()).unwrap();
        assert_eq!(none.send_command, None);
        assert_eq!(none.remote_ssh_command, None);
        let empty = fill_pull_connect(
            config.remote("none").as_ref(),
            PullConnectOptions::default(),
        )
        .unwrap();
        assert_eq!(empty.send_command, None);
        assert_eq!(empty.remote_ssh_command, None);
    }

    /// Each field of HTTP alone is refused with an ssh address, by the name
    /// of its option. A retry count of 0 is accepted.
    #[test]
    fn the_fields_of_http_alone_are_refused() {
        let addr = ssh(resolve("none", Some("u@h:x")));
        let refused = |opts: PullOptions, name: &str| match refuse_http_fields(&opts, &addr) {
            Err(Error::InvalidInput(msg)) => assert_eq!(
                msg,
                format!("{name} applies to a pull over HTTP, and 'u@h:x' is an ssh address")
            ),
            other => panic!("{name}: {other:?}"),
        };
        refused(
            PullOptions {
                http_headers: vec![("A".to_owned(), "B".to_owned())],
                ..PullOptions::default()
            },
            "http-header",
        );
        refused(
            PullOptions {
                n_network_retries: Some(1),
                ..PullOptions::default()
            },
            "network-retries",
        );
        refused(
            PullOptions {
                low_speed_limit_bytes: Some(0),
                ..PullOptions::default()
            },
            "low-speed-limit-bytes",
        );
        refused(
            PullOptions {
                low_speed_time: Some(Duration::ZERO),
                ..PullOptions::default()
            },
            "low-speed-time-seconds",
        );
        refuse_http_fields(
            &PullOptions {
                n_network_retries: Some(0),
                max_outstanding_fetches: Some(3),
                ..PullOptions::default()
            },
            &addr,
        )
        .unwrap();
        refuse_http_fields(&PullOptions::default(), &addr).unwrap();
    }
}
