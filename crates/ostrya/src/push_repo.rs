//! The client side of a push from a repository.
//!
//! Behind the `push` feature. [`resolve_push_remote`] gives the push address
//! and the connect options of a configured remote or of an address, and
//! [`is_push_address`] tells the two apart.
//! [`Repo::push`](crate::Repo::push) and
//! [`Repo::push_over_stream`](crate::Repo::push_over_stream) push the commits
//! of a set of refspecs with the options of [`RepoPushOptions`]. The
//! crate-private parts read the refspecs of a push against the local
//! repository, and give the objects of its commits to a push session.

mod negotiate;
mod refspec;
mod source;
#[cfg(test)]
mod test_repo;

pub use self::negotiate::RepoPushOptions;

use crate::config::RepoConfig;
use crate::error::{Error, Result};
use crate::push::{ConnectOptions, PushRemote};

/// Whether `remote` is a push address rather than the name of a remote
/// section: it holds a `:` or a `/`.
///
/// [`resolve_push_remote`] reads no configuration for such a value, so a
/// caller can leave the local repository unopened.
pub fn is_push_address(remote: &str) -> bool {
    remote.contains([':', '/'])
}

/// The push address of `remote`, and `connect` with the push keys of the
/// remote section added.
///
/// `remote` is an address when [`is_push_address`] holds for it, and it is
/// parsed with [`PushRemote::parse`]. Otherwise it is the name of a remote
/// section of `config`. The address of a remote section is its `push-url`. When
/// `push-url` is absent, a `url` that starts with `http://` or `https://` is
/// the address. A `url` of another form, for example `file://`, `metalink=`,
/// or `mirrorlist=`, is no push address. `url` is read only when `push-url`
/// is absent.
///
/// The `ssh-command` of the section fills
/// [`ConnectOptions::remote_ssh_command`], and its `receive-command` fills
/// [`ConnectOptions::receive_command`], each only when `connect` leaves the
/// field `None`. A field that `connect` sets wins over the key.
///
/// A name that `config` holds no section for, and a section with no push
/// address, are [`Error::Push`] with
/// [`InvalidInput`](crate::push::Error::InvalidInput). A `config` of `None`
/// holds no section. An address that does not parse is [`Error::Push`] with
/// the error of [`PushRemote::parse`].
pub fn resolve_push_remote(
    config: Option<&RepoConfig>,
    remote: &str,
    mut connect: ConnectOptions,
) -> Result<(PushRemote, ConnectOptions)> {
    if is_push_address(remote) {
        return Ok((PushRemote::parse(remote)?, connect));
    }
    let section = config
        .and_then(|config| config.remote(remote))
        .ok_or_else(|| invalid(format!("no remote '{remote}' is configured")))?;
    let address = match section.push_url()? {
        Some(push_url) => push_url,
        None => match section.url()? {
            Some(url) if url.starts_with("http://") || url.starts_with("https://") => url,
            Some(url) => {
                return Err(invalid(format!(
                    "remote '{remote}' has no push-url, and its url '{url}' is no push address"
                )));
            }
            None => {
                return Err(invalid(format!(
                    "remote '{remote}' has no push-url and no url"
                )));
            }
        },
    };
    let address = PushRemote::parse(&address)?;
    if connect.remote_ssh_command.is_none() {
        connect.remote_ssh_command = section.ssh_command()?;
    }
    if connect.receive_command.is_none() {
        connect.receive_command = section.receive_command()?;
    }
    Ok((address, connect))
}

/// A push request the client refuses.
pub(crate) fn invalid(msg: impl Into<String>) -> Error {
    Error::Push(crate::push::Error::InvalidInput(msg.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = "[core]\nrepo_version=1\nmode=archive-z2\n\n\
                          [remote \"both\"]\nurl=https://ex.com/pull\n\
                          push-url=ssh://pusher@ex.com/srv/repo\n\
                          ssh-command=ssh -o BatchMode=yes\n\
                          receive-command=/opt/bin/ostrya receive\n\n\
                          [remote \"https\"]\nurl=https://ex.com/repo\n\n\
                          [remote \"http\"]\nurl=http://ex.com/repo\n\n\
                          [remote \"file\"]\nurl=file:///srv/repo\n\n\
                          [remote \"metalink\"]\nurl=metalink=https://ex.com/metalink.xml\n\n\
                          [remote \"mirrorlist\"]\nurl=mirrorlist=https://ex.com/mirrors\n\n\
                          [remote \"none\"]\ngpg-verify=false\n\n\
                          [remote \"file-push\"]\nurl=file:///srv/repo\n\
                          push-url=host:srv/repo\n\n\
                          [remote \"bad-url\"]\nurl=a\\zb\n\
                          push-url=ssh://h/p\n";

    fn config() -> RepoConfig {
        RepoConfig::parse(CONFIG).unwrap()
    }

    fn assert_invalid(result: Result<(PushRemote, ConnectOptions)>, needle: &str) {
        match result {
            Err(Error::Push(crate::push::Error::InvalidInput(msg))) => {
                assert!(msg.contains(needle), "{msg:?} lacks {needle:?}")
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn an_address_holds_a_colon_or_a_slash() {
        for address in [
            "host:srv/repo",
            "host:",
            ":repo",
            "srv/repo",
            "/srv/repo",
            "ssh://host/srv/repo",
            "https://ex.com/r",
        ] {
            assert!(is_push_address(address), "{address}");
        }
        for name in ["origin", "my-remote", "a.b", "", "with space"] {
            assert!(!is_push_address(name), "{name:?}");
        }
    }

    #[test]
    fn a_value_with_a_colon_or_a_slash_is_an_address() {
        let cfg = config();
        for address in [
            "host:srv/repo",
            "host:repo",
            "ssh://host/srv/repo",
            "https://ex.com/r",
        ] {
            let (remote, connect) =
                resolve_push_remote(Some(&cfg), address, ConnectOptions::default()).unwrap();
            assert_eq!(remote, PushRemote::parse(address).unwrap());
            assert_eq!(connect, ConnectOptions::default());
        }
        // No configuration is read for an address.
        let (remote, _) =
            resolve_push_remote(None, "host:srv/repo", ConnectOptions::default()).unwrap();
        assert_eq!(remote, PushRemote::parse("host:srv/repo").unwrap());
        // An address that does not parse keeps the error of the parser, also
        // when it holds a `/` alone.
        for address in ["ftp://host/r", "srv/repo"] {
            let expected = match PushRemote::parse(address) {
                Err(crate::push::Error::InvalidInput(msg)) => msg,
                other => panic!("{address}: {other:?}"),
            };
            assert_invalid(
                resolve_push_remote(Some(&cfg), address, ConnectOptions::default()),
                &expected,
            );
        }
    }

    #[test]
    fn push_url_wins_over_url() {
        let cfg = config();
        let (remote, _) =
            resolve_push_remote(Some(&cfg), "both", ConnectOptions::default()).unwrap();
        assert_eq!(
            remote,
            PushRemote::parse("ssh://pusher@ex.com/srv/repo").unwrap()
        );
        // A push-url stands also when the url is no push address.
        let (remote, _) =
            resolve_push_remote(Some(&cfg), "file-push", ConnectOptions::default()).unwrap();
        assert_eq!(remote, PushRemote::parse("host:srv/repo").unwrap());
    }

    #[test]
    fn url_is_not_read_when_push_url_is_set() {
        let cfg = config();
        // The keyfile cannot read the escape `\z` of this url.
        assert!(cfg.remote("bad-url").unwrap().url().is_err());
        let (remote, _) =
            resolve_push_remote(Some(&cfg), "bad-url", ConnectOptions::default()).unwrap();
        assert_eq!(remote, PushRemote::parse("ssh://h/p").unwrap());
    }

    #[test]
    fn an_http_url_is_the_address_when_push_url_is_absent() {
        let cfg = config();
        for (name, url) in [
            ("https", "https://ex.com/repo"),
            ("http", "http://ex.com/repo"),
        ] {
            let (remote, _) =
                resolve_push_remote(Some(&cfg), name, ConnectOptions::default()).unwrap();
            assert_eq!(remote, PushRemote::parse(url).unwrap());
        }
    }

    #[test]
    fn a_url_of_another_form_is_no_push_address() {
        let cfg = config();
        for name in ["file", "metalink", "mirrorlist"] {
            assert_invalid(
                resolve_push_remote(Some(&cfg), name, ConnectOptions::default()),
                "is no push address",
            );
        }
        assert_invalid(
            resolve_push_remote(Some(&cfg), "none", ConnectOptions::default()),
            "no push-url and no url",
        );
    }

    #[test]
    fn an_unknown_remote_is_refused() {
        let cfg = config();
        assert_invalid(
            resolve_push_remote(Some(&cfg), "absent", ConnectOptions::default()),
            "no remote 'absent'",
        );
        assert_invalid(
            resolve_push_remote(None, "both", ConnectOptions::default()),
            "no remote 'both'",
        );
    }

    #[test]
    fn the_remote_keys_fill_the_unset_connect_fields() {
        let cfg = config();
        let (_, connect) =
            resolve_push_remote(Some(&cfg), "both", ConnectOptions::default()).unwrap();
        assert_eq!(
            connect,
            ConnectOptions {
                ssh_command: None,
                receive_command: Some("/opt/bin/ostrya receive".into()),
                remote_ssh_command: Some("ssh -o BatchMode=yes".into()),
            }
        );
        // A section with no push keys leaves the fields unset.
        let (_, connect) =
            resolve_push_remote(Some(&cfg), "https", ConnectOptions::default()).unwrap();
        assert_eq!(connect, ConnectOptions::default());
    }

    #[test]
    fn a_set_connect_field_wins_over_the_remote_keys() {
        let cfg = config();
        let given = ConnectOptions {
            ssh_command: Some(vec!["my-ssh".into()]),
            receive_command: Some("receiver".into()),
            remote_ssh_command: Some("other-ssh -v".into()),
        };
        let (_, connect) = resolve_push_remote(Some(&cfg), "both", given.clone()).unwrap();
        assert_eq!(connect, given);

        // Each field is filled on its own.
        let given = ConnectOptions {
            receive_command: Some("receiver".into()),
            ..ConnectOptions::default()
        };
        let (_, connect) = resolve_push_remote(Some(&cfg), "both", given).unwrap();
        assert_eq!(connect.receive_command.as_deref(), Some("receiver"));
        assert_eq!(
            connect.remote_ssh_command.as_deref(),
            Some("ssh -o BatchMode=yes")
        );
    }
}
