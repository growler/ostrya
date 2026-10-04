//! The client side of a push from a repository.
//!
//! Behind the `push` feature. [`resolve_push_remote`] gives the push address
//! and the connect options of a configured remote or of an address, and
//! [`is_push_address`] tells the two apart.
//! [`Repo::push`](crate::Repo::push) and
//! [`Repo::push_over_stream`](crate::Repo::push_over_stream) push the commits
//! of a set of refspecs with the options of [`RepoPushOptions`].
//! [`Repo::export_stream`](crate::Repo::export_stream) writes the commits of a
//! set of ref updates as one one-way stream, with the options of
//! [`ExportStreamOptions`]. The crate-private parts read the refspecs of a
//! push against the local repository, and give the objects of its commits to
//! a push session.

mod export;
mod negotiate;
mod refspec;
mod source;
#[cfg(test)]
mod test_repo;

pub use self::export::ExportStreamOptions;
pub use self::negotiate::RepoPushOptions;

use std::path::PathBuf;

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
/// The keys of the section fill the fields of `connect` that apply to the
/// transport of the address, each only when `connect` leaves the field
/// `None`. A field that `connect` sets wins over its key, and each key is
/// read on its own.
///
/// - For an ssh address, `ssh-command` fills
///   [`ConnectOptions::remote_ssh_command`], and `receive-command` fills
///   [`ConnectOptions::receive_command`]. The HTTP keys are not read.
/// - For an `http://` or `https://` address, `push-token-file`, `push-user`,
///   `tls-ca-path`, `tls-client-cert-path`, and `tls-client-key-path` fill
///   the fields of the same names, as written: a relative path stays
///   relative to the current directory of the process, and `~` is not
///   expanded. The ssh keys are not read.
/// - For an `https://` address, `tls-permissive=true` is [`Error::Push`] with
///   [`InvalidInput`](crate::push::Error::InvalidInput): a push verifies the
///   certificate chain of the server. An `http://` address uses no TLS, so
///   the key is not read.
///
/// No key of the section gives
/// [`ConnectOptions::allow_cleartext_credentials`]: only the caller sets it.
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
            Some(url) if is_http_address(&url) => url,
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
    let parsed = PushRemote::parse(&address)?;
    if is_http_address(&address) {
        if address.starts_with("https://") && section.tls_permissive()? {
            return Err(invalid(format!(
                "remote '{remote}' sets tls-permissive=true, which a push refuses: a \
                 push verifies the certificate chain of the server"
            )));
        }
        let path = |key: Option<String>| key.map(PathBuf::from);
        if connect.push_token_file.is_none() {
            connect.push_token_file = path(section.push_token_file()?);
        }
        if connect.push_user.is_none() {
            connect.push_user = section.push_user()?;
        }
        if connect.tls_ca_path.is_none() {
            connect.tls_ca_path = path(section.tls_ca_path()?);
        }
        if connect.tls_client_cert_path.is_none() {
            connect.tls_client_cert_path = path(section.tls_client_cert_path()?);
        }
        if connect.tls_client_key_path.is_none() {
            connect.tls_client_key_path = path(section.tls_client_key_path()?);
        }
    } else {
        if connect.remote_ssh_command.is_none() {
            connect.remote_ssh_command = section.ssh_command()?;
        }
        if connect.receive_command.is_none() {
            connect.receive_command = section.receive_command()?;
        }
    }
    Ok((parsed, connect))
}

/// Whether `address` is an `http://` or an `https://` push address, by the
/// rule of [`PushRemote::parse`].
fn is_http_address(address: &str) -> bool {
    address.starts_with("http://") || address.starts_with("https://")
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
                          receive-command=/opt/bin/ostrya receive\n\
                          push-token-file=/etc/ostrya/ssh-token\n\
                          push-user=ssh-user\n\
                          tls-ca-path=/etc/ostrya/ssh-ca.pem\n\
                          tls-client-cert-path=/etc/ostrya/ssh-client.pem\n\
                          tls-client-key-path=/etc/ostrya/ssh-client.key\n\
                          tls-permissive=true\n\n\
                          [remote \"https\"]\nurl=https://ex.com/repo\n\n\
                          [remote \"http-keys\"]\nurl=https://ex.com/repo\n\
                          push-token-file=/etc/ostrya/token\n\
                          push-user=alice\n\
                          tls-ca-path=/etc/ostrya/ca.pem\n\
                          tls-client-cert-path=/etc/ostrya/client.pem\n\
                          tls-client-key-path=/etc/ostrya/client.key\n\
                          tls-permissive=false\n\
                          ssh-command=ssh -o BatchMode=yes\n\
                          receive-command=/opt/bin/ostrya receive\n\n\
                          [remote \"http-push-url\"]\nurl=https://pull.ex.com/repo\n\
                          push-url=http://push.ex.com/\n\
                          push-token-file=/etc/ostrya/token\n\n\
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

    fn config() -> RepoConfig {
        RepoConfig::parse(CONFIG).unwrap()
    }

    /// Assert that `a` and `b` hold the same value in each field.
    /// `ConnectOptions` implements no `PartialEq`, because the options of its
    /// HTTP client implement none, so the fields compare through their
    /// `Debug` text.
    fn assert_same(a: &ConnectOptions, b: &ConnectOptions) {
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
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
            assert_same(&connect, &ConnectOptions::default());
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
        assert_same(
            &connect,
            &ConnectOptions {
                ssh_command: None,
                receive_command: Some("/opt/bin/ostrya receive".into()),
                remote_ssh_command: Some("ssh -o BatchMode=yes".into()),
                ..ConnectOptions::default()
            },
        );
        // A section with no push keys leaves the fields unset.
        let (_, connect) =
            resolve_push_remote(Some(&cfg), "https", ConnectOptions::default()).unwrap();
        assert_same(&connect, &ConnectOptions::default());
    }

    #[test]
    fn a_set_connect_field_wins_over_the_remote_keys() {
        let cfg = config();
        let given = ConnectOptions {
            ssh_command: Some(vec!["my-ssh".into()]),
            receive_command: Some("receiver".into()),
            remote_ssh_command: Some("other-ssh -v".into()),
            ..ConnectOptions::default()
        };
        let (_, connect) = resolve_push_remote(Some(&cfg), "both", given.clone()).unwrap();
        assert_same(&connect, &given);

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

    /// The HTTP fields that the section `http-keys` gives.
    fn http_keys() -> ConnectOptions {
        ConnectOptions {
            push_token_file: Some("/etc/ostrya/token".into()),
            push_user: Some("alice".into()),
            tls_ca_path: Some("/etc/ostrya/ca.pem".into()),
            tls_client_cert_path: Some("/etc/ostrya/client.pem".into()),
            tls_client_key_path: Some("/etc/ostrya/client.key".into()),
            ..ConnectOptions::default()
        }
    }

    #[test]
    fn an_http_address_takes_the_http_keys_and_ignores_the_ssh_keys() {
        let cfg = config();
        let (remote, connect) =
            resolve_push_remote(Some(&cfg), "http-keys", ConnectOptions::default()).unwrap();
        assert_eq!(remote, PushRemote::parse("https://ex.com/repo").unwrap());
        // `ssh-command` and `receive-command` of the section are not read,
        // so the connect does not refuse them.
        assert_same(&connect, &http_keys());
        // The keys of a section whose `push-url` is HTTP fill the fields too.
        let (remote, connect) =
            resolve_push_remote(Some(&cfg), "http-push-url", ConnectOptions::default()).unwrap();
        assert_eq!(remote, PushRemote::parse("http://push.ex.com/").unwrap());
        assert_same(
            &connect,
            &ConnectOptions {
                push_token_file: Some("/etc/ostrya/token".into()),
                ..ConnectOptions::default()
            },
        );
    }

    #[test]
    fn an_ssh_address_ignores_the_http_keys() {
        // `both` holds each HTTP key and `tls-permissive=true` beside its
        // ssh `push-url`.
        let cfg = config();
        let (_, connect) =
            resolve_push_remote(Some(&cfg), "both", ConnectOptions::default()).unwrap();
        assert_eq!(connect.push_token_file, None);
        assert_eq!(connect.push_user, None);
        assert_eq!(connect.tls_ca_path, None);
        assert_eq!(connect.tls_client_cert_path, None);
        assert_eq!(connect.tls_client_key_path, None);
    }

    #[test]
    fn a_set_connect_field_wins_over_the_http_keys() {
        let cfg = config();
        let given = ConnectOptions {
            push_token_file: Some("/given/token".into()),
            push_user: Some("bob".into()),
            tls_ca_path: Some("/given/ca.pem".into()),
            tls_client_cert_path: Some("/given/client.pem".into()),
            tls_client_key_path: Some("/given/client.key".into()),
            allow_cleartext_credentials: true,
            ..ConnectOptions::default()
        };
        let (_, connect) = resolve_push_remote(Some(&cfg), "http-keys", given.clone()).unwrap();
        assert_same(&connect, &given);

        // Each field is filled on its own.
        let keys = http_keys();
        type Field = fn(&mut ConnectOptions) -> &mut Option<std::path::PathBuf>;
        let paths: [Field; 4] = [
            |c| &mut c.push_token_file,
            |c| &mut c.tls_ca_path,
            |c| &mut c.tls_client_cert_path,
            |c| &mut c.tls_client_key_path,
        ];
        for field in paths {
            let mut given = ConnectOptions::default();
            *field(&mut given) = Some("/given".into());
            let (_, connect) = resolve_push_remote(Some(&cfg), "http-keys", given).unwrap();
            let mut expected = keys.clone();
            *field(&mut expected) = Some("/given".into());
            assert_same(&connect, &expected);
        }
        let given = ConnectOptions {
            push_user: Some("bob".into()),
            ..ConnectOptions::default()
        };
        let (_, connect) = resolve_push_remote(Some(&cfg), "http-keys", given).unwrap();
        assert_same(
            &connect,
            &ConnectOptions {
                push_user: Some("bob".into()),
                ..keys
            },
        );
    }

    #[test]
    fn tls_permissive_is_refused_for_an_https_push() {
        let cfg = config();
        for name in ["permissive", "permissive-push-url"] {
            assert_invalid(
                resolve_push_remote(Some(&cfg), name, ConnectOptions::default()),
                &format!("remote '{name}' sets tls-permissive=true"),
            );
        }
        // An `http://` push address uses no TLS, so the key is not read: a
        // value that is not a boolean is not read either.
        for (name, url) in [
            ("permissive-http", "http://push.ex.com/"),
            ("permissive-bad", "http://ex.com/repo"),
        ] {
            let (remote, _) =
                resolve_push_remote(Some(&cfg), name, ConnectOptions::default()).unwrap();
            assert_eq!(remote, PushRemote::parse(url).unwrap());
        }
        // An address reads no section, so no key refuses it.
        resolve_push_remote(Some(&cfg), "https://ex.com/repo", ConnectOptions::default()).unwrap();
    }
}
