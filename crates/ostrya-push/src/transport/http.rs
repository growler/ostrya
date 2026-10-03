//! The HTTP transport: the checks of the connect options, the token file and
//! the TLS files, and the fetcher of a session.

use std::io::Read;
use std::path::Path;

use ostrya_fetch::{
    BasicAuth, BearerToken, ClientIdentity, Fetcher, FetcherOptions, Proxy, TrustRoots,
};

use super::ConnectOptions;
use crate::error::{Error, Result};
use crate::session::http::{Credential, Endpoint, MAX_PARALLEL};

/// The most bytes the client reads of a token file or of a TLS file: 1 MiB.
const FILE_CAP: u64 = 1 << 20;

/// The most requests of one session in flight: an object stream for each
/// permit, and one `Have` or `Commit`.
const MAX_OUTSTANDING: usize = MAX_PARALLEL as usize + 1;

fn invalid(msg: impl Into<String>) -> Error {
    Error::InvalidInput(msg.into())
}

/// Check `connect` for the HTTP address `url`, read the files it names, and
/// build the fetcher of the session. Nothing is sent.
pub(super) async fn prepare(url: &str, connect: &ConnectOptions) -> Result<Endpoint> {
    check(url, connect)?;
    let credential = match &connect.push_token_file {
        Some(path) => {
            let token = read_token(path).await?;
            Some(match &connect.push_user {
                Some(user) => Credential::Basic(BasicAuth {
                    user: user.clone(),
                    password: token,
                }),
                None => Credential::Bearer(BearerToken { token }),
            })
        }
        None => None,
    };
    let mut http = connect.http.clone();
    if let Some(path) = &connect.tls_ca_path {
        http.tls.roots = TrustRoots::Pem(read_tls(path, "tls-ca-path").await?);
    }
    if let (Some(cert), Some(key)) = (&connect.tls_client_cert_path, &connect.tls_client_key_path) {
        http.tls.client_identity = Some(ClientIdentity {
            cert_chain_pem: read_tls(cert, "tls-client-cert-path").await?,
            key_pem: read_tls(key, "tls-client-key-path").await?,
            // A file names no passphrase, so the key must be one that needs
            // none. The fetcher refuses an encrypted key.
            key_passphrase: None,
        });
    }
    http.mirrors = vec![url.to_owned()];
    http.max_outstanding = MAX_OUTSTANDING;
    http.max_redirects = 0;
    // The future of the construction is large, and the connect futures of
    // the session would hold it inline, so it is boxed.
    let fetcher = Box::pin(Fetcher::new(http)).await.map_err(Error::Fetch)?;
    Ok(Endpoint {
        fetcher,
        url: url.to_owned(),
        credential,
        allow_cleartext: connect.allow_cleartext_credentials,
    })
}

/// Refuse the options that do not apply to an HTTP address, the options
/// that give two answers to one question, the TLS settings that verify no
/// server certificate, and a credential to an `http://` address without
/// [`ConnectOptions::allow_cleartext_credentials`].
fn check(url: &str, connect: &ConnectOptions) -> Result<()> {
    let not_http = |name: &str| {
        invalid(format!(
            "{name} applies to an ssh address, and '{url}' is an HTTP address"
        ))
    };
    if connect.ssh_command.is_some() {
        return Err(not_http("ssh-command"));
    }
    if connect.receive_command.is_some() {
        return Err(not_http("receive-command"));
    }
    let http = &connect.http;
    if !http.mirrors.is_empty() {
        return Err(invalid(
            "ConnectOptions::http names mirrors: the push address is the one server of a push",
        ));
    }
    if http.basic_auth.is_some() {
        return Err(invalid(
            "ConnectOptions::http sets basic_auth: a push takes its credential from \
             push-token-file and push-user",
        ));
    }
    if matches!(
        http.tls.roots,
        TrustRoots::DangerousAcceptAnyChain | TrustRoots::DangerousAcceptAny
    ) {
        return Err(invalid(
            "a push verifies the certificate of the server: ConnectOptions::http sets a TLS \
             setting that verifies no certificate chain",
        ));
    }
    if connect.tls_ca_path.is_some() && http.tls.roots != TrustRoots::System {
        return Err(invalid(
            "tls-ca-path and the trust roots of ConnectOptions::http are both set",
        ));
    }
    let client_files = (&connect.tls_client_cert_path, &connect.tls_client_key_path);
    match client_files {
        (Some(_), None) | (None, Some(_)) => {
            return Err(invalid(
                "a client certificate needs both tls-client-cert-path and tls-client-key-path",
            ));
        }
        (Some(_), Some(_)) if http.tls.client_identity.is_some() => {
            return Err(invalid(
                "tls-client-cert-path and the client identity of ConnectOptions::http are \
                 both set",
            ));
        }
        _ => {}
    }
    match (&connect.push_user, &connect.push_token_file) {
        (Some(_), None) => {
            return Err(invalid("push-user needs push-token-file"));
        }
        (Some(user), Some(_)) if user.is_empty() || user.contains(':') => {
            return Err(invalid(
                "push-user is empty or holds ':', which a Basic credential cannot carry",
            ));
        }
        _ => {}
    }
    let cleartext = url
        .get(..7)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http://"));
    if connect.push_token_file.is_some() && cleartext && !connect.allow_cleartext_credentials {
        return Err(invalid(format!(
            "the push address '{url}' is http://, so the token would travel in cleartext: \
             use https, or set allow-cleartext-credentials"
        )));
    }
    Ok(())
}

/// Whether `http` holds the default value of each field.
pub(super) fn is_default(http: &FetcherOptions) -> bool {
    let FetcherOptions {
        mirrors,
        headers,
        basic_auth,
        tls,
        proxy,
        http2,
        max_retries,
        max_redirects,
        max_outstanding,
        connect_timeout,
        progress_timeout,
        low_speed,
        fetch_timeout,
    } = http;
    let d = FetcherOptions::default();
    let same_proxy = match (proxy, &d.proxy) {
        (Proxy::None, Proxy::None) | (Proxy::Environment, Proxy::Environment) => true,
        (Proxy::Variables(a), Proxy::Variables(b)) => a == b,
        (Proxy::Url(a), Proxy::Url(b)) => a == b,
        _ => false,
    };
    *mirrors == d.mirrors
        && *headers == d.headers
        && *basic_auth == d.basic_auth
        && *tls == d.tls
        && same_proxy
        && *http2 == d.http2
        && *max_retries == d.max_retries
        && *max_redirects == d.max_redirects
        && *max_outstanding == d.max_outstanding
        && *connect_timeout == d.connect_timeout
        && *progress_timeout == d.progress_timeout
        && *low_speed == d.low_speed
        && *fetch_timeout == d.fetch_timeout
}

/// Read at most [`FILE_CAP`] bytes and one byte more of the file at `path`,
/// which the option `key` names, on the blocking pool. A failure names the
/// option and the path, and holds no byte of the file.
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
    read.map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("{key} '{}': {e}", path.display()),
        ))
    })
}

/// The bytes of the TLS file at `path`, which the option `key` names. A file
/// over [`FILE_CAP`] is refused.
async fn read_tls(path: &Path, key: &str) -> Result<Vec<u8>> {
    let bytes = read_capped(path, key).await?;
    if bytes.len() as u64 > FILE_CAP {
        return Err(invalid(format!("{key} '{}' is over 1 MiB", path.display())));
    }
    Ok(bytes)
}

/// The token of the token file at `path`: its first line. A refusal holds
/// no part of the token.
async fn read_token(path: &Path) -> Result<String> {
    let bytes = read_capped(path, "push-token-file").await?;
    let line = match bytes.iter().position(|b| *b == b'\n') {
        Some(end) => &bytes[..end],
        None if bytes.len() as u64 > FILE_CAP => {
            return Err(invalid(format!(
                "the first line of push-token-file '{}' is over 1 MiB",
                path.display()
            )));
        }
        None => &bytes[..],
    };
    token_of(line).map_err(|why| invalid(format!("push-token-file '{}': {why}", path.display())))
}

/// The token of the first line `line` of a token file.
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

/// Whether `token` has the token68 syntax of HTTP authentication: one or
/// more ASCII letters, digits, `-`, `.`, `_`, `~`, `+`, or `/`, then any
/// number of `=`.
fn is_token68(token: &str) -> bool {
    let body = token.trim_end_matches('=');
    !body.is_empty()
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(&b))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    struct Dir(PathBuf);

    impl Dir {
        fn new() -> Dir {
            static N: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "ostrya-push-http-{}-{}",
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
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn prepared(url: &str, connect: ConnectOptions) -> Result<Endpoint> {
        ostrya_rt::block_on(prepare(url, &connect))
    }

    fn refused(url: &str, connect: ConnectOptions) -> String {
        match prepared(url, connect) {
            Err(Error::InvalidInput(m)) => m,
            Err(other) => panic!("expected InvalidInput, got {other:?}"),
            Ok(_) => panic!("accepted"),
        }
    }

    /// The options with the token file `path`. They allow a cleartext
    /// credential, so a test needs no trust store of the host for a fetcher
    /// it builds over `http://`.
    fn with_token(path: PathBuf) -> ConnectOptions {
        ConnectOptions {
            push_token_file: Some(path),
            allow_cleartext_credentials: true,
            ..Default::default()
        }
    }

    /// The first line of the token file is a bearer token, or the password
    /// of a Basic credential with `push_user`.
    #[test]
    fn the_token_file_gives_a_bearer_or_a_basic_credential() {
        let dir = Dir::new();
        let file = dir.file("token", b"s3cr3t-T0ken==\nsecond line\n");
        let endpoint = prepared("http://h/", with_token(file.clone())).unwrap();
        match endpoint.credential {
            Some(Credential::Bearer(t)) => assert_eq!(t.token, "s3cr3t-T0ken=="),
            _ => panic!("no bearer token"),
        }
        let endpoint = prepared(
            "http://h/",
            ConnectOptions {
                push_user: Some("alice".into()),
                ..with_token(file)
            },
        )
        .unwrap();
        match endpoint.credential {
            Some(Credential::Basic(b)) => {
                assert_eq!(b.user, "alice");
                assert_eq!(b.password, "s3cr3t-T0ken==");
            }
            _ => panic!("no Basic credential"),
        }
        // A file with no line end holds the token alone.
        let file = dir.file("bare", b"abc");
        assert!(matches!(
            prepared("http://h/", with_token(file)).unwrap().credential,
            Some(Credential::Bearer(t)) if t.token == "abc"
        ));
        assert!(
            prepared("http://h/", ConnectOptions::default())
                .unwrap()
                .credential
                .is_none()
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
            let m = refused("http://h/", with_token(dir.file("t", bytes)));
            assert!(m.contains(part), "{bytes:?}: {m}");
            assert!(!m.contains("QX"), "{m}");
        }
    }

    /// A first line over 1 MiB and a TLS file over 1 MiB are refused. A
    /// token file whose first line is short can be longer.
    #[test]
    fn a_file_over_the_cap_is_refused() {
        let dir = Dir::new();
        let long = vec![b'a'; FILE_CAP as usize + 1];
        let m = refused("http://h/", with_token(dir.file("long", &long)));
        assert!(m.contains("over 1 MiB"), "{m}");
        let mut short = b"abc\n".to_vec();
        short.extend_from_slice(&long);
        prepared("http://h/", with_token(dir.file("short", &short))).unwrap();
        let mut at_cap = vec![b'a'; FILE_CAP as usize];
        at_cap.push(b'\n');
        prepared("http://h/", with_token(dir.file("at-cap", &at_cap))).unwrap();

        let m = refused(
            "https://h/",
            ConnectOptions {
                tls_ca_path: Some(dir.file("ca", &long)),
                ..Default::default()
            },
        );
        assert!(
            m.contains("tls-ca-path '") && m.contains("over 1 MiB"),
            "{m}"
        );
        // An absent file is an I/O error that names the option and the path.
        let absent = dir.0.join("absent");
        let message = |e: std::io::Error| {
            assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
            e.to_string()
        };
        match prepared("http://h/", with_token(absent.clone())) {
            Err(Error::Io(e)) => {
                let m = message(e);
                assert!(
                    m.starts_with(&format!("push-token-file '{}': ", absent.display())),
                    "{m}"
                );
            }
            other => panic!("{:?}", other.err()),
        }
        type Field = fn(&mut ConnectOptions) -> &mut Option<PathBuf>;
        let cases: [(&str, Field); 3] = [
            ("tls-ca-path", |c| &mut c.tls_ca_path),
            ("tls-client-cert-path", |c| &mut c.tls_client_cert_path),
            ("tls-client-key-path", |c| &mut c.tls_client_key_path),
        ];
        let pem = dir.file("pem", b"");
        for (key, field) in cases {
            let mut connect = ConnectOptions {
                tls_client_cert_path: Some(pem.clone()),
                tls_client_key_path: Some(pem.clone()),
                ..Default::default()
            };
            *field(&mut connect) = Some(absent.clone());
            match prepared("https://h/", connect) {
                Err(Error::Io(e)) => {
                    let m = message(e);
                    assert!(
                        m.starts_with(&format!("{key} '{}': ", absent.display())),
                        "{m}"
                    );
                }
                other => panic!("{key}: {:?}", other.err()),
            }
        }
    }

    /// `push_user` needs a token file, and holds no `:`.
    #[test]
    fn push_user_needs_a_token_file() {
        let m = refused(
            "https://h/",
            ConnectOptions {
                push_user: Some("alice".into()),
                ..Default::default()
            },
        );
        assert!(m.contains("push-user needs push-token-file"), "{m}");
        let dir = Dir::new();
        for user in ["", "a:b"] {
            let m = refused(
                "https://h/",
                ConnectOptions {
                    push_user: Some(user.into()),
                    ..with_token(dir.file("t", b"tok\n"))
                },
            );
            assert!(m.contains("push-user is empty"), "{user:?}: {m}");
        }
    }

    /// A token to an `http://` address is refused before any request,
    /// unless the options allow cleartext credentials.
    #[test]
    fn a_token_to_a_cleartext_address_needs_the_switch() {
        let dir = Dir::new();
        let file = dir.file("t", b"tok\n");
        for url in ["http://h/", "HTTP://h/"] {
            let m = refused(
                url,
                ConnectOptions {
                    allow_cleartext_credentials: false,
                    ..with_token(file.clone())
                },
            );
            assert!(
                m.contains("cleartext") && m.ends_with("set allow-cleartext-credentials"),
                "{m}"
            );
        }
        let endpoint = prepared("http://h/", with_token(file)).unwrap();
        assert!(endpoint.allow_cleartext);
        // With no credential, a cleartext address needs no switch.
        prepared("http://h/", ConnectOptions::default()).unwrap();
    }

    /// A TLS setting that verifies no certificate chain is refused, and so
    /// are the options that give two answers to one question.
    #[test]
    fn a_permissive_tls_setting_and_conflicts_are_refused() {
        for roots in [
            TrustRoots::DangerousAcceptAnyChain,
            TrustRoots::DangerousAcceptAny,
        ] {
            let mut connect = ConnectOptions::default();
            connect.http.tls.roots = roots;
            let m = refused("https://h/", connect);
            assert!(m.contains("verifies no certificate chain"), "{m}");
        }
        let dir = Dir::new();
        let pem = dir.file("pem", b"");
        let mut connect = ConnectOptions {
            tls_ca_path: Some(pem.clone()),
            ..Default::default()
        };
        connect.http.tls.roots = TrustRoots::Pem(Vec::new());
        assert!(refused("https://h/", connect).contains("both set"));
        for (cert, key) in [(Some(pem.clone()), None), (None, Some(pem.clone()))] {
            let m = refused(
                "https://h/",
                ConnectOptions {
                    tls_client_cert_path: cert,
                    tls_client_key_path: key,
                    ..Default::default()
                },
            );
            assert_eq!(
                m,
                "a client certificate needs both tls-client-cert-path and tls-client-key-path"
            );
        }
        let mut connect = ConnectOptions {
            tls_client_cert_path: Some(pem.clone()),
            tls_client_key_path: Some(pem),
            ..Default::default()
        };
        connect.http.tls.client_identity = Some(ClientIdentity {
            cert_chain_pem: Vec::new(),
            key_pem: Vec::new(),
            key_passphrase: None,
        });
        assert!(refused("https://h/", connect).contains("both set"));
        let mut connect = ConnectOptions::default();
        connect.http.mirrors = vec!["https://other/".into()];
        assert!(refused("https://h/", connect).contains("mirrors"));
        let mut connect = ConnectOptions::default();
        connect.http.basic_auth = Some(BasicAuth {
            user: "u".into(),
            password: "p".into(),
        });
        assert!(refused("https://h/", connect).contains("basic_auth"));
    }

    /// An ssh option with an HTTP address is refused.
    #[test]
    fn an_ssh_option_is_refused_with_an_http_address() {
        let m = refused(
            "https://h/",
            ConnectOptions {
                ssh_command: Some(vec!["ssh".into()]),
                ..Default::default()
            },
        );
        assert!(
            m.starts_with("ssh-command applies to an ssh address") && m.contains("HTTP address"),
            "{m}"
        );
        let m = refused(
            "http://h/",
            ConnectOptions {
                receive_command: Some("ostrya receive".into()),
                ..Default::default()
            },
        );
        assert!(m.starts_with("receive-command applies"), "{m}");
        // The ssh command of a remote section does not apply, and is not
        // read.
        prepared(
            "http://h/",
            ConnectOptions {
                remote_ssh_command: Some("ssh -v".into()),
                ..Default::default()
            },
        )
        .unwrap();
    }

    #[test]
    fn the_default_http_options_are_default() {
        assert!(is_default(&FetcherOptions::default()));
        let changes: [fn(&mut FetcherOptions); 6] = [
            |h| h.headers.push(("x".into(), "y".into())),
            |h| h.proxy = Proxy::None,
            |h| h.http2 = false,
            |h| h.max_retries += 1,
            |h| h.progress_timeout *= 2,
            |h| h.tls.roots = TrustRoots::Pem(Vec::new()),
        ];
        for change in changes {
            let mut http = FetcherOptions::default();
            change(&mut http);
            assert!(!is_default(&http), "{http:?}");
        }
    }
}
