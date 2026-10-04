use std::ffi::OsStr;

use super::ssh::{SshAddr, quote_posix, receive_command, send_command, ssh_program};
use super::*;

fn ssh(address: &str) -> SshAddr {
    match parse_remote(address, false).unwrap().inner {
        RemoteAddr::Ssh(addr) => addr,
        RemoteAddr::Http(url) => panic!("{address} parsed as HTTP: {url}"),
    }
}

fn argv(address: &str) -> Vec<String> {
    ssh(address).command_line(vec!["ssh".into()], "ostrya receive")
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn refused(address: &str, windows: bool) -> String {
    match parse_remote(address, windows) {
        Err(Error::InvalidInput(msg)) => msg,
        other => panic!("{address}: expected a refusal, got {other:?}"),
    }
}

#[test]
fn each_address_form_gives_its_command_line() {
    let cases: &[(&str, &[&str])] = &[
        (
            "ssh://host/srv/repo",
            &["ssh", "host", "ostrya receive --repo='/srv/repo'"],
        ),
        (
            "ssh://me@host:2222/srv/repo",
            &[
                "ssh",
                "-p",
                "2222",
                "me@host",
                "ostrya receive --repo='/srv/repo'",
            ],
        ),
        (
            "ssh://host/~/repos/a",
            &["ssh", "host", "ostrya receive --repo='repos/a'"],
        ),
        (
            "ssh://me@[::1]:22/r",
            &["ssh", "-p", "22", "me@::1", "ostrya receive --repo='/r'"],
        ),
        (
            "ssh://[::1]/r",
            &["ssh", "::1", "ostrya receive --repo='/r'"],
        ),
        (
            "host:repo",
            &["ssh", "host", "ostrya receive --repo='repo'"],
        ),
        (
            "me@host:/srv/repo",
            &["ssh", "me@host", "ostrya receive --repo='/srv/repo'"],
        ),
        (
            "host:~/repo",
            &["ssh", "host", "ostrya receive --repo='repo'"],
        ),
        (
            "[::1]:repo",
            &["ssh", "::1", "ostrya receive --repo='repo'"],
        ),
        (
            "me@[fe80::1]:a:b",
            &["ssh", "me@fe80::1", "ostrya receive --repo='a:b'"],
        ),
        ("C:repo", &["ssh", "C", "ostrya receive --repo='repo'"]),
        ("host:%41", &["ssh", "host", "ostrya receive --repo='%41'"]),
    ];
    for (address, want) in cases {
        assert_eq!(argv(address), strings(want), "{address}");
    }
}

#[test]
fn the_home_prefix_is_removed() {
    assert_eq!(ssh("ssh://h/~/a/b"), ssh("h:a/b"));
    assert_eq!(ssh("h:~/a"), ssh("h:a"));
    assert_eq!(ssh("ssh://h/a/b").to_string(), "ssh://h/a/b");
    assert_eq!(ssh("h:a/b").to_string(), "ssh://h/~/a/b");
    assert_eq!(ssh("ssh://u@[::1]:7/x").to_string(), "ssh://u@[::1]:7/x");
    // The path after the home prefix stays relative, however many `/` start
    // it.
    assert_eq!(ssh("host:~//etc/repo"), ssh("host:etc/repo"));
    assert_eq!(ssh("ssh://host/~//etc/repo"), ssh("host:etc/repo"));
    assert_eq!(ssh("ssh://host/~///etc/repo"), ssh("host:etc/repo"));
    for address in ["host:~//", "ssh://host/~//", "host:~///"] {
        let msg = refused(address, false);
        assert!(msg.contains("path is empty"), "{address}: {msg}");
    }
}

#[test]
fn the_scp_form_ends_the_host_at_the_first_colon() {
    // As git reads it: the scp form cannot give a user with `:`, and an IPv6
    // host needs brackets.
    assert_eq!(
        argv("u:p@host:path"),
        strings(&["ssh", "u", "ostrya receive --repo='p@host:path'"])
    );
    assert_eq!(
        argv("fe80::1:repo"),
        strings(&["ssh", "fe80", "ostrya receive --repo=':1:repo'"])
    );
    assert_eq!(
        argv("[fe80::1]:repo"),
        strings(&["ssh", "fe80::1", "ostrya receive --repo='repo'"])
    );
    // The `ssh://` form refuses a user with a password.
    let msg = refused("ssh://u:p@host/r", false);
    assert!(msg.contains("user"), "{msg}");
}

#[test]
fn a_host_or_a_user_outside_the_allowed_characters_is_refused() {
    for address in [
        "ssh://ho st/p",
        "ssh://h?x/p",
        "ssh://h;x/p",
        "ssh://$(x)/p",
        "ssh://h\nx/p",
        "ssh://h\tx/p",
        "ssh://h`x`/p",
        "ssh://h|x/p",
        "ssh://h&x/p",
        "ssh://h'x/p",
        "ssh://h\\x/p",
        "ssh://u x@h/p",
        "ssh://u;x@h/p",
        "ssh://$(u)@h/p",
        "ssh://u\n@h/p",
        "ssh://[::1;x]/p",
        "ssh://[::1 ]/p",
        "ssh://[fe80::1%e$x]/p",
        "ssh://[g::1]/p",
        "ho st:p",
        "h?x:p",
        "h;x:p",
        "$(x):p",
        "h\nx:p",
        "h\tx:p",
        "u x@h:p",
        "u;x@h:p",
        "$(u)@h:p",
        "u\t@h:p",
        "[::1;x]:p",
    ] {
        let msg = refused(address, false);
        assert!(msg.contains("character"), "{address:?}: {msg}");
    }
    for address in [
        "ssh://my-host.example_1/p",
        "ssh://u.s-e_r@h/p",
        "ssh://[fe80::1%eth0]/p",
        "ssh://[::ffff:192.0.2.1]:22/p",
        "my-host.example_1:p",
        "u.s-e_r@h:p",
        "[fe80::1%eth0]:p",
    ] {
        parse_remote(address, false).unwrap();
    }
    assert_eq!(
        argv("ssh://[fe80::1%eth0]/p"),
        strings(&["ssh", "fe80::1%eth0", "ostrya receive --repo='/p'"])
    );
}

#[test]
fn a_backslash_before_the_first_colon_is_a_local_path_on_windows() {
    for address in ["..\\dir:x", "\\\\?\\C:\\repo", "dir\\sub:x"] {
        let msg = refused(address, true);
        assert!(msg.contains("local path"), "{address}: {msg}");
        // Elsewhere the backslash is a character a host cannot hold.
        let msg = refused(address, false);
        assert!(msg.contains("character"), "{address}: {msg}");
    }
}

#[test]
fn malformed_addresses_are_refused() {
    for address in [
        "ssh://-oProxyCommand=x/r",
        "ssh://-u@host/r",
        "-oProxyCommand=x:r",
        "-u@host:r",
        "ssh://host",
        "ssh:///r",
        "ssh://@host/r",
        "ssh://host:/r",
        "ssh://host:0/r",
        "ssh://host:65536/r",
        "ssh://host:22x/r",
        "ssh://u:pw@host/r",
        "ssh://a@b@host/r",
        "ssh://host/~",
        "ssh://host/~/",
        "ssh://host/~user/r",
        "ssh://[::1/r",
        "ssh://[::1]x/r",
        "host:",
        "host:~",
        "host:~user/r",
        "a@b@host:r",
        "@host:r",
        ":r",
        "[::1:r",
        "ho]st:r",
        "file:///srv/repo",
        "ftp://host/r",
        "/srv/repo",
        "repo",
        "dir/host:r",
        "http://",
    ] {
        refused(address, false);
    }
}

/// A refusal names the address it refuses, and serves the push and the pull
/// alike.
#[test]
fn a_refusal_names_the_address() {
    assert_eq!(
        refused("ssh://host", false),
        "address 'ssh://host': an ssh:// address needs a path"
    );
    assert_eq!(refused("repo", false), "address 'repo': not an address");
    assert_eq!(
        refused("dir/host:r", false),
        "address 'dir/host:r': not an address"
    );
    assert!(refused("http://", false).starts_with("address: "));
}

#[test]
fn a_one_letter_host_is_a_local_path_on_windows() {
    for address in ["C:\\repo", "C:repo", "c:/repo", "u@C:repo"] {
        let msg = refused(address, true);
        assert!(msg.contains("local path"), "{address}: {msg}");
        parse_remote(address, false).unwrap();
    }
    parse_remote("ssh://C/repo", true).unwrap();
    parse_remote("ab:repo", true).unwrap();
    parse_remote("[C]:repo", true).unwrap();
}

#[test]
fn http_addresses_parse_and_their_malformed_forms_are_refused() {
    for address in [
        "http://h/repo",
        "https://h:8443/repo",
        "http://127.0.0.1:8080/",
        "https://[::1]/",
        "https://h",
        "http://h:080/",
    ] {
        let remote = PushRemote::parse(address).unwrap();
        assert_eq!(remote.to_string(), address);
        assert!(matches!(remote.inner, RemoteAddr::Http(_)), "{address}");
    }
    for (address, part) in [
        ("http://", "invalid url"),
        ("https://:443/r", "no host"),
        ("https://user:pw-QXZ@h/r", "userinfo"),
        ("https://h/r?x=1", "query string"),
        ("https://h/r#frag", "fragment"),
        ("https://h:65536/r", "not a number"),
        ("http://h:port/r", "not a number"),
        // A password that holds a `/` or a `?` ends the authority before the
        // `@`, and no message names it.
        ("https://user:443/pw-QXZ@h/repo", "userinfo"),
        ("https://user:1234?pw-QXZ@h/", "userinfo"),
        ("http://h:+80/", "not a number"),
    ] {
        let msg = refused(address, false);
        assert!(msg.contains(part), "{address}: {msg}");
        assert!(!msg.contains("QXZ"), "{address}: {msg}");
    }
}

/// An HTTP option with an ssh address is refused before the ssh client
/// starts, and so is a non-default `http` field.
#[test]
fn an_http_option_is_refused_with_an_ssh_address() {
    let remote = PushRemote::parse("ssh://host/srv/repo").unwrap();
    let mut changed_http = ConnectOptions::default();
    changed_http.http.http2 = false;
    let cases: Vec<(ConnectOptions, &str)> = vec![
        (
            ConnectOptions {
                push_token_file: Some("t".into()),
                ..Default::default()
            },
            "push-token-file",
        ),
        (
            ConnectOptions {
                push_user: Some("u".into()),
                ..Default::default()
            },
            "push-user",
        ),
        (
            ConnectOptions {
                tls_ca_path: Some("ca".into()),
                ..Default::default()
            },
            "tls-ca-path",
        ),
        (
            ConnectOptions {
                tls_client_cert_path: Some("c".into()),
                ..Default::default()
            },
            "tls-client-cert-path",
        ),
        (
            ConnectOptions {
                tls_client_key_path: Some("k".into()),
                ..Default::default()
            },
            "tls-client-key-path",
        ),
        (
            ConnectOptions {
                allow_cleartext_credentials: true,
                ..Default::default()
            },
            "allow-cleartext-credentials",
        ),
        (changed_http, "ConnectOptions::http "),
    ];
    for (connect, field) in cases {
        let r = ostrya_rt::block_on(prepare_with(&remote, &connect, None));
        match r {
            Err(Error::InvalidInput(msg)) => {
                assert!(msg.contains(field), "{msg:?} lacks {field:?}");
                assert!(msg.contains("is an ssh address"), "{msg}");
            }
            Err(other) => panic!("{field}: {other:?}"),
            Ok(_) => panic!("{field}: accepted"),
        }
    }
    let r = ostrya_rt::block_on(prepare_with(&remote, &ConnectOptions::default(), None));
    assert!(matches!(r, Ok(Prepared::Ssh(_))));
}

/// The `Debug` output of a prepared session names the transport and the
/// HTTP address, and holds no credential and no part of the ssh command
/// line.
#[test]
fn a_prepared_session_shows_no_credential() {
    let dir = std::env::temp_dir().join(format!("ostrya-push-prepared-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let token = dir.join("token");
    std::fs::write(&token, b"tok-QXZ\n").unwrap();
    let remote = PushRemote::parse("http://h:8080/").unwrap();
    let prepared = ostrya_rt::block_on(PushSession::prepare(
        &remote,
        ConnectOptions {
            push_token_file: Some(token),
            push_user: Some("user-QXZ".into()),
            allow_cleartext_credentials: true,
            ..Default::default()
        },
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let shown = format!("{:?}", prepared.unwrap());
    assert_eq!(
        shown,
        r#"PreparedSession { transport: "http", url: "http://h:8080/", .. }"#
    );

    let remote = PushRemote::parse("ssh://user-QXZ@h/srv/repo").unwrap();
    let prepared = ostrya_rt::block_on(PushSession::prepare(
        &remote,
        ConnectOptions {
            ssh_command: Some(strings(&["ssh", "-i", "key-QXZ"])),
            ..Default::default()
        },
    ));
    let shown = format!("{:?}", prepared.unwrap());
    assert_eq!(shown, r#"PreparedSession { transport: "ssh", .. }"#);
}

#[test]
fn a_path_with_quotes_and_spaces_is_quoted_for_the_shell() {
    assert_eq!(quote_posix("/a b/it's"), r"'/a b/it'\''s'");
    assert_eq!(quote_posix("''"), r"''\'''\'''");
    assert_eq!(quote_posix("$HOME `x` \\n"), "'$HOME `x` \\n'");
    assert_eq!(
        argv("ssh://h/srv/my repo's"),
        strings(&["ssh", "h", r"ostrya receive --repo='/srv/my repo'\''s'"])
    );
}

#[test]
fn the_ssh_command_is_explicit_then_env_then_remote_key() {
    let explicit = strings(&["my ssh", "-F", "cfg"]);
    let env = OsStr::new("env-ssh  -v\t-4");
    let key = Some("key-ssh -q");
    assert_eq!(
        ssh_program(Some(&explicit), Some(env), key).unwrap(),
        explicit
    );
    assert_eq!(
        ssh_program(None, Some(env), key).unwrap(),
        strings(&["env-ssh", "-v", "-4"])
    );
    assert_eq!(
        ssh_program(None, None, key).unwrap(),
        strings(&["key-ssh", "-q"])
    );
    assert_eq!(ssh_program(None, None, None).unwrap(), strings(&["ssh"]));
}

#[test]
fn an_empty_ssh_command_is_refused() {
    let empty: Vec<String> = Vec::new();
    for r in [
        ssh_program(Some(&empty), None, None),
        ssh_program(Some(&strings(&[" "])), None, None),
        ssh_program(None, Some(OsStr::new("")), Some("ssh")),
        ssh_program(None, Some(OsStr::new(" \t ")), Some("ssh")),
        ssh_program(None, None, Some("  ")),
    ] {
        assert!(matches!(r, Err(Error::InvalidInput(_))), "{r:?}");
    }
    assert!(matches!(
        receive_command(Some(" ")),
        Err(Error::InvalidInput(_))
    ));
    assert_eq!(receive_command(None).unwrap(), "ostrya receive");
    assert_eq!(
        receive_command(Some("/x/ostrya receive")).unwrap(),
        "/x/ostrya receive"
    );
}

/// The command line of a pull runs the send command, which the options can
/// name, and an HTTP address is refused.
#[test]
fn a_pull_runs_the_send_command_over_ssh() {
    let remote = PushRemote::parse("ssh://me@host:2222/srv/repo").unwrap();
    let argv = pull_command_line(&remote, &PullConnectOptions::default(), None).unwrap();
    assert_eq!(
        argv,
        strings(&[
            "ssh",
            "-p",
            "2222",
            "me@host",
            "ostrya send --repo='/srv/repo'"
        ])
    );
    let connect = PullConnectOptions {
        ssh_command: Some(strings(&["my-ssh", "-F", "cfg"])),
        send_command: Some("/opt/ostrya send".into()),
        remote_ssh_command: Some("key-ssh".into()),
    };
    let argv = pull_command_line(&remote, &connect, Some(OsStr::new("env-ssh"))).unwrap();
    assert_eq!(
        argv,
        strings(&[
            "my-ssh",
            "-F",
            "cfg",
            "-p",
            "2222",
            "me@host",
            "/opt/ostrya send --repo='/srv/repo'"
        ])
    );
    let connect = PullConnectOptions {
        remote_ssh_command: Some("key-ssh -q".into()),
        ..Default::default()
    };
    assert_eq!(
        pull_command_line(&remote, &connect, Some(OsStr::new("env-ssh")))
            .unwrap()
            .first()
            .unwrap(),
        "env-ssh"
    );
    assert_eq!(
        pull_command_line(&remote, &connect, None).unwrap()[..2],
        strings(&["key-ssh", "-q"])
    );

    assert!(matches!(
        send_command(Some(" ")),
        Err(Error::InvalidInput(_))
    ));
    assert_eq!(send_command(None).unwrap(), "ostrya send");

    let http = PushRemote::parse("https://h/repo").unwrap();
    match pull_command_line(&http, &PullConnectOptions::default(), None) {
        Err(Error::InvalidInput(msg)) => assert!(msg.contains("HTTP address"), "{msg}"),
        other => panic!("{other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn an_env_value_that_is_not_utf8_is_refused() {
    use std::os::unix::ffi::OsStrExt;
    let r = ssh_program(None, Some(OsStr::from_bytes(b"ssh\xff")), None);
    match r {
        Err(Error::InvalidInput(msg)) => assert!(msg.contains("UTF-8"), "{msg}"),
        other => panic!("{other:?}"),
    }
}

/// The sessions over a stand-in ssh client: a shell script that ignores the
/// ssh arguments and plays one server.
#[cfg(unix)]
mod standin {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    use ostrya_core::{Checksum, ObjectName, ObjectType};
    use ostrya_gvariant::Value;

    use super::super::connect_with;
    use super::*;
    use crate::proto::{
        CommitRequest, ErrorMessage, FrameWriter, Hello, HelloReply, MIN_FRAME_LIMIT, Message,
        PROTOCOL_VERSION,
    };
    use crate::{
        BoxFuture, Compression, Encoding, ErrorCode, Expected, ObjectData, ObjectSource,
        RefOutcome, RefState, RefUpdate,
    };

    const LIMIT: Duration = Duration::from_millis(300);
    /// The time limit of a session in a test that checks that a call waits
    /// for the exit of the stand-in. A call that waits returns when the
    /// stand-in exits, so the limit costs no time, and a loaded host cannot
    /// end the wait before the stand-in exits.
    const EXIT_LIMIT: Duration = Duration::from_secs(5);
    const AGENT: &str = "transport-test";

    struct Dir(PathBuf);

    impl Dir {
        fn new() -> Dir {
            static N: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "ostrya-push-transport-{}-{}",
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

    fn encode(msgs: &[Message]) -> Vec<u8> {
        let mut w = FrameWriter::new(Vec::new());
        for msg in msgs {
            futures_lite::future::block_on(w.write_message(msg)).unwrap();
        }
        w.into_inner()
    }

    fn refs() -> Vec<String> {
        vec!["main".to_owned()]
    }

    fn hello_len() -> usize {
        encode(&[Message::Hello(Hello {
            version: PROTOCOL_VERSION,
            agent: Some(AGENT.into()),
            refs: refs(),
            one_way: false,
        })])
        .len()
    }

    fn hello_reply() -> Vec<u8> {
        encode(&[Message::HelloReply(HelloReply {
            version: PROTOCOL_VERSION,
            mode: "archive".into(),
            collection_id: None,
            max_frame: MIN_FRAME_LIMIT,
            max_have: 16_384,
            encodings: vec![Encoding::Raw],
            parallel_uploads: 1,
            refs: vec![RefState {
                name: "main".into(),
                commit: None,
            }],
        })])
    }

    fn update() -> RefUpdate {
        RefUpdate {
            name: "main".into(),
            expected: Expected::Absent,
            new: Some(Checksum::from_bytes([7; 32])),
        }
    }

    fn commit_len() -> usize {
        encode(&[Message::Commit(CommitRequest {
            updates: vec![update()],
            force: false,
        })])
        .len()
    }

    /// A `dd` that reads `n` bytes of standard input and drops them.
    fn skip(n: usize) -> String {
        format!("dd bs=1 count={n} of=/dev/null 2>/dev/null")
    }

    fn cat(path: &Path) -> String {
        format!("cat {}", quote_posix(path.to_str().unwrap()))
    }

    fn options(script: &str) -> ConnectOptions {
        ConnectOptions {
            ssh_command: Some(strings(&["sh", "-c", script, "stand-in"])),
            ..Default::default()
        }
    }

    /// Open a session over the stand-in `script`. The streams of the child
    /// belong to the runtime that opens them, so each test opens and drives
    /// its session in one `block_on`.
    async fn open(script: &str) -> Result<PushSession> {
        open_with_limit(script, LIMIT).await
    }

    /// As [`open`], with `limit` as the time limit of the session.
    async fn open_with_limit(script: &str, limit: Duration) -> Result<PushSession> {
        let remote = PushRemote::parse("ssh://me@host:2222/srv/it's repo").unwrap();
        connect_with(
            &remote,
            &options(script),
            None,
            &refs(),
            SessionOptions {
                agent: Some(AGENT.into()),
                ..Default::default()
            },
            limit,
        )
        .await
    }

    #[test]
    fn a_program_that_cannot_run_is_a_transport_error() {
        let remote = PushRemote::parse("host:repo").unwrap();
        let connect = ConnectOptions {
            ssh_command: Some(strings(&["ostrya-no-such-ssh"])),
            ..Default::default()
        };
        let r = ostrya_rt::block_on(connect_with(
            &remote,
            &connect,
            None,
            &refs(),
            SessionOptions::default(),
            LIMIT,
        ));
        match r {
            Err(Error::Transport(msg)) => assert!(msg.contains("ostrya-no-such-ssh"), "{msg}"),
            Err(other) => panic!("{other:?}"),
            Ok(_) => panic!("connected"),
        }
    }

    #[test]
    fn a_failing_ssh_client_is_reported_with_its_status_and_gets_the_command_line() {
        let dir = Dir::new();
        let record = dir.0.join("argv");
        let script = format!(
            "printf '%s\\n' \"$@\" > {}; exit 255",
            quote_posix(record.to_str().unwrap())
        );
        match ostrya_rt::block_on(open(&script)) {
            Err(Error::Transport(msg)) => {
                assert!(msg.contains("'sh' exited with"), "{msg}");
                assert!(msg.contains("255"), "{msg}");
            }
            Err(other) => panic!("{other:?}"),
            Ok(_) => panic!("connected"),
        }
        let recorded = std::fs::read_to_string(&record).unwrap();
        assert_eq!(
            recorded,
            "-p\n2222\nme@host\nostrya receive --repo='/srv/it'\\''s repo'\n"
        );
    }

    #[test]
    fn an_error_at_hello_is_that_error_whatever_the_exit_status() {
        let dir = Dir::new();
        let reply = dir.file(
            "error",
            &encode(&[Message::Error(ErrorMessage {
                code: ErrorCode::LockingDisabled,
                message: "no locks".into(),
                missing: Vec::new(),
                current: None,
            })]),
        );
        let script = format!("{}; {}; exit 1", skip(hello_len()), cat(&reply));
        match ostrya_rt::block_on(open(&script)) {
            Err(Error::LockingDisabled(msg)) => assert_eq!(msg, "no locks"),
            Err(other) => panic!("{other:?}"),
            Ok(_) => panic!("connected"),
        }
    }

    /// A shell command that creates `path`.
    fn touch(path: &Path) -> String {
        format!(": > {}", quote_posix(path.to_str().unwrap()))
    }

    fn names(count: u32) -> Vec<ObjectName> {
        (0..count)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[..4].copy_from_slice(&i.to_be_bytes());
                ObjectName::new(Checksum::from_bytes(bytes), ObjectType::File)
            })
            .collect()
    }

    /// A server that reads `Hello`, closes its input, replies with
    /// `HelloReply` from `reply`, and then stays silent for `stay`. It closes
    /// its input before it replies, so each write of the session after the
    /// open fails. Its standard error is not the standard error of the test,
    /// so a run of the tests does not wait for it.
    fn silent_after_reply(reply: &Path, stay: Duration) -> String {
        format!(
            "{}; exec 0<&-; {}; exec sleep {}.{:03} 2>/dev/null",
            skip(hello_len()),
            cat(reply),
            stay.as_secs(),
            stay.subsec_millis()
        )
    }

    #[test]
    fn a_stand_in_that_exits_after_commit_gives_an_unknown_outcome() {
        let dir = Dir::new();
        let reply = dir.file("reply", &hello_reply());
        for (code, status_in_message) in [(0, false), (3, true)] {
            let script = format!(
                "{}; {}; {}; exit {code}",
                skip(hello_len()),
                cat(&reply),
                skip(commit_len())
            );
            let r = ostrya_rt::block_on(async {
                let session = open(&script).await.unwrap();
                session.commit(&[update()], false).await
            });
            match r {
                Err(Error::CommitOutcomeUnknown { refs, message }) => {
                    assert_eq!(refs, strings(&["main"]));
                    assert_eq!(
                        message.contains("'sh' exited with exit status: 3"),
                        status_in_message,
                        "exit {code}: {message}"
                    );
                }
                other => panic!("exit {code}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_failed_commit_write_with_a_silent_server_is_an_unknown_outcome_in_time() {
        let dir = Dir::new();
        let reply = dir.file("reply", &hello_reply());
        let script = silent_after_reply(&reply, LIMIT * 2 + Duration::from_secs(1));
        let (r, elapsed) = ostrya_rt::block_on(async {
            let session = open(&script).await.unwrap();
            let start = Instant::now();
            let r = session.commit(&[update()], false).await;
            (r, start.elapsed())
        });
        match r {
            Err(Error::CommitOutcomeUnknown { message, .. }) => {
                assert!(message.contains("the write of Commit failed"), "{message}")
            }
            other => panic!("{other:?}"),
        }
        // One limit for the pending read, and one for the wait for the exit,
        // which the silent server outlasts.
        assert!(elapsed >= LIMIT * 2, "{elapsed:?}");
        assert!(elapsed < LIMIT * 2 + Duration::from_secs(3), "{elapsed:?}");
    }

    #[test]
    fn a_session_that_committed_returns_its_outcome_whatever_the_exit_status() {
        let dir = Dir::new();
        let reply = dir.file("reply", &hello_reply());
        let eof_seen = dir.0.join("eof_seen");
        let outcome = RefOutcome {
            name: "main".into(),
            old: None,
            new: update().new,
        };
        let committed = dir.file(
            "committed",
            &encode(&[Message::CommitReply(vec![outcome.clone()])]),
        );
        // The stand-in reads to end of file, so it exits only once the
        // session closed its standard input.
        let script = format!(
            "{}; {}; {}; {}; cat > /dev/null; {}; exit 7",
            skip(hello_len()),
            cat(&reply),
            skip(commit_len()),
            cat(&committed),
            touch(&eof_seen)
        );
        let (done, elapsed) = ostrya_rt::block_on(async {
            let session = open(&script).await.unwrap();
            let start = Instant::now();
            let r = session.commit(&[update()], false).await;
            (r, start.elapsed())
        });
        assert_eq!(done.unwrap().refs, vec![outcome]);
        assert!(eof_seen.exists(), "the stand-in did not read end of file");
        assert!(elapsed < LIMIT, "{elapsed:?}");
    }

    #[test]
    fn abort_closes_the_input_and_waits_for_the_exit() {
        let dir = Dir::new();
        let reply = dir.file("reply", &hello_reply());
        let seen = dir.0.join("seen");
        let eof_seen = dir.0.join("eof_seen");
        // The stand-in reads to end of file, so it exits only once the
        // session closed its standard input.
        let script = format!(
            "{}; {}; cat > {}; {}; exit 1",
            skip(hello_len()),
            cat(&reply),
            quote_posix(seen.to_str().unwrap()),
            touch(&eof_seen)
        );
        let (r, elapsed) = ostrya_rt::block_on(async {
            let session = open(&script).await.unwrap();
            let start = Instant::now();
            let r = session.abort().await;
            (r, start.elapsed())
        });
        r.unwrap();
        assert!(eof_seen.exists(), "the stand-in did not read end of file");
        assert!(elapsed < LIMIT, "{elapsed:?}");
        let seen = std::fs::read(&seen).unwrap();
        assert_eq!(seen, encode(&[Message::Abort]));
    }

    #[test]
    fn an_abort_that_cannot_be_written_to_a_failed_ssh_client_is_a_transport_error() {
        let dir = Dir::new();
        let reply = dir.file("reply", &hello_reply());
        // The stand-in closes its input before it replies, so the write of
        // `Abort` fails, and it exits with a failure status.
        let script = format!("{}; exec 0<&-; {}; exit 5", skip(hello_len()), cat(&reply));
        let r = ostrya_rt::block_on(async { open(&script).await.unwrap().abort().await });
        match r {
            Err(Error::Transport(msg)) => {
                assert!(msg.contains("'sh' exited with exit status: 5"), "{msg}");
                assert!(msg.contains("Broken pipe"), "{msg}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn abort_after_a_failed_call_writes_nothing_and_waits_for_the_exit() {
        let dir = Dir::new();
        let reply = dir.file("reply", &hello_reply());
        let seen = dir.0.join("seen");
        let exited = dir.0.join("exited");
        // The stand-in closes its output after the reply, so `missing` reads
        // end of file and leaves the session broken. The stand-in then reads
        // its input to end of file, and exits a moment later.
        let script = format!(
            "{}; {}; exec 1>&-; cat > {}; sleep 0.1; {}; exit 3",
            skip(hello_len()),
            cat(&reply),
            quote_posix(seen.to_str().unwrap()),
            touch(&exited)
        );
        let (missing, aborted) = ostrya_rt::block_on(async {
            let session = open(&script).await.unwrap();
            let missing = session.missing(&names(1)).await;
            (missing, session.abort().await)
        });
        match missing {
            Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof),
            other => panic!("{other:?}"),
        }
        match aborted {
            Err(Error::InvalidInput(msg)) => assert!(msg.contains("broken"), "{msg}"),
            other => panic!("{other:?}"),
        }
        assert!(exited.exists(), "abort returned before the stand-in exited");
        // The stand-in read the `Have` of `missing` alone: no `Abort`.
        let have = encode(&[Message::Have(names(1))]);
        assert_eq!(std::fs::read(&seen).unwrap(), have);
    }

    /// A source whose each open fails.
    struct FailingSource;

    impl ObjectSource for FailingSource {
        fn objects<'a>(&'a self, _commit: &'a Checksum) -> BoxFuture<'a, Result<Vec<ObjectName>>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn open<'a>(
            &'a self,
            _name: &'a ObjectName,
            _encoding: Encoding,
        ) -> BoxFuture<'a, Result<ObjectData>> {
            Box::pin(async { Err(Error::InvalidInput("gone".into())) })
        }

        fn detached_metadata<'a>(
            &'a self,
            _commit: &'a Checksum,
        ) -> BoxFuture<'a, Result<Option<Value>>> {
            Box::pin(async { Ok(None) })
        }
    }

    /// A server that replies with `HelloReply` from `reply`, copies its
    /// input to `seen` until end of file, and creates `exited` a moment
    /// later, just before it exits with a failure status.
    fn reads_to_eof(reply: &Path, seen: &Path, exited: &Path) -> String {
        format!(
            "{}; {}; cat > {}; sleep 0.1; {}; exit 3",
            skip(hello_len()),
            cat(reply),
            quote_posix(seen.to_str().unwrap()),
            touch(exited)
        )
    }

    fn assert_broken<T: std::fmt::Debug>(r: Result<T>) {
        match r {
            Err(Error::InvalidInput(msg)) => assert!(msg.contains("broken"), "{msg}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn commit_after_a_failed_send_writes_nothing_and_waits_for_the_exit() {
        let dir = Dir::new();
        let reply = dir.file("reply", &hello_reply());
        let seen = dir.0.join("seen");
        let exited = dir.0.join("exited");
        let script = reads_to_eof(&reply, &seen, &exited);
        let (sent, committed) = ostrya_rt::block_on(async {
            let session = open_with_limit(&script, EXIT_LIMIT).await.unwrap();
            let sent = session
                .send(&FailingSource, &names(1), &[], Compression::None)
                .await;
            (sent, session.commit(&[update()], false).await)
        });
        match sent {
            Err(Error::Source(_)) => {}
            other => panic!("{other:?}"),
        }
        assert_broken(committed);
        assert!(exited.exists(), "commit did not wait for the stand-in");
        // The stand-in read the `Abort` of the failed `send` alone: no
        // `Commit`.
        assert_eq!(std::fs::read(&seen).unwrap(), encode(&[Message::Abort]));
    }

    #[test]
    fn commit_after_a_failed_missing_writes_nothing_and_waits_for_the_exit() {
        let dir = Dir::new();
        let reply = dir.file("reply", &hello_reply());
        let seen = dir.0.join("seen");
        let exited = dir.0.join("exited");
        // The stand-in closes its output after the reply, so `missing` reads
        // end of file and leaves the session broken.
        let script = format!(
            "{}; {}; exec 1>&-; cat > {}; sleep 0.1; {}; exit 3",
            skip(hello_len()),
            cat(&reply),
            quote_posix(seen.to_str().unwrap()),
            touch(&exited)
        );
        let (missing, committed) = ostrya_rt::block_on(async {
            let session = open_with_limit(&script, EXIT_LIMIT).await.unwrap();
            let missing = session.missing(&names(1)).await;
            (missing, session.commit(&[update()], false).await)
        });
        match missing {
            Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof),
            other => panic!("{other:?}"),
        }
        assert_broken(committed);
        assert!(exited.exists(), "commit did not wait for the stand-in");
        let have = encode(&[Message::Have(names(1))]);
        assert_eq!(std::fs::read(&seen).unwrap(), have);
    }

    #[test]
    fn commit_after_a_failed_send_gives_up_after_the_limit() {
        let dir = Dir::new();
        let reply = dir.file("reply", &hello_reply());
        let script = silent_after_reply(&reply, LIMIT + Duration::from_secs(1));
        let (committed, elapsed) = ostrya_rt::block_on(async {
            let session = open(&script).await.unwrap();
            let sent = session
                .send(&FailingSource, &names(1), &[], Compression::None)
                .await;
            assert!(matches!(sent, Err(Error::Source(_))), "{sent:?}");
            let start = Instant::now();
            let r = session.commit(&[update()], false).await;
            (r, start.elapsed())
        });
        assert_broken(committed);
        assert!(elapsed >= LIMIT, "{elapsed:?}");
        assert!(elapsed < LIMIT + Duration::from_secs(3), "{elapsed:?}");
    }

    #[test]
    fn a_refused_commit_writes_nothing_and_waits_for_the_exit() {
        let dir = Dir::new();
        let reply = dir.file("reply", &hello_reply());
        let other = RefUpdate {
            name: "other".into(),
            ..update()
        };
        let cases: [(&[RefUpdate], &str); 3] = [
            (&[], "at least one ref update"),
            (std::slice::from_ref(&other), "was not named"),
            (&[update(), update()], "updated twice"),
        ];
        for (updates, wanted) in cases {
            let seen = dir.0.join("seen");
            let exited = dir.0.join("exited");
            let _ = std::fs::remove_file(&exited);
            let script = reads_to_eof(&reply, &seen, &exited);
            let r = ostrya_rt::block_on(async {
                let session = open_with_limit(&script, EXIT_LIMIT).await.unwrap();
                session.commit(updates, false).await
            });
            match r {
                Err(Error::InvalidInput(msg)) => assert!(msg.contains(wanted), "{msg}"),
                other => panic!("{wanted}: {other:?}"),
            }
            assert!(exited.exists(), "{wanted}: commit did not wait");
            assert_eq!(std::fs::read(&seen).unwrap(), b"", "{wanted}");
        }
    }

    #[test]
    fn a_server_that_closes_its_input_and_stays_silent_ends_a_failed_write_in_time() {
        let dir = Dir::new();
        let reply = dir.file("reply", &hello_reply());
        let script = silent_after_reply(&reply, LIMIT + Duration::from_secs(1));
        let names = names(40_000);
        let (r, elapsed) = ostrya_rt::block_on(async {
            let session = open(&script).await.unwrap();
            let start = Instant::now();
            let r = session.missing(&names).await;
            (r, start.elapsed())
        });
        match r {
            Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe),
            other => panic!("{other:?}"),
        }
        assert!(elapsed >= LIMIT, "{elapsed:?}");
        assert!(elapsed < LIMIT + Duration::from_secs(3), "{elapsed:?}");
    }

    /// The pull sessions over a stand-in ssh client.
    mod pull {
        use super::super::super::connect_pull_with;
        use super::*;
        use crate::proto::{GetReply, PULL_PROTOCOL_VERSION, PullHello, PullHelloReply};
        use crate::{PullConnectOptions, PullSessionOptions};

        const PULL_AGENT: &str = "pull-transport-test";

        fn pull_hello_len() -> usize {
            encode(&[Message::PullHello(PullHello {
                version: PULL_PROTOCOL_VERSION,
                agent: Some(PULL_AGENT.into()),
            })])
            .len()
        }

        fn get_len(path: &str) -> usize {
            encode(&[Message::Get(path.into())]).len()
        }

        fn pull_reply() -> Vec<u8> {
            encode(&[Message::PullHelloReply(PullHelloReply {
                version: PULL_PROTOCOL_VERSION,
            })])
        }

        async fn open_pull(script: &str, limit: Duration) -> Result<crate::PullSession> {
            let remote = PushRemote::parse("ssh://me@host:2222/srv/it's repo").unwrap();
            connect_pull_with(
                &remote,
                &PullConnectOptions {
                    ssh_command: Some(strings(&["sh", "-c", script, "stand-in"])),
                    ..Default::default()
                },
                None,
                PullSessionOptions {
                    agent: Some(PULL_AGENT.into()),
                    ..Default::default()
                },
                limit,
            )
            .await
        }

        /// A stand-in that runs the send command gets the command line of a
        /// pull, and an ssh client that exits with a failure status after a
        /// clean end does not fail the session.
        #[test]
        fn a_failure_status_after_a_clean_end_is_no_failure() {
            let dir = Dir::new();
            let record = dir.0.join("argv");
            let eof_seen = dir.0.join("eof_seen");
            let reply = dir.file("reply", &pull_reply());
            let not_found = dir.file(
                "not_found",
                &encode(&[Message::GetReply(GetReply {
                    found: false,
                    len: None,
                })]),
            );
            let script = format!(
                "printf '%s\\n' \"$@\" > {}; {}; {}; {}; {}; cat > /dev/null; {}; exit 9",
                quote_posix(record.to_str().unwrap()),
                skip(pull_hello_len()),
                cat(&reply),
                skip(get_len("config")),
                cat(&not_found),
                touch(&eof_seen)
            );
            let r = ostrya_rt::block_on(async {
                let session = open_pull(&script, EXIT_LIMIT).await.unwrap();
                assert!(session.get("config", 64).await.unwrap().is_none());
                session.finish().await
            });
            r.unwrap();
            assert!(eof_seen.exists(), "the stand-in did not read end of file");
            assert_eq!(
                std::fs::read_to_string(&record).unwrap(),
                "-p\n2222\nme@host\nostrya send --repo='/srv/it'\\''s repo'\n"
            );
        }

        /// At an unclean end the session closes the input of the stand-in and
        /// drops its output before it waits. A stand-in blocked in the write
        /// of a body on a full pipe then fails the write and exits, so the
        /// wait ends with the exit and not with the time limit. This holds
        /// for a body that the caller dropped, and for a body that the caller
        /// still holds, whose later read then repeats the error.
        #[test]
        fn an_unclean_end_closes_both_sides_before_the_wait() {
            for hold in [false, true] {
                let dir = Dir::new();
                let reply = dir.file("reply", &pull_reply());
                let head = dir.file(
                    "head",
                    &encode(&[Message::GetReply(GetReply {
                        found: true,
                        len: None,
                    })]),
                );
                let mut chunk = 4096u32.to_be_bytes().to_vec();
                chunk.extend_from_slice(&[b'x'; 4096]);
                let chunk = dir.file("chunk", &chunk);
                let exited = dir.0.join("exited");
                // The stand-in writes chunks of the body until a write fails,
                // which happens when the client drops its side of the output.
                let script = format!(
                    "{}; {}; {}; {}; while {} 2>/dev/null; do :; done; {}; exit 6",
                    skip(pull_hello_len()),
                    cat(&reply),
                    skip(get_len("big")),
                    cat(&head),
                    cat(&chunk),
                    touch(&exited)
                );
                let (finished, elapsed) = ostrya_rt::block_on(async {
                    let session = open_pull(&script, EXIT_LIMIT).await.unwrap();
                    let mut body = session.get("big", u64::MAX).await.unwrap().unwrap();
                    let mut some = [0u8; 100];
                    futures_lite::io::AsyncReadExt::read_exact(&mut body, &mut some)
                        .await
                        .unwrap();
                    let held = if hold {
                        Some(body)
                    } else {
                        drop(body);
                        None
                    };
                    let start = Instant::now();
                    let finished = session.finish().await;
                    let elapsed = start.elapsed();
                    if let Some(mut body) = held {
                        let later = futures_lite::io::AsyncReadExt::read(&mut body, &mut some)
                            .await
                            .unwrap_err();
                        assert!(later.to_string().contains("unread"), "{later}");
                    }
                    (finished, elapsed)
                });
                let expected = if hold { "unread" } else { "dropped" };
                match finished {
                    Err(Error::InvalidInput(msg)) => {
                        assert!(msg.contains(expected), "hold {hold}: {msg}")
                    }
                    other => panic!("hold {hold}: {other:?}"),
                }
                assert!(
                    exited.exists(),
                    "hold {hold}: finish returned before the stand-in exited"
                );
                assert!(elapsed < EXIT_LIMIT, "hold {hold}: {elapsed:?}");
            }
        }

        /// A session that failed with an I/O error, over a stand-in that exits
        /// with a failure status, ends with a transport error that names the
        /// program and the status.
        #[test]
        fn an_io_error_with_a_failure_status_is_a_transport_error() {
            let dir = Dir::new();
            let reply = dir.file("reply", &pull_reply());
            let script = format!(
                "{}; {}; {}; exit 4",
                skip(pull_hello_len()),
                cat(&reply),
                skip(get_len("config"))
            );
            let (got, finished) = ostrya_rt::block_on(async {
                let session = open_pull(&script, EXIT_LIMIT).await.unwrap();
                let got = session.get("config", 64).await;
                (got, session.finish().await)
            });
            match got {
                Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof),
                other => panic!("{other:?}"),
            }
            match finished {
                Err(Error::Transport(msg)) => {
                    assert!(msg.contains("'sh' exited with exit status: 4"), "{msg}")
                }
                other => panic!("{other:?}"),
            }
        }
    }
}
