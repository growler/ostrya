use std::ffi::OsStr;

use super::ssh::{SshAddr, quote_posix, receive_command, ssh_program};
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
fn http_addresses_parse_and_connect_refuses_them() {
    for address in ["http://h/repo", "https://h:8443/repo"] {
        let remote = PushRemote::parse(address).unwrap();
        assert_eq!(remote.to_string(), address);
        let r = ostrya_rt::block_on(PushSession::connect(
            &remote,
            ConnectOptions::default(),
            &[],
            SessionOptions::default(),
        ));
        match r {
            Err(Error::InvalidInput(msg)) => assert!(msg.contains("HTTP"), "{msg}"),
            Err(other) => panic!("{address}: {other:?}"),
            Ok(_) => panic!("{address}: connected"),
        }
    }
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

    use super::super::connect_with;
    use super::*;
    use crate::proto::{
        CommitRequest, ErrorMessage, FrameWriter, Hello, HelloReply, MIN_FRAME_LIMIT, Message,
        PROTOCOL_VERSION,
    };
    use crate::{Encoding, ErrorCode, Expected, RefOutcome, RefState, RefUpdate};

    const LIMIT: Duration = Duration::from_millis(300);
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
            LIMIT,
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
}
