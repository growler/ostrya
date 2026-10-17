use std::ffi::OsStr;

use super::ssh::{quote_posix, receive_command, send_command, ssh_program};
use super::*;

fn ssh(address: &str) -> SshAddress {
    SshAddress::parse_with(address, false).unwrap()
}

fn argv(address: &str) -> Vec<String> {
    ssh(address).command_line(vec!["ssh".into()], "ostrya receive")
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn refused(address: &str, windows: bool) -> String {
    match parse_endpoint(address, windows) {
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
    assert_eq!(ssh("h:/~/a/b"), ssh("ssh://h/~/a/b"));
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
    // The scp form is read as git reads it. It cannot give a user with `:`,
    // and an IPv6 host needs brackets.
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
        parse_endpoint(address, false).unwrap();
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
        // On other systems, the backslash is a character that a host cannot
        // hold.
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

/// A refusal names the address that it refuses, without its userinfo. The
/// push and the pull get the same refusal.
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
    assert_eq!(
        refused("ssh://u:pw@h/r", false),
        "address 'ssh://h/r': the user holds ':'"
    );
    assert_eq!(
        refused("HTTPS://user:pw@h/r", false),
        "address 'HTTPS://h/r': the scheme is not supported"
    );
    assert_eq!(
        refused("a@b@host:r", false),
        "address 'host:r': the address holds more than one '@'"
    );
    assert_eq!(
        refused("alice:s3cret://x@host:repo", false),
        "address 'host:repo': the scheme is not supported"
    );
}

/// The scp form reads a leading `/~` of its path as the home prefix, as git
/// reads the form. Each other path that starts with `/` stays absolute.
#[test]
fn the_scp_form_reads_a_leading_slash_tilde_as_the_home_prefix() {
    for windows in [false, true] {
        let ssh = |address: &str| match SshAddress::parse_with(address, windows) {
            Ok(addr) => addr,
            other => panic!("{address} windows={windows}: {other:?}"),
        };
        let reason = |address: &str| {
            let msg = refused(address, windows);
            match msg.split_once("': ") {
                Some((_, reason)) => reason.to_owned(),
                None => panic!("{address}: {msg}"),
            }
        };
        assert_eq!(ssh("host:/~/r"), ssh("ssh://host/~/r"));
        assert_eq!(ssh("host:/~/r"), ssh("host:r"));
        assert_eq!(ssh("host:/~//r"), ssh("host:r"));
        assert_eq!(ssh("u@[::1]:/~/r"), ssh("ssh://u@[::1]/~/r"));
        assert_eq!(ssh("ab:/~/r").to_string(), "ssh://ab/~/r");
        assert_eq!(ssh("[C]:/~/r").to_string(), "ssh://C/~/r");
        for (scp, url) in [
            ("host:/~x/r", "ssh://host/~x/r"),
            ("host:/~", "ssh://host/~"),
            ("u@host:/~x", "ssh://u@host/~x"),
        ] {
            assert_eq!(reason(scp), reason(url), "{scp} windows={windows}");
        }
        let msg = refused("host:/~/", windows);
        assert!(msg.contains("path is empty"), "{msg}");
        for (address, shown) in [
            ("host:/./~x/r", "ssh://host/./~x/r"),
            ("host:/srv/~/r", "ssh://host/srv/~/r"),
        ] {
            assert_eq!(ssh(address).to_string(), shown, "windows={windows}");
        }
        // An scp path that starts with `//` puts `://` in the address, so the
        // parse reads a scheme.
        assert_eq!(reason("host://~/r"), "the scheme is not supported");
    }
    for address in ["C:/~/r", "C:/~x/r"] {
        let msg = refused(address, true);
        assert!(msg.contains("local path"), "{address}: {msg}");
    }
    assert_eq!(ssh("C:/~/r"), ssh("ssh://C/~/r"));
    let msg = refused("C:/~x/r", false);
    assert!(msg.contains("~USER"), "{msg}");
}

/// No refusal shows the user or the password of an address. The message
/// shows the address without the text up to its last `@`.
#[test]
fn no_refusal_shows_the_userinfo_of_an_address() {
    let both = SECRET.iter().flat_map(|a| [(*a, false), (*a, true)]);
    let windows_only = SECRET_ON_WINDOWS.iter().map(|a| (*a, true));
    for (address, windows) in both.chain(windows_only) {
        let results = [
            ("Endpoint", parse_endpoint(address, windows).map(drop)),
            (
                "SshAddress",
                SshAddress::parse_with(address, windows).map(drop),
            ),
        ];
        for (name, result) in results {
            match result {
                Err(Error::InvalidInput(msg)) => {
                    assert!(!msg.contains("QXZ"), "{name} {address:?}: {msg}");
                }
                other => panic!("{name} {address:?} windows={windows}: {other:?}"),
            }
        }
    }
}

#[test]
fn a_one_letter_host_is_a_local_path_on_windows() {
    for address in ["C:\\repo", "C:repo", "c:/repo", "u@C:repo"] {
        let msg = refused(address, true);
        assert!(msg.contains("local path"), "{address}: {msg}");
        parse_endpoint(address, false).unwrap();
    }
    parse_endpoint("ssh://C/repo", true).unwrap();
    parse_endpoint("ab:repo", true).unwrap();
    parse_endpoint("[C]:repo", true).unwrap();
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
        let Endpoint::Http(http) = Endpoint::parse(address).unwrap() else {
            panic!("{address} is not an HTTP endpoint");
        };
        assert_eq!(http.mirrors, [address], "{address}");
    }
    for (address, part) in [
        ("http://", "invalid url"),
        ("https://:443/r", "no host"),
        ("https://user:pw-QXZ@h/r", "userinfo"),
        ("https://h/r?x=1", "query string"),
        ("https://h/r#frag", "fragment"),
        ("https://h:65536/r", "not a number"),
        ("http://h:port/r", "not a number"),
        // A `/` or a `?` in a password ends the authority before the `@`. No
        // message names the password.
        ("https://user:443/pw-QXZ@h/repo", "userinfo"),
        ("https://user:1234?pw-QXZ@h/", "userinfo"),
        ("http://h:+80/", "not a number"),
    ] {
        let msg = refused(address, false);
        assert!(msg.contains(part), "{address}: {msg}");
        assert!(!msg.contains("QXZ"), "{address}: {msg}");
    }
}

/// The result of the parse of an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Want {
    Ssh,
    Http,
    Refused,
}

use Want::{Http, Refused, Ssh};

/// The addresses of the address tests, with the `windows` value of the parse
/// and the result.
const ROWS: &[(&str, bool, Want)] = &[
    // The forms and their command lines.
    ("ssh://host/srv/repo", false, Ssh),
    ("ssh://me@host:2222/srv/repo", false, Ssh),
    ("ssh://host/~/repos/a", false, Ssh),
    ("ssh://me@[::1]:22/r", false, Ssh),
    ("ssh://[::1]/r", false, Ssh),
    ("host:repo", false, Ssh),
    ("me@host:/srv/repo", false, Ssh),
    ("host:~/repo", false, Ssh),
    ("[::1]:repo", false, Ssh),
    ("me@[fe80::1]:a:b", false, Ssh),
    ("C:repo", false, Ssh),
    ("host:%41", false, Ssh),
    // The home prefix.
    ("ssh://h/~/a/b", false, Ssh),
    ("h:a/b", false, Ssh),
    ("h:~/a", false, Ssh),
    ("h:a", false, Ssh),
    ("ssh://h/a/b", false, Ssh),
    ("ssh://u@[::1]:7/x", false, Ssh),
    ("host:~//etc/repo", false, Ssh),
    ("host:etc/repo", false, Ssh),
    ("ssh://host/~//etc/repo", false, Ssh),
    ("ssh://host/~///etc/repo", false, Ssh),
    ("host:~//", false, Refused),
    ("ssh://host/~//", false, Refused),
    ("host:~///", false, Refused),
    // The first `:` of the scp form.
    ("u:p@host:path", false, Ssh),
    ("fe80::1:repo", false, Ssh),
    ("[fe80::1]:repo", false, Ssh),
    ("ssh://u:p@host/r", false, Refused),
    // The characters of a host and of a user.
    ("ssh://ho st/p", false, Refused),
    ("ssh://h?x/p", false, Refused),
    ("ssh://h;x/p", false, Refused),
    ("ssh://$(x)/p", false, Refused),
    ("ssh://h\nx/p", false, Refused),
    ("ssh://h\tx/p", false, Refused),
    ("ssh://h`x`/p", false, Refused),
    ("ssh://h|x/p", false, Refused),
    ("ssh://h&x/p", false, Refused),
    ("ssh://h'x/p", false, Refused),
    ("ssh://h\\x/p", false, Refused),
    ("ssh://u x@h/p", false, Refused),
    ("ssh://u;x@h/p", false, Refused),
    ("ssh://$(u)@h/p", false, Refused),
    ("ssh://u\n@h/p", false, Refused),
    ("ssh://[::1;x]/p", false, Refused),
    ("ssh://[::1 ]/p", false, Refused),
    ("ssh://[fe80::1%e$x]/p", false, Refused),
    ("ssh://[g::1]/p", false, Refused),
    ("ho st:p", false, Refused),
    ("h?x:p", false, Refused),
    ("h;x:p", false, Refused),
    ("$(x):p", false, Refused),
    ("h\nx:p", false, Refused),
    ("h\tx:p", false, Refused),
    ("u x@h:p", false, Refused),
    ("u;x@h:p", false, Refused),
    ("$(u)@h:p", false, Refused),
    ("u\t@h:p", false, Refused),
    ("[::1;x]:p", false, Refused),
    ("ssh://my-host.example_1/p", false, Ssh),
    ("ssh://u.s-e_r@h/p", false, Ssh),
    ("ssh://[fe80::1%eth0]/p", false, Ssh),
    ("ssh://[::ffff:192.0.2.1]:22/p", false, Ssh),
    ("my-host.example_1:p", false, Ssh),
    ("u.s-e_r@h:p", false, Ssh),
    ("[fe80::1%eth0]:p", false, Ssh),
    // A backslash before the first `:`.
    ("..\\dir:x", true, Refused),
    ("..\\dir:x", false, Refused),
    ("\\\\?\\C:\\repo", true, Refused),
    ("\\\\?\\C:\\repo", false, Refused),
    ("dir\\sub:x", true, Refused),
    ("dir\\sub:x", false, Refused),
    // Malformed addresses.
    ("ssh://-oProxyCommand=x/r", false, Refused),
    ("ssh://-u@host/r", false, Refused),
    ("-oProxyCommand=x:r", false, Refused),
    ("-u@host:r", false, Refused),
    ("ssh://host", false, Refused),
    ("ssh:///r", false, Refused),
    ("ssh://@host/r", false, Refused),
    ("ssh://host:/r", false, Refused),
    ("ssh://host:0/r", false, Refused),
    ("ssh://host:65536/r", false, Refused),
    ("ssh://host:22x/r", false, Refused),
    ("ssh://u:pw@host/r", false, Refused),
    ("ssh://a@b@host/r", false, Refused),
    ("ssh://host/~", false, Refused),
    ("ssh://host/~/", false, Refused),
    ("ssh://host/~user/r", false, Refused),
    ("ssh://[::1/r", false, Refused),
    ("ssh://[::1]x/r", false, Refused),
    ("host:", false, Refused),
    ("host:~", false, Refused),
    ("host:~user/r", false, Refused),
    ("a@b@host:r", false, Refused),
    ("@host:r", false, Refused),
    (":r", false, Refused),
    ("[::1:r", false, Refused),
    ("ho]st:r", false, Refused),
    ("file:///srv/repo", false, Refused),
    ("ftp://host/r", false, Refused),
    ("/srv/repo", false, Refused),
    ("repo", false, Refused),
    ("dir/host:r", false, Refused),
    ("http://", false, Refused),
    // A one-letter host on Windows.
    ("C:\\repo", true, Refused),
    ("C:\\repo", false, Ssh),
    ("C:repo", true, Refused),
    ("c:/repo", true, Refused),
    ("c:/repo", false, Ssh),
    ("u@C:repo", true, Refused),
    ("u@C:repo", false, Ssh),
    ("ssh://C/repo", true, Ssh),
    ("ab:repo", true, Ssh),
    ("[C]:repo", true, Ssh),
    // A leading `/~` of the scp path, and a zone in a bracketed host.
    ("host:/~/r", false, Ssh),
    ("host:/~/r", true, Ssh),
    ("host:/~//r", false, Ssh),
    ("host:/~//r", true, Ssh),
    ("u@[::1]:/~/r", false, Ssh),
    ("u@[::1]:/~/r", true, Ssh),
    ("host:/./~x/r", false, Ssh),
    ("host:/./~x/r", true, Ssh),
    ("host:/srv/~/r", false, Ssh),
    ("host:/srv/~/r", true, Ssh),
    ("ab:/~/r", false, Ssh),
    ("ab:/~/r", true, Ssh),
    ("[C]:/~/r", false, Ssh),
    ("[C]:/~/r", true, Ssh),
    ("ssh://host/~/r", false, Ssh),
    ("host:r", false, Ssh),
    ("ssh://u@[::1]/~/r", false, Ssh),
    ("h:/~/a/b", false, Ssh),
    ("C:/~/r", false, Ssh),
    ("ssh://C/~/r", false, Ssh),
    ("[fe80%eth0]:r", false, Ssh),
    ("ssh://[fe80%eth0]/r", false, Ssh),
    ("ssh://h/srv/my repo's", false, Ssh),
    ("ssh://user-QXZ@h/srv/repo", false, Ssh),
    ("ssh://me@host:2222/srv/it's repo", false, Ssh),
    ("host:/~x/r", false, Refused),
    ("host:/~x/r", true, Refused),
    ("host:/~", false, Refused),
    ("host:/~", true, Refused),
    ("host://~/r", false, Refused),
    ("host://~/r", true, Refused),
    ("host:/~/", false, Refused),
    ("host:/~/", true, Refused),
    ("C:/~x/r", false, Refused),
    ("C:/~x/r", true, Refused),
    ("C:/~/r", true, Refused),
    ("u@C:/~/r", true, Refused),
    // HTTP addresses.
    ("http://h/repo", false, Http),
    ("https://h:8443/repo", false, Http),
    ("http://127.0.0.1:8080/", false, Http),
    ("https://[::1]/", false, Http),
    ("https://h", false, Http),
    ("http://h:080/", false, Http),
    ("https://:443/r", false, Refused),
    ("https://user:pw-QXZ@h/r", false, Refused),
    ("https://h/r?x=1", false, Refused),
    ("https://h/r#frag", false, Refused),
    ("https://h:65536/r", false, Refused),
    ("http://h:port/r", false, Refused),
    ("https://user:443/pw-QXZ@h/repo", false, Refused),
    ("https://user:1234?pw-QXZ@h/", false, Refused),
    ("http://h:+80/", false, Refused),
];

/// Addresses with userinfo that each parse refuses, with `windows` set to
/// `false` and to `true`. `QXZ` marks the user and the password.
const SECRET: &[&str] = &[
    "HTTPS://user-QXZ:pw-QXZ@h/r",
    "HTTP://user-QXZ@h/r",
    "SSH://user-QXZ:pw-QXZ@h/r",
    "Ssh://user-QXZ@h/r",
    "ftp://user-QXZ:pw-QXZ@h/r",
    "file://user-QXZ@h/r",
    "https://user-QXZ:pw-QXZ@h/r",
    "http://user-QXZ@h/r",
    "ssh://user-QXZ:pw-QXZ@h/r",
    "ssh://user-QXZ@h",
    "ssh://user-QXZ@h:0/r",
    "ssh://user-QXZ:p/w-QXZ@h/r",
    "ssh://user-QXZ:p?w-QXZ@h/r",
    "ssh://user-QXZ:pw@QXZ@h/r",
    "ssh://-user-QXZ@h/r",
    "ssh://user QXZ@h/r",
    "ssh://user-QXZ@h/~x/r",
    "ssh://user-QXZ@h/~/",
    "ssh://user-QXZ@[::1/r",
    "user-QXZ@h:",
    "user-QXZ@h:~x/r",
    "user-QXZ@h:/~x/r",
    "user-QXZ@h:/~",
    "user-QXZ@@h:r",
    "a@user-QXZ@h:r",
    "user-QXZ@-h:r",
    "user-QXZ@h;x:r",
    "user QXZ@h:r",
    "user;QXZ:pw-QXZ@h:r",
    "user-QXZ@[::1:r",
    "user-QXZ@host",
    "dir/user-QXZ@h:r",
    "user-QXZ:pw-QXZ://x@h:r",
    "user-QXZ:pw-QXZ://x@h/r",
];

/// Addresses with userinfo that each parse refuses on Windows alone.
const SECRET_ON_WINDOWS: &[&str] = &["user-QXZ@C:repo", "user-QXZ@dir\\x:r"];

/// `Endpoint::parse` gives the transport of the `want` column for each
/// address. An ssh address and the refusal of an ssh address are those of
/// `SshAddress::parse`.
#[test]
fn an_endpoint_parses_each_address_of_the_table() {
    let secret = SECRET
        .iter()
        .flat_map(|a| [(*a, false, Refused), (*a, true, Refused)]);
    let secret_on_windows = SECRET_ON_WINDOWS.iter().map(|a| (*a, true, Refused));
    for (address, windows, want) in ROWS.iter().copied().chain(secret).chain(secret_on_windows) {
        let endpoint = parse_endpoint(address, windows);
        let case = format!("{address:?} windows={windows}");
        let is_http = address.starts_with("http://") || address.starts_with("https://");
        match want {
            Ssh => {
                let Ok(Endpoint::Ssh {
                    address: parsed,
                    options,
                }) = endpoint
                else {
                    panic!("{case}: the endpoint is not ssh: {endpoint:?}");
                };
                let ssh = SshAddress::parse_with(address, windows).unwrap();
                assert_eq!(parsed, ssh, "{case}");
                assert_eq!(options, SshOptions::default(), "{case}");
            }
            Http => {
                let Ok(Endpoint::Http(http)) = endpoint else {
                    panic!("{case}: the endpoint is not HTTP: {endpoint:?}");
                };
                let new = ostrya_fetch::FetcherOptions::new(address);
                assert_eq!(http.mirrors, vec![address.to_owned()], "{case}");
                assert_eq!(http.headers, new.headers, "{case}");
                assert!(http.basic_auth.is_none(), "{case}");
                assert!(http.bearer_token.is_none(), "{case}");
                assert_eq!(
                    http.allow_cleartext_credentials, new.allow_cleartext_credentials,
                    "{case}"
                );
                assert_eq!(http.max_retries, new.max_retries, "{case}");
                assert_eq!(http.max_redirects, new.max_redirects, "{case}");
                assert_eq!(http.max_outstanding, new.max_outstanding, "{case}");
            }
            Refused => {
                let Err(Error::InvalidInput(msg)) = endpoint else {
                    panic!("{case}: the endpoint is not refused: {endpoint:?}");
                };
                if !is_http {
                    let Err(Error::InvalidInput(from_ssh)) =
                        SshAddress::parse_with(address, windows)
                    else {
                        panic!("{case}: the ssh address is not refused");
                    };
                    assert_eq!(msg, from_ssh, "{case}");
                }
            }
        }
    }
}

/// The parse of the `Display` output of an ssh address gives an equal
/// address.
#[test]
fn the_parse_of_the_display_gives_an_equal_address() {
    for &(address, windows, want) in ROWS {
        if want != Ssh {
            continue;
        }
        let case = format!("{address:?} windows={windows}");
        let parsed = SshAddress::parse_with(address, windows).unwrap();
        let shown = parsed.to_string();
        assert_eq!(
            SshAddress::parse_with(&shown, windows).unwrap(),
            parsed,
            "{case}: {shown}"
        );
    }
}

/// The parse of an ssh address refuses an HTTP address, and the message does
/// not show the address.
#[test]
fn an_ssh_address_is_not_an_http_address() {
    for address in [
        "http://h/repo",
        "https://h:8443/repo",
        "https://user:pw-QXZ@h/r",
        "https://user:443/pw-QXZ@h/repo",
        "http://",
    ] {
        for windows in [false, true] {
            match SshAddress::parse_with(address, windows) {
                Err(Error::InvalidInput(msg)) => {
                    assert_eq!(msg, "address: an HTTP address is not an ssh address");
                }
                other => panic!("{address}: expected a refusal, got {other:?}"),
            }
        }
        assert!(SshAddress::parse(address).is_err(), "{address}");
    }
    // The other schemes keep their refusal.
    let msg = match SshAddress::parse_with("ftp://host/r", false) {
        Err(Error::InvalidInput(msg)) => msg,
        other => panic!("expected a refusal, got {other:?}"),
    };
    assert_eq!(msg, "address 'ftp://host/r': the scheme is not supported");
}

/// Returns the transport that `endpoint` prepares, with no value of the
/// environment variable.
fn prepared(endpoint: Endpoint) -> Result<Prepared> {
    ostrya_rt::block_on(prepare_with(endpoint, None))
}

/// Returns an HTTP endpoint with the mirrors `mirrors`.
fn http_endpoint(mirrors: &[&str]) -> Endpoint {
    Endpoint::Http(ostrya_fetch::FetcherOptions {
        mirrors: strings(mirrors),
        ..Default::default()
    })
}

/// An ssh endpoint gives the command line of its options, with
/// `ostrya receive` as the default remote command.
#[test]
fn an_ssh_endpoint_gives_the_command_line_of_its_options() {
    let address = SshAddress::parse("ssh://me@host:2222/srv/repo").unwrap();
    let argv = |options: SshOptions, env: Option<&OsStr>| {
        let endpoint = Endpoint::Ssh {
            address: address.clone(),
            options,
        };
        match ostrya_rt::block_on(prepare_with(endpoint, env)) {
            Ok(Prepared::Ssh(argv)) => argv,
            Ok(Prepared::Http(_)) => panic!("an ssh endpoint prepared HTTP"),
            Err(e) => panic!("{e:?}"),
        }
    };
    assert_eq!(
        argv(SshOptions::default(), None),
        strings(&[
            "ssh",
            "-p",
            "2222",
            "me@host",
            "ostrya receive --repo='/srv/repo'"
        ])
    );
    let options = SshOptions {
        command: None,
        config_command: Some("key-ssh -q".into()),
        remote_command: Some("/opt/ostrya receive".into()),
    };
    assert_eq!(
        argv(options.clone(), None),
        strings(&[
            "key-ssh",
            "-q",
            "-p",
            "2222",
            "me@host",
            "/opt/ostrya receive --repo='/srv/repo'"
        ])
    );
    assert_eq!(
        argv(options.clone(), Some(OsStr::new("env-ssh")))[0],
        "env-ssh"
    );
    let options = SshOptions {
        command: Some(strings(&["my ssh"])),
        ..options
    };
    assert_eq!(argv(options, Some(OsStr::new("env-ssh")))[0], "my ssh");
    let empty = Endpoint::Ssh {
        address,
        options: SshOptions {
            remote_command: Some(" ".into()),
            ..Default::default()
        },
    };
    assert!(matches!(prepared(empty), Err(Error::InvalidInput(_))));
}

/// The options of an HTTP endpoint must name exactly one mirror, which
/// `ostrya_fetch::check_base_url` accepts. A refusal holds no userinfo.
#[test]
fn an_http_endpoint_needs_exactly_one_mirror() {
    for mirrors in [&[][..], &["https://a/", "https://b/"]] {
        match prepared(http_endpoint(mirrors)) {
            Err(Error::InvalidInput(msg)) => {
                assert!(msg.contains("exactly one mirror"), "{msg}");
                assert!(msg.ends_with(&format!("name {}", mirrors.len())), "{msg}");
            }
            Err(other) => panic!("{mirrors:?}: {other:?}"),
            Ok(_) => panic!("{mirrors:?}: accepted"),
        }
    }
    for mirror in [
        "https://user:pw-QXZ@h/r",
        "https://h/r#x",
        "https://h/r?q=1",
    ] {
        match prepared(http_endpoint(&[mirror])) {
            Err(Error::InvalidInput(msg)) => {
                assert!(msg.starts_with("address: "), "{msg}");
                assert!(!msg.contains("QXZ"), "{msg}");
            }
            Err(other) => panic!("{mirror}: {other:?}"),
            Ok(_) => panic!("{mirror}: accepted"),
        }
    }
}

/// The options of an HTTP endpoint carry the credential, the cleartext
/// permission, and each trust setting. The trust settings include the two
/// settings that verify no certificate chain.
#[test]
fn an_http_endpoint_takes_its_credential_and_its_trust_setting() {
    use ostrya_fetch::{BasicAuth, BearerToken, TrustRoots};

    let mut bearer = ostrya_fetch::FetcherOptions::new("http://h/");
    bearer.bearer_token = Some(BearerToken { token: "t".into() });
    bearer.allow_cleartext_credentials = true;
    let mut basic = ostrya_fetch::FetcherOptions::new("http://h/");
    basic.basic_auth = Some(BasicAuth {
        user: "u".into(),
        password: "p".into(),
    });
    basic.allow_cleartext_credentials = true;
    let mut any_chain = ostrya_fetch::FetcherOptions::new("https://h/");
    any_chain.tls.roots = TrustRoots::DangerousAcceptAnyChain;
    let mut any = ostrya_fetch::FetcherOptions::new("https://h/");
    any.tls.roots = TrustRoots::DangerousAcceptAny;
    for http in [bearer, basic, any_chain, any] {
        let shown = format!("{http:?}");
        assert!(
            matches!(prepared(Endpoint::Http(http)), Ok(Prepared::Http(_))),
            "{shown}"
        );
    }
    // The fetcher refuses a credential to an `http://` address without the
    // cleartext permission.
    let mut cleartext = ostrya_fetch::FetcherOptions::new("http://h/");
    cleartext.bearer_token = Some(BearerToken { token: "t".into() });
    assert!(matches!(
        prepared(Endpoint::Http(cleartext)),
        Err(Error::Fetch(_))
    ));
}

/// The `Debug` output of a prepared session names the transport and the
/// HTTP address, and holds no credential and no part of the ssh command
/// line.
#[test]
fn a_prepared_session_shows_no_credential() {
    let mut http = ostrya_fetch::FetcherOptions::new("http://h:8080/");
    http.basic_auth = Some(ostrya_fetch::BasicAuth {
        user: "user-QXZ".into(),
        password: "tok-QXZ".into(),
    });
    http.allow_cleartext_credentials = true;
    let prepared = ostrya_rt::block_on(PushSession::prepare(Endpoint::Http(http)));
    let shown = format!("{:?}", prepared.unwrap());
    assert_eq!(
        shown,
        r#"PreparedSession { transport: "http", url: "http://h:8080/", .. }"#
    );

    let endpoint = Endpoint::Ssh {
        address: SshAddress::parse("ssh://user-QXZ@h/srv/repo").unwrap(),
        options: SshOptions {
            command: Some(strings(&["ssh", "-i", "key-QXZ"])),
            ..Default::default()
        },
    };
    let prepared = ostrya_rt::block_on(PushSession::prepare(endpoint));
    let shown = format!("{:?}", prepared.unwrap());
    assert_eq!(shown, r#"PreparedSession { transport: "ssh", .. }"#);
}

/// The `Debug` output of an HTTP endpoint shows the header name and no
/// header value.
#[test]
fn the_debug_of_an_http_endpoint_shows_no_header_value() {
    let mut http = ostrya_fetch::FetcherOptions::new("https://h/");
    http.headers = vec![("Authorization".into(), "Bearer tok-QXZ".into())];
    let shown = format!("{:?}", Endpoint::Http(http));
    assert!(!shown.contains("QXZ"), "{shown}");
    assert!(
        shown.contains(r#"("Authorization", "<redacted>")"#),
        "{shown}"
    );
}

/// The `Debug` output of an HTTP endpoint shows the host and the path of a
/// mirror URL, and no userinfo or query.
#[test]
fn the_debug_of_an_http_endpoint_shows_no_mirror_secret() {
    let http = ostrya_fetch::FetcherOptions::new("https://user-QXZ:pw-QXZ@h/repo?t=QXZ");
    let shown = format!("{:?}", Endpoint::Http(http));
    assert!(!shown.contains("QXZ"), "{shown}");
    assert!(shown.contains(r#""https://h/repo?<redacted>""#), "{shown}");
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

/// The ssh program of the options comes from `command`, then from the
/// environment variable, then from `config_command`, then it is `ssh`. The
/// remote command does not change it.
#[test]
fn the_ssh_program_of_the_options_is_command_then_env_then_config_command() {
    let command = strings(&["my ssh", "-F", "cfg"]);
    let env = OsStr::new("env-ssh  -v\t-4");
    for remote_command in [None, Some("/opt/ostrya receive".to_owned())] {
        let all = SshOptions {
            command: Some(command.clone()),
            config_command: Some("key-ssh -q".into()),
            remote_command: remote_command.clone(),
        };
        assert_eq!(all.program(Some(env)).unwrap(), command);
        let no_command = SshOptions {
            command: None,
            ..all.clone()
        };
        assert_eq!(
            no_command.program(Some(env)).unwrap(),
            strings(&["env-ssh", "-v", "-4"])
        );
        assert_eq!(
            no_command.program(None).unwrap(),
            strings(&["key-ssh", "-q"])
        );
        let none = SshOptions {
            remote_command,
            ..SshOptions::default()
        };
        assert_eq!(none.program(None).unwrap(), strings(&["ssh"]));
    }
    let empty = SshOptions {
        command: Some(Vec::new()),
        ..SshOptions::default()
    };
    assert!(matches!(empty.program(None), Err(Error::InvalidInput(_))));
    assert!(matches!(
        SshOptions::default().program(Some(OsStr::new(" \t "))),
        Err(Error::InvalidInput(_))
    ));
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

/// The command line of a pull runs the send command. The options can name
/// the send command.
#[test]
fn a_pull_runs_the_send_command_over_ssh() {
    let address = SshAddress::parse("ssh://me@host:2222/srv/repo").unwrap();
    let argv = pull_command_line(&address, &SshOptions::default(), None).unwrap();
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
    let options = SshOptions {
        command: Some(strings(&["my-ssh", "-F", "cfg"])),
        remote_command: Some("/opt/ostrya send".into()),
        config_command: Some("key-ssh".into()),
    };
    let argv = pull_command_line(&address, &options, Some(OsStr::new("env-ssh"))).unwrap();
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
    let options = SshOptions {
        config_command: Some("key-ssh -q".into()),
        ..Default::default()
    };
    assert_eq!(
        pull_command_line(&address, &options, Some(OsStr::new("env-ssh")))
            .unwrap()
            .first()
            .unwrap(),
        "env-ssh"
    );
    assert_eq!(
        pull_command_line(&address, &options, None).unwrap()[..2],
        strings(&["key-ssh", "-q"])
    );

    assert!(matches!(
        send_command(Some(" ")),
        Err(Error::InvalidInput(_))
    ));
    assert_eq!(send_command(None).unwrap(), "ostrya send");
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
/// ssh arguments and acts as one server.
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
    /// stand-in exits, so the limit costs no time. The stand-in exits 0.1 s
    /// after the end of its input. A limit of 5 s, 50 times that delay, keeps
    /// a loaded host from ending the wait before the stand-in exits.
    const EXIT_LIMIT: Duration = Duration::from_secs(5);
    const AGENT: &str = "transport-test";

    struct Dir(PathBuf);

    impl Dir {
        fn new() -> Dir {
            static N: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "ostrya-remote-transport-{}-{}",
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
            collection: None,
            one_way: false,
        })])
        .len()
    }

    fn hello_reply() -> Vec<u8> {
        encode(&[Message::HelloReply(HelloReply {
            version: PROTOCOL_VERSION,
            mode: "archive".into(),
            collection_id: None,
            collection: None,
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
            server_commit: None,
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

    fn endpoint(address: &str, command: Vec<String>) -> Endpoint {
        Endpoint::Ssh {
            address: SshAddress::parse(address).unwrap(),
            options: SshOptions {
                command: Some(command),
                ..Default::default()
            },
        }
    }

    /// Opens a session over the stand-in `script`. The streams of the child
    /// belong to the runtime that opens them, so each test opens and drives
    /// its session in one `block_on`.
    async fn open(script: &str) -> Result<PushSession> {
        open_with_limit(script, LIMIT).await
    }

    /// Opens a session as [`open`] does, with `limit` as the time limit of the
    /// session.
    async fn open_with_limit(script: &str, limit: Duration) -> Result<PushSession> {
        connect_with(
            endpoint(
                "ssh://me@host:2222/srv/it's repo",
                strings(&["sh", "-c", script, "stand-in"]),
            ),
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
        let r = ostrya_rt::block_on(connect_with(
            endpoint("host:repo", strings(&["ostrya-no-such-ssh"])),
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
        // The call spends one limit on the pending read and one limit on the
        // wait for the exit. The silent server outlasts the wait for the exit.
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
        // The stand-in reads to end of file, so it exits only after the
        // session closes its standard input.
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
        // The stand-in reads to end of file, so it exits only after the
        // session closes its standard input.
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
        // `Abort` fails. Then the stand-in exits with a failure status.
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
        // end of file and leaves the session broken. Then the stand-in reads
        // its input to end of file and exits 0.1 s later.
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
        // The stand-in read only the `Have` of `missing`, and no `Abort`.
        let have = encode(&[Message::Have(names(1))]);
        assert_eq!(std::fs::read(&seen).unwrap(), have);
    }

    /// A source for which each open fails.
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

    /// A server that replies with `HelloReply` from `reply` and copies its
    /// input to `seen` until end of file. 0.1 s later, the server creates
    /// `exited`, and then it exits with a failure status.
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
        // The stand-in read only the `Abort` of the failed `send`, and no
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

    /// The stream sessions over a stand-in ssh client.
    mod pull {
        use super::super::super::connect_pull_with;
        use super::*;
        use crate::StreamSessionOptions;
        use crate::proto::{GetReply, PULL_PROTOCOL_VERSION, PullHello, PullHelloReply};

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

        async fn open_pull(script: &str, limit: Duration) -> Result<crate::StreamSession> {
            let address = SshAddress::parse("ssh://me@host:2222/srv/it's repo").unwrap();
            connect_pull_with(
                &address,
                &SshOptions {
                    command: Some(strings(&["sh", "-c", script, "stand-in"])),
                    ..Default::default()
                },
                None,
                StreamSessionOptions {
                    agent: Some(PULL_AGENT.into()),
                    ..Default::default()
                },
                limit,
            )
            .await
        }

        /// A stand-in that runs the send command gets the command line of a
        /// pull. If the ssh client exits with a failure status after a clean
        /// end, the session does not fail.
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

        /// At an unclean end, the session closes the input of the stand-in and
        /// drops its output before it waits. Then a stand-in that is blocked
        /// in the write of a body on a full pipe fails the write and exits.
        /// The wait ends at the exit of the stand-in, before the time limit.
        /// This holds for a body that the caller dropped and for a body that
        /// the caller still holds. A later read of a held body repeats the
        /// error.
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
                // The stand-in writes chunks of the body until a write fails.
                // A write fails when the client drops its side of the output.
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

        /// If a session fails with an I/O error and the stand-in exits with a
        /// failure status, the session ends with `Error::Transport`. The error
        /// names the program and the status.
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
