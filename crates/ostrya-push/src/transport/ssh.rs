//! The ssh transport: the address parser, the command line, and the child
//! process of the ssh client.

use std::ffi::OsStr;
use std::fmt;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::session::stream::{Input, Output};

/// The default receive command.
const DEFAULT_RECEIVE_COMMAND: &str = "ostrya receive";

/// The default send command.
const DEFAULT_SEND_COMMAND: &str = "ostrya send";

fn invalid(msg: impl Into<String>) -> Error {
    Error::InvalidInput(msg.into())
}

/// A parsed ssh address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SshAddr {
    user: Option<String>,
    /// The host, without the brackets of an IPv6 address.
    host: String,
    port: Option<u16>,
    /// The path that the remote command gets. It is absolute, or relative to
    /// the remote home directory.
    path: String,
}

impl SshAddr {
    /// Parses an `ssh://` address or a scp-form address.
    ///
    /// If `windows` is `true`, the call refuses a scp-form address that names
    /// a local path: a one-letter host, or a `\` before the first `:`. A
    /// refusal is [`Error::InvalidInput`] with the address and the reason.
    pub(super) fn parse(address: &str, windows: bool) -> Result<SshAddr> {
        let bad = |why: &str| invalid(format!("address '{address}': {why}"));
        if let Some(rest) = address.strip_prefix("ssh://") {
            let (authority, path) = match rest.find('/') {
                Some(i) => rest.split_at(i),
                None => return Err(bad("an ssh:// address needs a path")),
            };
            let (user, hostport) = split_user(authority).map_err(&bad)?;
            let (host, port) = split_port(hostport).map_err(&bad)?;
            let path = match path.strip_prefix("/~") {
                Some(home) => home_relative(home).map_err(&bad)?,
                None => path,
            };
            return SshAddr::checked(user, host, port, path).map_err(&bad);
        }
        if address.contains("://") {
            return Err(bad("the scheme is not ssh, http, or https"));
        }
        let colon = separator(address).ok_or_else(|| bad("not an address"))?;
        let (prefix, path) = (&address[..colon], &address[colon + 1..]);
        if windows && address[..address.find(':').unwrap_or(colon)].contains('\\') {
            return Err(bad(
                "a '\\' before the first ':' names a local path on Windows",
            ));
        }
        if prefix.contains('/') {
            return Err(bad("not an address"));
        }
        let (user, host) = split_user(prefix).map_err(&bad)?;
        let host = unbracket(host).map_err(&bad)?;
        if windows
            && !host.bracketed
            && host.name.len() == 1
            && host.name.as_bytes()[0].is_ascii_alphabetic()
        {
            return Err(bad("a one-letter host is a local path on Windows"));
        }
        let path = match path.strip_prefix('~') {
            Some(home) => home_relative(home).map_err(&bad)?,
            None => path,
        };
        SshAddr::checked(user, host, None, path).map_err(&bad)
    }

    fn checked(
        user: Option<&str>,
        host: Host<'_>,
        port: Option<u16>,
        path: &str,
    ) -> std::result::Result<SshAddr, &'static str> {
        if let Some(user) = user {
            if user.is_empty() {
                return Err("the user is empty");
            }
            if user.starts_with('-') {
                return Err("the user starts with '-'");
            }
            if user.contains(':') {
                return Err("the user holds ':'");
            }
            if !user.bytes().all(name_byte) {
                return Err("the user holds a character outside A-Z, a-z, 0-9, '.', '-', and '_'");
            }
        }
        if host.name.is_empty() {
            return Err("the host is empty");
        }
        if host.name.starts_with('-') {
            return Err("the host starts with '-'");
        }
        if host.bracketed {
            if !ipv6_literal(host.name) {
                return Err("the bracketed host holds a character outside an IPv6 address");
            }
        } else if !host.name.bytes().all(name_byte) {
            return Err("the host holds a character outside A-Z, a-z, 0-9, '.', '-', and '_'");
        }
        if path.is_empty() {
            return Err("the path is empty");
        }
        Ok(SshAddr {
            user: user.map(str::to_owned),
            host: host.name.to_owned(),
            port,
            path: path.to_owned(),
        })
    }

    /// Returns the command line that runs `command` on the remote side.
    ///
    /// `command` is the receive command or the send command. The line is
    /// `program`, then `-p PORT` if the address has a port, then
    /// `[USER@]HOST`. The last argument is one string: `command`, then
    /// `--repo=` and the quoted path.
    pub(super) fn command_line(&self, program: Vec<String>, command: &str) -> Vec<String> {
        let mut argv = program;
        if let Some(port) = self.port {
            argv.push("-p".to_owned());
            argv.push(port.to_string());
        }
        argv.push(match &self.user {
            Some(user) => format!("{user}@{}", self.host),
            None => self.host.clone(),
        });
        argv.push(format!("{command} --repo={}", quote_posix(&self.path)));
        argv
    }
}

impl fmt::Display for SshAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ssh://")?;
        if let Some(user) = &self.user {
            write!(f, "{user}@")?;
        }
        if self.host.contains(':') {
            write!(f, "[{}]", self.host)?;
        } else {
            f.write_str(&self.host)?;
        }
        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }
        if self.path.starts_with('/') {
            f.write_str(&self.path)
        } else {
            write!(f, "/~/{}", self.path)
        }
    }
}

/// Splits `USER@REST` at its one `@`. More than one `@` is refused.
fn split_user(s: &str) -> std::result::Result<(Option<&str>, &str), &'static str> {
    match s.split_once('@') {
        None => Ok((None, s)),
        Some((_, rest)) if rest.contains('@') => Err("the address holds more than one '@'"),
        Some((user, rest)) => Ok((Some(user), rest)),
    }
}

/// A host of an address, without the brackets of an IPv6 address.
#[derive(Clone, Copy)]
struct Host<'a> {
    name: &'a str,
    /// `true` if the address gives the host in brackets.
    bracketed: bool,
}

/// Removes the brackets of an IPv6 host. A bracket in any other position is
/// refused.
fn unbracket(host: &str) -> std::result::Result<Host<'_>, &'static str> {
    if let Some(inner) = host.strip_prefix('[') {
        return match inner.strip_suffix(']') {
            Some(inner) if !inner.contains(['[', ']']) => Ok(Host {
                name: inner,
                bracketed: true,
            }),
            _ => Err("the host has an unclosed or a stray bracket"),
        };
    }
    if host.contains(['[', ']']) {
        return Err("the host has a stray bracket");
    }
    Ok(Host {
        name: host,
        bracketed: false,
    })
}

/// Returns `true` if `b` is a byte that a user name or a host name can hold.
fn name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')
}

/// Returns `true` if `s` holds only the characters of an IPv6 address: hex
/// digits, `:`, and `.`. An optional `%ZONE` of one or more ASCII letters and
/// digits can follow.
fn ipv6_literal(s: &str) -> bool {
    let (addr, zone) = match s.split_once('%') {
        Some((addr, zone)) => (addr, Some(zone)),
        None => (s, None),
    };
    addr.bytes()
        .all(|b| b.is_ascii_hexdigit() || matches!(b, b':' | b'.'))
        && zone.is_none_or(|z| !z.is_empty() && z.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// Returns the path after a `~` home prefix.
///
/// `/RELATIVE` gives `RELATIVE`. The call removes each leading `/`, so the
/// path stays relative to the home directory. A `home` that does not start
/// with `/` is a path of the form `~` or `~USER`, which is refused.
fn home_relative(home: &str) -> std::result::Result<&str, &'static str> {
    match home.strip_prefix('/') {
        Some(relative) => Ok(relative.trim_start_matches('/')),
        None => Err("a path of the form ~ or ~USER is not supported"),
    }
}

/// Splits `HOST[:PORT]` of an `ssh://` address. The port must be a number
/// from 1 to 65535.
fn split_port(s: &str) -> std::result::Result<(Host<'_>, Option<u16>), &'static str> {
    let (host, port) = if s.starts_with('[') {
        match s.find(']') {
            Some(end) => {
                let (host, rest) = s.split_at(end + 1);
                match rest {
                    "" => (host, None),
                    _ => match rest.strip_prefix(':') {
                        Some(port) => (host, Some(port)),
                        None => return Err("text after the bracketed host"),
                    },
                }
            }
            None => return Err("the host has an unclosed bracket"),
        }
    } else {
        match s.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (s, None),
        }
    };
    let host = unbracket(host)?;
    let port = match port {
        None => None,
        Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => match p.parse() {
            Ok(0) | Err(_) => return Err("the port is not in 1 to 65535"),
            Ok(n) => Some(n),
        },
        Some(_) => return Err("the port is not a number"),
    };
    Ok((host, port))
}

/// Returns the index of the `:` that ends the host of a scp-form address.
/// That is the first `:` outside brackets.
fn separator(s: &str) -> Option<usize> {
    let mut in_brackets = false;
    for (i, c) in s.char_indices() {
        match c {
            '[' => in_brackets = true,
            ']' => in_brackets = false,
            ':' if !in_brackets => return Some(i),
            _ => {}
        }
    }
    None
}

/// Quotes `s` for a POSIX shell. The result puts single quotes around `s`
/// and writes each `'` as `'\''`.
pub(super) fn quote_posix(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Splits the command line `value` at ASCII whitespace. If the result is
/// empty, the call returns [`Error::InvalidInput`], which names `source`.
fn split_command(source: &str, value: &str) -> Result<Vec<String>> {
    let argv: Vec<String> = value.split_ascii_whitespace().map(str::to_owned).collect();
    if argv.is_empty() {
        return Err(invalid(format!("{source} is empty")));
    }
    Ok(argv)
}

/// Returns the ssh command line from the first source that is set.
///
/// The sources are `explicit`, the `OSTRYA_SSH_COMMAND` value `env`, and the
/// remote key `key`, in this order. If none is set, the command line is
/// `ssh`.
pub(super) fn ssh_program(
    explicit: Option<&[String]>,
    env: Option<&OsStr>,
    key: Option<&str>,
) -> Result<Vec<String>> {
    if let Some(argv) = explicit {
        if argv.first().is_none_or(|p| p.trim().is_empty()) {
            return Err(invalid("the ssh command of the options is empty"));
        }
        return Ok(argv.to_vec());
    }
    if let Some(env) = env {
        let value = env
            .to_str()
            .ok_or_else(|| invalid("OSTRYA_SSH_COMMAND is not UTF-8"))?;
        return split_command("OSTRYA_SSH_COMMAND", value);
    }
    if let Some(key) = key {
        return split_command("the ssh command of the remote", key);
    }
    Ok(vec!["ssh".to_owned()])
}

/// Returns the receive command: `explicit`, or `ostrya receive` if
/// `explicit` is `None`.
///
/// A command that is empty or holds only whitespace is refused.
pub(super) fn receive_command(explicit: Option<&str>) -> Result<&str> {
    match explicit {
        Some(cmd) if cmd.trim().is_empty() => Err(invalid("the receive command is empty")),
        Some(cmd) => Ok(cmd),
        None => Ok(DEFAULT_RECEIVE_COMMAND),
    }
}

/// Returns the send command: `explicit`, or `ostrya send` if `explicit` is
/// `None`.
///
/// A command that is empty or holds only whitespace is refused.
pub(super) fn send_command(explicit: Option<&str>) -> Result<&str> {
    match explicit {
        Some(cmd) if cmd.trim().is_empty() => Err(invalid("the send command is empty")),
        Some(cmd) => Ok(cmd),
        None => Ok(DEFAULT_SEND_COMMAND),
    }
}

/// The ssh client of a session.
pub(crate) struct Transport {
    child: ostrya_rt::Child,
    program: String,
    /// The longest wait for the child to exit.
    limit: Duration,
}

impl Transport {
    /// Starts `argv` with piped standard input and standard output.
    ///
    /// The call returns the input from the child, the output to the child,
    /// and the transport. A program that cannot start is [`Error::Transport`],
    /// which names the program.
    pub(super) fn spawn(argv: &[String], limit: Duration) -> Result<(Input, Output, Transport)> {
        let (program, args) = argv.split_first().expect("the command line has a program");
        let mut command = ostrya_rt::Command::new(program);
        for arg in args {
            command.arg(arg);
        }
        let mut child = command
            .spawn()
            .map_err(|e| Error::Transport(format!("cannot run '{program}': {e}")))?;
        let stdin = child.take_stdin().expect("standard input is piped");
        let stdout = child.take_stdout().expect("standard output is piped");
        Ok((
            Box::new(stdout),
            Box::new(stdin),
            Transport {
                child,
                program: program.clone(),
                limit,
            },
        ))
    }

    /// Waits for the child to exit, for at most the limit, and returns the
    /// result of the session.
    ///
    /// The caller must close or drop the streams of the session first, so
    /// that the child reads end of file. If the child exits with a failure
    /// status within the limit, the call changes two results:
    ///
    /// - An [`Error::Io`] becomes an [`Error::Transport`] with the status.
    /// - The message of an [`Error::CommitOutcomeUnknown`] gets the status.
    ///
    /// The call returns each other result unchanged. It also returns `result`
    /// unchanged if the child exits with success, if the wait fails, or if
    /// the limit ends first.
    pub(crate) async fn finish<T>(mut self, result: Result<T>) -> Result<T> {
        let wait = async { self.child.wait().await.ok() };
        let timeout = async {
            ostrya_rt::Timer::after(self.limit).await;
            None
        };
        let status = futures_lite::future::or(wait, timeout).await;
        let Some(status) = status.filter(|s| !s.success()) else {
            return result;
        };
        let program = &self.program;
        match result {
            Err(Error::Io(e)) => Err(Error::Transport(format!(
                "'{program}' exited with {status}: {e}"
            ))),
            Err(Error::CommitOutcomeUnknown { refs, message }) => {
                Err(Error::CommitOutcomeUnknown {
                    refs,
                    message: format!("{message}; '{program}' exited with {status}"),
                })
            }
            other => other,
        }
    }
}
