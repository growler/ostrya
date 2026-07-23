//! Run a short-lived helper process with piped standard streams.
//!
//! [`Command`] spawns a program through the compiled backend's async process
//! API (`smol::process` under smol, `tokio::process` under tokio), feeds it a
//! byte payload on stdin, and collects the exit status and both output
//! streams. The GPG signing engine drives the `gpg` binary through it. The
//! payloads involved are bounded metadata, so whole-buffer input and output
//! fit the crate's streaming rules.

use std::ffi::OsString;
use std::io;
use std::process::Output;

/// A command to run with piped stdin, stdout, and stderr.
///
/// The builder mirrors the small subset of `std::process::Command` the
/// library needs: a program, its arguments, and one-shot execution over a
/// stdin payload.
pub struct Command {
    program: OsString,
    args: Vec<OsString>,
}

impl Command {
    /// A command running `program`, resolved through `PATH` when relative.
    pub fn new(program: impl Into<OsString>) -> Command {
        Command {
            program: program.into(),
            args: Vec::new(),
        }
    }

    /// Append one argument.
    pub fn arg(&mut self, arg: impl Into<OsString>) -> &mut Command {
        self.args.push(arg.into());
        self
    }

    /// Run the command, write `input` to its stdin, and collect the exit
    /// status and both output streams.
    ///
    /// stdin is closed once `input` is written. A stdin write failure (the
    /// child exiting without reading it all, for example) is not an error of
    /// the run; the exit status and stderr carry the child's side of the
    /// story. The input is written while both output streams drain, so a
    /// child that interleaves reading and writing cannot deadlock on a full
    /// pipe.
    #[cfg(feature = "tokio")]
    pub async fn output(&self, input: &[u8]) -> io::Result<Output> {
        use std::process::Stdio;
        use tokio::io::AsyncWriteExt;

        let mut child = tokio::process::Command::new(&self.program)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut stdin = child.stdin.take().expect("stdin is piped");
        let input = input.to_vec();
        let writer = tokio::spawn(async move {
            let _ = stdin.write_all(&input).await;
            let _ = stdin.shutdown().await;
        });
        let output = child.wait_with_output().await;
        let _ = writer.await;
        output
    }

    /// Run the command, write `input` to its stdin, and collect the exit
    /// status and both output streams.
    ///
    /// stdin is closed once `input` is written. A stdin write failure (the
    /// child exiting without reading it all, for example) is not an error of
    /// the run; the exit status and stderr carry the child's side of the
    /// story. The input is written while both output streams drain, so a
    /// child that interleaves reading and writing cannot deadlock on a full
    /// pipe.
    #[cfg(all(feature = "smol", not(feature = "tokio")))]
    pub async fn output(&self, input: &[u8]) -> io::Result<Output> {
        use smol::io::{AsyncReadExt, AsyncWriteExt};
        use std::process::Stdio;

        let mut child = smol::process::Command::new(&self.program)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut stdin = child.stdin.take().expect("stdin is piped");
        let mut stdout = child.stdout.take().expect("stdout is piped");
        let mut stderr = child.stderr.take().expect("stderr is piped");
        let write = async move {
            let _ = stdin.write_all(input).await;
            let _ = stdin.close().await;
        };
        let read_out = async move {
            let mut buf = Vec::new();
            stdout.read_to_end(&mut buf).await.map(|_| buf)
        };
        let read_err = async move {
            let mut buf = Vec::new();
            stderr.read_to_end(&mut buf).await.map(|_| buf)
        };
        let ((), (out, err)) =
            smol::future::zip(write, smol::future::zip(read_out, read_err)).await;
        let status = child.status().await?;
        Ok(Output {
            status,
            stdout: out?,
            stderr: err?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_on;

    #[test]
    fn output_round_trips_stdin_and_collects_streams() {
        let output = block_on(async {
            let mut cmd = Command::new("sh");
            cmd.arg("-c").arg("cat; echo two >&2");
            cmd.output(b"one").await.unwrap()
        });
        assert!(output.status.success());
        assert_eq!(output.stdout, b"one");
        assert_eq!(output.stderr, b"two\n");
    }

    #[test]
    fn nonzero_exit_is_reported_in_the_status() {
        let output = block_on(async {
            let mut cmd = Command::new("sh");
            cmd.arg("-c").arg("exit 3");
            cmd.output(b"").await.unwrap()
        });
        assert!(!output.status.success());
        assert_eq!(output.status.code(), Some(3));
    }

    #[test]
    fn missing_program_is_a_spawn_error() {
        let result = block_on(async { Command::new("ostrya-no-such-program").output(b"").await });
        assert!(result.is_err());
    }
}
