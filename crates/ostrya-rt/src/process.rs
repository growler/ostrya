//! Run a helper process with piped standard streams.
//!
//! [`Command`] spawns a program through the compiled backend's async process
//! API (`smol::process` under smol, `tokio::process` under tokio). It runs the
//! program in two forms:
//!
//! - [`Command::output`] is a short-lived run. It feeds the program a byte
//!   payload on stdin and collects the exit status and both output streams.
//!   The GPG signing engine drives the `gpg` binary through it. The payloads
//!   involved are bounded metadata, so whole-buffer input and output fit the
//!   crate's streaming rules.
//! - [`Command::spawn`] starts a long-lived [`Child`]. Its standard input and
//!   standard output are async streams, and its standard error is the
//!   standard error of this process.

use std::ffi::OsString;
use std::io;
use std::pin::Pin;
use std::process::Output;
use std::task::{Context, Poll};

#[cfg(all(feature = "smol", not(feature = "tokio")))]
use smol::process as backend;
#[cfg(feature = "tokio")]
use tokio::process as backend;

/// A command to run with piped stdin, stdout, and stderr.
///
/// The builder mirrors the small subset of `std::process::Command` the
/// library needs: a program, its arguments, one-shot execution over a stdin
/// payload ([`output`](Command::output)), and a long-lived child with streamed
/// standard input and output ([`spawn`](Command::spawn)).
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

impl Command {
    /// Start the command with its standard input and standard output piped
    /// and the standard error of this process.
    ///
    /// The returned [`Child`] holds both pipes; take them with
    /// [`Child::take_stdin`] and [`Child::take_stdout`]. Under the tokio
    /// backend this must be called from within a runtime context, as
    /// `tokio::process::Command::spawn` requires.
    pub fn spawn(&self) -> io::Result<Child> {
        use std::process::Stdio;

        let mut child = backend::Command::new(&self.program)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let stdin = child
            .stdin
            .take()
            .map(|inner| ChildStdin { inner: Some(inner) });
        let stdout = child.stdout.take().map(|inner| ChildStdout { inner });
        Ok(Child {
            inner: child,
            stdin,
            stdout,
        })
    }
}

/// A long-lived child process that [`Command::spawn`] started.
pub struct Child {
    inner: backend::Child,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
}

impl Child {
    /// Take the standard input of the child. The second call gives `None`.
    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.stdin.take()
    }

    /// Take the standard output of the child. The second call gives `None`.
    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.stdout.take()
    }

    /// Wait for the child to exit and return its exit status.
    ///
    /// The wait first drops a standard input the caller did not take, so a
    /// child that reads its standard input to the end sees end of file. A
    /// [`ChildStdin`] the caller took stays open: close or drop it first.
    pub async fn wait(&mut self) -> io::Result<std::process::ExitStatus> {
        self.stdin = None;
        #[cfg(feature = "tokio")]
        {
            self.inner.wait().await
        }
        #[cfg(all(feature = "smol", not(feature = "tokio")))]
        {
            self.inner.status().await
        }
    }
}

/// The standard input of a [`Child`], as a `futures-io` `AsyncWrite`.
///
/// `close` flushes the pipe and then closes it, so the child reads end of
/// file. After `close`, a write fails with [`io::ErrorKind::BrokenPipe`],
/// and a flush or a second close succeeds and does nothing.
pub struct ChildStdin {
    /// `None` after `close`: the pipe is dropped to close the descriptor,
    /// because the close of neither backend closes it.
    inner: Option<backend::ChildStdin>,
}

/// The standard output of a [`Child`], as a `futures-io` `AsyncRead`.
pub struct ChildStdout {
    inner: backend::ChildStdout,
}

impl futures_io::AsyncWrite for ChildStdin {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let Some(inner) = self.get_mut().inner.as_mut() else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "standard input is closed",
            )));
        };
        #[cfg(feature = "tokio")]
        {
            tokio::io::AsyncWrite::poll_write(Pin::new(inner), cx, buf)
        }
        #[cfg(all(feature = "smol", not(feature = "tokio")))]
        {
            futures_io::AsyncWrite::poll_write(Pin::new(inner), cx, buf)
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(inner) = self.get_mut().inner.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        #[cfg(feature = "tokio")]
        {
            tokio::io::AsyncWrite::poll_flush(Pin::new(inner), cx)
        }
        #[cfg(all(feature = "smol", not(feature = "tokio")))]
        {
            futures_io::AsyncWrite::poll_flush(Pin::new(inner), cx)
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                self.get_mut().inner = None;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl futures_io::AsyncRead for ChildStdout {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        #[cfg(feature = "tokio")]
        {
            let mut read_buf = tokio::io::ReadBuf::new(buf);
            match tokio::io::AsyncRead::poll_read(
                Pin::new(&mut self.get_mut().inner),
                cx,
                &mut read_buf,
            ) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }
        #[cfg(all(feature = "smol", not(feature = "tokio")))]
        {
            futures_io::AsyncRead::poll_read(Pin::new(&mut self.get_mut().inner), cx, buf)
        }
    }
}

/// The child types move freely across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Child>();
    assert_send_sync::<ChildStdin>();
    assert_send_sync::<ChildStdout>();
};

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
    fn spawned_child_echoes_standard_input() {
        use futures_lite::io::{AsyncReadExt, AsyncWriteExt};

        let (status, out) = block_on(async {
            let mut child = Command::new("cat").spawn().unwrap();
            let mut stdin = child.take_stdin().unwrap();
            let mut stdout = child.take_stdout().unwrap();
            stdin.write_all(b"ping\n").await.unwrap();
            // `close` alone must give `cat` its end of file: `stdin` stays in
            // scope until after the read.
            stdin.close().await.unwrap();
            let mut out = Vec::new();
            stdout.read_to_end(&mut out).await.unwrap();
            assert!(child.take_stdin().is_none());
            assert!(child.take_stdout().is_none());
            let err = stdin.write_all(b"late").await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
            stdin.close().await.unwrap();
            (child.wait().await.unwrap(), out)
        });
        assert!(status.success());
        assert_eq!(out, b"ping\n");
    }

    #[test]
    fn wait_closes_standard_input_the_caller_did_not_take() {
        use std::time::Duration;

        let status = block_on(async {
            let mut child = Command::new("cat").spawn().unwrap();
            let wait = async { Some(child.wait().await.unwrap()) };
            let timeout = async {
                crate::Timer::after(Duration::from_secs(10)).await;
                None
            };
            futures_lite::future::or(wait, timeout).await
        });
        let status = status.expect("wait did not close standard input");
        assert!(status.success());
    }

    #[test]
    fn missing_program_is_a_spawn_error() {
        let result = block_on(async { Command::new("ostrya-no-such-program").output(b"").await });
        assert!(result.is_err());
    }
}
