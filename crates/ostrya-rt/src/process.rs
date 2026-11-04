//! Helper processes with piped standard streams.
//!
//! [`Command`] starts a program through the async process API of the
//! backend: `smol::process` with the `smol` feature, and `tokio::process`
//! with the `tokio` feature.
//!
//! [`Command::output`] holds the input and both outputs of a run in memory,
//! and it applies no limit to an output. The GPG signing engine runs
//! `gpg --detach-sign` and `gpg --list-secret-keys` through it, with metadata
//! as the input.
//!
//! [`Command::output_capped`] keeps at most a given number of bytes of
//! standard output and at most 64 KiB of standard error. So these caps set a
//! limit on the memory that the run holds. A buffer grows in steps, and each
//! step can double its size. So each buffer can grow to approximately two
//! times its cap. The GPG signing engine runs `gpg --export` through it.

use std::ffi::OsString;
use std::io;
use std::pin::Pin;
use std::process::Output;
use std::task::{Context, Poll};

#[cfg(all(feature = "smol", not(feature = "tokio")))]
use smol::process as backend;
#[cfg(feature = "tokio")]
use tokio::process as backend;

/// The number of bytes of standard error that [`Command::output_capped`]
/// keeps.
const STDERR_CAP: u64 = 64 * 1024;

/// A program and its arguments to run as a child process.
///
/// The command runs in one of two forms: a one-shot run with
/// [`output`](Command::output) or [`output_capped`](Command::output_capped),
/// or a long-lived [`Child`] with [`spawn`](Command::spawn).
pub struct Command {
    program: OsString,
    args: Vec<OsString>,
}

/// The builder and the one-shot run.
impl Command {
    /// Creates a command that runs `program` with no arguments.
    ///
    /// [`output`](Command::output), [`output_capped`](Command::output_capped),
    /// and [`spawn`](Command::spawn) give `program` unchanged to the process
    /// API of the backend, which finds the program file.
    pub fn new(program: impl Into<OsString>) -> Command {
        Command {
            program: program.into(),
            args: Vec::new(),
        }
    }

    /// Adds one argument.
    pub fn arg(&mut self, arg: impl Into<OsString>) -> &mut Command {
        self.args.push(arg.into());
        self
    }

    /// Runs the command with `input` on standard input and collects its output.
    ///
    /// The returned [`Output`] holds the exit status, the standard output, and
    /// the standard error of the child. The run holds `input` and both outputs
    /// in memory, so it fits small payloads. For a stream of any size,
    /// [`spawn`](Command::spawn) gives async pipes.
    ///
    /// The run writes `input` while it reads both outputs, so a child that
    /// reads and writes in turn cannot block on a full pipe. After the run
    /// writes `input`, it closes standard input.
    ///
    /// A failure to write standard input is not an error of the run. For
    /// example, the child can exit before it reads all of `input`. The exit
    /// status and the standard error then tell what the child did.
    ///
    /// # Errors
    ///
    /// - An I/O error if the program does not start, for example if the
    ///   program does not exist.
    /// - An I/O error from the wait for the child, or from a read of standard
    ///   output or standard error.
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

    /// Runs the command with `input` on standard input and collects its output.
    ///
    /// The returned [`Output`] holds the exit status, the standard output, and
    /// the standard error of the child. The run holds `input` and both outputs
    /// in memory, so it fits small payloads. For a stream of any size,
    /// [`spawn`](Command::spawn) gives async pipes.
    ///
    /// The run writes `input` while it reads both outputs, so a child that
    /// reads and writes in turn cannot block on a full pipe. After the run
    /// writes `input`, it closes standard input.
    ///
    /// A failure to write standard input is not an error of the run. For
    /// example, the child can exit before it reads all of `input`. The exit
    /// status and the standard error then tell what the child did.
    ///
    /// # Errors
    ///
    /// - An I/O error if the program does not start, for example if the
    ///   program does not exist.
    /// - An I/O error from the wait for the child, or from a read of standard
    ///   output or standard error.
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

    /// Runs the command with `input` on standard input and collects its output,
    /// with a limit on each output.
    ///
    /// The run reads at most `stdout_cap` bytes of standard output. When it
    /// has read `stdout_cap` bytes, it closes the pipe and reads no more. A
    /// child that then writes to standard output gets a broken pipe. The run
    /// then waits for the child to exit. A child that does not exit makes the
    /// run wait.
    ///
    /// To find an output that is longer than a limit, give the limit plus one
    /// as `stdout_cap`. A standard output of the cap length is then longer
    /// than the limit.
    ///
    /// The run keeps the first 64 KiB of standard error. It reads the remaining
    /// bytes of standard error to the end and discards them. So a child that
    /// writes much text to standard error does not block on a full pipe.
    ///
    /// The returned [`Output`] holds the exit status, the bytes of standard
    /// output that the run read, and the bytes of standard error that it kept.
    /// The run writes `input` as [`output`](Command::output) does.
    ///
    /// # Errors
    ///
    /// - An I/O error if the program does not start, for example if the
    ///   program does not exist.
    /// - An I/O error from the wait for the child, or from a read of standard
    ///   output or standard error.
    #[cfg(feature = "tokio")]
    pub async fn output_capped(&self, input: &[u8], stdout_cap: u64) -> io::Result<Output> {
        use std::process::Stdio;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut child = tokio::process::Command::new(&self.program)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut stdin = child.stdin.take().expect("stdin is piped");
        let stdout = child.stdout.take().expect("stdout is piped");
        let mut stderr = child.stderr.take().expect("stderr is piped");
        let input = input.to_vec();
        let writer = tokio::spawn(async move {
            let _ = stdin.write_all(&input).await;
            let _ = stdin.shutdown().await;
        });
        let err_reader = tokio::spawn(async move {
            let mut kept = Vec::new();
            (&mut stderr)
                .take(STDERR_CAP)
                .read_to_end(&mut kept)
                .await?;
            tokio::io::copy(&mut stderr, &mut tokio::io::sink()).await?;
            Ok::<_, io::Error>(kept)
        });
        // The read takes the pipe and drops it at its end, so the child gets a
        // broken pipe if it writes more.
        let mut out = Vec::new();
        let out_read = stdout.take(stdout_cap).read_to_end(&mut out).await;
        let err_read = err_reader.await.map_err(io::Error::other);
        let status = child.wait().await?;
        let _ = writer.await;
        out_read?;
        Ok(Output {
            status,
            stdout: out,
            stderr: err_read??,
        })
    }

    /// Runs the command with `input` on standard input and collects its output,
    /// with a limit on each output.
    ///
    /// The run reads at most `stdout_cap` bytes of standard output. When it
    /// has read `stdout_cap` bytes, it closes the pipe and reads no more. A
    /// child that then writes to standard output gets a broken pipe. The run
    /// then waits for the child to exit. A child that does not exit makes the
    /// run wait.
    ///
    /// To find an output that is longer than a limit, give the limit plus one
    /// as `stdout_cap`. A standard output of the cap length is then longer
    /// than the limit.
    ///
    /// The run keeps the first 64 KiB of standard error. It reads the remaining
    /// bytes of standard error to the end and discards them. So a child that
    /// writes much text to standard error does not block on a full pipe.
    ///
    /// The returned [`Output`] holds the exit status, the bytes of standard
    /// output that the run read, and the bytes of standard error that it kept.
    /// The run writes `input` as [`output`](Command::output) does.
    ///
    /// # Errors
    ///
    /// - An I/O error if the program does not start, for example if the
    ///   program does not exist.
    /// - An I/O error from the wait for the child, or from a read of standard
    ///   output or standard error.
    #[cfg(all(feature = "smol", not(feature = "tokio")))]
    pub async fn output_capped(&self, input: &[u8], stdout_cap: u64) -> io::Result<Output> {
        use smol::io::{AsyncReadExt, AsyncWriteExt};
        use std::process::Stdio;

        let mut child = smol::process::Command::new(&self.program)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut stdin = child.stdin.take().expect("stdin is piped");
        let stdout = child.stdout.take().expect("stdout is piped");
        let mut stderr = child.stderr.take().expect("stderr is piped");
        let write = async move {
            let _ = stdin.write_all(input).await;
            let _ = stdin.close().await;
        };
        // The read takes the pipe and drops it at its end, so the child gets a
        // broken pipe if it writes more.
        let read_out = async move {
            let mut buf = Vec::new();
            stdout
                .take(stdout_cap)
                .read_to_end(&mut buf)
                .await
                .map(|_| buf)
        };
        let read_err = async move {
            let mut kept = Vec::new();
            (&mut stderr)
                .take(STDERR_CAP)
                .read_to_end(&mut kept)
                .await?;
            smol::io::copy(&mut stderr, smol::io::sink()).await?;
            Ok::<_, io::Error>(kept)
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

/// The start of a long-lived child process.
impl Command {
    /// Starts the command as a long-lived child process.
    ///
    /// The child gets piped standard input and standard output. It writes to
    /// the standard error of this process. The returned [`Child`] holds both
    /// pipes, and [`Child::take_stdin`] and [`Child::take_stdout`] return them.
    ///
    /// With the `tokio` feature, the call must run inside a tokio runtime
    /// context.
    ///
    /// # Errors
    ///
    /// An I/O error if the program does not start, for example if the program
    /// does not exist.
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
    /// Takes the standard input of the child.
    ///
    /// A second call returns `None`.
    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.stdin.take()
    }

    /// Takes the standard output of the child.
    ///
    /// A second call returns `None`.
    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.stdout.take()
    }

    /// Waits for the child to exit and returns its exit status.
    ///
    /// If the caller did not take the standard input, the wait drops it first.
    /// A child that reads its standard input to the end then gets end of file.
    /// A [`ChildStdin`] that the caller took stays open until the caller
    /// closes or drops it.
    ///
    /// # Errors
    ///
    /// An I/O error from the wait for the child.
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
    /// `None` after `close`. `close` drops the pipe to close the descriptor,
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

// The child types move freely across tasks and threads.
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

    /// Runs `script` with `sh -c` through [`Command::output_capped`], and
    /// fails if the run takes more than ten seconds.
    fn capped(script: &str, stdout_cap: u64) -> Output {
        use std::time::Duration;

        let output = block_on(async {
            let mut cmd = Command::new("sh");
            cmd.arg("-c").arg(script);
            let run = async { Some(cmd.output_capped(b"", stdout_cap).await.unwrap()) };
            let timeout = async {
                crate::Timer::after(Duration::from_secs(10)).await;
                None
            };
            futures_lite::future::or(run, timeout).await
        });
        output.expect("the capped run did not finish")
    }

    #[test]
    fn capped_output_under_the_caps_is_whole() {
        use std::time::Duration;

        let output = block_on(async {
            let mut cmd = Command::new("sh");
            cmd.arg("-c").arg("cat; echo two >&2");
            let run = async { Some(cmd.output_capped(b"one", 4).await.unwrap()) };
            let timeout = async {
                crate::Timer::after(Duration::from_secs(10)).await;
                None
            };
            futures_lite::future::or(run, timeout).await
        });
        let output = output.expect("the capped run did not finish");
        assert!(output.status.success());
        assert_eq!(output.stdout, b"one");
        assert_eq!(output.stderr, b"two\n");
    }

    #[test]
    fn capped_output_stops_at_the_stdout_cap() {
        let output = capped("head -c 1048576 /dev/zero", 1000);
        assert_eq!(output.stdout, vec![0; 1000]);
    }

    #[test]
    fn capped_output_closes_stdout_for_a_child_that_writes_without_end() {
        let output = capped("yes", 4096);
        assert_eq!(output.stdout.len(), 4096);
        assert!(!output.status.success());
    }

    #[test]
    fn capped_output_keeps_the_start_of_stderr_and_drains_the_rest() {
        let output = capped("head -c 1048576 /dev/zero >&2; echo done", 100);
        assert!(output.status.success());
        assert_eq!(output.stdout, b"done\n");
        assert_eq!(output.stderr.len() as u64, STDERR_CAP);
    }

    #[test]
    fn capped_output_reports_the_exit_status() {
        let output = capped("echo text; exit 3", 100);
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(output.stdout, b"text\n");
    }

    #[test]
    fn missing_program_is_a_spawn_error_of_the_capped_run() {
        let result = block_on(async {
            Command::new("ostrya-no-such-program")
                .output_capped(b"", 1)
                .await
        });
        assert!(result.is_err());
    }

    #[test]
    fn missing_program_is_a_spawn_error() {
        let result = block_on(async { Command::new("ostrya-no-such-program").output(b"").await });
        assert!(result.is_err());
    }
}
