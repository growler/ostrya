//! Async TCP over the selected backend.
//!
//! [`TcpStream`] and [`TcpListener`] wrap the backend's TCP types
//! (`smol::net` or `tokio::net`) and present the `futures-io` traits under both
//! backends, so the fetcher and the TLS layer stay runtime-neutral. Under the
//! `tokio` feature the stream additionally implements the tokio I/O traits.
//!
//! Name resolution happens inside the backend's `connect`, which runs the
//! lookup off the async path.

use std::io;
use std::io::IoSlice;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

#[cfg(all(feature = "smol", not(feature = "tokio")))]
use smol::net as backend;
#[cfg(feature = "tokio")]
use tokio::net as backend;

/// A connected TCP stream.
///
/// Nagle's algorithm is disabled on connect: request and response bodies are
/// written in bounded chunks, and delaying a short final write stalls the
/// exchange.
#[derive(Debug)]
pub struct TcpStream {
    inner: backend::TcpStream,
}

impl TcpStream {
    /// Resolve `host` and connect to the first address that accepts.
    pub async fn connect(host: &str, port: u16) -> io::Result<TcpStream> {
        let inner = backend::TcpStream::connect((host, port)).await?;
        inner.set_nodelay(true)?;
        Ok(TcpStream { inner })
    }

    /// The local address the socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// The address of the peer.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    /// Whether `poll_write_vectored` writes more than the first slice. The
    /// `futures-io` write trait carries no such query, so a caller deciding
    /// whether to hand over several slices or coalesce them itself asks here.
    /// Both backends write the slices in one syscall.
    pub fn is_write_vectored(&self) -> bool {
        #[cfg(feature = "tokio")]
        {
            tokio::io::AsyncWrite::is_write_vectored(&self.inner)
        }
        #[cfg(all(feature = "smol", not(feature = "tokio")))]
        {
            // async-net answers the vectored write with `write_vectored` on the
            // underlying socket; it offers no query of its own to forward to.
            true
        }
    }
}

/// A listening TCP socket.
#[derive(Debug)]
pub struct TcpListener {
    inner: backend::TcpListener,
}

impl TcpListener {
    /// Bind to `addr`. Passing port 0 lets the kernel choose a free port,
    /// which [`local_addr`](TcpListener::local_addr) then reports.
    pub async fn bind(addr: SocketAddr) -> io::Result<TcpListener> {
        let inner = backend::TcpListener::bind(addr).await?;
        Ok(TcpListener { inner })
    }

    /// The address the socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Accept the next connection.
    pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let (stream, peer) = self.inner.accept().await?;
        stream.set_nodelay(true)?;
        Ok((TcpStream { inner: stream }, peer))
    }
}

// --- smol backend: the async-net stream already speaks futures-io ---

#[cfg(all(feature = "smol", not(feature = "tokio")))]
mod smol_impls {
    use super::*;
    use futures_io::{AsyncRead, AsyncWrite};

    impl AsyncRead for TcpStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TcpStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_close(cx)
        }
    }
}

// --- tokio backend: present futures-io over the tokio stream, and the tokio
// traits natively for tokio-native callers ---

#[cfg(feature = "tokio")]
mod tokio_impls {
    use super::*;
    use tokio::io::{AsyncRead as TokioRead, AsyncWrite as TokioWrite, ReadBuf};

    impl futures_io::AsyncRead for TcpStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let mut read_buf = ReadBuf::new(buf);
            match TokioRead::poll_read(Pin::new(&mut self.get_mut().inner), cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl futures_io::AsyncWrite for TcpStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            TokioWrite::poll_write(Pin::new(&mut self.get_mut().inner), cx, buf)
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            TokioWrite::poll_write_vectored(Pin::new(&mut self.get_mut().inner), cx, bufs)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            TokioWrite::poll_flush(Pin::new(&mut self.get_mut().inner), cx)
        }

        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            TokioWrite::poll_shutdown(Pin::new(&mut self.get_mut().inner), cx)
        }
    }

    impl TokioRead for TcpStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            TokioRead::poll_read(Pin::new(&mut self.get_mut().inner), cx, buf)
        }
    }

    impl TokioWrite for TcpStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            TokioWrite::poll_write(Pin::new(&mut self.get_mut().inner), cx, buf)
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            TokioWrite::poll_write_vectored(Pin::new(&mut self.get_mut().inner), cx, bufs)
        }

        fn is_write_vectored(&self) -> bool {
            TokioWrite::is_write_vectored(&self.inner)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            TokioWrite::poll_flush(Pin::new(&mut self.get_mut().inner), cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            TokioWrite::poll_shutdown(Pin::new(&mut self.get_mut().inner), cx)
        }
    }
}

/// The TCP types move freely across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<TcpStream>();
    assert_send_sync::<TcpListener>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{block_on, spawn};
    use futures_lite::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn round_trips_bytes_over_loopback() {
        block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let addr = listener.local_addr().unwrap();
            let server = spawn(async move {
                let (mut stream, _peer) = listener.accept().await.unwrap();
                let mut got = [0u8; 5];
                stream.read_exact(&mut got).await.unwrap();
                stream.write_all(b"pong").await.unwrap();
                stream.flush().await.unwrap();
                got
            });
            let mut client = TcpStream::connect("127.0.0.1", addr.port()).await.unwrap();
            client.write_all(b"ping!").await.unwrap();
            client.flush().await.unwrap();
            let mut back = Vec::new();
            client.read_to_end(&mut back).await.unwrap();
            assert_eq!(&back, b"pong");
            assert_eq!(&server.await, b"ping!");
            assert_eq!(client.peer_addr().unwrap(), addr);
        });
    }

    /// A vectored write hands every slice to the socket in one call, which is
    /// what a caller that asked `is_write_vectored` is promised. The default
    /// `futures-io` implementation would take the first slice alone.
    #[test]
    fn a_vectored_write_takes_every_slice() {
        block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let addr = listener.local_addr().unwrap();
            let server = spawn(async move {
                let (mut stream, _peer) = listener.accept().await.unwrap();
                let mut got = [0u8; 9];
                stream.read_exact(&mut got).await.unwrap();
                got
            });
            let mut client = TcpStream::connect("127.0.0.1", addr.port()).await.unwrap();
            assert!(client.is_write_vectored());
            let slices = [
                IoSlice::new(b"one"),
                IoSlice::new(b"two"),
                IoSlice::new(b"six"),
            ];
            let written = std::future::poll_fn(|cx| {
                futures_io::AsyncWrite::poll_write_vectored(Pin::new(&mut client), cx, &slices)
            })
            .await
            .unwrap();
            assert_eq!(written, 9);
            client.flush().await.unwrap();
            assert_eq!(&server.await, b"onetwosix");
        });
    }

    #[test]
    fn accept_yields_the_peer_address() {
        block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let addr = listener.local_addr().unwrap();
            let server = spawn(async move {
                let (stream, peer) = listener.accept().await.unwrap();
                (stream.local_addr().unwrap(), peer)
            });
            let client = TcpStream::connect("127.0.0.1", addr.port()).await.unwrap();
            let client_addr = client.local_addr().unwrap();
            let (server_local, server_peer) = server.await;
            assert_eq!(server_local, addr);
            assert_eq!(server_peer, client_addr);
        });
    }
}
