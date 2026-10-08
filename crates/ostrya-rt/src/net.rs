//! Async TCP over the selected backend.
//!
//! [`TcpStream`] and [`TcpListener`] wrap `smol::net` or `tokio::net`. The
//! fetcher and the TLS layer use them through the `futures-io` traits, so
//! these layers do not name the backend. The doc of [`TcpStream::connect`]
//! holds the rules of the connect race.

use std::fmt;
use std::future::Future;
use std::io;
use std::io::IoSlice;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use crate::timer::Deadline;

#[cfg(all(feature = "smol", not(feature = "tokio")))]
use smol::net as backend;
#[cfg(feature = "tokio")]
use tokio::net as backend;

/// The wait between the start of one connect attempt and the start of the
/// next. An attempt that fails inside the window starts the next attempt at
/// once.
const ATTEMPT_STAGGER: Duration = Duration::from_millis(250);

/// A connected TCP stream.
///
/// [`connect`](TcpStream::connect) and [`TcpListener::accept`] turn off
/// Nagle's algorithm on the socket. Request and response bodies go out in
/// bounded chunks, and a delay of a short last write stalls the exchange.
///
/// The stream implements `AsyncRead` and `AsyncWrite` of `futures-io` with
/// each backend. With the `tokio` feature, it also implements `AsyncRead` and
/// `AsyncWrite` of `tokio_io`.
#[derive(Debug)]
pub struct TcpStream {
    inner: backend::TcpStream,
}

impl TcpStream {
    /// Resolves `host` and returns the first connection that completes.
    ///
    /// If `host` parses as an [`IpAddr`], that address is the one address to
    /// reach. Every other host goes to the resolver on the blocking pool. An
    /// IPv6 address in brackets, for example `[::1]`, does not parse as an
    /// [`IpAddr`]. A caller gives an IPv6 address with no brackets.
    ///
    /// # Connect race
    ///
    /// The attempts keep the order of the resolver. If the answer holds IPv4
    /// and IPv6 addresses, the first address of the other family moves to the
    /// second place. The addresses that this address moves past keep their
    /// order behind it. As a result, the first two attempts reach different
    /// families.
    ///
    /// The first attempt starts at once. Each later attempt starts 250 ms
    /// after the start of the attempt before it. If an attempt fails, the next
    /// attempt starts at once.
    ///
    /// All started attempts stay in flight. The first attempt that completes
    /// wins, and the function drops the other attempts. At one time, an
    /// attempt can be in flight to each address of the answer. A caller sizes
    /// its descriptor budget for the largest answer that it expects.
    ///
    /// The function has no time limit of its own. A caller that needs a time
    /// limit puts it around the whole call.
    ///
    /// # Errors
    ///
    /// - The I/O error of the resolver, unchanged, if the resolution fails.
    /// - An error of kind [`io::ErrorKind::NotFound`] if the answer holds no
    ///   address.
    /// - The error of the attempt to the first address in the attempt order,
    ///   if all attempts fail. Its kind is the kind of that failure, and its
    ///   message names the address. Its [`source`](std::error::Error::source)
    ///   is the backend error. A caller downcasts the source to [`io::Error`]
    ///   to read the operating-system error.
    /// - An I/O error of the socket if the function cannot turn off Nagle's
    ///   algorithm on the connected socket.
    ///
    /// # Examples
    ///
    /// ```
    /// use futures_lite::io::{AsyncReadExt, AsyncWriteExt};
    /// use ostrya_rt::{TcpListener, TcpStream};
    ///
    /// ostrya_rt::block_on(async {
    ///     let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap()).await?;
    ///     let port = listener.local_addr()?.port();
    ///     let server = ostrya_rt::spawn(async move {
    ///         let (mut stream, _peer) = listener.accept().await?;
    ///         let mut request = [0u8; 4];
    ///         stream.read_exact(&mut request).await?;
    ///         stream.write_all(b"pong").await?;
    ///         stream.flush().await?;
    ///         std::io::Result::Ok(request)
    ///     });
    ///
    ///     let mut client = TcpStream::connect("127.0.0.1", port).await?;
    ///     client.write_all(b"ping").await?;
    ///     client.flush().await?;
    ///     let mut reply = Vec::new();
    ///     client.read_to_end(&mut reply).await?;
    ///     assert_eq!(reply, b"pong");
    ///     assert_eq!(&server.await?, b"ping");
    ///     std::io::Result::Ok(())
    /// })?;
    /// # std::io::Result::Ok(())
    /// ```
    pub async fn connect(host: &str, port: u16) -> io::Result<TcpStream> {
        let mut addrs = if let Ok(ip) = host.parse::<IpAddr>() {
            vec![SocketAddr::new(ip, port)]
        } else {
            let name = host.to_owned();
            crate::unblock(move || {
                (name.as_str(), port)
                    .to_socket_addrs()
                    .map(|addrs| addrs.collect::<Vec<SocketAddr>>())
            })
            .await?
        };
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no address for {host}:{port}"),
            ));
        }
        order_families(&mut addrs);
        connect_addrs(addrs, ATTEMPT_STAGGER).await
    }

    /// Returns the local address of the socket.
    ///
    /// # Errors
    ///
    /// An I/O error of the socket if the address query fails.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Returns the address of the peer.
    ///
    /// # Errors
    ///
    /// An I/O error of the socket if the address query fails.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    /// Returns `true` if `poll_write_vectored` writes more than the first slice.
    ///
    /// The `futures-io` write trait has no such query. A caller asks here
    /// before it gives several slices to one write or joins them itself. With
    /// each backend, one `poll_write_vectored` call gives all the slices to the
    /// socket.
    ///
    /// With the `smol` feature, the function returns `true`.
    ///
    /// With the `tokio` feature, the function returns the answer of the tokio
    /// stream.
    pub fn is_write_vectored(&self) -> bool {
        #[cfg(feature = "tokio")]
        {
            tokio::io::AsyncWrite::is_write_vectored(&self.inner)
        }
        #[cfg(all(feature = "smol", not(feature = "tokio")))]
        {
            // async-net answers a vectored write with `write_vectored` on the
            // socket. It has no query of its own to forward to.
            true
        }
    }
}

/// A connect failure together with the address the attempt reached for.
///
/// It travels inside an [`io::Error`] of the same kind as the failure it
/// holds. The message names the address, and the failure the backend gave
/// stays reachable through [`std::error::Error::source`], which keeps the
/// operating-system error number with it.
#[derive(Debug)]
struct AddrError {
    addr: SocketAddr,
    source: io::Error,
}

impl fmt::Display for AddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.addr, self.source)
    }
}

impl std::error::Error for AddrError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Orders `addrs` so that the first two addresses hold different families.
///
/// The order of the resolver stays. If the list holds an IPv4 and an IPv6
/// address, the first address of the other family moves to the second place.
/// The addresses that it moves past keep their order behind it.
fn order_families(addrs: &mut [SocketAddr]) {
    let Some(head) = addrs.first() else {
        return;
    };
    let head_is_v6 = head.is_ipv6();
    if let Some(other) = addrs.iter().position(|addr| addr.is_ipv6() != head_is_v6) {
        addrs[1..=other].rotate_right(1);
    }
}

/// Races a connect attempt to each address in `addrs`, in the given order.
///
/// [`TcpStream::connect`] states the rules of the race and of the error. Here
/// the wait between two starts is `stagger`. If all attempts fail, the error
/// names the address that comes first in `addrs`. If `addrs` is empty, the
/// error has the kind [`io::ErrorKind::NotFound`]. The function uses the
/// timer only if `addrs` holds more than one address.
async fn connect_addrs(addrs: Vec<SocketAddr>, stagger: Duration) -> io::Result<TcpStream> {
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no address to connect to",
        ));
    }
    // A connect future holds a self-reference, so each one sits in a box of
    // its own and stays put while the vector around it grows.
    let mut pending = Vec::with_capacity(addrs.len());
    // The window serves a list that holds an attempt to start after the first
    // one. A single address runs the race without a timer.
    let mut window = (addrs.len() > 1).then(|| Deadline::new(stagger));
    let mut started = 0usize;
    let mut start_next = true;
    let mut earliest_failure: Option<(usize, io::Error)> = None;

    let inner = std::future::poll_fn(move |cx| {
        loop {
            if start_next && started < addrs.len() {
                pending.push((
                    started,
                    Box::pin(backend::TcpStream::connect(addrs[started])),
                ));
                started += 1;
                start_next = false;
                // The window opens for the attempt that comes next. The last
                // attempt has none behind it and leaves the timer alone.
                if started < addrs.len()
                    && let Some(window) = window.as_mut()
                {
                    window.restart();
                }
            }

            let mut a_failure = false;
            let mut slot = 0;
            while slot < pending.len() {
                match pending[slot].1.as_mut().poll(cx) {
                    Poll::Ready(Ok(stream)) => {
                        // The drop of the other attempts cancels them.
                        pending.clear();
                        return Poll::Ready(Ok(stream));
                    }
                    Poll::Ready(Err(e)) => {
                        let (index, _) = pending.remove(slot);
                        if earliest_failure
                            .as_ref()
                            .is_none_or(|(first, _)| index < *first)
                        {
                            earliest_failure = Some((index, e));
                        }
                        a_failure = true;
                    }
                    Poll::Pending => slot += 1,
                }
            }

            if a_failure && started < addrs.len() {
                start_next = true;
                continue;
            }
            if pending.is_empty() {
                let (index, source) = earliest_failure
                    .take()
                    .expect("every attempt ended in a failure");
                let kind = source.kind();
                let addr = addrs[index];
                return Poll::Ready(Err(io::Error::new(kind, AddrError { addr, source })));
            }
            if started < addrs.len()
                && let Some(window) = window.as_mut()
                && window.poll_expired(cx).is_ready()
            {
                start_next = true;
                continue;
            }
            return Poll::Pending;
        }
    })
    .await?;
    inner.set_nodelay(true)?;
    Ok(TcpStream { inner })
}

/// A listening TCP socket.
#[derive(Debug)]
pub struct TcpListener {
    inner: backend::TcpListener,
}

impl TcpListener {
    /// Binds a listener to `addr`.
    ///
    /// If the port of `addr` is 0, the operating system selects a free port.
    /// [`local_addr`](TcpListener::local_addr) returns the selected port.
    ///
    /// # Errors
    ///
    /// An I/O error of the socket if the bind fails.
    pub async fn bind(addr: SocketAddr) -> io::Result<TcpListener> {
        let inner = backend::TcpListener::bind(addr).await?;
        Ok(TcpListener { inner })
    }

    /// Returns the address that the socket is bound to.
    ///
    /// # Errors
    ///
    /// An I/O error of the socket if the address query fails.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Accepts the next connection and returns the stream and the peer address.
    ///
    /// # Errors
    ///
    /// - An I/O error of the socket if the accept fails.
    /// - An I/O error of the socket if the function cannot turn off Nagle's
    ///   algorithm on the new stream.
    pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let (stream, peer) = self.inner.accept().await?;
        stream.set_nodelay(true)?;
        Ok((TcpStream { inner: stream }, peer))
    }
}

// --- smol backend: the async-net stream implements futures-io ---

#[cfg(all(feature = "smol", not(feature = "tokio")))]
mod smol_impls {
    use super::*;
    use futures_io::{AsyncRead, AsyncWrite};

    /// The read trait of `futures-io`.
    impl AsyncRead for TcpStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    /// The write trait of `futures-io`.
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

// --- tokio backend: futures-io over the tokio stream, and the tokio traits
// for callers that use tokio ---

#[cfg(feature = "tokio")]
mod tokio_impls {
    use super::*;
    use tokio::io::{AsyncRead as TokioRead, AsyncWrite as TokioWrite, ReadBuf};

    /// The read trait of `futures-io`.
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

    /// The write trait of `futures-io`.
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

    /// The read trait of `tokio`, also in [`tokio_io`](crate::tokio_io).
    impl TokioRead for TcpStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            TokioRead::poll_read(Pin::new(&mut self.get_mut().inner), cx, buf)
        }
    }

    /// The write trait of `tokio`, also in [`tokio_io`](crate::tokio_io).
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

// The TCP types are `Send` and `Sync`, so they move across tasks and threads.
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
    use std::error::Error as _;
    use std::time::Instant;

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

    /// A vectored write gives every slice to the socket in one call.
    /// `is_write_vectored` promises this to a caller. The default `futures-io`
    /// implementation takes the first slice alone.
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

    /// Parses a socket address that a test states as text.
    fn at(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    /// The stagger of the timing tests. It is long enough to measure and short
    /// enough to keep the suite quick.
    const TEST_STAGGER: Duration = Duration::from_millis(10);

    /// The upper limit of a timing test on the time of a completed open. A race
    /// with the 250 ms window of the library in place of [`TEST_STAGGER`] takes
    /// more time.
    const TIMING_CEILING: Duration = Duration::from_millis(200);

    /// Returns `true` if a connect attempt to `addr` is still pending after a
    /// short probe.
    ///
    /// A TEST-NET-1 address has no host. If a network drops the packet, the
    /// attempt stays pending while the operating system retries. If a network
    /// answers with an ICMP refusal, the attempt fails at once.
    ///
    /// The failure starts the next attempt, so the stagger window never runs
    /// and a measured window has no lower bound to hold. [`answers_now`] reads
    /// this to tell the two networks apart.
    async fn stays_pending(addr: SocketAddr) -> bool {
        let mut attempt = Box::pin(backend::TcpStream::connect(addr));
        for _ in 0..5 {
            let polled = std::future::poll_fn(|cx| Poll::Ready(attempt.as_mut().poll(cx))).await;
            if polled.is_ready() {
                return false;
            }
            crate::Timer::after(Duration::from_millis(4)).await;
        }
        true
    }

    /// Returns `true` if an address in `addrs` answers a connect attempt now.
    ///
    /// The function probes the addresses in the given order and stops at the
    /// first address that answers. It writes the name of that address to the
    /// standard error stream.
    ///
    /// A test calls this only after the race, and only if the race misses the
    /// timing that the test states. An address can answer during the race and
    /// hold the attempt pending again after it. Such an address reads the same
    /// as a race that ran at the wrong time.
    async fn answers_now(addrs: &[SocketAddr]) -> bool {
        for addr in addrs {
            if !stays_pending(*addr).await {
                eprintln!("{addr} answers a connect attempt here");
                return true;
            }
        }
        false
    }

    /// Returns two loopback addresses that refuse a connection.
    ///
    /// The function holds both ports at the same time, so the kernel gives two
    /// different ports. Both sockets close when the function returns.
    async fn two_closed_ports() -> (SocketAddr, SocketAddr) {
        let first = TcpListener::bind(at("127.0.0.1:0")).await.unwrap();
        let second = TcpListener::bind(at("127.0.0.1:0")).await.unwrap();
        (first.local_addr().unwrap(), second.local_addr().unwrap())
    }

    /// A list that starts with IPv4 and holds IPv6 puts the first IPv6
    /// address second. Every other address keeps the order of the resolver.
    #[test]
    fn ordering_moves_the_other_family_to_second_place() {
        let mut addrs = vec![
            at("1.1.1.1:80"),
            at("2.2.2.2:80"),
            at("[2001:db8::1]:80"),
            at("[2001:db8::2]:80"),
        ];
        order_families(&mut addrs);
        assert_eq!(
            addrs,
            vec![
                at("1.1.1.1:80"),
                at("[2001:db8::1]:80"),
                at("2.2.2.2:80"),
                at("[2001:db8::2]:80"),
            ]
        );

        let mut addrs = vec![
            at("[2001:db8::1]:80"),
            at("[2001:db8::2]:80"),
            at("1.1.1.1:80"),
        ];
        order_families(&mut addrs);
        assert_eq!(
            addrs,
            vec![
                at("[2001:db8::1]:80"),
                at("1.1.1.1:80"),
                at("[2001:db8::2]:80")
            ]
        );
    }

    /// A list of one family keeps the order of the resolver. A list whose first
    /// two addresses hold both families also keeps it.
    #[test]
    fn ordering_leaves_a_list_that_needs_no_move_alone() {
        for mut addrs in [
            vec![at("1.1.1.1:80"), at("2.2.2.2:80"), at("3.3.3.3:80")],
            vec![at("[2001:db8::1]:80"), at("[2001:db8::2]:80")],
            vec![at("1.1.1.1:80"), at("[2001:db8::1]:80"), at("2.2.2.2:80")],
            vec![at("1.1.1.1:80")],
            vec![],
        ] {
            let before = addrs.clone();
            order_families(&mut addrs);
            assert_eq!(addrs, before);
        }
    }

    /// An address that black-holes the attempt holds the race for one stagger
    /// window alone. The next address takes the connection, and the open ends
    /// one window in.
    ///
    /// If a network answers the TEST-NET-1 address with an ICMP refusal, the
    /// first attempt fails at once. That failure starts the second attempt
    /// inside the window. On such a network the test leaves out the lower
    /// bound. [`answers_now`] identifies such a network.
    #[test]
    fn a_black_holed_address_gives_way_to_the_next_one() {
        block_on(async {
            let dark = [at("192.0.2.1:80")];
            let listener = TcpListener::bind(at("127.0.0.1:0")).await.unwrap();
            let live = listener.local_addr().unwrap();
            let server = spawn(async move { listener.accept().await.unwrap().1 });
            let start = Instant::now();
            let client = connect_addrs(vec![dark[0], live], TEST_STAGGER)
                .await
                .unwrap();
            let elapsed = start.elapsed();
            assert_eq!(client.peer_addr().unwrap(), live);
            assert!(elapsed < TIMING_CEILING, "the open took {elapsed:?}");
            if elapsed < TEST_STAGGER {
                assert!(answers_now(&dark).await, "the open took {elapsed:?}");
                eprintln!(
                    "the attempt behind it starts on that failure and the \
                     timing bound is left out"
                );
            }
            assert_eq!(server.await, client.local_addr().unwrap());
        });
    }

    /// Two black-holed addresses hold the race for two stagger windows, so the
    /// third attempt starts two windows in and takes the connection.
    ///
    /// If a network answers a TEST-NET-1 address with an ICMP refusal, the
    /// attempt fails at once. That failure starts the attempt behind it inside
    /// the window. On such a network the test leaves out the lower bound.
    /// [`answers_now`] identifies such a network.
    #[test]
    fn a_second_window_starts_the_third_attempt() {
        block_on(async {
            let dark = [at("192.0.2.1:80"), at("192.0.2.2:80")];
            let listener = TcpListener::bind(at("127.0.0.1:0")).await.unwrap();
            let live = listener.local_addr().unwrap();
            let server = spawn(async move { listener.accept().await.unwrap().1 });
            let start = Instant::now();
            let client = connect_addrs(vec![dark[0], dark[1], live], TEST_STAGGER)
                .await
                .unwrap();
            let elapsed = start.elapsed();
            assert_eq!(client.peer_addr().unwrap(), live);
            assert!(elapsed < TIMING_CEILING, "the open took {elapsed:?}");
            if elapsed < 2 * TEST_STAGGER {
                assert!(answers_now(&dark).await, "the open took {elapsed:?}");
                eprintln!(
                    "the attempt behind it starts on that failure and the \
                     timing bound is left out"
                );
            }
            assert_eq!(server.await, client.local_addr().unwrap());
        });
    }

    /// If every attempt fails, the race reports the failure of the first
    /// address in the list. The report names this address in each time order
    /// of the failures. The failure from the operating system stays reachable
    /// under it, with its error number.
    ///
    /// The ports of the pair are free. A test that runs in parallel in the same
    /// process can bind one of them after the pair returns and before the race
    /// starts. If a pair answers, the test drops it and takes a new pair.
    #[test]
    fn every_attempt_failing_reports_the_first_address() {
        block_on(async {
            for remaining in (0..8).rev() {
                let (first, second) = two_closed_ports().await;
                let Err(failure) = connect_addrs(vec![first, second], TEST_STAGGER).await else {
                    assert!(remaining > 0, "a closed port answered on every try");
                    continue;
                };
                let text = failure.to_string();
                assert!(text.contains(&first.to_string()), "{text}");
                assert!(!text.contains(&second.to_string()), "{text}");
                assert_eq!(failure.kind(), io::ErrorKind::ConnectionRefused);
                let source = failure.source().expect("the backend failure is reachable");
                let backend_failure = source
                    .downcast_ref::<io::Error>()
                    .expect("the source is the backend's io error");
                assert_eq!(backend_failure.kind(), io::ErrorKind::ConnectionRefused);
                assert!(
                    backend_failure.raw_os_error().is_some(),
                    "the operating-system error number is kept"
                );
                return;
            }
        });
    }

    /// An attempt that fails starts the next attempt at once. If two addresses
    /// refuse the attempt, the third address gets the connection inside the
    /// first stagger window.
    ///
    /// The ports of the pair are free. A test that runs in parallel in the same
    /// process can bind one of them after the pair returns and before the race
    /// starts. If the race connects to such a port, the test drops it and takes
    /// a new pair.
    #[test]
    fn a_failed_attempt_starts_the_next_one_at_once() {
        block_on(async {
            for remaining in (0..8).rev() {
                let listener = TcpListener::bind(at("127.0.0.1:0")).await.unwrap();
                let live = listener.local_addr().unwrap();
                let (first, second) = two_closed_ports().await;
                let start = Instant::now();
                let client = connect_addrs(vec![first, second, live], TEST_STAGGER)
                    .await
                    .unwrap();
                let elapsed = start.elapsed();
                if client.peer_addr().unwrap() != live {
                    assert!(remaining > 0, "a closed port answered on every try");
                    continue;
                }
                assert!(
                    elapsed < TEST_STAGGER,
                    "two refusals waited for a window: {elapsed:?}"
                );
                let peer = listener.accept().await.unwrap().1;
                assert_eq!(peer, client.local_addr().unwrap());
                return;
            }
        });
    }

    /// A drop of the race while attempts are in flight cancels them. After the
    /// drop, the runtime opens the next connection.
    ///
    /// If a network answers a TEST-NET-1 address, the race ends before the
    /// drop. The race then has no attempt to cancel, and the test leaves out
    /// the cancellation half. [`answers_now`] identifies such a network.
    #[test]
    fn dropping_the_race_mid_flight_leaves_the_runtime_working() {
        block_on(async {
            let dark = [at("192.0.2.1:80"), at("192.0.2.2:80")];
            let mut race = Box::pin(connect_addrs(dark.to_vec(), TEST_STAGGER));
            let mut ended_early = false;
            for _ in 0..4 {
                let polled = std::future::poll_fn(|cx| Poll::Ready(race.as_mut().poll(cx))).await;
                if polled.is_ready() {
                    ended_early = true;
                    break;
                }
                crate::Timer::after(TEST_STAGGER).await;
            }
            drop(race);
            if ended_early {
                assert!(
                    answers_now(&dark).await,
                    "an attempt to a black-holed address completed"
                );
                eprintln!("the race ended before the drop");
            }

            let listener = TcpListener::bind(at("127.0.0.1:0")).await.unwrap();
            let live = listener.local_addr().unwrap();
            let server = spawn(async move { listener.accept().await.unwrap().1 });
            let client = connect_addrs(vec![live], TEST_STAGGER).await.unwrap();
            assert_eq!(client.peer_addr().unwrap(), live);
            assert_eq!(server.await, client.local_addr().unwrap());
        });
    }

    /// An empty address list fails at once.
    #[test]
    fn an_empty_address_list_fails() {
        block_on(async {
            let failure = connect_addrs(Vec::new(), TEST_STAGGER).await.unwrap_err();
            assert_eq!(failure.kind(), io::ErrorKind::NotFound);
        });
    }
}
