//! A bounded in-process byte pipe, for a session between a test client and
//! a server in one process.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use futures_io::{AsyncRead, AsyncWrite};

pub struct PipeState {
    buf: VecDeque<u8>,
    cap: usize,
    writer_closed: bool,
    reader_closed: bool,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

/// The write half of a bounded in-process byte pipe. Dropping it gives the
/// reader end of file.
pub struct PipeWriter(Arc<Mutex<PipeState>>);

/// The read half of a bounded in-process byte pipe. Dropping it fails each
/// later write with `BrokenPipe`.
pub struct PipeReader(Arc<Mutex<PipeState>>);

pub fn pipe(cap: usize) -> (PipeWriter, PipeReader) {
    let state = Arc::new(Mutex::new(PipeState {
        buf: VecDeque::new(),
        cap,
        writer_closed: false,
        reader_closed: false,
        read_waker: None,
        write_waker: None,
    }));
    (PipeWriter(state.clone()), PipeReader(state))
}

impl AsyncWrite for PipeWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut st = self.0.lock().unwrap();
        if st.reader_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let room = st.cap - st.buf.len();
        if room == 0 {
            st.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = room.min(buf.len());
        st.buf.extend(&buf[..n]);
        if let Some(w) = st.read_waker.take() {
            w.wake();
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Drop for PipeWriter {
    fn drop(&mut self) {
        let mut st = self.0.lock().unwrap();
        st.writer_closed = true;
        if let Some(w) = st.read_waker.take() {
            w.wake();
        }
    }
}

impl AsyncRead for PipeReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut st = self.0.lock().unwrap();
        if st.buf.is_empty() {
            if st.writer_closed {
                return Poll::Ready(Ok(0));
            }
            st.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = buf.len().min(st.buf.len());
        for (dst, src) in buf[..n].iter_mut().zip(st.buf.drain(..n)) {
            *dst = src;
        }
        if let Some(w) = st.write_waker.take() {
            w.wake();
        }
        Poll::Ready(Ok(n))
    }
}

impl Drop for PipeReader {
    fn drop(&mut self) {
        let mut st = self.0.lock().unwrap();
        st.reader_closed = true;
        if let Some(w) = st.write_waker.take() {
            w.wake();
        }
    }
}
