#![forbid(unsafe_code)]

//! The push protocol of ostrya.
//!
//! A push client sends the objects of a set of commits to a server
//! repository and then asks it to update refs in one transaction. The
//! [`proto`] module holds the wire protocol: the messages, their GVariant
//! encoding, the frame codec with its size limit, and the chunked object
//! stream with its abandon marker. The module docs of [`proto`] state the
//! wire format in full.
//!
//! [`Error`] is the error type of the crate. Each of its variants except
//! [`Error::Aborted`] and [`Error::Io`] is one wire code, and [`ErrorCode`]
//! names the codes.
//!
//! The codec is generic over the `futures-io` traits `AsyncRead` and
//! `AsyncWrite`, so it needs no async runtime. The crate has no repository
//! knowledge. It compiles on Linux, macOS, and Windows.

mod error;
pub mod proto;

pub use error::{Error, ErrorCode, Result};
pub use proto::{Encoding, Expected, RefOutcome, RefUpdate};

/// The public types of the protocol move freely across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Error>();
    assert_send_sync::<proto::Message>();
    assert_send_sync::<proto::FrameReader<&[u8]>>();
    assert_send_sync::<proto::ObjectBody<'static, &[u8]>>();
    assert_send_sync::<proto::FrameWriter<Vec<u8>>>();
};
