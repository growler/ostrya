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
//! The [`session`] module holds the client side. [`PushSession`] runs one
//! session over a pair of byte streams: it opens with `Hello`, asks which
//! objects the server needs, sends them from an [`ObjectSource`], and asks
//! the server to update its refs. [`PushProgress`] shows the counters of a
//! session while it runs, and [`PushOutcome`] gives the ref outcomes and the
//! [`PushStats`] of a session that committed.
//!
//! The [`transport`] module holds the transports. [`PushRemote`] parses a
//! push address, and [`PushSession::connect`] opens a session over ssh: it
//! runs the ssh client as a child process, and the remote side runs the
//! receive command.
//!
//! [`Error`] is the error type of the crate. Each of its variants except
//! [`Error::Aborted`], [`Error::CommitOutcomeUnknown`], [`Error::Source`],
//! [`Error::InvalidInput`], [`Error::Transport`], and [`Error::Io`] is one
//! wire code, and [`ErrorCode`] names the codes.
//!
//! The codec and [`PushSession::over_stream`] are generic over the
//! `futures-io` traits `AsyncRead` and `AsyncWrite`, so they need no async
//! runtime. The ssh transport runs on the runtime backend that the `smol`
//! (default) or the `tokio` feature selects. The crate has no repository
//! knowledge. It compiles on Linux, macOS, and Windows.

mod error;
pub mod proto;
pub mod session;
pub mod transport;

pub use error::{Error, ErrorCode, Result};
pub use proto::{Encoding, Expected, RefOutcome, RefState, RefUpdate};
pub use session::{
    BoxFuture, Compression, ObjectData, ObjectReader, ObjectSource, PushOutcome, PushPhase,
    PushProgress, PushProgressSnapshot, PushSession, PushStats, ServerInfo, SessionOptions,
};
pub use transport::{ConnectOptions, PushRemote};

/// The public types of the protocol move freely across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Error>();
    assert_send_sync::<proto::Message>();
    assert_send_sync::<proto::FrameReader<&[u8]>>();
    assert_send_sync::<proto::ObjectBody<'static, &[u8]>>();
    assert_send_sync::<proto::FrameWriter<Vec<u8>>>();
    assert_send_sync::<PushSession>();
    assert_send_sync::<PushProgress>();
    assert_send_sync::<PushStats>();
    assert_send_sync::<PushOutcome>();
    assert_send_sync::<ServerInfo>();
    assert_send_sync::<ObjectData>();
    assert_send_sync::<Box<dyn ObjectReader>>();
    assert_send_sync::<PushRemote>();
    assert_send_sync::<ConnectOptions>();
};

/// The futures of the session calls can run on a multi-threaded executor.
#[allow(dead_code)]
fn session_futures_are_send(
    session: &PushSession,
    owned: PushSession,
    source: &dyn ObjectSource,
    names: &[ostrya_core::ObjectName],
    commits: &[ostrya_core::Checksum],
    updates: &[RefUpdate],
) {
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&session.missing(names));
    assert_send(&session.send(source, names, commits, Compression::None));
    assert_send(&owned.commit(updates, false));
}

/// The future of a connect can run on a multi-threaded executor.
#[allow(dead_code)]
fn connect_future_is_send(remote: &PushRemote, refs: &[String]) {
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&PushSession::connect(
        remote,
        ConnectOptions::default(),
        refs,
        SessionOptions::default(),
    ));
}
