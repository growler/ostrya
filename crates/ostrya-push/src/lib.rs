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
//! push address, and [`PushSession::connect`] opens a session to it.
//! [`PushSession::prepare`] checks the options and makes the transport ready
//! first, and [`PreparedSession::open`] opens the session later. Over
//! ssh it runs the ssh client as a child process, and the remote side runs
//! the receive command. Over HTTP each step of the session is one request to
//! the receive endpoint of the server, and the object streams of a session
//! run in parallel.
//!
//! The [`tree`] module walks a local directory into a
//! [`TreeModel`](tree::TreeModel): the entry metadata, with an entry filter
//! that can change it, and the checksum of each object of the tree.
//!
//! [`push_tree`] pushes a local directory as one commit: it walks and hashes
//! the tree, opens a session over ssh or HTTP, builds and signs the commit
//! over the tree, sends the objects the server lacks, and sets the target
//! refs.
//! [`push_tree_prepared`] runs the same push over a [`PreparedSession`], and
//! [`push_tree_over_stream`] over a pair of byte streams.
//! [`TreePushOptions`] holds their options.
//!
//! [`Error`] is the error type of the crate. Each of its variants except
//! [`Error::Aborted`], [`Error::CommitOutcomeUnknown`], [`Error::Source`],
//! [`Error::InvalidInput`], [`Error::Transport`], [`Error::Fetch`],
//! [`Error::Io`], [`Error::Walk`], and [`Error::Sign`] is one wire code, and
//! [`ErrorCode`] names the codes.
//!
//! The codec and [`PushSession::over_stream`] are generic over the
//! `futures-io` traits `AsyncRead` and `AsyncWrite`, so they need no async
//! runtime. The ssh and the HTTP transports run on the runtime backend that
//! the `smol` (default) or the `tokio` feature selects. The crate has no repository
//! knowledge. It compiles on Linux, macOS, and Windows.

mod commit;
mod error;
pub mod proto;
mod push_tree;
pub mod session;
pub mod transport;
pub mod tree;

pub use error::{Error, ErrorCode, Result};
pub use proto::{Encoding, Expected, RefOutcome, RefState, RefUpdate};
pub use push_tree::{
    ParentPolicy, TreePushOptions, push_tree, push_tree_over_stream, push_tree_prepared,
};
pub use session::{
    BoxFuture, Compression, ObjectData, ObjectReader, ObjectSource, PushOutcome, PushPhase,
    PushProgress, PushProgressSnapshot, PushSession, PushStats, ServerInfo, SessionOptions,
};
pub use transport::{ConnectOptions, PreparedSession, PushRemote};

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
    assert_send_sync::<PreparedSession>();
    assert_send_sync::<tree::TreeModel>();
    assert_send_sync::<tree::EntryMeta>();
    assert_send_sync::<tree::EntryKind>();
    assert_send_sync::<tree::EntryAction>();
    assert_send_sync::<tree::EntryPath>();
    assert_send_sync::<ParentPolicy>();
};

/// The options of a tree scan and the future of the scan move to another
/// thread.
#[allow(dead_code)]
fn scan_future_is_send(root: &std::path::Path, options: tree::ScanOptions) {
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&options);
    assert_send(&tree::TreeModel::scan(root, options));
}

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

/// The future of a connect, and the futures of its two steps, can run on a
/// multi-threaded executor, over ssh and over HTTP.
#[allow(dead_code)]
fn connect_future_is_send(remote: &PushRemote, refs: &[String], prepared: PreparedSession) {
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&PushSession::connect(
        remote,
        ConnectOptions::default(),
        refs,
        SessionOptions::default(),
    ));
    assert_send(&PushSession::prepare(remote, ConnectOptions::default()));
    assert_send(&prepared.open(refs, SessionOptions::default()));
}

/// The options of a tree push and the futures of the push can run on a
/// multi-threaded executor.
#[allow(dead_code)]
fn push_tree_futures_are_send(
    remote: &PushRemote,
    root: &std::path::Path,
    prepared: PreparedSession,
) {
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&TreePushOptions::default());
    assert_send(&push_tree(
        remote,
        root,
        ConnectOptions::default(),
        TreePushOptions::default(),
    ));
    assert_send(&push_tree_prepared(
        prepared,
        root,
        TreePushOptions::default(),
    ));
    assert_send(&push_tree_over_stream(
        futures_lite::io::empty(),
        futures_lite::io::sink(),
        root,
        TreePushOptions::default(),
    ));
}
