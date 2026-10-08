#![forbid(unsafe_code)]

//! The wire codec and the client sessions of the ostrya push and ssh pull.
//!
//! A caller pushes a local directory as one commit with [`push_tree`](fn@push_tree), or the
//! objects of its own source with a [`PushSession`]. A [`PullSession`] reads the
//! files of a server repository over ssh. The crate has no repository knowledge,
//! and it compiles on Linux, macOS, and Windows.
//!
//! # Entry points
//!
//! - [`push_tree`](fn@push_tree) pushes a local directory to a [`PushRemote`] as one commit.
//! - [`push_tree_prepared`] and [`push_tree_over_stream`] run that push over other transports.
//! - [`PushSession::connect`] opens a push session to an address that [`PushRemote::parse`] reads.
//! - [`PushSession::prepare`] checks a transport, and [`PreparedSession::open`] opens its session.
//! - [`PushSession::over_stream`] opens a push session over a pair of byte streams.
//! - [`PullSession::connect`] opens a pull session over ssh, and [`PullSession::get`] reads a file.
//! - [`Error`] is the error of each fallible operation, and [`ErrorCode`] names its wire codes.
//!
//! # Modules
//!
//! - [`proto`]: the wire format and its codec.
//! - [`session`]: the push and pull sessions, their progress, and the one-way stream.
//! - [`transport`]: the push addresses and the ssh and HTTP transports.
//! - [`tree`]: the walk and the hash of a local directory.
//!
//! # Features
//!
//! - `smol` (default): the `smol` backend of `ostrya-rt` for the ssh and HTTP transports.
//! - `tokio`: the `tokio` backend of `ostrya-rt` for the ssh and HTTP transports.
//!
//! # Examples
//!
//! ```no_run
//! use ostrya_push::{TreePushOptions, push_tree, transport::{ConnectOptions, PushRemote}};
//! # async fn run() -> ostrya_push::Result<()> {
//! let remote = PushRemote::parse("ssh://builder@repo.example.com/srv/repo")?;
//! let opts = TreePushOptions { refs: vec!["exampleos/stable".into()], ..Default::default() };
//! let outcome = push_tree(&remote, "rootfs".as_ref(), ConnectOptions::default(), opts).await?;
//! println!("{:?}", outcome.commit);
//! # Ok(()) }
//! ```

mod commit;
mod error;
pub mod proto;
mod push_tree;
pub mod session;
pub mod transport;
pub mod tree;

pub use error::{Error, ErrorCode, Result};
#[doc(hidden)]
pub use proto::{Encoding, Expected, RefOutcome, RefState, RefUpdate};
pub use push_tree::{
    ParentPolicy, TreePushOptions, push_tree, push_tree_over_stream, push_tree_prepared,
};
#[doc(hidden)]
pub use session::{
    BoxFuture, Compression, ObjectData, ObjectReader, ObjectSource, PullBody, PullSession,
    PullSessionOptions, PushOutcome, PushPhase, PushProgress, PushProgressFn, PushProgressSnapshot,
    PushSession, PushStats, ServerInfo, SessionOptions,
};
#[doc(hidden)]
pub use transport::{ConnectOptions, PreparedSession, PullConnectOptions, PushRemote};

// The public types of the protocol move freely across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Error>();
    assert_send_sync::<proto::Message>();
    assert_send_sync::<proto::PullHello>();
    assert_send_sync::<proto::PullHelloReply>();
    assert_send_sync::<proto::GetReply>();
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
    assert_send_sync::<PullSession>();
    assert_send_sync::<PullBody>();
    assert_send_sync::<PullSessionOptions>();
    assert_send_sync::<PullConnectOptions>();
};

/// The futures of a pull session can run on a multi-threaded executor.
#[allow(dead_code)]
fn pull_session_futures_are_send(remote: &PushRemote, session: &PullSession, owned: PullSession) {
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&PullSession::connect(
        remote,
        PullConnectOptions::default(),
        PullSessionOptions::default(),
    ));
    assert_send(&PullSession::over_stream(
        futures_lite::io::empty(),
        futures_lite::io::sink(),
        PullSessionOptions::default(),
    ));
    assert_send(&session.get("config", 1));
    assert_send(&owned.finish());
}

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
    assert_send(&session::export_stream(
        futures_lite::io::sink(),
        source,
        names,
        commits,
        updates,
        Compression::None,
        SessionOptions::default(),
    ));
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
