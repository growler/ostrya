#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! The wire codec and the client sessions of the ostrya push and pull.
//!
//! A caller pushes a local directory as a commit that the server makes with
//! [`push_tree`](fn@push_tree), or its own objects with a [`PushSession`]. A [`PullSession`] reads the summary and the ref listings of a remote. The
//! crate has no repository knowledge, and it compiles on Linux, macOS, and Windows.
//!
//! With the `s3` feature, the `s3` module signs S3 requests, reads the
//! settings and the credentials of an S3 endpoint, and holds the client of a
//! bucket repository.
//!
//! # Entry points
//!
//! - [`Endpoint::parse`] reads an ssh or HTTP address into an [`Endpoint`].
//! - [`push_tree`](fn@push_tree) pushes a local directory to an endpoint as one server commit.
//! - [`PushSession::connect`] opens a push session to an endpoint.
//! - [`PushSession::prepare`] checks an endpoint before the session opens.
//! - [`PushSession::over_stream`] opens a push session over a pair of byte streams.
//! - [`PullSession::connect`] opens the session of a pull to an endpoint.
//! - [`StreamSession::connect`] opens a stream session over ssh.
//! - [`StreamSession::check_command_line`] checks the ssh command line of a pull before the session opens.
//! - [`Error`] is the error of each fallible operation.
//!
//! # Modules
//!
//! - [`proto`]: the wire format and its codec.
//! - [`session`]: the push and pull sessions, their progress, and the one-way stream.
//! - [`transport`]: the endpoints, the addresses, and the ssh and HTTP transports.
//! - [`tree`]: the walk and the hash of a local directory.
//! - `s3` (feature `s3`): S3 request signing, the settings and credentials of an S3 endpoint, the address of a bucket repository, and the bucket client.
//!
//! # Features
//!
//! - `smol` (default): the `smol` backend of `ostrya-rt` for the ssh and HTTP transports.
//! - `tokio`: the `tokio` backend of `ostrya-rt` for the ssh and HTTP transports.
//! - `s3`: the `s3` module, which signs S3 requests with AWS Signature Version 4, reads the AWS credentials, and holds the bucket client.
//!
//! # Examples
//!
//! ```no_run
//! use ostrya_remote::{TreePushOptions, push_tree, transport::Endpoint};
//! # async fn run() -> ostrya_remote::Result<()> {
//! let endpoint = Endpoint::parse("ssh://builder@repo.example.com/srv/repo")?;
//! let opts = TreePushOptions { onto: "exampleos/stable".into(), ..Default::default() };
//! let outcome = push_tree(endpoint, "rootfs".as_ref(), opts).await?;
//! println!("{:?}", outcome.commit);
//! # Ok(()) }
//! ```

mod error;
pub mod proto;
mod push_tree;
#[cfg(feature = "s3")]
pub mod s3;
pub mod session;
pub mod transport;
pub mod tree;

pub use error::{Error, ErrorCode, Result};
#[doc(hidden)]
pub use proto::{Encoding, Expected, RefOutcome, RefState, RefUpdate};
pub use push_tree::{TreePushOptions, push_tree, push_tree_over_stream, push_tree_prepared};
#[doc(hidden)]
pub use session::{
    BoxFuture, Compression, DetachedMetadata, ObjectData, ObjectReader, ObjectSource, PullBody,
    PullSession, PushOutcome, PushPhase, PushProgress, PushProgressFn, PushProgressSnapshot,
    PushSession, PushStats, ServerInfo, SessionOptions, StreamSession, StreamSessionOptions,
};
#[doc(hidden)]
pub use transport::{Endpoint, PreparedSession, SshAddress, SshOptions, without_userinfo};

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
    assert_send_sync::<DetachedMetadata>();
    assert_send_sync::<Box<dyn ObjectReader>>();
    assert_send_sync::<PreparedSession>();
    assert_send_sync::<tree::TreeModel>();
    assert_send_sync::<tree::EntryMeta>();
    assert_send_sync::<tree::EntryKind>();
    assert_send_sync::<tree::EntryAction>();
    assert_send_sync::<tree::EntryPath>();
    assert_send_sync::<StreamSession>();
    assert_send_sync::<PullSession>();
    assert_send_sync::<PullBody>();
    assert_send_sync::<StreamSessionOptions>();
    assert_send_sync::<Endpoint>();
    assert_send_sync::<SshAddress>();
    assert_send_sync::<SshOptions>();
};

// The signer, the credentials, the settings of an S3 endpoint, the bucket
// client, and its results move freely across tasks and threads.
#[cfg(feature = "s3")]
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<s3::SigV4>();
    assert_send_sync::<s3::Credentials>();
    assert_send_sync::<s3::Resolved>();
    assert_send_sync::<s3::Settings>();
    assert_send_sync::<s3::Environment>();
    assert_send_sync::<s3::Address>();
    assert_send_sync::<s3::Location>();
    assert_send_sync::<s3::S3Endpoint>();
    assert_send_sync::<s3::Bucket>();
    assert_send_sync::<s3::Object>();
    assert_send_sync::<s3::ObjectStream>();
    assert_send_sync::<s3::PutIfAbsent>();
    assert_send_sync::<s3::Listing>();
    assert_send_sync::<s3::Listed>();
    assert_send_sync::<s3::Upload>();
};

/// The future of the resolution of an S3 endpoint can run on a
/// multi-threaded executor.
#[cfg(feature = "s3")]
#[allow(dead_code)]
fn s3_resolve_future_is_send(settings: &s3::Settings, environment: &s3::Environment) {
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&s3::resolve(settings, environment));
}

/// The futures of the bucket client and of the resolution of its endpoint can
/// run on a multi-threaded executor.
#[cfg(feature = "s3")]
#[allow(dead_code)]
fn bucket_futures_are_send(
    endpoint: &s3::S3Endpoint,
    bucket: &s3::Bucket,
    settings: &s3::Settings,
    environment: &s3::Environment,
) {
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&s3::S3Endpoint::resolve("s3://b/p", settings, environment));
    assert_send(&s3::Bucket::new(endpoint));
    assert_send(&bucket.get("config", 1));
    assert_send(&bucket.get_stream("config"));
    assert_send(&bucket.put("config", Vec::new()));
    assert_send(&bucket.put_if_absent("config", Vec::new()));
    assert_send(&bucket.delete("config"));
    assert_send(&bucket.list("objects/"));
    assert_send(&bucket.list_delimited("objects/"));
    assert_send(&bucket.list_uploads());
}

/// The futures of a stream session can run on a multi-threaded executor.
#[allow(dead_code)]
fn stream_session_futures_are_send(
    address: &SshAddress,
    options: &SshOptions,
    session: &StreamSession,
    owned: StreamSession,
    selector: &ostrya_core::RefSelector,
) {
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&StreamSession::connect(
        address,
        options,
        StreamSessionOptions::default(),
    ));
    assert_send(&StreamSession::over_stream(
        futures_lite::io::empty(),
        futures_lite::io::sink(),
        StreamSessionOptions::default(),
    ));
    assert_send(&session.get("config", 1));
    assert_send(&session.list_refs(selector, Some(selector), 1));
    assert_send(&owned.finish());
}

/// The futures of a pull session can run on a multi-threaded executor.
#[allow(dead_code)]
fn pull_session_futures_are_send(
    endpoint: &Endpoint,
    session: &PullSession,
    owned: PullSession,
    selector: &ostrya_core::RefSelector,
) {
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&PullSession::connect(
        endpoint.clone(),
        StreamSessionOptions::default(),
    ));
    assert_send(&PullSession::over_stream(
        futures_lite::io::empty(),
        futures_lite::io::sink(),
        StreamSessionOptions::default(),
    ));
    assert_send(&session.fetch_summary());
    assert_send(&session.fetch_refs(selector, Some(selector)));
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

/// The future of a server commit can run on a multi-threaded executor.
#[allow(dead_code)]
fn server_commit_future_is_send(owned: PushSession, server_commit: proto::ServerCommit) {
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&owned.server_commit(server_commit));
}

/// The future of a connect, and the futures of its two steps, can run on a
/// multi-threaded executor, over ssh and over HTTP.
#[allow(dead_code)]
fn connect_future_is_send(endpoint: &Endpoint, refs: &[String], prepared: PreparedSession) {
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&PushSession::connect(
        endpoint.clone(),
        refs,
        SessionOptions::default(),
    ));
    assert_send(&PushSession::prepare(endpoint.clone()));
    assert_send(&prepared.open(refs, SessionOptions::default()));
}

/// The options of a tree push and the futures of the push can run on a
/// multi-threaded executor.
#[allow(dead_code)]
fn push_tree_futures_are_send(
    endpoint: &Endpoint,
    root: &std::path::Path,
    prepared: PreparedSession,
) {
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&TreePushOptions::default());
    assert_send(&push_tree(
        endpoint.clone(),
        root,
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
