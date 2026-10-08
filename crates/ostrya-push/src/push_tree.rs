//! The push of a local directory: the walk and the hash pass, the commit
//! over the tree, and one session that sends the objects that the server
//! lacks and sets the target refs.

use std::collections::HashSet;
use std::path::Path;

use futures_io::{AsyncRead, AsyncWrite};
use ostrya_core::{Checksum, MAX_METADATA_SIZE, Value};

use crate::commit::{
    CommitInputs, build_commit, check_commit_floor, check_ref_states, commit_size_floor,
    detached_dict, entry_dict, ref_updates, resolve_parent,
};
use crate::error::Result;
use crate::proto::RefUpdate;
use crate::session::{
    Compression, ObjectSource, PushOutcome, PushProgress, PushSession, SessionOptions,
    deflate_level, invalid,
};
use crate::transport::{ConnectOptions, PreparedSession, PushRemote};
use crate::tree::{EntryFilter, ScanOptions, TreeModel};

/// The parent of the commit of a tree push.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ParentPolicy {
    /// The commit of the first target ref on the server, as `HelloReply`
    /// reports it.
    ///
    /// If that ref is absent, the commit has no parent.
    #[default]
    CurrentTip,
    /// No parent.
    None,
    /// The commit of the given full checksum.
    ///
    /// The client cannot resolve a ref name or an abbreviated checksum on the
    /// server.
    Commit(Checksum),
}

/// The options of a tree push.
///
/// [`push_tree`], [`push_tree_prepared`], and [`push_tree_over_stream`] take
/// them. The struct carries no `#[non_exhaustive]`. A caller builds it with
/// `..Default::default()`.
#[derive(Default)]
pub struct TreePushOptions {
    /// The target refs, one or more, each a ref name below `refs/heads`.
    ///
    /// The push sets each of them to the commit.
    pub refs: Vec<String>,
    /// The parent of the commit.
    pub parent: ParentPolicy,
    /// The subject of the commit, empty if not set.
    pub subject: Option<String>,
    /// The body of the commit, empty if not set.
    pub body: Option<String>,
    /// The entries of the `a{sv}` metadata dict of the commit, in order.
    ///
    /// Each value is a variant. The bindings follow the entries.
    pub metadata: Vec<(String, Value)>,
    /// The entries of the detached metadata dict of the commit, in order.
    ///
    /// Each value is a variant. The signatures follow the entries.
    pub detached_metadata: Vec<(String, Value)>,
    /// The timestamp of the commit, in seconds since the Unix epoch, UTC.
    ///
    /// If this field is not set, the push takes the `SOURCE_DATE_EPOCH`
    /// environment variable. If that variable is also not set, the push takes
    /// the current time.
    pub timestamp: Option<u64>,
    /// The switch that leaves out `ostree.ref-binding` and
    /// `ostree.collection-binding`.
    pub no_bindings: bool,
    /// The signers of the commit, in order.
    pub signers: Vec<Box<dyn ostrya_sign::Signer>>,
    /// The encoding of the content objects.
    pub compression: Compression,
    /// The filter that sees each entry of the walk.
    pub entry_filter: Option<EntryFilter>,
    /// The maximum number of regular files that the hash pass reads at one
    /// time.
    ///
    /// [`ScanOptions::hash_jobs`] gives the default and the limits.
    pub hash_jobs: Option<usize>,
    /// The switch that sets each target ref whatever its state on the server.
    ///
    /// If it is `true`, `Commit` also asks the server to allow an update that
    /// is not a fast-forward.
    pub force: bool,
    /// The progress handle of the scan and of the session.
    ///
    /// The scan sets its phases in the handle, and the session counts its
    /// progress into it.
    pub progress: Option<PushProgress>,
}

/// Pushes the directory `root` to `remote` as one commit.
///
/// The server sets the target refs to the commit in one transaction. The push
/// runs in this order:
///
/// 1. It checks `opts` and refuses each value that [`push_tree_over_stream`]
///    refuses. Then it makes the transport ready with
///    [`PushSession::prepare`]. For ssh, it builds the command line. For
///    HTTP, it reads the files that `connect` names and builds the HTTP
///    client. It refuses each value that [`PushSession::connect`] refuses
///    before it starts the transport.
/// 2. It walks and hashes the tree with [`TreeModel::scan`], with
///    `entry_filter` and `hash_jobs`.
/// 3. It starts the ssh client, or sends the first HTTP request. It opens the
///    session with the target refs in one `Hello`.
/// 4. It builds the commit and signs it. It offers each object of the tree
///    and the commit in one round of `Have`. It sends the objects that the
///    server lacks, with the detached metadata of the commit, and then it
///    sends `Commit`.
///
/// A refusal of the options, a walk error, and a hash error start no ssh
/// client, send no request, and open no session. [`push_tree_over_stream`]
/// gives the rules of the commit and of the session.
///
/// [`PushStats::elapsed`](crate::session::PushStats::elapsed) of the outcome
/// covers the session alone, from the open of the session. It excludes the
/// time of the scan.
///
/// Under the tokio backend, the call must run within a runtime that has the
/// IO driver and the time driver enabled, as [`PushSession::connect`] states.
///
/// # Errors
///
/// - Each error of [`push_tree_prepared`](push_tree_prepared#errors).
/// - [`Error::InvalidInput`] if `connect` holds a value that
///   [`PushSession::prepare`] refuses.
/// - [`Error::Io`] if the token file or a TLS file of `connect` cannot be
///   read.
/// - [`Error::Fetch`] if the HTTP client cannot be built.
///
/// [`Error::InvalidInput`]: crate::Error::InvalidInput
/// [`Error::Io`]: crate::Error::Io
/// [`Error::Fetch`]: crate::Error::Fetch
pub async fn push_tree(
    remote: &PushRemote,
    root: &Path,
    connect: ConnectOptions,
    opts: TreePushOptions,
) -> Result<PushOutcome> {
    let (scan, push) = Prepared::new(opts)?;
    let transport = PushSession::prepare(remote, connect).await?;
    push.scan_and_run(transport, root, scan).await
}

/// Pushes the directory `root` as one commit over a prepared transport.
///
/// `session` is a transport that [`PushSession::prepare`] made ready. The
/// server sets the target refs to the commit in one transaction. The push is
/// that of [`push_tree`] with the transport checks done first, so a caller
/// can do them before the work that builds `opts`. For example, the caller
/// can start a signer after the checks.
///
/// The push checks `opts` as [`push_tree`] does, then scans the tree, and then
/// opens `session`. A refusal of the options, a walk error, and a hash error
/// start no ssh client, send no request, and open no session. The other rules
/// are those of [`push_tree`].
///
/// # Errors
///
/// - Each error of [`push_tree_over_stream`](push_tree_over_stream#errors).
/// - [`Error::Transport`] if the ssh client cannot be started, or if it exits
///   with a failure status after the session fails with an I/O error.
/// - [`Error::Transport`] if an HTTP server answers with a status that the
///   receive endpoint does not give, or with a body that is not one frame.
/// - [`Error::Unauthorized`] if an HTTP server refuses the credential of the
///   session with an `Error` message of the code `unauthorized`.
/// - [`Error::Fetch`] for a failure of the HTTP client.
///
/// [`Error::Transport`]: crate::Error::Transport
/// [`Error::Unauthorized`]: crate::Error::Unauthorized
/// [`Error::Fetch`]: crate::Error::Fetch
pub async fn push_tree_prepared(
    session: PreparedSession,
    root: &Path,
    opts: TreePushOptions,
) -> Result<PushOutcome> {
    let (scan, push) = Prepared::new(opts)?;
    push.scan_and_run(session, root, scan).await
}

/// Pushes the directory `root` as one commit over a pair of byte streams.
///
/// `input` comes from the server, and `output` goes to it. The server sets the
/// target refs to the commit in one transaction. The push scans the tree
/// before it writes the first byte to `output`.
///
/// # Refusals
///
/// Before the scan, the push refuses these values of `opts`:
///
/// - empty `refs`, and a ref named twice
/// - a ref that holds `:` or `^`, a ref of 64 lowercase hex characters, and a
///   ref that fails the ref-name rule of [`ostrya_core::is_ref_name`]
/// - a DEFLATE level outside 1 through 9
/// - a malformed `SOURCE_DATE_EPOCH` if `timestamp` is not set, and a system
///   clock before the Unix epoch if neither is set
/// - an empty key in `metadata` or in `detached_metadata`, entries that do not
///   serialize as an `a{sv}` dict, and entries whose serialized dict is more
///   than [`MAX_METADATA_SIZE`]
/// - a `subject`, a `body`, and `metadata` whose commit object is more than
///   `MAX_METADATA_SIZE` without the bindings and without a parent of
///   [`ParentPolicy::CurrentTip`]
///
/// A revision cannot name a ref that holds `^`, because it reads `^` as the
/// parent of a commit. It also cannot name a ref of 64 lowercase hex
/// characters, because it reads that name as a commit checksum.
///
/// The bindings and a parent from the server only add bytes to the commit
/// object. As a result, the size check before the scan never refuses a commit
/// object that the check after `HelloReply` accepts.
///
/// The push reads the timestamp before the scan. The scan refuses `hash_jobs`
/// of `Some(0)` before the walk starts. If the push refuses a value, or if
/// the walk or the hash pass fails, the push writes nothing.
///
/// # Commit
///
/// After `HelloReply`, the push builds the commit object:
///
/// - The parent comes from [`ParentPolicy`].
/// - The metadata dict holds the entries of `metadata`, in order. Then it
///   holds `ostree.ref-binding` with the target refs sorted. Then it holds
///   `ostree.collection-binding` with the collection id of the server, if the
///   server has one.
/// - With `no_bindings`, the dict holds the entries of `metadata` alone.
///
/// The dict follows the rule of [`ostrya_core::commit_metadata`]. As a result,
/// the commit checksum equals the checksum of the commit that
/// `Transaction::write_commit` of `ostrya` writes over the same tree with the
/// same inputs.
///
/// # Ref states
///
/// Without `force`, each target ref must have the state of the first target
/// ref on the server: all absent, or all at one commit. If the target refs
/// are in mixed states, the push offers no object. The message of the error
/// names each ref and its commit.
///
/// # Signatures
///
/// The push signs the serialized commit with each signer of `signers`, in
/// order, while the session is open. It checks the key of each signer before
/// the first signer signs.
///
/// The detached metadata dict holds the entries of `detached_metadata`, in
/// order. Then it holds each signature under the
/// [`metadata_key`](ostrya_sign::Signer::metadata_key) of its signer. If the
/// dict is empty, the push sends no detached metadata.
///
/// A signature goes into the `aay` array of its key, after the blobs that the
/// array already holds. This is also the rule if the array is an entry of
/// `detached_metadata`.
///
/// # Objects and refs
///
/// The push offers each object of the tree and the commit in one round of
/// `Have`. It sends the objects that the server lacks. It sends the detached
/// metadata of the commit also if the server holds the commit.
///
/// Each ref update expects the state that `HelloReply` reported for its ref:
/// the commit of the ref, or an absent ref. With `force`, each update expects
/// any state, and `Commit` carries `force`. [`PushOutcome::commit`] holds the
/// commit.
///
/// The server verifies each object. If the bytes of a file change after the
/// hash pass, the server sends an `Error` message and no ref changes.
///
/// # Failures
///
/// A failure after the session opens and before `Commit` ends the session, and
/// the push returns that failure. If the stream is still usable, the push
/// writes `Abort`. Over HTTP, the push ends the session with `DELETE`.
/// [`PushStats::elapsed`](crate::session::PushStats::elapsed)
/// covers the session alone.
///
/// # Errors
///
/// - [`Error::InvalidInput`] for each value of [Refusals](#refusals), and if
///   `hash_jobs` is `Some(0)`.
/// - [`Error::InvalidInput`] if the target refs are in mixed states on the
///   server without `force`.
/// - [`Error::InvalidInput`] if the commit object or the detached metadata
///   dict is more than [`MAX_METADATA_SIZE`].
/// - [`Error::Walk`] if the walk or the hash pass fails. [`TreeModel::scan`]
///   gives the `io::ErrorKind` of each case.
/// - [`Error::Source`] if the send pass cannot open or read a file of the
///   tree. The error of a failed open is the [`Error::Walk`] of that file.
/// - [`Error::Sign`] if a signer fails, or if `detached_metadata` holds a
///   value that is not an `aay` under the key of a signer.
/// - [`Error::Protocol`] or [`Error::LimitExceeded`] if the codec refuses a
///   frame of the session.
/// - [`Error::Io`] for an I/O error of `input` or `output`.
/// - [`Error::CommitOutcomeUnknown`] if the session ends after `Commit` with
///   no reply that the client can read.
/// - An `Error` message from the server, as the [`Error`] variant of its code.
///   An example is [`Error::RefMismatch`] if a target ref is not in the state
///   that `HelloReply` reported.
///
/// [`Error`]: crate::Error
/// [`Error::InvalidInput`]: crate::Error::InvalidInput
/// [`Error::Walk`]: crate::Error::Walk
/// [`Error::Source`]: crate::Error::Source
/// [`Error::Sign`]: crate::Error::Sign
/// [`Error::Protocol`]: crate::Error::Protocol
/// [`Error::LimitExceeded`]: crate::Error::LimitExceeded
/// [`Error::Io`]: crate::Error::Io
/// [`Error::CommitOutcomeUnknown`]: crate::Error::CommitOutcomeUnknown
/// [`Error::RefMismatch`]: crate::Error::RefMismatch
pub async fn push_tree_over_stream<R, W>(
    input: R,
    output: W,
    root: &Path,
    opts: TreePushOptions,
) -> Result<PushOutcome>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (scan, push) = Prepared::new(opts)?;
    let model = push.scan(root, scan).await?;
    let session =
        PushSession::over_stream(input, output, &push.refs, push.session_options()).await?;
    push.run(session, model).await
}

/// The checked options of a tree push, without the options of the scan.
struct Prepared {
    refs: Vec<String>,
    parent: ParentPolicy,
    subject: String,
    body: String,
    /// The entries of the metadata dict, checked.
    metadata: Vec<Value>,
    /// The entries of the detached metadata dict, checked.
    detached: Vec<Value>,
    timestamp: u64,
    no_bindings: bool,
    signers: Vec<Box<dyn ostrya_sign::Signer>>,
    compression: Compression,
    force: bool,
    progress: Option<PushProgress>,
}

impl Prepared {
    /// Checks `opts` and resolves the timestamp. Returns the options of the
    /// scan as a separate value, because the entry filter is not `Sync`.
    fn new(opts: TreePushOptions) -> Result<(ScanOptions, Prepared)> {
        let TreePushOptions {
            refs,
            parent,
            subject,
            body,
            metadata,
            detached_metadata,
            timestamp,
            no_bindings,
            signers,
            compression,
            entry_filter,
            hash_jobs,
            force,
            progress,
        } = opts;
        check_refs(&refs)?;
        deflate_level(compression)?;
        let timestamp = ostrya_core::commit_timestamp(timestamp)
            .map_err(|e| invalid(format!("the commit timestamp: {e}")))?;
        let (metadata, metadata_len) = entry_dict(metadata, "metadata")?;
        let (detached, _) = entry_dict(detached_metadata, "detached metadata")?;
        let subject = subject.unwrap_or_default();
        let body = body.unwrap_or_default();
        let floor = commit_size_floor(metadata_len, &subject, &body, parent);
        check_commit_floor(floor, MAX_METADATA_SIZE)?;
        let scan = ScanOptions {
            entry_filter,
            hash_jobs,
        };
        let push = Prepared {
            refs,
            parent,
            subject,
            body,
            metadata,
            detached,
            timestamp,
            no_bindings,
            signers,
            compression,
            force,
            progress,
        };
        Ok((scan, push))
    }

    /// Walks and hashes the tree at `root`, and sets the phases of the scan
    /// in the progress handle.
    async fn scan(&self, root: &Path, scan: ScanOptions) -> Result<TreeModel> {
        TreeModel::scan_with(root, scan, self.progress.as_ref()).await
    }

    /// Scans the tree at `root`, opens `transport`, and runs the push.
    async fn scan_and_run(
        self,
        transport: PreparedSession,
        root: &Path,
        scan: ScanOptions,
    ) -> Result<PushOutcome> {
        let model = self.scan(root, scan).await?;
        let session = transport.open(&self.refs, self.session_options()).await?;
        self.run(session, model).await
    }

    fn session_options(&self) -> SessionOptions {
        SessionOptions {
            progress: self.progress.clone(),
            ..SessionOptions::default()
        }
    }

    /// Runs the push over `session`. A failure before `Commit` ends the
    /// session, with `Abort` if the stream is still usable.
    async fn run(self, session: PushSession, model: TreeModel) -> Result<PushOutcome> {
        let force = self.force;
        match self.upload(&session, model).await {
            Ok((commit, updates)) => {
                let mut outcome = session.commit(&updates, force).await?;
                outcome.commit = Some(commit);
                Ok(outcome)
            }
            Err(e) => {
                let _ = session.abort().await;
                Err(e)
            }
        }
    }

    /// Checks the ref states, builds the commit, runs the one `Have` round,
    /// and sends the objects. Returns the commit and the ref updates of
    /// `Commit`.
    async fn upload(
        self,
        session: &PushSession,
        mut model: TreeModel,
    ) -> Result<(Checksum, Vec<RefUpdate>)> {
        let server = session.server();
        if !self.force {
            check_ref_states(server, &self.refs)?;
        }
        let (commit, bytes) = build_commit(CommitInputs {
            parent: resolve_parent(self.parent, server, &self.refs),
            subject: self.subject,
            body: self.body,
            timestamp: self.timestamp,
            metadata: self.metadata,
            refs: &self.refs,
            no_bindings: self.no_bindings,
            collection_id: server.collection_id.as_deref(),
            root_dirtree: model.root_dirtree(),
            root_dirmeta: model.root_dirmeta(),
        })?;
        let detached = detached_dict(self.detached, &self.signers, &bytes).await?;
        model.set_commit(commit, bytes, detached);
        let names = model.objects(&commit).await?;
        let missing = session.missing(&names).await?;
        drop(names);
        session
            .send(&model, &missing, &[commit], self.compression)
            .await?;
        Ok((commit, ref_updates(server, &self.refs, commit, self.force)))
    }
}

/// Refuses empty `refs`, a ref that holds `:`, a ref that holds `^`, a ref
/// that fails the ref-name rule, a ref of 64 lowercase hex characters, and a
/// ref named twice.
fn check_refs(refs: &[String]) -> Result<()> {
    if refs.is_empty() {
        return Err(invalid("a tree push needs at least one target ref"));
    }
    let mut seen = HashSet::new();
    for name in refs {
        if name.contains(':') {
            return Err(invalid(format!(
                "ref '{name}' holds ':'; a tree push sets refs below refs/heads"
            )));
        }
        if name.contains('^') {
            return Err(invalid(format!(
                "ref '{name}' holds '^', which a revision reads as the parent of a commit"
            )));
        }
        if !ostrya_core::is_ref_name(name) {
            return Err(invalid(format!("ref '{name}' is not a valid ref name")));
        }
        if ostrya_core::is_checksum_shaped(name) {
            return Err(invalid(format!(
                "ref '{name}' is 64 hex characters, which a revision reads as a commit checksum"
            )));
        }
        if !seen.insert(name.as_str()) {
            return Err(invalid(format!("ref '{name}' is named twice")));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    fn refused(opts: TreePushOptions) -> String {
        match Prepared::new(opts) {
            Err(Error::InvalidInput(m)) => m,
            Err(e) => panic!("{e:?}"),
            Ok(_) => panic!("accepted"),
        }
    }

    fn with_refs(refs: &[&str]) -> TreePushOptions {
        TreePushOptions {
            refs: refs.iter().map(|s| s.to_string()).collect(),
            timestamp: Some(1),
            ..Default::default()
        }
    }

    #[test]
    fn the_target_refs_are_checked_before_the_scan() {
        assert!(refused(with_refs(&[])).contains("at least one"));
        assert!(refused(with_refs(&["a", "b", "a"])).contains("twice"));
        assert!(refused(with_refs(&["origin:main"])).contains("':'"));
        assert!(refused(with_refs(&["main", "o:a:b"])).contains("':'"));
        for caret in ["main^", "a^b", "^", "x/y^"] {
            assert!(
                refused(with_refs(&["main", caret])).contains("'^'"),
                "{caret}"
            );
        }
        for bad in ["", "/a", "a/", "a//b", ".", "..", "a/../b", "a\0b"] {
            assert!(
                refused(with_refs(&[bad])).contains("not a valid ref name"),
                "{bad:?}"
            );
        }
        let hex = "ab".repeat(32);
        assert!(refused(with_refs(&["main", &hex])).contains("commit checksum"));
        Prepared::new(with_refs(&[
            "main",
            "a/b",
            "x.y",
            &hex.to_uppercase(),
            &hex[1..],
        ]))
        .unwrap();
    }

    #[test]
    fn the_other_options_are_checked_before_the_scan() {
        for level in [0, 10] {
            let m = refused(TreePushOptions {
                compression: Compression::Deflate { level },
                ..with_refs(&["main"])
            });
            assert!(m.contains("compression level"), "{m}");
        }
        let variant = Value::variant(ostrya_core::Type::Str, Value::Str("v".into()));
        let m = refused(TreePushOptions {
            metadata: vec![(String::new(), variant.clone())],
            ..with_refs(&["main"])
        });
        assert!(m.contains("metadata holds an empty key"), "{m}");
        let m = refused(TreePushOptions {
            detached_metadata: vec![(String::new(), variant)],
            ..with_refs(&["main"])
        });
        assert!(m.contains("detached metadata holds an empty key"), "{m}");
        let m = refused(TreePushOptions {
            metadata: vec![("k".into(), Value::Str("bare".into()))],
            ..with_refs(&["main"])
        });
        assert!(m.contains("not an a{sv} dict"), "{m}");
    }

    #[test]
    fn the_scan_shows_scanning_during_the_walk_and_hashing_after_it() {
        use std::sync::{Arc, Mutex};

        use crate::PushPhase;
        use crate::tree::EntryAction;

        let root =
            std::env::temp_dir().join(format!("ostrya-push-scan-phases-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("dir")).unwrap();
        std::fs::write(root.join("dir/file"), b"file").unwrap();
        // A reused handle holds the phase of an earlier push.
        let progress = PushProgress::new();
        progress.set_phase(PushPhase::Committing);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = (seen.clone(), progress.clone());
        let filter: EntryFilter = Box::new(move |_path, _meta| {
            record.0.lock().unwrap().push(record.1.snapshot().phase);
            EntryAction::Keep
        });
        let scan = ScanOptions {
            entry_filter: Some(filter),
            hash_jobs: None,
        };
        let model = ostrya_rt::block_on(TreeModel::scan_with(&root, scan, Some(&progress)));
        let _ = std::fs::remove_dir_all(&root);
        model.unwrap();
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 3, "{seen:?}");
        assert!(seen.iter().all(|p| *p == PushPhase::Scanning), "{seen:?}");
        assert_eq!(progress.snapshot().phase, PushPhase::Hashing);
    }

    #[test]
    fn the_given_timestamp_wins() {
        let (_, push) = Prepared::new(TreePushOptions {
            timestamp: Some(42),
            ..with_refs(&["main"])
        })
        .unwrap();
        assert_eq!(push.timestamp, 42);
    }
}
