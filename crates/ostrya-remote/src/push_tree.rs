//! The push of a local directory: the walk and the hash pass, and one session
//! that sends the objects that the server lacks and asks the server to commit
//! the tree.

use std::collections::HashSet;
use std::path::Path;

use futures_io::{AsyncRead, AsyncWrite};
use ostrya_core::{Checksum, Type, Value};

use crate::error::{Error, Result};
use crate::proto::ServerCommit;
use crate::session::{
    Compression, PushOutcome, PushProgress, PushSession, ServerInfo, SessionOptions, deflate_level,
    invalid,
};
use crate::transport::{Endpoint, PreparedSession};
use crate::tree::{EntryFilter, ScanOptions, TreeModel};

/// The longest collection id, in bytes. The server writes the refs of a
/// collection under one directory of that name.
const MAX_COLLECTION_ID_LEN: usize = 255;

/// The metadata keys of the bindings, which the server writes.
const BINDING_KEYS: [&str; 2] = ["ostree.ref-binding", "ostree.collection-binding"];

/// The options of a tree push.
///
/// [`push_tree`], [`push_tree_prepared`], and [`push_tree_over_stream`] take
/// them. The struct carries no `#[non_exhaustive]`. A caller builds it with
/// `..Default::default()`.
#[derive(Default)]
pub struct TreePushOptions {
    /// The branch of the server that the server moves to the new commit.
    ///
    /// The parent of the commit is the commit of the branch on the server
    /// when the server writes the commit. If the branch is absent, the commit
    /// has no parent.
    pub onto: String,
    /// The tags that the server creates at the new commit, in order.
    ///
    /// A tag that exists on the server refuses the push.
    pub tags: Vec<String>,
    /// The names that the commit binds and that get no ref, in order.
    ///
    /// The `ostree.ref-binding` of the commit holds the branch, each tag, and
    /// each of these names.
    pub bind_refs: Vec<String>,
    /// The switch that makes a commit with no parent.
    ///
    /// On a branch that exists, the server allows it only for a client that
    /// can also delete the branch.
    pub orphan: bool,
    /// The collection id of the namespace of the server that the push
    /// writes.
    ///
    /// `None` writes the local refs of the server. The collection id of the
    /// server also writes its local refs.
    pub collection: Option<String>,
    /// The subject of the commit, empty if not set.
    pub subject: Option<String>,
    /// The body of the commit, empty if not set.
    pub body: Option<String>,
    /// The entries of the `a{sv}` metadata dict of the commit, in order.
    ///
    /// Each value is a variant. The server writes the bindings after the
    /// entries.
    pub metadata: Vec<(String, Value)>,
    /// The timestamp of the commit, in seconds since the Unix epoch, UTC.
    ///
    /// If this field is not set, the server takes its clock. The push reads
    /// no environment variable.
    pub timestamp: Option<u64>,
    /// The encoding of the content objects.
    pub compression: Compression,
    /// The filter that sees each entry of the walk.
    pub entry_filter: Option<EntryFilter>,
    /// The maximum number of regular files that the hash pass reads at one
    /// time.
    ///
    /// [`ScanOptions::hash_jobs`] gives the default and the limits.
    pub hash_jobs: Option<usize>,
    /// The progress handle of the scan and of the session.
    ///
    /// The scan sets its phases in the handle, and the session counts its
    /// progress into it.
    pub progress: Option<PushProgress>,
}

/// Pushes the directory `root` to `endpoint` as one server commit.
///
/// The server makes the commit over the tree, moves the branch to it, and
/// creates each tag at it, in one transaction. The push runs in this order:
///
/// 1. It checks `opts` and refuses each value that [`push_tree_over_stream`]
///    refuses. Then it makes the transport ready with
///    [`PushSession::prepare`]. For ssh, it builds the command line. For
///    HTTP, it builds the HTTP client.
/// 2. It walks and hashes the tree with [`TreeModel::scan`], with
///    `entry_filter` and `hash_jobs`.
/// 3. It starts the ssh client, or sends the first HTTP request. It opens the
///    session with the branch and the tags in one `Hello`.
/// 4. It offers each object of the tree in one round of `Have`. It sends the
///    objects that the server lacks, and then it sends `Commit` with the
///    server commit.
///
/// A refusal of the options, a walk error, and a hash error start no ssh
/// client, send no request, and open no session. [`push_tree_over_stream`]
/// gives the rules of the server commit and of the session.
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
/// - [`Error::InvalidInput`] if the ssh command or the receive command is
///   empty or holds only white space, or if the value of `OSTRYA_SSH_COMMAND`
///   is not UTF-8. The [empty values](crate::SshOptions#empty-values) give
///   the full rule.
/// - [`Error::InvalidInput`] if the options of an HTTP endpoint do not name
///   exactly one mirror, or if
///   [`check_base_url`](ostrya_fetch::check_base_url) refuses the mirror.
/// - [`Error::Fetch`] if [`Fetcher::new`](ostrya_fetch::Fetcher::new) refuses
///   the options of an HTTP endpoint, for example a credential to an
///   `http://` address without `allow_cleartext_credentials`.
///
/// [`Error::InvalidInput`]: crate::Error::InvalidInput
/// [`Error::Fetch`]: crate::Error::Fetch
pub async fn push_tree(
    endpoint: Endpoint,
    root: &Path,
    opts: TreePushOptions,
) -> Result<PushOutcome> {
    let (scan, push) = Prepared::new(opts)?;
    let transport = PushSession::prepare(endpoint).await?;
    push.scan_and_run(transport, root, scan).await
}

/// Pushes the directory `root` as one server commit over a prepared
/// transport.
///
/// `session` is a transport that [`PushSession::prepare`] made ready. The
/// push is that of [`push_tree`] with the transport checks done first, so a
/// caller can do them before the work that builds `opts`. For example, the
/// caller can read a large body file after the checks.
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

/// Pushes the directory `root` as one server commit over a pair of byte
/// streams.
///
/// `input` comes from the server, and `output` goes to it. The push scans
/// the tree before it writes the first byte to `output`.
///
/// # Refusals
///
/// Before the scan, the push refuses these values of `opts`:
///
/// - a branch or a tag that holds `:`, that fails the ref-name rule of
///   [`is_ref_name`](ostrya_core::is_ref_name), for example a name that holds
///   `^`, or that is 64 lowercase hex characters, which a revision reads as
///   a commit checksum
/// - a tag that is the branch, and a tag named twice
/// - a bound name that holds `:` or that fails the ref-name rule
/// - a `collection` that fails
///   [`is_collection_id`](ostrya_core::is_collection_id) or is longer than
///   255 bytes
/// - a DEFLATE level outside 1 through 9
/// - an empty key in `metadata`, the key `ostree.ref-binding` or
///   `ostree.collection-binding`, which the server writes, and a value that
///   is not a variant
///
/// The scan refuses `hash_jobs` of `Some(0)` before the walk starts. If the
/// push refuses a value, or if the walk or the hash pass fails, the push
/// writes nothing.
///
/// # Server commit
///
/// The session opens with the branch and then each tag. The push sends
/// [`collection`](TreePushOptions::collection) in `Hello`. After `HelloReply`,
/// the push refuses a tag that the server holds with
/// [`Error::RefMismatch`]. Then it runs
/// [`PushSession::check_server_commit`]: a commit must hold each metadata
/// value, and the `Commit` frame of the server commit and the longest
/// `CommitReply` must fit in the `max-frame` of the server. Each refusal
/// comes before the push offers an object.
///
/// The push offers each object of the tree in one round of `Have`, and sends
/// the objects that the server lacks. It sends no commit object and no
/// detached metadata. Then it sends the server commit with the root dirtree
/// and the root dirmeta of the tree, the subject, the body, the entries of
/// `metadata`, the timestamp, the tags, the bound names, and `orphan`.
///
/// The server reads the tip of the branch and writes the commit with that tip
/// as its parent, the bindings of its namespace, and the keys of its own
/// signing rule. [`PushOutcome::commit`] holds the commit that the server
/// wrote.
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
/// - [`Error::Walk`] if the walk or the hash pass fails. [`TreeModel::scan`]
///   gives the `io::ErrorKind` of each case.
/// - [`Error::RefMismatch`] if `HelloReply` reports a commit for a tag.
/// - [`Error::InvalidInput`] if a commit cannot hold a value of `metadata`.
///   In a commit, a value can hold two levels of containers fewer than a
///   variant.
/// - [`Error::LimitExceeded`] if the `Commit` frame of the server commit, or
///   the longest `CommitReply` to it, is over the `max-frame` of the
///   server.
/// - [`Error::Source`] if the send pass cannot open or read a file of the
///   tree. The error of a failed open is the [`Error::Walk`] of that file.
/// - [`Error::Protocol`] or [`Error::LimitExceeded`] if the codec refuses a
///   frame of the session.
/// - [`Error::Io`] for an I/O error of `input` or `output`.
/// - [`Error::CommitOutcomeUnknown`] if the session ends after `Commit` with
///   no reply that the client can read.
/// - An `Error` message from the server, as the [`Error`] variant of its code.
///   An example is [`Error::RefDenied`] if the client has no `c` on the
///   branch, or if the server runs hooks, which take no server commit.
///
/// [`Error`]: crate::Error
/// [`Error::InvalidInput`]: crate::Error::InvalidInput
/// [`Error::Walk`]: crate::Error::Walk
/// [`Error::RefMismatch`]: crate::Error::RefMismatch
/// [`Error::LimitExceeded`]: crate::Error::LimitExceeded
/// [`Error::Source`]: crate::Error::Source
/// [`Error::Protocol`]: crate::Error::Protocol
/// [`Error::Io`]: crate::Error::Io
/// [`Error::CommitOutcomeUnknown`]: crate::Error::CommitOutcomeUnknown
/// [`Error::RefDenied`]: crate::Error::RefDenied
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

/// A tree that [`scan_tree`] walked and hashed, with the checked inputs of
/// its commit.
///
/// A writer that makes the commit itself takes this value in place of a
/// session. An example is the push of a tree to a bucket repository in the
/// `ostrya` crate.
#[non_exhaustive]
pub struct ScannedTree {
    /// The model of the tree, which is the source of its objects.
    pub model: TreeModel,
    /// The commit that the options describe.
    ///
    /// The root dirtree and the root dirmeta are those of
    /// [`model`](ScannedTree::model). The metadata entries are the bytes of
    /// each value as a `v` in normal form, in the order of the options. A
    /// commit can hold each value.
    pub commit: ServerCommit,
    /// The collection id of the namespace that the push writes, from
    /// [`TreePushOptions::collection`].
    pub collection: Option<String>,
    /// The encoding of the content objects, from
    /// [`TreePushOptions::compression`].
    pub compression: Compression,
    /// The progress handle, from [`TreePushOptions::progress`].
    pub progress: Option<PushProgress>,
}

/// Checks `opts` and scans the directory `root`, with no transport.
///
/// The call refuses each value that [`push_tree_over_stream`] refuses before
/// its scan, as its [Refusals](push_tree_over_stream#refusals) state. It also
/// refuses a metadata value that a commit cannot hold, which a session push
/// refuses after the session opens. It does not check the `max-frame` of a
/// server, which limits the `Commit` frame of a session push. The writer
/// applies its own size limit to the commit. Then it walks and hashes the
/// tree with [`TreeModel::scan`], with `entry_filter` and `hash_jobs`, and
/// sets the phases of the scan in the progress handle. The call sends nothing
/// and writes nothing.
///
/// # Errors
///
/// - [`Error::InvalidInput`] for each value of
///   [Refusals](push_tree_over_stream#refusals), and if `hash_jobs` is
///   `Some(0)`.
/// - [`Error::InvalidInput`] if a commit cannot hold a value of `metadata`.
///   In a commit, a value can hold two levels of containers fewer than a
///   variant.
/// - [`Error::Walk`] if the walk or the hash pass fails. [`TreeModel::scan`]
///   gives the `io::ErrorKind` of each case.
///
/// [`Error::InvalidInput`]: crate::Error::InvalidInput
/// [`Error::Walk`]: crate::Error::Walk
pub async fn scan_tree(root: &Path, opts: TreePushOptions) -> Result<ScannedTree> {
    let (scan, push) = Prepared::new(opts)?;
    crate::proto::check_server_commit_metadata(&push.commit)?;
    let model = push.scan(root, scan).await?;
    let Prepared {
        mut commit,
        collection,
        compression,
        progress,
        ..
    } = push;
    commit.root_dirtree = model.root_dirtree();
    commit.root_dirmeta = model.root_dirmeta();
    Ok(ScannedTree {
        model,
        commit,
        collection,
        compression,
        progress,
    })
}

/// The checked options of a tree push, without the options of the scan.
struct Prepared {
    /// The refs of `Hello`: the branch, then each tag.
    refs: Vec<String>,
    /// The server commit, with no root checksums before the scan.
    commit: ServerCommit,
    collection: Option<String>,
    compression: Compression,
    progress: Option<PushProgress>,
}

impl Prepared {
    /// Checks `opts`. Returns the options of the scan as a separate value,
    /// because the entry filter is not `Sync`.
    fn new(opts: TreePushOptions) -> Result<(ScanOptions, Prepared)> {
        let TreePushOptions {
            onto,
            tags,
            bind_refs,
            orphan,
            collection,
            subject,
            body,
            metadata,
            timestamp,
            compression,
            entry_filter,
            hash_jobs,
            progress,
        } = opts;
        check_names(&onto, &tags, &bind_refs)?;
        if let Some(id) = &collection {
            check_collection(id)?;
        }
        deflate_level(compression)?;
        let metadata = metadata_entries(metadata)?;
        let scan = ScanOptions {
            entry_filter,
            hash_jobs,
        };
        let refs = std::iter::once(onto.clone())
            .chain(tags.iter().cloned())
            .collect();
        // The scan gives the root checksums.
        let unset = Checksum::from_bytes([0; 32]);
        let push = Prepared {
            refs,
            commit: ServerCommit {
                branch: onto,
                tags,
                bind_refs,
                root_dirtree: unset,
                root_dirmeta: unset,
                subject: subject.unwrap_or_default(),
                body: body.unwrap_or_default(),
                metadata,
                timestamp,
                orphan,
            },
            collection,
            compression,
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
        // The future of the run is large. The box keeps it out of the future
        // of the push.
        Box::pin(self.run(session, model)).await
    }

    fn session_options(&self) -> SessionOptions {
        SessionOptions {
            collection: self.collection.clone(),
            progress: self.progress.clone(),
            ..SessionOptions::default()
        }
    }

    /// Runs the push over `session`. A failure before `Commit` ends the
    /// session, with `Abort` if the stream is still usable.
    async fn run(self, session: PushSession, model: TreeModel) -> Result<PushOutcome> {
        let mut commit = self.commit;
        commit.root_dirtree = model.root_dirtree();
        commit.root_dirmeta = model.root_dirmeta();
        match upload(&session, &model, &commit, self.compression).await {
            Ok(()) => {
                drop(model);
                session.server_commit(commit).await
            }
            Err(e) => {
                let _ = session.abort().await;
                Err(e)
            }
        }
    }
}

/// Runs the checks after `HelloReply`, the one `Have` round, and the upload
/// of the objects of `model` that the server lacks.
async fn upload(
    session: &PushSession,
    model: &TreeModel,
    commit: &ServerCommit,
    compression: Compression,
) -> Result<()> {
    check_tags_absent(session.server(), &commit.tags)?;
    session.check_server_commit(commit)?;
    let names = model.object_names();
    let missing = session.missing(&names).await?;
    drop(names);
    session.send(model, &missing, &[], compression).await
}

/// Refuses a tag that `server` reports at a commit, with
/// [`Error::RefMismatch`]. The server refuses it at `Commit` too.
fn check_tags_absent(server: &ServerInfo, tags: &[String]) -> Result<()> {
    match tags
        .iter()
        .find_map(|tag| server.tip(tag).map(|tip| (tag, tip)))
    {
        Some((tag, current)) => Err(Error::RefMismatch {
            message: format!("ref '{tag}' is at {current}"),
            name: tag.clone(),
            current: Some(current),
        }),
        None => Ok(()),
    }
}

/// Refuses a name of a ref that the server commit writes: a name that holds
/// `:`, a name that fails the ref-name rule (which includes a name that holds
/// `^`), and a name of 64 lowercase hex characters. `what` names the ref in
/// the message.
fn check_ref(name: &str, what: &str) -> Result<()> {
    if name.contains(':') {
        return Err(invalid(format!(
            "{what} '{name}' holds ':'; a tree push writes refs below refs/heads"
        )));
    }
    if !ostrya_core::is_ref_name(name) {
        return Err(invalid(format!("{what} '{name}' is not a valid ref name")));
    }
    if ostrya_core::is_checksum_shaped(name) {
        return Err(invalid(format!(
            "{what} '{name}' is 64 hex characters, which a revision reads as a commit checksum"
        )));
    }
    Ok(())
}

/// Refuses a bad branch, a bad tag, a tag that is the branch, a tag named
/// twice, and a bound name that holds `:` or fails the ref-name rule.
fn check_names(onto: &str, tags: &[String], bind_refs: &[String]) -> Result<()> {
    check_ref(onto, "branch")?;
    let mut seen = HashSet::new();
    for tag in tags {
        check_ref(tag, "tag")?;
        if tag == onto {
            return Err(invalid(format!("the tag '{tag}' is also the branch")));
        }
        if !seen.insert(tag.as_str()) {
            return Err(invalid(format!("the tag '{tag}' is named twice")));
        }
    }
    for name in bind_refs {
        if name.contains(':') || !ostrya_core::is_ref_name(name) {
            return Err(invalid(format!(
                "bound name '{name}' is not a valid ref name"
            )));
        }
    }
    Ok(())
}

/// Refuses a collection id that fails the collection-id rule or is longer
/// than [`MAX_COLLECTION_ID_LEN`] bytes.
fn check_collection(id: &str) -> Result<()> {
    if id.len() > MAX_COLLECTION_ID_LEN {
        return Err(invalid(format!(
            "the collection id of {} bytes is longer than {MAX_COLLECTION_ID_LEN} bytes",
            id.len()
        )));
    }
    if !ostrya_core::is_collection_id(id) {
        return Err(invalid(format!("invalid collection id '{id}'")));
    }
    Ok(())
}

/// Returns the metadata entries of a server commit: each key with the bytes of
/// its value as a `v` in normal form, in order.
///
/// An empty key, a binding key, and a value that is not a variant are
/// [`Error::InvalidInput`].
fn metadata_entries(entries: Vec<(String, Value)>) -> Result<Vec<(String, Vec<u8>)>> {
    entries
        .into_iter()
        .map(|(key, value)| {
            if key.is_empty() {
                return Err(invalid("the metadata holds an empty key"));
            }
            if BINDING_KEYS.contains(&key.as_str()) {
                return Err(invalid(format!(
                    "the metadata holds the key '{key}', which the server writes"
                )));
            }
            let bytes = ostrya_core::to_bytes(&Type::Variant, &value).map_err(|e| {
                invalid(format!(
                    "the metadata value under '{key}' is not a variant: {e}"
                ))
            })?;
            Ok((key, bytes))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(opts: TreePushOptions) -> String {
        match Prepared::new(opts) {
            Err(Error::InvalidInput(m)) => m,
            Err(e) => panic!("{e:?}"),
            Ok(_) => panic!("accepted"),
        }
    }

    fn onto(branch: &str) -> TreePushOptions {
        TreePushOptions {
            onto: branch.into(),
            timestamp: Some(1),
            ..Default::default()
        }
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    const BAD_NAMES: [&str; 16] = [
        "", "main^", "a^b", "^", "x/y^", "/a", "a/", "a//b", ".", "..", "a/../b", "a\0b", "a b",
        "a*", "-a", "a/.b",
    ];

    #[test]
    fn the_branch_and_the_tags_are_checked_before_the_scan() {
        let hex = "ab".repeat(32);
        for (what, make) in [
            (
                "branch",
                (|name: &str| onto(name)) as fn(&str) -> TreePushOptions,
            ),
            ("tag", |name: &str| TreePushOptions {
                tags: strings(&[name]),
                ..onto("main")
            }),
        ] {
            assert!(refused(make("origin:main")).contains("':'"), "{what}");
            for bad in BAD_NAMES {
                let m = refused(make(bad));
                assert!(m.contains("not a valid ref name"), "{what} {bad:?}: {m}");
                assert!(m.starts_with(what), "{what} {bad:?}: {m}");
            }
            assert!(refused(make(&hex)).contains("commit checksum"), "{what}");
        }
        let m = refused(TreePushOptions {
            tags: strings(&["t", "main"]),
            ..onto("main")
        });
        assert!(m.contains("'main' is also the branch"), "{m}");
        let m = refused(TreePushOptions {
            tags: strings(&["t", "u", "t"]),
            ..onto("main")
        });
        assert!(m.contains("'t' is named twice"), "{m}");
        let (_, push) = Prepared::new(TreePushOptions {
            tags: strings(&["a/b", "x.y", &hex.to_uppercase(), &hex[1..]]),
            ..onto("main")
        })
        .unwrap();
        assert_eq!(
            push.refs,
            ["main", "a/b", "x.y", &hex.to_uppercase(), &hex[1..]]
        );
    }

    #[test]
    fn a_bound_name_passes_the_ref_name_rule_with_no_colon() {
        for bad in BAD_NAMES.iter().copied().chain(["o:main"]) {
            let m = refused(TreePushOptions {
                bind_refs: strings(&[bad]),
                ..onto("main")
            });
            assert!(m.contains("bound name"), "{bad:?}: {m}");
        }
        // A bound name can repeat, can be the branch, and can be 64 hex
        // characters, because it gets no ref.
        let hex = "ab".repeat(32);
        let (_, push) = Prepared::new(TreePushOptions {
            bind_refs: strings(&["x", "x", "main", &hex]),
            ..onto("main")
        })
        .unwrap();
        assert_eq!(push.commit.bind_refs, ["x", "x", "main", hex.as_str()]);
        assert_eq!(push.refs, ["main"]);
    }

    #[test]
    fn the_collection_is_checked_before_the_scan() {
        let longest = format!("org.{}", "a".repeat(251));
        let over = format!("org.{}", "a".repeat(252));
        for (id, needle) in [("no-dot", "invalid collection id"), (&*over, "256 bytes")] {
            let m = refused(TreePushOptions {
                collection: Some(id.into()),
                ..onto("main")
            });
            assert!(m.contains(needle), "{m}");
        }
        let (_, push) = Prepared::new(TreePushOptions {
            collection: Some(longest.clone()),
            ..onto("main")
        })
        .unwrap();
        assert_eq!(push.session_options().collection, Some(longest));
    }

    #[test]
    fn the_other_options_are_checked_before_the_scan() {
        for level in [0, 10] {
            let m = refused(TreePushOptions {
                compression: Compression::Deflate { level },
                ..onto("main")
            });
            assert!(m.contains("compression level"), "{m}");
        }
        let variant = Value::variant(ostrya_core::Type::Str, Value::Str("v".into()));
        let m = refused(TreePushOptions {
            metadata: vec![(String::new(), variant.clone())],
            ..onto("main")
        });
        assert!(m.contains("metadata holds an empty key"), "{m}");
        for key in BINDING_KEYS {
            let m = refused(TreePushOptions {
                metadata: vec![("k".into(), variant.clone()), (key.into(), variant.clone())],
                ..onto("main")
            });
            assert!(
                m.contains(&format!("'{key}', which the server writes")),
                "{m}"
            );
        }
        let m = refused(TreePushOptions {
            metadata: vec![("k".into(), Value::Str("bare".into()))],
            ..onto("main")
        });
        assert!(m.contains("not a variant"), "{m}");
    }

    #[test]
    fn the_server_commit_carries_the_options() {
        let string = |s: &str| Value::variant(ostrya_core::Type::Str, Value::Str(s.into()));
        let (_, push) = Prepared::new(TreePushOptions {
            tags: strings(&["t"]),
            bind_refs: strings(&["b"]),
            orphan: true,
            subject: Some("s".into()),
            body: Some("m".into()),
            metadata: vec![("z".into(), string("1")), ("a".into(), string("2"))],
            timestamp: Some(42),
            ..onto("main")
        })
        .unwrap();
        let sc = push.commit;
        assert_eq!(sc.branch, "main");
        assert_eq!(sc.tags, ["t"]);
        assert_eq!(sc.bind_refs, ["b"]);
        assert!(sc.orphan);
        assert_eq!((sc.subject.as_str(), sc.body.as_str()), ("s", "m"));
        let v = |value: &Value| ostrya_core::to_bytes(&Type::Variant, value).unwrap();
        assert_eq!(
            sc.metadata,
            [
                ("z".to_owned(), v(&string("1"))),
                ("a".to_owned(), v(&string("2")))
            ]
        );
        assert_eq!(sc.timestamp, Some(42));
        let (_, push) = Prepared::new(TreePushOptions {
            timestamp: None,
            ..onto("main")
        })
        .unwrap();
        assert_eq!(push.commit.timestamp, None);
        assert_eq!(push.commit.subject, "");
    }

    #[test]
    fn a_tag_that_the_server_holds_is_ref_mismatch() {
        use crate::proto::{Encoding, RefState};
        let tip = Checksum::from_bytes([5; 32]);
        let server = ServerInfo {
            version: 1,
            mode: "archive".into(),
            collection_id: None,
            collection: None,
            max_frame: 1 << 20,
            max_have: 16_384,
            encodings: vec![Encoding::Raw],
            parallel_uploads: 1,
            refs: [("main", Some(tip)), ("a", None), ("b", Some(tip))]
                .into_iter()
                .map(|(name, commit)| RefState {
                    name: name.into(),
                    commit,
                })
                .collect(),
        };
        check_tags_absent(&server, &strings(&["a"])).unwrap();
        match check_tags_absent(&server, &strings(&["a", "b"])) {
            Err(Error::RefMismatch { name, current, .. }) => {
                assert_eq!(name, "b");
                assert_eq!(current, Some(tip));
            }
            other => panic!("{other:?}"),
        }
    }

    /// `scan_tree` refuses a metadata value that a commit cannot hold before
    /// the walk, and gives the commit the root checksums of the model.
    #[test]
    fn scan_tree_checks_the_depth_and_fills_the_roots() {
        let root =
            std::env::temp_dir().join(format!("ostrya-remote-scan-tree-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("dir")).unwrap();
        std::fs::write(root.join("dir/file"), b"file").unwrap();
        let deep = (0..126).fold(Value::Byte(1), |value, _| {
            Value::Maybe(Some(Box::new(value)))
        });
        let ty = (0..126).fold(Type::Byte, |ty, _| Type::maybe(ty));
        let absent = root.join("absent");
        // The walk root is absent, so a refusal shows that the check runs
        // before the walk.
        match ostrya_rt::block_on(scan_tree(
            &absent,
            TreePushOptions {
                metadata: vec![("deep".into(), Value::variant(ty, deep))],
                ..onto("main")
            },
        )) {
            Err(Error::InvalidInput(m)) => assert!(m.contains("cannot hold"), "{m}"),
            other => panic!("{:?}", other.map(|_| ())),
        }
        let scanned = ostrya_rt::block_on(scan_tree(
            &root,
            TreePushOptions {
                collection: Some("org.example.A".into()),
                compression: Compression::Deflate { level: 3 },
                ..onto("main")
            },
        ));
        let _ = std::fs::remove_dir_all(&root);
        let scanned = scanned.unwrap();
        assert_eq!(scanned.commit.root_dirtree, scanned.model.root_dirtree());
        assert_eq!(scanned.commit.root_dirmeta, scanned.model.root_dirmeta());
        assert_eq!(scanned.commit.branch, "main");
        assert_eq!(scanned.commit.timestamp, Some(1));
        assert_eq!(scanned.collection.as_deref(), Some("org.example.A"));
        assert_eq!(scanned.compression, Compression::Deflate { level: 3 });
        // Two dirtrees, one dirmeta that the two directories share, and the
        // file.
        assert_eq!(scanned.model.object_names().len(), 4);
    }

    #[test]
    fn the_scan_shows_scanning_during_the_walk_and_hashing_after_it() {
        use std::sync::{Arc, Mutex};

        use crate::PushPhase;
        use crate::tree::EntryAction;

        let root =
            std::env::temp_dir().join(format!("ostrya-remote-scan-phases-{}", std::process::id()));
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
}
