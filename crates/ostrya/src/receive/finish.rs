//! The `Commit` message that ends a push session.
//!
//! This module holds the checks of the ref updates and the server
//! signatures. It also holds the hooks of the host, the update lock, the ref
//! writes, the transaction commit, and the summary.

use std::any::Any;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::os::fd::AsFd;
use std::sync::Arc;

use ostrya_core::{
    Checksum, Commit, ObjectName, ObjectType, Type, Value, loose_path, to_bytes, validate,
};

use super::ancestry::{Parents, Walks};
use super::hooks::{self, HookRefusal, HostEntry, ReceiveHooks, UpdatePlan};
use super::merge::{
    SIGNATURE_KEYS, check_stored, merge_detached, replace_entries, signature_keys_in,
};
use super::session::{Failure, ReceiveReport, ReceiveStep, ReceiveWarning};
use super::walk::{self, Missing};
use super::{ReceivePolicy, ReceiveRule, ReceiveVerify, ServerSigner, TrustedKeys};
use crate::MAX_METADATA_SIZE;
use crate::error::{Error, Result};
use crate::object::read_meta_object;
use crate::push::proto::{CommitRequest, MAX_FRAME, Message};
use crate::push::{self, Expected, RefOutcome, RefUpdate};
use crate::refs::{RefFileState, refspec_to_relpath};
use crate::repo::Repo;
use crate::sign::append_signature;
use crate::summary::{
    OSTREE_METADATA_REF, SUMMARY_FILE, SUMMARY_SIG_FILE, SummaryOptions, parse_signature_dict,
    serialize_signature_dict,
};
use crate::transaction::Transaction;
use crate::write::flat_name;

/// The detached-metadata key of GPG signatures. The `ostree` command writes
/// the summary signatures of this key first in `summary.sig`, and ostrya does
/// the same. `docs/format-reference.md`, "Summary signature", records this
/// order.
const GPG_KEY: &str = "ostree.gpgsigs";

type Checked<T> = std::result::Result<T, Failure>;

/// A serialized detached-metadata dict, shared with the blocking pool.
type Bytes = Arc<Vec<u8>>;

fn protocol(message: String) -> Failure {
    Failure::Wire(push::Error::Protocol(message))
}

fn ref_denied(message: String) -> Failure {
    Failure::Wire(push::Error::RefDenied(message))
}

/// A commit that a ref update names as its new value.
struct Target {
    checksum: Checksum,
    /// The serialized commit, the payload of its signatures.
    bytes: Vec<u8>,
    commit: Commit,
    /// The index of each ref update whose new value the commit is.
    updates: Vec<usize>,
}

/// A server signature over the bytes of a new commit, made before the
/// update lock.
struct Prepared<'a> {
    signer: &'a ServerSigner,
    signature: Vec<u8>,
}

/// The detached-metadata edit of one commit of the session, planned before
/// the update lock and checked again under it.
struct Edit<'a> {
    commit: Checksum,
    /// The commit bytes, the payload of its signatures. A commit that no
    /// update names gets no signature, and its payload is empty.
    payload: &'a [u8],
    /// The dict that the repository held at the time of the plan, `None` for
    /// no dict.
    stored: Option<Bytes>,
    /// The filtered incoming dict, with the entries of the host in place of
    /// each client entry of the same key.
    incoming: Option<Bytes>,
    /// The keys of the host entries whose value stays where the stored dict
    /// holds the key, shared with the blocking pool.
    keep: Arc<Vec<String>>,
    /// The server keys of the rules of the updates of the commit, which the
    /// plan before the lock signs with.
    signers: Vec<&'a Arc<ServerSigner>>,
    /// The prepared signatures whose key did not sign the commit in the
    /// merged dict, with the signatures kept before each.
    signatures: Vec<Prepared<'a>>,
    /// The size of the dict the commit writes, where it is over
    /// `MAX_METADATA_SIZE`.
    oversize: Option<u64>,
}

/// Runs the checks of the ref updates of `request`, then writes the refs and
/// commits `txn` under the update lock.
///
/// `named` holds the refs of `Hello`. `commit_meta` holds the detached
/// metadata dicts of the session.
///
/// # Checks
///
/// The checks run in this order. The first failure ends the session, and the
/// session publishes nothing.
///
/// - Each ref name is valid, and no update writes a commit to a ref name of
///   64 lowercase hex characters (`invalid-ref`). A delete of such a ref
///   passes. The message holds one update at least, and each update names a
///   ref of `Hello` once (`protocol`).
/// - The `CommitReply` of the updates fits in a frame of [`MAX_FRAME`], with
///   the longest outcome of each update (`limit-exceeded`). Because of this
///   check, the server can always send the reply of a commit that wrote its
///   refs.
/// - Each detached metadata dict belongs to a commit of the session: a staged
///   commit, or the new commit of an update (`protocol`).
/// - The rule of each update accepts it, and no update names the collection
///   anchor ref of a repository with a collection id (`ref-denied`).
/// - Each new commit is staged or present (`missing-objects`), and each
///   commit of the session parses.
/// - The tree of each commit of the session is complete (`missing-objects`).
/// - The ref binding and the collection binding of each new commit name its
///   refs and the repository (`binding-mismatch`).
/// - Each new commit passes the signature verification of each of its rules
///   (`signature-required`). The verification reads the union of the stored
///   and the incoming detached metadata.
///
/// # Before the update lock
///
/// After the checks, the incoming detached metadata goes through the filter.
/// Then the staged objects become durable. At the same time, each new commit
/// gets a signature from each server key of its rules. A key makes no
/// signature if it already signed the commit in one of these places:
///
/// - The merge of the filtered incoming dict into the stored dict.
/// - A signature that a key before it made.
///
/// If no `hooks` are given, this step also finds the size of each dict that
/// the commit writes. Then the fast-forward walk of each update reads the
/// parent chain as far as the ref tip that this function read before the
/// lock. If the client sent `force` and the rule allows a non-fast-forward
/// update, no walk runs.
///
/// # Hooks
///
/// If `hooks` are given, [`ReceiveHooks::before_update`] runs next,
/// immediately before the update lock. If the hook refuses, the session ends
/// with the code of the refusal. This function then checks the plan of the
/// hook. If the checks refuse the plan, the failure is on the server side.
///
/// The entries of the host merge into the incoming dicts. Each commit with
/// host entries and no edit gets a new edit. Then this function finds the
/// size of each dict that the commit writes. If a dict with host entries is
/// over the size limit, the failure is `limit-exceeded`.
///
/// If a failure occurs after the hook, the carried value of the plan drops
/// once, after the release of the update lock. `after_update` does not run.
///
/// # Under the update lock
///
/// Under the lock, this function reads the refs again. These cases are
/// `ref-denied`:
///
/// - A ref that is an alias.
/// - A path that a ref write cannot replace.
/// - Two updates where one update names a directory of the other.
///
/// Each update then gets these checks:
///
/// - The ref is in the state that the update expects (`ref-mismatch`).
/// - The rule allows the delete of a present ref (`delete-denied`).
/// - The new commit is a fast-forward (`non-fast-forward`).
///
/// This function then reads the stored detached metadata again. If it changed
/// after the plan, this function drops each prepared signature whose key
/// signed the commit in the new merge. The size is also found again, with the
/// keys of the host entries that keep a stored value. Then each dict over the
/// size limit is `limit-exceeded`. Only a dict with host entries can fail the
/// size check before the lock.
///
/// The merges, the signatures, and the refs that change go into the queue of
/// the transaction. If the repository has a collection id, the policy
/// regenerates the summary, and a ref changes, the anchor commit also goes
/// into the queue. Then the transaction commits.
///
/// After the transaction commit, this function removes the partial marker of
/// each commit of the session. If the policy regenerates the summary and a ref
/// changed, it builds, signs, and writes the summary. A failure of these last
/// steps is a warning of the report.
///
/// # Failure of the transaction commit
///
/// The transaction commit is not atomic. These failures can leave the
/// detached metadata and some refs written:
///
/// - A failure of a detached-metadata write.
/// - A failure of a ref write.
/// - A failure of the `fsync` of a ref directory.
///
/// In this case, this function returns the error, and `after_update` does not
/// run.
///
/// # After the update lock
///
/// This function then releases the update lock. If `hooks` are given,
/// [`ReceiveHooks::after_update`] runs next with the report and the carried
/// value. It runs also when no ref changes.
///
/// An error of the hook is `internal`, with the message cut at 4096 bytes at a
/// character boundary. After an error of the hook, the refs and the detached
/// metadata stay written.
pub(super) async fn finish(
    repo: &Repo,
    policy: &ReceivePolicy,
    hooks: Option<&dyn ReceiveHooks>,
    txn: Transaction,
    named: &[String],
    commit_meta: HashMap<Checksum, Vec<u8>>,
    request: CommitRequest,
) -> Checked<ReceiveReport> {
    let CommitRequest { updates, force } = request;
    check_names(named, &updates)?;
    check_reply_fits(&updates)?;
    check_commit_meta_commits(&txn, &updates, &commit_meta)?;
    let rules = select_rules(repo, policy, &updates)?;
    let Loaded {
        targets,
        session_commits,
        roots,
        parents,
    } = load_commits(&txn, &updates).await?;
    let missing = walk::completeness(&txn, roots).await?;
    if missing.total > 0 {
        return Err(missing_objects(missing, "the trees of the commits reach"));
    }
    check_bindings(repo, &updates, &targets)?;
    let commit_meta: HashMap<Checksum, Bytes> = commit_meta
        .into_iter()
        .map(|(commit, bytes)| (commit, Arc::new(bytes)))
        .collect();
    let mut stored = read_stored_for(repo, &rules, &targets, &commit_meta).await?;
    check_signatures(&rules, &commit_meta, &targets, &stored).await?;
    let incoming = filter_detached(policy, commit_meta).await?;
    let edits = plan(&rules, &targets, &mut stored, incoming);
    // The dicts that no edit took. The merge of the host entries takes them,
    // so they stay only where the session has hooks.
    let leftover = match hooks {
        Some(_) => stored,
        None => {
            drop(stored);
            HashMap::new()
        }
    };

    let (synced, edits) = futures_lite::future::zip(
        txn.sync_staged(),
        prepare_signatures(edits, hooks.is_none()),
    )
    .await;
    synced.map_err(Failure::Internal)?;
    let edits = edits?;
    let names: Vec<String> = updates.iter().map(|u| u.name.clone()).collect();
    let tips = repo
        .resolve_ref_tips(&names)
        .await
        .map_err(Failure::Internal)?;
    let mut walks = Walks::new(parents);
    let mut chains = Vec::with_capacity(updates.len());
    for ((update, tip), rule) in updates.iter().zip(&tips).zip(&rules) {
        chains.push(match (update.new, tip) {
            // A forced update that the rule allows needs no walk.
            _ if force && rule.allow_non_fast_forward => None,
            (Some(new), Some(tip)) if new != *tip => Some(walks.chain(&txn, new, *tip).await?),
            _ => None,
        });
    }

    // Declared before the update lock, so on each failure the carried value
    // drops after the lock is released. On success it goes to `after_update`,
    // after the lock is released.
    let mut carried: Option<Box<dyn Any + Send>> = None;
    let edits = match hooks {
        None => edits,
        Some(hooks) => {
            let UpdatePlan {
                metadata,
                carried: value,
            } = hooks
                .before_update(&updates)
                .await
                .map_err(HookRefusal::into_failure)?;
            carried = Some(value);
            add_host_entries(repo, &targets, edits, leftover, metadata).await?
        }
    };
    let held = repo.lock_update().await.map_err(Failure::Internal)?;
    let anchor = policy.update_summary && repo.config().collection_id().is_some();
    let (states, anchor_parent) = repo
        .read_ref_states(&names, anchor.then_some(OSTREE_METADATA_REF))
        .await
        .map_err(Failure::Internal)?;
    let current = check_ref_paths(&updates, &states)?;
    let mut changes = Vec::with_capacity(updates.len());
    for (i, update) in updates.iter().enumerate() {
        let changed = check_ref(
            &txn, update, rules[i], force, current[i], chains[i], &mut walks,
        )
        .await?;
        changes.push(changed);
    }
    queue_detached(repo, &txn, edits).await?;
    for (update, changed) in updates.iter().zip(&changes) {
        if *changed {
            txn.set_ref(&update.name, update.new.as_ref());
        }
    }
    let summary = policy.update_summary && changes.contains(&true);
    if summary && let Some(collection_id) = repo.config().collection_id().map(str::to_owned) {
        let parent = anchor_parent
            .transpose()
            .map_err(Failure::Internal)?
            .flatten();
        repo.stage_anchor_commit(&txn, &collection_id, parent, None)
            .await
            .map_err(Failure::Internal)?;
    }
    let stats = txn.commit_under(&held).await.map_err(Failure::Internal)?;
    let mut warnings: Vec<ReceiveWarning> = repo
        .remove_partial_markers(session_commits)
        .await
        .into_iter()
        .map(|(commit, e)| ReceiveWarning {
            step: ReceiveStep::PartialMarker,
            message: format!("the partial marker of commit {commit}: {e}"),
        })
        .collect();
    if summary && let Err(warning) = write_summary(repo, &policy.summary_signers).await {
        warnings.push(warning);
    }
    drop(held);
    // The state of the checks is freed here, so it is not held while the
    // hook of the host runs.
    drop((walks, targets, chains, tips, names, rules, states, changes));

    let refs = updates
        .into_iter()
        .zip(current)
        .map(|(update, old)| RefOutcome {
            name: update.name,
            old,
            new: update.new,
        })
        .collect();
    let report = ReceiveReport {
        refs,
        stats,
        warnings,
    };
    if let (Some(hooks), Some(carried)) = (hooks, carried)
        && let Err(mut message) = hooks.after_update(&report, carried).await
    {
        hooks::cut(&mut message);
        return Err(Failure::Wire(push::Error::Internal(message)));
    }
    Ok(report)
}

/// Checks the ref names of the updates against the refs of `Hello`.
///
/// - Each ref name is valid.
/// - No update writes a commit to a ref name of 64 lowercase hex characters.
/// - The message holds one update at least.
/// - Each update names a ref of `Hello`, once.
fn check_names(named: &[String], updates: &[RefUpdate]) -> Checked<()> {
    for update in updates {
        crate::validate_refspec(&update.name).map_err(|e| match e {
            Error::InvalidRefspec(_) => Failure::Wire(push::Error::InvalidRef(format!(
                "invalid ref name '{}'",
                update.name
            ))),
            other => Failure::Internal(other),
        })?;
        // A revision reads 64 lowercase hex characters as a checksum, so a
        // push writes no commit to such a ref. A delete of it passes.
        if update.new.is_some() && ostrya_core::is_checksum_shaped(&update.name) {
            return Err(Failure::Wire(push::Error::InvalidRef(format!(
                "invalid ref name '{}'",
                update.name
            ))));
        }
    }
    if updates.is_empty() {
        return Err(protocol("the Commit message holds no ref update".into()));
    }
    let named: HashSet<&str> = named.iter().map(String::as_str).collect();
    let mut seen = HashSet::with_capacity(updates.len());
    for update in updates {
        if !named.contains(update.name.as_str()) {
            return Err(protocol(format!(
                "ref '{}' was not named in Hello",
                update.name
            )));
        }
        if !seen.insert(update.name.as_str()) {
            return Err(protocol(format!(
                "ref '{}' is updated more than once",
                update.name
            )));
        }
    }
    Ok(())
}

/// Checks that the `CommitReply` of `updates` fits in a frame of
/// [`MAX_FRAME`].
///
/// The check uses the longest outcome that each update can get. That
/// outcome holds the name and the new commit of the update, and an old
/// commit. An update that expects its ref absent, or that takes any state,
/// does not state the old commit. Under the lock, the ref can still hold one.
///
/// A reply over the limit is `limit-exceeded`. The check runs before any ref
/// write.
fn check_reply_fits(updates: &[RefUpdate]) -> Checked<()> {
    let any_commit = Checksum::from_bytes([0; 32]);
    let longest = Message::CommitReply(
        updates
            .iter()
            .map(|u| RefOutcome {
                name: u.name.clone(),
                old: Some(any_commit),
                new: u.new,
            })
            .collect(),
    );
    let body = longest.encode_body().map_err(Failure::Wire)?;
    let len = body.len() as u64 + 1;
    if len > u64::from(MAX_FRAME) {
        return Err(Failure::Wire(push::Error::LimitExceeded(format!(
            "the reply to the {} ref updates of Commit can need a frame of {len} bytes, over the \
             limit {MAX_FRAME}",
            updates.len()
        ))));
    }
    Ok(())
}

/// Checks that each detached metadata dict of the session belongs to a commit
/// of the session.
///
/// A commit of the session is a commit that the session staged, or the new
/// commit of an update. Without this check, a dict for any other commit can
/// edit the detached metadata of a commit that no rule of the message covers.
fn check_commit_meta_commits(
    txn: &Transaction,
    updates: &[RefUpdate],
    commit_meta: &HashMap<Checksum, Vec<u8>>,
) -> Checked<()> {
    let new: HashSet<&Checksum> = updates.iter().filter_map(|u| u.new.as_ref()).collect();
    for commit in commit_meta.keys() {
        if !(new.contains(commit) || txn.is_staged(commit, ObjectType::Commit)) {
            return Err(protocol(format!(
                "detached metadata for commit {commit}, which the session did not stage \
                 and no ref update names"
            )));
        }
    }
    Ok(())
}

/// Returns the rule of each update, in order.
///
/// These updates are `ref-denied`:
///
/// - An update that no rule covers.
/// - An update whose rule refuses it.
/// - An update of the anchor ref of a repository with a collection id.
fn select_rules<'a>(
    repo: &Repo,
    policy: &'a ReceivePolicy,
    updates: &[RefUpdate],
) -> Checked<Vec<&'a ReceiveRule>> {
    let collection = repo.config().collection_id().is_some();
    updates
        .iter()
        .map(|update| {
            let name = &update.name;
            if collection && name == OSTREE_METADATA_REF {
                return Err(ref_denied(format!(
                    "ref '{name}' holds the collection anchor commit, which the server writes"
                )));
            }
            match policy.rule_for(name) {
                Some(rule) if rule.accept => Ok(rule),
                Some(_) => Err(ref_denied(format!(
                    "the policy refuses updates of ref '{name}'"
                ))),
                None => Err(ref_denied(format!(
                    "no rule of the policy covers the remote ref '{name}'"
                ))),
            }
        })
        .collect()
}

/// The commits of the session, as [`load_commits`] reads them.
struct Loaded {
    /// The new commits of the updates, each once, in the order of the
    /// updates.
    targets: Vec<Target>,
    /// Every commit of the session: the staged commits and the new commits.
    session_commits: Vec<Checksum>,
    /// The root dirtree and root dirmeta of each commit of the session.
    roots: Vec<(Checksum, Checksum)>,
    /// The parent of each commit of the session.
    parents: Parents,
}

/// One commit as [`read_commits`] returns it.
enum ReadCommit {
    /// A new commit that neither the session nor the repository holds.
    Absent,
    /// A commit that does not parse.
    Unparsable(ostrya_core::Error),
    /// A new commit, with its bytes.
    Target(Vec<u8>, Commit),
    /// A staged commit that no update names: its root and its parent.
    Other((Checksum, Checksum), Option<Checksum>),
}

/// Reads and parses the commits of the session.
///
/// The commits of the session are the new commit of each update and each
/// staged commit. The reads and the parses run in one trip to the blocking
/// pool. The read of a commit tries the staging directory before `objects/`.
///
/// A new commit that is neither staged nor present is `missing-objects`. A
/// staged commit that does not parse is `protocol`. A stored commit that does
/// not parse is a failure on the server side.
async fn load_commits(txn: &Transaction, updates: &[RefUpdate]) -> Checked<Loaded> {
    let mut news: Vec<(Checksum, Vec<usize>)> = Vec::new();
    let mut index: HashMap<Checksum, usize> = HashMap::new();
    for (i, update) in updates.iter().enumerate() {
        let Some(new) = update.new else {
            continue;
        };
        match index.entry(new) {
            Entry::Occupied(at) => news[*at.get()].1.push(i),
            Entry::Vacant(at) => {
                at.insert(news.len());
                news.push((new, vec![i]));
            }
        }
    }
    let mut reads: Vec<(Checksum, bool)> = news
        .iter()
        .map(|(new, _)| (*new, txn.is_staged(new, ObjectType::Commit)))
        .collect();
    reads.extend(
        txn.staged_of_type(ObjectType::Commit)
            .into_iter()
            .filter(|commit| !index.contains_key(commit))
            .map(|commit| (commit, true)),
    );
    let count = news.len();
    let mut read = read_commits(txn, reads.clone(), count)
        .await
        .map_err(Failure::Internal)?;
    let others = read.split_off(count);

    let parse_failure = |checksum: &Checksum, staged: bool, e: ostrya_core::Error| {
        let message = format!("commit {checksum} does not parse: {e}");
        if staged {
            protocol(message)
        } else {
            Failure::Internal(Error::InvalidFormat(message))
        }
    };
    let mut loaded = Loaded {
        targets: Vec::with_capacity(count),
        session_commits: Vec::with_capacity(reads.len()),
        roots: Vec::with_capacity(reads.len()),
        parents: Parents::with_capacity(reads.len()),
    };
    let mut absent = Missing::default();
    for (((checksum, staged), read), (_, updates)) in reads.iter().zip(read).zip(news) {
        match read {
            ReadCommit::Absent => absent.add(ObjectName::new(*checksum, ObjectType::Commit)),
            ReadCommit::Unparsable(e) => return Err(parse_failure(checksum, *staged, e)),
            ReadCommit::Target(bytes, commit) => {
                loaded.session_commits.push(*checksum);
                loaded
                    .roots
                    .push((commit.root_dirtree, commit.root_dirmeta));
                loaded.parents.insert(*checksum, commit.parent);
                loaded.targets.push(Target {
                    checksum: *checksum,
                    bytes,
                    commit,
                    updates,
                });
            }
            ReadCommit::Other(..) => unreachable!("a new commit is read with its bytes"),
        }
    }
    if absent.total > 0 {
        return Err(missing_objects(absent, "the ref updates name"));
    }
    for ((checksum, staged), read) in reads[count..].iter().zip(others) {
        match read {
            ReadCommit::Other(root, parent) => {
                loaded.session_commits.push(*checksum);
                loaded.roots.push(root);
                loaded.parents.insert(*checksum, parent);
            }
            ReadCommit::Unparsable(e) => return Err(parse_failure(checksum, *staged, e)),
            ReadCommit::Absent | ReadCommit::Target(..) => {
                unreachable!("a staged commit is read without its bytes")
            }
        }
    }
    Ok(loaded)
}

/// Reads and parses `reads` on the blocking pool.
///
/// Each entry of `reads` is a commit and a flag that is `true` if the session
/// staged the commit. The first `targets` entries are new commits. A new
/// commit keeps its bytes, and it reads as absent if the repository does not
/// hold it.
async fn read_commits(
    txn: &Transaction,
    reads: Vec<(Checksum, bool)>,
    targets: usize,
) -> Result<Vec<ReadCommit>> {
    let mode = txn.repo().mode();
    let objects = txn.repo().objects_fd().try_clone_to_owned()?;
    let staging = txn.staging_fd().try_clone_to_owned()?;
    ostrya_rt::unblock(move || {
        reads
            .into_iter()
            .enumerate()
            .map(|(i, (checksum, staged))| {
                let bytes = if staged {
                    let name = flat_name(&checksum, ObjectType::Commit, mode);
                    read_meta_object(staging.as_fd(), &name, MAX_METADATA_SIZE)?
                } else {
                    let path = loose_path(&checksum, ObjectType::Commit, mode);
                    match read_meta_object(objects.as_fd(), &path, MAX_METADATA_SIZE) {
                        Ok(bytes) => bytes,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            return Ok(ReadCommit::Absent);
                        }
                        Err(e) => return Err(Error::Io(e)),
                    }
                };
                Ok(match Commit::parse(&bytes) {
                    Err(e) => ReadCommit::Unparsable(e),
                    Ok(commit) if i < targets => ReadCommit::Target(bytes, commit),
                    Ok(commit) => {
                        ReadCommit::Other((commit.root_dirtree, commit.root_dirmeta), commit.parent)
                    }
                })
            })
            .collect()
    })
    .await
}

/// Returns the `missing-objects` failure for `missing`.
///
/// `what` completes the phrase "objects that ..." of the message.
fn missing_objects(missing: Missing, what: &str) -> Failure {
    let mut message = format!(
        "{} objects that {what} are neither staged nor present",
        missing.total
    );
    if missing.listed.len() < missing.total {
        message.push_str(&format!(", the first {} listed", missing.listed.len()));
    }
    Failure::Wire(push::Error::MissingObjects {
        message,
        missing: missing.listed,
    })
}

/// Checks the ref binding and the collection binding of each new commit.
///
/// The `ostree.ref-binding` of each new commit lists each ref that the commit
/// is the new value of, without the remote part of a remote ref. If the
/// repository has a collection id, the `ostree.collection-binding` of each new
/// commit is that id. A commit without the key passes.
fn check_bindings(repo: &Repo, updates: &[RefUpdate], targets: &[Target]) -> Checked<()> {
    let collection = repo.config().collection_id();
    for target in targets {
        let bindings = target.commit.ref_bindings();
        if !bindings.is_empty() {
            for &i in &target.updates {
                let name = updates[i].name.as_str();
                let bare = name.split_once(':').map_or(name, |(_, bare)| bare);
                if !bindings.contains(&bare) {
                    return Err(Failure::Wire(push::Error::BindingMismatch(format!(
                        "commit {} is bound to the refs {bindings:?}, which do not hold '{bare}'",
                        target.checksum
                    ))));
                }
            }
        }
        if let (Some(id), Some(bound)) = (collection, target.commit.collection_binding())
            && id != bound
        {
            return Err(Failure::Wire(push::Error::BindingMismatch(format!(
                "commit {} is bound to the collection '{bound}', not '{id}'",
                target.checksum
            ))));
        }
    }
    Ok(())
}

/// Returns the trusted keys of the rules of the updates of `target`, each set
/// once.
fn target_keys<'a>(rules: &[&'a ReceiveRule], target: &Target) -> Vec<&'a Arc<TrustedKeys>> {
    let mut keys: Vec<&Arc<TrustedKeys>> = Vec::new();
    for &i in &target.updates {
        if let ReceiveVerify::Keys(held) = &rules[i].verify
            && !keys.iter().any(|k| Arc::ptr_eq(k, held))
        {
            keys.push(held);
        }
    }
    keys
}

/// Returns the union of the server keys of the rules of the updates of
/// `target`, each key once.
fn target_signers<'a>(rules: &[&'a ReceiveRule], target: &Target) -> Vec<&'a Arc<ServerSigner>> {
    let mut signers: Vec<&Arc<ServerSigner>> = Vec::new();
    for &i in &target.updates {
        for signer in &rules[i].signers {
            if !signers.iter().any(|s| Arc::ptr_eq(s, signer)) {
                signers.push(signer);
            }
        }
    }
    signers
}

/// Reads the stored detached metadata of each commit whose dict a later step
/// reads.
///
/// These commits are each new commit with a signature verification or a
/// server key, and each commit with an incoming dict.
async fn read_stored_for(
    repo: &Repo,
    rules: &[&ReceiveRule],
    targets: &[Target],
    commit_meta: &HashMap<Checksum, Bytes>,
) -> Checked<HashMap<Checksum, Option<Bytes>>> {
    let mut commits: Vec<Checksum> = targets
        .iter()
        .filter(|t| {
            !target_keys(rules, t).is_empty()
                || !target_signers(rules, t).is_empty()
                || commit_meta.contains_key(&t.checksum)
        })
        .map(|t| t.checksum)
        .collect();
    let listed: HashSet<Checksum> = commits.iter().copied().collect();
    commits.extend(commit_meta.keys().filter(|c| !listed.contains(c)).copied());
    let stored = read_stored(repo, commits.clone()).await?;
    Ok(commits.into_iter().zip(stored).collect())
}

/// Reads the detached metadata dict that the repository holds for each of
/// `commits`, in order.
///
/// The reads run in one trip to the blocking pool. The result is `None` for no
/// file and for the zero-length "no metadata" marker.
async fn read_stored(repo: &Repo, commits: Vec<Checksum>) -> Checked<Vec<Option<Bytes>>> {
    let mode = repo.mode();
    let objects = repo
        .objects_fd()
        .try_clone_to_owned()
        .map_err(|e| Failure::Internal(e.into()))?;
    ostrya_rt::unblock(move || {
        commits
            .iter()
            .map(|commit| {
                let path = loose_path(commit, ObjectType::CommitMeta, mode);
                match read_meta_object(objects.as_fd(), &path, MAX_METADATA_SIZE) {
                    Ok(bytes) if bytes.is_empty() => Ok(None),
                    Ok(bytes) => Ok(Some(Arc::new(bytes))),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Err(e) => Err(Error::Io(e)),
                }
            })
            .collect::<Result<Vec<_>>>()
    })
    .await
    .map_err(Failure::Internal)
}

/// Returns the merge of `incoming` into `stored`, each a serialized dict.
///
/// The result is `None` if neither holds a dict. Under a key of `keep` that
/// `stored` holds, the stored value stays.
fn merged_dict(
    stored: Option<&[u8]>,
    incoming: Option<&[u8]>,
    keep: &[String],
) -> Result<Option<Value>> {
    let stored = stored.map(parse_signature_dict).transpose()?.flatten();
    match incoming.map(parse_signature_dict).transpose()?.flatten() {
        Some(incoming) => merge_detached(stored, incoming, keep).map(Some),
        None => Ok(stored),
    }
}

/// Returns an empty `a{sv}` dict.
fn empty_dict() -> Value {
    Value::Array(Vec::new())
}

/// Verifies the signatures of each new commit against each rule of its
/// updates, once for each set of trusted keys.
///
/// The verification reads the union of the stored detached metadata of the
/// commit and the incoming dict, before the detached-metadata filter. This
/// function builds the union on the blocking pool.
async fn check_signatures(
    rules: &[&ReceiveRule],
    commit_meta: &HashMap<Checksum, Bytes>,
    targets: &[Target],
    stored: &HashMap<Checksum, Option<Bytes>>,
) -> Checked<()> {
    for target in targets {
        let keys = target_keys(rules, target);
        if keys.is_empty() {
            continue;
        }
        let stored = stored.get(&target.checksum).cloned().flatten();
        let incoming = commit_meta.get(&target.checksum).cloned();
        let dict = ostrya_rt::unblock(move || {
            merged_dict(
                stored.as_deref().map(Vec::as_slice),
                incoming.as_deref().map(Vec::as_slice),
                &[],
            )
        })
        .await
        .map_err(Failure::Internal)?;
        let subject = format!("commit {}", target.checksum);
        for held in keys {
            held.check(&subject, &target.bytes, dict.as_ref())
                .await
                .map_err(|e| match e {
                    Error::Signature(message) => {
                        Failure::Wire(push::Error::SignatureRequired(message))
                    }
                    other => Failure::Internal(other),
                })?;
        }
    }
    Ok(())
}

/// Checks the ref paths under the lock and returns the commit that each ref
/// names.
///
/// These cases are `ref-denied`:
///
/// - A ref that is an alias.
/// - A path that a ref write cannot replace.
/// - Two updates that write refs, where one ref names a directory of the
///   other.
///
/// In these cases no ref write can complete, so the check runs before any
/// write goes into the queue.
fn check_ref_paths(
    updates: &[RefUpdate],
    states: &[RefFileState],
) -> Checked<Vec<Option<Checksum>>> {
    let mut current = Vec::with_capacity(updates.len());
    for (update, state) in updates.iter().zip(states) {
        let name = &update.name;
        current.push(match state {
            RefFileState::Absent => None,
            RefFileState::Commit(commit) => Some(*commit),
            RefFileState::Alias => {
                return Err(ref_denied(format!(
                    "ref '{name}' is an alias of another ref"
                )));
            }
            RefFileState::NotARef => {
                return Err(ref_denied(format!(
                    "ref '{name}' names a directory or a path below a ref file, \
                     which a ref write cannot replace"
                )));
            }
        });
    }
    let mut written: HashMap<String, &str> = HashMap::new();
    for update in updates.iter().filter(|u| u.new.is_some()) {
        let relpath = refspec_to_relpath(&update.name).map_err(Failure::Internal)?;
        written.insert(relpath, update.name.as_str());
    }
    for update in updates.iter().filter(|u| u.new.is_some()) {
        let relpath = refspec_to_relpath(&update.name).map_err(Failure::Internal)?;
        let mut path = relpath.as_str();
        while let Some((parent, _)) = path.rsplit_once('/') {
            if let Some(other) = written.get(parent) {
                return Err(ref_denied(format!(
                    "ref '{}' names a path below ref '{other}' of the same message",
                    update.name
                )));
            }
            path = parent;
        }
    }
    Ok(current)
}

/// Checks one update against the state of its ref under the lock.
///
/// The result is `true` if the update changes the ref. A delete of an absent
/// ref and an update to the current commit change nothing.
///
/// - The ref must be in the state that the update expects, also for `Any`.
/// - A delete of a ref that is present needs `allow_delete`.
/// - If a new commit differs from the current commit, the current commit must
///   be in the parent chain of the new commit. If the client sent `force` and
///   the rule has `allow_non_fast_forward`, this check does not apply.
///
/// `chain` is the walk made before the lock, if one was made.
async fn check_ref(
    txn: &Transaction,
    update: &RefUpdate,
    rule: &ReceiveRule,
    force: bool,
    current: Option<Checksum>,
    chain: Option<usize>,
    walks: &mut Walks,
) -> Checked<bool> {
    let name = &update.name;
    let expected = match update.expected {
        Expected::Absent => current.is_none(),
        Expected::Commit(commit) => current == Some(commit),
        Expected::Any => true,
    };
    if !expected {
        let state = match current {
            Some(commit) => format!("at {commit}"),
            None => "absent".into(),
        };
        return Err(Failure::Wire(push::Error::RefMismatch {
            message: format!("ref '{name}' is {state}"),
            name: name.clone(),
            current,
        }));
    }
    match (current, update.new) {
        (None, None) => Ok(false),
        (Some(_), None) if !rule.allow_delete => Err(Failure::Wire(push::Error::DeleteDenied(
            format!("the policy does not allow a delete of ref '{name}'"),
        ))),
        (Some(_), None) | (None, Some(_)) => Ok(true),
        (Some(current), Some(new)) if current == new => Ok(false),
        // A forced update that the rule allows needs no walk.
        (Some(_), Some(_)) if force && rule.allow_non_fast_forward => Ok(true),
        (Some(current), Some(new)) => {
            let chain = match chain {
                Some(chain) => chain,
                None => walks.chain(txn, new, current).await?,
            };
            if !walks.reaches(txn, chain, current).await? {
                return Err(Failure::Wire(push::Error::NonFastForward(format!(
                    "commit {new} does not descend from {current}, the commit of ref '{name}'"
                ))));
            }
            Ok(true)
        }
    }
}

/// Removes the keys that the filter excludes from each incoming detached
/// metadata dict, on the blocking pool.
///
/// The result leaves out a dict that the filter empties.
async fn filter_detached(
    policy: &ReceivePolicy,
    commit_meta: HashMap<Checksum, Bytes>,
) -> Checked<HashMap<Checksum, Bytes>> {
    let filter = policy.detached_metadata_filter.clone();
    ostrya_rt::unblock(move || -> Result<_> {
        let mut incoming = HashMap::with_capacity(commit_meta.len());
        for (commit, bytes) in commit_meta {
            let bytes = Arc::unwrap_or_clone(bytes);
            let filtered = match &filter {
                Some(filter) => filter.apply(&commit, bytes)?,
                None => Some(bytes),
            };
            if let Some(bytes) = filtered
                && !bytes.is_empty()
            {
                incoming.insert(commit, Arc::new(bytes));
            }
        }
        Ok(incoming)
    })
    .await
    .map_err(Failure::Internal)
}

/// Returns the detached-metadata edits of the session.
///
/// A new commit gets an edit if it has a server key or a filtered incoming
/// dict. Each other commit with a filtered incoming dict also gets an edit.
/// Each edit takes its stored dict out of `stored`.
fn plan<'a>(
    rules: &[&'a ReceiveRule],
    targets: &'a [Target],
    stored: &mut HashMap<Checksum, Option<Bytes>>,
    mut incoming: HashMap<Checksum, Bytes>,
) -> Vec<Edit<'a>> {
    let mut edit = |commit: Checksum, payload, incoming, signers| Edit {
        commit,
        payload,
        stored: stored.remove(&commit).flatten(),
        incoming,
        keep: Arc::default(),
        signers,
        signatures: Vec::new(),
        oversize: None,
    };
    let mut edits = Vec::new();
    for target in targets {
        let signers = target_signers(rules, target);
        let dict = incoming.remove(&target.checksum);
        if dict.is_some() || !signers.is_empty() {
            edits.push(edit(target.checksum, &target.bytes[..], dict, signers));
        }
    }
    for (commit, dict) in incoming {
        edits.push(edit(commit, &[][..], Some(dict), Vec::new()));
    }
    edits
}

/// Returns the keys of [`SIGNATURE_KEYS`] among `keys`, as the flags of
/// [`check_stored`].
fn flagged<'k>(keys: impl IntoIterator<Item = &'k str>) -> [bool; SIGNATURE_KEYS.len()] {
    let mut flags = [false; SIGNATURE_KEYS.len()];
    for key in keys {
        if let Some(i) = SIGNATURE_KEYS.iter().position(|k| *k == key) {
            flags[i] = true;
        }
    }
    flags
}

/// Checks on the blocking pool that an edit accepts `stored`, with signatures
/// appended under `keys`.
///
/// If `build` is `true`, this function also returns the merge of `incoming`
/// into `stored`, with the stored value kept under each key of `keep`. If the
/// edit refuses a stored dict, the failure is on the server side.
async fn check_edit(
    stored: Option<Bytes>,
    incoming: Option<Bytes>,
    keys: [bool; SIGNATURE_KEYS.len()],
    build: bool,
    keep: Arc<Vec<String>>,
) -> Checked<Option<Value>> {
    ostrya_rt::unblock(move || -> Result<Option<Value>> {
        let incoming = incoming.as_deref().map(Vec::as_slice);
        let stored = stored.as_deref().map(Vec::as_slice);
        if let Some(stored) = stored {
            let mut touched = match incoming {
                Some(incoming) => signature_keys_in(incoming)?,
                None => [false; SIGNATURE_KEYS.len()],
            };
            for (touched, key) in touched.iter_mut().zip(keys) {
                *touched |= key;
            }
            check_stored(stored, touched)?;
        }
        if !build {
            return Ok(None);
        }
        Ok(Some(
            merged_dict(stored, incoming, &keep)?.unwrap_or_else(empty_dict),
        ))
    })
    .await
    .map_err(Failure::Internal)
}

/// Returns the size of the dict that an edit writes, if the size is over
/// `limit` bytes.
///
/// The dict is the merge of `incoming` into `stored`, each a serialized dict.
/// The stored value stays under each key of `keep`, and `signatures` are
/// appended. If `written` is given, it is that dict, already built.
///
/// # Bound
///
/// A bound from the sizes of the inputs skips the serialization if the bound
/// shows that the dict fits. Each entry and each blob of the written dict
/// comes from the stored dict, from the incoming dict, or from a new
/// signature.
///
/// Relative to its place in its source, an entry gains at most 7 bytes of
/// padding and 7 bytes of framing offset. A blob gains at most 7 bytes of
/// framing offset. Each such element holds at least one byte of framing
/// offset in its source. As a result, the copied elements come to at most 15
/// times the source bytes.
///
/// A new signature adds its bytes and at most 8 bytes of offset. A signature
/// list that no source holds adds its key, its type, and their padding and
/// offsets. That is at most 64 bytes for each of the four keys.
///
/// The bound uses 16 times the source bytes, more than these 15 times. If the
/// bound is more than `limit`, this function builds and serializes the dict,
/// so the check is exact.
fn size_over(
    limit: u64,
    stored: Option<&[u8]>,
    incoming: Option<&[u8]>,
    signatures: &[(&str, &[u8])],
    written: Option<Value>,
    keep: &[String],
) -> Result<Option<u64>> {
    let sources = (stored.map_or(0, <[u8]>::len) + incoming.map_or(0, <[u8]>::len)) as u64;
    let bound = 16 * sources
        + signatures
            .iter()
            .map(|(_, signature)| signature.len() as u64 + 8)
            .sum::<u64>()
        + 64 * SIGNATURE_KEYS.len() as u64;
    if bound <= limit {
        return Ok(None);
    }
    let dict = match written {
        Some(dict) => dict,
        None => {
            let mut dict = merged_dict(stored, incoming, keep)?.unwrap_or_else(empty_dict);
            for (key, signature) in signatures {
                append_signature(&mut dict, key, signature.to_vec())?;
            }
            dict
        }
    };
    let size = serialize_signature_dict(&dict)?.len() as u64;
    Ok((size > limit).then_some(size))
}

/// Calls [`size_over`] for `edit` on the blocking pool.
///
/// The call uses `MAX_METADATA_SIZE`, the kept signatures, and the keys of the
/// edit that keep a stored value.
async fn oversize(edit: &Edit<'_>, written: Option<Value>) -> Checked<Option<u64>> {
    let stored = edit.stored.clone();
    let incoming = edit.incoming.clone();
    let keep = edit.keep.clone();
    let signatures: Vec<(String, Vec<u8>)> = edit
        .signatures
        .iter()
        .map(|p| {
            (
                p.signer.signer().metadata_key().to_owned(),
                p.signature.clone(),
            )
        })
        .collect();
    ostrya_rt::unblock(move || {
        let signatures: Vec<(&str, &[u8])> = signatures
            .iter()
            .map(|(key, signature)| (key.as_str(), signature.as_slice()))
            .collect();
        size_over(
            MAX_METADATA_SIZE,
            stored.as_deref().map(Vec::as_slice),
            incoming.as_deref().map(Vec::as_slice),
            &signatures,
            written,
            &keep,
        )
    })
    .await
    .map_err(Failure::Internal)
}

/// Returns the `limit-exceeded` failure of a merged dict of `size` bytes for
/// `commit`.
fn oversize_failure(commit: &Checksum, size: u64) -> Failure {
    Failure::Wire(push::Error::LimitExceeded(format!(
        "the merged detached metadata of commit {commit} is {size} bytes, larger than \
         {MAX_METADATA_SIZE} bytes"
    )))
}

/// Signs each new commit with each server key of its rules, before the update
/// lock.
///
/// A key makes no signature if it already signed the commit. The signature
/// can be in the merge of the filtered incoming dict into the stored dict.
/// It can also be a signature that a key before it made. As a result, two
/// keys that hold one secret sign once.
///
/// If `size` is `true`, this function then finds the size of the dict that
/// each edit writes. A session with hooks finds the size after the merge of
/// the host entries.
async fn prepare_signatures(mut edits: Vec<Edit<'_>>, size: bool) -> Checked<Vec<Edit<'_>>> {
    for edit in &mut edits {
        let signers = std::mem::take(&mut edit.signers);
        let keys = flagged(signers.iter().map(|s| s.signer().metadata_key()));
        let mut written = check_edit(
            edit.stored.clone(),
            edit.incoming.clone(),
            keys,
            !signers.is_empty(),
            edit.keep.clone(),
        )
        .await?;
        if let Some(dict) = written.as_mut() {
            for signer in signers {
                if signer.has_signed(edit.payload, Some(dict)).await {
                    continue;
                }
                let key = signer.signer().metadata_key();
                let signature = signer
                    .signer()
                    .sign(edit.payload)
                    .await
                    .map_err(|e| Failure::Internal(e.into()))?;
                append_signature(dict, key, signature.clone())
                    .map_err(|e| Failure::Internal(e.into()))?;
                edit.signatures.push(Prepared {
                    signer: signer.as_ref(),
                    signature,
                });
            }
        }
        if size {
            edit.oversize = oversize(edit, written).await?;
        }
    }
    Ok(edits)
}

/// Returns the failure for a refusal of the plan of the host, a failure on
/// the server side.
///
/// This function cuts the message to the length of a hook refusal message, at
/// a character boundary.
fn invalid_plan(mut message: String) -> Failure {
    hooks::cut(&mut message);
    Failure::Internal(Error::InvalidInput(message))
}

/// Returns a key of the host in the form that a refusal quotes.
///
/// This function cuts the key to the length of a hook refusal message, at a
/// character boundary.
fn quoted(key: &str) -> String {
    let mut key = key.to_owned();
    hooks::cut(&mut key);
    key
}

/// Checks the detached-metadata entries of the host, with no encode and no
/// I/O.
///
/// The result holds the entries of each tuple with the index of its target in
/// `targets`, the new commits of the updates. The result leaves out a tuple
/// with no entry.
///
/// The checks of each tuple run in order. Its commit must be the new commit
/// of an update, and no tuple before it can name the commit. Then the checks
/// of each entry of the tuple run in order:
///
/// - Its key is not a signature key.
/// - No entry before it in the tuple has the key.
/// - Its value is a variant.
///
/// The first failure is the refusal.
fn check_plan(
    targets: &[Checksum],
    metadata: Vec<(Checksum, Vec<HostEntry>)>,
) -> Checked<Vec<(usize, Vec<HostEntry>)>> {
    let index: HashMap<Checksum, usize> = targets
        .iter()
        .enumerate()
        .map(|(i, target)| (*target, i))
        .collect();
    let mut seen = HashSet::with_capacity(metadata.len());
    let mut plan = Vec::with_capacity(metadata.len());
    for (commit, entries) in metadata {
        let Some(&target) = index.get(&commit) else {
            return Err(invalid_plan(format!(
                "the host gives detached metadata for commit {commit}, which no ref update \
                 names as its new commit"
            )));
        };
        if !seen.insert(commit) {
            return Err(invalid_plan(format!(
                "the host gives the detached metadata of commit {commit} in two tuples"
            )));
        }
        let mut keys = HashSet::with_capacity(entries.len());
        for entry in &entries {
            let key = entry.key.as_str();
            if SIGNATURE_KEYS.contains(&key) {
                return Err(invalid_plan(format!(
                    "the host gives the signature key '{}' for commit {commit}",
                    quoted(key)
                )));
            }
            if !keys.insert(key) {
                return Err(invalid_plan(format!(
                    "the host gives the key '{}' two times for commit {commit}",
                    quoted(key)
                )));
            }
            if !matches!(entry.value, Value::Variant(_)) {
                return Err(invalid_plan(format!(
                    "the host gives the key '{}' for commit {commit} a value that is not a \
                     variant",
                    quoted(key)
                )));
            }
        }
        if !entries.is_empty() {
            plan.push((target, entries));
        }
    }
    Ok(plan)
}

/// Takes the key of the one entry of `dict`, a dict built from one host
/// entry.
fn into_key(dict: Value) -> String {
    if let Value::Array(entries) = dict
        && let Some(Value::Tuple(fields)) = entries.into_iter().next()
        && let Some(Value::Str(key)) = fields.into_iter().next()
    {
        return key;
    }
    String::new()
}

/// One commit with host entries.
///
/// The tuple holds these values:
///
/// - the index of the target of the commit
/// - its incoming dict with the host entries merged in
/// - the keys whose stored value stays
type HostMerge = (usize, Vec<u8>, Arc<Vec<String>>);

/// Adds the host entries of the plan to `edits` and finds the size of each
/// dict.
///
/// One trip to the blocking pool runs the checks of [`check_plan`] over the
/// whole plan. The same trip then drops each dict of `leftover` whose commit
/// the plan does not name. It serializes each entry as a dict of one entry and
/// checks it as an `a{sv}` in normal form. It refuses an entry that does not
/// encode.
///
/// Each commit with entries then gets the merge of its incoming dict with the
/// host entries. A host entry replaces each client entry of the same key. The
/// merge builds no value tree.
///
/// A commit that has an edit takes the merged dict as its incoming dict. A
/// commit with no edit gets a new edit with no signer. Its stored dict comes
/// from `leftover`, the dicts that the plan read and no edit took. For a
/// commit that `leftover` does not hold, this function reads the stored dict.
///
/// This function checks the stored dict of each new edit. Then it finds the
/// size of the dict of each edit, once. The plan of a session with hooks
/// leaves this step to this function. A dict with host entries over the size
/// limit is `limit-exceeded`, before the update lock.
///
/// An empty plan adds no host entry and reads no stored dict. This function
/// still finds the size of the dict of each edit.
async fn add_host_entries<'a>(
    repo: &Repo,
    targets: &'a [Target],
    mut edits: Vec<Edit<'a>>,
    leftover: HashMap<Checksum, Option<Bytes>>,
    metadata: Vec<(Checksum, Vec<HostEntry>)>,
) -> Checked<Vec<Edit<'a>>> {
    let commits: Vec<Checksum> = targets.iter().map(|target| target.checksum).collect();
    let at: HashMap<Checksum, usize> = edits
        .iter()
        .enumerate()
        .map(|(i, edit)| (edit.commit, i))
        .collect();
    // The incoming dict of each edit that the plan gives entries. A plan the
    // checks refuse ends the commit, so each dict taken here is merged.
    let mut incoming: HashMap<Checksum, Bytes> = metadata
        .iter()
        .filter(|(_, entries)| !entries.is_empty())
        .filter_map(|(commit, _)| {
            let &i = at.get(commit)?;
            Some((*commit, edits[i].incoming.take()?))
        })
        .collect();
    let (merged, mut leftover) = ostrya_rt::unblock(move || {
        let plan = check_plan(&commits, metadata)?;
        let named: HashSet<Checksum> = plan.iter().map(|(target, _)| commits[*target]).collect();
        let mut leftover = leftover;
        leftover.retain(|commit, _| named.contains(commit));
        let ty = Type::parse("a{sv}")
            .map_err(|e| Failure::Internal(ostrya_core::Error::from(e).into()))?;
        let mut encoded = Vec::with_capacity(plan.len());
        for (target, entries) in plan {
            let commit = commits[target];
            let mut host = Vec::with_capacity(entries.len());
            let mut keep = Vec::new();
            for HostEntry {
                key,
                value,
                keep_existing,
            } in entries
            {
                let dict = Value::Array(vec![Value::Tuple(vec![Value::Str(key), value])]);
                // The serializer writes the signature of a variant as the
                // type gives it. As a result, the check of the bytes refuses
                // a type that the parser does not read.
                let bytes = match to_bytes(&ty, &dict)
                    .and_then(|bytes| validate(&ty, &bytes).map(|()| bytes))
                {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        return Err(invalid_plan(format!(
                            "the host entry '{}' for commit {commit} does not encode: {e}",
                            quoted(&into_key(dict))
                        )));
                    }
                };
                if keep_existing {
                    keep.push(into_key(dict));
                }
                host.push(bytes);
            }
            encoded.push((target, host, keep));
        }
        let merged = encoded
            .into_iter()
            .map(|(target, host, keep)| {
                let incoming = incoming.remove(&commits[target]);
                let merged = replace_entries(incoming.as_deref().map(Vec::as_slice), &host)
                    .map_err(Failure::Internal)?;
                Ok((target, merged, Arc::new(keep)))
            })
            .collect::<Checked<Vec<HostMerge>>>()?;
        Ok((merged, leftover))
    })
    .await?;

    let reads: Vec<Checksum> = merged
        .iter()
        .map(|(target, ..)| targets[*target].checksum)
        .filter(|commit| !at.contains_key(commit) && !leftover.contains_key(commit))
        .collect();
    if !reads.is_empty() {
        let read = read_stored(repo, reads.clone()).await?;
        leftover.extend(reads.into_iter().zip(read));
    }
    let mut host = vec![false; edits.len()];
    let mut fresh = Vec::new();
    for (target, bytes, keep) in merged {
        let target = &targets[target];
        let incoming = Some(Arc::new(bytes));
        match at.get(&target.checksum) {
            Some(&i) => {
                edits[i].incoming = incoming;
                edits[i].keep = keep;
                host[i] = true;
            }
            None => {
                let stored = leftover.remove(&target.checksum).flatten();
                if let Some(stored) = &stored {
                    fresh.push(stored.clone());
                }
                host.push(true);
                edits.push(Edit {
                    commit: target.checksum,
                    payload: &target.bytes,
                    stored,
                    incoming,
                    keep,
                    signers: Vec::new(),
                    signatures: Vec::new(),
                    oversize: None,
                });
            }
        }
    }
    drop(leftover);
    if !fresh.is_empty() {
        ostrya_rt::unblock(move || {
            fresh
                .iter()
                .try_for_each(|stored| check_stored(stored, [false; SIGNATURE_KEYS.len()]))
        })
        .await
        .map_err(Failure::Internal)?;
    }
    for (edit, host) in edits.iter_mut().zip(host) {
        edit.oversize = match &edit.incoming {
            // If no stored dict and no signature exist, the written dict is
            // the merged dict less some blobs. It drops each blob of a
            // signature list that is byte-equal to a blob before it. As a
            // result, a merged dict that fits gives a written dict that fits.
            Some(merged)
                if host
                    && edit.stored.is_none()
                    && edit.signatures.is_empty()
                    && merged.len() as u64 <= MAX_METADATA_SIZE =>
            {
                None
            }
            _ => oversize(edit, None).await?,
        };
        if host && let Some(size) = edit.oversize {
            return Err(oversize_failure(&edit.commit, size));
        }
    }
    Ok(edits)
}

/// Queues the detached metadata of the session under the update lock.
///
/// This function reads the stored dict of each edit again, in one trip to the
/// blocking pool. If the dict holds the bytes that the plan read, the plan
/// stands. The kept signatures and the size then need no second check.
///
/// If the dict changed, this function drops some prepared signatures. It
/// drops each one whose key signed the commit in the new merge, or in a
/// signature kept before it. It then finds the size again. A dict over the
/// size limit is `limit-exceeded`.
///
/// Last, it queues the merge of each filtered incoming dict, with the keys of
/// the host entries that keep a stored value. It also queues the kept
/// signatures.
async fn queue_detached(repo: &Repo, txn: &Transaction, edits: Vec<Edit<'_>>) -> Checked<()> {
    let stored = read_stored(repo, edits.iter().map(|e| e.commit).collect()).await?;
    for (mut edit, stored) in edits.into_iter().zip(stored) {
        if stored != edit.stored {
            edit.stored = stored;
            let prepared = std::mem::take(&mut edit.signatures);
            let keys = flagged(prepared.iter().map(|p| p.signer.signer().metadata_key()));
            let mut written = check_edit(
                edit.stored.clone(),
                edit.incoming.clone(),
                keys,
                !prepared.is_empty(),
                edit.keep.clone(),
            )
            .await?;
            if let Some(dict) = written.as_mut() {
                for prepared in prepared {
                    if prepared.signer.has_signed(edit.payload, Some(dict)).await {
                        continue;
                    }
                    let key = prepared.signer.signer().metadata_key();
                    append_signature(dict, key, prepared.signature.clone())
                        .map_err(|e| Failure::Internal(e.into()))?;
                    edit.signatures.push(prepared);
                }
            }
            edit.oversize = oversize(&edit, written).await?;
        }
        if let Some(size) = edit.oversize {
            return Err(oversize_failure(&edit.commit, size));
        }
        if let Some(incoming) = edit.incoming {
            txn.merge_commit_detached(
                &edit.commit,
                Arc::unwrap_or_clone(incoming),
                Arc::unwrap_or_clone(edit.keep),
            );
        }
        for prepared in edit.signatures {
            txn.append_signature(
                &edit.commit,
                prepared.signer.signer().metadata_key(),
                prepared.signature,
            );
        }
    }
    Ok(())
}

/// Regenerates the summary and signs it with `signers`, GPG keys first.
///
/// This function makes each signature from the new bytes before any write,
/// so a failed signature leaves the old `summary` and `summary.sig`. It then
/// removes `summary.sig` before it writes `summary`. As a result, a failed
/// write never pairs the new summary with the old signatures. If the policy
/// names a summary signer, it then writes `summary.sig` with the new
/// signatures.
async fn write_summary(
    repo: &Repo,
    signers: &[Arc<ServerSigner>],
) -> std::result::Result<(), ReceiveWarning> {
    let warning = |step, what: &str, e: Error| ReceiveWarning {
        step,
        message: format!("{what}: {e}"),
    };
    let bytes = repo
        .build_summary(&SummaryOptions::default())
        .await
        .map_err(|e| warning(ReceiveStep::SummaryBuild, "the summary build", e))?;
    let is_gpg = |s: &&Arc<ServerSigner>| s.signer().metadata_key() == GPG_KEY;
    let ordered = signers
        .iter()
        .filter(is_gpg)
        .chain(signers.iter().filter(|s| !is_gpg(s)));
    let mut dict = Value::Array(Vec::new());
    for signer in ordered {
        let signer = signer.signer();
        let signature = signer.sign(&bytes).await.map_err(|e| {
            let what = format!("the summary signature with the {} key", signer.name());
            warning(ReceiveStep::SummarySign, &what, e.into())
        })?;
        append_signature(&mut dict, signer.metadata_key(), signature)
            .map_err(|e| warning(ReceiveStep::SummarySign, "the summary signature", e.into()))?;
    }
    let signatures = if signers.is_empty() {
        None
    } else {
        Some(
            serialize_signature_dict(&dict)
                .map_err(|e| warning(ReceiveStep::SummarySign, "the summary signature", e))?,
        )
    };
    let written = async {
        let fsync = repo.config().fsync()?;
        repo.remove_root_file(SUMMARY_SIG_FILE).await?;
        repo.write_root_file(SUMMARY_FILE, bytes, fsync).await?;
        match signatures {
            Some(signatures) => {
                repo.write_root_file(SUMMARY_SIG_FILE, signatures, fsync)
                    .await
            }
            None => Ok(()),
        }
    };
    written
        .await
        .map_err(|e| warning(ReceiveStep::SummaryWrite, "the summary write", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "ostree.sign.ed25519";

    /// Returns `count` updates that expect their refs absent. The request does
    /// not state an old commit, and the reply can.
    fn absent_updates(count: usize) -> Vec<RefUpdate> {
        (0..count)
            .map(|i| RefUpdate {
                name: format!("refs-{i:015}"),
                expected: Expected::Absent,
                new: Some(Checksum::from_bytes([1; 32])),
            })
            .collect()
    }

    /// The check refuses a `Commit` that fits in a frame if its reply, with an
    /// old commit for each ref, does not fit (`limit-exceeded`). A reply that
    /// fits passes, and the check is exact at the limit.
    #[test]
    fn a_commit_whose_reply_cannot_fit_is_refused() {
        let updates = absent_updates(15_000);
        let request = Message::Commit(CommitRequest {
            updates: updates.clone(),
            force: false,
        });
        let request_len = request.encode_body().unwrap().len() + 1;
        assert!(request_len <= MAX_FRAME as usize, "{request_len}");
        match check_reply_fits(&updates) {
            Err(Failure::Wire(push::Error::LimitExceeded(m))) => {
                assert!(m.contains("15000 ref updates"), "{m}")
            }
            Err(Failure::Wire(e)) => panic!("expected limit-exceeded, got {e}"),
            Err(_) => panic!("expected limit-exceeded, got another failure"),
            Ok(()) => panic!("a reply over the limit passed"),
        }
        assert!(check_reply_fits(&absent_updates(100)).is_ok());

        // The longest reply of the largest count that passes fits.
        let (mut low, mut high) = (100, 15_000);
        while high - low > 1 {
            let mid = (low + high) / 2;
            if check_reply_fits(&absent_updates(mid)).is_ok() {
                low = mid;
            } else {
                high = mid;
            }
        }
        let longest = |count| {
            Message::CommitReply(
                absent_updates(count)
                    .into_iter()
                    .map(|u| RefOutcome {
                        name: u.name,
                        old: Some(Checksum::from_bytes([2; 32])),
                        new: u.new,
                    })
                    .collect(),
            )
            .encode_body()
            .unwrap()
            .len()
                + 1
        };
        assert!(longest(low) <= MAX_FRAME as usize);
        assert!(longest(high) > MAX_FRAME as usize);
    }

    fn serialized(dict: &Value) -> Vec<u8> {
        serialize_signature_dict(dict).unwrap()
    }

    /// Returns a dict with the blobs `blobs` under [`KEY`].
    fn signed(blobs: &[&[u8]]) -> Value {
        let mut dict = Value::Array(Vec::new());
        for blob in blobs {
            append_signature(&mut dict, KEY, blob.to_vec()).unwrap();
        }
        dict
    }

    /// The size check is exact at its limit. A dict of `n` bytes is over a
    /// limit of `n - 1` and not over a limit of `n`. The dict it measures is
    /// the merge with the appended signatures. A limit more than the bound of
    /// the input sizes needs no serialization.
    #[test]
    fn the_size_check_is_exact_at_the_limit() {
        let stored = serialized(&signed(&[b"one"]));
        let incoming = serialized(&signed(&[b"one", b"two"]));
        let signatures: [(&str, &[u8]); 1] = [(KEY, b"three")];
        let written = serialized(&signed(&[b"one", b"two", b"three"]));
        let n = written.len() as u64;
        let over = |limit| {
            size_over(
                limit,
                Some(&stored),
                Some(&incoming),
                &signatures,
                None,
                &[],
            )
            .unwrap()
        };
        assert_eq!(over(n - 1), Some(n));
        assert_eq!(over(n), None);
        assert_eq!(over(0), Some(n));
        assert_eq!(over(u64::MAX), None);
        // A dict built already is measured as it stands.
        assert_eq!(
            size_over(
                n - 1,
                None,
                None,
                &[],
                Some(signed(&[b"one", b"two", b"three"])),
                &[],
            )
            .unwrap(),
            Some(n)
        );
    }

    /// The size check applies the keys that keep a stored value: the dict it
    /// measures holds the stored value under each such key.
    #[test]
    fn the_size_check_keeps_the_stored_value() {
        let blob = |len| Value::variant(Type::parse("ay").unwrap(), Value::Bytes(vec![7; len]));
        let dict = |len| {
            let mut dict = empty_dict();
            crate::commit::append_dict_entry(&mut dict, "k", blob(len)).unwrap();
            dict
        };
        let stored = serialized(&dict(100));
        let incoming = serialized(&dict(10));
        let keep = ["k".to_owned()];
        let over = |keep: &[String]| {
            size_over(0, Some(&stored), Some(&incoming), &[], None, keep).unwrap()
        };
        assert_eq!(over(&keep), Some(stored.len() as u64));
        assert_eq!(over(&[]), Some(incoming.len() as u64));
    }

    fn entry(key: &str, value: Value) -> HostEntry {
        HostEntry {
            key: key.into(),
            value,
            keep_existing: false,
        }
    }

    fn text(value: &str) -> Value {
        Value::variant(Type::Str, Value::Str(value.into()))
    }

    /// The checks of the plan of the host, in order, and the first failure
    /// is the refusal. A tuple with no entry is checked and left out.
    #[test]
    fn the_plan_checks_run_in_order() {
        let (a, b, c) = (
            Checksum::from_bytes([1; 32]),
            Checksum::from_bytes([2; 32]),
            Checksum::from_bytes([3; 32]),
        );
        let targets = [a, b];
        let sig = || entry("ostree.gpgsigs", text("x"));
        let bare = |key: &str| entry(key, Value::U32(1));
        let refused = |metadata: Vec<(Checksum, Vec<HostEntry>)>, needle: &str| match check_plan(
            &targets, metadata,
        ) {
            Err(Failure::Internal(Error::InvalidInput(m))) => {
                assert!(m.contains(needle), "{needle}: {m}")
            }
            Err(_) => panic!("{needle}: another failure"),
            Ok(_) => panic!("{needle}: the plan passed"),
        };

        let passed = |metadata| match check_plan(&targets, metadata) {
            Ok(plan) => plan,
            Err(_) => panic!("the plan was refused"),
        };
        let plan = passed(vec![
            (b, Vec::new()),
            (a, vec![entry("", text("empty key"))]),
        ]);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].0, 0);
        assert_eq!(plan[0].1, [entry("", text("empty key"))]);
        assert!(passed(Vec::new()).is_empty());

        // The checks of a tuple come before the checks of its entries.
        refused(vec![(c, vec![sig()])], "no ref update names");
        refused(vec![(c, Vec::new())], "no ref update names");
        refused(vec![(a, Vec::new()), (a, Vec::new())], "in two tuples");
        refused(vec![(a, Vec::new()), (a, vec![sig()])], "in two tuples");
        // The tuples are checked in order.
        refused(vec![(a, vec![sig()]), (c, Vec::new())], "signature key");
        refused(
            vec![(c, Vec::new()), (a, vec![sig()])],
            "no ref update names",
        );
        // The entries are checked in order, and each entry in the order of
        // its checks.
        refused(vec![(a, vec![bare("k"), sig()])], "not a variant");
        refused(vec![(a, vec![sig(), bare("k")])], "signature key");
        refused(
            vec![(a, vec![entry("k", text("x")), bare("k")])],
            "two times",
        );
        refused(vec![(a, vec![bare("ostree.sign.dummy")])], "signature key");
        for key in SIGNATURE_KEYS {
            refused(vec![(b, vec![entry(key, text("x"))])], "signature key");
        }
    }

    /// The bound of the input sizes is not less than the written size, for
    /// dicts whose framing offsets grow in the merge.
    #[test]
    fn the_size_bound_holds_when_the_offsets_grow() {
        let blobs: Vec<Vec<u8>> = (0..200u32).map(|i| i.to_le_bytes().to_vec()).collect();
        let half = blobs.len() / 2;
        let refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
        let stored = serialized(&signed(&refs[..half]));
        let incoming = serialized(&signed(&refs[half..]));
        let signature = vec![7u8; 300];
        let signatures: [(&str, &[u8]); 1] = [(KEY, &signature)];
        let mut all = refs.clone();
        all.push(&signature);
        let written = serialized(&signed(&all)).len() as u64;
        let bound = 16 * (stored.len() + incoming.len()) as u64
            + signature.len() as u64
            + 8
            + 64 * SIGNATURE_KEYS.len() as u64;
        assert!(bound >= written, "bound {bound} < written {written}");
        assert_eq!(
            size_over(
                written - 1,
                Some(&stored),
                Some(&incoming),
                &signatures,
                None,
                &[],
            )
            .unwrap(),
            Some(written)
        );
    }
}
