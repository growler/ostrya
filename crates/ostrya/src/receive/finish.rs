//! The `Commit` message that ends a push session: the checks of the ref
//! updates, the server signatures, the update lock, the ref writes, the
//! transaction commit, and the summary.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::os::fd::AsFd;
use std::sync::Arc;

use ostrya_core::{Checksum, Commit, ObjectName, ObjectType, Value, loose_path};

use super::ancestry::{Parents, Walks};
use super::merge::{SIGNATURE_KEYS, check_stored, merge_detached, signature_keys_in};
use super::session::{Failure, ReceiveReport, ReceiveStep, ReceiveWarning};
use super::walk::{self, Missing};
use super::{ReceivePolicy, ReceiveRule, ReceiveVerify, ServerSigner, TrustedKeys};
use crate::MAX_METADATA_SIZE;
use crate::error::{Error, Result};
use crate::object::read_meta_object;
use crate::push::proto::CommitRequest;
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

/// The detached-metadata key of GPG signatures. The summary signatures of
/// this key come first in `summary.sig`, where the tool writes them.
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
    /// The dict the repository held when the plan was made, `None` for no
    /// dict.
    stored: Option<Bytes>,
    /// The filtered incoming dict.
    incoming: Option<Bytes>,
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

/// Run the checks of the ref updates of `request`, then write the refs and
/// commit `txn` under the update lock.
///
/// `named` holds the refs of `Hello`, and `commit_meta` the detached metadata
/// dicts of the session. The checks run in this order, and the first failure
/// ends the session with nothing published:
///
/// - each ref name is valid (`invalid-ref`), the message holds one update at
///   least, and each update names a ref of `Hello` once (`protocol`);
/// - each detached metadata dict belongs to a commit of the session: a
///   staged commit, or the new commit of an update (`protocol`);
/// - the rule of each update accepts it, and no update names the collection
///   anchor ref of a repository with a collection id (`ref-denied`);
/// - each new commit is staged or present (`missing-objects`), and each commit
///   of the session parses;
/// - the tree of each commit of the session is complete (`missing-objects`);
/// - the ref and collection bindings of each new commit name its refs and the
///   repository (`binding-mismatch`);
/// - each new commit passes the signature check of each of its rules, over the
///   union of the stored and the incoming detached metadata
///   (`signature-required`).
///
/// The staged objects are then made durable. At the same time the incoming
/// detached metadata is filtered, and each new commit gets a signature from
/// each server key of its rules, unless the key already signed it in the
/// merge of the filtered incoming dict into the stored dict, or in a
/// signature kept before it. The size of each dict the commit is to write is
/// found then too. The fast-forward walk of each update reads the parent
/// chain as far as the ref tips read before the lock, unless the client sent
/// `force` and the rule allows a non-fast-forward update.
///
/// Under the lock the refs are read again. A ref that is an alias, a path
/// that a ref write cannot replace, and two updates of which one names a
/// directory of the other are `ref-denied`. Each update is then checked
/// against the state it expects (`ref-mismatch`), for a delete
/// (`delete-denied`), and for a fast-forward (`non-fast-forward`). The stored
/// detached metadata is read again: where it changed since the plan, the
/// signatures of each prepared key are checked again over the new merge, and
/// the size is found again. A dict over the size limit is `limit-exceeded`.
/// The merges, the signatures, and the refs that change are queued, and so is
/// the anchor commit of a repository with a collection id where the summary
/// is regenerated. The transaction then commits. The partial marker of each
/// commit of the session is removed, and the summary is regenerated and signed
/// where the policy asks for it. A failure of these last steps is a warning of
/// the report.
pub(super) async fn finish(
    repo: &Repo,
    policy: &ReceivePolicy,
    txn: Transaction,
    named: &[String],
    commit_meta: HashMap<Checksum, Vec<u8>>,
    request: CommitRequest,
) -> Checked<ReceiveReport> {
    let CommitRequest { updates, force } = request;
    check_names(named, &updates)?;
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
    drop(stored);

    let (synced, edits) =
        futures_lite::future::zip(txn.sync_staged(), prepare_signatures(edits)).await;
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

    let refs = updates
        .into_iter()
        .zip(current)
        .map(|(update, old)| RefOutcome {
            name: update.name,
            old,
            new: update.new,
        })
        .collect();
    Ok(ReceiveReport {
        refs,
        stats,
        warnings,
    })
}

/// Each ref name is valid, the message holds one update at least, and each
/// update names a ref of `Hello`, once.
fn check_names(named: &[String], updates: &[RefUpdate]) -> Checked<()> {
    for update in updates {
        crate::validate_refspec(&update.name).map_err(|e| match e {
            Error::InvalidRefspec(_) => Failure::Wire(push::Error::InvalidRef(format!(
                "invalid ref name '{}'",
                update.name
            ))),
            other => Failure::Internal(other),
        })?;
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

/// Each detached metadata dict of the session belongs to a commit of the
/// session: a commit the session staged, or the new commit of an update. A
/// dict for any other commit would edit the detached metadata of a commit
/// that no rule of the message covers.
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

/// The rule of each update, in order. An update that no rule covers, one whose
/// rule refuses it, and one of the anchor ref of a repository with a
/// collection id are `ref-denied`.
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

/// One commit as [`read_commits`] gives it.
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

/// Read and parse the commits of the session: the new commit of each update,
/// and each staged commit. The reads and the parses run in one trip to the
/// blocking pool, and a commit is read from the staging directory before
/// `objects/`.
///
/// A new commit that is neither staged nor present is `missing-objects`. A
/// staged commit that does not parse is `protocol`, and a stored one that does
/// not parse fails on the server side.
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

/// Read and parse `reads`, each a commit and whether the session staged it,
/// on the blocking pool. The first `targets` are new commits, which keep their
/// bytes and read as absent where the repository does not hold them.
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

/// The `missing-objects` failure for `missing`, the objects `what`.
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

/// The `ostree.ref-binding` of each new commit lists each ref whose new value
/// it is, the remote part of a remote ref left out. Where the repository has a
/// collection id, the `ostree.collection-binding` of each new commit is that
/// id. A commit without the key passes.
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

/// The trusted keys of the rules of the updates of `target`, each set once.
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

/// The union of the server keys of the rules of the updates of `target`, each
/// key once.
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

/// Read the detached metadata the repository holds for each commit whose
/// dict a later step reads: each new commit with a signature check or a
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

/// The detached metadata dict the repository holds for each of `commits`, in
/// order, read in one trip to the blocking pool: `None` for no file and for
/// the zero-length "no metadata" marker.
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

/// The merge of `incoming` into `stored`, each a serialized dict, or `None`
/// where neither holds a dict.
fn merged_dict(stored: Option<&[u8]>, incoming: Option<&[u8]>) -> Result<Option<Value>> {
    let stored = stored.map(parse_signature_dict).transpose()?.flatten();
    match incoming.map(parse_signature_dict).transpose()?.flatten() {
        Some(incoming) => merge_detached(stored, incoming).map(Some),
        None => Ok(stored),
    }
}

/// An empty `a{sv}` dict.
fn empty_dict() -> Value {
    Value::Array(Vec::new())
}

/// Each new commit passes the signature check of each rule of its updates,
/// once for each set of trusted keys. The check reads the union of the
/// detached metadata the repository holds for the commit and the incoming
/// dict, before the detached-metadata filter. The union is built on the
/// blocking pool.
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

/// The state of each ref under the lock, as the commit it names. A ref that
/// is an alias, a path that a ref write cannot replace, and two updates that
/// write refs of which one names a directory of the other are `ref-denied`.
/// No ref write could then complete, and the check runs before anything is
/// queued.
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

/// Check one update against the state of its ref under the lock, and tell
/// whether the update changes the ref.
///
/// The ref must be in the state the update expects, also for `Any`. A delete of
/// a ref that is present needs `allow_delete`. A new commit that differs from
/// the current one must have it in its parent chain, unless the client sent
/// `force` and the rule has `allow_non_fast_forward`. `chain` is the walk made
/// before the lock, where one was made. A delete of an absent ref and an update
/// to the current commit change nothing.
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

/// Each incoming detached metadata dict, with the keys the filter excludes
/// removed, on the blocking pool. A dict the filter empties is left out.
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

/// The detached-metadata edits of the session: one for each new commit with a
/// server key or a filtered incoming dict, and one for each other commit with
/// a filtered incoming dict. Each takes its stored dict out of `stored`.
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

/// The keys of [`SIGNATURE_KEYS`] among `keys`, as the flags of
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

/// Check on the blocking pool that an edit accepts `stored`, with signatures
/// appended under `keys`, and give the merge of `incoming` into it where
/// `build` asks for the merged dict. A stored dict the edit refuses fails on
/// the server side.
async fn check_edit(
    stored: Option<Bytes>,
    incoming: Option<Bytes>,
    keys: [bool; SIGNATURE_KEYS.len()],
    build: bool,
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
            merged_dict(stored, incoming)?.unwrap_or_else(empty_dict),
        ))
    })
    .await
    .map_err(Failure::Internal)
}

/// The size of the dict an edit writes, where it is over `limit` bytes: the
/// merge of `incoming` into `stored`, each a serialized dict, with
/// `signatures` appended. `written`, where given, is that dict already built.
///
/// A bound from the sizes of the inputs skips the serialization where it
/// shows the dict fits. Each entry and each blob of the written dict is a
/// stored or an incoming one, or a new signature. Relative to its place in
/// its source, an entry gains at most 7 bytes of padding and 7 bytes of
/// framing offset, and a blob at most 7 bytes of framing offset. Each such
/// element holds at least one byte of framing offset in its source, so the
/// copied elements come to at most 15 times the source bytes. A new signature
/// adds its bytes and at most 8 bytes of offset. A signature list that no
/// source holds adds its key, its type, and their padding and offsets, at
/// most 64 bytes for each of the four keys. Above the bound the dict is
/// built and serialized, so the check is exact.
fn size_over(
    limit: u64,
    stored: Option<&[u8]>,
    incoming: Option<&[u8]>,
    signatures: &[(&str, &[u8])],
    written: Option<Value>,
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
            let mut dict = merged_dict(stored, incoming)?.unwrap_or_else(empty_dict);
            for (key, signature) in signatures {
                append_signature(&mut dict, key, signature.to_vec())?;
            }
            dict
        }
    };
    let size = serialize_signature_dict(&dict)?.len() as u64;
    Ok((size > limit).then_some(size))
}

/// [`size_over`] for `edit`, with `MAX_METADATA_SIZE` and the kept
/// signatures, on the blocking pool.
async fn oversize(edit: &Edit<'_>, written: Option<Value>) -> Checked<Option<u64>> {
    let stored = edit.stored.clone();
    let incoming = edit.incoming.clone();
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
        )
    })
    .await
    .map_err(Failure::Internal)
}

/// Sign each new commit with each server key of its rules, before the
/// update lock. A key that already signed the commit in the merge of the
/// filtered incoming dict into the stored dict, or in a signature made before
/// it, makes no signature, so two keys that hold one secret sign once. The
/// size of the dict each edit writes is then found.
async fn prepare_signatures(mut edits: Vec<Edit<'_>>) -> Checked<Vec<Edit<'_>>> {
    for edit in &mut edits {
        let signers = std::mem::take(&mut edit.signers);
        let keys = flagged(signers.iter().map(|s| s.signer().metadata_key()));
        let mut written = check_edit(
            edit.stored.clone(),
            edit.incoming.clone(),
            keys,
            !signers.is_empty(),
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
        edit.oversize = oversize(edit, written).await?;
    }
    Ok(edits)
}

/// Queue the detached metadata of the session under the update lock.
///
/// The stored dict of each edit is read again, in one trip to the blocking
/// pool. Where it holds the bytes the plan read, the plan stands: the kept
/// signatures and the size need no second check. Where it changed, each
/// prepared signature whose key signed the commit in the new merge, or in a
/// signature kept before it, is dropped, and the size is found again. A dict
/// over the size limit is `limit-exceeded`. The merge of each filtered
/// incoming dict and the kept signatures are then queued.
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
            return Err(Failure::Wire(push::Error::LimitExceeded(format!(
                "the merged detached metadata of commit {} is {size} bytes, larger than \
                 {MAX_METADATA_SIZE} bytes",
                edit.commit
            ))));
        }
        if let Some(incoming) = edit.incoming {
            txn.merge_commit_detached(&edit.commit, Arc::unwrap_or_clone(incoming));
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

/// Regenerate the summary and sign it with `signers`, GPG keys first. Each
/// signature is made from the bytes just built, before any write, so a failed
/// signature leaves the old `summary` and `summary.sig`. `summary.sig` is then
/// removed before `summary` is written, so a failed write never pairs the new
/// summary with the old signatures. Where the policy names a summary signer,
/// `summary.sig` is then written with the new signatures.
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

    fn serialized(dict: &Value) -> Vec<u8> {
        serialize_signature_dict(dict).unwrap()
    }

    /// A dict with the blobs `blobs` under [`KEY`].
    fn signed(blobs: &[&[u8]]) -> Value {
        let mut dict = Value::Array(Vec::new());
        for blob in blobs {
            append_signature(&mut dict, KEY, blob.to_vec()).unwrap();
        }
        dict
    }

    /// The size check is exact at its limit: a dict of `n` bytes is over a
    /// limit of `n - 1` and not over a limit of `n`. The dict it measures is
    /// the merge with the appended signatures, and a limit above the bound of
    /// the input sizes needs no serialization.
    #[test]
    fn the_size_check_is_exact_at_the_limit() {
        let stored = serialized(&signed(&[b"one"]));
        let incoming = serialized(&signed(&[b"one", b"two"]));
        let signatures: [(&str, &[u8]); 1] = [(KEY, b"three")];
        let written = serialized(&signed(&[b"one", b"two", b"three"]));
        let n = written.len() as u64;
        let over =
            |limit| size_over(limit, Some(&stored), Some(&incoming), &signatures, None).unwrap();
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
                Some(signed(&[b"one", b"two", b"three"]))
            )
            .unwrap(),
            Some(n)
        );
    }

    /// The bound of the input sizes is not below the written size, for dicts
    /// whose framing offsets grow in the merge.
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
                None
            )
            .unwrap(),
            Some(written)
        );
    }
}
