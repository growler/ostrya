//! The server commit of a `Commit` message: a commit that the server makes
//! from a tree and the fields that the client sends.

use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock};

use ostrya_core::{Checksum, ObjectType, Type, validate};

use super::finish::{
    Checked, Named, check_ref_paths, missing_objects, protocol, publish, queue_ref, ref_denied,
    report, sign_server_commit,
};
use super::hooks::{self, HookRefusal, ReceiveHooks};
use super::policy::SessionPolicy;
use super::session::{Failure, ReceiveReport};
use super::walk;
use crate::access::Namespace;
use crate::error::Error;
use crate::remote::proto::{CommitRequest, MAX_FRAME, Message, ServerCommit};
use crate::remote::{self, RefOutcome};
use crate::repo::Repo;
use crate::server_commit::{clock, commit_bytes};
use crate::summary::OSTREE_METADATA_REF;
use crate::transaction::Transaction;

/// The type of a `v` at the depth of a metadata value in a commit.
///
/// The codec of a commit reads and writes its metadata dict with the depth
/// limit counted from the dict. In the dict, the `v` of an entry is under two
/// containers: the `a{sv}` dict and the `{sv}` entry. A tuple with one member
/// of variable size holds the bytes of the member and no framing, so the
/// bytes of a `v` are also the bytes of `((v))`. A check of the bytes as this
/// type applies the depth limit of the commit to the value.
static VALUE_IN_COMMIT: LazyLock<Type> =
    LazyLock::new(|| Type::parse("((v))").expect("valid signature"));

/// Runs the checks of a `Commit` with a server commit, then writes the
/// commit and its refs and commits `txn` under the update lock.
///
/// `named` holds the refs of `Hello`, their paths, and their namespace.
/// `commit_meta` holds the detached metadata dicts of the session.
///
/// # Checks
///
/// The checks run in this order. The first failure ends the session, and the
/// session publishes nothing.
///
/// 1. The branch and each tag are valid ref names, and none is 64 lowercase
///    hex characters. Each bound name is a valid ref name with no `:`
///    (`invalid-ref`). The message holds no ref update and no `force`, the
///    branch and each tag are refs of `Hello`, no ref occurs two times among
///    them, and a commit can hold each metadata value within the depth
///    limit of 128 levels of containers (`protocol`).
/// 2. The `CommitReply` fits in a frame of [`MAX_FRAME`], with an old commit
///    on the branch (`limit-exceeded`).
/// 3. The session holds no detached metadata dict and no composefs image,
///    and staged no commit object (`protocol`).
/// 4. No ref is the collection anchor ref of the local refs of a repository
///    with a collection id, and `policy` gives the rule of the server commit
///    (`ref-denied`).
/// 5. The tree of the commit is complete (`missing-objects`).
///
/// The bindings and the signature verification of a commit that the client
/// built do not apply.
///
/// # Hooks
///
/// After the checks, the staged objects become durable. If `hooks` are given,
/// [`ReceiveHooks::before_server_commit`] runs next with `sc`, immediately
/// before the update lock. If the hook refuses, the session ends with the
/// code of the refusal. The default method of the trait refuses with
/// `ref-denied`, so a host without the method refuses each server commit at
/// this step.
///
/// If a failure occurs after the hook, the carried value drops once, after
/// the release of the update lock. `after_update` does not run.
///
/// # Under the update lock
///
/// Then this function takes the update lock and reads the refs. The checks of
/// the ref paths of [`finish`](super::finish::finish) apply, with a write to
/// each ref. The branch comes first, then each tag in order:
///
/// - `orphan` on a branch that is present needs `d` on the branch
///   (`non-fast-forward`).
/// - A tag that is present is `ref-mismatch`.
///
/// Then this function builds the commit. Its parent is the commit of the
/// branch, or none with `orphan` or for an absent branch. Its metadata comes
/// from the commit builder that the tree push to a bucket repository also
/// uses. Its timestamp is the value of the client,
/// else the system clock. The server keys of the rule sign the commit. The
/// branch moves to the commit, and each tag is created at the commit. A bound
/// name gets no ref. A failure of the build is `internal`.
///
/// The steps of [`publish`] follow. The report holds the outcome of the
/// branch, then the outcome of each tag.
///
/// # After the update lock
///
/// [`publish`] releases the update lock. If `hooks` are given,
/// [`ReceiveHooks::after_update`] runs next with the report and the carried
/// value. An error of the hook is `internal`, with the message cut at 4096
/// bytes at a character boundary. After an error of the hook, the refs stay
/// written.
#[allow(clippy::too_many_arguments)]
pub(super) async fn finish(
    repo: &Repo,
    policy: &dyn SessionPolicy,
    hooks: Option<&dyn ReceiveHooks>,
    txn: Transaction,
    named: Named<'_>,
    commit_meta: HashMap<Checksum, Vec<u8>>,
    images: HashMap<Checksum, Option<[u8; 32]>>,
    request: CommitRequest,
) -> Checked<ReceiveReport> {
    let CommitRequest {
        updates,
        force,
        server_commit,
    } = request;
    let Some(sc) = server_commit.map(|sc| *sc) else {
        unreachable!("the commit of a session passes a request with a server commit")
    };
    let paths: Arc<[String]> = check_names(&named, &sc, updates.len(), force)?.into();
    check_metadata(&sc)?;
    check_reply_fits(&sc)?;
    check_session_objects(&txn, &commit_meta, &images)?;
    if named.is_local() && repo.config().collection_id().is_some() {
        for name in refs(&sc) {
            if name == OSTREE_METADATA_REF {
                return Err(ref_denied(format!(
                    "ref '{name}' holds the collection anchor commit, which the server writes"
                )));
            }
        }
    }
    let rule = policy.server_commit_rule(&sc.branch, &sc.tags)?;
    let root = (sc.root_dirtree, sc.root_dirmeta);
    let missing = walk::completeness(&txn, [root]).await?;
    if missing.total > 0 {
        return Err(missing_objects(
            missing,
            "the tree of the server commit reaches",
        ));
    }
    txn.sync_staged().await.map_err(Failure::Internal)?;

    // Declared before the update lock, so on each failure the carried value
    // drops after the lock is released. On success it goes to `after_update`,
    // after the lock is released.
    let carried: Option<Box<dyn Any + Send>> = match hooks {
        None => None,
        Some(hooks) => Some(
            hooks
                .before_server_commit(&sc)
                .await
                .map_err(HookRefusal::into_failure)?,
        ),
    };
    let held = repo.lock_update().await.map_err(Failure::Internal)?;
    let anchor = policy.regenerates_summary() && repo.config().collection_id().is_some();
    let (states, anchor_parent) = repo
        .read_ref_states(Arc::clone(&paths), anchor.then_some(OSTREE_METADATA_REF))
        .await
        .map_err(Failure::Internal)?;
    let written: Vec<(&str, &str, bool)> = refs(&sc)
        .zip(paths.iter())
        .map(|(name, path)| (name, path.as_str(), true))
        .collect();
    let current = check_ref_paths(&written, &states)?;
    drop(written);
    let tip = current[0];
    if let Some(tip) = tip
        && sc.orphan
        && !rule.allow_orphan_over_branch
    {
        return Err(Failure::Wire(remote::Error::NonFastForward(format!(
            "ref '{}' is at {tip}, and the policy does not allow a commit with no parent on it",
            sc.branch
        ))));
    }
    for (tag, current) in sc.tags.iter().zip(&current[1..]) {
        if let Some(commit) = current {
            return Err(Failure::Wire(remote::Error::RefMismatch {
                message: format!(
                    "ref '{tag}' is at {commit}, and a tag of a server commit creates its ref"
                ),
                name: tag.clone(),
                current: Some(*commit),
            }));
        }
    }

    let collection_id = match named.namespace {
        Some(Namespace::Collection(id)) => Some(id.as_str()),
        _ => repo.config().collection_id(),
    };
    let timestamp = match sc.timestamp {
        Some(timestamp) => timestamp,
        None => clock().map_err(Failure::Internal)?,
    };
    let bytes = Arc::new(
        commit_bytes(&sc, tip, timestamp, collection_id)
            .map_err(|e| Failure::Internal(e.into()))?,
    );
    // The commit bytes hold the other fields of the server commit. They are
    // freed here, so they are not held while the hook of the host runs.
    let ServerCommit {
        branch,
        tags,
        bind_refs,
        subject,
        body,
        metadata,
        ..
    } = sc;
    drop((bind_refs, subject, body, metadata));
    let commit = txn
        .write_metadata(ObjectType::Commit, None, &bytes)
        .await
        .map_err(Failure::Internal)?;
    sign_server_commit(repo, &txn, commit, &bytes, rule.signers).await?;
    drop(bytes);

    let moves = tip != Some(commit);
    if moves {
        queue_ref(&txn, named.namespace, &branch, Some(&commit));
    }
    for tag in &tags {
        queue_ref(&txn, named.namespace, tag, Some(&commit));
    }
    let changed = moves || !tags.is_empty();
    // The future of the publication is large. The box keeps it out of the
    // future of the checks.
    let (stats, warnings) = Box::pin(publish(
        repo,
        policy,
        txn,
        held,
        changed,
        anchor_parent,
        vec![commit],
    ))
    .await?;
    // The state of the checks is freed here, so it is not held while the
    // hook of the host runs.
    drop((paths, states, current));

    let refs = outcomes(branch, tags, tip, commit);
    let report = report(policy, named.namespace, refs, stats, warnings);
    if let (Some(hooks), Some(carried)) = (hooks, carried)
        && let Err(mut message) = hooks.after_update(&report, carried).await
    {
        hooks::cut(&mut message);
        return Err(Failure::Wire(remote::Error::Internal(message)));
    }
    Ok(report)
}

/// Returns the names of the refs of `sc`: the branch, then each tag.
fn refs(sc: &ServerCommit) -> impl Iterator<Item = &str> {
    std::iter::once(sc.branch.as_str()).chain(sc.tags.iter().map(String::as_str))
}

/// Returns the outcomes of a server commit: the branch from `tip` to
/// `commit`, then each tag from absent to `commit`.
fn outcomes(
    branch: String,
    tags: Vec<String>,
    tip: Option<Checksum>,
    commit: Checksum,
) -> Vec<RefOutcome> {
    std::iter::once(RefOutcome {
        name: branch,
        old: tip,
        new: Some(commit),
    })
    .chain(tags.into_iter().map(|name| RefOutcome {
        name,
        old: None,
        new: Some(commit),
    }))
    .collect()
}

/// Returns the `invalid-ref` failure of `name`, or the failure on the server
/// side of an error that is not a refusal of the name.
fn name_failure(e: Error, what: &str, name: &str) -> Failure {
    match e {
        Error::InvalidRefspec(_) => Failure::Wire(remote::Error::InvalidRef(format!(
            "invalid {what} '{name}'"
        ))),
        other => Failure::Internal(other),
    }
}

/// Checks the names of `sc` and the form of the message, and returns the path
/// under `refs/` of the branch, then of each tag.
///
/// `updates` is the number of ref updates of the message, and `force` is its
/// `force` flag.
///
/// - The branch and each tag pass the refspec rule and are not 64 lowercase
///   hex characters (`invalid-ref`).
/// - Each bound name passes the refspec rule and has no `:` (`invalid-ref`).
/// - The message holds no update and no `force` (`protocol`).
/// - The branch and each tag are refs of `Hello`, and none occurs two times
///   among them (`protocol`).
fn check_names(
    named: &Named<'_>,
    sc: &ServerCommit,
    updates: usize,
    force: bool,
) -> Checked<Vec<String>> {
    for name in refs(sc) {
        crate::validate_refspec(name).map_err(|e| name_failure(e, "ref name", name))?;
        // A revision reads 64 lowercase hex characters as a checksum, so the
        // server writes no commit to such a ref.
        if ostrya_core::is_checksum_shaped(name) {
            return Err(Failure::Wire(remote::Error::InvalidRef(format!(
                "invalid ref name '{name}'"
            ))));
        }
    }
    for name in &sc.bind_refs {
        crate::validate_refspec(name).map_err(|e| name_failure(e, "bound name", name))?;
        if name.contains(':') {
            return Err(Failure::Wire(remote::Error::InvalidRef(format!(
                "invalid bound name '{name}'"
            ))));
        }
    }
    if updates > 0 {
        return Err(protocol(format!(
            "the Commit message holds a server commit and {updates} ref updates"
        )));
    }
    if force {
        return Err(protocol(
            "the Commit message holds a server commit and force".into(),
        ));
    }
    let paths: HashMap<&str, &String> = named
        .names
        .iter()
        .map(String::as_str)
        .zip(named.paths)
        .collect();
    let mut seen = HashSet::with_capacity(sc.tags.len() + 1);
    let mut found = Vec::with_capacity(sc.tags.len() + 1);
    for name in refs(sc) {
        let Some(&path) = paths.get(name) else {
            return Err(protocol(format!("ref '{name}' was not named in Hello")));
        };
        if !seen.insert(name) {
            return Err(protocol(format!("ref '{name}' is written more than once")));
        }
        found.push(path.clone());
    }
    Ok(found)
}

/// Checks that a commit can hold each metadata value of `sc` (`protocol`).
///
/// The bytes of each value must be a `v` in normal form, which the decoder
/// of the message checks with the depth limit of a `v`. In a commit, the
/// `v` is two levels deeper, so this check applies the depth limit of the
/// commit. The commit takes the bytes of each value as they are, so without
/// this check a value that is too deep gives a commit that does not parse.
fn check_metadata(sc: &ServerCommit) -> Checked<()> {
    for (key, value) in &sc.metadata {
        validate(&VALUE_IN_COMMIT, value).map_err(|e| {
            protocol(format!(
                "a commit cannot hold the metadata value under '{key}': {e}"
            ))
        })?;
    }
    Ok(())
}

/// Checks that the `CommitReply` of `sc` fits in a frame of [`MAX_FRAME`].
///
/// The reply holds the branch with an old commit and each tag with no old
/// commit. A tag that is present fails under the lock, so this is the longest
/// reply. A reply over the limit is `limit-exceeded`.
fn check_reply_fits(sc: &ServerCommit) -> Checked<()> {
    let any_commit = Checksum::from_bytes([0; 32]);
    let longest = Message::CommitReply(outcomes(
        sc.branch.clone(),
        sc.tags.clone(),
        Some(any_commit),
        any_commit,
    ));
    let body = longest.encode_body().map_err(Failure::Wire)?;
    let len = body.len() as u64 + 1;
    if len > u64::from(MAX_FRAME) {
        return Err(Failure::Wire(remote::Error::LimitExceeded(format!(
            "the reply to the server commit with {} tags can need a frame of {len} bytes, over \
             the limit {MAX_FRAME}",
            sc.tags.len()
        ))));
    }
    Ok(())
}

/// Checks that the session sent no detached metadata dict and no composefs
/// image, and staged no commit object (`protocol`).
///
/// A server commit is the one commit of its session, and the server signs
/// it alone.
fn check_session_objects(
    txn: &Transaction,
    commit_meta: &HashMap<Checksum, Vec<u8>>,
    images: &HashMap<Checksum, Option<[u8; 32]>>,
) -> Checked<()> {
    if let Some(commit) = commit_meta.keys().min() {
        return Err(protocol(format!(
            "detached metadata for commit {commit} in a session with a server commit"
        )));
    }
    if let Some(commit) = images.keys().min() {
        return Err(protocol(format!(
            "a composefs image for commit {commit} in a session with a server commit"
        )));
    }
    if let Some(commit) = txn.staged_of_type(ObjectType::Commit).into_iter().min() {
        return Err(protocol(format!(
            "commit {commit} is staged in a session with a server commit"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ostrya_core::{Commit, Value, to_bytes};

    /// An entry of the client: `key` and the bytes of the `v` `value`.
    fn entry(key: &str, value: Value) -> (String, Vec<u8>) {
        (key.into(), to_bytes(&Type::Variant, &value).unwrap())
    }

    /// A server commit on `main` with the metadata `metadata`.
    fn with_metadata(metadata: Vec<(String, Vec<u8>)>) -> ServerCommit {
        ServerCommit {
            branch: "main".into(),
            tags: Vec::new(),
            bind_refs: Vec::new(),
            root_dirtree: Checksum::from_bytes([1; 32]),
            root_dirmeta: Checksum::from_bytes([2; 32]),
            subject: String::new(),
            body: String::new(),
            metadata,
            timestamp: None,
            orphan: false,
        }
    }

    /// The metadata check accepts a value exactly when a commit that holds
    /// it serializes and parses. The deepest value that a commit holds is a
    /// `y` under 125 levels of maybe.
    #[test]
    fn the_metadata_check_follows_the_depth_of_a_commit() {
        for levels in 123..=127 {
            let ty = (0..levels).fold(Type::Byte, |ty, _| Type::maybe(ty));
            let value = (0..levels).fold(Value::Byte(1), |value, _| {
                Value::Maybe(Some(Box::new(value)))
            });
            let value = Value::variant(ty, value);
            let commit = Commit {
                metadata: Value::Array(vec![Value::Tuple(vec![
                    Value::Str("deep".into()),
                    value.clone(),
                ])]),
                parent: None,
                related: Vec::new(),
                subject: String::new(),
                body: String::new(),
                timestamp: 0,
                root_dirtree: Checksum::from_bytes([1; 32]),
                root_dirmeta: Checksum::from_bytes([2; 32]),
            };
            let sc = with_metadata(vec![entry("deep", value)]);
            let checked = check_metadata(&sc);
            assert_eq!(checked.is_ok(), levels <= 125, "{levels} levels");
            let bytes = commit.serialize();
            assert_eq!(bytes.is_ok(), levels <= 125, "{levels} levels");
            if let Ok(bytes) = bytes {
                assert_eq!(Commit::parse(&bytes).unwrap(), commit, "{levels} levels");
            }
            if levels > 125 {
                assert!(
                    matches!(checked, Err(Failure::Wire(remote::Error::Protocol(_)))),
                    "{levels} levels"
                );
            }
        }
    }

    /// The reply bound of a server commit is exact: the largest count of
    /// tags that passes gives a reply that fits, and one tag more does not.
    #[test]
    fn the_reply_bound_of_a_server_commit_is_the_encoded_size() {
        let commit = |count: usize| ServerCommit {
            tags: (0..count).map(|i| format!("tag-{i:015}")).collect(),
            ..with_metadata(Vec::new())
        };
        let encoded = |count: usize| {
            let sc = commit(count);
            let any = Checksum::from_bytes([3; 32]);
            Message::CommitReply(outcomes(sc.branch, sc.tags, Some(any), any))
                .encode_body()
                .unwrap()
                .len()
                + 1
        };
        let (mut low, mut high) = (0, 30_000);
        assert!(check_reply_fits(&commit(low)).is_ok());
        assert!(check_reply_fits(&commit(high)).is_err());
        while high - low > 1 {
            let mid = (low + high) / 2;
            if check_reply_fits(&commit(mid)).is_ok() {
                low = mid;
            } else {
                high = mid;
            }
        }
        assert!(encoded(low) <= MAX_FRAME as usize);
        assert!(encoded(high) > MAX_FRAME as usize);
        match check_reply_fits(&commit(high)) {
            Err(Failure::Wire(remote::Error::LimitExceeded(m))) => {
                assert!(m.contains(&format!("{high} tags")), "{m}")
            }
            _ => panic!("expected limit-exceeded"),
        }
    }
}
