//! The server commit of a `Commit` message: a commit that the server makes
//! from a tree and the fields that the client sends.

use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use ostrya_core::{Checksum, ObjectType, Ref, Type, validate};

use super::finish::{
    Checked, Named, check_anchor, check_ref_paths, commit_ref, missing_objects, protocol, publish,
    report, sign_server_commit,
};
use super::hooks::{self, HookRefusal, ReceiveHooks, ReceiveServerCommit};
use super::policy::SessionPolicy;
use super::session::{Failure, ReceiveCommit, ReceiveRefOutcome};
use super::walk;
use crate::composefs::{StagedComposefsImage, digest_hex, entries_digest};
use crate::error::Error;
use crate::remote::proto::{CommitRequest, MAX_FRAME, Message, ServerCommit};
use crate::remote::{self, RefOutcome};
use crate::repo::Repo;
use crate::server_commit::{CommitFields, clock, commit_bytes};
use crate::summary::OSTREE_METADATA_REF;
use crate::transaction::Transaction;
use crate::tree::RepoTree;

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
/// `named` holds the refs of `Hello`, their canonical forms, and their
/// paths. `commit_meta` holds the detached metadata dicts of the session.
///
/// # Checks
///
/// The checks run in this order. The first failure ends the session, and the
/// session publishes nothing.
///
/// 1. The branch and each tag are valid refs, and no local ref among them is
///    64 lowercase hex characters. Each bound name is a valid ref name with
///    no `:` (`invalid-ref`). The message holds no ref update and no
///    `force`, the branch and each tag are refs of `Hello`, no ref occurs two
///    times among them, the branch and each tag are in one namespace, and a
///    commit can hold each metadata value within the depth limit of 128
///    levels of containers (`protocol`).
/// 2. The `CommitReply` fits in a frame of [`MAX_FRAME`], with an old commit
///    on the branch (`limit-exceeded`).
/// 3. The session holds no detached metadata dict and staged no commit
///    object (`protocol`).
/// 4. No ref is the local collection anchor ref of a repository with a
///    collection id, and `policy` gives the rule of the server commit, with
///    the rights of each ref in its namespace (`ref-denied`).
/// 5. The tree of the commit is complete (`missing-objects`).
///
/// The bindings and the signature verification of a commit that the client
/// built do not apply.
///
/// # Hooks
///
/// After the checks, if `[ex-ostrya] generate-composefs` of the repository is
/// `true` and the metadata of the commit carries `ostree.composefs.digest.v0`,
/// this function reads the key. A malformed key is `protocol`. Then the
/// staged objects become durable. If `hooks` are given,
/// [`ReceiveHooks::before_server_commit`] runs next with the server commit
/// and the canonical name of its branch and of each tag. If the hook
/// refuses, the session ends with the code of the refusal. The default method
/// of the trait refuses with `ref-denied`, so a host without the method
/// refuses each server commit at this step.
///
/// After the hook and before the update lock, if this function read a key, it
/// builds the composefs image of the tree and checks its digest against the
/// key. An image whose digest is not the key is `checksum-mismatch`. Each
/// other failure of the build is `internal`. After a failure, nothing is
/// published.
///
/// If a failure occurs after the hook, the carried value drops once. If the
/// update lock is held, it drops after the release of the lock.
/// `after_update` does not run.
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
/// uses. The `ostree.ref-binding` holds the name of the branch and of each
/// tag without the `@ID:` part, and each bound name. The
/// `ostree.collection-binding` is the id of the namespace of the branch: the
/// collection id of the repository for a local ref, with no key in a
/// repository with no collection id. Its timestamp is the value of the
/// client, else the system clock. The server keys of the rule sign the
/// commit. The branch moves to the commit, and each tag is created at the
/// commit. A bound name gets no ref. A failure of the build is `internal`.
///
/// If `[ex-ostrya] generate-composefs` of the repository is `true` and the
/// metadata of the commit carries `ostree.composefs.digest.v0`, the image of
/// the tree is built after the hook and before the update lock. This step
/// stages it as the composefs image of the commit. A commit that the
/// repository holds already gets no image.
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
pub(super) async fn finish(
    repo: &Repo,
    policy: &dyn SessionPolicy,
    hooks: Option<&dyn ReceiveHooks>,
    txn: Transaction,
    named: Named<'_>,
    commit_meta: HashMap<Checksum, Vec<u8>>,
    request: CommitRequest,
) -> Checked<ReceiveCommit> {
    let CommitRequest {
        updates,
        force,
        server_commit,
    } = request;
    let Some(sc) = server_commit.map(|sc| *sc) else {
        unreachable!("the commit of a session passes a request with a server commit")
    };
    let own = repo.config().collection_id();
    let indices = check_names(own, &named, &sc, updates.len(), force)?;
    let paths: Arc<[String]> = indices.iter().map(|&i| named.paths[i].clone()).collect();
    check_metadata(&sc)?;
    check_reply_fits(&sc)?;
    check_session_objects(&txn, &commit_meta)?;
    // The client text of each name goes into the reply. The server commit
    // keeps the canonical names.
    let ServerCommit {
        branch: branch_text,
        tags: tag_texts,
        bind_refs,
        root_dirtree,
        root_dirmeta,
        subject,
        body,
        metadata,
        timestamp,
        orphan,
    } = sc;
    let mut names = indices.iter().map(|&i| named.refs[i].clone());
    let sc = ReceiveServerCommit {
        branch: names.next().expect("a server commit names its branch"),
        tags: names.collect(),
        bind_refs,
        root_dirtree,
        root_dirmeta,
        subject,
        body,
        metadata,
        timestamp,
        orphan,
    };
    drop(indices);
    for name in std::iter::once(&sc.branch).chain(&sc.tags) {
        check_anchor(own.is_some(), name)?;
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
    let key = image_key(&txn, &sc)?;
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
    // The future of the build is large. The box keeps it out of the future
    // of the session.
    let image = match key {
        Some(key) => Some(Box::pin(build_image(&txn, &sc, key)).await?),
        None => None,
    };
    let held = repo.lock_update().await.map_err(Failure::Internal)?;
    let anchor = policy.regenerates_summary() && repo.config().collection_id().is_some();
    let (states, anchor_parent) = repo
        .read_ref_states(Arc::clone(&paths), anchor.then_some(OSTREE_METADATA_REF))
        .await
        .map_err(Failure::Internal)?;
    let written: Vec<(&str, &str, bool)> = std::iter::once(branch_text.as_str())
        .chain(tag_texts.iter().map(String::as_str))
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
            "ref '{branch_text}' is at {tip}, and the policy does not allow a commit with no \
             parent on it"
        ))));
    }
    for (tag, current) in tag_texts.iter().zip(&current[1..]) {
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

    let collection_id = match &sc.branch {
        Ref::Collection { id, .. } => Some(id.as_str()),
        _ => own,
    };
    let timestamp = match sc.timestamp {
        Some(timestamp) => timestamp,
        None => clock().map_err(Failure::Internal)?,
    };
    let fields = CommitFields {
        refs: std::iter::once(&sc.branch)
            .chain(&sc.tags)
            .map(Ref::name)
            .chain(sc.bind_refs.iter().map(String::as_str))
            .collect(),
        root_dirtree: sc.root_dirtree,
        root_dirmeta: sc.root_dirmeta,
        subject: &sc.subject,
        body: &sc.body,
        metadata: &sc.metadata,
        orphan: sc.orphan,
    };
    let bytes = Arc::new(
        commit_bytes(&fields, tip, timestamp, collection_id)
            .map_err(|e| Failure::Internal(e.into()))?,
    );
    drop(fields);
    // The commit bytes hold the other fields of the server commit. They are
    // freed here, so they are not held while the hook of the host runs.
    let ReceiveServerCommit {
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
    // A commit that the repository holds already is not staged, and gets no
    // image.
    if let Some(image) = image.filter(|_| txn.is_staged(&commit, ObjectType::Commit)) {
        Box::pin(txn.attach_composefs_image(&commit, image))
            .await
            .map_err(Failure::Internal)?;
    }
    sign_server_commit(repo, &txn, commit, &bytes, rule.signers).await?;
    drop(bytes);

    let moves = tip != Some(commit);
    if moves {
        txn.set_ref(&branch, Some(&commit));
    }
    for tag in &tags {
        txn.set_ref(tag, Some(&commit));
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

    let refs = std::iter::once((branch, tip))
        .chain(tags.into_iter().map(|tag| (tag, None)))
        .map(|(name, old)| ReceiveRefOutcome {
            name,
            old,
            new: Some(commit),
        })
        .collect();
    let reply = outcomes(branch_text, tag_texts, tip, commit);
    let report = report(policy, refs, stats, warnings);
    if let (Some(hooks), Some(carried)) = (hooks, carried)
        && let Err(mut message) = hooks.after_update(&report, carried).await
    {
        hooks::cut(&mut message);
        return Err(Failure::Wire(remote::Error::Internal(message)));
    }
    Ok(ReceiveCommit { report, reply })
}

/// Returns the digest that `ostree.composefs.digest.v0` of `sc` records,
/// under `[ex-ostrya] generate-composefs`.
///
/// Returns `None` with the key `false` or with no digest key. This step
/// reads no tree, so it runs before the hook of the host. A malformed key is
/// `protocol`. An error of the config read is `internal`.
fn image_key(txn: &Transaction, sc: &ReceiveServerCommit) -> Checked<Option<[u8; 32]>> {
    if !txn
        .repo()
        .config()
        .generate_composefs()
        .map_err(Failure::Internal)?
    {
        return Ok(None);
    }
    entries_digest(&sc.metadata).map_err(|e| protocol(e.to_string()))
}

/// Builds the composefs image of the tree of `sc` and checks the digest of
/// the image against `key`.
///
/// The build runs after the hook of the host, so a request that the host
/// refuses reads no tree. It runs before the update lock, so the other
/// writers of refs do not wait for it. An image whose digest is not `key` is
/// `checksum-mismatch`. Each other error of the build is `internal`.
async fn build_image<'t>(
    txn: &'t Transaction,
    sc: &ReceiveServerCommit,
    key: [u8; 32],
) -> Checked<StagedComposefsImage<'t>> {
    let tree = RepoTree::from_parts(txn.repo().clone(), sc.root_dirtree, sc.root_dirmeta);
    let image = txn
        .build_composefs_image(&tree)
        .await
        .map_err(Failure::Internal)?;
    if *image.digest() != key {
        return Err(Failure::Wire(remote::Error::ChecksumMismatch(format!(
            "the composefs image of the tree of the server commit has the fs-verity digest {}, \
             and ostree.composefs.digest.v0 records {}",
            digest_hex(image.digest()),
            digest_hex(&key)
        ))));
    }
    Ok(image)
}

/// Returns the names of the refs of `sc`, as the client sent them: the
/// branch, then each tag.
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

/// Checks the names of `sc` and the form of the message, and returns the
/// index in `named` of the branch, then of each tag.
///
/// `own` is the collection id of the repository. `updates` is the number of
/// ref updates of the message, and `force` is its `force` flag.
///
/// - The branch and each tag are refs, and no local ref among them is 64
///   lowercase hex characters, after the map of `@ID:NAME` with `ID` `own`
///   to the local ref `NAME` (`invalid-ref`).
/// - Each bound name passes the refspec rule and has no `:` (`invalid-ref`).
/// - The message holds no update and no `force` (`protocol`).
/// - The branch and each tag are refs of `Hello`, with the text of `Hello`,
///   and none occurs two times among them (`protocol`).
/// - The branch and each tag are in one namespace (`protocol`).
fn check_names(
    own: Option<&str>,
    named: &Named<'_>,
    sc: &ServerCommit,
    updates: usize,
    force: bool,
) -> Checked<Vec<usize>> {
    for name in refs(sc) {
        commit_ref(own, name, true)?;
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
    let found = named.indices(refs(sc), "written")?;
    let branch = &named.refs[found[0]];
    for &i in &found[1..] {
        let tag = &named.refs[i];
        if !same_namespace(tag, branch) {
            return Err(protocol(format!(
                "tag '{tag}' is not in the namespace of the branch '{branch}' of the server \
                 commit"
            )));
        }
    }
    Ok(found)
}

/// Returns `true` if the canonical refs `a` and `b` are in one namespace:
/// both local, both of one collection, or both of one remote.
fn same_namespace(a: &Ref, b: &Ref) -> bool {
    match (a, b) {
        (Ref::Local { .. }, Ref::Local { .. }) => true,
        (Ref::Collection { id: x, .. }, Ref::Collection { id: y, .. }) => x == y,
        (Ref::Remote { remote: x, .. }, Ref::Remote { remote: y, .. }) => x == y,
        _ => false,
    }
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

/// Checks that the session sent no detached metadata dict and staged no
/// commit object (`protocol`).
///
/// A server commit is the one commit of its session, and the server signs
/// it alone.
fn check_session_objects(
    txn: &Transaction,
    commit_meta: &HashMap<Checksum, Vec<u8>>,
) -> Checked<()> {
    if let Some(commit) = commit_meta.keys().min() {
        return Err(protocol(format!(
            "detached metadata for commit {commit} in a session with a server commit"
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
