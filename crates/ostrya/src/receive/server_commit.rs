//! The server commit of a `Commit` message: a commit that the server makes
//! from a tree and the fields that the client sends.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock};

use ostrya_core::{
    Checksum, Commit, GvDecode, GvEncode, ObjectType, Type, Value, VariantBytes, ref_binding,
    to_bytes, validate, write_array,
};

use super::finish::{
    Checked, Named, check_ref_paths, missing_objects, protocol, publish, queue_ref, ref_denied,
    report, sign_server_commit,
};
use super::hooks::ReceiveHooks;
use super::policy::SessionPolicy;
use super::session::{Failure, ReceiveReport};
use super::walk;
use crate::access::Namespace;
use crate::error::Error;
use crate::remote::proto::{CommitRequest, MAX_FRAME, Message, ServerCommit};
use crate::remote::{self, RefOutcome};
use crate::repo::Repo;
use crate::summary::OSTREE_METADATA_REF;
use crate::transaction::Transaction;

/// The metadata key of the ref binding.
const REF_BINDING_KEY: &str = "ostree.ref-binding";
/// The metadata key of the collection binding.
const COLLECTION_BINDING_KEY: &str = "ostree.collection-binding";
/// The metadata key of the composefs digest of a commit.
const COMPOSEFS_DIGEST_KEY: &str = "ostree.composefs.digest.v0";
/// The metadata key of the size records of a commit.
const SIZES_KEY: &str = "ostree.sizes";

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
/// 4. The session has no hooks, no ref is the collection anchor ref of the
///    local refs of a repository with a collection id, and `policy` gives
///    the rule of the server commit (`ref-denied`).
/// 5. The tree of the commit is complete (`missing-objects`).
///
/// The bindings and the signature verification of a commit that the client
/// built do not apply.
///
/// # Under the update lock
///
/// After the checks, the staged objects become durable. Then this function
/// takes the update lock and reads the refs. The checks of the ref paths of
/// [`finish`](super::finish::finish) apply, with a write to each ref. The
/// branch comes first, then each tag in order:
///
/// - `orphan` on a branch that is present needs `d` on the branch
///   (`non-fast-forward`).
/// - A tag that is present is `ref-mismatch`.
///
/// Then this function builds the commit. Its parent is the commit of the
/// branch, or none with `orphan` or for an absent branch. Its metadata comes
/// from [`server_commit_metadata`]. Its timestamp is the value of the client,
/// else the system clock. The server keys of the rule sign the commit. The
/// branch moves to the commit, and each tag is created at the commit. A bound
/// name gets no ref. A failure of the build is `internal`.
///
/// The steps of [`publish`] follow. The report holds the outcome of the
/// branch, then the outcome of each tag.
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
    if hooks.is_some() {
        return Err(ref_denied(
            "the session has the hooks of a host, which take no server commit".into(),
        ));
    }
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
    let ServerCommit {
        branch,
        tags,
        bind_refs,
        root_dirtree,
        root_dirmeta,
        subject,
        body,
        metadata,
        timestamp,
        orphan,
    } = sc;
    let bound: Vec<&str> = std::iter::once(branch.as_str())
        .chain(tags.iter().map(String::as_str))
        .chain(bind_refs.iter().map(String::as_str))
        .collect();
    let timestamp = match timestamp {
        Some(timestamp) => timestamp,
        None => server_clock().map_err(Failure::Internal)?,
    };
    let core = |e: ostrya_core::Error| Failure::Internal(e.into());
    let metadata = server_commit_metadata(metadata, &bound, collection_id).map_err(core)?;
    let bytes = Commit {
        metadata: Value::Array(Vec::new()),
        parent: if orphan { None } else { tip },
        related: Vec::new(),
        subject,
        body,
        timestamp,
        root_dirtree,
        root_dirmeta,
    }
    .serialize_with_metadata(&metadata)
    .map_err(core)?;
    drop(metadata);
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
    let refs = outcomes(branch, tags, tip, commit);
    Ok(report(policy, named.namespace, refs, stats, warnings))
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

/// Returns the time of the system clock in seconds since the Unix epoch, UTC.
///
/// The server reads no `SOURCE_DATE_EPOCH`.
fn server_clock() -> crate::error::Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|now| now.as_secs())
        .map_err(|_| Error::InvalidFormat("the system clock is before the Unix epoch".into()))
}

/// Returns the serialized `a{sv}` metadata dict of a server commit.
///
/// Each entry of `client` is a key and the bytes of a `v` in normal form,
/// which [`check_metadata`] checked. The call copies these bytes into the
/// dict and builds no value tree of them. The dict holds these entries, in
/// this order, which is the order of a commit of the `ostree` command:
///
/// 1. Each entry of `client`, in order, with duplicate keys kept. The entries
///    under `ostree.ref-binding` and `ostree.collection-binding` are dropped.
///    The entries under `ostree.composefs.digest.v0` and `ostree.sizes` come
///    later.
/// 2. `ostree.ref-binding` with `refs`, sorted byte-wise, duplicates kept.
/// 3. `ostree.collection-binding` with `collection_id`, if it is set.
/// 4. Each entry of `client` under `ostree.composefs.digest.v0`, in order.
/// 5. Each entry of `client` under `ostree.sizes`, in order.
fn server_commit_metadata(
    client: Vec<(String, Vec<u8>)>,
    refs: &[&str],
    collection_id: Option<&str>,
) -> ostrya_core::Result<Vec<u8>> {
    let refs = to_bytes(&Type::Variant, &ref_binding(refs))?;
    let collection = collection_id
        .map(|id| to_bytes(&Type::Variant, &Value::variant(Type::Str, id.into())))
        .transpose()?;
    let mut entries = Vec::with_capacity(client.len() + 2);
    let mut digests = Vec::new();
    let mut sizes = Vec::new();
    for (key, value) in &client {
        let entry = (key.as_str(), value.as_slice());
        match entry.0 {
            REF_BINDING_KEY | COLLECTION_BINDING_KEY => {}
            COMPOSEFS_DIGEST_KEY => digests.push(entry),
            SIZES_KEY => sizes.push(entry),
            _ => entries.push(entry),
        }
    }
    entries.push((REF_BINDING_KEY, &refs));
    if let Some(collection) = &collection {
        entries.push((COLLECTION_BINDING_KEY, collection));
    }
    entries.extend(digests);
    entries.extend(sizes);
    let mut dict = Vec::new();
    write_array(&mut dict, 8, false, entries.len(), |out, i| {
        let (key, value) = entries[i];
        (key, VariantBytes::decode(value)?).encode(out)
    })?;
    Ok(dict)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ostrya_core::from_bytes;

    fn text(value: &str) -> Value {
        Value::variant(Type::Str, Value::Str(value.into()))
    }

    /// An entry of the client: `key` and the bytes of the `v` `value`.
    fn entry(key: &str, value: Value) -> (String, Vec<u8>) {
        (key.into(), to_bytes(&Type::Variant, &value).unwrap())
    }

    /// Returns the dict of the serialized `a{sv}` `dict` as a value tree.
    fn parse_dict(dict: &[u8]) -> Value {
        from_bytes(&Type::parse("a{sv}").unwrap(), dict).unwrap()
    }

    /// The keys of the dict, in order.
    fn keys(dict: &Value) -> Vec<String> {
        let Value::Array(items) = dict else {
            panic!("the dict is an array")
        };
        items
            .iter()
            .map(|item| match item {
                Value::Tuple(fields) => match &fields[0] {
                    Value::Str(key) => key.clone(),
                    other => panic!("a key {other:?}"),
                },
                other => panic!("an entry {other:?}"),
            })
            .collect()
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

    /// The binding keys of the client are dropped, each occurrence. The other
    /// entries keep their order and their duplicates, the digest and the sizes
    /// come after the binding keys, and the ref binding is sorted with its
    /// duplicates. The bytes are the bytes of the dict as a value tree.
    #[test]
    fn the_metadata_has_the_order_of_commit() {
        let client = vec![
            entry(SIZES_KEY, text("sizes")),
            entry("b", text("1")),
            entry(REF_BINDING_KEY, text("x")),
            entry(COMPOSEFS_DIGEST_KEY, text("digest")),
            entry("a", text("2")),
            entry(COLLECTION_BINDING_KEY, text("y")),
            entry("b", text("3")),
            entry(REF_BINDING_KEY, text("z")),
        ];
        let refs = ["main", "v1", "alias", "main"];
        let bytes = server_commit_metadata(client, &refs, Some("org.a")).unwrap();
        let dict = parse_dict(&bytes);
        assert_eq!(
            keys(&dict),
            [
                "b",
                "a",
                "b",
                REF_BINDING_KEY,
                COLLECTION_BINDING_KEY,
                COMPOSEFS_DIGEST_KEY,
                SIZES_KEY,
            ]
        );
        assert_eq!(dict.dict_get("b"), Some(&text("1")));
        let tree = |key: &str, value: Value| (key.to_owned(), value);
        let mut expected = ostrya_core::commit_metadata(
            [
                tree("b", text("1")),
                tree("a", text("2")),
                tree("b", text("3")),
            ],
            Some(&refs),
            Some("org.a"),
        );
        if let Value::Array(items) = &mut expected {
            for (key, value) in [(COMPOSEFS_DIGEST_KEY, "digest"), (SIZES_KEY, "sizes")] {
                items.push(Value::Tuple(vec![Value::Str(key.into()), text(value)]));
            }
        }
        assert_eq!(
            bytes,
            to_bytes(&Type::parse("a{sv}").unwrap(), &expected).unwrap()
        );
        let commit = Commit {
            metadata: dict,
            parent: None,
            related: Vec::new(),
            subject: String::new(),
            body: String::new(),
            timestamp: 0,
            root_dirtree: Checksum::from_bytes([1; 32]),
            root_dirmeta: Checksum::from_bytes([2; 32]),
        };
        let commit = Commit::parse(&commit.serialize().unwrap()).unwrap();
        assert_eq!(commit.ref_bindings(), ["alias", "main", "main", "v1"]);
        assert_eq!(commit.collection_binding(), Some("org.a"));
    }

    /// With no collection id, the dict holds no collection binding.
    #[test]
    fn no_collection_id_writes_no_collection_binding() {
        let bytes = server_commit_metadata(vec![entry("k", text("v"))], &["main"], None).unwrap();
        assert_eq!(keys(&parse_dict(&bytes)), ["k", REF_BINDING_KEY]);
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
