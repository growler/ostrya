//! The commit of a tree push: the parent, the metadata dict, the states of the
//! target refs, the signatures, and the ref updates.

use std::sync::LazyLock;

use ostrya_core::{Checksum, Commit, MAX_METADATA_SIZE, Type, Value, commit_metadata, to_bytes};
use ostrya_sign::Signer;

use crate::error::{Error, Result};
use crate::proto::{Expected, RefUpdate};
use crate::push_tree::ParentPolicy;
use crate::session::{ServerInfo, invalid};

/// The `a{sv}` type of a metadata dict.
static DICT_TYPE: LazyLock<Type> =
    LazyLock::new(|| Type::parse("a{sv}").expect("a{sv} is a valid signature"));

/// The type of the signature array of an engine in a detached dict.
const SIGNATURE_ARRAY: &str = "aay";

/// The entries of an `a{sv}` dict, in order, as `(key, value)` tuples. An
/// empty key, entries that do not serialize as an `a{sv}` dict, and a dict
/// over [`MAX_METADATA_SIZE`] are [`Error::InvalidInput`]. The object that
/// holds the dict is never smaller than the dict. `what` names the dict in
/// the message.
pub(crate) fn entry_dict(entries: Vec<(String, Value)>, what: &str) -> Result<Vec<Value>> {
    if entries.iter().any(|(key, _)| key.is_empty()) {
        return Err(invalid(format!("the {what} holds an empty key")));
    }
    let dict = Value::Array(
        entries
            .into_iter()
            .map(|(key, value)| Value::Tuple(vec![Value::Str(key), value]))
            .collect(),
    );
    let len = to_bytes(&DICT_TYPE, &dict)
        .map_err(|e| invalid(format!("the {what} is not an a{{sv}} dict: {e}")))?
        .len();
    if len as u64 > MAX_METADATA_SIZE {
        return Err(invalid(format!(
            "the {what} is {len} bytes, over the limit of {MAX_METADATA_SIZE}"
        )));
    }
    match dict {
        Value::Array(items) => Ok(items),
        _ => unreachable!("the dict is an array"),
    }
}

/// The key and the value of an entry that [`entry_dict`] gave.
fn split_entry(entry: Value) -> (String, Value) {
    match entry {
        Value::Tuple(fields) => match <[Value; 2]>::try_from(fields) {
            Ok([Value::Str(key), value]) => (key, value),
            _ => unreachable!("an entry is a key and a value"),
        },
        _ => unreachable!("an entry is a tuple"),
    }
}

/// The parent of the commit under `policy`. `CurrentTip` is the server tip of
/// the first target ref, or `None` when that ref is absent.
pub(crate) fn resolve_parent(
    policy: ParentPolicy,
    server: &ServerInfo,
    refs: &[String],
) -> Option<Checksum> {
    match policy {
        ParentPolicy::CurrentTip => refs.first().and_then(|name| server.tip(name)),
        ParentPolicy::None => None,
        ParentPolicy::Commit(commit) => Some(commit),
    }
}

/// Refuse target refs in mixed states: each target ref must have the state of
/// the first one, all absent or all at one tip. The message names each ref and
/// its tip.
pub(crate) fn check_ref_states(server: &ServerInfo, refs: &[String]) -> Result<()> {
    debug_assert!(names_match(server, refs));
    let Some((first, rest)) = server.refs.split_first() else {
        return Ok(());
    };
    if rest.iter().all(|state| state.commit == first.commit) {
        return Ok(());
    }
    let states = server
        .refs
        .iter()
        .map(|state| match state.commit {
            Some(tip) => format!("'{}' is at {tip}", state.name),
            None => format!("'{}' is absent", state.name),
        })
        .collect::<Vec<_>>()
        .join(", ");
    Err(invalid(format!(
        "the target refs are in mixed states on the server: {states}; without force each \
         target ref must be absent, or each must be at one commit"
    )))
}

/// Whether the session reported the state of each ref of `refs`, in the
/// order of `refs`. The session open refuses a `HelloReply` that does not.
fn names_match(server: &ServerInfo, refs: &[String]) -> bool {
    server.refs.len() == refs.len() && server.refs.iter().zip(refs).all(|(s, n)| s.name == *n)
}

/// The inputs of the commit object of a tree push.
pub(crate) struct CommitInputs<'a> {
    pub(crate) parent: Option<Checksum>,
    pub(crate) subject: String,
    pub(crate) body: String,
    pub(crate) timestamp: u64,
    /// The entries of the caller, from [`entry_dict`].
    pub(crate) metadata: Vec<Value>,
    /// The target refs, which the ref binding names.
    pub(crate) refs: &'a [String],
    /// Leave out the ref binding and the collection binding.
    pub(crate) no_bindings: bool,
    /// The collection id of the server.
    pub(crate) collection_id: Option<&'a str>,
    pub(crate) root_dirtree: Checksum,
    pub(crate) root_dirmeta: Checksum,
}

/// The checksum and the serialized bytes of the commit object over `inputs`.
///
/// The metadata dict holds the entries of the caller, in order, then
/// `ostree.ref-binding` with the target refs sorted, then
/// `ostree.collection-binding` when the server has a collection id. With
/// `no_bindings` it holds the entries of the caller alone. A commit over
/// [`MAX_METADATA_SIZE`] is [`Error::InvalidInput`].
pub(crate) fn build_commit(inputs: CommitInputs<'_>) -> Result<(Checksum, Vec<u8>)> {
    let names: Vec<&str> = inputs.refs.iter().map(String::as_str).collect();
    let bindings = (!inputs.no_bindings).then_some(names.as_slice());
    let metadata = commit_metadata(
        inputs.metadata.into_iter().map(split_entry),
        bindings,
        inputs.collection_id,
    );
    let bytes = Commit {
        metadata,
        parent: inputs.parent,
        related: Vec::new(),
        subject: inputs.subject,
        body: inputs.body,
        timestamp: inputs.timestamp,
        root_dirtree: inputs.root_dirtree,
        root_dirmeta: inputs.root_dirmeta,
    }
    .serialize()
    .map_err(|e| invalid(format!("the commit does not serialize: {e}")))?;
    if bytes.len() as u64 > MAX_METADATA_SIZE {
        return Err(invalid(format!(
            "the commit object is {} bytes, over the limit of {MAX_METADATA_SIZE}",
            bytes.len()
        )));
    }
    Ok((Checksum::sha256(&bytes), bytes))
}

/// The detached metadata dict of the commit `bytes`: the entries of the
/// caller, in order, then the signature of each signer of `signers`, in
/// order, under its `metadata_key`. `None` when the dict is empty.
///
/// A signature goes into the `aay` array of its key, after the blobs that
/// the array already holds, the array of an entry of the caller included.
/// A value of the caller under the key of a signer that is not an `aay` is
/// [`Error::Sign`] with `InvalidFormat`, and so is a failed signer. The key
/// of each signer is checked before the first signer signs. A dict
/// over [`MAX_METADATA_SIZE`] is [`Error::InvalidInput`].
pub(crate) async fn detached_dict(
    entries: Vec<Value>,
    signers: &[Box<dyn Signer>],
    bytes: &[u8],
) -> Result<Option<Value>> {
    let mut dict = Value::Array(entries);
    for signer in signers {
        let key = signer.metadata_key();
        if let Some((ty, _)) = dict.dict_get(key).and_then(Value::as_variant)
            && ty.signature() != SIGNATURE_ARRAY
        {
            return Err(Error::Sign(ostrya_sign::Error::InvalidFormat(format!(
                "the detached metadata holds '{key}' of type {}, not {SIGNATURE_ARRAY}",
                ty.signature()
            ))));
        }
    }
    for signer in signers {
        let signature = signer.sign(bytes).await.map_err(Error::Sign)?;
        ostrya_sign::append_signature(&mut dict, signer.metadata_key(), signature)
            .map_err(Error::Sign)?;
    }
    if dict.as_array().is_some_and(<[Value]>::is_empty) {
        return Ok(None);
    }
    let len = to_bytes(&DICT_TYPE, &dict)
        .map_err(|e| invalid(format!("the detached metadata does not serialize: {e}")))?
        .len();
    if len as u64 > MAX_METADATA_SIZE {
        return Err(invalid(format!(
            "the detached metadata is {len} bytes, over the limit of {MAX_METADATA_SIZE}"
        )));
    }
    Ok(Some(dict))
}

/// The ref updates that set each target ref to `commit`. Each expects the
/// state the server reported, or any state with `force`.
pub(crate) fn ref_updates(
    server: &ServerInfo,
    refs: &[String],
    commit: Checksum,
    force: bool,
) -> Vec<RefUpdate> {
    debug_assert!(names_match(server, refs));
    server
        .refs
        .iter()
        .map(|state| RefUpdate {
            name: state.name.clone(),
            expected: match (force, state.commit) {
                (true, _) => Expected::Any,
                (false, Some(tip)) => Expected::Commit(tip),
                (false, None) => Expected::Absent,
            },
            new: Some(commit),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use ostrya_core::base64;
    use ostrya_sign::{DummySigner, Ed25519Signer, Ed25519Verifier, Verifier};

    use super::*;
    use crate::proto::{Encoding, RefState};

    fn csum(byte: u8) -> Checksum {
        Checksum::from_bytes([byte; 32])
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn string(s: &str) -> Value {
        Value::variant(Type::Str, Value::Str(s.to_owned()))
    }

    fn server(collection_id: Option<&str>, refs: &[(&str, Option<Checksum>)]) -> ServerInfo {
        ServerInfo {
            version: 1,
            mode: "archive".into(),
            collection_id: collection_id.map(str::to_owned),
            max_frame: 1 << 20,
            max_have: 16_384,
            encodings: vec![Encoding::Raw],
            parallel_uploads: 1,
            refs: refs
                .iter()
                .map(|(name, commit)| RefState {
                    name: (*name).to_owned(),
                    commit: *commit,
                })
                .collect(),
        }
    }

    fn inputs<'a>(metadata: Vec<Value>, refs: &'a [String]) -> CommitInputs<'a> {
        CommitInputs {
            parent: None,
            subject: "subject".into(),
            body: "body".into(),
            timestamp: 1_700_000_000,
            metadata,
            refs,
            no_bindings: false,
            collection_id: None,
            root_dirtree: csum(1),
            root_dirmeta: csum(2),
        }
    }

    /// The keys of a dict, in order.
    fn keys(dict: &Value) -> Vec<String> {
        dict.as_array()
            .unwrap()
            .iter()
            .map(|entry| entry.as_tuple().unwrap()[0].as_str().unwrap().to_owned())
            .collect()
    }

    fn caller_entries() -> Vec<Value> {
        entry_dict(
            vec![
                ("zz.last".into(), string("1")),
                ("aa.first".into(), string("2")),
            ],
            "metadata",
        )
        .unwrap()
    }

    #[test]
    fn the_metadata_holds_the_caller_entries_then_the_bindings() {
        let refs = strings(&["b", "a"]);
        let (checksum, bytes) = build_commit(CommitInputs {
            collection_id: Some("org.example.C"),
            ..inputs(caller_entries(), &refs)
        })
        .unwrap();
        assert_eq!(checksum, Checksum::sha256(&bytes));
        let commit = Commit::parse(&bytes).unwrap();
        assert_eq!(
            keys(&commit.metadata),
            [
                "zz.last",
                "aa.first",
                "ostree.ref-binding",
                "ostree.collection-binding"
            ]
        );
        assert_eq!(commit.ref_bindings(), ["a", "b"]);
        assert_eq!(commit.collection_binding(), Some("org.example.C"));
        let want = commit_metadata(
            [
                ("zz.last".to_owned(), string("1")),
                ("aa.first".to_owned(), string("2")),
            ],
            Some(&["b", "a"]),
            Some("org.example.C"),
        );
        assert_eq!(commit.metadata, want);
    }

    #[test]
    fn no_bindings_leaves_out_both_bindings() {
        let refs = strings(&["main"]);
        let (_, bytes) = build_commit(CommitInputs {
            no_bindings: true,
            collection_id: Some("org.example.C"),
            ..inputs(caller_entries(), &refs)
        })
        .unwrap();
        let commit = Commit::parse(&bytes).unwrap();
        assert_eq!(keys(&commit.metadata), ["zz.last", "aa.first"]);
    }

    #[test]
    fn the_collection_binding_needs_a_server_collection_id() {
        let refs = strings(&["main"]);
        let (_, bytes) = build_commit(inputs(Vec::new(), &refs)).unwrap();
        let commit = Commit::parse(&bytes).unwrap();
        assert_eq!(keys(&commit.metadata), ["ostree.ref-binding"]);
        assert_eq!(commit.collection_binding(), None);
    }

    #[test]
    fn the_commit_carries_its_fields() {
        let refs = strings(&["main"]);
        let (_, bytes) = build_commit(CommitInputs {
            parent: Some(csum(9)),
            ..inputs(Vec::new(), &refs)
        })
        .unwrap();
        let commit = Commit::parse(&bytes).unwrap();
        assert_eq!(commit.parent, Some(csum(9)));
        assert_eq!(commit.subject, "subject");
        assert_eq!(commit.body, "body");
        assert_eq!(commit.timestamp, 1_700_000_000);
        assert_eq!(commit.root_dirtree, csum(1));
        assert_eq!(commit.root_dirmeta, csum(2));
        assert!(commit.related.is_empty());
    }

    #[test]
    fn a_metadata_dict_with_an_empty_key_or_a_bare_value_is_refused() {
        let empty = entry_dict(vec![(String::new(), string("x"))], "metadata");
        assert!(
            matches!(&empty, Err(Error::InvalidInput(m)) if m.contains("empty key")),
            "{empty:?}"
        );
        let bare = entry_dict(
            vec![("k".into(), Value::Str("not a variant".into()))],
            "detached metadata",
        );
        assert!(
            matches!(&bare, Err(Error::InvalidInput(m)) if m.contains("detached metadata")),
            "{bare:?}"
        );
    }

    #[test]
    fn the_parent_follows_the_policy() {
        let refs = strings(&["a", "b"]);
        let at = server(None, &[("a", Some(csum(5))), ("b", Some(csum(5)))]);
        let absent = server(None, &[("a", None), ("b", None)]);
        assert_eq!(
            resolve_parent(ParentPolicy::CurrentTip, &at, &refs),
            Some(csum(5))
        );
        assert_eq!(
            resolve_parent(ParentPolicy::CurrentTip, &absent, &refs),
            None
        );
        assert_eq!(resolve_parent(ParentPolicy::None, &at, &refs), None);
        assert_eq!(
            resolve_parent(ParentPolicy::Commit(csum(7)), &absent, &refs),
            Some(csum(7))
        );
    }

    #[test]
    fn target_refs_in_mixed_states_are_refused() {
        let refs = strings(&["a", "b"]);
        let accepted = [
            server(None, &[("a", None), ("b", None)]),
            server(None, &[("a", Some(csum(5))), ("b", Some(csum(5)))]),
        ];
        for info in &accepted {
            check_ref_states(info, &refs).unwrap();
        }
        let refused = [
            server(None, &[("a", None), ("b", Some(csum(5)))]),
            server(None, &[("a", Some(csum(5))), ("b", None)]),
            server(None, &[("a", Some(csum(5))), ("b", Some(csum(6)))]),
        ];
        for info in &refused {
            match check_ref_states(info, &refs) {
                Err(Error::InvalidInput(m)) => {
                    for state in &info.refs {
                        let want = match state.commit {
                            Some(tip) => format!("'{}' is at {tip}", state.name),
                            None => format!("'{}' is absent", state.name),
                        };
                        assert!(m.contains(&want), "{m}");
                    }
                }
                other => panic!("{:?}: {other:?}", info.refs),
            }
        }
        check_ref_states(&server(None, &[("a", Some(csum(5)))]), &refs[..1]).unwrap();
    }

    #[test]
    fn each_update_expects_the_reported_state_or_any_with_force() {
        let refs = strings(&["a", "b"]);
        let info = server(None, &[("a", Some(csum(5))), ("b", None)]);
        let updates = ref_updates(&info, &refs, csum(8), false);
        assert_eq!(
            updates,
            [
                RefUpdate {
                    name: "a".into(),
                    expected: Expected::Commit(csum(5)),
                    new: Some(csum(8)),
                },
                RefUpdate {
                    name: "b".into(),
                    expected: Expected::Absent,
                    new: Some(csum(8)),
                },
            ]
        );
        for update in ref_updates(&info, &refs, csum(8), true) {
            assert_eq!(update.expected, Expected::Any);
        }
    }

    /// The base64 of a 64-byte ed25519 secret key (seed, then public key).
    const SECRET_B64: &str =
        "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";

    /// The blobs of the `aay` under `key`.
    fn blobs(dict: &Value, key: &str) -> Vec<Vec<u8>> {
        let (_, inner) = dict.dict_get(key).unwrap().as_variant().unwrap();
        inner
            .as_array()
            .unwrap()
            .iter()
            .map(|blob| blob.as_bytes().unwrap().to_vec())
            .collect()
    }

    #[test]
    fn signatures_follow_the_caller_entries_in_signer_order() {
        let secret = base64::decode(SECRET_B64).unwrap();
        let signers: Vec<Box<dyn Signer>> = vec![
            Box::new(DummySigner::new(b"dummy-key".to_vec())),
            Box::new(Ed25519Signer::from_secret_key(&secret).unwrap()),
        ];
        let entries = entry_dict(vec![("xa.k".into(), string("v"))], "detached").unwrap();
        let payload = b"commit bytes";
        let dict = futures_lite::future::block_on(detached_dict(entries, &signers, payload))
            .unwrap()
            .unwrap();
        assert_eq!(
            keys(&dict),
            ["xa.k", "ostree.sign.dummy", "ostree.sign.ed25519"]
        );
        assert_eq!(blobs(&dict, "ostree.sign.dummy"), [b"dummy-key".to_vec()]);
        let verifier = Ed25519Verifier::new([&secret[32..]], Vec::<Vec<u8>>::new()).unwrap();
        let outcome = futures_lite::future::block_on(
            verifier.verify(payload, &blobs(&dict, "ostree.sign.ed25519")),
        )
        .unwrap();
        assert!(outcome.valid);
    }

    #[test]
    fn a_caller_signature_array_gets_the_signature_appended() {
        let signers: Vec<Box<dyn Signer>> = vec![Box::new(DummySigner::new(b"new".to_vec()))];
        let array = Value::variant(
            Type::parse(SIGNATURE_ARRAY).unwrap(),
            Value::Array(vec![Value::Bytes(b"old".to_vec())]),
        );
        let entries = entry_dict(vec![("ostree.sign.dummy".into(), array)], "detached").unwrap();
        let dict = futures_lite::future::block_on(detached_dict(entries, &signers, b"x"))
            .unwrap()
            .unwrap();
        assert_eq!(keys(&dict), ["ostree.sign.dummy"]);
        assert_eq!(
            blobs(&dict, "ostree.sign.dummy"),
            [b"old".to_vec(), b"new".to_vec()]
        );
    }

    #[test]
    fn a_caller_value_of_another_type_under_a_signer_key_is_invalid_format() {
        let signers: Vec<Box<dyn Signer>> = vec![Box::new(DummySigner::new(b"new".to_vec()))];
        for value in [
            string("x"),
            Value::variant(Type::parse("as").unwrap(), Value::Array(Vec::new())),
        ] {
            let entries =
                entry_dict(vec![("ostree.sign.dummy".into(), value)], "detached").unwrap();
            let r = futures_lite::future::block_on(detached_dict(entries, &signers, b"x"));
            assert!(
                matches!(r, Err(Error::Sign(ostrya_sign::Error::InvalidFormat(_)))),
                "{r:?}"
            );
        }
    }

    /// A signer that records whether `sign` was called.
    struct Recording {
        called: Arc<AtomicBool>,
    }

    impl Signer for Recording {
        fn name(&self) -> &str {
            "recording"
        }

        fn metadata_key(&self) -> &str {
            "ostree.sign.recording"
        }

        fn sign<'a>(&'a self, _data: &'a [u8]) -> ostrya_sign::SignFuture<'a> {
            self.called.store(true, Ordering::SeqCst);
            Box::pin(async { Ok(b"recorded".to_vec()) })
        }
    }

    #[test]
    fn the_key_of_each_signer_is_checked_before_the_first_signs() {
        let called = Arc::new(AtomicBool::new(false));
        let signers: Vec<Box<dyn Signer>> = vec![
            Box::new(Recording {
                called: called.clone(),
            }),
            Box::new(DummySigner::new(b"new".to_vec())),
        ];
        let entries =
            entry_dict(vec![("ostree.sign.dummy".into(), string("x"))], "detached").unwrap();
        let r = futures_lite::future::block_on(detached_dict(entries, &signers, b"x"));
        assert!(
            matches!(r, Err(Error::Sign(ostrya_sign::Error::InvalidFormat(_)))),
            "{r:?}"
        );
        assert!(!called.load(Ordering::SeqCst));
    }

    #[test]
    fn an_empty_detached_dict_is_none() {
        let r = futures_lite::future::block_on(detached_dict(Vec::new(), &[], b"x")).unwrap();
        assert_eq!(r, None);
    }
}
