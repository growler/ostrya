//! Summary generation, signing, and verification (Phase 14).
//!
//! Byte-identity is checked against golden summaries the `ostree` tool wrote for
//! the same repositories (`tests/fixtures/generated/summary` and
//! `summary-collection`, produced by `generate.sh`). The tool's wall-clock
//! `ostree.summary.last-modified` is patched in the golden to a fixed epoch, and
//! the port is asked to reproduce that epoch, so the comparison is deterministic.
//! The collection fixture ships the repository in its pre-summary state, so the
//! port generates the `ostree-metadata` anchor commit itself and its checksum is
//! checked against the tool's.

mod common;

use std::path::Path;
use std::process::Command;

use common::{TmpDir, fixture_root, ostree_available, ostree_supports_ed25519};
use ostrya::base64;
use ostrya::{
    Checksum, DeltaOptions, Ed25519Signer, Ed25519Verifier, Repo, Summary, SummaryOptions, Value,
};
use ostrya_rt::block_on;

/// The fixed epoch patched into both golden summaries' `last-modified` and used
/// as the collection anchor commit's timestamp (`generate.sh`).
const FIXED_EPOCH: u64 = 1_700_000_000;
/// The collection id of the `summary-collection` fixture.
const COLLECTION_ID: &str = "org.ostrya.Test";
/// The `ostree-metadata` anchor commit the tool wrote for the collection
/// fixture (first generation, parentless, timestamp `FIXED_EPOCH`).
const ANCHOR_COMMIT: &str = "04fd8792152380dd12ef240cda008ef098407791011c01b3dd4f75f9964d6068";

/// A fixed ed25519 keypair for sign/verify round-trips (from `sign_ed25519.rs`).
const SECRET_B64: &str =
    "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";
const PUBLIC_B64: &str = "wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=";

/// Recursively copy a directory tree, preserving attributes.
fn copy_tree(from: &Path, to: &Path) {
    let status = Command::new("cp")
        .args(["-a"])
        .arg(from)
        .arg(to)
        .status()
        .expect("run cp");
    assert!(status.success(), "cp -a {from:?} {to:?} failed");
}

/// Copy a fixture's `repo/` into a fresh writable temp directory and return it.
fn writable_fixture(fixture: &str, tag: &str) -> (TmpDir, std::path::PathBuf) {
    let tmp = TmpDir::new(tag);
    let repo = tmp.path().join("repo");
    copy_tree(&fixture_root().join(fixture).join("repo"), &repo);
    (tmp, repo)
}

#[test]
fn plain_summary_is_byte_identical_to_the_tool() {
    let (_tmp, repo_dir) = writable_fixture("summary", "summary-plain");
    block_on(async {
        let repo = Repo::open(&repo_dir).await.unwrap();
        repo.regenerate_summary(&SummaryOptions {
            last_modified: Some(FIXED_EPOCH),
            metadata_commit_timestamp: None,
        })
        .await
        .unwrap();

        let got = repo.read_summary().await.unwrap().expect("summary written");
        let want = std::fs::read(fixture_root().join("summary").join("summary")).unwrap();
        assert_eq!(
            got, want,
            "the port's summary must be byte-identical to the tool's"
        );
    });
}

#[test]
fn regenerate_removes_a_stale_signature() {
    let (_tmp, repo_dir) = writable_fixture("summary", "summary-stale-sig");
    block_on(async {
        let repo = Repo::open(&repo_dir).await.unwrap();
        repo.regenerate_summary(&SummaryOptions {
            last_modified: Some(FIXED_EPOCH),
            metadata_commit_timestamp: None,
        })
        .await
        .unwrap();
        repo.sign_summary(&Ed25519Signer::from_base64(SECRET_B64).unwrap())
            .await
            .unwrap();
        assert!(repo.read_summary_signature().await.unwrap().is_some());

        // A fresh summary invalidates the old signature, so it is removed.
        repo.regenerate_summary(&SummaryOptions {
            last_modified: Some(FIXED_EPOCH),
            metadata_commit_timestamp: None,
        })
        .await
        .unwrap();
        assert!(
            repo.read_summary_signature().await.unwrap().is_none(),
            "regeneration must drop a stale summary.sig"
        );
    });
}

#[test]
fn collection_summary_and_anchor_match_the_tool() {
    let (_tmp, repo_dir) = writable_fixture("summary-collection", "summary-collection");
    block_on(async {
        let repo = Repo::open(&repo_dir).await.unwrap();
        assert_eq!(repo.config().collection_id(), Some(COLLECTION_ID));

        repo.regenerate_summary(&SummaryOptions {
            last_modified: Some(FIXED_EPOCH),
            metadata_commit_timestamp: Some(FIXED_EPOCH),
        })
        .await
        .unwrap();

        // The port generated the anchor commit; its checksum matches the tool's.
        let anchor = repo
            .resolve_rev("ostree-metadata", false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            anchor.to_hex(),
            ANCHOR_COMMIT,
            "the ostree-metadata anchor commit must match the tool's"
        );

        let got = repo.read_summary().await.unwrap().expect("summary written");
        let want =
            std::fs::read(fixture_root().join("summary-collection").join("summary")).unwrap();
        assert_eq!(
            got, want,
            "the port's collection summary must be byte-identical to the tool's"
        );
    });
}

#[test]
fn sign_and_verify_round_trip() {
    let (_tmp, repo_dir) = writable_fixture("summary", "summary-sign");
    block_on(async {
        let repo = Repo::open(&repo_dir).await.unwrap();
        repo.regenerate_summary(&SummaryOptions {
            last_modified: Some(FIXED_EPOCH),
            metadata_commit_timestamp: None,
        })
        .await
        .unwrap();

        repo.sign_summary(&Ed25519Signer::from_base64(SECRET_B64).unwrap())
            .await
            .unwrap();

        let public = base64::decode(PUBLIC_B64).unwrap();
        let trusted = Ed25519Verifier::new([public], Vec::<Vec<u8>>::new()).unwrap();
        let outcome = repo.verify_summary(&[&trusted]).await.unwrap();
        assert!(outcome.valid, "a signed summary must verify with the key");

        let wrong = Ed25519Verifier::new([vec![0u8; 32]], Vec::<Vec<u8>>::new()).unwrap();
        let outcome = repo.verify_summary(&[&wrong]).await.unwrap();
        assert!(!outcome.valid, "a foreign key must not verify the summary");
    });
}

/// The reverse-direction gate: the `ostree` tool verifies a summary the port
/// generated and signed. Wrong-key rejection is covered by the port's own
/// `verify_summary` above; the tool's summary cache makes a second in-process
/// verify under a different key unreliable, so it is not asserted here.
#[test]
fn tool_verifies_a_port_signed_summary() {
    if !ostree_supports_ed25519() {
        eprintln!("skipping: ostree tool has no ed25519 engine");
        return;
    }
    let (_tmp, repo_dir) = writable_fixture("summary", "summary-tool-verify");
    block_on(async {
        let repo = Repo::open(&repo_dir).await.unwrap();
        repo.regenerate_summary(&SummaryOptions {
            last_modified: Some(FIXED_EPOCH),
            metadata_commit_timestamp: None,
        })
        .await
        .unwrap();
        repo.sign_summary(&Ed25519Signer::from_base64(SECRET_B64).unwrap())
            .await
            .unwrap();
    });

    let url = format!("file://{}", repo_dir.display());
    let add = |name: &str, key: &str| {
        let status = Command::new("ostree")
            .arg(format!("--repo={}", repo_dir.display()))
            .args(["remote", "add", name, &url, "--no-gpg-verify"])
            .arg(format!("--sign-verify=ed25519=inline:{key}"))
            .status()
            .expect("run ostree remote add");
        assert!(status.success(), "ostree remote add {name} failed");
    };
    let remote_summary = |name: &str| {
        Command::new("ostree")
            .arg(format!("--repo={}", repo_dir.display()))
            .args(["remote", "summary", name])
            .output()
            .expect("run ostree remote summary")
            .status
            .success()
    };

    add("good", PUBLIC_B64);
    assert!(
        remote_summary("good"),
        "the tool must verify a summary the port signed"
    );
}

/// A repository holding static deltas advertises them in its summary:
/// `ostree.static-deltas` maps each delta's name to the SHA-256 of its
/// superblock, and the key sits between `tombstone-commits` and
/// `indexed-deltas`, which is where the tool was observed to write it.
#[test]
fn the_summary_advertises_the_deltas_the_repository_holds() {
    let (_tmp, repo_dir) = writable_fixture("summary", "summary-deltas");
    block_on(async {
        let repo = Repo::open(&repo_dir).await.unwrap();

        // Without a delta the key is absent.
        repo.regenerate_summary(&SummaryOptions {
            last_modified: Some(FIXED_EPOCH),
            metadata_commit_timestamp: None,
        })
        .await
        .unwrap();
        let bytes = repo.read_summary().await.unwrap().unwrap();
        let summary = Summary::parse(&bytes).unwrap();
        assert!(summary.metadata_value("ostree.static-deltas").is_none());

        // One delta of each shape: from scratch, and from a source commit.
        let refs = repo.list_refs(None).await.unwrap();
        let (_, to) = refs.first().expect("the fixture holds a ref");
        let (_, from) = refs.get(1).expect("the fixture holds a second ref");
        let opts = DeltaOptions {
            timestamp: Some(FIXED_EPOCH),
            ..DeltaOptions::default()
        };
        let scratch_dir = repo.generate_static_delta(None, to, &opts).await.unwrap();
        let from_to_dir = repo
            .generate_static_delta(Some(from), to, &opts)
            .await
            .unwrap();
        repo.regenerate_summary(&SummaryOptions {
            last_modified: Some(FIXED_EPOCH),
            metadata_commit_timestamp: None,
        })
        .await
        .unwrap();

        let bytes = repo.read_summary().await.unwrap().unwrap();
        let summary = Summary::parse(&bytes).unwrap();
        let map = summary
            .metadata_value("ostree.static-deltas")
            .expect("the summary advertises the deltas");
        // Each delta the repository holds is named in the map under the digest of
        // its own superblock.
        let advertised = |name: &str| {
            map.dict_get(name)
                .and_then(Value::as_variant)
                .and_then(|(_, value)| value.as_bytes())
                .unwrap_or_else(|| panic!("the map must name delta {name}"))
        };
        let digest_of = |dir: &Path| {
            let superblock = std::fs::read(repo_dir.join(dir).join("superblock")).unwrap();
            Checksum::sha256(&superblock)
        };
        assert_eq!(
            advertised(&to.to_hex()),
            digest_of(&scratch_dir).as_bytes(),
            "the map must carry the from-scratch delta's superblock digest"
        );
        assert_eq!(
            advertised(&format!("{}-{}", from.to_hex(), to.to_hex())),
            digest_of(&from_to_dir).as_bytes(),
            "the map must carry the from-to delta's superblock digest"
        );

        // The key's neighbours: the entries appear in the order byte identity
        // relies on.
        let keys: Vec<String> = match &summary.metadata {
            Value::Array(entries) => entries
                .iter()
                .filter_map(|entry| match entry {
                    Value::Tuple(fields) => fields.first()?.as_str().map(str::to_owned),
                    _ => None,
                })
                .collect(),
            other => panic!("the summary metadata is not a dict: {other:?}"),
        };
        let position = |key: &str| keys.iter().position(|k| k == key).expect(key);
        assert!(
            position("ostree.summary.tombstone-commits") < position("ostree.static-deltas")
                && position("ostree.static-deltas") < position("ostree.summary.indexed-deltas"),
            "{keys:?}"
        );
    });
}

/// The `ostree` tool reads the delta map the port wrote, which is the
/// interoperability the advertisement exists for: a fetcher finds the deltas
/// through it.
#[test]
fn the_tool_reads_the_port_written_delta_map() {
    if !ostree_available() {
        eprintln!("skipping: ostree tool not available");
        return;
    }
    let (_tmp, repo_dir) = writable_fixture("summary", "summary-deltas-tool");
    let to = block_on(async {
        let repo = Repo::open(&repo_dir).await.unwrap();
        let refs = repo.list_refs(None).await.unwrap();
        let (_, to) = *refs.first().expect("the fixture holds a ref");
        repo.generate_static_delta(
            None,
            &to,
            &DeltaOptions {
                timestamp: Some(FIXED_EPOCH),
                ..DeltaOptions::default()
            },
        )
        .await
        .unwrap();
        repo.regenerate_summary(&SummaryOptions {
            last_modified: Some(FIXED_EPOCH),
            metadata_commit_timestamp: None,
        })
        .await
        .unwrap();
        to
    });

    let printed = Command::new("ostree")
        .arg(format!("--repo={}", repo_dir.display()))
        .args(["summary", "--print-metadata-key=ostree.static-deltas"])
        .output()
        .expect("run ostree summary");
    assert!(
        printed.status.success(),
        "the tool must read the port's summary: {}",
        String::from_utf8_lossy(&printed.stderr)
    );
    let text = String::from_utf8_lossy(&printed.stdout);
    assert!(
        text.contains(&to.to_hex()),
        "the tool must list the delta the port advertised: {text}"
    );
}
