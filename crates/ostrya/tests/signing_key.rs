//! `SigningKey::from_key_group`: the signers of one `[ex-ostrya key "NAME"]`
//! group, and `Repo::has_signed_commit`.
//!
//! The call reads the one key group that its argument names. The tests need
//! no `receive` feature.

mod common;

use std::os::fd::AsFd;
use std::path::Path;

#[cfg(feature = "sign-gpg")]
use common::GnupgHome;
use common::TmpDir;
#[cfg(feature = "sign-spki")]
use common::wrap_pem;
use ostrya::sign::SigningKey;
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, Ed25519Signer,
    Ed25519Verifier, Error, MutableTree, Ref, Repo, RepoMode, Signer, Verifier, base64,
};
use ostrya_rt::block_on;

/// The base64 of a 64-byte ed25519 secret key (seed, then public key).
const SECRET_B64: &str =
    "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";
/// The matching 32-byte ed25519 public key.
const PUBLIC_B64: &str = "wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=";
/// Another ed25519 secret key.
const OTHER_SECRET_B64: &str =
    "5ILWxT+l9G/u3h0BptRpmSi35C9uog7YDdD+Fp1Xk+Hz52p0NlYh6xBA73kJEJKhKbbnjcE0rsWA5XA/K5Sq5Q==";

/// The payload that the tests sign.
const PAYLOAD: &[u8] = b"payload";

/// Creates and opens an archive repository at `dir/repo` whose config
/// carries `groups` after `[core]`.
fn repo_with(dir: &Path, groups: &str) -> Repo {
    let root = dir.join("repo");
    block_on(async {
        Repo::create(&root, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let mut config = std::fs::read_to_string(root.join("config")).unwrap();
        config.push('\n');
        config.push_str(groups);
        std::fs::write(root.join("config"), config).unwrap();
        Repo::open(&root).await.unwrap()
    })
}

/// Writes the ed25519 secret key `secret_b64` to `path` as one line.
fn write_secret(path: &Path, secret_b64: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, format!("\n{secret_b64}\n")).unwrap();
}

/// An ed25519 key group `name` whose key is `file`.
fn ed25519_group(name: &str, file: &str) -> String {
    format!("[ex-ostrya key \"{name}\"]\ntype=ed25519\nsecret-key-file={file}\n")
}

/// Returns the ed25519 signature of [`PAYLOAD`] with `secret_b64`.
fn ed25519_signature(secret_b64: &str) -> Vec<u8> {
    let signer = Ed25519Signer::from_base64(secret_b64).unwrap();
    block_on(signer.sign(PAYLOAD)).unwrap()
}

/// Returns the signature of [`PAYLOAD`] that `key` makes.
fn signature(key: &SigningKey) -> Vec<u8> {
    block_on(key.signer().sign(PAYLOAD)).unwrap()
}

/// Returns the refusal of the key group `k` that `group` states.
fn refusal(group: &str) -> Error {
    let dir = TmpDir::new("signing-key-refused");
    let repo = repo_with(dir.path(), group);
    block_on(SigningKey::from_key_group(&repo, "k")).unwrap_err()
}

/// Asserts that `group` is refused with `Error::InvalidFormat`, and that the
/// message names the group and holds `part`.
fn assert_malformed(group: &str, part: &str) {
    let err = refusal(group);
    assert!(
        matches!(&err, Error::InvalidFormat(m)
            if m.contains("[ex-ostrya key \"k\"]") && m.contains(part)),
        "{group}: {err}"
    );
}

/// Writes a commit of a tree of one file to `test/main` and returns its
/// checksum. The source tree is `src` beside the repository.
fn small_commit(repo: &Repo) -> Checksum {
    let base = repo.path().parent().unwrap();
    std::fs::create_dir_all(base.join("src")).unwrap();
    std::fs::write(base.join("src/file"), b"signed content\n").unwrap();
    block_on(async {
        let txn = repo.transaction().await.unwrap();
        let mut mtree = MutableTree::new();
        let mut modifier = CommitModifier::new(CommitModifierFlags::SKIP_XATTRS);
        let dfd = std::fs::File::open(base).unwrap();
        txn.write_dfd_to_mtree(
            dfd.as_fd(),
            Path::new("src"),
            &mut mtree,
            Some(&mut modifier),
        )
        .await
        .unwrap();
        let root = txn.write_mtree(&mut mtree).await.unwrap();
        let opts = CommitOptions {
            subject: Some("signing key fixture".to_owned()),
            timestamp: Some(1_700_000_000),
            ..CommitOptions::default()
        };
        let commit = txn.write_commit(opts, &root).await.unwrap();
        txn.set_ref(&Ref::local("test/main"), Some(&commit));
        txn.commit().await.unwrap();
        commit
    })
}

/// An ed25519 key group gives one key. Its signature verifies with the public
/// key, and it is the signature of the secret key of the file.
#[test]
fn an_ed25519_key_group_gives_one_key() {
    let dir = TmpDir::new("signing-key-ed25519");
    let file = dir.path().join("secret.ed25519");
    write_secret(&file, SECRET_B64);
    let repo = repo_with(dir.path(), &ed25519_group("k", &file.display().to_string()));

    let keys = block_on(SigningKey::from_key_group(&repo, "k")).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].signer().name(), "ed25519");
    let signed = signature(&keys[0]);
    assert_eq!(signed, ed25519_signature(SECRET_B64));
    let verifier =
        Ed25519Verifier::new([base64::decode(PUBLIC_B64).unwrap()], Vec::<Vec<u8>>::new()).unwrap();
    assert!(verifier.verify(PAYLOAD, &[signed]).unwrap().valid);
}

/// The secret key of the first spki fixture, base64 of a PKCS#8 DER.
#[cfg(feature = "sign-spki")]
const SPKI_SECRET_A: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2L708EsnnzHER0SYasMNIUcG\
v63QapC/3kVsoPerzKGhRANCAATxfzfHKUPeJtyLTGMUoxHhvBS1NT9guWhUQPGiZRLZIcB8Wc3\
csdVU1iOiTRmbZGKJTtekOdEAbVRrx5HxIpst";
/// The secret key of the second spki fixture, base64 of a PKCS#8 DER.
#[cfg(feature = "sign-spki")]
const SPKI_SECRET_B: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQga/Vn02DKuHPztB29\
97ybXVngf9XlVRkpxQl0PMHYB2GhRANCAARapiXxcZO+MwxDicFtiWeYWfMDNYF8\
zlrMtaYLMVD5RNnxfTNPW/JLR8DreWpEAJCsrmwMcsVoL66GqkOOOx1R";

/// An spki key group gives one key for each `PRIVATE KEY` block, in the
/// order of the file.
#[cfg(feature = "sign-spki")]
#[test]
fn an_spki_key_group_gives_one_key_for_each_block() {
    let dir = TmpDir::new("signing-key-spki");
    let file = dir.path().join("secret.spki");
    std::fs::write(
        &file,
        format!(
            "{}{}",
            wrap_pem("PRIVATE KEY", SPKI_SECRET_A),
            wrap_pem("PRIVATE KEY", SPKI_SECRET_B)
        ),
    )
    .unwrap();
    let repo = repo_with(
        dir.path(),
        &format!(
            "[ex-ostrya key \"k\"]\ntype=spki\nsecret-key-file={}\n",
            file.display()
        ),
    );

    let keys = block_on(SigningKey::from_key_group(&repo, "k")).unwrap();
    assert_eq!(keys.len(), 2);
    for (key, secret) in keys.iter().zip([SPKI_SECRET_A, SPKI_SECRET_B]) {
        assert_eq!(key.signer().name(), "spki");
        let expected = ostrya::SpkiSigner::from_base64(secret).unwrap();
        assert_eq!(
            signature(key),
            block_on(expected.sign(PAYLOAD)).unwrap(),
            "the keys sign in the order of the file"
        );
    }
}

/// A name of no group and a malformed name are refused with
/// `Error::InvalidInput`.
#[test]
fn a_missing_group_and_a_malformed_name_are_refused() {
    let dir = TmpDir::new("signing-key-name");
    let file = dir.path().join("secret.ed25519");
    write_secret(&file, SECRET_B64);
    let repo = repo_with(dir.path(), &ed25519_group("k", &file.display().to_string()));

    let err = block_on(SigningKey::from_key_group(&repo, "absent")).unwrap_err();
    let Error::InvalidInput(m) = &err else {
        panic!("{err}");
    };
    assert_eq!(m, "the config has no [ex-ostrya key \"absent\"] group");

    for name in ["", "a\"b", "a\nb"] {
        let err = block_on(SigningKey::from_key_group(&repo, name)).unwrap_err();
        let Error::InvalidInput(m) = &err else {
            panic!("{name:?}: {err}");
        };
        assert_eq!(
            m,
            &format!(
                "malformed key group name '{name}': the name is not empty, and holds no '\"' \
                 and no control character"
            )
        );
    }
}

/// A malformed key group is refused with `Error::InvalidFormat`, and the
/// message names the group.
#[test]
fn a_malformed_key_group_is_refused_with_its_name() {
    assert_malformed(
        "[ex-ostrya key \"k\"]\nsecret-key-file=/nonexistent/ostrya/secret\n",
        "needs type",
    );
    assert_malformed(
        "[ex-ostrya key \"k\"]\ntype=ed25519\nsecret-key-file=/s\ngpg-key=ABCD\n",
        "does not take",
    );
    assert_malformed(
        "[ex-ostrya key \"k\"]\ntype=ed25519\nsecret-key-file=\n",
        "needs secret-key-file",
    );
}

/// A key file that does not exist is refused with `Error::Signature`, and the
/// message names the group.
#[test]
fn an_absent_key_file_is_refused_with_the_group_name() {
    let err = refusal(&ed25519_group("k", "/nonexistent/ostrya/secret"));
    assert!(
        matches!(&err, Error::Signature(m)
            if m == "[ex-ostrya key \"k\"]: the secret key file \
                     '/nonexistent/ostrya/secret' does not exist"),
        "{err}"
    );
}

/// An spki key group is refused with `Error::Unsupported` in a build with no
/// `sign-spki` feature, and the message names the group.
#[cfg(not(feature = "sign-spki"))]
#[test]
fn an_spki_key_group_is_unsupported_without_the_spki_engine() {
    let err = refusal("[ex-ostrya key \"k\"]\ntype=spki\nsecret-key-file=/s\n");
    let Error::Unsupported(m) = &err else {
        panic!("{err}");
    };
    assert_eq!(
        m,
        "[ex-ostrya key \"k\"] is an spki key, which this build cannot sign with; build with \
         the sign-spki feature"
    );
}

/// A GPG key group is refused with `Error::Unsupported` in a build with no
/// `sign-gpg` feature, and the message names the group.
#[cfg(not(feature = "sign-gpg"))]
#[test]
fn a_gpg_key_group_is_unsupported_without_gpg_signing() {
    let err = refusal("[ex-ostrya key \"k\"]\ntype=gpg\ngpg-key=ABCD\n");
    let Error::Unsupported(m) = &err else {
        panic!("{err}");
    };
    assert_eq!(
        m,
        "[ex-ostrya key \"k\"] is a GPG key, which this build cannot sign with; build with the \
         sign-gpg feature"
    );
}

/// A bad trust group, a bad server group, a bad client group, and a bad
/// other key group do not stop the build of the named key group.
#[test]
fn a_bad_group_that_the_call_does_not_name_is_not_read() {
    const BAD_CLIENT: &str = "[ex-ostrya client \"bad\"]\nauth=ssh:c\nunknown-key=1\n";
    let dir = TmpDir::new("signing-key-neighbours");
    let file = dir.path().join("secret.ed25519");
    write_secret(&file, SECRET_B64);
    let repo = repo_with(
        dir.path(),
        &format!(
            "[ex-ostrya trust \"bad\"]\nunknown-key=1\n\
             [ex-ostrya server]\nunknown-key=1\n\
             {BAD_CLIENT}\
             [ex-ostrya key \"other\"]\ntype=dummy\nsecret-key-file=/s\n\
             {}",
            ed25519_group("k", &file.display().to_string())
        ),
    );

    // Each neighbour is bad. The read of the client groups reads the server
    // group first, so the client group is read alone from a config of its
    // own.
    assert!(block_on(ostrya::verify::TrustedKeys::from_trust_group(&repo, "bad")).is_err());
    let err = ostrya::access::ClientAccess::from_config(repo.config()).unwrap_err();
    assert!(
        matches!(&err, Error::InvalidFormat(m) if m.starts_with("[ex-ostrya server] ")),
        "{err}"
    );
    let client_only = ostrya::RepoConfig::parse(&format!(
        "[core]\nrepo_version=1\nmode=archive-z2\n\n{BAD_CLIENT}"
    ))
    .unwrap();
    let err = ostrya::access::ClientAccess::from_config(&client_only).unwrap_err();
    assert!(
        matches!(&err, Error::InvalidFormat(m) if m.starts_with("[ex-ostrya client \"bad\"] ")),
        "{err}"
    );
    let err = block_on(SigningKey::from_key_group(&repo, "other")).unwrap_err();
    assert!(matches!(err, Error::InvalidFormat(_)), "{err}");

    let keys = block_on(SigningKey::from_key_group(&repo, "k")).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(signature(&keys[0]), ed25519_signature(SECRET_B64));
}

/// The helper process of the test of a relative key file.
///
/// The process runs in another current directory. It builds the key group `k`
/// of the repository and checks that its key is the key under the repository
/// root, and not the decoy under the current directory.
#[test]
#[ignore = "helper process for the relative key file test"]
fn writer_child_subprocess() {
    common::writer_child_main(|path, arg| {
        assert_eq!(arg, "relative");
        let repo = block_on(Repo::open(path)).unwrap();
        let keys = block_on(SigningKey::from_key_group(&repo, "k")).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(signature(&keys[0]), ed25519_signature(SECRET_B64));
    });
}

/// A relative `secret-key-file` is relative to the repository root, and not
/// to the current directory of the process. A relative path with a `..`
/// component is refused as malformed.
#[test]
fn a_relative_secret_key_file_is_relative_to_the_repository_root() {
    let dir = TmpDir::new("signing-key-relative");
    let repo = repo_with(dir.path(), &ed25519_group("k", "keys/k"));
    write_secret(&repo.path().join("keys/k"), SECRET_B64);
    let other = dir.path().join("cwd");
    write_secret(&other.join("keys/k"), OTHER_SECRET_B64);

    common::writer_child_with(repo.path(), "relative", |command| {
        command.current_dir(&other);
    })
    .wait();

    assert_malformed(
        &ed25519_group("k", "../k"),
        "secret-key-file ../k has a `..` component",
    );
}

/// `has_signed_commit` gives `false` before the key signs the commit, and
/// `true` after. A signature of another key gives `false`.
#[test]
fn has_signed_commit_sees_the_signature_of_the_key() {
    let dir = TmpDir::new("signing-key-has-signed");
    let file = dir.path().join("secret.ed25519");
    write_secret(&file, SECRET_B64);
    let other_file = dir.path().join("other.ed25519");
    write_secret(&other_file, OTHER_SECRET_B64);
    let repo = repo_with(
        dir.path(),
        &format!(
            "{}{}",
            ed25519_group("k", &file.display().to_string()),
            ed25519_group("o", &other_file.display().to_string())
        ),
    );
    let key = block_on(SigningKey::from_key_group(&repo, "k"))
        .unwrap()
        .remove(0);
    let other = block_on(SigningKey::from_key_group(&repo, "o"))
        .unwrap()
        .remove(0);
    let commit = small_commit(&repo);

    assert!(!block_on(repo.has_signed_commit(&commit, &key)).unwrap());
    block_on(repo.sign_commit(&commit, other.signer())).unwrap();
    assert!(!block_on(repo.has_signed_commit(&commit, &key)).unwrap());
    assert!(block_on(repo.has_signed_commit(&commit, &other)).unwrap());
    block_on(repo.sign_commit(&commit, key.signer())).unwrap();
    assert!(block_on(repo.has_signed_commit(&commit, &key)).unwrap());

    // `has_signed` over the bytes of the commit and its detached metadata
    // agrees.
    let data = block_on(repo.load_object_bytes(ostrya::ObjectType::Commit, &commit)).unwrap();
    let dict = block_on(repo.read_commit_detached_metadata(&commit)).unwrap();
    assert!(block_on(key.has_signed(&data, dict.as_ref())));
    assert!(!block_on(key.has_signed(b"other bytes", dict.as_ref())));
    assert!(!block_on(key.has_signed(&data, None)));

    // A commit that the repository does not hold.
    let absent = Checksum::from_hex(&"ab".repeat(32)).unwrap();
    let err = block_on(repo.has_signed_commit(&absent, &key)).unwrap_err();
    assert!(matches!(err, Error::ObjectNotFound { .. }), "{err}");
}

/// A GPG key group gives one key. `has_signed_commit` sees its signature.
#[cfg(feature = "sign-gpg")]
#[test]
fn a_gpg_key_group_gives_one_key() {
    if !common::gnupg_available(&["gpg", "gpgconf"]) {
        return;
    }
    let dir = TmpDir::new("signing-key-gpg");
    let home = GnupgHome::new(&dir.path().join("gnupg"), "Signer <signer@example.org>");
    let repo = repo_with(
        dir.path(),
        &format!(
            "[ex-ostrya key \"g\"]\ntype=gpg\ngpg-key=signer@example.org\ngpg-homedir={}\n",
            home.dir.display()
        ),
    );

    let keys = block_on(SigningKey::from_key_group(&repo, "g")).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].signer().name(), "gpg");
    let commit = small_commit(&repo);
    assert!(!block_on(repo.has_signed_commit(&commit, &keys[0])).unwrap());
    block_on(repo.sign_commit(&commit, keys[0].signer())).unwrap();
    assert!(block_on(repo.has_signed_commit(&commit, &keys[0])).unwrap());
}

/// A signing key moves across tasks and threads.
#[test]
fn a_signing_key_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SigningKey>();
}
