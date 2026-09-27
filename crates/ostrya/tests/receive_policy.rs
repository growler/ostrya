//! `ReceivePolicy::from_config`: the receive keys of the `[ex-ostrya]` group,
//! `[core] auto-update-summary`, and `detached-metadata-exclude`.
//!
//! Each case writes one repository configuration and reads the policy from
//! it. A malformed value is refused with the error kind the policy documents,
//! and each accepted value reaches its own field alone.

#![cfg(feature = "receive")]

mod common;

use std::path::Path;

use common::TmpDir;
use ostrya::{
    CreateOptions, Error, ReceivePolicy, ReceiveVerify, Repo, RepoMode, ServerSigner, base64,
};
use ostrya_rt::block_on;

/// The base64 of a 64-byte ed25519 secret key (seed, then public key).
const SECRET_B64: &str =
    "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";
/// The matching 32-byte ed25519 public key.
const PUBLIC_B64: &str = "wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=";

/// Create an archive repository under `dir` whose config carries `core` at the
/// end of `[core]` and `ex_ostrya` as the `[ex-ostrya]` group, and read its
/// receive policy.
fn policy_with(dir: &Path, core: &str, ex_ostrya: &str) -> ostrya::Result<ReceivePolicy> {
    let root = dir.join("repo");
    block_on(async {
        Repo::create(&root, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let mut config = std::fs::read_to_string(root.join("config")).unwrap();
        config.push_str(core);
        config.push_str("\n[ex-ostrya]\n");
        config.push_str(ex_ostrya);
        std::fs::write(root.join("config"), config).unwrap();
        let repo = Repo::open(&root).await.unwrap();
        ReceivePolicy::from_config(&repo).await
    })
}

/// The policy of one `[ex-ostrya]` group, in a fresh repository.
fn policy(ex_ostrya: &str) -> ostrya::Result<ReceivePolicy> {
    let dir = TmpDir::new("receive-policy");
    policy_with(dir.path(), "", ex_ostrya)
}

/// The refusal of one `[ex-ostrya]` group.
fn refusal(ex_ostrya: &str) -> Error {
    match policy(ex_ostrya) {
        Ok(policy) => panic!("the group {ex_ostrya:?} was accepted as {policy:?}"),
        Err(err) => err,
    }
}

/// The policy with no receive key is the strictest one.
#[test]
fn the_defaults_accept_fast_forwards_alone() {
    let policy = policy("").unwrap();
    assert!(!policy.allow_non_fast_forward);
    assert!(!policy.allow_delete);
    assert!(!policy.allow_privileged);
    assert!(!policy.allow_remote_refs);
    assert_eq!(policy.require_signature, ReceiveVerify::default());
    assert!(policy.signers.is_empty());
    assert!(!policy.sign_summary);
    assert!(!policy.update_summary);
    assert!(policy.detached_metadata_filter.is_none());
}

/// Each boolean key reaches its own field and no other.
#[test]
fn each_boolean_reaches_its_own_field() {
    type Field = fn(&ReceivePolicy) -> bool;
    let fields: [(&str, Field); 5] = [
        ("receive-allow-non-fast-forward", |p| {
            p.allow_non_fast_forward
        }),
        ("receive-allow-delete", |p| p.allow_delete),
        ("receive-allow-privileged", |p| p.allow_privileged),
        ("receive-allow-remote-refs", |p| p.allow_remote_refs),
        ("receive-sign-summary", |p| p.sign_summary),
    ];
    for (key, _) in &fields {
        for (value, expected) in [("true", true), ("1", true), ("false", false), ("0", false)] {
            let policy = policy(&format!("{key}={value}\n")).unwrap();
            for (other, read) in &fields {
                assert_eq!(
                    read(&policy),
                    expected && other == key,
                    "{key}={value}, field of {other}"
                );
            }
        }
    }
}

/// A boolean the key-file syntax does not read is refused as a key-file
/// error.
#[test]
fn a_malformed_boolean_is_refused() {
    for key in [
        "receive-allow-non-fast-forward",
        "receive-allow-delete",
        "receive-allow-privileged",
        "receive-allow-remote-refs",
        "receive-sign-summary",
    ] {
        let err = refusal(&format!("{key}=yes\n"));
        assert!(matches!(err, Error::Core(_)), "{key}: {err}");
    }
}

/// `update_summary` reads `[core] auto-update-summary` and its alias, and
/// either one true turns it on.
#[test]
fn update_summary_reads_the_core_keys() {
    for (core, expected) in [
        ("auto-update-summary=true\n", true),
        ("commit-update-summary=true\n", true),
        (
            "auto-update-summary=false\ncommit-update-summary=true\n",
            true,
        ),
        (
            "auto-update-summary=true\ncommit-update-summary=false\n",
            true,
        ),
        ("auto-update-summary=false\n", false),
    ] {
        let dir = TmpDir::new("receive-summary");
        let policy = policy_with(dir.path(), core, "").unwrap();
        assert_eq!(policy.update_summary, expected, "{core:?}");
    }
    let dir = TmpDir::new("receive-summary");
    let err = policy_with(dir.path(), "auto-update-summary=yes\n", "").unwrap_err();
    assert!(matches!(err, Error::Core(_)), "{err}");
}

/// The spellings `receive-verify` takes.
#[test]
fn receive_verify_reads_its_spellings() {
    let key = format!("receive-verification-ed25519-key={PUBLIC_B64}\n");
    let verify = |value: &str| {
        policy(&format!("receive-verify={value}\n{key}"))
            .unwrap()
            .require_signature
    };
    assert_eq!(verify("off"), ReceiveVerify::default());
    assert_eq!(
        verify("ed25519"),
        ReceiveVerify {
            gpg: false,
            sign: vec!["ed25519".to_owned()],
        }
    );
    // A name given twice counts once, and a trailing separator adds nothing.
    assert_eq!(
        verify("ed25519;ed25519;"),
        ReceiveVerify {
            gpg: false,
            sign: vec!["ed25519".to_owned()],
        }
    );
}

/// `gpg` in `receive-verify` turns on the GPG axis beside the engines it
/// names.
#[cfg(feature = "verify-gpg")]
#[test]
fn receive_verify_takes_gpg_with_an_engine() {
    if !common::gnupg_available(&["gpg", "gpgconf"]) {
        return;
    }
    let dir = TmpDir::new("receive-verify-gpg");
    let home = GnupgHome::new(&dir.path().join("gnupg"), "Trusted <trusted@example.org>");
    let keyring = dir.path().join("trusted.gpg");
    std::fs::write(&keyring, home.export()).unwrap();
    let policy = policy_with(
        dir.path(),
        "",
        &format!(
            "receive-verify=gpg;ed25519\nreceive-gpgkeypath={}\n\
             receive-verification-ed25519-key={PUBLIC_B64}\n",
            keyring.display()
        ),
    )
    .unwrap();
    assert_eq!(
        policy.require_signature,
        ReceiveVerify {
            gpg: true,
            sign: vec!["ed25519".to_owned()],
        }
    );
}

/// A `receive-gpgkeypath` whose keyrings hold no certificate is refused: an
/// empty keyring file, and a directory with no `*.gpg` keyring.
#[cfg(feature = "verify-gpg")]
#[test]
fn receive_verify_gpg_needs_a_certificate() {
    let dir = TmpDir::new("receive-verify-gpg-empty");
    let keyring = dir.path().join("empty.gpg");
    std::fs::write(&keyring, b"").unwrap();
    let keys = dir.path().join("keys.d");
    std::fs::create_dir(&keys).unwrap();
    std::fs::write(keys.join("README"), b"no keyring here").unwrap();
    for entry in [&keyring, &keys] {
        let err = refusal(&format!(
            "receive-verify=gpg\nreceive-gpgkeypath={}\n",
            entry.display()
        ));
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("receive-gpgkeypath names no key")),
            "{}: {err}",
            entry.display()
        );
    }
}

/// Each malformed `receive-verify` value is refused as malformed.
#[test]
fn a_malformed_receive_verify_is_refused() {
    for value in [
        "",
        ";",
        "true",
        "false",
        "off;gpg",
        "ed25519;;spki",
        "nosuch",
        "dummy",
        "ed25519,spki",
        "Ed25519",
    ] {
        let err = refusal(&format!(
            "receive-verify={value}\nreceive-verification-ed25519-key={PUBLIC_B64}\n"
        ));
        assert!(
            matches!(&err, Error::InvalidFormat(m) if m.contains("malformed [ex-ostrya] receive-verify")),
            "{value:?}: {err}"
        );
    }
}

/// An engine `receive-verify` names needs a trusted key, and each key source
/// that cannot be read or does not decode is refused.
#[test]
fn a_receive_verify_engine_needs_a_readable_key() {
    let err = refusal("receive-verify=ed25519\n");
    assert!(
        matches!(&err, Error::Signature(m) if m.contains("no trusted key for signature engine 'ed25519'")),
        "{err}"
    );

    let err = refusal("receive-verify=ed25519\nreceive-verification-ed25519-key=!!!\n");
    assert!(matches!(err, Error::Core(_)), "{err}");

    let err = refusal(
        "receive-verify=ed25519\n\
         receive-verification-ed25519-file=/nonexistent/ostrya/keys.ed25519\n",
    );
    assert!(
        matches!(&err, Error::Signature(m) if m.contains("/nonexistent/ostrya/keys.ed25519")),
        "{err}"
    );

    // A key file of trusted keys, one per line, is read.
    let dir = TmpDir::new("receive-keyfile");
    let file = dir.path().join("keys.ed25519");
    std::fs::write(&file, format!("{PUBLIC_B64}\n\n")).unwrap();
    policy_with(
        dir.path(),
        "",
        &format!(
            "receive-verify=ed25519\nreceive-verification-ed25519-file={}\n",
            file.display()
        ),
    )
    .unwrap();
}

/// A remote's verification keys do not reach the receive policy.
#[test]
fn a_remote_key_is_not_a_receive_key() {
    let dir = TmpDir::new("receive-remote-key");
    let err = policy_with(
        dir.path(),
        &format!(
            "\n[remote \"origin\"]\nurl=http://localhost/\n\
             verification-ed25519-key={PUBLIC_B64}\n"
        ),
        "receive-verify=ed25519\n",
    )
    .unwrap_err();
    assert!(matches!(err, Error::Signature(_)), "{err}");
}

/// `spki` in `receive-verify` needs the spki engine.
#[cfg(not(feature = "sign-spki"))]
#[test]
fn receive_verify_spki_needs_the_engine() {
    let err = refusal("receive-verify=spki\n");
    assert!(matches!(err, Error::Unsupported(_)), "{err}");
}

/// `gpg` in `receive-verify` needs the GPG engine.
#[cfg(not(feature = "verify-gpg"))]
#[test]
fn receive_verify_gpg_needs_the_engine() {
    let err = refusal("receive-verify=gpg\n");
    assert!(matches!(err, Error::Unsupported(_)), "{err}");
}

/// The GPG axis needs `receive-gpgkeypath`, and each entry has to name a
/// keyring file or a directory.
#[cfg(feature = "verify-gpg")]
#[test]
fn receive_verify_gpg_needs_a_keypath() {
    let err = refusal("receive-verify=gpg\n");
    assert!(
        matches!(&err, Error::Signature(m) if m.contains("receive-gpgkeypath names no keyring")),
        "{err}"
    );
    let err = refusal("receive-verify=gpg\nreceive-gpgkeypath=/nonexistent/ostrya/keys.gpg\n");
    assert!(
        matches!(&err, Error::Signature(m) if m.contains("receive-gpgkeypath entry")),
        "{err}"
    );
}

/// The sign-api signing key: `receive-sign-key-file` alone is an ed25519 key,
/// and the key signs as the server.
#[test]
fn the_sign_api_signing_key_is_read() {
    for ex_ostrya in ["", "receive-sign-type=ed25519\n"] {
        let dir = TmpDir::new("receive-signer");
        let file = dir.path().join("secret.ed25519");
        std::fs::write(&file, format!("\n{SECRET_B64}\n")).unwrap();
        let policy = policy_with(
            dir.path(),
            "",
            &format!("{ex_ostrya}receive-sign-key-file={}\n", file.display()),
        )
        .unwrap();
        assert_eq!(policy.signers.len(), 1);
        assert_eq!(policy.signers[0].signer().name(), "ed25519");
        let expected = ServerSigner::ed25519(&base64::decode(SECRET_B64).unwrap()).unwrap();
        let payload = b"payload";
        assert_eq!(
            block_on(policy.signers[0].signer().sign(payload)).unwrap(),
            block_on(expected.signer().sign(payload)).unwrap(),
            "the configured key signs"
        );
    }
}

/// Each malformed sign-api signing key configuration is refused.
#[test]
fn a_malformed_signing_key_is_refused() {
    let err = refusal("receive-sign-type=ed25519\n");
    assert!(matches!(err, Error::InvalidFormat(_)), "{err}");

    for kind in ["gpg", "dummy", "rsa"] {
        let err = refusal(&format!(
            "receive-sign-type={kind}\nreceive-sign-key-file=/nonexistent/ostrya/secret\n"
        ));
        assert!(
            matches!(&err, Error::InvalidFormat(m) if m.contains("receive-sign-type")),
            "{kind}: {err}"
        );
    }

    let err = refusal("receive-sign-key-file=/nonexistent/ostrya/secret\n");
    assert!(
        matches!(&err, Error::Signature(m) if m.contains("does not exist")),
        "{err}"
    );

    for (contents, part) in [
        ("".to_owned(), "holds no key"),
        (format!("{SECRET_B64}\n{SECRET_B64}\n"), "more than one key"),
    ] {
        let dir = TmpDir::new("receive-signer-bad");
        let file = dir.path().join("secret.ed25519");
        std::fs::write(&file, contents).unwrap();
        let err = policy_with(
            dir.path(),
            "",
            &format!("receive-sign-key-file={}\n", file.display()),
        )
        .unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains(part)),
            "{part}: {err}"
        );
    }

    // A key of the wrong length.
    let dir = TmpDir::new("receive-signer-short");
    let file = dir.path().join("secret.ed25519");
    std::fs::write(&file, format!("{PUBLIC_B64}\n")).unwrap();
    let err = policy_with(
        dir.path(),
        "",
        &format!("receive-sign-key-file={}\n", file.display()),
    )
    .unwrap_err();
    assert!(matches!(err, Error::Signature(_)), "{err}");
}

/// `receive-sign-type=spki` needs the spki engine.
#[cfg(not(feature = "sign-spki"))]
#[test]
fn an_spki_signing_key_needs_the_engine() {
    let err = refusal("receive-sign-type=spki\nreceive-sign-key-file=/nonexistent/ostrya/k\n");
    assert!(matches!(err, Error::Unsupported(_)), "{err}");
}

/// An spki signing key is read from its base64 PKCS#8 form.
#[cfg(feature = "sign-spki")]
#[test]
fn an_spki_signing_key_is_read() {
    const SECRET_PKCS8_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2L708EsnnzHER0SYasMNIUcG\
v63QapC/3kVsoPerzKGhRANCAATxfzfHKUPeJtyLTGMUoxHhvBS1NT9guWhUQPGiZRLZIcB8Wc3\
csdVU1iOiTRmbZGKJTtekOdEAbVRrx5HxIpst";
    let dir = TmpDir::new("receive-signer-spki");
    let file = dir.path().join("secret.spki");
    std::fs::write(&file, format!("{SECRET_PKCS8_B64}\n")).unwrap();
    let policy = policy_with(
        dir.path(),
        "",
        &format!(
            "receive-sign-type=spki\nreceive-sign-key-file={}\n",
            file.display()
        ),
    )
    .unwrap();
    assert_eq!(policy.signers.len(), 1);
    assert_eq!(policy.signers[0].signer().name(), "spki");
}

/// A GPG selector needs GPG signing.
#[cfg(not(feature = "sign-gpg"))]
#[test]
fn a_gpg_signing_key_needs_the_engine() {
    let err = refusal("receive-gpg-sign=0123456789ABCDEF\n");
    assert!(matches!(err, Error::Unsupported(_)), "{err}");
    // A home directory alone names no key.
    policy("receive-gpg-homedir=/nonexistent/ostrya/gnupg\n").unwrap();
}

/// The GPG signing keys come after the sign-api key, and a selector that
/// names no secret key is refused by the entry.
#[cfg(feature = "sign-gpg")]
#[test]
fn the_gpg_signing_keys_are_read() {
    if !common::gnupg_available(&["gpg", "gpgconf"]) {
        return;
    }
    let dir = TmpDir::new("receive-gpg-signer");
    let home = GnupgHome::new(
        &dir.path().join("gnupg"),
        "Receive Server <server@example.org>",
    );
    let file = dir.path().join("secret.ed25519");
    std::fs::write(&file, format!("{SECRET_B64}\n")).unwrap();

    let policy = policy_with(
        dir.path(),
        "",
        &format!(
            "receive-gpg-sign=server@example.org;\nreceive-gpg-homedir={}\n\
             receive-sign-key-file={}\n",
            home.dir.display(),
            file.display()
        ),
    )
    .unwrap();
    let names: Vec<&str> = policy.signers.iter().map(|s| s.signer().name()).collect();
    assert_eq!(names, ["ed25519", "gpg"]);

    let dir2 = TmpDir::new("receive-gpg-signer-missing");
    let err = policy_with(
        dir2.path(),
        "",
        &format!(
            "receive-gpg-sign=nobody@example.org\nreceive-gpg-homedir={}\n",
            home.dir.display()
        ),
    )
    .unwrap_err();
    assert!(
        matches!(&err, Error::Signature(m)
            if m.contains("receive-gpg-sign entry 'nobody@example.org'") && m.contains("no secret key")),
        "{err}"
    );
}

/// A private GnuPG home holding one fresh, passphrase-free signing key.
/// Dropping it stops the agent GnuPG started for the home.
#[cfg(feature = "verify-gpg")]
struct GnupgHome {
    dir: std::path::PathBuf,
}

#[cfg(feature = "verify-gpg")]
impl GnupgHome {
    fn new(dir: &Path, uid: &str) -> GnupgHome {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(dir).unwrap();
        let status = std::process::Command::new("gpg")
            .arg("--homedir")
            .arg(dir)
            .args(["--batch", "--pinentry-mode", "loopback", "--passphrase", ""])
            .args(["--quick-gen-key", uid, "ed25519", "sign", "never"])
            .status()
            .unwrap();
        assert!(status.success(), "gpg --quick-gen-key failed");
        GnupgHome {
            dir: dir.to_owned(),
        }
    }

    /// The public certificates of the home, as `gpg --export` writes them.
    fn export(&self) -> Vec<u8> {
        let out = std::process::Command::new("gpg")
            .arg("--homedir")
            .arg(&self.dir)
            .args(["--batch", "--export"])
            .output()
            .unwrap();
        assert!(
            out.status.success() && !out.stdout.is_empty(),
            "gpg --export failed"
        );
        out.stdout
    }
}

#[cfg(feature = "verify-gpg")]
impl Drop for GnupgHome {
    fn drop(&mut self) {
        let _ = std::process::Command::new("gpgconf")
            .arg("--homedir")
            .arg(&self.dir)
            .args(["--kill", "gpg-agent"])
            .status();
    }
}

/// `detached-metadata-exclude` gives a filter when it names a key, and none
/// when it is empty.
#[test]
fn detached_metadata_exclude_gives_the_filter() {
    let named = policy("detached-metadata-exclude=app.secret;app.other\n").unwrap();
    assert!(named.detached_metadata_filter.is_some());
    let empty = policy("detached-metadata-exclude=\n").unwrap();
    assert!(empty.detached_metadata_filter.is_none());
}

/// The policy moves across tasks and threads.
#[test]
fn the_policy_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ReceivePolicy>();
    assert_send_sync::<ReceiveVerify>();
    assert_send_sync::<ServerSigner>();
}
