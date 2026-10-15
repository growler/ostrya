//! `ReceivePolicies::from_config`: the receive policy of each client group,
//! the trust groups, the key groups, `[core] auto-update-summary`, and
//! `detached-metadata-exclude`.
//!
//! Each case writes one repository configuration and reads the policies. The
//! read refuses a malformed group with the error kind that the policies
//! document. Each accepted value reaches its own field alone.

#![cfg(feature = "receive")]

mod common;

use std::path::Path;
use std::sync::Arc;

use common::TmpDir;
#[cfg(feature = "verify-gpg")]
use common::receive::GnupgHome;
use ostrya::access::AccessModes;
use ostrya::{
    CreateOptions, Error, ReceivePolicies, ReceivePolicy, ReceiveVerify, Repo, RepoMode,
    ServerSigner, TrustedKeys, base64,
};
use ostrya_rt::block_on;

/// The base64 of a 64-byte ed25519 secret key (seed, then public key).
const SECRET_B64: &str =
    "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";
/// The matching 32-byte ed25519 public key.
const PUBLIC_B64: &str = "wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=";

/// The header of a trust group `t` that selects ed25519, with no key.
const TRUST_T: &str = "[ex-ostrya trust \"t\"]\nsign-verify=ed25519\n";

/// A client group `c` of the local refs that pushes to each ref.
const CLIENT_C: &str = "[ex-ostrya client \"c\"]\nauth=ssh:c\nallow=w:**\n";

/// A trust group `t` that trusts [`PUBLIC_B64`], with its key.
fn trust_t() -> String {
    format!("{TRUST_T}verification-ed25519-key={PUBLIC_B64}\n")
}

/// Creates and opens an archive repository under `dir` whose config carries
/// `core` at the end of `[core]` and `groups` after it.
fn repo_with(dir: &Path, core: &str, groups: &str) -> Repo {
    let root = dir.join("repo");
    block_on(async {
        Repo::create(&root, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let mut config = std::fs::read_to_string(root.join("config")).unwrap();
        config.push_str(core);
        config.push('\n');
        config.push_str(groups);
        std::fs::write(root.join("config"), config).unwrap();
        Repo::open(&root).await.unwrap()
    })
}

/// The policies of a repository under `dir` whose config carries `core` and
/// `groups`.
fn policy_with(dir: &Path, core: &str, groups: &str) -> ostrya::Result<ReceivePolicies> {
    let repo = repo_with(dir, core, groups);
    block_on(ReceivePolicies::from_config(&repo))
}

/// The policies of `groups`, in a fresh repository.
fn policy(groups: &str) -> ostrya::Result<ReceivePolicies> {
    let dir = TmpDir::new("receive-policy");
    policy_with(dir.path(), "", groups)
}

/// The policy of the group `name` of `policies`.
fn group<'a>(policies: &'a ReceivePolicies, name: &str) -> &'a ReceivePolicy {
    policies
        .get(name)
        .unwrap_or_else(|| panic!("no group {name}"))
}

/// The refusal of `groups`.
fn refusal(groups: &str) -> Error {
    match policy(groups) {
        Ok(policies) => panic!("the groups {groups:?} were accepted as {policies:?}"),
        Err(err) => err,
    }
}

/// Asserts that `from_config` refuses `groups` as malformed, with `part` in the
/// message.
fn assert_malformed(groups: &str, part: &str) {
    let err = refusal(groups);
    assert!(
        matches!(&err, Error::InvalidFormat(m) if m.contains(part)),
        "{groups:?}: {err}"
    );
}

/// A secret key file under `dir` that holds [`SECRET_B64`].
fn secret_file(dir: &Path) -> std::path::PathBuf {
    let file = dir.join("secret.ed25519");
    std::fs::write(&file, format!("\n{SECRET_B64}\n")).unwrap();
    file
}

/// An ed25519 key group `name` whose key is `file`.
fn key_group(name: &str, file: &Path) -> String {
    format!(
        "[ex-ostrya key \"{name}\"]\ntype=ed25519\nsecret-key-file={}\n",
        file.display()
    )
}

/// The trusted keys of a policy, `None` for no check.
fn keys(policy: &ReceivePolicy) -> Option<&Arc<TrustedKeys>> {
    match &policy.verify {
        ReceiveVerify::Off => None,
        ReceiveVerify::Keys(keys) => Some(keys),
    }
}

/// A config with no client group gives the policies of the two implicit
/// groups. Each one reads each ref, opens no push session, and has the
/// defaults of the other fields.
#[test]
fn no_client_group_gives_the_implicit_policies() {
    let policies = policy("").unwrap();
    let names: Vec<&str> = policies
        .access()
        .groups()
        .iter()
        .map(|g| g.name())
        .collect();
    assert_eq!(names, ["anonymous", "anonymous-collections"]);
    for name in names {
        let policy = group(&policies, name);
        assert_eq!(policy.rights("main"), AccessModes::READ, "{name}");
        assert_eq!(policy.rights("a/b/c"), AccessModes::READ, "{name}");
        assert!(!policy.rules.opens_push_session(), "{name}");
        assert!(keys(policy).is_none());
        assert!(policy.allow_unsigned);
        assert!(policy.signers.is_empty());
        assert!(!policy.allow_privileged);
        assert!(policy.summary_signers.is_empty());
        assert!(!policy.update_summary);
        assert!(policy.detached_metadata_filter.is_none());
    }
    assert!(policies.get("c").is_none());
}

/// Each key of a client group reaches its own field, and `sign-summary` of
/// the server group reaches each policy. Each other field keeps its default.
#[test]
fn each_group_key_reaches_its_own_field() {
    let dir = TmpDir::new("receive-fields");
    let file = secret_file(dir.path());
    let policies = policy_with(
        dir.path(),
        "",
        &format!(
            "[ex-ostrya server]\nsign-summary=k\n\
             [ex-ostrya client \"full\"]\nauth=ssh:full\nallow=wd:apps/**;r:**\n\
             deny=apps/secret\nverify=trust:t\nsign=k\nallow-privileged=true\n\
             [ex-ostrya client \"plain\"]\nauth=ssh:plain\nallow=t:tags/**\n{}{}",
            trust_t(),
            key_group("k", &file)
        ),
    )
    .unwrap();
    let full = group(&policies, "full");
    assert_eq!(full.rights("apps/a").to_string(), "rwd");
    assert_eq!(full.rights("main").to_string(), "r");
    assert_eq!(full.rights("apps/secret"), AccessModes::NONE);
    assert!(keys(full).is_some());
    assert!(!full.allow_unsigned);
    assert_eq!(full.signers.len(), 1);
    assert!(full.allow_privileged);
    assert_eq!(full.summary_signers.len(), 1);

    let plain = group(&policies, "plain");
    assert_eq!(plain.rights("tags/v1").to_string(), "rt");
    assert_eq!(plain.rights("main"), AccessModes::NONE);
    assert!(keys(plain).is_none());
    assert!(plain.allow_unsigned);
    assert!(plain.signers.is_empty());
    assert!(!plain.allow_privileged);
    assert_eq!(plain.summary_signers.len(), 1);
    assert!(Arc::ptr_eq(&plain.summary_signers[0], &full.signers[0]));
}

/// `allow-unsigned` defaults to false with `verify` and to true without it,
/// and an explicit value reaches the policy.
#[test]
fn allow_unsigned_has_two_defaults() {
    for (keys_text, want) in [
        ("", true),
        ("verify=trust:t\n", false),
        ("verify=trust:t\nallow-unsigned=true\n", true),
        ("verify=trust:t\nallow-unsigned=false\n", false),
    ] {
        let policies = policy(&format!("{CLIENT_C}{keys_text}{}", trust_t())).unwrap();
        assert_eq!(group(&policies, "c").allow_unsigned, want, "{keys_text:?}");
    }
}

/// The groups of the removed receive policy are refused, and the message names
/// the client group in their place.
#[test]
fn the_receive_groups_are_refused() {
    for group in ["ex-ostrya receive", "ex-ostrya receive \"apps/**\""] {
        assert_malformed(
            &format!("[{group}]\naccept=true\n{CLIENT_C}"),
            "[ex-ostrya client \"NAME\"]",
        );
    }
}

/// A refusal of the client groups or the server group fails the read, before
/// a key source is read.
#[test]
fn a_refused_client_group_fails_the_read() {
    assert_malformed(&format!("{CLIENT_C}owner=token:x\n"), "unknown key 'owner'");
    assert_malformed(
        &format!(
            "{CLIENT_C}[ex-ostrya key \"k\"]\ntype=ed25519\n\
             secret-key-file=/nonexistent/ostrya/secret\n\
             [ex-ostrya client \"d\"]\nauth=ssh:c\n"
        ),
        "their namespaces overlap",
    );
    assert_malformed("[ex-ostrya server]\nlisten=\n", "listen is empty");
}

/// `from_config` refuses a boolean that the key-file syntax does not read, with
/// a key-file error.
#[test]
fn a_malformed_boolean_is_refused() {
    for key in ["allow-privileged", "allow-unsigned"] {
        let err = refusal(&format!("{CLIENT_C}{key}=yes\n"));
        assert!(matches!(err, Error::Core(_)), "{key}: {err}");
    }
    let err = refusal("[ex-ostrya trust \"t\"]\ngpg-verify=yes\n");
    assert!(matches!(err, Error::Core(_)), "{err}");
}

/// `update_summary` reads `[core] auto-update-summary` and its alias
/// `commit-update-summary`. If either key is true, `update_summary` is `true`.
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
        let policies = policy_with(dir.path(), core, CLIENT_C).unwrap();
        assert_eq!(group(&policies, "c").update_summary, expected, "{core:?}");
    }
    let dir = TmpDir::new("receive-summary");
    let err = policy_with(dir.path(), "auto-update-summary=yes\n", "").unwrap_err();
    assert!(matches!(err, Error::Core(_)), "{err}");
}

/// If `detached-metadata-exclude` names a key, the policy has a filter. If the
/// value is empty, the policy has no filter.
#[test]
fn detached_metadata_exclude_gives_the_filter() {
    let named = policy("[ex-ostrya]\ndetached-metadata-exclude=app.secret;app.other\n").unwrap();
    assert!(
        group(&named, "anonymous")
            .detached_metadata_filter
            .is_some()
    );
    let empty = policy("[ex-ostrya]\ndetached-metadata-exclude=\n").unwrap();
    assert!(
        group(&empty, "anonymous")
            .detached_metadata_filter
            .is_none()
    );
}

/// `from_config` refuses an unknown key in a trust group and in a key group.
#[test]
fn an_unknown_key_is_refused() {
    let dir = TmpDir::new("receive-unknown");
    let file = secret_file(dir.path());
    for groups in [
        format!("{}gpg-verfy=true\n", trust_t()),
        format!("{}comment=x\n", key_group("k", &file)),
    ] {
        assert_malformed(&groups, "unknown key");
    }
}

/// `from_config` refuses a reference to a group that does not exist.
#[test]
fn a_reference_to_a_missing_group_is_refused() {
    assert_malformed(
        &format!("{CLIENT_C}verify=trust:nosuch\n"),
        "names no [ex-ostrya trust \"nosuch\"] group",
    );
    assert_malformed(
        &format!("{CLIENT_C}sign=nosuch\n"),
        "no [ex-ostrya key \"nosuch\"] group exists",
    );
    assert_malformed(
        "[ex-ostrya server]\nsign-summary=nosuch\n",
        "no [ex-ostrya key \"nosuch\"] group exists",
    );
}

/// `sign-verify=true` in a trust group names every engine of the build.
/// `from_config` skips an engine that has no key.
#[test]
fn a_trust_group_takes_every_engine() {
    let policies = policy(&format!(
        "{CLIENT_C}verify=trust:t\n\
         [ex-ostrya trust \"t\"]\nsign-verify=true\nverification-ed25519-key={PUBLIC_B64}\n"
    ))
    .unwrap();
    assert!(keys(group(&policies, "c")).is_some());
}

/// A trust group takes a GPG axis over a keyring that holds a certificate,
/// together with a sign-api axis.
#[cfg(feature = "verify-gpg")]
#[test]
fn a_trust_group_takes_both_axes() {
    if !common::gnupg_available(&["gpg", "gpgconf"]) {
        return;
    }
    let dir = TmpDir::new("receive-trust-gpg");
    let home = GnupgHome::new(&dir.path().join("gnupg"), "Trusted <trusted@example.org>");
    let keyring = dir.path().join("trusted.gpg");
    std::fs::write(&keyring, home.export()).unwrap();
    let policies = policy_with(
        dir.path(),
        "",
        &format!(
            "{CLIENT_C}verify=trust:t\n\
             [ex-ostrya trust \"t\"]\ngpg-verify=true\ngpgkeypath={}\n\
             sign-verify=ed25519\nverification-ed25519-key={PUBLIC_B64}\n",
            keyring.display()
        ),
    )
    .unwrap();
    let debug = format!("{:?}", keys(group(&policies, "c")).unwrap());
    assert!(debug.contains("gpg: true"), "{debug}");
    assert!(debug.contains("ostree.sign.ed25519"), "{debug}");
}

/// `from_config` reads an ed25519 key group. Its key signs as the server.
#[test]
fn an_ed25519_key_group_is_read() {
    let dir = TmpDir::new("receive-signer");
    let file = secret_file(dir.path());
    let policies = policy_with(
        dir.path(),
        "",
        &format!("{CLIENT_C}sign=k\n{}", key_group("k", &file)),
    )
    .unwrap();
    let signers = &group(&policies, "c").signers;
    assert_eq!(signers.len(), 1);
    assert_eq!(signers[0].signer().name(), "ed25519");
    let expected = ServerSigner::ed25519(&base64::decode(SECRET_B64).unwrap()).unwrap();
    let payload = b"payload";
    assert_eq!(
        block_on(signers[0].signer().sign(payload)).unwrap(),
        block_on(expected.signer().sign(payload)).unwrap(),
        "the configured key signs"
    );
}

/// `from_config` reads an spki key group from its base64 PKCS#8 form.
#[cfg(feature = "sign-spki")]
#[test]
fn an_spki_key_group_is_read() {
    const SECRET_PKCS8_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2L708EsnnzHER0SYasMNIUcG\
v63QapC/3kVsoPerzKGhRANCAATxfzfHKUPeJtyLTGMUoxHhvBS1NT9guWhUQPGiZRLZIcB8Wc3\
csdVU1iOiTRmbZGKJTtekOdEAbVRrx5HxIpst";
    let dir = TmpDir::new("receive-signer-spki");
    let file = dir.path().join("secret.spki");
    std::fs::write(&file, format!("{SECRET_PKCS8_B64}\n")).unwrap();
    let policies = policy_with(
        dir.path(),
        "",
        &format!(
            "{CLIENT_C}sign=k\n[ex-ostrya key \"k\"]\ntype=spki\nsecret-key-file={}\n",
            file.display()
        ),
    )
    .unwrap();
    let signers = &group(&policies, "c").signers;
    assert_eq!(signers.len(), 1);
    assert_eq!(signers[0].signer().name(), "spki");
}

/// `from_config` reads a GPG key group. It refuses a selector that names no
/// secret key, and the message names the group.
#[cfg(feature = "sign-gpg")]
#[test]
fn a_gpg_key_group_is_read() {
    if !common::gnupg_available(&["gpg", "gpgconf"]) {
        return;
    }
    let dir = TmpDir::new("receive-gpg-signer");
    let home = GnupgHome::new(
        &dir.path().join("gnupg"),
        "Receive Server <server@example.org>",
    );
    let file = secret_file(dir.path());
    let policies = policy_with(
        dir.path(),
        "",
        &format!(
            "{CLIENT_C}sign=ed;gpg\n{}\
             [ex-ostrya key \"gpg\"]\ntype=gpg\ngpg-key=server@example.org\ngpg-homedir={}\n",
            key_group("ed", &file),
            home.dir.display(),
        ),
    )
    .unwrap();
    let names: Vec<&str> = group(&policies, "c")
        .signers
        .iter()
        .map(|s| s.signer().name())
        .collect();
    assert_eq!(names, ["ed25519", "gpg"]);

    let dir2 = TmpDir::new("receive-gpg-signer-missing");
    let err = policy_with(
        dir2.path(),
        "",
        &format!(
            "[ex-ostrya key \"gpg\"]\ntype=gpg\ngpg-key=nobody@example.org\ngpg-homedir={}\n",
            home.dir.display()
        ),
    )
    .unwrap_err();
    assert!(
        matches!(&err, Error::Signature(m)
            if m.contains("[ex-ostrya key \"gpg\"]") && m.contains("no secret key")),
        "{err}"
    );
}

/// Two groups that name one key group share one signer. The summary shares
/// that signer too. Two groups that name one trust group share its keys. If a
/// list gives a name two times, the name counts once.
#[test]
fn the_groups_share_what_the_trust_and_key_groups_build() {
    let dir = TmpDir::new("receive-share");
    let file = secret_file(dir.path());
    let policies = policy_with(
        dir.path(),
        "",
        &format!(
            "[ex-ostrya server]\nsign-summary=k\n\
             [ex-ostrya client \"a\"]\nauth=ssh:a\nallow=w:**\nsign=k;k\nverify=trust:t\n\
             [ex-ostrya client \"b\"]\nauth=ssh:b\nallow=w:**\nsign=k\nverify=trust:t\n{}{}",
            key_group("k", &file),
            trust_t()
        ),
    )
    .unwrap();
    let a = group(&policies, "a");
    let b = group(&policies, "b");
    assert_eq!(a.signers.len(), 1);
    assert!(Arc::ptr_eq(&a.signers[0], &b.signers[0]));
    assert!(Arc::ptr_eq(&a.signers[0], &a.summary_signers[0]));
    assert!(Arc::ptr_eq(keys(a).unwrap(), keys(b).unwrap()));
}

/// A trust group must turn on one axis at least. It must state no summary key.
#[test]
fn a_trust_group_turns_on_an_axis() {
    for group in [
        "[ex-ostrya trust \"t\"]\n",
        "[ex-ostrya trust \"t\"]\ngpg-verify=false\nsign-verify=false\n",
    ] {
        assert_malformed(group, "turns on no signature check");
    }
    for key in ["gpg-verify-summary=true", "sign-verify-summary=ed25519"] {
        assert_malformed(
            &format!("{}{key}\n", trust_t()),
            "a push carries no summary",
        );
    }
}

/// `from_config` refuses a trust group key that no axis reads. It also refuses
/// an engine that is not ed25519 or spki.
#[test]
fn a_trust_group_key_no_axis_reads_is_refused() {
    assert_malformed(
        &format!("{}gpgkeypath=/keys.gpg\n", trust_t()),
        "no check reads it",
    );
    assert_malformed(
        &format!("{}gpg-verify=false\ngpgkeypath=/keys.gpg\n", trust_t()),
        "no check reads it",
    );
    assert_malformed(
        &format!(
            "[ex-ostrya trust \"t\"]\nsign-verify=false\ngpg-verify=true\nverification-ed25519-key={PUBLIC_B64}\ngpgkeypath=/k.gpg\n"
        ),
        "no check reads it",
    );
    assert_malformed(
        &format!("{}verification-foo-key=AAAA\n", trust_t()),
        "is not ed25519 or spki",
    );
    for engines in ["dummy", "ed25519;foo"] {
        assert_malformed(
            &format!(
                "[ex-ostrya trust \"t\"]\nsign-verify={engines}\nverification-ed25519-key={PUBLIC_B64}\n"
            ),
            "is not ed25519 or spki",
        );
    }
    // This case puts an spki key under an axis that selects ed25519 alone.
    let err = refusal(&format!("{}verification-spki-key=AAAA\n", trust_t()));
    #[cfg(feature = "sign-spki")]
    assert!(
        matches!(&err, Error::InvalidFormat(m) if m.contains("no check reads it")),
        "{err}"
    );
    #[cfg(not(feature = "sign-spki"))]
    assert!(matches!(err, Error::Unsupported(_)), "{err}");
}

/// `from_config` reads the key sources of each trust group, also of a group
/// that no rule names.
#[test]
fn a_trust_group_needs_readable_keys() {
    let err = refusal(TRUST_T);
    assert!(
        matches!(&err, Error::Signature(m) if m.contains("no trusted key for signature engine 'ed25519'")),
        "{err}"
    );
    let err = refusal(&format!("{TRUST_T}verification-ed25519-key=!!!\n"));
    assert!(matches!(err, Error::Core(_)), "{err}");
    let err = refusal(&format!(
        "{TRUST_T}verification-ed25519-file=/nonexistent/ostrya/keys.ed25519\n"
    ));
    assert!(
        matches!(&err, Error::Signature(m) if m.contains("/nonexistent/ostrya/keys.ed25519")),
        "{err}"
    );
    // `from_config` reads a key file of trusted keys, one key per line.
    let dir = TmpDir::new("receive-keyfile");
    let file = dir.path().join("keys.ed25519");
    std::fs::write(&file, format!("{PUBLIC_B64}\n\n")).unwrap();
    policy_with(
        dir.path(),
        "",
        &format!("{TRUST_T}verification-ed25519-file={}\n", file.display()),
    )
    .unwrap();
}

/// The verification keys of a remote do not reach a trust group.
#[test]
fn a_remote_key_is_not_a_trust_group_key() {
    let err = refusal(&format!(
        "[remote \"t\"]\nurl=http://localhost/\nverification-ed25519-key={PUBLIC_B64}\n{TRUST_T}"
    ));
    assert!(matches!(err, Error::Signature(_)), "{err}");
}

/// The GPG axis of a trust group needs `gpgkeypath`. A build without the GPG
/// engine refuses the axis.
#[test]
fn a_trust_group_gpg_axis_needs_a_keypath() {
    let err = refusal("[ex-ostrya trust \"t\"]\ngpg-verify=true\ngpgkeypath=;\n");
    #[cfg(feature = "verify-gpg")]
    assert!(
        matches!(&err, Error::InvalidFormat(m) if m.contains("gpgkeypath names no keyring")),
        "{err}"
    );
    #[cfg(not(feature = "verify-gpg"))]
    assert!(matches!(err, Error::Unsupported(_)), "{err}");
}

/// `from_config` refuses a `gpgkeypath` entry that names nothing, and the
/// message names the group and the entry. It also refuses keyrings that hold
/// no certificate.
#[cfg(feature = "verify-gpg")]
#[test]
fn a_trust_group_gpg_axis_needs_a_certificate() {
    let err = refusal(
        "[ex-ostrya trust \"t\"]\ngpg-verify=true\ngpgkeypath=/nonexistent/ostrya/keys.gpg\n",
    );
    assert!(
        matches!(&err, Error::Signature(m)
            if m.contains("[ex-ostrya trust \"t\"] gpgkeypath entry '/nonexistent/ostrya/keys.gpg'")),
        "{err}"
    );
    let dir = TmpDir::new("receive-trust-gpg-empty");
    let keyring = dir.path().join("empty.gpg");
    std::fs::write(&keyring, b"").unwrap();
    let keys = dir.path().join("keys.d");
    std::fs::create_dir(&keys).unwrap();
    std::fs::write(keys.join("README"), b"no keyring here").unwrap();
    for entry in [&keyring, &keys] {
        let err = refusal(&format!(
            "[ex-ostrya trust \"t\"]\ngpg-verify=true\ngpgkeypath={}\n",
            entry.display()
        ));
        assert!(
            matches!(&err, Error::Signature(m) if m.contains("names no key")),
            "{}: {err}",
            entry.display()
        );
    }
}

/// The spki engine of a trust group needs the spki engine of the build.
#[cfg(not(feature = "sign-spki"))]
#[test]
fn a_trust_group_spki_axis_needs_the_engine() {
    let err = refusal("[ex-ostrya trust \"t\"]\nsign-verify=spki\nverification-spki-key=AAAA\n");
    assert!(matches!(err, Error::Unsupported(_)), "{err}");
}

/// `from_config` refuses each malformed key group.
#[test]
fn a_malformed_key_group_is_refused() {
    assert_malformed(
        "[ex-ostrya key \"k\"]\nsecret-key-file=/nonexistent/ostrya/secret\n",
        "needs type",
    );
    for kind in ["dummy", "rsa", "ED25519"] {
        assert_malformed(
            &format!(
                "[ex-ostrya key \"k\"]\ntype={kind}\nsecret-key-file=/nonexistent/ostrya/secret\n"
            ),
            "malformed [ex-ostrya key \"k\"] type",
        );
    }
    for group in [
        "type=ed25519\nsecret-key-file=/s\ngpg-key=ABCD\n",
        "type=ed25519\nsecret-key-file=/s\ngpg-homedir=/gnupg\n",
        "type=spki\nsecret-key-file=/s\ngpg-key=ABCD\n",
        "type=gpg\ngpg-key=ABCD\nsecret-key-file=/s\n",
    ] {
        assert_malformed(&format!("[ex-ostrya key \"k\"]\n{group}"), "does not take");
    }
    for (kind, part) in [
        ("ed25519", "needs secret-key-file"),
        ("spki", "needs secret-key-file"),
        ("gpg", "needs gpg-key"),
    ] {
        assert_malformed(&format!("[ex-ostrya key \"k\"]\ntype={kind}\n"), part);
    }
}

/// The key file of a key group must hold exactly one key. Each refusal names
/// the group.
#[test]
fn a_key_group_file_holds_one_key() {
    let err = refusal(
        "[ex-ostrya key \"k\"]\ntype=ed25519\nsecret-key-file=/nonexistent/ostrya/secret\n",
    );
    assert!(
        matches!(&err, Error::Signature(m) if m.contains("[ex-ostrya key \"k\"]") && m.contains("does not exist")),
        "{err}"
    );
    for (contents, part) in [
        ("".to_owned(), "holds no key"),
        (format!("{SECRET_B64}\n{SECRET_B64}\n"), "more than one key"),
        (format!("{PUBLIC_B64}\n"), "[ex-ostrya key \"k\"]"),
    ] {
        let dir = TmpDir::new("receive-signer-bad");
        let file = dir.path().join("secret.ed25519");
        std::fs::write(&file, contents).unwrap();
        let err = policy_with(dir.path(), "", &key_group("k", &file)).unwrap_err();
        assert!(
            matches!(&err, Error::Signature(m) if m.contains(part)),
            "{part}: {err}"
        );
    }
}

/// An spki key group needs the spki engine.
#[cfg(not(feature = "sign-spki"))]
#[test]
fn an_spki_key_group_needs_the_engine() {
    let err = refusal("[ex-ostrya key \"k\"]\ntype=spki\nsecret-key-file=/nonexistent/ostrya/k\n");
    assert!(matches!(err, Error::Unsupported(_)), "{err}");
}

/// A GPG key group needs GPG signing.
#[cfg(not(feature = "sign-gpg"))]
#[test]
fn a_gpg_key_group_needs_the_engine() {
    let err = refusal("[ex-ostrya key \"k\"]\ntype=gpg\ngpg-key=0123456789ABCDEF\n");
    assert!(matches!(err, Error::Unsupported(_)), "{err}");
}

/// `from_config` also builds a key group that no rule names. If it cannot read
/// the key, the call fails.
#[test]
fn an_unnamed_key_group_is_built() {
    let err = refusal(
        "[ex-ostrya key \"spare\"]\ntype=ed25519\nsecret-key-file=/nonexistent/ostrya/secret\n",
    );
    assert!(matches!(err, Error::Signature(_)), "{err}");
}

/// Runs the `ostree` command on the repository `repo`.
fn ostree(repo: &Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new("ostree")
        .arg(format!("--repo={}", repo.display()))
        .args(args)
        .output()
        .unwrap()
}

/// The `ostree` command reads a repository whose config holds the client
/// groups, the server group, a trust group, and a key group. Its `refs`,
/// `fsck`, and `summary -u` commands exit 0 and write nothing to standard
/// error.
#[test]
fn the_tool_tolerates_the_client_groups() {
    if !common::ostree_available() {
        eprintln!("skipping: ostree not available");
        return;
    }
    let dir = TmpDir::new("receive-tool");
    let repo = dir.path().join("repo");
    let tree = dir.path().join("tree");
    std::fs::create_dir(&tree).unwrap();
    std::fs::write(tree.join("file"), b"content").unwrap();
    let out = ostree(&repo, &["init", "--mode=archive"]);
    assert!(out.status.success(), "{out:?}");
    let out = ostree(
        &repo,
        &[
            "commit",
            "-b",
            "x",
            &format!("--tree=dir={}", tree.display()),
        ],
    );
    assert!(out.status.success(), "{out:?}");

    let mut config = std::fs::read_to_string(repo.join("config")).unwrap();
    config.push_str(&format!(
        "\n[ex-ostrya server]\nlisten=127.0.0.1:8080\nsign-summary=central-ed\n\
         [ex-ostrya client \"public\"]\nauth=anonymous\nallow=r:**\n\
         [ex-ostrya client \"mirror\"]\nauth=ssh:mirror;net:10.0.0.0/24\n\
         collection=org.example.Os;org.example.Apps\n\
         allow=wd:apps/**;t:releases/*\ndeny=apps/secret\n\
         verify=trust:release\nallow-unsigned=false\nsign=central-ed\n\
         [ex-ostrya trust \"release\"]\nsign-verify=ed25519\n\
         verification-ed25519-key={PUBLIC_B64}\n\
         [ex-ostrya key \"central-ed\"]\ntype=ed25519\n\
         secret-key-file=/nonexistent/central.ed25519.key\n"
    ));
    std::fs::write(repo.join("config"), config).unwrap();

    for args in [&["refs"][..], &["fsck"], &["summary", "-u"]] {
        let out = ostree(&repo, args);
        assert!(
            out.status.success() && out.stderr.is_empty(),
            "ostree {args:?}: {}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    assert!(repo.join("summary").exists());
}

/// The tool writes a key of a client group with `config set`, keeps the group
/// and the value verbatim in the config, and still runs its commands. The
/// policies read the group and the value.
#[test]
fn the_tool_keeps_a_client_group_verbatim() {
    if !common::ostree_available() {
        eprintln!("skipping: ostree not available");
        return;
    }
    let dir = TmpDir::new("receive-tool-verbatim");
    let repo = dir.path().join("repo");
    let out = ostree(&repo, &["init", "--mode=archive"]);
    assert!(out.status.success(), "{out:?}");
    for (key, value) in [("auth", "ssh:ci"), ("allow", "w:apps/**;r:**")] {
        let out = ostree(
            &repo,
            &[
                "config",
                "set",
                &format!("ex-ostrya client \"ci\".{key}"),
                value,
            ],
        );
        assert!(out.status.success(), "{out:?}");
    }
    let config = std::fs::read_to_string(repo.join("config")).unwrap();
    assert!(
        config.contains("[ex-ostrya client \"ci\"]\nauth=ssh:ci\nallow=w:apps/**;r:**\n"),
        "{config}"
    );
    for args in [&["refs"][..], &["fsck"], &["summary", "-u"]] {
        let out = ostree(&repo, args);
        assert!(out.status.success(), "ostree {args:?}: {out:?}");
    }
    let repo = block_on(Repo::open(&repo)).unwrap();
    let policies = block_on(ReceivePolicies::from_config(&repo)).unwrap();
    let ci = group(&policies, "ci");
    assert_eq!(ci.rights("apps/a/b").to_string(), "rw");
    assert_eq!(ci.rights("main").to_string(), "r");
}

/// The policies move across tasks and threads.
#[test]
fn the_policies_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ReceivePolicies>();
    assert_send_sync::<ReceivePolicy>();
    assert_send_sync::<ReceiveVerify>();
    assert_send_sync::<TrustedKeys>();
    assert_send_sync::<ServerSigner>();
}
