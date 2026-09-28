//! `ReceivePolicy::from_config` and `ReceivePolicy::from_file`: the receive
//! groups, `[core] auto-update-summary`, and `detached-metadata-exclude`.
//!
//! Each case writes one repository configuration, and a policy file where the
//! case needs one, and reads the policy from it. A malformed group is refused
//! with the error kind the policy documents, and each accepted value reaches
//! its own field alone.

#![cfg(feature = "receive")]

mod common;

use std::path::Path;
use std::sync::Arc;

use common::TmpDir;
use ostrya::{
    CreateOptions, Error, ReceivePolicy, ReceiveRule, ReceiveVerify, RefPattern, Repo, RepoMode,
    ServerSigner, TrustedKeys, base64,
};
use ostrya_rt::block_on;

/// The base64 of a 64-byte ed25519 secret key (seed, then public key).
const SECRET_B64: &str =
    "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";
/// The matching 32-byte ed25519 public key.
const PUBLIC_B64: &str = "wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=";

/// A trust group `t` that trusts [`PUBLIC_B64`].
const TRUST_T: &str = "[ex-ostrya trust \"t\"]\nsign-verify=ed25519\n";

/// A trust group `t` that trusts [`PUBLIC_B64`], with its key.
fn trust_t() -> String {
    format!("{TRUST_T}verification-ed25519-key={PUBLIC_B64}\n")
}

/// Create an archive repository under `dir` whose config carries `core` at the
/// end of `[core]` and `groups` after it, and open it.
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

/// The receive policy of a repository under `dir` whose config carries `core`
/// and `groups`.
fn policy_with(dir: &Path, core: &str, groups: &str) -> ostrya::Result<ReceivePolicy> {
    let repo = repo_with(dir, core, groups);
    block_on(ReceivePolicy::from_config(&repo))
}

/// The receive policy of `groups`, in a fresh repository.
fn policy(groups: &str) -> ostrya::Result<ReceivePolicy> {
    let dir = TmpDir::new("receive-policy");
    policy_with(dir.path(), "", groups)
}

/// The refusal of `groups`.
fn refusal(groups: &str) -> Error {
    match policy(groups) {
        Ok(policy) => panic!("the groups {groups:?} were accepted as {policy:?}"),
        Err(err) => err,
    }
}

/// Assert that `groups` is refused as malformed, with `part` in the message.
fn assert_malformed(groups: &str, part: &str) {
    let err = refusal(groups);
    assert!(
        matches!(&err, Error::InvalidFormat(m) if m.contains(part)),
        "{groups:?}: {err}"
    );
}

/// The policy that the file `text` states, for a repository under `dir` whose
/// config carries `groups`.
fn file_policy(dir: &Path, groups: &str, text: &str) -> ostrya::Result<ReceivePolicy> {
    let repo = repo_with(dir, "", groups);
    let file = dir.join("receive.conf");
    std::fs::write(&file, text).unwrap();
    block_on(ReceivePolicy::from_file(&repo, &file))
}

/// A secret key file holding [`SECRET_B64`] under `dir`.
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

/// The trusted keys of a rule, `None` for no check.
fn keys(rule: &ReceiveRule) -> Option<&Arc<TrustedKeys>> {
    match &rule.verify {
        ReceiveVerify::Off => None,
        ReceiveVerify::Keys(keys) => Some(keys),
    }
}

/// The policy with no receive group is the default rule with its defaults.
#[test]
fn no_group_gives_the_default_rule() {
    let policy = policy("").unwrap();
    let rule = &policy.default_rule;
    assert!(rule.accept);
    assert!(keys(rule).is_none());
    assert!(!rule.allow_non_fast_forward);
    assert!(!rule.allow_delete);
    assert!(rule.signers.is_empty());
    assert!(policy.rules.is_empty());
    assert!(!policy.allow_privileged);
    assert!(policy.summary_signers.is_empty());
    assert!(!policy.update_summary);
    assert!(policy.detached_metadata_filter.is_none());
    assert!(std::ptr::eq(policy.rule_for("main").unwrap(), rule));
    assert!(policy.rule_for("origin:main").is_none());
}

/// Each boolean rule key reaches its own field, in the default group and in a
/// pattern group, and a pattern rule takes no key from the default rule.
#[test]
fn each_rule_boolean_reaches_its_own_field() {
    type Field = fn(&ReceiveRule) -> bool;
    let fields: [(&str, bool, Field); 3] = [
        ("accept", true, |r| r.accept),
        ("allow-non-fast-forward", false, |r| {
            r.allow_non_fast_forward
        }),
        ("allow-delete", false, |r| r.allow_delete),
    ];
    for (key, _, _) in &fields {
        for (value, expected) in [("true", true), ("1", true), ("false", false), ("0", false)] {
            // A rule that refuses its refs takes none of the other keys.
            if !expected && *key != "accept" {
                continue;
            }
            let groups =
                format!("[ex-ostrya receive]\n{key}={value}\n[ex-ostrya receive \"apps/*\"]\n");
            let policy = policy(&groups).unwrap();
            let (_, pattern_rule) = &policy.rules[0];
            for (other, default, read) in &fields {
                let want = if other == key { expected } else { *default };
                assert_eq!(read(&policy.default_rule), want, "{key}={value}, {other}");
                assert_eq!(read(pattern_rule), *default, "{key}={value}, {other}");
            }
        }
    }
}

/// The session keys reach their fields in the default group, and a pattern
/// group that states one is refused.
#[test]
fn the_session_keys_live_in_the_default_group() {
    let dir = TmpDir::new("receive-session");
    let file = secret_file(dir.path());
    let policy = policy_with(
        dir.path(),
        "",
        &format!(
            "[ex-ostrya receive]\nallow-privileged=true\nsign-summary=k\n{}",
            key_group("k", &file)
        ),
    )
    .unwrap();
    assert!(policy.allow_privileged);
    assert_eq!(policy.summary_signers.len(), 1);

    for key in ["allow-privileged=true", "sign-summary=k"] {
        assert_malformed(
            &format!(
                "[ex-ostrya receive \"main\"]\n{key}\n{}",
                key_group("k", &file)
            ),
            "valid in [ex-ostrya receive] alone",
        );
    }
}

/// A boolean the key-file syntax does not read is refused as a key-file
/// error.
#[test]
fn a_malformed_boolean_is_refused() {
    for key in [
        "accept",
        "allow-non-fast-forward",
        "allow-delete",
        "allow-privileged",
    ] {
        let err = refusal(&format!("[ex-ostrya receive]\n{key}=yes\n"));
        assert!(matches!(err, Error::Core(_)), "{key}: {err}");
    }
    let err = refusal("[ex-ostrya trust \"t\"]\ngpg-verify=yes\n");
    assert!(matches!(err, Error::Core(_)), "{err}");
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

/// `detached-metadata-exclude` gives a filter when it names a key, and none
/// when it is empty.
#[test]
fn detached_metadata_exclude_gives_the_filter() {
    let named = policy("[ex-ostrya]\ndetached-metadata-exclude=app.secret;app.other\n").unwrap();
    assert!(named.detached_metadata_filter.is_some());
    let empty = policy("[ex-ostrya]\ndetached-metadata-exclude=\n").unwrap();
    assert!(empty.detached_metadata_filter.is_none());
}

/// Each pattern group becomes a rule under its pattern, in file order, and
/// the rules select as their patterns say.
#[test]
fn the_pattern_groups_become_rules() {
    let policy = policy(
        "[ex-ostrya receive]\naccept=false\n\
         [ex-ostrya receive \"apps/*\"]\nallow-delete=true\n\
         [ex-ostrya receive \"central:*\"]\n\
         [ex-ostrya receive \"*:apps/x\"]\n",
    )
    .unwrap();
    let patterns: Vec<&str> = policy.rules.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(patterns, ["apps/*", "central:*", "*:apps/x"]);
    assert!(!policy.rule_for("main").unwrap().accept);
    assert!(policy.rule_for("apps/a").unwrap().allow_delete);
    let central = policy.rule_for("central:apps/x").unwrap();
    assert!(std::ptr::eq(central, &policy.rules[1].1));
    let other = policy.rule_for("other:apps/x").unwrap();
    assert!(std::ptr::eq(other, &policy.rules[2].1));
    assert!(policy.rule_for("other:apps/y").is_none());
}

/// A hand-built rule takes a pattern `RefPattern::parse` accepts.
#[test]
fn a_hand_built_policy_selects_its_rules() {
    let policy = ReceivePolicy {
        rules: vec![(
            RefPattern::parse("*:*").unwrap(),
            ReceiveRule {
                allow_delete: true,
                ..ReceiveRule::default()
            },
        )],
        ..ReceivePolicy::default()
    };
    assert!(policy.rule_for("origin:x").unwrap().allow_delete);
    assert!(!policy.rule_for("x").unwrap().allow_delete);
}

/// Each malformed pattern in a group name is refused.
#[test]
fn a_malformed_pattern_is_refused() {
    for pattern in [
        "*", "**", "a*", "*/x", "a/*/b", "/*", "a//*", ":x", "r:", "r/x:y", "..", "a/./b",
    ] {
        assert_malformed(
            &format!("[ex-ostrya receive \"{pattern}\"]\n"),
            "malformed receive pattern",
        );
    }
}

/// Each group name that starts with `ex-ostrya ` and has no shape of a receive
/// group is refused, and `[ex-ostrya]` keeps its keys.
#[test]
fn an_unknown_receive_group_is_refused() {
    for group in [
        "ex-ostrya bogus",
        "ex-ostrya receive p",
        "ex-ostrya receive \"\"",
        "ex-ostrya receive \"a\"b\"",
        "ex-ostrya trust",
        "ex-ostrya key \"\"",
    ] {
        let err = refusal(&format!("[{group}]\n"));
        assert!(matches!(err, Error::InvalidFormat(_)), "{group}: {err}");
    }
    policy("[ex-ostrya]\ngc-root-metadata-keys=app.roots\n").unwrap();
}

/// An unknown key in each receive group shape is refused.
#[test]
fn an_unknown_key_is_refused() {
    let dir = TmpDir::new("receive-unknown");
    let file = secret_file(dir.path());
    for groups in [
        "[ex-ostrya receive]\nallow-remote-refs=true\n".to_owned(),
        "[ex-ostrya receive \"main\"]\nverfy=off\n".to_owned(),
        format!("{}gpg-verfy=true\n", trust_t()),
        format!("{}comment=x\n", key_group("k", &file)),
    ] {
        assert_malformed(&groups, "unknown key");
    }
}

/// The values of `verify`: `off`, `trust:NAME`, and `remote:NAME`.
#[test]
fn verify_reads_its_three_forms() {
    let policy = policy(&format!(
        "[ex-ostrya receive]\nverify=off\n\
         [ex-ostrya receive \"a\"]\nverify=trust:t\n\
         [ex-ostrya receive \"b\"]\nverify=remote:central\n\
         {}\
         [remote \"central\"]\nurl=http://localhost/\ngpg-verify=false\n\
         sign-verify=ed25519\nverification-ed25519-key={PUBLIC_B64}\n",
        trust_t()
    ))
    .unwrap();
    assert!(keys(&policy.default_rule).is_none());
    assert!(keys(&policy.rules[0].1).is_some());
    assert!(keys(&policy.rules[1].1).is_some());
}

/// Each malformed `verify` value is refused.
#[test]
fn a_malformed_verify_is_refused() {
    for value in [
        "", "OFF", "true", "gpg", "ed25519", "trust:", "remote:", "trust",
    ] {
        assert_malformed(
            &format!("[ex-ostrya receive]\nverify={value}\n{}", trust_t()),
            "malformed [ex-ostrya receive] verify value",
        );
    }
    // One value, so the `;` is part of the trust group name.
    assert_malformed(
        &format!(
            "[ex-ostrya receive]\nverify=trust:t;remote:c\n{}",
            trust_t()
        ),
        "names no [ex-ostrya trust \"t;remote:c\"] group",
    );
}

/// The remote name of `verify=remote:NAME` is one path component, even where
/// a remote section of that name exists.
#[test]
fn a_remote_reference_names_one_path_component() {
    for name in ["../x", "a/b", "..", "."] {
        assert_malformed(
            &format!(
                "[remote \"{name}\"]\nurl=http://localhost/\n\
                 [ex-ostrya receive]\nverify=remote:{name}\n"
            ),
            "the remote name is one path component",
        );
    }
}

/// A reference to a group or a section that does not exist is refused.
#[test]
fn a_reference_to_a_missing_group_is_refused() {
    assert_malformed(
        "[ex-ostrya receive]\nverify=trust:nosuch\n",
        "names no [ex-ostrya trust \"nosuch\"] group",
    );
    assert_malformed(
        "[ex-ostrya receive]\nverify=remote:nosuch\n",
        "names no [remote \"nosuch\"] group",
    );
    for key in ["sign", "sign-summary"] {
        assert_malformed(
            &format!("[ex-ostrya receive]\n{key}=nosuch\n"),
            "no [ex-ostrya key \"nosuch\"] group exists",
        );
    }
    // An empty element names no group either.
    let dir = TmpDir::new("receive-empty-sign");
    let file = secret_file(dir.path());
    let err = policy_with(
        dir.path(),
        "",
        &format!("[ex-ostrya receive]\nsign=k;;\n{}", key_group("k", &file)),
    )
    .unwrap_err();
    assert!(
        matches!(&err, Error::InvalidFormat(m) if m.contains("key group ''")),
        "{err}"
    );
}

/// A rule that refuses its refs and states a key that only an accepted ref
/// reads is refused, whatever the value. The session keys are not such keys.
#[test]
fn a_refusing_rule_takes_no_accept_only_key() {
    for key in [
        "verify=off",
        "sign=k",
        "allow-non-fast-forward=false",
        "allow-delete=true",
    ] {
        for group in ["ex-ostrya receive", "ex-ostrya receive \"main\""] {
            let dir = TmpDir::new("receive-dead-keys");
            let file = secret_file(dir.path());
            let err = policy_with(
                dir.path(),
                "",
                &format!("[{group}]\naccept=false\n{key}\n{}", key_group("k", &file)),
            )
            .unwrap_err();
            assert!(
                matches!(&err, Error::InvalidFormat(m) if m.contains("has no effect")),
                "{group} {key}: {err}"
            );
        }
    }
    let dir = TmpDir::new("receive-dead-keys");
    let file = secret_file(dir.path());
    let policy = policy_with(
        dir.path(),
        "",
        &format!(
            "[ex-ostrya receive]\naccept=false\nallow-privileged=true\nsign-summary=k\n{}",
            key_group("k", &file)
        ),
    )
    .unwrap();
    assert!(!policy.default_rule.accept);
}

/// A trust group turns on one axis at least, and states no summary key.
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

/// A trust group key that no axis reads is refused, and so is an engine
/// other than ed25519 and spki.
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
    // An spki key under an axis that selects ed25519 alone.
    let err = refusal(&format!("{}verification-spki-key=AAAA\n", trust_t()));
    #[cfg(feature = "sign-spki")]
    assert!(
        matches!(&err, Error::InvalidFormat(m) if m.contains("no check reads it")),
        "{err}"
    );
    #[cfg(not(feature = "sign-spki"))]
    assert!(matches!(err, Error::Unsupported(_)), "{err}");
}

/// `sign-verify=true` in a trust group names every engine of the build, and
/// an engine with no key is passed over.
#[test]
fn a_trust_group_takes_every_engine() {
    let policy = policy(&format!(
        "[ex-ostrya receive]\nverify=trust:t\n\
         [ex-ostrya trust \"t\"]\nsign-verify=true\nverification-ed25519-key={PUBLIC_B64}\n"
    ))
    .unwrap();
    assert!(keys(&policy.default_rule).is_some());
}

/// The key sources of a trust group are read when the policy is read, also
/// for a group that no rule names.
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
    // A key file of trusted keys, one per line, is read.
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

/// A remote's verification keys do not reach a trust group.
#[test]
fn a_remote_key_is_not_a_trust_group_key() {
    let err = refusal(&format!(
        "[remote \"t\"]\nurl=http://localhost/\nverification-ed25519-key={PUBLIC_B64}\n{TRUST_T}"
    ));
    assert!(matches!(err, Error::Signature(_)), "{err}");
}

/// The GPG axis of a trust group needs `gpgkeypath`, and a build without the
/// GPG engine refuses the axis.
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

/// A `gpgkeypath` entry that names nothing is refused by the group and the
/// entry, and keyrings that hold no certificate are refused.
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

/// A trust group with a GPG axis over a keyring that holds a certificate, and
/// a sign-api axis beside it.
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
    let policy = policy_with(
        dir.path(),
        "",
        &format!(
            "[ex-ostrya receive]\nverify=trust:t\n\
             [ex-ostrya trust \"t\"]\ngpg-verify=true\ngpgkeypath={}\n\
             sign-verify=ed25519\nverification-ed25519-key={PUBLIC_B64}\n",
            keyring.display()
        ),
    )
    .unwrap();
    let debug = format!("{:?}", keys(&policy.default_rule).unwrap());
    assert!(debug.contains("gpg: true"), "{debug}");
    assert!(debug.contains("ostree.sign.ed25519"), "{debug}");
}

/// The spki engine of a trust group needs the spki engine of the build.
#[cfg(not(feature = "sign-spki"))]
#[test]
fn a_trust_group_spki_axis_needs_the_engine() {
    let err = refusal("[ex-ostrya trust \"t\"]\nsign-verify=spki\nverification-spki-key=AAAA\n");
    assert!(matches!(err, Error::Unsupported(_)), "{err}");
}

/// `remote:NAME` refuses a remote whose pull turns on no check.
#[test]
fn a_remote_reference_turns_on_a_check() {
    assert_malformed(
        "[ex-ostrya receive]\nverify=remote:c\n\
         [remote \"c\"]\nurl=http://localhost/\ngpg-verify=false\n",
        "turns on no signature check",
    );
}

/// An ed25519 key group is read, and its key signs as the server.
#[test]
fn an_ed25519_key_group_is_read() {
    let dir = TmpDir::new("receive-signer");
    let file = secret_file(dir.path());
    let policy = policy_with(
        dir.path(),
        "",
        &format!("[ex-ostrya receive]\nsign=k\n{}", key_group("k", &file)),
    )
    .unwrap();
    let signers = &policy.default_rule.signers;
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

/// Each malformed key group is refused.
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

/// The key file of a key group holds exactly one key, and each refusal names
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

/// An spki key group is read from its base64 PKCS#8 form.
#[cfg(feature = "sign-spki")]
#[test]
fn an_spki_key_group_is_read() {
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
            "[ex-ostrya receive]\nsign=k\n[ex-ostrya key \"k\"]\ntype=spki\nsecret-key-file={}\n",
            file.display()
        ),
    )
    .unwrap();
    assert_eq!(policy.default_rule.signers.len(), 1);
    assert_eq!(policy.default_rule.signers[0].signer().name(), "spki");
}

/// A GPG key group needs GPG signing.
#[cfg(not(feature = "sign-gpg"))]
#[test]
fn a_gpg_key_group_needs_the_engine() {
    let err = refusal("[ex-ostrya key \"k\"]\ntype=gpg\ngpg-key=0123456789ABCDEF\n");
    assert!(matches!(err, Error::Unsupported(_)), "{err}");
}

/// A GPG key group is read, and a selector that names no secret key is
/// refused by the group.
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
    let policy = policy_with(
        dir.path(),
        "",
        &format!(
            "[ex-ostrya receive]\nsign=ed;gpg\n{}\
             [ex-ostrya key \"gpg\"]\ntype=gpg\ngpg-key=server@example.org\ngpg-homedir={}\n",
            key_group("ed", &file),
            home.dir.display(),
        ),
    )
    .unwrap();
    let names: Vec<&str> = policy
        .default_rule
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

/// A key group that no rule names is built too, so a key it cannot read fails
/// the call.
#[test]
fn an_unnamed_key_group_is_built() {
    let err = refusal(
        "[ex-ostrya key \"spare\"]\ntype=ed25519\nsecret-key-file=/nonexistent/ostrya/secret\n",
    );
    assert!(matches!(err, Error::Signature(_)), "{err}");
}

/// Two rules that name one key group share one signer, and so does the
/// summary. Two rules that name one trust group share its keys. A name given
/// twice in one list counts once.
#[test]
fn the_rules_share_what_the_groups_build() {
    let dir = TmpDir::new("receive-share");
    let file = secret_file(dir.path());
    let policy = policy_with(
        dir.path(),
        "",
        &format!(
            "[ex-ostrya receive]\nsign=k;k\nsign-summary=k\nverify=trust:t\n\
             [ex-ostrya receive \"apps/*\"]\nsign=k\nverify=trust:t\n{}{}",
            key_group("k", &file),
            trust_t()
        ),
    )
    .unwrap();
    let default = &policy.default_rule;
    let apps = &policy.rules[0].1;
    assert_eq!(default.signers.len(), 1);
    assert!(Arc::ptr_eq(&default.signers[0], &apps.signers[0]));
    assert!(Arc::ptr_eq(&default.signers[0], &policy.summary_signers[0]));
    assert!(Arc::ptr_eq(keys(default).unwrap(), keys(apps).unwrap()));
}

/// Under `from_file`, the receive groups come from the file alone: the groups
/// of the repository config are not read, a malformed one included, and
/// `update_summary` and the filter still come from the repository config.
#[test]
fn a_policy_file_replaces_the_config_groups() {
    let dir = TmpDir::new("receive-file");
    let repo = repo_with(
        dir.path(),
        "auto-update-summary=true\n",
        "[ex-ostrya]\ndetached-metadata-exclude=app.secret\n\
         [ex-ostrya receive]\nallow-delete=true\n\
         [ex-ostrya bogus]\n",
    );
    let file = dir.path().join("receive.conf");
    std::fs::write(&file, "[ex-ostrya receive]\naccept=false\n").unwrap();
    let policy = block_on(ReceivePolicy::from_file(&repo, &file)).unwrap();
    assert!(!policy.default_rule.accept);
    assert!(!policy.default_rule.allow_delete);
    assert!(policy.update_summary);
    assert!(policy.detached_metadata_filter.is_some());
}

/// Under `from_file`, `remote:NAME` resolves in the file alone.
#[test]
fn a_policy_file_resolves_remotes_in_itself() {
    let remote = format!(
        "[remote \"central\"]\nurl=http://localhost/\ngpg-verify=false\n\
         sign-verify=ed25519\nverification-ed25519-key={PUBLIC_B64}\n"
    );
    let rule = "[ex-ostrya receive \"central:*\"]\nverify=remote:central\n";
    let dir = TmpDir::new("receive-file-remote");
    let policy = file_policy(dir.path(), "", &format!("{rule}{remote}")).unwrap();
    assert!(keys(&policy.rules[0].1).is_some());

    let dir = TmpDir::new("receive-file-remote-config");
    let err = file_policy(dir.path(), &remote, rule).unwrap_err();
    assert!(
        matches!(&err, Error::InvalidFormat(m) if m.contains("names no [remote \"central\"] group")),
        "{err}"
    );
}

/// A policy file holds the receive groups and remote sections alone, and a
/// file that cannot be read is refused by its path.
#[test]
fn a_policy_file_holds_the_receive_groups_alone() {
    for text in [
        "[core]\nmode=archive\n",
        "[ex-ostrya]\ndetached-metadata-exclude=app.x\n",
        "[other]\nk=v\n",
    ] {
        let dir = TmpDir::new("receive-file-extra");
        let err = file_policy(dir.path(), "", text).unwrap_err();
        assert!(
            matches!(&err, Error::InvalidFormat(m) if m.contains("the receive policy file holds")),
            "{text:?}: {err}"
        );
    }
    let dir = TmpDir::new("receive-file-unused-remote");
    file_policy(
        dir.path(),
        "",
        "[remote \"spare\"]\nurl=http://localhost/\n",
    )
    .unwrap();

    let dir = TmpDir::new("receive-file-missing");
    let repo = repo_with(dir.path(), "", "");
    let missing = dir.path().join("absent.conf");
    let err = block_on(ReceivePolicy::from_file(&repo, &missing)).unwrap_err();
    assert!(
        matches!(&err, Error::InvalidFormat(m) if m.contains("absent.conf")),
        "{err}"
    );
    let err = block_on(ReceivePolicy::from_file(&repo, dir.path())).unwrap_err();
    assert!(
        matches!(&err, Error::InvalidFormat(m) if m.contains("regular file")),
        "{err}"
    );
}

/// The tool reads a repository whose config holds the receive group shapes:
/// `refs`, `fsck`, and `summary -u` exit 0 and write nothing to standard
/// error.
#[test]
fn the_tool_tolerates_the_receive_groups() {
    if !common::ostree_available() {
        eprintln!("skipping: ostree not available");
        return;
    }
    let dir = TmpDir::new("receive-tool");
    let repo = dir.path().join("repo");
    let tree = dir.path().join("tree");
    std::fs::create_dir(&tree).unwrap();
    std::fs::write(tree.join("file"), b"content").unwrap();
    let ostree = |args: &[&str]| {
        std::process::Command::new("ostree")
            .arg(format!("--repo={}", repo.display()))
            .args(args)
            .output()
            .unwrap()
    };
    let out = ostree(&["init", "--mode=archive"]);
    assert!(out.status.success(), "{out:?}");
    let out = ostree(&[
        "commit",
        "-b",
        "x",
        &format!("--tree=dir={}", tree.display()),
    ]);
    assert!(out.status.success(), "{out:?}");

    let mut config = std::fs::read_to_string(repo.join("config")).unwrap();
    config.push_str(&format!(
        "\n[ex-ostrya receive]\naccept=false\nsign-summary=central-ed\n\
         [ex-ostrya receive \"apps/*\"]\nverify=trust:release\nsign=central-ed\n\
         [ex-ostrya receive \"central:*\"]\nverify=remote:central\n\
         [ex-ostrya receive \"*:apps/x.y\"]\nallow-delete=true\n\
         [ex-ostrya trust \"release\"]\nsign-verify=ed25519\n\
         verification-ed25519-key={PUBLIC_B64}\n\
         [ex-ostrya key \"central-ed\"]\ntype=ed25519\n\
         secret-key-file=/nonexistent/central.ed25519.key\n\
         [remote \"central\"]\nurl=https://central.example/repo\ngpg-verify=false\n\
         sign-verify=ed25519\nverification-ed25519-file=/nonexistent/central.ed25519\n"
    ));
    std::fs::write(repo.join("config"), config).unwrap();

    for args in [&["refs"][..], &["fsck"], &["summary", "-u"]] {
        let out = ostree(args);
        assert!(
            out.status.success() && out.stderr.is_empty(),
            "ostree {args:?}: {}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    assert!(repo.join("summary").exists());
}

/// A private GnuPG home holding one fresh, passphrase-free signing key.
/// Dropping it stops the GnuPG daemons of the home and removes their socket
/// directory.
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
        common::remove_gnupg_sockets(&self.dir);
    }
}

/// The policy moves across tasks and threads.
#[test]
fn the_policy_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ReceivePolicy>();
    assert_send_sync::<ReceiveRule>();
    assert_send_sync::<ReceiveVerify>();
    assert_send_sync::<RefPattern>();
    assert_send_sync::<TrustedKeys>();
    assert_send_sync::<ServerSigner>();
}
