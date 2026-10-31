//! The receive policy of a client group, and the policies of the client
//! groups of a repository.

use std::sync::Arc;

use crate::access::{
    AccessModes, AccessRules, AuthItem, ClientAccess, ClientGroup, CollectionScope, Namespace,
};
use crate::error::Result;
use crate::remote::{self, RefUpdate};
use crate::repo::Repo;

use super::reader;
use super::session::Failure;
use super::{ServerSigner, StreamPolicy, TrustedKeys};

/// The rules of one client group for a push session.
///
/// The policy states which refs a session can read and change, how the
/// server verifies the commits of the client, and which keys sign them. It
/// also states the steps after an accepted session: the server signatures of
/// the summary and the summary regeneration.
///
/// [`ReceivePolicies::from_config`] builds one policy for each client group
/// of a repository. A caller can also build a policy in code.
///
/// The [`Default`] policy has no allow item. It opens no push session, so
/// each `Hello` gets `ref-denied`.
///
/// # Rights
///
/// [`rights`](ReceivePolicy::rights) gives the effective rights of a ref. A
/// session applies them in this way:
///
/// - The [`scope`](ReceivePolicy::scope) must cover the namespace of
///   `Hello`.
/// - Each ref of `Hello` needs `r`. A remote ref `REMOTE:NAME` has no right,
///   so a push session never reads or writes one.
/// - A session opens only if an allow item has `w`, `c`, `t`, or `d`.
/// - An update that writes a commit needs `w` or `t`. With `t` and no `w`,
///   the update can create the ref and cannot write to a ref that exists,
///   also when the commit is the current one.
/// - An update with `w` is a fast-forward. With `w`, `d`, and `force` in the
///   request, it can also be a non-fast-forward update.
/// - A delete of a ref that exists needs `d`. A delete of an absent ref
///   changes nothing.
/// - A server commit needs `c` on its branch. With `orphan` on a branch that
///   exists, it needs `c` and `d`. Each tag of a server commit needs `t` or
///   `w`, and the tag must not exist, also with `w`. A bound name of a
///   server commit gets no ref and needs no right.
#[derive(Debug, Clone, Default)]
pub struct ReceivePolicy {
    /// The namespace of the group.
    ///
    /// A session opens only in a namespace that the scope covers, as
    /// [`CollectionScope::covers`] states. The rules name the refs of that
    /// namespace. The default is [`CollectionScope::Local`].
    pub scope: CollectionScope,
    /// The allow items and the deny items of the group.
    pub rules: AccessRules,
    /// The signatures that a new commit must carry.
    ///
    /// The verification applies to each new commit of a ref update that a
    /// client builds and pushes. A server commit gets no verification. A
    /// commit that no update names gets no verification, a staged parent and
    /// a dependency included. The checksum of a dependency is in field 2 of
    /// a commit. A new commit is that commit, or binds it through the parent
    /// checksums of its history, and the signatures of the new commit cover
    /// these checksums.
    pub verify: ReceiveVerify,
    /// The switch that accepts a new commit with no signature.
    ///
    /// The switch applies only with [`ReceiveVerify::Keys`], and only to a
    /// new commit that the client built, which
    /// [`verify`](ReceivePolicy::verify) applies to. A commit has no
    /// signature if its detached metadata holds no blob under
    /// `ostree.gpgsigs`, `ostree.sign.ed25519`, `ostree.sign.spki`, and
    /// `ostree.sign.dummy`. A commit with a blob under one of these keys must
    /// pass the verification on each axis of the keys, also when the switch
    /// is `true`.
    pub allow_unsigned: bool,
    /// The keys that the server signs each new commit with, in order.
    ///
    /// An spki key group gives one key for each block of its secret key file,
    /// so the list can hold more keys than the client group names groups.
    ///
    /// A new commit is a commit that becomes the new value of a ref. A server
    /// commit is a new commit too. The server signs no other commit, a staged
    /// parent and a dependency included. The server signature on a new
    /// commit covers its field 2 and its parent checksum.
    pub signers: Vec<Arc<ServerSigner>>,
    /// The switch that accepts privileged content in a `bare` repository.
    ///
    /// Privileged content is a setuid or setgid mode bit, or the
    /// `security.capability` or `security.selinux` extended attribute.
    pub allow_privileged: bool,
    /// The keys that the server signs each regenerated summary with, in
    /// order. An spki key group gives one key for each block of its secret
    /// key file.
    pub summary_signers: Vec<Arc<ServerSigner>>,
    /// The switch that regenerates the summary of each auth item, as
    /// [`Repo::regenerate_summaries`](crate::Repo::regenerate_summaries)
    /// writes them, after a session that writes a ref.
    pub update_summary: bool,
    /// The name of the client group of the policy.
    ///
    /// [`ReceivePolicies::from_config`] sets the name of each group. A policy
    /// built in code can have `None`. A session copies the name into
    /// [`ReceiveReport::group`](super::ReceiveReport::group).
    pub group: Option<String>,
}

/// The signatures that a received commit must carry.
#[derive(Debug, Clone, Default)]
pub enum ReceiveVerify {
    /// No signature verification.
    #[default]
    Off,
    /// A valid signature on each axis of the trusted keys.
    ///
    /// # Trust groups
    ///
    /// A trust group, `[ex-ostrya trust "NAME"]`, uses the key names of a
    /// remote section:
    ///
    /// - `gpgkeypath` for the GPG axis
    /// - `verification-<engine>-key` and `verification-<engine>-file` for the
    ///   sign-api axis
    ///
    /// `gpg-verify` and `sign-verify` turn on the axes. In a trust group,
    /// `gpg-verify` has the default `false`.
    ///
    /// A trust group trusts these keys alone. It reads no system key store, no
    /// revoked set, no per-remote keyring, and no global trusted directory. A
    /// server verifies a commit against the keys that the group names, and
    /// against no other key.
    Keys(Arc<TrustedKeys>),
}

impl ReceivePolicy {
    /// Returns the effective rights of the ref `refspec`.
    ///
    /// For a plain ref `NAME`, the result is
    /// [`AccessRules::rights`] of `NAME`. A remote ref `REMOTE:NAME` has no
    /// right, because a push session does not write remote refs.
    pub fn rights(&self, refspec: &str) -> AccessModes {
        if refspec.contains(':') {
            return AccessModes::NONE;
        }
        self.rules.rights(refspec)
    }
}

/// The receive policy of each client group of a repository.
///
/// [`from_config`](ReceivePolicies::from_config) builds the value.
#[derive(Debug, Clone)]
pub struct ReceivePolicies {
    access: Arc<ClientAccess>,
    /// The policy of each group of `access`, in the same order.
    policies: Vec<Arc<ReceivePolicy>>,
}

impl ReceivePolicies {
    /// Reads the client groups of the configuration of `repo` and builds the
    /// receive policy of each group.
    ///
    /// [`ClientAccess::from_config`] reads the client groups and
    /// `[ex-ostrya server]`. A config with no client group has the two
    /// implicit groups, and each one gets a policy. Then the call reads each
    /// `[ex-ostrya trust "NAME"]` and each `[ex-ostrya key "NAME"]` group,
    /// and builds each one once, in file order, also a group that no client
    /// group names. So a key source that the policies cannot use fails the
    /// call.
    ///
    /// The policy of a group takes these values:
    ///
    /// - [`scope`](ReceivePolicy::scope) from `collection`
    /// - [`rules`](ReceivePolicy::rules) from `allow` and `deny`
    /// - [`verify`](ReceivePolicy::verify) from `verify`, with the keys of the
    ///   trust group
    /// - [`allow_unsigned`](ReceivePolicy::allow_unsigned) from
    ///   `allow-unsigned`, or its default
    /// - [`signers`](ReceivePolicy::signers) from `sign`
    /// - [`allow_privileged`](ReceivePolicy::allow_privileged) from
    ///   `allow-privileged`
    /// - [`summary_signers`](ReceivePolicy::summary_signers) from
    ///   `sign-summary` of `[ex-ostrya server]`
    /// - [`update_summary`](ReceivePolicy::update_summary) from
    ///   `[core] auto-update-summary` and its alias, as
    ///   [`auto_update_summary`](crate::RepoConfig::auto_update_summary) reads
    ///   them.
    ///
    /// # Trust groups and key groups
    ///
    /// A trust group takes `gpg-verify`, `gpgkeypath`, `sign-verify`,
    /// `verification-ENGINE-key`, and `verification-ENGINE-file`, in the value
    /// forms of a remote section.
    ///
    /// A key group takes `type`, which is `ed25519`, `spki`, or `gpg`. An
    /// `ed25519` or `spki` key group takes `secret-key-file`. A `gpg` key group
    /// takes `gpg-key`, and `gpg-homedir` as an option.
    ///
    /// The `secret-key-file` of an `ed25519` key group holds one base64 key on
    /// one line. The `secret-key-file` of an `spki` key group holds PEM
    /// `PRIVATE KEY` blocks, as `spki_secret_keys` of the `spki` module reads
    /// them. Each block gives one key.
    ///
    /// # Errors
    ///
    /// - Each error of [`ClientAccess::from_config`].
    /// - [`Error::InvalidFormat`](crate::Error::InvalidFormat) if:
    ///   - a trust group or a key group holds a key that it does not take
    ///   - a key has no effect
    ///   - a trust group turns on no signature verification
    ///   - a trust group names an engine other than `ed25519` or `spki`, or
    ///     sets `gpg-verify=true` and its `gpgkeypath` names no keyring or
    ///     holds an empty entry
    ///   - a key group has no `type`, an unknown `type`, the type `dummy`, or
    ///     no value for a required key.
    /// - [`Error::Unsupported`](crate::Error::Unsupported) if a group names a
    ///   signing or verification engine that this build does not have.
    /// - [`Error::Signature`](crate::Error::Signature) if:
    ///   - a key source cannot be read
    ///   - a secret key file does not exist
    ///   - a secret key file holds no key, or holds more than one key (an
    ///     `ed25519` key group)
    ///   - `spki_secret_keys` refuses the secret key file of an `spki` key
    ///     group
    ///   - an engine refuses a key
    ///   - a GPG selector names no secret key or more than one, or `gpg` fails
    ///   - an engine that `sign-verify` names has no trusted key, or no engine
    ///     has a trusted key
    ///   - the keyrings that a trust group names hold no certificate.
    /// - [`Error::Core`](crate::Error::Core) if a boolean value is malformed,
    ///   a string value holds a malformed escape sequence, or a key is not
    ///   valid base64.
    /// - [`Error::Io`](crate::Error::Io) if a directory of keys cannot be
    ///   listed, or if the read of the output of `gpg` or the wait for `gpg`
    ///   fails.
    pub async fn from_config(repo: &Repo) -> Result<ReceivePolicies> {
        let (access, policies) = reader::read(repo).await?;
        Ok(ReceivePolicies {
            access: Arc::new(access),
            policies,
        })
    }

    /// Returns the client groups and the server settings that the policies
    /// come from. A clone of the `Arc` shares them.
    pub fn access(&self) -> &Arc<ClientAccess> {
        &self.access
    }

    /// Returns the policy of the client group `group`, or `None` if no group
    /// has this name.
    ///
    /// `group` is the quoted part of the group name, as
    /// [`ClientGroup::name`](crate::access::ClientGroup::name) returns it.
    pub fn get(&self, group: &str) -> Option<&Arc<ReceivePolicy>> {
        self.access
            .groups()
            .iter()
            .position(|held| held.name() == group)
            .map(|i| &self.policies[i])
    }

    /// Returns the client group that carries `item` in `namespace`, with its
    /// policy, or `None`.
    ///
    /// [`ClientAccess::select`] states the selection.
    pub fn select(
        &self,
        item: &AuthItem,
        namespace: &Namespace,
    ) -> Option<(&ClientGroup, &Arc<ReceivePolicy>)> {
        self.access
            .select_index(item, namespace)
            .map(|i| (&self.access.groups()[i], &self.policies[i]))
    }
}

/// The rule that the commit of a session applies to one ref update.
pub(super) struct UpdateRule<'a> {
    /// `true` if the update can create its ref and cannot write a commit to
    /// a ref that exists.
    pub(super) create_only: bool,
    /// `true` if the update can delete a ref that exists.
    pub(super) allow_delete: bool,
    /// `true` if the update can be a non-fast-forward update, when the client
    /// asks for one.
    pub(super) allow_non_fast_forward: bool,
    /// The signatures that the new commit must carry.
    pub(super) verify: &'a ReceiveVerify,
    /// `true` if a new commit with no signature passes the verification of
    /// `verify`.
    pub(super) allow_unsigned: bool,
    /// The keys that the server signs the new commit with.
    pub(super) signers: &'a [Arc<ServerSigner>],
}

/// The rule that the commit of a session applies to a server commit.
pub(super) struct ServerCommitRule<'a> {
    /// `true` if an `orphan` server commit can replace a branch that exists.
    pub(super) allow_orphan_over_branch: bool,
    /// The keys that the server signs the commit with.
    pub(super) signers: &'a [Arc<ServerSigner>],
}

/// The rules that a session applies: the policy of a client group, or the
/// policy of a one-way stream.
pub(super) trait SessionPolicy: Send + Sync {
    /// Returns `true` if the session accepts privileged content in a `bare`
    /// repository.
    fn privileged_allowed(&self) -> bool;

    /// Checks the namespace and the refs of `Hello` before the session
    /// opens, with no I/O.
    fn check_hello(
        &self,
        namespace: &Namespace,
        refs: &[String],
    ) -> std::result::Result<(), Failure>;

    /// Returns the rule of `update`, or the `ref-denied` refusal of the
    /// update.
    fn rule(&self, update: &RefUpdate) -> std::result::Result<UpdateRule<'_>, Failure>;

    /// Returns the rule of a server commit on `branch` that creates `tags`,
    /// or the `ref-denied` refusal of the server commit.
    fn server_commit_rule(
        &self,
        branch: &str,
        tags: &[String],
    ) -> std::result::Result<ServerCommitRule<'_>, Failure>;

    /// Returns `true` if the session regenerates the summary after it writes
    /// a ref.
    fn regenerates_summary(&self) -> bool;

    /// Returns the keys that sign each regenerated summary.
    fn summary_keys(&self) -> &[Arc<ServerSigner>];

    /// Returns the name of the client group of the session, for the report.
    fn group(&self) -> Option<&str>;
}

fn ref_denied(message: String) -> Failure {
    Failure::Wire(remote::Error::RefDenied(message))
}

/// Returns `namespace` as the words of a message: `the local refs` or `the
/// collection 'ID'`.
pub(super) fn namespace_text(namespace: &Namespace) -> String {
    match namespace {
        Namespace::Local => "the local refs".into(),
        Namespace::Collection(id) => format!("the collection '{id}'"),
    }
}

impl SessionPolicy for ReceivePolicy {
    fn privileged_allowed(&self) -> bool {
        self.allow_privileged
    }

    /// Refuses a namespace that the scope does not cover, a policy that
    /// opens no push session, and a ref without `r`.
    fn check_hello(
        &self,
        namespace: &Namespace,
        refs: &[String],
    ) -> std::result::Result<(), Failure> {
        if !self.scope.covers(namespace) {
            return Err(ref_denied(format!(
                "the policy of the session does not cover {}",
                namespace_text(namespace)
            )));
        }
        if !self.rules.opens_push_session() {
            return Err(ref_denied(
                "the policy of the session opens no push session: no allow item has the \
                 mode w, c, t, or d"
                    .into(),
            ));
        }
        for name in refs {
            if name.contains(':') {
                return Err(ref_denied(format!(
                    "ref '{name}' is a remote ref, which a push session does not read or write"
                )));
            }
            if !self.rights(name).contains(AccessModes::READ) {
                return Err(ref_denied(format!("the policy gives no r on ref '{name}'")));
            }
        }
        Ok(())
    }

    /// Refuses a remote ref, and a write of a commit without `w` or `t`. The
    /// rule of a delete comes from `d`, under the update lock.
    fn rule(&self, update: &RefUpdate) -> std::result::Result<UpdateRule<'_>, Failure> {
        let name = &update.name;
        if name.contains(':') {
            return Err(ref_denied(format!(
                "ref '{name}' is a remote ref, which a push session does not write"
            )));
        }
        let rights = self.rights(name);
        let write = rights.contains(AccessModes::WRITE);
        let tag = rights.contains(AccessModes::TAG);
        if update.new.is_some() && !write && !tag {
            return Err(ref_denied(format!(
                "the policy gives no w or t on ref '{name}'"
            )));
        }
        let delete = rights.contains(AccessModes::DELETE);
        Ok(UpdateRule {
            create_only: tag && !write,
            allow_delete: delete,
            allow_non_fast_forward: write && delete,
            verify: &self.verify,
            allow_unsigned: self.allow_unsigned,
            signers: &self.signers,
        })
    }

    /// Refuses a remote ref, a branch without `c`, and a tag without `t` or
    /// `w`. The rule of `orphan` on a branch that exists comes from `d`,
    /// under the update lock.
    fn server_commit_rule(
        &self,
        branch: &str,
        tags: &[String],
    ) -> std::result::Result<ServerCommitRule<'_>, Failure> {
        for name in std::iter::once(branch).chain(tags.iter().map(String::as_str)) {
            if name.contains(':') {
                return Err(ref_denied(format!(
                    "ref '{name}' is a remote ref, which a push session does not write"
                )));
            }
        }
        let rights = self.rights(branch);
        if !rights.contains(AccessModes::COMMIT) {
            return Err(ref_denied(format!(
                "the policy gives no c on ref '{branch}'"
            )));
        }
        for tag in tags {
            let tag_rights = self.rights(tag);
            if !tag_rights.contains(AccessModes::TAG) && !tag_rights.contains(AccessModes::WRITE) {
                return Err(ref_denied(format!(
                    "the policy gives no t or w on ref '{tag}'"
                )));
            }
        }
        Ok(ServerCommitRule {
            allow_orphan_over_branch: rights.contains(AccessModes::DELETE),
            signers: &self.signers,
        })
    }

    fn regenerates_summary(&self) -> bool {
        self.update_summary
    }

    fn summary_keys(&self) -> &[Arc<ServerSigner>] {
        &self.summary_signers
    }

    fn group(&self) -> Option<&str> {
        self.group.as_deref()
    }
}

impl SessionPolicy for StreamPolicy {
    fn privileged_allowed(&self) -> bool {
        self.allow_privileged
    }

    /// A one-way stream has no namespace, and checks its refs at `Commit`
    /// alone.
    fn check_hello(
        &self,
        _namespace: &Namespace,
        _refs: &[String],
    ) -> std::result::Result<(), Failure> {
        Ok(())
    }

    /// Refuses an update that no rule covers and an update whose rule
    /// refuses it. The rule takes no server key.
    fn rule(&self, update: &RefUpdate) -> std::result::Result<UpdateRule<'_>, Failure> {
        let name = &update.name;
        match self.rule_for(name) {
            Some(rule) if rule.accept => Ok(UpdateRule {
                create_only: false,
                allow_delete: rule.allow_delete,
                allow_non_fast_forward: rule.allow_non_fast_forward,
                verify: &rule.verify,
                allow_unsigned: false,
                signers: &[],
            }),
            Some(_) => Err(ref_denied(format!(
                "the policy refuses updates of ref '{name}'"
            ))),
            None => Err(ref_denied(format!(
                "no rule of the policy covers the remote ref '{name}'"
            ))),
        }
    }

    /// A one-way stream carries no server commit.
    fn server_commit_rule(
        &self,
        _branch: &str,
        _tags: &[String],
    ) -> std::result::Result<ServerCommitRule<'_>, Failure> {
        Err(Failure::Wire(remote::Error::Protocol(
            "a one-way stream carries no server commit".into(),
        )))
    }

    /// A one-way stream does not regenerate the summary.
    fn regenerates_summary(&self) -> bool {
        false
    }

    /// A one-way stream does not regenerate the summary.
    fn summary_keys(&self) -> &[Arc<ServerSigner>] {
        &[]
    }

    /// A one-way stream has no client group.
    fn group(&self) -> Option<&str> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::AllowItem;
    use crate::remote::Expected;

    fn policy(allow: &[&str]) -> ReceivePolicy {
        ReceivePolicy {
            rules: AccessRules {
                allow: allow.iter().map(|t| AllowItem::parse(t).unwrap()).collect(),
                deny: Vec::new(),
            },
            ..ReceivePolicy::default()
        }
    }

    fn update(name: &str, new: bool) -> RefUpdate {
        RefUpdate {
            name: name.into(),
            expected: Expected::Any,
            new: new.then(|| ostrya_core::Checksum::from_bytes([1; 32])),
        }
    }

    fn accepted<T>(result: std::result::Result<T, Failure>) -> T {
        match result {
            Ok(value) => value,
            Err(_) => panic!("refused"),
        }
    }

    fn denied<T>(result: std::result::Result<T, Failure>) -> String {
        match result {
            Err(Failure::Wire(remote::Error::RefDenied(message))) => message,
            Err(_) => panic!("another failure"),
            Ok(_) => panic!("accepted"),
        }
    }

    /// A remote ref has no right, also under an item that matches each ref.
    /// The rules alone read `origin:main` as one part, which `**` matches.
    #[test]
    fn a_remote_ref_has_no_right() {
        let policy = policy(&["rwctd:**"]);
        assert_eq!(policy.rights("main").to_string(), "rwctd");
        assert_eq!(policy.rules.rights("origin:main").to_string(), "rwctd");
        assert_eq!(policy.rights("origin:main"), AccessModes::NONE);
        let message = denied(policy.check_hello(&Namespace::Local, &["origin:main".into()]));
        assert!(message.contains("remote ref"), "{message}");
        let message = denied(policy.rule(&update("origin:main", true)));
        assert!(message.contains("remote ref"), "{message}");
    }

    /// `Hello` needs a push mode in an allow item and `r` on each ref.
    #[test]
    fn hello_needs_a_push_mode_and_read() {
        let names = |names: &[&str]| -> Vec<String> { names.iter().map(|&n| n.into()).collect() };
        let local = &Namespace::Local;
        denied(ReceivePolicy::default().check_hello(local, &[]));
        denied(policy(&["r:**"]).check_hello(local, &names(&["a"])));
        denied(policy(&["d:a"]).check_hello(local, &names(&["a"])));
        accepted(policy(&["rd:a"]).check_hello(local, &names(&["a"])));
        accepted(policy(&["r:**", "w:a"]).check_hello(local, &names(&["a", "b"])));
        let message = denied(policy(&["w:a"]).check_hello(local, &names(&["a", "b"])));
        assert!(message.contains("'b'"), "{message}");
    }

    /// `Hello` needs a scope that covers its namespace. The scope check comes
    /// before the other checks.
    #[test]
    fn hello_needs_a_scope_that_covers_the_namespace() {
        let os = Namespace::Collection("org.example.Os".into());
        let other = Namespace::Collection("org.example.Other".into());
        let refs = ["main".to_owned()];
        let local = policy(&["w:**"]);
        let message = denied(local.check_hello(&os, &refs));
        assert!(
            message.contains("the collection 'org.example.Os'"),
            "{message}"
        );
        let exact = ReceivePolicy {
            scope: CollectionScope::Ids(vec!["org.example.Os".into()]),
            ..policy(&["w:**"])
        };
        accepted(exact.check_hello(&os, &refs));
        denied(exact.check_hello(&other, &refs));
        let message = denied(exact.check_hello(&Namespace::Local, &refs));
        assert!(message.contains("the local refs"), "{message}");
        let all = ReceivePolicy {
            scope: CollectionScope::AllOther,
            ..ReceivePolicy::default()
        };
        let message = denied(all.check_hello(&Namespace::Local, &[]));
        assert!(message.contains("does not cover"), "{message}");
    }

    /// A write needs `w` or `t`, and the modes give the rule of the update.
    #[test]
    fn the_modes_give_the_rule_of_an_update() {
        denied(policy(&["rd:a"]).rule(&update("a", true)));
        let delete = policy(&["rd:a"]);
        let rule = accepted(delete.rule(&update("a", false)));
        assert!(rule.allow_delete && !rule.allow_non_fast_forward);
        let tag = policy(&["t:a"]);
        let rule = accepted(tag.rule(&update("a", true)));
        assert!(rule.create_only && !rule.allow_delete);
        let write_tag = policy(&["wt:a"]);
        let rule = accepted(write_tag.rule(&update("a", true)));
        assert!(!rule.create_only && !rule.allow_non_fast_forward);
        let forced = policy(&["w:a", "d:a"]);
        let rule = accepted(forced.rule(&update("a", true)));
        assert!(rule.allow_non_fast_forward && rule.allow_delete);
    }

    /// A server commit needs `c` on its branch and `t` or `w` on each tag.
    /// `d` on the branch allows `orphan` over a branch that exists. A deny
    /// item takes each right, and a bound name needs none.
    #[test]
    fn the_modes_give_the_rule_of_a_server_commit() {
        let tags = |names: &[&str]| -> Vec<String> { names.iter().map(|&n| n.into()).collect() };
        let commit = policy(&["c:main"]);
        let rule = accepted(commit.server_commit_rule("main", &[]));
        assert!(!rule.allow_orphan_over_branch);
        let orphan = policy(&["cd:main"]);
        let rule = accepted(orphan.server_commit_rule("main", &[]));
        assert!(rule.allow_orphan_over_branch);
        let message = denied(policy(&["wtd:main"]).server_commit_rule("main", &[]));
        assert!(message.contains("no c on ref 'main'"), "{message}");
        let message = denied(policy(&["r:**"]).server_commit_rule("main", &[]));
        assert!(message.contains("no c"), "{message}");

        let both = policy(&["c:main", "t:v1", "w:v2"]);
        accepted(both.server_commit_rule("main", &tags(&["v1", "v2"])));
        let message = denied(both.server_commit_rule("main", &tags(&["v1", "v3"])));
        assert!(message.contains("no t or w on ref 'v3'"), "{message}");
        let message =
            denied(policy(&["c:main", "cd:v1"]).server_commit_rule("main", &tags(&["v1"])));
        assert!(message.contains("'v1'"), "{message}");

        let denying = ReceivePolicy {
            rules: AccessRules {
                allow: vec![AllowItem::parse("ctwd:**").unwrap()],
                deny: vec![ostrya_core::RefPattern::parse("v1").unwrap()],
            },
            ..ReceivePolicy::default()
        };
        accepted(denying.server_commit_rule("main", &tags(&["v2"])));
        let message = denied(denying.server_commit_rule("main", &tags(&["v1"])));
        assert!(message.contains("'v1'"), "{message}");
        let message = denied(denying.server_commit_rule("v1", &[]));
        assert!(message.contains("no c"), "{message}");

        let message = denied(policy(&["c:**"]).server_commit_rule("origin:main", &[]));
        assert!(message.contains("remote ref"), "{message}");
    }
}
