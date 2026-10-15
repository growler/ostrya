//! The client groups and the server settings of a repository config.
//!
//! A client group, `[ex-ostrya client "NAME"]`, states how a client
//! authenticates, which refs it can read and change in one namespace, how
//! its commits are verified, and which keys sign them. `[ex-ostrya server]`
//! holds the settings of a server. [`ClientAccess::from_config`] reads both
//! kinds of group.
//!
//! - [`ClientAccess`] holds the groups and the server settings, and selects
//!   the group of an auth item in a namespace.
//! - [`ClientGroup`] is one client group.
//! - [`AuthItem`] is one item of the `auth` list, and [`IpNet`] is the
//!   network of a `net:` item or of a `trusted-proxy` entry.
//! - [`AccessRules`] holds the allow items and the deny items of a group,
//!   and gives the effective rights of a ref as [`AccessModes`].
//! - [`ServerSettings`] holds the keys of `[ex-ostrya server]`.
//!
//! # Client group keys
//!
//! - `auth` (list, necessary) -- the [`AuthItem`]s of the group. An item
//!   that occurs two times in one group counts one time.
//! - `collection` (list, or `*`) -- the namespace of the group, as a
//!   [`CollectionScope`]. Without the key, the group applies to the local
//!   refs. `*` is valid only as the whole value. Each id passes
//!   [`is_collection_id`](crate::is_collection_id) and differs from
//!   `[core] collection-id`.
//! - `allow` (list) -- the [`AllowItem`]s. Without the key, the group has no
//!   right on a ref.
//! - `deny` (list) -- the deny items, each a [`RefPattern`](crate::RefPattern).
//! - `tls-accept-claim` (boolean, default false) -- read the claims of the
//!   client certificate. A group with no `tls:*`, `tls:NAME`, or
//!   `tls-sha256:HEX` item cannot hold this key, with any value.
//! - `verify` (`trust:NAME`) -- the trust group that verifies each
//!   client-built commit of the group.
//! - `allow-unsigned` (boolean) -- accept a client-built commit with no
//!   signature. The default is true without `verify`, and false with
//!   `verify`. `allow-unsigned=false` needs `verify`.
//! - `sign` (list) -- the key groups that sign each new commit of a ref
//!   update of the group. A name that occurs two times counts one time. An
//!   empty value is refused.
//! - `allow-privileged` (boolean, default false) -- accept the privileged
//!   file modes and extended attributes in a `bare` repository.
//!
//! [`ServerSettings`] lists the keys of `[ex-ostrya server]`.
//!
//! # Checks
//!
//! [`ClientAccess::from_config`] refuses a group name that starts with
//! `ex-ostrya ` and has no shape of a known group, and a key that a client
//! group or the server group does not take. It also refuses the config in
//! these cases:
//!
//! - Two groups carry the same item, and their namespaces overlap: both
//!   apply to the local refs, both name one id, or both have `*`.
//! - A collection id fails the collection-id rule, or is the own collection
//!   id of the repository.
//! - A network has host bits set.
//! - `verify`, `sign`, or `sign-summary` names a trust group or a key group
//!   that does not exist.
//!
//! [`ClientAccess::check_server`] checks the server settings after the
//! values of the command line replace the keys.
//!
//! # Implicit groups
//!
//! A config with no client group has two implicit groups:
//!
//! ```text
//! [ex-ostrya client "anonymous"]
//! auth=anonymous
//! allow=r:**
//!
//! [ex-ostrya client "anonymous-collections"]
//! auth=anonymous
//! collection=*
//! allow=r:**
//! ```
//!
//! # Examples
//!
//! ```
//! use ostrya::config::RepoConfig;
//! use ostrya::access::{AccessModes, AuthItem, ClientAccess, Namespace};
//!
//! let config = RepoConfig::parse(
//!     "[core]\nrepo_version=1\nmode=archive-z2\n\
//!      [ex-ostrya client \"developer\"]\nauth=ssh:user\nallow=cd:devel/user/**\n",
//! )?;
//! let access = ClientAccess::from_config(&config, "/srv/repo".as_ref())?;
//! let item = AuthItem::parse("ssh:user")?;
//! let group = access.select(&item, &Namespace::Local).unwrap();
//! assert_eq!(group.name(), "developer");
//! let rights = group.rules().rights("devel/user/main");
//! assert!(rights.contains(AccessModes::COMMIT));
//! assert!(rights.contains(AccessModes::READ));
//! # Ok::<(), ostrya::Error>(())
//! ```

mod item;
mod reader;
mod rights;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

pub use item::{AuthItem, IpNet};
pub use rights::{AccessModes, AccessRules, AllowItem};

use crate::config::RepoConfig;
use crate::error::{Error, Result};

/// The namespace of a request: the local refs or the refs of one
/// collection.
///
/// [`ClientAccess::namespace`] maps a collection id to a namespace.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Namespace {
    /// The local refs, under `refs/heads/`.
    Local,
    /// The refs of one collection, under `refs/mirrors/ID/`.
    Collection(String),
}

/// The namespace of a client group, from its `collection` key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectionScope {
    /// No `collection` key: the local refs.
    Local,
    /// A list of collection ids, in the order of the config, each one time.
    Ids(Vec<String>),
    /// `collection=*`: each collection other than the own collection of the
    /// repository.
    AllOther,
}

impl CollectionScope {
    /// Returns `true` if one namespace is in both scopes.
    fn overlaps(&self, other: &CollectionScope) -> bool {
        match (self, other) {
            (CollectionScope::Local, CollectionScope::Local)
            | (CollectionScope::AllOther, CollectionScope::AllOther) => true,
            (CollectionScope::Ids(a), CollectionScope::Ids(b)) => a.iter().any(|id| b.contains(id)),
            _ => false,
        }
    }
}

/// One client group, `[ex-ostrya client "NAME"]`.
///
/// [`ClientAccess::from_config`] builds each group. The module doc lists the
/// keys of a group.
#[derive(Debug, Clone)]
pub struct ClientGroup {
    name: String,
    auth: Vec<AuthItem>,
    scope: CollectionScope,
    rules: AccessRules,
    tls_accept_claim: bool,
    verify_trust: Option<String>,
    allow_unsigned: bool,
    sign: Vec<String>,
    allow_privileged: bool,
    implicit: bool,
}

impl ClientGroup {
    /// Returns the name of the group, the quoted part of its group name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the auth items of the group, in the order of the config, each
    /// one time.
    pub fn auth(&self) -> &[AuthItem] {
        &self.auth
    }

    /// Returns the namespace of the group.
    pub fn scope(&self) -> &CollectionScope {
        &self.scope
    }

    /// Returns the allow items and the deny items of the group.
    pub fn rules(&self) -> &AccessRules {
        &self.rules
    }

    /// Returns the value of `tls-accept-claim`.
    pub fn tls_accept_claim(&self) -> bool {
        self.tls_accept_claim
    }

    /// Returns the name of the trust group of `verify`, or `None` with no
    /// `verify` key.
    pub fn verify_trust(&self) -> Option<&str> {
        self.verify_trust.as_deref()
    }

    /// Returns the value of `allow-unsigned`, or its default.
    ///
    /// The default is `true` without `verify`, and `false` with `verify`.
    pub fn allow_unsigned(&self) -> bool {
        self.allow_unsigned
    }

    /// Returns the names of the key groups of `sign`, each one time.
    pub fn sign(&self) -> &[String] {
        &self.sign
    }

    /// Returns the value of `allow-privileged`.
    pub fn allow_privileged(&self) -> bool {
        self.allow_privileged
    }

    /// Returns `true` for one of the two groups that a config with no client
    /// group has.
    pub fn is_implicit(&self) -> bool {
        self.implicit
    }

    /// Returns `true` if the scope of the group holds `namespace`.
    ///
    /// The method reads the scope alone. A `*` scope holds each
    /// [`Collection`](Namespace::Collection) whose id passes the
    /// collection-id rule. [`ClientAccess::select`] also refuses the own
    /// collection id, which [`ClientAccess::namespace`] maps to
    /// [`Local`](Namespace::Local).
    pub fn covers(&self, namespace: &Namespace) -> bool {
        match (&self.scope, namespace) {
            (CollectionScope::Local, Namespace::Local) => true,
            (CollectionScope::Ids(ids), Namespace::Collection(id)) => ids.contains(id),
            (CollectionScope::AllOther, Namespace::Collection(id)) => {
                ostrya_core::is_collection_id(id)
            }
            _ => false,
        }
    }

    /// Returns the group name of the group, for the error messages.
    fn header(&self) -> String {
        format!("[ex-ostrya client \"{}\"]", self.name)
    }
}

/// The keys of `[ex-ostrya server]`.
///
/// Each field is `None` when the key is absent. The server takes its default
/// for an absent key. A caller can build the struct with
/// `..Default::default()`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerSettings {
    /// `listen`: the addresses to listen on, each `ADDR:PORT`. A host name is
    /// refused, and so is an empty value.
    pub listen: Option<Vec<SocketAddr>>,
    /// `tls-cert`: the PEM certificate chain.
    pub tls_cert: Option<PathBuf>,
    /// `tls-key`: the PEM private key of `tls-cert`.
    pub tls_key: Option<PathBuf>,
    /// `tls-client-ca`: the PEM CA certificates that verify a client
    /// certificate.
    pub tls_client_ca: Option<PathBuf>,
    /// `trusted-proxy`: the networks of the peers whose forwarding data the
    /// server reads. An empty value is refused.
    pub trusted_proxy: Option<Vec<IpNet>>,
    /// `trusted-proxy-client-cert`: the name of the request header that
    /// carries the client certificate from a trusted proxy. The name is an
    /// HTTP token.
    pub trusted_proxy_client_cert: Option<String>,
    /// `proxy-protocol`: each connection starts with a PROXY protocol header.
    pub proxy_protocol: Option<bool>,
    /// `allow-cleartext-credentials`: take a credential on a connection with
    /// no TLS.
    pub allow_cleartext_credentials: Option<bool>,
    /// `session-timeout`: the idle time of a push session, in seconds, 1 or
    /// more.
    pub session_timeout: Option<u64>,
    /// `max-sessions`: the number of push sessions at the same time, 1 or
    /// more.
    pub max_sessions: Option<u64>,
    /// `parallel-uploads`: the number of object streams of a push session,
    /// 1 to 31.
    pub parallel_uploads: Option<u32>,
    /// `body-timeout`: the time that a response waits for the client, in
    /// seconds, 1 or more.
    pub body_timeout: Option<u64>,
    /// `sign-summary`: the key groups that sign a summary that a push writes
    /// again, each one time. An empty value is refused.
    pub sign_summary: Option<Vec<String>>,
}

/// The client groups and the server settings of a repository config.
///
/// [`from_config`](ClientAccess::from_config) builds the value. The module
/// doc lists the keys and the checks.
#[derive(Debug, Clone)]
pub struct ClientAccess {
    collection_id: Option<String>,
    server: ServerSettings,
    groups: Vec<ClientGroup>,
    /// The indexes in `groups` of the groups that carry each item, in the
    /// order of the config.
    by_item: HashMap<AuthItem, Vec<usize>>,
}

impl ClientAccess {
    /// Reads `[ex-ostrya server]` and each `[ex-ostrya client "NAME"]` of
    /// `config`.
    ///
    /// A relative path in `tls-cert`, `tls-key`, or `tls-client-ca` is joined
    /// onto `repo_dir`. The call reads no file. It records the names of the
    /// `[ex-ostrya trust "NAME"]` and `[ex-ostrya key "NAME"]` groups, for
    /// the checks of `verify`, `sign`, and `sign-summary`, and reads no key
    /// of these groups. It skips `[ex-ostrya receive]` and each
    /// `[ex-ostrya receive "PATTERN"]`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if a group, a key, or a value is malformed,
    ///   or if a check of the module doc fails. The message names the group
    ///   and the key.
    /// - [`Error::Core`] if a boolean or an integer value does not parse, or
    ///   if a value holds a malformed escape sequence.
    pub fn from_config(config: &RepoConfig, repo_dir: &Path) -> Result<ClientAccess> {
        reader::read(config, repo_dir)
    }

    /// Returns the keys of `[ex-ostrya server]`.
    pub fn server(&self) -> &ServerSettings {
        &self.server
    }

    /// Returns the client groups, in the order of the config, or the two
    /// implicit groups.
    pub fn groups(&self) -> &[ClientGroup] {
        &self.groups
    }

    /// Returns each group that carries `item`, in the order of the config.
    pub fn groups_of<'a>(&'a self, item: &'a AuthItem) -> impl Iterator<Item = &'a ClientGroup> {
        self.carriers(item).iter().map(|&i| &self.groups[i])
    }

    /// Returns the indexes in `groups` of the groups that carry `item`, in
    /// the order of the config.
    fn carriers(&self, item: &AuthItem) -> &[usize] {
        self.by_item.get(item).map_or(&[], Vec::as_slice)
    }

    /// Returns the namespace of the collection id `collection`.
    ///
    /// `None` and the own collection id of the repository give
    /// [`Local`](Namespace::Local). Each other id gives
    /// [`Collection`](Namespace::Collection), also an id that fails the
    /// collection-id rule.
    pub fn namespace(&self, collection: Option<&str>) -> Namespace {
        match collection {
            Some(id) if Some(id) != self.collection_id.as_deref() => {
                Namespace::Collection(id.to_owned())
            }
            _ => Namespace::Local,
        }
    }

    /// Returns the group that carries `item` in `namespace`, or `None`.
    ///
    /// For [`Local`](Namespace::Local), the result is the group of the local
    /// refs that carries `item`. For a [`Collection`](Namespace::Collection),
    /// the result is the first of these that exists:
    ///
    /// 1. the group that carries `item` and names the id in `collection`;
    /// 2. the group that carries `item` and has `collection=*`.
    ///
    /// An id that fails the collection-id rule and the own collection id
    /// give `None`. The selection compares `item` alone, so a `tls:NAME` item
    /// never selects a group of `tls:*`.
    pub fn select(&self, item: &AuthItem, namespace: &Namespace) -> Option<&ClientGroup> {
        let mut carriers = self.carriers(item).iter().map(|&i| &self.groups[i]);
        match namespace {
            Namespace::Local => carriers.find(|group| group.scope == CollectionScope::Local),
            Namespace::Collection(id) => {
                if !ostrya_core::is_collection_id(id)
                    || Some(id.as_str()) == self.collection_id.as_deref()
                {
                    return None;
                }
                carriers
                    .clone()
                    .find(|group| matches!(&group.scope, CollectionScope::Ids(ids) if ids.contains(id)))
                    .or_else(|| carriers.find(|group| group.scope == CollectionScope::AllOther))
            }
        }
    }

    /// Checks the server settings that a server runs with.
    ///
    /// `merged` holds the keys of `[ex-ostrya server]`, with the values of
    /// the command line in place of the keys that they replace. The call
    /// refuses these cases:
    ///
    /// - A group carries a `tls:*`, `tls:NAME`, or `tls-sha256:HEX` item,
    ///   and `tls_client_ca` is `None`.
    /// - `trusted_proxy_client_cert` is set, and `tls_client_ca` is `None`.
    /// - `trusted_proxy_client_cert` is set, and `trusted_proxy` is `None`.
    /// - `tls_cert` is set and `tls_key` is `None`, or the reverse.
    /// - `tls_client_ca` is set, and `tls_cert` and
    ///   `trusted_proxy_client_cert` are `None`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFormat`] for each case above.
    pub fn check_server(&self, merged: &ServerSettings) -> Result<()> {
        if merged.tls_client_ca.is_none() {
            for group in &self.groups {
                if let Some(item) = group.auth.iter().find(|item| item.is_tls()) {
                    return Err(Error::InvalidFormat(format!(
                        "{} carries the item {item}, and the server has no tls-client-ca",
                        group.header()
                    )));
                }
            }
            if merged.trusted_proxy_client_cert.is_some() {
                return Err(Error::InvalidFormat(
                    "trusted-proxy-client-cert is set, and the server has no tls-client-ca"
                        .to_owned(),
                ));
            }
        }
        if merged.trusted_proxy_client_cert.is_some() && merged.trusted_proxy.is_none() {
            return Err(Error::InvalidFormat(
                "trusted-proxy-client-cert is set, and the server has no trusted-proxy".to_owned(),
            ));
        }
        match (&merged.tls_cert, &merged.tls_key) {
            (Some(_), None) => {
                return Err(Error::InvalidFormat(
                    "tls-cert is set, and tls-key is not".to_owned(),
                ));
            }
            (None, Some(_)) => {
                return Err(Error::InvalidFormat(
                    "tls-key is set, and tls-cert is not".to_owned(),
                ));
            }
            _ => {}
        }
        if merged.tls_client_ca.is_some()
            && merged.tls_cert.is_none()
            && merged.trusted_proxy_client_cert.is_none()
        {
            return Err(Error::InvalidFormat(
                "tls-client-ca is set, and tls-cert and trusted-proxy-client-cert are not"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// The access types move freely across tasks and threads, so one value can
/// serve each connection of a server.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ClientAccess>();
    assert_send_sync::<ClientGroup>();
    assert_send_sync::<ServerSettings>();
    assert_send_sync::<Namespace>();
    assert_send_sync::<CollectionScope>();
    assert_send_sync::<AuthItem>();
    assert_send_sync::<IpNet>();
    assert_send_sync::<AccessModes>();
    assert_send_sync::<AllowItem>();
    assert_send_sync::<AccessRules>();
};

#[cfg(test)]
mod tests {
    use super::*;

    /// The `[core]` group of each test config.
    const CORE: &str = "[core]\nrepo_version=1\nmode=archive-z2\n";

    fn access(text: &str) -> ClientAccess {
        try_access(text).unwrap()
    }

    fn try_access(text: &str) -> Result<ClientAccess> {
        let config = RepoConfig::parse(&format!("{CORE}{text}"))?;
        ClientAccess::from_config(&config, Path::new("/srv/repo"))
    }

    fn item(text: &str) -> AuthItem {
        AuthItem::parse(text).unwrap()
    }

    fn collection(id: &str) -> Namespace {
        Namespace::Collection(id.to_owned())
    }

    fn selected<'a>(access: &'a ClientAccess, item_text: &str, ns: &Namespace) -> Option<&'a str> {
        access.select(&item(item_text), ns).map(ClientGroup::name)
    }

    /// The example config of the client groups parses, and each request
    /// selects the group that the example states.
    #[test]
    fn the_example_config_selects_its_groups() {
        let access = access(
            r#"
[ex-ostrya server]
listen=0.0.0.0:8443
tls-cert=/etc/ostrya/server.pem
tls-key=/etc/ostrya/server.key
tls-client-ca=/etc/ostrya/clients-ca.pem
trusted-proxy=10.0.0.0/24

[ex-ostrya client "public"]
auth=anonymous
allow=r:**

[ex-ostrya client "public-collections"]
auth=anonymous
collection=*
allow=r:**

[ex-ostrya client "developer"]
auth=ssh:user
allow=cd:devel/user/**

[ex-ostrya client "developer-release"]
auth=ssh:user
collection=com.company.client
allow=c:role/client/main/head;t:role/client/release/**
sign=release-key

[ex-ostrya client "mirror"]
auth=tls:mirror.example.com
collection=com.company.os
allow=w:os/stable;w:os/beta;t:os/release/**
verify=trust:release

[ex-ostrya client "farm"]
auth=net:10.0.1.0/24;net:2001:db8::/56
allow=r:devel/**

[ex-ostrya client "ci-cert"]
auth=tls:*
tls-accept-claim=true
allow=r:release/**

[ex-ostrya trust "release"]
sign-verify=ed25519
verification-ed25519-file=/etc/ostrya/release.ed25519

[ex-ostrya key "release-key"]
type=ed25519
secret-key-file=/etc/ostrya/release.secret
"#,
        );
        access.check_server(access.server()).unwrap();
        assert_eq!(access.groups().len(), 7);
        assert!(access.groups().iter().all(|g| !g.is_implicit()));

        let os = collection("com.company.os");
        let client = collection("com.company.client");
        let other = collection("org.example.other");
        let local = Namespace::Local;
        assert_eq!(selected(&access, "anonymous", &local), Some("public"));
        assert_eq!(
            selected(&access, "anonymous", &os),
            Some("public-collections")
        );
        assert_eq!(selected(&access, "ssh:user", &local), Some("developer"));
        assert_eq!(
            selected(&access, "ssh:user", &client),
            Some("developer-release")
        );
        assert_eq!(selected(&access, "ssh:user", &other), None);
        assert_eq!(
            selected(&access, "tls:mirror.example.com", &os),
            Some("mirror")
        );
        assert_eq!(selected(&access, "tls:mirror.example.com", &local), None);
        assert_eq!(selected(&access, "tls:*", &local), Some("ci-cert"));
        assert_eq!(selected(&access, "tls:*", &os), None);
        assert_eq!(selected(&access, "net:10.0.1.0/24", &local), Some("farm"));
        assert_eq!(
            selected(&access, "net:2001:0db8::/56", &local),
            Some("farm")
        );

        let mirror = access.select(&item("tls:mirror.example.com"), &os).unwrap();
        assert_eq!(mirror.verify_trust(), Some("release"));
        assert!(!mirror.allow_unsigned());
        assert!(mirror.rules().opens_push_session());
        assert_eq!(
            mirror.rules().rights("os/stable"),
            AccessModes::parse("rw").unwrap()
        );
        let release = access.select(&item("ssh:user"), &client).unwrap();
        assert_eq!(release.sign(), ["release-key"]);
        assert!(release.allow_unsigned());
        let ci = access.select(&item("tls:*"), &local).unwrap();
        assert!(ci.tls_accept_claim());
        assert!(!ci.rules().opens_push_session());
        assert_eq!(
            access.server().trusted_proxy,
            Some(vec![IpNet::parse("10.0.0.0/24").unwrap()])
        );
    }

    /// A config with no client group has the two implicit groups, also when
    /// it has a server group.
    #[test]
    fn a_config_with_no_client_group_has_the_implicit_groups() {
        for text in [
            "",
            "[ex-ostrya server]\nlisten=127.0.0.1:0\n",
            "[ex-ostrya key \"k\"]\ntype=ed25519\n",
        ] {
            let access = access(text);
            let groups = access.groups();
            assert_eq!(groups.len(), 2, "{text:?}");
            assert_eq!(groups[0].name(), "anonymous");
            assert_eq!(groups[0].scope(), &CollectionScope::Local);
            assert_eq!(groups[1].name(), "anonymous-collections");
            assert_eq!(groups[1].scope(), &CollectionScope::AllOther);
            for group in groups {
                assert!(group.is_implicit());
                assert_eq!(group.auth(), [AuthItem::Anonymous]);
                assert_eq!(group.rules().allow.len(), 1);
                assert_eq!(group.rules().allow[0].to_string(), "r:**");
                assert!(group.rules().deny.is_empty());
                assert!(group.allow_unsigned());
                assert!(!group.rules().opens_push_session());
            }
            assert_eq!(
                selected(&access, "anonymous", &Namespace::Local),
                Some("anonymous")
            );
            assert_eq!(
                selected(&access, "anonymous", &collection("a.b")),
                Some("anonymous-collections")
            );
        }
    }

    /// One client group of any kind removes the implicit groups.
    #[test]
    fn one_client_group_removes_the_implicit_groups() {
        let access = access("[ex-ostrya client \"c\"]\nauth=ssh:c\n");
        assert_eq!(access.groups().len(), 1);
        assert!(!access.groups()[0].is_implicit());
        assert_eq!(selected(&access, "anonymous", &Namespace::Local), None);
    }

    /// A group that names the collection wins over a group with `*`, and `*`
    /// covers each other collection.
    #[test]
    fn an_exact_collection_wins_over_the_wildcard() {
        let access = access(
            "[ex-ostrya client \"exact\"]\nauth=ssh:u\ncollection=a.b;c.d\n\
             [ex-ostrya client \"any\"]\nauth=ssh:u\ncollection=*\n\
             [ex-ostrya client \"local\"]\nauth=ssh:u\n",
        );
        assert_eq!(
            selected(&access, "ssh:u", &collection("a.b")),
            Some("exact")
        );
        assert_eq!(
            selected(&access, "ssh:u", &collection("c.d")),
            Some("exact")
        );
        assert_eq!(selected(&access, "ssh:u", &collection("e.f")), Some("any"));
        assert_eq!(selected(&access, "ssh:u", &Namespace::Local), Some("local"));
        assert_eq!(selected(&access, "ssh:v", &Namespace::Local), None);
    }

    /// The selection never moves to another item.
    #[test]
    fn the_selection_never_falls_back_to_another_item() {
        let access = access(
            "[ex-ostrya client \"name\"]\nauth=tls:n\ncollection=a.b\n\
             [ex-ostrya client \"any\"]\nauth=tls:*\n\
             [ex-ostrya client \"anon\"]\nauth=anonymous\ncollection=*\n",
        );
        assert_eq!(selected(&access, "tls:n", &Namespace::Local), None);
        assert_eq!(selected(&access, "tls:n", &collection("c.d")), None);
        assert_eq!(selected(&access, "tls:*", &collection("a.b")), None);
        assert_eq!(selected(&access, "tls:n", &collection("a.b")), Some("name"));
    }

    /// An id that fails the collection-id rule and the own collection id
    /// select no group, and the own id maps to the local namespace.
    #[test]
    fn the_own_id_and_an_invalid_id_select_no_collection_group() {
        let config = RepoConfig::parse(
            "[core]\nrepo_version=1\nmode=archive-z2\ncollection-id=own.id\n\
             [ex-ostrya client \"any\"]\nauth=anonymous\ncollection=*\n\
             [ex-ostrya client \"local\"]\nauth=anonymous\n",
        )
        .unwrap();
        let access = ClientAccess::from_config(&config, Path::new("/r")).unwrap();
        assert_eq!(access.namespace(Some("own.id")), Namespace::Local);
        assert_eq!(access.namespace(None), Namespace::Local);
        assert_eq!(access.namespace(Some("a.b")), collection("a.b"));
        assert_eq!(access.namespace(Some("bad")), collection("bad"));
        assert_eq!(selected(&access, "anonymous", &collection("own.id")), None);
        assert_eq!(selected(&access, "anonymous", &collection("bad")), None);
        assert_eq!(selected(&access, "anonymous", &collection("a..b")), None);
        assert_eq!(
            selected(&access, "anonymous", &collection("a.b")),
            Some("any")
        );
        let ns = access.namespace(Some("own.id"));
        assert_eq!(selected(&access, "anonymous", &ns), Some("local"));
        let any = &access.groups()[0];
        assert!(any.covers(&collection("a.b")));
        assert!(!any.covers(&collection("bad")));
        assert!(!any.covers(&Namespace::Local));
    }

    /// With no own collection id, each id maps to its collection, and no id
    /// maps to the local namespace.
    #[test]
    fn with_no_own_id_each_id_maps_to_its_collection() {
        let access = access("");
        assert_eq!(access.namespace(Some("a.b")), collection("a.b"));
        assert_eq!(access.namespace(None), Namespace::Local);
    }

    /// `groups_of` gives each group of an item in config order.
    #[test]
    fn groups_of_gives_each_group_of_an_item() {
        let access = access(
            "[ex-ostrya client \"a\"]\nauth=ssh:u;anonymous\n\
             [ex-ostrya client \"b\"]\nauth=ssh:v\n\
             [ex-ostrya client \"c\"]\nauth=ssh:u\ncollection=*\n",
        );
        let ssh = item("ssh:u");
        let names: Vec<&str> = access.groups_of(&ssh).map(ClientGroup::name).collect();
        assert_eq!(names, ["a", "c"]);
        assert_eq!(access.groups_of(&item("ssh:w")).count(), 0);
    }

    /// Two groups with one item are refused when their namespaces overlap.
    #[test]
    fn an_item_in_two_overlapping_groups_is_refused() {
        for (a, b) in [
            ("", ""),
            ("collection=a.b\n", "collection=c.d;a.b\n"),
            ("collection=*\n", "collection=*\n"),
        ] {
            let text = format!(
                "[ex-ostrya client \"one\"]\nauth=ssh:u\n{a}\
                 [ex-ostrya client \"two\"]\nauth=anonymous;ssh:u\n{b}"
            );
            let Err(Error::InvalidFormat(message)) = try_access(&text) else {
                panic!("{a:?} {b:?} was accepted");
            };
            assert!(message.contains("ssh:u"), "{message}");
            assert!(message.contains("\"one\""), "{message}");
            assert!(message.contains("\"two\""), "{message}");
        }
        let text = "[ex-ostrya client \"one\"]\nauth=net:2001:db8::/56\n\
                    [ex-ostrya client \"two\"]\nauth=net:2001:0db8::/56\n";
        assert!(try_access(text).is_err());
    }

    /// Two groups with one item are accepted when their namespaces differ.
    #[test]
    fn an_item_in_two_disjoint_groups_is_accepted() {
        for (a, b) in [
            ("", "collection=*\n"),
            ("", "collection=a.b\n"),
            ("collection=a.b\n", "collection=c.d\n"),
            ("collection=a.b\n", "collection=*\n"),
        ] {
            let text = format!(
                "[ex-ostrya client \"one\"]\nauth=ssh:u\n{a}\
                 [ex-ostrya client \"two\"]\nauth=ssh:u\n{b}"
            );
            try_access(&text).unwrap();
        }
    }

    fn settings() -> ServerSettings {
        ServerSettings {
            tls_cert: Some("/c.pem".into()),
            tls_key: Some("/k.pem".into()),
            tls_client_ca: Some("/ca.pem".into()),
            ..ServerSettings::default()
        }
    }

    fn check(access: &ClientAccess, merged: &ServerSettings) -> String {
        match access.check_server(merged) {
            Err(Error::InvalidFormat(message)) => message,
            other => panic!("{merged:?}: {other:?}"),
        }
    }

    /// A TLS item needs `tls-client-ca`, and so does a proxy certificate
    /// header.
    #[test]
    fn a_tls_item_needs_the_client_ca() {
        for item_text in [
            "tls:*",
            "tls:n",
            "tls-sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ] {
            let access = access(&format!(
                "[ex-ostrya client \"c\"]\nauth=anonymous;{item_text}\n"
            ));
            access.check_server(&settings()).unwrap();
            let merged = ServerSettings {
                tls_client_ca: None,
                ..settings()
            };
            let message = check(&access, &merged);
            assert!(message.contains(item_text), "{message}");
            assert!(message.contains("tls-client-ca"), "{message}");
        }
        let access = access("[ex-ostrya client \"c\"]\nauth=anonymous\n");
        access.check_server(&ServerSettings::default()).unwrap();
        let proxy = Some(vec![IpNet::parse("10.0.0.0/24").unwrap()]);
        let merged = ServerSettings {
            trusted_proxy_client_cert: Some("X-Client-Cert".into()),
            trusted_proxy: proxy.clone(),
            ..ServerSettings::default()
        };
        let message = check(&access, &merged);
        assert!(message.contains("trusted-proxy-client-cert"), "{message}");
        assert!(message.contains("tls-client-ca"), "{message}");
        let merged = ServerSettings {
            trusted_proxy_client_cert: Some("X-Client-Cert".into()),
            trusted_proxy: proxy,
            tls_client_ca: Some("/ca.pem".into()),
            ..ServerSettings::default()
        };
        access.check_server(&merged).unwrap();
    }

    /// A proxy certificate header needs `trusted-proxy`.
    #[test]
    fn a_proxy_certificate_header_needs_a_trusted_proxy() {
        let anonymous = access("[ex-ostrya client \"c\"]\nauth=anonymous\n");
        let merged = ServerSettings {
            trusted_proxy_client_cert: Some("X-Client-Cert".into()),
            tls_client_ca: Some("/ca.pem".into()),
            ..ServerSettings::default()
        };
        let message = check(&anonymous, &merged);
        assert_eq!(
            message,
            "trusted-proxy-client-cert is set, and the server has no trusted-proxy"
        );
        let configured = access(
            "[ex-ostrya server]\ntls-client-ca=/ca.pem\n\
             trusted-proxy-client-cert=X-Client-Cert\n",
        );
        let message = check(&configured, configured.server());
        assert!(message.contains("no trusted-proxy"), "{message}");
    }

    /// `tls-cert` and `tls-key` go together, and `tls-client-ca` needs
    /// `tls-cert` or a proxy certificate header.
    #[test]
    fn the_tls_files_go_together() {
        let access = access("");
        let merged = ServerSettings {
            tls_key: None,
            ..settings()
        };
        assert!(check(&access, &merged).contains("tls-key"));
        let merged = ServerSettings {
            tls_cert: None,
            ..settings()
        };
        assert!(check(&access, &merged).contains("tls-cert"));
        let merged = ServerSettings {
            tls_client_ca: Some("/ca.pem".into()),
            ..ServerSettings::default()
        };
        assert!(check(&access, &merged).contains("tls-client-ca"));
        let merged = ServerSettings {
            tls_client_ca: None,
            ..settings()
        };
        access.check_server(&merged).unwrap();
    }
}
