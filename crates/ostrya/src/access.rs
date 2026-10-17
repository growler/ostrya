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
//! - [`Claims`] holds the claims of a client certificate, and
//!   [`ClientAccess::claim_rules`] gives their rules for one namespace.
//! - [`ForwardedHeader`] is a value of `trusted-proxy-header`, and
//!   [`is_header_name`] checks a value of `trusted-proxy-client-cert`.
//! - [`ReadAccess`] holds the read rights of one identified client, which
//!   the archive view, the ref listing, and a pull session take.
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
//!   client certificate (see [Claims](#claims)). A group with no `tls:*`,
//!   `tls:NAME`, or `tls-sha256:HEX` item cannot hold this key, with any
//!   value.
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
//! - `summary` (boolean, default false) -- add the namespace of the group to
//!   the summary of each auth item of the group (see
//!   [Summaries](#summaries)). A group with `tls-accept-claim=true` cannot
//!   set `summary=true`.
//!
//! [`ServerSettings`] lists the keys of `[ex-ostrya server]`.
//!
//! # Checks
//!
//! [`ClientAccess::from_config`] refuses a group name that starts with
//! `ex-ostrya ` and has no shape of a known group, and a key that a client
//! group or the server group does not take. It refuses `[ex-ostrya receive]`
//! and `[ex-ostrya receive "PATTERN"]` with a message that names
//! `[ex-ostrya client "NAME"]`. It also refuses the config in these cases:
//!
//! - Two groups carry the same item, and their namespaces overlap: both
//!   apply to the local refs, both name one id, or both have `*`.
//! - A collection id fails the collection-id rule, or is the own collection
//!   id of the repository.
//! - A network has host bits set.
//! - A group sets `tls-accept-claim=true` and `summary=true`.
//! - `verify`, `sign`, or `sign-summary` names a trust group or a key group
//!   that does not exist.
//!
//! [`ServerSettings::overridden_by`] puts the values of the command line in
//! place of the keys that they replace, and [`ClientAccess::check_server`]
//! checks the result.
//!
//! # Claims
//!
//! A claim is a URI SAN of a client certificate that states an allow item or
//! a deny item. [`Claim`] lists the forms. With `tls-accept-claim=true`, a
//! server reads the claims of the certificate that gives the auth item of a
//! request:
//!
//! - A group of the local refs reads the `ostrya:ref:` claims, and the
//!   `ostrya:collection:ID:` claims whose `ID` is `[core] collection-id`. A
//!   group of a collection reads the `ostrya:collection:ID:` claims of the
//!   collection of the request.
//! - When the certificate holds one or more claims for the namespace, they
//!   replace `allow` and `deny` of the group.
//! - When the certificate holds no claim for the namespace, `allow` and
//!   `deny` apply.
//!
//! The claims can give more rights than the group, so the client CA grants
//! the rights of each certificate that it signs. The other keys of the group
//! apply as they are.
//!
//! # Read access
//!
//! A client reads `refs/heads/NAME` and `refs/mirrors/ID/NAME` when the
//! group of its item in the namespace of the path has `r` on `NAME`. The own
//! collection id under `refs/mirrors/` names the local refs. An alias needs
//! `r` on its name and on its target. No client reads another path under
//! `refs/`. `summary` and `summary.sig` give the summary of the item of the
//! client (see [Summaries](#summaries)). [`ReadAccess`] states the rules.
//!
//! # Summaries
//!
//! An auth item has a summary when one or more of its groups has
//! `summary=true`. Each other item has no summary. The summary of an item
//! holds the refs that the item reads in each namespace whose selected
//! group has `summary=true`. A namespace whose selected group has
//! `summary=false` adds no ref, and no other group takes its place.
//!
//! [`ClientAccess::summary_digest`] gives the access digest of an item: the
//! SHA-256 digest of a text that holds `[core] collection-id` and the
//! namespace, the allow items, the deny items, and the value of `summary`
//! of each group of the item, `summary=false` groups included:
//!
//! ```text
//! collection-id=ID
//! namespace=NS
//! allow=ITEMS
//! deny=PATTERNS
//! summary=BOOL
//! ```
//!
//! - `ID` is `[core] collection-id`, or empty with no collection id.
//! - Each group adds the four lines `namespace=`, `allow=`, `deny=`, and
//!   `summary=`. The groups come in the byte-wise order of their
//!   `namespace=` lines.
//! - `NS` is empty for the local refs, `*` for `collection=*`, and else the
//!   collection ids, sorted byte-wise and joined by `;`.
//! - `ITEMS` is the allow items in the form `MODES:PATTERN`, with the modes
//!   in the order `rwctd`. Each distinct item occurs one time. The items
//!   are sorted byte-wise and joined by `;`.
//! - `PATTERNS` is the deny patterns, in the same way.
//! - `BOOL` is `true` or `false`, the value of `summary`.
//! - Each line ends with a newline.
//!
//! The text holds each group that the item can select in a namespace, so
//! the digest changes when a change to the config can change the refs of
//! the summary. The group names are not in the text, so a new group name
//! keeps the digest.
//!
//! # Implicit groups
//!
//! A config with no client group has two implicit groups:
//!
//! ```text
//! [ex-ostrya client "anonymous"]
//! auth=anonymous
//! allow=r:**
//! summary=true
//!
//! [ex-ostrya client "anonymous-collections"]
//! auth=anonymous
//! collection=*
//! allow=r:**
//! summary=true
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

mod claim;
mod item;
mod read;
mod reader;
mod rights;

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

pub use claim::{Claim, ClaimError, ClaimRule, Claims, MAX_CLAIMS};
pub use item::{AuthItem, IpNet};
pub use read::ReadAccess;
pub(crate) use read::reads;
#[cfg(feature = "receive")]
pub(crate) use reader::{Group, classify};
pub use rights::{AccessModes, AccessRules, AllowItem};

use ostrya_core::Checksum;

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

impl Namespace {
    /// Returns the namespace of the collection id `collection` in a
    /// repository whose own collection id is `own`.
    ///
    /// `None` and `own` give [`Local`](Namespace::Local). Each other id gives
    /// [`Collection`](Namespace::Collection).
    pub(crate) fn of(collection: Option<&str>, own: Option<&str>) -> Namespace {
        match collection {
            Some(id) if Some(id) != own => Namespace::Collection(id.to_owned()),
            _ => Namespace::Local,
        }
    }

    /// Returns the collection id of a collection namespace, or `None` for
    /// the local refs.
    #[cfg(feature = "receive")]
    pub(crate) fn collection(&self) -> Option<&str> {
        match self {
            Namespace::Local => None,
            Namespace::Collection(id) => Some(id),
        }
    }
}

/// The namespace of a client group, from its `collection` key.
///
/// The [`Default`] scope is [`Local`](CollectionScope::Local).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum CollectionScope {
    /// No `collection` key: the local refs.
    #[default]
    Local,
    /// A list of collection ids, in the order of the config, each one time.
    Ids(Vec<String>),
    /// `collection=*`: each collection other than the own collection of the
    /// repository.
    AllOther,
}

impl CollectionScope {
    /// Returns `true` if the scope holds `namespace`.
    ///
    /// A `*` scope holds each [`Collection`](Namespace::Collection) whose id
    /// passes the collection-id rule. [`ClientAccess::select`] also refuses
    /// the own collection id, which [`ClientAccess::namespace`] maps to
    /// [`Local`](Namespace::Local).
    pub fn covers(&self, namespace: &Namespace) -> bool {
        match (self, namespace) {
            (CollectionScope::Local, Namespace::Local) => true,
            (CollectionScope::Ids(ids), Namespace::Collection(id)) => ids.contains(id),
            (CollectionScope::AllOther, Namespace::Collection(id)) => {
                ostrya_core::is_collection_id(id)
            }
            _ => false,
        }
    }

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
    summary: bool,
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

    /// Returns the value of `tls-accept-claim`: `true` if the claims of a
    /// client certificate replace the rules of the group.
    ///
    /// The [module doc](crate::access#claims) states the rule.
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

    /// Returns the value of `summary`: `true` if the namespace of the group
    /// is in the summary of each auth item of the group.
    ///
    /// The [module doc](crate::access#summaries) states the rule.
    pub fn summary(&self) -> bool {
        self.summary
    }

    /// Returns `true` for one of the two groups that a config with no client
    /// group has.
    pub fn is_implicit(&self) -> bool {
        self.implicit
    }

    /// Returns `true` if the scope of the group holds `namespace`.
    ///
    /// The method reads the scope alone, as [`CollectionScope::covers`]
    /// states.
    pub fn covers(&self, namespace: &Namespace) -> bool {
        self.scope.covers(namespace)
    }

    /// Returns the group name of the group, for the error messages.
    fn header(&self) -> String {
        format!("[ex-ostrya client \"{}\"]", self.name)
    }
}

/// The request header from which a server reads the client address of a
/// request from a trusted proxy: a value of `trusted-proxy-header`.
///
/// The text form is the lowercase name of the header. [`parse`](Self::parse)
/// takes that form alone.
///
/// # Examples
///
/// ```
/// use ostrya::access::ForwardedHeader;
///
/// let header = ForwardedHeader::parse("x-forwarded-for")?;
/// assert_eq!(header, ForwardedHeader::XForwardedFor);
/// assert_eq!(header.to_string(), "x-forwarded-for");
/// assert!(ForwardedHeader::parse("X-Forwarded-For").is_err());
/// # Ok::<(), ostrya::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ForwardedHeader {
    /// `forwarded`: the `Forwarded` header of RFC 7239.
    Forwarded,
    /// `x-forwarded-for`: the `X-Forwarded-For` header.
    XForwardedFor,
    /// `x-real-ip`: the `X-Real-IP` header.
    XRealIp,
}

impl ForwardedHeader {
    /// Parses a value of `trusted-proxy-header`: `forwarded`,
    /// `x-forwarded-for`, or `x-real-ip`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFormat`] for each other text, also for a name in
    /// another case.
    pub fn parse(text: &str) -> Result<ForwardedHeader> {
        match text {
            "forwarded" => Ok(ForwardedHeader::Forwarded),
            "x-forwarded-for" => Ok(ForwardedHeader::XForwardedFor),
            "x-real-ip" => Ok(ForwardedHeader::XRealIp),
            _ => Err(Error::InvalidFormat(format!(
                "malformed trusted-proxy-header value '{text}': the value is forwarded, \
                 x-forwarded-for, or x-real-ip"
            ))),
        }
    }

    /// Returns the text form: the lowercase name of the header.
    pub fn as_str(self) -> &'static str {
        match self {
            ForwardedHeader::Forwarded => "forwarded",
            ForwardedHeader::XForwardedFor => "x-forwarded-for",
            ForwardedHeader::XRealIp => "x-real-ip",
        }
    }
}

impl fmt::Display for ForwardedHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Returns `true` if `name` is a name of an HTTP header: a token of HTTP, one
/// or more of the ASCII letters, the digits, and the characters
/// ``!#$%&'*+-.^_`|~``.
///
/// A value of `trusted-proxy-client-cert` must pass this check.
///
/// # Examples
///
/// ```
/// use ostrya::access::is_header_name;
///
/// assert!(is_header_name("X-SSL-Client-Cert"));
/// assert!(!is_header_name("X Client"));
/// assert!(!is_header_name(""));
/// ```
pub fn is_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
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
    /// `trusted-proxy-header`: the request header from which the server reads
    /// the client address of a request from a trusted proxy.
    pub trusted_proxy_header: Option<ForwardedHeader>,
    /// `trusted-proxy-client-cert`: the name of the request header that
    /// carries the client certificate from a trusted proxy. The name passes
    /// [`is_header_name`].
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

impl ServerSettings {
    /// Returns the settings with each field of `flags` that is set in place
    /// of the field of `self`.
    ///
    /// A server takes the keys of `[ex-ostrya server]` as `self` and the
    /// values of its command line as `flags`. A field that is `None` in
    /// `flags` keeps the value of `self`. A list in `flags` replaces the
    /// whole list of `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// use ostrya::access::ServerSettings;
    ///
    /// let keys = ServerSettings {
    ///     listen: Some(vec!["0.0.0.0:80".parse()?, "[::]:80".parse()?]),
    ///     max_sessions: Some(8),
    ///     ..ServerSettings::default()
    /// };
    /// let flags = ServerSettings {
    ///     listen: Some(vec!["127.0.0.1:8080".parse()?]),
    ///     ..ServerSettings::default()
    /// };
    /// let merged = keys.overridden_by(&flags);
    /// assert_eq!(merged.listen, flags.listen);
    /// assert_eq!(merged.max_sessions, Some(8));
    /// # Ok::<(), std::net::AddrParseError>(())
    /// ```
    pub fn overridden_by(&self, flags: &ServerSettings) -> ServerSettings {
        fn pick<T: Clone>(flag: &Option<T>, key: &Option<T>) -> Option<T> {
            flag.as_ref().or(key.as_ref()).cloned()
        }
        // The pattern names each field, so a new field does not compile
        // until it is merged here.
        let ServerSettings {
            listen,
            tls_cert,
            tls_key,
            tls_client_ca,
            trusted_proxy,
            trusted_proxy_header,
            trusted_proxy_client_cert,
            proxy_protocol,
            allow_cleartext_credentials,
            session_timeout,
            max_sessions,
            parallel_uploads,
            body_timeout,
            sign_summary,
        } = flags;
        ServerSettings {
            listen: pick(listen, &self.listen),
            tls_cert: pick(tls_cert, &self.tls_cert),
            tls_key: pick(tls_key, &self.tls_key),
            tls_client_ca: pick(tls_client_ca, &self.tls_client_ca),
            trusted_proxy: pick(trusted_proxy, &self.trusted_proxy),
            trusted_proxy_header: pick(trusted_proxy_header, &self.trusted_proxy_header),
            trusted_proxy_client_cert: pick(
                trusted_proxy_client_cert,
                &self.trusted_proxy_client_cert,
            ),
            proxy_protocol: pick(proxy_protocol, &self.proxy_protocol),
            allow_cleartext_credentials: pick(
                allow_cleartext_credentials,
                &self.allow_cleartext_credentials,
            ),
            session_timeout: pick(session_timeout, &self.session_timeout),
            max_sessions: pick(max_sessions, &self.max_sessions),
            parallel_uploads: pick(parallel_uploads, &self.parallel_uploads),
            body_timeout: pick(body_timeout, &self.body_timeout),
            sign_summary: pick(sign_summary, &self.sign_summary),
        }
    }
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
    /// The summary files of each item that has a summary.
    summaries: HashMap<AuthItem, SummaryFiles>,
}

/// The access digest of one auth item with a summary, and the stem of the
/// names of its files under `extensions/ostrya/summary/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SummaryFiles {
    /// The access digest of the item.
    pub(crate) digest: Checksum,
    /// `HEX`: the SHA-256 digest of the text of the item, in 64 lowercase
    /// hex digits.
    pub(crate) stem: String,
}

impl ClientAccess {
    /// Reads `[ex-ostrya server]` and each `[ex-ostrya client "NAME"]` of
    /// `config`.
    ///
    /// A relative path in `tls-cert`, `tls-key`, or `tls-client-ca` is joined
    /// onto `repo_dir`. The call reads no file. It records the names of the
    /// `[ex-ostrya trust "NAME"]` and `[ex-ostrya key "NAME"]` groups, for
    /// the checks of `verify`, `sign`, and `sign-summary`, and reads no key
    /// of these groups.
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

    /// Returns the two implicit groups of a config with no client group, with
    /// the own collection id `collection_id` and the default server
    /// settings.
    ///
    /// The value is the value that
    /// [`from_config`](ClientAccess::from_config) gives for a config with no
    /// client group, no `[ex-ostrya server]`, and `[core] collection-id` set
    /// to `collection_id`. The call checks no value.
    ///
    /// # Examples
    ///
    /// ```
    /// use ostrya::access::{AuthItem, ClientAccess, Namespace};
    ///
    /// let access = ClientAccess::implicit(Some("com.example.own"));
    /// assert!(!access.has_client_groups());
    /// let own = access.namespace(Some("com.example.own"));
    /// assert_eq!(own, Namespace::Local);
    /// let group = access.select(&AuthItem::Anonymous, &own).unwrap();
    /// assert_eq!(group.name(), "anonymous");
    /// ```
    pub fn implicit(collection_id: Option<&str>) -> ClientAccess {
        let groups = reader::implicit_groups();
        let by_item = reader::index(&groups);
        let summaries = reader::summary_digests(&groups, &by_item, collection_id);
        ClientAccess {
            collection_id: collection_id.map(str::to_owned),
            server: ServerSettings::default(),
            groups,
            by_item,
            summaries,
        }
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

    /// Returns the access digest of `item`, or `None` if `item` has no
    /// summary.
    ///
    /// An item has a summary when one or more of its groups has
    /// `summary=true`. The digest covers `[core] collection-id` and the
    /// namespace, the allow items, the deny items, and the value of
    /// `summary` of each group of the item. The
    /// [module doc](crate::access#summaries) states the text.
    /// The value computes the digests one time, when it reads the config.
    ///
    /// # Examples
    ///
    /// ```
    /// use ostrya::config::RepoConfig;
    /// use ostrya::access::{AuthItem, ClientAccess};
    ///
    /// let config = RepoConfig::parse(
    ///     "[core]\nrepo_version=1\nmode=archive-z2\n\
    ///      [ex-ostrya client \"public\"]\nauth=anonymous\nallow=r:pub/**\nsummary=true\n\
    ///      [ex-ostrya client \"ci\"]\nauth=ssh:ci\nallow=r:**\n",
    /// )?;
    /// let access = ClientAccess::from_config(&config, "/srv/repo".as_ref())?;
    /// assert!(access.summary_digest(&AuthItem::Anonymous).is_some());
    /// assert!(access.summary_digest(&AuthItem::parse("ssh:ci")?).is_none());
    /// # Ok::<(), ostrya::Error>(())
    /// ```
    pub fn summary_digest(&self, item: &AuthItem) -> Option<Checksum> {
        self.summaries.get(item).map(|files| files.digest)
    }

    /// Returns the access digest of `item` and the stem of the names of its
    /// files, or `None` if `item` has no summary.
    pub(crate) fn summary_files(&self, item: &AuthItem) -> Option<&SummaryFiles> {
        self.summaries.get(item)
    }

    /// Returns the namespace of the collection id `collection`.
    ///
    /// `None` and the own collection id of the repository give
    /// [`Local`](Namespace::Local). Each other id gives
    /// [`Collection`](Namespace::Collection), also an id that fails the
    /// collection-id rule.
    pub fn namespace(&self, collection: Option<&str>) -> Namespace {
        Namespace::of(collection, self.collection_id.as_deref())
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
        self.select_index(item, namespace).map(|i| &self.groups[i])
    }

    /// Returns the index in `groups` of the group that
    /// [`select`](ClientAccess::select) returns.
    pub(crate) fn select_index(&self, item: &AuthItem, namespace: &Namespace) -> Option<usize> {
        let mut carriers = self.carriers(item).iter().copied();
        let scope = |i: usize| &self.groups[i].scope;
        match namespace {
            Namespace::Local => carriers.find(|&i| *scope(i) == CollectionScope::Local),
            Namespace::Collection(id) => {
                if !ostrya_core::is_collection_id(id)
                    || Some(id.as_str()) == self.collection_id.as_deref()
                {
                    return None;
                }
                carriers
                    .clone()
                    .find(|&i| matches!(scope(i), CollectionScope::Ids(ids) if ids.contains(id)))
                    .or_else(|| carriers.find(|&i| *scope(i) == CollectionScope::AllOther))
            }
        }
    }

    /// Returns the rules of the claims of `claims` for `namespace`, or `None`
    /// if no claim names `namespace`.
    ///
    /// A claim of the collection `[core] collection-id` names the
    /// [`Local`](Namespace::Local) namespace. A
    /// [`Collection`](Namespace::Collection) of that id is the
    /// [`Local`](Namespace::Local) namespace too, as in
    /// [`namespace`](ClientAccess::namespace). The allow items and the deny
    /// items keep the order of `claims`. With `Some`, the rules replace the
    /// rules of a group with `tls-accept-claim=true`. The [module
    /// doc](crate::access#claims) states the rule.
    ///
    /// # Examples
    ///
    /// ```
    /// use ostrya::config::RepoConfig;
    /// use ostrya::access::{AccessModes, Claims, ClientAccess, Namespace};
    ///
    /// let config = RepoConfig::parse(
    ///     "[core]\nrepo_version=1\nmode=archive-z2\ncollection-id=com.example.own\n",
    /// )?;
    /// let access = ClientAccess::from_config(&config, "/srv/repo".as_ref())?;
    /// let claims = Claims::parse([
    ///     "ostrya:ref:w:main",
    ///     "ostrya:collection:com.example.own:!secret",
    ///     "ostrya:collection:com.example.os:r:os/**",
    /// ])
    /// .unwrap();
    /// let local = access.claim_rules(&claims, &Namespace::Local).unwrap();
    /// assert!(local.rights("main").contains(AccessModes::WRITE));
    /// assert_eq!(local.deny.len(), 1);
    /// let own = Namespace::Collection("com.example.own".into());
    /// assert_eq!(access.claim_rules(&claims, &own), Some(local));
    /// let other = Namespace::Collection("org.example.other".into());
    /// assert!(access.claim_rules(&claims, &other).is_none());
    /// # Ok::<(), ostrya::Error>(())
    /// ```
    pub fn claim_rules(&self, claims: &Claims, namespace: &Namespace) -> Option<AccessRules> {
        let namespace = match namespace {
            Namespace::Collection(id) if Some(id.as_str()) == self.collection_id.as_deref() => {
                &Namespace::Local
            }
            other => other,
        };
        let mut rules = AccessRules::default();
        let mut found = false;
        for claim in claims.as_slice() {
            let names = match (&claim.namespace, namespace) {
                (Namespace::Local, Namespace::Local) => true,
                (Namespace::Collection(id), Namespace::Local) => {
                    Some(id.as_str()) == self.collection_id.as_deref()
                }
                (Namespace::Collection(id), Namespace::Collection(wanted)) => id == wanted,
                (Namespace::Local, Namespace::Collection(_)) => false,
            };
            if !names {
                continue;
            }
            found = true;
            match &claim.rule {
                ClaimRule::Allow(item) => rules.allow.push(item.clone()),
                ClaimRule::Deny(pattern) => rules.deny.push(pattern.clone()),
            }
        }
        found.then_some(rules)
    }

    /// Returns the rules of `group` in `namespace`, with the claims of
    /// `claims`.
    ///
    /// When the group has `tls-accept-claim=true` and
    /// [`claim_rules`](ClientAccess::claim_rules) gives the rules of
    /// `claims` for `namespace`, the result is these rules, owned. Else the
    /// result is the rules of the group, borrowed. The [module
    /// doc](crate::access#claims) states the rule.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::borrow::Cow;
    ///
    /// use ostrya::config::RepoConfig;
    /// use ostrya::access::{AuthItem, Claims, ClientAccess, Namespace};
    ///
    /// let config = RepoConfig::parse(
    ///     "[core]\nrepo_version=1\nmode=archive-z2\n\
    ///      [ex-ostrya client \"certs\"]\nauth=tls:*\ntls-accept-claim=true\nallow=r:**\n",
    /// )?;
    /// let access = ClientAccess::from_config(&config, "/srv/repo".as_ref())?;
    /// let group = access.select(&AuthItem::TlsAny, &Namespace::Local).unwrap();
    /// let claims = Claims::parse(["ostrya:ref:w:main"]).unwrap();
    /// let rules = access.effective_rules(group, &Namespace::Local, Some(&claims));
    /// assert!(matches!(rules, Cow::Owned(_)));
    /// let rules = access.effective_rules(group, &Namespace::Local, None);
    /// assert!(matches!(rules, Cow::Borrowed(_)));
    /// # Ok::<(), ostrya::Error>(())
    /// ```
    pub fn effective_rules<'g>(
        &self,
        group: &'g ClientGroup,
        namespace: &Namespace,
        claims: Option<&Claims>,
    ) -> Cow<'g, AccessRules> {
        match claims {
            Some(claims) if group.tls_accept_claim => match self.claim_rules(claims, namespace) {
                Some(rules) => Cow::Owned(rules),
                None => Cow::Borrowed(&group.rules),
            },
            _ => Cow::Borrowed(&group.rules),
        }
    }

    /// Returns `true` if the config has one or more client groups, and
    /// `false` if it has the two implicit groups.
    pub fn has_client_groups(&self) -> bool {
        !self.groups.iter().all(ClientGroup::is_implicit)
    }

    /// Returns `true` if `id` is `[core] collection-id`.
    fn is_own_collection(&self, id: &str) -> bool {
        Some(id) == self.collection_id.as_deref()
    }

    /// Returns each auth item of the groups one time, in the order of its
    /// first group in the config.
    pub fn items(&self) -> impl Iterator<Item = &AuthItem> {
        self.groups.iter().enumerate().flat_map(move |(i, group)| {
            group
                .auth
                .iter()
                .filter(move |item| self.carriers(item).first() == Some(&i))
        })
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
    /// - `trusted_proxy` is set, and `trusted_proxy_header` is `None`.
    /// - `trusted_proxy_header` is set, and `trusted_proxy` is `None`.
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
        match (&merged.trusted_proxy, &merged.trusted_proxy_header) {
            (Some(_), None) => {
                return Err(Error::InvalidFormat(
                    "trusted-proxy is set, and the server has no trusted-proxy-header".to_owned(),
                ));
            }
            (None, Some(_)) => {
                return Err(Error::InvalidFormat(
                    "trusted-proxy-header is set, and the server has no trusted-proxy".to_owned(),
                ));
            }
            _ => {}
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
    assert_send_sync::<ForwardedHeader>();
    assert_send_sync::<AccessModes>();
    assert_send_sync::<AllowItem>();
    assert_send_sync::<AccessRules>();
    assert_send_sync::<Claims>();
    assert_send_sync::<Claim>();
    assert_send_sync::<ClaimRule>();
    assert_send_sync::<ClaimError>();
    assert_send_sync::<ReadAccess>();
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
trusted-proxy-header=x-forwarded-for

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
        assert_eq!(
            access.server().trusted_proxy_header,
            Some(ForwardedHeader::XForwardedFor)
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

    /// [`ClientAccess::implicit`] gives the groups and the server settings
    /// of a config with no client group. It keeps the own collection id as
    /// given, also an id that a config text holds only with an escape.
    #[test]
    fn the_implicit_access_has_the_groups_of_a_config_with_no_client_group() {
        let from_config = access("");
        for id in [None, Some("a.b"), Some("a\\b"), Some(" a.b")] {
            let implicit = ClientAccess::implicit(id);
            assert_eq!(
                format!("{:?}", implicit.groups()),
                format!("{:?}", from_config.groups()),
                "{id:?}"
            );
            assert_eq!(implicit.server(), from_config.server(), "{id:?}");
            assert!(!implicit.has_client_groups(), "{id:?}");
            if let Some(id) = id {
                assert_eq!(implicit.namespace(Some(id)), Namespace::Local, "{id:?}");
            }
        }
        assert_eq!(
            ClientAccess::implicit(None).namespace(Some("a.b")),
            collection("a.b")
        );
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

    /// The rules of the claims for a namespace hold the claims of that
    /// namespace alone, in order. A claim of the own collection id counts
    /// for the local refs. No claim for a namespace gives `None`, also with
    /// claims of other namespaces.
    #[test]
    fn the_claim_rules_hold_the_claims_of_one_namespace() {
        let config = RepoConfig::parse(&format!("{CORE}collection-id=own.id\n")).unwrap();
        let access = ClientAccess::from_config(&config, Path::new("/r")).unwrap();
        let claims = Claims::parse([
            "ostrya:ref:w:main",
            "ostrya:collection:a.b:t:os/**",
            "ostrya:ref:!secret/**",
            "ostrya:collection:own.id:d:devel/**",
            "ostrya:collection:a.b:!os/secret",
        ])
        .unwrap();
        let local = access.claim_rules(&claims, &Namespace::Local).unwrap();
        let allow: Vec<String> = local.allow.iter().map(AllowItem::to_string).collect();
        assert_eq!(allow, ["w:main", "d:devel/**"]);
        assert_eq!(local.deny.len(), 1);
        assert_eq!(local.deny[0].as_str(), "secret/**");
        assert_eq!(local.rights("main"), AccessModes::parse("rw").unwrap());
        assert_eq!(local.rights("secret/a"), AccessModes::NONE);

        let ab = access.claim_rules(&claims, &collection("a.b")).unwrap();
        let allow: Vec<String> = ab.allow.iter().map(AllowItem::to_string).collect();
        assert_eq!(allow, ["t:os/**"]);
        assert_eq!(ab.rights("os/secret"), AccessModes::NONE);
        assert!(access.claim_rules(&claims, &collection("c.d")).is_none());
        assert!(
            access
                .claim_rules(&Claims::default(), &Namespace::Local)
                .is_none()
        );

        let collections_only = Claims::parse(["ostrya:collection:a.b:w:main"]).unwrap();
        assert!(
            access
                .claim_rules(&collections_only, &Namespace::Local)
                .is_none()
        );
        let deny_only = Claims::parse(["ostrya:ref:!secret/**"]).unwrap();
        let rules = access.claim_rules(&deny_only, &Namespace::Local).unwrap();
        assert!(rules.allow.is_empty());
        assert_eq!(rules.rights("main"), AccessModes::NONE);

        let no_own_id = self::access("");
        let own = Claims::parse(["ostrya:collection:own.id:w:main"]).unwrap();
        assert!(no_own_id.claim_rules(&own, &Namespace::Local).is_none());
        assert!(no_own_id.claim_rules(&own, &collection("own.id")).is_some());
    }

    /// The namespace of the own collection id gives the rules of the local
    /// refs: the `ostrya:ref:` claims and the claims of the own id.
    #[test]
    fn the_own_collection_id_gives_the_claim_rules_of_the_local_refs() {
        let config = RepoConfig::parse(&format!("{CORE}collection-id=own.id\n")).unwrap();
        let access = ClientAccess::from_config(&config, Path::new("/r")).unwrap();
        let claims = Claims::parse([
            "ostrya:ref:w:main",
            "ostrya:collection:own.id:d:devel/**",
            "ostrya:collection:a.b:t:os/**",
            "ostrya:ref:!secret/**",
        ])
        .unwrap();
        let own = access.claim_rules(&claims, &collection("own.id")).unwrap();
        let allow: Vec<String> = own.allow.iter().map(AllowItem::to_string).collect();
        assert_eq!(allow, ["w:main", "d:devel/**"]);
        assert_eq!(own.deny.len(), 1);
        assert_eq!(Some(own), access.claim_rules(&claims, &Namespace::Local));
        let refs_only = Claims::parse(["ostrya:ref:w:main"]).unwrap();
        assert!(
            access
                .claim_rules(&refs_only, &collection("own.id"))
                .is_some()
        );
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

    /// `items` gives each item one time, in the order of its first group.
    /// Two texts of one network are one item.
    #[test]
    fn items_gives_each_item_one_time() {
        let access = access(
            "[ex-ostrya client \"a\"]\nauth=ssh:u;anonymous\n\
             [ex-ostrya client \"b\"]\nauth=net:2001:0db8::/56;ssh:v\n\
             [ex-ostrya client \"c\"]\nauth=ssh:u;net:2001:db8::/56;tls:*\ncollection=*\n",
        );
        let items: Vec<String> = access.items().map(AuthItem::to_string).collect();
        assert_eq!(
            items,
            ["ssh:u", "anonymous", "net:2001:db8::/56", "ssh:v", "tls:*"]
        );
        let implicit = self::access("");
        let items: Vec<&AuthItem> = implicit.items().collect();
        assert_eq!(items, [&AuthItem::Anonymous]);
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
            trusted_proxy_header: Some(ForwardedHeader::XForwardedFor),
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

    /// `trusted-proxy` and `trusted-proxy-header` go together, from a key or
    /// from a flag.
    #[test]
    fn a_trusted_proxy_and_its_header_go_together() {
        let anonymous = access("[ex-ostrya client \"c\"]\nauth=anonymous\n");
        let proxy = Some(vec![IpNet::parse("10.0.0.0/24").unwrap()]);
        let merged = ServerSettings {
            trusted_proxy: proxy.clone(),
            ..ServerSettings::default()
        };
        assert_eq!(
            check(&anonymous, &merged),
            "trusted-proxy is set, and the server has no trusted-proxy-header"
        );
        let merged = ServerSettings {
            trusted_proxy_header: Some(ForwardedHeader::Forwarded),
            ..ServerSettings::default()
        };
        assert_eq!(
            check(&anonymous, &merged),
            "trusted-proxy-header is set, and the server has no trusted-proxy"
        );
        let merged = ServerSettings {
            trusted_proxy: proxy,
            trusted_proxy_header: Some(ForwardedHeader::XRealIp),
            ..ServerSettings::default()
        };
        anonymous.check_server(&merged).unwrap();
        let configured = access("[ex-ostrya server]\ntrusted-proxy-header=x-real-ip\n");
        let message = check(&configured, configured.server());
        assert!(message.contains("no trusted-proxy"), "{message}");
        let configured = access("[ex-ostrya server]\ntrusted-proxy=10.0.0.0/8\n");
        let flags = ServerSettings {
            trusted_proxy_header: Some(ForwardedHeader::Forwarded),
            ..ServerSettings::default()
        };
        let merged = configured.server().overridden_by(&flags);
        configured.check_server(&merged).unwrap();
    }

    /// A value of `trusted-proxy-header` is one of three lowercase names.
    #[test]
    fn a_forwarded_header_has_three_names() {
        for (text, header) in [
            ("forwarded", ForwardedHeader::Forwarded),
            ("x-forwarded-for", ForwardedHeader::XForwardedFor),
            ("x-real-ip", ForwardedHeader::XRealIp),
        ] {
            assert_eq!(ForwardedHeader::parse(text).unwrap(), header);
            assert_eq!(header.to_string(), text);
        }
        for text in [
            "",
            "Forwarded",
            "X-Real-IP",
            "x-forwarded-proto",
            " forwarded",
        ] {
            let err = ForwardedHeader::parse(text).unwrap_err();
            assert!(matches!(err, Error::InvalidFormat(_)), "{text:?}: {err}");
        }
    }

    /// `is_header_name` takes the characters of an HTTP token.
    #[test]
    fn a_header_name_is_an_http_token() {
        for name in ["X-Client-Cert", "ssl_client_cert", "a!#$%&'*+-.^_`|~9"] {
            assert!(is_header_name(name), "{name}");
        }
        for name in ["", "a b", "a:b", "a\"b", "a(b", "a/b", "\u{e9}", "a\tb"] {
            assert!(!is_header_name(name), "{name:?}");
        }
    }

    /// A field of the flags that is set replaces the key, a list in whole,
    /// and a field that is `None` keeps the key.
    #[test]
    fn a_flag_overrides_its_key() {
        let net = |text: &str| IpNet::parse(text).unwrap();
        let keys = ServerSettings {
            listen: Some(vec![
                "127.0.0.1:1".parse().unwrap(),
                "127.0.0.1:2".parse().unwrap(),
            ]),
            tls_cert: Some("/key/c.pem".into()),
            tls_key: Some("/key/k.pem".into()),
            tls_client_ca: Some("/key/ca.pem".into()),
            trusted_proxy: Some(vec![net("10.0.0.0/8"), net("10.1.0.0/16")]),
            trusted_proxy_header: Some(ForwardedHeader::Forwarded),
            trusted_proxy_client_cert: Some("X-Key".into()),
            proxy_protocol: Some(false),
            allow_cleartext_credentials: Some(true),
            session_timeout: Some(1),
            max_sessions: Some(2),
            parallel_uploads: Some(3),
            body_timeout: Some(4),
            sign_summary: Some(vec!["a".into(), "b".into()]),
        };
        let flags = ServerSettings {
            listen: Some(vec!["127.0.0.1:3".parse().unwrap()]),
            tls_cert: Some("flag/c.pem".into()),
            tls_key: Some("flag/k.pem".into()),
            tls_client_ca: Some("flag/ca.pem".into()),
            trusted_proxy: Some(vec![net("192.0.2.0/24")]),
            trusted_proxy_header: Some(ForwardedHeader::XRealIp),
            trusted_proxy_client_cert: Some("X-Flag".into()),
            proxy_protocol: Some(true),
            allow_cleartext_credentials: Some(false),
            session_timeout: Some(10),
            max_sessions: Some(20),
            parallel_uploads: Some(30),
            body_timeout: Some(40),
            sign_summary: Some(vec!["c".into()]),
        };
        assert_eq!(keys.overridden_by(&flags), flags);
        assert_eq!(keys.overridden_by(&ServerSettings::default()), keys);
        assert_eq!(ServerSettings::default().overridden_by(&flags), flags);
        let one = ServerSettings {
            max_sessions: Some(20),
            ..ServerSettings::default()
        };
        let merged = keys.overridden_by(&one);
        assert_eq!(merged.max_sessions, Some(20));
        assert_eq!(
            merged,
            ServerSettings {
                max_sessions: Some(20),
                ..keys.clone()
            }
        );
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
