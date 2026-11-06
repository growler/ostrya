//! The reader of `[ex-ostrya server]` and of the client groups.
//!
//! The reader reads each group by the shape of its name, then checks the
//! references between the groups. It reads no file.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use ostrya_core::{Checksum, KeyFile, RefPattern};

use super::item::{AuthItem, parse_item, parse_net};
use super::rights::{
    AccessModes, AccessRules, AllowItem, NamespaceRules, parse_allow_item, parse_deny_item,
};
use super::{
    ClientAccess, ClientGroup, ForwardedHeader, ServerSettings, SummaryFiles, is_header_name,
};
use crate::config::RepoConfig;
use crate::error::{Error, Result};
use crate::summary::summary_stem;

/// The name of the server group.
const SERVER_GROUP: &str = "ex-ostrya server";
/// The name prefix of a client group, before the quoted name.
const CLIENT_PREFIX: &str = "ex-ostrya client \"";
/// The name prefix of a trust group, before the quoted name.
const TRUST_PREFIX: &str = "ex-ostrya trust \"";
/// The name prefix of a key group, before the quoted name.
const KEY_PREFIX: &str = "ex-ostrya key \"";
/// The name of a group that the config refuses, with a message that names
/// the client group.
const RECEIVE_GROUP: &str = "ex-ostrya receive";
/// The name prefix of a group that the config refuses in the same way, before
/// the quoted pattern.
const RECEIVE_PREFIX: &str = "ex-ostrya receive \"";
/// The name prefix of each group of the extensions. A group name with this
/// prefix and no known shape is refused.
const RESERVED_PREFIX: &str = "ex-ostrya ";

/// The keys of a client group.
const CLIENT_KEYS: &[&str] = &[
    "auth",
    "allow",
    "deny",
    "tls-accept-claim",
    "verify",
    "allow-unsigned",
    "sign",
    "allow-privileged",
    "disable-verify-bindings",
    "summary",
];
/// The keys of the server group.
const SERVER_KEYS: &[&str] = &[
    "listen",
    "tls-cert",
    "tls-key",
    "tls-client-ca",
    "trusted-proxy",
    "trusted-proxy-header",
    "trusted-proxy-client-cert",
    "proxy-protocol",
    "allow-cleartext-credentials",
    "session-timeout",
    "max-sessions",
    "parallel-uploads",
    "body-timeout",
    "sign-summary",
];

/// One group of the extensions, by the shape of its name.
pub(crate) enum Group<'a> {
    /// `[ex-ostrya server]`.
    Server,
    /// `[ex-ostrya client "NAME"]`, with the name.
    Client(&'a str),
    /// `[ex-ostrya trust "NAME"]`, with the name.
    Trust(&'a str),
    /// `[ex-ostrya key "NAME"]`, with the name.
    Key(&'a str),
}

/// The names of the trust groups and the key groups, for the checks of the
/// references.
struct Names<'a> {
    trusts: HashSet<&'a str>,
    keys: HashSet<&'a str>,
}

/// Reads the client groups and the server group of `config`.
pub(super) fn read(config: &RepoConfig, repo_dir: &Path) -> Result<ClientAccess> {
    let keyfile = config.keyfile();
    let own_id = config.collection_id();
    let mut server = None;
    let mut clients: Vec<(&str, &str)> = Vec::new();
    let mut names = Names {
        trusts: HashSet::new(),
        keys: HashSet::new(),
    };
    for group in keyfile.groups() {
        match classify(group)? {
            Some(Group::Server) => server = Some(group),
            Some(Group::Client(name)) => clients.push((name, group)),
            Some(Group::Trust(name)) => {
                names.trusts.insert(name);
            }
            Some(Group::Key(name)) => {
                names.keys.insert(name);
            }
            None => {}
        }
    }

    let server = match server {
        Some(group) => parse_server(keyfile, group, &names, repo_dir)?,
        None => ServerSettings::default(),
    };
    let mut groups = Vec::with_capacity(clients.len());
    for (name, group) in clients {
        groups.push(parse_client(keyfile, name, group, &names, own_id)?);
    }
    if groups.is_empty() {
        groups = implicit_groups();
    }
    let by_item = index(&groups);
    check_overlap(&groups, &by_item)?;
    let summaries = summary_digests(&groups, &by_item, own_id);
    Ok(ClientAccess {
        collection_id: own_id.map(str::to_owned),
        server,
        groups,
        by_item,
        summaries,
    })
}

/// Returns the group that `group` names, or `None` for a group outside the
/// extensions.
///
/// If the name starts with `ex-ostrya ` and has no known shape, the function
/// returns [`Error::InvalidFormat`]. It also refuses `[ex-ostrya receive]` and
/// each `[ex-ostrya receive "PATTERN"]`, with a message that names the client
/// group in their place.
pub(crate) fn classify(group: &str) -> Result<Option<Group<'_>>> {
    if group == SERVER_GROUP {
        return Ok(Some(Group::Server));
    }
    if group == RECEIVE_GROUP || group.starts_with(RECEIVE_PREFIX) {
        return Err(Error::InvalidFormat(format!(
            "[{group}] is a group of the removed receive policy; a client group \
             [ex-ostrya client \"NAME\"] states the rights of a push"
        )));
    }
    if let Some(rest) = group.strip_prefix(CLIENT_PREFIX) {
        return quoted(group, rest).map(|name| Some(Group::Client(name)));
    }
    if let Some(rest) = group.strip_prefix(TRUST_PREFIX) {
        return quoted(group, rest).map(|name| Some(Group::Trust(name)));
    }
    if let Some(rest) = group.strip_prefix(KEY_PREFIX) {
        return quoted(group, rest).map(|name| Some(Group::Key(name)));
    }
    if group.starts_with(RESERVED_PREFIX) {
        return Err(Error::InvalidFormat(format!(
            "[{group}] is not a server, client, trust, or key group"
        )));
    }
    Ok(None)
}

/// Returns the quoted part of a group name.
///
/// `rest` is the text after the opening `"`. If the part does not end the
/// name, is empty, or holds a `"` or a control character, the function
/// returns [`Error::InvalidFormat`].
fn quoted<'a>(group: &str, rest: &'a str) -> Result<&'a str> {
    match rest.strip_suffix('"') {
        Some(name)
            if !name.is_empty() && !name.contains('"') && !name.contains(char::is_control) =>
        {
            Ok(name)
        }
        _ => Err(Error::InvalidFormat(format!(
            "malformed group name [{group}]: the quoted name ends the group name, is \
             not empty, and holds no '\"' and no control character"
        ))),
    }
}

/// Refuses a key of `group` outside `known`.
fn check_keys(keyfile: &KeyFile, group: &str, known: &[&str]) -> Result<()> {
    match keyfile.keys(group).find(|key| !known.contains(key)) {
        Some(key) => Err(Error::InvalidFormat(format!(
            "[{group}] holds the unknown key '{key}'"
        ))),
        None => Ok(()),
    }
}

/// Returns the error for a malformed item of the list key `key`.
fn malformed_item(group: &str, key: &str, text: &str, why: &str) -> Error {
    Error::InvalidFormat(format!("malformed [{group}] {key} item '{text}': {why}"))
}

/// Reads the client group `group`, whose quoted name is `name`.
fn parse_client(
    keyfile: &KeyFile,
    name: &str,
    group: &str,
    names: &Names<'_>,
    own_id: Option<&str>,
) -> Result<ClientGroup> {
    if keyfile.get_value(group, "collection").is_some() {
        return Err(Error::InvalidFormat(format!(
            "[{group}] holds the removed key 'collection'; an allow item or a deny item \
             names the refs of a collection as @ID:PATTERN"
        )));
    }
    check_keys(keyfile, group, CLIENT_KEYS)?;

    let mut auth: Vec<AuthItem> = Vec::new();
    for text in keyfile.get_string_list(group, "auth")?.unwrap_or_default() {
        let item = parse_item(&text).map_err(|why| malformed_item(group, "auth", &text, &why))?;
        if !auth.contains(&item) {
            auth.push(item);
        }
    }
    if auth.is_empty() {
        return Err(Error::InvalidFormat(format!(
            "[{group}] needs auth, a list of one or more items"
        )));
    }

    let mut rules = NamespaceRules::default();
    for text in keyfile.get_string_list(group, "allow")?.unwrap_or_default() {
        let (id, item) =
            parse_allow_item(&text).map_err(|why| malformed_item(group, "allow", &text, &why))?;
        rules_of(&mut rules, id, own_id).allow.push(item);
    }
    for text in keyfile.get_string_list(group, "deny")?.unwrap_or_default() {
        let (id, pattern) =
            parse_deny_item(&text).map_err(|why| malformed_item(group, "deny", &text, &why))?;
        rules_of(&mut rules, id, own_id).deny.push(pattern);
    }

    if keyfile.get_value(group, "tls-accept-claim").is_some() && !auth.iter().any(AuthItem::is_tls)
    {
        return Err(Error::InvalidFormat(format!(
            "[{group}] holds tls-accept-claim, and has no tls:*, tls:NAME, or \
             tls-sha256:HEX item"
        )));
    }
    let tls_accept_claim = keyfile
        .get_bool(group, "tls-accept-claim")?
        .unwrap_or(false);
    let summary = keyfile.get_bool(group, "summary")?.unwrap_or(false);
    if tls_accept_claim && summary {
        return Err(Error::InvalidFormat(format!(
            "[{group}] sets tls-accept-claim=true and summary=true; the claims of a \
             client certificate cannot give the refs of a summary"
        )));
    }

    let verify_trust = parse_verify(keyfile, group, names)?;
    let allow_unsigned = match keyfile.get_bool(group, "allow-unsigned")? {
        Some(false) if verify_trust.is_none() => {
            return Err(Error::InvalidFormat(format!(
                "[{group}] sets allow-unsigned=false, which needs verify"
            )));
        }
        Some(value) => value,
        None => verify_trust.is_none(),
    };

    Ok(ClientGroup {
        name: name.to_owned(),
        auth,
        rules,
        tls_accept_claim,
        verify_trust,
        allow_unsigned,
        sign: key_list(keyfile, group, "sign", names)?.unwrap_or_default(),
        allow_privileged: keyfile
            .get_bool(group, "allow-privileged")?
            .unwrap_or(false),
        disable_verify_bindings: keyfile
            .get_bool(group, "disable-verify-bindings")?
            .unwrap_or(false),
        summary,
        implicit: false,
    })
}

/// Returns the rules of `rules` that an item with the collection id `id`
/// joins. An item with no id and an item of the own collection id `own_id`
/// join the rules of the local refs.
fn rules_of<'a>(
    rules: &'a mut NamespaceRules,
    id: Option<String>,
    own_id: Option<&str>,
) -> &'a mut AccessRules {
    match id {
        Some(id) if Some(id.as_str()) != own_id => rules.collections.entry(id).or_default(),
        _ => &mut rules.local,
    }
}

/// Reads the `verify` key of `group`: the name of a trust group, or `None`.
fn parse_verify(keyfile: &KeyFile, group: &str, names: &Names<'_>) -> Result<Option<String>> {
    let Some(raw) = keyfile.get_string(group, "verify")? else {
        return Ok(None);
    };
    if let Some(name) = raw.strip_prefix("trust:").filter(|name| !name.is_empty()) {
        if !names.trusts.contains(name) {
            return Err(Error::InvalidFormat(format!(
                "[{group}] verify={raw} names no [{TRUST_PREFIX}{name}\"] group"
            )));
        }
        return Ok(Some(name.to_owned()));
    }
    if raw.starts_with("remote:") {
        return Err(Error::InvalidFormat(format!(
            "[{group}] verify={raw}: the remote:NAME form is removed; name a trust \
             group with trust:NAME"
        )));
    }
    Err(Error::InvalidFormat(format!(
        "malformed [{group}] verify value '{raw}': the value is trust:NAME; leave out \
         the key for no verification"
    )))
}

/// Reads the list of key group names in the key `key` of `group`.
///
/// Each entry must name a key group. An entry that occurs twice counts once.
/// An empty value is refused.
fn key_list(
    keyfile: &KeyFile,
    group: &str,
    key: &str,
    names: &Names<'_>,
) -> Result<Option<Vec<String>>> {
    let Some(entries) = keyfile.get_string_list(group, key)? else {
        return Ok(None);
    };
    if entries.is_empty() {
        return Err(Error::InvalidFormat(format!(
            "[{group}] {key} is empty; remove the key or name a key group"
        )));
    }
    let mut kept: Vec<String> = Vec::new();
    for name in entries {
        if !names.keys.contains(name.as_str()) {
            return Err(Error::InvalidFormat(format!(
                "[{group}] {key} names the key group '{name}', and no \
                 [{KEY_PREFIX}{name}\"] group exists"
            )));
        }
        if !kept.contains(&name) {
            kept.push(name);
        }
    }
    Ok(Some(kept))
}

/// Returns the implicit group of a config with no client group:
/// `auth=anonymous`, `summary=true`, and `r` on each ref of each namespace.
pub(super) fn implicit_groups() -> Vec<ClientGroup> {
    let read_all = AccessRules {
        allow: vec![AllowItem {
            modes: AccessModes::READ,
            pattern: RefPattern::parse("**").expect("`**` is a valid pattern"),
        }],
        deny: Vec::new(),
    };
    vec![ClientGroup {
        name: "anonymous".to_owned(),
        auth: vec![AuthItem::Anonymous],
        rules: NamespaceRules {
            local: read_all.clone(),
            collections: BTreeMap::new(),
            other: Some(read_all),
        },
        tls_accept_claim: false,
        verify_trust: None,
        allow_unsigned: true,
        sign: Vec::new(),
        allow_privileged: false,
        disable_verify_bindings: false,
        summary: true,
        implicit: true,
    }]
}

/// Returns the indexes in `groups` of the groups that carry each item, in
/// the order of the config.
pub(super) fn index(groups: &[ClientGroup]) -> HashMap<AuthItem, Vec<usize>> {
    let mut by_item: HashMap<AuthItem, Vec<usize>> = HashMap::new();
    for (i, group) in groups.iter().enumerate() {
        for item in &group.auth {
            by_item.entry(item.clone()).or_default().push(i);
        }
    }
    by_item
}

/// Returns the summary files of each auth item that has a summary: each
/// item that a group with `summary=true` carries.
///
/// `by_item` is the index of [`index`], and `own_id` is `[core]
/// collection-id`. The digest is the SHA-256 digest of [`access_text`] of the
/// group of the item.
pub(super) fn summary_digests(
    groups: &[ClientGroup],
    by_item: &HashMap<AuthItem, Vec<usize>>,
    own_id: Option<&str>,
) -> HashMap<AuthItem, SummaryFiles> {
    by_item
        .iter()
        .filter_map(|(item, carriers)| {
            let group = &groups[*carriers.first()?];
            if !group.summary {
                return None;
            }
            let text = access_text(own_id, group);
            let files = SummaryFiles {
                digest: Checksum::sha256(text.as_bytes()),
                stem: summary_stem(item),
            };
            Some((item.clone(), files))
        })
        .collect()
}

/// Returns the text of the access digest of an item whose group is `group`,
/// in a repository whose own collection id is `own_id`.
///
/// The text is the line `collection-id=ID`, with an empty `ID` when
/// `own_id` is `None`. Then come four lines for each namespace of the group,
/// in the byte-wise order of their `namespace=` lines: the local refs, each
/// collection with one or more items, and each other collection in the
/// implicit group.
///
/// - `namespace=NS`: empty for the local refs, the collection id for a
///   collection, and `*` for each other collection.
/// - `allow=ITEMS`: the allow items in the form `MODES:PATTERN`, with the
///   modes in the order `rwctd`, each distinct item one time, sorted
///   byte-wise and joined by `;`.
/// - `deny=PATTERNS`: the deny patterns, in the same way.
/// - `summary=true` or `summary=false`: the value of `summary`.
///
/// Each line ends with a newline. The text holds no group name.
pub(super) fn access_text(own_id: Option<&str>, group: &ClientGroup) -> String {
    fn joined(mut items: Vec<String>) -> String {
        items.sort();
        items.dedup();
        items.join(";")
    }
    let rules = &group.rules;
    let mut namespaces: Vec<(&str, &AccessRules)> = vec![("", &rules.local)];
    namespaces.extend(rules.collections.iter().map(|(id, r)| (id.as_str(), r)));
    namespaces.extend(rules.other.iter().map(|r| ("*", r)));
    namespaces.sort_by_key(|&(namespace, _)| namespace);
    let mut text = format!("collection-id={}\n", own_id.unwrap_or(""));
    for (namespace, rules) in namespaces {
        let allow = joined(rules.allow.iter().map(ToString::to_string).collect());
        let deny = joined(
            rules
                .deny
                .iter()
                .map(|pattern| pattern.as_str().to_owned())
                .collect(),
        );
        let summary = group.summary;
        text.push_str(&format!(
            "namespace={namespace}\nallow={allow}\ndeny={deny}\nsummary={summary}\n"
        ));
    }
    text
}

/// Refuses two groups that carry one item.
///
/// `by_item` is the index of [`index`]. The error names the first such pair
/// in the order of the config, and the first item of the first group that
/// the second group carries.
fn check_overlap(groups: &[ClientGroup], by_item: &HashMap<AuthItem, Vec<usize>>) -> Result<()> {
    for (i, first) in groups.iter().enumerate() {
        let found = first
            .auth
            .iter()
            .filter_map(|item| {
                let carriers = &by_item[item];
                let later = &carriers[carriers.partition_point(|&j| j <= i)..];
                later.first().map(|&j| (j, item))
            })
            .min_by_key(|&(j, _)| j);
        if let Some((j, item)) = found {
            return Err(Error::InvalidFormat(format!(
                "{} and {} both carry the item {item}; one client group carries each item",
                first.header(),
                groups[j].header()
            )));
        }
    }
    Ok(())
}

/// Reads the server group `group`.
fn parse_server(
    keyfile: &KeyFile,
    group: &str,
    names: &Names<'_>,
    repo_dir: &Path,
) -> Result<ServerSettings> {
    check_keys(keyfile, group, SERVER_KEYS)?;

    let listen = match keyfile.get_string_list(group, "listen")? {
        None => None,
        Some(entries) if entries.is_empty() => {
            return Err(Error::InvalidFormat(format!(
                "[{group}] listen is empty; remove the key for the default address"
            )));
        }
        Some(entries) => Some(
            entries
                .iter()
                .map(|text| {
                    text.parse::<SocketAddr>().map_err(|_| {
                        malformed_item(
                            group,
                            "listen",
                            text,
                            "the item is ADDR:PORT, an IP address and a port",
                        )
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        ),
    };

    let trusted_proxy = match keyfile.get_string_list(group, "trusted-proxy")? {
        None => None,
        Some(entries) if entries.is_empty() => {
            return Err(Error::InvalidFormat(format!(
                "[{group}] trusted-proxy is empty; remove the key or name a network"
            )));
        }
        Some(entries) => Some(
            entries
                .iter()
                .map(|text| {
                    parse_net(text)
                        .map_err(|why| malformed_item(group, "trusted-proxy", text, &why))
                })
                .collect::<Result<Vec<_>>>()?,
        ),
    };

    let trusted_proxy_header = match keyfile.get_string(group, "trusted-proxy-header")? {
        None => None,
        Some(text) => Some(ForwardedHeader::parse(&text).map_err(|_| {
            Error::InvalidFormat(format!(
                "malformed [{group}] trusted-proxy-header value '{text}': the value is \
                 forwarded, x-forwarded-for, or x-real-ip"
            ))
        })?),
    };

    let trusted_proxy_client_cert = keyfile.get_string(group, "trusted-proxy-client-cert")?;
    if let Some(name) = &trusted_proxy_client_cert
        && !is_header_name(name)
    {
        return Err(Error::InvalidFormat(format!(
            "malformed [{group}] trusted-proxy-client-cert value '{name}': the value is \
             a header name, one or more letters, digits, and the characters \
             !#$%&'*+-.^_`|~"
        )));
    }

    Ok(ServerSettings {
        listen,
        tls_cert: path(keyfile, group, "tls-cert", repo_dir)?,
        tls_key: path(keyfile, group, "tls-key", repo_dir)?,
        tls_client_ca: path(keyfile, group, "tls-client-ca", repo_dir)?,
        trusted_proxy,
        trusted_proxy_header,
        trusted_proxy_client_cert,
        proxy_protocol: keyfile.get_bool(group, "proxy-protocol")?,
        allow_cleartext_credentials: keyfile.get_bool(group, "allow-cleartext-credentials")?,
        session_timeout: positive(keyfile, group, "session-timeout", u64::MAX)?,
        max_sessions: positive(keyfile, group, "max-sessions", u64::MAX)?,
        parallel_uploads: positive(keyfile, group, "parallel-uploads", 31)?
            .map(|n| u32::try_from(n).expect("the value is at most 31")),
        body_timeout: positive(keyfile, group, "body-timeout", u64::MAX)?,
        sign_summary: key_list(keyfile, group, "sign-summary", names)?,
    })
}

/// Reads the path key `key` of `group`.
///
/// A relative path is joined onto `repo_dir`. An empty value is refused.
fn path(keyfile: &KeyFile, group: &str, key: &str, repo_dir: &Path) -> Result<Option<PathBuf>> {
    match keyfile.get_string(group, key)? {
        None => Ok(None),
        Some(value) if value.is_empty() => Err(Error::InvalidFormat(format!(
            "[{group}] {key} is empty; remove the key or name a file"
        ))),
        Some(value) => Ok(Some(repo_dir.join(value))),
    }
}

/// Reads the integer key `key` of `group`, which must be from 1 to `max`.
fn positive(keyfile: &KeyFile, group: &str, key: &str, max: u64) -> Result<Option<u64>> {
    match keyfile.get_integer(group, key)? {
        None => Ok(None),
        Some(value) => match u64::try_from(value) {
            Ok(n) if (1..=max).contains(&n) => Ok(Some(n)),
            _ if max == u64::MAX => Err(Error::InvalidFormat(format!(
                "[{group}] {key} is {value}; the value is a positive integer"
            ))),
            _ => Err(Error::InvalidFormat(format!(
                "[{group}] {key} is {value}; the value is 1 to {max}"
            ))),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use crate::access::{IpNet, Namespace};

    const CORE: &str = "[core]\nrepo_version=1\nmode=archive-z2\n";
    const HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn try_access(text: &str) -> Result<ClientAccess> {
        let config = RepoConfig::parse(&format!("{CORE}{text}"))?;
        read(&config, Path::new("/srv/repo"))
    }

    fn access(text: &str) -> ClientAccess {
        try_access(text).unwrap()
    }

    /// Returns the one client group of `keys`, in a group named `c`, with the
    /// other groups of `extra`.
    fn client(keys: &str, extra: &str) -> Result<ClientGroup> {
        let access = try_access(&format!("[ex-ostrya client \"c\"]\n{keys}{extra}"))?;
        Ok(access.groups()[0].clone())
    }

    /// Returns the message of an [`Error::InvalidFormat`].
    fn refused(result: Result<impl std::fmt::Debug>) -> String {
        match result {
            Err(Error::InvalidFormat(message)) => message,
            other => panic!("{other:?}"),
        }
    }

    fn server(keys: &str, extra: &str) -> Result<ServerSettings> {
        Ok(try_access(&format!("[ex-ostrya server]\n{keys}{extra}"))?
            .server()
            .clone())
    }

    /// `classify` tells the shapes apart, and the groups outside the
    /// extensions pass through.
    #[test]
    fn the_group_shapes_are_told_apart() {
        assert!(matches!(
            classify("ex-ostrya server").unwrap(),
            Some(Group::Server)
        ));
        assert!(matches!(
            classify("ex-ostrya client \"a b\"").unwrap(),
            Some(Group::Client("a b"))
        ));
        assert!(matches!(
            classify("ex-ostrya client \"a:b\"").unwrap(),
            Some(Group::Client("a:b"))
        ));
        assert!(matches!(
            classify("ex-ostrya trust \"t\"").unwrap(),
            Some(Group::Trust("t"))
        ));
        assert!(matches!(
            classify("ex-ostrya key \"k\"").unwrap(),
            Some(Group::Key("k"))
        ));
        for group in ["ex-ostrya", "ex-ostryax", "core", "remote \"origin\""] {
            assert!(classify(group).unwrap().is_none(), "{group}");
        }
    }

    /// Each other name that starts with `ex-ostrya ` is refused.
    #[test]
    fn the_other_reserved_names_are_refused() {
        for group in [
            "ex-ostrya servers",
            "ex-ostrya server \"x\"",
            "ex-ostrya client",
            "ex-ostrya client c",
            "ex-ostrya client \"\"",
            "ex-ostrya client \"a\"b\"",
            "ex-ostrya client \"a\tb\"",
            "ex-ostrya client \"c\" ",
            "ex-ostrya clients \"c\"",
            "ex-ostrya trust \"\"",
            "ex-ostrya key \"a\"\"",
            "ex-ostrya receive \"\"",
            "ex-ostrya bogus",
            "ex-ostrya ",
        ] {
            let Err(err) = classify(group) else {
                panic!("{group:?} was accepted");
            };
            assert!(matches!(err, Error::InvalidFormat(_)), "{group:?}: {err}");
        }
    }

    /// `[ex-ostrya receive]` and each `[ex-ostrya receive "PATTERN"]` are
    /// refused, and the message names the client group in their place.
    #[test]
    fn the_receive_groups_are_refused() {
        for group in [
            "ex-ostrya receive",
            "ex-ostrya receive \"a/**\"",
            "ex-ostrya receive \"\"",
        ] {
            let message = refused(try_access(&format!(
                "[{group}]\naccept=true\n[ex-ostrya client \"c\"]\nauth=anonymous\n"
            )));
            assert!(message.starts_with(&format!("[{group}] ")), "{message}");
            assert!(message.contains("[ex-ostrya client \"NAME\"]"), "{message}");
        }
        let message = refused(try_access("[ex-ostrya receivex]\n"));
        assert!(!message.contains("receive policy"), "{message}");
    }

    /// A key that a client group or the server group does not take is
    /// refused.
    #[test]
    fn an_unknown_key_is_refused() {
        let message = refused(client("auth=anonymous\nowner=x\n", ""));
        assert!(message.contains("unknown key 'owner'"), "{message}");
        let message = refused(server("accept=true\n", ""));
        assert!(message.contains("unknown key 'accept'"), "{message}");
        let message = refused(server("allow-privileged=true\n", ""));
        assert!(message.contains("allow-privileged"), "{message}");
    }

    /// A trust group and a key group are recorded by name, and their keys are
    /// not read.
    #[test]
    fn trust_and_key_groups_are_recorded_by_name() {
        let group = client(
            "auth=anonymous\nverify=trust:t\nsign=k\n",
            "[ex-ostrya trust \"t\"]\nany=thing\n[ex-ostrya key \"k\"]\nother=1\n",
        )
        .unwrap();
        assert_eq!(group.verify_trust(), Some("t"));
        assert_eq!(group.sign(), ["k"]);
    }

    /// `auth` is necessary, and an empty list is refused.
    #[test]
    fn auth_is_necessary() {
        for keys in ["", "auth=\n", "allow=r:**\n"] {
            let message = refused(client(keys, ""));
            assert!(message.contains("needs auth"), "{keys:?}: {message}");
        }
        for keys in ["auth=;\n", "auth=anonymous;;ssh:a\n"] {
            let message = refused(client(keys, ""));
            assert!(message.contains("auth item ''"), "{keys:?}: {message}");
        }
    }

    /// An auth item that occurs two times in one group counts one time, also
    /// in two spellings of one network.
    #[test]
    fn a_repeated_auth_item_counts_once() {
        let group = client(
            "auth=ssh:a;anonymous;ssh:a;net:2001:db8::/56;net:2001:0db8::/56\n",
            "",
        )
        .unwrap();
        let texts: Vec<String> = group.auth().iter().map(ToString::to_string).collect();
        assert_eq!(texts, ["ssh:a", "anonymous", "net:2001:db8::/56"]);
    }

    /// A malformed auth item is refused with the group, the key, and the
    /// item in the message.
    #[test]
    fn a_malformed_auth_item_names_the_group_and_the_key() {
        for item in [
            format!("token:{HEX}"),
            format!("cert:{HEX}"),
            " anonymous".to_owned(),
            " ssh:b".to_owned(),
            "ssh:b ".to_owned(),
            "ssh: b".to_owned(),
            "net:10.0.0.1/24".to_owned(),
            "net:::ffff:10.0.0.0/104".to_owned(),
        ] {
            let message = refused(client(&format!("auth=ssh:a;{item}\n"), ""));
            assert!(
                message.starts_with(&format!(
                    "malformed [ex-ostrya client \"c\"] auth item '{item}': "
                )),
                "{message}"
            );
        }
        let message = refused(client(&format!("auth=basic-sha256:a:b:{HEX}\n"), ""));
        assert!(message.contains("USER"), "{message}");
    }

    /// The key file removes the white space before a value and keeps the
    /// white space after it. So white space after the last item reaches the
    /// item, and the item is refused.
    #[test]
    fn white_space_after_an_auth_value_is_refused() {
        for keys in [
            "auth=ssh:user \n",
            "auth= ssh:user\tx \n",
            "auth=tls:n \n",
            "auth=\\sssh:user\n",
            "auth=ssh:\\suser\n",
            &format!("auth=basic-sha256:ci :{HEX}\n"),
        ] {
            let message = refused(client(keys, ""));
            assert!(
                message.starts_with("malformed [ex-ostrya client \"c\"] auth item '"),
                "{keys:?}: {message}"
            );
        }
        let group = client("auth=  ssh:user\n", "").unwrap();
        assert_eq!(group.auth(), [AuthItem::Ssh("user".into())]);
    }

    /// The key `collection` is refused with any value, and the message names
    /// the form `@ID:PATTERN`.
    #[test]
    fn the_collection_key_is_refused() {
        for value in ["*", "a.b", "a.b;c.d", "", "fresh"] {
            let message = refused(client(&format!("auth=anonymous\ncollection={value}\n"), ""));
            assert!(
                message.starts_with("[ex-ostrya client \"c\"] holds the removed key 'collection'"),
                "{message}"
            );
            assert!(message.contains("@ID:PATTERN"), "{message}");
        }
    }

    /// An allow item and a deny item with `@ID:` join the rules of the
    /// collection `ID`. `MODES` comes before `@ID:`.
    #[test]
    fn an_item_with_an_id_joins_its_collection() {
        let group = client(
            "auth=anonymous\nallow=@a.b:os/**;wd:@a.b:os/x;r:main;t:@c.d:**\n\
             deny=@a.b:os/secret;secret\n",
            "",
        )
        .unwrap();
        let texts = |rules: &AccessRules| -> (Vec<String>, Vec<String>) {
            (
                rules.allow.iter().map(ToString::to_string).collect(),
                rules.deny.iter().map(|p| p.as_str().to_owned()).collect(),
            )
        };
        let rules = group.rules();
        assert_eq!(
            texts(&rules.local),
            (vec!["r:main".into()], vec!["secret".into()])
        );
        assert_eq!(
            texts(&rules.collections["a.b"]),
            (
                vec!["r:os/**".into(), "wd:os/x".into()],
                vec!["os/secret".into()]
            )
        );
        assert_eq!(
            texts(&rules.collections["c.d"]),
            (vec!["t:**".into()], vec![])
        );
        assert_eq!(rules.collections.len(), 2);
        let longest = format!("a.{}", "b".repeat(ostrya_core::MAX_COLLECTION_ID_LEN - 2));
        let group = client(&format!("auth=anonymous\nallow=@{longest}:a\n"), "").unwrap();
        assert!(group.rules().collections.contains_key(&longest));
    }

    /// An item of the own collection id joins the rules of the local refs.
    #[test]
    fn an_item_of_the_own_collection_id_is_local() {
        let config = RepoConfig::parse(&format!(
            "{CORE}collection-id=own.id\n\
             [ex-ostrya client \"c\"]\nauth=anonymous\nallow=w:@own.id:a;r:b\n\
             deny=@own.id:a/secret\n"
        ))
        .unwrap();
        let access = read(&config, Path::new("/r")).unwrap();
        let rules = access.groups()[0].rules();
        assert!(rules.collections.is_empty());
        let allow: Vec<String> = rules.local.allow.iter().map(ToString::to_string).collect();
        assert_eq!(allow, ["w:a", "r:b"]);
        assert_eq!(rules.local.deny[0].as_str(), "a/secret");
    }

    /// `allow` and `deny` read their items, and an absent or empty key gives
    /// no item.
    #[test]
    fn allow_and_deny_read_their_items() {
        let group = client(
            "auth=anonymous\nallow=os/**;rw:os/stable;dtcwr:x\ndeny=os/secret/**;y\n",
            "",
        )
        .unwrap();
        let local = &group.rules().local;
        let allow: Vec<String> = local.allow.iter().map(ToString::to_string).collect();
        assert_eq!(allow, ["r:os/**", "rw:os/stable", "rwctd:x"]);
        let deny: Vec<&str> = local.deny.iter().map(RefPattern::as_str).collect();
        assert_eq!(deny, ["os/secret/**", "y"]);
        for keys in ["auth=anonymous\n", "auth=anonymous\nallow=\ndeny=\n"] {
            let group = client(keys, "").unwrap();
            assert_eq!(group.rules(), &NamespaceRules::default(), "{keys:?}");
            assert!(group.rules().rights(&Namespace::Local, "a").is_empty());
        }
    }

    /// A malformed allow item or deny item names the group and the key.
    #[test]
    fn a_malformed_allow_or_deny_item_is_refused() {
        for (key, item) in [
            ("allow", "R:a"),
            ("allow", "rr:a"),
            ("allow", ":a"),
            ("allow", "r:"),
            ("allow", "r:origin:a"),
            ("allow", "r:a*"),
            ("deny", "!a"),
            ("deny", "a//b"),
            ("deny", "r:a"),
            ("allow", "@a.b:r:a"),
            ("allow", "r:@a.b"),
            ("allow", "@a.b:"),
            ("allow", "@:a"),
            ("allow", "@fresh:a"),
            ("allow", "r:@a..b:a"),
            ("allow", "@a.b:@c.d:a"),
            ("allow", "r:@a.b:@c.d:a"),
            ("deny", "@a.b"),
            ("deny", "@a.b:"),
            ("deny", "@1a.b:a"),
            ("deny", "!@a.b:a"),
            ("deny", "@a.b:!a"),
        ] {
            let message = refused(client(&format!("auth=anonymous\n{key}={item}\n"), ""));
            assert!(
                message.starts_with(&format!(
                    "malformed [ex-ostrya client \"c\"] {key} item '{item}': "
                )),
                "{message}"
            );
        }
    }

    /// `tls-accept-claim` needs a TLS item, whatever its value.
    #[test]
    fn tls_accept_claim_needs_a_tls_item() {
        for item in ["tls:*", "tls:n", &format!("tls-sha256:{HEX}")] {
            let group = client(&format!("auth={item}\ntls-accept-claim=true\n"), "").unwrap();
            assert!(group.tls_accept_claim(), "{item}");
            let group = client(&format!("auth={item}\n"), "").unwrap();
            assert!(!group.tls_accept_claim(), "{item}");
        }
        for value in ["true", "false", "0", "maybe", ""] {
            let message = refused(client(
                &format!("auth=anonymous;ssh:a;token-sha256:{HEX}\ntls-accept-claim={value}\n"),
                "",
            ));
            assert!(message.contains("tls-accept-claim"), "{value}: {message}");
        }
        let err = client("auth=tls:*\ntls-accept-claim=yes\n", "").unwrap_err();
        assert!(matches!(err, Error::Core(_)), "{err}");
    }

    /// `verify` takes `trust:NAME` of a trust group, and refuses each other
    /// form.
    #[test]
    fn verify_takes_a_trust_group() {
        let trust = "[ex-ostrya trust \"t\"]\n";
        let group = client("auth=anonymous\nverify=trust:t\n", trust).unwrap();
        assert_eq!(group.verify_trust(), Some("t"));
        let message = refused(client("auth=anonymous\nverify=trust:u\n", trust));
        assert!(
            message.contains("names no [ex-ostrya trust \"u\"]"),
            "{message}"
        );
        let message = refused(client("auth=anonymous\nverify=remote:origin\n", trust));
        assert!(message.contains("removed"), "{message}");
        for value in ["off", "trust:", "", "t", "Trust:t"] {
            let message = refused(client(&format!("auth=anonymous\nverify={value}\n"), trust));
            assert!(message.contains("malformed"), "{value:?}: {message}");
        }
    }

    /// `allow-unsigned` defaults to true without `verify` and to false with
    /// it, and `allow-unsigned=false` needs `verify`.
    #[test]
    fn allow_unsigned_has_two_defaults() {
        let trust = "[ex-ostrya trust \"t\"]\n";
        let cases = [
            ("", true),
            ("allow-unsigned=true\n", true),
            ("verify=trust:t\n", false),
            ("verify=trust:t\nallow-unsigned=true\n", true),
            ("verify=trust:t\nallow-unsigned=false\n", false),
        ];
        for (keys, want) in cases {
            let group = client(&format!("auth=anonymous\n{keys}"), trust).unwrap();
            assert_eq!(group.allow_unsigned(), want, "{keys:?}");
        }
        for value in ["false", "0"] {
            let message = refused(client(
                &format!("auth=anonymous\nallow-unsigned={value}\n"),
                trust,
            ));
            assert!(message.contains("needs verify"), "{message}");
        }
    }

    /// `sign` names key groups, each one time, and `allow-privileged` is a
    /// boolean that defaults to false.
    #[test]
    fn sign_and_allow_privileged() {
        let keys = "[ex-ostrya key \"a\"]\n[ex-ostrya key \"b\"]\n";
        let group = client("auth=anonymous\nsign=b;a;b\nallow-privileged=1\n", keys).unwrap();
        assert_eq!(group.sign(), ["b", "a"]);
        assert!(group.allow_privileged());
        let group = client("auth=anonymous\n", keys).unwrap();
        assert!(group.sign().is_empty());
        assert!(!group.allow_privileged());
        let message = refused(client("auth=anonymous\nsign=a;c\n", keys));
        assert!(message.contains("'c'"), "{message}");
        let message = refused(client("auth=anonymous\nsign=\n", keys));
        assert!(message.contains("sign is empty"), "{message}");
        let err = client("auth=anonymous\nallow-privileged=yes\n", "").unwrap_err();
        assert!(matches!(err, Error::Core(_)), "{err}");
    }

    /// `disable-verify-bindings` is a boolean that defaults to false.
    #[test]
    fn disable_verify_bindings_is_a_boolean() {
        let group = client("auth=anonymous\n", "").unwrap();
        assert!(!group.disable_verify_bindings());
        let group = client("auth=anonymous\ndisable-verify-bindings=true\n", "").unwrap();
        assert!(group.disable_verify_bindings());
        let group = client("auth=anonymous\ndisable-verify-bindings=false\n", "").unwrap();
        assert!(!group.disable_verify_bindings());
        let err = client("auth=anonymous\ndisable-verify-bindings=yes\n", "").unwrap_err();
        assert!(matches!(err, Error::Core(_)), "{err}");
    }

    /// `summary` is a boolean that defaults to false. The implicit group sets
    /// it.
    #[test]
    fn summary_is_a_boolean_that_defaults_to_false() {
        assert!(!client("auth=anonymous\n", "").unwrap().summary());
        assert!(
            client("auth=anonymous\nsummary=true\n", "")
                .unwrap()
                .summary()
        );
        assert!(
            !client("auth=anonymous\nsummary=false\n", "")
                .unwrap()
                .summary()
        );
        let err = client("auth=anonymous\nsummary=yes\n", "").unwrap_err();
        assert!(matches!(err, Error::Core(_)), "{err}");
        assert!(access("").groups().iter().all(ClientGroup::summary));
    }

    /// A group with `tls-accept-claim=true` refuses `summary=true`. Each other
    /// pair of values is accepted.
    #[test]
    fn the_claims_refuse_a_summary() {
        let message = refused(client(
            "auth=tls:*\ntls-accept-claim=true\nsummary=true\n",
            "",
        ));
        assert!(message.contains("tls-accept-claim=true"), "{message}");
        assert!(message.contains("summary=true"), "{message}");
        assert!(
            message.starts_with("[ex-ostrya client \"c\"] "),
            "{message}"
        );
        for keys in [
            "tls-accept-claim=true\nsummary=false\n",
            "tls-accept-claim=false\nsummary=true\n",
            "summary=true\n",
        ] {
            client(&format!("auth=tls:*\n{keys}"), "").unwrap();
        }
    }

    /// Returns the access digest of `item` under the client groups of `text`.
    fn digest(text: &str, item: &str) -> Option<Checksum> {
        access(text).summary_digest(&AuthItem::parse(item).unwrap())
    }

    /// The text of the implicit group holds the local refs, then each other
    /// collection, and the own collection id.
    #[test]
    fn the_access_text_of_the_implicit_group() {
        let groups = implicit_groups();
        let text = "namespace=\nallow=r:**\ndeny=\nsummary=true\n\
                    namespace=*\nallow=r:**\ndeny=\nsummary=true\n";
        assert_eq!(
            access_text(None, &groups[0]),
            format!("collection-id=\n{text}")
        );
        assert_eq!(
            access_text(Some("a.b"), &groups[0]),
            format!("collection-id=a.b\n{text}")
        );
        let want = Checksum::sha256(format!("collection-id=\n{text}").as_bytes());
        assert_eq!(digest("", "anonymous"), Some(want));
        assert_eq!(
            ClientAccess::implicit(None).summary_digest(&AuthItem::Anonymous),
            Some(want)
        );
        assert_eq!(
            ClientAccess::implicit(None).summary_files(&AuthItem::Anonymous),
            Some(&SummaryFiles {
                digest: want,
                stem: summary_stem(&AuthItem::Anonymous),
            })
        );
    }

    /// The allow items and the deny patterns of each namespace are sorted
    /// byte-wise, each one time. The namespaces come in byte-wise order, the
    /// local refs first, also with no item.
    #[test]
    fn the_access_text_is_sorted_and_has_each_item_one_time() {
        let access = access(
            "[ex-ostrya client \"b\"]\nauth=ssh:u\n\
             allow=r:@c.d:b;rw:@c.d:a;@c.d:b;wr:@c.d:a;d:@a.b:z\ndeny=@c.d:y;@c.d:x;@c.d:y\n\
             summary=true\n",
        );
        assert_eq!(
            access_text(None, &access.groups()[0]),
            "collection-id=\n\
             namespace=\nallow=\ndeny=\nsummary=true\n\
             namespace=a.b\nallow=d:z\ndeny=\nsummary=true\n\
             namespace=c.d\nallow=r:b;rw:a\ndeny=x;y\nsummary=true\n"
        );
    }

    /// A new group name keeps the digest. A change to `allow`, to `deny`, to
    /// the namespace of an item, to `summary`, or to `[core] collection-id`
    /// changes it. An item whose group has `summary=false` has no summary.
    #[test]
    fn the_access_digest_follows_the_rules_of_the_summary() {
        let config = |name: &str, rules: &str| {
            format!(
                "[ex-ostrya client \"{name}\"]\nauth=ssh:u;anonymous\n{rules}summary=true\n\
                 [ex-ostrya client \"ci\"]\nauth=ssh:ci\nallow=r:**\n"
            )
        };
        let rules = "allow=r:a/**;r:@c.d:**\ndeny=a/secret\n";
        let base = digest(&config("one", rules), "ssh:u").unwrap();
        assert_eq!(digest(&config("two", rules), "ssh:u"), Some(base));
        assert_eq!(digest(&config("one", rules), "anonymous"), Some(base));
        for changed in [
            config("one", "allow=r:a/**;r:b;r:@c.d:**\ndeny=a/secret\n"),
            config("one", "allow=rw:a/**;r:@c.d:**\ndeny=a/secret\n"),
            config("one", "allow=r:a/**;r:@c.d:**\ndeny=a/secret;a/hidden\n"),
            config("one", "allow=r:a/**;r:@c.d:**\n"),
            config("one", "allow=r:a/**;r:@c.d:**\ndeny=@c.d:a/secret\n"),
            config("one", "allow=r:a/**;r:@e.f:**\ndeny=a/secret\n"),
            config("one", "allow=r:@a.b:a/**;r:@c.d:**\ndeny=a/secret\n"),
        ] {
            assert_ne!(digest(&changed, "ssh:u"), Some(base), "{changed}");
        }
        assert_eq!(digest(&config("one", rules), "ssh:ci"), None);
        let with_id = RepoConfig::parse(&format!(
            "{CORE}collection-id=own.id\n{}",
            config("one", rules)
        ))
        .unwrap();
        let own = read(&with_id, Path::new("/r")).unwrap();
        assert_ne!(
            own.summary_digest(&AuthItem::parse("ssh:u").unwrap()),
            Some(base)
        );
    }

    /// An item of the own collection id gives the digest of the same item
    /// with no `@ID:`.
    #[test]
    fn an_item_of_the_own_collection_id_keeps_the_digest() {
        let digest_of = |allow: &str| {
            let config = RepoConfig::parse(&format!(
                "{CORE}collection-id=own.id\n\
                 [ex-ostrya client \"c\"]\nauth=anonymous\nallow={allow}\nsummary=true\n"
            ))
            .unwrap();
            read(&config, Path::new("/r"))
                .unwrap()
                .summary_digest(&AuthItem::Anonymous)
        };
        assert_eq!(digest_of("r:@own.id:a"), digest_of("r:a"));
        assert_ne!(digest_of("r:@a.b:a"), digest_of("r:a"));
    }

    /// The server keys parse to their values, and a relative path is joined
    /// onto the repository directory.
    #[test]
    fn the_server_keys_parse() {
        let settings = server(
            "listen=0.0.0.0:8443;[::1]:0\n\
             tls-cert=certs/server.pem\n\
             tls-key=/etc/ostrya/server.key\n\
             tls-client-ca=~/ca.pem\n\
             trusted-proxy=10.0.0.0/24;2001:db8::1\n\
             trusted-proxy-header=forwarded\n\
             trusted-proxy-client-cert=X-SSL-Client-Cert\n\
             proxy-protocol=true\n\
             allow-cleartext-credentials=0\n\
             session-timeout=600\n\
             max-sessions=1\n\
             parallel-uploads=31\n\
             body-timeout=30\n\
             sign-summary=k;k\n",
            "[ex-ostrya key \"k\"]\n",
        )
        .unwrap();
        assert_eq!(
            settings.listen,
            Some(vec![
                "0.0.0.0:8443".parse().unwrap(),
                "[::1]:0".parse().unwrap()
            ])
        );
        assert_eq!(
            settings.tls_cert,
            Some(PathBuf::from("/srv/repo/certs/server.pem"))
        );
        assert_eq!(
            settings.tls_key,
            Some(PathBuf::from("/etc/ostrya/server.key"))
        );
        assert_eq!(
            settings.tls_client_ca,
            Some(PathBuf::from("/srv/repo/~/ca.pem"))
        );
        let proxies = settings.trusted_proxy.as_ref().unwrap();
        assert_eq!(proxies.len(), 2);
        assert!(proxies[0].contains("10.0.0.7".parse::<IpAddr>().unwrap()));
        assert_eq!(proxies[1], IpNet::parse("2001:db8::1/128").unwrap());
        assert_eq!(
            settings.trusted_proxy_header,
            Some(ForwardedHeader::Forwarded)
        );
        assert_eq!(
            settings.trusted_proxy_client_cert.as_deref(),
            Some("X-SSL-Client-Cert")
        );
        assert_eq!(settings.proxy_protocol, Some(true));
        assert_eq!(settings.allow_cleartext_credentials, Some(false));
        assert_eq!(settings.session_timeout, Some(600));
        assert_eq!(settings.max_sessions, Some(1));
        assert_eq!(settings.parallel_uploads, Some(31));
        assert_eq!(settings.body_timeout, Some(30));
        assert_eq!(settings.sign_summary, Some(vec!["k".to_owned()]));
    }

    /// An absent server group and an empty one give no value.
    #[test]
    fn an_absent_server_key_gives_none() {
        assert_eq!(server("", "").unwrap(), ServerSettings::default());
        assert_eq!(access("").server(), &ServerSettings::default());
    }

    /// The malformed server values are refused.
    #[test]
    fn the_malformed_server_values_are_refused() {
        for keys in [
            "listen=\n",
            "listen=localhost:8080\n",
            "listen=127.0.0.1\n",
            "listen=::1:80\n",
            "listen=127.0.0.1:80; [::1]:80\n",
            "tls-cert=\n",
            "tls-key=\n",
            "tls-client-ca=\n",
            "trusted-proxy=\n",
            "trusted-proxy=;\n",
            "trusted-proxy=10.0.0.1/24\n",
            "trusted-proxy=fe80::1%eth0\n",
            "trusted-proxy=::ffff:10.0.0.0/104\n",
            "trusted-proxy-client-cert=\n",
            "trusted-proxy-client-cert=X Client\n",
            "trusted-proxy-client-cert=X:Client\n",
            "trusted-proxy-header=\n",
            "trusted-proxy-header=X-Forwarded-For\n",
            "trusted-proxy-header=x-forwarded-proto\n",
            "trusted-proxy-header=forwarded;x-real-ip\n",
            "session-timeout=0\n",
            "session-timeout=-1\n",
            "max-sessions=0\n",
            "body-timeout=0\n",
            "parallel-uploads=0\n",
            "parallel-uploads=32\n",
            "sign-summary=nokey\n",
            "sign-summary=\n",
        ] {
            refused(server(keys, "[ex-ostrya key \"k\"]\n"));
        }
        for key in ["listen", "trusted-proxy", "sign-summary"] {
            let message = refused(server(&format!("{key}=\n"), ""));
            assert!(message.contains(&format!("{key} is empty")), "{message}");
        }
        for keys in [
            "session-timeout=+5\n",
            "max-sessions=1.5\n",
            "parallel-uploads=0x4\n",
            "proxy-protocol=yes\n",
            "allow-cleartext-credentials=on\n",
        ] {
            let err = server(keys, "").unwrap_err();
            assert!(matches!(err, Error::Core(_)), "{keys:?}: {err}");
        }
    }

    /// The trust group of `verify` and the key groups of `sign` and
    /// `sign-summary` must exist.
    #[test]
    fn a_reference_to_a_missing_group_is_refused() {
        refused(client("auth=anonymous\nverify=trust:t\n", ""));
        refused(client("auth=anonymous\nsign=k\n", ""));
        refused(server("sign-summary=k\n", "[ex-ostrya trust \"k\"]\n"));
        refused(client(
            "auth=anonymous\nverify=trust:k\n",
            "[ex-ostrya key \"k\"]\n",
        ));
    }
}
