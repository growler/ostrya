//! The read rights of one identified client.

use std::borrow::Cow;
use std::sync::{Arc, OnceLock};

use ostrya_core::Checksum;

use super::{
    AccessModes, AccessRules, AuthItem, Claims, ClientAccess, Namespace, NamespaceRules,
    SummaryFiles,
};

/// The read rights of one identified client: the client groups, the auth
/// item of the client, and the claims of its client certificate.
///
/// The archive view, the ref listing, and a pull session take this value. A
/// server builds one value for each request or session, after it identified
/// the client. A clone shares the value.
///
/// # Rules
///
/// - `refs/heads/NAME` is in the local namespace. `refs/mirrors/ID/NAME` is
///   in the namespace of collection `ID`. When `ID` is `[core]
///   collection-id`, the path is in the local namespace.
/// - The client reads `NAME` when the group that carries its item
///   ([`ClientAccess::select`]) has `r` on `NAME` in the namespace. The
///   rules of the group are the rules that
///   [`ClientAccess::effective_rules`] gives with the claims. `w`, `c`, and
///   `t` include `r`.
/// - Each other path under `refs/` is never read, `refs/remotes/` included.
///   A directory under `refs/mirrors/` whose name fails the collection-id
///   rule has no rules, so the client reads no ref in it.
///
/// `summary` and `summary.sig` are the files of the summary of the item.
/// [`summary_digest`](ReadAccess::summary_digest) gives the access digest
/// that these files must match.
///
/// The value finds the group and computes the rules with the claims one
/// time, at their first use.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
///
/// use ostrya::config::RepoConfig;
/// use ostrya::access::{AuthItem, ClientAccess, ReadAccess};
///
/// let config = RepoConfig::parse(
///     "[core]\nrepo_version=1\nmode=archive-z2\ncollection-id=com.example.own\n\
///      [ex-ostrya client \"public\"]\nauth=anonymous\nallow=r:pub/**\n",
/// )?;
/// let access = Arc::new(ClientAccess::from_config(&config, "/srv/repo".as_ref())?);
/// let read = ReadAccess::new(access, AuthItem::Anonymous, None);
/// assert!(read.can_read_path("refs/heads/pub/main"));
/// assert!(read.can_read_path("refs/mirrors/com.example.own/pub/main"));
/// assert!(!read.can_read_path("refs/heads/secret"));
/// assert!(!read.can_read_path("refs/remotes/origin/pub/main"));
/// assert!(read.summary_digest().is_none());
/// # Ok::<(), ostrya::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct ReadAccess {
    inner: Arc<Reader>,
}

/// The state that each clone of a [`ReadAccess`] shares.
#[derive(Debug)]
struct Reader {
    access: Arc<ClientAccess>,
    item: Arc<AuthItem>,
    claims: Option<Arc<Claims>>,
    /// `true` for the rights of the summary of the item: a selected group
    /// with `summary=false` gives no right.
    summary_only: bool,
    /// The rules of the group of the item, or `None` with no group. The value
    /// finds them at their first use.
    rules: OnceLock<Option<Rules>>,
}

/// The rules of the group of the item of a [`Reader`].
#[derive(Debug)]
enum Rules {
    /// The rules of the group at this index of the groups.
    Group(usize),
    /// The rules of the group with the rules of the claims in place of the
    /// rules of the group for each namespace of the claims.
    Claimed(NamespaceRules),
}

impl ReadAccess {
    /// Returns the read rights of the client with the auth item `item` and
    /// the claims `claims`, under the client groups of `access`.
    ///
    /// `item` is an [`AuthItem`] or an `Arc` of one, which the value shares.
    /// `claims` are the claims of the client certificate that gave `item`.
    /// They apply only in a group with `tls-accept-claim=true`.
    pub fn new(
        access: Arc<ClientAccess>,
        item: impl Into<Arc<AuthItem>>,
        claims: Option<Arc<Claims>>,
    ) -> ReadAccess {
        ReadAccess {
            inner: Arc::new(Reader {
                access,
                item: item.into(),
                claims,
                summary_only: false,
                rules: OnceLock::new(),
            }),
        }
    }

    /// Returns the rights that give the refs of the summary of `item`.
    ///
    /// The group of the item is selected as for [`new`](ReadAccess::new).
    /// When that group has `summary=false`, the value reads no ref. The value
    /// takes no claims.
    pub(crate) fn for_summary(access: Arc<ClientAccess>, item: AuthItem) -> ReadAccess {
        ReadAccess {
            inner: Arc::new(Reader {
                access,
                item: Arc::new(item),
                claims: None,
                summary_only: true,
                rules: OnceLock::new(),
            }),
        }
    }

    /// Returns the client groups.
    pub fn access(&self) -> &ClientAccess {
        &self.inner.access
    }

    /// Returns the auth item of the client.
    pub fn item(&self) -> &AuthItem {
        &self.inner.item
    }

    /// Returns `true` if the client reads the ref `name` of `namespace`.
    ///
    /// A [`Collection`](Namespace::Collection) of `[core] collection-id` is
    /// the local namespace. An id that fails the collection-id rule gives
    /// `false`.
    pub fn can_read(&self, namespace: &Namespace, name: &str) -> bool {
        let rules = match namespace {
            Namespace::Collection(id) if !self.inner.access.is_own_collection(id) => {
                self.collection_rules(id)
            }
            _ => self.local_rules(),
        };
        rules.is_some_and(|rules| reads(rules, name))
    }

    /// Returns `true` if the client reads the file at `path` under `refs/`.
    ///
    /// `path` is relative to the repository root. `refs/heads/NAME` and
    /// `refs/mirrors/ID/NAME` give the answer of
    /// [`can_read`](ReadAccess::can_read) for `NAME`. Each other path gives
    /// `false`. The call reads no file.
    pub fn can_read_path(&self, path: &str) -> bool {
        let Some(rest) = path.strip_prefix("refs/") else {
            return false;
        };
        if let Some(name) = rest.strip_prefix("heads/") {
            return !name.is_empty() && self.can_read(&Namespace::Local, name);
        }
        if let Some(rest) = rest.strip_prefix("mirrors/")
            && let Some((id, name)) = rest.split_once('/')
            && !id.is_empty()
            && !name.is_empty()
        {
            return self.can_read(&Namespace::Collection(id.to_owned()), name);
        }
        false
    }

    /// Returns the access digest of the item of the client, or `None` if the
    /// item has no summary.
    ///
    /// The value is [`ClientAccess::summary_digest`] of the item.
    pub fn summary_digest(&self) -> Option<Checksum> {
        self.inner.access.summary_digest(&self.inner.item)
    }

    /// Returns the access digest of the item of the client and the stem of
    /// the names of its files, or `None` if the item has no summary.
    pub(crate) fn summary_files(&self) -> Option<&SummaryFiles> {
        self.inner.access.summary_files(&self.inner.item)
    }

    /// Returns `true` if the rules of the local namespace have an allow item
    /// that gives `r`. With `false`, the client reads no local ref.
    pub(crate) fn reads_local_refs(&self) -> bool {
        self.local_rules().is_some_and(AccessRules::gives_read)
    }

    /// Returns the rules of the group of the item in the namespace of the
    /// collection `id`, with the claims, or `None`.
    ///
    /// The result is `None` for `[core] collection-id`, which is the local
    /// namespace, for an id that fails the collection-id rule, and when the
    /// rules of the group name no ref of the collection.
    pub(crate) fn collection_rules(&self, id: &str) -> Option<&AccessRules> {
        if self.inner.access.is_own_collection(id) {
            return None;
        }
        self.group_rules()?.collection(id)
    }

    /// Returns the rules of the group of the item in the local namespace,
    /// with the claims, or `None` with no group.
    pub(crate) fn local_rules(&self) -> Option<&AccessRules> {
        self.group_rules().map(|rules| &rules.local)
    }

    /// Returns the rules of the group of the item, with the claims, or `None`
    /// with no group. The value finds them at the first call.
    fn group_rules(&self) -> Option<&NamespaceRules> {
        let access = &self.inner.access;
        let rules = self.inner.rules.get_or_init(|| {
            let index = access.select_index(&self.inner.item)?;
            let group = &access.groups()[index];
            if self.inner.summary_only && !group.summary() {
                return None;
            }
            let claims = self.inner.claims.as_deref();
            let rules = match access.effective_rules(group, claims) {
                Cow::Owned(rules) => Rules::Claimed(rules),
                Cow::Borrowed(_) => Rules::Group(index),
            };
            Some(rules)
        });
        match rules.as_ref()? {
            Rules::Group(index) => Some(access.groups()[*index].rules()),
            Rules::Claimed(rules) => Some(rules),
        }
    }
}

/// Returns `true` if `rules` give `r` on `name`.
pub(crate) fn reads(rules: &AccessRules, name: &str) -> bool {
    rules.rights(name).contains(AccessModes::READ)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::config::RepoConfig;

    /// The `[core]` group of each test config, with the own collection id
    /// `own.id`.
    const CORE: &str = "[core]\nrepo_version=1\nmode=archive-z2\ncollection-id=own.id\n";

    fn access(text: &str) -> Arc<ClientAccess> {
        let config = RepoConfig::parse(&format!("{CORE}{text}")).unwrap();
        Arc::new(ClientAccess::from_config(&config, Path::new("/srv/repo")).unwrap())
    }

    fn reader(text: &str, item: &str, claims: Option<&[&str]>) -> ReadAccess {
        let claims = claims.map(|uris| Arc::new(Claims::parse(uris.iter().copied()).unwrap()));
        ReadAccess::new(access(text), AuthItem::parse(item).unwrap(), claims)
    }

    fn collection(id: &str) -> Namespace {
        Namespace::Collection(id.to_owned())
    }

    /// A group with `tls-accept-claim=true` takes the claims of a namespace
    /// in place of its rules there. With no claim of a namespace, the rules
    /// of the group apply there. A group with `tls-accept-claim=false`
    /// ignores the claims.
    #[test]
    fn effective_rules_take_the_claims_of_a_claim_group() {
        let groups = "[ex-ostrya client \"certs\"]\nauth=tls:*\ntls-accept-claim=true\n\
                      allow=r:group/**;r:@a.b:group/**\n\
                      [ex-ostrya client \"names\"]\nauth=tls:host\nallow=r:group/**\n";
        let claims: &[&str] = &["ostrya:ref:claim/**", "ostrya:ref:@a.b:other/**"];
        let certs = reader(groups, "tls:*", Some(claims));
        assert!(certs.can_read(&Namespace::Local, "claim/x"));
        assert!(!certs.can_read(&Namespace::Local, "group/x"));
        assert!(certs.can_read(&collection("a.b"), "other/x"));
        assert!(!certs.can_read(&collection("a.b"), "group/x"));
        let no_local = reader(groups, "tls:*", Some(&["ostrya:ref:@a.b:x"]));
        assert!(no_local.can_read(&Namespace::Local, "group/x"));
        assert!(!no_local.can_read(&Namespace::Local, "claim/x"));
        assert!(no_local.can_read_path("refs/mirrors/a.b/x"));
        let own = reader(groups, "tls:*", Some(&["ostrya:ref:@own.id:claim/**"]));
        assert!(own.can_read(&Namespace::Local, "claim/x"));
        assert!(!own.can_read(&Namespace::Local, "group/x"));
        assert!(own.can_read(&collection("a.b"), "group/x"));
        let names = reader(groups, "tls:host", Some(claims));
        assert!(names.can_read(&Namespace::Local, "group/x"));
        assert!(!names.can_read(&Namespace::Local, "claim/x"));
    }

    /// `r`, `w`, `c`, and `t` give a read. `d` alone does not. A deny item
    /// wins.
    #[test]
    fn read_rights_follow_the_selected_group() {
        let read = reader(
            "[ex-ostrya client \"c\"]\nauth=ssh:u\n\
             allow=r:r/**;w:w/**;c:c/**;t:t/**;d:d/**;r:x/**\ndeny=x/secret\n",
            "ssh:u",
            None,
        );
        for name in ["r/a", "w/a", "c/a", "t/a", "x/open"] {
            assert!(read.can_read(&Namespace::Local, name), "{name}");
        }
        for name in ["d/a", "x/secret", "other"] {
            assert!(!read.can_read(&Namespace::Local, name), "{name}");
        }
        let other = reader(
            "[ex-ostrya client \"c\"]\nauth=ssh:u\nallow=r:**\n",
            "ssh:v",
            None,
        );
        assert!(!other.can_read(&Namespace::Local, "main"));
    }

    /// `refs/heads/NAME` and `refs/mirrors/ID/NAME` name a ref. Each other
    /// path under `refs/`, and a path outside `refs/`, names none.
    #[test]
    fn ref_paths_name_heads_and_mirrors_alone() {
        let read = reader("", "anonymous", None);
        for path in ["refs/heads/a/b", "refs/heads/main", "refs/mirrors/a.b/x"] {
            assert!(read.can_read_path(path), "{path}");
        }
        for path in [
            "refs/remotes/o/x",
            "refs/x",
            "refs/heads",
            "refs/heads/",
            "refs/mirrors/a.b",
            "refs/mirrors/a.b/",
            "refs/mirrors//x",
            "refs/mirrors",
            "heads/main",
            "summary",
            "",
        ] {
            assert!(!read.can_read_path(path), "{path}");
        }
    }

    /// A mirror path takes the items of its collection. The own id takes the
    /// rules of the local refs. An id that fails the collection-id rule
    /// reads nothing.
    #[test]
    fn a_mirror_path_uses_the_items_of_its_collection() {
        let read = reader(
            "[ex-ostrya client \"c\"]\nauth=ssh:u\n\
             allow=r:local/**;r:@a.b:exact/**;r:@c.d:other/**\n",
            "ssh:u",
            None,
        );
        assert!(read.can_read_path("refs/mirrors/a.b/exact/x"));
        assert!(!read.can_read_path("refs/mirrors/a.b/other/x"));
        assert!(!read.can_read_path("refs/mirrors/a.b/local/x"));
        assert!(read.can_read_path("refs/mirrors/c.d/other/x"));
        assert!(!read.can_read_path("refs/mirrors/e.f/other/x"));
        assert!(read.can_read_path("refs/mirrors/own.id/local/x"));
        assert!(!read.can_read_path("refs/mirrors/own.id/exact/x"));
        assert!(read.can_read(&collection("own.id"), "local/x"));
        assert!(!read.can_read_path("refs/heads/exact/x"));
        let implicit = reader("", "anonymous", None);
        assert!(implicit.can_read_path("refs/mirrors/e.f/x"));
        assert!(!implicit.can_read_path("refs/mirrors/bad/x"));
        assert!(!implicit.can_read_path("refs/mirrors/a..b/x"));
    }

    /// The rules of a collection come from the items of that collection
    /// alone. The own id, an id that fails the collection-id rule, and an
    /// id with no item give none. The claims of a namespace replace the
    /// rules of a claim group there.
    #[test]
    fn collection_rules_take_the_items_of_the_collection() {
        let groups = "[ex-ostrya client \"u\"]\nauth=ssh:u\nallow=r:**;r:@a.b:exact/**\n\
                      [ex-ostrya client \"v\"]\nauth=ssh:v\nallow=d:@a.b:**\n";
        let read = reader(groups, "ssh:u", None);
        let exact = read.collection_rules("a.b").unwrap();
        assert!(reads(exact, "exact/x"));
        assert!(!reads(exact, "any/x"));
        for id in ["c.d", "own.id", "bad", "a..b", "1a.b"] {
            assert!(read.collection_rules(id).is_none(), "{id}");
        }
        let delete = reader(groups, "ssh:v", None);
        assert!(!delete.collection_rules("a.b").unwrap().gives_read());
        assert!(
            reader(groups, "ssh:w", None)
                .collection_rules("a.b")
                .is_none()
        );

        let claims = "[ex-ostrya client \"certs\"]\nauth=tls:*\n\
                      tls-accept-claim=true\nallow=r:@a.b:group/**;r:@c.d:group/**\n";
        let claimed = reader(claims, "tls:*", Some(&["ostrya:ref:@a.b:claim/**"]));
        let rules = claimed.collection_rules("a.b").unwrap();
        assert!(reads(rules, "claim/x"));
        assert!(!reads(rules, "group/x"));
        let rules = claimed.collection_rules("c.d").unwrap();
        assert!(reads(rules, "group/x"));
        assert!(!reads(rules, "claim/x"));
    }

    /// With no client group, the implicit group reads each local ref and
    /// each collection ref, and the item has a summary. A client group with
    /// no `summary` key gives no summary.
    #[test]
    fn the_implicit_group_reads_each_local_and_collection_ref() {
        let read = reader("", "anonymous", None);
        assert!(read.can_read(&Namespace::Local, "a/b"));
        assert!(read.can_read(&collection("a.b"), "x"));
        assert!(read.summary_digest().is_some());
        assert!(!read.access().has_client_groups());
        let groups = reader(
            "[ex-ostrya client \"c\"]\nauth=anonymous\nallow=r:**\n",
            "anonymous",
            None,
        );
        assert!(groups.can_read(&Namespace::Local, "a/b"));
        assert!(!groups.can_read(&collection("a.b"), "x"));
        assert!(groups.summary_digest().is_none());
        assert!(groups.access().has_client_groups());
    }

    /// The rights of a summary keep the group of the item only with
    /// `summary=true`. Then they hold the rights of each namespace.
    #[test]
    fn the_rights_of_a_summary_keep_a_group_with_summary() {
        let groups = "[ex-ostrya client \"with\"]\nauth=ssh:u\nallow=r:**;r:@a.b:**\n\
                      summary=true\n\
                      [ex-ostrya client \"without\"]\nauth=ssh:v\nallow=r:**;r:@a.b:**\n";
        let access = access(groups);
        for (item, kept) in [("ssh:u", true), ("ssh:v", false)] {
            let item = AuthItem::parse(item).unwrap();
            let full = ReadAccess::new(access.clone(), item.clone(), None);
            let summary = ReadAccess::for_summary(access.clone(), item);
            assert!(full.can_read(&Namespace::Local, "x"));
            assert!(full.can_read(&collection("a.b"), "x"));
            assert_eq!(summary.can_read(&Namespace::Local, "x"), kept);
            assert_eq!(summary.reads_local_refs(), kept);
            assert_eq!(summary.can_read(&collection("a.b"), "x"), kept);
            assert_eq!(summary.collection_rules("a.b").is_some(), kept);
            assert!(summary.collection_rules("c.d").is_none());
            assert_eq!(summary.summary_digest().is_some(), kept);
        }
    }
}
