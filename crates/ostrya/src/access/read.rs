//! The read rights of one identified client.

use std::borrow::Cow;
use std::sync::{Arc, OnceLock};

use super::{AccessModes, AccessRules, AuthItem, Claims, ClientAccess, Namespace};

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
/// - The client reads `NAME` when the group that carries its item in the
///   namespace ([`ClientAccess::select`]) has `r` on `NAME`. The rules of
///   the group are the rules that [`ClientAccess::effective_rules`] gives
///   with the claims. `w`, `c`, and `t` include `r`.
/// - Each other path under `refs/` is never read, `refs/remotes/` included.
///   A directory under `refs/mirrors/` whose name fails the collection-id
///   rule selects no group, so the client reads no ref in it.
/// - The client reads `summary` and `summary.sig` when the config has no
///   client group.
///
/// The value computes the rules of the local namespace one time, at their
/// first use. It computes the rules of a collection namespace for each use.
/// A ref listing computes them one time for each collection.
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
/// assert!(!read.serves_summary());
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
    /// The rules of the local namespace, or `None` with no group of the
    /// item there. The value finds them at their first use.
    local: OnceLock<Option<Local>>,
}

/// The rules of the local namespace of a [`Reader`].
#[derive(Debug)]
enum Local {
    /// The rules of the group at this index of the groups.
    Group(usize),
    /// The rules of the claims, which replace the rules of the group.
    Claimed(AccessRules),
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
                local: OnceLock::new(),
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
        let local = match namespace {
            Namespace::Local => true,
            Namespace::Collection(id) => self.inner.access.is_own_collection(id),
        };
        if local {
            return self.local_rules().is_some_and(|rules| reads(rules, name));
        }
        self.rules(namespace)
            .is_some_and(|rules| reads(&rules, name))
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

    /// Returns `true` if the client reads `summary` and `summary.sig`: the
    /// config has no client group.
    pub fn serves_summary(&self) -> bool {
        !self.inner.access.has_client_groups()
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
    /// namespace, for an id that fails the collection-id rule, and when no
    /// group carries the item in the namespace. The group is the group that
    /// [`ClientAccess::select`] gives: the group of the exact id, else the
    /// group of `collection=*`. The rules of the two groups never combine.
    pub(crate) fn collection_rules(&self, id: &str) -> Option<Cow<'_, AccessRules>> {
        if self.inner.access.is_own_collection(id) {
            return None;
        }
        self.rules(&Namespace::Collection(id.to_owned()))
    }

    /// Returns the rules of the group of the item in the local namespace,
    /// with the claims, or `None` with no such group. The value finds them
    /// at the first call.
    fn local_rules(&self) -> Option<&AccessRules> {
        let access = &self.inner.access;
        let local = self.inner.local.get_or_init(|| {
            let index = access.select_index(&self.inner.item, &Namespace::Local)?;
            let group = &access.groups()[index];
            let claims = self.inner.claims.as_deref();
            let rules = match access.effective_rules(group, &Namespace::Local, claims) {
                Cow::Owned(rules) => Local::Claimed(rules),
                Cow::Borrowed(_) => Local::Group(index),
            };
            Some(rules)
        });
        match local.as_ref()? {
            Local::Group(index) => Some(access.groups()[*index].rules()),
            Local::Claimed(rules) => Some(rules),
        }
    }

    /// Returns the rules of the group of the item in `namespace`, with the
    /// claims, or `None` with no such group.
    fn rules(&self, namespace: &Namespace) -> Option<Cow<'_, AccessRules>> {
        let access = &self.inner.access;
        let group = access.select(&self.inner.item, namespace)?;
        Some(access.effective_rules(group, namespace, self.inner.claims.as_deref()))
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

    /// A group with `tls-accept-claim=true` takes the claims of the
    /// namespace in place of its rules. With no claim of the namespace, the
    /// rules of the group apply. A group with `tls-accept-claim=false`
    /// ignores the claims.
    #[test]
    fn effective_rules_take_the_claims_of_a_claim_group() {
        let groups = "[ex-ostrya client \"certs\"]\nauth=tls:*\ntls-accept-claim=true\n\
                      allow=r:group/**\n\
                      [ex-ostrya client \"names\"]\nauth=tls:host\nallow=r:group/**\n";
        let claims: &[&str] = &["ostrya:ref:claim/**", "ostrya:collection:a.b:other/**"];
        let certs = reader(groups, "tls:*", Some(claims));
        assert!(certs.can_read(&Namespace::Local, "claim/x"));
        assert!(!certs.can_read(&Namespace::Local, "group/x"));
        let no_local = reader(groups, "tls:*", Some(&["ostrya:collection:a.b:x"]));
        assert!(no_local.can_read(&Namespace::Local, "group/x"));
        assert!(!no_local.can_read(&Namespace::Local, "claim/x"));
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

    /// A mirror path takes the group of its collection: the exact id wins
    /// over `*`. The own id takes the rules of the local refs. An id that
    /// fails the collection-id rule reads nothing.
    #[test]
    fn a_mirror_path_uses_the_group_of_its_collection() {
        let read = reader(
            "[ex-ostrya client \"local\"]\nauth=ssh:u\nallow=r:local/**\n\
             [ex-ostrya client \"exact\"]\nauth=ssh:u\ncollection=a.b\nallow=r:exact/**\n\
             [ex-ostrya client \"any\"]\nauth=ssh:u\ncollection=*\nallow=r:any/**\n",
            "ssh:u",
            None,
        );
        assert!(read.can_read_path("refs/mirrors/a.b/exact/x"));
        assert!(!read.can_read_path("refs/mirrors/a.b/any/x"));
        assert!(read.can_read_path("refs/mirrors/c.d/any/x"));
        assert!(!read.can_read_path("refs/mirrors/c.d/exact/x"));
        assert!(read.can_read_path("refs/mirrors/own.id/local/x"));
        assert!(!read.can_read_path("refs/mirrors/own.id/any/x"));
        assert!(read.can_read(&collection("own.id"), "local/x"));
        assert!(!read.can_read_path("refs/mirrors/bad/any/x"));
        assert!(!read.can_read_path("refs/mirrors/a..b/any/x"));
    }

    /// The rules of a collection come from the group of its exact id, else
    /// from the group of `collection=*`, and never from both. The own id, an
    /// id that fails the collection-id rule, and an id with no group give
    /// none. The claims of a namespace replace the rules of a claim group.
    #[test]
    fn collection_rules_take_the_selected_group_alone() {
        let groups = "[ex-ostrya client \"local\"]\nauth=ssh:u\nallow=r:**\n\
                      [ex-ostrya client \"exact\"]\nauth=ssh:u\ncollection=a.b\nallow=r:exact/**\n\
                      [ex-ostrya client \"any\"]\nauth=ssh:u\ncollection=*\nallow=r:any/**\n\
                      [ex-ostrya client \"deny\"]\nauth=ssh:v\ncollection=*\nallow=d:**\n";
        let read = reader(groups, "ssh:u", None);
        let exact = read.collection_rules("a.b").unwrap();
        assert!(reads(&exact, "exact/x"));
        assert!(!reads(&exact, "any/x"));
        let any = read.collection_rules("c.d").unwrap();
        assert!(reads(&any, "any/x"));
        assert!(!reads(&any, "exact/x"));
        for id in ["own.id", "bad", "a..b", "1a.b"] {
            assert!(read.collection_rules(id).is_none(), "{id}");
        }
        let delete = reader(groups, "ssh:v", None);
        assert!(!delete.collection_rules("a.b").unwrap().gives_read());
        assert!(
            reader(groups, "ssh:w", None)
                .collection_rules("a.b")
                .is_none()
        );

        let claims = "[ex-ostrya client \"certs\"]\nauth=tls:*\ncollection=*\n\
                      tls-accept-claim=true\nallow=r:group/**\n";
        let claimed = reader(claims, "tls:*", Some(&["ostrya:collection:a.b:claim/**"]));
        let rules = claimed.collection_rules("a.b").unwrap();
        assert!(reads(&rules, "claim/x"));
        assert!(!reads(&rules, "group/x"));
        let rules = claimed.collection_rules("c.d").unwrap();
        assert!(reads(&rules, "group/x"));
        assert!(!reads(&rules, "claim/x"));
    }

    /// With no client group, the implicit groups read each local ref and
    /// each collection ref, and the summary is served. One client group
    /// stops the summary.
    #[test]
    fn the_implicit_groups_read_each_local_and_collection_ref() {
        let read = reader("", "anonymous", None);
        assert!(read.can_read(&Namespace::Local, "a/b"));
        assert!(read.can_read(&collection("a.b"), "x"));
        assert!(read.serves_summary());
        assert!(!read.access().has_client_groups());
        let groups = reader(
            "[ex-ostrya client \"c\"]\nauth=anonymous\nallow=r:**\n",
            "anonymous",
            None,
        );
        assert!(groups.can_read(&Namespace::Local, "a/b"));
        assert!(!groups.serves_summary());
        assert!(groups.access().has_client_groups());
    }
}
