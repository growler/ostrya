//! Ref resolution, listing, and writing.
//!
//! A ref is a loose file under `refs/` holding a 64-char hex checksum and a
//! trailing newline (65 bytes). A local ref `name` maps to `refs/heads/name`; a
//! refspec `remote:name` maps to `refs/remotes/remote/name`; a collection ref
//! maps to `refs/mirrors/collection/name`. A ref may be a relative symlink
//! aliasing another ref; opening follows the link and reads the target ref's
//! checksum. Refspec components are validated to keep resolution inside the
//! `refs/` tree.
//!
//! A revision string is a refspec, a 64-char lowercase hex checksum, an
//! abbreviated checksum -- a shorter run of lowercase hex naming the one commit
//! object whose checksum starts with it -- or any of those followed by one or
//! more `^` characters, each of which steps one generation back along the
//! commit's `parent` field.
//!
//! Writes are individually atomic -- a fresh file written, `fdatasync`-ed when
//! fsync is enabled, and renamed over the target, with the parent directories
//! created for a `/`-bearing name. Under fsync the directory holding the ref is
//! `fsync`-ed after the rename, so the name is durable together with the
//! content. Where the write created parent directories, the directory holding
//! each created name is `fsync`-ed too, deepest first, so the whole path of a
//! `/`-bearing name is durable and not the leaf entry alone. A removal and an
//! alias write carry no content of their own and sync directories alone. A
//! `None` checksum removes the ref file. A transaction queues its ref writes
//! with [`Transaction::set_ref`] and applies them at commit after object
//! publication, under the fsync policy the transaction resolved for its object
//! writes; [`Repo::set_ref_immediate`](Repo::set_ref_immediate) writes one
//! outside a transaction and reads `[core] fsync` itself.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use ostrya_core::{Checksum, RepoMode};
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;

use crate::error::{Error, Result};
use crate::perm;
use crate::repo::Repo;
use crate::transaction::Transaction;
use crate::traverse::read_dir_names;

/// A collection-qualified ref: a ref name optionally bound to a collection id.
///
/// A ref with a collection id maps to `refs/mirrors/<collection>/<name>`; one
/// without maps to a local `refs/heads/<name>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionRef {
    /// The collection id, or `None` for a local ref.
    pub collection_id: Option<String>,
    /// The ref name, which may contain `/`.
    pub ref_name: String,
}

impl CollectionRef {
    /// A ref bound to a collection id.
    pub fn new(collection_id: impl Into<String>, ref_name: impl Into<String>) -> CollectionRef {
        CollectionRef {
            collection_id: Some(collection_id.into()),
            ref_name: ref_name.into(),
        }
    }

    /// A local ref with no collection id.
    pub fn local(ref_name: impl Into<String>) -> CollectionRef {
        CollectionRef {
            collection_id: None,
            ref_name: ref_name.into(),
        }
    }
}

/// One collection-qualified ref of a repository, as
/// [`Repo::list_collection_refs`] reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionRefEntry {
    /// The collection id the ref is qualified by.
    pub collection: String,
    /// The ref name, which for a local ref is its refspec.
    pub name: String,
    /// The commit the ref names.
    pub commit: Checksum,
    /// Whether the ref lives under `refs/heads`, qualified by the repository's
    /// own collection id, rather than under `refs/mirrors`.
    pub local: bool,
}

/// One ref stored as an alias: a relative symlink to another ref's file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefAlias {
    /// The refspec the alias itself is stored under.
    pub refspec: String,
    /// The symlink target, verbatim.
    pub target: String,
}

/// A queued ref target: either a refspec or a collection ref.
enum QueuedRef {
    Ref(String),
    Collection(CollectionRef),
}

impl QueuedRef {
    /// The path under `refs/` this target writes to, rejecting a name that
    /// would escape the tree.
    fn relpath(&self) -> Result<String> {
        match self {
            QueuedRef::Ref(refspec) => refspec_to_relpath(refspec),
            QueuedRef::Collection(cref) => collection_ref_to_relpath(cref),
        }
    }
}

/// One queued ref write: a target and the checksum to point it at (`None`
/// removes the ref).
pub(crate) struct RefWrite {
    target: QueuedRef,
    checksum: Option<Checksum>,
}

impl Transaction {
    /// Queue a refspec-to-checksum write, applied at
    /// [`commit`](Transaction::commit) after object publication. A `None`
    /// checksum queues the ref's removal. The refspec is validated at commit,
    /// before any object is published.
    pub fn set_ref(&self, refspec: &str, checksum: Option<&Checksum>) {
        self.refs.lock().unwrap().push(RefWrite {
            target: QueuedRef::Ref(refspec.to_owned()),
            checksum: checksum.copied(),
        });
    }

    /// Queue a collection-ref write, applied at
    /// [`commit`](Transaction::commit). A `None` checksum queues the ref's
    /// removal.
    pub fn set_collection_ref(&self, cref: &CollectionRef, checksum: Option<&Checksum>) {
        self.refs.lock().unwrap().push(RefWrite {
            target: QueuedRef::Collection(cref.clone()),
            checksum: checksum.copied(),
        });
    }

    /// Map every queued ref to its path under `refs/`, failing on a malformed
    /// refspec. Called at the start of [`commit`](Transaction::commit) so a bad
    /// refspec fails before any object is published.
    pub(crate) fn resolve_ref_queue(&self) -> Result<Vec<(String, Option<Checksum>)>> {
        let queue = self.refs.lock().unwrap();
        queue
            .iter()
            .map(|w| Ok((w.target.relpath()?, w.checksum)))
            .collect()
    }

    /// Write the resolved refs on the blocking pool, each atomically, under the
    /// transaction's resolved fsync policy, so the whole transaction -- the
    /// per-object writes, the publication step, and the ref writes -- reads one
    /// value.
    pub(crate) async fn write_resolved_refs(
        &self,
        refs: &[(String, Option<Checksum>)],
    ) -> Result<()> {
        if refs.is_empty() {
            return Ok(());
        }
        let (fsync, _) = self.fsync_flags()?;
        let repo_mode = self.repo().mode();
        let repo_fd = self.repo().repo_fd().try_clone_to_owned()?;
        let refs = refs.to_vec();
        ostrya_rt::unblock(move || {
            for (relpath, checksum) in &refs {
                write_ref_blocking(repo_fd.as_fd(), relpath, *checksum, fsync, repo_mode)?;
            }
            Ok(())
        })
        .await
    }
}

/// The largest ref file the reader will load; a ref is 65 bytes.
const REF_READ_CAP: u64 = 4096;

impl Repo {
    /// Resolve a revision string to a commit id. A 64-char lowercase hex string
    /// resolves to itself; a shorter run of lowercase hex resolves to the one
    /// commit object whose checksum it prefixes; anything else is a refspec. A
    /// trailing run of `^` characters steps that many generations back along the
    /// resolved commit's `parent` field. When the refspec names no ref,
    /// `allow_noent` chooses between `Ok(None)` and [`Error::RefNotFound`];
    /// walking past a root commit is [`Error::NoParentCommit`] and a prefix more
    /// than one commit carries is [`Error::AmbiguousRefspec`] whatever
    /// `allow_noent` says, since neither is an absent name.
    pub async fn resolve_rev(&self, rev: &str, allow_noent: bool) -> Result<Option<Checksum>> {
        let (base, generations) = split_ancestry(rev);
        let Some(mut checksum) = self.resolve_base_rev(base, allow_noent).await? else {
            return Ok(None);
        };
        for _ in 0..generations {
            let (commit, _) = self.load_commit(&checksum).await?;
            checksum = commit.parent.ok_or(Error::NoParentCommit(checksum))?;
        }
        Ok(Some(checksum))
    }

    /// Resolve a revision with no ancestry suffix: a bare checksum, an
    /// abbreviated checksum, or a refspec, tried in that order.
    ///
    /// A 64-character name is a checksum in lowercase hex alone, so an
    /// uppercase or mixed-case name of that length is read as a refspec
    /// (`docs/format-reference.md`, "Revision syntax"). The checksum parser
    /// keeps its tolerance where a checksum is read as stored bytes, which is
    /// ref file content and delta metadata.
    ///
    /// A shorter run of lowercase hex is an abbreviated checksum, and it stands
    /// ahead of the ref store: a name the store carries as a ref resolves to the
    /// commit it prefixes rather than to that ref's target. A prefix no commit
    /// object carries falls through to the ref store, so a hex name is a ref
    /// name for as long as no commit begins with it.
    async fn resolve_base_rev(&self, rev: &str, allow_noent: bool) -> Result<Option<Checksum>> {
        if let Ok(checksum) = Checksum::from_hex_lower(rev) {
            return Ok(Some(checksum));
        }

        if is_abbreviated_checksum(rev) {
            let repo = self.clone();
            let prefix = rev.to_owned();
            match ostrya_rt::unblock(move || match_abbreviated(repo.objects_fd(), &prefix)).await? {
                AbbrevMatch::One(checksum) => return Ok(Some(checksum)),
                AbbrevMatch::Ambiguous => return Err(Error::AmbiguousRefspec(rev.to_owned())),
                AbbrevMatch::None => {}
            }
        }

        match self.resolve_ref_tip(rev).await? {
            Some(checksum) => Ok(Some(checksum)),
            None if allow_noent => Ok(None),
            None => Err(Error::RefNotFound(rev.to_owned())),
        }
    }

    /// The commit a refspec names, reading the ref store alone: no checksum
    /// syntax, no abbreviated checksum, and no ancestry suffix. This is the
    /// ref-store read for a caller that holds a ref name rather than a
    /// revision -- a pull's local tip, the metadata ref a summary chains, and
    /// the CLI's alias-target check, an alias recording a name. `None` says the
    /// store carries no such ref.
    pub async fn resolve_ref_tip(&self, refspec: &str) -> Result<Option<Checksum>> {
        let relpath = refspec_to_relpath(refspec)?;
        let repo = self.clone();
        let bytes = ostrya_rt::unblock(move || read_ref_file(repo.repo_fd(), &relpath)).await?;
        match bytes {
            Some(bytes) => Ok(Some(parse_ref_content(&bytes)?)),
            None => Ok(None),
        }
    }

    /// List local refs (under `refs/heads`) as (name, commit) pairs, sorted by
    /// name. `prefix`, when given, keeps only the ref equal to it or nested
    /// under it.
    pub async fn list_refs(&self, prefix: Option<&str>) -> Result<Vec<(String, Checksum)>> {
        let repo = self.clone();
        let mut refs = ostrya_rt::unblock(move || collect_heads(&repo)).await?;
        if let Some(prefix) = prefix {
            let nested = format!("{prefix}/");
            refs.retain(|(name, _)| name == prefix || name.starts_with(&nested));
        }
        refs.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(refs)
    }

    /// List remote refs (under `refs/remotes`) as `(refspec, commit)` pairs,
    /// sorted by refspec. The first path component under `refs/remotes` is the
    /// remote name, so each ref is named by its `remote:name` refspec.
    pub async fn list_remote_refs(&self) -> Result<Vec<(String, Checksum)>> {
        let repo = self.clone();
        let mut refs = ostrya_rt::unblock(move || collect_remotes(&repo)).await?;
        refs.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(refs)
    }

    /// List collection-mirror refs (under `refs/mirrors`) as
    /// `(collection_id, ref_name, commit)` triples. The first path component
    /// under `refs/mirrors` is the collection id; the remainder is the ref
    /// name, which may contain `/`. Results are unsorted; callers that need a
    /// stable order sort them.
    pub async fn list_mirror_refs(&self) -> Result<Vec<(String, String, Checksum)>> {
        let repo = self.clone();
        ostrya_rt::unblock(move || collect_mirrors(&repo)).await
    }

    /// List the collection-qualified refs of the repository, sorted by
    /// collection id and then by ref name.
    ///
    /// The set is the local refs qualified by the repository's own
    /// `[core] collection-id`, where it sets one, together with every ref under
    /// `refs/mirrors`, which carries its collection id in its path. A mirror
    /// ref under the repository's own id is listed as a mirror ref.
    pub async fn list_collection_refs(&self) -> Result<Vec<CollectionRefEntry>> {
        let heads = match self.config().collection_id() {
            Some(_) => self.list_refs(None).await?,
            None => Vec::new(),
        };
        self.collection_refs_over(&heads).await
    }

    /// The listing [`list_collection_refs`](Repo::list_collection_refs) makes,
    /// over a `refs/heads` listing the caller has already read. A repository
    /// carrying no `[core] collection-id` qualifies no local ref, and `heads`
    /// is then ignored.
    pub(crate) async fn collection_refs_over(
        &self,
        heads: &[(String, Checksum)],
    ) -> Result<Vec<CollectionRefEntry>> {
        let mut all = Vec::new();
        if let Some(collection) = self.config().collection_id().map(str::to_owned) {
            for (name, commit) in heads {
                all.push(CollectionRefEntry {
                    collection: collection.clone(),
                    name: name.clone(),
                    commit: *commit,
                    local: true,
                });
            }
        }
        for (collection, name, commit) in self.list_mirror_refs().await? {
            all.push(CollectionRefEntry {
                collection,
                name,
                commit,
                local: false,
            });
        }
        all.sort_by(|a, b| (&a.collection, &a.name).cmp(&(&b.collection, &b.name)));
        Ok(all)
    }

    /// List the local and remote refs stored as aliases, sorted by refspec. An
    /// alias whose target names no ref is listed too, since the listing reads
    /// the link and not the ref behind it.
    pub async fn list_ref_aliases(&self) -> Result<Vec<RefAlias>> {
        let repo = self.clone();
        let mut aliases = ostrya_rt::unblock(move || collect_aliases(&repo)).await?;
        aliases.sort_by(|a, b| a.refspec.cmp(&b.refspec));
        Ok(aliases)
    }

    /// Probe one path below `refs/`, as a listing prefix names it, reporting the
    /// one condition that ends an enumeration: a component above the last that is
    /// not a directory, which is `ENOTDIR`.
    ///
    /// A path naming nothing is `Ok(())`, since a prefix matching no ref
    /// enumerates nothing, and so is every other probe failure -- the prefix
    /// filters the listing in that case rather than ending it. The last component
    /// is not followed, so a path naming an alias symlink is the link itself.
    pub async fn check_refs_path(&self, relpath: &str) -> Result<()> {
        let path = format!("refs/{relpath}");
        let repo = self.clone();
        ostrya_rt::unblock(move || {
            match rustix::fs::statat(repo.repo_fd(), &path, AtFlags::SYMLINK_NOFOLLOW) {
                Err(Errno::NOTDIR) => Err(Error::Io(Errno::NOTDIR.into())),
                _ => Ok(()),
            }
        })
        .await
    }

    /// Write one ref outside a transaction, atomically. A `None` checksum
    /// removes the ref file. The write follows the same tmpfile, `fdatasync`,
    /// rename, directory `fsync` sequence a transaction uses, honoring
    /// `[core] fsync`.
    pub async fn set_ref_immediate(
        &self,
        refspec: &str,
        checksum: Option<&Checksum>,
    ) -> Result<()> {
        let relpath = refspec_to_relpath(refspec)?;
        self.write_ref_relpath(relpath, checksum).await
    }

    /// Write one collection ref outside a transaction, atomically, the way
    /// [`set_ref_immediate`](Repo::set_ref_immediate) writes a refspec. A
    /// `None` checksum removes the ref file.
    pub async fn set_collection_ref_immediate(
        &self,
        cref: &CollectionRef,
        checksum: Option<&Checksum>,
    ) -> Result<()> {
        let relpath = collection_ref_to_relpath(cref)?;
        self.write_ref_relpath(relpath, checksum).await
    }

    async fn write_ref_relpath(&self, relpath: String, checksum: Option<&Checksum>) -> Result<()> {
        let fsync = self.config().fsync()?;
        let repo_mode = self.mode();
        let checksum = checksum.copied();
        let repo_fd = self.repo_fd().try_clone_to_owned()?;
        ostrya_rt::unblock(move || {
            write_ref_blocking(repo_fd.as_fd(), &relpath, checksum, fsync, repo_mode)
        })
        .await
    }

    /// Write one ref as an alias of another: a relative symlink from
    /// `refspec`'s file to `target`'s, replacing whatever `refspec` named
    /// before. Both refspecs are validated; neither ref need already exist,
    /// since the link records a name and not a checksum. The write honors
    /// `[core] fsync`, which for a symlink reaches the directory holding it.
    pub async fn set_ref_alias_immediate(&self, refspec: &str, target: &str) -> Result<()> {
        let fsync = self.config().fsync()?;
        let repo_mode = self.mode();
        let relpath = refspec_to_relpath(refspec)?;
        let link = relative_link(&relpath, &refspec_to_relpath(target)?);
        let repo_fd = self.repo_fd().try_clone_to_owned()?;
        ostrya_rt::unblock(move || {
            write_alias_blocking(repo_fd.as_fd(), &relpath, &link, fsync, repo_mode)
        })
        .await
    }
}

/// Split a revision string into its base and the number of trailing `^`
/// characters, each of which asks for one more generation of ancestry.
fn split_ancestry(rev: &str) -> (&str, usize) {
    let base = rev.trim_end_matches('^');
    (base, rev.len() - base.len())
}

/// Whether a revision names a commit by an abbreviated checksum: a run of one
/// to 63 lowercase hex characters. A 64-character run is the checksum itself,
/// and one uppercase character makes the name a refspec, the case rule a full
/// checksum carries (`docs/format-reference.md`, "Revision syntax").
fn is_abbreviated_checksum(rev: &str) -> bool {
    !rev.is_empty()
        && rev.len() < 64
        && rev
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// What an abbreviated checksum matched among the commit objects present.
enum AbbrevMatch {
    /// No commit object's checksum starts with the prefix.
    None,
    /// Exactly one does.
    One(Checksum),
    /// More than one does.
    Ambiguous,
}

/// Scan the loose commit objects for the ones whose checksum starts with
/// `prefix`.
///
/// The match set holds commit objects alone: a `dirtree`, a `dirmeta`, or a file
/// object sharing the prefix takes no part, and a prefix only such an object
/// carries matches nothing. The `objects/<xx>/` fanout carries the first two
/// characters of a checksum. A prefix of two or more characters names one
/// fanout with its first two characters, and that directory is opened by name.
/// A one-character prefix scans the sixteen fanouts whose name starts with it,
/// found by listing `objects/`.
fn match_abbreviated(objects_fd: BorrowedFd<'_>, prefix: &str) -> Result<AbbrevMatch> {
    let mut found: Option<Checksum> = None;
    if prefix.len() >= 2 {
        let (fanout, within) = prefix.split_at(2);
        if scan_fanout(objects_fd, fanout, within, &mut found)? {
            return Ok(AbbrevMatch::Ambiguous);
        }
    } else {
        for fanout in read_dir_names(objects_fd)? {
            // Object fanout directories are exactly two hex characters; anything
            // else under `objects/` is not a loose-object fanout.
            if fanout.len() != 2 || !fanout.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            if !fanout.starts_with(prefix) {
                continue;
            }
            if scan_fanout(objects_fd, &fanout, "", &mut found)? {
                return Ok(AbbrevMatch::Ambiguous);
            }
        }
    }
    Ok(match found {
        Some(checksum) => AbbrevMatch::One(checksum),
        None => AbbrevMatch::None,
    })
}

/// Scan one `objects/<fanout>/` directory for the commit objects whose name
/// starts with `within`, recording each in `found`. An absent fanout directory
/// holds no match. The returned flag reports the prefix ambiguous.
fn scan_fanout(
    objects_fd: BorrowedFd<'_>,
    fanout: &str,
    within: &str,
    found: &mut Option<Checksum>,
) -> Result<bool> {
    let dir = match rustix::fs::openat(
        objects_fd,
        fanout,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(false),
        Err(e) => return Err(Error::Io(e.into())),
    };
    for entry in read_dir_names(dir.as_fd())? {
        let Some(checksum) = matching_commit(fanout, &entry, within) else {
            continue;
        };
        // The fanout carries a checksum's first two characters, so two entries
        // are two commits and a second match is ambiguity.
        if found.replace(checksum).is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The checksum of one `objects/<fanout>/<rest>.commit` entry whose name starts
/// with `within`, or `None` for any other entry.
fn matching_commit(fanout: &str, entry: &str, within: &str) -> Option<Checksum> {
    let (rest, ext) = entry.rsplit_once('.')?;
    if ext != "commit" || rest.len() != 62 || !rest.starts_with(within) {
        return None;
    }
    Checksum::from_hex_lower(&format!("{fanout}{rest}")).ok()
}

/// The symlink body an alias at `from_relpath` needs to point at
/// `to_relpath`, both relative to the repository root: the shared leading
/// components are dropped, one `..` is emitted per component the alias's own
/// directory holds beyond them, and the target's remaining components follow.
fn relative_link(from_relpath: &str, to_relpath: &str) -> String {
    let from: Vec<&str> = from_relpath.split('/').collect();
    let to: Vec<&str> = to_relpath.split('/').collect();
    // The alias's own name is not part of the directory the link is read in,
    // and the target's own name is never a shared component.
    let from_dir = &from[..from.len() - 1];
    let common = from_dir
        .iter()
        .zip(&to[..to.len() - 1])
        .take_while(|(a, b)| a == b)
        .count();
    let mut parts = vec![".."; from_dir.len() - common];
    parts.extend_from_slice(&to[common..]);
    parts.join("/")
}

/// Collect every ref under `refs/heads`, walking subdirectories.
fn collect_heads(repo: &Repo) -> Result<Vec<(String, Checksum)>> {
    let Some(heads) = open_refs_dir(repo, "refs/heads")? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    walk_ref_dir(heads.as_fd(), "", &mut |entry| {
        if let Some(bytes) = read_ref_file(entry.dir, entry.name)? {
            out.push((entry.path.to_owned(), parse_ref_content(&bytes)?));
        }
        Ok(())
    })?;
    Ok(out)
}

/// Collect every ref under `refs/remotes`, naming each by its `remote:name`
/// refspec: the first path component is the remote, the remainder the ref name.
fn collect_remotes(repo: &Repo) -> Result<Vec<(String, Checksum)>> {
    let Some(remotes) = open_refs_dir(repo, "refs/remotes")? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    walk_ref_dir(remotes.as_fd(), "", &mut |entry| {
        let Some(bytes) = read_ref_file(entry.dir, entry.name)? else {
            return Ok(());
        };
        let checksum = parse_ref_content(&bytes)?;
        // A file directly under refs/remotes names no remote; ignore it, the
        // way collect_mirrors ignores one naming no collection.
        if let Some((remote, ref_name)) = entry.path.split_once('/') {
            out.push((format!("{remote}:{ref_name}"), checksum));
        }
        Ok(())
    })?;
    Ok(out)
}

/// Collect the aliases under `refs/heads` and `refs/remotes`, naming each the
/// way the corresponding listing names a ref.
fn collect_aliases(repo: &Repo) -> Result<Vec<RefAlias>> {
    let mut out = Vec::new();
    if let Some(heads) = open_refs_dir(repo, "refs/heads")? {
        walk_ref_dir(heads.as_fd(), "", &mut |entry| {
            if let Some(target) = read_alias_target(&entry)? {
                out.push(RefAlias {
                    refspec: entry.path.to_owned(),
                    target,
                });
            }
            Ok(())
        })?;
    }
    if let Some(remotes) = open_refs_dir(repo, "refs/remotes")? {
        walk_ref_dir(remotes.as_fd(), "", &mut |entry| {
            if let Some(target) = read_alias_target(&entry)?
                && let Some((remote, ref_name)) = entry.path.split_once('/')
            {
                out.push(RefAlias {
                    refspec: format!("{remote}:{ref_name}"),
                    target,
                });
            }
            Ok(())
        })?;
    }
    Ok(out)
}

/// Open one directory under `refs/`, or `None` when it does not exist.
fn open_refs_dir(repo: &Repo, relpath: &str) -> Result<Option<OwnedFd>> {
    match rustix::fs::openat(
        repo.repo_fd(),
        relpath,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => Ok(Some(fd)),
        Err(Errno::NOENT) => Ok(None),
        Err(e) => Err(Error::Io(e.into())),
    }
}

/// Collect every ref under `refs/mirrors`, splitting each into its collection
/// id (the first path component) and ref name (the remainder).
fn collect_mirrors(repo: &Repo) -> Result<Vec<(String, String, Checksum)>> {
    let Some(mirrors) = open_refs_dir(repo, "refs/mirrors")? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    walk_ref_dir(mirrors.as_fd(), "", &mut |entry| {
        let Some(bytes) = read_ref_file(entry.dir, entry.name)? else {
            return Ok(());
        };
        let checksum = parse_ref_content(&bytes)?;
        // A mirror ref is <collection>/<ref>; the collection id is a single
        // component, the ref name is everything after the first slash. A file
        // directly under refs/mirrors has no collection component; ignore it,
        // matching the tool's collection-qualified layout.
        if let Some((collection, ref_name)) = entry.path.split_once('/') {
            out.push((collection.to_owned(), ref_name.to_owned(), checksum));
        }
        Ok(())
    })?;
    Ok(out)
}

/// One entry a ref-tree walk reports.
pub(crate) struct RefEntry<'a> {
    /// The open directory holding the entry.
    pub(crate) dir: BorrowedFd<'a>,
    /// The entry's name in that directory.
    pub(crate) name: &'a str,
    /// The path walked to reach the entry, from the walk's root.
    pub(crate) path: &'a str,
    /// The entry's type, classified without following symlinks.
    pub(crate) file_type: FileType,
}

/// Walk a directory under `refs/`, descending into each subdirectory and
/// reporting every other entry to `visit`.
///
/// Entries are classified with `SYMLINK_NOFOLLOW`, so a real directory alone is
/// descended into and an alias carries [`FileType::Symlink`] whatever it names.
/// A link naming a directory is reported rather than joined to the walk: a
/// caller reading it as a ref fails the read with `EISDIR`, and one reading it
/// as an alias reads the link. A name that is not UTF-8 is skipped, as is one
/// removed between the directory read and the classification.
pub(crate) fn walk_ref_dir(
    dir: BorrowedFd<'_>,
    prefix: &str,
    visit: &mut impl FnMut(RefEntry<'_>) -> Result<()>,
) -> Result<()> {
    for name in read_dir_names(dir)? {
        let stat = match rustix::fs::statat(dir, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => continue, // removed between readdir and stat
            Err(e) => return Err(Error::Io(e.into())),
        };
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let file_type = FileType::from_raw_mode(stat.st_mode);
        if file_type == FileType::Directory {
            let sub = rustix::fs::openat(
                dir,
                name.as_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| Error::Io(e.into()))?;
            walk_ref_dir(sub.as_fd(), &path, visit)?;
        } else {
            visit(RefEntry {
                dir,
                name: &name,
                path: &path,
                file_type,
            })?;
        }
    }
    Ok(())
}

/// The symlink target of an alias entry, verbatim. `None` for an entry that is
/// not a symlink and for a target that is not UTF-8.
fn read_alias_target(entry: &RefEntry<'_>) -> Result<Option<String>> {
    if entry.file_type != FileType::Symlink {
        return Ok(None);
    }
    let target = rustix::fs::readlinkat(entry.dir, entry.name, Vec::new())
        .map_err(|e| Error::Io(e.into()))?;
    Ok(target.into_string().ok())
}

/// Read a ref file relative to `dir`, following alias symlinks. `None` when the
/// file does not exist.
fn read_ref_file(
    dir: rustix::fd::BorrowedFd<'_>,
    relpath: &str,
) -> std::io::Result<Option<Vec<u8>>> {
    let fd = match rustix::fs::openat(
        dir,
        relpath,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut buf = Vec::new();
    std::fs::File::from(fd)
        .take(REF_READ_CAP)
        .read_to_end(&mut buf)?;
    Ok(Some(buf))
}

/// Parse a ref file's content: a hex checksum with trailing whitespace.
fn parse_ref_content(bytes: &[u8]) -> Result<Checksum> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::InvalidFormat("ref content is not valid UTF-8".into()))?;
    Ok(Checksum::from_hex(text.trim())?)
}

/// Whether a refspec names a path under `refs/`: a ref name, optionally
/// preceded by a `<remote>:` prefix. A refspec that would escape the tree is
/// [`Error::InvalidRefspec`], carrying the refspec as given.
pub fn validate_refspec(refspec: &str) -> Result<()> {
    refspec_to_relpath(refspec).map(drop)
}

/// Map a refspec to its path under `refs/`, rejecting anything that would
/// escape the tree.
fn refspec_to_relpath(refspec: &str) -> Result<String> {
    if let Some((remote, name)) = refspec.split_once(':') {
        if !is_component(remote) || !is_ref_path(name) {
            return Err(Error::InvalidRefspec(refspec.to_owned()));
        }
        Ok(format!("refs/remotes/{remote}/{name}"))
    } else {
        if !is_ref_path(refspec) {
            return Err(Error::InvalidRefspec(refspec.to_owned()));
        }
        Ok(format!("refs/heads/{refspec}"))
    }
}

/// Whether the name a listing gave a ref addresses the file it was listed
/// from: whether [`refspec_to_relpath`] maps `name` to exactly `<top>/<path>`,
/// where `top` is the directory of `refs/` the listing walked and `path` is the
/// path of the ref file below it.
///
/// Prune classifies a ref only where this answers true, so every ref the
/// classifier sees reads and deletes through the file it was listed from. A
/// name the mapping refuses answers false.
///
/// The name alone decides this for a ref below `refs/heads`, where a `:` in the
/// name sends the mapping to `refs/remotes` and so to a different file. The
/// name alone cannot decide it for a ref below `refs/remotes`. A listing names
/// such a ref by replacing the first `/` of its path with a `:`, and the
/// mapping splits at the first `:`, so two files give one name: both
/// `refs/remotes/a:b/main` and `refs/remotes/a/b:main` list as `a:b:main`, and
/// the mapping sends that name to the second of the two. The signature takes
/// the path for this reason.
///
/// No refspec maps to a path below `refs/mirrors`, so a mirror ref always
/// answers false.
///
/// The body mirrors [`refspec_to_relpath`] branch for branch and allocates
/// nothing, because prune calls it once for each ref in the repository.
pub(crate) fn listed_name_addresses_it(name: &str, top: &str, path: &str) -> bool {
    match name.split_once(':') {
        Some((remote, rest)) => {
            top == "refs/remotes"
                && is_component(remote)
                && is_ref_path(rest)
                && path
                    .split_once('/')
                    .is_some_and(|(dir, below)| dir == remote && below == rest)
        }
        None => top == "refs/heads" && is_ref_path(name) && path == name,
    }
}

/// The same rule as [`Error::InvalidRefspec`]-bearing validation, for a bare
/// ref name.
///
/// An HTTP pull applies it before a ref name becomes a request path: a
/// traversal component there asks the server for a different resource, the way
/// it would name a different file here.
pub(crate) fn check_ref_path(name: &str) -> Result<()> {
    if is_ref_path(name) {
        Ok(())
    } else {
        Err(Error::InvalidRefspec(name.to_owned()))
    }
}

/// A ref name may contain `/` but no empty, `.`, or `..` components, and no
/// interior NUL.
fn is_ref_path(name: &str) -> bool {
    !name.is_empty() && name.split('/').all(is_component)
}

/// A single path component: non-empty, not a traversal, no slash or NUL.
fn is_component(component: &str) -> bool {
    !(component.is_empty()
        || component == "."
        || component == ".."
        || component.contains('/')
        || component.contains('\0'))
}

/// Map a collection ref to its path under `refs/`. A collection id places the
/// ref under `refs/mirrors/<collection>/`; a `None` id is a local
/// `refs/heads/` ref. The collection id is a single component (dots allowed, no
/// slash or traversal).
fn collection_ref_to_relpath(cref: &CollectionRef) -> Result<String> {
    let name = &cref.ref_name;
    match &cref.collection_id {
        Some(collection_id) => {
            if !is_component(collection_id) || !is_ref_path(name) {
                return Err(Error::InvalidRefspec(format!("{collection_id}:{name}")));
            }
            Ok(format!("refs/mirrors/{collection_id}/{name}"))
        }
        None => {
            if !is_ref_path(name) {
                return Err(Error::InvalidRefspec(name.to_owned()));
            }
            Ok(format!("refs/heads/{name}"))
        }
    }
}

/// The permission bits forced on a ref file, independent of the umask, matching
/// the tool's `0644` ref files.
const REF_FILE_MODE: u32 = 0o644;
/// The request mode for a created ref parent directory, reduced by the umask
/// (the tool's ref subdirectories are `0755` under a `022` umask). In a
/// `bare-user-shared` repository a parent directory the write creates is then
/// forced to [`perm::SHARED_DIR_MODE`], so every member of the repository group
/// publishes a ref under it.
const REF_DIR_MODE: u32 = 0o777;

/// Write or remove one ref file relative to `repo_fd`, atomically.
///
/// `Some(checksum)` writes the 65-byte `<hex>\n` content to a fresh temp file
/// in the target's parent directory (created as needed), `fdatasync`-es it when
/// `fsync` is set, and renames it over the target. `None` unlinks the ref,
/// treating an already-absent file as success. Under `fsync` the directory
/// holding the ref is `fsync`-ed after the rename or the unlink, so the name
/// the operation created or removed is durable and not only the file's content,
/// and [`sync_created_ref_parents`] then makes durable the name of every parent
/// directory this write created.
fn write_ref_blocking(
    repo_fd: BorrowedFd<'_>,
    relpath: &str,
    checksum: Option<Checksum>,
    fsync: bool,
    repo_mode: RepoMode,
) -> Result<()> {
    let Some(checksum) = checksum else {
        return match rustix::fs::unlinkat(repo_fd, relpath, AtFlags::empty()) {
            Ok(()) => {
                if fsync {
                    sync_ref_parent(repo_fd, relpath)?;
                }
                Ok(())
            }
            Err(Errno::NOENT) => Ok(()),
            Err(e) => Err(e.into()),
        };
    };

    let created = create_ref_parents(repo_fd, relpath, repo_mode)?;
    let content = format!("{}\n", checksum.to_hex());
    let tmp = format!(
        "{relpath}.tmp-{}-{}",
        std::process::id(),
        crate::write::unique()
    );
    let fd = rustix::fs::openat(
        repo_fd,
        tmp.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(REF_FILE_MODE),
    )?;
    let write_and_rename = || -> Result<()> {
        let mut file = std::fs::File::from(fd);
        file.write_all(content.as_bytes())?;
        file.flush()?;
        rustix::fs::fchmod(file.as_fd(), Mode::from_raw_mode(REF_FILE_MODE))?;
        if fsync {
            rustix::fs::fdatasync(file.as_fd())?;
        }
        drop(file);
        rustix::fs::renameat(repo_fd, tmp.as_str(), repo_fd, relpath)?;
        if fsync {
            sync_ref_parent(repo_fd, relpath)?;
            sync_created_ref_parents(repo_fd, &created)?;
        }
        Ok(())
    };
    write_and_rename().inspect_err(|_| {
        let _ = rustix::fs::unlinkat(repo_fd, tmp.as_str(), AtFlags::empty());
    })
}

/// Write one alias symlink relative to `repo_fd`, atomically.
///
/// The link is created under a fresh temp name in the target's parent
/// directory, then renamed over the target, so an existing ref file or an
/// existing alias is replaced in one step. A symlink carries no content of its
/// own to sync, so `fsync` reaches the directory holding the link and the
/// directory holding each parent this write created.
fn write_alias_blocking(
    repo_fd: BorrowedFd<'_>,
    relpath: &str,
    link: &str,
    fsync: bool,
    repo_mode: RepoMode,
) -> Result<()> {
    let created = create_ref_parents(repo_fd, relpath, repo_mode)?;
    let tmp = format!(
        "{relpath}.tmp-{}-{}",
        std::process::id(),
        crate::write::unique()
    );
    rustix::fs::symlinkat(link, repo_fd, tmp.as_str())?;
    rustix::fs::renameat(repo_fd, tmp.as_str(), repo_fd, relpath).inspect_err(|_| {
        let _ = rustix::fs::unlinkat(repo_fd, tmp.as_str(), AtFlags::empty());
    })?;
    if fsync {
        sync_ref_parent(repo_fd, relpath)?;
        sync_created_ref_parents(repo_fd, &created)?;
    }
    Ok(())
}

/// Remove every ref that still names the checksum the caller recorded for it,
/// relative to `repo_fd`, in one blocking pass.
///
/// Each name is mapped to its path by the same refspec rule the asynchronous
/// writes use, so the read and the unlink address the file the rest of the
/// library addresses. The read sits immediately ahead of its own unlink: a ref
/// that now names a different commit is left where it stands, which covers a
/// repository whose `[core] locking` is false and a caller that moved the ref
/// after it recorded the checksum. A read that finds no file unlinks all the
/// same -- the name the caller recorded is gone or dangles, `unlinkat` removes
/// a symlink and not the file it names, and an already-absent name is success.
///
/// Under `fsync` each directory an unlink emptied of one name is `fsync`-ed
/// once, after the last unlink, so every removed name is durable. A directory
/// is recorded only where its own unlink reported success. A recorded
/// directory that is gone by the time the pass reaches it holds no entry to
/// make durable, so its absence is success as well. A hash set carries the
/// membership test, and a vector carries the order the `fsync` calls run in.
/// That order is the order the first unlink of each directory ran in. The
/// membership test reads the borrowed path, so a parent the set already holds
/// costs no allocation.
///
/// Returns the names it removed, in the order it was given them.
pub(crate) fn delete_matching_refs_blocking(
    repo_fd: BorrowedFd<'_>,
    refs: Vec<(String, Checksum)>,
    fsync: bool,
) -> Result<Vec<String>> {
    let mut removed = Vec::with_capacity(refs.len());
    let mut parents: Vec<String> = Vec::new();
    let mut held: HashSet<String> = HashSet::new();
    for (name, target) in refs {
        let relpath = refspec_to_relpath(&name)?;
        if let Some(bytes) = read_ref_file(repo_fd, &relpath)?
            && parse_ref_content(&bytes)? != target
        {
            continue;
        }
        match rustix::fs::unlinkat(repo_fd, relpath.as_str(), AtFlags::empty()) {
            Ok(()) => {
                if fsync {
                    let parent = ref_parent(&relpath);
                    if !held.contains(parent) {
                        held.insert(parent.to_owned());
                        parents.push(parent.to_owned());
                    }
                }
            }
            Err(Errno::NOENT) => {}
            Err(e) => return Err(Error::Io(e.into())),
        }
        removed.push(name);
    }
    for parent in &parents {
        sync_dir_present(repo_fd, parent)?;
    }
    Ok(removed)
}

/// The directory holding the ref at `relpath`. A refspec always maps below
/// `refs/`, so the path carries a parent; a bare name names the repository
/// root.
fn ref_parent(relpath: &str) -> &str {
    relpath.rsplit_once('/').map_or(".", |(dir, _)| dir)
}

/// `fsync` the directory holding the ref at `relpath`, making a rename or an
/// unlink of that name durable.
fn sync_ref_parent(repo_fd: BorrowedFd<'_>, relpath: &str) -> Result<()> {
    sync_dir(repo_fd, ref_parent(relpath))
}

/// `fsync` one directory named relative to the repository root, where it still
/// stands. A directory that is gone carries no entry to make durable, so its
/// absence is success.
fn sync_dir_present(repo_fd: BorrowedFd<'_>, path: &str) -> Result<()> {
    match sync_dir(repo_fd, path) {
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// `fsync` one directory named relative to the repository root.
fn sync_dir(repo_fd: BorrowedFd<'_>, path: &str) -> Result<()> {
    let dir = rustix::fs::openat(
        repo_fd,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    rustix::fs::fsync(dir.as_fd())?;
    Ok(())
}

/// Create the parent directories of a ref path, idempotently. Every component
/// but the last is created; existing directories are left in place. Returns the
/// paths this call created, shallowest first, for
/// [`sync_created_ref_parents`] to make durable.
///
/// In a `bare-user-shared` repository each directory this call creates is
/// forced to [`perm::SHARED_DIR_MODE`]. A directory that already stands keeps
/// the mode and the group it has.
fn create_ref_parents(
    repo_fd: BorrowedFd<'_>,
    relpath: &str,
    repo_mode: RepoMode,
) -> Result<Vec<String>> {
    let mut created = Vec::new();
    let mut acc = String::new();
    let mut components: Vec<&str> = relpath.split('/').collect();
    components.pop(); // the final component is the ref file itself
    for component in components {
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(component);
        match rustix::fs::mkdirat(repo_fd, acc.as_str(), Mode::from_raw_mode(REF_DIR_MODE)) {
            Ok(()) => {
                perm::force_created_dir(repo_fd, acc.as_str(), repo_mode)?;
                created.push(acc.clone());
            }
            Err(Errno::EXIST) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(created)
}

/// `fsync` the directory that holds each entry [`create_ref_parents`] created,
/// deepest first.
///
/// A `mkdirat` adds a name to the directory it is called in, so the directory
/// made durable for a created `refs/heads/deep/nest` is `refs/heads/deep`, the
/// one that holds the `nest` entry. Syncing the created directory's own file
/// descriptor makes its contents durable and leaves its name unrecorded.
///
/// The order is child before parent, the order the object fanout uses: the ref
/// file's own name, which [`sync_ref_parent`] makes durable, then the name of
/// the directory holding it, then the name of the directory above that. A crash
/// part way through therefore leaves a prefix of the path recorded and never a
/// directory entry naming a directory whose own contents are unrecorded.
///
/// A directory the call found already in place is not synced; its name is
/// already durable.
fn sync_created_ref_parents(repo_fd: BorrowedFd<'_>, created: &[String]) -> Result<()> {
    for dir in created.iter().rev() {
        sync_ref_parent(repo_fd, dir)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refspec_maps_local_and_remote() {
        assert_eq!(
            refspec_to_relpath("test/main").unwrap(),
            "refs/heads/test/main"
        );
        assert_eq!(
            refspec_to_relpath("origin:test/main").unwrap(),
            "refs/remotes/origin/test/main"
        );
    }

    #[test]
    fn refspec_rejects_traversal() {
        // The error names the whole refspec, which is what a caller reporting a
        // refused name has in hand, and not the component that failed.
        for bad in [
            "",
            "..",
            "a/../b",
            "/a",
            "a/",
            "a//b",
            "a/..",
            "origin:../escape",
            // A remote is one component, so a `/` in it names no remote.
            "a/b:x",
            ":x",
            "origin:",
        ] {
            let err = refspec_to_relpath(bad).unwrap_err();
            assert!(
                matches!(&err, Error::InvalidRefspec(name) if name == bad),
                "should reject {bad:?}, got {err}"
            );
        }
        assert!(validate_refspec("test/main").is_ok());
        assert!(validate_refspec("origin:test/main").is_ok());
    }

    #[test]
    fn collection_ref_names_the_pair_it_rejects() {
        let err = collection_ref_to_relpath(&CollectionRef::new("org.example.Foo", "a/../b"))
            .unwrap_err();
        assert!(
            matches!(&err, Error::InvalidRefspec(name) if name == "org.example.Foo:a/../b"),
            "{err}"
        );
        let err = collection_ref_to_relpath(&CollectionRef::local("a/../b")).unwrap_err();
        assert!(
            matches!(&err, Error::InvalidRefspec(name) if name == "a/../b"),
            "{err}"
        );
    }

    #[test]
    fn splits_the_ancestry_suffix() {
        assert_eq!(split_ancestry("test/main"), ("test/main", 0));
        assert_eq!(split_ancestry("test/main^"), ("test/main", 1));
        assert_eq!(split_ancestry("test/main^^^"), ("test/main", 3));
        assert_eq!(split_ancestry("^"), ("", 1));
    }

    #[test]
    fn builds_the_alias_link_body() {
        // A sibling alias names the target directly.
        assert_eq!(
            relative_link("refs/heads/alias", "refs/heads/test/main"),
            "test/main"
        );
        // A nested alias climbs out of its own directory first.
        assert_eq!(relative_link("refs/heads/p/q", "refs/heads/one"), "../one");
        // A target one level up from the alias's directory.
        assert_eq!(relative_link("refs/heads/a/b", "refs/heads/a"), "../a");
        // Across the two ref roots.
        assert_eq!(
            relative_link("refs/heads/alias", "refs/remotes/origin/main"),
            "../remotes/origin/main"
        );
    }

    /// Every case the addressability predicate is checked against, as
    /// `(name, top, path, expected)`.
    const ADDRESSABILITY_CASES: &[(&str, &str, &str, bool)] = &[
        // A local name addresses its own file where the mapping accepts it.
        ("main", "refs/heads", "main", true),
        ("test/main", "refs/heads", "test/main", true),
        // A `:` reads as the separator of a remote name, so the mapping gives
        // a path under `refs/remotes`.
        ("foo:bar", "refs/heads", "foo:bar", false),
        ("a/b:c", "refs/heads", "a/b:c", false),
        // A local name the mapping accepts still has to match the path it was
        // listed at.
        ("main", "refs/heads", "other", false),
        // A name the mapping refuses answers false as well.
        ("a/../b", "refs/heads", "a/../b", false),
        ("", "refs/heads", "", false),
        // A remote name addresses its own file where the first `/` of the path
        // is the `:` of the name.
        ("origin:main", "refs/remotes", "origin/main", true),
        ("origin:foo:bar", "refs/remotes", "origin/foo:bar", true),
        // One name, two files. The name addresses the second of the two.
        ("a:b:main", "refs/remotes", "a:b/main", false),
        ("a:b:main", "refs/remotes", "a/b:main", true),
        // A file directly under `refs/remotes` names no remote, so its name
        // maps under `refs/heads`.
        ("stray", "refs/remotes", "stray", false),
        // An empty remote component is refused.
        (":x:main", "refs/remotes", ":x/main", false),
        // So is a traversal, in the remote component and in the name below it.
        ("..:main", "refs/remotes", "../main", false),
        ("origin:a/../b", "refs/remotes", "origin/a/../b", false),
        // No refspec maps below `refs/mirrors`.
        (
            "org.example.Coll/mm",
            "refs/mirrors",
            "org.example.Coll/mm",
            false,
        ),
        // A remote refspec at the path it would take under another top answers
        // false, because the mapping names one top alone.
        ("origin:main", "refs/mirrors", "origin/main", false),
    ];

    #[test]
    fn a_listed_name_addresses_its_own_file_only_where_the_mapping_returns_it() {
        for (name, top, path, expected) in ADDRESSABILITY_CASES {
            assert_eq!(
                listed_name_addresses_it(name, top, path),
                *expected,
                "{name:?} under {top:?} at {path:?}"
            );
        }
    }

    #[test]
    fn the_addressability_predicate_agrees_with_the_refspec_mapping() {
        // The predicate reads the name in place, so this holds it to the
        // mapping it mirrors.
        for (name, top, path, _) in ADDRESSABILITY_CASES {
            assert_eq!(
                listed_name_addresses_it(name, top, path),
                refspec_to_relpath(name).ok() == Some(format!("{top}/{path}")),
                "{name:?} under {top:?} at {path:?}"
            );
        }
    }

    #[test]
    fn parses_ref_content_with_newline() {
        let hex = "b3c8e8525e8a5c3409bf6e6db5f5d656da77ae76d08cbc4f8b75b71879757a89";
        let checksum = parse_ref_content(format!("{hex}\n").as_bytes()).unwrap();
        assert_eq!(checksum.to_hex(), hex);
        assert!(parse_ref_content(b"not-a-checksum\n").is_err());
    }
}
