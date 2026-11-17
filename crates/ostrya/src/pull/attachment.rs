//! The search for the static delta of each attachment of a pull.
//!
//! A static delta carries its target commit alone. A pull looks for the delta
//! of each attachment after it reads the commits that name the attachment,
//! and fetches the attachments as one more level. [`pair_targets`] finds the
//! targets whose chains name each attachment, and [`lookups`] finds the
//! source commit of each delta from the paired entries.
//!
//! The chain of a target is the target and the parents that the depth of the
//! pull takes. The paired entry of an attachment for one target is the entry
//! with the same name in field 2 of the commit that the ref of the target
//! names here before the pull. A target gives at most one paired entry. The
//! `from` of the delta is the first paired entry, in target order, that this
//! repository holds complete. The pull takes the from-scratch delta only if
//! it holds no paired entry complete.
//!
//! [`Attachments`] holds the attachments that a pull met, the commits that
//! name them, and the errors that name the commit that first named an
//! attachment, for the local pull and for the pull over HTTP.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};

use ostrya_core::{Checksum, ObjectType};

use crate::error::{Error, Result};
use crate::related::{self, RelationField};
use crate::repo::Repo;

use super::RefPlace;
use super::delta::{AttachmentLookup, complete_here_blocking};

/// The attachments that one pull met, and the commits that name them.
///
/// The type records the state alone. Each engine chooses when it calls
/// [`named_error`](Attachments::named_error) or
/// [`nested_error`](Attachments::nested_error): the local pull gives an
/// error when its walk of the attachments reads an attachment, and the pull
/// over HTTP checks each commit when its step ends.
#[derive(Default)]
pub(super) struct Attachments {
    /// Each attachment, in the order in which the pull first recorded it.
    order: Vec<Checksum>,
    /// The commit that first named each attachment, and the name of its
    /// entry.
    named: HashMap<Checksum, (Checksum, String)>,
    /// The entries of field 2 of each commit whose field 2 is not empty, in
    /// the stored order. Under `keys_only`, each commit has an empty list
    /// here.
    naming: HashMap<Checksum, Vec<(String, Checksum)>>,
    /// `true` if `naming` keeps the commits alone, for the checks. A pull
    /// that reads no static delta of an attachment pairs no attachment with a
    /// target, so it keeps no entry.
    keys_only: bool,
}

impl Attachments {
    /// Returns an empty record. `keys_only` is `true` if the record keeps no
    /// entry of field 2.
    pub(super) fn new(keys_only: bool) -> Self {
        Self {
            keys_only,
            ..Self::default()
        }
    }

    /// Returns `true` if the record keeps no entry of field 2.
    pub(super) fn keys_only(&self) -> bool {
        self.keys_only
    }

    /// Records the attachments `attachments` of `commit`.
    ///
    /// An attachment that an earlier commit named keeps the first commit and
    /// entry name. An empty list records nothing.
    pub(super) fn record(&mut self, commit: Checksum, attachments: Vec<(String, Checksum)>) {
        if attachments.is_empty() {
            return;
        }
        for (name, attachment) in &attachments {
            if let Entry::Vacant(slot) = self.named.entry(*attachment) {
                slot.insert((commit, name.clone()));
                self.order.push(*attachment);
            }
        }
        let entries = if self.keys_only {
            Vec::new()
        } else {
            attachments
        };
        self.naming.insert(commit, entries);
    }

    /// Returns each attachment, in the order in which the pull first
    /// recorded it.
    pub(super) fn order(&self) -> &[Checksum] {
        &self.order
    }

    /// Returns the commit that first named `attachment`, and the name of its
    /// entry, or `None` if no commit named it.
    pub(super) fn named(&self, attachment: &Checksum) -> Option<(Checksum, &str)> {
        self.named
            .get(attachment)
            .map(|(commit, name)| (*commit, name.as_str()))
    }

    /// Returns the entries of field 2 of each commit whose field 2 is not
    /// empty. Under `keys_only`, each list is empty.
    pub(super) fn naming(&self) -> &HashMap<Checksum, Vec<(String, Checksum)>> {
        &self.naming
    }

    /// Returns the nested-attachment error for `attachment`, or `None` if no
    /// commit named it. The error names the commit that first named the
    /// attachment. The caller calls this method when it finds that
    /// `attachment` has attachments of its own.
    pub(super) fn nested_error(&self, attachment: &Checksum) -> Option<Error> {
        self.named(attachment)
            .map(|(commit, name)| related::nested_attachment(commit, name, attachment))
    }

    /// Returns the [`Error::InvalidRelations`] in field 2 for `attachment`,
    /// with the end `end` of its reason, or `None` if no commit named it.
    /// The error names the commit that first named the attachment, and the
    /// name of its entry.
    pub(super) fn named_error(&self, attachment: &Checksum, end: &str) -> Option<Error> {
        self.named(attachment)
            .map(|(commit, name)| Error::InvalidRelations {
                commit: Some(commit),
                field: RelationField::Attachments,
                reason: related::attachment_reason(name, attachment, end),
            })
    }
}

/// An attachment that a pull fetches, with the targets whose chains name it.
pub(super) struct Named {
    /// The attachment.
    pub(super) checksum: Checksum,
    /// The position of the first target whose chain names the attachment, or
    /// `None` if no chain of a target names it.
    first: Option<usize>,
    /// The name of the entry that names the attachment in the chain of the
    /// first target, nearest to its tip. If no chain names the attachment,
    /// the name comes from the commit with the lowest checksum that names it,
    /// as [`pair_targets`] states.
    name: String,
    /// The position of each target whose chain names the attachment, in
    /// target order, with the name of the entry nearest to its tip.
    pairs: Vec<(usize, String)>,
}

/// Returns each attachment of `pending`, with the targets whose chains name
/// it.
///
/// `targets` holds the name and the commit of each target, in the order of
/// the pull. `depth` is the depth of the pull, `-1` for all parents.
/// `parents` holds the parent of each commit that the pull reached, and
/// `naming` holds the entries of field 2 of each commit of the pull whose
/// field 2 is not empty. `pending` holds each attachment that the pull did
/// not reach.
///
/// The walk of each chain stops at a parent that the pull did not reach. The
/// result holds the attachments that a chain names first, in the order in
/// which the walk meets them: target by target, from the tip, and in field 2
/// order. The other attachments of `pending` follow, in the given order.
///
/// An attachment that no chain names gets its name from the commit of
/// `naming` with the lowest checksum that names it. If that commit names it
/// in two entries, the lowest name applies. So the name does not depend on
/// the order in which the pull fetched the commits.
pub(super) fn pair_targets(
    targets: &[(String, Checksum)],
    depth: i32,
    parents: &HashMap<Checksum, Option<Checksum>>,
    naming: &HashMap<Checksum, Vec<(String, Checksum)>>,
    pending: Vec<Checksum>,
) -> Vec<Named> {
    if pending.is_empty() {
        return Vec::new();
    }
    let wanted: HashSet<Checksum> = pending.iter().copied().collect();
    let mut out: Vec<Named> = Vec::new();
    let mut position: HashMap<Checksum, usize> = HashMap::new();
    for (target, (_, tip)) in targets.iter().enumerate() {
        let mut commit = *tip;
        let mut left = depth;
        loop {
            for (name, attachment) in naming.get(&commit).into_iter().flatten() {
                if !wanted.contains(attachment) {
                    continue;
                }
                let at = *position.entry(*attachment).or_insert_with(|| {
                    out.push(Named {
                        checksum: *attachment,
                        first: Some(target),
                        name: name.clone(),
                        pairs: Vec::new(),
                    });
                    out.len() - 1
                });
                let named = &mut out[at];
                if named.pairs.last().is_none_or(|(last, _)| *last != target) {
                    named.pairs.push((target, name.clone()));
                }
            }
            if left == 0 {
                break;
            }
            match parents.get(&commit) {
                Some(Some(parent)) if parents.contains_key(parent) => commit = *parent,
                _ => break,
            }
            if left > 0 {
                left -= 1;
            }
        }
    }
    let outside: HashSet<Checksum> = pending
        .iter()
        .filter(|checksum| !position.contains_key(*checksum))
        .copied()
        .collect();
    if outside.is_empty() {
        return out;
    }
    let mut names: HashMap<Checksum, (Checksum, &str)> = HashMap::new();
    for (commit, entries) in naming {
        for (name, attachment) in entries {
            if !outside.contains(attachment) {
                continue;
            }
            let candidate = (*commit, name.as_str());
            names
                .entry(*attachment)
                .and_modify(|lowest| *lowest = (*lowest).min(candidate))
                .or_insert(candidate);
        }
    }
    for checksum in pending {
        if !position.contains_key(&checksum) {
            let name = names
                .get(&checksum)
                .map_or_else(String::new, |(_, name)| (*name).to_owned());
            out.push(Named {
                checksum,
                first: None,
                name,
                pairs: Vec::new(),
            });
        }
    }
    out
}

/// Returns the delta lookup of each attachment of `named` that this
/// repository does not hold complete, in order, and the completeness of each
/// commit that the call checked.
///
/// `targets` and `named` are the arguments and the result of
/// [`pair_targets`]. `place` is the place of the pulled refs here. The call
/// reads the ref of each target that a pair names, the commit that the ref
/// names, and field 2 of that commit. A target whose name is the full hex
/// form of its commit is a pull by checksum, and gives no paired entry. So
/// does a name that is not a ref path, a ref that is absent, a commit that
/// this repository does not hold, and a field 2 that does not decode or has
/// a defective entry. If field 2 has two entries with one name, the first
/// entry is the paired entry.
///
/// `checked` holds the completeness of commits that the caller checked. The
/// call makes no check of such a commit, and gives `checked` back in the
/// result with its own checks.
///
/// The reads and the checks of completeness run in one call on the blocking
/// pool. Each commit gets one check. The search for the deltas reads the
/// checks again, and does not make them a second time.
///
/// # Errors
///
/// [`Error::Io`] or [`Error::InvalidFormat`] if a ref file cannot be read or
/// parsed, and the errors of the read of a commit object other than an
/// absent object.
pub(super) async fn lookups(
    repo: &Repo,
    targets: &[(String, Checksum)],
    place: RefPlace<'_>,
    named: Vec<Named>,
    checked: HashMap<Checksum, bool>,
) -> Result<(Vec<AttachmentLookup>, HashMap<Checksum, bool>)> {
    if named.is_empty() {
        return Ok((Vec::new(), checked));
    }
    let mut relpaths: Vec<Option<String>> = vec![None; targets.len()];
    for (target, _) in named.iter().flat_map(|named| &named.pairs) {
        let (name, tip) = &targets[*target];
        if relpaths[*target].is_none() && *name != tip.to_hex() {
            relpaths[*target] = place.ref_path(name).ok();
        }
    }
    let names: Vec<String> = targets.iter().map(|(name, _)| name.clone()).collect();
    let repo = repo.clone();
    ostrya_rt::unblock(move || {
        let mut entries: Vec<Option<HashMap<String, Checksum>>> = Vec::with_capacity(names.len());
        for relpath in &relpaths {
            entries.push(match relpath {
                Some(relpath) => held_entries(&repo, relpath)?,
                None => None,
            });
        }
        let mut complete = checked;
        let mut is_complete = |commit: &Checksum| -> Result<bool> {
            if let Some(held) = complete.get(commit) {
                return Ok(*held);
            }
            let held = complete_here_blocking(&repo, commit)?;
            complete.insert(*commit, held);
            Ok(held)
        };
        let mut out = Vec::with_capacity(named.len());
        for named in named {
            if is_complete(&named.checksum)? {
                continue;
            }
            let mut from = None;
            for (target, name) in &named.pairs {
                if let Some(paired) = entries[*target].as_ref().and_then(|map| map.get(name))
                    && is_complete(paired)?
                {
                    from = Some(*paired);
                    break;
                }
            }
            let target = names
                .get(named.first.unwrap_or(0))
                .map_or("", String::as_str);
            out.push(AttachmentLookup {
                checksum: named.checksum,
                subject: format!("{} of {target}", named.name),
                from,
                scratch: from.is_none(),
            });
        }
        Ok((out, complete))
    })
    .await
}

/// Returns the entries of field 2 of the commit that the ref at `relpath`
/// names in `repo`, by name, on the calling thread. Returns `None` for an
/// absent ref, an absent commit, and a field 2 that does not decode or has a
/// defective entry.
fn held_entries(repo: &Repo, relpath: &str) -> Result<Option<HashMap<String, Checksum>>> {
    let Some(tip) = repo.resolve_relpath_tip_blocking(relpath)? else {
        return Ok(None);
    };
    let Some(bytes) = repo.held_object_bytes_blocking(ObjectType::Commit, &tip)? else {
        return Ok(None);
    };
    let Ok(entries) = related::parse_attachments(&bytes).and_then(|entries| {
        related::checked_entries(RelationField::Attachments, Some(tip), entries)
    }) else {
        return Ok(None);
    };
    let mut map = HashMap::with_capacity(entries.len());
    for (name, checksum) in entries {
        map.entry(name).or_insert(checksum);
    }
    Ok(Some(map))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cs(byte: u8) -> Checksum {
        Checksum::from_bytes([byte; 32])
    }

    fn entries(list: &[(&str, u8)]) -> Vec<(String, Checksum)> {
        list.iter()
            .map(|(name, byte)| ((*name).to_owned(), cs(*byte)))
            .collect()
    }

    fn pending(list: &[u8]) -> Vec<Checksum> {
        list.iter().map(|byte| cs(*byte)).collect()
    }

    /// An attachment that two commits name is recorded once, with the commit
    /// and the entry name of the first. Each commit with an attachment is
    /// recorded, and a commit with an empty field 2 is not.
    #[test]
    fn attachments_keep_the_first_naming_commit() {
        let mut atts = Attachments::new(false);
        atts.record(cs(1), entries(&[("boot/uki", 3)]));
        atts.record(cs(2), entries(&[("lib/uki", 3), ("lib/c", 4)]));
        atts.record(cs(5), Vec::new());
        assert!(!atts.keys_only());
        assert_eq!(atts.order(), [cs(3), cs(4)]);
        assert_eq!(atts.named(&cs(3)), Some((cs(1), "boot/uki")));
        assert_eq!(atts.named(&cs(4)), Some((cs(2), "lib/c")));
        assert_eq!(atts.named(&cs(5)), None);
        let mut naming: Vec<&Checksum> = atts.naming().keys().collect();
        naming.sort_unstable();
        assert_eq!(naming, [&cs(1), &cs(2)]);
        assert_eq!(atts.naming()[&cs(2)][1], ("lib/c".to_owned(), cs(4)));
    }

    /// Under `keys_only`, the record keeps each commit that names an
    /// attachment, with an empty list, and keeps the order and the first
    /// naming commit of each attachment.
    #[test]
    fn attachments_keep_the_commits_alone_under_keys_only() {
        let mut atts = Attachments::new(true);
        atts.record(cs(1), entries(&[("boot/uki", 3)]));
        atts.record(cs(2), entries(&[("lib/c", 4), ("lib/uki", 3)]));
        atts.record(cs(5), Vec::new());
        assert!(atts.keys_only());
        assert_eq!(atts.order(), [cs(3), cs(4)]);
        assert_eq!(atts.named(&cs(3)), Some((cs(1), "boot/uki")));
        let mut naming: Vec<&Checksum> = atts.naming().keys().collect();
        naming.sort_unstable();
        assert_eq!(naming, [&cs(1), &cs(2)]);
        assert!(atts.naming().values().all(Vec::is_empty));
    }

    /// The error for an attachment names the commit and the entry that first
    /// named the attachment, with the end of the reason that the caller
    /// gives. The nested-attachment error has the same form. An attachment
    /// that no commit named gives no error.
    #[test]
    fn an_attachment_error_names_the_first_naming_commit() {
        let mut atts = Attachments::new(false);
        atts.record(cs(1), entries(&[("lib/b", 2)]));
        atts.record(cs(3), entries(&[("lib/x", 2)]));
        let reason = |err: Option<Error>| match err {
            Some(Error::InvalidRelations {
                commit,
                field: RelationField::Attachments,
                reason,
            }) => (commit, reason),
            other => panic!("expected InvalidRelations in field 2, got {other:?}"),
        };
        assert_eq!(
            reason(atts.named_error(&cs(2), related::UNHELD_REASON)),
            (
                Some(cs(1)),
                format!(
                    "attachment lib/b names commit {}, which neither a source nor this \
                     repository holds",
                    cs(2)
                )
            )
        );
        assert_eq!(
            reason(atts.nested_error(&cs(2))),
            (
                Some(cs(1)),
                format!(
                    "attachment lib/b names commit {}, which has attachments of its own",
                    cs(2)
                )
            )
        );
        assert!(atts.named_error(&cs(4), related::UNHELD_REASON).is_none());
        assert!(atts.nested_error(&cs(4)).is_none());
    }

    /// One result of [`pair_targets`]: the first byte of the checksum, the
    /// first target, the name, and the pairs.
    type Flat<'a> = (u8, Option<usize>, &'a str, Vec<(usize, &'a str)>);

    /// Returns each result of [`pair_targets`] as a [`Flat`].
    fn flat(named: &[Named]) -> Vec<Flat<'_>> {
        named
            .iter()
            .map(|named| {
                (
                    named.checksum.as_bytes()[0],
                    named.first,
                    named.name.as_str(),
                    named
                        .pairs
                        .iter()
                        .map(|(target, name)| (*target, name.as_str()))
                        .collect(),
                )
            })
            .collect()
    }

    /// Two targets name one attachment under different names. The first
    /// target gives the first pair and the name of the error. An attachment
    /// that no chain names follows.
    #[test]
    fn the_first_target_names_an_attachment_first() {
        let targets = vec![("one".to_owned(), cs(1)), ("two".to_owned(), cs(2))];
        let parents = HashMap::from([(cs(1), None), (cs(2), None), (cs(5), None)]);
        let naming = HashMap::from([
            (cs(1), entries(&[("boot/a", 9)])),
            (cs(2), entries(&[("boot/b", 9), ("boot/c", 8)])),
            (cs(5), entries(&[("lib/x", 7)])),
        ]);
        let named = pair_targets(&targets, 0, &parents, &naming, pending(&[7, 8, 9]));
        assert_eq!(
            flat(&named),
            [
                (9, Some(0), "boot/a", vec![(0, "boot/a"), (1, "boot/b")]),
                (8, Some(1), "boot/c", vec![(1, "boot/c")]),
                (7, None, "lib/x", vec![]),
            ]
        );
        assert!(pair_targets(&targets, 0, &parents, &naming, Vec::new()).is_empty());
    }

    /// An attachment that no chain names takes its name from the commit with
    /// the lowest checksum that names it, and from the lowest name of that
    /// commit. The order in which the pull recorded the commits does not
    /// change the name.
    #[test]
    fn an_attachment_outside_every_chain_takes_the_lowest_name() {
        let targets = vec![("main".to_owned(), cs(1))];
        let parents = HashMap::from([(cs(1), None)]);
        let records = [
            (cs(6), entries(&[("lib/f", 9)])),
            (cs(4), entries(&[("lib/z", 9), ("lib/d", 9)])),
            (cs(5), entries(&[("lib/a", 9)])),
        ];
        for order in [[0, 1, 2], [2, 1, 0], [1, 2, 0]] {
            let mut naming = HashMap::new();
            for at in order {
                naming.insert(records[at].0, records[at].1.clone());
            }
            let named = pair_targets(&targets, -1, &parents, &naming, pending(&[9]));
            assert_eq!(flat(&named), [(9, None, "lib/d", vec![])]);
        }
    }

    /// The walk of a chain stops at the depth of the pull and at a parent
    /// that the pull did not reach. The entry nearest to the tip gives the
    /// pair of a target.
    #[test]
    fn the_walk_keeps_to_the_depth_and_the_reached_parents() {
        let targets = vec![("main".to_owned(), cs(1))];
        // 1 -> 2 -> 3 -> 4, and the pull did not reach 4.
        let parents = HashMap::from([
            (cs(1), Some(cs(2))),
            (cs(2), Some(cs(3))),
            (cs(3), Some(cs(4))),
        ]);
        let naming = HashMap::from([
            (cs(1), entries(&[("boot/new", 9)])),
            (cs(2), entries(&[("boot/old", 9), ("boot/two", 8)])),
            (cs(3), entries(&[("boot/three", 7)])),
            (cs(4), entries(&[("boot/four", 6)])),
        ]);
        let all = pending(&[6, 7, 8, 9]);
        let at = |depth| {
            flat(&pair_targets(
                &targets,
                depth,
                &parents,
                &naming,
                all.clone(),
            ))
            .into_iter()
            .map(|(byte, first, _, pairs)| (byte, first, pairs.len()))
            .collect::<Vec<_>>()
        };
        assert_eq!(
            flat(&pair_targets(&targets, 1, &parents, &naming, all.clone()))[0],
            (9, Some(0), "boot/new", vec![(0, "boot/new")])
        );
        assert_eq!(
            at(0),
            [(9, Some(0), 1), (6, None, 0), (7, None, 0), (8, None, 0)]
        );
        assert_eq!(
            at(1),
            [(9, Some(0), 1), (8, Some(0), 1), (6, None, 0), (7, None, 0)]
        );
        for depth in [-1, 5] {
            assert_eq!(
                at(depth),
                [
                    (9, Some(0), 1),
                    (8, Some(0), 1),
                    (7, Some(0), 1),
                    (6, None, 0)
                ]
            );
        }
    }
}
