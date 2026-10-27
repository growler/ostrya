//! The planner of chains of static deltas over a list that the caller gives.
//!
//! [`PullOptions::static_deltas`](crate::PullOptions::static_deltas) holds the
//! list. Each entry is one step: a delta from its source commit to its target
//! commit. A delta from scratch is a step from no commit. The scratch rule of
//! the target decides if a chain can take such a step, as [`scratch_allowed`]
//! states.
//!
//! [`plan_chain`] finds the chain with the fewest steps to one target. The
//! search is breadth-first and goes backward from the target, one level of
//! steps at a time. A chain starts at a commit that this repository holds
//! complete, or with a step from scratch. The search ignores a delta from a
//! commit to itself, and a cycle in the list ends the search. These rules
//! break a tie between two chains with the same number of steps, in this
//! order:
//!
//! 1. A chain that starts at a complete commit wins over a chain that starts
//!    with a step from scratch.
//! 2. The chain whose first step comes first in the list wins.
//! 3. The chain whose list indices come first in lexicographic order wins.
//!
//! [`merge`] joins the chains of the targets of one pull. If two chains make
//! the same commit, the first chain wins. Then `merge` removes each step that
//! makes no target and whose commit no kept step reads. The intermediate
//! commits of the result go into levels. A commit of a level is made from a
//! complete commit, from scratch, or from a commit of an earlier level.
//!
//! [`Edges`] owns the list and sorts its indices once, by target. A search
//! finds the steps to a commit with a binary search, and visits only the
//! steps that reach its target. Each commit enters a search once.
//! [`complete_sources`] checks each commit that reaches a target at most
//! once, in batches on the blocking pool.
//!
//! [`ChainSearch`] owns the list, the complete commits, and the result of the
//! search of each target. Discovery moves it to the blocking pool for each
//! pass. If the remote does not hold a delta of the plan, discovery excludes
//! that delta. The search then plans again only the targets whose chain holds
//! it, and merges the chains again.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};

use ostrya_core::Checksum;

use crate::deltagen::delta_name;
use crate::error::{Error, Result};
use crate::repo::Repo;
use crate::summary::AdvertisedDelta;

use super::delta::complete_here_blocking;

/// Returns `true` if a pull can take a delta from scratch to `to`.
///
/// `tip` is the commit that the pulled ref names in this repository. `from`
/// is the source commit that the pull found for the ref: `tip`, if this
/// repository holds it complete. A ref that names a complete commit stops a
/// delta from scratch, which delivers each object of the target again. If the
/// ref names the target and the target is partial here, the pull also takes no
/// delta from scratch. In both cases the pull fetches the missing objects
/// loose.
pub(super) fn scratch_allowed(
    tip: Option<Checksum>,
    from: Option<Checksum>,
    to: &Checksum,
) -> bool {
    from.is_none() && tip != Some(*to)
}

/// The deltas of a list, by target commit.
pub(super) struct Edges {
    /// The list that the caller gives.
    list: Vec<AdvertisedDelta>,
    /// The indices into `list`, sorted by target commit and then by source
    /// commit. Each pair of source and target is here once, at the index of
    /// its first entry in `list`.
    by_target: Vec<usize>,
}

impl Edges {
    /// Sorts the indices of `list` by target commit, and keeps `list`.
    ///
    /// An entry that is equal to an earlier entry is dropped, and the earlier
    /// entry keeps its index.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInput`] if two entries have the same source and target
    /// and different digests. The message names the delta.
    pub(super) fn new(list: Vec<AdvertisedDelta>) -> Result<Edges> {
        let mut by_target: Vec<usize> = (0..list.len()).collect();
        // The index breaks a tie, so the first entry of a pair comes first.
        by_target.sort_unstable_by(|&a, &b| {
            (&list[a].to, &list[a].from, a).cmp(&(&list[b].to, &list[b].from, b))
        });
        for pair in by_target.windows(2) {
            let (earlier, later) = (&list[pair[0]], &list[pair[1]]);
            if earlier.from == later.from
                && earlier.to == later.to
                && earlier.superblock != later.superblock
            {
                return Err(Error::InvalidInput(format!(
                    "static delta {} is listed with two superblock digests",
                    delta_name(earlier.from.as_ref(), &earlier.to)
                )));
            }
        }
        by_target.dedup_by(|later, earlier| {
            list[*later].from == list[*earlier].from && list[*later].to == list[*earlier].to
        });
        Ok(Edges { list, by_target })
    }

    /// Returns the entry of the list at `index`.
    pub(super) fn delta(&self, index: usize) -> &AdvertisedDelta {
        &self.list[index]
    }

    /// Returns the list indices of the steps to `to`, sorted by source commit.
    /// A step from scratch comes first.
    fn steps_to(&self, to: &Checksum) -> &[usize] {
        let start = self
            .by_target
            .partition_point(|&index| self.list[index].to < *to);
        let len = self.by_target[start..]
            .iter()
            .take_while(|&&index| self.list[index].to == *to)
            .count();
        &self.by_target[start..start + len]
    }
}

/// The result of the search for a chain to one target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Planned {
    /// The list indices of the steps of the chain, first step first.
    Chain(Vec<usize>),
    /// No chain. The list holds a delta from scratch to the target itself
    /// that is not excluded and that the scratch rule refuses. This delta
    /// meets the requirement of
    /// [`require_static_deltas`](crate::PullOptions::require_static_deltas).
    Declined,
    /// No chain.
    None,
}

/// Finds the chain with the fewest steps to `target`.
///
/// `complete` holds the commits that this repository holds complete.
/// `scratch` is the scratch rule for this target, from [`scratch_allowed`].
/// `excluded` holds the list indices of the deltas that the remote does not
/// hold. The caller gives a target that this repository does not hold
/// complete. The module doc states the rules of the search.
pub(super) fn plan_chain(
    edges: &Edges,
    target: &Checksum,
    complete: &HashSet<Checksum>,
    scratch: bool,
    excluded: &HashSet<usize>,
) -> Planned {
    // No complete commit and no step from scratch can start a chain.
    if !scratch && complete.is_empty() {
        return no_chain(edges, target, scratch, excluded);
    }
    // For each commit that the search reached: its number of steps to the
    // target, and the smallest list index of a step from it to a commit one
    // step nearer the target. The target has no step.
    let mut seen: HashMap<Checksum, (u32, usize)> = HashMap::new();
    seen.insert(*target, (0, usize::MAX));
    let mut frontier = vec![*target];
    let mut distance = 0u32;
    while !frontier.is_empty() {
        let mut next = Vec::new();
        let mut scratch_first: Option<usize> = None;
        for node in &frontier {
            for &index in edges.steps_to(node) {
                if excluded.contains(&index) {
                    continue;
                }
                let Some(source) = edges.delta(index).from else {
                    if scratch {
                        scratch_first = Some(scratch_first.map_or(index, |best| best.min(index)));
                    }
                    continue;
                };
                // A source that the search reached at this level or before,
                // the node itself included, gives no shorter chain.
                match seen.entry(source) {
                    Entry::Vacant(entry) => {
                        entry.insert((distance + 1, index));
                        next.push(source);
                    }
                    Entry::Occupied(mut entry) => {
                        let (reached, best) = entry.get_mut();
                        if *reached == distance + 1 && index < *best {
                            *best = index;
                        }
                    }
                }
            }
        }
        // A complete commit of the next level starts a chain of the same
        // length as a step from scratch at this level, and wins over it.
        let first = next
            .iter()
            .filter(|source| complete.contains(*source))
            .map(|source| seen[source].1)
            .min()
            .or(scratch_first);
        if let Some(first) = first {
            let mut chain = vec![first];
            let mut made = edges.delta(first).to;
            while made != *target {
                let step = seen[&made].1;
                chain.push(step);
                made = edges.delta(step).to;
            }
            return Planned::Chain(chain);
        }
        frontier = next;
        distance += 1;
    }
    no_chain(edges, target, scratch, excluded)
}

/// Returns the result of a search that finds no chain to `target`:
/// [`Planned::Declined`] or [`Planned::None`].
fn no_chain(edges: &Edges, target: &Checksum, scratch: bool, excluded: &HashSet<usize>) -> Planned {
    let declined = !scratch
        && edges
            .steps_to(target)
            .iter()
            .any(|index| edges.delta(*index).from.is_none() && !excluded.contains(index));
    if declined {
        Planned::Declined
    } else {
        Planned::None
    }
}

/// The steps that the chains of the targets of one pull keep.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct ChainPlan {
    /// The list index of the step that makes each commit of the plan.
    pub(super) steps: HashMap<Checksum, usize>,
    /// The commits that a kept step reads, by level, in plan order.
    ///
    /// A commit of level 0 is made from a complete commit or from scratch. A
    /// commit of level `k` is made from a commit of level `k - 1`. A commit in
    /// `steps` and in no level is a target that no kept step reads, and the
    /// pull applies it last.
    pub(super) levels: Vec<Vec<Checksum>>,
}

/// Joins the chains of the targets of one pull.
///
/// `chains` gives the chain of each target that has one, in the order of the
/// targets. `targets` holds each requested target that this repository does
/// not hold complete. A target that the chain of another target makes stays
/// in the plan, also if its own scratch rule refuses that step.
pub(super) fn merge<'a>(
    edges: &Edges,
    chains: impl IntoIterator<Item = &'a Vec<usize>>,
    targets: &HashSet<Checksum>,
) -> ChainPlan {
    // The first chain that makes a commit gives its step. A step reads a
    // commit that comes before its own commit in `order`, so `order` is a
    // topological order of the plan.
    let mut steps: HashMap<Checksum, usize> = HashMap::new();
    let mut order: Vec<Checksum> = Vec::new();
    for chain in chains {
        for &index in chain {
            let made = edges.delta(index).to;
            if let Entry::Vacant(entry) = steps.entry(made) {
                entry.insert(index);
                order.push(made);
            }
        }
    }
    // The number of kept steps that read each commit of the plan.
    let mut readers: HashMap<Checksum, u32> = HashMap::new();
    for index in steps.values() {
        if let Some(source) = edges.delta(*index).from
            && steps.contains_key(&source)
        {
            *readers.entry(source).or_default() += 1;
        }
    }
    let unread = |readers: &HashMap<Checksum, u32>, commit: &Checksum| {
        !targets.contains(commit) && readers.get(commit).is_none_or(|count| *count == 0)
    };
    let mut removable: Vec<Checksum> = order
        .iter()
        .filter(|commit| unread(&readers, commit))
        .copied()
        .collect();
    while let Some(commit) = removable.pop() {
        let Some(index) = steps.remove(&commit) else {
            continue;
        };
        if let Some(source) = edges.delta(index).from
            && let Some(count) = readers.get_mut(&source)
        {
            *count -= 1;
            if unread(&readers, &source) {
                removable.push(source);
            }
        }
    }
    let mut depth: HashMap<Checksum, usize> = HashMap::with_capacity(steps.len());
    let mut levels: Vec<Vec<Checksum>> = Vec::new();
    for commit in &order {
        let Some(index) = steps.get(commit) else {
            continue;
        };
        let level = edges
            .delta(*index)
            .from
            .and_then(|source| depth.get(&source))
            .map_or(0, |source_level| source_level + 1);
        depth.insert(*commit, level);
        if readers.get(commit).is_some_and(|count| *count > 0) {
            if levels.len() <= level {
                levels.resize_with(level + 1, Vec::new);
            }
            levels[level].push(*commit);
        }
    }
    ChainPlan { steps, levels }
}

/// The number of deltas that one search excludes and plans again around.
///
/// Each exclusion costs a new search for each target whose chain holds the
/// delta. The limit bounds this cost for a list that names many deltas that
/// the remote does not hold. After the limit, a target whose chain holds an
/// excluded delta gets no chain.
pub(super) const MAX_EXCLUDED: usize = 64;

/// The search for the chains of the targets of one pull.
///
/// The search owns its data, so a caller can move it to the blocking pool for
/// each pass. A pass plans each target that needs it and merges the chains.
pub(super) struct ChainSearch {
    edges: Edges,
    /// The commits that this repository holds complete.
    complete: HashSet<Checksum>,
    /// The list indices of the deltas that the remote does not hold.
    excluded: HashSet<usize>,
    /// Each target and its scratch rule, in the order of the targets.
    targets: Vec<(Checksum, bool)>,
    /// The commits of `targets`.
    target_set: HashSet<Checksum>,
    /// The result of the search of each target, in the order of `targets`.
    planned: Vec<Planned>,
}

impl ChainSearch {
    /// Plans the chain of each target in `targets` over `edges`.
    ///
    /// `targets` holds each target that this repository does not hold
    /// complete, once, with its scratch rule. `complete` holds the commits
    /// that [`complete_sources`] found.
    pub(super) fn new(
        edges: Edges,
        complete: HashSet<Checksum>,
        targets: Vec<(Checksum, bool)>,
    ) -> ChainSearch {
        let excluded = HashSet::new();
        let planned = targets
            .iter()
            .map(|(target, scratch)| plan_chain(&edges, target, &complete, *scratch, &excluded))
            .collect();
        let target_set = targets.iter().map(|(target, _)| *target).collect();
        ChainSearch {
            edges,
            complete,
            excluded,
            targets,
            target_set,
            planned,
        }
    }

    /// Excludes the delta at list index `index`, and plans again each target
    /// whose chain holds it.
    ///
    /// After [`MAX_EXCLUDED`] deltas, the search does not plan again. Each
    /// target whose chain holds `index` then gets no chain. A delta from
    /// scratch to such a target that the scratch rule refuses still gives
    /// [`Planned::Declined`].
    pub(super) fn exclude(&mut self, index: usize) {
        let again = self.excluded.len() < MAX_EXCLUDED;
        self.excluded.insert(index);
        for ((target, scratch), planned) in self.targets.iter().zip(&mut self.planned) {
            if matches!(planned, Planned::Chain(chain) if chain.contains(&index)) {
                *planned = if again {
                    plan_chain(
                        &self.edges,
                        target,
                        &self.complete,
                        *scratch,
                        &self.excluded,
                    )
                } else {
                    no_chain(&self.edges, target, *scratch, &self.excluded)
                };
            }
        }
    }

    /// Joins the chains of the targets with [`merge`].
    pub(super) fn merged(&self) -> ChainPlan {
        let chains = self.planned.iter().filter_map(|planned| match planned {
            Planned::Chain(chain) => Some(chain),
            _ => None,
        });
        merge(&self.edges, chains, &self.target_set)
    }

    /// Returns each target, in the order of the targets, with the result of
    /// its search.
    pub(super) fn targets(&self) -> impl Iterator<Item = (&Checksum, &Planned)> {
        self.targets
            .iter()
            .map(|(target, _)| target)
            .zip(&self.planned)
    }

    /// Returns the deltas of the search.
    pub(super) fn edges(&self) -> &Edges {
        &self.edges
    }
}

/// The maximum number of commits that one blocking call of
/// [`complete_sources`] checks.
const COMPLETE_BATCH: usize = 4096;

/// Returns the commits that this repository holds complete and that start a
/// chain to a target.
///
/// `targets` holds the requested targets that this repository does not hold
/// complete. The walk goes backward over the list from the targets, one level
/// at a time. The walk of each level and the check of its new source commits
/// run on the blocking pool, at most [`COMPLETE_BATCH`] commits in one call.
/// The walk checks each source commit once, and does not walk past a complete
/// commit. The function takes `edges` and gives it back, so that the walk can
/// move it to the blocking pool.
pub(super) async fn complete_sources(
    repo: &Repo,
    edges: Edges,
    targets: &[Checksum],
) -> Result<(Edges, HashSet<Checksum>)> {
    let mut edges = edges;
    let mut complete = HashSet::new();
    let mut seen: HashSet<Checksum> = targets.iter().copied().collect();
    let mut frontier: Vec<Checksum> = targets.to_vec();
    while !frontier.is_empty() {
        let sources;
        (edges, seen, sources) = ostrya_rt::unblock(move || {
            let mut sources = Vec::new();
            for node in &frontier {
                for &index in edges.steps_to(node) {
                    if let Some(source) = edges.delta(index).from
                        && seen.insert(source)
                    {
                        sources.push(source);
                    }
                }
            }
            (edges, seen, sources)
        })
        .await;
        frontier = Vec::new();
        for (commit, is_complete) in check_complete(repo, &sources).await? {
            if is_complete {
                complete.insert(commit);
            } else {
                frontier.push(commit);
            }
        }
    }
    Ok((edges, complete))
}

/// Returns each commit of `commits` with `true` if this repository holds it
/// complete, in order.
///
/// The checks run on the blocking pool, at most [`COMPLETE_BATCH`] commits in
/// one call.
pub(super) async fn check_complete(
    repo: &Repo,
    commits: &[Checksum],
) -> Result<Vec<(Checksum, bool)>> {
    let mut checked = Vec::with_capacity(commits.len());
    for batch in commits.chunks(COMPLETE_BATCH) {
        let repo = repo.clone();
        let batch = batch.to_vec();
        checked.extend(
            ostrya_rt::unblock(move || {
                batch
                    .into_iter()
                    .map(|commit| Ok((commit, complete_here_blocking(&repo, &commit)?)))
                    .collect::<Result<Vec<_>>>()
            })
            .await?,
        );
    }
    Ok(checked)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cs(byte: u8) -> Checksum {
        Checksum::from_bytes([byte; 32])
    }

    /// Returns the delta from `from` to `to`, with a digest that the pair
    /// gives. `None` is a delta from scratch.
    fn d(from: Option<u8>, to: u8) -> AdvertisedDelta {
        let mut digest = [0xd5; 32];
        digest[0] = from.unwrap_or(0);
        digest[1] = to;
        digest[2] = u8::from(from.is_some());
        AdvertisedDelta {
            from: from.map(cs),
            to: cs(to),
            superblock: Checksum::from_bytes(digest),
        }
    }

    fn set(bytes: &[u8]) -> HashSet<Checksum> {
        bytes.iter().copied().map(cs).collect()
    }

    /// Plans the chain to `target` over `list`.
    fn plan(
        list: &[AdvertisedDelta],
        target: u8,
        complete: &[u8],
        scratch: bool,
        excluded: &[usize],
    ) -> Planned {
        let edges = Edges::new(list.to_vec()).unwrap();
        let excluded = excluded.iter().copied().collect();
        plan_chain(&edges, &cs(target), &set(complete), scratch, &excluded)
    }

    /// Returns each step of `planned` as its source and its target.
    fn steps(list: &[AdvertisedDelta], planned: Planned) -> Vec<(Option<u8>, u8)> {
        let Planned::Chain(chain) = planned else {
            panic!("no chain: {planned:?}");
        };
        chain.iter().map(|index| pair(&list[*index])).collect()
    }

    fn pair(delta: &AdvertisedDelta) -> (Option<u8>, u8) {
        (
            delta.from.map(|from| from.as_bytes()[0]),
            delta.to.as_bytes()[0],
        )
    }

    const A: u8 = b'A';
    const B: u8 = b'B';
    const C: u8 = b'C';
    const P: u8 = b'P';
    const Q: u8 = b'Q';
    const R: u8 = b'R';
    const T: u8 = b'T';
    const X: u8 = b'X';
    const Y: u8 = b'Y';

    #[test]
    fn a_direct_delta_wins_over_a_chain() {
        let list = [d(Some(A), B), d(Some(B), T), d(Some(A), T)];
        let planned = plan(&list, T, &[A], false, &[]);
        assert_eq!(steps(&list, planned), [(Some(A), T)]);
    }

    #[test]
    fn a_chain_of_three_steps() {
        let list = [d(Some(A), B), d(Some(B), C), d(Some(C), T)];
        let planned = plan(&list, T, &[A], false, &[]);
        assert_eq!(
            steps(&list, planned),
            [(Some(A), B), (Some(B), C), (Some(C), T)]
        );
    }

    /// The chain starts at a complete commit that no ref names. The delta
    /// from a commit that is not complete gives no chain.
    #[test]
    fn a_chain_starts_at_a_complete_commit() {
        let list = [d(Some(R), T), d(Some(X), Y), d(Some(Y), T)];
        let planned = plan(&list, T, &[X], false, &[]);
        assert_eq!(steps(&list, planned), [(Some(X), Y), (Some(Y), T)]);
    }

    #[test]
    fn a_cycle_ends_and_a_delta_to_itself_is_ignored() {
        let list = [d(Some(B), C), d(Some(C), B), d(Some(C), C)];
        assert_eq!(plan(&list, C, &[], false, &[]), Planned::None);

        let list = [d(Some(B), B), d(Some(B), T)];
        let planned = plan(&list, T, &[B], false, &[]);
        assert_eq!(steps(&list, planned), [(Some(B), T)]);

        let list = [d(Some(T), B), d(Some(B), T)];
        assert_eq!(plan(&list, T, &[], false, &[]), Planned::None);
    }

    #[test]
    fn no_chain_gives_none() {
        let list = [d(Some(A), B), d(Some(C), T)];
        assert_eq!(plan(&list, T, &[A], true, &[]), Planned::None);
        assert_eq!(plan(&[], T, &[A], true, &[]), Planned::None);
    }

    #[test]
    fn the_scratch_rule() {
        let (to, other) = (cs(T), cs(B));
        // A ref that names no commit.
        assert!(scratch_allowed(None, None, &to));
        // A ref that names the target, held here partial.
        assert!(!scratch_allowed(Some(to), None, &to));
        // A ref that names a complete commit.
        assert!(!scratch_allowed(Some(other), Some(other), &to));
        // A ref that names another commit, held here partial.
        assert!(scratch_allowed(Some(other), None, &to));

        let list = [d(None, T)];
        let planned = plan(&list, T, &[], true, &[]);
        assert_eq!(steps(&list, planned), [(None, T)]);
        assert_eq!(plan(&list, T, &[], false, &[]), Planned::Declined);

        // A step from scratch to an intermediate commit follows the rule of
        // the target, and a refused one is not reported.
        let list = [d(None, P), d(Some(P), T)];
        let planned = plan(&list, T, &[], true, &[]);
        assert_eq!(steps(&list, planned), [(None, P), (Some(P), T)]);
        assert_eq!(plan(&list, T, &[], false, &[]), Planned::None);
    }

    #[test]
    fn a_refused_delta_from_scratch_is_reported() {
        let list = [d(None, T), d(Some(A), B)];
        assert_eq!(plan(&list, T, &[A], false, &[]), Planned::Declined);

        // A chain wins over the report.
        let list = [d(None, T), d(Some(A), T)];
        let planned = plan(&list, T, &[A], false, &[]);
        assert_eq!(steps(&list, planned), [(Some(A), T)]);

        // An excluded delta from scratch is not reported.
        let list = [d(None, T)];
        assert_eq!(plan(&list, T, &[], false, &[0]), Planned::None);
    }

    /// With no complete commit and no step from scratch, the search gives
    /// the same result as a search with a complete commit that starts no
    /// chain.
    #[test]
    fn no_complete_commit_and_no_scratch_gives_no_chain() {
        for (list, excluded, expected) in [
            (vec![d(None, T), d(Some(A), T)], vec![], Planned::Declined),
            (vec![d(None, T), d(Some(A), T)], vec![0], Planned::None),
            (vec![d(Some(A), B), d(Some(B), T)], vec![], Planned::None),
        ] {
            assert_eq!(plan(&list, T, &[], false, &excluded), expected, "{list:?}");
            assert_eq!(plan(&list, T, &[X], false, &excluded), expected, "{list:?}");
        }
    }

    #[test]
    fn a_complete_start_wins_over_scratch_at_equal_length() {
        for list in [
            vec![d(None, T), d(Some(A), T)],
            vec![d(Some(A), T), d(None, T)],
        ] {
            let planned = plan(&list, T, &[A], true, &[]);
            assert_eq!(steps(&list, planned), [(Some(A), T)], "{list:?}");
        }
        for list in [
            vec![d(None, P), d(Some(P), T), d(Some(A), Q), d(Some(Q), T)],
            vec![d(Some(A), Q), d(Some(Q), T), d(None, P), d(Some(P), T)],
        ] {
            let planned = plan(&list, T, &[A], true, &[]);
            assert_eq!(
                steps(&list, planned),
                [(Some(A), Q), (Some(Q), T)],
                "{list:?}"
            );
        }
        // A shorter chain from scratch wins over a longer chain.
        let list = [d(Some(A), B), d(Some(B), T), d(None, T)];
        let planned = plan(&list, T, &[A], true, &[]);
        assert_eq!(steps(&list, planned), [(None, T)]);
    }

    #[test]
    fn the_list_order_breaks_a_tie() {
        let list = [d(Some(B), T), d(Some(A), T)];
        let planned = plan(&list, T, &[A, B], false, &[]);
        assert_eq!(steps(&list, planned), [(Some(B), T)]);

        let list = [d(Some(A), T), d(Some(B), T)];
        let planned = plan(&list, T, &[A, B], false, &[]);
        assert_eq!(steps(&list, planned), [(Some(A), T)]);

        // The first step decides, also if a later step of the other chain
        // comes first.
        let list = [d(Some(A), X), d(Some(B), Y), d(Some(Y), T), d(Some(X), T)];
        let planned = plan(&list, T, &[A, B], false, &[]);
        assert_eq!(steps(&list, planned), [(Some(A), X), (Some(X), T)]);

        // With the same first step, the second step that comes first in the
        // list wins, also if the third step of its chain comes last.
        let list = [
            d(Some(A), P),
            d(Some(P), Q),
            d(Some(P), R),
            d(Some(R), T),
            d(Some(Q), T),
        ];
        let edges = Edges::new(list.to_vec()).unwrap();
        let planned = plan_chain(&edges, &cs(T), &set(&[A]), false, &HashSet::new());
        assert_eq!(planned, Planned::Chain(vec![0, 1, 4]));
    }

    /// Asserts that each step of `plan` reads a complete commit, nothing, or
    /// a commit of an earlier level, and that each commit is in one level at
    /// most.
    fn assert_acyclic(edges: &Edges, plan: &ChainPlan, complete: &HashSet<Checksum>) {
        let mut level_of = HashMap::new();
        for (level, commits) in plan.levels.iter().enumerate() {
            for commit in commits {
                assert!(level_of.insert(*commit, level).is_none(), "{commit}");
                assert!(plan.steps.contains_key(commit), "{commit}");
            }
        }
        for (commit, index) in &plan.steps {
            let level = level_of.get(commit).copied().unwrap_or(plan.levels.len());
            match edges.delta(*index).from {
                None => {}
                Some(source) if complete.contains(&source) => {}
                Some(source) => {
                    let source_level = level_of[&source];
                    assert!(source_level < level, "{source} -> {commit}");
                }
            }
        }
    }

    fn plan_steps(list: &[AdvertisedDelta], plan: &ChainPlan) -> Vec<(Option<u8>, u8)> {
        let mut steps: Vec<_> = plan.steps.values().map(|i| pair(&list[*i])).collect();
        steps.sort();
        steps
    }

    const T1: u8 = 0x71;
    const T2: u8 = 0x72;

    #[test]
    fn two_targets_share_a_step() {
        let list = [d(Some(A), B), d(Some(B), T1), d(Some(B), T2)];
        let edges = Edges::new(list.to_vec()).unwrap();
        let complete = set(&[A]);
        let none = HashSet::new();
        let chains: Vec<Vec<usize>> = [T1, T2]
            .iter()
            .map(
                |target| match plan_chain(&edges, &cs(*target), &complete, false, &none) {
                    Planned::Chain(chain) => chain,
                    other => panic!("{other:?}"),
                },
            )
            .collect();
        let plan = merge(&edges, &chains, &set(&[T1, T2]));
        assert_eq!(
            plan_steps(&list, &plan),
            [(Some(A), B), (Some(B), T1), (Some(B), T2)]
        );
        assert_eq!(plan.levels, [vec![cs(B)]]);
        assert_acyclic(&edges, &plan, &complete);
    }

    #[test]
    fn a_target_is_an_intermediate_commit_of_another_target() {
        let list = [d(Some(A), T1), d(Some(T1), T2)];
        let edges = Edges::new(list.to_vec()).unwrap();
        let complete = set(&[A]);
        let none = HashSet::new();
        let chain_of = |target: u8| match plan_chain(&edges, &cs(target), &complete, false, &none) {
            Planned::Chain(chain) => chain,
            other => panic!("{other:?}"),
        };
        for targets in [[T1, T2], [T2, T1]] {
            let chains: Vec<_> = targets.iter().map(|target| chain_of(*target)).collect();
            let plan = merge(&edges, &chains, &set(&targets));
            assert_eq!(plan_steps(&list, &plan), [(Some(A), T1), (Some(T1), T2)]);
            assert_eq!(plan.levels, [vec![cs(T1)]], "{targets:?}");
            assert_acyclic(&edges, &plan, &complete);
        }
    }

    /// Target `X` takes the delta from scratch. Target `T` has the chain
    /// `A-P`, `P-X`, `X-T`. The merged plan holds no `A-P` and no `P-X`.
    #[test]
    fn merge_removes_a_step_that_no_kept_step_reads() {
        let list = [d(None, X), d(Some(A), P), d(Some(P), X), d(Some(X), T)];
        let edges = Edges::new(list.to_vec()).unwrap();
        let complete = set(&[A]);
        let none = HashSet::new();
        let to_x = plan_chain(&edges, &cs(X), &complete, true, &none);
        assert_eq!(to_x, Planned::Chain(vec![0]));
        let to_t = plan_chain(&edges, &cs(T), &complete, false, &none);
        assert_eq!(to_t, Planned::Chain(vec![1, 2, 3]));
        let plan = merge(&edges, &[vec![0], vec![1, 2, 3]], &set(&[X, T]));
        assert_eq!(plan_steps(&list, &plan), [(None, X), (Some(X), T)]);
        assert_eq!(plan.steps[&cs(X)], 0);
        assert_eq!(plan.levels, [vec![cs(X)]]);
        assert_acyclic(&edges, &plan, &complete);

        // The removal of `Q-X` leaves `P-Q` unread, so `merge` removes it
        // too.
        let list = [
            d(None, X),
            d(Some(A), P),
            d(Some(P), Q),
            d(Some(Q), X),
            d(Some(X), T),
        ];
        let edges = Edges::new(list.to_vec()).unwrap();
        let plan = merge(&edges, &[vec![0], vec![1, 2, 3, 4]], &set(&[X, T]));
        assert_eq!(plan_steps(&list, &plan), [(None, X), (Some(X), T)]);
        assert_eq!(plan.levels, [vec![cs(X)]]);
        assert_acyclic(&edges, &plan, &complete);
    }

    #[test]
    fn an_excluded_delta_is_not_used() {
        let list = [d(Some(A), T), d(Some(A), B), d(Some(B), T)];
        let planned = plan(&list, T, &[A], false, &[0]);
        assert_eq!(steps(&list, planned), [(Some(A), B), (Some(B), T)]);
        assert_eq!(plan(&list, T, &[A], false, &[0, 1, 2]), Planned::None);
    }

    /// An exclusion plans again each target whose chain holds the excluded
    /// delta, and gives the result of a new search with the same exclusion.
    #[test]
    fn an_exclusion_plans_again_the_targets_that_use_the_delta() {
        let list = [
            d(Some(A), B),
            d(Some(B), T1),
            d(Some(A), X),
            d(Some(X), T1),
            d(Some(A), T2),
            d(Some(B), T2),
        ];
        let targets = vec![(cs(T1), false), (cs(T2), false)];
        let mut search = ChainSearch::new(
            Edges::new(list.to_vec()).unwrap(),
            set(&[A]),
            targets.clone(),
        );
        let planned: Vec<_> = search.targets().map(|(_, p)| p.clone()).collect();
        assert_eq!(
            planned,
            [Planned::Chain(vec![0, 1]), Planned::Chain(vec![4])]
        );
        assert_eq!(search.merged().levels, [vec![cs(B)]]);

        search.exclude(0);
        let planned: Vec<_> = search.targets().map(|(_, p)| p.clone()).collect();
        assert_eq!(
            planned,
            [Planned::Chain(vec![2, 3]), Planned::Chain(vec![4])]
        );
        let edges = Edges::new(list.to_vec()).unwrap();
        let excluded = HashSet::from([0]);
        for ((target, scratch), planned) in targets.iter().zip(&planned) {
            assert_eq!(
                plan_chain(&edges, target, &set(&[A]), *scratch, &excluded),
                *planned
            );
        }
        let plan = search.merged();
        assert_eq!(
            plan_steps(&list, &plan),
            [(Some(A), X), (Some(A), T2), (Some(X), T1)]
        );
        assert_eq!(plan.levels, [vec![cs(X)]]);
        assert_eq!(search.edges().delta(2).to, cs(X));

        search.exclude(4);
        let planned: Vec<_> = search.targets().map(|(_, p)| p.clone()).collect();
        assert_eq!(planned[1], Planned::None);
    }

    /// The search plans again around the first excluded deltas alone. After
    /// the limit, a target whose chain holds an excluded delta gets no chain,
    /// also if the list holds another chain. A refused delta from scratch to
    /// that target still counts.
    #[test]
    fn the_search_stops_planning_again_after_the_limit() {
        let source = cs(A);
        let target = cs(T);
        let alternative = |i: usize| {
            let mut bytes = [0x80; 32];
            bytes[..8].copy_from_slice(&(i as u64).to_be_bytes());
            Checksum::from_bytes(bytes)
        };
        let mut list = Vec::new();
        for i in 0..=MAX_EXCLUDED + 1 {
            list.push(AdvertisedDelta {
                from: Some(source),
                to: alternative(i),
                superblock: cs(0),
            });
            list.push(AdvertisedDelta {
                from: Some(alternative(i)),
                to: target,
                superblock: cs(0),
            });
        }
        list.push(AdvertisedDelta {
            from: None,
            to: target,
            superblock: cs(0),
        });
        let mut search = ChainSearch::new(
            Edges::new(list).unwrap(),
            HashSet::from([source]),
            vec![(target, false)],
        );
        for i in 0..MAX_EXCLUDED {
            let Some((_, Planned::Chain(chain))) = search.targets().next() else {
                panic!("no chain after {i} exclusions");
            };
            assert_eq!(chain, &vec![2 * i, 2 * i + 1]);
            search.exclude(2 * i);
        }
        let planned = search.targets().next().unwrap().1.clone();
        assert_eq!(
            planned,
            Planned::Chain(vec![2 * MAX_EXCLUDED, 2 * MAX_EXCLUDED + 1])
        );
        search.exclude(2 * MAX_EXCLUDED);
        assert_eq!(*search.targets().next().unwrap().1, Planned::Declined);
        assert!(search.merged().steps.is_empty());
    }

    #[test]
    fn edges_drop_an_equal_entry_and_refuse_two_digests() {
        let list = [d(Some(A), T), d(Some(B), T), d(Some(A), T)];
        let edges = Edges::new(list.to_vec()).unwrap();
        assert_eq!(edges.steps_to(&cs(T)), [0, 1]);
        let planned = plan_chain(&edges, &cs(T), &set(&[A, B]), false, &HashSet::new());
        assert_eq!(planned, Planned::Chain(vec![0]));

        let mut other = d(Some(A), T);
        other.superblock = cs(0xee);
        let list = [d(Some(A), T), d(Some(B), T), other];
        let Err(Error::InvalidInput(message)) = Edges::new(list.to_vec()) else {
            panic!("two digests for one delta pass");
        };
        assert_eq!(
            message,
            format!(
                "static delta {} is listed with two superblock digests",
                delta_name(Some(&cs(A)), &cs(T))
            )
        );
    }

    /// Writes a commit with an empty tree at `timestamp` and returns it.
    async fn empty_commit(repo: &Repo, timestamp: u64) -> Checksum {
        let txn = repo.transaction().await.unwrap();
        let dirmeta = ostrya_core::DirMeta {
            uid: 0,
            gid: 0,
            mode: 0o40755,
            xattrs: Default::default(),
        };
        let dirmeta = txn
            .write_metadata(
                ostrya_core::ObjectType::DirMeta,
                None,
                &dirmeta.serialize().unwrap(),
            )
            .await
            .unwrap();
        let mut mtree = crate::mtree::MutableTree::new();
        mtree.set_metadata_checksum(dirmeta);
        let root = txn.write_mtree(&mut mtree).await.unwrap();
        let options = crate::commit::CommitOptions {
            parent: None,
            subject: None,
            body: None,
            timestamp: Some(timestamp),
            metadata: None,
            related: Vec::new(),
        };
        let commit = txn.write_commit(options, &root).await.unwrap();
        txn.commit().await.unwrap();
        commit
    }

    /// The walk finds the complete commits that reach the target. It walks
    /// through a partial commit and stops at a complete commit.
    #[test]
    fn complete_sources_stops_at_a_complete_commit() {
        let dir = std::env::temp_dir().join(format!(
            "ostrya-chain-sources-{}-{}",
            std::process::id(),
            crate::write::unique()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        ostrya_rt::block_on(async {
            let create = crate::CreateOptions::new(ostrya_core::RepoMode::Archive);
            let repo = Repo::create(&dir, create).await.unwrap();
            let z = empty_commit(&repo, 1_700_000_001).await;
            let a = empty_commit(&repo, 1_700_000_002).await;
            let p = empty_commit(&repo, 1_700_000_003).await;
            let q = empty_commit(&repo, 1_700_000_004).await;
            std::fs::create_dir_all(dir.join("state")).unwrap();
            std::fs::write(dir.join(crate::pull::partial_path(&p)), b"").unwrap();
            let t = cs(T);
            let delta = |from: Checksum, to: Checksum| AdvertisedDelta {
                from: Some(from),
                to,
                superblock: cs(0),
            };
            let list = [
                delta(z, a),
                delta(a, t),
                delta(p, t),
                delta(q, p),
                AdvertisedDelta {
                    from: None,
                    to: t,
                    superblock: cs(0),
                },
            ];
            let edges = Edges::new(list.to_vec()).unwrap();
            let (_, found) = complete_sources(&repo, edges, &[t]).await.unwrap();
            assert_eq!(found, HashSet::from([a, q]));

            // The walk goes through a commit that this repository does not
            // hold, and does not check a target.
            let x = cs(X);
            let list = [delta(z, x), delta(x, t), delta(t, x), delta(p, a)];
            let edges = Edges::new(list.to_vec()).unwrap();
            let (_, found) = complete_sources(&repo, edges, &[t, a]).await.unwrap();
            assert_eq!(found, HashSet::from([z]));
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The future of the walk moves across threads.
    const _: fn() = || {
        fn assert_send<T: Send>(_: &T) {}
        let _ = |repo: &Repo, edges: Edges| assert_send(&complete_sources(repo, edges, &[]));
    };
}
