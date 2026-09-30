//! The refspecs of a push.
//!
//! A refspec is `SRC[:DST]`, split at its last `:`. `SRC` is a revision of
//! the local repository, and `DST` is the ref of the server that takes the
//! commit `SRC` names. An empty `SRC` before a `DST` (`:DST`) deletes the ref
//! `DST` of the server. The split is at the last `:`, so `SRC` can name a
//! remote ref, as in `origin:main:DST`. `DST` holds no `:`, so a push names
//! no remote ref of the server. `DST` holds no `^` either.

use std::collections::HashSet;

use ostrya_core::Checksum;

use super::invalid;
use crate::error::{Error, Result};
use crate::refs::{RevKind, validate_refspec};
use crate::repo::Repo;

/// One ref update of a push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PushTarget {
    /// The ref of the server.
    pub(crate) dst: String,
    /// The local commit the ref takes, or `None` to delete the ref.
    pub(crate) commit: Option<Checksum>,
}

/// A refspec split into its parts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Refspec<'a> {
    /// The local revision, or `None` for a delete.
    src: Option<&'a str>,
    /// The ref of the server, when the refspec names one.
    dst: Option<&'a str>,
}

/// Split `spec` at its last `:`.
///
/// The split refuses an empty refspec, `:`, an empty `DST`, and a `SRC` with
/// a `^` suffix and no `DST`. Each of these is [`Error::Push`] with
/// [`InvalidInput`](crate::push::Error::InvalidInput). A `DST` that
/// [`validate_refspec`] refuses, and a `DST` that holds a `^`, are
/// [`Error::InvalidRefspec`] with the `DST`.
fn split(spec: &str) -> Result<Refspec<'_>> {
    if spec.is_empty() {
        return Err(invalid("a refspec is empty"));
    }
    let Some((src, dst)) = spec.rsplit_once(':') else {
        if spec.ends_with('^') {
            return Err(invalid(format!(
                "refspec '{spec}': a source with a '^' suffix needs a destination"
            )));
        }
        return Ok(Refspec {
            src: Some(spec),
            dst: None,
        });
    };
    if dst.is_empty() {
        return Err(invalid(format!("refspec '{spec}' names no destination")));
    }
    validate_refspec(dst)?;
    if dst.contains('^') {
        return Err(Error::InvalidRefspec(dst.to_owned()));
    }
    Ok(Refspec {
        src: (!src.is_empty()).then_some(src),
        dst: Some(dst),
    })
}

impl Repo {
    /// The ref updates of the push `refspecs`, in the order of the refspecs.
    ///
    /// Each `SRC` resolves as [`resolve_rev`](Repo::resolve_rev) resolves it,
    /// with its errors. `DST` defaults to `SRC` when `SRC` resolves as a ref
    /// with no `^` suffix. A `SRC` that resolves as a full or an abbreviated
    /// checksum, and a `SRC` with a `^` suffix, need a `DST`.
    ///
    /// A refspec that [`split`] refuses gives the error of [`split`]. An
    /// empty list, a checksum `SRC` with no `DST`, and a `DST` named twice
    /// are [`Error::Push`] with
    /// [`InvalidInput`](crate::push::Error::InvalidInput). The split of every
    /// refspec, and the check of the `DST` names that the refspecs spell,
    /// come before any resolution.
    pub(crate) async fn push_targets(&self, refspecs: &[String]) -> Result<Vec<PushTarget>> {
        if refspecs.is_empty() {
            return Err(invalid("a push needs at least one refspec"));
        }
        let specs = refspecs
            .iter()
            .map(|spec| split(spec))
            .collect::<Result<Vec<_>>>()?;
        let mut seen = HashSet::new();
        for dst in specs.iter().filter_map(|parts| parts.dst) {
            if !seen.insert(dst) {
                return Err(named_twice(dst));
            }
        }
        let mut targets = Vec::with_capacity(specs.len());
        for (spec, parts) in refspecs.iter().zip(specs) {
            let Some(src) = parts.src else {
                let dst = parts.dst.expect("a delete names a destination");
                targets.push(PushTarget {
                    dst: dst.to_owned(),
                    commit: None,
                });
                continue;
            };
            let (commit, kind) = self
                .resolve_rev_kind(src, false)
                .await?
                .ok_or_else(|| Error::RefNotFound(src.to_owned()))?;
            let dst = match (parts.dst, kind) {
                (Some(dst), _) => dst,
                (None, RevKind::Ref) => {
                    // A `DST` that defaults to `SRC` is known only now.
                    if !seen.insert(src) {
                        return Err(named_twice(src));
                    }
                    src
                }
                (None, RevKind::Checksum) => {
                    return Err(invalid(format!(
                        "refspec '{spec}': a checksum source needs a destination"
                    )));
                }
            };
            targets.push(PushTarget {
                dst: dst.to_owned(),
                commit: Some(commit),
            });
        }
        Ok(targets)
    }
}

/// The refusal of a `DST` that two refspecs name.
fn named_twice(dst: &str) -> Error {
    invalid(format!("the destination '{dst}' is named twice"))
}

#[cfg(test)]
mod tests {
    use super::super::test_repo::{Scratch, commit_tree};
    use super::*;
    use ostrya_core::RepoMode;

    fn refspecs(specs: &[&str]) -> Vec<String> {
        specs.iter().map(|s| (*s).to_owned()).collect()
    }

    fn target(dst: &str, commit: Option<Checksum>) -> PushTarget {
        PushTarget {
            dst: dst.to_owned(),
            commit,
        }
    }

    fn assert_invalid<T: std::fmt::Debug>(result: Result<T>, needle: &str) {
        match result {
            Err(Error::Push(crate::push::Error::InvalidInput(msg))) => {
                assert!(msg.contains(needle), "{msg:?} lacks {needle:?}")
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    fn assert_invalid_refspec<T: std::fmt::Debug>(result: Result<T>, dst: &str) {
        match result {
            Err(Error::InvalidRefspec(name)) => assert_eq!(name, dst),
            other => panic!("expected InvalidRefspec, got {other:?}"),
        }
    }

    #[test]
    fn a_refspec_splits_at_its_last_colon() {
        assert_eq!(
            split("main").unwrap(),
            Refspec {
                src: Some("main"),
                dst: None
            }
        );
        assert_eq!(
            split("a:b").unwrap(),
            Refspec {
                src: Some("a"),
                dst: Some("b")
            }
        );
        assert_eq!(
            split("origin:main:dst").unwrap(),
            Refspec {
                src: Some("origin:main"),
                dst: Some("dst")
            }
        );
        assert_eq!(
            split("x:y:z").unwrap(),
            Refspec {
                src: Some("x:y"),
                dst: Some("z")
            }
        );
        assert_eq!(
            split(":gone").unwrap(),
            Refspec {
                src: None,
                dst: Some("gone")
            }
        );
        assert_eq!(
            split("main^:old").unwrap(),
            Refspec {
                src: Some("main^"),
                dst: Some("old")
            }
        );
    }

    #[test]
    fn a_destination_never_names_a_remote_ref() {
        // What reads as a remote ref after the first `:` is the source.
        let parts = split("main:origin:main").unwrap();
        assert_eq!(parts.src, Some("main:origin"));
        assert_eq!(parts.dst, Some("main"));
        let parts = split("origin:main").unwrap();
        assert_eq!(parts.src, Some("origin"));
        assert_eq!(parts.dst, Some("main"));
        // So `origin:main^` is the source `origin` and the destination
        // `main^`, which is refused.
        assert_invalid_refspec(split("origin:main^"), "main^");
    }

    #[test]
    fn the_forms_that_name_no_update_are_refused() {
        assert_invalid(split(""), "empty");
        assert_invalid(split(":"), "names no destination");
        assert_invalid(split("main:"), "names no destination");
        assert_invalid(split("a:b:"), "names no destination");
        assert_invalid(split("main^"), "'^' suffix needs a destination");
        assert_invalid(split("main^^"), "'^' suffix needs a destination");
    }

    #[test]
    fn a_destination_that_is_no_ref_name_is_an_invalid_refspec() {
        assert_invalid_refspec(split("main:a/../b"), "a/../b");
        assert_invalid_refspec(split("main:/b"), "/b");
    }

    #[test]
    fn a_destination_with_a_caret_is_an_invalid_refspec() {
        assert_invalid_refspec(split("main:dst^"), "dst^");
        assert_invalid_refspec(split("main:a^b"), "a^b");
        assert_invalid_refspec(split(":^"), "^");
        // The refusal comes before any resolution.
        ostrya_rt::block_on(async {
            let scratch = Scratch::new("caret-dst");
            let repo = scratch.create(RepoMode::BareUser).await;
            commit_tree(&repo, &scratch, "main", None, b"one").await;
            assert_invalid_refspec(
                repo.push_targets(&refspecs(&["absent", "main:dst^"])).await,
                "dst^",
            );
        });
    }

    #[test]
    fn refspecs_resolve_against_the_repository() {
        ostrya_rt::block_on(async {
            let scratch = Scratch::new("refspecs");
            let repo = scratch.create(RepoMode::BareUser).await;
            let first = commit_tree(&repo, &scratch, "main", None, b"one").await;
            let second = commit_tree(&repo, &scratch, "main", Some(first), b"two").await;
            let other = commit_tree(&repo, &scratch, "origin:main", None, b"three").await;

            let got = repo
                .push_targets(&refspecs(&[
                    "main",
                    "main^:old",
                    "origin:main:mirror",
                    ":gone",
                    &format!("{second}:full"),
                ]))
                .await
                .unwrap();
            assert_eq!(
                got,
                vec![
                    target("main", Some(second)),
                    target("old", Some(first)),
                    target("mirror", Some(other)),
                    target("gone", None),
                    target("full", Some(second)),
                ]
            );
        });
    }

    #[test]
    fn an_abbreviated_checksum_source_is_a_checksum() {
        ostrya_rt::block_on(async {
            let scratch = Scratch::new("abbrev");
            let repo = scratch.create(RepoMode::BareUser).await;
            let commit = commit_tree(&repo, &scratch, "main", None, b"one").await;
            let hex = commit.to_hex();
            let short = &hex[..10];

            let got = repo
                .push_targets(&refspecs(&[&format!("{short}:dst")]))
                .await
                .unwrap();
            assert_eq!(got, vec![target("dst", Some(commit))]);

            assert_invalid(
                repo.push_targets(&refspecs(&[short])).await,
                "a checksum source needs a destination",
            );
            assert_invalid(
                repo.push_targets(&refspecs(&[&hex])).await,
                "a checksum source needs a destination",
            );
        });
    }

    #[test]
    fn a_hex_ref_name_that_no_commit_prefixes_is_a_ref() {
        ostrya_rt::block_on(async {
            let scratch = Scratch::new("hex-ref");
            let repo = scratch.create(RepoMode::BareUser).await;
            let commit = commit_tree(&repo, &scratch, "main", None, b"one").await;
            // A name of lowercase hex that the one commit checksum does not
            // start with.
            let name = if commit.to_hex().starts_with('a') {
                "bbbb"
            } else {
                "aaaa"
            };
            repo.set_ref_immediate(name, Some(&commit)).await.unwrap();

            let got = repo.push_targets(&refspecs(&[name])).await.unwrap();
            assert_eq!(got, vec![target(name, Some(commit))]);
        });
    }

    #[test]
    fn refused_refspecs_name_the_reason() {
        ostrya_rt::block_on(async {
            let scratch = Scratch::new("refused");
            let repo = scratch.create(RepoMode::BareUser).await;
            commit_tree(&repo, &scratch, "main", None, b"one").await;
            commit_tree(&repo, &scratch, "other", None, b"two").await;

            assert_invalid(repo.push_targets(&[]).await, "at least one refspec");
            assert_invalid(
                repo.push_targets(&refspecs(&["main:x", "other:x"])).await,
                "'x' is named twice",
            );
            assert_invalid(
                repo.push_targets(&refspecs(&["main", "other:main"])).await,
                "'main' is named twice",
            );
            assert_invalid(
                repo.push_targets(&refspecs(&["main", ":main"])).await,
                "'main' is named twice",
            );
            assert_invalid(
                repo.push_targets(&refspecs(&["main^"])).await,
                "'^' suffix needs a destination",
            );
            // A syntax refusal comes before any resolution.
            assert_invalid(
                repo.push_targets(&refspecs(&["absent", "main:"])).await,
                "names no destination",
            );
            // So does a destination that two refspecs spell.
            assert_invalid(
                repo.push_targets(&refspecs(&["absent:x", "main:x"])).await,
                "'x' is named twice",
            );
            // A destination that defaults to its source is checked when the
            // source resolves as a ref.
            assert_invalid(
                repo.push_targets(&refspecs(&["main", "main"])).await,
                "'main' is named twice",
            );
        });
    }

    #[test]
    fn resolution_errors_keep_their_kinds() {
        ostrya_rt::block_on(async {
            let scratch = Scratch::new("resolve-errors");
            let repo = scratch.create(RepoMode::BareUser).await;
            let root = commit_tree(&repo, &scratch, "main", None, b"one").await;

            assert!(matches!(
                repo.push_targets(&refspecs(&["absent"])).await,
                Err(Error::RefNotFound(name)) if name == "absent"
            ));
            assert!(matches!(
                repo.push_targets(&refspecs(&["main^^:x"])).await,
                Err(Error::NoParentCommit(c)) if c == root
            ));
            assert!(matches!(
                repo.push_targets(&refspecs(&["a/../b:x"])).await,
                Err(Error::InvalidRefspec(_))
            ));
        });
    }

    #[test]
    fn an_ambiguous_abbreviated_checksum_is_refused() {
        ostrya_rt::block_on(async {
            let scratch = Scratch::new("ambiguous");
            let repo = scratch.create(RepoMode::BareUser).await;
            // Seventeen commits hold two whose checksums start with one hex
            // digit.
            let mut firsts = HashSet::new();
            let mut shared = None;
            for i in 0..17u8 {
                let commit = commit_tree(&repo, &scratch, "main", None, &[i]).await;
                let first = commit.to_hex()[..1].to_owned();
                if !firsts.insert(first.clone()) {
                    shared = Some(first);
                }
            }
            let shared = shared.expect("two commits share a first digit");
            assert!(matches!(
                repo.push_targets(&refspecs(&[&format!("{shared}:x")])).await,
                Err(Error::AmbiguousRefspec(rev)) if rev == shared
            ));
        });
    }
}
