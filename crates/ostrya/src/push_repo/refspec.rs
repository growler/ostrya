//! The refspecs of a push.
//!
//! `RepoPushOptions::refspecs` states the syntax of a refspec, `SRC[:DST]`.
//! One parser splits each refspec of a push, of a one-way stream, and of a
//! push to a bucket repository.

use std::collections::HashSet;

use ostrya_core::{Checksum, Ref};

use super::invalid;
use crate::error::{Error, Result};
use crate::refs::{RevKind, validate_refspec};
use crate::remote::{Expected, RefUpdate};
use crate::repo::Repo;

/// One ref update of a push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PushTarget {
    /// The ref of the server: a local ref or a collection ref.
    pub(crate) dst: Ref,
    /// The local commit that the ref takes, or `None` for a delete of the ref.
    pub(crate) commit: Option<Checksum>,
}

/// A refspec split into its parts.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Refspec<'a> {
    /// The local revision, or `None` for a delete.
    src: Option<&'a str>,
    /// The ref of the server, if the refspec names one.
    dst: Option<Ref>,
}

/// Splits `spec` into the text of `SRC` and the text of `DST`, with no
/// check.
///
/// `DST` is the last ref of the refspec. If the `:`-separated field before
/// the last field starts with `@`, the last ref is `@ID:NAME`, two fields.
/// Else the last ref is the last field. If the last ref is the whole
/// refspec, the refspec has a `SRC` alone, and the call gives no `DST`. Else
/// `SRC` is the text before the `:` that comes before the last ref, and an
/// empty `SRC` is a delete. No part of a ref other than a collection id
/// starts with `@`, so the rule never guesses.
fn fields(spec: &str) -> (&str, Option<&str>) {
    let Some(last) = spec.rfind(':') else {
        return (spec, None);
    };
    let before = &spec[..last];
    let field = before.rfind(':').map_or(0, |at| at + 1);
    let start = if before[field..].starts_with('@') {
        field
    } else {
        last + 1
    };
    match start {
        0 => (spec, None),
        _ => (&spec[..start - 1], Some(&spec[start..])),
    }
}

/// Returns `true` if `spec` is a delete `:DST`, `:@ID:NAME` included.
///
/// The call splits `spec` as [`split`] does, with no check of the parts.
pub(super) fn is_delete(spec: &str) -> bool {
    matches!(fields(spec), ("", Some(dst)) if !dst.is_empty())
}

/// Splits `spec` into `SRC` and `DST` by the rule of [`fields`], and reads
/// `DST` as a [`Ref`].
///
/// These forms give [`Error::Remote`] with
/// [`InvalidInput`](crate::remote::Error::InvalidInput):
///
/// - An empty refspec.
/// - The refspec `:` and each other refspec with an empty `DST`.
/// - A `SRC` with a `^` suffix and no `DST`.
///
/// These forms of `DST` give [`Error::InvalidRefspec`] with the `DST`:
///
/// - A `DST` that is not `NAME` or `@ID:NAME` under [`Ref::validate`].
/// - A local `DST` that [`is_checksum_shaped`](ostrya_core::is_checksum_shaped)
///   marks, after a non-empty `SRC`.
///
/// A delete (`:DST`) of a checksum-shaped `DST` passes.
fn split(spec: &str) -> Result<Refspec<'_>> {
    if spec.is_empty() {
        return Err(invalid("a refspec is empty"));
    }
    let (src, dst) = fields(spec);
    let Some(dst) = dst else {
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
    let dst: Ref = dst.parse()?;
    // A revision reads 64 lowercase hex characters as a checksum, so a push
    // writes no commit to such a local ref. A delete of it passes.
    if !src.is_empty()
        && let Ref::Local { name } = &dst
        && ostrya_core::is_checksum_shaped(name)
    {
        return Err(Error::InvalidRefspec(name.clone()));
    }
    Ok(Refspec {
        src: (!src.is_empty()).then_some(src),
        dst: Some(dst),
    })
}

/// Returns the ref `r` of a push under the collection `collection`.
///
/// With a collection `ID`, a local ref `NAME` becomes `@ID:NAME`, a ref
/// `@ID:NAME` stays, and a ref of another collection is
/// [`InvalidInput`](crate::remote::Error::InvalidInput). `what` names the
/// ref in the message. A remote ref stays, and the caller refuses it. With
/// no collection, `r` stays.
pub(super) fn in_collection(r: Ref, collection: Option<&str>, what: &str) -> Result<Ref> {
    let Some(id) = collection else {
        return Ok(r);
    };
    r.in_collection(id).map_err(|r| {
        let Ref::Collection { id: other, .. } = &r else {
            unreachable!("a refused ref is a collection ref");
        };
        invalid(format!(
            "the {what} '{r}' names the collection '{other}', and the push names the \
             collection '{id}'"
        ))
    })
}

impl Repo {
    /// Returns the ref updates of the push `refspecs`, in the order of the
    /// refspecs.
    ///
    /// Each `SRC` resolves as [`resolve_rev`](Repo::resolve_rev) resolves it.
    /// If `SRC` resolves as a ref with no `^` suffix, `DST` defaults to the
    /// text of `SRC`. A `SRC` that resolves as a full or an abbreviated
    /// checksum needs a `DST`. A `SRC` with a `^` suffix also needs a `DST`.
    ///
    /// Each `DST` goes through [`in_collection`] with `collection`, also a
    /// `DST` that defaults to its `SRC`.
    ///
    /// The split of each refspec comes before any resolution. The check of
    /// the `DST` refs that the refspecs spell also comes before any
    /// resolution. Two `DST` refs of the same text are refused. The server
    /// refuses two texts of one ref, `NAME` and `@OWN:NAME`.
    ///
    /// # Errors
    ///
    /// - The error of [`split`] if it refuses a refspec.
    /// - The error of [`in_collection`] if it refuses a `DST`.
    /// - [`Error::Remote`] with [`InvalidInput`](crate::remote::Error::InvalidInput)
    ///   for an empty list, a checksum `SRC` with no `DST`, and a `DST` that
    ///   two refspecs name.
    /// - [`Error::RefNotFound`] with the `SRC` if `SRC` resolves to no commit.
    /// - The errors of [`resolve_rev`](Repo::resolve_rev) for a `SRC`.
    pub(crate) async fn push_targets(
        &self,
        refspecs: &[String],
        collection: Option<&str>,
    ) -> Result<Vec<PushTarget>> {
        if refspecs.is_empty() {
            return Err(invalid("a push needs at least one refspec"));
        }
        let mut specs = Vec::with_capacity(refspecs.len());
        for spec in refspecs {
            let Refspec { src, dst } = split(spec)?;
            let dst = dst
                .map(|dst| in_collection(dst, collection, "destination"))
                .transpose()?;
            specs.push((src, dst));
        }
        let mut seen = HashSet::new();
        for dst in specs.iter().filter_map(|(_, dst)| dst.as_ref()) {
            if !seen.insert(dst.clone()) {
                return Err(named_twice(dst));
            }
        }
        let mut targets = Vec::with_capacity(specs.len());
        for (spec, (src, dst)) in refspecs.iter().zip(specs) {
            let Some(src) = src else {
                let dst = dst.expect("a delete names a destination");
                targets.push(PushTarget { dst, commit: None });
                continue;
            };
            let (commit, kind) = self
                .resolve_rev_kind(src, false)
                .await?
                .ok_or_else(|| Error::RefNotFound(src.to_owned()))?;
            let dst = match (dst, kind) {
                (Some(dst), _) => dst,
                (None, RevKind::Ref) => {
                    // A `DST` that defaults to `SRC` is known only now.
                    let dst = in_collection(src.parse()?, collection, "destination")?;
                    if !seen.insert(dst.clone()) {
                        return Err(named_twice(&dst));
                    }
                    dst
                }
                (None, RevKind::Checksum) => {
                    return Err(invalid(format!(
                        "refspec '{spec}': a checksum source needs a destination"
                    )));
                }
            };
            targets.push(PushTarget {
                dst,
                commit: Some(commit),
            });
        }
        Ok(targets)
    }

    /// Returns the ref updates of a one-way stream for `refspecs`, in the
    /// order of the refspecs.
    ///
    /// A refspec is `SRC[:DST]`, and the rules of
    /// [`RepoPushOptions::refspecs`](crate::RepoPushOptions::refspecs) apply,
    /// with the same grammar. Each `SRC` resolves in this repository. If
    /// `SRC` is a ref with no `^` suffix, `DST` defaults to the text of
    /// `SRC`. A `SRC` that is a checksum, or that has a `^` suffix, needs a
    /// `DST`.
    ///
    /// A one-way stream deletes no ref, so the call refuses a delete, `:DST`,
    /// `:@ID:NAME` included. The call refuses a local `DST` of 64 lowercase
    /// hex characters after a `SRC`. Without `remote`, the reason is that a
    /// revision reads such a name as a commit checksum. With `remote`, the
    /// call refuses it by the refspec rule of [`push`](Repo::push).
    ///
    /// Without `remote`, the name of each update is the text of `DST`,
    /// `NAME` or `@ID:NAME`. With `remote`, it is `REMOTE:DST`, and the
    /// receiver writes a remote ref. A remote ref has no collection, so with
    /// `remote` the call refuses a `DST` `@ID:NAME`. The call checks each
    /// remote ref with [`validate_refspec`], so each name that it returns
    /// passes the ref-name checks of [`export_stream`](Repo::export_stream).
    ///
    /// The call does not check the bindings of a commit.
    /// [`export_stream`](Repo::export_stream) checks them before it writes a
    /// byte. If the commit of a `SRC` has an `ostree.ref-binding` list that
    /// does not hold the name part of `DST`, an empty list included, it
    /// refuses the update with [`Error::Remote`] and
    /// [`BindingMismatch`](crate::remote::Error::BindingMismatch), unless
    /// [`disable_verify_bindings`](crate::ExportStreamOptions::disable_verify_bindings)
    /// is set. A commit of `ostrya commit -b BRANCH` is bound to `BRANCH`.
    ///
    /// Each update expects [`Any`](Expected::Any) and sets the commit of its
    /// `SRC`. So the receiver applies its own rules to the state of the ref.
    /// The updates go in
    /// [`ExportStreamOptions::updates`](crate::ExportStreamOptions::updates).
    ///
    /// The call takes no lock. `export_stream` takes the repository lock.
    ///
    /// # Errors
    ///
    /// - [`Error::Remote`] with
    ///   [`InvalidInput`](crate::remote::Error::InvalidInput) if a refspec is
    ///   a delete. This check comes before each other check.
    /// - [`Error::Remote`] with
    ///   [`InvalidInput`](crate::remote::Error::InvalidInput) for an empty
    ///   list, an empty refspec, a refspec with an empty `DST`, a `SRC` with
    ///   a `^` suffix and no `DST`, a checksum `SRC` with no `DST`, and a
    ///   `DST` that two refspecs name.
    /// - [`Error::InvalidRefspec`] with the `DST` if the `DST` is not `NAME`
    ///   or `@ID:NAME` under the ref-name rule, or if a local `DST` after a
    ///   `SRC` is 64 lowercase hex characters.
    /// - [`Error::RefNotFound`] with the `SRC` if `SRC` resolves to no commit.
    /// - The errors of [`resolve_rev`](Repo::resolve_rev) for a `SRC`.
    /// - [`Error::Remote`] with
    ///   [`InvalidInput`](crate::remote::Error::InvalidInput) if `remote` is
    ///   set and a `DST` is `@ID:NAME`.
    /// - [`Error::InvalidRefspec`] with `REMOTE:DST` if [`validate_refspec`]
    ///   refuses the name of an update.
    ///
    /// # Examples
    ///
    /// Write a one-way stream of the refs `main` and `stable` to a file. The
    /// receiver writes the refs `origin:main` and `origin:stable`. Each `DST`
    /// is its `SRC`, so a commit bound to its branch passes the binding
    /// check:
    ///
    /// ```no_run
    /// use ostrya::{ExportStreamOptions, Repo};
    ///
    /// # async fn run() -> ostrya::Result<()> {
    /// let repo = Repo::open("/srv/repo".as_ref()).await?;
    /// let refspecs = ["main".to_owned(), "stable".to_owned()];
    /// let updates = repo.export_updates(&refspecs, Some("origin")).await?;
    /// let output = ostrya_rt::File::from(std::fs::File::create("stream")?);
    /// let opts = ExportStreamOptions {
    ///     updates,
    ///     ..ExportStreamOptions::default()
    /// };
    /// repo.export_stream(output, opts).await?;
    /// # Ok(()) }
    /// ```
    pub async fn export_updates(
        &self,
        refspecs: &[String],
        remote: Option<&str>,
    ) -> Result<Vec<RefUpdate>> {
        if let Some(spec) = refspecs.iter().find(|spec| is_delete(spec)) {
            return Err(invalid(format!(
                "a one-way stream deletes no ref, and the refspec '{spec}' is a delete"
            )));
        }
        let mut updates = Vec::with_capacity(refspecs.len());
        for target in self.push_targets(refspecs, None).await? {
            let name = match (remote, target.dst) {
                (Some(remote), Ref::Local { name }) => {
                    let name = format!("{remote}:{name}");
                    validate_refspec(&name)?;
                    name
                }
                (Some(_), dst) => {
                    return Err(invalid(format!(
                        "a remote ref has no collection, and the destination '{dst}' names one"
                    )));
                }
                (None, dst) => dst.to_string(),
            };
            updates.push(RefUpdate {
                name,
                expected: Expected::Any,
                new: Some(target.commit.expect("a delete is refused")),
            });
        }
        Ok(updates)
    }
}

/// Returns the error for a `DST` that two refspecs name.
fn named_twice(dst: &Ref) -> Error {
    invalid(format!("the destination '{dst}' is named twice"))
}

#[cfg(test)]
mod tests {
    use super::super::test_repo::{Scratch, commit_tree};
    use super::*;
    use crate::Ref;
    use ostrya_core::RepoMode;

    fn refspecs(specs: &[&str]) -> Vec<String> {
        specs.iter().map(|s| (*s).to_owned()).collect()
    }

    fn target(dst: &str, commit: Option<Checksum>) -> PushTarget {
        PushTarget {
            dst: dst.parse().unwrap(),
            commit,
        }
    }

    fn assert_invalid<T: std::fmt::Debug>(result: Result<T>, needle: &str) {
        match result {
            Err(Error::Remote(crate::remote::Error::InvalidInput(msg))) => {
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

    /// Returns the parts of a refspec: `src`, and `dst` read as a ref.
    fn parts<'a>(src: Option<&'a str>, dst: Option<&str>) -> Refspec<'a> {
        Refspec {
            src,
            dst: dst.map(|dst| dst.parse().unwrap()),
        }
    }

    #[test]
    fn a_refspec_splits_before_its_last_ref() {
        for (spec, src, dst) in [
            ("main", Some("main"), None),
            ("origin:main", Some("origin"), Some("main")),
            ("R:main:dst", Some("R:main"), Some("dst")),
            ("@X.y:a", Some("@X.y:a"), None),
            ("main:@X.y:a", Some("main"), Some("@X.y:a")),
            ("R:main:@X.y:a", Some("R:main"), Some("@X.y:a")),
            ("@X.y:a:b", Some("@X.y:a"), Some("b")),
            ("@X.y:a:@Y.z:b", Some("@X.y:a"), Some("@Y.z:b")),
            ("@X.y:main^:b", Some("@X.y:main^"), Some("b")),
            (":@X.y:a", None, Some("@X.y:a")),
            ("a:b", Some("a"), Some("b")),
            ("x:y:z", Some("x:y"), Some("z")),
            (":gone", None, Some("gone")),
            ("main^:old", Some("main^"), Some("old")),
        ] {
            assert_eq!(split(spec).unwrap(), parts(src, dst), "{spec}");
        }
        // The field before the last field names no collection, so the last
        // field is the destination `@X.y`, which the ref-name rule refuses.
        assert_eq!(fields("a:@X.y"), ("a", Some("@X.y")));
        assert_invalid_refspec(split("a:@X.y"), "@X.y");
    }

    #[test]
    fn a_delete_names_its_destination_after_an_empty_source() {
        for spec in [":gone", ":@X.y:a", ":a/b"] {
            assert!(is_delete(spec), "{spec}");
        }
        // The `SRC` of `:@X.y:a:b` is `:@X.y:a`, and the `DST` is `b`.
        for spec in [
            "",
            ":",
            "main",
            "@X.y:a",
            "main:gone",
            "@X.y:a:b",
            "a:@X.y:a",
            ":@X.y:a:b",
        ] {
            assert!(!is_delete(spec), "{spec}");
        }
    }

    #[test]
    fn a_destination_never_names_a_remote_ref() {
        // What reads as a remote ref after the first `:` is the source.
        assert_eq!(
            split("main:origin:main").unwrap(),
            parts(Some("main:origin"), Some("main"))
        );
        assert_eq!(
            split("origin:main").unwrap(),
            parts(Some("origin"), Some("main"))
        );
        // The refspec `origin:main^` is the source `origin` and the
        // destination `main^`. The split refuses this destination.
        assert_invalid_refspec(split("origin:main^"), "main^");
    }

    /// Under a collection, a local ref takes the collection, a ref of the
    /// collection stays, and a ref of another collection is refused. With no
    /// collection, each ref stays.
    #[test]
    fn a_collection_names_the_namespace_of_each_plain_ref() {
        let x = Some("org.example.X");
        assert_eq!(
            in_collection(Ref::local("a"), x, "destination").unwrap(),
            Ref::collection("org.example.X", "a")
        );
        let own = Ref::collection("org.example.X", "a");
        assert_eq!(in_collection(own.clone(), x, "tag").unwrap(), own);
        assert_invalid(
            in_collection(Ref::collection("org.example.Y", "a"), x, "tag"),
            "the tag '@org.example.Y:a' names the collection 'org.example.Y', and the push \
             names the collection 'org.example.X'",
        );
        for r in [
            Ref::local("a"),
            Ref::collection("org.example.Y", "a"),
            Ref::remote("o", "a"),
        ] {
            assert_eq!(in_collection(r.clone(), None, "tag").unwrap(), r);
        }
        assert_eq!(
            in_collection(Ref::remote("o", "a"), x, "tag").unwrap(),
            Ref::remote("o", "a")
        );
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
    fn a_destination_outside_the_ref_name_rule_is_an_invalid_refspec() {
        for dst in ["a b", "a*", "-a", "a/.b", "a~b"] {
            assert_invalid_refspec(split(&format!("main:{dst}")), dst);
            assert_invalid_refspec(split(&format!(":{dst}")), dst);
        }
        for dst in ["a.", "_a", "1a", "é"] {
            assert_eq!(
                split(&format!("main:{dst}")).unwrap().dst,
                Some(Ref::local(dst))
            );
        }
    }

    #[test]
    fn a_destination_of_64_lowercase_hex_characters_is_an_invalid_refspec() {
        let hex = "ab".repeat(32);
        assert_invalid_refspec(split(&format!("main:{hex}")), &hex);
        assert_invalid_refspec(split(&format!("origin:main:{hex}")), &hex);
        let upper = hex.to_uppercase();
        assert_eq!(
            split(&format!("main:{upper}")).unwrap().dst,
            Some(Ref::local(upper.as_str()))
        );
        // A collection ref of 64 lowercase hex characters is no checksum.
        let spec = format!("main:@org.example.X:{hex}");
        assert_eq!(
            split(&spec).unwrap().dst,
            Some(Ref::collection("org.example.X", hex.as_str()))
        );
    }

    #[test]
    fn a_delete_of_64_lowercase_hex_characters_is_accepted() {
        let hex = "ab".repeat(32);
        let spec = format!(":{hex}");
        assert_eq!(split(&spec).unwrap(), parts(None, Some(&hex)));
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
                repo.push_targets(&refspecs(&["absent", "main:dst^"]), None)
                    .await,
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
                .push_targets(
                    &refspecs(&[
                        "main",
                        "main^:old",
                        "origin:main:mirror",
                        ":gone",
                        &format!("{second}:full"),
                    ]),
                    None,
                )
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
                .push_targets(&refspecs(&[&format!("{short}:dst")]), None)
                .await
                .unwrap();
            assert_eq!(got, vec![target("dst", Some(commit))]);

            assert_invalid(
                repo.push_targets(&refspecs(&[short]), None).await,
                "a checksum source needs a destination",
            );
            assert_invalid(
                repo.push_targets(&refspecs(&[&hex]), None).await,
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
            // A name of lowercase hex that is not a prefix of the checksum
            // of the one commit.
            let name = if commit.to_hex().starts_with('a') {
                "bbbb"
            } else {
                "aaaa"
            };
            repo.set_ref_immediate(&Ref::local(name), Some(&commit))
                .await
                .unwrap();

            let got = repo.push_targets(&refspecs(&[name]), None).await.unwrap();
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

            assert_invalid(repo.push_targets(&[], None).await, "at least one refspec");
            assert_invalid(
                repo.push_targets(&refspecs(&["main:x", "other:x"]), None)
                    .await,
                "'x' is named twice",
            );
            assert_invalid(
                repo.push_targets(&refspecs(&["main", "other:main"]), None)
                    .await,
                "'main' is named twice",
            );
            assert_invalid(
                repo.push_targets(&refspecs(&["main", ":main"]), None).await,
                "'main' is named twice",
            );
            assert_invalid(
                repo.push_targets(&refspecs(&["main^"]), None).await,
                "'^' suffix needs a destination",
            );
            // A syntax refusal comes before any resolution.
            assert_invalid(
                repo.push_targets(&refspecs(&["absent", "main:"]), None)
                    .await,
                "names no destination",
            );
            // A destination that two refspecs spell also gives an error
            // before any resolution.
            assert_invalid(
                repo.push_targets(&refspecs(&["absent:x", "main:x"]), None)
                    .await,
                "'x' is named twice",
            );
            // The check of a destination that defaults to its source comes
            // when the source resolves as a ref.
            assert_invalid(
                repo.push_targets(&refspecs(&["main", "main"]), None).await,
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
                repo.push_targets(&refspecs(&["absent"]), None).await,
                Err(Error::RefNotFound(name)) if name == "absent"
            ));
            assert!(matches!(
                repo.push_targets(&refspecs(&["main^^:x"]), None).await,
                Err(Error::NoParentCommit(c)) if c == root
            ));
            assert!(matches!(
                repo.push_targets(&refspecs(&["a/../b:x"]), None).await,
                Err(Error::InvalidRefspec(_))
            ));
        });
    }

    #[test]
    fn an_ambiguous_abbreviated_checksum_is_refused() {
        ostrya_rt::block_on(async {
            let scratch = Scratch::new("ambiguous");
            let repo = scratch.create(RepoMode::BareUser).await;
            // Of 17 commits, at least two have checksums that start with the
            // same hex digit.
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
                repo.push_targets(&refspecs(&[&format!("{shared}:x")]), None).await,
                Err(Error::AmbiguousRefspec(rev)) if rev == shared
            ));
        });
    }

    fn any(name: &str, commit: Checksum) -> RefUpdate {
        RefUpdate {
            name: name.to_owned(),
            expected: Expected::Any,
            new: Some(commit),
        }
    }

    #[test]
    fn the_updates_of_a_one_way_stream_expect_any_state() {
        ostrya_rt::block_on(async {
            let scratch = Scratch::new("export-updates");
            let repo = scratch.create(RepoMode::BareUser).await;
            let first = commit_tree(&repo, &scratch, "main", None, b"one").await;
            let second = commit_tree(&repo, &scratch, "main", Some(first), b"two").await;
            let other = commit_tree(&repo, &scratch, "origin:main", None, b"three").await;
            let full = format!("{second}:full");

            let got = repo
                .export_updates(
                    &refspecs(&["main", "main^:old", "origin:main:mirror", &full]),
                    None,
                )
                .await
                .unwrap();
            assert_eq!(
                got,
                vec![
                    any("main", second),
                    any("old", first),
                    any("mirror", other),
                    any("full", second),
                ]
            );

            let got = repo
                .export_updates(&refspecs(&["main", "main^:old"]), Some("os"))
                .await
                .unwrap();
            assert_eq!(got, vec![any("os:main", second), any("os:old", first)]);
        });
    }

    #[test]
    fn a_one_way_stream_refuses_a_delete() {
        ostrya_rt::block_on(async {
            let scratch = Scratch::new("export-delete");
            let repo = scratch.create(RepoMode::BareUser).await;
            commit_tree(&repo, &scratch, "main", None, b"one").await;
            let hex = "ab".repeat(32);

            for specs in [
                refspecs(&[":gone"]),
                refspecs(&[&format!(":{hex}")]),
                refspecs(&["main", ":gone"]),
                // The refusal comes before any resolution.
                refspecs(&["absent", ":gone"]),
            ] {
                assert_invalid(
                    repo.export_updates(&specs, None).await,
                    "a one-way stream deletes no ref, and the refspec ':",
                );
            }
        });
    }

    #[test]
    fn the_updates_of_a_one_way_stream_keep_the_push_rules() {
        ostrya_rt::block_on(async {
            let scratch = Scratch::new("export-rules");
            let repo = scratch.create(RepoMode::BareUser).await;
            commit_tree(&repo, &scratch, "main", None, b"one").await;
            let hex = "ab".repeat(32);

            assert_invalid(repo.export_updates(&[], None).await, "at least one refspec");
            assert!(matches!(
                repo.export_updates(&refspecs(&["absent"]), None).await,
                Err(Error::RefNotFound(name)) if name == "absent"
            ));
            // A checksum-shaped `DST` is refused, also with a remote.
            assert_invalid_refspec(
                repo.export_updates(&refspecs(&[&format!("main:{hex}")]), Some("os"))
                    .await,
                &hex,
            );
        });
    }

    /// Under a collection, each plain destination takes the collection,
    /// also a destination that defaults to its source. A destination of
    /// another collection is refused, and so are two destinations that name
    /// one ref after the collection applies.
    #[test]
    fn a_collection_applies_to_each_destination() {
        ostrya_rt::block_on(async {
            let scratch = Scratch::new("collection");
            let repo = scratch.create(RepoMode::BareUser).await;
            let main = commit_tree(&repo, &scratch, "main", None, b"one").await;
            let mirror = commit_tree(&repo, &scratch, "@org.example.Y:a", None, b"two").await;
            let x = Some("org.example.X");

            let got = repo
                .push_targets(&refspecs(&["main", "main:b", "main:@org.example.X:c"]), x)
                .await
                .unwrap();
            assert_eq!(
                got,
                vec![
                    target("@org.example.X:main", Some(main)),
                    target("@org.example.X:b", Some(main)),
                    target("@org.example.X:c", Some(main)),
                ]
            );
            let got = repo
                .push_targets(&refspecs(&["@org.example.Y:a:b"]), x)
                .await
                .unwrap();
            assert_eq!(got, vec![target("@org.example.X:b", Some(mirror))]);
            for specs in [
                &["main:@org.example.Y:b"][..],
                &["@org.example.Y:a"],
                &[":@org.example.Y:b"],
            ] {
                assert_invalid(
                    repo.push_targets(&refspecs(specs), x).await,
                    "names the collection 'org.example.Y', and the push names the collection \
                     'org.example.X'",
                );
            }
            assert_invalid(
                repo.push_targets(&refspecs(&["main", "main:@org.example.X:main"]), x)
                    .await,
                "'@org.example.X:main' is named twice",
            );
            // With no collection, the two texts name two refs here. The
            // server maps them.
            let got = repo
                .push_targets(&refspecs(&["main", "main:@org.example.X:main"]), None)
                .await
                .unwrap();
            assert_eq!(got.len(), 2);
        });
    }

    #[test]
    fn a_one_way_stream_names_collection_refs() {
        ostrya_rt::block_on(async {
            let scratch = Scratch::new("export-collection");
            let repo = scratch.create(RepoMode::BareUser).await;
            let main = commit_tree(&repo, &scratch, "main", None, b"one").await;
            let mirror = commit_tree(&repo, &scratch, "@org.example.Y:a", None, b"two").await;

            let got = repo
                .export_updates(
                    &refspecs(&["main:@org.example.X:a", "@org.example.Y:a"]),
                    None,
                )
                .await
                .unwrap();
            assert_eq!(
                got,
                vec![
                    any("@org.example.X:a", main),
                    any("@org.example.Y:a", mirror)
                ]
            );
            // A remote ref has no collection.
            for specs in [&["main:@org.example.X:a"][..], &["@org.example.Y:a"]] {
                assert_invalid(
                    repo.export_updates(&refspecs(specs), Some("os")).await,
                    "a remote ref has no collection, and the destination '@org.example.",
                );
            }
            let got = repo
                .export_updates(&refspecs(&["@org.example.Y:a:b"]), Some("os"))
                .await
                .unwrap();
            assert_eq!(got, vec![any("os:b", mirror)]);
            // The delete of a collection ref is a delete.
            assert_invalid(
                repo.export_updates(&refspecs(&["main", ":@org.example.X:a"]), None)
                    .await,
                "a one-way stream deletes no ref, and the refspec ':@org.example.X:a' is a delete",
            );
        });
    }

    #[test]
    fn a_remote_that_makes_no_ref_name_is_an_invalid_refspec() {
        // The remote name rule accepts the character, and the ref-name rule
        // refuses it.
        let remote = "\u{1f130}";
        assert!(crate::valid_remote_name(remote));
        ostrya_rt::block_on(async {
            let scratch = Scratch::new("export-remote");
            let repo = scratch.create(RepoMode::BareUser).await;
            commit_tree(&repo, &scratch, "main", None, b"one").await;
            assert_invalid_refspec(
                repo.export_updates(&refspecs(&["main"]), Some(remote))
                    .await,
                &format!("{remote}:main"),
            );
        });
    }
}
