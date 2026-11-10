//! The claims of a client certificate: the allow items and the deny items
//! that the URI SANs of the certificate state.

use std::fmt;

use ostrya_core::RefPattern;

use super::Namespace;
use super::rights::{AccessRules, AllowItem, parse_allow_item, parse_deny_item};

/// The most claims that one certificate can hold.
///
/// [`Claims::parse`] refuses more claims with [`ClaimError::TooMany`].
/// A [`Claims`] list that `collect` makes from [`Claim`] values has no limit.
pub const MAX_CLAIMS: usize = 256;

/// The scheme of a claim, with its `:`.
const SCHEME: &str = "ostrya:";

/// The rule of one claim: an allow item or a deny item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimRule {
    /// An allow item: the modes and the pattern of
    /// `[MODES:][@ID:]PATTERN`.
    Allow(AllowItem),
    /// A deny item: the pattern of `![@ID:]PATTERN`.
    Deny(RefPattern),
}

/// One claim of a client certificate.
///
/// A claim is a URI SAN in one of these forms:
///
/// - `ostrya:ref:[MODES:]PATTERN` -- an allow item of the local refs.
/// - `ostrya:ref:!PATTERN` -- a deny item of the local refs.
/// - `ostrya:ref:[MODES:]@ID:PATTERN` -- an allow item of the collection
///   `ID`.
/// - `ostrya:ref:!@ID:PATTERN` -- a deny item of the collection `ID`.
///
/// The text after `ostrya:ref:` is an allow item of a client group, or `!`
/// and a deny item of a client group, so a claim with no `MODES` has the
/// mode `r`. `MODES` comes before `@ID:`, and `!` comes before `@ID:`.
/// `PATTERN` is a [`RefPattern`]. `ID` passes
/// [`is_collection_id`](crate::is_collection_id) and is at most
/// [`MAX_COLLECTION_ID_LEN`](ostrya_core::MAX_COLLECTION_ID_LEN) bytes. A
/// claim with `@ID:` of the own collection id names the local refs, as
/// [`Claims::rules`] states.
///
/// [`Claim::parse`] reads a URI. [`Claim::parse_ref`] reads the text after
/// `ostrya:ref:`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// The namespace that the claim names: [`Local`](Namespace::Local) for a
    /// claim with no `@ID:`, and the collection `ID` for a claim with
    /// `@ID:`. The parse does not map `[core] collection-id` to
    /// [`Local`](Namespace::Local).
    pub namespace: Namespace,
    /// The allow item or the deny item of the claim.
    pub rule: ClaimRule,
}

impl Claim {
    /// Parses the URI `uri` as a claim.
    ///
    /// The result is `None` if `uri` is not a claim: its scheme is not
    /// `ostrya`, in any case. The scheme and the kind `ref` are lowercase in
    /// a claim. Each other spelling and each other kind is a malformed
    /// claim.
    ///
    /// # Errors
    ///
    /// [`ClaimError::Malformed`] if the scheme of `uri` is `ostrya` and the
    /// text is no claim form.
    pub fn parse(uri: &str) -> Option<Result<Claim, ClaimError>> {
        if !is_claim(uri) {
            return None;
        }
        Some(parse_claim(uri).map_err(|reason| ClaimError::Malformed {
            claim: uri.to_owned(),
            reason,
        }))
    }

    /// Parses `text`, the text after `ostrya:ref:` of a claim.
    ///
    /// The result is the claim that [`Claim::parse`] gives for `ostrya:ref:`
    /// and `text`.
    ///
    /// # Errors
    ///
    /// [`ClaimError::Malformed`] if `text` is no claim form. The error holds
    /// `text`.
    ///
    /// # Examples
    ///
    /// ```
    /// use ostrya::access::{Claim, ClaimError};
    ///
    /// let claim = Claim::parse_ref("c:@com.example.app:**")?;
    /// let uri = Claim::parse("ostrya:ref:c:@com.example.app:**").unwrap()?;
    /// assert_eq!(claim, uri);
    /// let Err(ClaimError::Malformed { claim, .. }) = Claim::parse_ref("x:a") else {
    ///     panic!("x:a is a claim");
    /// };
    /// assert_eq!(claim, "x:a");
    /// # Ok::<(), ClaimError>(())
    /// ```
    pub fn parse_ref(text: &str) -> Result<Claim, ClaimError> {
        parse_body(text).map_err(|reason| ClaimError::Malformed {
            claim: text.to_owned(),
            reason,
        })
    }
}

/// Returns `true` if the scheme of `uri` is `ostrya`, in any case.
fn is_claim(uri: &str) -> bool {
    uri.get(..SCHEME.len())
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case(SCHEME))
}

/// Parses the claim `uri`, whose scheme is `ostrya` in any case. The error
/// is the reason.
fn parse_claim(uri: &str) -> Result<Claim, String> {
    const FORMS: &str = "a claim starts with ostrya:ref:";
    let body = uri
        .strip_prefix(SCHEME)
        .and_then(|rest| rest.strip_prefix("ref:"))
        .ok_or(FORMS)?;
    parse_body(body)
}

/// Parses the text after `ostrya:ref:` of a claim. The error is the reason.
fn parse_body(body: &str) -> Result<Claim, String> {
    let (id, rule) = match body.strip_prefix('!') {
        Some(item) => {
            let (id, pattern) = parse_deny_item(item)?;
            (id, ClaimRule::Deny(pattern))
        }
        None => {
            let (id, item) = parse_allow_item(body)?;
            (id, ClaimRule::Allow(item))
        }
    };
    let namespace = id.map_or(Namespace::Local, Namespace::Collection);
    Ok(Claim { namespace, rule })
}

/// Why a claim text or the URI SANs of a certificate give no claims.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClaimError {
    /// A claim text is no claim form: a URI whose scheme is `ostrya`, or the
    /// text after `ostrya:ref:`.
    Malformed {
        /// The claim text as the caller gave it: the URI for
        /// [`Claim::parse`] and [`Claims::parse`], and the text after
        /// `ostrya:ref:` for [`Claim::parse_ref`].
        claim: String,
        /// Why the text is no claim.
        reason: String,
    },
    /// The certificate holds more than [`MAX_CLAIMS`] URIs whose scheme is
    /// `ostrya`.
    TooMany,
}

impl fmt::Display for ClaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClaimError::Malformed { claim, reason } => {
                write!(f, "malformed claim '{claim}': {reason}")
            }
            ClaimError::TooMany => write!(f, "the certificate holds more than {MAX_CLAIMS} claims"),
        }
    }
}

impl std::error::Error for ClaimError {}

/// A list of claims, in order.
///
/// [`Claims::parse`] reads the claims of the URI SANs of a client
/// certificate, in the order of the URI SANs. `collect` makes the list of the
/// [`Claim`] values of an iterator, in the order of the iterator.
///
/// [`Claims::rules`] gives the rules of the claims for one namespace, and
/// [`ClientAccess::effective_rules`](super::ClientAccess::effective_rules)
/// puts the rules of the claims of each namespace in place of the rules of a
/// group.
///
/// # Examples
///
/// ```
/// use ostrya::access::{ClaimRule, Claims, Namespace};
///
/// let claims = Claims::parse([
///     "https://example.com/",
///     "ostrya:ref:wd:devel/**",
///     "ostrya:ref:!@com.example.os:os/secret",
/// ])?;
/// assert_eq!(claims.as_slice().len(), 2);
/// assert_eq!(claims.as_slice()[0].namespace, Namespace::Local);
/// let os = Namespace::Collection("com.example.os".into());
/// assert_eq!(claims.as_slice()[1].namespace, os);
/// assert!(matches!(claims.as_slice()[1].rule, ClaimRule::Deny(_)));
/// assert!(Claims::parse(["ostrya:ref:x:a"]).is_err());
/// assert!(Claims::parse(["ostrya:collection:com.example.os:r:a"]).is_err());
/// # Ok::<(), ostrya::access::ClaimError>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Claims {
    inner: Vec<Claim>,
}

impl Claims {
    /// Reads the claims of the URI SANs `uris`.
    ///
    /// A URI whose scheme is not `ostrya`, in any case, is no claim and has
    /// no effect. A claim that occurs two times counts two times.
    ///
    /// # Errors
    ///
    /// - [`ClaimError::TooMany`] if more than [`MAX_CLAIMS`] URIs have the
    ///   scheme `ostrya`.
    /// - [`ClaimError::Malformed`] for the first URI with the scheme
    ///   `ostrya` that is no claim form, as [`Claim::parse`] reads it.
    pub fn parse<'a>(uris: impl IntoIterator<Item = &'a str>) -> Result<Claims, ClaimError> {
        let mut inner = Vec::new();
        let mut count = 0;
        for uri in uris {
            let Some(claim) = Claim::parse(uri) else {
                continue;
            };
            count += 1;
            if count > MAX_CLAIMS {
                return Err(ClaimError::TooMany);
            }
            inner.push(claim?);
        }
        Ok(Claims { inner })
    }

    /// Returns `true` if the list holds no claim.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the claims, in the order of the list.
    pub fn as_slice(&self) -> &[Claim] {
        &self.inner
    }

    /// Returns the rules of the claims for `namespace`, or `None` if no
    /// claim names `namespace`.
    ///
    /// `own` is the own collection id of the repository. A claim of the
    /// collection `own` names the [`Local`](Namespace::Local) namespace. A
    /// [`Collection`](Namespace::Collection) of that id is the
    /// [`Local`](Namespace::Local) namespace too, as in [`Namespace::of`].
    /// The allow items and the deny items keep the order of the claims. The
    /// [module doc](crate::access#claims) states the rule.
    ///
    /// # Examples
    ///
    /// ```
    /// use ostrya::access::{AccessModes, Claim, Claims, Namespace};
    ///
    /// let claims: Claims = ["w:main", "!@com.example.own:secret", "r:@com.example.os:os/**"]
    ///     .into_iter()
    ///     .map(Claim::parse_ref)
    ///     .collect::<Result<_, _>>()?;
    /// let own = Some("com.example.own");
    /// let local = claims.rules(&Namespace::Local, own).unwrap();
    /// assert!(local.rights("main").contains(AccessModes::WRITE));
    /// assert_eq!(local.deny.len(), 1);
    /// let os = Namespace::of(Some("com.example.os"), own);
    /// assert_eq!(claims.rules(&os, own).unwrap().allow.len(), 1);
    /// assert!(claims.rules(&Namespace::Local, None).unwrap().deny.is_empty());
    /// let other = Namespace::Collection("org.example.other".into());
    /// assert!(claims.rules(&other, own).is_none());
    /// # Ok::<(), ostrya::access::ClaimError>(())
    /// ```
    pub fn rules(&self, namespace: &Namespace, own: Option<&str>) -> Option<AccessRules> {
        let namespace = match namespace {
            Namespace::Collection(id) if Some(id.as_str()) == own => &Namespace::Local,
            other => other,
        };
        let mut rules = AccessRules::default();
        let mut found = false;
        for claim in &self.inner {
            let names = match (&claim.namespace, namespace) {
                (Namespace::Local, Namespace::Local) => true,
                (Namespace::Collection(id), Namespace::Local) => Some(id.as_str()) == own,
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
}

impl FromIterator<Claim> for Claims {
    /// Makes the list of the claims of `iter`, in order.
    ///
    /// A claim that occurs two times counts two times. The list has no
    /// [`MAX_CLAIMS`] limit.
    fn from_iter<I: IntoIterator<Item = Claim>>(iter: I) -> Claims {
        Claims {
            inner: iter.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(uri: &str) -> Claim {
        Claim::parse(uri).unwrap().unwrap()
    }

    fn allow(uri: &str) -> (Namespace, String) {
        let claim = claim(uri);
        let ClaimRule::Allow(item) = claim.rule else {
            panic!("{uri} is no allow item");
        };
        (claim.namespace, item.to_string())
    }

    fn deny(uri: &str) -> (Namespace, String) {
        let claim = claim(uri);
        let ClaimRule::Deny(pattern) = claim.rule else {
            panic!("{uri} is no deny item");
        };
        (claim.namespace, pattern.as_str().to_owned())
    }

    fn collection(id: &str) -> Namespace {
        Namespace::Collection(id.to_owned())
    }

    /// Each of the four forms parses, and a claim with no modes has `r`. The
    /// own collection id stays a collection in the parse.
    #[test]
    fn each_form_parses() {
        assert_eq!(
            allow("ostrya:ref:wd:devel/**"),
            (Namespace::Local, "wd:devel/**".to_owned())
        );
        assert_eq!(
            allow("ostrya:ref:main"),
            (Namespace::Local, "r:main".to_owned())
        );
        assert_eq!(
            allow("ostrya:ref:dtcwr:*/stable"),
            (Namespace::Local, "rwctd:*/stable".to_owned())
        );
        assert_eq!(
            deny("ostrya:ref:!secret/**"),
            (Namespace::Local, "secret/**".to_owned())
        );
        assert_eq!(
            allow("ostrya:ref:t:@com.example.os:os/release/**"),
            (collection("com.example.os"), "t:os/release/**".to_owned())
        );
        assert_eq!(
            allow("ostrya:ref:wd:@X.y:os/**"),
            (collection("X.y"), "wd:os/**".to_owned())
        );
        assert_eq!(
            allow("ostrya:ref:@_a.b_1:os"),
            (collection("_a.b_1"), "r:os".to_owned())
        );
        assert_eq!(
            deny("ostrya:ref:!@a.b:os/secret"),
            (collection("a.b"), "os/secret".to_owned())
        );
        assert_eq!(
            allow("ostrya:ref:@own.id:a"),
            (collection("own.id"), "r:a".to_owned())
        );
        let longest = format!("a.{}", "b".repeat(ostrya_core::MAX_COLLECTION_ID_LEN - 2));
        assert_eq!(
            allow(&format!("ostrya:ref:@{longest}:a")),
            (collection(&longest), "r:a".to_owned())
        );
    }

    /// A URI whose scheme is not `ostrya` is no claim.
    #[test]
    fn another_uri_is_no_claim() {
        for uri in [
            "",
            "https://example.com/",
            "urn:a:b",
            "spiffe://example.org/ci",
            "ostryax:ref:a",
            "ostrya",
            "ostry:ref:a",
        ] {
            assert!(Claim::parse(uri).is_none(), "{uri:?}");
        }
        let claims = Claims::parse(["https://example.com/", "urn:a"]).unwrap();
        assert!(claims.is_empty());
    }

    /// The malformed claim URIs.
    const MALFORMED: &[&str] = &[
        "ostrya:",
        "ostrya:ref",
        "ostrya:ref:",
        "ostrya:ref::a",
        "ostrya:ref:x:a",
        "ostrya:ref:R:a",
        "ostrya:ref:rr:a",
        "ostrya:ref:r:a:b",
        "ostrya:ref:r:!a",
        "ostrya:ref:!",
        "ostrya:ref:!!a",
        "ostrya:ref:!r:a",
        "ostrya:ref:a*",
        "ostrya:ref:a//b",
        "ostrya:ref: a",
        "ostrya:ref:a ",
        "ostrya:ref:%41",
        "ostrya:ref:a\n",
        "ostrya:tag:a",
        "ostrya:Ref:a",
        "ostrya:REF:a",
        "OSTRYA:ref:a",
        "Ostrya:ref:a",
        "ostrya:Collection:a.b:a",
        "ostrya:collection:",
        "ostrya:collection:a.b:a",
        "ostrya:collection:a.b:r:a",
        "ostrya:collection:a.b:!a",
        "ostrya:ref:@a.b:r:a",
        "ostrya:ref:@a.b:",
        "ostrya:ref:@a.b",
        "ostrya:ref:@:a",
        "ostrya:ref:r:@:a",
        "ostrya:ref:@fresh:a",
        "ostrya:ref:@1a.b:a",
        "ostrya:ref:r:@a..b:a",
        "ostrya:ref:r:@a.b",
        "ostrya:ref:@a.b:@c.d:a",
        "ostrya:ref:x:@a.b:a",
        "ostrya:ref:@a.b:!a",
        "ostrya:ref:!@a.b:!a",
        "ostrya:ref:!r:@a.b:a",
        "ostrya:ref:!@a.b",
    ];

    /// Each malformed form is refused with its URI and a reason.
    #[test]
    fn a_malformed_claim_is_refused() {
        for &uri in MALFORMED {
            let Some(Err(err)) = Claim::parse(uri) else {
                panic!("{uri:?} was accepted");
            };
            let ClaimError::Malformed {
                claim: held,
                reason,
            } = &err
            else {
                panic!("{uri:?}: {err:?}");
            };
            assert_eq!(held, uri);
            assert!(!reason.is_empty(), "{uri:?}");
            assert_eq!(
                err.to_string(),
                format!("malformed claim '{uri}': {reason}")
            );
        }
    }

    /// The reason of a malformed claim names the rule that it fails.
    #[test]
    fn the_reason_names_the_rule() {
        let reason = |uri: &str| match Claim::parse(uri) {
            Some(Err(ClaimError::Malformed { reason, .. })) => reason,
            other => panic!("{uri:?}: {other:?}"),
        };
        assert_eq!(reason("ostrya:tag:a"), "a claim starts with ostrya:ref:");
        assert_eq!(reason("OSTRYA:ref:a"), "a claim starts with ostrya:ref:");
        assert_eq!(
            reason("ostrya:collection:a.b:r:a"),
            "a claim starts with ostrya:ref:"
        );
        assert_eq!(
            reason("ostrya:ref:@fresh:a"),
            "the collection id fails the collection-id rule"
        );
        assert_eq!(
            reason("ostrya:ref:!@a..b:a"),
            "the collection id fails the collection-id rule"
        );
        let long = format!("a.{}", "b".repeat(ostrya_core::MAX_COLLECTION_ID_LEN - 1));
        assert_eq!(
            reason(&format!("ostrya:ref:@{long}:a")),
            "the collection id is longer than 255 bytes"
        );
        assert_eq!(
            reason("ostrya:ref:x:a"),
            "the modes are one or more of r, w, c, t, and d"
        );
        assert_eq!(
            reason("ostrya:ref:rr:a"),
            "each mode occurs at most one time"
        );
    }

    /// `parse` keeps the claims in order, stops at the first malformed
    /// claim, and counts a claim that occurs two times two times.
    #[test]
    fn parse_keeps_the_order_and_stops_at_a_malformed_claim() {
        let claims = Claims::parse([
            "ostrya:ref:a",
            "dns-like",
            "ostrya:ref:w:@a.b:b",
            "ostrya:ref:a",
        ])
        .unwrap();
        let namespaces: Vec<&Namespace> = claims.as_slice().iter().map(|c| &c.namespace).collect();
        assert_eq!(
            namespaces,
            [&Namespace::Local, &collection("a.b"), &Namespace::Local]
        );
        let err = Claims::parse(["ostrya:ref:a", "ostrya:ref:x:a", "ostrya:ref:y:a"]).unwrap_err();
        assert_eq!(
            err,
            ClaimError::Malformed {
                claim: "ostrya:ref:x:a".to_owned(),
                reason: "the modes are one or more of r, w, c, t, and d".to_owned(),
            }
        );
    }

    /// A certificate with more than `MAX_CLAIMS` claims is refused. URIs of
    /// another scheme do not count.
    #[test]
    fn more_than_the_most_claims_is_refused() {
        let uris: Vec<String> = (0..MAX_CLAIMS)
            .map(|i| format!("ostrya:ref:r{i}"))
            .collect();
        let mut with_others: Vec<&str> = uris.iter().map(String::as_str).collect();
        with_others.push("https://example.com/");
        assert_eq!(
            Claims::parse(with_others.clone()).unwrap().as_slice().len(),
            MAX_CLAIMS
        );
        with_others.push("OSTRYA:x");
        assert_eq!(Claims::parse(with_others).unwrap_err(), ClaimError::TooMany);
        assert_eq!(
            ClaimError::TooMany.to_string(),
            "the certificate holds more than 256 claims"
        );
    }

    /// `parse_ref` gives the claim that `parse` gives for `ostrya:ref:` and
    /// the text, for each form.
    #[test]
    fn parse_ref_gives_the_claim_of_the_uri() {
        let longest = format!("a.{}", "b".repeat(ostrya_core::MAX_COLLECTION_ID_LEN - 2));
        for text in [
            "wd:devel/**",
            "main",
            "dtcwr:*/stable",
            "!secret/**",
            "t:@com.example.os:os/release/**",
            "wd:@X.y:os/**",
            "@_a.b_1:os",
            "!@a.b:os/secret",
            "@own.id:a",
            &format!("@{longest}:a"),
        ] {
            assert_eq!(
                Claim::parse_ref(text).unwrap(),
                claim(&format!("ostrya:ref:{text}")),
                "{text:?}"
            );
        }
    }

    /// `parse_ref` refuses the text after `ostrya:ref:` of each malformed
    /// claim, with the text and the reason that `parse` gives.
    #[test]
    fn parse_ref_refuses_a_malformed_text() {
        for &uri in MALFORMED {
            let Some(text) = uri.strip_prefix("ostrya:ref:") else {
                continue;
            };
            let Some(Err(ClaimError::Malformed { reason, .. })) = Claim::parse(uri) else {
                panic!("{uri:?} was accepted");
            };
            assert_eq!(
                Claim::parse_ref(text),
                Err(ClaimError::Malformed {
                    claim: text.to_owned(),
                    reason,
                }),
                "{text:?}"
            );
        }
    }

    /// `collect` keeps the order and the repeats, and applies no
    /// `MAX_CLAIMS` limit.
    #[test]
    fn collect_keeps_the_order_and_has_no_limit() {
        let claims: Claims = ["a", "w:@a.b:b", "a"]
            .into_iter()
            .map(|text| Claim::parse_ref(text).unwrap())
            .collect();
        let namespaces: Vec<&Namespace> = claims.as_slice().iter().map(|c| &c.namespace).collect();
        assert_eq!(
            namespaces,
            [&Namespace::Local, &collection("a.b"), &Namespace::Local]
        );
        let texts: Vec<String> = (0..=MAX_CLAIMS).map(|i| format!("r{i}")).collect();
        let claims: Claims = texts
            .iter()
            .map(|text| Claim::parse_ref(text).unwrap())
            .collect();
        assert_eq!(claims.as_slice().len(), MAX_CLAIMS + 1);
        assert_eq!(
            claims.as_slice()[MAX_CLAIMS],
            Claim::parse_ref(&format!("r{MAX_CLAIMS}")).unwrap()
        );
        assert!(std::iter::empty::<Claim>().collect::<Claims>().is_empty());
    }
}
