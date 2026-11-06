//! The claims of a client certificate: the allow items and the deny items
//! that the URI SANs of the certificate state.

use std::fmt;

use ostrya_core::RefPattern;

use super::Namespace;
use super::rights::{AllowItem, parse_allow_item, parse_deny_item};

/// The most claims that one certificate can hold.
///
/// [`Claims::parse`] refuses more claims with [`ClaimError::TooMany`].
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
/// claim with `@ID:` of `[core] collection-id` names the local refs, as
/// [`ClientAccess::claim_rules`](super::ClientAccess::claim_rules) states.
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
            uri: uri.to_owned(),
            reason,
        }))
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

/// Why the URI SANs of a certificate give no claims.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClaimError {
    /// A URI whose scheme is `ostrya` is no claim form.
    Malformed {
        /// The URI.
        uri: String,
        /// Why the URI is no claim.
        reason: String,
    },
    /// The certificate holds more than [`MAX_CLAIMS`] URIs whose scheme is
    /// `ostrya`.
    TooMany,
}

impl fmt::Display for ClaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClaimError::Malformed { uri, reason } => write!(f, "malformed claim '{uri}': {reason}"),
            ClaimError::TooMany => write!(f, "the certificate holds more than {MAX_CLAIMS} claims"),
        }
    }
}

impl std::error::Error for ClaimError {}

/// The claims of a client certificate, in the order of its URI SANs.
///
/// [`ClientAccess::claim_rules`](super::ClientAccess::claim_rules) gives the
/// rules of the claims for one namespace, and
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

    /// Returns `true` if the certificate holds no claim.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the claims, in the order of the URI SANs.
    pub fn as_slice(&self) -> &[Claim] {
        &self.inner
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

    /// Each malformed form is refused with its URI and a reason.
    #[test]
    fn a_malformed_claim_is_refused() {
        for uri in [
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
        ] {
            let Some(Err(err)) = Claim::parse(uri) else {
                panic!("{uri:?} was accepted");
            };
            let ClaimError::Malformed { uri: held, reason } = &err else {
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
                uri: "ostrya:ref:x:a".to_owned(),
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
}
