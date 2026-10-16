//! The claims of a client certificate: the allow items and the deny items
//! that the URI SANs of the certificate state.

use std::fmt;

use ostrya_core::RefPattern;

use super::Namespace;
use super::rights::{AllowItem, parse_allow, parse_pattern};

/// The most claims that one certificate can hold.
///
/// [`Claims::parse`] refuses more claims with [`ClaimError::TooMany`].
pub const MAX_CLAIMS: usize = 256;

/// The scheme of a claim, with its `:`.
const SCHEME: &str = "ostrya:";

/// The rule of one claim: an allow item or a deny item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimRule {
    /// An allow item, `[MODES:]PATTERN`.
    Allow(AllowItem),
    /// A deny item, `!PATTERN`.
    Deny(RefPattern),
}

/// One claim of a client certificate.
///
/// A claim is a URI SAN in one of these forms:
///
/// - `ostrya:ref:[MODES:]PATTERN` -- an allow item of the local refs.
/// - `ostrya:ref:!PATTERN` -- a deny item of the local refs.
/// - `ostrya:collection:ID:[MODES:]PATTERN` -- an allow item of the
///   collection `ID`.
/// - `ostrya:collection:ID:!PATTERN` -- a deny item of the collection `ID`.
///
/// `[MODES:]PATTERN` is the text that [`AllowItem::parse`] reads, so a claim
/// with no `MODES` has the mode `r`. `PATTERN` is a [`RefPattern`]. `ID`
/// passes [`is_collection_id`](crate::is_collection_id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// The namespace that the claim names: [`Local`](Namespace::Local) for
    /// `ostrya:ref:`, and the collection `ID` for `ostrya:collection:ID:`.
    pub namespace: Namespace,
    /// The allow item or the deny item of the claim.
    pub rule: ClaimRule,
}

impl Claim {
    /// Parses the URI `uri` as a claim.
    ///
    /// The result is `None` if `uri` is not a claim: its scheme is not
    /// `ostrya`, in any case. The scheme and the kind, `ref` or
    /// `collection`, are lowercase in a claim. Each other spelling is a
    /// malformed claim.
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
    const FORMS: &str = "a claim starts with ostrya:ref: or ostrya:collection:ID:";
    let rest = uri.strip_prefix(SCHEME).ok_or(FORMS)?;
    let (namespace, rule) = if let Some(rule) = rest.strip_prefix("ref:") {
        (Namespace::Local, rule)
    } else if let Some(rest) = rest.strip_prefix("collection:") {
        let (id, rule) = rest.split_once(':').ok_or(FORMS)?;
        if !ostrya_core::is_collection_id(id) {
            return Err("the collection id fails the collection-id rule".to_owned());
        }
        (Namespace::Collection(id.to_owned()), rule)
    } else {
        return Err(FORMS.to_owned());
    };
    let rule = match rule.strip_prefix('!') {
        Some(pattern) => ClaimRule::Deny(parse_pattern(pattern)?),
        None => ClaimRule::Allow(parse_allow(rule)?),
    };
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
/// rules of the claims for one namespace.
///
/// # Examples
///
/// ```
/// use ostrya::access::{ClaimRule, Claims, Namespace};
///
/// let claims = Claims::parse([
///     "https://example.com/",
///     "ostrya:ref:wd:devel/**",
///     "ostrya:collection:com.example.os:!os/secret",
/// ])?;
/// assert_eq!(claims.as_slice().len(), 2);
/// assert_eq!(claims.as_slice()[0].namespace, Namespace::Local);
/// assert!(matches!(claims.as_slice()[1].rule, ClaimRule::Deny(_)));
/// assert!(Claims::parse(["ostrya:ref:x:a"]).is_err());
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

    /// Each of the four forms parses, and a claim with no modes has `r`.
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
            allow("ostrya:collection:com.example.os:t:os/release/**"),
            (collection("com.example.os"), "t:os/release/**".to_owned())
        );
        assert_eq!(
            allow("ostrya:collection:_a.b_1:os"),
            (collection("_a.b_1"), "r:os".to_owned())
        );
        assert_eq!(
            deny("ostrya:collection:a.b:!os/*"),
            (collection("a.b"), "os/*".to_owned())
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
            "ostrya:collection:a.b",
            "ostrya:collection:a.b:",
            "ostrya:collection::r:a",
            "ostrya:collection:fresh:r:a",
            "ostrya:collection:1a.b:r:a",
            "ostrya:collection:a..b:r:a",
            "ostrya:collection:a.b:x:a",
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
        assert_eq!(
            reason("ostrya:tag:a"),
            "a claim starts with ostrya:ref: or ostrya:collection:ID:"
        );
        assert_eq!(
            reason("OSTRYA:ref:a"),
            "a claim starts with ostrya:ref: or ostrya:collection:ID:"
        );
        assert_eq!(
            reason("ostrya:collection:fresh:a"),
            "the collection id fails the collection-id rule"
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
            "ostrya:collection:a.b:w:b",
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
