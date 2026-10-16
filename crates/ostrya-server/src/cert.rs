//! The client certificate of a TLS connection, and the client certificate
//! that a trusted proxy forwards in a request header.
//!
//! A forwarded certificate is one of these values:
//!
//! - a URL-escaped PEM certificate, as nginx `$ssl_client_escaped_cert`
//!   gives it;
//! - a base64 DER certificate, as HAProxy `ssl_c_der,base64` gives it, or
//!   URL-escaped, as Traefik `passTLSClientCert` gives it.
//!
//! The server percent-decodes each value, and `+` stays `+`. A value that
//! starts with `-----BEGIN` is PEM, and each other value is base64. An empty
//! value is no certificate. A value with a comma, more than one line of the
//! header, and PEM with more than one `CERTIFICATE` section hold more than
//! one certificate. The server verifies the certificate with the verifier of
//! the client CA, with no intermediate. It keeps each verified certificate in
//! a cache of [`CACHE_ENTRIES`] entries, keyed by the SHA-256 digest of its
//! DER bytes, until the end of its validity period.
//!
//! The server reads the claims of a certificate, its URI SANs with the
//! scheme `ostrya`, when it reads the certificate. A cache entry keeps them,
//! also when they do not parse.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_rustls::pki_types::pem::PemObject;
use futures_rustls::pki_types::{CertificateDer, UnixTime};
use futures_rustls::rustls::server::danger::ClientCertVerifier;
use hyper::HeaderMap;
use hyper::header::HeaderName;
use ostrya::Checksum;
use ostrya::access::{ClaimError, Claims};
use x509_cert::Certificate;
use x509_cert::der::asn1::{PrintableStringRef, Utf8StringRef};
use x509_cert::der::oid::db::rfc4519::CN;
use x509_cert::der::oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME;
use x509_cert::der::{Decode, Tag, Tagged};
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::name::Name;

use crate::event::Escaped;

/// The most verified certificates that the cache of forwarded certificates
/// holds. When the cache is full, a new entry removes the oldest entry.
pub(crate) const CACHE_ENTRIES: usize = 1024;

/// What the server reads from the end-entity certificate of a client. The
/// server reads the certificate of a TLS handshake one time for each
/// connection.
#[derive(Debug)]
pub(crate) struct ClientCert {
    /// The SHA-256 digest of the DER bytes of the certificate.
    pub(crate) digest: Checksum,
    /// The text `tls-sha256:HEX` of `digest`. It is the owner key of a
    /// client whose certificate gives the item of a group with
    /// `tls-accept-claim=true`.
    pub(crate) owner: Arc<str>,
    /// The one CN of the subject. It is `None` if the subject holds no CN,
    /// more than one CN, or a CN of a type other than UTF8String or
    /// PrintableString, and if the DER bytes do not parse.
    pub(crate) cn: Option<String>,
    /// The end of the validity period, as the time since the Unix epoch. It
    /// is `None` if the DER bytes do not parse.
    pub(crate) not_after: Option<Duration>,
    /// The claims of the URI SANs, or why they do not parse.
    pub(crate) claims: Result<Claims, ClaimFault>,
}

impl ClientCert {
    /// Reads the certificate `der`. If the bytes do not parse, the result
    /// has the digest and no CN, so the certificate can still match a
    /// `tls-sha256:HEX` or a `tls:*` item.
    pub(crate) fn from_der(der: &[u8]) -> ClientCert {
        ClientCert::from_der_with_digest(der, Checksum::sha256(der))
    }

    /// [`from_der`](ClientCert::from_der), with the digest `digest` of `der`
    /// that the caller computed.
    fn from_der_with_digest(der: &[u8], digest: Checksum) -> ClientCert {
        let cert = Certificate::from_der(der).ok();
        ClientCert {
            owner: format!("tls-sha256:{digest}").into(),
            digest,
            cn: cert
                .as_ref()
                .and_then(|cert| subject_cn(&cert.tbs_certificate.subject)),
            not_after: cert
                .as_ref()
                .map(|cert| cert.tbs_certificate.validity.not_after.to_unix_duration()),
            claims: cert
                .as_ref()
                .map_or(Err(ClaimFault::Unreadable(UNDECODABLE)), claims),
        }
    }
}

/// Why the server reads no claims from a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClaimFault {
    /// A URI SAN with the scheme `ostrya` is no claim, or the certificate
    /// holds too many claims.
    Claim(ClaimError),
    /// The certificate or its subjectAltName extension does not decode, or
    /// the certificate holds more than one subjectAltName extension. The
    /// text is the reason.
    Unreadable(&'static str),
}

/// The reason of a certificate that does not decode.
const UNDECODABLE: &str = "the certificate does not decode";

/// The reason of a certificate with more than one subjectAltName extension.
const TWO_SANS: &str = "the certificate holds more than one subjectAltName extension";

/// The reason of a subjectAltName extension that does not decode.
const BAD_SAN: &str = "the subjectAltName extension of the certificate does not decode";

impl ClaimFault {
    /// The URI SAN that is no claim, if one is.
    pub(crate) fn san(&self) -> Option<&str> {
        match self {
            ClaimFault::Claim(ClaimError::Malformed { uri, .. }) => Some(uri),
            _ => None,
        }
    }

    /// Why the claims do not parse, without the URI SAN.
    pub(crate) fn reason(&self) -> String {
        match self {
            ClaimFault::Claim(ClaimError::Malformed { reason, .. }) => reason.clone(),
            ClaimFault::Claim(other) => other.to_string(),
            ClaimFault::Unreadable(reason) => (*reason).to_owned(),
        }
    }
}

/// The URI SAN and the reason, with each control character escaped.
impl fmt::Display for ClaimFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(san) = self.san() {
            write!(f, "malformed claim '{}': ", Escaped(san))?;
        }
        write!(f, "{}", Escaped(&self.reason()))
    }
}

/// The claims of the URI SANs of `cert`.
fn claims(cert: &Certificate) -> Result<Claims, ClaimFault> {
    let mut extensions = cert
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .filter(|extension| extension.extn_id == ID_CE_SUBJECT_ALT_NAME);
    let Some(extension) = extensions.next() else {
        return Ok(Claims::default());
    };
    if extensions.next().is_some() {
        return Err(ClaimFault::Unreadable(TWO_SANS));
    }
    let names = SubjectAltName::from_der(extension.extn_value.as_bytes())
        .map_err(|_| ClaimFault::Unreadable(BAD_SAN))?;
    Claims::parse(names.0.iter().filter_map(|name| match name {
        GeneralName::UniformResourceIdentifier(uri) => Some(uri.as_str()),
        _ => None,
    }))
    .map_err(ClaimFault::Claim)
}

/// Why a forwarded certificate gets 403.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Bad {
    /// The header holds more than one certificate.
    MoreThanOne,
    /// The value does not decode to one certificate.
    Invalid,
    /// The verifier of the client CA refuses the certificate.
    Unverified,
}

impl Bad {
    /// The message of the refusal.
    pub(crate) fn message(self) -> &'static str {
        match self {
            Bad::MoreThanOne => "the forwarded client certificate holds more than one certificate",
            Bad::Invalid => "the forwarded client certificate does not parse",
            Bad::Unverified => "the client CA does not verify the forwarded client certificate",
        }
    }
}

/// The DER bytes of the forwarded certificate in the header `name` of
/// `headers`, or `None` when the header is absent or empty.
fn forwarded_der(headers: &HeaderMap, name: &HeaderName) -> Result<Option<Vec<u8>>, Bad> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(Bad::MoreThanOne);
    }
    let text = std::str::from_utf8(value.as_bytes()).map_err(|_| Bad::Invalid)?;
    let text = crate::router::percent_decode(text).ok_or(Bad::Invalid)?;
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    if text.contains(',') {
        return Err(Bad::MoreThanOne);
    }
    if !text.starts_with("-----BEGIN") {
        return ostrya::base64::decode(text)
            .map(Some)
            .map_err(|_| Bad::Invalid);
    }
    let mut certs = CertificateDer::pem_slice_iter(text.as_bytes());
    let der = certs
        .next()
        .ok_or(Bad::Invalid)?
        .map_err(|_| Bad::Invalid)?;
    match certs.next() {
        None => Ok(Some(der.to_vec())),
        Some(Ok(_)) => Err(Bad::MoreThanOne),
        Some(Err(_)) => Err(Bad::Invalid),
    }
}

/// The certificates that trusted proxies forward in the request header
/// `header`, and the verifier of the client CA.
pub(crate) struct ForwardedCerts {
    header: HeaderName,
    verifier: Arc<dyn ClientCertVerifier>,
    cache: Mutex<Cache>,
}

/// The verified forwarded certificates, by the SHA-256 digest of their DER
/// bytes.
struct Cache {
    capacity: usize,
    entries: HashMap<[u8; 32], Cached>,
    /// The keys of `entries`, from the oldest to the newest.
    order: VecDeque<[u8; 32]>,
}

/// One verified certificate.
struct Cached {
    cert: Arc<ClientCert>,
    /// The end of the validity period of the certificate.
    not_after: Duration,
}

impl Cache {
    /// Removes the entry of `key`.
    fn remove(&mut self, key: &[u8; 32]) {
        if self.entries.remove(key).is_some() {
            self.order.retain(|k| k != key);
        }
    }

    /// Adds `cert` under `key`. When the cache is full, the oldest entry
    /// goes.
    fn insert(&mut self, key: [u8; 32], cert: Arc<ClientCert>, not_after: Duration) {
        if self.entries.contains_key(&key) {
            return;
        }
        while self.entries.len() >= self.capacity {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.entries.remove(&oldest);
        }
        self.entries.insert(key, Cached { cert, not_after });
        self.order.push_back(key);
    }
}

impl ForwardedCerts {
    /// The certificates of the header `header`, verified by `verifier`.
    pub(crate) fn new(header: HeaderName, verifier: Arc<dyn ClientCertVerifier>) -> ForwardedCerts {
        ForwardedCerts::with_capacity(header, verifier, CACHE_ENTRIES)
    }

    fn with_capacity(
        header: HeaderName,
        verifier: Arc<dyn ClientCertVerifier>,
        capacity: usize,
    ) -> ForwardedCerts {
        ForwardedCerts {
            header,
            verifier,
            cache: Mutex::new(Cache {
                capacity,
                entries: HashMap::new(),
                order: VecDeque::new(),
            }),
        }
    }

    /// The verified certificate of a request with `headers` at the time
    /// `now`, or `None` when the header is absent or empty.
    ///
    /// A cache entry serves the request while `now` is before the end of the
    /// validity period of its certificate. Else the function verifies the
    /// certificate, and keeps a verified certificate in the cache. It keeps
    /// no refusal.
    pub(crate) fn certificate(
        &self,
        headers: &HeaderMap,
        now: UnixTime,
    ) -> Result<Option<Arc<ClientCert>>, Bad> {
        let Some(der) = forwarded_der(headers, &self.header)? else {
            return Ok(None);
        };
        let digest = Checksum::sha256(&der);
        let key = *digest.as_bytes();
        let at = Duration::from_secs(now.as_secs());
        {
            let mut cache = self.cache.lock().expect("certificate cache mutex");
            if let Some(entry) = cache.entries.get(&key) {
                if at < entry.not_after {
                    return Ok(Some(entry.cert.clone()));
                }
                cache.remove(&key);
            }
        }
        self.verifier
            .verify_client_cert(&CertificateDer::from(der.as_slice()), &[], now)
            .map_err(|_| Bad::Unverified)?;
        let cert = Arc::new(ClientCert::from_der_with_digest(&der, digest));
        if let Some(not_after) = cert.not_after {
            let mut cache = self.cache.lock().expect("certificate cache mutex");
            cache.insert(key, cert.clone(), not_after);
        }
        Ok(Some(cert))
    }
}

/// The CN of `name`. The function reads each attribute of each RDN, so a CN
/// in a multi-valued RDN counts too. It gives `Some` only if `name` holds
/// exactly one CN, of type UTF8String or PrintableString, with a valid value
/// of that type.
fn subject_cn(name: &Name) -> Option<String> {
    let mut cns = name
        .0
        .iter()
        .flat_map(|rdn| rdn.0.iter())
        .filter(|attribute| attribute.oid == CN);
    let value = &cns.next()?.value;
    if cns.next().is_some() {
        return None;
    }
    match value.tag() {
        Tag::Utf8String => value
            .decode_as::<Utf8StringRef<'_>>()
            .ok()
            .map(|text| text.as_str().to_owned()),
        Tag::PrintableString => value
            .decode_as::<PrintableStringRef<'_>>()
            .ok()
            .map(|text| text.as_str().to_owned()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use futures_rustls::rustls;
    use futures_rustls::rustls::client::danger::HandshakeSignatureValid;
    use futures_rustls::rustls::server::danger::ClientCertVerified;
    use futures_rustls::rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
    use hyper::header::HeaderValue;

    use super::*;
    use crate::test_pki::TestCa;

    /// The CN of the subject `text`, in the string form of RFC 4514. A value
    /// `#HEX` is the DER bytes of the value, with its tag.
    fn cn(text: &str) -> Option<String> {
        subject_cn(&text.parse::<Name>().unwrap())
    }

    #[test]
    fn one_utf8_or_printable_cn_is_the_name() {
        assert_eq!(cn("CN=ostrya test").as_deref(), Some("ostrya test"));
        assert_eq!(cn("CN=#0c03616263").as_deref(), Some("abc"));
        assert_eq!(cn("CN=#1303616263").as_deref(), Some("abc"));
        assert_eq!(cn("O=org,CN=host,C=DE").as_deref(), Some("host"));
    }

    /// Two CNs give no name, also in one multi-valued RDN.
    #[test]
    fn two_cns_give_no_name() {
        assert_eq!(cn("CN=a,CN=b"), None);
        assert_eq!(cn("CN=a,O=org,CN=a"), None);
        assert_eq!(cn("CN=a+CN=b"), None);
        assert_eq!(cn("O=org+CN=a,CN=b"), None);
        assert_eq!(cn("O=org+CN=a").as_deref(), Some("a"));
    }

    #[test]
    fn no_cn_gives_no_name() {
        assert_eq!(cn("O=org,C=DE"), None);
        assert_eq!(subject_cn(&Name::default()), None);
    }

    /// A CN of another type, and a value that is not valid for its type,
    /// give no name.
    #[test]
    fn a_cn_of_another_type_gives_no_name() {
        // BMPString, TeletexString, IA5String, VisibleString.
        for value in ["1e020061", "1403616263", "1603616263", "1a03616263"] {
            assert_eq!(cn(&format!("CN=#{value}")), None, "{value}");
        }
        // A UTF8String that is not UTF-8, and a PrintableString with `@`.
        assert_eq!(cn("CN=#0c01ff"), None);
        assert_eq!(cn("CN=#130140"), None);
    }

    /// The fixture client certificate has the subject `CN=ostrya test`.
    #[test]
    fn the_fixture_certificate_gives_its_digest_and_cn() {
        let der = der(CLIENT_PEM);
        let cert = ClientCert::from_der(&der);
        assert_eq!(cert.digest, Checksum::sha256(&der));
        assert_eq!(cert.cn.as_deref(), Some("ostrya test"));
    }

    /// The fixture client certificate ends its validity on 2126-07-02 at
    /// 12:02:20 UTC.
    #[test]
    fn the_fixture_certificate_gives_its_not_after() {
        let cert = ClientCert::from_der(&der(CLIENT_PEM));
        assert_eq!(cert.not_after, Some(Duration::from_secs(4_938_667_340)));
    }

    /// Bytes that do not parse give the digest and no CN.
    #[test]
    fn bad_der_gives_the_digest_and_no_cn() {
        for der in [&b"not a certificate"[..], &[0x30, 0x03, 0x02, 0x01], &[]] {
            let cert = ClientCert::from_der(der);
            assert_eq!(cert.digest, Checksum::sha256(der));
            assert_eq!(cert.cn, None);
            assert_eq!(cert.not_after, None);
        }
    }

    const CLIENT_PEM: &str = include_str!("../../../tests/fixtures/tls/client.pem");
    const SERVER_PEM: &str = include_str!("../../../tests/fixtures/tls/server.pem");
    const CA_PEM: &str = include_str!("../../../tests/fixtures/tls/ca.pem");
    const UNTRUSTED_PEM: &str = include_str!("../../../tests/fixtures/tls/server-untrusted.pem");

    /// The base64 of the one certificate of `pem`, with no line break.
    fn base64(pem: &str) -> String {
        pem.lines()
            .filter(|line| !line.starts_with("-----"))
            .collect()
    }

    /// The DER bytes of the one certificate of `pem`.
    fn der(pem: &str) -> Vec<u8> {
        ostrya::base64::decode(&base64(pem)).unwrap()
    }

    /// `text` with each byte other than a letter, a digit, `-`, `.`, `_`, and
    /// `~` as `%XX`.
    fn escape(text: &str) -> String {
        text.bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                    char::from(b).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect()
    }

    fn name() -> HeaderName {
        HeaderName::from_static("x-client-cert")
    }

    /// The headers with one line of `name` for each of `values`.
    fn headers(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(name(), value.parse().unwrap());
        }
        headers
    }

    fn decoded(values: &[&str]) -> Result<Option<Vec<u8>>, Bad> {
        forwarded_der(&headers(values), &name())
    }

    /// The forms of nginx, HAProxy, and Traefik give the DER bytes of the
    /// certificate.
    #[test]
    fn the_forms_of_each_proxy_decode_to_the_der() {
        let der = der(CLIENT_PEM);
        let base64 = base64(CLIENT_PEM);
        assert!(base64.contains('+') || base64.contains('/'));
        for value in [
            escape(CLIENT_PEM),
            base64.clone(),
            escape(&base64),
            format!(" {base64} "),
            escape(&CLIENT_PEM.replace('\n', "\r\n")),
        ] {
            assert_eq!(decoded(&[&value]), Ok(Some(der.clone())), "{value}");
        }
    }

    /// An absent header, an empty value, and white space alone give no
    /// certificate.
    #[test]
    fn an_empty_value_is_no_certificate() {
        assert_eq!(decoded(&[]), Ok(None));
        for value in ["", " ", "%20", "%0A%09"] {
            assert_eq!(decoded(&[value]), Ok(None), "{value:?}");
        }
    }

    /// A comma, two lines of the header, and two PEM sections hold more
    /// than one certificate.
    #[test]
    fn more_than_one_certificate_is_refused() {
        let base64 = base64(CLIENT_PEM);
        let other = self::base64(SERVER_PEM);
        let two = format!("{CLIENT_PEM}{SERVER_PEM}");
        for values in [
            vec![format!("{base64},{other}")],
            vec![escape(&format!("{base64},{other}"))],
            vec![format!("{base64},")],
            vec![base64.clone(), other.clone()],
            vec![base64.clone(), String::new()],
            vec![escape(&two)],
        ] {
            let values: Vec<&str> = values.iter().map(String::as_str).collect();
            assert_eq!(decoded(&values), Err(Bad::MoreThanOne), "{values:?}");
        }
    }

    /// A bad escape, bad base64, and PEM with no `CERTIFICATE` section do
    /// not parse.
    #[test]
    fn a_value_that_does_not_decode_is_invalid() {
        let key = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        for value in [
            "%zz".to_owned(),
            "abc%".to_owned(),
            "%00".to_owned(),
            "!!!".to_owned(),
            "QUJD RA==".to_owned(),
            "A".to_owned(),
            escape(key),
            escape("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n"),
            "-----BEGIN CERTIFICATE-----".to_owned(),
        ] {
            assert_eq!(decoded(&[&value]), Err(Bad::Invalid), "{value}");
        }
        let bytes = HeaderValue::from_bytes(b"\xffabc").unwrap();
        let mut headers = HeaderMap::new();
        headers.append(name(), bytes);
        assert_eq!(forwarded_der(&headers, &name()), Err(Bad::Invalid));
    }

    /// A verifier that accepts each certificate whose DER bytes are not in
    /// `refused`, and counts its calls.
    #[derive(Debug, Default)]
    struct Counting {
        calls: AtomicUsize,
        refused: Vec<Vec<u8>>,
    }

    impl ClientCertVerifier for Counting {
        fn root_hint_subjects(&self) -> &[DistinguishedName] {
            &[]
        }

        fn verify_client_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            _now: UnixTime,
        ) -> Result<ClientCertVerified, rustls::Error> {
            assert!(intermediates.is_empty());
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.refused.iter().any(|der| der[..] == end_entity[..]) {
                return Err(rustls::Error::General("refused".into()));
            }
            Ok(ClientCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Err(rustls::Error::General("unused".into()))
        }

        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Err(rustls::Error::General("unused".into()))
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            Vec::new()
        }
    }

    fn at(secs: u64) -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(secs))
    }

    /// A cache hit verifies no more. An entry serves until the end of the
    /// validity period of its certificate, and then the certificate is
    /// verified again.
    #[test]
    fn a_cache_hit_verifies_no_more_until_not_after() {
        let counting = Arc::new(Counting::default());
        let certs = ForwardedCerts::new(name(), counting.clone());
        let request = headers(&[&base64(CLIENT_PEM)]);
        let calls = || counting.calls.load(Ordering::Relaxed);
        let not_after = 4_938_667_340;
        let first = certs.certificate(&request, at(1)).unwrap().unwrap();
        assert_eq!(first.cn.as_deref(), Some("ostrya test"));
        assert_eq!(first.digest, Checksum::sha256(&der(CLIENT_PEM)));
        let second = certs
            .certificate(&request, at(not_after - 1))
            .unwrap()
            .unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(calls(), 1);
        let third = certs.certificate(&request, at(not_after)).unwrap().unwrap();
        assert!(!Arc::ptr_eq(&first, &third));
        assert_eq!(calls(), 2);
        certs.certificate(&request, at(2)).unwrap().unwrap();
        assert_eq!(calls(), 2);
    }

    /// A full cache removes its oldest entry for a new one.
    #[test]
    fn a_full_cache_removes_the_oldest_entry() {
        let counting = Arc::new(Counting::default());
        let certs = ForwardedCerts::with_capacity(name(), counting.clone(), 2);
        let calls = || counting.calls.load(Ordering::Relaxed);
        let get = |pem: &str| {
            certs
                .certificate(&headers(&[&base64(pem)]), at(1))
                .unwrap()
                .unwrap();
        };
        get(CLIENT_PEM);
        get(SERVER_PEM);
        get(CLIENT_PEM);
        assert_eq!(calls(), 2);
        get(CA_PEM);
        assert_eq!(calls(), 3);
        get(SERVER_PEM);
        get(CA_PEM);
        assert_eq!(calls(), 3);
        get(CLIENT_PEM);
        assert_eq!(calls(), 4);
        get(CA_PEM);
        assert_eq!(calls(), 4);
        get(SERVER_PEM);
        assert_eq!(calls(), 5);
        assert_eq!(certs.cache.lock().unwrap().entries.len(), 2);
        assert_eq!(certs.cache.lock().unwrap().order.len(), 2);
        assert_eq!(CACHE_ENTRIES, 1024);
    }

    /// A refusal of the verifier is no cache entry, and a value that does
    /// not decode reaches no verifier.
    #[test]
    fn a_refusal_is_not_cached() {
        let counting = Arc::new(Counting {
            refused: vec![der(UNTRUSTED_PEM)],
            ..Counting::default()
        });
        let certs = ForwardedCerts::new(name(), counting.clone());
        let request = headers(&[&base64(UNTRUSTED_PEM)]);
        for _ in 0..2 {
            assert_eq!(
                certs.certificate(&request, at(1)).err(),
                Some(Bad::Unverified)
            );
        }
        assert_eq!(counting.calls.load(Ordering::Relaxed), 2);
        assert!(certs.cache.lock().unwrap().entries.is_empty());
        assert_eq!(
            certs.certificate(&headers(&["!"]), at(1)).err(),
            Some(Bad::Invalid)
        );
        assert_eq!(
            certs.certificate(&headers(&[]), at(1)).unwrap().map(|_| ()),
            None
        );
        assert_eq!(counting.calls.load(Ordering::Relaxed), 2);
    }

    use x509_cert::der::Encode;
    use x509_cert::der::asn1::Ia5String;

    /// The URIs of the claims of `cert`, as the claims write them.
    fn claim_texts(cert: &ClientCert) -> Vec<String> {
        use ostrya::access::ClaimRule;
        cert.claims
            .as_ref()
            .unwrap()
            .as_slice()
            .iter()
            .map(|claim| match &claim.rule {
                ClaimRule::Allow(item) => format!("{:?} {item}", claim.namespace),
                ClaimRule::Deny(pattern) => format!("{:?} !{}", claim.namespace, pattern.as_str()),
            })
            .collect()
    }

    /// The URI SANs with the scheme `ostrya` are the claims, in order. Other
    /// URIs and DNS names are no claims.
    #[test]
    fn the_uri_sans_give_the_claims() {
        let ca = TestCa::new();
        let leaf = ca.leaf(
            "claims",
            &[
                "ostrya:ref:w:main",
                "https://example.com/",
                "ostrya:collection:a.b:!os/**",
            ],
        );
        let cert = ClientCert::from_der(&leaf);
        assert_eq!(cert.cn.as_deref(), Some("claims"));
        assert_eq!(
            claim_texts(&cert),
            [
                "Local w:main".to_owned(),
                "Collection(\"a.b\") !os/**".to_owned()
            ]
        );
        let san = SubjectAltName(vec![
            GeneralName::DnsName(Ia5String::new("ostrya:ref:x:a").unwrap()),
            GeneralName::UniformResourceIdentifier(Ia5String::new("ostrya:ref:d:b").unwrap()),
        ]);
        let dns = ClientCert::from_der(&ca.leaf_with("dns", None, &[san.to_der().unwrap()]));
        assert_eq!(claim_texts(&dns), ["Local d:b".to_owned()]);
        let none = ClientCert::from_der(&ca.leaf("none", &[]));
        assert_eq!(none.claims, Ok(ostrya::access::Claims::default()));
        let fixture = ClientCert::from_der(&der(CLIENT_PEM));
        assert_eq!(fixture.claims, Ok(ostrya::access::Claims::default()));
    }

    /// A malformed claim gives its URI and the reason. Too many claims, a
    /// subjectAltName extension that does not decode, two subjectAltName
    /// extensions, and bytes that do not parse give a fault with no URI, each
    /// with its own reason.
    #[test]
    fn claims_that_do_not_parse_give_a_fault() {
        let ca = TestCa::new();
        let bad = ClientCert::from_der(&ca.leaf("bad", &["ostrya:ref:a", "ostrya:ref:x:b"]));
        let fault = bad.claims.unwrap_err();
        assert_eq!(fault.san(), Some("ostrya:ref:x:b"));
        assert_eq!(
            fault.to_string(),
            "malformed claim 'ostrya:ref:x:b': the modes are one or more of r, w, c, t, and d"
        );
        let upper = ClientCert::from_der(&ca.leaf("upper", &["OSTRYA:ref:a"]));
        assert_eq!(upper.claims.unwrap_err().san(), Some("OSTRYA:ref:a"));
        let uris: Vec<String> = (0..=ostrya::access::MAX_CLAIMS)
            .map(|i| format!("ostrya:ref:r{i}"))
            .collect();
        let uris: Vec<&str> = uris.iter().map(String::as_str).collect();
        let many = ClientCert::from_der(&ca.leaf("many", &uris));
        let fault = many.claims.unwrap_err();
        assert_eq!(fault, ClaimFault::Claim(ClaimError::TooMany));
        assert_eq!(fault.san(), None);
        assert_eq!(
            fault.to_string(),
            "the certificate holds more than 256 claims"
        );
        // A SEQUENCE with one URI whose byte 0x80 is not IA5.
        let undecodable = ca.leaf_with("raw", None, &[vec![0x30, 0x03, 0x86, 0x01, 0x80]]);
        let cert = ClientCert::from_der(&undecodable);
        assert_eq!(cert.cn.as_deref(), Some("raw"));
        let fault = cert.claims.unwrap_err();
        assert_eq!(fault.san(), None);
        assert_eq!(
            fault.to_string(),
            "the subjectAltName extension of the certificate does not decode"
        );
        let san = crate::test_pki::uri_sans(&["ostrya:ref:a"]);
        let two = ClientCert::from_der(&ca.leaf_with("two", None, &[san.clone(), san]));
        let fault = two.claims.unwrap_err();
        assert_eq!(fault.san(), None);
        assert_eq!(
            fault.to_string(),
            "the certificate holds more than one subjectAltName extension"
        );
        let fault = ClientCert::from_der(b"not a certificate")
            .claims
            .unwrap_err();
        assert_eq!(fault.san(), None);
        assert_eq!(fault.to_string(), "the certificate does not decode");
    }

    /// A control character of a malformed claim is escaped in the text of
    /// the fault.
    #[test]
    fn a_fault_escapes_control_characters() {
        let fault = ClaimFault::Claim(ClaimError::Malformed {
            uri: "ostrya:ref:a\nb".to_owned(),
            reason: "why\r".to_owned(),
        });
        assert_eq!(
            fault.to_string(),
            "malformed claim 'ostrya:ref:a\\nb': why\\r"
        );
    }

    /// A cache entry keeps the claims of a forwarded certificate, also when
    /// they do not parse, and a cache hit verifies and parses nothing.
    #[test]
    fn a_cache_entry_keeps_the_claims() {
        let ca = TestCa::new();
        let verifier = ostrya_fetch::client_cert_verifier(ca.pem.as_bytes()).unwrap();
        let certs = ForwardedCerts::new(name(), verifier);
        for uris in [&["ostrya:ref:w:main"][..], &["ostrya:ref:x:main"]] {
            let der = ca.leaf("forwarded", uris);
            let request = headers(&[&ostrya::base64::encode(&der)]);
            let first = certs
                .certificate(&request, UnixTime::now())
                .unwrap()
                .unwrap();
            let second = certs
                .certificate(&request, UnixTime::now())
                .unwrap()
                .unwrap();
            assert!(Arc::ptr_eq(&first, &second));
            assert_eq!(first.claims, ClientCert::from_der(&der).claims);
        }
        assert_eq!(certs.cache.lock().unwrap().entries.len(), 2);
    }

    /// The verifier of the fixture CA accepts the fixture client
    /// certificate, and refuses a certificate with no `clientAuth` usage.
    #[test]
    fn the_verifier_of_the_client_ca_checks_a_forwarded_certificate() {
        let verifier = ostrya_fetch::client_cert_verifier(CA_PEM.as_bytes()).unwrap();
        let certs = ForwardedCerts::new(name(), verifier);
        let cert = certs
            .certificate(&headers(&[&escape(CLIENT_PEM)]), UnixTime::now())
            .unwrap()
            .unwrap();
        assert_eq!(cert.cn.as_deref(), Some("ostrya test"));
        for pem in [SERVER_PEM, UNTRUSTED_PEM] {
            let request = headers(&[&base64(pem)]);
            assert_eq!(
                certs.certificate(&request, UnixTime::now()).err(),
                Some(Bad::Unverified)
            );
        }
    }
}
