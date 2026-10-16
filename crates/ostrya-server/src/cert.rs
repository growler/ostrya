//! The client certificate of a TLS connection.

use ostrya::Checksum;
use x509_cert::Certificate;
use x509_cert::der::asn1::{PrintableStringRef, Utf8StringRef};
use x509_cert::der::oid::db::rfc4519::CN;
use x509_cert::der::{Decode, Tag, Tagged};
use x509_cert::name::Name;

/// What the server reads from the end-entity certificate of a client. The
/// server reads it one time for each connection.
#[derive(Debug)]
pub(crate) struct ClientCert {
    /// The SHA-256 digest of the DER bytes of the certificate.
    pub(crate) digest: Checksum,
    /// The one CN of the subject. It is `None` if the subject holds no CN,
    /// more than one CN, or a CN of a type other than UTF8String or
    /// PrintableString, and if the DER bytes do not parse.
    pub(crate) cn: Option<String>,
}

impl ClientCert {
    /// Reads the certificate `der`. If the bytes do not parse, the result
    /// has the digest and no CN, so the certificate can still match a
    /// `tls-sha256:HEX` or a `tls:*` item.
    pub(crate) fn from_der(der: &[u8]) -> ClientCert {
        let cn = Certificate::from_der(der)
            .ok()
            .and_then(|cert| subject_cn(&cert.tbs_certificate.subject));
        ClientCert {
            digest: Checksum::sha256(der),
            cn,
        }
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
    use super::*;

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
        let pem = include_str!("../../../tests/fixtures/tls/client.pem");
        let base64: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let der = ostrya::base64::decode(&base64).unwrap();
        let cert = ClientCert::from_der(&der);
        assert_eq!(cert.digest, Checksum::sha256(&der));
        assert_eq!(cert.cn.as_deref(), Some("ostrya test"));
    }

    /// Bytes that do not parse give the digest and no CN.
    #[test]
    fn bad_der_gives_the_digest_and_no_cn() {
        for der in [&b"not a certificate"[..], &[0x30, 0x03, 0x02, 0x01], &[]] {
            let cert = ClientCert::from_der(der);
            assert_eq!(cert.digest, Checksum::sha256(der));
            assert_eq!(cert.cn, None);
        }
    }
}
