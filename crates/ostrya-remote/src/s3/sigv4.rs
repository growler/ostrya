//! The AWS Signature Version 4 of an S3 request.

use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use ostrya_fetch::{RequestSigner, SignPayload, SignRequest};
use sha2::{Digest, Sha256};

use super::Credentials;
use crate::{Error, Result};

/// The SHA-256 of an empty body, in lowercase hexadecimal.
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// The message of a refused streamed body.
const STREAMED: &str =
    "SigV4 signs the SHA-256 of the whole body, and a streamed body has no bytes to hash";

/// A request signer that signs each request to S3 with AWS Signature
/// Version 4.
///
/// [`FetcherOptions::signer`](ostrya_fetch::FetcherOptions::signer) takes the
/// signer. The fetcher calls it for each attempt, so each attempt has a fresh
/// date.
///
/// # Signature
///
/// The signer puts the signature in the `Authorization` header, in the
/// form `AWS4-HMAC-SHA256 Credential=<id>/<scope>, SignedHeaders=<list>,
/// Signature=<hex>`. The scope is `<YYYYMMDD>/<region>/s3/aws4_request`, so
/// the service is always `s3`. The date is the UTC time of the host clock
/// when the fetcher calls the signer.
///
/// The signer returns these headers:
///
/// - `Authorization`
/// - `x-amz-date`, the time in the form `YYYYMMDDTHHMMSSZ`
/// - `x-amz-content-sha256`, the SHA-256 of the body in lowercase
///   hexadecimal
/// - `x-amz-security-token`, if the credentials have a session token
///
/// The signed headers are `host`, `x-amz-content-sha256`, `x-amz-date`, and
/// `x-amz-security-token` if the credentials have a session token. The
/// value of `host` is the authority of the request as the fetcher sends it.
/// The signer does not see the other headers of a request. So a request must
/// carry no other `x-amz-*` header, because S3 refuses a request with an
/// `x-amz-*` header that the signature does not sign.
///
/// The canonical path and the canonical query decode each percent escape of
/// the request, and encode again each byte other than `A-Z`, `a-z`, `0-9`,
/// `-`, `.`, `_`, and `~` as `%XX`. A `/` of the path stays as it is, and a
/// `/` of the query is encoded. A `+` of the path is a literal `+` and is
/// encoded as `%2B`. The path is not normalized: `//`, `/./`, and `/../` stay
/// as they are.
///
/// The signer refuses a query that holds a `+`, because a server reads a `+`
/// of a query as a space. A query sends a literal `+` as `%2B`, and the
/// signer signs it as `%2B`.
///
/// # Body
///
/// The signer hashes a body that the fetcher gives whole
/// ([`SignPayload::Bytes`]). It refuses a streamed body
/// ([`SignPayload::Streamed`]), because the signature holds the hash of the
/// body.
///
/// # Cleartext
///
/// The signer is a credential for the fetcher. A mirror on `http://` needs
/// [`allow_cleartext_credentials`](ostrya_fetch::FetcherOptions::allow_cleartext_credentials).
///
/// # Signing key
///
/// The signer keeps the signing key of the current date, and makes a new key
/// when the date changes.
///
/// The [`Debug`] output shows the region and the credentials as the
/// [`Debug`] output of [`Credentials`] shows them.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use ostrya_fetch::FetcherOptions;
/// use ostrya_remote::s3::{Credentials, SigV4};
/// # fn run() -> ostrya_remote::Result<()> {
/// let credentials = Credentials::new(
///     "AKIAIOSFODNN7EXAMPLE".into(),
///     "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
///     None,
/// )?;
/// let signer = SigV4::new(credentials, "eu-central-1")?;
/// let mut options = FetcherOptions::new("https://bucket.s3.eu-central-1.amazonaws.com/");
/// options.signer = Some(Arc::new(signer));
/// # Ok(()) }
/// # run().unwrap();
/// ```
pub struct SigV4 {
    credentials: Credentials,
    region: String,
    key: Mutex<Option<SigningKey>>,
}

/// The signing key of one date.
struct SigningKey {
    /// The date, in the form `YYYYMMDD`.
    date: [u8; 8],
    key: [u8; 32],
}

impl SigV4 {
    /// Returns the signer of `credentials` for the region `region`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInput`] if `region` is empty, is longer than 63 bytes,
    /// or holds a character other than an ASCII letter, a digit, `-`, `_`,
    /// or `.`.
    pub fn new(credentials: Credentials, region: &str) -> Result<SigV4> {
        if !valid_region(region) {
            return Err(Error::InvalidInput(region_refusal(region, "the region")));
        }
        Ok(SigV4 {
            credentials,
            region: region.to_owned(),
            key: Mutex::new(None),
        })
    }

    /// Returns the region of the signature scope.
    pub fn region(&self) -> &str {
        &self.region
    }

    /// Returns the headers that sign `request` at the time `now`.
    fn sign_at(
        &self,
        request: &SignRequest<'_>,
        now: SystemTime,
    ) -> ostrya_fetch::Result<Vec<(String, String)>> {
        let payload_hash = match request.payload {
            SignPayload::Empty => EMPTY_SHA256.to_owned(),
            SignPayload::Bytes(bytes) => hex(&Sha256::digest(bytes)),
            // `Streamed`, and each body form that a later fetcher adds.
            _ => return Err(ostrya_fetch::Error::Fetch(STREAMED.into())),
        };
        let amz_date = amz_date(now)?;
        let date = &amz_date[..8];
        let uri = canonical_uri(request.path)?;
        let query = canonical_query(request.query)?;
        let mut headers = vec![
            ("host", request.authority),
            ("x-amz-content-sha256", payload_hash.as_str()),
            ("x-amz-date", amz_date.as_str()),
        ];
        if let Some(token) = self.credentials.session_token() {
            headers.push(("x-amz-security-token", token));
        }
        let creq = canonical_request(request.method, &uri, &query, &headers, &payload_hash);
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let key = self.signing_key_of(date);
        let signature = hex(&hmac_sha256(
            &key,
            string_to_sign(&amz_date, &scope, &creq).as_bytes(),
        ));
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={}, Signature={signature}",
            self.credentials.access_key_id(),
            signed_headers(&headers),
        );
        let token = self.credentials.session_token().map(str::to_owned);
        let mut signed = vec![
            ("Authorization".to_owned(), authorization),
            ("x-amz-date".to_owned(), amz_date),
            ("x-amz-content-sha256".to_owned(), payload_hash),
        ];
        if let Some(token) = token {
            signed.push(("x-amz-security-token".to_owned(), token));
        }
        Ok(signed)
    }

    /// Returns the signing key of `date`, from the cache if the cache holds
    /// the key of that date.
    fn signing_key_of(&self, date: &str) -> [u8; 32] {
        let mut cached = self.key.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(cached) = &*cached
            && cached.date.as_slice() == date.as_bytes()
        {
            return cached.key;
        }
        let key = signing_key(self.credentials.secret_access_key(), date, &self.region);
        let mut stamp = [0; 8];
        stamp.copy_from_slice(date.as_bytes());
        *cached = Some(SigningKey { date: stamp, key });
        key
    }
}

impl RequestSigner for SigV4 {
    fn sign(&self, request: &SignRequest<'_>) -> ostrya_fetch::Result<Vec<(String, String)>> {
        self.sign_at(request, SystemTime::now())
    }
}

impl std::fmt::Debug for SigV4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigV4")
            .field("region", &self.region)
            .field("credentials", &self.credentials)
            .finish_non_exhaustive()
    }
}

/// Returns `true` if `region` is 1 to 63 bytes of ASCII letters, digits, `-`,
/// `_`, and `.`.
pub(super) fn valid_region(region: &str) -> bool {
    (1..=63).contains(&region.len())
        && region
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Returns the message of the refusal of the region `region`, which `source`
/// gives.
pub(super) fn region_refusal(region: &str, source: &str) -> String {
    format!(
        "{source}: the region {region:?} is not 1 to 63 ASCII letters, digits, '-', '_', or '.'"
    )
}

/// Returns `time` as an `x-amz-date` value: `YYYYMMDDTHHMMSSZ` in UTC.
fn amz_date(time: SystemTime) -> ostrya_fetch::Result<String> {
    let secs = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            ostrya_fetch::Error::Fetch(
                "the clock of the host is before 1970-01-01, so SigV4 has no date to sign".into(),
            )
        })?
        .as_secs();
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX / 2);
    let rest = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (rest / 3600, (rest % 3600) / 60, rest % 60);
    Ok(format!(
        "{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z"
    ))
}

/// Returns the civil date `days` days after 1970-01-01.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Percent-decodes `text`, a path or a part of a query.
///
/// `%` starts an escape of exactly two hexadecimal digits. `None` states that
/// `text` holds a different escape.
fn percent_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] != b'%' {
            decoded.push(bytes[at]);
            at += 1;
            continue;
        }
        let escape = bytes.get(at + 1..at + 3)?;
        if !escape.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        let text = std::str::from_utf8(escape).ok()?;
        decoded.push(u8::from_str_radix(text, 16).ok()?);
        at += 3;
    }
    Some(decoded)
}

/// Appends `bytes` to `out`, with each byte other than `A-Z`, `a-z`, `0-9`,
/// `-`, `.`, `_`, and `~` as `%XX` in uppercase. A `/` is encoded if
/// `encode_slash` is `true`.
fn uri_encode(bytes: &[u8], encode_slash: bool, out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else if b == b'/' && !encode_slash {
            out.push('/');
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 0xf)]));
        }
    }
}

/// Returns the canonical URI of the request path `path`.
fn canonical_uri(path: &str) -> ostrya_fetch::Result<String> {
    if path.is_empty() {
        return Ok("/".into());
    }
    let decoded = percent_decode(path).ok_or_else(|| {
        ostrya_fetch::Error::Fetch(format!(
            "SigV4: the request path {path:?} holds a malformed percent escape"
        ))
    })?;
    let mut uri = String::with_capacity(decoded.len());
    uri_encode(&decoded, false, &mut uri);
    Ok(uri)
}

/// Returns the canonical query string of the request query `query`.
///
/// Each parameter splits at its first `=`. A parameter with no `=` has an
/// empty value. The parameters are sorted by the encoded name, then by the
/// encoded value. A query that holds a `+` is refused. No message holds the
/// query, because a query can hold a credential.
fn canonical_query(query: Option<&str>) -> ostrya_fetch::Result<String> {
    let Some(query) = query else {
        return Ok(String::new());
    };
    if query.contains('+') {
        return Err(ostrya_fetch::Error::Fetch(
            "SigV4: the request query holds a '+', which a server reads as a space; \
             send a literal '+' as %2B"
                .into(),
        ));
    }
    let encoded = |part: &str| {
        let decoded = percent_decode(part).ok_or_else(|| {
            ostrya_fetch::Error::Fetch(
                "SigV4: the request query holds a malformed percent escape".into(),
            )
        })?;
        let mut out = String::with_capacity(decoded.len());
        uri_encode(&decoded, true, &mut out);
        Ok::<_, ostrya_fetch::Error>(out)
    };
    let mut params = Vec::new();
    for param in query.split('&').filter(|param| !param.is_empty()) {
        let (name, value) = param.split_once('=').unwrap_or((param, ""));
        params.push((encoded(name)?, encoded(value)?));
    }
    params.sort();
    let joined: Vec<String> = params
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect();
    Ok(joined.join("&"))
}

/// Returns the names of `headers` joined by `;`.
fn signed_headers(headers: &[(&str, &str)]) -> String {
    let names: Vec<&str> = headers.iter().map(|(name, _)| *name).collect();
    names.join(";")
}

/// Returns the canonical request.
///
/// `headers` holds the signed headers, with lowercase names, sorted by name.
fn canonical_request(
    method: &str,
    uri: &str,
    query: &str,
    headers: &[(&str, &str)],
    payload_hash: &str,
) -> String {
    let mut canonical_headers = String::new();
    for (name, value) in headers {
        canonical_headers.push_str(name);
        canonical_headers.push(':');
        canonical_headers.push_str(value);
        canonical_headers.push('\n');
    }
    format!(
        "{method}\n{uri}\n{query}\n{canonical_headers}\n{}\n{payload_hash}",
        signed_headers(headers)
    )
}

/// Returns the string to sign of the canonical request `creq`, with the date
/// `amz_date` and the scope `scope`.
fn string_to_sign(amz_date: &str, scope: &str, creq: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex(&Sha256::digest(creq.as_bytes()))
    )
}

/// Returns the signing key of `secret` for the date `date` (`YYYYMMDD`), the
/// region `region`, and the service `s3`.
fn signing_key(secret: &str, date: &str, region: &str) -> [u8; 32] {
    let mut seed = Vec::with_capacity(4 + secret.len());
    seed.extend_from_slice(b"AWS4");
    seed.extend_from_slice(secret.as_bytes());
    let key = hmac_sha256(&seed, date.as_bytes());
    let key = hmac_sha256(&key, region.as_bytes());
    let key = hmac_sha256(&key, b"s3");
    hmac_sha256(&key, b"aws4_request")
}

/// Returns the HMAC-SHA256 of `data` with `key`.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Returns `bytes` in lowercase hexadecimal.
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0xf)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    const ID: &str = "AKIAIOSFODNN7EXAMPLE";
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const HOST: &str = "examplebucket.s3.amazonaws.com";
    /// 2013-05-24T00:00:00Z, the date of the AWS examples.
    const EXAMPLE_SECS: u64 = 1_369_353_600;

    fn signer(token: Option<&str>) -> SigV4 {
        let credentials =
            Credentials::new(ID.into(), SECRET.into(), token.map(Into::into)).unwrap();
        SigV4::new(credentials, "us-east-1").unwrap()
    }

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn get<'a>(authority: &'a str, path: &'a str, query: Option<&'a str>) -> SignRequest<'a> {
        SignRequest {
            method: "GET",
            authority,
            path,
            query,
            payload: SignPayload::Empty,
        }
    }

    fn header<'a>(headers: &'a [(String, String)], name: &str) -> &'a str {
        headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("no {name} header in {headers:?}"))
    }

    fn signature(headers: &[(String, String)]) -> &str {
        header(headers, "Authorization")
            .rsplit_once("Signature=")
            .unwrap()
            .1
    }

    fn uri(path: &str) -> String {
        canonical_uri(path).unwrap()
    }

    fn query(query: Option<&str>) -> String {
        canonical_query(query).unwrap()
    }

    // The vectors below come from the AWS page "Signature Calculations for
    // the Authorization Header: Transferring Payload in a Single Chunk".

    #[test]
    fn the_signing_key_matches_the_aws_example() {
        assert_eq!(
            hex(&signing_key(SECRET, "20130524", "us-east-1")),
            "dbb893acc010964918f1fd433add87c70e8b0db6be30c1fbeafefa5ec6ba8378"
        );
    }

    /// Returns the signature of `creq` with the example key and date.
    fn example_signature(creq: &str) -> String {
        let key = signing_key(SECRET, "20130524", "us-east-1");
        let sts = string_to_sign(
            "20130524T000000Z",
            "20130524/us-east-1/s3/aws4_request",
            creq,
        );
        hex(&hmac_sha256(&key, sts.as_bytes()))
    }

    #[test]
    fn get_object_matches_the_aws_example() {
        let creq = canonical_request(
            "GET",
            &uri("/test.txt"),
            &query(None),
            &[
                ("host", HOST),
                ("range", "bytes=0-9"),
                ("x-amz-content-sha256", EMPTY_SHA256),
                ("x-amz-date", "20130524T000000Z"),
            ],
            EMPTY_SHA256,
        );
        assert_eq!(
            hex(&Sha256::digest(creq.as_bytes())),
            "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"
        );
        assert_eq!(
            example_signature(&creq),
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn put_object_matches_the_aws_example() {
        let body_hash = hex(&Sha256::digest(b"Welcome to Amazon S3."));
        assert_eq!(
            body_hash,
            "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
        );
        let path = uri("/test$file.text");
        assert_eq!(path, "/test%24file.text");
        let creq = canonical_request(
            "PUT",
            &path,
            &query(None),
            &[
                ("date", "Fri, 24 May 2013 00:00:00 GMT"),
                ("host", HOST),
                ("x-amz-content-sha256", &body_hash),
                ("x-amz-date", "20130524T000000Z"),
                ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
            ],
            &body_hash,
        );
        assert_eq!(
            hex(&Sha256::digest(creq.as_bytes())),
            "9e0e90d9c76de8fa5b200d8c849cd5b8dc7a3be3951ddb7f6a76b4158342019d"
        );
        assert_eq!(
            example_signature(&creq),
            "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
        );
    }

    #[test]
    fn get_bucket_lifecycle_matches_the_aws_example() {
        let signed = signer(None)
            .sign_at(&get(HOST, "/", Some("lifecycle")), at(EXAMPLE_SECS))
            .unwrap();
        assert_eq!(
            header(&signed, "Authorization"),
            "AWS4-HMAC-SHA256 \
             Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
             Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"
        );
        assert_eq!(header(&signed, "x-amz-date"), "20130524T000000Z");
        assert_eq!(header(&signed, "x-amz-content-sha256"), EMPTY_SHA256);
        assert_eq!(signed.len(), 3);
    }

    #[test]
    fn list_objects_matches_the_aws_example() {
        let signed = signer(None)
            .sign_at(
                &get(HOST, "/", Some("max-keys=2&prefix=J")),
                at(EXAMPLE_SECS),
            )
            .unwrap();
        assert_eq!(
            signature(&signed),
            "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
        );
        // The order of the parameters on the wire does not change the
        // signature.
        let reversed = signer(None)
            .sign_at(
                &get(HOST, "/", Some("prefix=J&max-keys=2")),
                at(EXAMPLE_SECS),
            )
            .unwrap();
        assert_eq!(signature(&reversed), signature(&signed));
    }

    #[test]
    fn the_canonical_request_of_list_objects_matches_the_aws_example() {
        let creq = canonical_request(
            "GET",
            &uri("/"),
            &query(Some("max-keys=2&prefix=J")),
            &[
                ("host", HOST),
                ("x-amz-content-sha256", EMPTY_SHA256),
                ("x-amz-date", "20130524T000000Z"),
            ],
            EMPTY_SHA256,
        );
        assert_eq!(
            hex(&Sha256::digest(creq.as_bytes())),
            "df57d21db20da04d7fa30298dd4488ba3a2b47ca3a489c74750e0f1e7df1b9b7"
        );
        let lifecycle = canonical_request(
            "GET",
            &uri("/"),
            &query(Some("lifecycle")),
            &[
                ("host", HOST),
                ("x-amz-content-sha256", EMPTY_SHA256),
                ("x-amz-date", "20130524T000000Z"),
            ],
            EMPTY_SHA256,
        );
        assert_eq!(
            hex(&Sha256::digest(lifecycle.as_bytes())),
            "9766c798316ff2757b517bc739a67f6213b4ab36dd5da2f94eaebf79c77395ca"
        );
    }

    #[test]
    fn a_session_token_is_signed_and_sent() {
        // The expected signature was computed with `python3 -I`, `hmac`, and
        // `hashlib` over the canonical request of this test.
        let signed = signer(Some(TOKEN))
            .sign_at(
                &get(HOST, "/", Some("max-keys=2&prefix=J")),
                at(EXAMPLE_SECS),
            )
            .unwrap();
        assert_eq!(header(&signed, "x-amz-security-token"), TOKEN);
        assert_eq!(
            header(&signed, "Authorization"),
            "AWS4-HMAC-SHA256 \
             Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, \
             Signature=9f97f1f05270aa4321dd9c6e8624ca4ceb68938459d93a2c5dbf09a20bcee3fe"
        );
        assert_eq!(signed.len(), 4);
    }

    const TOKEN: &str = "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==";

    #[test]
    fn the_signing_key_is_kept_for_its_date() {
        let sigv4 = signer(None);
        let request = get(HOST, "/", Some("lifecycle"));
        // 2013-05-24T23:59:59Z and 2013-05-25T00:00:00Z.
        let late = at(EXAMPLE_SECS + 86_399);
        let next = at(EXAMPLE_SECS + 86_400);

        let first = sigv4.sign_at(&request, late).unwrap();
        let cached_key = sigv4.key.lock().unwrap().as_ref().map(|k| (k.date, k.key));
        let again = sigv4.sign_at(&request, late).unwrap();
        assert_eq!(first, again);
        assert_eq!(
            sigv4.key.lock().unwrap().as_ref().map(|k| (k.date, k.key)),
            cached_key
        );
        assert_eq!(cached_key.unwrap().0, *b"20130524");

        let after = sigv4.sign_at(&request, next).unwrap();
        assert_eq!(
            sigv4.key.lock().unwrap().as_ref().map(|k| k.date),
            Some(*b"20130525")
        );
        assert!(header(&first, "Authorization").contains("/20130524/us-east-1/s3/"));
        assert!(header(&after, "Authorization").contains("/20130525/us-east-1/s3/"));

        // Each signature equals the signature of a signer with no cached key.
        assert_eq!(signer(None).sign_at(&request, late).unwrap(), first);
        assert_eq!(signer(None).sign_at(&request, next).unwrap(), after);
    }

    #[test]
    fn a_streamed_body_is_refused_with_no_secret() {
        let request = SignRequest {
            payload: SignPayload::Streamed,
            ..get(HOST, "/object", None)
        };
        let err = signer(Some(TOKEN)).sign_at(&request, at(EXAMPLE_SECS));
        let Err(ostrya_fetch::Error::Fetch(msg)) = err else {
            panic!("expected a refusal, got {err:?}");
        };
        assert_eq!(msg, STREAMED);
        assert!(!msg.contains(SECRET) && !msg.contains(TOKEN));
    }

    #[test]
    fn an_empty_body_hashes_as_no_body() {
        let empty = SignRequest {
            method: "PUT",
            payload: SignPayload::Bytes(&[]),
            ..get(HOST, "/object", None)
        };
        let none = SignRequest {
            method: "PUT",
            ..get(HOST, "/object", None)
        };
        let sigv4 = signer(None);
        let empty = sigv4.sign_at(&empty, at(EXAMPLE_SECS)).unwrap();
        assert_eq!(header(&empty, "x-amz-content-sha256"), EMPTY_SHA256);
        assert_eq!(empty, sigv4.sign_at(&none, at(EXAMPLE_SECS)).unwrap());
        assert_eq!(hex(&Sha256::digest(b"")), EMPTY_SHA256);
    }

    #[test]
    fn a_body_given_whole_is_hashed() {
        let request = SignRequest {
            method: "PUT",
            payload: SignPayload::Bytes(b"Welcome to Amazon S3."),
            ..get(HOST, "/test$file.text", None)
        };
        let signed = signer(None).sign_at(&request, at(EXAMPLE_SECS)).unwrap();
        assert_eq!(
            header(&signed, "x-amz-content-sha256"),
            "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
        );
    }

    #[test]
    fn the_canonical_uri_decodes_and_encodes_each_byte() {
        let cases = [
            ("+", "/%2B"),
            ("%2B", "/%2B"),
            ("%2b", "/%2B"),
            ("_~-.", "/_~-."),
            ("%7e", "/~"),
            ("a b", "/a%20b"),
            ("a%20b", "/a%20b"),
            ("$", "/%24"),
            ("caf%C3%A9", "/caf%C3%A9"),
            ("café", "/caf%C3%A9"),
            ("%FF", "/%FF"),
            (
                "deltas/Ab/Cd+e_f-superblock",
                "/deltas/Ab/Cd%2Be_f-superblock",
            ),
        ];
        for (path, want) in cases {
            assert_eq!(uri(&format!("/{path}")), want, "{path}");
        }
        assert_eq!(uri("//a/./b/../c"), "//a/./b/../c");
        assert_eq!(uri(""), "/");
        for bad in ["/%", "/%4", "/%zz", "/a%g0"] {
            let err = canonical_uri(bad).unwrap_err();
            assert!(
                matches!(&err, ostrya_fetch::Error::Fetch(msg) if msg.contains("malformed")),
                "{bad}: {err:?}"
            );
        }
    }

    #[test]
    fn the_canonical_query_sorts_and_encodes_each_parameter() {
        assert_eq!(query(Some("uploads")), "uploads=");
        assert_eq!(
            query(Some("uploadId=ID&partNumber=1")),
            "partNumber=1&uploadId=ID"
        );
        assert_eq!(
            query(Some("prefix=repo/objects/00/")),
            "prefix=repo%2Fobjects%2F00%2F"
        );
        assert_eq!(
            query(Some("prefix=repo%2Fobjects%2F00%2F")),
            "prefix=repo%2Fobjects%2F00%2F"
        );
        assert_eq!(query(Some("a=2&a=1&a=10")), "a=1&a=10&a=2");
        assert_eq!(query(Some("a=x%2By&b=%2b")), "a=x%2By&b=%2B");
        assert_eq!(query(Some("k=v=w")), "k=v%3Dw");
        assert_eq!(query(Some("")), "");
        assert_eq!(query(None), "");
        assert_eq!(query(Some("a&&b")), "a=&b=");
        for bad in ["a=%", "a%zz=1", "a=%4"] {
            assert!(canonical_query(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_raw_plus_in_the_query_is_refused() {
        for bad in ["a+b=1", "a=x+y", "a=1&b=+", "+"] {
            let err = signer(None)
                .sign_at(&get(HOST, "/", Some(bad)), at(EXAMPLE_SECS))
                .unwrap_err();
            assert!(
                matches!(&err, ostrya_fetch::Error::Fetch(msg) if msg.contains("'+'")),
                "{bad}: {err:?}"
            );
        }
    }

    #[test]
    fn an_escaped_plus_in_the_query_is_signed_as_2b() {
        assert_eq!(query(Some("a%2Bb=x%2By")), "a%2Bb=x%2By");
        assert_eq!(query(Some("a%2bb=x%2by")), "a%2Bb=x%2By");
        let sigv4 = signer(None);
        let upper = sigv4
            .sign_at(&get(HOST, "/", Some("a=x%2By")), at(EXAMPLE_SECS))
            .unwrap();
        let lower = sigv4
            .sign_at(&get(HOST, "/", Some("a=x%2by")), at(EXAMPLE_SECS))
            .unwrap();
        assert_eq!(upper, lower);
        let creq = canonical_request(
            "GET",
            "/",
            "a=x%2By",
            &[
                ("host", HOST),
                ("x-amz-content-sha256", EMPTY_SHA256),
                ("x-amz-date", "20130524T000000Z"),
            ],
            EMPTY_SHA256,
        );
        assert_eq!(signature(&upper), example_signature(&creq));
    }

    #[test]
    fn a_raw_plus_in_the_path_is_signed_as_2b() {
        let sigv4 = signer(None);
        let raw = sigv4
            .sign_at(&get(HOST, "/a+b", None), at(EXAMPLE_SECS))
            .unwrap();
        let escaped = sigv4
            .sign_at(&get(HOST, "/a%2Bb", None), at(EXAMPLE_SECS))
            .unwrap();
        assert_eq!(raw, escaped);
        assert_eq!(uri("/a+b"), "/a%2Bb");
    }

    #[test]
    fn a_refusal_of_the_query_holds_no_query_text() {
        for bad in [
            "X-Amz-Signature=SECRETVALUE&a=%zz",
            "token=SECRETVALUE%4",
            "token=SECRETVALUE+x",
            "SECRETVALUE+x=1",
        ] {
            let err = signer(None)
                .sign_at(&get(HOST, "/", Some(bad)), at(EXAMPLE_SECS))
                .unwrap_err();
            let ostrya_fetch::Error::Fetch(msg) = &err else {
                panic!("{bad}: expected a refusal, got {err:?}");
            };
            assert!(!msg.contains("SECRETVALUE"), "{bad}: {msg}");
        }
    }

    #[test]
    fn amz_date_is_the_utc_time() {
        let cases = [
            (0, "19700101T000000Z"),
            (951_868_799, "20000229T235959Z"),
            (EXAMPLE_SECS, "20130524T000000Z"),
            (4_107_542_400, "21000301T000000Z"),
        ];
        for (secs, want) in cases {
            assert_eq!(amz_date(at(secs)).unwrap(), want, "{secs}");
        }
        let before = UNIX_EPOCH - Duration::from_secs(1);
        let err = amz_date(before).unwrap_err();
        assert!(
            matches!(&err, ostrya_fetch::Error::Fetch(msg) if msg.contains("clock")),
            "{err:?}"
        );
    }

    #[test]
    fn the_authority_is_signed_as_given() {
        for authority in ["127.0.0.1:9000", "[::1]:9000"] {
            let request = get(authority, "/", None);
            let signed = signer(None).sign_at(&request, at(EXAMPLE_SECS)).unwrap();
            let creq = canonical_request(
                "GET",
                "/",
                "",
                &[
                    ("host", authority),
                    ("x-amz-content-sha256", EMPTY_SHA256),
                    ("x-amz-date", "20130524T000000Z"),
                ],
                EMPTY_SHA256,
            );
            assert!(creq.contains(&format!("\nhost:{authority}\n")));
            assert_eq!(signature(&signed), example_signature(&creq));
        }
    }

    #[test]
    fn new_refuses_an_invalid_region() {
        let credentials = Credentials::new(ID.into(), SECRET.into(), None).unwrap();
        for region in ["", "us/east", "us east", &"a".repeat(64)] {
            let err = SigV4::new(credentials.clone(), region).unwrap_err();
            assert!(matches!(err, Error::InvalidInput(_)), "{region}: {err:?}");
        }
        let sigv4 = SigV4::new(credentials, &"a".repeat(63)).unwrap();
        assert_eq!(sigv4.region().len(), 63);
        SigV4::new(
            Credentials::new(ID.into(), SECRET.into(), None).unwrap(),
            "eu-central_1.x",
        )
        .unwrap();
    }

    #[test]
    fn debug_hides_the_secret_and_the_token() {
        let sigv4 = signer(Some(TOKEN));
        sigv4
            .sign_at(&get(HOST, "/", None), at(EXAMPLE_SECS))
            .unwrap();
        let debug = format!("{sigv4:?}");
        assert!(debug.contains("us-east-1") && debug.contains(ID), "{debug}");
        assert!(!debug.contains(SECRET) && !debug.contains(TOKEN), "{debug}");
    }
}
