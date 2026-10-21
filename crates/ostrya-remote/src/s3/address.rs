//! The address of a bucket repository: `s3://BUCKET[/PREFIX]`.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use crate::{Error, Result};

/// The scheme of an S3 address.
const SCHEME: &str = "s3://";

/// The address of a bucket repository: a bucket and a key prefix.
///
/// The form is `s3://BUCKET[/PREFIX]`.
///
/// - `BUCKET` is 3 to 63 characters: lowercase ASCII letters, digits, `.`,
///   and `-`. It starts and ends with a letter or a digit. It holds no `..`,
///   and it is not four decimal numbers that `.` separates, as an IPv4
///   address is.
/// - `PREFIX` is one or more segments that `/` separates. Each segment is
///   not empty, is not `.` or `..`, and holds the characters `A-Z`, `a-z`,
///   `0-9`, `-`, `.`, `_`, and `~` alone. One trailing `/` is dropped.
/// - The address holds no userinfo, no port, no query, and no fragment.
///
/// The keys of the repository start with `PREFIX/`. With no prefix, they
/// start at the root of the bucket and have no leading `/`.
///
/// The [`Display`](fmt::Display) output is the canonical form, with no
/// trailing `/`.
///
/// # Examples
///
/// ```
/// use ostrya_remote::s3::Address;
/// # fn main() -> ostrya_remote::Result<()> {
/// let address = Address::parse("s3://builds/exampleos/")?;
/// assert_eq!(address.bucket(), "builds");
/// assert_eq!(address.prefix(), "exampleos");
/// assert_eq!(address.to_string(), "s3://builds/exampleos");
/// assert!(Address::parse("s3://Builds").is_err());
/// # Ok(()) }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Address {
    bucket: String,
    prefix: String,
}

impl Address {
    /// Parses `address` in the form `s3://BUCKET[/PREFIX]`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInput`] if `address` does not have the form that
    /// [`Address`] states. The message names the part that is refused. It
    /// holds no userinfo.
    pub fn parse(address: &str) -> Result<Address> {
        let rest = address
            .strip_prefix(SCHEME)
            .ok_or_else(|| refused("an S3 address starts with s3://, in lowercase".to_owned()))?;
        // Each of these characters is outside the alphabet of a bucket and
        // of a prefix. The message names the part that the character starts.
        for (found, part) in [
            ('@', "userinfo"),
            (':', "a port"),
            ('?', "a query"),
            ('#', "a fragment"),
        ] {
            if rest.contains(found) {
                return Err(refused(format!(
                    "an S3 address holds no {part}, and this one holds '{found}'"
                )));
            }
        }
        let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
        check_bucket(bucket)?;
        let prefix = prefix.strip_suffix('/').unwrap_or(prefix);
        if !prefix.is_empty() {
            for segment in prefix.split('/') {
                check_segment(segment)?;
            }
        }
        Ok(Address {
            bucket: bucket.to_owned(),
            prefix: prefix.to_owned(),
        })
    }

    /// Returns the name of the bucket.
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// Returns the prefix of the keys, with no leading `/` and no trailing
    /// `/`. It is empty for an address with no prefix.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{SCHEME}{}", self.bucket)?;
        if !self.prefix.is_empty() {
            write!(f, "/{}", self.prefix)?;
        }
        Ok(())
    }
}

impl FromStr for Address {
    type Err = Error;

    fn from_str(address: &str) -> Result<Address> {
        Address::parse(address)
    }
}

/// Returns the refusal of an address with `why`.
fn refused(why: String) -> Error {
    Error::InvalidInput(format!("S3 address: {why}"))
}

/// Checks the name of a bucket.
fn check_bucket(bucket: &str) -> Result<()> {
    if !(3..=63).contains(&bucket.len()) {
        return Err(refused(format!(
            "the bucket name {bucket:?} is not 3 to 63 characters long"
        )));
    }
    if !bucket
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
    {
        return Err(refused(format!(
            "the bucket name {bucket:?} holds a character other than a lowercase letter, a \
             digit, '.', or '-'"
        )));
    }
    let edge = |b: Option<&u8>| b.is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    if !edge(bucket.as_bytes().first()) || !edge(bucket.as_bytes().last()) {
        return Err(refused(format!(
            "the bucket name {bucket:?} does not start and end with a letter or a digit"
        )));
    }
    if bucket.contains("..") {
        return Err(refused(format!("the bucket name {bucket:?} holds '..'")));
    }
    if bucket.parse::<Ipv4Addr>().is_ok() {
        return Err(refused(format!(
            "the bucket name {bucket:?} has the form of an IPv4 address"
        )));
    }
    Ok(())
}

/// Checks one segment of a prefix.
fn check_segment(segment: &str) -> Result<()> {
    if segment.is_empty() {
        return Err(refused("the prefix holds an empty segment".to_owned()));
    }
    if segment == "." || segment == ".." {
        return Err(refused(format!("the prefix holds the segment {segment:?}")));
    }
    if !segment
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(refused(format!(
            "the prefix segment {segment:?} holds a character other than A-Z, a-z, 0-9, '-', \
             '.', '_', or '~'"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(address: &str) -> (String, String) {
        let address = Address::parse(address).unwrap_or_else(|e| panic!("{address}: {e}"));
        (address.bucket().to_owned(), address.prefix().to_owned())
    }

    fn refusal(address: &str) -> String {
        match Address::parse(address) {
            Ok(parsed) => panic!("{address} parsed as {parsed:?}"),
            Err(Error::InvalidInput(message)) => message,
            Err(other) => panic!("{address}: {other}"),
        }
    }

    #[test]
    fn an_address_gives_its_bucket_and_prefix() {
        let cases = [
            ("s3://abc", "abc", ""),
            ("s3://abc/", "abc", ""),
            ("s3://a.b-c/p", "a.b-c", "p"),
            ("s3://bucket/a/b/c/", "bucket", "a/b/c"),
            ("s3://bucket/A-z_0.9~", "bucket", "A-z_0.9~"),
            ("s3://0bucket9", "0bucket9", ""),
            (
                "s3://a23456789012345678901234567890123456789012345678901234567890123",
                "a23456789012345678901234567890123456789012345678901234567890123",
                "",
            ),
        ];
        for (address, bucket, prefix) in cases {
            assert_eq!(parts(address), (bucket.into(), prefix.into()), "{address}");
        }
    }

    #[test]
    fn a_bucket_name_out_of_the_rule_is_refused() {
        for address in [
            "s3://ab",
            "s3://a234567890123456789012345678901234567890123456789012345678901234",
            "s3://Bucket",
            "s3://buck_et",
            "s3://-bucket",
            "s3://bucket-",
            "s3://.bucket",
            "s3://bucket.",
            "s3://buc..ket",
            "s3://192.168.1.10",
            "s3://",
            "s3:///prefix",
        ] {
            assert!(refusal(address).contains("bucket name"), "{address}");
        }
    }

    #[test]
    fn a_prefix_out_of_the_rule_is_refused() {
        for address in [
            "s3://bucket//p",
            "s3://bucket/p//q",
            "s3://bucket/p/./q",
            "s3://bucket/..",
            "s3://bucket/p q",
            "s3://bucket/p+q",
            "s3://bucket/p%41",
            "s3://bucket/ü",
            "s3://bucket/p//",
        ] {
            assert!(refusal(address).contains("prefix"), "{address}");
        }
    }

    #[test]
    fn userinfo_a_port_a_query_and_a_fragment_are_refused_by_name() {
        let cases = [
            ("s3://key:secret@bucket/p", "userinfo"),
            ("s3://bucket:9000/p", "a port"),
            ("s3://bucket/p?x=1", "a query"),
            ("s3://bucket/p#f", "a fragment"),
        ];
        for (address, part) in cases {
            let message = refusal(address);
            assert!(message.contains(part), "{address}: {message}");
            assert!(!message.contains("secret"), "{message}");
        }
    }

    #[test]
    fn another_scheme_is_refused() {
        for address in ["S3://bucket", "s3:/bucket", "https://bucket", "bucket/p"] {
            assert!(refusal(address).contains("s3://"), "{address}");
        }
    }

    #[test]
    fn the_display_is_the_canonical_form() {
        for (address, shown) in [
            ("s3://bucket", "s3://bucket"),
            ("s3://bucket/", "s3://bucket"),
            ("s3://bucket/a/b/", "s3://bucket/a/b"),
        ] {
            let parsed = Address::parse(address).unwrap();
            assert_eq!(parsed.to_string(), shown);
            assert_eq!(shown.parse::<Address>().unwrap(), parsed);
        }
    }
}
