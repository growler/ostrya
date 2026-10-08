//! The 32-byte SHA-256 object checksum and its forms.
//!
//! The hex, standard base64, and modified base64 codecs are hand-written to
//! the RFC 4648 alphabet. The `sha2` crate computes the digest.

use ostrya_gvariant::{GvEncode, GvType};

use crate::error::{Error, Result};

/// A 32-byte SHA-256 checksum that names an object.
///
/// # Forms
///
/// A checksum has these forms:
///
/// - 64 lowercase hex characters, in refs, loose paths, and object names. See
///   [`to_hex`](Checksum::to_hex) and [`from_hex`](Checksum::from_hex).
/// - The raw 32-byte `ay`, inside commit and dirtree objects. See
///   [`as_bytes`](Checksum::as_bytes) and [`from_ay`](Checksum::from_ay).
/// - Modified base64, in static-delta directory names. See
///   [`to_base64_modified`](Checksum::to_base64_modified) and
///   [`from_base64_modified`](Checksum::from_base64_modified).
/// - Standard padded base64. See [`to_base64`](Checksum::to_base64) and
///   [`from_base64`](Checksum::from_base64).
///
/// # Order
///
/// `Checksum` values compare byte-wise. The byte order equals the order of
/// the lowercase hex strings. A sort of `Checksum` values gives the ASCII
/// checksum order of the on-disk format, for example the order of the
/// `ostree.sizes` entries.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Checksum([u8; 32]);

const STD_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const MOD_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+_";

impl Checksum {
    /// Creates a checksum from the raw digest bytes.
    pub fn from_bytes(b: [u8; 32]) -> Checksum {
        Checksum(b)
    }

    /// Returns the SHA-256 digest of `data`.
    ///
    /// This digest is the checksum of a metadata object, where `data` is the
    /// serialized GVariant form of the object.
    pub fn sha256(data: &[u8]) -> Checksum {
        use sha2::{Digest, Sha256};
        Checksum(Sha256::digest(data).into())
    }

    /// Returns the raw digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parses 64 lowercase hex characters.
    ///
    /// This is the form that [`to_hex`](Checksum::to_hex) writes. The rule
    /// applies to a revision: a name of 64 characters is a checksum only if
    /// it is lowercase hex. An uppercase or mixed-case name of that length is
    /// a ref name.
    ///
    /// For a checksum from stored bytes, [`from_hex`](Checksum::from_hex) is
    /// the parser. It accepts both cases.
    ///
    /// # Errors
    ///
    /// The function returns [`Error::InvalidChecksum`] with one of these
    /// messages:
    ///
    /// - `hex checksum is not lowercase` if `s` holds an uppercase character.
    ///   This check comes first.
    /// - `hex checksum is not 64 characters` if `s` is not 64 bytes long.
    /// - `hex checksum has a non-hex character` if a character is not in
    ///   `0-9` or `a-f`.
    pub fn from_hex_lower(s: &str) -> Result<Checksum> {
        if s.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(Error::InvalidChecksum("hex checksum is not lowercase"));
        }
        Checksum::from_hex(s)
    }

    /// Parses 64 hex characters in uppercase, lowercase, or mixed case.
    ///
    /// [`to_hex`](Checksum::to_hex) writes the result in lowercase.
    ///
    /// # Errors
    ///
    /// The function returns [`Error::InvalidChecksum`] with one of these
    /// messages:
    ///
    /// - `hex checksum is not 64 characters` if `s` is not 64 bytes long.
    /// - `hex checksum has a non-hex character` if a character is not in
    ///   `0-9`, `a-f`, or `A-F`.
    pub fn from_hex(s: &str) -> Result<Checksum> {
        let bytes = s.as_bytes();
        if bytes.len() != 64 {
            return Err(Error::InvalidChecksum("hex checksum is not 64 characters"));
        }
        let mut out = [0u8; 32];
        for (i, pair) in bytes.chunks_exact(2).enumerate() {
            let hi = hex_val(pair[0])?;
            let lo = hex_val(pair[1])?;
            out[i] = (hi << 4) | lo;
        }
        Ok(Checksum(out))
    }

    /// Returns the checksum as 64 lowercase hex characters.
    pub fn to_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(64);
        for &b in &self.0 {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0x0f) as usize] as char);
        }
        s
    }

    /// Creates a checksum from the payload of a GVariant `ay` value.
    ///
    /// # Errors
    ///
    /// The function returns [`Error::InvalidChecksum`] with the message
    /// `ay checksum is not 32 bytes` if `b` is not exactly 32 bytes long.
    pub fn from_ay(b: &[u8]) -> Result<Checksum> {
        let arr: [u8; 32] = b
            .try_into()
            .map_err(|_| Error::InvalidChecksum("ay checksum is not 32 bytes"))?;
        Ok(Checksum(arr))
    }

    /// Returns the checksum as standard padded base64 of 44 characters.
    ///
    /// The string holds 43 data characters and one `=` pad.
    pub fn to_base64(&self) -> String {
        base64_encode(&self.0, STD_ALPHABET, true)
    }

    /// Parses standard padded base64 of exactly 44 characters.
    ///
    /// The string must hold 43 data characters and one `=` pad. Each checksum
    /// has exactly one accepted spelling.
    ///
    /// # Errors
    ///
    /// The function returns [`Error::InvalidChecksum`] with one of these
    /// messages:
    ///
    /// - `base64 checksum has the wrong length` if `s` is not 44 bytes long.
    /// - `base64 checksum is missing its pad` if the last character is not
    ///   `=`.
    /// - `base64 has an invalid character` if a data character is not in the
    ///   standard alphabet. The modified character `_` is not in this
    ///   alphabet.
    /// - `base64 checksum has nonzero trailing bits` if the two unused low
    ///   bits of the last data character are not zero.
    pub fn from_base64(s: &str) -> Result<Checksum> {
        Ok(Checksum(base64_decode_checksum(s, STD_ALPHABET, true)?))
    }

    /// Returns the checksum as modified base64 of 43 characters.
    ///
    /// Modified base64 is standard base64 with `_` in the place of `/` and
    /// with no trailing `=`.
    pub fn to_base64_modified(&self) -> String {
        base64_encode(&self.0, MOD_ALPHABET, false)
    }

    /// Parses modified base64 of exactly 43 characters with no pad.
    ///
    /// Each checksum has exactly one accepted spelling.
    ///
    /// # Errors
    ///
    /// The function returns [`Error::InvalidChecksum`] with one of these
    /// messages:
    ///
    /// - `base64 checksum has the wrong length` if `s` is not 43 bytes long.
    ///   A stray trailing `=` makes the string 44 bytes long.
    /// - `base64 has an invalid character` if a character is not in the
    ///   modified alphabet. The standard character `/` and the pad `=` are
    ///   not in this alphabet.
    /// - `base64 checksum has nonzero trailing bits` if the two unused low
    ///   bits of the last character are not zero.
    pub fn from_base64_modified(s: &str) -> Result<Checksum> {
        Ok(Checksum(base64_decode_checksum(s, MOD_ALPHABET, false)?))
    }
}

fn hex_val(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(Error::InvalidChecksum(
            "hex checksum has a non-hex character",
        )),
    }
}

fn base64_encode(input: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        out.push(alphabet[(b0 >> 2) as usize] as char);
        match chunk.len() {
            1 => {
                out.push(alphabet[((b0 & 0x03) << 4) as usize] as char);
                if pad {
                    out.push_str("==");
                }
            }
            2 => {
                let b1 = chunk[1];
                out.push(alphabet[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
                out.push(alphabet[((b1 & 0x0f) << 2) as usize] as char);
                if pad {
                    out.push('=');
                }
            }
            _ => {
                let (b1, b2) = (chunk[1], chunk[2]);
                out.push(alphabet[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
                out.push(alphabet[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
                out.push(alphabet[(b2 & 0x3f) as usize] as char);
            }
        }
    }
    out
}

/// Decodes exactly one 32-byte checksum, with the sextets read from `alphabet`.
///
/// A 32-byte digest is 43 significant base64 characters: ten groups of 4
/// characters (30 bytes) and then one group of 3 characters (2 bytes). The
/// standard form adds one `=` pad, for a total of 44 characters. The modified
/// form is the 43 characters alone.
///
/// The decoder is strict, so each checksum has exactly one accepted spelling:
///
/// - The length must be exact.
/// - Each character must be in `alphabet`, so the standard `/` and the
///   modified `_` do not alias.
/// - The two unused low bits of the last significant sextet must be zero.
fn base64_decode_checksum(s: &str, alphabet: &[u8; 64], padded: bool) -> Result<[u8; 32]> {
    let bytes = s.as_bytes();
    let expected = if padded { 44 } else { 43 };
    if bytes.len() != expected {
        return Err(Error::InvalidChecksum(
            "base64 checksum has the wrong length",
        ));
    }
    if padded && bytes[43] != b'=' {
        return Err(Error::InvalidChecksum("base64 checksum is missing its pad"));
    }
    let data = &bytes[..43];
    let mut out = [0u8; 32];
    for (group, chunk) in data[..40].chunks_exact(4).enumerate() {
        let s0 = base64_val(chunk[0], alphabet)?;
        let s1 = base64_val(chunk[1], alphabet)?;
        let s2 = base64_val(chunk[2], alphabet)?;
        let s3 = base64_val(chunk[3], alphabet)?;
        out[group * 3] = (s0 << 2) | (s1 >> 4);
        out[group * 3 + 1] = (s1 << 4) | (s2 >> 2);
        out[group * 3 + 2] = (s2 << 6) | s3;
    }
    let s0 = base64_val(data[40], alphabet)?;
    let s1 = base64_val(data[41], alphabet)?;
    let s2 = base64_val(data[42], alphabet)?;
    if s2 & 0x03 != 0 {
        return Err(Error::InvalidChecksum(
            "base64 checksum has nonzero trailing bits",
        ));
    }
    out[30] = (s0 << 2) | (s1 >> 4);
    out[31] = (s1 << 4) | (s2 >> 2);
    Ok(out)
}

fn base64_val(c: u8, alphabet: &[u8; 64]) -> Result<u8> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'+' => Ok(62),
        // Index 63 is the only character that differs between the alphabets:
        // `/` in the standard alphabet, `_` in the modified alphabet. Accept
        // the character of `alphabet` and refuse the other one.
        _ if c == alphabet[63] => Ok(63),
        _ => Err(Error::InvalidChecksum("base64 has an invalid character")),
    }
}

impl std::fmt::Display for Checksum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl std::fmt::Debug for Checksum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Checksum({})", self.to_hex())
    }
}

impl std::str::FromStr for Checksum {
    type Err = Error;
    fn from_str(s: &str) -> Result<Checksum> {
        Checksum::from_hex(s)
    }
}

impl GvType for Checksum {
    const SIGNATURE: &'static str = "ay";
    const ALIGNMENT: usize = 1;
    const FIXED_SIZE: Option<usize> = None;
}

/// Encodes the checksum as its raw 32 bytes, the GVariant `ay` form.
///
/// [`Checksum::from_ay`] decodes this form.
// There is no `GvDecode` impl. `from_ay` returns `Error::InvalidChecksum` if
// the width is wrong, and the decoder path goes through it.
impl GvEncode for Checksum {
    fn encode(&self, out: &mut Vec<u8>) -> ostrya_gvariant::Result<()> {
        out.extend_from_slice(&self.0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The commit checksum that the fixture generator recorded in
    // tests/fixtures/generated/MANIFEST.
    const FIXTURE_COMMIT: &str = "b3c8e8525e8a5c3409bf6e6db5f5d656da77ae76d08cbc4f8b75b71879757a89";

    #[test]
    fn hex_round_trips_and_is_lowercase() {
        let c = Checksum::from_hex(FIXTURE_COMMIT).unwrap();
        assert_eq!(c.to_hex(), FIXTURE_COMMIT);
        // Uppercase input parses to the same value.
        let upper = Checksum::from_hex(&FIXTURE_COMMIT.to_uppercase()).unwrap();
        assert_eq!(upper, c);
    }

    #[test]
    fn hex_rejects_bad_length_and_characters() {
        assert!(Checksum::from_hex("abcd").is_err());
        assert!(Checksum::from_hex(&"g".repeat(64)).is_err());
    }

    #[test]
    fn lowercase_hex_refuses_an_uppercase_character() {
        let c = Checksum::from_hex_lower(FIXTURE_COMMIT).unwrap();
        assert_eq!(c.to_hex(), FIXTURE_COMMIT);
        assert!(Checksum::from_hex_lower(&FIXTURE_COMMIT.to_uppercase()).is_err());
        // One uppercase character is enough, and the length rule still holds.
        let mixed = format!("B{}", &FIXTURE_COMMIT[1..]);
        assert!(Checksum::from_hex_lower(&mixed).is_err());
        assert!(Checksum::from_hex_lower("abcd").is_err());
    }

    #[test]
    fn ay_conversion_validates_length() {
        let c = Checksum::from_hex(FIXTURE_COMMIT).unwrap();
        assert_eq!(Checksum::from_ay(c.as_bytes()).unwrap(), c);
        assert!(Checksum::from_ay(&[0u8; 31]).is_err());
        assert!(Checksum::from_ay(&[0u8; 33]).is_err());
    }

    #[test]
    fn base64_reference_vectors() {
        // 32 zero bytes: 43 'A' sextets, one '=' pad under standard base64.
        let zero = Checksum::from_bytes([0u8; 32]);
        assert_eq!(zero.to_base64_modified(), "A".repeat(43));
        assert_eq!(zero.to_base64(), format!("{}=", "A".repeat(43)));

        // 32 0xff bytes test the high sextets and the '_' for '/' swap.
        // Ten full 0xffffff groups give index-63 sextets ('_' modified, '/'
        // standard). The last two bytes give '_' '_' '8'.
        let ones = Checksum::from_bytes([0xffu8; 32]);
        assert_eq!(ones.to_base64_modified(), format!("{}8", "_".repeat(42)));
        assert_eq!(ones.to_base64(), format!("{}8=", "/".repeat(42)));
        // The two alphabets differ only in the index-63 glyph.
        assert_eq!(
            ones.to_base64_modified(),
            ones.to_base64().trim_end_matches('=').replace('/', "_")
        );
    }

    #[test]
    fn base64_round_trips_both_alphabets() {
        let c = Checksum::from_hex(FIXTURE_COMMIT).unwrap();
        assert_eq!(Checksum::from_base64(&c.to_base64()).unwrap(), c);
        assert_eq!(
            Checksum::from_base64_modified(&c.to_base64_modified()).unwrap(),
            c
        );
        assert_eq!(c.to_base64_modified().len(), 43);
        assert_eq!(c.to_base64().len(), 44);
    }

    // A spread of checksums for the strict-decoding round-trip checks.
    fn sample_checksums() -> Vec<Checksum> {
        let mut v = vec![
            Checksum::from_bytes([0u8; 32]),
            Checksum::from_bytes([0xffu8; 32]),
            Checksum::from_hex(FIXTURE_COMMIT).unwrap(),
        ];
        // A few deterministic byte patterns exercise varied final sextets.
        for seed in [1u8, 7, 31, 63, 128, 200, 254] {
            let mut b = [0u8; 32];
            for (i, x) in b.iter_mut().enumerate() {
                *x = seed.wrapping_mul(i as u8).wrapping_add(seed);
            }
            v.push(Checksum::from_bytes(b));
        }
        v
    }

    #[test]
    fn base64_parse_then_render_is_identity_for_accepted_strings() {
        for c in sample_checksums() {
            let std = c.to_base64();
            assert_eq!(Checksum::from_base64(&std).unwrap().to_base64(), std);
            let modified = c.to_base64_modified();
            assert_eq!(
                Checksum::from_base64_modified(&modified)
                    .unwrap()
                    .to_base64_modified(),
                modified
            );
        }
    }

    #[test]
    fn base64_rejects_cross_alphabet_glyphs() {
        // The modified rendering of all-ones carries '_', invalid in standard.
        let modified = Checksum::from_bytes([0xffu8; 32]).to_base64_modified();
        assert!(modified.contains('_'));
        assert!(Checksum::from_base64(&modified).is_err());
        // The standard form holds '/', which is not in the modified alphabet.
        // Trim its pad first, so that the test covers only the alphabet.
        let std = Checksum::from_bytes([0xffu8; 32]).to_base64();
        assert!(std.contains('/'));
        assert!(Checksum::from_base64_modified(std.trim_end_matches('=')).is_err());
    }

    #[test]
    fn base64_rejects_nonzero_trailing_bits() {
        // The last significant sextet of a 32-byte checksum has two unused low
        // bits. The parsers must refuse a character that sets them ('9' is
        // sextet 61).
        let mut modified = Checksum::from_bytes([0xffu8; 32]).to_base64_modified();
        modified.pop();
        modified.push('9');
        assert!(Checksum::from_base64_modified(&modified).is_err());

        let mut std = Checksum::from_bytes([0u8; 32]).to_base64();
        // Replace the last data character (index 42), before the '=' pad.
        std.replace_range(42..43, "9");
        assert!(Checksum::from_base64(&std).is_err());
    }

    #[test]
    fn base64_rejects_wrong_length_and_stray_padding() {
        let c = Checksum::from_hex(FIXTURE_COMMIT).unwrap();
        // The standard form requires one trailing pad. The parser refuses the
        // unpadded form of 43 characters and a double-padded form of 45.
        assert!(Checksum::from_base64(c.to_base64().trim_end_matches('=')).is_err());
        assert!(Checksum::from_base64(&format!("{}=", c.to_base64())).is_err());
        // The modified form takes exactly 43 characters with no pad. The
        // parser refuses a stray pad and a padded string of standard length.
        assert!(Checksum::from_base64_modified(&format!("{}=", c.to_base64_modified())).is_err());
        assert!(Checksum::from_base64_modified(&c.to_base64()).is_err());
    }

    #[test]
    fn sha256_matches_the_empty_input_vector() {
        // The well-known SHA-256 digest of the empty input.
        assert_eq!(
            Checksum::sha256(b"").to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn ordering_matches_hex_ordering() {
        let a = Checksum::from_hex(&"00".repeat(32)).unwrap();
        let b = Checksum::from_hex(&"ff".repeat(32)).unwrap();
        assert!(a < b);
        assert!(a.to_hex() < b.to_hex());
    }
}
