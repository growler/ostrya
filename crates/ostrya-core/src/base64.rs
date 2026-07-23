//! General standard-alphabet base64 for arbitrary-length byte strings.
//!
//! The [`Checksum`](crate::Checksum) codec is fixed to 32-byte digests; sign-api
//! keys and signature blobs are arbitrary-length, so this module carries a
//! standard-alphabet (RFC 4648) encoder and decoder over any byte string. The
//! spki engine reuses it to decode PEM key bodies.

use crate::error::{Error, Result};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode `input` as standard, padded base64.
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        match chunk.len() {
            1 => {
                out.push(ALPHABET[((b0 & 0x03) << 4) as usize] as char);
                out.push_str("==");
            }
            2 => {
                let b1 = chunk[1];
                out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
                out.push(ALPHABET[((b1 & 0x0f) << 2) as usize] as char);
                out.push('=');
            }
            _ => {
                let (b1, b2) = (chunk[1], chunk[2]);
                out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
                out.push(ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
                out.push(ALPHABET[(b2 & 0x3f) as usize] as char);
            }
        }
    }
    out
}

/// Decode standard base64. Trailing `=` padding is optional; every other
/// character must be in the alphabet, and a group of one leftover character is
/// rejected as truncated.
pub fn decode(s: &str) -> Result<Vec<u8>> {
    let bytes = s.trim_end_matches('=').as_bytes();
    let full = bytes.len() / 4;
    let rem = bytes.len() % 4;
    if rem == 1 {
        return Err(Error::InvalidBase64("truncated base64 group"));
    }
    let mut out = Vec::with_capacity(full * 3 + rem.saturating_sub(1));
    let mut i = 0;
    for _ in 0..full {
        let s0 = val(bytes[i])?;
        let s1 = val(bytes[i + 1])?;
        let s2 = val(bytes[i + 2])?;
        let s3 = val(bytes[i + 3])?;
        out.push((s0 << 2) | (s1 >> 4));
        out.push((s1 << 4) | (s2 >> 2));
        out.push((s2 << 6) | s3);
        i += 4;
    }
    match rem {
        2 => {
            let s0 = val(bytes[i])?;
            let s1 = val(bytes[i + 1])?;
            out.push((s0 << 2) | (s1 >> 4));
        }
        3 => {
            let s0 = val(bytes[i])?;
            let s1 = val(bytes[i + 1])?;
            let s2 = val(bytes[i + 2])?;
            out.push((s0 << 2) | (s1 >> 4));
            out.push((s1 << 4) | (s2 >> 2));
        }
        _ => {}
    }
    Ok(out)
}

/// Map one base64 character to its 6-bit value.
fn val(c: u8) -> Result<u8> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(Error::InvalidBase64("invalid base64 character")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        // The RFC 4648 section 10 test vectors.
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn decode_matches_encode() {
        for input in [
            b"".as_slice(),
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
        ] {
            let encoded = encode(input);
            assert_eq!(decode(&encoded).unwrap(), input);
        }
    }

    #[test]
    fn decode_accepts_unpadded() {
        assert_eq!(decode("Zg").unwrap(), b"f");
        assert_eq!(decode("Zm8").unwrap(), b"fo");
        assert_eq!(decode("Zm9vYg").unwrap(), b"foob");
    }

    #[test]
    fn decode_round_trips_binary() {
        let data: Vec<u8> = (0u16..=255).map(|b| b as u8).collect();
        assert_eq!(decode(&encode(&data)).unwrap(), data);
    }

    #[test]
    fn decode_rejects_bad_input() {
        assert!(decode("Z").is_err()); // one leftover character
        assert!(decode("Zg=Z").is_err()); // stray character after padding strip
        assert!(decode("Zm9 v").is_err()); // internal whitespace
        assert!(decode("Zm9_").is_err()); // modified-alphabet glyph rejected
    }
}
