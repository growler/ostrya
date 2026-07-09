//! Protobuf-style LEB128 varints.
//!
//! Little-endian base-128: each byte carries seven value bits, and the high
//! bit is the continuation flag. This is the encoding used for the sizes in
//! `ostree.sizes` packed entries and for static-delta operation operands.

use crate::error::{Error, Result};

/// Append the LEB128 encoding of `value` to `out`.
pub fn encode(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Decode a LEB128 varint from the front of `input`, returning the value and
/// the number of bytes consumed.
///
/// Rejects a truncated sequence (a continuation bit with no following byte),
/// any encoding whose value does not fit in 64 bits, and any non-minimal
/// encoding (a multi-byte sequence whose terminating byte is `0x00`, which
/// contributes no value bits and so has a shorter canonical form). Rejecting
/// non-minimal forms keeps unpack-then-pack of an `ostree.sizes` entry
/// byte-identical.
pub fn decode(input: &[u8]) -> Result<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in input.iter().enumerate() {
        let payload = u64::from(byte & 0x7f);
        if shift >= 64 || (shift == 63 && payload > 1) {
            return Err(Error::InvalidVarint("varint overflows 64 bits"));
        }
        value |= payload << shift;
        if byte & 0x80 == 0 {
            if i > 0 && byte == 0 {
                return Err(Error::InvalidVarint("varint is not minimally encoded"));
            }
            return Ok((value, i + 1));
        }
        shift += 7;
    }
    Err(Error::InvalidVarint("varint is truncated"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference vectors for protobuf-style LEB128 (little-endian base-128).
    const VECTORS: &[(u64, &[u8])] = &[
        (0, &[0x00]),
        (1, &[0x01]),
        (127, &[0x7f]),
        (128, &[0x80, 0x01]),
        (255, &[0xff, 0x01]),
        (300, &[0xac, 0x02]),
        (16384, &[0x80, 0x80, 0x01]),
        (2097151, &[0xff, 0xff, 0x7f]),
        (
            u64::MAX,
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01],
        ),
    ];

    #[test]
    fn encodes_reference_vectors() {
        for &(value, bytes) in VECTORS {
            let mut out = Vec::new();
            encode(value, &mut out);
            assert_eq!(out, bytes, "encoding {value}");
        }
    }

    #[test]
    fn decodes_reference_vectors_with_length() {
        for &(value, bytes) in VECTORS {
            assert_eq!(
                decode(bytes).unwrap(),
                (value, bytes.len()),
                "decoding {value}"
            );
        }
    }

    #[test]
    fn decode_stops_at_the_varint_and_reports_consumed() {
        // 300 followed by trailing bytes: consume only the two varint bytes.
        let buf = [0xac, 0x02, 0xde, 0xad];
        assert_eq!(decode(&buf).unwrap(), (300, 2));
    }

    #[test]
    fn rejects_non_minimal_encodings() {
        // A trailing 0x00 payload byte adds no value bits: the value has a
        // shorter encoding, so the long form is not canonical.
        assert!(matches!(
            decode(&[0x80, 0x00]),
            Err(Error::InvalidVarint("varint is not minimally encoded"))
        ));
        assert!(matches!(
            decode(&[0xff, 0x80, 0x00]),
            Err(Error::InvalidVarint("varint is not minimally encoded"))
        ));
        // A lone 0x00 is the minimal encoding of zero and stays valid.
        assert_eq!(decode(&[0x00]).unwrap(), (0, 1));
    }

    #[test]
    fn decode_then_encode_reproduces_every_accepted_input() {
        // Every accepted encoding is minimal, so re-encoding the decoded value
        // reproduces the original bytes exactly. Sweep a dense low range and
        // the powers of two up to u64::MAX to cover each byte-length boundary.
        let mut values: Vec<u64> = (0u64..2048).collect();
        for shift in 0..64 {
            let p = 1u64 << shift;
            values.push(p.wrapping_sub(1));
            values.push(p);
            values.push(p.wrapping_add(1));
        }
        values.push(u64::MAX);
        for value in values {
            let mut encoded = Vec::new();
            encode(value, &mut encoded);
            let (decoded, consumed) = decode(&encoded).unwrap();
            assert_eq!(decoded, value, "value {value}");
            assert_eq!(consumed, encoded.len(), "consumed for {value}");
            let mut reencoded = Vec::new();
            encode(decoded, &mut reencoded);
            assert_eq!(reencoded, encoded, "re-encode for {value}");
        }
    }

    #[test]
    fn rejects_truncated_and_overflowing_input() {
        assert!(matches!(
            decode(&[0x80]),
            Err(Error::InvalidVarint("varint is truncated"))
        ));
        assert!(matches!(decode(&[]), Err(Error::InvalidVarint(_))));
        // Eleven bytes: a 71-bit value cannot fit in u64.
        let overflow = [0x80u8; 11];
        assert!(matches!(
            decode(&overflow),
            Err(Error::InvalidVarint("varint overflows 64 bits"))
        ));
        // Tenth byte carrying more than one payload bit also overflows.
        let overflow = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02];
        assert!(matches!(
            decode(&overflow),
            Err(Error::InvalidVarint("varint overflows 64 bits"))
        ));
    }
}
