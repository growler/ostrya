//! Big-endian scalars at the GVariant value level.
//!
//! Some on-disk fields are big-endian at the GVariant value level: uid, gid,
//! mode, rdev, the timestamp, and the uncompressed size of the archive form. The
//! rest of the format is little-endian. The newtypes of this module hold the
//! value in host order and encode and decode the big-endian wire form. The
//! object structs hold plain integers, and each serialize and parse site uses
//! these newtypes for the byte-order conversion.

use ostrya_gvariant::{GvDecode, GvEncode, GvType};

/// A `u32` that is big-endian on the wire, with the GVariant signature `u`.
///
/// The wrapped value is in host order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Be32(pub u32);

impl GvType for Be32 {
    const SIGNATURE: &'static str = "u";
    const ALIGNMENT: usize = 4;
    const FIXED_SIZE: Option<usize> = Some(4);
}

impl GvEncode for Be32 {
    fn encode(&self, out: &mut Vec<u8>) -> ostrya_gvariant::Result<()> {
        out.extend_from_slice(&self.0.to_be_bytes());
        Ok(())
    }
}

impl<'a> GvDecode<'a> for Be32 {
    fn decode(data: &'a [u8]) -> ostrya_gvariant::Result<Self> {
        let arr: [u8; 4] = data
            .try_into()
            .map_err(|_| ostrya_gvariant::Error::NotNormal("u32 has the wrong size"))?;
        Ok(Be32(u32::from_be_bytes(arr)))
    }
}

/// A `u64` that is big-endian on the wire, with the GVariant signature `t`.
///
/// The wrapped value is in host order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Be64(pub u64);

impl GvType for Be64 {
    const SIGNATURE: &'static str = "t";
    const ALIGNMENT: usize = 8;
    const FIXED_SIZE: Option<usize> = Some(8);
}

impl GvEncode for Be64 {
    fn encode(&self, out: &mut Vec<u8>) -> ostrya_gvariant::Result<()> {
        out.extend_from_slice(&self.0.to_be_bytes());
        Ok(())
    }
}

impl<'a> GvDecode<'a> for Be64 {
    fn decode(data: &'a [u8]) -> ostrya_gvariant::Result<Self> {
        let arr: [u8; 8] = data
            .try_into()
            .map_err(|_| ostrya_gvariant::Error::NotNormal("u64 has the wrong size"))?;
        Ok(Be64(u64::from_be_bytes(arr)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ostrya_gvariant::encode_to_vec;

    #[test]
    fn be32_writes_big_endian_and_round_trips() {
        let bytes = encode_to_vec(&Be32(0x0102_0304)).unwrap();
        assert_eq!(bytes, [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(Be32::decode(&bytes).unwrap(), Be32(0x0102_0304));
    }

    #[test]
    fn be64_writes_big_endian_and_round_trips() {
        let bytes = encode_to_vec(&Be64(0x0102_0304_0506_0708)).unwrap();
        assert_eq!(bytes, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(Be64::decode(&bytes).unwrap(), Be64(0x0102_0304_0506_0708));
    }

    #[test]
    fn rejects_wrong_width() {
        assert!(Be32::decode(&[0; 3]).is_err());
        assert!(Be64::decode(&[0; 7]).is_err());
    }
}
