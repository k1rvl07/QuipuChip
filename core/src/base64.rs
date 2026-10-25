//! Strict RFC 4648 base64 (standard alphabet, padding only in the last group).

use alloc::string::String;
use alloc::vec::Vec;

use crate::config::KEYFILE_MAX_BYTES;

/// Encodes bytes as standard RFC 4648 base64 with padding.
#[must_use]
pub fn encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(char::from(ALPHABET[((n >> 18) & 63) as usize]));
        out.push(char::from(ALPHABET[((n >> 12) & 63) as usize]));
        out.push(if chunk.len() > 1 {
            char::from(ALPHABET[((n >> 6) & 63) as usize])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(ALPHABET[(n & 63) as usize])
        } else {
            '='
        });
    }
    out
}

fn value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decodes a base64 string, rejecting non-alphabet characters, misplaced or
/// missing padding, and output larger than [`KEYFILE_MAX_BYTES`].
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.is_empty() || !b.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    for chunk in b.as_chunks::<4>().0 {
        let a = value(chunk[0])?;
        let b2 = value(chunk[1])?;
        let c_pad = chunk[2] == b'=';
        let d_pad = chunk[3] == b'=';
        if c_pad && !d_pad {
            return None;
        }
        let c = if c_pad { 0 } else { value(chunk[2])? };
        let d = if d_pad { 0 } else { value(chunk[3])? };
        out.push((a << 2) | (b2 >> 4));
        if c_pad {
            continue;
        }
        out.push(((b2 & 0x0F) << 4) | (c >> 2));
        if d_pad {
            continue;
        }
        out.push(((c & 0x03) << 6) | d);
    }
    if out.len() > KEYFILE_MAX_BYTES {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_padded_and_unpadded_groups() {
        assert_eq!(decode("TWFu").unwrap(), b"Man");
        assert_eq!(decode("TWE=").unwrap(), b"Ma");
        assert_eq!(decode("TQ==").unwrap(), b"M");
    }

    #[test]
    fn encodes_known_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(encode(&[0x00, 0x01, 0x02, 0xfd, 0xfe, 0xff]), "AAEC/f7/");
    }

    #[test]
    fn encode_decode_round_trip() {
        for sample in [
            &b"f"[..],
            b"fo",
            b"foo",
            b"foob",
            b"foobar",
            b"\x00\x01\x02\xfd\xfe\xff",
        ] {
            assert_eq!(decode(&encode(sample)).unwrap(), sample.to_vec());
        }
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(decode("").is_none());
        assert!(decode("TWF").is_none());
        assert!(decode("T=Fu").is_none());
        assert!(decode("TW!u").is_none());
        assert!(decode("T===").is_none());
    }

    #[test]
    fn rejects_padding_in_the_wrong_place() {
        // Padding may only appear in the last group, and only as "=" or "==".
        assert!(decode("=AAA").is_none());
        assert!(decode("A=AA").is_none());
        assert!(decode("AA=A").is_none());
        assert!(decode("A===").is_none());
        assert!(decode("=AAA====").is_none());
        // A group whose padding is only one '=' where two are needed is fine:
        // "TQ==" is one byte.
        assert_eq!(decode("TQ==").unwrap(), b"M");
    }

    #[test]
    fn rejects_an_oversized_key_file() {
        // The cap exists so a hostile client cannot make the device allocate an
        // arbitrary buffer.
        let big = encode(&vec![0u8; KEYFILE_MAX_BYTES + 1]);
        assert!(decode(&big).is_none());
        let at_limit = encode(&vec![0u8; KEYFILE_MAX_BYTES]);
        assert_eq!(decode(&at_limit).unwrap().len(), KEYFILE_MAX_BYTES);
    }

    #[test]
    fn rejects_whitespace_and_newlines() {
        assert!(decode("TWFu\n").is_none());
        assert!(decode("TW Fu").is_none());
        assert!(decode("\n").is_none());
    }
}
