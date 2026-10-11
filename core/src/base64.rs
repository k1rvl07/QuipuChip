//! Strict RFC 4648 base64 (standard alphabet, padding only in the last group).

use alloc::vec::Vec;

use crate::config::KEYFILE_MAX_BYTES;

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
    fn rejects_malformed_input() {
        assert!(decode("").is_none());
        assert!(decode("TWF").is_none());
        assert!(decode("T=Fu").is_none());
        assert!(decode("TW!u").is_none());
        assert!(decode("T===").is_none());
    }
}
