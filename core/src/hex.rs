//! Lowercase hex encode/decode, shared by the vault, auth and firmware layers.

use alloc::string::String;

/// Encodes `bytes` as lowercase hex (two chars per byte).
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decodes one hex digit, accepting either case.
pub fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decodes `hex` (exactly `out.len() * 2` bytes) into `out`.
///
/// Returns `false` on a length mismatch or any non-hex digit; `out` is then
/// partially written and must be ignored by the caller.
#[must_use]
pub fn decode_into(hex: &[u8], out: &mut [u8]) -> bool {
    if hex.len() != out.len() * 2 {
        return false;
    }
    for (i, byte) in out.iter_mut().enumerate() {
        let Some(hi) = nibble(hex[i * 2]) else {
            return false;
        };
        let Some(lo) = nibble(hex[i * 2 + 1]) else {
            return false;
        };
        *byte = (hi << 4) | lo;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_accepts_both_cases() {
        let bytes = [0x00u8, 0x0f, 0x44, 0xff];
        let hex = encode(&bytes);
        assert_eq!(hex, "000f44ff");
        let mut out = [0u8; 4];
        assert!(decode_into(hex.as_bytes(), &mut out));
        assert_eq!(out, bytes);
        assert!(decode_into(b"000F44FF", &mut out));
        assert_eq!(out, bytes);
    }

    #[test]
    fn rejects_bad_input() {
        let mut out = [0u8; 2];
        assert!(!decode_into(b"abc", &mut out));
        assert!(!decode_into(b"zzzz", &mut out));
        assert!(!decode_into(b"00g0", &mut out));
    }
}
