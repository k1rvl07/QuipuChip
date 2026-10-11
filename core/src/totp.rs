//! TOTP (RFC 6238), ported from `src/totp.cpp`.
//!
//! Algorithm is fixed: SHA-1, 6 digits, 30-second period. The secret is stored
//! as an RFC 4648 base32 string (case-insensitive, optional `=` padding). Only
//! the standard profile is supported; `otpauth://` URIs are not parsed.

use alloc::{format, string::String};

use crate::config::{TOTP_DIGITS, TOTP_PERIOD_SEC, TOTP_SECRET_MAX};
use crate::crypto::hmac_sha1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpError {
    /// Secret is empty, too short, too long, or not valid base32.
    BadSecret,
}

/// Value of one base32 character (RFC 4648), or `None` if invalid.
fn b32val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a'),
        b'2'..=b'7' => Some(c - b'2' + 26),
        _ => None,
    }
}

/// Decodes base32 into `out`. Returns the number of bytes written, or `None` on
/// invalid input. A non-zero leftover bit group is rejected: a valid base32
/// encoding pads the final group with zero bits, and a non-zero remainder would
/// silently change the key.
pub fn decode_base32(secret: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut n = secret.len();
    while n > 0 && secret[n - 1] == b'=' {
        n -= 1;
    }
    if n == 0 {
        return None;
    }
    let mut out_len = 0usize;
    let mut acc: u32 = 0;
    let mut bits: i32 = 0;
    for &c in &secret[..n] {
        let v = b32val(c)?;
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if out_len >= out.len() {
                return None;
            }
            out[out_len] = ((acc >> bits) & 0xff) as u8;
            out_len += 1;
            acc &= if bits > 0 { (1u32 << bits) - 1 } else { 0 };
        }
    }
    if acc != 0 {
        return None;
    }
    Some(out_len)
}

/// Validates a secret string the same way the C++ reference does: length in
/// `16..TOTP_SECRET_MAX` and at least 10 decoded bytes.
pub fn valid_secret(secret: &str) -> bool {
    let bytes = secret.as_bytes();
    if bytes.is_empty() || bytes.len() >= TOTP_SECRET_MAX || bytes.len() < 16 {
        return false;
    }
    let mut key = [0u8; 64];
    matches!(decode_base32(bytes, &mut key), Some(n) if n >= 10)
}

/// Computes the 6-digit code for `time_sec`. Returns it zero-padded.
pub fn code(secret: &str, time_sec: u64) -> Result<String, TotpError> {
    let mut key = [0u8; 64];
    let key_len = decode_base32(secret.as_bytes(), &mut key).ok_or(TotpError::BadSecret)?;
    if key_len < 10 {
        crate::crypto::wipe(&mut key);
        return Err(TotpError::BadSecret);
    }
    let counter = time_sec / TOTP_PERIOD_SEC;
    let msg = counter.to_be_bytes();
    let mac = hmac_sha1(&key[..key_len], &msg);
    crate::crypto::wipe(&mut key);

    // Dynamic truncation (RFC 4226 §5.3).
    let off = (mac[19] & 0x0f) as usize;
    let bin = (u32::from(mac[off] & 0x7f) << 24)
        | (u32::from(mac[off + 1]) << 16)
        | (u32::from(mac[off + 2]) << 8)
        | u32::from(mac[off + 3]);
    let modulus = 10u32.pow(TOTP_DIGITS);
    Ok(format!(
        "{:0width$}",
        bin % modulus,
        width = TOTP_DIGITS as usize
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_sha1_vectors() {
        // ASCII "12345678901234567890" as base32.
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let vectors: &[(u64, &str)] = &[
            (59, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
        ];
        for (t, want) in vectors {
            assert_eq!(code(secret, *t).unwrap(), *want, "t={}", t);
        }
    }

    #[test]
    fn rejects_invalid_secrets() {
        assert!(!valid_secret("abc"));
        // '1' is not in the base32 alphabet.
        assert!(!valid_secret("ABCDEFGH1IJKLMNOP"));
        assert!(!valid_secret(""));
        assert!(code("too-short", 59).is_err());
        // Sanity: the RFC secret above must be valid.
        assert!(valid_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
    }

    #[test]
    fn rejects_nonzero_leftover_bits() {
        // "my" -> 0x66 0x60? base32 "my======" decodes to 'f' with padding bits.
        let mut out = [0u8; 8];
        // A single 'A' plus a non-zero final group is not a real base32 string;
        // construct bits that leave a non-zero remainder: 1 group is 5 bits < 8,
        // so leftover acc = value of 'B' = 1 -> rejected.
        assert_eq!(decode_base32(b"B", &mut out), None);
        assert_eq!(decode_base32(b"B=======", &mut out), None);
    }
}
