//! TOTP (RFC 6238), ported from the removed C++ reference.
//!
//! Algorithm is fixed: SHA-1. The digit count and period are per entry; a record
//! that carries no explicit value falls back to the reference profile (6 digits,
//! 30-second period). The secret is stored as an RFC 4648 base32 string
//! (case-insensitive, optional `=` padding). Only the standard profile is
//! supported; `otpauth://` URIs are not parsed.

use alloc::{format, string::String};

use crate::config::{
    TOTP_DIGITS, TOTP_DIGITS_MAX, TOTP_DIGITS_MIN, TOTP_PERIOD_MAX_SEC, TOTP_PERIOD_MIN_SEC,
    TOTP_PERIOD_SEC, TOTP_SECRET_MAX,
};
use crate::crypto::hmac_sha1;

/// Errors from computing a TOTP code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpError {
    /// Secret is empty, too short, too long, or not valid base32.
    BadSecret,
    /// Digit count or period is out of range.
    BadParams,
}

impl core::fmt::Display for TotpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            TotpError::BadSecret => "invalid TOTP secret",
            TotpError::BadParams => "invalid TOTP parameters",
        })
    }
}

impl core::error::Error for TotpError {}

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
pub fn is_valid_secret(secret: &str) -> bool {
    let bytes = secret.as_bytes();
    if bytes.is_empty() || bytes.len() >= TOTP_SECRET_MAX || bytes.len() < 16 {
        return false;
    }
    let mut key = [0u8; 64];
    matches!(decode_base32(bytes, &mut key), Some(n) if n >= 10)
}

/// Computes the TOTP code for `time_sec`.
///
/// `digits` must be in `TOTP_DIGITS_MIN..=TOTP_DIGITS_MAX` and `period` must be
/// in `TOTP_PERIOD_MIN_SEC..=TOTP_PERIOD_MAX_SEC`. The code is zero-padded to
/// `digits`.
pub fn compute(secret: &str, time_sec: u64, digits: u32, period: u64) -> Result<String, TotpError> {
    if !(TOTP_DIGITS_MIN..=TOTP_DIGITS_MAX).contains(&digits)
        || !(TOTP_PERIOD_MIN_SEC..=TOTP_PERIOD_MAX_SEC).contains(&period)
    {
        return Err(TotpError::BadParams);
    }
    let mut key = [0u8; 64];
    let key_len = decode_base32(secret.as_bytes(), &mut key).ok_or(TotpError::BadSecret)?;
    if key_len < 10 {
        crate::crypto::wipe(&mut key);
        return Err(TotpError::BadSecret);
    }
    let counter = time_sec / period;
    let msg = counter.to_be_bytes();
    let mac = hmac_sha1(&key[..key_len], &msg);
    crate::crypto::wipe(&mut key);

    // Dynamic truncation (RFC 4226 §5.3).
    let off = (mac[19] & 0x0f) as usize;
    let bin = (u32::from(mac[off] & 0x7f) << 24)
        | (u32::from(mac[off + 1]) << 16)
        | (u32::from(mac[off + 2]) << 8)
        | u32::from(mac[off + 3]);
    let modulus = 10u32.pow(digits);
    Ok(format!(
        "{:0width$}",
        bin % modulus,
        width = digits as usize
    ))
}

/// Resolves a stored digit count. Empty means the default profile; a non-empty
/// value must be decimal ASCII within `TOTP_DIGITS_MIN..=TOTP_DIGITS_MAX`.
#[must_use]
pub fn resolve_digits(raw: &[u8]) -> Option<u32> {
    let v = parse_bounded(
        raw,
        u64::from(TOTP_DIGITS),
        u64::from(TOTP_DIGITS_MIN),
        u64::from(TOTP_DIGITS_MAX),
    )?;
    u32::try_from(v).ok()
}

/// Resolves a stored period (seconds). Empty means the default profile; a
/// non-empty value must be decimal ASCII within the accepted range.
#[must_use]
pub fn resolve_period(raw: &[u8]) -> Option<u64> {
    parse_bounded(
        raw,
        TOTP_PERIOD_SEC,
        TOTP_PERIOD_MIN_SEC,
        TOTP_PERIOD_MAX_SEC,
    )
}

/// Shared parser: empty -> `default`, otherwise decimal ASCII within
/// `min..=max`. Anything else (non-digit, empty-but-present, out of range,
/// overflow) is rejected.
fn parse_bounded(raw: &[u8], default: u64, min: u64, max: u64) -> Option<u64> {
    if raw.is_empty() {
        return Some(default);
    }
    let s = core::str::from_utf8(raw).ok()?;
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let v: u64 = s.parse().ok()?;
    (min..=max).contains(&v).then_some(v)
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
            assert_eq!(
                compute(secret, *t, TOTP_DIGITS, TOTP_PERIOD_SEC).unwrap(),
                *want,
                "t={t}"
            );
        }
    }

    #[test]
    fn rfc6238_sha1_vectors_8_digits() {
        // Same secret, 8-digit profile (RFC 6238 appendix B).
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let vectors: &[(u64, &str)] = &[
            (59, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
        ];
        for (t, want) in vectors {
            assert_eq!(
                compute(secret, *t, 8, TOTP_PERIOD_SEC).unwrap(),
                *want,
                "t={t}"
            );
        }
    }

    #[test]
    fn digits_and_period_resolution() {
        // Empty -> default profile.
        assert_eq!(resolve_digits(b""), Some(TOTP_DIGITS));
        assert_eq!(resolve_period(b""), Some(TOTP_PERIOD_SEC));
        // Explicit valid values.
        assert_eq!(resolve_digits(b"8"), Some(8));
        assert_eq!(resolve_period(b"60"), Some(60));
        assert_eq!(resolve_period(b"120"), Some(120));
        // Out of range / not a number.
        assert_eq!(resolve_digits(b"5"), None);
        assert_eq!(resolve_digits(b"9"), None);
        assert_eq!(resolve_period(b"9"), None);
        assert_eq!(resolve_period(b"121"), None);
        assert_eq!(resolve_digits(b"6x"), None);
        assert_eq!(resolve_period(b"-1"), None);
    }

    #[test]
    fn compute_rejects_bad_parameters() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert_eq!(compute(secret, 59, 5, 30), Err(TotpError::BadParams));
        assert_eq!(compute(secret, 59, 9, 30), Err(TotpError::BadParams));
        assert_eq!(compute(secret, 59, 6, 0), Err(TotpError::BadParams));
        assert_eq!(compute(secret, 59, 6, 9), Err(TotpError::BadParams));
    }

    #[test]
    fn rejects_invalid_secrets() {
        assert!(!is_valid_secret("abc"));
        // '1' is not in the base32 alphabet.
        assert!(!is_valid_secret("ABCDEFGH1IJKLMNOP"));
        assert!(!is_valid_secret(""));
        assert!(compute("too-short", 59, TOTP_DIGITS, TOTP_PERIOD_SEC).is_err());
        // Sanity: the RFC secret above must be valid.
        assert!(is_valid_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
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

    #[test]
    fn decode_base32_accepts_lowercase_and_padding() {
        let mut out = [0u8; 16];
        // "MZXW6===" -> "foo".
        assert_eq!(decode_base32(b"MZXW6===", &mut out), Some(3));
        assert_eq!(&out[..3], b"foo");
        // The same secret in lower case must decode identically.
        assert_eq!(decode_base32(b"mzxw6===", &mut out), Some(3));
        assert_eq!(&out[..3], b"foo");
        // Padding is optional.
        assert_eq!(decode_base32(b"MZXW6", &mut out), Some(3));
    }

    #[test]
    fn decode_base32_rejects_an_empty_secret_and_a_short_output() {
        let mut out = [0u8; 16];
        assert_eq!(decode_base32(b"", &mut out), None);
        assert_eq!(decode_base32(b"====", &mut out), None);
        // 20 base32 chars decode to 12 bytes; a 4-byte buffer must be refused
        // rather than truncated.
        let mut small = [0u8; 4];
        assert_eq!(
            decode_base32(b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", &mut small),
            None
        );
    }

    #[test]
    fn secret_length_boundaries() {
        // The reference accepts 16..TOTP_SECRET_MAX-1 characters.
        let short = "GEZDGNBVGY3TQOJQ"; // 16 chars -> 10 bytes
        assert!(is_valid_secret(short));
        assert!(!is_valid_secret(&short[..15]));
        // TOTP_SECRET_MAX characters is one too many; one below is fine.
        let at_limit = "A".repeat(TOTP_SECRET_MAX - 1);
        assert!(is_valid_secret(&at_limit));
        let too_long = "A".repeat(TOTP_SECRET_MAX);
        assert!(!is_valid_secret(&too_long));
    }

    #[test]
    fn compute_rejects_a_short_decoded_secret() {
        // 16 base32 characters decode to 10 bytes, which is the minimum; a
        // shorter secret must be refused even if it is well-formed base32.
        assert_eq!(
            compute("GEZDGNBVGY3TQO", 59, TOTP_DIGITS, TOTP_PERIOD_SEC),
            Err(TotpError::BadSecret)
        );
    }

    #[test]
    fn codes_are_zero_padded_to_the_requested_width() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        // RFC 6238 vector 1111111109 -> "081804" with six digits: the leading
        // zero is part of the code, not an accident.
        let code = compute(secret, 1_111_111_109, TOTP_DIGITS, TOTP_PERIOD_SEC).unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.starts_with('0'));
    }

    #[test]
    fn a_code_is_stable_inside_its_time_step_and_changes_across_it() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let period = TOTP_PERIOD_SEC;
        let base = 1_234_567_890u64;
        let a = compute(secret, base, TOTP_DIGITS, period).unwrap();
        let b = compute(secret, base + period - 1, TOTP_DIGITS, period).unwrap();
        let c = compute(secret, base + period, TOTP_DIGITS, period).unwrap();
        assert_eq!(a, b, "the code must not change inside a step");
        assert_ne!(a, c, "the code must change at a step boundary");
    }

    #[test]
    fn resolve_rejects_non_numeric_and_overflowing_values() {
        assert_eq!(resolve_digits(b" 6"), None);
        assert_eq!(resolve_digits(b"+6"), None);
        assert_eq!(resolve_digits(b"18446744073709551616"), None);
        assert_eq!(resolve_period(b"18446744073709551616"), None);
        assert_eq!(resolve_digits(b"6"), Some(6));
        assert_eq!(resolve_period(b"10"), Some(10));
    }
}
