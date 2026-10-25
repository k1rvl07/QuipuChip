//! TOTP contract tests (RFC 6238 vectors).

#![allow(clippy::unwrap_used)]

use pm_core::config::{TOTP_DIGITS, TOTP_PERIOD_SEC};
use pm_core::totp::{compute, is_valid_secret, resolve_digits, resolve_period};

#[test]
fn rfc6238_sha1_vectors() {
    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    assert_eq!(compute(secret, 59, 8, 30).unwrap(), "94287082");
    assert_eq!(compute(secret, 1111111109, 8, 30).unwrap(), "07081804");
    assert_eq!(compute(secret, 1111111111, 8, 30).unwrap(), "14050471");
    assert_eq!(compute(secret, 1234567890, 8, 30).unwrap(), "89005924");
    assert_eq!(compute(secret, 2000000000, 8, 30).unwrap(), "69279037");
}

#[test]
fn defaults_and_resolution() {
    assert_eq!(resolve_digits(b""), Some(TOTP_DIGITS));
    assert_eq!(resolve_period(b""), Some(TOTP_PERIOD_SEC));
    assert_eq!(resolve_digits(b"6"), Some(6));
    assert_eq!(resolve_digits(b"8"), Some(8));
    assert_eq!(resolve_period(b"30"), Some(30));
    assert_eq!(resolve_period(b"60"), Some(60));
    assert_eq!(resolve_digits(b"5"), None);
    assert_eq!(resolve_digits(b"9"), None);
}

#[test]
fn secret_validation() {
    assert!(is_valid_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
    assert!(!is_valid_secret(""));
    assert!(!is_valid_secret("abc"));
    assert!(!is_valid_secret("ABCDEFGH1IJKLMNOP"));
}
