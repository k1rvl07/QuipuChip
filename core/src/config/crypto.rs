//! Crypto and TOTP constants.

/// AES-256 key length.
pub const AES_KEY_LEN: usize = 32;
/// GCM nonce length.
pub const GCM_IV_LEN: usize = 12;
/// GCM authentication tag length.
pub const GCM_TAG_LEN: usize = 16;

/// PBKDF2-HMAC-SHA256 iteration count (`kPbkdf2Iters`).
pub const PBKDF2_ITERS: u32 = 30_000;
/// PBKDF2 salt length.
pub const PBKDF2_SALT_LEN: usize = 16;
/// Mirrors `kKdfParamsLen` (`4 + 4 + 1 + kPbkdf2SaltLen`). The C++ reference
/// does not name the individual fields, so this keeps the same breakdown.
pub const KDF_PARAMS_LEN: usize = 4 + 4 + 1 + PBKDF2_SALT_LEN;

/// TOTP (RFC 6238): SHA1, 6 digits, 30 s, base32 secret string.
pub const TOTP_SECRET_MAX: usize = 64;
/// Number of digits in a generated TOTP code.
pub const TOTP_DIGITS: u32 = 6;
/// TOTP time-step length in seconds.
pub const TOTP_PERIOD_SEC: u64 = 30;
