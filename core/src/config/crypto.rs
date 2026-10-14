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

/// TOTP (RFC 6238): SHA1, base32 secret string. Digits and period are stored
/// per entry; the constants below are the defaults used when a record carries no
/// explicit value (and keep the reference profile: 6 digits, 30 s).
pub const TOTP_SECRET_MAX: usize = 64;
/// Default number of digits in a generated TOTP code.
pub const TOTP_DIGITS: u32 = 6;
/// Default TOTP time-step length in seconds.
pub const TOTP_PERIOD_SEC: u64 = 30;

/// Smallest accepted digit count (RFC 4226/6238 standard profile).
pub const TOTP_DIGITS_MIN: u32 = 6;
/// Largest accepted digit count. `10^8` still fits `u32`.
pub const TOTP_DIGITS_MAX: u32 = 8;
/// Smallest accepted period.
pub const TOTP_PERIOD_MIN_SEC: u64 = 10;
/// Largest accepted period.
pub const TOTP_PERIOD_MAX_SEC: u64 = 120;
