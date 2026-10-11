//! Authentication barrier and session constants.

/// Length of the challenge nonce.
pub const NONCE_LEN: usize = 32;
/// Length of the HMAC key.
pub const HMAC_KEY_LEN: usize = 32;
/// Length of the HMAC tag.
pub const HMAC_LEN: usize = 32;
/// Failed unlock attempts before the lockout engages.
pub const AUTH_MAX_FAIL: u8 = 5;
/// Lockout duration after too many failures.
pub const AUTH_LOCKOUT_MS: u32 = 60 * 1000;
/// Idle session lifetime.
pub const SESSION_TTL_MS: u32 = 15 * 60 * 1000;
/// Session token length; distinct entity from the challenge nonce.
pub const SESSION_TOKEN_LEN: usize = 32;
