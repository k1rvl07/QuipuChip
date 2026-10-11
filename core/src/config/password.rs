//! Password, master-password and key-file constants.

/// Shortest accepted master password.
pub const MIN_PASS_CHARS: usize = 12;
/// Longest accepted master password.
pub const MAX_PASS_CHARS: usize = 256;

/// Master password layout: 6 words of 12 bits each plus 2 decimal digits.
pub const MASTER_WORDS: usize = 6;
/// Number of decimal digits appended to the master password.
pub const MASTER_DIGITS: usize = 2;
/// Bytes per dictionary word.
pub const MASTER_WORD_BYTES: usize = 5;
/// `6*5 + 6 + 2 == 38`. The six hyphens are five separators plus the one that
/// precedes the digit block; the C++ formula was once 37 for this reason.
pub const MASTER_PASSWORD_CHARS: usize =
    MASTER_WORDS * MASTER_WORD_BYTES + MASTER_WORDS + MASTER_DIGITS;

/// Cap on rejection-sampling retries when drawing a master-password digit.
pub const MAX_DIGIT_ATTEMPTS: u32 = 256;

/// Minimum length of a generated site password.
pub const PASSWORD_LEN_MIN: u8 = 8;
/// Maximum length of a generated site password.
pub const PASSWORD_LEN_MAX: u8 = 128;
/// Alphabet for generated site passwords (no ambiguous `l`/`I`/`1`/`0`/`O`).
pub const PASSWORD_ALPHABET: &[u8] =
    b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*()-_=+[]{}";

/// Key file is never stored on device; the client sends it (base64).
pub const KEYFILE_MAX_BYTES: usize = 4096;
