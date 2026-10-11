//! Core configuration constants, ported from `include/config.h`.
//!
//! Only the constants that participate in the on-flash/on-wire formats and the
//! crypto/password/TOTP logic live here. Networking, USB and HTTP tuning stay in
//! the firmware crate: the core must build on the host with no board dependency.
//!
//! Names follow the C++ originals; the mapping is mechanical
//! (`kAesKeyLen` -> `AES_KEY_LEN`). Values must stay byte-identical to the C++
//! reference so that a vault written by one implementation opens in the other.

/// Firmware version reported over the API (`config::kFirmwareVersion`).
pub const FIRMWARE_VERSION: &str = "0.2.0";

/// On-flash vault container magic (`PMV1`).
pub const VAULT_MAGIC: [u8; 4] = *b"PMV1";
/// Export container magic (`PMX1`).
pub const EXPORT_MAGIC: [u8; 4] = *b"PMX1";
/// Export format version; grows on incompatible layout changes.
pub const EXPORT_VERSION: u32 = 1;

pub const AES_KEY_LEN: usize = 32;
pub const GCM_IV_LEN: usize = 12;
pub const GCM_TAG_LEN: usize = 16;

/// PBKDF2-HMAC-SHA256 iteration count (`kPbkdf2Iters`).
pub const PBKDF2_ITERS: u32 = 30_000;
pub const MIN_PASS_CHARS: usize = 12;
pub const MAX_PASS_CHARS: usize = 256;
pub const PBKDF2_SALT_LEN: usize = 16;
/// Mirrors `kKdfParamsLen` (`4 + 4 + 1 + kPbkdf2SaltLen`). The C++ reference
/// does not name the individual fields, so this keeps the same breakdown.
pub const KDF_PARAMS_LEN: usize = 4 + 4 + 1 + PBKDF2_SALT_LEN;

/// Master password layout: 6 words of 12 bits each plus 2 decimal digits.
pub const MASTER_WORDS: usize = 6;
pub const MASTER_DIGITS: usize = 2;
pub const MASTER_WORD_BYTES: usize = 5;
/// `6*5 + 6 + 2 == 38`. The six hyphens are five separators plus the one that
/// precedes the digit block; the C++ formula was once 37 for this reason.
pub const MASTER_PASSWORD_CHARS: usize =
    MASTER_WORDS * MASTER_WORD_BYTES + MASTER_WORDS + MASTER_DIGITS;

/// Cap on rejection-sampling retries when drawing a master-password digit.
pub const MAX_DIGIT_ATTEMPTS: u32 = 256;

/// Vault partition capacity (512 KiB, see `partitions.csv`).
pub const VAULT_PARTITION_BYTES: usize = 512 * 1024;
/// Header occupies exactly one SPI flash page.
pub const VAULT_HEADER_BYTES: usize = 256;
pub const FLASH_SECTOR_BYTES: usize = 4096;
/// Each header slot owns its own sector: writing a slot requires an erase.
pub const VAULT_HEADER_SLOT_BYTES: usize = FLASH_SECTOR_BYTES;
pub const VAULT_HEADER_SLOTS: usize = 2;
/// Journal regions begin after both header slots.
pub const VAULT_REGION0_OFFSET: usize = VAULT_HEADER_SLOT_BYTES * VAULT_HEADER_SLOTS;
pub const VAULT_REGION_BYTES: usize =
    ((VAULT_PARTITION_BYTES - VAULT_REGION0_OFFSET) / 2 / FLASH_SECTOR_BYTES) * FLASH_SECTOR_BYTES;
/// Compaction is triggered once half of a region is in use.
pub const VAULT_COMPACT_TRIGGER_BYTES: usize = VAULT_REGION_BYTES / 2;
/// Hard byte budget for live payload data.
pub const VAULT_LIVE_BUDGET_BYTES: usize = 192 * 1024;

pub const MAX_ENTRY_LEN: usize = 1280;
pub const MAX_ENTRIES: u32 = 1000;
pub const PASSWORD_LEN_MIN: u8 = 8;
pub const PASSWORD_LEN_MAX: u8 = 128;
pub const PASSWORD_ALPHABET: &[u8] =
    b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*()-_=+[]{}";

/// Key file is never stored on device; the client sends it (base64).
pub const KEYFILE_MAX_BYTES: usize = 4096;

/// TOTP (RFC 6238): SHA1, 6 digits, 30 s, base32 secret string.
pub const TOTP_SECRET_MAX: usize = 64;
pub const TOTP_DIGITS: u32 = 6;
pub const TOTP_PERIOD_SEC: u64 = 30;

/// Entries per `POST /api/import` request.
pub const IMPORT_BATCH_ENTRIES: usize = 4;

/// Authentication barrier: HMAC challenge-response.
pub const NONCE_LEN: usize = 32;
pub const HMAC_KEY_LEN: usize = 32;
pub const HMAC_LEN: usize = 32;
pub const AUTH_MAX_FAIL: u8 = 5;
pub const AUTH_LOCKOUT_MS: u32 = 60 * 1000;
pub const SESSION_TTL_MS: u32 = 15 * 60 * 1000;
/// Session token length; distinct entity from the challenge nonce.
pub const SESSION_TOKEN_LEN: usize = 32;

const _: () = assert!(MASTER_PASSWORD_CHARS == 38);
const _: () = assert!(MASTER_PASSWORD_CHARS <= MAX_PASS_CHARS);
const _: () = assert!(MASTER_PASSWORD_CHARS >= MIN_PASS_CHARS);
const _: () = assert!(VAULT_REGION0_OFFSET + 2 * VAULT_REGION_BYTES == VAULT_PARTITION_BYTES);
#[allow(clippy::manual_is_multiple_of)]
const _: () = assert!(VAULT_REGION_BYTES % FLASH_SECTOR_BYTES == 0);
const _: () = assert!(VAULT_COMPACT_TRIGGER_BYTES < VAULT_REGION_BYTES);
const _: () = assert!(VAULT_LIVE_BUDGET_BYTES + MAX_ENTRY_LEN + 64 <= VAULT_REGION_BYTES);
const _: () = assert!(KEYFILE_MAX_BYTES <= 4096);
