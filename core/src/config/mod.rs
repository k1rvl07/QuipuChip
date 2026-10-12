//! Core configuration constants, ported from the removed C++ reference.
//!
//! Only the constants that participate in the on-flash/on-wire formats and the
//! crypto/password/TOTP logic live here. Networking, USB and HTTP tuning stay in
//! the firmware crate: the core must build on the host with no board dependency.
//!
//! Names follow the C++ originals; the mapping is mechanical
//! (`kAesKeyLen` -> `AES_KEY_LEN`). Values must stay byte-identical to the C++
//! reference so that a vault written by one implementation opens in the other.

mod auth;
mod crypto;
mod password;
mod tls;
mod vault;

pub use auth::*;
pub use crypto::*;
pub use password::*;
pub use tls::*;
pub use vault::*;

/// Firmware version reported over the API (`config::kFirmwareVersion`).
pub const FIRMWARE_VERSION: &str = "0.2.0";

const _: () = assert!(MASTER_PASSWORD_CHARS == 38);
const _: () = assert!(MASTER_PASSWORD_CHARS <= MAX_PASS_CHARS);
const _: () = assert!(MASTER_PASSWORD_CHARS >= MIN_PASS_CHARS);
const _: () = assert!(VAULT_REGION0_OFFSET + 2 * VAULT_REGION_BYTES == VAULT_PARTITION_BYTES);
#[allow(clippy::manual_is_multiple_of)]
const _: () = assert!(VAULT_REGION_BYTES % FLASH_SECTOR_BYTES == 0);
const _: () = assert!(VAULT_COMPACT_TRIGGER_BYTES < VAULT_REGION_BYTES);
const _: () = assert!(VAULT_LIVE_BUDGET_BYTES + MAX_ENTRY_LEN + 64 <= VAULT_REGION_BYTES);
const _: () = assert!(KEYFILE_MAX_BYTES <= 4096);
