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
const _: () = assert!(KEYFILE_GENERATED_BYTES > 0);
const _: () = assert!(KEYFILE_GENERATED_BYTES <= KEYFILE_MAX_BYTES);

#[cfg(test)]
mod tests {
    use super::*;

    /// The constants below are compatibility contracts with the removed C++
    /// reference and with the on-flash layout. Changing one silently changes
    /// what an older build can read, so every value is pinned here: a change
    /// must be a deliberate edit to this test, not an accident.

    #[test]
    fn container_magics_and_version() {
        assert_eq!(&VAULT_MAGIC, b"PMV1");
        assert_eq!(&EXPORT_MAGIC, b"PMX1");
        assert_eq!(EXPORT_VERSION, 1);
        assert_eq!(TLS_BLOB_MAGIC, *b"PMT1");
        assert_eq!(TLS_BLOB_VERSION, 1);
    }

    #[test]
    fn vault_partition_layout() {
        assert_eq!(VAULT_PARTITION_BYTES, 512 * 1024);
        assert_eq!(VAULT_HEADER_BYTES, 256);
        assert_eq!(FLASH_SECTOR_BYTES, 4096);
        assert_eq!(VAULT_HEADER_SLOT_BYTES, 4096);
        assert_eq!(VAULT_HEADER_SLOTS, 2);
        assert_eq!(VAULT_REGION0_OFFSET, 8192);
        assert_eq!(VAULT_REGION_BYTES, 258_048);
        assert_eq!(VAULT_COMPACT_TRIGGER_BYTES, VAULT_REGION_BYTES / 2);
        assert_eq!(VAULT_LIVE_BUDGET_BYTES, 192 * 1024);
        assert_eq!(MAX_ENTRY_LEN, 1280);
        assert_eq!(MAX_ENTRIES, 1000);
        assert_eq!(IMPORT_BATCH_ENTRIES, 4);
    }

    #[test]
    fn the_header_fits_exactly_one_flash_page() {
        // A header that crossed the page boundary put the auth tag outside the
        // buffer; the AGENTS.md records that as a real, expensive bug.
        const { assert!(VAULT_HEADER_BYTES <= FLASH_SECTOR_BYTES) };
        assert_eq!(VAULT_HEADER_BYTES, 256);
    }
    #[test]
    fn the_journal_layout_uses_whole_sectors() {
        // Erase requires a 4096-aligned offset and length.
        assert_eq!(VAULT_REGION0_OFFSET % FLASH_SECTOR_BYTES, 0);
        assert_eq!(VAULT_REGION_BYTES % FLASH_SECTOR_BYTES, 0);
        assert_eq!(
            VAULT_REGION0_OFFSET + 2 * VAULT_REGION_BYTES,
            VAULT_PARTITION_BYTES
        );
    }

    #[test]
    fn crypto_constants() {
        assert_eq!(AES_KEY_LEN, 32);
        assert_eq!(GCM_IV_LEN, 12);
        assert_eq!(GCM_TAG_LEN, 16);
        assert_eq!(PBKDF2_ITERS, 30_000);
        assert_eq!(PBKDF2_SALT_LEN, 16);
        assert_eq!(KDF_PARAMS_LEN, 4 + 4 + 1 + PBKDF2_SALT_LEN);
        assert_eq!(KDF_PARAMS_LEN, 25);
    }

    #[test]
    fn totp_constants() {
        assert_eq!(TOTP_SECRET_MAX, 64);
        assert_eq!(TOTP_DIGITS, 6);
        assert_eq!(TOTP_PERIOD_SEC, 30);
        assert_eq!(TOTP_DIGITS_MIN, 6);
        assert_eq!(TOTP_DIGITS_MAX, 8);
        assert_eq!(TOTP_PERIOD_MIN_SEC, 10);
        assert_eq!(TOTP_PERIOD_MAX_SEC, 120);
        // The default profile must be inside the accepted range, otherwise a
        // record without explicit parameters could never be computed.
        const { assert!(TOTP_DIGITS_MIN <= TOTP_DIGITS && TOTP_DIGITS <= TOTP_DIGITS_MAX) };
        const {
            assert!(
                TOTP_PERIOD_MIN_SEC <= TOTP_PERIOD_SEC && TOTP_PERIOD_SEC <= TOTP_PERIOD_MAX_SEC
            );
        };
    }

    #[test]
    fn password_constants() {
        assert_eq!(MIN_PASS_CHARS, 12);
        assert_eq!(MAX_PASS_CHARS, 256);
        assert_eq!(MASTER_WORDS, 6);
        assert_eq!(MASTER_DIGITS, 2);
        assert_eq!(MASTER_WORD_BYTES, 5);
        assert_eq!(MASTER_PASSWORD_CHARS, 38);
        assert_eq!(MAX_DIGIT_ATTEMPTS, 256);
        assert_eq!(PASSWORD_LEN_MIN, 8);
        assert_eq!(PASSWORD_LEN_MAX, 128);
    }

    #[test]
    fn master_password_length_formula_counts_every_hyphen() {
        // Six words need five separators, plus one more before the digit
        // block: 6*5 + 6 + 2 == 38. The C++ formula gave 37 and overflowed the
        // password buffer on the very first run.
        assert_eq!(
            MASTER_PASSWORD_CHARS,
            MASTER_WORDS * MASTER_WORD_BYTES + MASTER_WORDS + MASTER_DIGITS
        );
        assert_eq!(MASTER_PASSWORD_CHARS, 38);
        const { assert!(MASTER_PASSWORD_CHARS <= MAX_PASS_CHARS) };
        const { assert!(MASTER_PASSWORD_CHARS >= MIN_PASS_CHARS) };
    }

    #[test]
    fn password_alphabet_has_no_ambiguous_glyphs() {
        // The documented promise: no l/I/1/0/O.
        for bad in *b"lI10O" {
            assert!(
                !PASSWORD_ALPHABET.contains(&bad),
                "ambiguous glyph {:?} is in the alphabet",
                bad as char
            );
        }
    }

    #[test]
    fn password_alphabet_is_printable_and_unique() {
        let mut seen = [false; 256];
        for &b in PASSWORD_ALPHABET {
            assert!((0x21..=0x7E).contains(&b), "non-printable byte {b:#04x}");
            assert!(!seen[b as usize], "duplicate byte {b:#04x} in the alphabet");
            seen[b as usize] = true;
        }
        assert!(
            PASSWORD_ALPHABET.len() > 32,
            "alphabet is suspiciously short"
        );
    }

    #[test]
    fn keyfile_constants() {
        assert_eq!(KEYFILE_MAX_BYTES, 4096);
        assert_eq!(KEYFILE_GENERATED_BYTES, 32);
        // 32 raw random bytes is the KeePass key-file convention, so a file
        // minted by the device opens a real KeePass database.
        assert_eq!(KEYFILE_GENERATED_BYTES, 32);
        const { assert!(KEYFILE_GENERATED_BYTES <= KEYFILE_MAX_BYTES) };
    }

    #[test]
    fn auth_constants() {
        assert_eq!(NONCE_LEN, 32);
        assert_eq!(HMAC_KEY_LEN, 32);
        assert_eq!(HMAC_LEN, 32);
        assert_eq!(AUTH_MAX_FAIL, 5);
        assert_eq!(AUTH_LOCKOUT_MS, 60_000);
        assert_eq!(SESSION_TTL_MS, 900_000);
        assert_eq!(SESSION_TOKEN_LEN, 32);
    }

    #[test]
    fn tls_constants() {
        assert_eq!(TLS_CA_CN, "QuipuChip CA");
        assert_eq!(TLS_LEAF_CN, "QuipuChip");
        assert_eq!(TLS_VALID_FROM_UNIX, 1_577_836_800);
        assert_eq!(TLS_VALID_UNTIL_UNIX, 4_102_444_800);
        const { assert!(TLS_VALID_FROM_UNIX < TLS_VALID_UNTIL_UNIX) };
        assert_eq!(TLS_KEY_BYTES, 32);
        assert_eq!(TLS_ENTROPY_ATTEMPTS, 64);
        assert_eq!(TLS_OID_SERVER_AUTH, "1.3.6.1.5.5.7.3.1");
        assert_eq!(TLS_OID_ECDSA_SHA256, "1.2.840.10045.4.3.2");
        assert_eq!(TLS_BLOB_HEADER_BYTES, 32);
        assert_eq!(TLS_BLOB_HASH_BYTES, 32);
        assert_eq!(TLS_PARTITION_BYTES, 64 * 1024);
    }

    #[test]
    fn firmware_version_is_a_dotted_triple() {
        let parts: Vec<&str> = FIRMWARE_VERSION.split('.').collect();
        assert_eq!(parts.len(), 3, "version {FIRMWARE_VERSION}");
        for p in parts {
            assert!(!p.is_empty(), "empty component in {FIRMWARE_VERSION}");
            assert!(
                p.bytes().all(|b| b.is_ascii_digit()),
                "non-numeric component in {FIRMWARE_VERSION}"
            );
        }
    }
}
