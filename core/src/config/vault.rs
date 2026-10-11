//! Vault partition layout, container magic and entry limits.

/// On-flash vault container magic (`PMV1`).
pub const VAULT_MAGIC: [u8; 4] = *b"PMV1";
/// Export container magic (`PMX1`).
pub const EXPORT_MAGIC: [u8; 4] = *b"PMX1";
/// Export format version; grows on incompatible layout changes.
pub const EXPORT_VERSION: u32 = 1;

/// Vault partition capacity (512 KiB, see `partitions.csv`).
pub const VAULT_PARTITION_BYTES: usize = 512 * 1024;
/// Header occupies exactly one SPI flash page.
pub const VAULT_HEADER_BYTES: usize = 256;
/// Erase granularity of the SPI flash.
pub const FLASH_SECTOR_BYTES: usize = 4096;
/// Each header slot owns its own sector: writing a slot requires an erase.
pub const VAULT_HEADER_SLOT_BYTES: usize = FLASH_SECTOR_BYTES;
/// Number of alternating header slots.
pub const VAULT_HEADER_SLOTS: usize = 2;
/// Journal regions begin after both header slots.
pub const VAULT_REGION0_OFFSET: usize = VAULT_HEADER_SLOT_BYTES * VAULT_HEADER_SLOTS;
/// Usable size of one journal region, rounded down to a sector multiple.
pub const VAULT_REGION_BYTES: usize =
    ((VAULT_PARTITION_BYTES - VAULT_REGION0_OFFSET) / 2 / FLASH_SECTOR_BYTES) * FLASH_SECTOR_BYTES;
/// Compaction is triggered once half of a region is in use.
pub const VAULT_COMPACT_TRIGGER_BYTES: usize = VAULT_REGION_BYTES / 2;
/// Hard byte budget for live payload data.
pub const VAULT_LIVE_BUDGET_BYTES: usize = 192 * 1024;

/// Longest serialized record accepted by the vault.
pub const MAX_ENTRY_LEN: usize = 1280;
/// Maximum number of live entries.
pub const MAX_ENTRIES: u32 = 1000;

/// Entries per `POST /api/import` request.
pub const IMPORT_BATCH_ENTRIES: usize = 4;
