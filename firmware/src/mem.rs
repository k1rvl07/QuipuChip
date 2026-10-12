//! Heap setup.
//!
//! Two pools: internal DRAM (task stacks, control state, everything the vault
//! touches while the flash cache is off) and the 8 MB OPI PSRAM found on this
//! board (large working sets, HTTP bodies, the web bundle). The vault payload
//! itself is ciphertext on flash, so buffering it in PSRAM is fine.
//!
//! `esp-alloc`'s global allocator picks the smallest region that fits a
//! request; PSRAM is only reached through the `External` capability, so callers
//! that must live in DRAM simply request less than the internal region holds.

use esp_hal::peripherals::PSRAM;

/// Size of the internal heap carved out for the allocator. Large enough for
/// the vault header/index and the HTTP machinery, small enough to leave DRAM
/// for the RTOS task stacks.
const INTERNAL_HEAP_BYTES: usize = 64 * 1024;

/// Registers the internal and PSRAM regions with the global allocator.
///
/// Must be called exactly once, after `esp_hal::init`, before anything
/// allocates.
pub fn init(psram: PSRAM<'static>) {
    esp_alloc::heap_allocator!(size: INTERNAL_HEAP_BYTES);
    esp_alloc::psram_allocator!(psram, esp_hal::psram);

    let stats = esp_alloc::HEAP.stats();
    log::info!(
        "heap: {} bytes total, {} bytes used",
        stats.size,
        stats.current_usage
    );
}
