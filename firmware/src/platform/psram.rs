//! PSRAM (external SPI RAM) inspection.
//!
//! The entries working set is megabytes, while internal DRAM is scarce, so the
//! firmware routes its buffers to PSRAM and reports both pools. These are the
//! only safe wrappers around the `heap_caps_*` calls.

use esp_idf_svc::sys;

/// Free bytes in the pool selected by `MALLOC_CAP_*` flags.
pub fn free_bytes(caps: u32) -> usize {
    unsafe { sys::heap_caps_get_free_size(caps) }
}

/// Free internal DRAM, where task stacks and control state live.
pub fn dram_free() -> usize {
    free_bytes(sys::MALLOC_CAP_INTERNAL)
}

/// Free external SPI RAM.
pub fn spiram_free() -> usize {
    free_bytes(sys::MALLOC_CAP_SPIRAM)
}

/// Total external SPI RAM.
pub fn spiram_total() -> usize {
    unsafe { sys::heap_caps_get_total_size(sys::MALLOC_CAP_SPIRAM) }
}

/// Size of the largest contiguous external SPI RAM block.
pub fn spiram_largest() -> usize {
    unsafe { sys::heap_caps_get_largest_free_block(sys::MALLOC_CAP_SPIRAM) }
}

/// Whether `ptr` points into external SPI RAM.
pub fn is_external(ptr: *const u8) -> bool {
    unsafe { sys::esp_ptr_external_ram(ptr.cast()) }
}
