//! Raw flash partition backing the PMV1 vault.
//!
//! The C++ reference talks to the `vault` partition directly through
//! `esp_partition_*`, without a filesystem. This mirrors that on top of
//! `esp-storage`'s [`FlashStorage`].
//!
//! Two flash facts drive the implementation (see `AGENTS.md`):
//!
//! * `write` must reproduce NOR semantics: the stored byte is the bitwise AND
//!   of old and new, so bits only ever go `1 -> 0`. `FlashStorage::write`
//!   erases-then-writes and would silently resurrect bits, so the write path
//!   uses `write_nor` instead.
//! * `write_nor` requires the offset and length to be word aligned, while the
//!   vault writes arbitrary ranges. Each write therefore reads the surrounding
//!   aligned word window, splices the new bytes in, and writes it back. AND
//!   makes the untouched bytes a no-op.

use alloc::vec;
use core::cell::RefCell;

use esp_storage::FlashStorage;
use pm_core::entry::VaultError;
use pm_core::vault::Storage;

const WORD: usize = FlashStorage::WORD_SIZE as usize;

/// A [`Storage`] view over one flash partition.
///
/// The flash peripheral is handed over once and never shared; the vault
/// serialises its own access, so a `RefCell` is enough to satisfy the trait's
/// `read(&self)` / `write(&mut self)` split.
pub struct VaultStorage {
    flash: RefCell<FlashStorage<'static>>,
    base: u32,
    size: usize,
}

impl VaultStorage {
    /// Wraps `flash` as the region `[base, base + size)`.
    ///
    /// `base` and `size` must describe a whole erase-aligned partition; the
    /// vault relies on `esp_partition_erase_range`-compatible boundaries.
    pub fn new(flash: FlashStorage<'static>, base: u32, size: usize) -> Self {
        Self {
            flash: RefCell::new(flash),
            base,
            size,
        }
    }

    pub fn base(&self) -> u32 {
        self.base
    }
}

impl Storage for VaultStorage {
    fn size(&self) -> usize {
        self.size
    }

    fn read(&self, offset: usize, buf: &mut [u8]) -> Result<(), VaultError> {
        let mut flash = self.flash.borrow_mut();
        flash
            .read(self.base + offset as u32, buf)
            .map_err(|_| VaultError::Io)
    }

    fn write(&mut self, offset: usize, buf: &[u8]) -> Result<(), VaultError> {
        if buf.is_empty() {
            return Ok(());
        }

        let start = offset & !(WORD - 1);
        let end = (offset + buf.len() + WORD - 1) & !(WORD - 1);

        let mut window = vec![0xFFu8; end - start];
        let mut flash = self.flash.borrow_mut();
        flash
            .read(self.base + start as u32, &mut window)
            .map_err(|_| VaultError::Io)?;
        window[offset - start..offset - start + buf.len()].copy_from_slice(buf);
        flash
            .write_nor(self.base + start as u32, &window)
            .map_err(|_| VaultError::Io)
    }

    fn erase(&mut self, offset: usize, len: usize) -> Result<(), VaultError> {
        let from = self.base + offset as u32;
        let mut flash = self.flash.borrow_mut();
        flash
            .erase(from, from + len as u32)
            .map_err(|_| VaultError::Io)
    }
}
