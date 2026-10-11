//! In-memory flash and helpers shared by the host test modules.
//!
//! `MemStorage` reproduces the only property the vault relies on: writes may
//! only clear bits (`1 -> 0`), and erase sets a sector back to `0xFF`.

use alloc::vec;
use alloc::vec::Vec;

use crate::config::VAULT_PARTITION_BYTES;
use crate::types::VaultError;
use crate::vault::{Storage, Vault};

/// Device MAC in the reversed byte order the vault expects (see
/// [`crate::device::factor`]).
pub const TEST_MAC: [u8; 6] = [0x44, 0x21, 0x5b, 0x5f, 0x0c, 0x7c];

/// A flash partition held in RAM.
pub struct MemStorage {
    data: Vec<u8>,
}

impl MemStorage {
    /// Erased (`0xFF`) partition of `size` bytes.
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0xFF; size],
        }
    }
}

impl Storage for MemStorage {
    fn size(&self) -> usize {
        self.data.len()
    }

    fn read(&self, offset: usize, buf: &mut [u8]) -> Result<(), VaultError> {
        let end = offset.checked_add(buf.len()).ok_or(VaultError::Io)?;
        if end > self.data.len() {
            return Err(VaultError::Io);
        }
        buf.copy_from_slice(&self.data[offset..end]);
        Ok(())
    }

    fn write(&mut self, offset: usize, buf: &[u8]) -> Result<(), VaultError> {
        let end = offset.checked_add(buf.len()).ok_or(VaultError::Io)?;
        if end > self.data.len() {
            return Err(VaultError::Io);
        }
        for (dst, &src) in self.data[offset..end].iter_mut().zip(buf) {
            *dst &= src; // flash can only clear bits
        }
        Ok(())
    }

    fn erase(&mut self, offset: usize, len: usize) -> Result<(), VaultError> {
        let end = offset.checked_add(len).ok_or(VaultError::Io)?;
        if end > self.data.len() {
            return Err(VaultError::Io);
        }
        self.data[offset..end].fill(0xFF);
        Ok(())
    }
}

/// An empty vault over a full-size in-memory partition.
pub fn vault() -> Vault<MemStorage> {
    Vault::new(MemStorage::new(VAULT_PARTITION_BYTES), TEST_MAC)
}
