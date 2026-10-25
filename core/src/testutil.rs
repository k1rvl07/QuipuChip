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

    /// Rebuilds a partition from a raw image, e.g. to simulate a reboot: the
    /// same flash contents seen by a fresh [`crate::vault::Vault`].
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Raw image of the partition.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::VAULT_PARTITION_BYTES;

    #[test]
    fn new_partition_is_fully_erased() {
        let s = MemStorage::new(4096);
        assert_eq!(s.size(), 4096);
        let mut buf = [0u8; 4096];
        assert_eq!(s.read(0, &mut buf), Ok(()));
        assert!(buf.iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn write_can_only_clear_bits() {
        // The one property the vault relies on: a rewrite that would need to
        // raise a bit is silently lost. Reproducing it here is the only way a
        // host test can catch a regression in that assumption.
        let mut s = MemStorage::new(16);
        assert_eq!(s.write(0, &[0b0000_1111]), Ok(()));
        let mut buf = [0u8; 1];
        assert_eq!(s.read(0, &mut buf), Ok(()));
        assert_eq!(buf[0], 0b0000_1111);

        // Raising a bit: 0b0000_1111 -> 0b1111_1111 must NOT take effect.
        assert_eq!(s.write(0, &[0b1111_1111]), Ok(()));
        assert_eq!(s.read(0, &mut buf), Ok(()));
        assert_eq!(buf[0], 0b0000_1111);

        // Clearing more bits does take effect.
        assert_eq!(s.write(0, &[0b0000_0000]), Ok(()));
        assert_eq!(s.read(0, &mut buf), Ok(()));
        assert_eq!(buf[0], 0b0000_0000);
    }

    #[test]
    fn erase_restores_the_erased_state() {
        let mut s = MemStorage::new(16);
        assert_eq!(s.write(4, &[0x00, 0x00]), Ok(()));
        assert_eq!(s.erase(4, 2), Ok(()));
        let mut buf = [0u8; 2];
        assert_eq!(s.read(4, &mut buf), Ok(()));
        assert_eq!(&buf, &[0xFF, 0xFF]);
    }

    #[test]
    fn read_write_erase_reject_out_of_range_access() {
        let mut s = MemStorage::new(16);
        let mut buf = [0u8; 4];

        assert_eq!(s.read(13, &mut buf), Err(VaultError::Io));
        assert_eq!(s.read(16, &mut buf), Err(VaultError::Io));
        assert_eq!(s.read(usize::MAX, &mut buf), Err(VaultError::Io));
        assert_eq!(s.write(13, &buf), Err(VaultError::Io));
        assert_eq!(s.write(usize::MAX, &buf), Err(VaultError::Io));
        assert_eq!(s.erase(13, 4), Err(VaultError::Io));
        assert_eq!(s.erase(usize::MAX, 4), Err(VaultError::Io));
    }

    #[test]
    fn a_zero_length_access_at_the_end_is_allowed() {
        let mut s = MemStorage::new(16);
        let mut buf: [u8; 0] = [];
        assert_eq!(s.read(16, &mut buf), Ok(()));
        assert_eq!(s.write(16, &buf), Ok(()));
        assert_eq!(s.erase(16, 0), Ok(()));
    }

    #[test]
    fn the_test_vault_has_the_real_partition_size() {
        let v = vault();
        assert_eq!(v.storage_ref().size(), VAULT_PARTITION_BYTES);
    }
}
