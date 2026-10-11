//! Raw flash partition backing the PMV1 vault.
//!
//! The C++ reference talks to the `vault` partition directly through
//! `esp_partition_*`, without a filesystem. This mirrors that: a plain
//! [`pm_core::vault::Storage`] over `esp_partition_read/write/erase_range`.
//!
//! The partition pointer is valid for the lifetime of the application, and all
//! access is serialized by the vault mutex, so the raw pointer is sound to
//! share across the worker/HTTP threads.

use core::ffi::c_void;

use esp_idf_svc::sys;
use pm_core::entry::VaultError;
use pm_core::vault::Storage;

pub struct EspVaultStorage {
    part: *const sys::esp_partition_t,
    size: usize,
}

// SAFETY: the partition pointer is an application-lifetime constant and every
// access goes through the serializing vault mutex.
unsafe impl Send for EspVaultStorage {}
unsafe impl Sync for EspVaultStorage {}

impl EspVaultStorage {
    /// Finds the partition by label. Mirrors the C++ `findFirst(..., kFsVault)`.
    pub fn open(label: &str) -> Result<Self, VaultError> {
        let c_label = std::ffi::CString::new(label).map_err(|_| VaultError::Io)?;
        let part = unsafe {
            sys::esp_partition_find_first(
                sys::esp_partition_type_t_ESP_PARTITION_TYPE_DATA,
                sys::esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_ANY,
                c_label.as_ptr(),
            )
        };
        if part.is_null() {
            return Err(VaultError::NotFound);
        }
        let size = unsafe { (*part).size as usize };
        Ok(Self { part, size })
    }

    #[allow(dead_code)]
    pub fn erase_size(&self) -> usize {
        unsafe { (*self.part).erase_size as usize }
    }
}

impl Storage for EspVaultStorage {
    fn size(&self) -> usize {
        self.size
    }

    fn read(&self, offset: usize, buf: &mut [u8]) -> Result<(), VaultError> {
        let rc = unsafe {
            sys::esp_partition_read(
                self.part,
                offset,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
            )
        };
        if rc == sys::ESP_OK {
            Ok(())
        } else {
            Err(VaultError::Io)
        }
    }

    fn write(&mut self, offset: usize, buf: &[u8]) -> Result<(), VaultError> {
        let rc = unsafe {
            sys::esp_partition_write(self.part, offset, buf.as_ptr() as *const c_void, buf.len())
        };
        if rc == sys::ESP_OK {
            Ok(())
        } else {
            Err(VaultError::Io)
        }
    }

    fn erase(&mut self, offset: usize, len: usize) -> Result<(), VaultError> {
        let rc = unsafe { sys::esp_partition_erase_range(self.part, offset, len) };
        if rc == sys::ESP_OK {
            Ok(())
        } else {
            Err(VaultError::Io)
        }
    }
}
