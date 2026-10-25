//! Flash semantics: MemStorage enforces AND-only writes and erase to 0xFF.

#![cfg(feature = "test-utils")]
#![allow(clippy::unwrap_used)]

use pm_core::testutil::MemStorage;
use pm_core::types::VaultError;
use pm_core::vault::Storage;

#[test]
fn and_only_write_cannot_raise_bits() {
    let mut s = MemStorage::new(64);
    assert_eq!(s.write(0, &[0b0000_1111]), Ok(()));
    let mut buf = [0u8; 1];
    s.read(0, &mut buf).unwrap();
    assert_eq!(buf[0], 0b0000_1111);
    s.write(0, &[0b1111_1111]).unwrap();
    s.read(0, &mut buf).unwrap();
    assert_eq!(buf[0], 0b0000_1111);
    s.write(0, &[0b0000_0011]).unwrap();
    s.read(0, &mut buf).unwrap();
    assert_eq!(buf[0], 0b0000_0011);
}

#[test]
fn erase_fills_with_0xff() {
    let mut s = MemStorage::new(4096);
    s.write(100, &[0x00, 0xAA]).unwrap();
    s.erase(0, 4096).unwrap();
    let mut buf = [0u8; 4096];
    s.read(0, &mut buf).unwrap();
    assert!(buf.iter().all(|&b| b == 0xFF));
}

#[test]
fn out_of_bounds_rejected() {
    let mut s = MemStorage::new(16);
    let mut buf = [0u8; 4];
    assert_eq!(s.read(13, &mut buf), Err(VaultError::Io));
    assert_eq!(s.write(13, &[0; 4]), Err(VaultError::Io));
    assert_eq!(s.erase(13, 4), Err(VaultError::Io));
}

#[test]
fn from_bytes_to_bytes_roundtrip() {
    let data = vec![0x5Au8; 256];
    let s = MemStorage::from_bytes(data.clone());
    assert_eq!(s.to_bytes(), data);
}
