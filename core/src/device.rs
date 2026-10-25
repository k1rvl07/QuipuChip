//! Device factor, ported from the removed C++ reference.
//!
//! The factor is `HMAC-SHA256(mac6, "pm-vault-device" || salt_dev)`: a 32-byte
//! key derived from the factory MAC and the per-vault salt. The MAC is read at
//! call time and never stored.
//!
//! Byte order matters for PMV1 compatibility. The C++ reference writes
//! `mac[i] = efuseMac >> ((5 - i) * 8)` where `efuseMac` is `ESP.getEfuseMac()`
//! (little-endian packing of the canonical MAC bytes). The net effect is that
//! the HMAC key is the canonical MAC in **reverse** order: for the board MAC
//! `7c:0c:5f:5b:21:44` the key bytes are `44 21 5b 5f 0c 7c`. The firmware crate
//! is responsible for producing `mac6` in exactly this order.

use crate::config::PBKDF2_SALT_LEN;
use crate::crypto::hmac_sha256;

/// Domain-separation label; length is fixed and part of the MACed message.
pub const DEVICE_LABEL: &[u8] = b"pm-vault-device";

/// Errors from deriving the device factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceError {
    /// `mac6` was all zero: the eFuse was not read, so there is no factor.
    NoMac,
    /// Salt is empty or longer than `PBKDF2_SALT_LEN`.
    BadSalt,
}

impl core::fmt::Display for DeviceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            DeviceError::NoMac => "device MAC not available",
            DeviceError::BadSalt => "invalid device salt length",
        })
    }
}

impl core::error::Error for DeviceError {}

/// Derives the device factor from the (already reversed) 6-byte MAC and salt.
pub fn factor(mac6: &[u8; 6], salt_dev: &[u8]) -> Result<[u8; 32], DeviceError> {
    if mac6.iter().all(|&b| b == 0) {
        return Err(DeviceError::NoMac);
    }
    if salt_dev.is_empty() || salt_dev.len() > PBKDF2_SALT_LEN {
        return Err(DeviceError::BadSalt);
    }
    let mut msg = [0u8; DEVICE_LABEL.len() + PBKDF2_SALT_LEN];
    msg[..DEVICE_LABEL.len()].copy_from_slice(DEVICE_LABEL);
    msg[DEVICE_LABEL.len()..DEVICE_LABEL.len() + salt_dev.len()].copy_from_slice(salt_dev);
    let key = hmac_sha256(mac6, &msg[..DEVICE_LABEL.len() + salt_dev.len()]);
    crate::crypto::wipe(&mut msg);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{ct_equal, hmac_sha256};

    #[test]
    fn matches_explicit_hmac_of_label_then_salt() {
        // Board MAC 7c:0c:5f:5b:21:44 reversed by the C++ layout.
        let mac6 = [0x44, 0x21, 0x5b, 0x5f, 0x0c, 0x7c];
        let salt = [1u8; 16];
        let got = factor(&mac6, &salt).unwrap();

        let mut msg = Vec::new();
        msg.extend_from_slice(DEVICE_LABEL);
        msg.extend_from_slice(&salt);
        let want = hmac_sha256(&mac6, &msg);
        assert!(ct_equal(&got, &want));
    }

    #[test]
    fn stable_and_salt_dependent() {
        let s1 = [1u8; 16];
        let s2 = [2u8; 16];
        let f1 = factor(&[0x44, 0x21, 0x5b, 0x5f, 0x0c, 0x7c], &s1).unwrap();
        let f2 = factor(&[0x44, 0x21, 0x5b, 0x5f, 0x0c, 0x7c], &s1).unwrap();
        let f3 = factor(&[0x44, 0x21, 0x5b, 0x5f, 0x0c, 0x7c], &s2).unwrap();
        assert!(ct_equal(&f1, &f2));
        assert!(!ct_equal(&f1, &f3));
    }

    #[test]
    fn rejects_zero_mac_and_bad_salt() {
        assert_eq!(factor(&[0u8; 6], &[1u8; 16]), Err(DeviceError::NoMac));
        let mac = [0x44, 0x21, 0x5b, 0x5f, 0x0c, 0x7c];
        assert_eq!(factor(&mac, &[]), Err(DeviceError::BadSalt));
        assert_eq!(factor(&mac, &[0u8; 17]), Err(DeviceError::BadSalt));
    }

    #[test]
    fn the_domain_label_is_fixed() {
        // The label is MACed into the key; changing it would change every
        // device factor and lock out every existing vault.
        assert_eq!(DEVICE_LABEL, b"pm-vault-device");
        assert_eq!(DEVICE_LABEL.len(), 15);
    }

    #[test]
    fn a_full_length_salt_is_accepted() {
        let mac = [0x44, 0x21, 0x5b, 0x5f, 0x0c, 0x7c];
        assert!(factor(&mac, &[7u8; PBKDF2_SALT_LEN]).is_ok());
        assert_eq!(
            factor(&mac, &[7u8; PBKDF2_SALT_LEN + 1]),
            Err(DeviceError::BadSalt)
        );
    }

    #[test]
    fn a_short_salt_changes_the_factor() {
        // The salt length is part of the MACed message, so a shorter salt is a
        // different factor rather than a padded one.
        let mac = [0x44, 0x21, 0x5b, 0x5f, 0x0c, 0x7c];
        let short = factor(&mac, &[1u8; 8]).unwrap();
        let full = factor(&mac, &[1u8; 16]).unwrap();
        assert!(!ct_equal(&short, &full));
    }

    #[test]
    fn the_mac_order_is_the_reversed_efuse_order() {
        // The C++ reference writes mac[i] = efuseMac >> ((5 - i) * 8), i.e. the
        // canonical MAC 7c:0c:5f:5b:21:44 becomes 44 21 5b 5f 0c 7c.
        let canonical = [0x7c, 0x0c, 0x5f, 0x5b, 0x21, 0x44];
        let mut reversed = canonical;
        reversed.reverse();
        assert_eq!(reversed, [0x44, 0x21, 0x5b, 0x5f, 0x0c, 0x7c]);
        // The factor depends on the order, so the two must not agree.
        let a = factor(&reversed, &[1u8; 16]).unwrap();
        let b = factor(&canonical, &[1u8; 16]).unwrap();
        assert!(!ct_equal(&a, &b));
    }

    #[test]
    fn device_error_messages() {
        assert_eq!(DeviceError::NoMac.to_string(), "device MAC not available");
        assert_eq!(
            DeviceError::BadSalt.to_string(),
            "invalid device salt length"
        );
    }
}
