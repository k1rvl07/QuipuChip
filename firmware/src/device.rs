//! Device identity: the factory MAC in the byte order the vault KDF expects.
//!
//! The vault derives its device factor from `HMAC(DEVICE_LABEL, mac_reversed)`
//! where `mac_reversed` is the canonical MAC in reverse byte order. For this
//! board (`7c:0c:5f:5b:21:44`) that is `44 21 5b 5f 0c 7c`.

use esp_hal::efuse;

/// Canonical WiFi-station MAC, reversed for the device factor.
///
/// Returns `None` when the eFuse MAC is unreadable or all zero, which must be
/// treated as a hard failure rather than falling back to a guess.
pub fn reversed_mac6() -> Option<[u8; 6]> {
    let base = efuse::base_mac_address();
    let bytes = base.as_bytes();
    if bytes.len() != 6 || bytes.iter().all(|&b| b == 0) {
        return None;
    }

    let mut out = [0u8; 6];
    for (slot, &byte) in out.iter_mut().zip(bytes.iter().rev()) {
        *slot = byte;
    }
    Some(out)
}

/// The MAC advertised to the USB host as the NCM interface address.
///
/// Same reversed factory MAC, with the locally-administered bit set and the
/// multicast bit cleared on the first byte.
pub fn usb_mac6() -> [u8; 6] {
    match reversed_mac6() {
        Some(mut m) => {
            m[0] = (m[0] | 0x02) & 0xFE;
            m
        }
        None => [0x7C, 0xDF, 0xA1, 0x00, 0x00, 0x01],
    }
}
