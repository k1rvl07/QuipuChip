//! Device factor input: the factory MAC in the byte order the C++ reference
//! feeds to HMAC.
//!
//! `src/device_factor.cpp` builds the HMAC key as
//! `mac[i] = efuseMac >> ((5 - i) * 8)`, i.e. the canonical MAC in **reverse**
//! order. For the board MAC `7c:0c:5f:5b:21:44` the key bytes are
//! `44 21 5b 5f 0c 7c`.

use esp_idf_svc::sys;

/// Reads the canonical WiFi MAC and returns it reversed, ready for
/// `pm_core::device::factor`.
pub fn reversed_mac6() -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];
    let rc = unsafe { sys::esp_read_mac(mac.as_mut_ptr(), sys::esp_mac_type_t_ESP_MAC_WIFI_STA) };
    if rc != sys::ESP_OK || mac.iter().all(|&b| b == 0) {
        return None;
    }
    let mut out = [0u8; 6];
    for (slot, &byte) in out.iter_mut().zip(mac.iter().rev()) {
        *slot = byte;
    }
    Some(out)
}

/// The MAC advertised to the USB host as the NCM interface address.
///
/// `src/usb_stack.cpp::macAddress()` reads the factory MAC through
/// `ESP.getEfuseMac()` (same 6 bytes as `ESP_MAC_WIFI_STA`), reverses them, then
/// sets the locally-administered bit and clears the multicast bit on the first
/// byte: `out[0] = (out[0] | 0x02) & 0xFE`. Falls back to the built-in value
/// when the eFuse is unreadable.
pub fn usb_mac6() -> [u8; 6] {
    match reversed_mac6() {
        Some(mut m) => {
            m[0] = (m[0] | 0x02) & 0xFE;
            m
        }
        None => [0x7C, 0xDF, 0xA1, 0x00, 0x00, 0x01],
    }
}
