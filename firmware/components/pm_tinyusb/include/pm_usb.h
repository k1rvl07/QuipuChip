#pragma once

#include <stdbool.h>
#include <stdint.h>

// Bridge between the vendored TinyUSB component (C) and the Rust firmware.
//
// Descriptors and the TinyUSB device/network callbacks live in C because the
// NCM configuration descriptor is assembled by the TUD_* macros, which are
// preprocessor-only. The Rust side owns everything else (PHY bring-up, the
// tud_task loop, the esp_netif bridge) and injects the NCM MAC here.

#ifdef __cplusplus
extern "C" {
#endif

// Set the 6-byte MAC used for the iMACAddress string descriptor (STRID_MAC).
void pm_usb_set_mac(const uint8_t mac[6]);

// Lift the USB_OTG peripheral out of reset and enable its clock. On ESP32-S3
// the block starts held in reset with its clock gated, and dcd_init() writes to
// the controller are silently dropped until this is done — it must run before
// tusb_init()/usb_new_phy(). Ported from the reference releaseUsbDomain().
void pm_usb_release_domain(void);

// Wire the OTG session/ID control signals (constant inputs) the internal FSLS
// PHY does not drive by itself. Ported from the reference configure_pins();
// must run after usb_new_phy() and before tusb_init().
void pm_usb_route_pins(void);

// Mount/link state latched by tud_mount_cb()/tud_umount_cb() and
// tud_network_link_state_cb().
bool pm_usb_mounted(void);
bool pm_usb_link(void);

// Provided by Rust.
//
// Deliver a received Ethernet frame to the network bridge. Must copy if it keeps
// the data: `src` points at TinyUSB's receive buffer, which is reused right
// after this returns.
bool pm_net_on_frame(const uint8_t *src, uint16_t size);

// Route a short diagnostic string through the Rust logger.
void pm_usb_log(const char *msg);

#ifdef __cplusplus
}
#endif
