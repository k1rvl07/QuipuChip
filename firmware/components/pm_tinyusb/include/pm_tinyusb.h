#pragma once

// Bindings entry for the vendored NCM-only TinyUSB component.
//
// tusb.h exposes the whole device API we drive from Rust: tusb_init(),
// tud_task_ext(), tud_ready()/tud_suspended(), the NCM network hooks
// (tud_network_*), and the descriptor callbacks (tud_descriptor_*). The
// esp_private USB PHY header provides usb_new_phy()/usb_del_phy(), which is
// what the Arduino core's tinyusb_driver_install() used to bring the internal
// PHY up before tusb_init().
//
// CFG_TUSB_OS_INC_PATH must be set here as well: bindgen parses this header
// with its own clang invocation that does not inherit the component's
// compile definitions, and tusb_option.h only defines it when absent. Without
// it, the FreeRTOS OSAL include resolves to FreeRTOS.h instead of
// freertos/FreeRTOS.h and bindgen cannot find the kernel headers.
#define CFG_TUSB_OS_INC_PATH freertos/

#include "tusb.h"
#include "esp_private/usb_phy.h"
#include "pm_usb.h"
