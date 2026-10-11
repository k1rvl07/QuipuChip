// USB descriptors and TinyUSB device/network callbacks for PassManager.
//
// Ported one-for-one from the reference src/usb_descriptors.cpp and the
// TinyUSB callbacks at the bottom of src/usb_stack.cpp. Kept in C because the
// NCM configuration descriptor is built from the TUD_* preprocessor macros.
//
// The numeric values mirror include/config.h (kUsb* / kNcm*). They are repeated
// literally here instead of including the C++ config header, which pulls in
// <string> and other host headers this component must not depend on.

#include <string.h>

#include "soc/gpio_sig_map.h"
#include "soc/system_struct.h"
#include "soc/usb_periph.h"
#include "esp_rom_gpio.h"
#include "hal/gpio_ll.h"
#include "tusb.h"

#include "pm_usb.h"

#define PM_USB_VID 0x303A
#define PM_USB_PID 0x4001
#define PM_USB_BCD_USB 0x0200
#define PM_USB_BCD_DEVICE 0x0100
#define PM_USB_MAX_PACKET_SIZE0 64
#define PM_USB_EP_INTERRUPT 0x81
#define PM_USB_EP_INTERRUPT_SIZE 16
#define PM_USB_EP_BULK_IN 0x82
#define PM_USB_EP_BULK_OUT 0x02
#define PM_USB_EP_BULK_SIZE 64
#define PM_NCM_MAX_SEGMENT_SIZE 1514

enum {
  STRID_LANGID = 0,
  STRID_MANUF = 1,
  STRID_PRODUCT = 2,
  STRID_SERIAL = 3,
  STRID_NCM = 4,
  STRID_MAC = 5,
};

enum { ITF_COUNT = 2 };

#define CONFIG_TOTAL_LEN (TUD_CONFIG_DESC_LEN + TUD_CDC_NCM_DESC_LEN)

static const tusb_desc_device_t desc_device = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = PM_USB_BCD_USB,
    .bDeviceClass = TUSB_CLASS_MISC,
    .bDeviceSubClass = MISC_SUBCLASS_COMMON,
    .bDeviceProtocol = MISC_PROTOCOL_IAD,
    .bMaxPacketSize0 = PM_USB_MAX_PACKET_SIZE0,
    .idVendor = PM_USB_VID,
    .idProduct = PM_USB_PID,
    .bcdDevice = PM_USB_BCD_DEVICE,
    .iManufacturer = STRID_MANUF,
    .iProduct = STRID_PRODUCT,
    .iSerialNumber = STRID_SERIAL,
    .bNumConfigurations = 1,
};

static const uint8_t desc_config[] = {
    TUD_CONFIG_DESCRIPTOR(1, ITF_COUNT, 0, CONFIG_TOTAL_LEN,
                          TUSB_DESC_CONFIG_ATT_REMOTE_WAKEUP, 100),
    TUD_CDC_NCM_DESCRIPTOR(0, STRID_NCM, STRID_MAC, PM_USB_EP_INTERRUPT,
                           PM_USB_EP_INTERRUPT_SIZE, PM_USB_EP_BULK_OUT,
                           PM_USB_EP_BULK_IN, PM_USB_EP_BULK_SIZE,
                           PM_NCM_MAX_SEGMENT_SIZE),
};

_Static_assert(sizeof(desc_config) == CONFIG_TOTAL_LEN,
               "NCM config descriptor length mismatch");

static const char *const string_desc_arr[] = {
    NULL,   "PassManager",      "PassManager NCM", "",
    "NCM",  "",
};

static uint16_t desc_str[32 + 1];

static uint8_t s_mac[6] = {0};
static bool s_mac_set = false;
static bool s_mac_logged = false;
static bool s_mounted = false;
static bool s_link = false;

void pm_usb_set_mac(const uint8_t mac[6]) {
  for (int i = 0; i < 6; ++i) s_mac[i] = mac[i];
  s_mac_set = true;
}

void pm_usb_release_domain(void) {
  // The block powers up in reset with its clock gated. Clear reset first, then
  // enable the clock, so the following controller writes are not dropped.
  SYSTEM.perip_rst_en0.usb_rst = 0;
  SYSTEM.perip_clk_en0.usb_clk_en = 1;
}

// Force the OTG session/ID signals that the internal FSLS PHY does not drive by
// itself. Ported from the reference configure_pins() (Arduino usb_hal): with the
// internal PHY the only non-external entries in usb_periph_iopins are constant
// inputs, and wiring IDDIG/VBUSVALID/BVALID high and AVALID low is what lets the
// controller accept a session and pull D+ up. usb_new_phy() (IDF 5.5) does not
// do this, which is why the host never saw the device enumerate.
void pm_usb_route_pins(void) {
  for (const usb_iopin_dsc_t *iopin = usb_periph_iopins; iopin->pin != -1;
       ++iopin) {
    // Internal PHY only: the real GPIO pads are for an external PHY.
    if (iopin->ext_phy_only) continue;

    // Constant-input selector (not a real pad): wire it to the signal and stop.
    if (iopin->pin == GPIO_MATRIX_CONST_ONE_INPUT ||
        iopin->pin == GPIO_MATRIX_CONST_ZERO_INPUT) {
      esp_rom_gpio_connect_in_signal(iopin->pin, iopin->func, false);
      continue;
    }

    esp_rom_gpio_pad_select_gpio(iopin->pin);
    if (iopin->is_output) {
      esp_rom_gpio_connect_out_signal(iopin->pin, iopin->func, false, false);
    } else {
      esp_rom_gpio_connect_in_signal(iopin->pin, iopin->func, false);
      gpio_ll_input_enable(&GPIO, iopin->pin);
    }
    esp_rom_gpio_pad_unhold(iopin->pin);
  }
}

bool pm_usb_mounted(void) { return s_mounted; }
bool pm_usb_link(void) { return s_link; }

// 12 uppercase hex chars, no colons: this is what the Linux cdc_ncm/CDC-ECM
// iMACAddress parser expects.
static size_t build_mac_utf16le(const uint8_t *mac, uint16_t *out, size_t cap) {
  static const char kHex[] = "0123456789ABCDEF";
  const size_t need = 6 * 2;
  if (cap < need + 1) return 0;
  for (size_t i = 0; i < 6; ++i) {
    out[i * 2] = (uint16_t)kHex[mac[i] >> 4];
    out[i * 2 + 1] = (uint16_t)kHex[mac[i] & 0x0F];
  }
  out[need] = '\0';
  return need;
}

uint8_t const *tud_descriptor_device_cb(void) {
  return (uint8_t const *)&desc_device;
}

uint8_t const *tud_descriptor_configuration_cb(uint8_t index) {
  (void)index;
  return desc_config;
}

uint16_t const *tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
  (void)langid;

  if (index == STRID_LANGID) {
    desc_str[0] = (uint16_t)((TUSB_DESC_STRING << 8) | 4);
    desc_str[1] = 0x0409;
    return desc_str;
  }

  if (index == STRID_MAC) {
    size_t n = 0;
    if (s_mac_set) {
      n = build_mac_utf16le(s_mac, desc_str + 1, 31);
    }
    if (n == 0) {
      desc_str[0] = (uint16_t)((TUSB_DESC_STRING << 8) | 4);
      desc_str[1] = ' ';
      n = 1;
    } else {
      // bLength = 2 header bytes + 2 per character. TinyUSB sends exactly
      // bLength bytes; omitting the +2 made the host read 11 instead of 12
      // characters and cdc_ncm could not bind.
      desc_str[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2u * n + 2));
    }
    if (!s_mac_logged) {
      s_mac_logged = true;
      pm_usb_log("mac-str idx5");
    }
    return desc_str;
  }

  const char *s = NULL;
  if (index < sizeof(string_desc_arr) / sizeof(string_desc_arr[0])) {
    s = string_desc_arr[index];
  }
  if (s == NULL) s = "";
  uint8_t len = 0;
  while (s[len] && len < 31) {
    desc_str[1 + len] = (uint16_t)s[len];
    ++len;
  }
  desc_str[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2u * len + 2));
  return desc_str;
}

// --- TinyUSB device callbacks -----------------------------------------------

void tud_mount_cb(void) {
  s_mounted = true;
  pm_usb_log("usb: mounted");
}

void tud_umount_cb(void) {
  s_mounted = false;
  s_link = false;
  pm_usb_log("usb: unmounted");
}

void tud_network_init_cb(void) { pm_usb_log("ncm: init"); }

void tud_network_link_state_cb(bool state) {
  s_link = state;
  pm_usb_log(state ? "ncm: link up" : "ncm: link down");
}

bool tud_network_recv_cb(const uint8_t *src, uint16_t size) {
  // TinyUSB 0.16 discards this return value (ncm_device.c calls the callback
  // without checking), so the frame must be consumed here: either handed to the
  // bridge (copied) or deliberately dropped.
  pm_net_on_frame(src, size);

  // Mandatory renew: handle_incoming_datagram() calls tud_network_recv_renew()
  // exactly once and it feeds one datagram. Without this call the next renew
  // never happens, the OUT transfer is not re-armed, and RX freezes at 1.
  tud_network_recv_renew();
  return true;
}

uint16_t tud_network_xmit_cb(uint8_t *dst, void *ref, uint16_t arg) {
  if (ref == NULL || arg == 0) return 0;
  memcpy(dst, ref, arg);
  return arg;
}
