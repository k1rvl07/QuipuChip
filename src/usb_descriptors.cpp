#include <string.h>

#include "tusb.h"

#include "config.h"
#include "logger.h"
#include "usb_stack.h"

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
    .bcdUSB = 0x0200,
    .bDeviceClass = TUSB_CLASS_MISC,
    .bDeviceSubClass = MISC_SUBCLASS_COMMON,
    .bDeviceProtocol = MISC_PROTOCOL_IAD,
    .bMaxPacketSize0 = pm::config::kUsbMaxPacketSize0,
    .idVendor = pm::config::kUsbVid,
    .idProduct = pm::config::kUsbPid,
    .bcdDevice = 0x0100,
    .iManufacturer = STRID_MANUF,
    .iProduct = STRID_PRODUCT,
    .iSerialNumber = STRID_SERIAL,
    .bNumConfigurations = 1,
};

static const uint8_t desc_config[] = {
    TUD_CONFIG_DESCRIPTOR(1, ITF_COUNT, 0, CONFIG_TOTAL_LEN, TUSB_DESC_CONFIG_ATT_REMOTE_WAKEUP, 100),
    TUD_CDC_NCM_DESCRIPTOR(0, STRID_NCM, STRID_MAC, pm::config::kUsbEpInterrupt,
                           pm::config::kUsbEpInterruptSize, pm::config::kUsbEpBulkOut,
                           pm::config::kUsbEpBulkIn, pm::config::kUsbEpBulkSize,
                           pm::config::kNcmMaxSegmentSize),
};

static_assert(sizeof(desc_config) == CONFIG_TOTAL_LEN, "config descriptor length mismatch");

static char const* string_desc_arr[] = {
    nullptr,
    pm::config::kUsbManufacturer,
    pm::config::kUsbProduct,
    "",
    pm::config::kUsbNcmInterface,
    "",
};

static uint16_t desc_str[32 + 1];

static bool s_macLogged = false;

static size_t build_mac_utf16le(uint8_t const* mac, uint16_t* out, size_t cap) {
  static const char kHex[] = "0123456789ABCDEF";
  // CDC ECM/NCM string for iMacAddress: kernel expects exactly 12 hex chars (no colons)
  const size_t need = pm::usb::kMacLen * 2; // 12
  if (cap < need + 1) return 0;
  for (size_t i = 0; i < pm::usb::kMacLen; ++i) {
    out[i * 2] = kHex[mac[i] >> 4];
    out[i * 2 + 1] = kHex[mac[i] & 0x0F];
  }
  out[need] = '\0';
  return need;
}

extern "C" uint8_t const* tud_descriptor_device_cb(void) {
  ++pm::usb::diag().descDevice;
  return (uint8_t const*)&desc_device;
}

extern "C" uint8_t const* tud_descriptor_configuration_cb(uint8_t index) {
  (void)index;
  ++pm::usb::diag().descConfig;
  return desc_config;
}

extern "C" uint16_t const* tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
  (void)langid;
  ++pm::usb::diag().descString;

  if (index == STRID_LANGID) {
    ++pm::usb::diag().strLangidReqs;
    desc_str[0] = static_cast<uint16_t>((TUSB_DESC_STRING << 8) | 4);
    desc_str[1] = 0x0409;
    return desc_str;
  }

  if (index == STRID_MAC) {
    ++pm::usb::diag().strMacReqs;
    uint8_t mac_bytes[pm::usb::kMacLen];
    pm::usb::macAddress(mac_bytes);
    size_t n = build_mac_utf16le(mac_bytes, desc_str + 1, 31);
    pm::usb::diag().strMacLen = static_cast<uint32_t>(n);
    if (n == 0) {
      desc_str[0] = static_cast<uint16_t>((TUSB_DESC_STRING << 8) | 4);
      desc_str[1] = ' ';
      n = 1;
    } else {
      // bLength = 2 (заголовок) + 2 * символов. TinyUSB шлёт ровно bLength
      // байт (usbd.c: tu_desc_len(desc_str)); без +2 хост получал на один
      // символ меньше, и usb_string() возвращал 11 вместо 12 -> bind падал.
      desc_str[0] = static_cast<uint16_t>((TUSB_DESC_STRING << 8) | (2u * n + 2));
    }
    if (!s_macLogged) {
      s_macLogged = true;
      pm::log::info("mac-str idx5 n %u bLength %u — %02x%02x%02x%02x%02x%02x", n,
                    (unsigned)(desc_str[0] & 0xFFu), mac_bytes[0], mac_bytes[1],
                    mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]);
    }
    return desc_str;
  }

  const char* s = nullptr;
  if (index < sizeof(string_desc_arr) / sizeof(string_desc_arr[0])) {
    s = string_desc_arr[index];
  }
  if (s == nullptr) s = "";
  uint8_t len = 0;
  while (s[len] && len < 31) {
    desc_str[1 + len] = static_cast<uint16_t>(s[len]);
    ++len;
  }
  // bLength включает 2-байтовый заголовок (см. комментарий выше по STRID_MAC).
  desc_str[0] = static_cast<uint16_t>((TUSB_DESC_STRING << 8) | (2u * len + 2));
  return desc_str;
}
