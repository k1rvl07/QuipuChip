#pragma once

// Конфиг TinyUSB для PassManager.
//
// Этот файл лежит в -iquote-каталоге (lib/tinyusb/src) и перебивает
// конфиг ядра Arduino: esp32-hal-tinyusb.h включает "tusb_config.h" кавычками,
// порядок поиска для кавычечного include — каталог включающего файла, затем
// -iquote, затем -I. В cores/esp32/ своего tusb_config.h нет, поэтому ours
// выигрывает детерминированно.
//
// PM_OWN_TUSB_CONFIG — сентинел. Если ядро всё-таки подменит конфиг, сборка
// упадёт на #error в src/usb_stack.cpp, а не на загадочных tud_cdc_* в .map.
#define PM_OWN_TUSB_CONFIG 1

#ifdef __cplusplus
extern "C" {
#endif

// MCU: ESP32-S3 использует тот же OPT_MCU_ESP32S2 (tusb_mcu.h:316).
// Мы НЕ включаем sdkconfig.h намеренно: оттуда приехали бы
// CONFIG_TINYUSB_*_ENABLED, среди них CDC_ENABLED=1.
#define CFG_TUSB_MCU OPT_MCU_ESP32S2
#define CFG_TUSB_RHPORT0_MODE OPT_MODE_DEVICE
#define CFG_TUSB_OS OPT_OS_FREERTOS

// Буферы class-драйвера объявлены с CFG_TUSB_MEM_SECTION. На ESP32-S3
// littlefs/usb_ram нет, а PSRAM недоступен для DMA, поэтому оставляем пустым —
// это внутренняя RAM. Размер: transmit_ntb[2] 6400 + receive_ntb 3200 + NDP.
#define CFG_TUSB_MEM_SECTION
#define CFG_TUSB_MEM_ALIGN TU_ATTR_ALIGNED(4)

#define CFG_TUD_MAINTASK_SIZE 8192
#define CFG_TUD_ENDOINT0_SIZE 64

// Единственный включённый класс. Всё остальное — ноль: иначе в линковку
// попадут tud_cdc_*, tud_hid_* и т.д.
#define CFG_TUD_CDC 0
#define CFG_TUD_MSC 0
#define CFG_TUD_HID 0
#define CFG_TUD_MIDI 0
#define CFG_TUD_VIDEO 0
#define CFG_TUD_CUSTOM_CLASS 0
#define CFG_TUD_DFU_RUNTIME 0
#define CFG_TUD_DFU 0
#define CFG_TUD_VENDOR 0
#define CFG_TUD_ECM_RNDIS 0
#define CFG_TUD_NCM 1
// Дефолты самого TinyUSB 0.16.0 (net_device.h:48-60). Эти же макросы
// собирают внутреннюю структуру ntb_parameters в ncm_device.c, поэтому
// дескриптор обязан ссылаться на те же значения — в usb_descriptors.cpp они
// подставляются из CFG_TUD_NCM_* напрямую, а не пишутся числами.
#define CFG_TUD_NCM_IN_NTB_MAX_SIZE 3200
#define CFG_TUD_NCM_OUT_NTB_MAX_SIZE 3200
#define CFG_TUD_NCM_MAX_DATAGRAMS_PER_NTB 8
#define CFG_TUD_NCM_ALIGNMENT 4
#define CFG_TUD_NCM_LOG_LEVEL 0

#ifdef __cplusplus
}
#endif
#ifndef TINYUSB_USE_CUSTOM_DESCRIPTORS
#define TINYUSB_USE_CUSTOM_DESCRIPTORS 1
#endif
#ifndef TUD_USE_CUSTOM_DEVICE_DESCRIPTOR
#define TUD_USE_CUSTOM_DEVICE_DESCRIPTOR 1
#endif
#ifndef TUD_USE_CUSTOM_CONFIG_DESCRIPTOR
#define TUD_USE_CUSTOM_CONFIG_DESCRIPTOR 1
#endif
