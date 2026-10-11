# Vendored NCM-only TinyUSB (lib/tinyusb/src in the repo) as a local ESP-IDF
# component. The trimmed tree mirrors the PlatformIO build one-for-one: the
# same 27 files, the same tusb_config.h (CFG_TUD_NCM=1, everything else 0),
# the same esp32sx DCD portable driver. Keeping the file list explicit means a
# future TinyUSB bump cannot silently pull in classes we did not vet.
set(PM_TINYUSB "${CMAKE_CURRENT_LIST_DIR}/../../../lib/tinyusb/src")

idf_component_register(
    SRCS
        "${PM_TINYUSB}/tusb.c"
        "${PM_TINYUSB}/common/tusb_fifo.c"
        "${PM_TINYUSB}/device/usbd.c"
        "${PM_TINYUSB}/device/usbd_control.c"
        "${PM_TINYUSB}/class/net/ncm_device.c"
        "${PM_TINYUSB}/portable/espressif/esp32sx/dcd_esp32sx.c"
        "${CMAKE_CURRENT_LIST_DIR}/pm_usb.c"
    INCLUDE_DIRS
        "${PM_TINYUSB}"
        "${PM_TINYUSB}/class/cdc"
        "${PM_TINYUSB}/class/hid"
        "include"
    REQUIRES
        soc
        esp_hw_support
        esp_timer
        driver
        usb
        freertos
        hal
        esp_system
)

# The vendored tusb_config.h was written for the Arduino core, whose freertos
# component exposed FreeRTOS.h at the top level. ESP-IDF nests kernel headers
# under freertos/, so we point TinyUSB's OSAL include prefix there rather than
# editing the vendored (reference) config file.
# CFG_TUSB_OS_INC_PATH is token-pasted with the file name by TU_INCLUDE_PATH,
# so it must be a bare prefix (freertos/), not a quoted string.
target_compile_definitions(${COMPONENT_LIB} PRIVATE CFG_TUSB_OS_INC_PATH=freertos/)

# The vendored esp32sx DCD driver was written against the IDF 4.4 SoC headers
# shipped with the reference Arduino core. Two things changed in IDF 5.5:
#   1. soc/usb_struct.h (defines USB0) and soc/usb_reg.h (defines the USB_*_M
#      bit masks) are no longer pulled in transitively by the headers the driver
#      includes, so force-include them.
#   2. USB_OUT_EP_NUM (the DWC2 endpoint count) was removed from soc/usb_types.h;
#      it was 7 in the reference headers (USB_OUT_EP_0..6 then _NUM). The driver
#      only uses it to size its endpoint table and bound loops.
# Both are supplied here rather than by editing the vendored (reference) tree.
set_source_files_properties(
    "${PM_TINYUSB}/portable/espressif/esp32sx/dcd_esp32sx.c"
    PROPERTIES
        COMPILE_OPTIONS "-include;soc/usb_struct.h;-include;soc/usb_reg.h;-DUSB_OUT_EP_NUM=7;-DUSB_IN_EP_NUM=7"
)
