#include "psram.h"

#include <Arduino.h>
#include <esp_err.h>
#include <esp_heap_caps.h>
#include <string.h>

#include "esp32s3/spiram.h"

#include "config.h"
#include "logger.h"

namespace pm {
namespace {

size_t chipBytes() { return esp_spiram_get_size(); }

}  // namespace

bool initPsram() {
#if defined(CONFIG_SPIRAM_BOOT_INIT)
  if (chipBytes() == 0) {
    // HAL при CONFIG_SPIRAM_BOOT_INIT=1 этот блок пропускает, а bootloader
    // ESP32-S3 из пакета PSRAM не поднимает — делаем это сами.
    if (esp_spiram_init() != ESP_OK) {
      log::error("psram init failed");
      return false;
    }
    esp_spiram_init_cache();
    if (!esp_spiram_test()) {
      log::error("psram test failed");
      return false;
    }
    if (esp_spiram_add_to_heapalloc() != ESP_OK) {
      log::error("psram not added to heap");
      return false;
    }
#if defined(CONFIG_SPIRAM_USE_MALLOC) && !defined(CONFIG_ARDUINO_ISR_IRAM)
    heap_caps_malloc_extmem_enable(CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL);
#endif
  }

  void* probe = heap_caps_malloc(config::kPsramProbeBytes, MALLOC_CAP_SPIRAM);
  if (probe == nullptr) {
    log::error("psram alloc %u KB failed", static_cast<unsigned>(config::kPsramProbeBytes >> 10));
    return false;
  }
  memset(probe, 0xA5, config::kPsramProbeBytes);
  const uint8_t* bytes = static_cast<const uint8_t*>(probe);
  bool ok = true;
  for (size_t i = 0; i < config::kPsramProbeBytes; ++i) {
    if (bytes[i] != 0xA5) {
      ok = false;
      break;
    }
  }
  heap_caps_free(probe);

  log::info("psram chip %u MB heap %u MB block %u KB probe %s",
            static_cast<unsigned>(chipBytes() >> 20), static_cast<unsigned>(ESP.getPsramSize() >> 20),
            static_cast<unsigned>(heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM) >> 10),
            ok ? "ok" : "MISMATCH");
  return ok;
#else
  return ESP.getPsramSize() != 0;
#endif
}

}  // namespace pm
