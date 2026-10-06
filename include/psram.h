#pragma once

#include <stdbool.h>

namespace pm {

// arduino-esp32 2.0.17: все варианты памяти *_opi (в т.ч. наш qio_opi) собираются
// с CONFIG_SPIRAM_BOOT_INIT=1, и HAL целиком пропускает esp_spiram_init() в
// расчёте на то, что PSRAM поднял bootloader. Ни один из prebuilt bootloader'ов
// ESP32-S3 в пакете framework-arduinoespressif32 PSRAM не инициализирует, поэтому
// поднимаем Octal PSRAM здесь той же последовательностью, что делает HAL.
// В board.json обязателен -DBOARD_HAS_PSRAM: иначе esp32-hal-psram.h делает
// #undef CONFIG_SPIRAM и весь PSRAM-код HAL вырождается в заглушку.
// Возвращает true, если PSRAM доступен приложению.
bool initPsram();

}  // namespace pm
