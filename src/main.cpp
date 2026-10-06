#include <Arduino.h>

#include "config.h"
#include "auth.h"
#include "fs.h"
#include "http_server.h"
#include "logger.h"
#include "net_bridge.h"
#include "psram.h"
#include "selftest.h"
#include "usb_stack.h"
#include "vault.h"

namespace {

// Включать гейты стадии 4a в собранном образе нельзя: они разрушительны для
// раздела vault и выполняются до поднятия USB, то есть отладочный вывод виден
// только по UART. Для разового прогона достаточно нажать кнопку BOOT (GPIO0) при
// включении питания — этот путь стирать раздел не вправе и откажется работать с
// непустым хранилищем.
//
// Временное включение нужно только на время отладки: при true гейты стирают
// раздел vault на КАЖДОЙ загрузке. Для прогона в этом режиме раздел должен быть
// пуст, иначе гейты не смогут завершиться. По окончании отладки вернуть false —
// иначе устройство уничтожит хранилище при первом же старте.
constexpr bool kRunSelfTest = false;

// Требует, чтобы GPIO0 был прижат НЕПРЕРЫВНО, и только тогда включает гейты.
//
// Одиночное чтение было ошибкой. IO0 — это одновременно кнопка BOOT и вывод
// выбора загрузчика, которым управляет DTR. После прошивки или любой команды
// esptool линия остаётся прижатой ещё на долю секунды, и следующая загрузка
// приложения читала LOW как нажатую кнопку: гейты запускались и стирали раздел
// vault при каждой прошивке. На стенде это и происходило — хранилище
// пересоздавалось само, без участия пользователя.
//
// Поэтому линия опрашивается несколько раз за интервал, и гейты включаются
// только если она всё это время была прижата. Настоящее нажатие кнопки длится
// гораздо дольше, а кратковременный остаточный уровень от DTR отсеивается.
constexpr int kSelfTestSamples = 12;
constexpr int kSelfTestSampleDelayMs = 20;

bool selfTestRequested() {
  static bool requested = false;
  static bool checked = false;
  if (!checked) {
    pinMode(0, INPUT_PULLUP);
    requested = digitalRead(0) == LOW;
    for (int i = 1; requested && i < kSelfTestSamples; ++i) {
      delay(kSelfTestSampleDelayMs);
      if (digitalRead(0) != LOW) {
        requested = false;
      }
    }
    pinMode(0, INPUT);
    checked = true;
    if (!requested) {
      pm::log::info("selftest: not requested, vault left untouched");
    }
  }
  return requested;
}

void banner() {
  const uint64_t chipId = ESP.getEfuseMac();
  pm::log::info("PassManager %s", pm::config::kFirmwareVersion);
  pm::log::info("chip %s rev %d cores %d", ESP.getChipModel(), ESP.getChipRevision(),
                ESP.getChipCores());
  pm::log::info("chip id %04x%08x", static_cast<unsigned>(chipId >> 32), static_cast<unsigned>(chipId));
  pm::log::info("flash %u MB psram %u MB heap %u KB", static_cast<unsigned>(ESP.getFlashChipSize() >> 20),
                static_cast<unsigned>(ESP.getPsramSize() >> 20),
                static_cast<unsigned>(ESP.getFreeHeap() >> 10));
  pm::log::info("cpu %d MHz", static_cast<int>(ESP.getCpuFreqMHz()));
}

// Раздел web поднимаем ДО USB: mount ни от чего не зависит, а диагностика
// образа нужна в логе даже когда USB не поднялся (иначе нечем отличить "сломался
// NCM" от "устройство не залито"). Сам HTTP-сервер, наоборот, строго после
// моста — см. ниже.
void mountWeb() {
  if (!pm::fs::mountWeb()) {
    pm::log::error("stage 3: web mount failed (run: pio run -t uploadall)");
    return;
  }
  size_t indexSize = 0;
  if (pm::fs::webIndexSize(indexSize)) {
    pm::log::info("stage 3: %s %u B", "/index.html", static_cast<unsigned>(indexSize));
  } else {
    pm::log::error("stage 3: /index.html missing — образ web пуст или не залит");
  }
}

}  // namespace

void setup() {
  pm::log::init();
  pm::initPsram();
  banner();
  // Гейты стадии 4a одноразовые: они затирают раздел vault и в конце стирают его
  // снова. Запускать их на каждой загрузке нельзя — это стоит erase раздела при
  // каждом старте, а износ флеша накапливается молча. Вход включает их разово, по
  // изменению GPIO0 при загрузке, либо оставленным в коде PM_RUN_SELFTEST.
  if (kRunSelfTest || selfTestRequested()) {
    pm::log::warn("stage 4a: selftest enabled, vault partition will be erased");
    // Стирать раздел разрешаем только когда гейты включены флагом сборки: это
    // осознанный dev-режим. Запуск по GPIO0 стирать не вправе, иначе случайно
    // удержатая кнопка уничтожит настоящее хранилище.
    pm::selftest::run(kRunSelfTest);
  }
  mountWeb();
  // До USB, моста и HTTP: initialize() создаёт мьютекс и читает признак
  // provisioned с флеша. Позже HTTP-сервер уже не сможет отличить заполненное
  // устройство от пустого, не спросив раздел сам, — а различать обязан.
  pm::vault::initialize();
  // Auth поднимаем после initialize() (ему нужен признак provisioned с флеша) и
  // до install() HTTP-сервера: обработчики читают состояние сессии с первого
  // же запроса, и ни один из них не имеет права увидеть «модуль не поднят».
  //
  // Отказ install() здесь не фатален: HTTP поднимется и ответит на /api/auth/state
  // как locked, а submit вернёт 0. Лучше живой сервер с отказом в разблокировке,
  // чем отсутствие сервера вообще.
  if (pm::auth::install()) {
    pm::log::info("stage 5: auth worker up");
  } else {
    pm::log::error("stage 5: auth install failed");
  }
  if (pm::usb::install()) {
    // Мост ставим после USB: мосту нужен MAC из usb::macAddress(), а кадры
    // пойдут только когда хост поднимет интерфейс. Сам netif поднимается
    // сразу и без DHCP: адрес статический, ждать тут нечего — сервер это мы.
    // Флаг ESP_NETIF_FLAG_AUTOUP, который тут ещё упоминается, на netif без
    // IO-драйвера сам по себе не действует: lwIP стартует только из явного
    // esp_netif_action_start() в net_bridge::install().
    pm::log::info("stage 2b: ncm ready, installing bridge");
    if (pm::net_bridge::install()) {
      pm::log::info("stage 2b: bridge up 192.168.7.1");
      // HTTP поднимаем только после моста: listen() привязывается к netif, и
      // на мёртвом lwIP сокет не примет ни одного соединения даже после того,
      // как сеть оживёт. netif к этому моменту уже поднят — install() ждёт
      // именно этого.
      if (pm::http_server::install()) {
        pm::log::info("stage 3: ready on http://192.168.7.1/");
      } else {
        pm::log::error("stage 3: http server install failed");
      }
    } else {
      pm::log::error("stage 2b: bridge install failed");
    }
  } else {
    pm::log::error("stage 2a: usb start failed");
  }
}

void loop() {
  delay(1000);
}
