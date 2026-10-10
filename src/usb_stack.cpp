#include "usb_stack.h"

#include <Arduino.h>
#include <esp_heap_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <string.h>

#include "tusb.h"

// Сентинел конфига: если ядро Arduino подсунуло свой tusb_config.h, упали бы мы
// тут, а не загадочными tud_cdc_* в .map. Проверять надо ПОСЛЕ подключения
// tusb.h — только он тянет tusb_config.h.
#ifndef PM_OWN_TUSB_CONFIG
#error "tusb_config.h ядра перебил наш — проверь -iquote lib/tinyusb/src"
#endif

// Регистры USB-периферии S3 для диагностики. Те же заголовки использует
// dcd_esp32sx.c, пути те же — USB0 объявлен в soc/usb_struct.h как extern.
#include "soc/usb_struct.h"
#include "soc/usb_wrap_struct.h"
#include "soc/system_struct.h"
#include "soc/usb_reg.h"

#include "config.h"
#include "logger.h"
#include "net_bridge.h"

namespace pm {
namespace usb {
namespace {

// --- core helper -----------------------------------------------------------
// esp32-hal-tinyusb.c экспортирует tinyusb_driver_install, но НЕ объявляет его
// ни в одном заголовке: и tinyusb_config_t, и прототип живут внутри .c
// (строки 52-56 и 81). Поэтому объявляем сами. Структура из одного bool —
// если ядро её расширит, здесь будет расхождение ABI; это единственная точка
// связности с ядром.
extern "C" struct TinyUsbInstallConfig {
  bool external_phy;
};
extern "C" esp_err_t tinyusb_driver_install(const TinyUsbInstallConfig* config);

}  // namespace
}  // namespace usb
}  // namespace pm

// Состояние держим на уровне файла: TinyUSB-callback'и ниже объявлены в tusb.h
// внутри extern "C", то есть вне namespace, и до анонимного пространства
// им не дотянуться.
struct UsbState {
  bool mounted = false;
  bool link = false;
  TaskHandle_t task = nullptr;
};

static UsbState g;
static pm::usb::Diag gDiag;

namespace pm {
namespace usb {
namespace {

void usbTask(void* /*arg*/) {
  uint32_t nextLog = millis();
  uint32_t lastGintsts = 0;
  uint32_t gintChanges = 0;
  pm::log::info("usb: task alive prio %u", static_cast<unsigned>(uxTaskPriorityGet(nullptr)));

  for (;;) {
    // Кадры, которые lwIP хочет отправить, отдаём хосту здесь: tud_network_xmit()
    // трогает состояние DCD, которым единолично владеет эта задача. Пока
    // can_xmit() врёт про NTB, pump() просто ничего не заберёт.
    pm::net_bridge::pump();

    // Обслуживаем USB-события. Раньше здесь был tud_task() ==
    // tud_task_ext(UINT32_MAX, false): задача спала до события, поэтому
    // «задача спит и ждёт хоста» было неотличимо от «задача мертва». Теперь
    // tud_task_ext(0, false) — неблокирующий слив очереди, а ждать мы умеем
    // сами: ulTaskNotifyTake ниже проснётся и на кадр от lwIP (usb::wake()),
    // и по таймауту.
    tud_task_ext(0, false);

    // 10 мс — потолок задержки обработки USB-событий, он же раньше был
    // таймаутом tud_task_ext. Кадр от lwIP будит нас немедленно, поэтому на
    // пропускной способности TX этот потолок не сказывается.
    ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(10));

    const uint32_t now = millis();
    if (static_cast<int32_t>(now - nextLog) < 0) continue;
    nextLog = now + 1000;

    // Счётчик изменений gintsts: если хоста нет, он не растёт. Если растёт, а
    // mount не происходит — события доходят до DCD, но не обрабатываются.
    const uint32_t gintsts = USB0.gintsts;
    if (gintsts != lastGintsts) {
      ++gintChanges;
      lastGintsts = gintsts;
    }

    const pm::net_bridge::Stats& s = pm::net_bridge::stats();
    const Diag& d = pm::usb::diag();
    uint8_t nip[4] = {0, 0, 0, 0};
    pm::net_bridge::ip(nip);
    // Диагностика зависшего TX. Три исхода картины «tx замёрз»:
    //   q=0  — lwIP ничего не отдаёт: кадры не доходят до него (malloc в
    //          onFrame падает) либо lwIP молчит;
    //   q>0, cx=1 — pump() обязан транслировать, если не транслирует —
    //          очередь/задача;
    //   q>0, cx=0 — NTB заблокирован, хост не добирает IN-эндпоинт.
    // ps — свободная PSRAM: карта «внезапно ничего не аллоцируется».
    const uint32_t q = pm::net_bridge::txQueueWaiting();
    const int cx = tud_network_can_xmit(64) ? 1 : 0;
    const uint32_t ps = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    const uint32_t ih = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    pm::log::info(
        "ncm rx %lu f/%lu B tx %lu f/%lu B drop %lu | link %d dhcp %d up %d step %s/%d "
        "ip %u.%u.%u.%u stk %lu | "
        "ready %d mnt %d susp %d | gintsts %08x msk %08x dctl %08x dcfg %08x dsts %08x gotgctl %08x wrap %08x chg %lu | "
        "desc d %lu c %lu s %lu s0 %lu s5 %lu l5 %lu | q %lu cx %d ps %lu ih %lu",
        static_cast<unsigned long>(s.rxFrames), static_cast<unsigned long>(s.rxBytes),
        static_cast<unsigned long>(s.txFrames), static_cast<unsigned long>(s.txBytes),
        static_cast<unsigned long>(s.txDropped), g.link ? 1 : 0,
        pm::net_bridge::dhcpStarted() ? 1 : 0, pm::net_bridge::netifUp() ? 1 : 0,
        pm::net_bridge::lastStep(),
        pm::net_bridge::lastError(), nip[0], nip[1], nip[2], nip[3],
        static_cast<unsigned long>(uxTaskGetStackHighWaterMark(nullptr)),
        tud_ready() ? 1 : 0, g.mounted ? 1 : 0, tud_suspended() ? 1 : 0,
        static_cast<unsigned>(gintsts), static_cast<unsigned>(USB0.gintmsk),
        static_cast<unsigned>(USB0.dctl), static_cast<unsigned>(USB0.dcfg),
        static_cast<unsigned>(USB0.dsts), static_cast<unsigned>(USB0.gotgctl),
        static_cast<unsigned>(USB_WRAP.otg_conf.val),
        static_cast<unsigned long>(gintChanges),
        static_cast<unsigned long>(d.descDevice), static_cast<unsigned long>(d.descConfig),
        static_cast<unsigned long>(d.descString), static_cast<unsigned long>(d.strLangidReqs),
        static_cast<unsigned long>(d.strMacReqs), static_cast<unsigned long>(d.strMacLen),
        static_cast<unsigned long>(q), cx, static_cast<unsigned long>(ps),
        static_cast<unsigned long>(ih));
  }
}

}  // namespace


void macAddress(uint8_t out[kMacLen]) {
  const uint64_t efuse = ESP.getEfuseMac();
  if (efuse == 0) {
    memcpy(out, config::kMacFallback, kMacLen);
    return;
  }
  out[0] = static_cast<uint8_t>(efuse >> 40);
  out[1] = static_cast<uint8_t>(efuse >> 32);
  out[2] = static_cast<uint8_t>(efuse >> 24);
  out[3] = static_cast<uint8_t>(efuse >> 16);
  out[4] = static_cast<uint8_t>(efuse >> 8);
  out[5] = static_cast<uint8_t>(efuse);
  // Locally administered (бит 1) + unicast (бит 0 сброшен): адрес не должен
  // выглядеть как чужой vendor-assigned.
  out[0] = static_cast<uint8_t>((out[0] | 0x02) & 0xFE);
}

// Поднятие домена USB_OTG. На этом ESP32-S3 блок стартует в сбросе и без часов
// (usb_rst=1, usb_clk_en=0), а usb_hal_init() из libhal.a — это всего лишь
// usb_ll_int_phy_enable(): он конфигурирует PHY-пины и ничего не знает про
// periph_module. Из-за этого записи dcd_init() молча терялись, прерывания не
// включались, а хост получал error -71. Сброс снимаем и часы включаем сами —
// обязательно ДО tinyusb_driver_install(), иначе dcd_init уже ничего не увидит.
static void releaseUsbDomain() {
  const bool wasInReset = SYSTEM.perip_rst_en0.usb_rst != 0;
  const bool hadNoClock = SYSTEM.perip_clk_en0.usb_clk_en == 0;
  SYSTEM.perip_rst_en0.usb_rst = 0;
  SYSTEM.perip_clk_en0.usb_clk_en = 1;
  pm::log::info("usb: domain released (was rst=%d noclk=%d)", wasInReset ? 1 : 0,
                hadNoClock ? 1 : 0);
}

bool install() {
  TinyUsbInstallConfig cfg;
  cfg.external_phy = false;

  releaseUsbDomain();

  // Прайм-чтения ДО tusb_init()/dcd_init(): состояние dwc2, которое застанет
  // dcd_init. CURMOD (GOTGCTL bit21): 0=device, 1=host. Если ядро пришло в
  // host-режиме, force+CSFTRST в dcd_init должны были его перевести.
  pm::log::info("usb: prime gsnpsid %08x gotgctl %08x dctl %08x dcfg %08x grstctl %08x dsts %08x curmod %d conid %d",
                static_cast<unsigned>(USB0.gsnpsid), static_cast<unsigned>(USB0.gotgctl),
                static_cast<unsigned>(USB0.dctl), static_cast<unsigned>(USB0.dcfg),
                static_cast<unsigned>(USB0.grstctl), static_cast<unsigned>(USB0.dsts),
                (USB0.gotgctl & USB_CURMOD_M) ? 1 : 0,
                (USB0.gotgctl & USB_CONIDSTS_M) ? 1 : 0);

  // helper ядра: usb_hal_init() (символ лежит в libhal.a) + пины + tusb_init().
  const esp_err_t err = tinyusb_driver_install(&cfg);
  if (err != ESP_OK) {
    pm::log::error("usb: driver install failed %d", static_cast<int>(err));
    return false;
  }

  // Сразу после install: tud_init/tusb_init уже отработали внутри, но событий
  // dcfg/gusbcfg/gahbcfg и ненулевой gintmsk пишет ТОЛЬКО dcd_init — это
  // подтверждение, что tud_init дошёл до инициализации контроллера.
  pm::log::info("usb: install ok, gintmsk %08x dctl %08x dcfg %08x gusbcfg %08x gahbcfg %08x dsts %08x ready %d",
                static_cast<unsigned>(USB0.gintmsk), static_cast<unsigned>(USB0.dctl),
                static_cast<unsigned>(USB0.dcfg), static_cast<unsigned>(USB0.gusbcfg),
                static_cast<unsigned>(USB0.gahbcfg), static_cast<unsigned>(USB0.dsts),
                tud_ready() ? 1 : 0);

  if (xTaskCreate(usbTask, "usb_dev", config::kUsbTaskStackWords, nullptr,
                  configMAX_PRIORITIES - 1, &g.task) != pdPASS) {
    pm::log::error("usb: task create failed");
    return false;
  }

  uint8_t mac[kMacLen];
  macAddress(mac);
  pm::log::info("usb: ncm %04x:%04x mac %02x:%02x:%02x:%02x:%02x:%02x stk %u", config::kUsbVid,
                config::kUsbPid, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                config::kUsbTaskStackWords);
  return true;
}

bool mounted() { return g.mounted; }
bool linkUp() { return g.link; }
Diag& diag() { return gDiag; }

void wake() {
  if (g.task != nullptr) xTaskNotifyGive(g.task);
}

}  // namespace usb
}  // namespace pm

// --- TinyUSB callbacks ------------------------------------------------------
extern "C" {

void tud_mount_cb(void) {
  g.mounted = true;
  pm::log::info("usb: mounted");
}

void tud_umount_cb(void) {
  g.mounted = false;
  g.link = false;
  pm::log::info("usb: unmounted");
}

void tud_network_init_cb(void) { pm::log::info("ncm: init"); }

void tud_network_link_state_cb(bool state) {
  g.link = state;
  pm::log::info("ncm: link %s", state ? "up" : "down");
}

bool tud_network_recv_cb(const uint8_t* src, uint16_t size) {
  // TinyUSB 0.16 ВЫБРАСЫВАЕТ возвращаемое значение tud_network_recv_cb
  // (ncm_device.c:249 — вызов без проверки), поэтому «вернуть false и ждать
  // renew» не работает: кадр всё равно считается потреблённым. Значит кадр
  // нужно здесь же либо отдать в lwIP, либо осознанно сбросить. Никакого
  // «буфер занят, ждём следующий вызов» — он бы навсегда заклинил поток.
  //
  // Кадр отдаётся мосту копией: src указывает на приёмный буфер TinyUSB,
  // который переиспользуется сразу после возврата, а lwIP разбирает кадр
  // позже, в потоке TCPIP.
  pm::net_bridge::onFrame(src, size);

  // ОБЯЗАТЕЛЬНЫЙ renew, иначе приём умирает после первого кадра.
  // Механика такая: handle_incoming_datagram() зовёт tud_network_recv_renew()
  // РОВНО ОДИН раз, а renew отдаёт ОДИН датаграмму и уменьшает num_datagrams
  // (ncm_device.c:237-249). Дальше renew никто не зовёт: ни netd_xfer_cb, ни
  // обработчик. Если num_datagrams стал 0, следующий вызов renew — это и есть
  // usbd_edpt_xfer() на ep_out, то есть перевзводка OUT-трансфера. Без нашего
  // вызова перевзводки не происходит, хост шлёт ARP/DHCP в пустоту, и счётчик
  // rx навсегда замирает на 1. Проверено: без этой строки было ровно так.
  tud_network_recv_renew();
  return true;
}

uint16_t tud_network_xmit_cb(uint8_t* dst, void* ref, uint16_t arg) {
  // Кадр от lwIP, который мост уже скопировал в свой буфер и передал сюда
  // через tud_network_xmit(). Это единственная точка, где Ethernet-кадр
  // попадает в NTB, поэтому копируем ровно arg байт без заголовков и правок.
  if (ref == nullptr || arg == 0) return 0;
  memcpy(dst, ref, arg);
  return arg;
}

}  // extern "C"
