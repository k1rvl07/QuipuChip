#include "net_bridge.h"

#include <esp_heap_caps.h>
#include <esp_event.h>
#include <esp_netif.h>
#include <esp_netif_defaults.h>
#include <esp_netif_net_stack.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <string.h>
#include <tusb.h>

#include "config.h"
#include "logger.h"
#include "usb_stack.h"

namespace pm {
namespace net_bridge {
namespace {

// Ethernet MTU 1500 плюс запас на служебное. Стек TinyUSB дальше сам разберёт
// NTB, отдаём payload.
constexpr size_t kFrameBuf = 1600;

// Очередь исходящих кадров. Глубокая настолько, чтобы пережить пачку
// TCP-сегментов от lwIP, пока задача tud_task занята USB-обработкой.
constexpr UBaseType_t kTxQueueLen = 16;

constexpr const char* kServerIp = "192.168.7.1";
constexpr const char* kNetmask = "255.255.255.0";

// IDF 4.4.7: esp_ip4_addr_t — это голый uint32_t в сетевом порядке, поля с
// байтами нет. На Xtensa (little-endian) старший байт числа — последний октет.
void ip4Octets(uint32_t addr, uint8_t out[4]) {
  out[0] = static_cast<uint8_t>(addr & 0xFFu);
  out[1] = static_cast<uint8_t>((addr >> 8) & 0xFFu);
  out[2] = static_cast<uint8_t>((addr >> 16) & 0xFFu);
  out[3] = static_cast<uint8_t>((addr >> 24) & 0xFFu);
}

// «Устройство» для esp_netif. Структура обязана начинаться с esp_netif_driver_base_t:
// esp_netif_attach() в IDF 4.4.7 устроен как вызов функции по смещению 0 от
// переданного handle (l32i a8, a3, 0 + callx8 a8) — это post_attach. Если первым
// положитьesp_netif_t*, он будет вызван как код и получим InstructionFetchError
// ровно на адресе самого netif. То же касается transmit(): первым аргументом
// получает тот же handle.
struct Device {
  esp_netif_driver_base_t base;
  QueueHandle_t txQueue;
};

struct TxItem {
  uint8_t* data;
  size_t len;
};

Device g_dev = {};
Stats g_stats;
bool g_dhcp = false;
bool g_netifUp = false;
esp_netif_ip_info_t g_ip = {};

// Шаг, на котором install() оборвался, и код esp_err_t. Периодическая строка
// usbTask выводит их, потому что сами log::error() из install() случаются до
// первого тика usbTask и в захват не попадают.
const char* g_step = "none";
int g_err = 0;

void fail(const char* step, esp_err_t err) {
  g_step = step;
  g_err = static_cast<int>(err);
  log::error("netif: failed at %s err %d", step, g_err);
}

esp_netif_inherent_config_t g_base = {
    // AUTOUP: поднять интерфейс при attach. DHCP_SERVER: адрес получает хост,
    // не мы. GARP: gratuitous ARP при подъёме, чтобы хост узнал наш MAC.
    .flags = static_cast<esp_netif_flags_t>(ESP_NETIF_FLAG_AUTOUP | ESP_NETIF_DHCP_SERVER |
                                            ESP_NETIF_FLAG_GARP),
    .mac = {0, 0, 0, 0, 0, 0},
    .ip_info = &g_ip,
    .get_ip_event = 0,
    .lost_ip_event = 0,
    .if_key = config::kNetifIfKey,
    .if_desc = config::kNetifIfDesc,
    .route_prio = 20,
};

// Кадр от lwIP. Копируем в свой буфер: lwIP отдаёт свою память и сразу
// переиспользует её, а нам нужно пережить ещё и очередь FreeRTOS.
esp_err_t transmit(void* h, void* buffer, size_t len) {
  Device* dev = static_cast<Device*>(h);
  if (dev == nullptr || dev->txQueue == nullptr || len == 0 || len > kFrameBuf) {
    ++g_stats.txDropped;
    return ESP_OK;
  }
  uint8_t* copy = static_cast<uint8_t*>(heap_caps_malloc(len, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
  if (copy == nullptr) {
    ++g_stats.txDropped;
    return ESP_OK;
  }
  memcpy(copy, buffer, len);
  const TxItem item = {copy, len};
  // Timeout 0: поток TCPIP не должен вставать из-за неготового USB. Лучше
  // потерять кадр (TCP перешлёт), чем заблокировать lwIP.
  if (xQueueSend(dev->txQueue, &item, 0) != pdTRUE) {
    heap_caps_free(copy);
    ++g_stats.txDropped;
    return ESP_OK;
  }
  usb::wake();
  return ESP_OK;
}

void freeRxBuffer(void* h, void* buffer) {
  (void)h;
  if (buffer != nullptr) heap_caps_free(buffer);
}

// Сигнатура обязана совпадать с esp_netif_driver_base_t::post_attach: её же
// esp_netif_attach() вызывает по смещению 0 от handle.
esp_err_t postAttach(esp_netif_t* netif, esp_netif_iodriver_handle h) {
  Device* dev = static_cast<Device*>(h);
  if (dev == nullptr) return ESP_FAIL;
  dev->base.netif = netif;
  log::info("netif: attached %s", config::kNetifIfDesc);
  return ESP_OK;
}

esp_netif_driver_ifconfig_t g_driver = {
    .handle = &g_dev,
    .transmit = transmit,
    .transmit_wrap = nullptr,
    .driver_free_rx_buffer = freeRxBuffer,
};

}  // namespace

bool onFrame(const uint8_t* src, uint16_t size) {
  ++g_stats.rxFrames;
  g_stats.rxBytes += size;
  if (g_dev.base.netif == nullptr) return false;

  uint8_t* copy = static_cast<uint8_t*>(heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
  if (copy == nullptr) {
    ++g_stats.txDropped;
    return false;
  }
  memcpy(copy, src, size);
  // Буфер освободит lwIP через driver_free_rx_buffer, когда обработает кадр.
  return esp_netif_receive(g_dev.base.netif, copy, size, nullptr) == ESP_OK;
}

void pump() {
  if (g_dev.txQueue == nullptr) return;
  TxItem item;
  for (;;) {
    // Именно peek, а не receive. NTB конечен, и когда он заполнен, кадр должен
    // подождать освобождения места, а не пропасть: данные долетели из lwIP
    // один раз, повторно взять их неоткуда. Пока идёт передача, место
    // освободит netd_xfer_cb() на ep_in completion, который сам вызовет
    // ncm_start_tx(). Живой цикл usbTask переспрашивает can_xmit каждые 10 мс,
    // так что « NTB полон и никогда не распустеет » привести к зависанию не может:
    // в худшем случае кадры переполнят очередь и начнут честно отсчитываться
    // в txDropped.
    if (xQueuePeek(g_dev.txQueue, &item, 0) != pdTRUE) return;
    if (!tud_network_can_xmit(static_cast<uint16_t>(item.len))) return;
    if (xQueueReceive(g_dev.txQueue, &item, 0) != pdTRUE) return;

    // Синхронно копирует кадр в NTB и, если передача не занята, стартует её
    // прямо здесь. Возврат — единственная точка, где можно освободить буфер.
    tud_network_xmit(item.data, static_cast<uint16_t>(item.len));
    heap_caps_free(item.data);
    ++g_stats.txFrames;
    g_stats.txBytes += item.len;
  }
}

Stats stats() { return g_stats; }

bool dhcpStarted() { return g_dhcp; }
bool netifUp() { return g_netifUp; }
const char* lastStep() { return g_step; }
int lastError() { return g_err; }

bool ip(uint8_t out[4]) {
  if (g_dev.base.netif == nullptr) return false;
  esp_netif_ip_info_t now = {};
  if (esp_netif_get_ip_info(g_dev.base.netif, &now) != ESP_OK) return false;
  ip4Octets(now.ip.addr, out);
  return true;
}

uint32_t txQueueWaiting() {
  if (g_dev.txQueue == nullptr) return 0xFFFFFFFFul;
  return static_cast<uint32_t>(uxQueueMessagesWaiting(g_dev.txQueue));
}

bool install() {
  g_dev.txQueue = xQueueCreate(kTxQueueLen, sizeof(TxItem));
  if (g_dev.txQueue == nullptr) {
    fail("tx_queue", ESP_ERR_NO_MEM);
    return false;
  }

  uint8_t mac[usb::kMacLen];
  usb::macAddress(mac);
  memcpy(g_base.mac, mac, sizeof(mac));

  if (esp_netif_str_to_ip4(kServerIp, &g_ip.ip) != ESP_OK ||
      esp_netif_str_to_ip4(kServerIp, &g_ip.gw) != ESP_OK ||
      esp_netif_str_to_ip4(kNetmask, &g_ip.netmask) != ESP_OK) {
    fail("parse_ip", ESP_ERR_INVALID_ARG);
    return false;
  }

  // esp_netif_init() идемпотентен: если ядро Arduino уже дёрнуло его на старте,
  // вернётся ESP_ERR_INVALID_STATE, и это НЕ ошибка моста — продолжаем.
  esp_err_t err = esp_netif_init();
  if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
    fail("netif_init", err);
    return false;
  }

  // Свой base-конфиг вместо ESP_NETIF_DEFAULT_*: нужен DHCP_SERVER и свой
  // if_key. Netstack берём готовый eth — SLIP-овского в этой сборке нет
  // (CONFIG_LWIP_SLIP выключен, символ не собран), так что ESP_NETIF_DEFAULT_SLIP()
  // дал бы нерезолвящийся символ.
  esp_netif_config_t cfg = {};
  cfg.base = &g_base;
  cfg.driver = &g_driver;
  cfg.stack = ESP_NETIF_NETSTACK_DEFAULT_ETH;

  g_dev.base.post_attach = postAttach;

  g_dev.base.netif = esp_netif_new(&cfg);
  if (g_dev.base.netif == nullptr) {
    fail("netif_new", ESP_FAIL);
    return false;
  }

  err = esp_netif_set_driver_config(g_dev.base.netif, &g_driver);
  if (err != ESP_OK) {
    fail("driver_cfg", err);
    return false;
  }

  err = esp_netif_attach(g_dev.base.netif, &g_dev);
  if (err != ESP_OK) {
    fail("attach", err);
    return false;
  }

  // esp_netif_set_ip_info() здесь НЕ вызываем намеренно. Разбор
  // esp_netif_set_ip_info_api_api показывает проверку: если выставлен флаг
  // ESP_NETIF_DHCP_SERVER (бит 1), статический IP принимается только когда
  // статус dhcps == running, иначе возвращается ESP_ERR_ESP_NETIF_DHCP_NOT_STOPPED
  // (0x5007). Мы выставляем этот флаг в base-конфиге, то есть попали бы в
  // ровно эту проверку. Адрес приезжает через base->ip_info на esp_netif_new(),
  // а dhcps-сервер подхватывает его как свой. Ниже проверяем это чтением назад.
  //
  // Сначала ОТДЕЛЬНО поднимаем интерфейс. Флаг ESP_NETIF_FLAG_AUTOUP задан, но
  // сам по себе он не срабатывает: в esp_netif он обрабатывается внутри
  // esp_netif_action_start(), которую esp_netif вешает на событие старта
  // IO-драйвера. У нас нет IO-драйвера, который бы это событие опубликовал,
  // поэтому action никогда не вызывается. Наблюдаемое следствие было
  // характерным: esp_netif_is_netif_up() == false, rx растёт, tx вечно 0 —
  // lwIP получает кадры, но не отвечает ни на что, потому что интерфейс лежит.
  // esp_netif_action_start() публична и прямо документирована как
  // "building block ... if AUTOUP enabled turns the interface on", так что
  // вызываем её напрямую. Побочный эффект — она же стартует dhcps-сервер,
  // если выставлен ESP_NETIF_DHCP_SERVER, поэтому следующий вызов
  // esp_netif_dhcps_start() может вернуть ALREADY_STARTED — это не ошибка.
  esp_netif_action_start(g_dev.base.netif, ESP_EVENT_ANY_BASE, ESP_EVENT_ANY_ID, nullptr);

  err = esp_netif_dhcps_start(g_dev.base.netif);
  if (err != ESP_OK && err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STARTED) {
    fail("dhcps", err);
    return false;
  }
  g_dhcp = true;
  g_step = "ok";
  g_err = 0;

  // Читаем адрес обратно: base->ip_info мог и не примениться, и тогда мы бы
  // сообщили "bridge up 192.168.7.1", имея на интерфейсе 0.0.0.0.
  esp_netif_ip_info_t got = {};
  if (esp_netif_get_ip_info(g_dev.base.netif, &got) != ESP_OK) {
    fail("get_ip", ESP_FAIL);
    return false;
  }
  g_ip = got;

  // Диагностика для Gate C: up-состояние интерфейса в lwIP. Флаг
  // ESP_NETIF_FLAG_AUTOUP задан в конфиге, но если подъём не произошёл, lwIP
  // молча игнорирует входящие ARP/DHCP и не формирует ответы — счётчики rx
  // растут, а tx остаётся 0. Это ровно наблюдаемая картина, поэтому
  // esp_netif_is_netif_up() — прямой ответ, а не догадка по счётчикам.
  g_netifUp = esp_netif_is_netif_up(g_dev.base.netif);
  log::info("netif: %s lwip_up %d", config::kNetifIfDesc, g_netifUp ? 1 : 0);

  uint8_t a[4];
  ip4Octets(g_ip.ip.addr, a);
  log::info("netif: %s up %u.%u.%u.%u dhcp on mac %02x:%02x:%02x:%02x:%02x:%02x",
            config::kNetifIfDesc, a[0], a[1], a[2], a[3], mac[0], mac[1], mac[2], mac[3], mac[4],
            mac[5]);
  return true;
}

}  // namespace net_bridge
}  // namespace pm
