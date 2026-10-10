#pragma once

#include <stddef.h>
#include <stdint.h>

namespace pm {
namespace usb {

constexpr size_t kMacLen = 6;

// Адрес САМОГО интерфейса NCM: efuse-MAC с локальным битом, fallback при
// нечитаемом efuse. Единственный источник истины — им пользуются и iMAC в
// строковом дескрипторе, и esp_netif в 2.2.
// Это НЕ адрес клиента: проверки и логирования MAC клиента в проекте нет.
void macAddress(uint8_t out[kMacLen]);

// Ставит драйвер TinyUSB (helper ядра Arduino) и поднимает задачу tud_task.
bool install();

// Будит задачу tud_task из чужого потока. Нужен мосту: когда lwIP хочет
// отправить кадр, transmit() кладёт его в очередь и зовёт сюда, чтобы кадр
// ушёл в USB немедленно, а не через подслеживание очереди раз в 10 мс.
void wake();

bool mounted();
bool linkUp();

// Счётчиков кадров здесь больше нет: с 2b единственный поток кадров — NCM →
// lwIP → USB, и он живёт в pm::net_bridge::Stats. Дублировать те же числа в
// двух местах значит завести источник расхождения.

// Диагностика Гейта Б. Счётчики растут только если стек реально обрабатывает
// setup-пакеты: каждый вызов tud_descriptor_*_cb — это один входящий
// GET_DESCRIPTOR, то есть доказательство, что control-путь живой.
struct Diag {
  uint32_t descDevice;  // tud_descriptor_device_cb
  uint32_t descConfig;  // tud_descriptor_configuration_cb
  uint32_t descString;  // tud_descriptor_string_cb
  uint32_t suspends;
  uint32_t resumes;
  uint32_t strLangidReqs;  // GET_DESCRIPTOR string 0 (usb_get_langid)
  uint32_t strMacReqs;     // GET_DESCRIPTOR string 5 (iMACAddress)
  uint32_t strMacLen;      // сколько символов MAC-строки отдали при последнем запросе
};

Diag& diag();

}  // namespace usb
}  // namespace pm
