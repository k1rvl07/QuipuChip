#pragma once

#include <stddef.h>
#include <stdint.h>

// Мост между кадрами NCM и lwIP. Наружу торчат три вещи:
//   onFrame()  — вызывается из tud_network_recv_cb (контекст задачи tud_task),
//                отдаёт принятый кадр в lwIP;
//   pump()     — вызывается из той же задачи, забирает кадры, которые lwIP
//                хочет отправить, и отдаёт их TinyUSB;
//   install()  — создаёт netif и запускает DHCP-сервер.
//
// Почему TX идёт через очередь, а не напрямую в tud_network_xmit():
// esp_netif вызывает transmit() из потока TCPIP, а tud_network_xmit() трогает
// состояние DCD, которым единолично владеет задача tud_task. Прямой вызов
// из другого потока — гонка с ISR и с самой задачей. Поэтому transmit() только
// кладёт кадр в очередь и будит задачу, а tud_network_xmit() зовёт pump().
namespace pm {
namespace net_bridge {

struct Stats {
  uint32_t rxFrames;      // кадров отдано в lwIP
  uint32_t txFrames;      // кадров отдано хосту
  uint32_t rxBytes;
  uint32_t txBytes;
  uint32_t txDropped;     // не влезло в очередь — счётчик, а не блокировка
};

bool install();

// Кадр, пришедший с хоста. Возвращает false, если netif ещё не поднят: кадр
// осознанно теряется, но счётчик rxFrames при этом растёт.
bool onFrame(const uint8_t* src, uint16_t size);

// Забирает накопившиеся кадры lwIP и отдаёт их хосту. Зовётся только из
// задачи tud_task.
void pump();

Stats stats();

  bool dhcpStarted();

// Фактическое состояние интерфейса в lwIP (esp_netif_is_netif_up). Не равно
// "мост поднялся": если lwIP-интерфейс лежит, кадры принимаются, но lwIP не
// отвечает ни на что, и tx навсегда остаётся 0.
bool netifUp();

// Диагностика install(): на каком шаге оборвалось и с каким esp_err_t. Нужно
// потому, что install() зовётся из setup() один раз, а лог моста в этот момент
// уже прошёл и в периодическую строку usbTask не попадает.
const char* lastStep();
int lastError();

// Текущий адрес интерфейса, прочитанный из esp_netif. Нужен в периодической
// строке: setup() печатает адрес один раз и до тика usbTask, поэтому без этого
// нельзя отличить «bridge up 192.168.7.1» от «bridge up, адреса нет».
bool ip(uint8_t out[4]);

// Глубина очереди кадров lwIP → USB. 0xFFFFFFFF, если очередь не создана.
// Нужно heartbeat'у различать «lwIP ничего не отдаёт» (q=0) от «кадры стоят в
// очереди, но pump() не может их забрать» (q>0 при замёрзшем tx).
uint32_t txQueueWaiting();

}  // namespace net_bridge
}  // namespace pm
