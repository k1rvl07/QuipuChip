#pragma once

#include <stddef.h>
#include <stdint.h>

// HTTP-сервер на ESP-IDF esp_http_server.
//
// Почему не WebServer из библиотеки Arduino и не самописный парсер: httpd уже
// в include-пути этого SDK (espressif32 подтягивает компонент esp_http_server
// безо всяких build_flags), а его CONFIG_HTTPD_MAX_URI_LEN = 512 в точности
// равен config::kHttpMaxUri. То есть пределы URI в проекте и в httpd уже
// совпадают, и дублировать их проверку незачем.
//
// Статику отдаём из раздела web (см. fs.h), API — на ArduinoJson.
//
// Не-GET httpd отвергает САМ ответом 405, не читая тело: он сначала подбирает
// шаблон по URI и только потом сверяет метод. Поэтому отдельная проверка метода
// в обработчике статики была бы недостижимым кодом — на стенде POST /index.html
// даёт штатную страницу httpd, а не JSON этого модуля.
namespace pm {
namespace http_server {

// Поднимает сервер. Вызывать ПОСЛЕ успешного net_bridge::install(): иначе
// listen() привяжется к netif, который не поднят, и сокет не будет принимать
// соединения даже после того, как lwIP оживёт.
bool install();

// Гасит сервер. Счётчики запросов при этом НЕ обнуляются: они живут в
// обработчиках, и после stop() их увидит уже следующий install().
void stop();

}  // namespace http_server
}  // namespace pm
