#include "http_server.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <esp_heap_caps.h>
#include <esp_http_server.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include <string.h>

#include "auth.h"
#include "config.h"
#include "crypto.h"
#include "fs.h"
#include "logger.h"
#include "net_bridge.h"
#include "psram.h"
#include "totp.h"
#include "vault.h"

namespace pm {
namespace http_server {
namespace {

httpd_handle_t g_server = nullptr;

// Счётчики для /api/health. Всё крутится в таске httpd, поэтому синхронизация
// не нужна.
//
// Число ОТКРЫТЫХ сессий здесь не считается намеренно. И open_fn, и close_fn в
// IDF 4.4 ломают сервер: с зарегистрированными хуками (даже если они только
// считают и всегда отдают ESP_OK) после ~12 соединений connect() возвращает 0,
// но recv() отдаёт ECONNRESET, и сервер не отвечает уже никогда — при этом
// исчерпывается пул TCP PCB (CONFIG_LWIP_NUM_TCP_PCB=16) и socket() начинает
// падать с ENFILE. Свободной кучи 8.7 МБ, стек задачи не исчерпан, panic и
// перезагрузки нет. Воспроизведено на loopback без участия NCM, дефект в httpd
// из IDF 4.4. Поэтому лимит сессий держит max_open_sockets, а мы считаем
// только запросы в обработке.
uint32_t g_inFlight = 0;
uint32_t g_requests = 0;

// Стек задачи httpd. Рост с 4096 (дефолт IDF) из-за буфера раздачи на
// kHttpChunkBytes в обработчике: буфер лежит на стеке, потому что сессий
// одновременно до четырёх и общий статический буфер дал бы гонку.
constexpr uint32_t kHttpdStackBytes = 8192;

// httpd отдаёт 5-секундные таймауты на recv/send из коробки. По USB-NCM
// кадры идут через хост, и на первом запросе (особенно при загрузке образа
// web) этого хватает впритык.
constexpr uint8_t kSockTimeoutSec = 10;

struct Mime {
  const char* ext;
  const char* type;
};

// Опережающее объявление: нижележащие помощники вызывают sendJson(), а её
// определение стоит после блока API-помощников.
esp_err_t sendJson(httpd_req_t* r, const char* body, size_t len);

// Раньше здесь стоял rejectNonGet(), гасящий не-GET на статическом пути, и
// предполагалось, что без него "/api/entries/1" методом POST провалится в "/*"
// и получит index.html с кодом 200. Проверка на стенде это опровергла:
// httpd сначала подбирает шаблон по URI, и только потом сверяет метод, поэтому
// не-GET отсекается его собственным 405 ещё до вызова обработчика. На
// POST /index.html приходит штатная страница httpd «Request method for this URI
// is not handled by server», а не JSON этого модуля.
//
// Своя проверка была бы недостижимым кодом: обработчик статики зарегистрирован
// только на HTTP_GET, и не-GET в него не попадает физически.

// По умолчанию httpd отдаёт любой файл как text/html. Для JSON, JS и картинок
// это ломает и выполнение скриптов, и кэширование, поэтому таблица своя.
constexpr Mime kMimes[] = {
    {".html", "text/html; charset=utf-8"},
    {".htm", "text/html; charset=utf-8"},
    {".js", "application/javascript; charset=utf-8"},
    {".mjs", "application/javascript; charset=utf-8"},
    {".css", "text/css; charset=utf-8"},
    {".json", "application/json"},
    {".svg", "image/svg+xml"},
    {".png", "image/png"},
    {".jpg", "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".gif", "image/gif"},
    {".ico", "image/vnd.microsoft.icon"},
    {".woff2", "font/woff2"},
    {".woff", "font/woff"},
    {".txt", "text/plain; charset=utf-8"},
    {".map", "application/json"},
};

const char* mimeFor(const char* path) {
  const char* dot = strrchr(path, '.');
  if (dot == nullptr) {
    return "application/octet-stream";
  }
  for (const Mime& m : kMimes) {
    if (strcasecmp(dot, m.ext) == 0) {
      return m.type;
    }
  }
  return "application/octet-stream";
}

// В httpd_req_t лежит весь URI вместе с query-строкой: отдельного поля с путём
// в структуре нет. Без срезания "/index.html?v=2" искал бы файл с именем
// "index.html?v=2" и получил бы 404 на каждом обновлении страницы.
//
// Перцент-энкодинг здесь НАМЕРЕННО не декодируется. Закодированный обход
// "%2e%2e%2f" после декодирования стал бы настоящим ".." и проверка в
// fs::normalize() успела бы его отвергнуть, но не отвергла бы — потому что
// декодировать надо ДО нормализации, то есть ещё в одном месте. Не декодируя, мы
// получаем гарантию, что любой вход, где есть закодированный "..", просто не
// найдёт файла. Плата: имя файла с буквальным "%" отдать нельзя, а в статике
// web такие имена не встречаются.
bool requestPath(const httpd_req_t* r, char* out, size_t outSize) {
  const char* q = strchr(r->uri, '?');
  const size_t n = q != nullptr ? static_cast<size_t>(q - r->uri) : strlen(r->uri);
  if (n == 0 || n + 1 > outSize) {
    return false;
  }
  memcpy(out, r->uri, n);
  out[n] = '\0';
  return true;
}

// Считает запросы и запросы "в полёте". Guard, а не свободная функция, чтобы
// in_flight гарантированно уменьшился на любом пути выхода из обработчика,
// включая ранний return из-за ошибки.
class RequestGuard {
 public:
  RequestGuard() {
    ++g_requests;
    ++g_inFlight;
  }
  ~RequestGuard() {
    --g_inFlight;
  }
  RequestGuard(const RequestGuard&) = delete;
  RequestGuard& operator=(const RequestGuard&) = delete;
};

esp_err_t sendFile(httpd_req_t* r, const char* relPath) {
  fs::WebFile f;
  if (!fs::openWeb(relPath, f)) {
    return httpd_resp_send_404(r);
  }

  // MIME — по РАЗОБРАННОМУ имени файла, а не по пути запроса: для "/" и ""
  // расширения в запросе нет вовсе, и корень ушёл бы как octet-stream.
  httpd_resp_set_type(r, mimeFor(f.name));
  // Ассеты будущего SPA пока без хэша в имени, поэтому no-store: иначе браузер
  // после смены образа продолжит отдавать старый index.html из своего кэша, и
  // баг будет выглядеть как "прошивка не работает". Когда появятся хэшированные
  // имена, кэринг для них включается точечно.
  httpd_resp_set_hdr(r, "Cache-Control", "no-store");
  // Файл отдаётся по пути, который пришёл от клиента: без nosniff браузер
  // возьмёт из нашего text/css-sniff-контента скрипт, если файл переименован.
  httpd_resp_set_hdr(r, "X-Content-Type-Options", "nosniff");

  uint8_t buf[config::kHttpChunkBytes];
  size_t left = f.size;
  esp_err_t err = ESP_OK;

  while (left > 0) {
    const size_t want = left < sizeof(buf) ? left : sizeof(buf);
    const size_t got = fs::readWeb(f, buf, want);
    if (got == 0) {
      err = ESP_FAIL;
      break;
    }
    err = httpd_resp_send_chunk(r, reinterpret_cast<const char*>(buf), got);
    if (err != ESP_OK) {
      break;
    }
    left -= got;
  }

  fs::closeWeb(f);
  if (err != ESP_OK) {
    return err;
  }
  // Пустой чанк закрывает поток chunked-ответа; без него клиент с open-ended
  // телом ждал бы следующий запрос вместо того, чтобы прочитать ответ целиком.
  return httpd_resp_send_chunk(r, nullptr, 0);
}

// ─── Общие помощники API ──────────────────────────────────────────────────────
//
// Здесь живут функции, нужные всем API-обработчикам, а не одному. Держать их
// в healthHandler было бы неправильно: это единственный маршрут без
// аутентификации, и он не должен ни читать тела, ни знать про сессии.

// Имя вида job'а для лога и JSON. У auth нет toString(Job): там перечисление
// Job не выводится в интерфейс напрямую, и добавлять его ради двух строк значило
// бы расширять контракт модуля без нужды.
const char* jobKindName(auth::Job k) {
  switch (k) {
    case auth::Job::Provision:
      return "provision";
    case auth::Job::Unlock:
      return "unlock";
    case auth::Job::Reset:
      return "reset";
    case auth::Job::Rekey:
      return "rekey";
  }
  return "unknown";
}

// Ошибка API отдаётся САМИМ сервером, а не через httpd_resp_send_err(), и на то
// две причины.
//
// Первая: в IDF 4.4 перечисление httpd_err_code_t содержит всего 13 кодов, и среди
// них нет 409, 413, 415, 429 и 503 — то есть ровно тех, что различают для клиента
// «занято» (503), «слишком много попыток» (429), «нечего стирать» (409), «тело
// велико» (413) и «не тот тип запроса» (415). Нечем ответить, кроме как поставить
// код руками.
//
// Вторая: httpd_resp_send_err() отдаёт text/html и закрывает соединение, а SPA
// нужно разбирать тело ошибки (отличить 401 от 429 и показать «подождите N
// секунд»), то есть ошибка должна быть таким же JSON, как успешный ответ.
esp_err_t failJson(httpd_req_t* r, const char* status, const char* code) {
  JsonDocument d;
  d["ok"] = false;
  d["error"] = code;
  // Тело ошибки фиксированного размера, поэтому стека хватает с запасом на
  // самый длинный код, который здесь встречается.
  char body[96];
  const size_t n = serializeJson(d, body, sizeof(body));
  if (n == 0) {
    log::error("http: error json did not fit for code %s", code);
    return httpd_resp_send_err(r, HTTPD_500_INTERNAL_SERVER_ERROR, "error json overflow");
  }
  httpd_resp_set_status(r, status);
  return sendJson(r, body, n);
}

// Ответ на готовый JSON-буфер. Единая точка для заголовков приватности,
// чтобы один маршрут не забыл про no-store и не отдал мастер-пароль из кэша
// браузера.
esp_err_t sendJson(httpd_req_t* r, const char* body, size_t len) {
  httpd_resp_set_type(r, "application/json");
  httpd_resp_set_hdr(r, "Cache-Control", "no-store");
  httpd_resp_set_hdr(r, "X-Content-Type-Options", "nosniff");
  return httpd_resp_send(r, body, len);
}

// Сериализация документа в заранее выделенный буфер. Формулировка ошибки здесь
// одна на весь API: клиенту не полезно знать, в какой именно из двадцати
// обработчиков документ не поместился.
esp_err_t sendDoc(httpd_req_t* r, JsonDocument& doc, const char* what) {
  const int n = measureJson(doc);
  if (n < 0) {
    log::error("http: %s doc is broken", what);
    return failJson(r, "500 Internal Server Error", "json_build_failed");
  }
  // Один байт на нуль-терминатор: httpd_resp_send умеет работать с длиной без
  // него, но буфер без терминатора ломает отладку и любые последующие strlen().
  char* buf = static_cast<char*>(malloc(static_cast<size_t>(n) + 1));
  if (buf == nullptr) {
    log::error("http: %s json alloc failed for %d bytes", what, n);
    return httpd_resp_send_err(r, HTTPD_500_INTERNAL_SERVER_ERROR, "out of memory");
  }
  const size_t wrote = serializeJson(doc, buf, static_cast<size_t>(n) + 1);
  if (wrote == 0) {
    // Буфер рассчитан ровно по measureJson, поэтому сюда попасть не должны:
    // либо документ изменился между замером и сериализацией. Отдать 500, а не
    // усечённый JSON — иначе клиент разберёт половину документа и решит, что
    // запись просто не нашлась.
    free(buf);
    log::error("http: %s json serialize failed", what);
    return httpd_resp_send_err(r, HTTPD_500_INTERNAL_SERVER_ERROR, "json serialize failed");
  }
  const esp_err_t err = sendJson(r, buf, wrote);
  // Тело ответа уже ушло в сокет, поэтому стирать буфер нужно ДО освобождения,
  // иначе компилятор вправе переиспользовать память под что угодно раньше, чем
  // lwIP допишет её в сокет. Для мастер-пароля это была бы утечка через
  // переиспользованный кусок памяти.
  crypto::wipe(buf, wrote);
  free(buf);
  return err;
}

// То же для мелких ответов без динамического буфера: health и ошибки, где
// размер известен заранее.
esp_err_t sendStaticJson(httpd_req_t* r, const char* body) {
  return sendJson(r, body, strlen(body));
}

// Проверка Origin для изменяющих запросов.
//
// Зачем: устройство доступно по USB-NCM хосту, но запрос с чужого Origin означает
// браузер на другой странице, который пытается управлять хранилищем. Без CORS
// браузер не прочитает ответ, но ЗАПРОС всё равно уйдёт — то есть без этой
// проверки CSRF-подобная атака со страницы злоумышленника работала бы в одном
// направлении: пароль provisioning'а в ответе ей не достанется, но запись в
// хранилище — вполне.
//
// Сравнение регистронезависимое по схеме и хосту, порт при сравнении схемы
// отбрасывается: Origin без порта означает порт по умолчанию.
bool originMatchesHost(httpd_req_t* r) {
  // В IDF 4.4 httpd_req_get_hdr_value_len() возвращает size_t, а ноль значит
  // «поля нет». Отсутствие Origin не считается нарушением: это не браузерный
  // запрос (curl, тесты) либо same-origin, и запрет сделал бы устройство
  // недоступным из командной строки.
  const size_t olen = httpd_req_get_hdr_value_len(r, "Origin");
  if (olen == 0) {
    return true;
  }
  char buf[80];
  if (olen >= sizeof(buf)) {
    // Не помещается — отвергаем. Разбирать частично нельзя: обрезанный хост
    // сравнился бы с префиксом настоящего и прошёл бы проверку.
    return false;
  }
  if (httpd_req_get_hdr_value_str(r, "Origin", buf, sizeof(buf)) != ESP_OK) {
    return false;
  }
  // Отрезаем схему. Ищем "://", после него идёт authority до '/'.
  const char* schemeEnd = strstr(buf, "://");
  if (schemeEnd == nullptr) {
    return false;
  }
  const char* hostStart = schemeEnd + 3;
  const char* hostEnd = strchr(hostStart, '/');
  size_t hostLen = (hostEnd != nullptr) ? static_cast<size_t>(hostEnd - hostStart)
                                        : strlen(hostStart);
  // Отбрасываем порт, если он есть: http://h:80 и http://h — один и тот же
  // источник, и отвергать второе было бы ложным срабатыванием.
  const char* colon = static_cast<const char*>(memchr(hostStart, ':', hostLen));
  if (colon != nullptr) {
    hostLen = static_cast<size_t>(colon - hostStart);
  }
  if (hostLen == 0) {
    return false;
  }

  // Host обязан присутствовать: HTTP/1.1 требует его, и без него сравнивать
  // не с чем. Отсутствие — отказ, а не «не проверять».
  char hostBuf[80];
  const size_t hostHdrLen = httpd_req_get_hdr_value_len(r, "Host");
  if (hostHdrLen == 0 || hostHdrLen >= sizeof(hostBuf)) {
    return false;
  }
  if (httpd_req_get_hdr_value_str(r, "Host", hostBuf, sizeof(hostBuf)) != ESP_OK) {
    return false;
  }
  // То же для Host: 192.168.7.1:80 и 192.168.7.1 совпадают.
  size_t hdrHostLen = strlen(hostBuf);
  const char* hdrColon = strchr(hostBuf, ':');
  if (hdrColon != nullptr) {
    hdrHostLen = static_cast<size_t>(hdrColon - hostBuf);
  }
  return hostLen == hdrHostLen && strncasecmp(hostStart, hostBuf, hostLen) == 0;
}

// Host обязан называть само устройство.
//
// Проверка Origin выше ловит браузерный запрос с чужой страницы, но не ловит
// подделку, в которой злоумышленник послал Host: 192.168.7.1 и Origin:
// http://192.168.7.1 одновременно: оба заголовка он контролирует. Единственная
// защита, не зависящая от заголовков, — убедиться, что адрес в Host совпадает с
// тем, под которым устройство отвечает.
//
// Сравнение идёт с собственной точки зрения: net_bridge::ip() отдаёт адрес, на
// котором устройство реально слушает. Никакой конфигурации из заголовков.
//
// Строгий вид: только числовой адрес, ровно совпадающий. «localhost» не
// принимается — иначе подставился бы любой процесс на машине, к которой
// подключён USB-NCM, а это ровно тот случай, который проверка обязана ловить.
//
// Пропуск: если адреса ещё нет (мост не поднялся), маршрута на хосте не
// существует и сравнивать не с чем — тогда проверка пропускается. Мост
// поднимается до старта httpd, так что в рабочем состоянии она включена.
bool hostIsDevice(httpd_req_t* r) {
  char hostBuf[80];
  const size_t len = httpd_req_get_hdr_value_len(r, "Host");
  if (len == 0 || len >= sizeof(hostBuf)) {
    return false;
  }
  if (httpd_req_get_hdr_value_str(r, "Host", hostBuf, sizeof(hostBuf)) != ESP_OK) {
    return false;
  }
  size_t hostLen = strlen(hostBuf);
  const char* colon = strchr(hostBuf, ':');
  if (colon != nullptr) {
    hostLen = static_cast<size_t>(colon - hostBuf);
  }
  // 15 символов — предел длины "255.255.255.255".
  if (hostLen == 0 || hostLen >= 16) {
    return false;
  }

  uint8_t mine[4] = {};
  if (!net_bridge::ip(mine)) {
    return true;  // адреса нет — сравнивать не с чем
  }

  // Строгий разбор "a.b.c.d": ровно четыре части, каждая 0..255, без букв и без
  // ведущих нулей. Разбор на глаз ("если только цифры и точки") прощал бы
  // "1.2.3.4.5" и "1.2.3.", а memcmp с четырьмя байтами такие строки сравнил бы
  // с первыми четырьмя октетами и мог бы случайно совпасть.
  uint8_t got[4] = {};
  size_t part = 0;
  size_t digits = 0;
  unsigned val = 0;
  for (size_t i = 0; i <= hostLen; ++i) {
    const char c = (i < hostLen) ? hostBuf[i] : '.';
    if (c >= '0' && c <= '9') {
      val = val * 10 + static_cast<unsigned>(c - '0');
      if (++digits > 3 || val > 255) {
        return false;
      }
    } else if (c == '.') {
      if (part >= 4 || digits == 0) {
        return false;
      }
      got[part++] = static_cast<uint8_t>(val);
      val = 0;
      digits = 0;
    } else {
      return false;  // буква, пробел или двоеточие не там
    }
  }
  // part == 4 гарантирует завершающая точка цикла; хвост после четвёртой части
  // поймался бы как не-цифра.
  if (memcmp(got, mine, sizeof(got)) == 0) {
    return true;
  }
  log::warn("http: Host %.*s is not an address of this device", static_cast<int>(hostLen),
            hostBuf);
  return false;
}

// Sec-Fetch-Site — заголовок, который браузер шлёт всегда и который подделать из
// обычного fetch() нельзя: он forbidden-header, его не выставляет JS.
//
// Смысл в том, что браузерный запрос с чужой страницы однозначно помечен
// cross-site, даже если злоумышленник подделал Origin. Наивная проверка Origin
// для этого не годится: Origin можно задать вручную в curl или в
// fetch(..., {mode:'no-cors'}), и тогда подделка Origin не отличима от
// same-origin.
//
// Пропуск: curl и тесты заголовка не шлют, и их отсутствие не должно делать
// устройство недоступным из командной строки. Если заголовок ЕСТЬ, его значение
// обязано быть same-origin или none — иначе отказ.
bool secFetchSiteAllowed(httpd_req_t* r) {
  const size_t len = httpd_req_get_hdr_value_len(r, "Sec-Fetch-Site");
  if (len == 0) {
    return true;  // не браузерный клиент
  }
  char buf[32];
  if (len >= sizeof(buf)) {
    return false;
  }
  if (httpd_req_get_hdr_value_str(r, "Sec-Fetch-Site", buf, sizeof(buf)) != ESP_OK) {
    return false;
  }
  const bool sameOrigin = (strcasecmp(buf, "same-origin") == 0);
  const bool none = (strcasecmp(buf, "none") == 0);
  if (!sameOrigin && !none) {
    log::warn("http: Sec-Fetch-Site %s refused", buf);
    return false;
  }
  return true;
}

// Читает тело запроса в out и разбирает как JSON. outSize — вместимость out;
// тело длиннее отвергается, а не усекается: усечённый JSON иногда разбирается
// и выглядит как корректный запрос.
//
// Content-Type обязан быть application/json. Без этой проверки клиент может
// прислать urlencoded, ArduinoJson его не разберёт и вернёт пустой документ,
// то есть обработчик решит, что поле отсутствует — тихий отказ вместо понятной
// ошибки.
// Ширину Content-Type сравниваем по длине префикса, а не до ';': реальные клиенты
// шлют "application/json; charset=utf-8", и отвергнуть такое — значит
// несовместимость с любым нормальным fetch(). При этом "application/jsonx"
// префиксом проходит, поэтому после сравнения обязательно проверяется, что
// дальше либо конец строки, либо ';'. Иначе подмена типа проходит молча.
bool contentTypeIsJson(httpd_req_t* r) {
  const size_t len = httpd_req_get_hdr_value_len(r, "Content-Type");
  if (len == 0) {
    return false;
  }
  char ctype[64];
  if (len >= sizeof(ctype)) {
    return false;
  }
  if (httpd_req_get_hdr_value_str(r, "Content-Type", ctype, sizeof(ctype)) != ESP_OK) {
    return false;
  }
  static const char kJson[] = "application/json";
  const size_t kLen = sizeof(kJson) - 1;
  if (strncasecmp(ctype, kJson, kLen) != 0) {
    return false;
  }
  return ctype[kLen] == '\0' || ctype[kLen] == ';' || ctype[kLen] == ' ';
}

esp_err_t readJsonBody(httpd_req_t* r, JsonDocument& doc) {
  if (!contentTypeIsJson(r)) {
    return failJson(r, "415 Unsupported Media Type", "json_content_type_required");
  }
  if (r->content_len < 0) {
    // Отрицательный content_len в IDF 4.4 означает «длина неизвестна», то есть
    // chunked-кодирование, которое httpd не принимает. Отвергаем явно, иначе
    // цикл чтения ниже считал бы мусор и разбирал его как JSON.
    return failJson(r, "411 Length Required", "content_length_required");
  }

  if (r->content_len == 0) {
    return failJson(r, "400 Bad Request", "empty_body");
  }
  if (r->content_len > static_cast<int>(config::kHttpMaxBody)) {
    // Отвечаем ДО чтения. Тело не вычитывается до конца, поэтому клиент может
    // уйти на RST — это правильно: чем больше тела, тем меньше причин его
    // принимать.
    return failJson(r, "413 Payload Too Large", "body_too_large");
  }

  // Буфер на config::kHttpMaxBody в PSRAM: на стеке задачи httpd (8192 б,
  // из которых четверть занята буфером раздачи) такой блок не поместился бы.
  char* buf = static_cast<char*>(heap_caps_malloc(config::kHttpMaxBody + 1, MALLOC_CAP_SPIRAM));
  if (buf == nullptr) {
    // Фолбэк в обычную кучу: без PSRAM устройство должно работать, пусть и с
    // меньшим лимитом тела.
    buf = static_cast<char*>(malloc(config::kHttpMaxBody + 1));
  }
  if (buf == nullptr) {
    return failJson(r, "500 Internal Server Error", "out_of_memory");
  }

  size_t got = 0;
  while (got < r->content_len) {
    const int n = httpd_req_recv(r, buf + got, r->content_len - got);
    if (n <= 0) {
      // n == HTTPD_SOCK_ERR_TIMEOUT клиент не дослал тело: это 408, а не пустое
      // тело. Различать обязательно, иначе «пароль не доехал» выглядит как
      // «пароль неверен» и пользователь будет искать не там.
      const bool timedOut = (n == HTTPD_SOCK_ERR_TIMEOUT);
      crypto::wipe(buf, got);
      free(buf);
      return timedOut ? failJson(r, "408 Request Timeout", "body_read_timeout")
                      : failJson(r, "400 Bad Request", "body_read_failed");
    }
    got += static_cast<size_t>(n);
  }
  buf[got] = '\0';

  DeserializationError err = deserializeJson(doc, buf, got);
  // Тело может содержать пароль, поэтому стирается ДО любого разбора ошибки:
  // если разбор упал, документ пуст и пароль в нём не появится, но в буфере он
  // остался бы лежать до следующего malloc на то же место.
  crypto::wipe(buf, got);
  free(buf);

  if (err) {
    return failJson(r, "400 Bad Request", "malformed_json");
  }
  if (!doc.is<JsonObject>()) {
    // Массив или строка вместо объекта — валидный JSON, но не тот, что ждёт
    // обработчик: doc["password"] на массиве даёт null и выглядит как
    // отсутствие поля.
    return failJson(r, "400 Bad Request", "expected_json_object");
  }
  return ESP_OK;
}

// Значение символа base64 (RFC 4648) или -1. '=' здесь не decoded: padding
// обрабатывается вызывающим, ему нужен только признак «валидный символ».
int b64Value(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

// Строгий декодер base64 для поля keyfile: только стандартный алфавит, padding
// ровно в последней группе и не более двух '='. Возвращаемое *outLen никогда не
// превышает outMax, поэтому буфер вызывающего не переполняется ни при каком
// входе.
//
// Ленивость к «нестандартному» base64 здесь была бы вредом, а не пользой:
// присланный ключевой файл обязан быть байт-в-байт тем файлом, что хранился
// при provisioning, и приём битого encoding'а дал бы молча неверный ключ.
bool base64Decode(const char* s, size_t len, uint8_t* out, size_t outMax,
                  size_t* outLen) {
  if (len == 0 || (len % 4) != 0) {
    return false;
  }
  size_t o = 0;
  for (size_t i = 0; i < len; i += 4) {
    const int a = b64Value(s[i]);
    const int b = b64Value(s[i + 1]);
    if (a < 0 || b < 0) {
      return false;  // '=' в первых двух позициях тоже отсекается здесь
    }
    const bool cPad = (s[i + 2] == '=');
    const bool dPad = (s[i + 3] == '=');
    if ((cPad || dPad) && i + 4 != len) {
      return false;  // padding только в последней группе
    }
    if (cPad && !dPad) {
      return false;  // "xx=x" не бывает; допустимы только "xx==" и "xxx="
    }
    if (!cPad && b64Value(s[i + 2]) < 0) {
      return false;
    }
    if (!dPad && b64Value(s[i + 3]) < 0) {
      return false;
    }
    const int c = cPad ? 0 : b64Value(s[i + 2]);
    const int d = dPad ? 0 : b64Value(s[i + 3]);
    if (o >= outMax) {
      return false;
    }
    out[o++] = static_cast<uint8_t>((a << 2) | (b >> 4));
    if (cPad) {
      break;  // "xx==" — ровно один выходной байт
    }
    if (o >= outMax) {
      return false;
    }
    out[o++] = static_cast<uint8_t>(((b & 0x0F) << 4) | (c >> 2));
    if (dPad) {
      break;  // "xxx=" — ровно два выходных байта
    }
    if (o >= outMax) {
      return false;
    }
    out[o++] = static_cast<uint8_t>(((c & 0x03) << 6) | d);
  }
  *outLen = o;
  return true;
}

// Опциональное поле ключевого файла (base64) из уже разобранного тела запроса.
// Имя поля — параметр: unlock/provision читают "keyfile", rekey читает
// "keyfile_current" и "keyfile_new".
//
// Отсутствие поля и пустая строка означают «файла нет» — это штатное состояние
// для хранилища без ключевого файла, а не ошибка. Наличие непустого, но
// неверного значения — ошибка, уже отправленная клиенту.
//
// *out выделяется на kKeyFileMaxBytes (всегда столько, чтобы wipe() знал
// фактический размер), вызывающий обязан crypto::wipe + free на ЛЮБОМ пути
// после вызова, включая отказы дальше по коду. При ошибке буфер стирает и
// освобождает сама эта функция.
esp_err_t parseKeyfileField(httpd_req_t* r, JsonDocument& doc, const char* key,
                            uint8_t** out, size_t* outLen) {
  *out = nullptr;
  *outLen = 0;
  JsonVariant v = doc[key];
  if (v.isNull()) {
    return ESP_OK;
  }
  if (!v.is<const char*>()) {
    return failJson(r, "400 Bad Request", "keyfile_not_a_string");
  }
  const char* b64 = v.as<const char*>();
  const size_t n = strlen(b64);
  if (n == 0) {
    return ESP_OK;
  }
  if ((n % 4) != 0) {
    return failJson(r, "400 Bad Request", "keyfile_invalid_base64");
  }
  // Верхняя граница декодированного размера: 3 байта на каждую группу из 4.
  // Если она уже больше лимита, файл не влезает в хранилище независимо от
  // padding'а — отказ до выделения и до декодирования.
  if ((n / 4) * 3 > config::kKeyFileMaxBytes) {
    return failJson(r, "400 Bad Request", "keyfile_too_large");
  }
  uint8_t* buf =
      static_cast<uint8_t*>(heap_caps_malloc(config::kKeyFileMaxBytes, MALLOC_CAP_SPIRAM));
  if (buf == nullptr) {
    buf = static_cast<uint8_t*>(malloc(config::kKeyFileMaxBytes));
  }
  if (buf == nullptr) {
    return failJson(r, "500 Internal Server Error", "out_of_memory");
  }
  size_t decoded = 0;
  if (!base64Decode(b64, n, buf, config::kKeyFileMaxBytes, &decoded)) {
    crypto::wipe(buf, config::kKeyFileMaxBytes);
    free(buf);
    return failJson(r, "400 Bad Request", "keyfile_invalid_base64");
  }
  if (decoded == 0) {
    // Вырождение вида "====": валидный base64, но байтов нет. Приравниваем к
    // «файла нет», а не к ошибке — иначе клиент, вычистивший поле, получил бы
    // 400 на запрос без ключевого файла.
    crypto::wipe(buf, config::kKeyFileMaxBytes);
    free(buf);
    return ESP_OK;
  }
  *out = buf;
  *outLen = decoded;
  return ESP_OK;
}

// Проверка сессии. 401 без различения причин: «нет токена», «не тот токен» и
// «сессии нет» отвечают одинаково, иначе по коду ответа можно перебирать
// действительные токены.
esp_err_t requireSession(httpd_req_t* r) {
  // Один код ответа на все причины отказа («нет заголовка», «сессии нет»,
  // «токен не тот»). Различать их в коде нельзя: иначе по 401 удалось бы
  // отличить «токен неверен» от «сессия не открыта» и перебирать действительные.
  //
  // httpd_req_get_hdr_value_len() возвращает size_t, а НЕ esp_err_t, и ноль
  // означает «поля нет». Сравнение с ESP_OK здесь компилировалось бы и было бы
  // ложью: ESP_OK == 0 совпало бы с отсутствующим полем.
  const size_t len = httpd_req_get_hdr_value_len(r, "X-PM-Session");
  if (len == 0) {
    return failJson(r, "401 Unauthorized", "session_required");
  }
  // Валидный токен — ровно kSessionTokenHexLen символов. Буквально равную длину
  // проверяем сразу, чтобы не копировать в буфер мусор произвольного размера.
  if (len != auth::kSessionTokenHexLen) {
    log::warn("http: %s rejected, session token len %u", r->uri, static_cast<unsigned>(len));
    return failJson(r, "401 Unauthorized", "session_required");
  }
  char tok[auth::kSessionTokenHexLen + 1];
  if (httpd_req_get_hdr_value_str(r, "X-PM-Session", tok, sizeof(tok)) != ESP_OK) {
    return failJson(r, "401 Unauthorized", "session_required");
  }
  const bool ok = auth::sessionValid(tok, len);
  // Стирается в обоих случаях: в буфере лежит присланный клиентом токен, и
  // валидный не должен ждать в стеке до конца обработчика.
  crypto::wipe(tok, sizeof(tok));
  if (!ok) {
    log::warn("http: %s rejected, bad session", r->uri);
    return failJson(r, "401 Unauthorized", "session_required");
  }
  return ESP_OK;
}

// Origin-проверка для всех изменяющих методов. Вызывается ДО чтения тела, чтобы
// чужой Origin не получил даже возможности начать разбор запроса.
// Три независимые проверки вместо одной.
//
// Порядок и смысл каждой:
//
//  1. originMatchesHost — ловит обычный браузерный запрос с чужой страницы.
//     Одной её мало: Origin подделывается из curl и из fetch(mode:'no-cors'),
//     поэтому подделка Origin не отличима от same-origin.
//  2. secFetchSiteAllowed — ловит именно браузер. Sec-Fetch-Site запрещённый
//     заголовок, JS его не выставляет, то есть значение «cross-site» может
//     прийти только от настоящего браузера с чужой страницы. Без curl его нет,
//     и это пропускается, иначе устройство стало бы недоступно из командной
//     строки.
//  3. hostIsDevice — единственная проверка, которая не зависит от заголовков
//     вообще: злоумышленник контролирует и Host, и Origin, но не может
//     назвать в Host адрес, которого у устройства нет.
//
// Отказ на любой из них одинаков, чтобы не сообщать атакующему, какая именно
// проверка его выдала.
esp_err_t requireSameOrigin(httpd_req_t* r) {
  if (!originMatchesHost(r)) {
    log::warn("http: %s rejected, cross-origin", r->uri);
    return failJson(r, "403 Forbidden", "cross_origin_refused");
  }
  if (!secFetchSiteAllowed(r)) {
    return failJson(r, "403 Forbidden", "cross_site_refused");
  }
  if (!hostIsDevice(r)) {
    return failJson(r, "403 Forbidden", "host_refused");
  }
  return ESP_OK;
}

// Ответ на результат job'а. Pending и Busy — не ошибки, а разные состояния:
// Pending означает «опроси позже», Busy «повтори сейчас». Слить их в один код
// нельзя, клиент либо перестанет опрашивать, либо зальёт устройство повторами.
esp_err_t sendJobError(httpd_req_t* r, const auth::Result res, const char* what) {
  switch (res) {
    case auth::Result::Ok:
      return ESP_OK;
    case auth::Result::Pending:
      return failJson(r, "503 Service Unavailable", "job_pending");
    case auth::Result::Busy:
      return failJson(r, "503 Service Unavailable", "busy");
    case auth::Result::WrongPassword:
      return failJson(r, "401 Unauthorized", "wrong_password");
    case auth::Result::Refused:
      return failJson(r, "409 Conflict", "refused");
    case auth::Result::Lockout:
      return failJson(r, "429 Too Many Requests", "lockout");
    case auth::Result::Error:
      log::error("http: %s failed in worker", what);
      return failJson(r, "500 Internal Server Error", "worker_error");
  }
  return failJson(r, "500 Internal Server Error", "unknown_result");
}

// Копирует поле записи в JSON с ЯВНОЙ длиной.
//
// Присваивания по const char* здесь недостаточно: в записи, прочитанной с
// флеша, нуль-байт может отсутствовать, и ArduinoJson взял бы длину по strlen() и
// ушёл бы читать за пределы поля — то есть отдал бы в JSON мусор из соседних
// байтов. У std::string_view ровно та же семантика длины, так что собственный
// буфер с гарантированным терминатором — единственный честный вариант.
//
// bufSize — размер локального буфера на стеке обработчика; он равен размеру
// поля плюс один байт на нуль-байт.
// Копирует src в buf с проверкой границ и кладёт в obj[key].
//
// Контейнер — шаблонный параметр, а не JsonDocument: список пишет в JsonObject
// по одному на запись, а карточка и секрет — в документ.
//
// Ключ принимается строкой, а не JsonVariant, и это не стилевое предпочтение.
// В ArduinoJson 7 выражение obj[key] возвращает MemberProxy, а MemberProxy
// приводится к JsonVariant через template operator T() в VariantRefBase, то есть
// это ПРИВЕДЕНИЕ К ЗНАЧЕНИЮ, а не привязка ссылки. Передав такой параметр в
// функцию, set() писал в оторванную копию и молча терял значение: ответ уходил
// с ok:true и вообще без полей.
//
// Поэтому ключ разбирается внутри, где obj[key] — полноценное lvalue-выражение и
// MemberProxy остаётся привязанным к контейнеру.
template <typename TObject>
bool setFieldBounded(TObject& obj, const char* key, const char* src, size_t srcMax,
                     char* buf, size_t bufSize) {
  if (srcMax + 1 > bufSize) {
    return false;  // вызывающий ошибся с размером, а не с данными
  }
  const size_t n = strnlen(src, srcMax);
  if (n == srcMax) {
    // Внутри srcMax нет нуль-байта, то есть буфер не нуль-терминирован. Поля в
    // записях vault всегда терминированы, поэтому это признак порчи хранилища.
    // Молча усекать нельзя: поле уехало бы битым.
    return false;
  }
  memcpy(buf, src, n + 1);
  obj[key].set(buf);
  return true;
}

// Разбор JobId из пути вида "/api/auth/job/1f4c0a...".
//
// Именно hex, а не десятичная запись: id выдаётся клиенту как 16 hex-символов,
// и разбор должен быть ровно обратным преобразованием. Разбирать строку частично
// нельзя — лишний символ означал бы подбор другого job'а.
//
// Строка фиксированной длины: это исключает неоднозначность «ведущие нули»
// (0x0abc… и 0xabc… — один и тот же id) и делает длину маршрута постоянной, то
// есть httpd не получает шаблонов разной длины для одного и того же поля.
bool pathJobId(const char* uri, const char* prefix, auth::JobId* out) {
  static const char kHexDigits[] = "0123456789abcdef";
  constexpr size_t kLen = 16;
  const size_t plen = strlen(prefix);
  if (strncmp(uri, prefix, plen) != 0) {
    return false;
  }
  const char* p = uri + plen;
  auth::JobId v = 0;
  for (size_t i = 0; i < kLen; ++i) {
    const char c = p[i];
    const char* pos = static_cast<const char*>(memchr(kHexDigits, c, sizeof(kHexDigits) - 1));
    if (pos == nullptr) {
      return false;
    }
    // Старшие разряды: младшие байты выгружаются первыми, поэтому сдвиг идёт
    // от kLen-1 к 0.
    v = (v << 4) | static_cast<auth::JobId>(pos - kHexDigits);
  }
  if (p[kLen] != '\0') {
    return false;
  }
  *out = v;
  return true;
}

// Разбор id записи из пути "/api/entries/7".
//
// Возвращает false, если хвост пути не является положительным числом. Строгость
// здесь важна: разбирать "7abc" частично нельзя, потому что id 7 существует и
// клиент получил бы чужую запись вместо ошибки.
bool pathId(const char* uri, const char* prefix, uint32_t* out) {
  const size_t plen = strlen(prefix);
  if (strncmp(uri, prefix, plen) != 0) {
    return false;
  }
  const char* p = uri + plen;
  if (*p < '0' || *p > '9') {
    return false;
  }
  uint32_t v = 0;
  for (; *p != '\0'; ++p) {
    if (*p < '0' || *p > '9') {
      return false;
    }
    const uint32_t digit = static_cast<uint32_t>(*p - '0');
    // Проверка до умножения: без неё id из 10 цифр тихо обернулся бы и совпал с
    // существующей записью.
    if (v > (UINT32_MAX - digit) / 10) {
      return false;
    }
    v = v * 10 + digit;
  }
  if (v == 0) {
    return false;  // 0 у vault означает «новая запись», не адрес
  }
  *out = v;
  return true;
}

// ─── Auth API ─────────────────────────────────────────────────────────────────

// GET /api/auth/state
//
// Единственный маршрут, который должен работать без сессии: по нему UI
// узнаёт, что показать. Поэтому здесь НИКОГДА не отдаётся токен и никакая
// другая приватная величина, кроме failCount — он и предназначен для показа в
// интерфейсе.
esp_err_t authStateHandler(httpd_req_t* r) {
  RequestGuard guard;
  const auth::State s = auth::state();
  JsonDocument doc;
  doc["ok"] = true;
  doc["provisioned"] = s.provisioned;
  doc["unlocked"] = s.unlocked;
  doc["busy"] = s.busy;
  doc["failCount"] = s.failCount;
  doc["lockoutMsLeft"] = s.lockoutMsLeft;
  // Нужен ли файл для открытия: без этого признака UI не знал бы, что показать
  // на форме unlock ДО ввода пароля. Читается с флеша без пароля, подделка
  // флага вредит только подсказке — без самого файла ключ не выйдет.
  doc["keyfileRequired"] = vault::keyFileRequired();
  // Поля конфигурации, нужные UI: иначе клиент дублирует эти числа у себя и
  // разойдётся с устройством при смене прошивки.
  doc["masterPasswordChars"] = static_cast<unsigned>(config::kMasterPasswordChars);
  doc["maxEntryCount"] = static_cast<unsigned>(config::kMaxEntries);
  doc["keyFileMaxBytes"] = static_cast<unsigned>(config::kKeyFileMaxBytes);
  return sendDoc(r, doc, "auth_state");
}

// JobId в том же виде, в каком клиент обязан вернуть его в URL: 16 hex-символов.
// Числом отдавать нельзя — 64 бита в double не помещаются, и JSON отдал бы
// округлённое значение, то есть клиент опрашивал бы несуществующий job.
void writeJobIdHex(char* out, auth::JobId id) {
  static const char kHex[] = "0123456789abcdef";
  for (size_t i = 0; i < 16; ++i) {
    const unsigned shift = static_cast<unsigned>((15 - i) * 4);
    out[i] = kHex[(id >> shift) & 0x0f];
  }
  out[16] = '\0';
}

// Тело ответа на принятый job. 202 Accepted: работа ещё не сделана, клиент
// обязан опрашивать /api/auth/job/{id}.
esp_err_t sendJobAccepted(httpd_req_t* r, auth::JobId jobId) {
  char hex[17];
  writeJobIdHex(hex, jobId);
  JsonDocument doc;
  doc["ok"] = true;
  doc["job"] = hex;
  httpd_resp_set_status(r, "202 Accepted");
  return sendDoc(r, doc, "job_accepted");
}

// POST /api/auth/provision
esp_err_t authProvisionHandler(httpd_req_t* r) {
  RequestGuard guard;
  const esp_err_t g = requireSameOrigin(r);
  if (g != ESP_OK) {
    return g;
  }

  // Проверка ДО чтения тела и ДО submit: повторный provisioning поверх
  // заполненного хранилища стирает раздел. Подтверждение пользователя проверяет
  // UI, а устройство обязано отказать само, даже если запрос пришёл в обход
  // интерфейса.
  const auth::State s = auth::state();
  if (s.provisioned) {
    log::warn("http: provision refused, already provisioned");
    return failJson(r, "409 Conflict", "already_provisioned");
  }
  if (s.unlocked) {
    // Устройство не provisioned, но уже открыто — рассинхрон флеша и RAM.
    // Стирать в этом состоянии опаснее, чем отказать.
    log::error("http: provision refused, unprovisioned but unlocked");
    return failJson(r, "409 Conflict", "inconsistent_state");
  }

  // Тело опционально: пустое — provisioning без ключевого файла (штатный
  // случай), непустое — только поле keyfile в base64. Прежний запрет тела был
  // снят вместе с появлением файла: читать его целиком по-прежнему незачем.
  uint8_t* keyFile = nullptr;
  size_t keyFileLen = 0;
  if (r->content_len > 0) {
    JsonDocument doc;
    const esp_err_t rd = readJsonBody(r, doc);
    if (rd != ESP_OK) {
      return rd;
    }
const esp_err_t kfe = parseKeyfileField(r, doc, "keyfile", &keyFile, &keyFileLen);
    doc.clear();
    if (kfe != ESP_OK) {
      if (keyFile != nullptr) {
        crypto::wipe(keyFile, config::kKeyFileMaxBytes);
        free(keyFile);
      }
      return kfe;
    }
  }

  const auth::JobId id = auth::submitProvision(keyFile, keyFileLen);
  if (keyFile != nullptr) {
    // Копия уже лежит в очереди воркера; локальная больше не нужна на любом
    // пути — и при успехе, и при отказе.
    crypto::wipe(keyFile, config::kKeyFileMaxBytes);
    free(keyFile);
  }
  if (id == auth::kNoJob) {
    return failJson(r, "503 Service Unavailable", "busy");
  }
  log::info("http: provisioning requested");
  return sendJobAccepted(r, id);
}

// POST /api/auth/unlock
esp_err_t authUnlockHandler(httpd_req_t* r) {
  RequestGuard guard;
  const esp_err_t g = requireSameOrigin(r);
  if (g != ESP_OK) {
    return g;
  }

  JsonDocument doc;
  const esp_err_t rd = readJsonBody(r, doc);
  if (rd != ESP_OK) {
    return rd;
  }

  // Отсутствующее и нестроковое поле password отвергаем одинаково, чтобы по
  // ответу нельзя было отличить «поле не прислали» от «прислали не строку».
  const char* pw = doc["password"];
  if (!pw || !doc["password"].is<const char*>()) {
    return failJson(r, "400 Bad Request", "password_required");
  }
  const size_t n = strlen(pw);
  if (n < config::kMinPassChars || n >= config::kMaxPassChars) {
    // Границы проверяются здесь, а не в submit(), чтобы клиент узнал о неверной
    // длине сразу и не ждал 5.8 с воркера. Сам пароль в лог не попадает.
    log::warn("http: unlock rejected, password length %u out of range",
              static_cast<unsigned>(n));
    return failJson(r, "400 Bad Request", "password_length_out_of_range");
  }

  // Копия пароля в локальный буфер нужна затем, чтобы стереть его ДО submit() и
  // до формирования ответа: в документе ArduinoJson пароль останется лежать в
  // куче до конца обработчика, а submitUnlock() копирует его ещё раз внутрь.
  char pwCopy[config::kMaxPassChars + 1];
  memcpy(pwCopy, pw, n + 1);

  // Ключевой файл (base64) — опционально и ДО очистки документа: parse читает
  // doc["keyfile"]. Отказ здесь возвращает пароль в кучу документа, поэтому
  // pwCopy стирается перед возвратом.
  uint8_t* keyFile = nullptr;
  size_t keyFileLen = 0;
  const esp_err_t kfe = parseKeyfileField(r, doc, "keyfile", &keyFile, &keyFileLen);
  if (kfe != ESP_OK) {
    crypto::wipe(pwCopy, sizeof(pwCopy));
    return kfe;
  }

  // Документ очищается сразу после копий: в куче ArduinoJson пароль и файл
  // остались бы лежать до конца обработчика. Очистка освобождает память, но
  // вполне может НЕ занулить её, поэтому копии стираются отдельно, уже после
  // submit().
  doc.clear();

  const auth::JobId id = auth::submitUnlock(pwCopy, keyFile, keyFileLen);
  crypto::wipe(pwCopy, sizeof(pwCopy));
  if (keyFile != nullptr) {
    crypto::wipe(keyFile, config::kKeyFileMaxBytes);
    free(keyFile);
  }
  if (id == auth::kNoJob) {
    // Воркер занят ИЛИ идёт блокировка по неудачным попыткам: submit() отвергает
    // оба случая одинаково, чтобы не давать oracle по состоянию lockout.
    return failJson(r, "503 Service Unavailable", "busy");
  }
  log::info("http: unlock requested");
  return sendJobAccepted(r, id);
}

// GET /api/auth/job/{id}
esp_err_t authJobHandler(httpd_req_t* r) {
  RequestGuard guard;
  auth::JobId jobId = auth::kNoJob;
  if (!pathJobId(r->uri, "/api/auth/job/", &jobId)) {
    return failJson(r, "400 Bad Request", "bad_job_id");
  }

  auth::JobView view = {};
  if (!auth::poll(jobId, &view)) {
    // Такого job'а нет или он вытеснен следующим. Клиент должен начать заново,
    // поэтому код именно 404, а не пустой успех.
    return failJson(r, "404 Not Found", "unknown_job");
  }

  if (view.result == auth::Result::Pending) {
    JsonDocument doc;
    doc["ok"] = true;
    doc["state"] = "pending";
    return sendDoc(r, doc, "job_pending");
  }

  if (view.result != auth::Result::Ok) {
    // Ошибка job'а: код из sendJobError(). Пароль в этот момент уже стёрт
    // poll()'ом либо его не было вовсе. Имя job'а — из его вида, а НЕ
    // auth::toString(result): toString() принимает Result, и подмена одного
    // перечисления другим компилировалась бы только при совпадении базовых
    // типов, а означала бы вывод «pending» вместо «unlock».
    return sendJobError(r, view.result, jobKindName(view.kind));
  }

  JsonDocument doc;
  doc["ok"] = true;
  doc["result"] = auth::toString(view.result);
  doc["job"] = jobKindName(view.kind);
  // Мастер-пароль отдаётся только здесь и только один раз: poll() стирает его в
  // слоте, поэтому второй запрос вернёт ok без пароля. Ниже пароль стирается
  // ДО возврата, а не после sendDoc(): sendDoc копирует буфер в сокет, и стирать
  // его раньше означало бы отдать нули.
  if (view.kind == auth::Job::Provision && view.password[0] != '\0') {
    doc["password"] = view.password;
  }
  // Токен новой сессии — второй секрет того же ответа. Без него разблокировавший
  // клиент не смог бы ни одного запроса к /api/entries: токен живёт только в
  // памяти модуля, а GET /api/auth/session требует его заголовком. Он тоже
  // одноразовый: poll() стирает его в слоте, и второй опрос вернёт ok без него.
  //
  // Секрет в doc[] копируется, поэтому оригинал view стирается сразу после
  // sendDoc(), а не через doc.clear(): тот освобождает память, но не обязан
  // занулить её.
  if (view.sessionToken[0] != '\0') {
    doc["session_token"] = view.sessionToken;
  }
  const esp_err_t err = sendDoc(r, doc, "job_result");
  crypto::wipe(view.password, sizeof(view.password));
  crypto::wipe(view.sessionToken, sizeof(view.sessionToken));
  return err;
}

// POST /api/auth/lock
esp_err_t authLockHandler(httpd_req_t* r) {
  RequestGuard guard;
  const esp_err_t g = requireSameOrigin(r);
  if (g != ESP_OK) {
    return g;
  }
  // Сессия обязательна: без неё запрос «закрыть меня» от кого угодно закрыл бы
  // чужую сессию. Это операция без необратимых последствий, но и оставлять её
  // без проверки нельзя — иначе чужая страница могла бы выбивать устройство из
  // сессии (DoS).
  const esp_err_t s = requireSession(r);
  if (s != ESP_OK) {
    return s;
  }
  if (!auth::lock()) {
    return failJson(r, "500 Internal Server Error", "lock_failed");
  }
  JsonDocument doc;
  doc["ok"] = true;
  doc["unlocked"] = false;
  return sendDoc(r, doc, "auth_lock");
}

// GET /api/auth/session
//
// Место, где токен выдаётся. Пароль при этом НЕ требуется: он уже предъявлен
// unlock'ом, и повторный запрос пароля здесь означал бы второй круг PBKDF2.
// Вместо этого проверяется именно токен.
esp_err_t authSessionHandler(httpd_req_t* r) {
  RequestGuard guard;
  const esp_err_t s = requireSession(r);
  if (s != ESP_OK) {
    return s;
  }
  char token[auth::kSessionTokenHexLen + 1];
  if (!auth::sessionTokenHex(token, sizeof(token))) {
    // Сессия прошла проверку, но токен не читается — состояние рассогласовано.
    log::error("http: session valid but token unreadable");
    return failJson(r, "500 Internal Server Error", "token_unavailable");
  }
  JsonDocument doc;
  doc["ok"] = true;
  doc["token"] = token;
  const auth::State st = auth::state();
  doc["expiresInMs"] = config::kSessionTtlMs;
  doc["entryCount"] = static_cast<unsigned>(st.provisioned ? st.unlocked ? vault::count() : 0 : 0);
  const esp_err_t err = sendDoc(r, doc, "auth_session");
  crypto::wipe(token, sizeof(token));
  return err;
}

// POST /api/auth/reset
esp_err_t authResetHandler(httpd_req_t* r) {
  RequestGuard guard;
  const esp_err_t g = requireSameOrigin(r);
  if (g != ESP_OK) {
    return g;
  }
  // Сессия обязательна, и это решение владельца проекта, а не компромисс.
  // Сброс уничтожает хранилище, и без сессии любой, кто дотянулся до устройства
  // по USB, стёр бы чужие данные одной кнопкой.
  //
  // Цена этого выбора известна и принята: сброс по ЗАБЫТОМУ мастер-паролю через
  // HTTP недостижим, потому что пароль и есть единственный способ получить
  // сессию. Восстановление в этом случае — физическое: стирание раздела vault
  // через esptool или удержание кнопки на пустой плате. Формулировка «сброс для
  // забытого пароля» в описании API была неточной: reset сбрасывает УСТРОЙКУ,
  // а не пароль.
  const esp_err_t s = requireSession(r);
  if (s != ESP_OK) {
    return s;
  }

  JsonDocument doc;
  const esp_err_t rd = readJsonBody(r, doc);
  if (rd != ESP_OK) {
    return rd;
  }
  // Подтверждение обязано быть точной строкой. Сравнение без const-time здесь
  // не нужно: это не секрет, а защита от случайного нажатия, и значение
  // заранее известно пользователю из интерфейса.
  const char* confirm = doc["confirm"];
  if (!confirm || !doc["confirm"].is<const char*>() ||
      strcmp(confirm, "RESET") != 0) {
    log::warn("http: reset refused, no confirmation");
    return failJson(r, "400 Bad Request", "confirmation_required");
  }

  const auth::JobId id = auth::submitReset();
  if (id == auth::kNoJob) {
    return failJson(r, "503 Service Unavailable", "busy");
  }
  // В лог уходит только факт запроса, без подтверждения и без содержимого.
  log::warn("http: vault reset requested, job %u", static_cast<unsigned>(id));
  return sendJobAccepted(r, id);
}

// POST /api/auth/rekey — смена мастер-пароля и/или ключевого файла.
//
// Старый мастер-пароль ОБЯЗАТЕЛЕН, а при включённом ключевом файле — и текущий
// файл (keyfile_current): пара «пароль + файл» проверяется в воркере боевым
// KDF (vault::begin) ДО самой смены ключа. Сессии для этого недостаточно — она
// живёт в RAM, не переживает перезагрузку и доказывает лишь то, что устройство
// когда-то открыли, а не текущее знание старого пароля.
//
// Тело (ключевые файлы — base64, ≤ kKeyFileMaxBytes):
//   old_password     текущий мастер-пароль, обязателен
//   password         новый мастер-пароль; отсутствие или "" = оставить прежним
//   keyfile_current  текущий файл; обязателен, если он включён
//   keyfile_action   "keep" | "set" | "clear" (по умолчанию "keep")
//   keyfile_new      новый файл; обязателен при action="set"
//
// Сессия обязана проверяться: без неё любой, кто дотянулся до открытого
// устройства по USB, мог бы сменить пароль на свой и увести данные у владельца.
//
// Ответ — 202 + поллинг /api/auth/job/{id}, как у unlock и reset: проверка
// старого пароля и смена ключа — два полных круга PBKDF2, и это не укладывается
// в один HTTP-запрос.
esp_err_t authRekeyHandler(httpd_req_t* r) {
  RequestGuard guard;
  const esp_err_t g = requireSameOrigin(r);
  if (g != ESP_OK) {
    return g;
  }
  const esp_err_t s = requireSession(r);
  if (s != ESP_OK) {
    return s;
  }

  JsonDocument doc;
  const esp_err_t rd = readJsonBody(r, doc);
  if (rd != ESP_OK) {
    return rd;
  }

  // Старый пароль: длина проверяется здесь, чтобы клиент узнал об ошибке сразу,
  // а не после PBKDF2 в воркере.
  const char* oldPw = doc["old_password"];
  if (!oldPw || !doc["old_password"].is<const char*>()) {
    return failJson(r, "400 Bad Request", "old_password_required");
  }
  const size_t oldLen = strlen(oldPw);
  if (oldLen < config::kMinPassChars || oldLen >= config::kMaxPassChars) {
    log::warn("http: rekey rejected, old password length %u out of range",
              static_cast<unsigned>(oldLen));
    return failJson(r, "400 Bad Request", "old_password_length_out_of_range");
  }
  char oldCopy[config::kMaxPassChars + 1];
  memcpy(oldCopy, oldPw, oldLen + 1);

  // Новый пароль опционален: пустое или отсутствующее поле означает «оставить
  // прежним», воркер возьмёт oldPassword.
  char newCopy[config::kMaxPassChars + 1] = {};
  bool hasNewPassword = false;
  const JsonVariant vNew = doc["password"];
  if (!vNew.isNull()) {
    if (!vNew.is<const char*>()) {
      crypto::wipe(oldCopy, sizeof(oldCopy));
      return failJson(r, "400 Bad Request", "password_not_a_string");
    }
    const char* np = vNew.as<const char*>();
    const size_t n = strlen(np);
    if (n > 0) {
      if (n < config::kMinPassChars || n >= config::kMaxPassChars) {
        crypto::wipe(oldCopy, sizeof(oldCopy));
        return failJson(r, "400 Bad Request", "password_length_out_of_range");
      }
      memcpy(newCopy, np, n + 1);
      hasNewPassword = true;
    }
  }

  uint8_t* curFile = nullptr;
  size_t curLen = 0;
  uint8_t* newFile = nullptr;
  size_t newLen = 0;

  // Текущий файл требуется только когда он реально включён: на хранилище без
  // файла поле бессмысленно, а воркер, получив непустой буфер, построил бы из
  // него неверный материал и принял бы верный пароль за чужой.
  const bool keyfileRequired = vault::keyFileRequired();
  if (keyfileRequired) {
    const esp_err_t kfe =
        parseKeyfileField(r, doc, "keyfile_current", &curFile, &curLen);
    if (kfe != ESP_OK) {
      crypto::wipe(oldCopy, sizeof(oldCopy));
      crypto::wipe(newCopy, sizeof(newCopy));
      return kfe;
    }
    if (curFile == nullptr) {
      crypto::wipe(oldCopy, sizeof(oldCopy));
      crypto::wipe(newCopy, sizeof(newCopy));
      return failJson(r, "400 Bad Request", "keyfile_current_required");
    }
  }

  auth::KeyfileAction action = auth::KeyfileAction::Keep;
  const JsonVariant vAct = doc["keyfile_action"];
  if (!vAct.isNull()) {
    if (!vAct.is<const char*>()) {
      crypto::wipe(oldCopy, sizeof(oldCopy));
      crypto::wipe(newCopy, sizeof(newCopy));
      if (curFile != nullptr) {
        crypto::wipe(curFile, config::kKeyFileMaxBytes);
        free(curFile);
      }
      return failJson(r, "400 Bad Request", "keyfile_action_invalid");
    }
    const char* a = vAct.as<const char*>();
    if (strcmp(a, "set") == 0) {
      action = auth::KeyfileAction::Set;
    } else if (strcmp(a, "clear") == 0) {
      action = auth::KeyfileAction::Clear;
    } else if (strcmp(a, "keep") != 0) {
      crypto::wipe(oldCopy, sizeof(oldCopy));
      crypto::wipe(newCopy, sizeof(newCopy));
      if (curFile != nullptr) {
        crypto::wipe(curFile, config::kKeyFileMaxBytes);
        free(curFile);
      }
      return failJson(r, "400 Bad Request", "keyfile_action_invalid");
    }
  }
  if (action == auth::KeyfileAction::Set) {
    const esp_err_t kfe =
        parseKeyfileField(r, doc, "keyfile_new", &newFile, &newLen);
    if (kfe != ESP_OK) {
      crypto::wipe(oldCopy, sizeof(oldCopy));
      crypto::wipe(newCopy, sizeof(newCopy));
      if (curFile != nullptr) {
        crypto::wipe(curFile, config::kKeyFileMaxBytes);
        free(curFile);
      }
      return kfe;
    }
    if (newFile == nullptr) {
      crypto::wipe(oldCopy, sizeof(oldCopy));
      crypto::wipe(newCopy, sizeof(newCopy));
      if (curFile != nullptr) {
        crypto::wipe(curFile, config::kKeyFileMaxBytes);
        free(curFile);
      }
      return failJson(r, "400 Bad Request", "keyfile_new_required");
    }
  }
  doc.clear();

  const auth::JobId id =
      auth::submitRekey(oldCopy, hasNewPassword ? newCopy : nullptr,
                        curFile, curLen, newFile, newLen, action);
  crypto::wipe(oldCopy, sizeof(oldCopy));
  crypto::wipe(newCopy, sizeof(newCopy));
  if (curFile != nullptr) {
    crypto::wipe(curFile, config::kKeyFileMaxBytes);
    free(curFile);
  }
  if (newFile != nullptr) {
    crypto::wipe(newFile, config::kKeyFileMaxBytes);
    free(newFile);
  }
  if (id == auth::kNoJob) {
    return failJson(r, "503 Service Unavailable", "busy");
  }
  log::info("http: master password and/or keyfile change requested");
  return sendJobAccepted(r, id);
}

// GET /api/auth/password — свежий кандидат мастер-пароля для UI.
//
// Отдаётся ИМЕННО кандидат, а не действующий пароль: действующий нигде не
// хранится (после provisioning он живёт только в слоте job'а, пока клиент не
// забрал его через poll). Назначение маршрута — экран смены пароля: словарь
// лежит в прошивке, и без этого запроса UI не смог бы предложить пользователю
// новую строку в том же формате, в каком её выдаёт provisioning.
//
// Каждый запрос даёт новый независимый кандидат, поэтому ответ не является
// долгоживущим секретом устройства — но всё равно сидит под сессией, чтобы
// посторонний не собирал строки генератора.
esp_err_t authPasswordHandler(httpd_req_t* r) {
  RequestGuard guard;
  const esp_err_t s = requireSession(r);
  if (s != ESP_OK) {
    return s;
  }
  char pw[config::kMasterPasswordChars + 1];
  (void)auth::generateMasterPassword(pw, sizeof(pw));
  JsonDocument doc;
  doc["ok"] = true;
  doc["password"] = pw;
  // sendDoc стирает свой буфер после отправки; локальную копию стираем сразу —
  // она не нужна после постановки в документ.
  const esp_err_t err = sendDoc(r, doc, "auth_password");
  crypto::wipe(pw, sizeof(pw));
  return err;
}

// ─── Entries API ──────────────────────────────────────────────────────────────

// Буфер под vault::load().
//
// 1000 записей по sizeof(vault::Entry) — это около 900 КБ, на стеке задачи
// httpd такой блок не поместился бы ни при каком размере стека. Память
// выделяется ОДИН раз при первом обращении и живёт до конца работы.
//
// Защита — один буфер на мьютекс, а не на каждого клиента: httpd держит до
// config::kHttpMaxSessions (4) соединений одновременно, и два параллельных
// GET /api/entries без блокировки разъехались бы по общей памяти. Сессия уже
// открыта, то есть все четыре соединения принадлежат одному пользователю, но
// гонку это не отменяет.
vault::Entry* g_entriesBuf = nullptr;
SemaphoreHandle_t g_entriesMux = nullptr;
portMUX_TYPE g_entriesSpin = portMUX_INITIALIZER_UNLOCKED;

// Буфер и мьютекс создаются лениво, но не «просто если nullptr»: httpd в IDF
// 4.4 обслуживает соединения в ОДНОЙ задаче, поэтому гонки тут нет и
// критическая секция была бы лишней. Она оставлена только потому, что стоит
// три строки и снимает вопрос целиком, если httpd когда-нибудь станет
// многопоточным: без неё два первых одновременных запроса создали бы два
// буфера, а детерминированный указатель уехал бы в сторону.
vault::Entry* entriesBuffer(uint32_t* outMax) {
  if (g_entriesBuf == nullptr) {
    portENTER_CRITICAL(&g_entriesSpin);
    const bool needInit = (g_entriesBuf == nullptr);
    if (needInit) {
      g_entriesMux = xSemaphoreCreateMutex();
      void* mem = heap_caps_malloc(sizeof(vault::Entry) * config::kMaxEntries,
                                   MALLOC_CAP_SPIRAM);
      if (g_entriesMux == nullptr || mem == nullptr) {
        log::error("http: entries buffer alloc failed");
        if (g_entriesMux != nullptr) {
          vSemaphoreDelete(g_entriesMux);
          g_entriesMux = nullptr;
        }
        free(mem);
        g_entriesBuf = nullptr;
      } else {
        g_entriesBuf = static_cast<vault::Entry*>(mem);
        log::info("http: entries buffer %u x %u B in psram",
                  static_cast<unsigned>(config::kMaxEntries),
                  static_cast<unsigned>(sizeof(vault::Entry)));
      }
    }
    portEXIT_CRITICAL(&g_entriesSpin);
  }
  if (g_entriesBuf == nullptr || g_entriesMux == nullptr) {
    return nullptr;
  }
  *outMax = config::kMaxEntries;
  return g_entriesBuf;
}

// Размер чанка при потоковой отдаче документа. Тот же размер, что и у буфера
// раздачи файлов: он уже измерен на этой плате и умеет укладываться в
// send_wait_timeout через USB-NCM.
constexpr size_t kDocChunkBytes = config::kHttpChunkBytes;

// Документ, который не поместился бы в один httpd_resp_send().
//
// measureJson даёт ТОЧНЫЙ размер, поэтому вычитание заранее: без него размер
// округлился бы вверх, chunked-ответ вышел бы длиннее тела на пару байт и
// клиент поймал бы «JSON с мусором в конце».
esp_err_t sendDocStreamed(httpd_req_t* r, JsonDocument& doc, const char* what) {
  const int n = measureJson(doc);
  if (n < 0) {
    log::error("http: %s doc is broken", what);
    return failJson(r, "500 Internal Server Error", "json_build_failed");
  }

  char* buf = static_cast<char*>(malloc(static_cast<size_t>(n) + 1));
  if (buf == nullptr) {
    return failJson(r, "500 Internal Server Error", "out_of_memory");
  }
  const size_t wrote = serializeJson(doc, buf, static_cast<size_t>(n) + 1);
  if (wrote == 0) {
    free(buf);
    return failJson(r, "500 Internal Server Error", "json_serialize_failed");
  }

  httpd_resp_set_type(r, "application/json");
  httpd_resp_set_hdr(r, "Cache-Control", "no-store");
  httpd_resp_set_hdr(r, "X-Content-Type-Options", "nosniff");

  size_t left = wrote;
  size_t off = 0;
  esp_err_t err = ESP_OK;
  while (left > 0) {
    const size_t want = (left < kDocChunkBytes) ? left : kDocChunkBytes;
    err = httpd_resp_send_chunk(r, buf + off, want);
    if (err != ESP_OK) {
      break;
    }
    off += want;
    left -= want;
  }
  // Пустой чанк закрывает поток. Без него клиент с открытым телом ждал бы
  // следующий запрос вместо того, чтобы прочитать ответ целиком.
  if (err == ESP_OK) {
    err = httpd_resp_send_chunk(r, nullptr, 0);
  }
  // Тело ушло в сокет, поэтому стирается до освобождения: компилятор вправе
  // отдать этот кусок под что угодно раньше, чем lwIP его допишет.
  crypto::wipe(buf, wrote);
  free(buf);
  return err;
}

// GET /api/entries — список БЕЗ паролей.
//
// Отдельный маршрут для пароля (GET /api/entries/{id}/secret) существует не для
// удобства: список отдаётся при каждом показе экрана, и если бы в нём были
// пароли, они оседали бы в кэше и в памяти вкладки шире, чем нужно.
esp_err_t entriesListHandler(httpd_req_t* r) {
  RequestGuard guard;
  const esp_err_t s = requireSession(r);
  if (s != ESP_OK) {
    return s;
  }

  uint32_t maxCount = 0;
  vault::Entry* buf = entriesBuffer(&maxCount);
  if (buf == nullptr) {
    return failJson(r, "500 Internal Server Error", "entries_buffer_unavailable");
  }
  if (xSemaphoreTake(g_entriesMux, pdMS_TO_TICKS(2000)) != pdTRUE) {
    // Мьютекс занят дольше двух секунд — это аномалия, а не ожидание: буфер
    // держится на время vault::load(), то есть доли секунды.
    return failJson(r, "503 Service Unavailable", "entries_busy");
  }

  uint32_t count = 0;
  const vault::VaultError rc = vault::load(buf, maxCount, &count);
  JsonDocument doc;
  if (rc != vault::VaultError::Ok) {
    xSemaphoreGive(g_entriesMux);
    log::error("http: vault::load failed %s", vault::toString(rc));
    return failJson(r, "500 Internal Server Error", "vault_load_failed");
  }

  doc["ok"] = true;
  doc["count"] = count;
  JsonArray arr = doc["entries"].to<JsonArray>();
  for (uint32_t i = 0; i < count; ++i) {
    const vault::Entry& e = buf[i];
JsonObject o = arr.add<JsonObject>();
    o["id"] = e.id;
    // Явная длина, а не присваивание по const char*: в записи с флеша нуль-байт
    // может отсутствовать, и strlen() ушёл бы читать за пределы поля. Пароль в
    // списке не копируется вовсе.
    // Буфер по НАИБОЛЬШЕМУ из используемых полей (url, 192 Б). tmp по размеру title
    // (48) был бы короче login и url, и setFieldBounded() вернул бы false на
    // каждой второй записи — то есть список молча подменял бы поля пустыми.
    char tmp[sizeof(vault::Entry::url) + 1];
    if (!setFieldBounded(o, "title", e.title, sizeof(e.title), tmp, sizeof(tmp))) {
      tmp[0] = '\0';
      o["title"] = "";
    }
    if (!setFieldBounded(o, "login", e.login, sizeof(e.login), tmp, sizeof(tmp))) {
      tmp[0] = '\0';
      o["login"] = "";
    }
    if (!setFieldBounded(o, "url", e.url, sizeof(e.url), tmp, sizeof(tmp))) {
      tmp[0] = '\0';
      o["url"] = "";
    }
    if (!setFieldBounded(o, "tags", e.tags, sizeof(e.tags), tmp, sizeof(tmp))) {
      tmp[0] = '\0';
      o["tags"] = "";
    }
    // Признак TOTP-секрета без самого секрета: значок в списке UI ставит по
    // нему, не вытягивая карточку каждой записи.
    o["hasTotp"] = (e.totp[0] != '\0');
  }
  xSemaphoreGive(g_entriesMux);

  // При 1000 записях документ занимает сотни килобайт, поэтому отдаётся потоком:
  // целиком в один httpd_resp_send() такой объём не поместился бы в доступный
  // буфер отправки, и соединение оборвалось бы на середине.
  return sendDocStreamed(r, doc, "entries_list");
}

// Заполнение vault::Entry из JSON с проверкой каждого поля по его размеру.
//
// Проверка обязательна именно здесь: sizeof(e.title) = 48, а title из JSON может
// быть любой длины до размера тела запроса. Копирование без проверки уронило бы
// запись соседними полями — тихая порча хранилища вместо внятного 400.
//
// Контейнер шаблонный: запись заполняется из JsonDocument (CRUD), батч импорта
// — из JsonObject одной записи. Внутри obj[key] остаётся lvalue-выражением,
// поэтому никакой ловушки с MemberProxy здесь нет (в отличие от setFieldBounded).
template <typename TObject>
bool fillField(TObject& doc, const char* key, char* dst, size_t dstSize) {
  JsonVariant v = doc[key];
  if (v.isNull()) {
    dst[0] = '\0';  // поле не прислано — это пустое поле, а не ошибка
    return true;
  }
  if (!v.is<const char*>()) {
    return false;  // число или объект вместо строки
  }
  const char* src = v.as<const char*>();
  // +1 — на нуль-байт. Строка ровно в sizeof(dst)-1 символов помещается, на
  // один длиннее уже нет.
  const size_t n = strlen(src);
  if (n >= dstSize) {
    return false;
  }
  memcpy(dst, src, n + 1);
  return true;
}

// POST /api/entries и POST /api/entries/{id} (создание и обновление).
//
// Один обработчик на оба случая: различие только в том, откуда берётся id, а
// тело и валидация совпадают полностью. Раздельные обработчики разошлись бы
// при первом же исправлении.
esp_err_t entriesWriteHandler(httpd_req_t* r) {
  RequestGuard guard;
  const esp_err_t g = requireSameOrigin(r);
  if (g != ESP_OK) {
    return g;
  }
  const esp_err_t s = requireSession(r);
  if (s != ESP_OK) {
    return s;
  }

  // id из пути: 0 означает создание. Разбор строгий (pathId), поэтому
  // "abc" отвергается, а не превращается в 0.
  uint32_t fromPath = 0;
  if (!pathId(r->uri, "/api/entries/", &fromPath)) {
    // Путь без хвоста и хвост с буквами — это либо создание ("/api/entries"),
    // либо мусор. Создание разрешаем только на точном "/api/entries".
    const bool isCreate = (strcmp(r->uri, "/api/entries") == 0);
    if (!isCreate) {
      return failJson(r, "400 Bad Request", "bad_entry_id");
    }
    fromPath = 0;
  }

  JsonDocument doc;
  const esp_err_t rd = readJsonBody(r, doc);
  if (rd != ESP_OK) {
    return rd;
  }

  vault::Entry e = {};
  e.id = fromPath;
  if (!fillField(doc, "title", e.title, sizeof(e.title)) ||
      !fillField(doc, "login", e.login, sizeof(e.login)) ||
      !fillField(doc, "password", e.password, sizeof(e.password)) ||
      !fillField(doc, "url", e.url, sizeof(e.url)) ||
      !fillField(doc, "note", e.note, sizeof(e.note)) ||
      !fillField(doc, "tags", e.tags, sizeof(e.tags)) ||
      !fillField(doc, "totp", e.totp, sizeof(e.totp))) {
    // Пароль в документе остаётся в куче — стираем через clear() ниже. Само тело
    // уже стёрто в readJsonBody().
    doc.clear();
    return failJson(r, "400 Bad Request", "field_too_long_or_not_a_string");
  }

  // Секрет проверяется при записи, а не при выдаче кода: битый base32 в
  // хранилище — это ошибка, которую пользователь должен увидеть в момент ввода,
  // а не позже, когда карточка уже сохранена и поле выглядит заполненным.
  // Пустое поле допустимо — это запись без TOTP.
  if (e.totp[0] != '\0' && !totp::validSecret(e.totp)) {
    crypto::wipe(&e, sizeof(e));
    doc.clear();
    return failJson(r, "400 Bad Request", "totp_secret_invalid");
  }

  // Проверки «запись обязана иметь title или login» больше нет: пустые по
  // обеим полям записи приходят при импорте KDBX-выгрузок и не должны
  // отвергаться на уровне API — искать их в списке UI может по любому из
  // оставшихся полей, а запрет бил бы именно по импорту.

  // Запись, которая пригодится для слияния пароля. Держится до конца add():
  // стирать её раньше нельзя, crypto::wipe(&e) ниже её затрёт.
  vault::Entry haveOld = {};
  bool mergePassword = false;

  // Обновление несуществующей записи — это 404, а не тихое создание новой.
  // Иначе клиент с опечаткой в id получил бы «успех» и новую запись, а старую
  // запись потерял бы из виду.
  if (fromPath != 0) {
    const vault::VaultError gotRc = vault::get(fromPath, &haveOld);
    if (gotRc == vault::VaultError::NotFound) {
      crypto::wipe(&haveOld, sizeof(haveOld));
      crypto::wipe(&e, sizeof(e));
      doc.clear();
      return failJson(r, "404 Not Found", "entry_not_found");
    }
    if (gotRc != vault::VaultError::Ok) {
      crypto::wipe(&haveOld, sizeof(haveOld));
      crypto::wipe(&e, sizeof(e));
      doc.clear();
      log::error("http: vault::get failed %s", vault::toString(gotRc));
      return failJson(r, "500 Internal Server Error", "vault_get_failed");
    }
    // Пароль при обновлении опционален: пустое поле означает «оставить прежний».
    // Запись, полученная из vault, пароль уже содержит — копируется, а не
    // переносится указателем, потому что он смотрит в другой буфер.
    mergePassword = (e.password[0] == '\0');
  }

  uint32_t newId = 0;
  if (mergePassword) {
    memcpy(e.password, haveOld.password, sizeof(e.password));
  }
  const vault::VaultError rc = vault::add(e, &newId);
  // Записи содержат пароли, поэтому стираются немедленно: они лежат на стеке
  // httpd ещё доли секунды после возврата.
  crypto::wipe(&haveOld, sizeof(haveOld));
  crypto::wipe(&e, sizeof(e));
  doc.clear();

  if (rc != vault::VaultError::Ok) {
    log::error("http: vault::add failed %s", vault::toString(rc));
    // TooManyEntries и Budget — это «хранилище переполнено», то есть 409 с
    // понятным кодом, а не 500: устройство работает верно, клиент должен
    // предложить удалить запись.
    if (rc == vault::VaultError::TooManyEntries) {
      return failJson(r, "409 Conflict", "too_many_entries");
    }
    if (rc == vault::VaultError::Budget) {
      return failJson(r, "409 Conflict", "storage_full");
    }
    if (rc == vault::VaultError::EntryTooLong) {
      return failJson(r, "400 Bad Request", "entry_too_long");
    }
    if (rc == vault::VaultError::BootStrap) {
      return failJson(r, "409 Conflict", "vault_not_open");
    }
    return failJson(r, "500 Internal Server Error", "vault_add_failed");
  }

  JsonDocument out;
  out["ok"] = true;
  out["id"] = newId;
  httpd_resp_set_status(r, fromPath != 0 ? "200 OK" : "201 Created");
  return sendDoc(r, out, "entry_write");
}

esp_err_t entriesDetailHandler(httpd_req_t* r);
esp_err_t entriesSecretHandler(httpd_req_t* r);
esp_err_t entriesTotpHandler(httpd_req_t* r);

// GET /api/entries/* — один обработчик на карточку, выдачу пароля и код TOTP.
//
// Разводить их в три шаблона нельзя: httpd_uri_match_wildcard() в IDF 4.4
// понимает '*' только как хвостовой подстановочный знак, и шаблон с '*' в
// середине не совпадёт ни с одним путём. Поэтому суффиксы "/secret" и "/totp"
// разбираются вручную здесь.
//
// Суффиксы сверяются с ПУТЁМ без query-строки: "/totp?t=123" заканчивается на
// значение параметра, а не на "/totp", и сравнение по полному URI не совпало бы
// никогда.
esp_err_t entriesGetHandler(httpd_req_t* r) {
  const char* q = strchr(r->uri, '?');
  const size_t pathLen = (q != nullptr) ? static_cast<size_t>(q - r->uri)
                                        : strlen(r->uri);
  static const char kSecretSuffix[] = "/secret";
  static const char kTotpSuffix[] = "/totp";
  constexpr size_t kSecretLen = sizeof(kSecretSuffix) - 1;
  constexpr size_t kTotpLen = sizeof(kTotpSuffix) - 1;
  if (pathLen > kSecretLen &&
      memcmp(r->uri + pathLen - kSecretLen, kSecretSuffix, kSecretLen) == 0) {
    return entriesSecretHandler(r);
  }
  if (pathLen > kTotpLen &&
      memcmp(r->uri + pathLen - kTotpLen, kTotpSuffix, kTotpLen) == 0) {
    return entriesTotpHandler(r);
  }
  return entriesDetailHandler(r);
}

// GET /api/entries/{id}
esp_err_t entriesDetailHandler(httpd_req_t* r) {
  RequestGuard guard;
  const esp_err_t s = requireSession(r);
  if (s != ESP_OK) {
    return s;
  }
  uint32_t id = 0;
  if (!pathId(r->uri, "/api/entries/", &id)) {
    return failJson(r, "400 Bad Request", "bad_entry_id");
  }

  vault::Entry e = {};
  const vault::VaultError rc = vault::get(id, &e);
  if (rc == vault::VaultError::NotFound) {
    return failJson(r, "404 Not Found", "entry_not_found");
  }
  if (rc != vault::VaultError::Ok) {
    crypto::wipe(&e, sizeof(e));
    log::error("http: vault::get failed %s", vault::toString(rc));
    return failJson(r, "500 Internal Server Error", "vault_get_failed");
  }

  // Пароль в detail НЕ отдаётся: для этого есть отдельный /secret. Список и
  // карточка — то, что UI держит открытыми постоянно, и тащить туда секрет
  // значило бы держать его в памяти вкладки без нужды.
  //
  // TOTP-секрет в detail отдаётся, в отличие от пароля: он нужен для
  // редактирования (иначе любая правка записи стёрла бы его, как стирает
  // сегодня неприсланный url), а на руках он только у того, у кого уже есть
  // сессия. Код при этом отдельно отдаёт только /totp — так UI не считает
  // коды сам и не держит секрет дольше одной карточки.
  JsonDocument doc;
  doc["ok"] = true;
  doc["id"] = e.id;
  // По наибольшему полю среди используемых здесь — note (400 Б).
  char tmp[sizeof(vault::Entry::note) + 1];
  bool clean = true;
  clean = setFieldBounded(doc, "title", e.title, sizeof(e.title), tmp, sizeof(tmp)) && clean;
  clean = setFieldBounded(doc, "login", e.login, sizeof(e.login), tmp, sizeof(tmp)) && clean;
  clean = setFieldBounded(doc, "url", e.url, sizeof(e.url), tmp, sizeof(tmp)) && clean;
  clean = setFieldBounded(doc, "note", e.note, sizeof(e.note), tmp, sizeof(tmp)) && clean;
  clean = setFieldBounded(doc, "tags", e.tags, sizeof(e.tags), tmp, sizeof(tmp)) && clean;
  clean = setFieldBounded(doc, "totp", e.totp, sizeof(e.totp), tmp, sizeof(tmp)) && clean;
  if (!clean) {
    // Поле без нуль-байта во всю свою длину: обрезать молча нельзя, поле в JSON
    // было бы битым. Само значение уходит в лог только как длина, не содержимое.
    log::warn("http: entry %u has unterminated field", static_cast<unsigned>(e.id));
    crypto::wipe(&e, sizeof(e));
    return failJson(r, "500 Internal Server Error", "entry_field_unterminated");
  }
  doc["hasPassword"] = (e.password[0] != '\0');
  doc["hasTotp"] = (e.totp[0] != '\0');
  const esp_err_t err = sendDoc(r, doc, "entry_detail");
  crypto::wipe(&e, sizeof(e));
  return err;
}

// Часть обработчика GET /api/entries/*, отвечающая за выдачу пароля.
//
// Вынесена в отдельную функцию, но регистрируется ОТДЕЛЬНЫМ маршрутом только
// потому, что так выглядит естественно. Реальная причина обратная:
//
// httpd_uri_match_wildcard() в IDF 4.4 понимает '*' ТОЛЬКО как хвостовой
// подстановочный знак. Он находит первый '*' и дальше сравнивает префикс длиной
// strlen(шаблон) - 1, то есть "/api/entries/*/secret" против "/api/entries/7/secret"
// сравнился бы как "/api/entries/*/secre" против "/api/entries/7/secre" и не
// совпал бы НИКОГДА. Маршрут с '*' в середине здесь просто мёртвый.
//
// Поэтому secret разбирается вручную: шаблон "/api/entries/*" хватает и
// "/api/entries/7", и "/api/entries/7/secret", а суффикс проверяется здесь.
//
// Единственный маршрут, отдающий пароль. Отдельный по существу, а не для
// удобства: чтобы НЕ показать чужой пароль, UI достаточно не вызывать его, а
// любые выборки из списка или карточки не содержат секрета в принципе.
esp_err_t entriesSecretHandler(httpd_req_t* r) {
  RequestGuard guard;
  const esp_err_t s = requireSession(r);
  if (s != ESP_OK) {
    return s;
  }
  // Суффикс "/secret" отрезается ДО разбора id. Иначе pathId() увидел бы в хвосте
  // "/secret" и отверг бы путь как нечисловой, то есть маршрут не сработал бы
  // никогда. Проверка суффикса строгая: "/api/entries/7/secretx" отвергается.
  static const char kSuffix[] = "/secret";
  const size_t sufLen = sizeof(kSuffix) - 1;
  const size_t uriLen = strlen(r->uri);
  if (uriLen <= sufLen || strcmp(r->uri + uriLen - sufLen, kSuffix) != 0) {
    return failJson(r, "400 Bad Request", "bad_entry_id");
  }
  char base[config::kHttpMaxUri + 1];
  const size_t baseLen = uriLen - sufLen;
  if (baseLen >= sizeof(base)) {
    return failJson(r, "400 Bad Request", "bad_entry_id");
  }
  memcpy(base, r->uri, baseLen);
  base[baseLen] = '\0';

  uint32_t id = 0;
  if (!pathId(base, "/api/entries/", &id)) {
    return failJson(r, "400 Bad Request", "bad_entry_id");
  }

  vault::Entry e = {};
  const vault::VaultError rc = vault::get(id, &e);
  if (rc == vault::VaultError::NotFound) {
    return failJson(r, "404 Not Found", "entry_not_found");
  }
  if (rc != vault::VaultError::Ok) {
    crypto::wipe(&e, sizeof(e));
    log::error("http: vault::get failed %s", vault::toString(rc));
    return failJson(r, "500 Internal Server Error", "vault_get_failed");
  }

  JsonDocument doc;
  doc["ok"] = true;
  doc["id"] = e.id;
  char pw[sizeof(vault::Entry::password) + 1];
  if (!setFieldBounded(doc, "password", e.password, sizeof(e.password), pw, sizeof(pw))) {
    log::warn("http: entry %u password unterminated", static_cast<unsigned>(e.id));
    crypto::wipe(pw, sizeof(pw));
    crypto::wipe(&e, sizeof(e));
    return failJson(r, "500 Internal Server Error", "entry_field_unterminated");
  }
  // Ответ идёт в браузер, где пароль останется в памяти вкладки и может попасть
  // в журнал DevTools. Поэтому явный Cache-Control: no-store обязателен, и он
  // уже ставится в sendJson() для всех ответов.
  const esp_err_t err = sendDoc(r, doc, "entry_secret");
  // Пароль стирается сразу: буфер ответа уже сформирован и отдан httpd.
  crypto::wipe(&e, sizeof(e));
  return err;
}

// Разбор query-строки вида "t=1712345678&..." — только параметр t, строго
// десятичные цифры до '&'. Прочие параметры молча пропускаются: их наличие не
// делает запрос некорректным, а незнакомые параметры парсеров ломают клиенты
// при каждом расширении API.
bool queryTime(const char* uri, uint32_t* out) {
  const char* q = strchr(uri, '?');
  if (q == nullptr) {
    return false;
  }
  const char* p = q + 1;
  while (*p != '\0') {
    const char* amp = strchr(p, '&');
    const size_t len = (amp != nullptr) ? static_cast<size_t>(amp - p) : strlen(p);
    if (len > 2 && p[0] == 't' && p[1] == '=') {
      uint32_t v = 0;
      for (size_t i = 2; i < len; ++i) {
        if (p[i] < '0' || p[i] > '9') {
          return false;
        }
        const uint32_t digit = static_cast<uint32_t>(p[i] - '0');
        if (v > (UINT32_MAX - digit) / 10) {
          return false;  // переполнение 32 бит: время вне досягаемости
        }
        v = v * 10 + digit;
      }
      *out = v;
      return true;
    }
    if (amp == nullptr) {
      break;
    }
    p = amp + 1;
  }
  return false;
}

// GET /api/entries/{id}/totp?t=<epoch-seconds>
//
// Время приходит СНАРУЖИ: на плате нет ни RTC, ни NTP, и устройство не может
// само отличить настоящую эпоху от прошлогодней. Клиент шлёт свои часы, сервер
// считает код из секрета, который покидает устройство только в виде готовых
// 6 цифр. Это осознанный обмен: подделать время способен только тот, у кого
// уже есть сессия, а вред от подделанного кода — показать пользователю не ту
// цифру, не давая ничего взамен.
esp_err_t entriesTotpHandler(httpd_req_t* r) {
  RequestGuard guard;
  const esp_err_t s = requireSession(r);
  if (s != ESP_OK) {
    return s;
  }

  // Путь без query — для разбора id: pathId() отверг бы "?t=..." как
  // нечисловой хвост.
  char base[config::kHttpMaxUri + 1];
  const char* q = strchr(r->uri, '?');
  const size_t pathLen =
      (q != nullptr) ? static_cast<size_t>(q - r->uri) : strlen(r->uri);
  if (pathLen >= sizeof(base)) {
    return failJson(r, "400 Bad Request", "bad_entry_id");
  }
  memcpy(base, r->uri, pathLen);
  base[pathLen] = '\0';

  // Суффикс "/totp" отрезается ДО разбора id — иначе pathId() увидел бы в
  // хвосте "1/totp" и отверг бы путь как нечисловой, то есть каждый запрос
  // кода возвращал бы bad_entry_id (тот же приём, что в entriesSecretHandler).
  // Сверка строгая: "/api/entries/7/totpx" не пройдёт.
  static const char kSuffix[] = "/totp";
  const size_t sufLen = sizeof(kSuffix) - 1;
  if (pathLen <= sufLen || memcmp(base + pathLen - sufLen, kSuffix, sufLen) != 0) {
    return failJson(r, "400 Bad Request", "bad_entry_id");
  }
  base[pathLen - sufLen] = '\0';

  uint32_t id = 0;
  if (!pathId(base, "/api/entries/", &id)) {
    return failJson(r, "400 Bad Request", "bad_entry_id");
  }

  uint32_t when = 0;
  if (!queryTime(r->uri, &when)) {
    return failJson(r, "400 Bad Request", "time_required");
  }

  vault::Entry e = {};
  const vault::VaultError rc = vault::get(id, &e);
  if (rc == vault::VaultError::NotFound) {
    return failJson(r, "404 Not Found", "entry_not_found");
  }
  if (rc != vault::VaultError::Ok) {
    crypto::wipe(&e, sizeof(e));
    log::error("http: vault::get failed %s", vault::toString(rc));
    return failJson(r, "500 Internal Server Error", "vault_get_failed");
  }

  if (e.totp[0] == '\0') {
    crypto::wipe(&e, sizeof(e));
    return failJson(r, "409 Conflict", "totp_not_configured");
  }

  char code[7] = {};
  const bool ok = totp::code(e.totp, when, code);
  // Секрет в записи уже прошёл проверку при записи, поэтому отказ здесь —
  // порча хранилища, а не ошибка пользователя.
  if (!ok) {
    crypto::wipe(&e, sizeof(e));
    log::error("http: entry %u totp secret unusable", static_cast<unsigned>(id));
    return failJson(r, "500 Internal Server Error", "totp_secret_invalid");
  }
  // Секрет стирается ДО формирования ответа: в документ попадают только
  // готовый код и цифры жизненного цикла.
  crypto::wipe(&e, sizeof(e));

  JsonDocument doc;
  doc["ok"] = true;
  doc["code"] = code;
  doc["periodSec"] = static_cast<unsigned>(config::kTotpPeriodSec);
  doc["expiresInSec"] =
      static_cast<unsigned>(config::kTotpPeriodSec - (when % config::kTotpPeriodSec));
  const esp_err_t err = sendDoc(r, doc, "entry_totp");
  crypto::wipe(code, sizeof(code));
  return err;
}

// DELETE /api/entries/{id}
esp_err_t entriesDeleteHandler(httpd_req_t* r) {
  RequestGuard guard;
  const esp_err_t g = requireSameOrigin(r);
  if (g != ESP_OK) {
    return g;
  }
  const esp_err_t s = requireSession(r);
  if (s != ESP_OK) {
    return s;
  }
  uint32_t id = 0;
  if (!pathId(r->uri, "/api/entries/", &id)) {
    return failJson(r, "400 Bad Request", "bad_entry_id");
  }

  // Удаление необратимо (запись уходит надгробной записью), поэтому требует
  // явного подтверждения, как и сброс хранилища. Без него один промах по кнопке
  // уничтожал бы пароль, который пришлось бы вводить заново.
  if (r->content_len != 0) {
    JsonDocument doc;
    const esp_err_t rd = readJsonBody(r, doc);
    if (rd != ESP_OK) {
      return rd;
    }
    const char* confirm = doc["confirm"];
    if (!confirm || !doc["confirm"].is<const char*>() || strcmp(confirm, "DELETE") != 0) {
      doc.clear();
      return failJson(r, "400 Bad Request", "confirmation_required");
    }
    doc.clear();
  } else {
    // Тела нет — подтверждения тоже нет. Без него клиент, забывший про
    // подтверждение, стёр бы запись молча.
    log::warn("http: delete refused, no confirmation");
    return failJson(r, "400 Bad Request", "confirmation_required");
  }

  const vault::VaultError rc = vault::remove(id);
  if (rc == vault::VaultError::NotFound) {
    return failJson(r, "404 Not Found", "entry_not_found");
  }
  if (rc != vault::VaultError::Ok) {
    log::error("http: vault::remove failed %s", vault::toString(rc));
    return failJson(r, "500 Internal Server Error", "vault_remove_failed");
  }
  log::info("http: entry %u deleted", static_cast<unsigned>(id));

  JsonDocument doc;
  doc["ok"] = true;
  doc["id"] = id;
  return sendDoc(r, doc, "entry_delete");
}

// ─── Export / Import API (PMX1) ───────────────────────────────────────────────

// GET /api/export — выгрузка всего хранилища в PMX1.
//
// Формат: {"ok":true,"format":"PMX1","version":1,"count":N,"entries":[...]}.
// id НЕ выгружается: при импорте он переназначается, и сохранять чужой было бы
// ложной стабильностью — два устройства выдали бы разные судьбы одной записи.
// Все семь строковых полей, включая пароль и TOTP-секрет: это выгрузка под
// сессией, и именно ради неё пользователь и открывает сессию.
//
// Отдаётся по частям, а НЕ одним sendDocStreamed: при тысяче записей документ
// порядка мегабайта, а sendDocStreamed делает один malloc на весь документ.
// Здесь буфер на одну запись (~1.5 КБ), поэтому размер хранилища не влияет на
// исход.
//
// Начатый chunked-ответ ошибкой дописать нельзя — заголовки уже ушли. При
// обрыве на середине клиент получает обрезанный JSON и падает на его разборе,
// что и является сигналом «выгрузка неполна».
esp_err_t exportHandler(httpd_req_t* r) {
  RequestGuard guard;
  const esp_err_t s = requireSession(r);
  if (s != ESP_OK) {
    return s;
  }

  uint32_t maxCount = 0;
  vault::Entry* buf = entriesBuffer(&maxCount);
  if (buf == nullptr) {
    return failJson(r, "500 Internal Server Error", "entries_buffer_unavailable");
  }
  if (xSemaphoreTake(g_entriesMux, pdMS_TO_TICKS(2000)) != pdTRUE) {
    return failJson(r, "503 Service Unavailable", "entries_busy");
  }

  uint32_t count = 0;
  const vault::VaultError rc = vault::load(buf, maxCount, &count);
  if (rc != vault::VaultError::Ok) {
    xSemaphoreGive(g_entriesMux);
    log::error("http: vault::load failed %s", vault::toString(rc));
    return failJson(r, "500 Internal Server Error", "vault_load_failed");
  }

  httpd_resp_set_type(r, "application/json");
  httpd_resp_set_hdr(r, "Cache-Control", "no-store");
  httpd_resp_set_hdr(r, "X-Content-Type-Options", "nosniff");
  // Ответ — полный архив паролей: браузер не должен оставить его в кэше и
  // отдать следующей вкладке после закрытия.
  httpd_resp_set_hdr(r, "Content-Disposition",
                     "attachment; filename=\"passmanager-export.json\"");

  char head[96];
  const int hn = snprintf(head, sizeof(head),
                          "{\"ok\":true,\"format\":\"PMX1\",\"version\":%u,\"count\":%u,"
                          "\"entries\":[",
                          static_cast<unsigned>(config::kExportVersion),
                          static_cast<unsigned>(count));
  if (hn <= 0 || static_cast<size_t>(hn) >= sizeof(head)) {
    xSemaphoreGive(g_entriesMux);
    return httpd_resp_send_err(r, HTTPD_500_INTERNAL_SERVER_ERROR, "export header overflow");
  }
  esp_err_t err = httpd_resp_send_chunk(r, head, hn);

  // По одной записи в чанк. Мьютекс держится до конца: буфер общий, и список,
  // начатый параллельно, увидел бы смешанное состояние.
  for (uint32_t i = 0; err == ESP_OK && i < count; ++i) {
    const vault::Entry& e = buf[i];
    JsonDocument ed;
    JsonObject o = ed.to<JsonObject>();
    // По наибольшему среди всех семи полей — note (400 Б): один tmp на все.
    char tmp[sizeof(vault::Entry::note) + 1];
    const bool clean =
        setFieldBounded(o, "title", e.title, sizeof(e.title), tmp, sizeof(tmp)) &&
        setFieldBounded(o, "login", e.login, sizeof(e.login), tmp, sizeof(tmp)) &&
        setFieldBounded(o, "password", e.password, sizeof(e.password), tmp, sizeof(tmp)) &&
        setFieldBounded(o, "url", e.url, sizeof(e.url), tmp, sizeof(tmp)) &&
        setFieldBounded(o, "note", e.note, sizeof(e.note), tmp, sizeof(tmp)) &&
        setFieldBounded(o, "tags", e.tags, sizeof(e.tags), tmp, sizeof(tmp)) &&
        setFieldBounded(o, "totp", e.totp, sizeof(e.totp), tmp, sizeof(tmp));
    if (!clean) {
      log::error("http: export aborted, entry %u has unterminated field",
                 static_cast<unsigned>(e.id));
      break;  // обрезанный JSON — честный сигнал клиенту
    }
    const int n = measureJson(ed);
    char* item = static_cast<char*>(malloc(static_cast<size_t>(n) + 2));  // + запятая
    if (item == nullptr) {
      log::error("http: export aborted, item alloc failed for %d bytes", n);
      break;
    }
    size_t pos = 0;
    if (i > 0) {
      item[pos++] = ',';
    }
    const size_t wrote = serializeJson(ed, item + pos, static_cast<size_t>(n) + 1);
    if (wrote == 0) {
      log::error("http: export aborted, entry %u did not serialize", static_cast<unsigned>(e.id));
      free(item);
      break;
    }
    err = httpd_resp_send_chunk(r, item, pos + wrote);
    // Строки здесь — не пароли в чистом виде (уже отправлены клиенту), но и
    // их стирать не вредно: буфер освобождается сразу.
    crypto::wipe(item, pos + wrote);
    free(item);
  }

  if (err == ESP_OK) {
    static const char kTail[] = "]}";
    err = httpd_resp_send_chunk(r, kTail, sizeof(kTail) - 1);
  }
  if (err == ESP_OK) {
    err = httpd_resp_send_chunk(r, nullptr, 0);
  }
  xSemaphoreGive(g_entriesMux);
  if (err == ESP_OK) {
    log::info("http: exported %u entries", static_cast<unsigned>(count));
  }
  return err;
}

// POST /api/import — приём одного батча PMX1.
//
// Целый экспорт в один запрос не влезает в kHttpMaxBody (8 КБ), поэтому клиент
// режет его на батчи по config::kImportBatchEntries записей. Формат батча —
// тот же, что у выгрузки, минус ok/count.
//
// Атомарность намеренно ограниченная: валидация ВСЕХ записей батча идёт до
// первого add(), то есть ошибка формата не оставляет половины батча. Сбой на
// самом add() (переполнение хранилища) оставляет добавленное и сообщает
// imported — откатывать чужие удачные записи ради чужой неудачной нельзя.
//
// id из тела игнорируется: назначает устройство, иначе импорт двух выгрузок
// сошёлся бы по чужим номерам.
esp_err_t importHandler(httpd_req_t* r) {
  RequestGuard guard;
  const esp_err_t g = requireSameOrigin(r);
  if (g != ESP_OK) {
    return g;
  }
  const esp_err_t s = requireSession(r);
  if (s != ESP_OK) {
    return s;
  }

  JsonDocument doc;
  const esp_err_t rd = readJsonBody(r, doc);
  if (rd != ESP_OK) {
    return rd;
  }

  const char* format = doc["format"];
  if (!format || !doc["format"].is<const char*>() ||
      strcmp(format, "PMX1") != 0) {
    doc.clear();
    return failJson(r, "400 Bad Request", "format_required");
  }
  if (!doc["version"].is<unsigned>() ||
      doc["version"].as<unsigned>() != config::kExportVersion) {
    doc.clear();
    return failJson(r, "400 Bad Request", "version_unsupported");
  }
  JsonArray arr = doc["entries"].as<JsonArray>();
  if (arr.isNull()) {
    doc.clear();
    return failJson(r, "400 Bad Request", "entries_required");
  }
  const size_t count = arr.size();
  if (count == 0) {
    doc.clear();
    return failJson(r, "400 Bad Request", "nothing_to_import");
  }
  if (count > config::kImportBatchEntries) {
    doc.clear();
    return failJson(r, "400 Bad Request", "batch_too_large");
  }

  vault::Entry* batch = static_cast<vault::Entry*>(
      heap_caps_malloc(count * sizeof(vault::Entry), MALLOC_CAP_SPIRAM));
  if (batch == nullptr) {
    batch = static_cast<vault::Entry*>(malloc(count * sizeof(vault::Entry)));
  }
  if (batch == nullptr) {
    doc.clear();
    return failJson(r, "500 Internal Server Error", "out_of_memory");
  }
  memset(batch, 0, count * sizeof(vault::Entry));

  // Отказ в фазе валидации: ни одна запись батча ещё не добавлена, батч
  // стирается и освобождается целиком.
  auto failBatch = [&](const char* code) -> esp_err_t {
    crypto::wipe(batch, count * sizeof(vault::Entry));
    free(batch);
    doc.clear();
    return failJson(r, "400 Bad Request", code);
  };

  for (size_t i = 0; i < count; ++i) {
    JsonObject o = arr[i].as<JsonObject>();
    if (o.isNull()) {
      return failBatch("entry_not_an_object");
    }
    vault::Entry& e = batch[i];
    if (!fillField(o, "title", e.title, sizeof(e.title)) ||
        !fillField(o, "login", e.login, sizeof(e.login)) ||
        !fillField(o, "password", e.password, sizeof(e.password)) ||
        !fillField(o, "url", e.url, sizeof(e.url)) ||
        !fillField(o, "note", e.note, sizeof(e.note)) ||
        !fillField(o, "tags", e.tags, sizeof(e.tags)) ||
        !fillField(o, "totp", e.totp, sizeof(e.totp))) {
      return failBatch("field_too_long_or_not_a_string");
    }
    if (e.totp[0] != '\0' && !totp::validSecret(e.totp)) {
      return failBatch("totp_secret_invalid");
    }
  }

  uint32_t added = 0;
  vault::VaultError rc = vault::VaultError::Ok;
  for (; added < count; ++added) {
    rc = vault::add(batch[added], nullptr);
    if (rc != vault::VaultError::Ok) {
      break;
    }
  }
  crypto::wipe(batch, count * sizeof(vault::Entry));
  free(batch);
  doc.clear();

  JsonDocument out;
  if (rc != vault::VaultError::Ok) {
    const char* status = "500 Internal Server Error";
    const char* code = "vault_add_failed";
    switch (rc) {
      case vault::VaultError::TooManyEntries:
        status = "409 Conflict";
        code = "too_many_entries";
        break;
      case vault::VaultError::Budget:
        status = "409 Conflict";
        code = "storage_full";
        break;
      case vault::VaultError::EntryTooLong:
        status = "400 Bad Request";
        code = "entry_too_long";
        break;
      case vault::VaultError::BootStrap:
        status = "409 Conflict";
        code = "vault_not_open";
        break;
      default:
        log::error("http: vault::add failed %s", vault::toString(rc));
        break;
    }
    out["ok"] = false;
    out["error"] = code;
    out["imported"] = added;
    httpd_resp_set_status(r, status);
    return sendDoc(r, out, "import_failed");
  }

  out["ok"] = true;
  out["imported"] = count;
  log::info("http: imported %u entries", static_cast<unsigned>(count));
  return sendDoc(r, out, "import");
}

esp_err_t healthHandler(httpd_req_t* r) {
  // Guard в начале: in_flight в ответе тогда включает и сам этот запрос.
  RequestGuard guard;

  JsonDocument doc;
  doc["ok"] = true;
  doc["fw"] = config::kFirmwareVersion;
  doc["uptime_ms"] = static_cast<uint32_t>(millis());
  doc["in_flight"] = g_inFlight;
  doc["max_sessions"] = static_cast<unsigned>(config::kHttpMaxSessions);
  doc["requests"] = g_requests;
  doc["web_used_kb"] = static_cast<uint32_t>(fs::webUsedBytes() >> 10);
  doc["web_total_kb"] = static_cast<uint32_t>(fs::webTotalBytes() >> 10);

  char body[320];
  const size_t n = serializeJson(doc, body, sizeof(body));
  if (n == 0) {
    // Документ перерос буфер. Отдать пустое тело с 200 хуже, чем честная ошибка:
    // клиент health-check не отличит «сервер жив» от «сервер сломан».
    log::error("http: health json did not fit in %u bytes", static_cast<unsigned>(sizeof(body)));
    return httpd_resp_send_err(r, HTTPD_500_INTERNAL_SERVER_ERROR, "health json overflow");
  }
  httpd_resp_set_type(r, "application/json");
  httpd_resp_set_hdr(r, "Cache-Control", "no-store");
  httpd_resp_set_hdr(r, "X-Content-Type-Options", "nosniff");
  return httpd_resp_send(r, body, n);
}

// Один обработчик на "/" и "/*": тела у них одинаковые, различается только
// шаблон регистрации. Короткий путь тоже свернётся в index.html внутри
// fs::normalize(), так что дублировать ветвление было бы лишним.
esp_err_t staticHandler(httpd_req_t* r) {
  RequestGuard guard;
  char path[config::kWebPathMax];
  if (!requestPath(r, path, sizeof(path))) {
    return httpd_resp_send_404(r);
  }
  return sendFile(r, path);
}

}  // namespace

bool install() {
  if (g_server != nullptr) {
    return true;
  }
  // Отказа при несмонтированном web здесь больше нет намеренно: он делал весь
  // сервер недоступным из-за одного сломанного раздела, то есть API лежал
  // вместе со статикой. openWeb() на несмонтированном разделе возвращает false,
  // поэтому статика честно отдаёт 404, а /api/health продолжает отвечать.

  // Маршруты объявлены ДО конфигурации: static_assert ниже проверяет, что их
  // число помещается в max_uri_handlers, и без объявления выше проверять нечего.
  //
  // Порядок регистрации значим: httpd ищет первый подходящий шаблон сверху вниз.
  // Поэтому ВСЕ /api/* обязаны быть объявлены ДО "/*", иначе статика перехватила
  // бы и корень, и API.
  const httpd_uri_t routes[] = {
      {.uri = "/api/health", .method = HTTP_GET, .handler = healthHandler, .user_ctx = nullptr},
      {.uri = "/api/auth/state", .method = HTTP_GET, .handler = authStateHandler, .user_ctx = nullptr},
      {.uri = "/api/auth/provision", .method = HTTP_POST, .handler = authProvisionHandler, .user_ctx = nullptr},
      {.uri = "/api/auth/unlock", .method = HTTP_POST, .handler = authUnlockHandler, .user_ctx = nullptr},
      {.uri = "/api/auth/job/*", .method = HTTP_GET, .handler = authJobHandler, .user_ctx = nullptr},
      {.uri = "/api/auth/lock", .method = HTTP_POST, .handler = authLockHandler, .user_ctx = nullptr},
      {.uri = "/api/auth/session", .method = HTTP_GET, .handler = authSessionHandler, .user_ctx = nullptr},
      {.uri = "/api/auth/reset", .method = HTTP_POST, .handler = authResetHandler, .user_ctx = nullptr},
      {.uri = "/api/auth/rekey", .method = HTTP_POST, .handler = authRekeyHandler, .user_ctx = nullptr},
      {.uri = "/api/auth/password", .method = HTTP_GET, .handler = authPasswordHandler, .user_ctx = nullptr},
      {.uri = "/api/entries", .method = HTTP_GET, .handler = entriesListHandler, .user_ctx = nullptr},
      {.uri = "/api/entries", .method = HTTP_POST, .handler = entriesWriteHandler, .user_ctx = nullptr},
      {.uri = "/api/entries/*", .method = HTTP_GET, .handler = entriesGetHandler, .user_ctx = nullptr},
      {.uri = "/api/entries/*", .method = HTTP_POST, .handler = entriesWriteHandler, .user_ctx = nullptr},
      {.uri = "/api/entries/*", .method = HTTP_DELETE, .handler = entriesDeleteHandler, .user_ctx = nullptr},
      {.uri = "/api/export", .method = HTTP_GET, .handler = exportHandler, .user_ctx = nullptr},
      {.uri = "/api/import", .method = HTTP_POST, .handler = importHandler, .user_ctx = nullptr},
      {.uri = "/", .method = HTTP_GET, .handler = staticHandler, .user_ctx = nullptr},
      {.uri = "/*", .method = HTTP_GET, .handler = staticHandler, .user_ctx = nullptr},
  };

  httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
  cfg.server_port = config::kHttpPort;
  cfg.ctrl_port = 32768;  // дефолт IDF, но задаём явно: иначе порт выбирается случайно
  cfg.stack_size = kHttpdStackBytes;
  // Маршрутов 19: 3 прежних (health, /, /*) + 9 auth + 5 entries + экспорт и
  // импорт. Лимит в 16 из старой версии был впритык: добавление любого
  // маршрута отказало бы в httpd_register_uri_handler(), и это выглядело бы
  // как «сломался сервер», а не как «не хватило места». Запас 5 оставлен на
  // будущие маршруты.
  cfg.max_uri_handlers = 24;
  static_assert(sizeof(routes) / sizeof(routes[0]) <= 24,
                "маршрутов больше, чем max_uri_handlers");
  // Лимит сессий держит сам httpd. Штатное поведение при переполнении: новое
  // соединение не принимается, клиент видит RST. Раньше лимит дублировался
  // счётчиком в open_fn, но регистрация хуков ломает сервер — см. выше.
  cfg.max_open_sockets = config::kHttpMaxSessions;
  cfg.recv_wait_timeout = kSockTimeoutSec;
  cfg.send_wait_timeout = kSockTimeoutSec;
  // Wildcard, а не NULL-овский strncmp: без него httpd не найдёт ни "/favicon.ico",
  // ни "/assets/app.js" и отдаст 404 на каждый файл, кроме корня.
  cfg.uri_match_fn = httpd_uri_match_wildcard;
  // open_fn/close_fn намеренно НЕ регистрируются: в IDF 4.4 их наличие ломает
  // сервер через ~12 соединений (утечка TCP PCB, дальше ENFILE), даже если
  // хуки только считают и всегда отдают ESP_OK. Проверено на loopback без
  // участия NCM. Подробности — у счётчиков выше.

  esp_err_t err = httpd_start(&g_server, &cfg);
  if (err != ESP_OK) {
    g_server = nullptr;
    log::error("http: httpd_start failed %d", static_cast<int>(err));
    return false;
  }

  for (const httpd_uri_t& route : routes) {
    err = httpd_register_uri_handler(g_server, &route);
    if (err != ESP_OK) {
      log::error("http: register %s failed %d", route.uri, static_cast<int>(err));
      httpd_stop(g_server);
      g_server = nullptr;
      return false;
    }
  }

  g_requests = 0;
  g_inFlight = 0;
  if (fs::webMounted()) {
    log::info("stage 3: http listening on port %u, web %u KB", config::kHttpPort,
              static_cast<unsigned>(fs::webUsedBytes() >> 10));
  } else {
    log::warn("stage 3: http listening on port %u, web NOT mounted: static will 404 "
              "(run: pio run -t uploadall)",
              static_cast<unsigned>(config::kHttpPort));
  }
  return true;
}

void stop() {
  if (g_server == nullptr) {
    return;
  }
  const esp_err_t err = httpd_stop(g_server);
  if (err != ESP_OK) {
    log::error("http: httpd_stop failed %d", static_cast<int>(err));
  }
  g_server = nullptr;
}

}  // namespace http_server
}  // namespace pm
