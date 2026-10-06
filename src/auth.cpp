#include "auth.h"

#include <Arduino.h>
#include <esp_random.h>
#include <esp_task_wdt.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include <string.h>

#include "crypto.h"
#include "logger.h"
#include "wordlist.h"

// Генерация мастер-пароля идёт по kMasterWordBytes/kMasterPasswordChars из
// config.h, а слова — из include/wordlist.h.
//
// Слова в проекте живут в единственном экземпляре: заголовок объявляет таблицу
// extern, а определяет её src/wordlist.cpp. Таблицу включают и этот файл, и
// selftest, поэтому раньше наивный `const char kWords[]` в заголовке давал по
// копии 24 КБ на каждый включающий TU. Подробности выбора приёма и почему не
// подошли inline-переменная и литерал внутри функции — в scripts/wordlist.py.
// namespace-скоупы config/wordlist начинаются ниже, поэтому проверки вынесены в
// конец файла, где pm уже открыт.


namespace pm {
namespace auth {
namespace {

// Очередь глубиной 1. Глубже незачем: одновременная разблокировка невозможна по
// смыслу, а лишние job'ы в очереди только копят невыполненные запросы, каждый из
// которых стоит 5.8 с CPU. Гонки за очередь нет: единственный писатель —
// вызывающий из задачи httpd, и он действует под authMux.
QueueHandle_t g_queue = nullptr;
SemaphoreHandle_t g_mux = nullptr;
portMUX_TYPE g_muxSpin = portMUX_INITIALIZER_UNLOCKED;

// Поля, которые читает HTTP-слой без блокировки (state()). Они пишутся и под
// authMux, и из воркера, поэтому читаются в критической секции — она тут держится
// доли микросекунды, а ждать на ней authMux нельзя.
volatile bool g_provisioned = false;
volatile bool g_unlocked = false;
volatile bool g_busy = false;
volatile uint8_t g_failCount = 0;
volatile uint32_t g_lockoutUntilMs = 0;

// Момент открытия сессии: по нему считается простой. 0 — сессии нет.
volatile uint32_t g_unlockedAtMs = 0;

struct Request {
  Job kind;
  JobId id;  // job сюда кладёт единственный писатель — submit()
  char password[config::kMaxPassChars];
};

// Слот результата. Один, а не очередь результатов: HTTP-слой опрашивает по id и
// после завершения job'а слот освобождается следующим submit(). Хранить историю
// незачем, а job без востребованного результата всё равно не отличить от
// устаревшего.
struct Slot {
  JobId id;
  Job kind;
  Result result;
  bool inFlight;
  // Секреты живут здесь между завершением job'а и первым poll(). Стираются при
  // заборе, при следующем submit(), при lock() и при install().
  //
  // Два секрета, а не один: provisioning отдаёт пароль, unlock — токен сессии.
  char password[config::kMasterPasswordChars + 1];
  char sessionToken[kSessionTokenHexLen + 1];
};

Slot g_slot = {};

// Токен сессии. Только в RAM: переживать перезагрузку ему не нужно и нельзя.
uint8_t g_token[config::kSessionTokenLen] = {};

uint32_t nowMs() {
  return static_cast<uint32_t>(millis());
}

// Сборка байт в hex. Опережающее объявление: runUnlock() и runProvision() кладут
// токен в слот до publishResult(), то есть раньше определения ниже.
void writeHex(const uint8_t* src, size_t srcLen, char* out) {
  static const char kHex[] = "0123456789abcdef";
  for (size_t i = 0; i < srcLen; ++i) {
    out[i * 2] = kHex[src[i] >> 4];
    out[i * 2 + 1] = kHex[src[i] & 0x0f];
  }
  out[srcLen * 2] = '\0';
}

// Случайный JobId.
//
// Идентификатор служит паролем на /api/auth/job/{id} до появления сессии, поэтому
// он обязан быть непредсказуемым. Счётчик дал бы перебор последовательными
// запросами, и это не теоретическая угроза: маршрут открыт, пока хранилище
// заблокировано, а под ним лежит одноразовый мастер-пароль.
JobId randomJobId() {
  JobId id = 0;
  esp_fill_random(&id, sizeof(id));
  return id;
}

const uint8_t* g_randSrc = nullptr;
size_t g_randLen = 0;
size_t g_randPos = 0;

// Читает len случайных байт из подменённого источника, либо настоящего, если
// подмены нет. Один вызов — один заряд: u32 берётся как четыре байта, поэтому
// границы u32 никогда не попадают внутрь словарь/цифры наполовину.
void fillRandom(uint8_t* out, size_t len) {
  if (g_randSrc == nullptr || g_randLen == 0) {
    esp_fill_random(out, len);
    return;
  }
  for (size_t i = 0; i < len; ++i) {
    out[i] = g_randSrc[g_randPos];
    if (++g_randPos == g_randLen) {
      g_randPos = 0;
    }
  }
}

// Равномерный индекс слова из 4096.
//
// Отбраковка НЕ нужна и добавление её было бы ошибкой: 4096 = 2^12, поэтому
// v >> 20 даёт ровно равномерное распределение по 4096 значениям. Режекция
// percent-по-модулю здесь ломает распределение; добавлять её «на всякий случай»
// нельзя, лишний код на равномерности не скажется, а на читаемости — да.
uint32_t randomWordIndex() {
  uint32_t v = 0;
  fillRandom(reinterpret_cast<uint8_t*>(&v), sizeof(v));
  return v >> 20;  // 32 - 12 = 20
}

// Равномерная цифра 0..9.
//
// 256 на 10 не делится, поэтому 6 значений (250..255) отбраковываются: без этого
// цифры 0..5 выпадали бы на 6/256 шанса каждая вместо 5/250. Цикл почти всегда
// берёт одну итерацию.
//
// Число попыток ограничено. С esp_fill_random() исход бесконечным быть не может
// (вероятность 256 неудач подряд = (6/256)^256), но источник подменяется тестом,
// и там встречаются буферы из одних 0xFF: цикл без ограничения там не
// заканчивается никогда, и гейт вешал всю плату на ребут. С лимитом худший
// случай — пароль с чуть смещённым распределением цифр, то есть отказ, а не
// зависание.
uint8_t randomDigit() {
  uint8_t b = 0;
  for (uint32_t attempt = 0; attempt < config::kMaxDigitAttempts; ++attempt) {
    fillRandom(&b, sizeof(b));
    if (b < 250) {
      return static_cast<uint8_t>(b % 10);
    }
  }
  log::error("auth: digit rejection exhausted %u attempts, biased fallback",
             static_cast<unsigned>(config::kMaxDigitAttempts));
  return static_cast<uint8_t>(b % 10);
}

// Собирает мастер-пароль в out. out — не меньше
// config::kMasterPasswordChars + 1 байт.
size_t generatePassword(char* out, size_t outLen) {
  if (outLen < config::kMasterPasswordChars + 1) {
    return 0;
  }
  char tmp[config::kMasterPasswordChars + 1];
  size_t n = 0;
  for (size_t w = 0; w < config::kMasterWords; ++w) {
    if (w != 0) {
      tmp[n++] = '-';
    }
    // Слово из словаря — ровно kWordBytes букв, дефисы между ними наше,
    // поэтому копируем фиксированную длину, а не strlen.
    const char* src = wordlist::word(randomWordIndex());
    memcpy(tmp + n, src, wordlist::kWordBytes);
    n += wordlist::kWordBytes;
  }
  tmp[n++] = '-';
  tmp[n++] = static_cast<char>('0' + randomDigit());
  tmp[n++] = static_cast<char>('0' + randomDigit());
  tmp[n] = '\0';

  // Запись обязана заполнить буфер ровно. Проверка не «на всякий случай»: без
  // неё ошибка в раскладке (забытый разделитель, лишнее слово) даёт тихий
  // выход за границу tmp и ребет с "Stack smashing protect failure" — диагноз
  // без указания на строку, которая писала лишний байт.
  if (n != config::kMasterPasswordChars) {
    crypto::wipe(tmp, sizeof(tmp));
    return 0;
  }

  memcpy(out, tmp, n + 1);
  crypto::wipe(tmp, sizeof(tmp));
  return n;
}

uint32_t lockoutLeftMs() {
  const uint32_t until = g_lockoutUntilMs;
  if (until == 0) {
    return 0;
  }
  // Сравнение обязано быть ЗНАКОВЫМ. millis() переполняется примерно раз в 49.7
  // дня, и беззнаковое `until > now` в этом случае выдаёт 0, то есть заявляет
  // об истёкшей блокировке: 60-секундный lockout отключается сам собой ровно в
  // момент переполнения, и пять неверных паролей перестают что-либо ограничивать.
  // Приведение к int32_t делает разность знаковой и переносит переход через 0.
  const int32_t left = static_cast<int32_t>(until - nowMs());
  return (left > 0) ? static_cast<uint32_t>(left) : 0;
}

void publishLocked() {
  portENTER_CRITICAL(&g_muxSpin);
  g_unlocked = false;
  g_unlockedAtMs = 0;
  portEXIT_CRITICAL(&g_muxSpin);
}

// Закрывает сессию целиком. Вызывается из lock(), из истечения простоя и из
// неудачной попытки разблокировки (там сессии и так нет, но wipe лишним не
// помешает).
void closeSession() {
  crypto::wipe(g_token, sizeof(g_token));
  publishLocked();
  vault::close();
}

// Результат job'а публикуется под g_mux — тем же самым, под которым слот читает
// poll() и стирает в submit().
//
// Смешивать здесь спинлок и g_mux было ошибкой: слот писался под одним замком, а
// читался и стирался под другим, то есть формально это гонка. Для трёх байт
// результата она почти всегда оставалась незамеченной, но пароль provisioning'а
// (38 байт) копировался под спинлоком и читался под мьютексом — то есть poll() мог
// забрать половину строки. Критическая секция тут не нужна: писатель и так не
// держит g_mux в этот момент, а блокировка мьютексом ничего не стоит.
void publishResult(JobId id, Job kind, Result result) {
  if (xSemaphoreTake(g_mux, portMAX_DELAY) != pdTRUE) {
    return;
  }
  g_slot.id = id;
  g_slot.kind = kind;
  g_slot.result = result;
  g_slot.inFlight = false;
  g_busy = false;
  xSemaphoreGive(g_mux);
}

// Основная работа. Выполняется только в задаче-воркере, поэтому блокировок не
// берёт: единственный конкурент — HTTP-слой, и он пишет в слот под authMux, а
// читает тоже под ним.
void runUnlock(Request& req) {
  const uint32_t left = lockoutLeftMs();
  if (left > 0) {
    log::warn("auth: unlock refused, lockout %u ms left", static_cast<unsigned>(left));
    publishResult(req.id, Job::Unlock, Result::Lockout);
    return;
  }

  const vault::VaultError rc = vault::begin(req.password);
  if (rc == vault::VaultError::Ok) {
    portENTER_CRITICAL(&g_muxSpin);
    g_failCount = 0;
    g_lockoutUntilMs = 0;
    g_unlocked = true;
    g_unlockedAtMs = nowMs();
    portEXIT_CRITICAL(&g_muxSpin);
    esp_fill_random(g_token, sizeof(g_token));
    // Токен кладётся в слот ДО publishResult(), по той же причине, что и пароль в
    // runProvision(): publishResult() сбрасывает g_busy, и после этого следующий
    // submit() вправе стереть слот как устаревший.
    //
    // Без этого выдачи токена протокол нерабочий: разблокировавший клиент не
    // знает токена своей сессии, а GET /api/auth/session требует его заголовком.
    if (xSemaphoreTake(g_mux, portMAX_DELAY) == pdTRUE) {
      writeHex(g_token, sizeof(g_token), g_slot.sessionToken);
      xSemaphoreGive(g_mux);
    }
    log::info("auth: unlocked");
    publishResult(req.id, Job::Unlock, Result::Ok);
    return;
  }

  // Неверный пароль. Счётчик и блокировка — только в RAM: после перезагрузки они
  // обнуляются, и это осознанно. Персистентный счётчик защищал бы от офлайн-подбора
  // ценой того, что забытый пароль блокирует устройство навсегда, и он же дал бы
  // атакующему физическим доступом способ залочить жертву необратимо.
  //
  // Ошибка хранилища (Tampered, Io, Crypto) НЕ увеличивает счётчик: это не вина
  // пользователя, и запирать устройство из-за сбоя флеша нельзя.
  if (rc == vault::VaultError::WrongPassword) {
    const uint8_t fails = static_cast<uint8_t>(g_failCount + 1);
    uint32_t until = 0;
    if (fails >= config::kAuthMaxFail) {
      until = nowMs() + config::kAuthLockoutMs;
    }
    portENTER_CRITICAL(&g_muxSpin);
    g_failCount = fails;
    g_lockoutUntilMs = until;
    portEXIT_CRITICAL(&g_muxSpin);
    log::warn("auth: wrong password, fails %u", static_cast<unsigned>(fails));
    publishResult(req.id, Job::Unlock, Result::WrongPassword);
    return;
  }

  log::error("auth: unlock failed %s", vault::toString(rc));
  publishResult(req.id, Job::Unlock, Result::Error);
}

void runProvision(Request& req) {
  (void)req;
  // Повторная проверка, а не только проверка в submitProvision(): между теми
  // моментами мог появиться результат чужого job'а. Стирание раздела на
  // provisioned-хранилище — необратимая потеря данных.
  if (vault::provisioned()) {
    log::warn("auth: provisioning refused, vault already provisioned");
    publishResult(req.id, Job::Provision, Result::Refused);
    return;
  }

  char pw[config::kMasterPasswordChars + 1] = {};
  if (generatePassword(pw, sizeof(pw)) != config::kMasterPasswordChars) {
    // При константах выше сюда не дойти, но проверка не стоит ничего: молча
    // записанный пароль не той длины означал бы, что пользователю отдаётся
    // строка, которую он не сможет ввести обратно.
    log::error("auth: password generator produced %u bytes",
               static_cast<unsigned>(config::kMasterPasswordChars));
    publishResult(req.id, Job::Provision, Result::Error);
    return;
  }

  const vault::VaultError rc = vault::begin(pw);
  if (rc != vault::VaultError::Ok) {
    crypto::wipe(pw, sizeof(pw));
    log::error("auth: provisioning failed %s", vault::toString(rc));
    publishResult(req.id, Job::Provision, Result::Error);
    return;
  }

  esp_fill_random(g_token, sizeof(g_token));
  portENTER_CRITICAL(&g_muxSpin);
  g_provisioned = true;
  g_unlocked = true;
  g_unlockedAtMs = nowMs();
  g_failCount = 0;
  g_lockoutUntilMs = 0;
  portEXIT_CRITICAL(&g_muxSpin);

  // Кладём пароль в слот ПОД publishResult. Порядок обязателен: publishResult
  // сбрасывает g_busy, и после этого submit() вправе стереть слот как
  // устаревший. Если бы сброс busy служился раньше записи пароля, следующий
  // job стёр бы пароль, который пользователь ещё не забрал.
  //
  // Токен сессии кладётся тут же: provisioning оставляет хранилище открытым, то
  // есть клиенту он тоже нужен, иначе первый же запрос к /api/entries откажется.
  if (xSemaphoreTake(g_mux, portMAX_DELAY) == pdTRUE) {
    memcpy(g_slot.password, pw, sizeof(g_slot.password));
    writeHex(g_token, sizeof(g_token), g_slot.sessionToken);
    xSemaphoreGive(g_mux);
  }

  // Локальная копия стирается сразу после того, как пароль уехал в слот. Раньше
  // wipe стоял только на ветке ошибки vault::begin(), и на успешном provisioning
  // мастер-пароль оставался лежать на стеке воркера до следующего вызова.
  crypto::wipe(pw, sizeof(pw));

  log::info("auth: provisioned, master password ready to collect");
  publishResult(req.id, Job::Provision, Result::Ok);
}

void runReset(Request& req) {
  (void)req;
  // Сброс уничтожает раздел целиком, поэтому повторная проверка состояния в
  // воркере, а не только в submitReset(): между теми моментами состояние могло
  // измениться. На неprovisioned-хранилище отвечаем Refused, а не Ok — иначе UI
  // сообщил бы об успешном уничтожении того, чего не было.
  if (!vault::provisioned()) {
    log::warn("auth: reset refused, nothing to destroy");
    publishResult(req.id, Job::Reset, Result::Refused);
    return;
  }

  const vault::VaultError rc = vault::reset();
  if (rc != vault::VaultError::Ok) {
    log::error("auth: reset failed %s", vault::toString(rc));
    publishResult(req.id, Job::Reset, Result::Error);
    return;
  }

  // Сессия после стирания не имеет смысла: токен был выдан для хранилища,
  // которого больше нет. closeSession() стирает токен и закрывает vault, то
  // есть публикация «unlocked» перед reset'ом была бы ложью.
  closeSession();
  portENTER_CRITICAL(&g_muxSpin);
  g_provisioned = false;
  g_unlocked = false;
  g_unlockedAtMs = 0;
  g_failCount = 0;
  g_lockoutUntilMs = 0;
  portEXIT_CRITICAL(&g_muxSpin);

  // Секреты прошлого job'а стираются под g_mux — тем же, под которым poll() их
  // читает. Вне мьютекса это гонка: если незабранный пароль provisioning'а лежал
  // в слоте, reset стирал бы его, пока HTTP-обработчик его копировал, и poll()
  // забрал бы половину строки. publishResult() сам этого не делает.
  if (xSemaphoreTake(g_mux, portMAX_DELAY) == pdTRUE) {
    crypto::wipe(g_slot.password, sizeof(g_slot.password));
    crypto::wipe(g_slot.sessionToken, sizeof(g_slot.sessionToken));
    xSemaphoreGive(g_mux);
  }

  log::warn("auth: vault destroyed by request, all entries lost");
  publishResult(req.id, Job::Reset, Result::Ok);
}

void workerTask(void* arg) {
  (void)arg;
  Request req;
  for (;;) {
    // Сессия закрывается по простою здесь, а не в HTTP-обработчике: иначе
    // устройство останется открытым, пока по нему никто не ходит, а простой —
    // это в том числе «пользователь ушёл, а экран оставил открытым».
    const uint32_t openedAt = g_unlockedAtMs;
    if (openedAt != 0 && (nowMs() - openedAt) >= config::kSessionTtlMs) {
      log::info("auth: idle timeout, session closed");
      closeSession();
    }

    if (xQueueReceive(g_queue, &req, pdMS_TO_TICKS(config::kAuthIdleCheckMs)) != pdTRUE) {
      continue;
    }
    if (req.kind == Job::Unlock) {
      runUnlock(req);
    } else if (req.kind == Job::Reset) {
      runReset(req);
    } else {
      runProvision(req);
    }
    crypto::wipe(req.password, sizeof(req.password));
  }
}

// Общий вход для всех submit(). Проверки дешёвые — до входа в критическую
// секцию; внутри только запись слота, чтобы не держать её на проверках.
JobId submit(Job kind, const char* password) {
  if (g_queue == nullptr) {
    return 0;
  }
  if (kind == Job::Provision && vault::provisioned()) {
    return 0;
  }
  if (kind == Job::Unlock && lockoutLeftMs() > 0) {
    return 0;
  }

  Request req = {};
  req.kind = kind;
  if (password != nullptr) {
    const size_t n = strlen(password);
    if (n == 0 || n >= sizeof(req.password)) {
      return 0;
    }
    memcpy(req.password, password, n + 1);
  }

  JobId id = kNoJob;
  if (xSemaphoreTake(g_mux, portMAX_DELAY) != pdTRUE) {
    return kNoJob;
  }
  if (g_busy) {
    xSemaphoreGive(g_mux);
    return kNoJob;
  }
  // Секреты прошлого job'а стираются ДО перезаписи слота: они могли остаться там
  // от provisioning, результат которого так и не забрали.
  crypto::wipe(g_slot.password, sizeof(g_slot.password));
  crypto::wipe(g_slot.sessionToken, sizeof(g_slot.sessionToken));
  id = randomJobId();
  // Крайне маловероятное kNoJob всё же запрещено: id обязан быть ненулевым,
  // потому что ноль submit() означает «job не принят».
  if (id == kNoJob) {
    id = 1;
  }
  g_slot.id = id;
  g_slot.kind = kind;
  g_slot.result = Result::Pending;
  g_slot.inFlight = true;
  g_busy = true;
  // id кладётся в Request, а не читается воркером из g_slot: слот следующий
  // submit() перезапишет, и воркер, читающий его после задержки в очереди,
  // опубликовал бы результат чужого job'а.
  req.id = id;
  xSemaphoreGive(g_mux);

  if (xQueueSend(g_queue, &req, 0) != pdTRUE) {
    // Очередь полна, хотя g_busy был false. Возможно только при гонке с
    // reset()/перезагрузкой; слот всё равно надо вернуть в согласованное
    // состояние, иначе устройство навсегда покажет «занято».
    if (xSemaphoreTake(g_mux, portMAX_DELAY) == pdTRUE) {
      g_busy = false;
      g_slot.inFlight = false;
      g_slot.result = Result::Busy;
      xSemaphoreGive(g_mux);
    }
    return 0;
  }
  return id;
}

}  // namespace

const char* toString(Result r) {
  switch (r) {
    case Result::Pending:
      return "pending";
    case Result::Ok:
      return "ok";
    case Result::WrongPassword:
      return "wrong_password";
    case Result::Refused:
      return "refused";
    case Result::Lockout:
      return "lockout";
    case Result::Busy:
      return "busy";
    case Result::Error:
      return "error";
  }
  return "unknown";
}

bool install() {
  if (g_queue != nullptr) {
    return true;
  }
  // При любом частичном сбое ресурсы освобождаются и указатели обнуляются. Иначе
  // повторный install() увидел бы непустой g_queue и вернул true, хотя воркера
  // нет: слой авторизации отвечал бы на запросы, которые никто не выполняет, и
  // принятый пароль был бы потерян без всякого результата.
  g_mux = xSemaphoreCreateMutex();
  if (g_mux == nullptr) {
    log::error("auth: cannot create mutex");
    return false;
  }
  g_queue = xQueueCreate(1, sizeof(Request));
  if (g_queue == nullptr) {
    log::error("auth: cannot create queue");
    vSemaphoreDelete(g_mux);
    g_mux = nullptr;
    return false;
  }

  // Состояние provisioned читается с флеша здесь, а не берётся из первого
  // результата job'а: до первого unlock/provision состояние всё равно нужно
  // ответить, иначе первый же GET /api/auth/state сказал бы «не настроено».
  g_provisioned = vault::provisioned();
  {
    const vault::Snapshot snap = vault::snapshot();
    g_unlocked = snap.state == vault::State::Unlocked;
  }

  if (xTaskCreate(workerTask, "auth_worker", config::kAuthWorkerStackBytes / sizeof(StackType_t),
                  nullptr, config::kAuthWorkerPriority, nullptr) != pdPASS) {
    log::error("auth: worker task create failed");
    vQueueDelete(g_queue);
    g_queue = nullptr;
    vSemaphoreDelete(g_mux);
    g_mux = nullptr;
    return false;
  }
  log::info("auth: worker up, provisioned %d",
            static_cast<int>(g_provisioned));
  return true;
}

size_t generateMasterPassword(char* out, size_t outLen) {
  if (out == nullptr) {
    return 0;
  }
  return generatePassword(out, outLen);
}

void setRandomSourceForTest(const uint8_t* bytes, size_t len) {
  g_randSrc = (len > 0) ? bytes : nullptr;
  g_randLen = len;
  g_randPos = 0;
}

JobId submitProvision() {
  return submit(Job::Provision, nullptr);
}

JobId submitUnlock(const char* password) {
  return submit(Job::Unlock, password);
}

// Проверки состояния здесь НЕТ намеренно: submit() вернул бы 0 и на занятом
// воркере, и на неprovisioned-хранилище, а HTTP обязан отличать эти два случая —
// «занято, повтори» это 503, а «нечего стирать» это 409. Ответ Refused даёт
// воркер (runReset), то есть решение принимается в одном месте и не может
// разойтись с тем, что потом реально сделает стирание.
JobId submitReset() {
  return submit(Job::Reset, nullptr);
}

bool poll(JobId jobId, JobView* out) {
  if (g_mux == nullptr || out == nullptr || jobId == kNoJob) {
    return false;
  }
  bool found = false;
  if (xSemaphoreTake(g_mux, portMAX_DELAY) != pdTRUE) {
    return false;
  }
  if (g_slot.id == jobId) {
    out->kind = g_slot.kind;
    out->result = g_slot.result;
    const bool ok = out->result == Result::Ok;
    // Секреты отдаются ровно один раз: иначе они осели бы в буфере HTTP-ответа
    // повторных опросов и жили бы в памяти дольше, чем нужно.
    if (ok && g_slot.password[0] != '\0') {
      memcpy(out->password, g_slot.password, sizeof(out->password));
      crypto::wipe(g_slot.password, sizeof(g_slot.password));
    } else {
      out->password[0] = '\0';
    }
    if (ok && g_slot.sessionToken[0] != '\0') {
      memcpy(out->sessionToken, g_slot.sessionToken, sizeof(out->sessionToken));
      crypto::wipe(g_slot.sessionToken, sizeof(g_slot.sessionToken));
    } else {
      out->sessionToken[0] = '\0';
    }
    found = true;
  }
  xSemaphoreGive(g_mux);
  return found;
}

State state() {
  State s = {};
  // vault::provisioned() и snapshot() читают флеш, а в критической секции
  // прерывания выключены. Два чтения по 256 байт там — это уже не «доли
  // микросекунды», и httpd на такой паузе получает таймаут. Поэтому флеш
  // читается ДО входа, а под секцией берутся только уже вычисленные значения.
  const vault::Snapshot snap = vault::snapshot();
  const bool onFlash = vault::provisioned();
  portENTER_CRITICAL(&g_muxSpin);
  s.provisioned = g_provisioned || onFlash;
  s.unlocked = g_unlocked && snap.state == vault::State::Unlocked;
  s.busy = g_busy;
  s.failCount = g_failCount;
  s.lockoutMsLeft = lockoutLeftMs();
  portEXIT_CRITICAL(&g_muxSpin);
  return s;
}

// Токен — 32 СЛУЧАЙНЫХ байта, а в заголовке X-PM-Session он идёт текстом, то
// есть 64 hex-символа. Base64 здесь не нужен: заголовок и так несёт 64 байта,
// а hex не требует алфавита, который пришлось бы исключать на стороне сервера.
// Сборка 32 байт в 64 hex-символа — writeHex() из анонимного пространства.
int hexNibble(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

bool sessionTokenHex(char* out, size_t outLen) {
  if (out == nullptr || outLen < kSessionTokenHexLen + 1) {
    return false;
  }
  if (!g_unlocked) {
    return false;
  }
  uint8_t allZero = 0;
  for (size_t i = 0; i < sizeof(g_token); ++i) {
    allZero = static_cast<uint8_t>(allZero | g_token[i]);
  }
  if (allZero == 0) {
    return false;
  }
  writeHex(g_token, sizeof(g_token), out);
  return true;
}

bool sessionValid(const char* tokenHex, size_t len) {
  if (tokenHex == nullptr || len != kSessionTokenHexLen) {
    return false;
  }
  if (!g_unlocked) {
    return false;
  }
  uint8_t allZero = 0;
  for (size_t i = 0; i < sizeof(g_token); ++i) {
    allZero = static_cast<uint8_t>(allZero | g_token[i]);
  }
  if (allZero == 0) {
    return false;  // сессия закрыта, токен wipe-нут
  }
  // Сначала весь заголовок декодируется и только потом сравнивается: сравнение
  // на лету остановилось бы на первом различии и дало бы oracle по длине
  // валидного префикса.
  uint8_t given[config::kSessionTokenLen];
  for (size_t i = 0; i < sizeof(given); ++i) {
    const int hi = hexNibble(tokenHex[i * 2]);
    const int lo = hexNibble(tokenHex[i * 2 + 1]);
    if (hi < 0 || lo < 0) {
      return false;
    }
    given[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  const bool ok = crypto::ctEqual(g_token, given, sizeof(g_token));
  crypto::wipe(given, sizeof(given));
  return ok;
}

bool lock() {
  if (g_mux == nullptr) {
    return false;
  }
  if (xSemaphoreTake(g_mux, portMAX_DELAY) != pdTRUE) {
    return false;
  }
  // Воркер держит мьютекс vault все ~5.8 с внутри begin(). Закрывать сессию под
  // g_mux нельзя: vault::close() ждал бы этот мьютекс, и на всё время ожидания
  // poll()/submit() встали бы, а вместе с ними — весь httpd. Поэтому секреты слота
  // стираются здесь, а закрытие хранилища уходит после отпускания.
  crypto::wipe(g_slot.password, sizeof(g_slot.password));
  crypto::wipe(g_slot.sessionToken, sizeof(g_slot.sessionToken));
  xSemaphoreGive(g_mux);

  closeSession();
  log::info("auth: session closed on request");
  return true;
}

void expireIdleSession(uint32_t ttlMs) {
  const uint32_t openedAt = g_unlockedAtMs;
  if (openedAt != 0 && (nowMs() - openedAt) >= ttlMs) {
    log::info("auth: idle timeout forced");
    closeSession();
  }
}

void clearLockout() {
  portENTER_CRITICAL(&g_muxSpin);
  g_failCount = 0;
  g_lockoutUntilMs = 0;
  portEXIT_CRITICAL(&g_muxSpin);
}

}  // namespace auth

static_assert(config::kMasterWordBytes == wordlist::kWordBytes,
              "config::kMasterWordBytes разошёлся с wordlist::kWordBytes");
static_assert(config::kMasterWords * wordlist::kWordStride <= 4096,
              "раскладка пароля перестала помещаться в generatePassword()");

}  // namespace pm
