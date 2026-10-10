#pragma once

#include <stddef.h>
#include <stdint.h>

namespace pm {
namespace config {

constexpr char kFirmwareVersion[] = "0.2.0";

constexpr char kVaultMagic[] = "PMV1";
constexpr char kExportMagic[] = "PMX1";
// Версия формата экспорта PMX1. Растёт при несовместимом изменении структуры.
constexpr uint32_t kExportVersion = 1;

constexpr uint16_t kUsbVid = 0x303A;
constexpr uint16_t kUsbPid = 0x4001;
constexpr uint8_t kUsbBcdUsbHi = 0x02;
constexpr uint8_t kUsbBcdUsbLo = 0x00;
constexpr uint8_t kUsbBcdDeviceHi = 0x01;
constexpr uint8_t kUsbBcdDeviceLo = 0x00;
constexpr uint8_t kUsbBcdNcmHi = 0x01;
constexpr uint8_t kUsbBcdNcmLo = 0x00;
constexpr uint8_t kUsbMaxPacketSize0 = 64;
constexpr uint8_t kUsbEpInterrupt = 0x81;
constexpr uint8_t kUsbEpBulkIn = 0x82;
constexpr uint8_t kUsbEpBulkOut = 0x02;
// 16, а не 8: уведомление CONNECTION_SPEED_CHANGE в TinyUSB — это
// ecm_notify_struct = 8 байт заголовка + 4 байта downlink + 4 байта uplink =
// 16 байт, и оно обязано лечь в один пакет. При wMaxPacketSize = 8 хост
// cdc_ncm не вытаскивает из него скорость линка, скорость остаётся 0,
// carrier не поднимается (netif_carrier_on живёт в __handle_link_change в
// usbnet.ko, куда cdc_ncm не доходит), cdc_ncm не начинает опрашивать наш
// bulk IN — и мы отправляем NTB в пустоту: tx растёт, а RX на хосте стоит.
constexpr uint8_t kUsbEpInterruptSize = 16;
constexpr uint8_t kUsbEpBulkSize = 64;
constexpr uint16_t kNcmMaxSegmentSize = 1514;

constexpr char kUsbManufacturer[] = "PassManager";
constexpr char kUsbProduct[] = "PassManager NCM";
constexpr char kUsbNcmInterface[] = "NCM";
constexpr char kUsbNtbInterface[] = "NTB";
constexpr char kUsbDataInterface[] = "Data";

// Эхо принятых кадров без единой правки байтов. Нужно было только на 2a, чтобы
// доказать живой data path. С 2b выключено: кадры уходят в lwIP, а эхо
// дублировало бы трафик и маскировало бы реальные ошибки data path.
constexpr bool kNcmLoopback = false;

// Глубина стека задачи tud_task в СЛОВАХ FreeRTOS, не в байтах:
// 8192 слов = 32 KB. CFG_TUD_MAINTASK_SIZE в нашем сборке никто не читает —
// размер задаёт только xTaskCreate здесь.
constexpr uint32_t kUsbTaskStackWords = 8192;

// Ключ и имя собственного netif. ESP_NETIF_BASE_DEFAULT_SLIP() — единственный
// готовый не-WiFi пример в IDF 4.4.7, но его if_key "SLP_DEF" и флаг
// ESP_NETIF_FLAG_IS_SLIP нам не подходят: нужен DHCP-сервер и автоподъём.
constexpr char kNetifIfKey[] = "NCM_DEF";
constexpr char kNetifIfDesc[] = "ncm";
// MTU через esp_netif в 4.4.7 не настраивается (нет API), и в этом нет
// необходимости: kNcmMaxSegmentSize = 1514 уже включает 14 байт Ethernet-заголовка,
// то есть ровно 1500 байт полезной нагрузки — стандартный MTU lwIP.

constexpr uint8_t kDhcpServerIp[4] = {192, 168, 7, 1};
constexpr uint8_t kDhcpDns[4] = {192, 168, 7, 1};
constexpr uint32_t kDhcpLeaseSecs = 24 * 3600;
// Fallback для адреса САМОГО интерфейса NCM, если не прочитался efuse.
// Это не allowlist: проверки и логирования MAC клиента в проекте нет вообще,
// доступ к API — только HMAC challenge-response.
constexpr uint8_t kMacFallback[6] = {0x7C, 0xDF, 0xA1, 0x00, 0x00, 0x01};

constexpr uint32_t kLogBaud = 115200;
// 256 не хватало сердцебиению ncm: строка обрезалась на desc-счётчиках и
// диагностика tx (q/cx/ps/ih) в лог не попадала вовсе. 320 покрывает полный
// формат с запасом; буфер один, на стеке vwrite.
constexpr size_t kLogLineMax = 320;
constexpr size_t kPsramProbeBytes = 64 * 1024;

constexpr uint16_t kHttpPort = 80;
constexpr size_t kHttpMaxUri = 512;
constexpr size_t kHttpMaxBody = 8192;
constexpr size_t kHttpMaxSessions = 4;

// kHttpMaxUri в точности равен CONFIG_HTTPD_MAX_URI_LEN из sdkconfig этого SDK,
// поэтому httpd сам отдаёт 414 на длинном URI и дублировать проверку не нужно.
// Лимит сессий держит max_open_sockets в httpd_config_t: отдельного
// max_open_sessions в IDF 4.4 нет, а счётчик в open_fn/close_fn использовать
// нельзя — регистрация этих хуков ломает сервер примерно через 12 соединений
// (утечка TCP PCB, дальше ENFILE), см. комментарий в src/http_server.cpp.

// Размер чанка, которым статический файл скармливается в сокет. Файл целиком в
// кучу не читается принципиально: раздел web — 1 MB, а отдавать его в heap
// одним куском значит забрать у lwIP память под пакеты.
constexpr size_t kHttpChunkBytes = 1024;

constexpr size_t kNonceLen = 32;
constexpr size_t kHmacKeyLen = 32;
constexpr size_t kHmacLen = 32;
constexpr uint8_t kAuthMaxFail = 5;
constexpr uint32_t kAuthLockoutMs = 60 * 1000;
constexpr uint32_t kSessionTtlMs = 15 * 60 * 1000;

// Токен сессии: 32 случайных байта, как и kNonceLen, но сущность другая — это
// не noncechallenge, а идентификатор открытой сессии, который клиент носит в
// заголовке X-PM-Session.
constexpr size_t kSessionTokenLen = 32;

// Период уступки CPU внутри PBKDF2. 1024 итерации ≈ 3 мс на ESP32-S3 при
// 240 МГц, то есть между уступками проходит примерно один квант планировщика.
// Степень двойки: условие сводится к (i & (kYieldEvery-1)) == 0, без деления
// и без счётчика в цикле.
constexpr uint32_t kYieldEvery = 1024;

// Предел числа попыток при отбраковке значения для цифры мастер-пароля.
// 256 попыток хватает с огромным запасом: вероятность, что все 256 байт
// окажутся в шести отбраковываемых значениях, равна (6/256)^256.
constexpr uint32_t kMaxDigitAttempts = 256;

// Задача-воркер, выполняющая PBKDF2.
//
// Приоритет НИЖЕ, чем у задачи httpd (tskIDLE_PRIORITY + 5 = 5). Это не
// оптимизация, а условие работоспособности: разблокировка держит CPU ~5.8 с
// плотным циклом (см. kPbkdf2Iters), и воркер на равном или высокем приоритете
// не отдал бы ядро задаче httpd — polling-эндпоинт перестал бы отвечать, то
// есть асинхронная модель 202 + опрос перестала бы работать. Ниже idle (0) опуститься
// нельзя: тогда на том же ядре перестанет идти задача idle, а с ней и сброс WDT.
constexpr uint32_t kAuthWorkerPriority = 4;
// Стек воркера. На нём всегда лежит Request целиком: password (256 Б) плюс
// keyFile (kKeyFileMaxBytes = 4096 Б) — файл копируется в запрос, а не в
// слот результата, поэтому 4.4 КБ заняты даже в простое. Плюс cand[2][256] в
// begin(), снимки заголовков в rekey() и кадры SHA-256/PBKDF2. 12 КБ берут
// запас под всё это; 6 КБ хватило бы только до появления keyFile в Request.
constexpr uint32_t kAuthWorkerStackBytes = 12 * 1024;
// Период проверки простоя сессии. Воркер просыпается по таймауту очереди и за
// этим интервалом смотрит, не пора ли закрыть сессию по kSessionTtlMs. Отдельный
// таймер не нужен: иначе его пришлось бы синхронизировать с состоянием сессии.
constexpr uint32_t kAuthIdleCheckMs = 1000;

// Политики MAC в проекте нет: ни фильтрации, ни логирования. Единственный
// барьер доступа к API — HMAC challenge-response (kNonceLen/kHmacKeyLen ниже).

constexpr size_t kAesKeyLen = 32;
constexpr size_t kGcmIvLen = 12;
constexpr size_t kGcmTagLen = 16;
// Замерено на железе (см. src/crypto.cpp): 96.6 мкс на итерацию, при 240 МГц и
// software SHA-256. Отсюда 30000 итераций = 2.9 с разблокировки.
//
// 200k с точки зрения стойкости ничего не давали: разница в 6.7x несоизмерима
// с энтропией пароля. Passphrase из 5-6 слов даёт 2^64-2^77 вариантов, и даже
// против одного замершего устройства перебор занимает тысячелетия. Аппаратный
// SHA-ускоритель S3 (SOC_SHA_SUPPORT_SHA256) в этой сборке не используется:
// драйвера esp_sha256_* в прекомпилированных библиотеках нет, а его включение
// требует пересборки ESP-IDF из исходников. Если итераций станет мало, миграция
// сводится к пересчёту KDF поверх существующего PMV1.
constexpr uint32_t kPbkdf2Iters = 30000;
constexpr size_t kMinPassChars = 12;
// Верхняя граница длины пароля. Держится в памяти во время опроса слотов
// заголовков: каждый слот проверяется своим ключом, а ключ выводится из соли
// в самом слоте, поэтому пароль приходится помнить между проверками.
constexpr size_t kMaxPassChars = 256;
constexpr uint32_t kPbkdf2SaltLen = 16;
constexpr size_t kKdfParamsLen = 4 + 4 + 1 + kPbkdf2SaltLen;

// Формат мастер-пароля, который устройство генерирует само при первом запуске.
// Пользователь его не выбирает и не вводит — он переписывает с экрана один раз.
//
// 6 слов из include/wordlist.h по 12 бит каждое плюс 2 десятичные цифры:
// 6*12 + log2(100) = 78.6 бита. Цифры добирают неполный байт: одни шесть слов
// дают ровно 2^72 вариантов, а 10 не кратно 2^n, поэтому одной цифры мало.
constexpr size_t kMasterWords = 6;
constexpr size_t kMasterDigits = 2;
constexpr size_t kMasterWordBytes = 5;  // == pm::wordlist::kWordBytes
// 6 слов по 5 букв (30) + дефисы + 2 цифры.
//
// Дефисов НЕ kMasterWords - 1, а kMasterWords: пять разделяют слова, и ещё один
// стоит перед блоком цифр ("abcde-fghij-...-vwxyz-42"). Первая версия формулы
// учитывала только пять и давала 37 при фактических 38. Буфер пароля брался по
// этой формуле, то есть был на байт короче записи, и первый же прогон гейтов
// упал с "Stack smashing protect failure" в generatePassword() — ровно тот класс
// ошибок, где static_assert на число не помогает и нужна сверка с генератором.
constexpr size_t kMasterPasswordChars =
    kMasterWords * kMasterWordBytes + kMasterWords + kMasterDigits;

static_assert(kMasterPasswordChars <= kMaxPassChars,
              "мастер-пароль не влезает в kMaxPassChars");
static_assert(kMasterPasswordChars >= kMinPassChars,
              "мастер-пароль короче kMinPassChars");
static_assert(kMasterPasswordChars == 38,
              "пересчитай формулу длины мастер-пароля");

// Ёмкость vault. Раздел 512 КБ (partitions.csv).
//
// Раскладка раздела (смещения кратны 4096 — размеру сектора SPI flash, иначе
// erase не проходит):
//   [0,      4096)  слот заголовка A
//   [4096,   8192)  слот заголовка B
//   [8192,   ...)   область 0 журнала
//   [...]           область 1 журнала
//
// ПОЧЕМУ ДВА СЛОТА ЗАГОЛОВКА. Заголовок содержит изменяемые поля: usedBytes,
// entryCount, liveBytes. Они меняются при каждом сохранении. SPI flash умеет
// только переход 1 -> 0, поэтому перезапись заголовка по месту не работает:
// запись, поднимающая бит (нужна, например, при переходе usedBytes с 0x1000 на
// 0x1068), молча теряется, и после перезагрузки хранилище выглядит пустым. Это
// не теоретическая проблема — на стенде заголовок так и не обновлялся, и все
// записанные записи исчезали.
//
// Решение — два слота, переключаемые по номеру поколения. Запись идёт в слот
// (generation & 1); слот стирается перед записью, а противоположный слот с
// предыдущим поколением остаётся нетронутым и служит резервной копией. При
// загрузке берётся слот с бОльшим поколением из двух, чей тег сошёлся, так что
// оборот записи заголовка не может оставить хранилище без заголовка вовсе.
constexpr size_t kVaultPartitionBytes = 512 * 1024;
// Заголовок занимает ровно одну страницу SPI flash (256 Б) при смещении,
// кратном сектору. Так он записывается одной page program, а после него остаётся
// место под маркер завершения записи: тег аутентификации не может быть последним
// байтом, иначе его невозможно отличить от недописанного (см. kHdrCommit в
// src/vault.cpp).
constexpr size_t kVaultHeaderBytes = 256;
constexpr size_t kFlashSectorBytes = 4096;
// Слоты заголовков. Каждый занимает свой сектор: запись в слот требует erase.
constexpr size_t kVaultHeaderSlotBytes = kFlashSectorBytes;
constexpr size_t kVaultHeaderSlots = 2;
// Области журнала начинаются после обоих слотов заголовков.
constexpr size_t kVaultRegion0Offset = kVaultHeaderSlotBytes * kVaultHeaderSlots;
constexpr size_t kVaultRegionBytes =
    ((kVaultPartitionBytes - kVaultRegion0Offset) / 2 / kFlashSectorBytes) *
    kFlashSectorBytes;
// Компакция при 50% области: активная область втрое больше живых данных, так
// что места хватает в худшем случае — 192 КБ данных плюс накладные на
// каждую из 1000 записей это ~232 КБ при доступных 252 КБ.
constexpr size_t kVaultCompactTriggerBytes = kVaultRegionBytes / 2;

// Жёсткий байтовый бюджет живых данных. Проверяется при каждом сохранении
// вместе со счётчиком и длиной записи; превышение отвергает запись с
// внятной ошибкой, а не приводит к тихой порче.
constexpr size_t kVaultLiveBudgetBytes = 192 * 1024;

// Три независимых инварианта ёмкости. 1000 записей по 1280 Б не помещаются
// в 192 КБ: это 1000 записей со средней <= 176 Б, а 1280 Б — потолок для
// отдельных крупных записей. Потолок payload (sizeof(Entry) - id) проверяется
// static_assert'ом в include/vault.h.
constexpr size_t kMaxEntryLen = 1280;
constexpr uint32_t kMaxEntries = 1000;
constexpr uint8_t kPasswordLenMin = 8;
constexpr uint8_t kPasswordLenMax = 128;
constexpr char kPasswordAlphabet[] =
    "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*()-_=+[]{}";

// Ключевой файл. На устройстве НЕ хранится: клиент присылает его (base64)
// при unlock/provision/rekey, KDF склеивает его SHA-256 с паролем, буфер
// стирается после вывода ключа. Флаг presence — kFlagKeyfile (заголовок).
constexpr size_t kKeyFileMaxBytes = 4096;

// TOTP (RFC 6238). Секрет хранится в Entry::totp как base32-строка; алгоритм
// фиксирован (SHA1, 6 цифр, 30 с) — параметры в otpauth URI не сохраняются,
// потому что полный URI не влезает в kTotpSecretMax.
constexpr size_t kTotpSecretMax = 64;
constexpr size_t kTotpDigits = 6;
constexpr uint32_t kTotpPeriodSec = 30;

// Число импортируемых записей в одном запросе POST /api/import. Тело запроса
// ограничено kHttpMaxBody (8 КБ), а запись в JSON с экранированием дорожает
// до ~1.1 КБ — 4 записи укладываются с запасом.
constexpr size_t kImportBatchEntries = 4;

static_assert(kVaultRegion0Offset + 2 * kVaultRegionBytes == kVaultPartitionBytes,
              "области журнала не покрывают раздел");
static_assert(kVaultRegionBytes % kFlashSectorBytes == 0,
              "область журнала не кратна сектору");
static_assert(kVaultCompactTriggerBytes < kVaultRegionBytes,
              "триггер компакции вне области");
static_assert(kVaultLiveBudgetBytes + kMaxEntryLen + 64 <= kVaultRegionBytes,
              "бюджет живых данных не оставляет места под компакцию");
static_assert(kKeyFileMaxBytes <= 4096, "ключевой файл больше страницы флеша");

// Каждый раздел монтируется на собственный базовый путь: корень "/" занят
// (esp_vfs_register("/") -> ESP_ERR_INVALID_STATE).
// Путь к файлу передаётся ОТДЕЛЬНО от базы, с ведущим слэшем: VFS требует
// абсолютный путь, а esp_littlefs префиксует базой только пути, которые её не
// содержат. И "/index.html" -> ок, и "index.html" -> "does not start with /",
// и "/web/index.html" -> ищет "/web/web/index.html".
constexpr char kFsVault[] = "vault";
constexpr char kFsWeb[] = "web";
constexpr char kFsVaultBase[] = "/vault";
constexpr char kFsWebBase[] = "/web";
constexpr char kVaultName[] = "/vault.bin";
constexpr char kWebIndexName[] = "/index.html";

// Предел длины нормализованного пути внутри web. 256 с запасом хватает на
// вложенные статики будущего SPA (assets/имя-хэша.js); при переполнении путь
// отвергается целиком, а не обрезается, — обрезанный путь отдал бы другой файл.
constexpr size_t kWebPathMax = 256;

}  // namespace config
}  // namespace pm
