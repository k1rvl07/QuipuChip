// Формат PMV1 — плоский шифротекст-блоб в разделе `vault` (512 КБ), доступ
// напрямую через esp_partition_*, без LittleFS.
//
// Раскладка (смещения от начала раздела):
//   0x00  заголовок 128 Б
//   0x50  dataStart — смещение первой записи текущего поколения
//   дальше записи переменной длины до usedBytes
//
// Формат записи (всё, кроме nonce/tag, зашифровано AES-256-GCM):
//   u32 id | u16 len | u8[12] nonce | u8[16] tag | u8[len] ciphertext
//   plaintext = поля Entry, каждое с '\0'; len = их суммарная длина
//   id с битом 0x80000000 — надгробная запись (удаление), len = 0
//
// GCM-nonce = 4 б поколения + 8 б смещения записи. Смещение строго растёт, а
// компакция увеличивает поколение, поэтому пара (поколение, смещение) не
// повторяется за всю жизнь хранилища. Прежний вариант требовал 8 б поколения
// плюс 4 б номера записи в тех же 12 байтах — диапазоны перекрывались, и индекс
// затирал половину поколения.
//
// AAD = заголовок с обнулёнными счётчиками, флагами и тегом проверки. Версия,
// поколение, итерации и обе соли входят в AAD, поэтому их подмена ломает
// аутентификацию. Счётчики исключены: они меняются при каждом сохранении, а при
// загрузке пересчитываются по записям и не берутся из заголовка.
//
// Проверка пароля: заголовок хранит GCM-тег шифротекста константы. Отдельной
// записи-сентинела нет — он занимал первую запись журнала, из-за чего счётчики
// не сходились с числом живых записей. Проверка сводится к пересчёту тега и
// сравнению, шифротекст для этого не нужен.
//
// Стирание. esp_partition_write пишет только по стёртой памяти. Записи журнала
// всегда пишутся в ещё не тронутую часть активной области, поэтому erase для них
// не нужен. Заголовок же содержит изменяемые поля и перезаписывается при каждом
// сохранении, поэтому пишется в один из ДВУХ слотов: слот стирается, в него
// кладётся новый заголовок, а второй слот с предыдущим поколением остаётся
// целым. При загрузке выбирается слот с бОльшим поколением, чей тег сошёлся.
//
// Компакция без потери данных при обрыве. Раздел поделён на две равные области
// (config::kVaultRegionBytes), активна одна. Компакция стирает НЕактивную область,
// пишет в неё только живые записи и одним изменением заголовка dataStart
// переключает активную. Если питание пропало до записи заголовка, активна
// прежняя область целиком и ничего не потеряно: незавершённая область не
// выглядит валидной ни для одного заголовка. Если пропало после переключения,
// новая область уже целиком записана. Старая область стирается при следующей
// компакции, а не сразу — это позволяет не терять данные и в этом случае тоже.
//
// Ключевой файл. Пароль и SHA-256 ключевого файла склеиваются в единый
// материал KDF (g_password/g_passwordLen), поэтому вывод ключа одинаков
// независимо от того, откуда пришли байты, а формат заголовка не изменился:
// без файла буфер и длина в точности равны строке пароля, и старые
// хранилища открываются как раньше. Наличие файла отражено флагом
// kFlagKeyfile в заголовке — он нужен UI (keyFileRequired()), а сам по себе
// не защищает: без самого файла ключ не выйдет, и тег не сойдётся.


#include "vault.h"

#include <esp_heap_caps.h>
#include <esp_partition.h>
#include <esp_random.h>
#include <esp_system.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#include <cstring>

#include "crypto.h"
#include "device_factor.h"
#include "logger.h"

namespace pm {
namespace vault {
namespace {

// Смещения полей заголовка.
constexpr size_t kHdrMagic = 0x00;
constexpr size_t kHdrVersion = 0x04;
constexpr size_t kHdrGeneration = 0x08;  // u32
constexpr size_t kHdrEntryCount = 0x0C;   // u32
constexpr size_t kHdrLiveBytes = 0x10;    // u32
constexpr size_t kHdrUsedBytes = 0x14;    // u32
constexpr size_t kHdrFlags = 0x18;        // u32
constexpr size_t kHdrIters = 0x1C;        // u32
constexpr size_t kHdrSaltPw = 0x20;       // u8[kPbkdf2SaltLen]
constexpr size_t kHdrSaltDev = 0x30;      // u8[kPbkdf2SaltLen]
// Проверка завершённости записи заголовка обязана отличать обрыв от подмены.
// Без неё «новый слот не прошёл проверку» и «новый слот записан наполовину»
// выглядят одинаково, и begin() откатывался бы на предыдущий слот при любой
// порче — то есть тихо отдавал бы устаревшее состояние вместо отказа. На стенде
// это и происходило: подмена байта в заголовке приводила к потере последней
// записи.
//
// Решение — commit-маркер, а не «тег не пустой». Слот стирается и заполняется по
// возрастанию адреса, поэтому маркер, лежащий ПОСЛЕ тега, пишется последним.
// Если маркер на месте, тег гарантированно дописан целиком, и его можно
// проверять честно. Если маркера нет, запись оборвалась, и откат на резервный
// слот уместен.
//
// Раньше тег сам был последним полем, и «все байты тега равны 0xFF» считалось
// признаком обрыва. Это неверно: при обрыве питания часть тега успевает
// записаться, маркер остаётся 0xFF, а слот ошибочно трактуется как подделка.
// Пользователь терял доступ к собственным паролям после обычного обесточивания
// во время сохранения.
constexpr size_t kCommitBytes = 4;
constexpr uint32_t kCommitMagic = 0x54494D43u;  // 'CMIT' в порядке записи байтов

// Тег идёт предпоследним, за ним маркер завершения. Смещения заданы через
// размер заголовка, а не константами: при жёстко зашитом смещении тег однажды
// вышел за пределы буфера на 8 байт, и buildAad ронял canary стека прямо во
// время selftest.
constexpr size_t kHdrCheck = config::kVaultHeaderBytes - kCommitBytes - crypto::kGcmTagLen;
constexpr size_t kHdrCommit = config::kVaultHeaderBytes - kCommitBytes;
// Заголовок копируется и обнуляется целиком в буферах размером
// kVaultHeaderBytes, поэтому любое поле за его пределами — переполнение буфера.
// Проверяем на этапе компиляции: ошибка смещения тега уже обрушивала canary
// стека прямо во время selftest.
static_assert(kHdrCheck + crypto::kGcmTagLen + kCommitBytes == config::kVaultHeaderBytes,
              "header tag and commit marker must end exactly at the end of the header");

constexpr size_t kHdrDataStart = 0x50;    // u32
// Монотонный номер записи заголовка (u32). Растёт на КАЖДОЕ сохранение, а не
// только на компакцию, и служит двум целям: выбирает, в какой слот писать
// (слот = seq & 1), и определяет, какой из двух слотов свежее при загрузке.
// Поколение для выбора не годится — оно меняется только при компакции, так что
// оба слота несли бы одно поколение, и свежесть было бы не различить.
//
// Поле НЕ входит в AAD: иначе первая же ротация слотов сломала бы теги ранее
// записанных записей. Подделка seq ничего не даёт — при загрузке побеждает слот
// с наибольшим seq, чей тег сошёлся, а счётчики сверяются с пересчитанными по
// журналу, так что поднятый seq лишь указывает на более старые данные, что
// безопасно.
constexpr size_t kHdrSeq = 0x54;        // u32
static_assert(kHdrSeq + 4 <= kHdrCheck, "seq must not overlap the header tag");

// Слоты заголовков. Смещения совпадают с началом секторов SPI flash, поэтому
// erase слота не задевает данные журнала.
constexpr size_t kHdrSlot0 = 0;
constexpr size_t kHdrSlot1 = config::kVaultHeaderSlotBytes;

constexpr uint32_t kFlagProvisioned = 1u << 0;
constexpr uint32_t kFlagCompacted = 1u << 1;
// Хранилище открыто/провижинено с ключевым файлом. Входит в flags, то есть НЕ
// в AAD (flags обнуляются в buildAad) — подделать его можно, но это меняет
// лишь подсказку UI: без самого файла ключ не выйдет, и тег не сойдётся.
constexpr uint32_t kFlagKeyfile = 1u << 2;

constexpr size_t kRecFixed = 4 + 2 + crypto::kGcmIvLen + crypto::kGcmTagLen;  // 34
constexpr uint8_t kSentinel[] = "PMV1-OK";
constexpr uint32_t kTombstoneBit = 0x80000000u;

// Смещение слота заголовка по его номеру: слот 0 по смещению 0, слот 1 — по
// смещению второго сектора. Запись идёт в слот, отличный от предыдущего, поэтому
// новый заголовок никогда не стирает единственную актуальную копию.
inline size_t headerSlotOffset(uint32_t slot) {
  return (slot & 1u) ? kHdrSlot1 : kHdrSlot0;
}

// Границы областей. Область 0 — [kVaultRegion0Offset, +Region), область 1 —
// [+Region, +2*Region). Активную задаёт заголовок через dataStart. Смещения и
// размеры кратны сектору SPI flash, иначе erase не прошёл бы.
inline size_t regionStart(int region) {
  return config::kVaultRegion0Offset +
         static_cast<size_t>(region) * config::kVaultRegionBytes;
}

struct Index {
  uint32_t id;
  size_t offset;
  uint16_t len;
};

Index g_index[config::kMaxEntries];
// Вторая таблица нужна на время компакции: g_index перезаполняется по мере
// записи, а читать старые смещения при этом всё ещё требуется. Копия в PSRAM
// стоит 16 КБ постоянно, зато не кладёт 16 КБ на стек задачи.
Index g_scratch[config::kMaxEntries];
uint32_t g_live = 0;
size_t g_livePayload = 0;

const esp_partition_t* g_part = nullptr;
bool g_ready = false;
uint8_t g_key[crypto::kAesKeyLen] = {};
uint8_t g_saltPw[config::kPbkdf2SaltLen] = {};
uint8_t g_saltDev[config::kPbkdf2SaltLen] = {};
uint8_t g_hdr[config::kVaultHeaderBytes] = {};

uint32_t g_generation = 1;
// Итерации PBKDF2, с которыми открыт текущий vault. При создании берутся из
// config, при открытии читаются из заголовка и больше не перезаписываются, пока
// хранилище живо.
uint32_t g_iters = config::kPbkdf2Iters;
size_t g_dataStart = config::kVaultRegion0Offset;
size_t g_usedEnd = config::kVaultRegion0Offset;  // абсолютное смещение конца журнала
int g_region = 0;                              // активная область 0 или 1
// Номер записи заголовка. Растёт при каждом сохранении; младший бит выбирает
// слот, поэтому предыдущая копия заголовка остаётся нетронутой резервной.
uint32_t g_hdrSeq = 0;
// Материал KDF: байты пароля и, при наличии ключевого файла, его SHA-256 (не
// NUL-терминирован, длина в g_passwordLen). В begin() нужен только на время
// опроса обоих слотов заголовков: каждый проверяется своим ключом, а ключ
// выводится из соли в самом слоте; clear()/rekey() собирают в этот же буфер
// материал нового пароля. Везде буфер стирается сразу после вывода ключа
// (PasswordGuard, wipe в clear/rekey). Без ключевого файла буфер и длина в
// точности равны строке пароля — так открывают все хранилища, созданные без
// файловой поддержки.
char g_password[config::kMaxPassChars + 32] = {};
size_t g_passwordLen = 0;
// Был ли ключевой файл при текущем открытии/провижининге — попадает в флаги
// заголовка. Сам файл здесь не хранится (и вообще нигде не хранится).
bool g_keyFileFlag = false;
uint32_t g_nextId = 1;
bool g_compactedOnce = false;

inline void put32(uint8_t* p, uint32_t v) {
  p[0] = static_cast<uint8_t>(v);
  p[1] = static_cast<uint8_t>(v >> 8);
  p[2] = static_cast<uint8_t>(v >> 16);
  p[3] = static_cast<uint8_t>(v >> 24);
}

inline void put16(uint8_t* p, uint16_t v) {
  p[0] = static_cast<uint8_t>(v);
  p[1] = static_cast<uint8_t>(v >> 8);
}

inline uint32_t get32(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

inline uint16_t get16(const uint8_t* p) {
  return static_cast<uint16_t>(static_cast<uint16_t>(p[0]) |
                               static_cast<uint16_t>(p[1]) << 8);
}

// AAD для тега проверки заголовка и для тегов записей. Счётчики, флаги и сам
// check-тег обнуляются, и это не упрощение, а требование: записи проверяются по
// ТЕКУЩЕМУ заголовку, поэтому любое поле, меняющееся при каждой записи
// (entryCount, liveBytes, usedBytes), обязано выпадать из AAD. Иначе добавление
// одной записи ломало бы теги всех предыдущих, и хранилище перестало бы
// открываться после первой же записи. Целостность счётчиков обеспечивается тем,
// что begin() пересчитывает их при сканировании и отвергает расхождение, а
// целостность поколения, солей, итераций и dataStart — тем, что они в AAD есть.
void buildAad(const uint8_t* hdr, uint8_t* aad) {
  std::memcpy(aad, hdr, config::kVaultHeaderBytes);
  std::memset(aad + kHdrEntryCount, 0, 4 + 4 + 4);  // entryCount, liveBytes, usedBytes
  std::memset(aad + kHdrFlags, 0, 4);
  std::memset(aad + kHdrCheck, 0, crypto::kGcmTagLen);
  // Маркер завершения тоже исключён из AAD: он пишется после вычисления тега и
  // на момент подписи в буфере ещё не выставлен.
  std::memset(aad + kHdrCommit, 0, kCommitBytes);
  // seq обнуляется по той же причине, что и счётчики: он меняется при каждом
  // сохранении, и если оставить его в AAD, тег любой ранее записанной записи
  // перестал бы сходиться после первой же записи.
  std::memset(aad + kHdrSeq, 0, 4);
}

void nonceFor(uint8_t nonce[crypto::kGcmIvLen], uint32_t generation, size_t offset) {
  std::memset(nonce, 0, crypto::kGcmIvLen);
  put32(nonce, generation);
  for (int i = 0; i < 8; ++i) {
    nonce[4 + i] = static_cast<uint8_t>(static_cast<uint64_t>(offset) >> ((7 - i) * 8));
  }
}

bool readRange(size_t off, void* buf, size_t len) {
  return g_part && esp_partition_read(g_part, off, buf, len) == ESP_OK;
}

bool writeRange(size_t off, const void* buf, size_t len) {
  return g_part && esp_partition_write(g_part, off, buf, len) == ESP_OK;
}

int findIndex(uint32_t id) {
  for (uint32_t i = 0; i < g_live; ++i) {
    if (g_index[i].id == id) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

void removeAt(uint32_t slot) {
  if (g_livePayload >= g_index[slot].len) {
    g_livePayload -= g_index[slot].len;
  }
  if (slot + 1 < g_live) {
    g_index[slot] = g_index[g_live - 1];
  }
  --g_live;
}

// Поля лежат в payload подряд, каждое NUL-терминировано: title, login,
// password, url, note, tags, totp. Порядок фиксирован, NUL — разделитель.
size_t serialize(const Entry& e, uint8_t* out, size_t outLen) {
  const char* fields[] = {e.title, e.login, e.password, e.url, e.note, e.tags,
                          e.totp};
  size_t n = 0;
  for (const char* f : fields) {
    const size_t len = std::strlen(f) + 1;
    if (n + len > outLen) {
      return 0;
    }
    std::memcpy(out + n, f, len);
    n += len;
  }
  return n;
}

// Читает поля до конца payload. Записи, созданные до v0.2.0, несут пять
// полей: pos доходит до len, остановка по `pos >= len`, и tags/totp остаются
// пустыми из-за memset. Обратное (новая запись на старой прошивке) откатом не
// поддерживается — старый scanLog вернёт Tampered, а не порчу данных.
void deserialize(uint32_t id, const uint8_t* in, size_t len, Entry& e) {
  std::memset(&e, 0, sizeof(e));
  e.id = id;
  char* fields[] = {e.title, e.login, e.password, e.url, e.note, e.tags,
                    e.totp};
  const size_t caps[] = {sizeof(e.title), sizeof(e.login), sizeof(e.password),
                         sizeof(e.url),    sizeof(e.note),   sizeof(e.tags),
                         sizeof(e.totp)};
  size_t pos = 0;
  for (size_t f = 0; f < 7; ++f) {
    if (pos >= len) {
      break;
    }
    size_t copy = 0;
    const size_t avail = len - pos;
    while (copy < avail && copy + 1 < caps[f] && in[pos + copy] != '\0') {
      ++copy;
    }
    std::memcpy(fields[f], in + pos, copy);
    fields[f][copy] = '\0';
    pos += copy;
    if (pos < len && in[pos] == '\0') {
      ++pos;
    }
  }
}

// Кладёт запись в индекс: обновляет существующую, снимает надгробную, иначе
// добавляет. Возвращает false при переполнении kMaxEntries.
bool applyToIndex(uint32_t rawId, size_t offset, uint16_t len) {
  const uint32_t id = rawId & ~kTombstoneBit;
  const int at = findIndex(id);
  if (rawId & kTombstoneBit) {
    if (at >= 0) {
      removeAt(static_cast<uint32_t>(at));
    }
    return true;
  }
  if (at >= 0) {
    g_livePayload -= g_index[at].len;
    g_livePayload += len;
    g_index[at].offset = offset;
    g_index[at].len = len;
    return true;
  }
  if (g_live >= config::kMaxEntries) {
    return false;
  }
  g_index[g_live].id = id;
  g_index[g_live].offset = offset;
  g_index[g_live].len = len;
  ++g_live;
  g_livePayload += len;
  return true;
}

// Шифрует и пишет запись по смещению off. payload может быть пустым (надгробная).
VaultError writeRecordAt(size_t off, uint32_t rawId, const uint8_t* payload,
                         size_t len) {
  // Надгробная запись (len == 0) всё равно несёт шифротекст-маркер длиной 1,
  // поэтому под неё нужно на байт больше, чем kRecFixed + len. Иначе
  // шифрование маркера писало бы за пределы выделенного буфера.
  const size_t total = kRecFixed + (len ? len : 1);
  // Запись обязана целиком поместиться в АКТИВНУЮ область. Проверять границу
  // раздела было бы слишком слабо: запись ушла бы в неактивную область и
  // испортила её содержимое до следующей компакции.
  if (off < g_dataStart || off + total > regionStart(g_region + 1)) {
    return VaultError::NoSpace;
  }
  uint8_t* rec = static_cast<uint8_t*>(heap_caps_malloc(total, MALLOC_CAP_SPIRAM));
  if (!rec) {
    return VaultError::NoSpace;
  }
  std::memset(rec, 0, kRecFixed);
  put32(rec, rawId);
  put16(rec + 4, static_cast<uint16_t>(len));
  uint8_t* nonce = rec + 6;
  nonceFor(nonce, g_generation, off);

  uint8_t aad[config::kVaultHeaderBytes];
  buildAad(g_hdr, aad);
  size_t ctLen = 0;
  int rc = static_cast<int>(crypto::CipherError::Ok);
  if (len > 0) {
    rc = crypto::aesGcmEncrypt(g_key, nonce, aad, sizeof(aad), payload, len,
                               rec + kRecFixed, &ctLen, rec + 6 + crypto::kGcmIvLen);
  } else {
    // Надгробная запись: полезной нагрузки нет, но маркер шифруется и
    // аутентифицируется вместе с AAD, чтобы подмена байтов в записи ломалась
    // так же, как и в обычной.
    rc = crypto::aesGcmEncrypt(g_key, nonce, aad, sizeof(aad), kSentinel, 1,
                               rec + kRecFixed, &ctLen, rec + 6 + crypto::kGcmIvLen);
  }
  if (rc != static_cast<int>(crypto::CipherError::Ok)) {
    heap_caps_free(rec);
    return VaultError::Crypto;
  }
  const bool ok = writeRange(off, rec, total);
  heap_caps_free(rec);
  return ok ? VaultError::Ok : VaultError::Io;
}

// Собирает заголовок в g_hdr из текущего состояния. Итерации берутся из g_iters,
// а не из config: иначе смена глобальной константы KDF молча переписала бы их в
// уже существующем хранилище, и следующее открытие посчитало бы другой ключ.
void buildHdr() {
  std::memcpy(g_hdr + kHdrMagic, config::kVaultMagic, 4);
  put32(g_hdr + kHdrVersion, 1);
  put32(g_hdr + kHdrGeneration, g_generation);
  put32(g_hdr + kHdrEntryCount, g_live);
  put32(g_hdr + kHdrLiveBytes, static_cast<uint32_t>(g_livePayload));
  put32(g_hdr + kHdrUsedBytes, static_cast<uint32_t>(g_usedEnd));
  put32(g_hdr + kHdrFlags,
        kFlagProvisioned | (g_compactedOnce ? kFlagCompacted : 0u) |
            (g_keyFileFlag ? kFlagKeyfile : 0u));
  put32(g_hdr + kHdrIters, g_iters);
  std::memcpy(g_hdr + kHdrSaltPw, g_saltPw, sizeof(g_saltPw));
  std::memcpy(g_hdr + kHdrSaltDev, g_saltDev, sizeof(g_saltDev));
  put32(g_hdr + kHdrDataStart, static_cast<uint32_t>(g_dataStart));
  put32(g_hdr + kHdrSeq, g_hdrSeq);
}

// Пишет собранный заголовок в слот, соответствующий текущему поколению, и
// пересчитывает тег проверки.
//
// Слот стирается целиком: заголовок содержит изменяемые поля (usedBytes,
// entryCount, liveBytes), а flash не умеет 0 -> 1. Стирание бьёт только по слоту
// поколения, противоположный слот с предыдущим поколением остаётся резервной
// копией, поэтому прерывание записи не оставляет хранилище без заголовка.
bool flushHeader() {
  buildHdr();
  uint8_t aad[config::kVaultHeaderBytes];
  buildAad(g_hdr, aad);
  uint8_t nonce[crypto::kGcmIvLen];
  nonceFor(nonce, g_generation, 0);
  uint8_t ct[sizeof(kSentinel)];
  size_t ctLen = 0;
  const int enc = crypto::aesGcmEncrypt(g_key, nonce, aad, sizeof(aad), kSentinel,
                                        sizeof(kSentinel) - 1, ct, &ctLen,
                                        g_hdr + kHdrCheck);
  crypto::wipe(ct, sizeof(ct));
  if (enc != static_cast<int>(crypto::CipherError::Ok)) {
    return false;
  }
  const size_t slot = headerSlotOffset(g_hdrSeq);
  if (esp_partition_erase_range(g_part, slot, config::kVaultHeaderSlotBytes) != ESP_OK) {
    return false;
  }
  // Маркер ставится в буфер ПОСЛЕ вычисления тега и лежит за ним по адресу,
  // поэтому при восходящей записи он физически дописывается последним. Запись
  // идёт одним вызовом на всю страницу заголовка.
  put32(g_hdr + kHdrCommit, kCommitMagic);
  if (!writeRange(slot, g_hdr, config::kVaultHeaderBytes)) {
    return false;
  }
  // Следующий заголовок пойдёт в другой слот, чтобы только что записанная копия
  // осталась резервной на случай обрыва питания.
  g_hdrSeq += 1;
  return true;
}

// Стирает g_password на любом пути выхода из begin(), а не только на успешном.
// Guard, а не свободная функция: после копирования пароля путей возврата
// тринадцать, и ручной wipe на каждом забывается первым же добавленным.
class PasswordGuard {
 public:
  PasswordGuard() = default;
  ~PasswordGuard() {
    crypto::wipe(g_password, sizeof(g_password));
  }
  PasswordGuard(const PasswordGuard&) = delete;
  PasswordGuard& operator=(const PasswordGuard&) = delete;
};

// Мьютекс хранилища.
//
// С появлением задачи авторизации PBKDF2 уехал из setup() в отдельную задачу, и
// хранилище впервые стало доступно двум задачам одновременно: httpd читает
// состояние, авторизация его меняет. ВСЕ глобалки выше — g_key, g_index, g_live,
// g_usedEnd, g_hdr, g_hdrSeq — общие, и гонка на них не даёт «редкий баг», а
// порчу заголовка: счётчики не входят в AAD, поэтому рассогласованные значения
// g_live/g_usedEnd будут подписаны как валидные и переживут перезагрузку.
//
// Мьютекс рекурсивный, потому что add() и remove() вызывают compact(), а та
// тоже трогает то же состояние. Инициализируется лениво: install() в setup()
// идёт после создания задач, но публичные функции vault не имеют Initialize
// (), а вызываться могут раньше.
SemaphoreHandle_t g_mutex = nullptr;

void ensureMutex() {
  if (g_mutex == nullptr) {
    g_mutex = xSemaphoreCreateRecursiveMutex();
  }
}

// Мьютекс берётся публичными функциями и только их. Внутренние помощники
// (compact, scanLog, flushHeader, readRecord) предполагают, что мьютекс уже
// держит вызывающий: повторный take() здесь был бы не нужен, а рекурсия
// заставила бы забыть, где граница вложенности.
struct Guard {
  Guard() {
    ensureMutex();
    if (g_mutex) {
      xSemaphoreTakeRecursive(g_mutex, portMAX_DELAY);
    }
  }
  ~Guard() {
    if (g_mutex) {
      xSemaphoreGiveRecursive(g_mutex);
    }
  }
  Guard(const Guard&) = delete;
  Guard& operator=(const Guard&) = delete;
};

// Снимок состояния для читателей без мьютекса. Пишется всегда под мьютексом и
// всегда в критической секции, читается так же. Состояние меняется в трёх точках
// (begin, close, add/remove) — все проходят через Guard.
//
// Отдельный spinlock, а не сам g_mutex: критическая секция тут держится доли
// микросекунды, а g_mutex на неё ждать нельзя — критическая секция не должна
// блокироваться.
Snapshot g_snap = {State::Unprovisioned, 0, 0, 0};
portMUX_TYPE g_snapMux = portMUX_INITIALIZER_UNLOCKED;

// Есть ли хранилище на флеше. Не выводится из счётчика: после close() записей
// в RAM нет, а хранилище на флеше осталось и должно читаться как Locked.
bool g_provisioned = false;

// Ищет раздел vault один раз и кэширует указатель.
//
// Отдельная функция, потому что provisioned() обязан работать ДО первого
// begin(). На старте устройства vault никто не открывает: setup() поднимает web,
// USB, мост и HTTP-сервер, и первый вопрос о состоянии приходит уже из
// HTTP-обработчика. Без этого provisioned() отвечал бы false на заполненном
// устройстве, UI предложил бы первичную настройку, и она стёрла бы данные.
void ensurePartition() {
  if (g_part) {
    return;
  }
  g_part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
                                   ESP_PARTITION_SUBTYPE_ANY, config::kFsVault);
  if (g_part && g_part->size < config::kVaultPartitionBytes) {
    g_part = nullptr;
  }
}

// Признак provisioned читается с флеша, а не из памяти, и истинен, если ЛИБО
// слот заголовка его содержит: оборванная запись свежего слота не должна
// превращать заполненное хранилище в «не настроено».
//
// Тег аутентификации здесь НЕ проверяется и это осознанно: вопрос «настроено ли
// устройство» должен решаться без пароля, а ответ по неаутентифицированному
// флагу подделывается дампом флеша. Подделка меняет только то, какое меню
// покажет UI, — содержимое всё равно не расшифровать без ключа.
bool probeProvisioned() {
  ensurePartition();
  if (!g_part) {
    return false;
  }
  uint8_t raw[config::kVaultHeaderBytes];
  for (size_t slot = 0; slot < 2; ++slot) {
    const size_t off = slot * config::kFlashSectorBytes;
    if (!readRange(off, raw, sizeof(raw))) {
      continue;
    }
    if (std::memcmp(raw + kHdrMagic, config::kVaultMagic, 4) == 0 &&
        (get32(raw + kHdrFlags) & kFlagProvisioned) != 0) {
      return true;
    }
  }
  return false;
}

// Требует ли вход ключевой файл. Читается заголовок с наибольшим seq среди
// полностью записанных (маркер kCommitMagic дописывается последним, поэтому
// у оборванной записи его нет) — ровно тот слот, который begin() выберет по
// тегу и из которого он сам переносит флаг в g_keyFileFlag.
//
// Прежний обход «любого из двух слотов» после rekey с файла на пароль без
// файла отдавал true: оставшийся в соседнем слоте старый заголовок — не
// актуальное состояние. UI показывал поле ключевого файла, которого вход уже
// не требует: пустое поле работало, а введённый по подсказке файл давал
// wrong_password. Тот же довод, что и у probeProvisioned(): без пароля
// аутентифицировать флаг нельзя, а подделка меняет лишь подсказку UI — без
// самого файла ключ не выйдет. Нужен, чтобы показать поле ключевого файла в
// форме до ввода пароля.
bool probeKeyFileFlag() {
  ensurePartition();
  if (!g_part) {
    return false;
  }
  uint8_t raw[config::kVaultHeaderBytes];
  bool found = false;
  uint32_t bestSeq = 0;
  bool bestFlag = false;
  for (size_t slot = 0; slot < 2; ++slot) {
    const size_t off = slot * config::kFlashSectorBytes;
    if (!readRange(off, raw, sizeof(raw))) {
      continue;
    }
    if (std::memcmp(raw + kHdrMagic, config::kVaultMagic, 4) != 0 ||
        get32(raw + kHdrCommit) != kCommitMagic) {
      continue;
    }
    const uint32_t seq = get32(raw + kHdrSeq);
    if (!found || seq > bestSeq) {
      found = true;
      bestSeq = seq;
      bestFlag = (get32(raw + kHdrFlags) & kFlagKeyfile) != 0;
    }
  }
  return bestFlag;
}

void publishSnapshot() {
  portENTER_CRITICAL(&g_snapMux);
  g_snap.state = g_ready ? State::Unlocked : (g_provisioned ? State::Locked
                                                             : State::Unprovisioned);
  g_snap.entryCount = g_live;
  g_snap.generation = g_generation;
  g_snap.liveBytes = g_livePayload;
  portEXIT_CRITICAL(&g_snapMux);
}

}  // namespace

const char* toString(VaultError e) {
  switch (e) {
    case VaultError::Ok:
      return "ok";
    case VaultError::NotFound:
      return "partition not found";
    case VaultError::BootStrap:
      return "not provisioned yet";
    case VaultError::WrongPassword:
      return "wrong password";
    case VaultError::Tampered:
      return "tampered";
    case VaultError::Budget:
      return "live byte budget exceeded";
    case VaultError::NoSpace:
      return "no space in vault";
    case VaultError::Serial:
      return "serialization failed";
    case VaultError::Crypto:
      return "crypto failed";
    case VaultError::Io:
      return "flash io failed";
    case VaultError::TooManyEntries:
      return "entry count limit";
    case VaultError::EntryTooLong:
      return "entry too long";
  }
  return "unknown";
}

const char* toString(State s) {
  switch (s) {
    case State::Unprovisioned:
      return "unprovisioned";
    case State::Locked:
      return "locked";
    case State::Unlocked:
      return "unlocked";
  }
  return "unknown";
}

bool initialized() {
  return g_ready;
}

uint32_t count() {
  return g_live;
}

void close() {
  const Guard guard;
  // Флеш не трогаем: close() выбрасывает материал из RAM, а не стирает записи.
  // Соли и заголовок тоже wipe — они не нужны для закрытия, а оставить их значит
  // оставить в памяти то, что нужно для следующего begin().
  crypto::wipe(g_key, sizeof(g_key));
  crypto::wipe(g_password, sizeof(g_password));
  g_passwordLen = 0;
  g_keyFileFlag = false;
  crypto::wipe(g_hdr, sizeof(g_hdr));
  crypto::wipe(g_saltPw, sizeof(g_saltPw));
  crypto::wipe(g_saltDev, sizeof(g_saltDev));
  std::memset(g_index, 0, sizeof(g_index));
  std::memset(g_scratch, 0, sizeof(g_scratch));
  g_live = 0;
  g_livePayload = 0;
  g_usedEnd = regionStart(0);
  g_dataStart = regionStart(0);
  g_region = 0;
  g_hdrSeq = 0;
  g_nextId = 1;
  g_generation = 1;
  g_iters = config::kPbkdf2Iters;
  g_compactedOnce = false;
  g_ready = false;
  publishSnapshot();
}

Snapshot snapshot() {
  Snapshot out;
  portENTER_CRITICAL(&g_snapMux);
  out = g_snap;
  portEXIT_CRITICAL(&g_snapMux);
  return out;
}

bool provisioned() {
  const Guard guard;
  return probeProvisioned();
}

bool keyFileRequired() {
  const Guard guard;
  return probeKeyFileFlag();
}

void initialize() {
  // Создание мьютекса здесь, а не лениво в ensureMutex(): ленивая инициализация
  // без защиты — гонка, когда два потока впервые входят в vault одновременно и
  // второй перезаписывает указатель уже после чужого take(). Здесь вызов один и
  // происходит до создания задач.
  const Guard guard;
  g_provisioned = probeProvisioned();
  publishSnapshot();
}

const Stats& stats() {
  // Ссылка на статику, поэтому читать результат после выхода функции нельзя:
  // под следующим вызовом он перезапишется. Читателям без блокировки —
  // snapshot(). Здесь мьютекс держим ради согласованности полей между собой.
  const Guard guard;
  static Stats s;
  s.entryCount = g_live;
  s.liveBytes = g_livePayload;
  s.usedBytes = g_usedEnd;
  s.generation = g_generation;
  s.compactedOnce = g_compactedOnce;
  return s;
}

namespace {

// Собирает материал KDF (пароль, за ним — SHA-256 ключевого файла) в buf.
// Возвращает длину в байтах или 0 при ошибке (nullptr, пароль длиннее
// kMaxPassChars, нехватка места, сбой SHA-256). Без ключевого файла результат
// в точности равен строке пароля — это обязано сохраняться, иначе старые
// хранилища перестанут открываться.
size_t buildMaterial(char* buf, size_t bufSize, const char* password,
                     const uint8_t* keyFile, size_t keyFileLen) {
  if (!buf || !password) {
    return 0;
  }
  const size_t pwLen = std::strlen(password);
  if (pwLen >= config::kMaxPassChars || pwLen + 32 > bufSize) {
    return 0;
  }
  std::memcpy(buf, password, pwLen);
  if (keyFile && keyFileLen > 0) {
    uint8_t h[32];
    if (crypto::sha256(keyFile, keyFileLen, h) !=
        static_cast<int>(crypto::CipherError::Ok)) {
      crypto::wipe(h, sizeof(h));
      return 0;
    }
    std::memcpy(buf + pwLen, h, 32);
    crypto::wipe(h, sizeof(h));
    return pwLen + 32;
  }
  return pwLen;
}

// Выводит KEK из материала KDF и device-фактора. Соль device-фактора берётся из
// заголовка, поэтому между provisioning и открытием она одна и та же.
VaultError deriveKey(const char* mat, size_t matLen, const uint8_t* saltDev,
                     uint32_t iters) {
  uint8_t fromPw[crypto::kAesKeyLen] = {};
  uint8_t term[crypto::kAesKeyLen] = {};
  const int rcPw = crypto::pbkdf2HmacSha256(mat, matLen,
                                            g_saltPw, config::kPbkdf2SaltLen, iters,
                                            fromPw);
  if (rcPw != static_cast<int>(crypto::CipherError::Ok)) {
    crypto::wipe(fromPw, sizeof(fromPw));
    return VaultError::Crypto;
  }
  // device::factor возвращает bool, а не CipherError: сравнивать его с Ok
  // (то есть с нулём) нельзя, иначе успешный расчёт true трактуется как ошибка,
  // а хранилище не открывается никогда.
  if (!device::factor(saltDev, config::kPbkdf2SaltLen, term)) {
    crypto::wipe(fromPw, sizeof(fromPw));
    crypto::wipe(term, sizeof(term));
    return VaultError::Crypto;
  }
  for (size_t i = 0; i < crypto::kAesKeyLen; ++i) {
    g_key[i] = fromPw[i] ^ term[i];
  }
  crypto::wipe(fromPw, sizeof(fromPw));
  crypto::wipe(term, sizeof(term));
  return VaultError::Ok;
}

// Проверяет, осталось ли что-то за usedEnd в неактивной части активной области.
//
// Оборванная запись оставляет за собой частично записанные байты. Формально они
// не входят в журнал, но следующая запись пойдёт ровно на usedEnd и попытается
// писать поверх них, а вспышка не умеет возвращать биты в 1. Такая запись
// молча испортилась бы: тег сошёлся бы, а запись потерялась.
//
// Сканируется не вся область, а только окно в два сектора. Этого хватает с
// запасом: оборваться может одна запись, а её максимальный размер
// kRecFixed + kMaxEntryLen + 1 = 1059 байт, то есть меньше одного сектора.
// Всё остальное за usedEnd гарантированно стёрто — либо erase-ом при
// provisioning, либо erase-ом неактивной области при компакции.
constexpr size_t kTornScanBytes = 2 * config::kFlashSectorBytes;

bool tailIsDirty() {
  if (!g_part) {
    return false;
  }
  const size_t regionEnd = regionStart(g_region + 1);
  const size_t scanEnd = g_usedEnd + kTornScanBytes;
  const size_t stop = scanEnd > regionEnd ? regionEnd : scanEnd;
  uint8_t buf[64];
  for (size_t off = g_usedEnd; off < stop; off += sizeof(buf)) {
    const size_t n = (stop - off) < sizeof(buf) ? (stop - off) : sizeof(buf);
    if (!readRange(off, buf, n)) {
      // Не прочитали — считаем хвост грязным: лишняя пересборка безопасна,
      // пропущенная привела бы к битой записи.
      return true;
    }
    for (size_t i = 0; i < n; ++i) {
      if (buf[i] != 0xFF) {
        return true;
      }
    }
  }
  return false;
}

// Что показал осмотр слота заголовка.
enum class SlotState {
  kAbsent,   // слот не записан: нет магии
  kTorn,     // магия есть, тег не записан — запись оборвалась
  kValid,    // тег сошёлся, слот пригоден
  kInvalid,  // структурно сломан: версия, итерации или поколение не читаются
  kTagMismatch,  // структура цела, но тег не подтверждается данным паролем
};

// Осматривает слот заголовка. Различение состояний существенно: kAbsent и kTorn
// допускают откат на другой слот, а kInvalid и kTagMismatch — нет. Без этого
// порча свежего заголовка молча приводила к отдаче устаревшего слота, то есть
// к тихой потере последней записи вместо отказа.
//
// kTagMismatch отделён от kInvalid не ради косметики: сломанная структура и
// чужой пароль — разные вещи, и путать их было ошибкой. Смена пароля оставляет
// в резервном слоте копию, которую старый пароль открывает, а новый слот —
// нет; при общем kInvalid это выглядело как «свежий слот порчен», и begin()
// отдавал Tampered на простой ввод старого пароля после rekey — UI показывал
// повреждение хранилища вместо неверного пароля.
SlotState probeHeaderSlot(size_t slot, uint8_t* out) {
  if (!readRange(slot, out, config::kVaultHeaderBytes)) {
    return SlotState::kAbsent;
  }
  if (std::memcmp(out + kHdrMagic, config::kVaultMagic, 4) != 0) {
    return SlotState::kAbsent;
  }
  if (get32(out + kHdrVersion) != 1) {
    return SlotState::kInvalid;
  }
  // Маркер завершения проверяется ДО тега и без всякой эвристики. Пока маркера
  // нет, запись заголовка не завершена, и слот отбрасывается в пользу резервного
  // независимо от того, что успел записаться: тег мог дописаться наполовину и
  // выглядеть «непустым», из-за чего подделка и обрыв были неразличимы.
  if (get32(out + kHdrCommit) != kCommitMagic) {
    return SlotState::kTorn;
  }
  const uint32_t iters = get32(out + kHdrIters);
  const uint32_t gen = get32(out + kHdrGeneration);
  if (iters == 0 || iters > 10000000u || gen == 0) {
    return SlotState::kInvalid;
  }
  // Соль для пароля нужна, чтобы вывести ключ, которым проверяется тег. Соль
  // устройства тоже: она входит в AAD.
  uint8_t trial[crypto::kAesKeyLen] = {};
  uint8_t fromPw[crypto::kAesKeyLen] = {};
  if (device::factor(out + kHdrSaltDev, config::kPbkdf2SaltLen, trial)) {
    const int rc = crypto::pbkdf2HmacSha256(g_password, g_passwordLen,
                                            out + kHdrSaltPw, config::kPbkdf2SaltLen,
                                            iters, fromPw);
    if (rc == static_cast<int>(crypto::CipherError::Ok)) {
      for (size_t i = 0; i < crypto::kAesKeyLen; ++i) {
        trial[i] ^= fromPw[i];
      }
    } else {
      trial[0] = 0;
      trial[1] = 0;
    }
    crypto::wipe(fromPw, sizeof(fromPw));
  } else {
    trial[0] = 0;
    trial[1] = 0;
  }
  uint8_t aad[config::kVaultHeaderBytes];
  buildAad(out, aad);
  uint8_t nonce[crypto::kGcmIvLen];
  nonceFor(nonce, gen, 0);
  // Шифротекст не читается — важен только тег, — но буфер всё равно нужен:
  // aesGcmEncrypt отклоняет nullptr и вернёт InvalidArg, из-за чего проверка
  // тега никогда бы не прошла и оба слота выглядели бы невалидными.
  uint8_t ct[sizeof(kSentinel) - 1];
  uint8_t tag[crypto::kGcmTagLen] = {};
  size_t ctLen = 0;
  const int enc = crypto::aesGcmEncrypt(trial, nonce, aad, sizeof(aad), kSentinel,
                                        sizeof(kSentinel) - 1, ct, &ctLen, tag);
  crypto::wipe(ct, sizeof(ct));
  crypto::wipe(trial, sizeof(trial));
  if (enc != static_cast<int>(crypto::CipherError::Ok)) {
    crypto::wipe(tag, sizeof(tag));
    return SlotState::kInvalid;
  }
  const bool ok = crypto::ctEqual(tag, out + kHdrCheck, crypto::kGcmTagLen);
  crypto::wipe(tag, sizeof(tag));
  return ok ? SlotState::kValid : SlotState::kTagMismatch;
}

// Пересчитывает тег проверочного шифротекста и сверяет с заголовком. Шифротекст
// нужен только как буфер для mbedtls, сам он не читается — важен только тег.
VaultError checkSentinel() {
  uint8_t aad[config::kVaultHeaderBytes];
  buildAad(g_hdr, aad);
  uint8_t nonce[crypto::kGcmIvLen];
  nonceFor(nonce, g_generation, 0);
  uint8_t ct[sizeof(kSentinel) - 1];
  uint8_t tag[crypto::kGcmTagLen] = {};
  size_t ctLen = 0;
  const int enc = crypto::aesGcmEncrypt(g_key, nonce, aad, sizeof(aad), kSentinel,
                                        sizeof(kSentinel) - 1, ct, &ctLen, tag);
  crypto::wipe(ct, sizeof(ct));
  if (enc != static_cast<int>(crypto::CipherError::Ok)) {
    return VaultError::Crypto;
  }
  const bool ok = crypto::ctEqual(tag, g_hdr + kHdrCheck, crypto::kGcmTagLen);
  crypto::wipe(tag, sizeof(tag));
  return ok ? VaultError::Ok : VaultError::WrongPassword;
}

// Проходит журнал и пересобирает индекс. Хвост за пределами usedBytes
// игнорируется: там лежит либо ничего, либо запись, записанная до обрыва.
// Опережающее объявление: begin() вызывает compact(), чтобы пересобрать журнал
// после обрыва записи. Определение compact() находится ниже по файлу, в том же
// внутреннем namespace.
VaultError compact();

VaultError scanLog() {
  g_live = 0;
  g_livePayload = 0;
  g_nextId = 1;
  size_t off = g_dataStart;
  uint8_t head[kRecFixed];
  while (off + kRecFixed <= g_usedEnd) {
    if (!readRange(off, head, kRecFixed)) {
      return VaultError::Io;
    }
    const uint32_t rawId = get32(head);
    const uint16_t len = get16(head + 4);
    const bool isTomb = (rawId & kTombstoneBit) != 0;
    if (isTomb && len != 0) {
      // У надгробной записи полезной нагрузки быть не должно: не ноль означает
      // подмену, а не штатное состояние журнала.
      return VaultError::Tampered;
    }
    if (len > config::kMaxEntryLen) {
      return VaultError::Tampered;
    }
    // Надгробная запись хранит один байт маркера, поэтому её длина на флеше на
    // байт больше len. Раньше здесь считалось kRecFixed + len, и журнал
    // рассыпался бы на первой же удалённой записи.
    const size_t bodyLen = len ? len : 1;
    const size_t total = kRecFixed + bodyLen;
    if (off + total > g_usedEnd) {
      // Запись за границей usedBytes: хвост оборван, журнал на этом кончился.
      break;
    }
    if (!isTomb && rawId == 0) {
      // id 0 недопустим: без него запись неотличима от неинициализированной
      // памяти и отличает её только наличие тега, а тег можно подделать,
      // записав запись с нулевым id самому.
      return VaultError::Tampered;
    }

    // Тег проверяем у всех записей, включая надгробные: маркер в них тоже
    // шифруется, и подмена байта должна ломать открытие так же, как и в обычной
    // записи. Иначе атакующий переписал бы id записи и получил бы подменённый
    // пароль, не сломав аутентификацию.
    uint8_t* buf = static_cast<uint8_t*>(heap_caps_malloc(bodyLen, MALLOC_CAP_SPIRAM));
    if (!buf) {
      return VaultError::NoSpace;
    }
    if (!readRange(off + kRecFixed, buf, bodyLen)) {
      heap_caps_free(buf);
      return VaultError::Io;
    }
    uint8_t aad[config::kVaultHeaderBytes];
    buildAad(g_hdr, aad);
    // Расшифровываем в отдельный буфер: полагаться на поддержку in-place у
    // mbedtls_gcm_auth_decrypt не стоит, а цена вопроса — один malloc.
    uint8_t* pt = static_cast<uint8_t*>(heap_caps_malloc(bodyLen, MALLOC_CAP_SPIRAM));
    if (!pt) {
      heap_caps_free(buf);
      return VaultError::NoSpace;
    }
    size_t ptLen = 0;
    const int dec = crypto::aesGcmDecrypt(g_key, head + 6, aad, sizeof(aad), buf, bodyLen,
                                          head + 6 + crypto::kGcmIvLen, pt, &ptLen);
    crypto::wipe(pt, bodyLen);
    heap_caps_free(pt);
    if (dec != static_cast<int>(crypto::CipherError::Ok)) {
      crypto::wipe(buf, bodyLen);
      heap_caps_free(buf);
      return VaultError::Tampered;
    }
    crypto::wipe(buf, bodyLen);
    heap_caps_free(buf);

    if (!applyToIndex(rawId, off, static_cast<uint16_t>(len))) {
      return VaultError::TooManyEntries;
    }
    if (!isTomb && (rawId & ~kTombstoneBit) >= g_nextId) {
      g_nextId = (rawId & ~kTombstoneBit) + 1;
    }
    off += total;
  }
  return VaultError::Ok;
}

}  // namespace

VaultError begin(const char* password, const uint8_t* keyFile,
                 size_t keyFileLen) {
  const Guard guard;
  g_ready = false;
  g_provisioned = false;
  publishSnapshot();
  g_live = 0;
  g_livePayload = 0;
  g_usedEnd = regionStart(0);
  g_dataStart = regionStart(0);
  g_region = 0;
  g_compactedOnce = false;
  g_generation = 1;
  g_hdrSeq = 0;
  std::memset(g_hdr, 0, sizeof(g_hdr));
  crypto::wipe(g_key, sizeof(g_key));
  // Ранние отказы ниже (нет раздела, слишком короткий пароль) выходят до
  // PasswordGuard, поэтому материал прошлой попытки стёр именно здесь.
  crypto::wipe(g_password, sizeof(g_password));
  g_passwordLen = 0;
  g_keyFileFlag = false;

  g_part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY,
                                    config::kFsVault);
  if (!g_part) {
    return VaultError::NotFound;
  }
  if (g_part->size < config::kVaultPartitionBytes) {
    return VaultError::NotFound;
  }

  // Признак provisioned читается с флеша ЗДЕСЬ, до всякой работы с паролем.
  //
  // Без этого неверный пароль оставлял снапшот в Unprovisioned: ниже стоял
  // g_provisioned = false, и до успешного открытия он больше не менялся. UI
  // после неудачной попытки показывал «устройство не настроено» и предлагал
  // первичную настройку поверх существующих данных. Для менеджера паролей это
  // путь к потере данных по неверной подсказке интерфейса.
  g_provisioned = probeProvisioned();
  publishSnapshot();

  if (!password || std::strlen(password) < config::kMinPassChars ||
      std::strlen(password) >= config::kMaxPassChars) {
    return VaultError::WrongPassword;
  }

  // Материал KDF запоминается: опрос слотов заголовков проверяет каждый своим
  // ключом, а ключ выводится из соли в самом слоте. Строка, а не указатель,
  // потому что вызывающая сторона вправе освободить свой буфер сразу после
  // вызова. Без ключевого файла это байт-в-байт строка пароля — так открывают
  // хранилища, созданные до появления файловой поддержки.
  const size_t matLen =
      buildMaterial(g_password, sizeof(g_password), password, keyFile, keyFileLen);
  if (matLen == 0) {
    crypto::wipe(g_password, sizeof(g_password));
    return VaultError::WrongPassword;
  }
  g_passwordLen = matLen;
  g_keyFileFlag = (keyFile != nullptr && keyFileLen > 0);
  const PasswordGuard pwGuard;

  uint8_t raw[config::kVaultHeaderBytes];
  if (!readRange(0, raw, sizeof(raw))) {
    return VaultError::Io;
  }

  const bool magicOk = std::memcmp(raw + kHdrMagic, config::kVaultMagic, 4) == 0;
  const bool provisioned = (get32(raw + kHdrFlags) & kFlagProvisioned) != 0;

  if (!magicOk || !provisioned) {
    // Provisioning. Соли берём из аппаратного ГПСЧ; esp_fill_random в IDF 4.4
    // возвращает void и отказать не может.
    esp_fill_random(g_saltPw, sizeof(g_saltPw));
    esp_fill_random(g_saltDev, sizeof(g_saltDev));
    // Считаем ключ сразу: если eFuse недоступен, хранилище заводить нельзя —
    // ключ тогда не совпадёт при следующем открытии. deriveKey берёт материал
    // из g_password (пароль + при наличии — хэш файла) и соль device-фактора,
    // которую мы только что сгенерировали.
    const VaultError dk =
        deriveKey(g_password, g_passwordLen, g_saltDev, config::kPbkdf2Iters);
    if (dk != VaultError::Ok) {
      return dk;
    }

    g_generation = 1;
    g_iters = config::kPbkdf2Iters;
    g_nextId = 1;
    g_dataStart = regionStart(0);
    g_usedEnd = g_dataStart;
    // Стираем раздел целиком: иначе в неактивной области и во втором слоте
    // заголовка остались бы записи прежнего хранилища под прежним ключом, и они
    // пережили бы пересоздание.
    if (esp_partition_erase_range(g_part, 0, g_part->size) != ESP_OK) {
      crypto::wipe(g_key, sizeof(g_key));
      return VaultError::Io;
    }
    if (!flushHeader()) {
      crypto::wipe(g_key, sizeof(g_key));
      return VaultError::Io;
    }
    g_ready = true;
    g_provisioned = true;
    publishSnapshot();
    log::info("vault: provisioned gen 1, iters %u",
              static_cast<unsigned>(config::kPbkdf2Iters));
    return VaultError::Ok;
  }

  // Открытие существующего. Оба слота заголовков осматриваются независимо, и
  // решение принимается по их состояниям, а не «какой тег сошёлся».
  //
  // Правило: откат на предыдущий слот допустим только если свежий слот не
  // дописан (kAbsent/kTorn) — тогда запись оборвалась, и предыдущая копия
  // цела. Если же свежий слот дописан, но не проходит проверку, это подмена или
  // порча, и откат молча отдал бы устаревшее состояние вместо отказа.
  {
    uint8_t cand[2][config::kVaultHeaderBytes];
    const SlotState stA = probeHeaderSlot(kHdrSlot0, cand[0]);
    const SlotState stB = probeHeaderSlot(kHdrSlot1, cand[1]);
    const uint32_t seqA = stA == SlotState::kAbsent ? 0 : get32(cand[0] + kHdrSeq);
    const uint32_t seqB = stB == SlotState::kAbsent ? 0 : get32(cand[1] + kHdrSeq);

    if (stA == SlotState::kInvalid || stB == SlotState::kInvalid ||
        stA == SlotState::kTagMismatch || stB == SlotState::kTagMismatch) {
      // Порча одного слота не приговор: второй может быть цел. Отказываемся
      // только если испорченный слот новее второго — тогда откатиться значило бы
      // отдать не то состояние, которое записано последним.
      const bool newerBroken =
          (stA == SlotState::kInvalid && (stB != SlotState::kValid || seqA > seqB)) ||
          (stB == SlotState::kInvalid && (stA != SlotState::kValid || seqB > seqA));
      const bool anyValid = stA == SlotState::kValid || stB == SlotState::kValid;
      if (newerBroken && anyValid) {
        log::warn("vault: header slot is corrupt and newer than the backup");
        return VaultError::Tampered;
      }
      if (!anyValid) {
        // Ни один дописанный слот не подошёл. Если подходящих паролей нет —
        // это просто неверный пароль; отличивать его от подмены нечем, да и не
        // нужно: оба случая требуют одного и того же действия от пользователя.
        log::warn("vault: no valid header slot for password given");
        return VaultError::WrongPassword;
      }
      // Структура новейшего слота цела, резерв данным паролем открывается, а
      // новейший — нет: пароль относится к резервной копии (смена пароля), а не
      // к текущему состоянию. И это отказ, а не откат: иначе старый пароль
      // после rekey отдавал бы устаревшее хранилище.
      const bool newerTagMismatch =
          (stA == SlotState::kTagMismatch && (stB != SlotState::kValid || seqA > seqB)) ||
          (stB == SlotState::kTagMismatch && (stA != SlotState::kValid || seqB > seqA));
      if (newerTagMismatch) {
        log::warn("vault: password matches the backup slot, not the current one");
        return VaultError::WrongPassword;
      }
    }

    const bool useA = stA == SlotState::kValid && (stB != SlotState::kValid || seqA > seqB);
    if (!useA && stB != SlotState::kValid && stA != SlotState::kValid) {
      return VaultError::WrongPassword;
    }
    std::memcpy(g_hdr, useA ? cand[0] : cand[1], config::kVaultHeaderBytes);
    g_hdrSeq = get32(g_hdr + kHdrSeq);
  }

  g_generation = get32(g_hdr + kHdrGeneration);
  g_iters = get32(g_hdr + kHdrIters);
  // Источник истины о ключевом файле — флаг выбранного заголовка, а не входной
  // параметр: он участвует в каждом последующем flushHeader. При успешном
  // открытии параметр и флаг уже согласованы по построению (несогласованный
  // материал даёт WrongPassword), поэтому здесь это не проверка, а запоминание.
  g_keyFileFlag = (get32(g_hdr + kHdrFlags) & kFlagKeyfile) != 0;
  g_dataStart = get32(g_hdr + kHdrDataStart);
  g_usedEnd = get32(g_hdr + kHdrUsedBytes);
  // dataStart обязан быть ровно границей одной из двух областей. Проверка «в
  // пределах раздела» была бы слишком мягкой: произвольный dataStart сместил бы
  // журнал, и при следующей компакции стёр бы сам себя.
  if (g_dataStart != regionStart(0) && g_dataStart != regionStart(1)) {
    return VaultError::Tampered;
  }
  g_region = (g_dataStart == regionStart(1)) ? 1 : 0;
  if (g_usedEnd < g_dataStart || g_usedEnd > regionStart(2)) {
    return VaultError::Tampered;
  }
  g_compactedOnce = (get32(g_hdr + kHdrFlags) & kFlagCompacted) != 0;
  std::memcpy(g_saltPw, g_hdr + kHdrSaltPw, sizeof(g_saltPw));
  std::memcpy(g_saltDev, g_hdr + kHdrSaltDev, sizeof(g_saltDev));

  const VaultError dk = deriveKey(g_password, g_passwordLen, g_saltDev, g_iters);
  if (dk != VaultError::Ok) {
    crypto::wipe(g_key, sizeof(g_key));
    return dk;
  }
  const VaultError sc = scanLog();
  if (sc != VaultError::Ok) {
    crypto::wipe(g_key, sizeof(g_key));
    g_live = 0;
    g_livePayload = 0;
    return sc;
  }

  // Счётчики заголовка сверяем с пересчитанными: расхождение означает подмену
  // или порчу, а не штатную работу. Защита не в теге (счётчики в AAD не входят,
  // иначе ломалась бы аутентификация каждой новой записи), а именно в этой
  // сверке — пересчитанные по журналу значения сравниваются с записанными.
  if (get32(g_hdr + kHdrEntryCount) != g_live ||
      get32(g_hdr + kHdrLiveBytes) != g_livePayload) {
    log::warn("vault: counters mismatch hdr %u/%u calc %u/%u",
              static_cast<unsigned>(get32(g_hdr + kHdrEntryCount)),
              static_cast<unsigned>(get32(g_hdr + kHdrLiveBytes)),
              static_cast<unsigned>(g_live), static_cast<unsigned>(g_livePayload));
    crypto::wipe(g_key, sizeof(g_key));
    g_live = 0;
    g_livePayload = 0;
    return VaultError::Tampered;
  }

  // Оборванный хвост: за usedEnd остались байты незавершённой записи. Стирать
  // сектор с usedEnd нельзя — в его начале лежат валидные записи, и erase снёс
  // бы их вместе с мусором. Вместо этого журнал пересобирается в чистой
  // области (compact стирает неактивную область целиком и пишет туда только
  // живые записи), после чего грязный хвост остаётся в неактивной области и
  // стирается при следующей пересборке.
  if (tailIsDirty()) {
    log::warn("vault: torn tail at %u B, rebuilding log",
              static_cast<unsigned>(g_usedEnd));
    const VaultError rc = compact();
    if (rc != VaultError::Ok) {
      crypto::wipe(g_key, sizeof(g_key));
      g_live = 0;
      g_livePayload = 0;
      return rc;
    }
  }

  g_ready = true;
  g_provisioned = true;
  publishSnapshot();
  log::info("vault: opened gen %u (hdr slot %s) entries %u live %u B used %u B",
            static_cast<unsigned>(g_generation),
            (get32(g_hdr + kHdrSeq) & 1u) ? "B" : "A", static_cast<unsigned>(g_live),
            static_cast<unsigned>(g_livePayload), static_cast<unsigned>(g_usedEnd));
  return VaultError::Ok;
}

namespace {

// Читает и расшифровывает одну запись по слоту индекса. Вынесено отдельно от
// load(), чтобы get() и load() НЕ могли разойтись в проверках: обе обязаны
// сверять то, что лежит на флеше, с индексом, иначе подмена байтов в заголовке
// записи сдвинула бы чтение и мы вернули бы вызывающему чужие данные.
VaultError readRecord(uint32_t slot, Entry& e) {
  const uint16_t len = g_index[slot].len;
  if (len == 0 || len > config::kMaxEntryLen) {
    return VaultError::Tampered;
  }
  uint8_t head[kRecFixed];
  if (!readRange(g_index[slot].offset, head, kRecFixed)) {
    return VaultError::Io;
  }
  if (get32(head) != g_index[slot].id || get16(head + 4) != len) {
    return VaultError::Tampered;
  }
  uint8_t* buf = static_cast<uint8_t*>(heap_caps_malloc(len, MALLOC_CAP_SPIRAM));
  if (!buf) {
    return VaultError::NoSpace;
  }
  if (!readRange(g_index[slot].offset + kRecFixed, buf, len)) {
    crypto::wipe(buf, len);
    heap_caps_free(buf);
    return VaultError::Io;
  }
  uint8_t aad[config::kVaultHeaderBytes];
  buildAad(g_hdr, aad);
  // Расшифровываем в отдельный буфер: полагаться на поддержку in-place у
  // mbedtls_gcm_auth_decrypt не стоит, цена вопроса — один malloc на запись.
  uint8_t* pt = static_cast<uint8_t*>(heap_caps_malloc(len, MALLOC_CAP_SPIRAM));
  if (!pt) {
    crypto::wipe(buf, len);
    heap_caps_free(buf);
    return VaultError::NoSpace;
  }
  size_t ptLen = 0;
  const int dec = crypto::aesGcmDecrypt(g_key, head + 6, aad, sizeof(aad), buf, len,
                                        head + 6 + crypto::kGcmIvLen, pt, &ptLen);
  crypto::wipe(buf, len);
  heap_caps_free(buf);
  if (dec != static_cast<int>(crypto::CipherError::Ok) || ptLen != len) {
    crypto::wipe(pt, len);
    heap_caps_free(pt);
    return VaultError::Tampered;
  }
  deserialize(g_index[slot].id, pt, len, e);
  crypto::wipe(pt, len);
  heap_caps_free(pt);
  return VaultError::Ok;
}

}  // namespace

VaultError get(uint32_t id, Entry* out) {
  const Guard guard;
  if (!g_ready) {
    return VaultError::BootStrap;
  }
  if (!out) {
    return VaultError::Io;
  }
  const int at = findIndex(id);
  if (at < 0) {
    return VaultError::NotFound;
  }
  return readRecord(static_cast<uint32_t>(at), *out);
}

VaultError load(Entry* out, uint32_t maxCount, uint32_t* outCount) {
  const Guard guard;
  if (!g_ready) {
    return VaultError::BootStrap;
  }
  if (!out || !outCount) {
    return VaultError::Io;
  }
  uint32_t n = 0;
  for (uint32_t i = 0; i < g_live && n < maxCount; ++i) {
    if (g_index[i].len == 0) {
      continue;
    }
    const VaultError r = readRecord(i, out[n]);
    if (r != VaultError::Ok) {
      return r;
    }
    ++n;
  }
  *outCount = n;
  return VaultError::Ok;
}

namespace {

// Компакция: переписывает живые записи в НЕактивную область, затем одним
// изменением заголовка переключает активную область. Активная область не
// трогается вообще, поэтому обрыв питания в любой момент оставляет целый
// согласованный набор записей.
VaultError compact() {
  const size_t oldDataStart = g_dataStart;
  const size_t oldUsedEnd = g_usedEnd;
  const int oldRegion = g_region;
  const int targetRegion = 1 - oldRegion;
  const size_t targetStart = regionStart(targetRegion);

  // Снимок заголовка: нужен для точного отката флага compacted, который после
  // первой же компакции уже выставлен и не должен сбрасываться при ошибке.
  uint8_t oldHdr[config::kVaultHeaderBytes];
  std::memcpy(oldHdr, g_hdr, sizeof(oldHdr));

  // Снимок индекса: g_index перезаполняется по мере записи новых записей, а
  // читать старые смещения при этом всё ещё требуется.
  Index* const saved = g_scratch;
  const uint32_t savedCount = g_live;
  const size_t savedPayload = g_livePayload;
  for (uint32_t i = 0; i < g_live; ++i) {
    saved[i] = g_index[i];
  }

  // Место под сборку считаем заранее и отказываем до любых записей.
  size_t needBytes = 0;
  for (uint32_t i = 0; i < savedCount; ++i) {
    needBytes += kRecFixed + saved[i].len;
  }
  if (targetStart + needBytes > regionStart(2)) {
    return VaultError::NoSpace;
  }

  // Стираем всю неактивную область. Ничего живого в ней нет: прошлая
  // компакция её либо не заполняла, либо следующая стёрла.
  if (esp_partition_erase_range(g_part, targetStart, config::kVaultRegionBytes) != ESP_OK) {
    return VaultError::Io;
  }

  // AAD для расшифровки старых записей — это заголовок, под которым они были
  // записаны: старое поколение и старый dataStart. Его нужно снять ДО любых
  // изменений, иначе старые записи не расшифруются.
  uint8_t oldAad[config::kVaultHeaderBytes];
  buildAad(g_hdr, oldAad);

  // AAD для новых записей — заголовок с НОВЫМ поколением и НОВЫМ dataStart.
  // Переключение выполняется здесь же, до записи: writeRecordAt строит AAD из
  // g_hdr, и если тот останется со старым dataStart, теги новых записей не
  // сойдутся после перезагрузки.
  g_generation += 1;
  g_region = targetRegion;
  g_dataStart = targetStart;
  g_usedEnd = targetStart;
  g_compactedOnce = true;
  buildHdr();
  const uint32_t oldNextId = g_nextId;

  uint8_t* buf = static_cast<uint8_t*>(heap_caps_malloc(config::kMaxEntryLen,
                                                       MALLOC_CAP_SPIRAM));
  uint8_t* pt = static_cast<uint8_t*>(heap_caps_malloc(config::kMaxEntryLen,
                                                      MALLOC_CAP_SPIRAM));
  if (!buf || !pt) {
    heap_caps_free(buf);
    heap_caps_free(pt);
    g_generation -= 1;
    g_region = oldRegion;
    g_dataStart = oldDataStart;
    g_usedEnd = oldUsedEnd;
    g_compactedOnce = (get32(oldHdr + kHdrFlags) & kFlagCompacted) != 0;
    buildHdr();
    return VaultError::NoSpace;
  }

  size_t cursor = targetStart;
  g_live = 0;
  g_livePayload = 0;
  bool ok = true;
  for (uint32_t i = 0; i < savedCount && ok; ++i) {
    uint8_t head[kRecFixed];
    if (!readRange(saved[i].offset, head, kRecFixed)) {
      ok = false;
      break;
    }
    if (!readRange(saved[i].offset + kRecFixed, buf, saved[i].len)) {
      ok = false;
      break;
    }
    size_t ptLen = 0;
    const int dec = crypto::aesGcmDecrypt(g_key, head + 6, oldAad, sizeof(oldAad),
                                          buf, saved[i].len,
                                          head + 6 + crypto::kGcmIvLen, pt, &ptLen);
    if (dec != static_cast<int>(crypto::CipherError::Ok)) {
      ok = false;
      break;
    }
    if (writeRecordAt(cursor, saved[i].id, pt, saved[i].len) != VaultError::Ok) {
      ok = false;
      break;
    }
    g_index[g_live].id = saved[i].id;
    g_index[g_live].offset = cursor;
    g_index[g_live].len = saved[i].len;
    ++g_live;
    g_livePayload += saved[i].len;
    cursor += kRecFixed + saved[i].len;
  }
  crypto::wipe(buf, config::kMaxEntryLen);
  crypto::wipe(pt, config::kMaxEntryLen);
  heap_caps_free(buf);
  heap_caps_free(pt);

  if (!ok) {
    // Неактивная область осталась недописанной. Активная не тронута, поэтому
    // откатываем только текущие поля — состояние на флеше уже корректное.
    g_generation -= 1;
    g_region = oldRegion;
    g_dataStart = oldDataStart;
    g_usedEnd = oldUsedEnd;
    g_compactedOnce = (get32(oldHdr + kHdrFlags) & kFlagCompacted) != 0;
    buildHdr();
    g_live = savedCount;
    g_livePayload = savedPayload;
    for (uint32_t i = 0; i < savedCount; ++i) {
      g_index[i] = saved[i];
    }
    g_nextId = oldNextId;
    return VaultError::Io;
  }

  // Состояние активной области уже переключено выше, до записи записей;
  // осталось довести конец журнала до фактической длины и зафиксировать
  // заголовком.
  g_usedEnd = cursor;
  buildHdr();
  if (!flushHeader()) {
    // Заголовок не записался: на флеше осталось старое поколение со старой
    // областью, а она цела. Откатываем поля в памяти.
    g_generation -= 1;
    g_region = oldRegion;
    g_dataStart = oldDataStart;
    g_usedEnd = oldUsedEnd;
    g_compactedOnce = (get32(oldHdr + kHdrFlags) & kFlagCompacted) != 0;
    buildHdr();
    g_live = savedCount;
    g_livePayload = savedPayload;
    for (uint32_t i = 0; i < savedCount; ++i) {
      g_index[i] = saved[i];
    }
    g_nextId = oldNextId;
    return VaultError::Io;
  }

  log::info("vault: compacted -> gen %u, region %d, %u entries, %u B live",
            static_cast<unsigned>(g_generation), g_region, static_cast<unsigned>(g_live),
            static_cast<unsigned>(g_livePayload));
  return VaultError::Ok;
}

}  // namespace

VaultError add(const Entry& e, uint32_t* outId) {
  const Guard guard;
  if (!g_ready) {
    return VaultError::BootStrap;
  }
  uint8_t buf[config::kMaxEntryLen];
  const size_t plen = serialize(e, buf, sizeof(buf));
  if (plen == 0) {
    return VaultError::EntryTooLong;
  }
  if (plen > config::kMaxEntryLen) {
    return VaultError::EntryTooLong;
  }

  const uint32_t id = e.id ? e.id : g_nextId;
  const int at = findIndex(id);
  const bool isUpdate = at >= 0;
  const size_t prevLen = isUpdate ? g_index[at].len : 0;

  if (!isUpdate && g_live >= config::kMaxEntries) {
    crypto::wipe(buf, sizeof(buf));
    return VaultError::TooManyEntries;
  }
  if (g_livePayload - prevLen + plen > config::kVaultLiveBudgetBytes) {
    crypto::wipe(buf, sizeof(buf));
    return VaultError::Budget;
  }
  // Порог срабатывания берётся из config (половина области), а не из заполнения
  // области до конца. Причины две. Первая: после пересборки живым данным надо
  // снова уместиться в области, и при пороге «впритык» одна-единственная
  // добавочная запись не влезала бы в свежесобранный журнал, хотя места за
  //ведомо много. Вторая: пока журнал не достиг порога, он не трогает второй
  //слот заголовка лишний раз, то есть реже идёт стирание.
  //
  // Проверка идёт по границе ОБЛАСТИ, а не раздела: активная область и есть
  // единственное место для записи. Считать от g_part->size было бы ошибкой —
  // это заставило бы компактить запись, которой есть куда лечь.
  //
  // Порядок важен: сначала порог, потом запись. Иначе при полной области
  // запись отказали бы, не дав собрать её.
  if (g_usedEnd - g_dataStart + kRecFixed + plen > config::kVaultCompactTriggerBytes) {
    const VaultError c = compact();
    if (c != VaultError::Ok) {
      crypto::wipe(buf, sizeof(buf));
      return c == VaultError::NoSpace ? VaultError::Budget : c;
    }
    // После пересборки живые данные занимают меньше места, чем занимал журнал с
    // надгробными записями, но гарантии на конкретный размер нет: если даже
    // после этого запись не влезает, места действительно нет.
    if (g_usedEnd - g_dataStart + kRecFixed + plen > config::kVaultRegionBytes) {
      crypto::wipe(buf, sizeof(buf));
      return VaultError::Budget;
    }
    // После компакции смещения поменялись, но id и длины в индексе те же.
  }

  const size_t off = g_usedEnd;
  const VaultError wr = writeRecordAt(off, id, buf, plen);
  crypto::wipe(buf, sizeof(buf));
  if (wr != VaultError::Ok) {
    return wr;
  }
  g_usedEnd = off + kRecFixed + plen;
  if (!applyToIndex(id, off, static_cast<uint16_t>(plen))) {
    g_usedEnd = off;
    return VaultError::TooManyEntries;
  }
  if (id >= g_nextId) {
    g_nextId = id + 1;
  }
  if (!flushHeader()) {
    return VaultError::Io;
  }
  if (outId) {
    *outId = id;
  }
  publishSnapshot();
  return VaultError::Ok;
}

VaultError remove(uint32_t id) {
  const Guard guard;
  if (!g_ready) {
    return VaultError::BootStrap;
  }
  if (findIndex(id) < 0) {
    return VaultError::NotFound;
  }
  // Надгробная запись тоже занимает kRecFixed + 1 байт маркера — столько же,
  // сколько обычная запись минимальной длины.
  if (g_usedEnd - g_dataStart + kRecFixed + 1 > config::kVaultRegionBytes) {
    const VaultError c = compact();
    if (c != VaultError::Ok) {
      return c;
    }
    if (g_usedEnd - g_dataStart + kRecFixed + 1 > config::kVaultRegionBytes) {
      return VaultError::NoSpace;
    }
  }
  const size_t off = g_usedEnd;
  const VaultError wr = writeRecordAt(off, id | kTombstoneBit, nullptr, 0);
  if (wr != VaultError::Ok) {
    return wr;
  }
  g_usedEnd = off + kRecFixed + 1;
  const int at = findIndex(id);
  if (at >= 0) {
    removeAt(static_cast<uint32_t>(at));
  }
  if (!flushHeader()) {
    return VaultError::Io;
  }
  publishSnapshot();
  return VaultError::Ok;
}

// Полное стирание: новые соли, новое поколение, пустой журнал. Прежние данные
// физически уничтожаются erase по всему разделу, поэтому восстановить их
// перебором нельзя. Пароль обязателен: без него новый KEK не вывести, а
// оставлять после стирания заголовок со старым ключом означало бы завести
// хранилище, которое нельзя открыть.
VaultError clear(const char* password, const uint8_t* keyFile,
                 size_t keyFileLen) {
  const Guard guard;
  if (!g_ready) {
    return VaultError::BootStrap;
  }
  if (!password || std::strlen(password) < config::kMinPassChars ||
      std::strlen(password) >= config::kMaxPassChars) {
    return VaultError::WrongPassword;
  }
  // Материал собирается ДО стирания раздела: при отказе (слишком длинный пароль,
  // сбой SHA-256) флеш остаётся нетронутым.
  const size_t matLen =
      buildMaterial(g_password, sizeof(g_password), password, keyFile, keyFileLen);
  if (matLen == 0) {
    crypto::wipe(g_password, sizeof(g_password));
    return VaultError::WrongPassword;
  }
  g_passwordLen = matLen;
  g_keyFileFlag = (keyFile != nullptr && keyFileLen > 0);
  if (esp_partition_erase_range(g_part, 0, g_part->size) != ESP_OK) {
    crypto::wipe(g_password, sizeof(g_password));
    g_passwordLen = 0;
    return VaultError::Io;
  }
  std::memset(g_key, 0, sizeof(g_key));
  std::memset(g_hdr, 0, sizeof(g_hdr));
  std::memset(g_index, 0, sizeof(g_index));
  std::memset(g_saltPw, 0, sizeof(g_saltPw));
  std::memset(g_saltDev, 0, sizeof(g_saltDev));
  g_live = 0;
  g_livePayload = 0;
  g_generation = 1;
  g_iters = config::kPbkdf2Iters;
  g_nextId = 1;
  g_compactedOnce = false;
  g_region = 0;
  g_dataStart = regionStart(0);
  g_usedEnd = g_dataStart;
  esp_fill_random(g_saltPw, sizeof(g_saltPw));
  esp_fill_random(g_saltDev, sizeof(g_saltDev));
  const VaultError dk = deriveKey(g_password, g_passwordLen, g_saltDev, g_iters);
  // Материал нужен ровно до вывода ключа; дальше его обязаны стирать все пути,
  // как это делает PasswordGuard в begin().
  crypto::wipe(g_password, sizeof(g_password));
  g_passwordLen = 0;
  if (dk != VaultError::Ok) {
    return dk;
  }
  if (!flushHeader()) {
    return VaultError::Io;
  }
  log::info("vault: cleared");
  publishSnapshot();
  return VaultError::Ok;
}

// Смена мастер-пароля открытого хранилища. Требует g_ready: без открытой
// сессии расшифровать существующие записи нечем, а без проверки открытой
// сессии операция была бы стиранием хранилища по одному лишь знанию HTTP-пути.
//
// Устройство операции повторяет компакцию: снимок состояния, новые соли и
// ключ, запись живых записей в неактивную область, переключение заголовком,
// и только потом уничтожение старой области. До flushHeader() отказ откатывается
// в RAM, и старый пароль действует — точка невозврата ровно одна, как и в
// compact().
VaultError rekey(const char* newPassword, const uint8_t* keyFile,
                 size_t keyFileLen) {
  const Guard guard;
  if (!g_ready) {
    return VaultError::BootStrap;
  }
  if (!newPassword || std::strlen(newPassword) < config::kMinPassChars ||
      std::strlen(newPassword) >= config::kMaxPassChars) {
    return VaultError::WrongPassword;
  }

  // Новый материал собирается в g_password: после begin() этот буфер свободен
  // (PasswordGuard стер его сразу после открытия), и чистить его вручную
  // не требуется — все пути ниже стирают его сами.
  const size_t matLen = buildMaterial(g_password, sizeof(g_password), newPassword,
                                      keyFile, keyFileLen);
  if (matLen == 0) {
    crypto::wipe(g_password, sizeof(g_password));
    return VaultError::WrongPassword;
  }
  g_passwordLen = matLen;
  const bool newKeyFileFlag = (keyFile != nullptr && keyFileLen > 0);

  const size_t oldDataStart = g_dataStart;
  const size_t oldUsedEnd = g_usedEnd;
  const int oldRegion = g_region;
  const int targetRegion = 1 - oldRegion;
  const size_t targetStart = regionStart(targetRegion);

  // Снимки, без которых отказ ниже не откатить: заголовок, обе соли, старый
  // ключ (для расшифровки старых записей — g_key перезапишется новым),
  // флаг ключевого файла и nextId.
  uint8_t oldHdr[config::kVaultHeaderBytes];
  std::memcpy(oldHdr, g_hdr, sizeof(oldHdr));
  uint8_t oldAad[config::kVaultHeaderBytes];
  buildAad(g_hdr, oldAad);
  uint8_t oldSaltPw[config::kPbkdf2SaltLen];
  uint8_t oldSaltDev[config::kPbkdf2SaltLen];
  std::memcpy(oldSaltPw, g_saltPw, sizeof(oldSaltPw));
  std::memcpy(oldSaltDev, g_saltDev, sizeof(oldSaltDev));
  uint8_t oldKey[crypto::kAesKeyLen];
  std::memcpy(oldKey, g_key, sizeof(oldKey));
  const bool oldKeyFileFlag = g_keyFileFlag;
  const uint32_t oldNextId = g_nextId;

  // Снимок индекса в g_scratch: g_index перезаполняется по мере записи, а
  // читать старые смещения при этом всё ещё требуется.
  Index* const saved = g_scratch;
  const uint32_t savedCount = g_live;
  const size_t savedPayload = g_livePayload;
  for (uint32_t i = 0; i < g_live; ++i) {
    saved[i] = g_index[i];
  }

  // Место под сборку считаем заранее и отказываем до любых изменений. Та же
  // сумма, что и при компакции: записи не меняют размер от смены ключа.
  size_t needBytes = 0;
  for (uint32_t i = 0; i < savedCount; ++i) {
    needBytes += kRecFixed + saved[i].len;
  }
  if (targetStart + needBytes > regionStart(2)) {
    crypto::wipe(g_password, sizeof(g_password));
    g_passwordLen = 0;
    return VaultError::NoSpace;
  }

  // Откат RAM на любой отказ до flushHeader: старые соли и старый ключ
  // восстанавливаются, и старый пароль открывает хранилище как прежде.
  // genBumped=false — для отказов, случившихся до g_generation += 1.
  auto rollback = [&](bool genBumped) {
    std::memcpy(g_saltPw, oldSaltPw, sizeof(oldSaltPw));
    std::memcpy(g_saltDev, oldSaltDev, sizeof(oldSaltDev));
    std::memcpy(g_key, oldKey, sizeof(oldKey));
    if (genBumped) {
      g_generation -= 1;
    }
    g_keyFileFlag = oldKeyFileFlag;
    g_region = oldRegion;
    g_dataStart = oldDataStart;
    g_usedEnd = oldUsedEnd;
    g_compactedOnce = (get32(oldHdr + kHdrFlags) & kFlagCompacted) != 0;
    std::memcpy(g_hdr, oldHdr, sizeof(oldHdr));
    g_live = savedCount;
    g_livePayload = savedPayload;
    for (uint32_t i = 0; i < savedCount; ++i) {
      g_index[i] = saved[i];
    }
    g_nextId = oldNextId;
    crypto::wipe(g_password, sizeof(g_password));
    g_passwordLen = 0;
    // Старый ключ больше не нужен: g_key уже восстановлен из копии.
    crypto::wipe(oldKey, sizeof(oldKey));
  };

  // Новые соли и новый ключ. Пока не перезаписан заголовок, на флеше ничего
  // не изменилось: любой отказ здесь откатывается без ущерба.
  esp_fill_random(g_saltPw, sizeof(g_saltPw));
  esp_fill_random(g_saltDev, sizeof(g_saltDev));
  const VaultError dk =
      deriveKey(g_password, g_passwordLen, g_saltDev, g_iters);
  if (dk != VaultError::Ok) {
    rollback(false);
    return dk;
  }
  g_keyFileFlag = newKeyFileFlag;
  crypto::wipe(g_password, sizeof(g_password));
  g_passwordLen = 0;

  // Стираем неактивную область: живого в ней нет, а под старым ключом
  // остатки прошлых компакций уже невалидны.
  if (esp_partition_erase_range(g_part, targetStart, config::kVaultRegionBytes) !=
      ESP_OK) {
    rollback(false);
    return VaultError::Io;
  }

  // Переключение до записи: writeRecordAt строит AAD из g_hdr, и если тот
  // останется со старым dataStart/поколением, теги новых записей не сойдутся
  // после перезагрузки. Поколение растёт — nonceFor включает его, поэтому
  // (generation, offset) новой записи не повторяет старый даже при совпадении
  // смещений, а здесь они ещё и в разных областях.
  g_generation += 1;
  g_region = targetRegion;
  g_dataStart = targetStart;
  g_usedEnd = targetStart;
  buildHdr();

  uint8_t* buf = static_cast<uint8_t*>(heap_caps_malloc(config::kMaxEntryLen,
                                                        MALLOC_CAP_SPIRAM));
  uint8_t* pt = static_cast<uint8_t*>(heap_caps_malloc(config::kMaxEntryLen,
                                                       MALLOC_CAP_SPIRAM));
  if (!buf || !pt) {
    heap_caps_free(buf);
    heap_caps_free(pt);
    rollback(true);
    return VaultError::NoSpace;
  }

  size_t cursor = targetStart;
  g_live = 0;
  g_livePayload = 0;
  bool ok = true;
  for (uint32_t i = 0; i < savedCount && ok; ++i) {
    uint8_t head[kRecFixed];
    if (!readRange(saved[i].offset, head, kRecFixed)) {
      ok = false;
      break;
    }
    if (!readRange(saved[i].offset + kRecFixed, buf, saved[i].len)) {
      ok = false;
      break;
    }
    // Старые записи: СТАРЫЙ ключ и СТАРЫЙ AAD — снимок сделан до каких-либо
    // изменений. Новые пишутся writeRecordAt уже под новым g_key и новым AAD.
    size_t ptLen = 0;
    const int dec = crypto::aesGcmDecrypt(oldKey, head + 6, oldAad, sizeof(oldAad),
                                          buf, saved[i].len,
                                          head + 6 + crypto::kGcmIvLen, pt, &ptLen);
    if (dec != static_cast<int>(crypto::CipherError::Ok) ||
        ptLen != saved[i].len) {
      ok = false;
      break;
    }
    if (writeRecordAt(cursor, saved[i].id, pt, saved[i].len) != VaultError::Ok) {
      ok = false;
      break;
    }
    g_index[g_live].id = saved[i].id;
    g_index[g_live].offset = cursor;
    g_index[g_live].len = saved[i].len;
    ++g_live;
    g_livePayload += saved[i].len;
    cursor += kRecFixed + saved[i].len;
  }
  crypto::wipe(buf, config::kMaxEntryLen);
  crypto::wipe(pt, config::kMaxEntryLen);
  heap_caps_free(buf);
  heap_caps_free(pt);

  if (!ok) {
    rollback(true);
    return VaultError::Io;
  }

  // Точка невозврата: заголовок с новым ключом дописан. С этого момента
  // старый пароль не открывает хранилище, новый — открывает.
  g_usedEnd = cursor;
  buildHdr();
  if (!flushHeader()) {
    rollback(true);
    return VaultError::Io;
  }

  // Старая область уходит сразу: там записи под старым ключом, которые новое
  // хранилище уже не читает. Best-effort — при обрыве стирания мусор доживёт
  // до следующей компакции, которая сотрёт неактивную область целиком.
  if (esp_partition_erase_range(g_part, regionStart(oldRegion),
                                config::kVaultRegionBytes) != ESP_OK) {
    log::warn("vault: rekey, old region erase failed (will be swept later)");
  }

  crypto::wipe(oldKey, sizeof(oldKey));
  crypto::wipe(oldSaltPw, sizeof(oldSaltPw));
  crypto::wipe(oldSaltDev, sizeof(oldSaltDev));
  log::info("vault: rekeyed -> gen %u, region %d, %u entries",
            static_cast<unsigned>(g_generation), g_region,
            static_cast<unsigned>(g_live));
  publishSnapshot();
  return VaultError::Ok;
}

// Уничтожение без пароля. В отличие от clear() не требует открытой сессии и не
// заводит новое хранилище: раздел просто стирается, и устройство переходит в
// Unprovisioned. Новый KEK не выводится намеренно — выводить нечего, старые
// соли уничтожены вместе с заголовками, а выдумывать соль здесь означало бы
// завести хранилище, минуя provisioning.
VaultError reset() {
  const Guard guard;
  if (!g_part) {
    g_part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY,
                                      config::kFsVault);
    if (!g_part) {
      return VaultError::NotFound;
    }
  }
  if (esp_partition_erase_range(g_part, 0, g_part->size) != ESP_OK) {
    return VaultError::Io;
  }
  crypto::wipe(g_key, sizeof(g_key));
  crypto::wipe(g_password, sizeof(g_password));
  g_passwordLen = 0;
  g_keyFileFlag = false;
  crypto::wipe(g_hdr, sizeof(g_hdr));
  crypto::wipe(g_saltPw, sizeof(g_saltPw));
  crypto::wipe(g_saltDev, sizeof(g_saltDev));
  std::memset(g_index, 0, sizeof(g_index));
  std::memset(g_scratch, 0, sizeof(g_scratch));
  g_live = 0;
  g_livePayload = 0;
  g_generation = 1;
  g_iters = config::kPbkdf2Iters;
  g_nextId = 1;
  g_compactedOnce = false;
  g_region = 0;
  g_dataStart = regionStart(0);
  g_usedEnd = g_dataStart;
  g_hdrSeq = 0;
  g_ready = false;
  g_provisioned = false;
  publishSnapshot();
  log::info("vault: reset, storage destroyed");
  return VaultError::Ok;
}

}  // namespace vault
}  // namespace pm
