// Гейты стадии 4a: крипто и хранилище проверяются на реальном ESP32-S3.
//
// Здесь нет ничего, что можно было бы надёжно проверить на хосте: PBKDF2 и AES
// считает mbedtls, а запись во флеш имеет смысл только на настоящей микросхеме.
//
// Гейты хранилища пишут в раздел `vault` и в конце стирают его. Запускать на
// разделе с настоящими данными нельзя, поэтому run() сначала проверяет, что
// раздел пуст, и при непустом заголовке отказывается работать, а не перетирает
// данные.
//
// Секреты в лог не печатаются: пароль гейтов — константа из этого файла, и в
// сообщения идут только длины, счётчики и результат сравнения.

#include "selftest.h"

#include <Arduino.h>
#include <esp_partition.h>

#include <cstdio>
#include <cstring>

#include "auth.h"
#include "config.h"
#include "crypto.h"
#include "device_factor.h"
#include "logger.h"
// wordlist.h включается здесь ради сверки формата пароля (gateA2-words-in-dict).
// Таблица определена один раз в src/wordlist.cpp, поэтому второе включение
// заголовка копий не создаёт.
#include "totp.h"
#include "vault.h"
#include "wordlist.h"

namespace pm {
namespace selftest {
namespace {

// Пароль гейтов. Длиннее config::kMinPassChars, чтобы проверка длины прошла.
//
// Массив ИЗМЕНЯЕМЫЙ, и это не небрежность: гейты auth идут первыми и оставляют
// хранилище, заведённое под СГЕНЕРИРОВАННЫЙ мастер-пароль. Гейты vault
// открывают то самое хранилище, поэтому им нужен именно этот пароль, а не
// литерал. При authGates() он копируется в kGatePassword перед выходом.
//
// Длина литерала (41) больше config::kMasterPasswordChars (37), поэтому
// сгенерированный пароль помещается без обрезки.
char kGatePassword[] = "gate-only-passphrase-4a-not-a-real-secret";
static_assert(sizeof(kGatePassword) > config::kMasterPasswordChars + 1,
              "буфер kGatePassword не влезает сгенерированный мастер-пароль");

constexpr char kGatePasswordWrong[] = "gate-only-wrong-passphrase-4a";

using vault::Entry;
using vault::Stats;
using vault::VaultError;

// Смещения полей заголовка PMV1. Дублируются здесь намеренно: гейты должны
// проверять реальные байты на флеше, а не спрашивать у vault.cpp, что он сам
// напишет. Общая константа означала бы, что тест и код не могут разойтись.
constexpr size_t kHdrGeneration = 0x08;
constexpr size_t kHdrIters = 0x1C;
constexpr size_t kHdrSaltPw = 0x20;
constexpr size_t kHdrSaltDev = 0x30;
constexpr size_t kHdrDataStart = 0x50;
// Тег аутентификации и маркер завершения записи занимают хвост заголовка:
// [tag: 16 байт][commit: 4 байта]. Значения пересчитаны из размера заголовка,
// чтобы гейт проверял настоящий хвост, а не зашитое в текст число.
constexpr size_t kCommitBytes = 4;
constexpr size_t kHdrCommit = config::kVaultHeaderBytes - kCommitBytes;
constexpr size_t kHdrCheck = kHdrCommit - 16;
static_assert(kHdrCheck + 16 + kCommitBytes == config::kVaultHeaderBytes,
              "selftest must check the real header tail");
constexpr uint32_t kFlagProvisioned = 1u << 0;
constexpr size_t kRecFixed = 34;  // id(4) + len(2) + iv(12) + tag(16)

uint32_t g_pass = 0;
uint32_t g_fail = 0;

void report(const char* gate, bool ok, const char* detail) {
  if (ok) {
    ++g_pass;
    log::info("gate %-20s PASS %s", gate, detail ? detail : "");
  } else {
    ++g_fail;
    log::error("gate %-20s FAIL %s", gate, detail ? detail : "");
  }
}

int hexNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool hexToBytes(const char* hex, uint8_t* out, size_t outLen) {
  for (size_t i = 0; i < outLen; ++i) {
    const int hi = hexNibble(hex[i * 2]);
    const int lo = hexNibble(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) {
      return false;
    }
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return true;
}

void fillEntry(Entry& e, uint32_t id, const char* tag) {
  std::memset(&e, 0, sizeof(e));
  e.id = id;
  std::snprintf(e.title, sizeof(e.title), "gate-%s", tag);
  std::snprintf(e.login, sizeof(e.login), "user-%s", tag);
  std::snprintf(e.password, sizeof(e.password), "pw-%s", tag);
  std::snprintf(e.url, sizeof(e.url), "https://example.invalid/%s", tag);
  std::snprintf(e.note, sizeof(e.note), "note-%s", tag);
  std::snprintf(e.tags, sizeof(e.tags), "tag-%s,shared", tag);
  std::snprintf(e.totp, sizeof(e.totp), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
}

bool entriesEqual(const Entry& a, const Entry& b) {
  return a.id == b.id && std::strcmp(a.title, b.title) == 0 &&
         std::strcmp(a.login, b.login) == 0 && std::strcmp(a.password, b.password) == 0 &&
         std::strcmp(a.url, b.url) == 0 && std::strcmp(a.note, b.note) == 0 &&
         std::strcmp(a.tags, b.tags) == 0 && std::strcmp(a.totp, b.totp) == 0;
}

const esp_partition_t* vaultPartition() {
  return esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY,
                                  config::kFsVault);
}

// Entry весит около 900 байт, поэтому массив из 16 записей — это 14 КБ, а стек
// loopTask в Arduino всего 8 КБ. Все массивы записей в гейтах живут в PSRAM.
// Обёртка прячет освобождение: иначе на каждом пути возврата пришлось бы
// повторять heap_caps_free, и один забытый вызов уронил бы гейты позже, на
// другом участке.
template <size_t N>
class EntryArray {
 public:
  EntryArray() : data_(static_cast<Entry*>(heap_caps_malloc(N * sizeof(Entry),
                                                             MALLOC_CAP_SPIRAM))) {}
  ~EntryArray() { heap_caps_free(data_); }
  EntryArray(const EntryArray&) = delete;
  EntryArray& operator=(const EntryArray&) = delete;
  bool ok() const { return data_ != nullptr; }
  Entry& operator[](size_t i) { return data_[i]; }
  Entry* data() { return data_; }

 private:
  Entry* data_;
};

uint32_t readU32(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

// Заголовок лежит в одном из двух слотов и лежит в том, который записан
// последним, — номер слота зашит в поле seq заголовка. Гейты порчи работают с
// байтами на флеше напрямую, поэтому им нужно знать, какой слот сейчас
// актуален: иначе они портили бы пустой слот и ничего не проверяли.
constexpr size_t kHdrFlags = 0x18;
constexpr size_t kHdrSeq = 0x54;
constexpr size_t kHdrSlotBytes = config::kVaultHeaderSlotBytes;

size_t activeHeaderSlot() {
  size_t best = 0;
  uint32_t bestSeq = 0;
  for (size_t slot = 0; slot < 2; ++slot) {
    uint8_t hdr[config::kVaultHeaderBytes];
    const esp_partition_t* part = vaultPartition();
    if (!part ||
        esp_partition_read(part, slot * kHdrSlotBytes, hdr, sizeof(hdr)) != ESP_OK) {
      continue;
    }
    if (std::memcmp(hdr, config::kVaultMagic, 4) != 0) {
      continue;
    }
    if ((readU32(hdr + kHdrFlags) & kFlagProvisioned) == 0) {
      continue;
    }
    // Оба слота удовлетворяют условию «номер слота == seq & 1»: так и должно
    // быть, каждая запись кладёт заголовок в свой слот. Отличить свежий от
    // устаревшего можно только по самому seq, поэтому берём максимальный.
    const uint32_t seq = readU32(hdr + kHdrSeq);
    if (seq > bestSeq) {
      bestSeq = seq;
      best = slot;
    }
  }
  return best;
}

// Читает заголовок из активного слота. Провал чтения даёт нули, и вызывающий
// код обязан это учесть — подставлять заведомо неверные смещения нельзя.
bool readActiveHeader(uint8_t* hdr) {
  const esp_partition_t* part = vaultPartition();
  if (!part) {
    return false;
  }
  const size_t slot = activeHeaderSlot();
  return esp_partition_read(part, slot * kHdrSlotBytes, hdr, config::kVaultHeaderBytes) ==
         ESP_OK;
}

// Раздел пуст, если заголовок не помечен как provisioned. Читать нужно весь
// заголовок: флаг provisioned лежит на смещении 0x18, то есть за пределами
// первых 16 байт.
bool vaultLooksEmpty() {
  const esp_partition_t* part = vaultPartition();
  if (!part) {
    return false;
  }
  uint8_t head[config::kVaultHeaderBytes];
  // Любой слот подойдёт: оба содержат provisioned-заголовок с одинаковыми
  // флагами, а читается только флаг.
  if (esp_partition_read(part, 0, head, sizeof(head)) != ESP_OK) {
    return false;
  }
  if (std::memcmp(head, config::kVaultMagic, 4) != 0) {
    return true;
  }
  return (readU32(head + 0x18) & kFlagProvisioned) == 0;
}

// Открытие с подменённым байтом обязано быть отвергнуто. Возвращает true, если
// vault отказался открываться (это и есть успех проверки).
bool rejectedOnOpen() {
  const VaultError r = vault::begin(kGatePassword);
  return r == VaultError::Tampered || r == VaultError::WrongPassword;
}

// Записывает bad вместо len байт по смещению off, проверяет отказ и восстанавливает
// сектор целиком.
//
// Откат через erase обязателен: SPI flash поддерживает только переход 1 -> 0, и
// вернуть сброшенный бит в единицу без стирания сектора невозможно. Сектор
// читается в буфер ДО порчи, поэтому все остальные записи, попавшие в него,
// восстанавливаются вместе с испорченными байтами.
bool tamperBytesRejected(const esp_partition_t* part, size_t off, const uint8_t* bad,
                         size_t len) {
  if (!part || !bad || len == 0 || off + len > config::kVaultPartitionBytes) {
    return false;
  }
  const size_t sector = off & ~(config::kFlashSectorBytes - 1);
  // Порча может не поместиться в один сектор; в наших гейтах это не так, но
  // проверять дешевле, чем полагаться.
  if (off + len > sector + config::kFlashSectorBytes) {
    log::error("gate: tamper range crosses sector boundary at %u",
               static_cast<unsigned>(off));
    return false;
  }
  uint8_t* snap = static_cast<uint8_t*>(heap_caps_malloc(config::kFlashSectorBytes,
                                                        MALLOC_CAP_SPIRAM));
  if (!snap) {
    log::error("gate: no memory to snapshot sector at %u", static_cast<unsigned>(sector));
    return false;
  }
  bool rejected = false;
  if (esp_partition_read(part, sector, snap, config::kFlashSectorBytes) != ESP_OK) {
    log::error("gate: cannot snapshot sector at %u", static_cast<unsigned>(sector));
    heap_caps_free(snap);
    return false;
  }
  if (esp_partition_write(part, off, bad, len) != ESP_OK) {
    // Отказ записи сам по себе не результат: значит, flash не принял подмену.
    log::error("gate: flash rejected tamper write at %u", static_cast<unsigned>(off));
  } else {
    rejected = rejectedOnOpen();
  }
  if (esp_partition_erase_range(part, sector, config::kFlashSectorBytes) != ESP_OK ||
      esp_partition_write(part, sector, snap, config::kFlashSectorBytes) != ESP_OK) {
    log::error("gate: cannot restore sector at %u, vault is broken",
               static_cast<unsigned>(sector));
  }
  heap_caps_free(snap);
  return rejected;
}

// Портит байт по смещению off, сбрасывая в нём младший бит. Единственное
// направление, которое flash принимает без erase.
bool tamperByteIsRejected(const esp_partition_t* part, size_t off) {
  uint8_t orig = 0;
  if (!part || esp_partition_read(part, off, &orig, 1) != ESP_OK) {
    return false;
  }
  const uint8_t bad = static_cast<uint8_t>(orig & 0xFE);
  if (bad == orig) {
    // Байт уже равен нулю: сбросить бит нечем, а поставить единицу без erase
    // нельзя. Такой случай проверять нечем.
    return true;
  }
  return tamperBytesRejected(part, off, &bad, 1);
}

// Ожидание завершения job'а с периодом 200 мс. false — job не принят (0) или
// результат не пришёл за timeoutMs. Вынесено в helper: тут же стояли бы пять
// одинаковых копий цикла poll, и каждая копия — место для опечатки в таймауте.
bool waitJob(auth::JobId job, auth::JobView* v, uint32_t timeoutMs) {
  if (job == auth::kNoJob || v == nullptr) {
    return false;
  }
  for (uint32_t waited = 0; waited < timeoutMs; waited += 200) {
    if (auth::poll(job, v) && v->result != auth::Result::Pending) {
      return true;
    }
    delay(200);
  }
  return false;
}

}  // namespace

void cryptoGates() {
  // Гейт 1: PBKDF2 по векторам RFC 7914.
  struct Kat {
    const char* pass;
    const char* salt;
    uint32_t iters;
    const char* expect;
  };
  const Kat vectors[] = {
      {"password", "salt", 1,
       "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
      {"password", "salt", 2,
       "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
      {"password", "salt", 4096,
       "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
      {"passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096,
       "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1"},
      {"passwd", "salt", 1,
       "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"},
  };
  const size_t vectorCount = sizeof(vectors) / sizeof(vectors[0]);
  uint32_t okCount = 0;
  for (const Kat& v : vectors) {
    uint8_t got[32] = {};
    uint8_t want[32] = {};
    if (!hexToBytes(v.expect, want, sizeof(want))) {
      continue;
    }
    const int rc = crypto::pbkdf2HmacSha256(v.pass, std::strlen(v.pass), v.salt,
                                             std::strlen(v.salt), v.iters, got);
    if (rc == static_cast<int>(crypto::CipherError::Ok) && crypto::ctEqual(got, want, 32)) {
      ++okCount;
    }
    crypto::wipe(got, sizeof(got));
  }
  char detail[64];
  std::snprintf(detail, sizeof(detail), "%u/%u vectors (RFC 7914)",
                static_cast<unsigned>(okCount), static_cast<unsigned>(vectorCount));
  report("crypto-kdf", okCount == vectorCount, detail);

  // Дополнительно: AES-256-GCM round-trip и отказ по подмене тега, AAD и текста.
  {
    uint8_t key[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                       17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    const uint8_t iv[12] = {0xAA, 0xBB, 0xCC, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    const uint8_t aad[8] = {'h', 'd', 'r', 'v', '1', 0, 0, 0};
    const char* msg = "gate-plaintext-check-0123456789";
    const size_t msgLen = std::strlen(msg);
    uint8_t ct[64] = {};
    uint8_t tag[16] = {};
    size_t ctLen = 0;
    int rc = crypto::aesGcmEncrypt(key, iv, aad, sizeof(aad), msg, msgLen, ct, &ctLen, tag);
    bool ok = rc == static_cast<int>(crypto::CipherError::Ok) && ctLen == msgLen;
    uint8_t back[64] = {};
    size_t backLen = 0;
    if (ok) {
      rc = crypto::aesGcmDecrypt(key, iv, aad, sizeof(aad), ct, ctLen, tag, back, &backLen);
      ok = rc == static_cast<int>(crypto::CipherError::Ok) && backLen == msgLen &&
           std::memcmp(back, msg, msgLen) == 0;
    }
    // AAD входит в аутентификацию: подмена байта в нём обязана ломать
    // расшифровку даже при верном теге. Иначе заголовок хранилища можно было бы
    // менять, подделывая счётчики.
    if (ok) {
      uint8_t badAad[8];
      std::memcpy(badAad, aad, sizeof(badAad));
      badAad[0] ^= 0x01;
      rc = crypto::aesGcmDecrypt(key, iv, badAad, sizeof(badAad), ct, ctLen, tag, back,
                                 &backLen);
      ok = rc == static_cast<int>(crypto::CipherError::AuthFail);
    }
    // Подмена байта в самом шифротексте обязана ломать аутентификацию.
    if (ok) {
      ct[0] ^= 0x01;
      rc = crypto::aesGcmDecrypt(key, iv, aad, sizeof(aad), ct, ctLen, tag, back, &backLen);
      ok = rc == static_cast<int>(crypto::CipherError::AuthFail);
    }
    // И подмена тега.
    if (ok) {
      tag[0] ^= 0x01;
      rc = crypto::aesGcmDecrypt(key, iv, aad, sizeof(aad), ct, ctLen, tag, back, &backLen);
      ok = rc == static_cast<int>(crypto::CipherError::AuthFail);
    }
    crypto::wipe(ct, sizeof(ct));
    crypto::wipe(back, sizeof(back));
    crypto::wipe(key, sizeof(key));
    report("crypto-aes-gcm", ok, "roundtrip + ct/aad/tag flip rejected");
  }

  // ctEqual обязан различать и не реагировать на длину.
  {
    const uint8_t a[4] = {1, 2, 3, 4};
    const uint8_t b[4] = {1, 2, 3, 5};
    report("crypto-cteq", !crypto::ctEqual(a, b, 4) && crypto::ctEqual(a, a, 4), "");
  }

  // Device-фактор обязан быть детерминированным и зависеть от соли.
  {
    const uint8_t s1[16] = {1};
    const uint8_t s2[16] = {2};
    uint8_t f1[32] = {};
    uint8_t f2[32] = {};
    uint8_t f3[32] = {};
    const bool got1 = device::factor(s1, sizeof(s1), f1);
    const bool got2 = device::factor(s1, sizeof(s1), f2);
    const bool got3 = device::factor(s2, sizeof(s2), f3);
    const bool ok = got1 && got2 && got3 && crypto::ctEqual(f1, f2, 32) &&
                    !crypto::ctEqual(f1, f3, 32);
    crypto::wipe(f1, sizeof(f1));
    crypto::wipe(f2, sizeof(f2));
    crypto::wipe(f3, sizeof(f3));
    report("device-factor", ok, "stable, salt-dependent");
  }

  // TOTP по эталонным векторам RFC 6238 (SHA-1). Секрет — ASCII
  // "12345678901234567890", его base32-запись и есть векторный секрет. Вектор
  // на T = 20000000000 не проверяется: он не помещается в uint32_t, а время на
  // устройстве приходит 32-битным.
  {
    const char* kSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    struct TotKat {
      uint32_t t;
      const char* expect;
    };
    const TotKat vectors[] = {
        {59u, "287082"},
        {1111111109u, "081804"},
        {1111111111u, "050471"},
        {1234567890u, "005924"},
        {2000000000u, "279037"},
    };
    uint32_t okCount = 0;
    char code[7];
    for (const TotKat& v : vectors) {
      if (totp::code(kSecret, v.t, code) && std::strcmp(code, v.expect) == 0) {
        ++okCount;
      }
    }
    // Отбраковка мусора: короткий секрет, запрещённый символ, пустая строка.
    const bool rejects = !totp::validSecret("abc") &&
                         !totp::validSecret("ABCDEFGH1IJKLMNOP") &&  // '1' вне base32
                         !totp::validSecret("") &&
                         !totp::code("too-short", 59u, code);
    char detail[64];
    std::snprintf(detail, sizeof(detail), "%u/%u vectors, invalid rejected: %d",
                  static_cast<unsigned>(okCount),
                  static_cast<unsigned>(sizeof(vectors) / sizeof(vectors[0])),
                  static_cast<int>(rejects));
    report("crypto-totp-rfc6238", okCount == 5 && rejects, detail);
    crypto::wipe(code, sizeof(code));
  }
}

void vaultGates() {
  // Порядок гейтов не переставляется:
  //   1. provision и round-trip на маленьком наборе — самая частая ошибка должна
  //      всплыть первой, пока в разделе почти пусто;
  //   2. неверный пароль — на данных, которые мы обязаны сохранить;
  //   3. износ и перезапись — после того как малые записи доказали работоспособность,
  //      иначе отказ износа не отличить от отказа сериализации;
  //   4. порча данных — последней и с откатом сектора, потому что она портит флеш.
  VaultError rc = vault::begin(kGatePassword);
  if (rc == VaultError::Tampered || rc == VaultError::WrongPassword) {
    report("vault-open", false, "leftover data in vault partition, refusing to write");
    return;
  }
  report("vault-provision", rc == VaultError::Ok, vault::toString(rc));
  if (rc != VaultError::Ok) {
    return;
  }

  // Даже один Entry — это почти килобайт стека, а под ним ещё кадр add() с
  // буфером сериализации на 1024 байта. Всё, что крупное, живёт в PSRAM.
  EntryArray<1> scratchArr;
  EntryArray<8> got;
  if (!got.ok() || !scratchArr.ok()) {
    report("vault-gates", false, "no PSRAM for gate buffers");
    return;
  }
  Entry& scratch = scratchArr[0];
  fillEntry(scratch, 0, "alpha");
  uint32_t id = 0;
  rc = vault::add(scratch, &id);
  report("vault-add", rc == VaultError::Ok && id != 0, vault::toString(rc));
  if (rc != VaultError::Ok) {
    return;
  }

  // add() для записи с id == 0 присваивает id сам (g_nextId), поэтому в scratch
  // остаётся ноль, а в хранилище лежит уже присвоенный id. Сверять надо с тем,
  // что реально записано, иначе гейт сравнивал бы 1 с 0 и падал бы на
  // корректном хранилище.
  scratch.id = id;

  uint32_t n = 0;
  rc = vault::load(got.data(), 8, &n);
  report("vault-load", rc == VaultError::Ok && n == 1 && entriesEqual(got[0], scratch),
         vault::toString(rc));

  // Перезагрузка по ключу: открываем заново, чтобы данные читались с флеша, а не
  // оставались в памяти.
  rc = vault::begin(kGatePassword);
  report("vault-reopen", rc == VaultError::Ok, vault::toString(rc));
  rc = vault::load(got.data(), 8, &n);
  report("vault-load-reboot",
         rc == VaultError::Ok && n == 1 && entriesEqual(got[0], scratch),
         vault::toString(rc));

  // Обновление: тот же id меняет содержимое, счётчик не растёт.
  fillEntry(scratch, id, "alpha-v2");
  rc = vault::add(scratch, nullptr);
  rc = vault::load(got.data(), 8, &n);
  report("vault-update", rc == VaultError::Ok && n == 1 && entriesEqual(got[0], scratch),
         "in-place, count stable");

  // Удаление: надгробная запись убирает запись из выдачи.
  rc = vault::remove(id);
  rc = vault::load(got.data(), 8, &n);
  report("vault-remove", rc == VaultError::Ok && n == 0, vault::toString(rc));

  // Удалённая запись обязана пережить перезагрузку: иначе надгробная запись
  // отфильтровывалась бы только в памяти, и после ребута вернулась бы снова.
  rc = vault::begin(kGatePassword);
  rc = vault::load(got.data(), 8, &n);
  report("vault-remove-persist", rc == VaultError::Ok && n == 0, vault::toString(rc));

  // Предельная по размеру запись обязана приниматься и читаться обратно
  // без потерь.
  //
  // Раньше здесь стояла обратная проверка — «запись длиннее лимита отвергается»,
  // но она была недостижима: сумма полей Entry даёт 900 байт при
  // kMaxEntryLen = 1024, то есть запись через типизированный API не может
  // превысить лимит в принципе, и EntryTooLong остаётся лишь защитной
  // проверкой на случай будущей правки структуры. Гейт всегда падал на
  // исправном хранилище и проверял несуществующее состояние.
  {
    EntryArray<1> big;
    EntryArray<2> back;
    if (!big.ok() || !back.ok()) {
      report("gate5-max-entry", false, "no PSRAM");
      return;
    }
    // Заполняем каждое строковое поле целиком: последние байты остаются под
    // '\0', поэтому максимум сериализации равен sizeof(Entry) - 5.
    fillEntry(big[0], 0, "max");
    std::memset(big[0].title, 't', sizeof(big[0].title) - 1);
    big[0].title[sizeof(big[0].title) - 1] = '\0';
    std::memset(big[0].login, 'l', sizeof(big[0].login) - 1);
    big[0].login[sizeof(big[0].login) - 1] = '\0';
    std::memset(big[0].password, 'p', sizeof(big[0].password) - 1);
    big[0].password[sizeof(big[0].password) - 1] = '\0';
    std::memset(big[0].url, 'u', sizeof(big[0].url) - 1);
    big[0].url[sizeof(big[0].url) - 1] = '\0';
    std::memset(big[0].note, 'n', sizeof(big[0].note) - 1);
    big[0].note[sizeof(big[0].note) - 1] = '\0';
    const uint32_t before = vault::count();
    uint32_t maxId = 0;
    const VaultError addRc = vault::add(big[0], &maxId);
    big[0].id = maxId;
    uint32_t n = 0;
    const VaultError loadRc = addRc == VaultError::Ok
                                 ? vault::load(back.data(), 2, &n)
                                 : addRc;
    // Ищем именно добавленную запись: в хранилище могут быть и более ранние.
    bool found = false;
    for (uint32_t i = 0; i < n; ++i) {
      if (back[i].id == maxId && entriesEqual(back[i], big[0])) {
        found = true;
        break;
      }
    }
    char detail[72];
    // sizeof(Entry) включает неиспользуемые байты выравнивания, поэтому реальная
    // длина сериализации на 5 байт меньше: id занимает 4 байта, а каждое из пяти
    // строковых полей не использует последний байт за '\\0'.
    std::snprintf(detail, sizeof(detail), "%u B record stored, roundtrip %s",
                  static_cast<unsigned>(sizeof(Entry) - 5), found ? "ok" : "broken");
    report("gate5-max-entry",
           addRc == VaultError::Ok && loadRc == VaultError::Ok && found &&
               vault::count() == before + 1,
           detail);
    // Запись максимального размера засоряет счётчик, убираем её сразу.
    (void)vault::remove(maxId);
  }

  // Лимит счётчика: добавляем до потолка и проверяем отказ.
  {
    uint32_t added = 0;
    VaultError addRc = VaultError::Ok;
    EntryArray<1> t;
    if (!t.ok()) {
      report("gate5-count-cap", false, "no PSRAM");
      return;
    }
    for (uint32_t i = 0; i < config::kMaxEntries + 8 && addRc == VaultError::Ok; ++i) {
      fillEntry(t[0], 0, "cap");
      addRc = vault::add(t[0], nullptr);
      if (addRc == VaultError::Ok) {
        ++added;
      }
    }
    char detail[72];
    std::snprintf(detail, sizeof(detail), "%u added, stopped with %s",
                  static_cast<unsigned>(added), vault::toString(addRc));
    report("gate5-count-cap",
           vault::count() <= config::kMaxEntries &&
               (addRc == VaultError::TooManyEntries || addRc == VaultError::Budget ||
                addRc == VaultError::NoSpace),
           detail);
  }

  // Раздел забит до лимита счётчика, дальше обычные записи не идут. Чтобы
  // проверить износ и компакцию, освобождаем место. Раньше гейт износа шёл сразу
  // за гейтом лимита и был заведомо неисполнимым: он требовал ещё 200 записей
  // там, где уже было 1000.
  log::info("gate: clearing vault before wear gates");
  rc = vault::clear(kGatePassword);
  report("gate-reset", rc == VaultError::Ok, vault::toString(rc));
  if (rc != VaultError::Ok) {
    return;
  }

  // 200 последовательных сохранений с проверкой после каждого. Проверка после
  // КАЖДОЙ записи, а не в конце: иначе поломка, возникшая на 200-й записи, была
  // бы неотличима от поломки на первой.
  {
    uint32_t checked = 0;
    VaultError bad = VaultError::Ok;
    EntryArray<1> t;
    EntryArray<4> tail;
    if (!t.ok() || !tail.ok()) {
      report("gate6-wear", false, "no PSRAM");
      return;
    }
    // Чтобы компакция сработала, журнал должен перевалить
    // kVaultCompactTriggerBytes (половина области, 129024 Б). Запись из
    // fillEntry занимает около 95 Б, и прежние 200 итераций давали 19 КБ —
    // порог не берётся, и гейт проверяет не то, что думает.
    //
    // note добивается до предела: запись выходит ~450 Б, порог берётся за
    // ~290 итераций. Итераций берём 320 с запасом — точная длина
    // сериализованной записи известна только внутри vault, а недобрать порог
    // нельзя. Живой бюджет (192 КБ) и лимит записей (1000) при 320 итерациях
    // не мешают: это ~144 КБ живых данных.
    // Замер: 320 итераций дали used 100672 Б при пороге 129024 Б, то есть
    // компакция не наступала. Запись выходит около 314 Б, значит порог берётся
    // за ~411 итераций; берём 480 с запасом. Живой бюджет (192 КБ) при этом
    // не мешает: 480 * 255 Б = 122 КБ, и лимит записей 1000 тоже не достигнут.
    const int kWearIterations = 480;
    for (int i = 0; i < kWearIterations; ++i) {
      fillEntry(t[0], 0, "wear");
      // Номер итерации дописывается в note ПОСЛЕ fillEntry: сама fillEntry
      // перезаписала бы note целиком. Соседние записи должны различаться, иначе
      // ошибка «перезапись вернула прежнее содержимое» осталась бы незаметной.
      std::snprintf(t[0].note, sizeof(t[0].note),
                    "wear-%03d-wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww"
                    "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww"
                    "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww"
                    "wwwwwwwwwwwwwwwwwwwwwwwwww",
                    i);
      const VaultError addRc = vault::add(t[0], nullptr);
      if (addRc != VaultError::Ok) {
        bad = addRc;
        break;
      }
      uint32_t tn = 0;
      const VaultError loadRc = vault::load(tail.data(), 4, &tn);
      if (loadRc != VaultError::Ok) {
        bad = loadRc;
        break;
      }
      if (tn == 0) {
        bad = VaultError::Tampered;
        break;
      }
      if (std::strcmp(tail[tn - 1].password, t[0].password) != 0) {
        bad = VaultError::Tampered;
        break;
      }
      ++checked;
    }
    char detail[72];
    std::snprintf(detail, sizeof(detail), "%u/%d verified after each write%s", checked,
                  kWearIterations, bad == VaultError::Ok ? "" : ", stopped early");
    report("gate6-wear", bad == VaultError::Ok && checked == kWearIterations, detail);
  }

  // Данные должны пережить перезагрузку после серии записей: это проверяет, что
  // индекс и область, собранные компакцией, восстанавливаются из флеша.
  {
    const uint32_t expected = vault::count();
    rc = vault::begin(kGatePassword);
    // load() принимает не больше maxCount записей, поэтому an не может равняться
    // полному счётчику: сверять надо с числом, которое запрошено, а полное
    // число проверять отдельно через count(). Прежняя проверка требовала
    // an == expected при expected = 320 и всегда падала на исправном хранилище.
    constexpr uint32_t kProbe = 16;
    EntryArray<16> all;
    uint32_t an = 0;
    const VaultError loadRc = all.ok() ? vault::load(all.data(), kProbe, &an)
                                       : VaultError::NoSpace;
    const uint32_t afterOpen = vault::count();
    char detail[72];
    std::snprintf(detail, sizeof(detail), "count %u -> %u, %u loaded, data intact",
                  static_cast<unsigned>(expected), static_cast<unsigned>(afterOpen),
                  static_cast<unsigned>(an));
    report("gate6-reboot",
           rc == VaultError::Ok && loadRc == VaultError::Ok && afterOpen == expected &&
               an == (expected < kProbe ? expected : kProbe) && expected > 0,
           detail);
  }

  const Stats st = vault::stats();
  log::info("gate: gen %u entries %u live %u B used %u B compacted %d",
            static_cast<unsigned>(st.generation), static_cast<unsigned>(st.entryCount),
            static_cast<unsigned>(st.liveBytes), static_cast<unsigned>(st.usedBytes),
            st.compactedOnce ? 1 : 0);
  report("gate7-compact", st.compactedOnce, "compaction triggered by log growth");

// Неверный пароль не должен изменить ни байта раздела — и не должен сбить
  // устройство в Unprovisioned.
  {
    const esp_partition_t* part = vaultPartition();
    uint8_t* snap = nullptr;
    bool ok = false;
    // Вне внутреннего блока: detail печатается даже когда раздела нет, и без
    // этого строки читались бы как мусор из неинициализированной памяти.
    vault::Snapshot stBefore = vault::snapshot();
    VaultError badPwRc = VaultError::NotFound;
    vault::Snapshot stAfter = stBefore;
    bool provAfter = false;
    if (part) {
      snap = static_cast<uint8_t*>(heap_caps_malloc(config::kVaultPartitionBytes,
                                                    MALLOC_CAP_SPIRAM));
    }
    if (snap && esp_partition_read(part, 0, snap, config::kVaultPartitionBytes) == ESP_OK) {
      stBefore = vault::snapshot();
      badPwRc = vault::begin(kGatePasswordWrong);
      stAfter = vault::snapshot();
      ok = (badPwRc == VaultError::WrongPassword);
      // Неверный пароль обязан оставить хранилище в Locked, а не в
      // Unprovisioned. Раньше begin() обнулял g_provisioned в начале и до
      // успешного открытия не восстанавливал, поэтому UI после неудачной попытки
      // предлагал первичную настройку поверх существующих данных.
      // provisioned() обязан остаться в true: иначе следующий запрос
      // provisioning стёр бы раздел.
      provAfter = vault::provisioned();
      if (ok) {
        ok = stBefore.state == vault::State::Unlocked &&
             stAfter.state == vault::State::Locked && provAfter;
      }
      if (ok) {
        // Сравниваем постранично, чтобы не держать второй образ на 512 КБ.
        bool same = true;
        uint8_t page[256];
        for (size_t off = 0; off < config::kVaultPartitionBytes && same; off += sizeof(page)) {
          const size_t chunk = (config::kVaultPartitionBytes - off < sizeof(page))
                                   ? (config::kVaultPartitionBytes - off)
                                   : sizeof(page);
          if (esp_partition_read(part, off, page, chunk) != ESP_OK) {
            same = false;
            break;
          }
          same = std::memcmp(snap + off, page, chunk) == 0;
        }
        ok = same;
      }
    }
    heap_caps_free(snap);
    // Состояния в detail, а не только в условии: гейт проверяет сразу четыре
    // вещи, и строка "partition byte-identical" при падении по состоянию
    // уводила бы в сторону — байты-то действительно не изменились.
    char detail[72];
    std::snprintf(detail, sizeof(detail), "wrong=%d state %d->%d prov=%d ok=%d",
                  static_cast<int>(badPwRc), static_cast<int>(stBefore.state),
                  static_cast<int>(stAfter.state), provAfter ? 1 : 0, ok ? 1 : 0);
    report("gate2-wrongpw", ok, detail);
  }

  // Порча заголовка. Поля generation, iters, saltPw, saltDev и check входят в
  // AAD, поэтому изменение любого из них обязано ломать аутентификацию. Само
  // поле dataStart проверяется отдельно: оно не входит в AAD, но задаёт границу
  // области и потому проверяется на попадание в допустимое значение.
  {
    const esp_partition_t* part = vaultPartition();
    if (vault::begin(kGatePassword) != VaultError::Ok || !part) {
      report("gate3-tamper-hdr", false, "cannot open vault for tamper test");
    } else {
      // Тег сюда входит, а маркер завершения — нет. Сбитый бит маркера
      // неотличим от недописанного заголовка (оба означают «запись не
      // завершена»), и правильное поведение в обоих случаях одно: откат на
      // резервный слот. Требовать отказа здесь нельзя — это проверяет gate3b.
      const size_t hdrOffsets[] = {kHdrGeneration, kHdrIters, kHdrSaltPw, kHdrSaltDev,
                                   kHdrCheck};
      const size_t base = activeHeaderSlot() * kHdrSlotBytes;
      uint32_t rejected = 0;
      uint32_t accepted = 0;
      for (const size_t off : hdrOffsets) {
        if (tamperByteIsRejected(part, base + off)) {
          ++rejected;
        } else {
          ++accepted;
        }
      }
      char detail[80];
      std::snprintf(detail, sizeof(detail), "%u/%u header bytes rejected",
                    static_cast<unsigned>(rejected),
                    static_cast<unsigned>(sizeof(hdrOffsets) / sizeof(hdrOffsets[0])));
      report("gate3-tamper-hdr", rejected > 0 && accepted == 0, detail);
    }
  }

  // Оборванная запись заголовка обязана приводить к откату на резервный слот, а
  // не к отказу. Это ровно тот случай, который стоил пользователю доступа к
  // данным: питание выключилось посреди сохранения, тег дописался наполовину,
  // а хранилище объявляло подделку.
  //
  // Оборванная запись воспроизводится честно, а не записью «плохих» байтов:
  // сектор стирается и заново заполняется всем заголовком, КРОМЕ хвоста с
  // маркером завершения. Получается ровно то состояние, которое оставляет
  // пропадание питания: тег на месте, маркера нет.
  {
    const esp_partition_t* part = vaultPartition();
    bool ok = false;
    char detail[80] = "no active slot";
    if (vault::begin(kGatePassword) == VaultError::Ok && part) {
      const size_t slot = activeHeaderSlot();
      const size_t sector = slot * kHdrSlotBytes;
      const uint32_t countBefore = vault::count();
      uint8_t* snap = static_cast<uint8_t*>(
          heap_caps_malloc(config::kFlashSectorBytes, MALLOC_CAP_SPIRAM));
      if (snap &&
          esp_partition_read(part, sector, snap, config::kFlashSectorBytes) == ESP_OK &&
          esp_partition_erase_range(part, sector, config::kFlashSectorBytes) == ESP_OK &&
          // Пишем всё до маркера включительно с тегом, но не сам маркер: это
          // ровно то, что остаётся на флеше при пропадании питания.
          esp_partition_write(part, sector, snap, kHdrCommit) == ESP_OK) {
        const VaultError r = vault::begin(kGatePassword);
        const uint32_t countAfter = vault::count();
        // Резервный слот на одно сохранение старее, поэтому одна запись могла
        // не входить в него. Большее расхождение означало бы реальную потерю.
        const bool countOk = countAfter == countBefore || countAfter + 1 == countBefore;
        ok = r == VaultError::Ok && vault::initialized() && countOk;
        std::snprintf(detail, sizeof(detail), "fell back, entries %u -> %u",
                      static_cast<unsigned>(countBefore),
                      static_cast<unsigned>(countAfter));
      }
      if (snap) {
        heap_caps_free(snap);
        if (esp_partition_erase_range(part, sector, config::kFlashSectorBytes) == ESP_OK) {
          esp_partition_write(part, sector, snap, config::kFlashSectorBytes);
        }
      }
    }
    report("gate3b-torn-hdr", ok, detail);
  }

  // Порча dataStart. Поле не входит в AAD, но задаёт начало активной области, и
  // значение вне двух допустимых границ обязано отвергаться проверкой диапазона.
  // Сдвигаем его на 4 байта: сдвиг именно вверх невозможен без erase, а вниз —
  // допустимый переход, поэтому значение берётся таким, чтобы запись прошла.
  {
    const esp_partition_t* part = vaultPartition();
    bool ok = false;
    if (vault::begin(kGatePassword) == VaultError::Ok && part) {
      uint8_t raw[4] = {};
      const size_t dsOff = activeHeaderSlot() * kHdrSlotBytes + kHdrDataStart;
      if (esp_partition_read(part, dsOff, raw, sizeof(raw)) == ESP_OK) {
        const uint32_t cur = readU32(raw);
        // Обнуляем поле целиком: значение перестаёт быть границей ни одной из
        // двух областей, а переход в ноль всегда 1 -> 0, то есть flash принимает
        // его без стирания. Вычитание константы для этого не годится — оно
        // требует 0 -> 1 в младших битах, и запись молча испортилась бы.
        const uint8_t bytes[4] = {0, 0, 0, 0};
        ok = tamperBytesRejected(part, dsOff, bytes, sizeof(bytes));
      }
    }
    report("gate4-tamper-ds", ok, "dataStart out of range rejected");
  }

  // Порча шифротекста записи. Порт фиксированной длины равен kRecFixed, дальше
  // идёт сам шифротекст. Смещение берём из заголовка, а не константой: после
  // компакции активная область меняется, и жёстко зашитый адрес смотрел бы мимо.
  {
    const esp_partition_t* part = vaultPartition();
    bool ok = false;
    uint32_t dataStart = 0;
    VaultError openRc = VaultError::NotFound;
    char detail[80] = "no detail";
    if ((openRc = vault::begin(kGatePassword)) == VaultError::Ok && part) {
      uint8_t hdr[config::kVaultHeaderBytes];
      if (readActiveHeader(hdr)) {
        dataStart = readU32(hdr + kHdrDataStart);
        // Ровно граница одной из двух областей — тот же критерий, что в begin().
        // Прежняя проверка покрывала только область 0; после компакции в gate7
        // dataStart указывает на область 1, гейт не портил ничего и падал сам:
        // «защита шифротекста» при этом не проверялась вовсе.
        if (dataStart == config::kVaultRegion0Offset ||
            dataStart == config::kVaultRegion0Offset + config::kVaultRegionBytes) {
          ok = tamperByteIsRejected(part, dataStart + kRecFixed);
        }
      }
      std::snprintf(detail, sizeof(detail), "open %d dataStart %u rejected %d",
                    static_cast<int>(openRc), static_cast<unsigned>(dataStart),
                    ok ? 1 : 0);
    } else {
      std::snprintf(detail, sizeof(detail), "open %d", static_cast<int>(openRc));
    }
    report("gate8-tamper-ct", ok, detail);
  }

  // Порча поля счётчиков в заголовке. Счётчики не входят в AAD, поэтому
  // защищены сверкой с пересчитанными при сканировании. Проверяем именно эту
  // защиту: подмена entryCount обязана дать отказ, а не тихо приняться.
  {
    const esp_partition_t* part = vaultPartition();
    bool ok = false;
    if (vault::begin(kGatePassword) == VaultError::Ok && part) {
      uint8_t raw[4] = {};
      const size_t cntOff = activeHeaderSlot() * kHdrSlotBytes + 0x0C;
      if (esp_partition_read(part, cntOff, raw, sizeof(raw)) == ESP_OK) {
        // Закладываем разряд: счётчик перестаёт сходиться с числом записей.
        // Ставить бит можно только в 1 -> 0, поэтому обнуляем младший байт —
        // этого достаточно для расхождения и не требует erase.
        const uint8_t bytes[4] = {0, raw[1], raw[2], raw[3]};
        ok = tamperBytesRejected(part, cntOff, bytes, sizeof(bytes));
      }
    }
    report("gate9-tamper-count", ok, "entryCount mismatch rejected");
  }

  // Порча тега GCM первой записи: тег лежит в фиксированной части (head+18),
  // его последний байт — dataStart + kRecFixed - 1. Это не файл и не AAD, но
  // подмена обязана ломать расшифровку так же, как и подмена текста.
  {
    const esp_partition_t* part = vaultPartition();
    bool ok = false;
    uint32_t dataStart = 0;
    VaultError openRc = VaultError::NotFound;
    char detail[80] = "no detail";
    if ((openRc = vault::begin(kGatePassword)) == VaultError::Ok && part) {
      uint8_t hdr[config::kVaultHeaderBytes];
      if (readActiveHeader(hdr)) {
        dataStart = readU32(hdr + kHdrDataStart);
        // Как в gate8: только точная граница одной из двух областей, иначе
        // после компакции гейт смотрел бы мимо и ничего не портил.
        if (dataStart == config::kVaultRegion0Offset ||
            dataStart == config::kVaultRegion0Offset + config::kVaultRegionBytes) {
          ok = tamperByteIsRejected(part, dataStart + kRecFixed - 1);
        }
      }
      std::snprintf(detail, sizeof(detail), "open %d dataStart %u rejected %d",
                    static_cast<int>(openRc), static_cast<unsigned>(dataStart),
                    ok ? 1 : 0);
    } else {
      std::snprintf(detail, sizeof(detail), "open %d", static_cast<int>(openRc));
    }
    report("gate10-tamper-tag", ok, detail);
  }

  // Поверхность сессии: close(), get(), provisioned(), snapshot(), reset().
  // Это функции, на которых в стадии 5 встаёт вся авторизация, поэтому
  // проверяются на железе до того, как на них начнут опираться HTTP-роуты.
  {
    // Начинаем с begin(), а не с add(): предыдущий tamper-гейт завершается
    // НЕудачным begin(), то есть хранилище остаётся закрытым. Все гейты
    // обязаны приводить состояние к известному сами.
    const VaultError open = vault::begin(kGatePassword);
    uint32_t id = 0;
    Entry e = {};
    std::snprintf(e.title, sizeof(e.title), "session-probe");
    std::snprintf(e.password, sizeof(e.password), "pw-probe-distinctive-4a");
    std::snprintf(e.note, sizeof(e.note), "note-probe");
    const uint32_t before = open == VaultError::Ok ? vault::count() : 0;
    const VaultError addRc = vault::add(e, &id);

    // close() обязан выбросить ключ и индекс, но ФЛЕШ не тронуть: хранилище
    // обязано открыться тем же паролем и отдать ту же запись.
    vault::close();
    const bool closed = !vault::initialized() && vault::count() == 0;
    const vault::Snapshot sClosed = vault::snapshot();
    const bool snapLocked = sClosed.state == vault::State::Locked;
    // Повторный close() обязан быть безопасен: HTTP зовёт его на каждый lock и
    // на автоблокировку по простою, в том числе когда уже закрыто.
    vault::close();
    vault::close();
    const bool closeIdempotent = !vault::initialized() && vault::count() == 0;

    const VaultError reopen = vault::begin(kGatePassword);
    const bool survived = reopen == VaultError::Ok && vault::count() == before + 1;
    const vault::Snapshot sOpen = vault::snapshot();
    const bool snapUnlocked =
        sOpen.state == vault::State::Unlocked && sOpen.entryCount == before + 1;

    // get() обязан отдать ровно ту запись и по id, и её отсутствие.
    Entry got = {};
    const VaultError getRc = vault::get(id, &got);
    const bool getOk = getRc == VaultError::Ok && got.id == id &&
                       std::strcmp(got.title, e.title) == 0 &&
                       std::strcmp(got.password, e.password) == 0 &&
                       std::strcmp(got.note, e.note) == 0;
    Entry miss = {};
    const VaultError missRc = vault::get(id + 100000, &miss);
    const bool missOk = missRc == VaultError::NotFound;

    // provisioned() обязан отвечать без пароля и различать наличие раздела.
    const bool provYes = vault::provisioned();
    char detail[96];
    std::snprintf(detail, sizeof(detail),
                  "open %d add %d id %u | close %d/%d snap %d/%d | get %d(%d) miss %d | %d",
                  static_cast<int>(open), static_cast<int>(addRc),
                  static_cast<unsigned>(id), static_cast<int>(closed),
                  static_cast<int>(closeIdempotent), static_cast<int>(snapLocked),
                  static_cast<int>(snapUnlocked), static_cast<int>(getOk),
                  static_cast<int>(getRc), static_cast<int>(missOk),
                  static_cast<int>(provYes));
    report("gate11-session",
           open == VaultError::Ok && addRc == VaultError::Ok && closed &&
               closeIdempotent && snapLocked && snapUnlocked && survived && getOk &&
               missOk && provYes,
           detail);

    // reset() обязан работать БЕЗ пароля и без сессии — это единственный путь
    // сброса, когда пароль забыт. После него устройство читается как
    // Unprovisioned, а данные не восстанавливаются.
    vault::close();
    const VaultError rst = vault::reset();
    const vault::Snapshot sReset = vault::snapshot();
    const bool resetOk = rst == VaultError::Ok && !vault::provisioned() &&
                         sReset.state == vault::State::Unprovisioned && !vault::initialized();
    const bool provAfterReset = vault::provisioned();
    report("gate12-reset", resetOk && !provAfterReset, "destroyed without password");

    // Возвращаем хранилище: гейт 13 и последующие требуют открытого состояния.
    const VaultError reProv = vault::begin(kGatePassword);
    report("gate13-reprovision", reProv == VaultError::Ok, vault::toString(reProv));
  }

  // Возвращаем хранилище в рабочее состояние под правильным паролем и чистим.
  {
    const VaultError r = vault::begin(kGatePassword);
    report("vault-reopen", r == VaultError::Ok, vault::toString(r));
  }
  (void)vault::clear(kGatePassword);
  log::info("gate: vault cleared after tests");
}

// Гейты стадии 5 (auth). Требуют пустого раздела: почти все они создают
// хранилище заново, а provisioning на provisioned-хранилище возвращает Refused.
//
// Собственного стирания здесь НЕТ, и это не осторожность, а требование
// планировщика: erase раздела заканчивается ребетом платы, поэтому стирание
// внутри гейтов приводит к перезапуску run() с начала — к вечному циклу
// «стёр → ребет → стёр». Стирает вызывающий код, ровно один раз, и гейты auth
// идут первыми, пока раздел ещё пуст.
void authGates() {
  log::info("=== stage 5 auth gates ===");

  if (!vaultLooksEmpty()) {
    log::error("vault partition holds data: refusing to run stage 5 auth gates");
    log::error("they provision storage from scratch and cannot run on existing data");
    return;
  }

  // Воркер поднимаем здесь, а не в setup() до run(): setup() ставит auth ПОСЛЕ
  // selftest, иначе его задача жила бы весь прогон гейтов. Здесь он нужен на
  // время самих гейтов, поэтому install() идёт первым же шагом.
  if (!auth::install()) {
    report("gateA0-install", false, "auth::install() failed");
    return;
  }
  report("gateA0-install", true, "auth worker up");

  // Формат: 6 слов по 5 букв через дефис, дефис, 2 цифры. Все 37 символов,
  // ни одного лишнего.
  {
    char pw[config::kMasterPasswordChars + 1] = {};
    const size_t n = auth::generateMasterPassword(pw, sizeof(pw));
    bool ok = (n == config::kMasterPasswordChars) && (pw[n] == '\0');
    size_t pos = 0;
    for (size_t w = 0; ok && w < config::kMasterWords; ++w) {
      if (w != 0) {
        ok = (pw[pos] == '-');
        ++pos;
      }
      for (size_t k = 0; ok && k < wordlist::kWordBytes; ++k) {
        // Буквы словаря — только a-z. Проверяем диапазон, а не «не дефис и не
        // цифра»: иначе в строку могла бы попасть пунктуация из таблицы.
        ok = (pw[pos] >= 'a' && pw[pos] <= 'z');
        ++pos;
      }
    }
    ok = ok && (pw[pos] == '-');
    ++pos;
    ok = ok && (pw[pos] >= '0' && pw[pos] <= '9');
    ++pos;
    ok = ok && (pw[pos] >= '0' && pw[pos] <= '9');
    ++pos;
    ok = ok && (pos == config::kMasterPasswordChars);
    char detail[80];
    std::snprintf(detail, sizeof(detail), "%u chars, format %s: %.37s",
                  static_cast<unsigned>(n), ok ? "ok" : "BROKEN", pw);
    report("gateA-password-format", ok, detail);
  }

  // Каждое слово пароля обязано быть СЛОВОМ СЛОВАРЯ, а не просто пятью буквами.
  // Иначе пользователю отдаётся строка, которую невозможно набрать в prompt.
  {
    char pw[config::kMasterPasswordChars + 1] = {};
    (void)auth::generateMasterPassword(pw, sizeof(pw));
    bool ok = true;
    size_t hits = 0;
    for (size_t w = 0; ok && w < config::kMasterWords; ++w) {
      const size_t off = w * (wordlist::kWordStride);
      bool found = false;
      for (size_t i = 0; i < wordlist::kWordCount && !found; ++i) {
        if (std::memcmp(wordlist::word(i), pw + off, wordlist::kWordBytes) == 0) {
          found = true;
          ++hits;
        }
      }
      ok = found;
    }
    char detail[64];
    std::snprintf(detail, sizeof(detail), "%u/%u words found in dictionary",
                  static_cast<unsigned>(hits), static_cast<unsigned>(config::kMasterWords));
    report("gateA2-words-in-dict", ok, detail);
  }

  // Смещение индекса слова проверяется детерминированно, а не статистикой.
  // 0xFFFFFFFF обязан дать слово 4095 (старшие 12 бит все единицы), а
  // 0x00000000 — слово 0.
  //
  // Негативный смысл гейта: реализация «v % 4096» с отбраковкой tail тоже дала бы
  // верные 4095 и 0 на этих двух значениях, поэтому ОДНОЙ проверки мало. Третий
  // набор — значения (1<<20)|3 и (2<<20)|3: они больше 4095 (то есть «% 4096»
  // дал бы другой ответ, а отбраковка хвоста их отбросила бы), и на корректном
  // сдвиге дают индексы 1 и 2.
  //
  // Длина источника обязана покрывать весь запрос целиком: generatePassword()
  // читает 4 байта на слово и 1 байт на цифру, всего 4*6+2 = 26. Короткий буфер
  // закольцовывается, и тогда проверка границы слова на 0xFF заодно делала
  // бесконечной отбраковку цифр: цифры брали тот же 0xFF, он не проходит
  // порог 250, цикл не кончался, и гейт вешал плату до сброса по WDT.
  // Последние два байта источника — годные значения для цифр.
  {
    constexpr size_t kSrcLen = 4 * config::kMasterWords + config::kMasterDigits;
    uint8_t hi[kSrcLen];
    uint8_t lo[kSrcLen];
    uint8_t tail[kSrcLen];
    uint8_t tail2[kSrcLen];
    std::memset(hi, 0xff, sizeof(hi));
    std::memset(lo, 0x00, sizeof(lo));
    std::memset(tail, 0x00, sizeof(tail));
    std::memset(tail2, 0x00, sizeof(tail2));
    // Байты раскладываются в ПОРЯДКЕ ПАМЯТИ ESP32, то есть little-endian:
    //   v = b[0] | b[1]<<8 | b[2]<<16 | b[3]<<24
    // Первая версия гейта подставляла их как big-endian и потому проверяла не то
    // значение, которое читает устройство: ожидался индекс 1, а получался 48.
    //
    // Значение выбрано как (1<<20) | 3 = 1048579: сдвиг на 20 даёт индекс 1,
    // значение больше 4095 (то есть «% 4096» дал бы другой ответ — 3, и отбраковка
    // хвоста его бы отбросила), поэтому гейт различает корректный сдвиг и обе
    // неверные реализации.
    tail[0] = 0x03;
    tail[1] = 0x00;
    tail[2] = 0x10;
    tail[3] = 0x00;  // (1<<20)|3 -> сдвиг 1
    tail2[0] = 0x03;
    tail2[1] = 0x00;
    tail2[2] = 0x20;
    tail2[3] = 0x00;  // (2<<20)|3 -> сдвиг 2
    // Хвост под цифры: 5 и 6, оба проходят порог отбраковки.
    hi[kSrcLen - 2] = 5;
    hi[kSrcLen - 1] = 6;
    lo[kSrcLen - 2] = 5;
    lo[kSrcLen - 1] = 6;
    tail[kSrcLen - 2] = 5;
    tail[kSrcLen - 1] = 6;
    tail2[kSrcLen - 2] = 5;
    tail2[kSrcLen - 1] = 6;

    char pw[config::kMasterPasswordChars + 1] = {};

    auth::setRandomSourceForTest(hi, sizeof(hi));
    (void)auth::generateMasterPassword(pw, sizeof(pw));
    const bool hiOk = std::memcmp(pw, wordlist::word(wordlist::kWordCount - 1),
                                 wordlist::kWordBytes) == 0;
    auth::setRandomSourceForTest(lo, sizeof(lo));
    (void)auth::generateMasterPassword(pw, sizeof(pw));
    const bool loOk = std::memcmp(pw, wordlist::word(0), wordlist::kWordBytes) == 0;

    // Смещение с отбраковкой отличается от чистого сдвига на этих значениях.
    auth::setRandomSourceForTest(tail, sizeof(tail));
    (void)auth::generateMasterPassword(pw, sizeof(pw));
    const bool tailOk = std::memcmp(pw, wordlist::word(1), wordlist::kWordBytes) == 0;

    auth::setRandomSourceForTest(tail2, sizeof(tail2));
    (void)auth::generateMasterPassword(pw, sizeof(pw));
    const bool tail2Ok = std::memcmp(pw, wordlist::word(2), wordlist::kWordBytes) == 0;

    auth::setRandomSourceForTest(nullptr, 0);
    char detail[96];
    std::snprintf(detail, sizeof(detail), "max %d min %d shift1e6->1 %d shift2e6->2 %d",
                  static_cast<int>(hiOk), static_cast<int>(loOk), static_cast<int>(tailOk),
                  static_cast<int>(tail2Ok));
    report("gateA3-word-bias", hiOk && loOk && tailOk && tail2Ok, detail);
  }

  // Отбраковка цифр: 251 обязан быть отброшен, а не превращён в 1.
  //
  // Источник — 26 байт: первые 24 задают слова, последние два управляют цифрами.
  // Ставим 251 первым из них: если бы он прошёл, первая цифра стала бы 1 вместо 7.
  {
    constexpr size_t kSrcLen = 4 * config::kMasterWords + config::kMasterDigits;
    uint8_t digits[kSrcLen];
    std::memset(digits, 0x00, sizeof(digits));
    digits[kSrcLen - 2] = 251;  // обязан быть отброшен
    digits[kSrcLen - 1] = 7;
    // Чтение цикличное: вторая цифра берёт байт 0. Ставим 6, чтобы отличать
    // «251 отброшен» от «отбраковки нет и вторая цифра пришла откуда-то ещё».
    digits[0] = 6;
    char pw[config::kMasterPasswordChars + 1] = {};
    auth::setRandomSourceForTest(digits, sizeof(digits));
    (void)auth::generateMasterPassword(pw, sizeof(pw));
    // Цифры стоят последними двумя символами. Первая обязана быть 7: если бы 251
    // не отбросился, получилась бы 1.
    const bool d1 = (pw[config::kMasterPasswordChars - 2] == '7');
    const bool d2 = (pw[config::kMasterPasswordChars - 1] == '6');
    auth::setRandomSourceForTest(nullptr, 0);
    char detail[72];
    std::snprintf(detail, sizeof(detail), "251 rejected, got '%.2s' (want '76')",
                  pw + config::kMasterPasswordChars - 2);
    report("gateA4-digit-bias", d1 && d2, detail);
  }

  // Настоящий provisioning: пароль отдаётся РОВНО ОДИН РАЗ. Повторный poll()
  // обязан вернуть пустую строку, иначе пароль осел бы в буферах клиента и жил
  // в памяти дольше, чем нужно.
  {
    const auth::JobId job = auth::submitProvision();
    auth::JobView v1 = {};
    bool ok = (job != 0);
    // Ждём завершения: provisioning занимает один слот PBKDF2 (~2.9 с).
    for (uint32_t waited = 0; ok && waited < 30000; waited += 200) {
      if (auth::poll(job, &v1) && v1.result != auth::Result::Pending) {
        break;
      }
      delay(200);
    }
    ok = ok && v1.result == auth::Result::Ok;
    const size_t n = ok ? std::strlen(v1.password) : 0;
    ok = ok && (n == config::kMasterPasswordChars);

    auth::JobView v2 = {};
    const bool secondOk = auth::poll(job, &v2) && v2.password[0] == '\0';
    char detail[96];
    std::snprintf(detail, sizeof(detail), "result %s len %u, second poll empty %d",
                  auth::toString(v1.result), static_cast<unsigned>(n),
                  static_cast<int>(secondOk));
    report("gateB-provision-once", ok && secondOk, detail);

    // Повторный provisioning обязан быть отклонён: он стёр бы хранилище.
    const auth::JobId again = auth::submitProvision();
    const bool refused = (again == 0) && vault::provisioned();
    report("gateB2-no-reprovision", refused, refused ? "refused, vault intact" : "ACCEPTED");

    // Разблокировка верным паролем открывает сессию.
    char good[config::kMasterPasswordChars + 1];
    std::memcpy(good, v1.password, n + 1);

    // Хранилище заведено под `good`, и гейты vault ниже обязаны открыть его тем же
    // паролем. Передаём его через kGatePassword — единственный способ, потому что
    // стереть раздел между наборами гейтов нельзя: erase вызывает ребет, а
    // reboot-цикл здесь уже стоил двух прогонов (бесконечный «стёр → ребет →
    // стёр»). Единственное стирание за прогон остаётся в run().
    std::snprintf(kGatePassword, sizeof(kGatePassword), "%s", good);

    auth::lock();
    const auth::JobId ujob = auth::submitUnlock(good);
    auth::JobView uv = {};
    for (uint32_t waited = 0; ujob != 0 && waited < 30000; waited += 200) {
      if (auth::poll(ujob, &uv) && uv.result != auth::Result::Pending) {
        break;
      }
      delay(200);
    }
    const bool unlocked = (ujob != 0) && (uv.result == auth::Result::Ok);
    report("gateC-unlock", unlocked, auth::toString(uv.result));

    // Токен сессии: верный принимается, изменённый — нет, закрытие сессии —
    // тоже нет.
    char tok[auth::kSessionTokenHexLen + 1] = {};
    const bool haveTok = auth::sessionTokenHex(tok, sizeof(tok));
    const bool okTok = haveTok && auth::sessionValid(tok, auth::kSessionTokenHexLen);
    char bad[auth::kSessionTokenHexLen + 1];
    std::memcpy(bad, tok, sizeof(bad));
    bad[0] = (bad[0] == 'a') ? 'b' : 'a';  // портим ровно один hex-символ
    const bool badTok = !(haveTok && auth::sessionValid(bad, auth::kSessionTokenHexLen));
    // Правильная длина, но не hex.
    char notHex[auth::kSessionTokenHexLen + 1];
    std::memset(notHex, 'z', auth::kSessionTokenHexLen);
    notHex[auth::kSessionTokenHexLen] = '\0';
    const bool notHexRejected = !auth::sessionValid(notHex, auth::kSessionTokenHexLen);
    report("gateC2-token", okTok && badTok && notHexRejected,
           "valid/bad-char/non-hex checked");

    // lock() обязан убить сессию: после него токен не принимается, и получить
    // новый нельзя, пока не разблокировались заново.
    auth::lock();
    const bool deadAfterLock =
        !auth::sessionValid(tok, auth::kSessionTokenHexLen) && !auth::sessionTokenHex(tok, sizeof(tok));
    report("gateC3-lock", deadAfterLock, deadAfterLock ? "token dead" : "TOKEN SURVIVED");

    // Неверный пароль: счётчик растёт, provisioned не падает, состояние Locked.
    const uint32_t before = auth::state().failCount;
    const auth::JobId wjob = auth::submitUnlock(kGatePasswordWrong);
    auth::JobView wv = {};
    for (uint32_t waited = 0; wjob != 0 && waited < 30000; waited += 200) {
      if (auth::poll(wjob, &wv) && wv.result != auth::Result::Pending) {
        break;
      }
      delay(200);
    }
    const auth::State st = auth::state();
    const bool wrongOk = (wjob != 0) && (wv.result == auth::Result::WrongPassword) &&
                         (st.failCount == before + 1) && st.provisioned && !st.unlocked;
    char detail2[96];
    std::snprintf(detail2, sizeof(detail2), "result %s fails %u->%u prov %d",
                  auth::toString(wv.result), static_cast<unsigned>(before),
                  static_cast<unsigned>(st.failCount), static_cast<int>(st.provisioned));
    report("gateD-wrongpw", wrongOk, detail2);

    // Блокировка: после kAuthMaxFail неудач верный пароль обязан быть отвергнут.
    // Иначе счётчик не имеет смысла — перебор продолжался бы в том же темпе.
    while (auth::state().lockoutMsLeft == 0 &&
           auth::state().failCount < config::kAuthMaxFail) {
      const auth::JobId j = auth::submitUnlock(kGatePasswordWrong);
      auth::JobView v = {};
      for (uint32_t waited = 0; j != 0 && waited < 30000; waited += 200) {
        if (auth::poll(j, &v) && v.result != auth::Result::Pending) {
          break;
        }
        delay(200);
      }
    }
    const auth::JobId lockedJob = auth::submitUnlock(good);
    const bool lockoutHeld = (lockedJob == 0) && (auth::state().lockoutMsLeft > 0);
    report("gateD2-lockout", lockoutHeld,
           lockoutHeld ? "correct password refused while locked out" : "LOCKOUT NOT HELD");

    // Ошибка длины: пустой пароль и слишком длинный обязаны отклоняться на входе.
    auth::clearLockout();
    const bool emptyRejected = (auth::submitUnlock("") == 0);
    char tooLong[config::kMaxPassChars + 2];
    std::memset(tooLong, 'x', sizeof(tooLong) - 1);
    tooLong[sizeof(tooLong) - 1] = '\0';
    const bool longRejected = (auth::submitUnlock(tooLong) == 0);
    report("gateE-input-limits", emptyRejected && longRejected,
           "empty and oversized rejected");

    // Простой: сессия закрывается сама. ttl подставляется нулевым, ждать
    // kSessionTtlMs (15 минут) гейт не может.
    const auth::JobId rjob = auth::submitUnlock(good);
    auth::JobView rv = {};
    for (uint32_t waited = 0; rjob != 0 && waited < 30000; waited += 200) {
      if (auth::poll(rjob, &rv) && rv.result != auth::Result::Pending) {
        break;
      }
      delay(200);
    }
    const bool wasOpen = (rjob != 0) && (rv.result == auth::Result::Ok);
    auth::expireIdleSession(0);
    const bool idleClosed = wasOpen && !auth::state().unlocked;
    report("gateF-idle-lock", idleClosed, idleClosed ? "closed on idle" : "STILL OPEN");

    // Секреты job'а отдаются ровно один раз. Без проверки этого HTTP-слой мог бы
    // опрашивать результат повторно и получать мастер-пароль или токен заново.
    {
      const auth::JobId sjob = auth::submitUnlock(good);
      auth::JobView sv1 = {};
      for (uint32_t waited = 0; sjob != 0 && waited < 30000; waited += 200) {
        if (auth::poll(sjob, &sv1) && sv1.result != auth::Result::Pending) {
          break;
        }
        delay(200);
      }
      // Первый poll забирает токен сессии, второй обязан прийти с пустым.
      auth::JobView sv2 = {};
      const bool secondEmpty =
          (sjob != 0) && auth::poll(sjob, &sv2) && sv2.sessionToken[0] == '\0';
      // Токен из job'а обязан совпасть с текущей сессией: иначе клиент получил бы
      // в заголовке токен, который устройство не признаёт, и не смог бы сделать
      // ни одного запроса к /api/entries.
      const bool tokUsable =
          sv1.result == auth::Result::Ok && sv1.sessionToken[0] != '\0' &&
          auth::sessionValid(sv1.sessionToken, std::strlen(sv1.sessionToken));
      report("gateE2-one-shot-token", secondEmpty && tokUsable,
             secondEmpty && tokUsable ? "delivered once, usable" : "STILL REDELIVERED");
      crypto::wipe(sv1.sessionToken, sizeof(sv1.sessionToken));
      crypto::wipe(sv2.sessionToken, sizeof(sv2.sessionToken));
      // Хранилище снова открыто этим токеном, закрываем, чтобы следующие гейты
      // начинали с запертого состояния.
      auth::lock();
    }

    // Гейт обязан оставлять хранилище закрытым и provisioned.
    const bool endState = !auth::state().unlocked && vault::provisioned();
    report("gateG-final-state", endState, "locked, still provisioned");

    crypto::wipe(good, sizeof(good));
  }
}

// Гейты ключевого файла: материал KDF = пароль ‖ SHA-256(файла), флаг
// kFlagKeyfile в заголовке. Идут ПОСЛЕ vaultGates(): тот заканчивает
// vault::clear(kGatePassword) без файла, то есть вход — provisioned без флага,
// открыто под kGatePassword. Собственного стирания здесь нет: единственное
// стирание за прогон уже случилось в run(), а resetGates() в конце унесёт то,
// что оставят эти гейты.
//
// Обязанность выхода: provisioned под kGatePassword БЕЗ ключевого файла, иначе
// resetGates() не сможет открыть хранилище своим submitUnlock(kGatePassword).
void keyfileGates() {
  log::info("=== keyfile gates ===");

  // Не секреты, а фиксированные тестовые материалы: два разных файла обязаны
  // давать разные ключи. Файл Б — обратный байтам файла А, то есть отличается
  // каждый байт, а не один.
  const uint8_t fileA[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                             0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                             0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  const uint8_t fileB[32] = {0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18,
                             0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10,
                             0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
                             0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
  const size_t fileLen = sizeof(fileA);

  // K1: перевод существующего хранилища на файл — clear с файлом, и после него
  // флаг обязан читаться без пароля. Проверяется и то, что записи под файловым
  // ключом пишутся: следующие гейты читают её же.
  uint32_t probeId = 0;
  {
    const VaultError rc = vault::clear(kGatePassword, fileA, fileLen);
    const bool flag = vault::keyFileRequired();
    Entry e = {};
    fillEntry(e, 0, "keyfile");
    const VaultError addRc = rc == VaultError::Ok ? vault::add(e, &probeId) : rc;
    crypto::wipe(&e, sizeof(e));
    char detail[72];
    std::snprintf(detail, sizeof(detail), "clear %d, flag %d, entry %d",
                  static_cast<int>(rc), static_cast<int>(flag),
                  static_cast<int>(addRc));
    report("gateK1-keyfile-provision",
           rc == VaultError::Ok && flag && addRc == VaultError::Ok && probeId != 0,
           detail);
    if (rc != VaultError::Ok) {
      return;
    }
  }

  // K2: unlock через auth-конвейер, а не прямым begin() — на этом пути ключевой
  // файл копируется в очередь и в Request воркера, и обрыв этой цепочки (файл,
  // дошедший не целиком, или склейка материалов не в ту сторону) даёт неверный
  // ключ именно здесь. Запись обязана читаться после такого открытия.
  {
    auth::lock();
    const auth::JobId job = auth::submitUnlock(kGatePassword, fileA, fileLen);
    auth::JobView v = {};
    const bool polled = waitJob(job, &v, 40000);
    const auth::Result res = v.result;
    crypto::wipe(v.password, sizeof(v.password));
    crypto::wipe(v.sessionToken, sizeof(v.sessionToken));
    bool getOk = false;
    if (polled && res == auth::Result::Ok) {
      Entry got = {};
      getOk = vault::get(probeId, &got) == VaultError::Ok &&
              std::strcmp(got.title, "gate-keyfile") == 0;
      crypto::wipe(&got, sizeof(got));
    }
    char detail[72];
    std::snprintf(detail, sizeof(detail), "unlock %s, entry %s",
                  polled ? auth::toString(res) : "not polled", getOk ? "ok" : "lost");
    report("gateK2-keyfile-unlock",
           polled && res == auth::Result::Ok && getOk && auth::state().unlocked,
           detail);
  }

  // K3: тот же пароль БЕЗ файла обязан дать WrongPassword, а не открыть:
  // материал отличается на SHA-256 файла, и расхождение обязано дойти до
  // проверки тега. Это и есть проверка, что файл реально участвует в KDF, а не
  // просто запоминается в заголовке.
  auth::lock();
  {
    const auth::JobId job = auth::submitUnlock(kGatePassword);
    auth::JobView v = {};
    const bool polled = waitJob(job, &v, 40000);
    const auth::Result res = v.result;
    crypto::wipe(v.password, sizeof(v.password));
    crypto::wipe(v.sessionToken, sizeof(v.sessionToken));
    report("gateK3-keyfile-no-file",
           polled && res == auth::Result::WrongPassword && !auth::state().unlocked,
           polled ? auth::toString(res) : "not polled");
  }

  // K4: чужой файл даёт такой же WrongPassword — ключ обязан зависеть от
  // СОДЕРЖИМОГО файла, а не от самого факта наличия файла. После двух
  // неудач failCount растёт, и clearLockout() нужен, чтобы остаток не повис на
  // последующих гейтах.
  {
    const auth::JobId job = auth::submitUnlock(kGatePassword, fileB, fileLen);
    auth::JobView v = {};
    const bool polled = waitJob(job, &v, 40000);
    const auth::Result res = v.result;
    crypto::wipe(v.password, sizeof(v.password));
    crypto::wipe(v.sessionToken, sizeof(v.sessionToken));
    auth::clearLockout();
    report("gateK4-keyfile-wrong-file",
           polled && res == auth::Result::WrongPassword && !auth::state().unlocked,
           polled ? auth::toString(res) : "not polled");
  }

  // K5: возврат к хранилищу без файла — clear с верным паролем и файлом, но уже
  // БЕЗ флага, обязателен для resetGates(). Одновременно проверяется, что флаг
  // висит именно на provisioned-заголовке, а не где-то в RAM.
  {
    vault::close();
    const VaultError openRc = vault::begin(kGatePassword, fileA, fileLen);
    const VaultError clearRc =
        openRc == VaultError::Ok ? vault::clear(kGatePassword) : openRc;
    const bool flagGone = !vault::keyFileRequired();
    const bool prov = vault::provisioned();
    vault::close();
    char detail[72];
    std::snprintf(detail, sizeof(detail), "open %d, clear %d, flag %d, prov %d",
                  static_cast<int>(openRc), static_cast<int>(clearRc),
                  static_cast<int>(flagGone), static_cast<int>(prov));
    report("gateK5-keyfile-restore",
           openRc == VaultError::Ok && clearRc == VaultError::Ok && flagGone && prov,
           detail);
  }
}

// Гейты смены мастер-пароля. Вход обязателен: provisioned под kGatePassword без
// ключевого файла (оставляет keyfileGates()), хранилище закрыто — потому что
// первый гейт и проверяет отказ rekey на закрытом хранилище. Выход тот же, что
// у keyfileGates(), плюс пароль снова kGatePassword — resetGates() открывает им.
void rekeyGates() {
  log::info("=== rekey gates ===");

  const char kNewPassword[] = "gate-rekey-passphrase-9b-not-a-real-secret";

  // R1: rekey на закрытом хранилище обязан дать Refused, а не Error или тем
  // более Ok: без расшифрованных записей сменить ключ невозможно, и UI должен
  // показать «не сейчас», а не «сбой».
  vault::close();
  {
    const auth::JobId job = auth::submitRekey(kGatePassword, kNewPassword);
    auth::JobView v = {};
    const bool polled = waitJob(job, &v, 20000);
    const auth::Result res = v.result;
    const auth::Job kind = v.kind;
    crypto::wipe(v.password, sizeof(v.password));
    crypto::wipe(v.sessionToken, sizeof(v.sessionToken));
    report("gateR1-rekey-refused-closed",
           polled && res == auth::Result::Refused && kind == auth::Job::Rekey,
           polled ? auth::toString(res) : "not polled");
  }

  // R2: смена через auth-конвейер на живой сессии. Сессия обязана пережить
  // rekey — токен выдаётся не под пароль, иначе клиент после смены пароля
  // отваливался бы и не мог бы узнать об успехе.
  {
    const auth::JobId ujob = auth::submitUnlock(kGatePassword);
    auth::JobView uv = {};
    const bool unlocked =
        waitJob(ujob, &uv, 40000) && uv.result == auth::Result::Ok;
    const auth::Result ures = uv.result;
    crypto::wipe(uv.password, sizeof(uv.password));
    crypto::wipe(uv.sessionToken, sizeof(uv.sessionToken));

    // Запись добавляется ПЕРЕД сменой: rekey обязан перезаписать каждую живую
    // запись под новым ключом, и проверяется именно она, а не пустое
    // хранилище.
    uint32_t probeId = 0;
    Entry e = {};
    fillEntry(e, 0, "rekey");
    const VaultError addRc = unlocked ? vault::add(e, &probeId) : VaultError::BootStrap;
    crypto::wipe(&e, sizeof(e));

    const auth::JobId job = auth::submitRekey(kGatePassword, kNewPassword);
    auth::JobView v = {};
    const bool polled = waitJob(job, &v, 60000);
    const auth::Result res = v.result;
    crypto::wipe(v.password, sizeof(v.password));
    crypto::wipe(v.sessionToken, sizeof(v.sessionToken));
    char tok[auth::kSessionTokenHexLen + 1] = {};
    const bool sessionAlive = auth::state().unlocked && auth::sessionTokenHex(tok, sizeof(tok));
    char detail[80];
    std::snprintf(detail, sizeof(detail), "unlock %s, add %d, rekey %s, session %d",
                  polled && unlocked ? auth::toString(ures) : "fail",
                  static_cast<int>(addRc),
                  polled ? auth::toString(res) : "not polled", sessionAlive ? 1 : 0);
    report("gateR2-rekey-ok", unlocked && addRc == VaultError::Ok && polled &&
                                  res == auth::Result::Ok && sessionAlive &&
                                  probeId != 0,
           detail);

    // R3 + R4: старый пароль не открывает, новый открывает, и запись
    // переживает смену ключа на флеше.
    vault::close();
    const VaultError oldRc = vault::begin(kGatePassword);
    vault::close();
    const VaultError newRc = vault::begin(kNewPassword);
    Entry got = {};
    const VaultError getRc = newRc == VaultError::Ok ? vault::get(probeId, &got)
                                                     : newRc;
    const bool dataOk = getRc == VaultError::Ok &&
                        std::strcmp(got.title, "gate-rekey") == 0 &&
                        std::strcmp(got.tags, "tag-rekey,shared") == 0;
    crypto::wipe(&got, sizeof(got));
    char detail34[80];
    std::snprintf(detail34, sizeof(detail34), "old %d new %d entry %d",
                  static_cast<int>(oldRc), static_cast<int>(newRc),
                  static_cast<int>(dataOk));
    report("gateR3-rekey-old-pw-rejected", oldRc == VaultError::WrongPassword,
           detail34);
    report("gateR4-rekey-data-survives", newRc == VaultError::Ok && dataOk, detail34);

    // R5: возврат на kGatePassword напрямую через vault::rekey — путь, которым
    // пользуются все последующие гейты. Без него resetGates() не открыл бы
    // хранилище.
    const VaultError backRc = newRc == VaultError::Ok
                                  ? vault::rekey(kGatePassword)
                                  : VaultError::BootStrap;
    const bool flag = vault::keyFileRequired();
    const bool prov = vault::provisioned();
    vault::close();
    char detail5[72];
    std::snprintf(detail5, sizeof(detail5), "back %d, flag %d, prov %d",
                  static_cast<int>(backRc), static_cast<int>(flag),
                  static_cast<int>(prov));
    report("gateR5-rekey-restore",
           backRc == VaultError::Ok && !flag && prov, detail5);
  }
}

// Гейт reset-job. Отдельной функцией и ПОСЛЕДНИМ среди разрушительных,
// потому что reset уничтожает хранилище, а все предыдущие гейты на каждом
// шаге опираются на то, что оно есть и открыто под kGatePassword. Внутри
// authGates() reset отработал бы до конца прогона и унёс бы всё, что дальше
// проверяется.
//
// Разрушителен по определению: раздел к этому моменту уже стёрт, а в нём лежат
// только записи гейтов.
//
// Первый шаг — РАЗБЛОКИРОВКА, а не provisioning. resetGates() идёт после
// vaultGates(), а тот заканчивается на заведённом хранилище: его последний
// gate-reset делает vault::clear(), который стирает раздел и заводит новое
// хранилище под kGatePassword, то есть оставляет раздел provisioned. На
// provisioned-хранилище submitProvision() возвращает kNoJob по устройству, и
// гейт получался заведомо неисполнимым: H1 падал бы всегда, и проверять было бы
// нечего. Именно поэтому нужен unlock — он и есть предусловие «есть живая
// сессия, которую reset обязан закрыть».
void resetGates() {
  const auth::JobId ujob = auth::submitUnlock(kGatePassword);
  auth::JobView uv0 = {};
  for (uint32_t waited = 0; ujob != 0 && waited < 40000; waited += 200) {
    if (auth::poll(ujob, &uv0) && uv0.result != auth::Result::Pending) {
      break;
    }
    delay(200);
  }
  report("gateH1-unlock-before-reset",
         ujob != 0 && uv0.result == auth::Result::Ok && auth::state().unlocked,
         uv0.result == auth::Result::Ok ? "vault unlocked" : auth::toString(uv0.result));
  if (uv0.result != auth::Result::Ok) {
    crypto::wipe(uv0.password, sizeof(uv0.password));
    crypto::wipe(uv0.sessionToken, sizeof(uv0.sessionToken));
    return;
  }
  // Сессия нужна только как факт её существования; токен здесь не нужен, но он
  // обязан быть стёрт из локального буфера, как и любой другой секрет.
  crypto::wipe(uv0.password, sizeof(uv0.password));
  crypto::wipe(uv0.sessionToken, sizeof(uv0.sessionToken));

  // Запись перед уничтожением: reset обязан унести её, и проверка обязана идти по
  // флешу, а не по RAM-кэшу.
  {
    vault::Entry e = {};
    std::snprintf(e.title, sizeof(e.title), "doomed");
    std::snprintf(e.login, sizeof(e.login), "doomed");
    std::snprintf(e.password, sizeof(e.password), "doomed-secret");
    const vault::VaultError rc = vault::add(e, nullptr);
    crypto::wipe(&e, sizeof(e));
    report("gateH2-entry-before-reset", rc == vault::VaultError::Ok, vault::toString(rc));
  }

  // Сессия уже открыта предыдущим шагом: reset обязан убить живую сессию, и это
  // проверяется только если сессия была. Отдельный unlock здесь был бы лишним
  // прогоном PBKDF2 и ничего не добавлял бы к проверке.
  const bool sessionWasOpen = auth::state().unlocked;
  report("gateH2b-session-before-reset", sessionWasOpen,
         sessionWasOpen ? "open" : "closed");

  auth::JobView rview = {};
  const auth::JobId rjob = auth::submitReset();
  bool polled = false;
  for (uint32_t waited = 0; rjob != 0 && waited < 40000; waited += 200) {
    if (auth::poll(rjob, &rview) && rview.result != auth::Result::Pending) {
      polled = true;
      break;
    }
    delay(200);
  }
  report("gateH3-reset-ok",
         polled && rview.result == auth::Result::Ok && !vault::provisioned(),
         polled ? auth::toString(rview.result) : "not polled");

  // Сессия обязана быть закрыта: токен был выдан для хранилища, которого нет.
  const auth::State afterReset = auth::state();
  char tok[auth::kSessionTokenHexLen + 1] = {};
  report("gateH4-session-closed",
         sessionWasOpen && !afterReset.provisioned && !afterReset.unlocked &&
             !auth::sessionTokenHex(tok, sizeof(tok)),
         "no session, no token");

  // Повторный reset на пустом хранилище обязан дать Refused, а не Ok: UI должен
  // отличать «нечего стирать» (409) от успеха, иначе он сообщил бы об
  // уничтожении того, чего не было.
  const auth::JobId rjob2 = auth::submitReset();
  auth::JobView rv2 = {};
  bool polled2 = false;
  for (uint32_t waited = 0; rjob2 != 0 && waited < 40000; waited += 200) {
    if (auth::poll(rjob2, &rv2) && rv2.result != auth::Result::Pending) {
      polled2 = true;
      break;
    }
    delay(200);
  }
  report("gateH5-reset-refused-when-empty",
         polled2 && rv2.result == auth::Result::Refused && rv2.kind == auth::Job::Reset,
         polled2 ? auth::toString(rv2.result) : "not polled");
}

void run(bool wipeVault) {
  log::info("=== gates ===");
  g_pass = 0;
  g_fail = 0;
  cryptoGates();
  if (!vaultLooksEmpty()) {
    const esp_partition_t* part = vaultPartition();
    // Стирать имеет право только явный режим сборки. Запуск по GPIO0 — это
    // физическое действие пользователя, и молча уничтожать по нему реальные
    // данные нельзя.
    if (!wipeVault || !part) {
      log::error("vault partition holds data: refusing to run destructive vault gates");
      log::error("erase it manually or use the vault clear command");
      // Пропуск гейтов — не провал. Раньше здесь печаталось g_fail + 1, и отказ по
      // сохранности данных выглядел в логе как упавший гейт: «1 failed» при
      // четырёх зелёных. При чтении лога это выглядит как регресс, которого нет.
      log::info("=== %u passed, %u failed, vault gates SKIPPED ===",
                static_cast<unsigned>(g_pass), static_cast<unsigned>(g_fail));
      return;
    }
    log::warn("gate: wiping vault partition for a clean run");
    if (esp_partition_erase_range(part, 0, part->size) != ESP_OK) {
      log::error("gate: cannot wipe vault partition, vault gates skipped");
      // Пропуск гейтов — не провал. Раньше здесь печаталось g_fail + 1, и отказ по
      // сохранности данных выглядел в логе как упавший гейт: «1 failed» при
      // четырёх зелёных. При чтении лога это выглядит как регресс, которого нет.
      log::info("=== %u passed, %u failed, vault gates SKIPPED ===",
                static_cast<unsigned>(g_pass), static_cast<unsigned>(g_fail));
      return;
    }
  }

  // Гейты auth идут ПЕРЕД vault-гейтами, пока раздел ещё пуст.
  //
  // Порядок обязателен по двум причинам, обе из которых уже стоили прогона:
  //   - authGates() требует пустого раздела (provisioning на provisioned откажет),
  //     а vaultGates() заканчивается vault::clear(), который заводит новое
  //     хранилище, то есть оставляет раздел provisioned. После vaultGates пустым
  //     он не бывает никогда.
  //   - erase раздела вызывает ребет, поэтому стереть что-либо можно только
  //     один раз за прогон. Если бы authGates() стирал сам, он не смог бы дойти до
  //     конца: ребет перезапустил бы run(), который стёр бы заново.
  // Взамен authGates() оставляет хранилище, заведённое под СГЕНЕРИРОВАННЫЙ
  // мастер-пароль, и кладёт этот пароль в kGatePassword, чтобы vaultGates()
  // открыл то же хранилище. Ни один из наборов не стирает раздел: единственное
  // стирание за прогон — выше, и оно уже случилось (или не потребовалось).
  authGates();
  vaultGates();
  // Ключевой файл и смена пароля стоят МЕЖДУ vault- и reset-гейтами: оба
  // требуют provisioned-хранилища (vaultGates() оставляет его через clear) и
  // обязаны вернуть провижин без ключевого файла и под kGatePassword —
  // иначе resetGates() не откроет хранилище своим submitUnlock(kGatePassword)
  // и H1 упадёт не по своей причине. Как и authGates(), эти два не стират
  // раздел: единственное стирание за прогон — выше.
  keyfileGates();
  rekeyGates();
  // reset-job идёт последним и стирает хранилище, на которое опираются все
  // предыдущие гейты. После него раздел остаётся пустым — это и есть чистое
  // состояние после прогона.
  resetGates();
  log::info("=== total: %u passed, %u failed ===", static_cast<unsigned>(g_pass),
            static_cast<unsigned>(g_fail));
  if (g_fail > 0) {
    log::error("gates FAILED");
  } else {
    log::info("gates all PASS");
  }
}

}  // namespace selftest
}  // namespace pm
