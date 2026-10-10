#include "totp.h"

#include <cstdio>
#include <cstring>

#include "config.h"
#include "crypto.h"

namespace pm {
namespace totp {
namespace {

// Значение символа base32 (RFC 4648): A-Z = 0..25, 2-7 = 26..31.
int b32Val(char c) {
  if (c >= 'A' && c <= 'Z') {
    return c - 'A';
  }
  if (c >= 'a' && c <= 'z') {
    return c - 'a';
  }
  if (c >= '2' && c <= '7') {
    return c - '2' + 26;
  }
  return -1;
}

}  // namespace

size_t decodeBase32(const char* s, uint8_t* out, size_t outMax) {
  if (!s || !out) {
    return 0;
  }
  size_t n = std::strlen(s);
  while (n > 0 && s[n - 1] == '=') {
    --n;
  }
  if (n == 0) {
    return 0;
  }
  size_t outLen = 0;
  uint32_t acc = 0;
  int bits = 0;
  for (size_t i = 0; i < n; ++i) {
    const int v = b32Val(s[i]);
    if (v < 0) {
      return 0;
    }
    acc = (acc << 5) | static_cast<uint32_t>(v);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      if (outLen >= outMax) {
        return 0;
      }
      out[outLen++] = static_cast<uint8_t>((acc >> bits) & 0xff);
      acc &= (bits ? (1u << bits) - 1 : 0);
    }
  }
  // Незавершённый байт обязан состоять из нулевых бит: так кодирует валидный
  // base32. Ненулевой остаток означает чужой формат и менял бы ключ молча —
  // отвергаем.
  if (acc != 0) {
    return 0;
  }
  return outLen;
}

bool validSecret(const char* secret) {
  if (!secret || secret[0] == '\0') {
    return false;
  }
  const size_t n = std::strlen(secret);
  if (n >= config::kTotpSecretMax) {
    return false;
  }
  // Минимум 16 символов = 80 бит. Для HMAC-SHA1 этого хватает с запасом;
  // более короткий секрет — обычно опечатка при копировании.
  if (n < 16) {
    return false;
  }
  uint8_t key[64];
  const size_t keyLen = decodeBase32(secret, key, sizeof(key));
  crypto::wipe(key, sizeof(key));
  return keyLen >= 10;
}

bool code(const char* secret, uint32_t timeSec, char out[7]) {
  if (!secret || !out) {
    return false;
  }
  uint8_t key[64];
  const size_t keyLen = decodeBase32(secret, key, sizeof(key));
  if (keyLen < 10) {
    crypto::wipe(key, sizeof(key));
    return false;
  }
  uint64_t counter = timeSec / config::kTotpPeriodSec;
  uint8_t msg[8];
  for (int i = 7; i >= 0; --i) {
    msg[i] = static_cast<uint8_t>(counter & 0xff);
    counter >>= 8;
  }
  uint8_t mac[20];
  const int rc = crypto::hmacSha1(key, keyLen, msg, sizeof(msg), mac);
  crypto::wipe(key, sizeof(key));
  crypto::wipe(msg, sizeof(msg));
  if (rc != 0) {
    return false;
  }
  // Динамическое усечение (RFC 4226, раздел 5.3): off — 4 байта младшего
  // октета, старший бит обнуляется, дальше mod 10^digits.
  const uint32_t off = mac[19] & 0x0f;
  const uint32_t bin = (static_cast<uint32_t>(mac[off] & 0x7f) << 24) |
                       (static_cast<uint32_t>(mac[off + 1]) << 16) |
                       (static_cast<uint32_t>(mac[off + 2]) << 8) |
                       static_cast<uint32_t>(mac[off + 3]);
  const uint32_t v = bin % 1000000;
  crypto::wipe(mac, sizeof(mac));
  std::snprintf(out, 7, "%06u", v);
  return true;
}

}  // namespace totp
}  // namespace pm
