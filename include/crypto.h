#pragma once

#include <stddef.h>
#include <stdint.h>

#include "config.h"

namespace pm {
namespace crypto {

// Контекстный стиль: ключи никогда не копируются лишний раз, wipe() обязателен.
// Все функции zero-allocation и детерминированны там, где это разумно.

enum class CipherError {
  Ok = 0,
  InvalidArg = 1,
  InvalidKeyLen = 2,
  InvalidIvLen = 3,
  InvalidTagLen = 4,
  AuthFail = 5,
  EncryptFail = 6,
  DecryptFail = 7,
};

// Константы соответствуют config.h: AES-256-GCM.
constexpr size_t kAesKeyLen = config::kAesKeyLen;
constexpr size_t kGcmIvLen = config::kGcmIvLen;
constexpr size_t kGcmTagLen = config::kGcmTagLen;

// Безопасное обнуление буфера.
void wipe(void* buf, size_t len);

// Детерминированное сравнение по времени (constant-time).
bool ctEqual(const void* a, const void* b, size_t len);

// PBKDF2-HMAC-SHA256. Вывод key[32], соль salt[16].
int pbkdf2HmacSha256(const void* password, size_t passwordLen, const void* salt,
                     size_t saltLen, uint32_t iterations, void* keyOut);

// HMAC-SHA256 (программный). Используется для KDF и в качестве плейсхолдера;
// в 4b может быть заменён на аппаратный esp_hmac_calculate() с eFuse-ключом.
int hmacSha256(const void* key, size_t keyLen, const void* data, size_t dataLen,
               void* macOut, size_t macOutLen);

// AES-256-GCM: шифрование (aad может быть пустым).
// output = ciphertext || tag (tag фиксированной длины kGcmTagLen).
int aesGcmEncrypt(const void* key, const void* iv, const void* aad, size_t aadLen,
                  const void* plaintext, size_t ptLen, void* ciphertextOut,
                  size_t* ctLenOut, void* tagOut);

// AES-256-GCM: расшифрование. Возвращает CipherError::AuthFail при неверном теге.
int aesGcmDecrypt(const void* key, const void* iv, const void* aad, size_t aadLen,
                  const void* ciphertext, size_t ctLen, const void* tagIn,
                  void* plaintextOut, size_t* ptLenOut);

}  // namespace crypto
}  // namespace pm
