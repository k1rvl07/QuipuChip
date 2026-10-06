// Device-фактор из заводского MAC-адреса ESP32-S3.
//
// MAC читается из eFuse в момент вызова и в хранилище не попадает. Ключ
// формируется как HMAC-SHA256(mac, "pm-vault-device" || salt_dev): доменное
// разделение через соль не даёт переиспользовать этот HMAC в других местах,
// а 32 б MAC растягиваются до 32 б ключа.
//
// Альтернативы, рассмотренные и отклонённые (подробности в AGENTS.md):
//   - eFuse KEY0..KEY5 + HMAC-периферия: ключ не покидает кремний, но требует
//     прожига eFuse, то есть необратимой операции;
//   - SRAM PUF: обратимо, но требует циклов физического питания и температурных
//     прогонов, плюс зависит от образа и загрузчика;
//   - ATECC608B: аппаратный и обратимый (заводской ключ нельзя записать), но
//     требует отдельной микросхемы на I2C.
// MAC выбран как единственный вариант без новых деталей и без прожига.

#include "device_factor.h"

#include <Arduino.h>

#include <cstring>

#include "crypto.h"

namespace pm {
namespace device {
namespace {

// Метка длиной 15 байт. Длина фиксирована и в HMAC подаётся вместе с солью в
// одном сообщении, поэтому граница однозначна и перестановка (метка, соль)
// невозможна: разные длины дают разные сообщения.
constexpr char kDeviceLabel[] = "pm-vault-device";

}  // namespace

bool factor(const uint8_t* saltDev, size_t saltDevLen, uint8_t out[32]) {
  if (!out) {
    return false;
  }
  crypto::wipe(out, 32);
  if (!saltDev || saltDevLen == 0) {
    return false;
  }

  // ESP.getEfuseMac() возвращает 48-битный MAC, собранный из eFuse BLK1.
  // Верхние 16 бит нулевые, но берём ровно 6 байт, а не 8, чтобы не зависеть
  // от представления Arduino.
  const uint64_t efuseMac = ESP.getEfuseMac();
  if (efuseMac == 0) {
    return false;  // eFuse не прочитан: фактора нет, лучше явный отказ
  }
  uint8_t mac[6];
  for (int i = 0; i < 6; ++i) {
    mac[i] = static_cast<uint8_t>(efuseMac >> ((5 - i) * 8));
  }

  // Сообщение для HMAC: метка || соль, без разделителя — длины фиксированы.
  constexpr size_t kLabelLen = sizeof(kDeviceLabel) - 1;
  uint8_t msg[sizeof(kDeviceLabel) - 1 + 16];
  if (saltDevLen > sizeof(msg) - kLabelLen) {
    return false;
  }
  std::memcpy(msg, kDeviceLabel, kLabelLen);
  std::memcpy(msg + kLabelLen, saltDev, saltDevLen);
  const size_t msgLen = kLabelLen + saltDevLen;

  const int rc = crypto::hmacSha256(mac, sizeof(mac), msg, msgLen, out, 32);
  crypto::wipe(msg, sizeof(msg));
  crypto::wipe(mac, sizeof(mac));
  return rc == static_cast<int>(crypto::CipherError::Ok);
}

}  // namespace device
}  // namespace pm
