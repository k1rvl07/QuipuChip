#pragma once

#include <stddef.h>
#include <stdint.h>

namespace pm {
namespace totp {

// TOTP (RFC 6238) с фиксированными параметрами: SHA-1, config::kTotpDigits
// (6), config::kTotpPeriodSec (30). Секрет хранится в Entry::totp как строка
// base32 (RFC 4648): A-Z2-7, опциональный '=' padding, регистр не важен.
//
// Часов на устройстве нет (нет RTC и нет NTP), поэтому время приходит СНАРУЖИ —
// из query-параметра t обработчика /api/entries/{id}/totp. Устройство не хранит
// и не оценивает время само; клиент с реальными часами шлёт эпоху, сервер
// считает код из секрета, который покидает устройство только в виде готового
// 6-значного числа.

// Декодирует base32 в out (outMax байт). Возвращает число байт или 0 при
// ошибке: недопустимый символ, обрыв строки, нехватка места.
size_t decodeBase32(const char* s, uint8_t* out, size_t outMax);

// Проверяет секрет по формату: непустая строка допустимых символов длиной
// не меньше 16 символов (80 бит — минимум RFC 4226 для HMAC-SHA1).
bool validSecret(const char* secret);

// Считает 6-значный код (с ведущими нулями, NUL-терминирован, out[7]) для
// секрета в момент timeSec (unix-время в секундах). false — секрет невалиден.
bool code(const char* secret, uint32_t timeSec, char out[7]);

}  // namespace totp
}  // namespace pm
