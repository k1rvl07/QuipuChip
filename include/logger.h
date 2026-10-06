#pragma once

#include <stdint.h>

namespace pm {
namespace log {

enum class Level : uint8_t { Info, Warn, Error };

void init();

void info(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void warn(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void error(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

}  // namespace log
}  // namespace pm
