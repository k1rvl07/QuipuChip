#include "logger.h"

#include <Arduino.h>
#include <stdarg.h>
#include <stdio.h>

#include "config.h"

namespace pm {
namespace log {
namespace {

HardwareSerial& uart() {
  return Serial;
}

const char* tag(Level level) {
  switch (level) {
    case Level::Warn:
      return "WARN";
    case Level::Error:
      return "ERR ";
    default:
      return "INFO";
  }
}

void vwrite(Level level, const char* fmt, va_list ap) {
  char line[config::kLogLineMax];
  vsnprintf(line, sizeof(line), fmt, ap);
  uart().printf("[%8lu] %s %s\n", static_cast<unsigned long>(millis()), tag(level), line);
}

}  // namespace

void init() {
  // TX-буфер не ресайзим: cores/esp32/main.cpp вызывает Serial.begin() до setup(),
  // поэтому setTxBufferSize() на этом этапе всегда падает. 256 байт хватает —
  // printf блокируется на заполненном буфере и не теряет строки.
  uart().begin(config::kLogBaud);
}

void info(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vwrite(Level::Info, fmt, ap);
  va_end(ap);
}

void warn(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vwrite(Level::Warn, fmt, ap);
  va_end(ap);
}

void error(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vwrite(Level::Error, fmt, ap);
  va_end(ap);
}

}  // namespace log
}  // namespace pm
