#include "fs.h"

#include <LittleFS.h>
#include <stdio.h>
#include <string.h>

#include <stdint.h>

#include "config.h"
#include "logger.h"

namespace pm {
namespace fs {
namespace {

constexpr uint8_t kMaxOpenFiles = 10;

bool g_webMounted = false;

// Возвращает длину нормализованного пути без завершающего NUL, либо SIZE_MAX,
// если путь отвергнут. В out пишется и сам путь, и завершающий NUL.
//
// Правила намеренно строже, чем требует LittleFS: сегмент ".." отвергается
// целиком, а не разруливается вверх. Для статики раздела web разруливание не
// нужно (в index.html не должно быть ссылок с ".."), зато правило ".." не даёт
// проверить упрощение пути: нельзя случайно отдать файл, который задумывался
// как "../vault/vault.bin", и нельзя забыть про этот случай в будущем коде.
size_t normalize(const char* relPath, char* out, size_t outSize) {
  static const char kIndex[] = "index.html";

  if (relPath == nullptr) {
    relPath = kIndex;
  }
  while (*relPath == '/') {
    ++relPath;
  }
  if (*relPath == '\0') {
    relPath = kIndex;
  }

  size_t n = 0;
  const char* seg = relPath;
  for (;;) {
    const char* sep = strchr(seg, '/');
    const size_t segLen = sep ? static_cast<size_t>(sep - seg) : strlen(seg);

    const bool isDot = (segLen == 1 && seg[0] == '.');
    const bool isDotDot = (segLen == 2 && seg[0] == '.' && seg[1] == '.');
    if (isDotDot) {
      return SIZE_MAX;
    }

    if (!isDot && segLen > 0) {
      if (n != 0) {
        if (n + 1 >= outSize) {
          return SIZE_MAX;
        }
        out[n++] = '/';
      }
      for (size_t i = 0; i < segLen; ++i) {
        const unsigned char c = static_cast<unsigned char>(seg[i]);
        // Управляющие байты и NUL в имя файла не попадают: NUL обрезал бы путь
        // так, что префикс прошёл бы проверку, а суффикс ушёл мимо неё.
        if (c < 0x20 || c == 0x7F) {
          return SIZE_MAX;
        }
        if (n + 1 >= outSize) {
          return SIZE_MAX;
        }
        out[n++] = seg[i];
      }
    }

    if (sep == nullptr) {
      break;
    }
    seg = sep + 1;
  }

  if (n == 0 || n + 1 > outSize) {
    // Путь выродился в "/", "///" или "a/.." — это не файл, отдавать нечего.
    return SIZE_MAX;
  }
  out[n] = '\0';
  return n;
}

}  // namespace

bool mountWeb() {
  if (g_webMounted) {
    return true;
  }
  // formatOnFail — всегда false. Автоформат стёр бы залитый образ web, и
  // устройство молча отдавало бы 404 на каждый запрос, пока туда не перезальют.
  if (!LittleFS.begin(false, config::kFsWebBase, kMaxOpenFiles, config::kFsWeb)) {
    return false;
  }
  g_webMounted = true;
  log::info("web mounted at %s, %u KB total, %u KB used", config::kFsWebBase,
            static_cast<unsigned>(LittleFS.totalBytes() >> 10),
            static_cast<unsigned>(LittleFS.usedBytes() >> 10));
  return true;
}

bool webMounted() {
  return g_webMounted;
}

size_t webTotalBytes() {
  return g_webMounted ? LittleFS.totalBytes() : 0;
}

size_t webUsedBytes() {
  return g_webMounted ? LittleFS.usedBytes() : 0;
}

bool openWeb(const char* relPath, WebFile& out) {
  if (!g_webMounted) {
    return false;
  }

  char rel[config::kWebPathMax];
  if (normalize(relPath, rel, sizeof(rel)) == SIZE_MAX) {
    return false;
  }

  // В VFS уходит ГОЛЫЙ абсолютный путь, без базы раздела: esp_littlefs
  // подставляет базу сам. Склейка base+rel даёт /web/web/index.html — ровно
  // то, что было в первом прогоне stage 3. Ср. kVaultName = "/vault.bin":
  // тоже без базы.
  char path[config::kWebPathMax];
  const int n = snprintf(path, sizeof(path), "/%s", rel);
  if (n <= 0 || static_cast<size_t>(n) >= sizeof(path)) {
    return false;
  }

  File f = LittleFS.open(path, FILE_READ);
  if (!f || f.isDirectory()) {
    return false;
  }
  // rel уже нормализован (без ведущего слэша, без "." и ".."), поэтому влезает
  // в name всегда; проверка на всякий случай — обрезанный MIME хуже, чем отказ.
  if (strlen(rel) >= sizeof(out.name)) {
    f.close();
    return false;
  }
  strcpy(out.name, rel);
  out.handle = f;
  out.size = f.size();
  return true;
}

size_t readWeb(WebFile& f, uint8_t* buf, size_t len) {
  if (len == 0) {
    return 0;
  }
  const int got = f.handle.read(buf, len);
  return got > 0 ? static_cast<size_t>(got) : 0;
}

void closeWeb(WebFile& f) {
  f.handle.close();
  f.size = 0;
  f.name[0] = '\0';
}

bool webIndexSize(size_t& sizeOut) {
  WebFile f;
  if (!openWeb("index.html", f)) {
    return false;
  }
  sizeOut = f.size;
  closeWeb(f);
  return true;
}

void stop() {
  if (!g_webMounted) {
    return;
  }
  LittleFS.end();
  g_webMounted = false;
}

}  // namespace fs
}  // namespace pm
