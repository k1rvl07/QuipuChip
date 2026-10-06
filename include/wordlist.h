#pragma once

// Файл сгенерирован scripts/wordlist.py. Правь скрипт, не эти файлы:
//     python3 scripts/wordlist.py
//     python3 scripts/wordlist.py --check   # проверка без записи
//
// 4096 слов по 5 букв, 12 бит на слово.
// Минимальное расстояние Хэмминга 3: промах в 1-2 буквы не может дать
// другое слово словаря, то есть опечатка обнаруживается сама.
// Слова непроизносимые и это осознанное: с расстоянием 3 в произносимом
// семействе CVC потолок 2000 слов, а нужно 4096.
// Словом выбирается равномерный индекс, а не слово из словаря.
//
// Таблица объявлена extern и ОПРЕДЕЛЕНА один раз, в src/wordlist.cpp:
// иначе каждый включающий TU тащил бы свою копию 24 КБ. Подробности
// о выборе этого приёма — в scripts/wordlist.py.

#include <stddef.h>

namespace pm {
namespace wordlist {

constexpr size_t kWordCount = 4096;
constexpr size_t kWordBytes = 5;
constexpr size_t kWordStride = 6;

// Таблица слов. Определена ровно один раз, в src/wordlist.cpp.
extern const char kWords[];

// Слово по индексу: возврат указателя на нуль-терминированную строку.
constexpr const char* word(size_t i) {
  return kWords + i * kWordStride;
}

}  // namespace wordlist
}  // namespace pm
