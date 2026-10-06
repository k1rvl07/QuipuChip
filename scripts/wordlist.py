#!/usr/bin/env python3
"""Генератор и валидатор мастер-словаря PassManager.

Зачем отдельным скриптом. Словарь — это МАТЕМАТИЧЕСКОЕ требование, а не
перечень: 4096 слов дают ровно 12 бит на слово, и любое слово, добавленное «для
удобства», либо ломает счёт (4097 слов = 12.0004 бита на слово вместо ровно
12), либо молча ослабляет гарантию. Проверять это вручную нельзя, поэтому
список собирается скриптом, валидатор проверяет ограничения, а результат
кладётся в include/wordlist.h и живёт дальше как обычный заголовочный файл.

Слова СИНТЕТИЧЕСКИЕ, а не словариковые, и непроизносимые. Причина не в лени,
а в требовании к расстоянию Хэмминга: ошибиться на 1-2 буквы в passphrase,
который переписывают с экрана, нельзя иначе как получив неверный пароль,
который выглядит правильным. Подробности конструкции — у MIN_HAMMING.

Ограничения (каждое проверяется валидатором, а не только комментируется):

  * ровно 4096 слов, ровно по 5 букв, только a-z;
  * минимальное расстояние Хэмминга между любыми двумя словами — 3;
  * нет слов, читающихся как запрещённые или как названия инструментов
    доступа. Проверка по подстрокам, то есть best-effort: полностью
    исключить осмысленную непристойность автоматически нельзя, и это
    ограничение самого подхода, а не недоработка скрипта.

Произносимость здесь сознательно принесена в жертву: алфавит полный, и слова
вроде «xkqtw» не выглядят как английские. Причина — в MIN_HAMMING ниже.

Запуск:
    python3 scripts/wordlist.py            пересобрать include/wordlist.h
    python3 scripts/wordlist.py --check    проверить, что заголовок соответствует
                                           генератору (для CI и ревью)
"""

import argparse
import pathlib
import sys

# Точное число — часть контракта: config::kMasterWords слов берут по 12 бит каждое.
# config::kMasterDigits добирает остаток. Менять 4096 на другое число можно
# только вместе с пересчётом kPbkdf2Iters и правкой комментария в config.h.
WORD_COUNT = 4096
WORD_BYTES = 5
PREFIX_BYTES = 4

ALPHABET = "abcdefghijklmnopqrstuvwxyz"

# Подстроки, из-за которых слово отбрасывается. Только те, что действительно
# недопустимы или опасны: трёхбуквенные безобидные вроде "oil" или "war" сюда
# НЕ входят, потому что в пятибуквенном слове они встречаются часто и вырезали
# бы добрую половину словаря ради ничего.
BLOCK_SUBSTRINGS = (
    # непристойное и оскорбительное
    "anal", "anus", "arse", "bast", "bitch", "boll", "boob", "butt",
    "cock", "coon", "cunt", "damn", "dick", "dyke", "fart", "fuk",
    "hell", "homo", "jizz", "kike", "nigg", "penis", "piss", "poop",
    "porn", "prick", "pube", "pussy", "queer", "rape", "sex", "shit",
    "slut", "spic", "tit", "turd", "twat", "wank", "whore",
    # инструменты доступа: слово "admin" в пароле подсказывает атакующему
    # слишком много, и появление его в passphrase читается как приглашение
    "root", "sudo", "admin", "login", "guest", "super", "master",
)


# Минимальное расстояние Хэмминга между любыми двумя словами.
#
# Требование не косметическое. При расстоянии 2 слова «babab» и «babac» обе
# валидны, и опечатка в одной букве даёт пароль, который ВЫГЛЯДИТ правильным:
# пользователь получает «пароль неверен» и теряет доступ к своим данным без
# подсказки, где ошибка. При расстоянии 3 промах на 1-2 буквы физически не может
# дать другое слово словаря, то есть ошибка обнаруживается сама.
#
# Расстояние 3 недостижимо в произносимом семействе CVC, и это доказуемо:
# при фиксированной тройке гласных consonant-тройки должны различаться во всех
# трёх позициях, то есть их не больше 16, а троек гласных 125. Потолок —
# 125 * 16 = 2000 слов, до 4096 не дотянуть ни одному алгоритму. Поэтому
# алфавит полный, а слова получаются непроизносимыми: это осознанный размен
# прочности на читаемость, и проигрывать здесь нечего.
MIN_HAMMING = 3

# Алфавит писем — 26 символов, а код строится над GF(27): в поле 27 элементов,
# лишний один отбрасывается. Отбрасывание символа расстояние НЕ уменьшает —
# подмножество кода по-прежнему имеет d >= 3. Строить над Z_26 нельзя: у
# кольца есть делители нуля, и проверка на d=3 ломается, например для разности
# (0, 13, 13) — 2*13 == 0 mod 26. Это не теоретическая тонкость, а вторая
# неработающая реализация подряд, поэтому класс выбран явно.
GF27_SIZE = 27

# Порядок буквы в слове — это полевое вычисление, а не арифметика по модулю
# числа букв. Ставим буквы первыми, два символа чётности последними.
#
# Минимальное расстояние 3 гарантировано конструкцией, а не подбором: у кода
# веса 1 или 2 не было бы, только если бы какие-то два из пяти столбцов
# порождающей матрицы были линейно зависимы. Проверено: все десять пар
# независимы. Отсюда 27^3 = 19683 кодовых слов, из которых отбираются 4096.
_MAX_CODEWORDS = GF27_SIZE ** 3


def _trits(x: int) -> tuple:
    """Элемент GF(27) как тройка троек: x = a + 3b + 9c, a,b,c in {0,1,2}."""
    return (x % 3, (x // 3) % 3, (x // 9) % 3)


def _pack(t: tuple) -> int:
    return t[0] + 3 * t[1] + 9 * t[2]


def _mul_t(d: tuple) -> tuple:
    """Умножение на t в GF(27) = GF(3)[t] / (t^3 - t - 1).

    Многочлен t^3 - t - 1 неприводим над GF(3): корней 0, 1, 2 нет, а для
    многочлена третьей степени отсутствие корней означает неприводимость.
    Отсюда t^3 = t + 1, и
        t*(a + b*t + c*t^2) = a*t + b*t^2 + c*(1 + t) = c + (a+c)*t + b*t^2.
    """
    a, b, c = d
    return (c, (a + c) % 3, b)


def _mul_2(d: tuple) -> tuple:
    """Умножение на 2 = (2,0,0): поэлементно по модулю 3."""
    return ((d[0] * 2) % 3, (d[1] * 2) % 3, (d[2] * 2) % 3)


def _parity(a: int, b: int, c: int) -> tuple:
    """Два символа чётности: p1 = a+b+c, p2 = a + 2b + 3c, где 3 это t."""
    ta, tb, tc = _trits(a), _trits(b), _trits(c)
    s, t3 = _mul_2(tb), _mul_t(tc)
    p1 = tuple((ta[i] + tb[i] + tc[i]) % 3 for i in range(3))
    p2 = tuple((ta[i] + s[i] + t3[i]) % 3 for i in range(3))
    return _pack(p1), _pack(p2)


def _signature_nums(d: list) -> list:
    """Все 3-буквенные подпоследовательности как числа, без строк.

    Два слова на расстоянии меньше MIN_HAMMING обязаны совпасть хотя бы на трёх
    позициях, то есть дать общую подпоследовательность. Поэтому проверка через
    множество подпоследовательностей точна, а не эвристическая, и стоит
    C(5,3) = 10 операций на слово вместо перебора всех пар.

    Ключ включает НОМЕР ТРОЙКИ ПОЗИЦИЙ, и это не косметика. Без него совпадение
    значений в разных тройках позиций даёт одну и ту же подпоследовательность:
    у слов «cwrci» и «ilwci» буквы c,c,i стоят на тройке (1,3,4) у первого и
    (2,3,4) у второго, значение одно, а слова не имеют ничего общего. С таким
    ключом валидатор браковал корректный код, а жадный отбор на нём же терял
    три четверти слов.
    """
    out = []
    triple = 0
    for i in range(3):
        a = d[i]
        for j in range(i + 1, 4):
            b = d[j]
            for k in range(j + 1, 5):
                out.append((a * 676 + b * 26 + d[k]) * 10 + triple)
                triple += 1
    return out


def build_words() -> list:
    """Отбирает WORD_COUNT слов из MDS-кода над GF(27) с расстоянием >= 3.

    Отбор разбросан линейным конгруэнтным генератором по пространству сообщений,
    чтобы буквы в паролях не приходили в лексикографическом порядке и первые
    строки заголовка не были вида «aaaaa, aaabb, ...».
    """
    words = []
    seen = set()
    step, idx = 4753, 0  # gcd(step, 27^3) = 1 -> полный период
    # Граница сверху — размер пространства сообщений, а не «пока не хватит»:
    # так цикл физически не может стать длиннее 19683 итераций.
    for _ in range(_MAX_CODEWORDS):
        if len(words) == WORD_COUNT:
            break
        idx = (idx + step) % _MAX_CODEWORDS
        a, b, c = idx // 729, (idx // 27) % 27, idx % 27
        p1, p2 = _parity(a, b, c)
        # Элемент 26 в GF(27) не соответствует букве, такие слова пропускаем.
        if 26 in (a, b, c, p1, p2):
            continue
        word = "".join(ALPHABET[x] for x in (a, b, c, p1, p2))
        if word in seen:
            continue
        if not any(ALPHABET[x] in "aeiou" for x in (a, b, c, p1, p2)):
            continue
        if any(bad in word for bad in BLOCK_SUBSTRINGS):
            continue
        seen.add(word)
        words.append(word)

    if len(words) < WORD_COUNT:
        raise SystemExit(
            f"набрано {len(words)} слов из {WORD_COUNT}. Проверь фильтры "
            "(гласная, запрещённые подстроки) или константы кода — молча "
            "уходить с неполным словарём нельзя."
        )
    return words


def validate(words: list) -> None:
    """Проверяет ограничения. Любое нарушение — ненулевой код возврата."""
    errors = []

    if len(words) != WORD_COUNT:
        errors.append(f"слов {len(words)}, ожидалось {WORD_COUNT}")

    bad_chars = sorted({c for w in words for c in w if c not in "abcdefghijklmnopqrstuvwxyz"})
    if bad_chars:
        errors.append(f"недопустимые символы: {''.join(bad_chars)}")

    wrong_len = [w for w in words if len(w) != WORD_BYTES]
    if wrong_len:
        errors.append(f"длина не {WORD_BYTES}: {wrong_len[:5]}")

    if len(set(words)) != len(words):
        errors.append("есть повторы")

    prefixes = {}
    for w in words:
        prefixes.setdefault(w[:PREFIX_BYTES], []).append(w)
    shared = {p: v for p, v in prefixes.items() if len(v) > 1}
    if shared:
        sample = list(shared.items())[:5]
        errors.append(f"общие первые {PREFIX_BYTES} букв: {sample}")

    # Минимальное расстояние Хэмминга проверяется через множество
    # 3-буквенных подпоследовательностей, а не попарным сравнением.
    #
    # Попарный вариант здесь непригоден: 4096 слов дают 8.4 млн пар, и это в
    # Python минуты на одном ядре — ровно тот расход, который уже один раз
    # положил этой машине процессор. Эквивалентная проверка через подпоследова-
    # тельности O(n) точна: если два слова ближе MIN_HAMMING, они совпадают на
    # трёх позициях, то есть дают общую 3-подпоследовательность.
    sig_seen = {}
    for w in words:
        d = [ord(c) - 97 for c in w]
        # Дедупликация обязательна, а не косметика: у слова с повторяющимися
        # буквами разные тройки позиций дают одну и ту же подпоследовательность
        # («abbac» — позиции 0,1,2 и 0,1,3 обе дают «abb»). Без set() слово
        # обвиняло бы само себя в совпадении на трёх позициях.
        own = set(_signature_nums(d))
        clash = next((sig_seen[sig] for sig in own if sig in sig_seen), None)
        if clash is not None:
            errors.append(
                f"{clash!r} и {w!r} совпадают на трёх позициях "
                f"(расстояние < {MIN_HAMMING})"
            )
        else:
            for sig in own:
                sig_seen[sig] = w

    blocked = [w for w in words if any(bad in w for bad in BLOCK_SUBSTRINGS)]
    if blocked:
        errors.append(f"запрещённые слова: {blocked[:5]}")

    if errors:
        for e in errors:
            print(f"ОШИБКА: {e}", file=sys.stderr)
        raise SystemExit(1)

    print(f"словарь валиден: {len(words)} слов, "
          f"{len(words).bit_length() - 1} бит на слово, "
          f"префиксов {len(prefixes)} уникальных, "
          f"мин. расстояние {MIN_HAMMING}")


def _word_rows(words: list, indent: str) -> list:
    """Строки со словами. Слова идут подряд, доступ — по фиксированной длине.

    Так вместо массива из 4096 указателей (16 КБ .rodata на каждый включающий
    TU) идёт одна строка 24 КБ, и разрядность индекса не зависит от того, откуда
    взяли слово.
    """
    stride = WORD_BYTES + 1  # плюс терминатор
    # Ровно 12 слов на строку: 12*6 = 72 символа данных плюс кавычки и пробелы
    # укладываются в 80 колонок без переноса посередине слова.
    per_line = 12
    rows = []
    for i in range(0, len(words), per_line):
        chunk = "".join(w + "\0" for w in words[i:i + per_line])
        # NUL на границе слова пишем escape-последовательностью \0 и сам байт
        # НЕ добавляем: f"\\0{c}" подставил бы и escape, и сам NUL, и строка в
        # C обрывалась бы на первом же слове. Здесь c не используется вовсе.
        esc = "".join(
            "\\0" if (c == "\0" and j % stride == stride - 1) else c
            for j, c in enumerate(chunk)
        )
        rows.append(f'{indent}"{esc}"')
    rows.append(indent + ";")
    return rows


# Объявление таблицы вынесено из определения намеренно, и на то были причины.
# Первая версия держала `const char kWords[]` прямо в заголовке — у такой
# декларации ВНУТРЕННЯЯ связность, и каждый включающий TU получал свою копию
# 24 КБ. Затем попробовали `inline const char kWords[]`: это уже одна копия, но
# C++17, а проект собирается gnu++11, и gcc предупреждал "inline variables are
# only available with -std=c++17". Поднимать стандарт ради таблицы нельзя, это
# задевает компиляцию ядра Arduino. Третья попытка — литерал внутри
# `inline constexpr const char* words()` — формально чистая, но строковые
# литералы функций линкер не склеивает: флеш вырос на 24.6 КБ, ровно на лишний
# TU. Четвёртая, шаблон-носитель Words<void>, не линковалась вовсе: static
# constexpr в классе требует определителя, а определить специализацию шаблона
# вне класса в C++11 нельзя (только в C++17).
#
# Остаётся классика: extern-объявление здесь, ровно одно определение в .cpp.
# Одна копия на программу при любом числе включающих файлов, и компилятор молчит.
WORDLIST_DECL = """// Таблица слов. Определена ровно один раз, в src/wordlist.cpp.
extern const char kWords[];

// Слово по индексу: возврат указателя на нуль-терминированную строку.
constexpr const char* word(size_t i) {
  return kWords + i * kWordStride;
}
"""


def render(words: list) -> str:
    """Печатает include/wordlist.h."""
    stride = WORD_BYTES + 1
    out = []
    out.append("#pragma once")
    out.append("")
    out.append("// Файл сгенерирован scripts/wordlist.py. Правь скрипт, не эти файлы:")
    out.append("//     python3 scripts/wordlist.py")
    out.append("//     python3 scripts/wordlist.py --check   # проверка без записи")
    out.append("//")
    out.append(f"// {WORD_COUNT} слов по {WORD_BYTES} букв, {len(words).bit_length() - 1} бит на слово.")
    out.append(f"// Минимальное расстояние Хэмминга {MIN_HAMMING}: промах в 1-2 буквы не может дать")
    out.append("// другое слово словаря, то есть опечатка обнаруживается сама.")
    out.append("// Слова непроизносимые и это осознанное: с расстоянием 3 в произносимом")
    out.append(f"// семействе CVC потолок {125 * 16} слов, а нужно {WORD_COUNT}.")
    out.append("// Словом выбирается равномерный индекс, а не слово из словаря.")
    out.append("//")
    out.append("// Таблица объявлена extern и ОПРЕДЕЛЕНА один раз, в src/wordlist.cpp:")
    out.append("// иначе каждый включающий TU тащил бы свою копию 24 КБ. Подробности")
    out.append("// о выборе этого приёма — в scripts/wordlist.py.")
    out.append("")
    out.append("#include <stddef.h>")
    out.append("")
    out.append("namespace pm {")
    out.append("namespace wordlist {")
    out.append("")
    out.append(f"constexpr size_t kWordCount = {WORD_COUNT};")
    out.append(f"constexpr size_t kWordBytes = {WORD_BYTES};")
    out.append(f"constexpr size_t kWordStride = {stride};")
    out.append("")
    out.append(WORDLIST_DECL.rstrip())
    out.append("")
    out.append("}  // namespace wordlist")
    out.append("}  // namespace pm")
    out.append("")
    return "\n".join(out)


def render_source(words: list) -> str:
    """Печатает src/wordlist.cpp — единственное определение таблицы."""
    out = []
    out.append("// Файл сгенерирован scripts/wordlist.py. Правь скрипт, не этот файл:")
    out.append("//     python3 scripts/wordlist.py")
    out.append("//     python3 scripts/wordlist.py --check   # проверка без записи")
    out.append("//")
    out.append("// Единственное место, где таблица слов существует как объект. Заголовок")
    out.append("// объявляет её extern, поэтому 24 КБ словаря попадают в прошивку РОВНО")
    out.append("// один раз, сколько бы файлов его ни включали.")
    out.append("")
    out.append('#include "wordlist.h"')
    out.append("")
    out.append("namespace pm {")
    out.append("namespace wordlist {")
    out.append("")
    out.append("const char kWords[] =")
    out.extend(_word_rows(words, "    "))
    out.append("")
    out.append("}  // namespace wordlist")
    out.append("}  // namespace pm")
    out.append("")
    return "\n".join(out)


ROOT = pathlib.Path(__file__).resolve().parent.parent
HEADER = ROOT / "include" / "wordlist.h"
SOURCE = ROOT / "src" / "wordlist.cpp"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="только проверить заголовок, ничего не записывать")
    args = ap.parse_args()

    words = build_words()
    validate(words)
    outputs = {HEADER: render(words), SOURCE: render_source(words)}

    if args.check:
        stale = []
        for path, rendered in outputs.items():
            if not path.exists():
                stale.append(f"{path} отсутствует")
            elif path.read_text(encoding="utf-8") != rendered:
                stale.append(f"{path} не соответствует генератору")
        if stale:
            for line in stale:
                print(f"ОШИБКА: {line}", file=sys.stderr)
            return 1
        for path in outputs:
            print(f"{path.name}: соответствует генератору")
        return 0

    for path, rendered in outputs.items():
        path.write_text(rendered, encoding="utf-8")
        print(f"записан {path} ({len(rendered)} байт)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
