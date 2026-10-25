#!/usr/bin/env python3
"""Генератор и валидатор мастер-словаря QuipuChip.

Словарь — это МАТЕМАТИЧЕСКОЕ требование, а не перечень: 4096 слов дают ровно
12 бит на слово, и любое слово, добавленное «для удобства», либо ломает счёт
(4097 слов = 12.0004 бита на слово вместо ровно 12), либо молча ослабляет
гарантию. Проверять это вручную нельзя, поэтому список собирается скриптом,
валидатор проверяет ограничения, а результат кладётся в core/src/wordlist.rs и
живёт дальше как обычный исходный файл.

Слова РЕАЛЬНЫЕ английские, по 5 букв, взятые из scripts/words5.txt. Отбор
описан в шапке этого файла: курируемый список Wordle (без имён собственных и
обсценной лексики), проранжированный по частоте в корпусе FrequencyWords.
Порядок в words5.txt задаёт и порядок в таблице: самые частотные и узнаваемые
слова идут первыми, но на безопасность это не влияет — пароль берёт индекс
словом равномерно по всем 4096.

Гарантии расстояния Хэмминга >= 3 больше НЕТ. Среди реальных слов она
доказуемо недостижима (потолок для произносимых семейств ~2000 слов), и это
осознанный размен, принятый владельцем: словарь читаем человеком, а потерянная
типозащита «неверный пароль выглядит правильным» покрывается тем, что любой
промах всё равно даёт неверную сверку. Несущая способность таблицы (12 бит на
слово) от этого не меняется.

Ограничения (каждое проверяется валидатором, а не только комментируется):

  * ровно 4096 слов, ровно по 5 букв, только a-z;
  * слова уникальны;
  * нет слов, содержащих запрещённые подстроки из BLOCK_SUBSTRINGS, и нет
    слов из WORD_EXCLUDE. Проверка по подстрокам — best-effort: полностью
    исключить осмысленную непристойность автоматически нельзя, и это
    ограничение самого подхода, а не недоработка скрипта.

Запуск:
    python3 scripts/wordlist.py            пересобрать core/src/wordlist.rs
    python3 scripts/wordlist.py --check    проверить, что файл соответствует
                                           генератору (для CI и ревью)
"""

import argparse
import pathlib
import sys

# Точное число — часть контракта: config::kMasterWords слов берут по 12 бит
# каждое (random_word_index отрезает старшие 12 бит u32 без отбраковки).
# config::kMasterDigits добирает остаток. Менять 4096 нельзя отдельно от
# password.rs.
WORD_COUNT = 4096
WORD_BYTES = 5

# Подстроки, из-за которых слово отбрасывается. Только те, что действительно
# недопустимы или опасны: трёхбуквенные безобидные вроде "oil" или "war" сюда
# НЕ входят, потому что в пятибуквенном слове они встречаются часто и вырезали
# бы добрую половину словаря ради ничего.
BLOCK_SUBSTRINGS = (
    # непристойное и оскорбительное
    "anal", "anus", "arse", "bast", "bitch", "boll", "boob", "butt",
    "cock", "coon", "cunt", "damn", "dick", "dyke", "fart", "fuk",
    "fuck", "fag", "hell", "homo", "jizz", "kike", "nigg", "penis",
    "piss", "poop", "porn", "prick", "pube", "pussy", "queer", "rape",
    "sex", "shit", "slut", "spic", "tit", "turd", "twat", "wank",
    "whore",
    # сленговые прозвища и оскорбления, реально встречающиеся в частотных
    # словарях (в синтетическом списке их не могло быть, поэтому в старом
    # перечне их не было)
    "chink", "gook", "honky", "negro", "sambo",
    # инструменты доступа: слово "admin" в пароле подсказывает атакующему
    # слишком много, и появление его в passphrase читается как приглашение
    "root", "sudo", "admin", "login", "guest", "super", "master",
)

# Целые слова, отбрасываемые отдельно: подстрока "ass" не входит в
# BLOCK_SUBSTRINGS сознательно — она обезглавила бы class/glass/grass/mass.
# Один случай ("asses") ровно это и делает в сленговом прочтении, поэтому он
# вынесен сюда как явный список, а не отсев по подстроке.
WORD_EXCLUDE = (
    "asses",
)


def load_words() -> list:
    """Читает scripts/words5.txt: строки из комментариев пропускаются."""
    path = ROOT / "scripts" / "words5.txt"
    words = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        words.append(line)
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

    blocked = [w for w in words if any(bad in w for bad in BLOCK_SUBSTRINGS)]
    if blocked:
        errors.append(f"запрещённые слова: {blocked[:5]}")

    excluded = [w for w in words if w in WORD_EXCLUDE]
    if excluded:
        errors.append(f"слова из WORD_EXCLUDE: {excluded}")

    if errors:
        for e in errors:
            print(f"ОШИБКА: {e}", file=sys.stderr)
        raise SystemExit(1)

    print(f"словарь валиден: {len(words)} слов, "
          f"{len(words).bit_length() - 1} бит на слово")


def render_rust(words: list) -> str:
    """Печатает core/src/wordlist.rs — таблицу для Rust-ядра.

    Раскладка бит-совместима с прежними версиями: одна строка, слово из 5 букв
    плюс NUL (stride 6). Строковый литерал продолжается обратным слэшем в
    конце строки, который в Rust съедает перевод строки и следующий отступ,
    поэтому переносы только косметические и на содержимое не влияют.
    """
    stride = WORD_BYTES + 1
    per_line = 12
    chunks = [
        "".join(w + r"\0" for w in words[i:i + per_line])
        for i in range(0, len(words), per_line)
    ]
    out = []
    out.append("//! Master wordlist, generated by scripts/wordlist.py from")
    out.append("//! scripts/words5.txt. Edit the source list, not this file:")
    out.append("//!     python3 scripts/wordlist.py")
    out.append("//!     python3 scripts/wordlist.py --check")
    out.append("//!")
    out.append(f"//! {WORD_COUNT} real English words of {WORD_BYTES} letters, "
               f"{len(words).bit_length() - 1} bits per word, ordered by")
    out.append("//! descending frequency (see scripts/words5.txt for sources).")
    out.append("//!")
    out.append("//! The table is one byte string with a NUL after every word (stride 6),")
    out.append("//! so a word's index does not depend on its position.")
    out.append("")
    out.append("/// Number of words in the list.")
    out.append(f"pub const WORD_COUNT: usize = {WORD_COUNT};")
    out.append("/// Letters per word (excluding the NUL terminator).")
    out.append(f"pub const WORD_BYTES: usize = {WORD_BYTES};")
    out.append("/// Byte stride between words: [`WORD_BYTES`] plus the NUL terminator.")
    out.append(f"pub const WORD_STRIDE: usize = {stride};")
    out.append("")
    out.append(f"/// {WORD_COUNT} words of {WORD_BYTES} letters, each followed by NUL.")
    out.append("pub static WORDS: &[u8; WORD_COUNT * WORD_STRIDE] = b\"\\")
    for idx, chunk in enumerate(chunks):
        tail = "\\" if idx < len(chunks) - 1 else "\";"
        out.append(f"    {chunk}{tail}")
    out.append("")
    out.append("/// Word at index `i`, without the trailing NUL.")
    out.append("#[inline]")
    out.append("pub fn word(i: usize) -> &'static [u8] {")
    out.append("    let start = i * WORD_STRIDE;")
    out.append("    &WORDS[start..start + WORD_BYTES]")
    out.append("}")
    out.append("")
    return "\n".join(out)


ROOT = pathlib.Path(__file__).resolve().parent.parent
RUST = ROOT / "core" / "src" / "wordlist.rs"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="только проверить сгенерированный файл, ничего не записывать")
    args = ap.parse_args()

    words = load_words()
    validate(words)
    outputs = {RUST: render_rust(words)}

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