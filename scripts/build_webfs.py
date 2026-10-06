Import("env")  # noqa: F821  — объект SCons-окружения подставляет PlatformIO

"""Сборка и прошивка образа раздела web (LittleFS) одной командой.

Зачем свой скрипт, если в espressif32 есть штатные buildfs/uploadfs:

    fetch_fs_size() в platforms/espressif32/builder/main.py перебирает разделы
    и берёт ПОСЛЕДНИЙ с type=data, subtype=spiffs, БЕЗ break. В partitions.csv
    таких разделов два — vault и web — поэтому uploadfs пишет образ туда,
    куда попал последний. Сейчас это web, но это совпадение порядка строк, а не
    намерение: перестановка таблицы молча отправила бы образ статики в vault и
    стёрла хранилище паролей.

Скрипт ищет раздел по ИМЕНИ ("web") и прошивает по его собственному смещению,
поэтому от порядка строк в partitions.csv не зависит. Штатный uploadfs при этом
остаётся доступен, но если он выбрал бы не web — скрипт ругается и отменяет
сборку, вместо того чтобы тихо затереть vault.

Параметры образа обязаны совпадать с тем, чем раздел потом монтируется:

    page 256   — CONFIG_LITTLEFS_PAGE_SIZE=256 в sdkconfig этого SDK
    block 4096 — дефолт esp_littlefs (LittleFS.begin() их не переопределяет)

Целевые файлы:
    pio run -t webfs      собрать образ web и залить его в раздел web
    pio run -t uploadall  залить прошивку И образ web
    pio run               только собрать (ничего не заливая)
"""

import csv
import os
import shutil
import sys
import time

from SCons.Script import COMMAND_LINE_TARGETS

WEB_LABEL = "web"

# Сколько ждём перечисления UART после hard reset, который делает esptool.
PORT_SETTLE_SEC = 6

# Подтипы, которые espressif32 считает файловыми разделами при выборе цели
# прошивки образа. Держим список в точности как в builder/main.py.
FS_SUBTYPES = ("spiffs", "fat", "littlefs")

MKLITTLEFS_PAGE = 256
MKLITTLEFS_BLOCK = 4096

PROJECT_DIR = env.subst("$PROJECT_DIR")
PARTITIONS_CSV = env.subst("$PARTITIONS_TABLE_CSV")
BUILD_DIR = env.subst("$BUILD_DIR")
IMAGE = os.path.join(BUILD_DIR, "webfs.bin")


def fail(message):
    sys.stderr.write("\n[webfs] %s\n\n" % message)
    env.Exit(1)


def read_partitions(path):
    rows = []
    with open(path, "r", encoding="utf-8") as handle:
        # Строки-комментарии gen_esp32part.py допускает, и они же есть в нашей
        # таблице, поэтому фильтруем до csv.reader, а не после.
        lines = [line for line in handle if not line.lstrip().startswith("#")]
    for row in csv.reader(lines):
        if len(row) < 5:
            continue
        try:
            offset = int(row[3].strip(), 0)
            size = int(row[4].strip(), 0)
        except ValueError:
            continue
        rows.append(
            {
                "name": row[0].strip(),
                "type": row[1].strip(),
                "subtype": row[2].strip(),
                "offset": offset,
                "size": size,
            }
        )
    return rows


def find_partition(label):
    for row in read_partitions(PARTITIONS_CSV):
        if row["name"] == label:
            return row
    fail(
        "в %s нет раздела с меткой '%s'.\n"
        "        webfs не знает, куда писать образ, и молча угадывать не будет."
        % (os.path.relpath(PARTITIONS_CSV, PROJECT_DIR), label)
    )


def check_native_fs_target():
    """Стоп-фактор для штатного uploadfs.

    Штатная цель выберет последний файловый раздел. Если это не web —
    прошивка образа уехала бы в vault, поэтому останавливаемся.
    """
    fs_rows = [
        row
        for row in read_partitions(PARTITIONS_CSV)
        if row["type"] == "data" and row["subtype"] in FS_SUBTYPES
    ]
    if not fs_rows:
        fail("в %s нет ни одного файлового раздела" % PARTITIONS_CSV)

    chosen = fs_rows[-1]
    if chosen["name"] == WEB_LABEL:
        return

    names = ", ".join(row["name"] for row in fs_rows)
    fail(
        "штатный uploadfs выбрал бы раздел '%s' (0x%X), а не '%s'.\n"
        "        Причина: espressif32 берёт последний раздел data/spiffs, а их в "
        "таблице несколько (%s).\n"
        "        Используй 'pio run -t webfs' — он ищет раздел по имени и от "
        "порядка строк не зависит."
        % (chosen["name"], chosen["offset"], WEB_LABEL, names)
    )


def mklittlefs_path():
    package_dir = env.PioPlatform().get_package_dir("tool-mklittlefs")
    if package_dir:
        candidate = os.path.join(package_dir, "mklittlefs")
        if os.path.exists(candidate):
            return candidate
    found = shutil.which("mklittlefs")
    if found:
        return found
    fail(
        "не найден mklittlefs.\n"
        "        Ожидался пакет tool-mklittlefs: "
        "pio pkg install -g -t tool-mklittlefs"
    )


def build_webfs(**_):
    # SCons зовёт action с target=/source=/env=, поэтому подпись без аргументов
    # не подходит: **_ молча съедает их и заодно документирует, что мы их не
    # используем (у цели нет ни зависимостей, ни файлов).
    partition = find_partition(WEB_LABEL)
    tool = mklittlefs_path()

    if not os.path.isdir(os.path.join(PROJECT_DIR, "data")):
        fail("нет каталога data/ — собирать образ нечего")

    if not os.path.isdir(BUILD_DIR):
        os.makedirs(BUILD_DIR)

    command = '"%s" -c "%s" -s %d -p %d -b %d "%s"' % (
        tool,
        os.path.join(PROJECT_DIR, "data"),
        partition["size"],
        MKLITTLEFS_PAGE,
        MKLITTLEFS_BLOCK,
        IMAGE,
    )
    print("[webfs] mklittlefs -> %s (%d bytes)" % (IMAGE, partition["size"]))
    if env.Execute(command) != 0:
        fail("mklittlefs завершился с ошибкой")

    produced = os.path.getsize(IMAGE)
    if produced != partition["size"]:
        fail(
            "образ вышел %d байт, раздел web — %d байт.\n"
            "        mklittlefs дописывает образ точно до размера раздела, так "
            "что расхождение означает неверный размер в partitions.csv."
            % (produced, partition["size"])
        )


def esptool_prefix(board):
    """Общая часть команды esptool: интерпретатор, тулза и параметры записи.

    --flash_mode/--flash_freq намеренно не передаём: это поля заголовка ОБРАЗА
    ПРОШИВКИ, и для сырых данных раздела они не имеют смысла. Всё остальное
    берётся из board/*.json, чтобы не плодить второй источник правды.
    """
    return [
        '"$PYTHONEXE"',
        '"$UPLOADER"',
        "--chip", board.get("build.mcu", "esp32s3"),
        "--port", '"$UPLOAD_PORT"',
        "--baud", "$UPLOAD_SPEED",
        "--before", board.get("upload.before_reset", "default_reset"),
        "--after", board.get("upload.after_reset", "hard_reset"),
        "write_flash", "-z",
        "--flash_size", board.get("upload.flash_size", "detect"),
    ]


def flash_webfs(**_):
    partition = find_partition(WEB_LABEL)
    if not os.path.exists(IMAGE):
        fail("нет %s — сначала 'pio run -t webfs'" % IMAGE)

    arguments = esptool_prefix(env.BoardConfig())
    arguments += ["0x%X" % partition["offset"], '"%s"' % IMAGE]

    print("[webfs] write_flash 0x%X (%s)" % (partition["offset"], WEB_LABEL))
    if env.Execute(" ".join(arguments)) != 0:
        fail("esptool завершился с ошибкой")

    # esptool в конце делает hard reset, после которого CH343 пересоздаёт
    # /dev/ttyACM0. Следующее действие того же запуска откроет порт сразу и
    # поймает либо "port is busy", либо ENOENT. Ждём перечисления, чтобы
    # порядок действий внутри одной цели был воспроизводимым.
    time.sleep(PORT_SETTLE_SEC)


def upload_firmware(**_):
    """Прошивка приложения: те же образы и то же смещение, что у штатного upload.

    Команда собирается из env, а не копируется текстом: список
    FLASH_EXTRA_IMAGES (bootloader, partitions, boot_app0) платформа формирует
    сама, и его состав меняется от платы к плате.

    $UPLOADCMD платформы для этого НЕ годится: env.subst() схлопывает $SOURCE в
    пустую строку, и esptool получает нечётное число аргументов
    ("... 0x10000" без имени файла).
    """
    if env.get("UPLOAD_PROTOCOL") != "esptool":
        fail(
            "uploadall поддерживает только upload_protocol = esptool, а в "
            "проекте стоит '%s'. Для остальных протоколов прошивайте раздельно: "
            "pio run -t upload, затем pio run -t webfs." % env.get("UPLOAD_PROTOCOL")
        )

    firmware = os.path.join(BUILD_DIR, "firmware.bin")
    if not os.path.exists(firmware):
        fail("нет %s — сначала соберите прошивку: pio run" % firmware)

    arguments = esptool_prefix(env.BoardConfig())
    for offset, image in env.get("FLASH_EXTRA_IMAGES", []):
        arguments += [str(offset), '"%s"' % env.subst(image)]
    arguments += ["0x%X" % int(env.subst("$ESP32_APP_OFFSET"), 0), '"%s"' % firmware]

    print("[uploadall] write_flash firmware + %d extra image(s)"
          % len(env.get("FLASH_EXTRA_IMAGES", [])))
    if env.Execute(" ".join(arguments)) != 0:
        fail("esptool (прошивка) завершился с ошибкой")
    time.sleep(PORT_SETTLE_SEC)


env.AddTarget(
    name="webfs",
    dependencies=None,
    actions=[build_webfs, flash_webfs],
    title="Build and flash web image",
    description="Собрать образ раздела web (LittleFS) из data/ и залить его в web",
    group="upload",
)

# uploadall НЕ объявляет upload и webfs зависимостями: псевдонины целей SCons
# выполняет независимо от порядка в списке, и два esptool одновременно держат
# /dev/ttyACM0 — второй падает с "Could not exclusively lock port". Поэтому это
# одна цель с тремя ПОСЛЕДОВАТЕЛЬНЫМИ действиями: каждое завершается до старта
# следующего, плюс settle-пауза после hard reset каждой записи.
#
# Зависимость от платформенной цели buildprog обязательна: у нашей цели нет
# actions сборки, поэтому без неё uploadall молча прошивает ПРЕЖНИЙ firmware.bin
# — ровно это и показала диагностика (webfs.bin свежий, firmware.bin на 13 минут
# старше, а правки исходников в логе не появились). Строка "buildprog"
# разрешается SCons в существующий узел $BUILD_DIR/firmware.bin.
env.AddTarget(
    name="uploadall",
    dependencies=["buildprog"],
    actions=[upload_firmware, build_webfs, flash_webfs],
    title="Upload firmware and web image",
    description="Собрать и залить прошивку и образ раздела web одной командой",
    group="upload",
)

# Страховка только для штатных целей: наш webfs ищет раздел по имени и от
# порядка строк не зависит, а вот buildfs/uploadfs — зависят.
if "uploadfs" in COMMAND_LINE_TARGETS:
    check_native_fs_target()
