import argparse
import copy
import json
import logging
import os
import sys

from cnf import ALERTS_FILE
from cnf import LOG_FILE
from cnf import IncTemplate


# Настройка аргументов командной строки.
parser = argparse.ArgumentParser()
parser.add_argument(
    "-v",
    "--verbose",
    action="store_true"
)
parser.add_argument(
    "mode",
    choices=["add", "get"]
)
parser.add_argument(
    "--event",
    default=""
)
parser.add_argument(
    "--tags",
    default=""
)
parser.add_argument(
    "--severity",
    default=""
)
parser.add_argument(
    "--insightId",
    default=""
)
parser.add_argument(
    "--groups",
    default=""
)
parser.add_argument(
    "--triggerTime",
    default=""
)
parser.add_argument(
    "--trigName",
    default=""
)
parser.add_argument(
    "--message",
    default=""
)
parser.add_argument(
    "--timestamp",
    default=""
)
args = parser.parse_args()

# Настройка логирования в файл и, при необходимости, в stdout.
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    encoding="utf-8"
)
logger = logging.getLogger("alerts_cli")

if args.verbose:
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter("%(levelname)s: %(message)s")
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

try:
    logger.info("Запуск скрипта. Режим: " + args.mode)

    # Создание файла хранилища, если он отсутствует.
    if not os.path.exists(ALERTS_FILE):
        file = open(ALERTS_FILE, "w", encoding="utf-8")
        json.dump([], file, ensure_ascii=False, indent=4)
        file.close()
        logger.info("Файл хранилища создан: " + ALERTS_FILE)

    # Чтение текущего содержимого хранилища.
    file = open(ALERTS_FILE, "r", encoding="utf-8")
    alerts = json.load(file)
    file.close()

    # Проверка корневого типа JSON.
    if type(alerts) != list:
        error_message = "Ошибка: корневой объект JSON должен быть списком. Файл: " + ALERTS_FILE
        logger.error(error_message)
        print(error_message, file=sys.stderr)
        sys.exit(1)

    # Режим добавления нового объекта.
    if args.mode == "add":
        new_object = copy.deepcopy(IncTemplate[0])

        new_object["event"] = args.event
        new_object["tags"] = args.tags
        new_object["severity"] = args.severity
        new_object["insightId"] = args.insightId
        new_object["groups"] = args.groups
        new_object["triggerTime"] = args.triggerTime
        new_object["trigName"] = args.trigName
        new_object["message"] = args.message
        new_object["timestamp"] = args.timestamp

        alerts.append(new_object)

        file = open(ALERTS_FILE, "w", encoding="utf-8")
        json.dump(alerts, file, ensure_ascii=False, indent=4)
        file.close()

        logger.info(
            "Объект добавлен. insightId: " + args.insightId + ". Всего объектов: " + str(len(alerts))
        )
        sys.exit(0)

    # Режим вывода всех объектов.
    if args.mode == "get":
        print(
            json.dumps(
                alerts,
                ensure_ascii=False,
                indent=4
            )
        )
        sys.exit(0)

except (OSError, ValueError, IndexError, TypeError, KeyError) as error:
    error_message = "Ошибка выполнения: " + str(error)
    logger.error(error_message)
    print(error_message, file=sys.stderr)
    sys.exit(1)
