#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import datetime
import json
import os
import re
import sys


STATE_FILE_DEFAULT = "/tmp/alerts.json"
LOG_FILE = "/tmp/alerts.log"
VERBOSE = False
GROUP_PATTERN = r"SG/([^,/]+)"


def write_log(message, level):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = "{} [{}] {}".format(now, level, message)

    file = open(LOG_FILE, "a", encoding="utf-8")
    file.write(log_message + "\n")
    file.close()

    if VERBOSE:
        print(log_message)


def extract_group_keys(groups):
    matches = re.findall(GROUP_PATTERN, groups)
    group_keys = []

    for match in matches:
        group_key = match.strip()
        if group_key == "":
            continue
        if group_key in group_keys:
            continue
        group_keys.append(group_key)

    return group_keys


def load_state(state_file):
    if not os.path.exists(state_file):
        write_log("JSON-файл отсутствует, будет создан новый: {}".format(state_file), "INFO")
        return {}

    try:
        file = open(state_file, "r", encoding="utf-8")
        content = file.read()
        file.close()
    except OSError as error:
        write_log("Ошибка чтения JSON-файла {}: {}".format(state_file, error), "ERROR")
        raise

    if content.strip() == "":
        return {}

    try:
        state = json.loads(content)
    except ValueError as error:
        write_log("Ошибка разбора JSON-файла {}: {}".format(state_file, error), "ERROR")
        raise

    if not isinstance(state, dict):
        raise ValueError("Неверная структура JSON: корневой элемент должен быть словарём")

    return state


def save_state(state_file, state):
    try:
        file = open(state_file, "w", encoding="utf-8")
        json.dump(
            state,
            file,
            ensure_ascii=False,
            indent=4
        )
        file.write("\n")
        file.close()
    except OSError as error:
        write_log("Ошибка записи JSON-файла {}: {}".format(state_file, error), "ERROR")
        raise

    write_log("Данные сохранены в {}".format(state_file), "INFO")


def add_alert(args):
    group_keys = extract_group_keys(args.groups)

    if len(group_keys) == 0:
        raise ValueError("Отсутствуют группы, начинающиеся с SG/")

    write_log("Получены ключи групп: {}".format(", ".join(group_keys)), "INFO")

    state = load_state(args.state_file)

    alert_data = {
        "event": args.event,
        "insightId": args.insight_id,
        "groups": args.groups,
        "triggerTime": args.trigger_time,
        "trigName": args.trig_name,
        "message": args.message,
        "severity": args.severity
    }

    for group_key in group_keys:
        if group_key in state:
            write_log("Ключ {} обновлён".format(group_key), "INFO")
        else:
            write_log("Ключ {} добавлен".format(group_key), "INFO")
        state[group_key] = alert_data.copy()

    save_state(args.state_file, state)


def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode")
    parser.add_argument("--event", required=True)
    parser.add_argument("--insightId", dest="insight_id", required=True)
    parser.add_argument("--groups", required=True)
    parser.add_argument("--triggerTime", dest="trigger_time", required=True)
    parser.add_argument("--trigName", dest="trig_name", required=True)
    parser.add_argument("--message", required=True)
    parser.add_argument("--severity", required=True)
    parser.add_argument("--state-file", dest="state_file", default=STATE_FILE_DEFAULT)
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def main():
    global VERBOSE

    parser = create_parser()
    args = parser.parse_args()
    VERBOSE = args.verbose

    try:
        write_log("Запуск скрипта в режиме {}".format(args.mode), "INFO")
        write_log("Выбранный режим: {}".format(args.mode), "INFO")

        if args.mode != "add":
            raise ValueError("Неподдерживаемый режим: {}".format(args.mode))

        add_alert(args)

        write_log("Работа скрипта завершена успешно", "INFO")
        sys.exit(0)
    except Exception as error:
        write_log("Ошибка выполнения: {}".format(error), "ERROR")
        sys.exit(1)


if __name__ == "__main__":
    main()
