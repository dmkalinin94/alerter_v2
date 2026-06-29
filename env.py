# -*- coding: utf-8 -*-

import os


ENV_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")


def ReadEnvFileValue(key, default_value):
    if not os.path.exists(ENV_FILE_PATH):
        return default_value

    file = open(ENV_FILE_PATH, "r", encoding="utf-8")
    try:
        for line in file:
            stripped_line = line.strip()
            if stripped_line == "" or stripped_line.startswith("#"):
                continue
            if "=" not in stripped_line:
                continue
            name, value = stripped_line.split("=", 1)
            if name.strip() != key:
                continue
            return value.strip().strip('"').strip("'")
    finally:
        file.close()

    return default_value


def ReadEnvFileIntegerValue(key, default_value):
    value = ReadEnvFileValue(key, str(default_value))
    try:
        return int(value)
    except (TypeError, ValueError):
        return default_value


DB_HOST = ReadEnvFileValue("DB_HOST", "")
DB_PORT = ReadEnvFileIntegerValue("DB_PORT", 5432)
DB_NAME = ReadEnvFileValue("DB_NAME", "trmetrics")
DB_USER = ReadEnvFileValue("DB_USER", "")
DB_PASSWORD = ReadEnvFileValue("DB_PASSWORD", "")
