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


def extract_root_keys_from_groups(groups):
    matches = re.findall(GROUP_PATTERN, groups)
    root_keys = []

    for match in matches:
        root_key = match.strip()
        if root_key == "":
            continue
        if root_key in root_keys:
            continue
        root_keys.append(root_key)

    return root_keys


def load_alert_dictionary_list(state_file):
    if not os.path.exists(state_file):
        write_log("State file does not exist, a new one will be created: {}".format(state_file), "INFO")
        return []

    try:
        file = open(state_file, "r", encoding="utf-8")
        content = file.read()
        file.close()
    except OSError as error:
        write_log("Failed to read state file {}: {}".format(state_file, error), "ERROR")
        raise

    if content.strip() == "":
        return []

    try:
        alert_dictionary_list = json.loads(content)
    except ValueError as error:
        write_log("Failed to parse state file {}: {}".format(state_file, error), "ERROR")
        raise

    if not isinstance(alert_dictionary_list, list):
        raise ValueError("Invalid state structure: root element must be a list")

    for alert_dictionary in alert_dictionary_list:
        if not isinstance(alert_dictionary, dict):
            raise ValueError("Invalid state structure: each list item must be a dictionary")

    return alert_dictionary_list


def save_alert_dictionary_list(state_file, alert_dictionary_list):
    try:
        file = open(state_file, "w", encoding="utf-8")
        json.dump(
            alert_dictionary_list,
            file,
            ensure_ascii=False,
            indent=4
        )
        file.write("\n")
        file.close()
    except OSError as error:
        write_log("Failed to write state file {}: {}".format(state_file, error), "ERROR")
        raise

    write_log("State saved to {}".format(state_file), "INFO")


def find_alert_dictionary_by_root_key(alert_dictionary_list, root_key):
    for alert_dictionary in alert_dictionary_list:
        if root_key in alert_dictionary:
            return alert_dictionary
    return None


def get_integer_value(value, field_name):
    try:
        return int(value)
    except ValueError:
        raise ValueError("Invalid integer value for {}: {}".format(field_name, value))


def create_event_one_alert_data(args):
    alert_data = {
        "event": "1",
        "insightId": args.insight_id,
        "groups": args.groups,
        "triggerTime": args.trigger_time,
        "trigName": args.trig_name,
        "message": args.message,
        "severity": args.severity,
        "balance": 1
    }
    return alert_data


def apply_event_one_to_alert_list(alert_dictionary_list, root_key, args):
    alert_dictionary = find_alert_dictionary_by_root_key(alert_dictionary_list, root_key)
    new_severity = get_integer_value(args.severity, "severity")

    if alert_dictionary is None:
        alert_data = create_event_one_alert_data(args)
        alert_dictionary_list.append({root_key: alert_data.copy()})
        write_log("Root key {} added with balance 1".format(root_key), "INFO")
        return

    alert_data = alert_dictionary[root_key]
    if not isinstance(alert_data, dict):
        raise ValueError("Invalid alert data for root key {}".format(root_key))

    old_balance = alert_data.get("balance", 0)
    old_balance = get_integer_value(old_balance, "balance")
    old_severity = alert_data.get("severity", "0")
    old_severity = get_integer_value(old_severity, "severity")

    alert_data["balance"] = old_balance + 1
    if new_severity > old_severity:
        alert_data["severity"] = args.severity

    write_log("Root key {} updated, balance is {}".format(root_key, alert_data["balance"]), "INFO")


def apply_event_zero_to_alert_list(alert_dictionary_list, root_key):
    alert_dictionary = find_alert_dictionary_by_root_key(alert_dictionary_list, root_key)

    if alert_dictionary is None:
        write_log("Root key {} was not found for event 0, nothing changed".format(root_key), "INFO")
        return

    alert_data = alert_dictionary[root_key]
    if not isinstance(alert_data, dict):
        raise ValueError("Invalid alert data for root key {}".format(root_key))

    old_balance = alert_data.get("balance", 0)
    old_balance = get_integer_value(old_balance, "balance")
    alert_data["balance"] = old_balance - 1

    write_log("Root key {} decreased, balance is {}".format(root_key, alert_data["balance"]), "INFO")


def update_alert_dictionary_list(args):
    root_keys = extract_root_keys_from_groups(args.groups)

    if len(root_keys) == 0:
        raise ValueError("No groups starting with SG/ were found")

    write_log("Extracted root keys: {}".format(", ".join(root_keys)), "INFO")

    event_value = get_integer_value(args.event, "event")
    if event_value != 0 and event_value != 1:
        raise ValueError("Unsupported event value: {}".format(args.event))

    alert_dictionary_list = load_alert_dictionary_list(args.state_file)

    for root_key in root_keys:
        if event_value == 1:
            apply_event_one_to_alert_list(alert_dictionary_list, root_key, args)
        else:
            apply_event_zero_to_alert_list(alert_dictionary_list, root_key)

    save_alert_dictionary_list(args.state_file, alert_dictionary_list)


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
        write_log("Script started in mode {}".format(args.mode), "INFO")
        write_log("Selected mode: {}".format(args.mode), "INFO")

        if args.mode != "add":
            raise ValueError("Unsupported mode: {}".format(args.mode))

        update_alert_dictionary_list(args)

        write_log("Script finished successfully", "INFO")
        sys.exit(0)
    except Exception as error:
        write_log("Execution failed: {}".format(error), "ERROR")
        sys.exit(1)


if __name__ == "__main__":
    main()
