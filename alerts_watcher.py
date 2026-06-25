#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import datetime
import json
import os
import subprocess
import sys


############################### VARS ###############################

CLI_PATH_DEFAULT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "alerts_cli.py"
)
STATE_FILE_DEFAULT = "/tmp/alerts.json"
LOG_FILE = "/tmp/alerts_watcher.log"
VERBOSE = False

DATETIME_FORMAT = "%Y.%m.%d %H:%M:%S"

DEFAULT_DELETE_DELAY_MINUTES = 30


DELETE_CONDITIONS = [
    {
        "field": "eventBalance",
        "operator": "equal",
        "value": 0
    },
    {
        "field": "criticalEventBalance",
        "operator": "equal",
        "value": 0
    },
    {
        "field": "zeroBalanceTime",
        "operator": "not_empty"
    }
]

DELETE_DELAY_RULES = [
    {
        "name": "night_period",
        "weekdays": None,
        "start_time": "21:00",
        "end_time": "09:00",
        "delay_minutes": 180
    },
    {
        "name": "weekend",
        "weekdays": [5, 6],
        "start_time": None,
        "end_time": None,
        "delay_minutes": 180
    }
]


############################### ARGS ###############################


def GetArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli-path", dest="cli_path", default=CLI_PATH_DEFAULT)
    parser.add_argument("--state-file", dest="state_file", default=STATE_FILE_DEFAULT)
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args()


############################### LOGS ###############################


def WriteLog(message, level):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = "{} [{}] {}".format(now, level, message)

    file = open(LOG_FILE, "a", encoding="utf-8")
    file.write(log_message + "\n")
    file.close()

    if VERBOSE:
        print(log_message)


############################### FUNCTIONS ###############################


def RunCliCommand(command):
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
    except OSError as error:
        WriteLog("Failed to run CLI command: {}".format(error), "ERROR")
        raise

    return result


def LoadAlertPackages(args):
    if not os.path.exists(args.cli_path):
        WriteLog("CLI file was not found: {}".format(args.cli_path), "ERROR")
        sys.exit(1)

    command = [
        sys.executable,
        args.cli_path,
        "select",
        "--state-file",
        args.state_file,
        "--path",
        "$"
    ]
    WriteLog("Loading alert packages with CLI select", "INFO")
    result = RunCliCommand(command)

    if result.returncode != 0:
        WriteLog("CLI select failed with code {}".format(result.returncode), "ERROR")
        WriteLog("CLI select stderr: {}".format(result.stderr.strip()), "ERROR")
        WriteLog("CLI select stdout: {}".format(result.stdout.strip()), "ERROR")
        sys.exit(1)

    try:
        alert_dictionary_list = json.loads(result.stdout)
    except ValueError as error:
        WriteLog("CLI select stdout is not valid JSON: {}".format(error), "ERROR")
        sys.exit(1)

    if not isinstance(alert_dictionary_list, list):
        WriteLog("CLI select root result is not a list", "ERROR")
        sys.exit(1)

    WriteLog("Received alert package dictionaries: {}".format(len(alert_dictionary_list)), "INFO")
    return alert_dictionary_list


def AddSeverityActions(args, root_key):
    command = [
        sys.executable,
        args.cli_path,
        "update",
        "--state-file",
        args.state_file,
        "--path",
        "$." + root_key,
        "--severity-actions"
    ]
    result = RunCliCommand(command)

    if result.returncode != 0:
        WriteLog("Failed to add severity actions for root key {}".format(root_key), "ERROR")
        WriteLog("CLI update return code: {}".format(result.returncode), "ERROR")
        WriteLog("CLI update stderr: {}".format(result.stderr.strip()), "ERROR")
        WriteLog("CLI update stdout: {}".format(result.stdout.strip()), "ERROR")
        return False

    try:
        result_data = json.loads(result.stdout)
    except ValueError:
        result_data = {}

    added_actions = result_data.get("added", [])
    if len(added_actions) == 0:
        WriteLog("No severity actions were added for root key {}".format(root_key), "INFO")
    else:
        WriteLog("Added severity actions for root key {}: {}".format(root_key, ", ".join(added_actions)), "INFO")

    return True, len(added_actions)


def CheckDeleteCondition(alert_data, condition):
    field_name = condition.get("field")
    operator = condition.get("operator")
    expected_value = condition.get("value")
    actual_value = alert_data.get(field_name)

    if operator == "equal":
        if isinstance(expected_value, int):
            try:
                actual_integer = int(actual_value)
            except (TypeError, ValueError):
                WriteLog("Condition {} failed: value is not integer: {}".format(field_name, actual_value), "ERROR")
                return False
            result = actual_integer == expected_value
            WriteLog("Condition {} equal {} result: {}".format(field_name, expected_value, result), "INFO")
            return result

        result = actual_value == expected_value
        WriteLog("Condition {} equal {} result: {}".format(field_name, expected_value, result), "INFO")
        return result

    if operator == "not_empty":
        result = True
        if actual_value is None:
            result = False
        elif isinstance(actual_value, str) and actual_value.strip() == "":
            result = False
        WriteLog("Condition {} not_empty result: {}".format(field_name, result), "INFO")
        return result

    WriteLog("Unknown delete condition operator: {}".format(operator), "ERROR")
    return False


def CheckDeleteConditions(alert_data):
    for condition in DELETE_CONDITIONS:
        if not CheckDeleteCondition(alert_data, condition):
            WriteLog("Package does not match delete conditions", "INFO")
            return False
    WriteLog("Package matches all delete conditions", "INFO")
    return True


def ParseTimeValue(value):
    return datetime.datetime.strptime(value, DATETIME_FORMAT)


def ParseRuleTimeValue(value, rule_name):
    if value is None:
        return None

    try:
        return datetime.datetime.strptime(value, "%H:%M").time()
    except ValueError:
        WriteLog("Invalid time value in delay rule {}: {}".format(rule_name, value), "ERROR")
        return False


def CheckTimeRange(check_time, start_time_value, end_time_value, rule_name):
    start_time = ParseRuleTimeValue(start_time_value, rule_name)
    end_time = ParseRuleTimeValue(end_time_value, rule_name)

    if start_time is False or end_time is False:
        return False

    if start_time is None and end_time is None:
        return True
    if start_time is not None and end_time is None:
        return check_time >= start_time
    if start_time is None and end_time is not None:
        return check_time < end_time
    if start_time <= end_time:
        return check_time >= start_time and check_time < end_time

    return check_time >= start_time or check_time < end_time


def CheckDelayRule(zero_balance_datetime, rule):
    rule_name = rule.get("name", "unknown")
    weekdays = rule.get("weekdays")

    if weekdays is not None:
        if zero_balance_datetime.weekday() not in weekdays:
            WriteLog("Delay rule {} does not match weekday".format(rule_name), "INFO")
            return False

    if not CheckTimeRange(
        zero_balance_datetime.time(),
        rule.get("start_time"),
        rule.get("end_time"),
        rule_name
    ):
        WriteLog("Delay rule {} does not match time".format(rule_name), "INFO")
        return False

    WriteLog("Delay rule {} matched".format(rule_name), "INFO")
    return True


def GetDeleteDelay(zero_balance_datetime):
    matched_rule_names = []
    matched_delay_minutes = []

    for rule in DELETE_DELAY_RULES:
        if CheckDelayRule(zero_balance_datetime, rule):
            matched_rule_names.append(rule.get("name", "unknown"))
            matched_delay_minutes.append(rule.get("delay_minutes", DEFAULT_DELETE_DELAY_MINUTES))

    if len(matched_delay_minutes) == 0:
        WriteLog("No special delay rules matched, using default delay", "INFO")
        WriteLog("Selected delete delay minutes: {}".format(DEFAULT_DELETE_DELAY_MINUTES), "INFO")
        return DEFAULT_DELETE_DELAY_MINUTES, matched_rule_names

    selected_delay = max(matched_delay_minutes)
    WriteLog("Matched delay rules: {}".format(", ".join(matched_rule_names)), "INFO")
    WriteLog("Selected delete delay minutes: {}".format(selected_delay), "INFO")
    return selected_delay, matched_rule_names


def CheckPackageAge(alert_data):
    zero_balance_time = alert_data.get("zeroBalanceTime")

    try:
        zero_balance_datetime = ParseTimeValue(zero_balance_time)
    except (TypeError, ValueError) as error:
        WriteLog("Invalid zeroBalanceTime value {}: {}".format(zero_balance_time, error), "ERROR")
        return False, 0, 0, []

    now = datetime.datetime.now()
    if zero_balance_datetime > now:
        WriteLog("zeroBalanceTime is in the future: {}".format(zero_balance_time), "WARNING")
        return False, 0, 0, []

    delete_delay_minutes, matched_rule_names = GetDeleteDelay(zero_balance_datetime)
    age = now - zero_balance_datetime
    age_minutes = int(age.total_seconds() / 60)
    WriteLog("Package age minutes: {}".format(age_minutes), "INFO")

    if age_minutes < delete_delay_minutes:
        WriteLog("Package is too young to delete", "INFO")
        return False, age_minutes, delete_delay_minutes, matched_rule_names

    return True, age_minutes, delete_delay_minutes, matched_rule_names


def DeletePackage(args, root_key):
    command = [
        sys.executable,
        args.cli_path,
        "del",
        "--state-file",
        args.state_file,
        "--key",
        root_key
    ]
    result = RunCliCommand(command)

    if result.returncode != 0:
        WriteLog("Failed to delete root key {}".format(root_key), "ERROR")
        WriteLog("CLI del return code: {}".format(result.returncode), "ERROR")
        WriteLog("CLI del stderr: {}".format(result.stderr.strip()), "ERROR")
        WriteLog("CLI del stdout: {}".format(result.stdout.strip()), "ERROR")
        return False

    return True


def ProcessPackage(args, root_key, alert_data, counters):
    counters["processed"] = counters["processed"] + 1
    WriteLog("Processing root key: {}".format(root_key), "INFO")

    if not isinstance(alert_data, dict):
        WriteLog("Alert data is not a dictionary for root key {}".format(root_key), "ERROR")
        counters["errors"] = counters["errors"] + 1
        return

    severity_actions_result = AddSeverityActions(args, root_key)
    if not severity_actions_result:
        counters["errors"] = counters["errors"] + 1
        return

    severity_actions_added = severity_actions_result[1]
    if severity_actions_added > 0:
        counters["actions_added"] = counters["actions_added"] + 1

    if not CheckDeleteConditions(alert_data):
        counters["skipped"] = counters["skipped"] + 1
        WriteLog("Root key {} was not deleted because delete conditions failed".format(root_key), "INFO")
        return

    should_delete, age_minutes, delay_minutes, matched_rule_names = CheckPackageAge(alert_data)
    if not should_delete:
        counters["skipped"] = counters["skipped"] + 1
        WriteLog("Root key {} was not deleted because age check failed".format(root_key), "INFO")
        return

    if DeletePackage(args, root_key):
        counters["deleted"] = counters["deleted"] + 1
        zero_balance_time = alert_data.get("zeroBalanceTime")
        if len(matched_rule_names) == 0:
            rule_text = "default delay"
        else:
            rule_text = ", ".join(matched_rule_names)
        WriteLog("Deleted root key {}".format(root_key), "INFO")
        WriteLog("Deleted root key {} zeroBalanceTime: {}".format(root_key, zero_balance_time), "INFO")
        WriteLog("Deleted root key {} age minutes: {}".format(root_key, age_minutes), "INFO")
        WriteLog("Deleted root key {} delay minutes: {}".format(root_key, delay_minutes), "INFO")
        WriteLog("Deleted root key {} matched rules: {}".format(root_key, rule_text), "INFO")
    else:
        counters["errors"] = counters["errors"] + 1


def ProcessAlertPackages(args, alert_dictionary_list):
    counters = {
        "processed": 0,
        "actions_added": 0,
        "deleted": 0,
        "skipped": 0,
        "errors": 0
    }

    if len(alert_dictionary_list) == 0:
        WriteLog("No alert packages found", "INFO")
        return counters

    for alert_dictionary in alert_dictionary_list:
        if not isinstance(alert_dictionary, dict):
            WriteLog("Alert package list item is not a dictionary", "ERROR")
            counters["skipped"] = counters["skipped"] + 1
            counters["errors"] = counters["errors"] + 1
            continue

        for root_key in alert_dictionary:
            ProcessPackage(args, root_key, alert_dictionary[root_key], counters)

    return counters


def Main():
    global VERBOSE

    args = GetArgs()
    VERBOSE = args.verbose

    try:
        WriteLog("Script started", "INFO")
    except OSError as error:
        print("Failed to open log file {}: {}".format(LOG_FILE, error))
        sys.exit(1)

    WriteLog("CLI path: {}".format(args.cli_path), "INFO")
    WriteLog("State file path: {}".format(args.state_file), "INFO")

    alert_dictionary_list = LoadAlertPackages(args)
    counters = ProcessAlertPackages(args, alert_dictionary_list)

    WriteLog("Script finished", "INFO")
    WriteLog("Processed packages: {}".format(counters["processed"]), "INFO")
    WriteLog("Packages with added actions: {}".format(counters["actions_added"]), "INFO")
    WriteLog("Deleted packages: {}".format(counters["deleted"]), "INFO")
    WriteLog("Skipped packages: {}".format(counters["skipped"]), "INFO")
    WriteLog("Packages with errors: {}".format(counters["errors"]), "INFO")
    sys.exit(0)


############################### BODY ###############################


if __name__ == "__main__":
    Main()
