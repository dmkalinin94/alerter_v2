#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import datetime
import json
import os
import subprocess
import sys

import alios
import db


CLI_PATH_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alios.py")
WATCHER_PATH_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alerts_watcher.py")
STATE_FILE_DEFAULT = "/tmp/alerts.json"
LOG_FILE = "/tmp/actor.log"
VERBOSE = False


def GetArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli-path", dest="cli_path", default=CLI_PATH_DEFAULT)
    parser.add_argument("--watcher-path", dest="watcher_path", default=WATCHER_PATH_DEFAULT)
    parser.add_argument("--state-file", dest="state_file", default=STATE_FILE_DEFAULT)
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args()


def WriteLog(message, level):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = "{} [{}] {}".format(now, level, message)
    file = open(LOG_FILE, "a", encoding="utf-8")
    file.write(log_message + "\n")
    file.close()
    if VERBOSE:
        print(log_message)


def RunCommand(command):
    return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def RunWatcher(args):
    if not os.path.exists(args.watcher_path):
        WriteLog("Watcher file was not found: {}".format(args.watcher_path), "ERROR")
        return False

    command = [
        sys.executable,
        args.watcher_path,
        "--cli-path",
        args.cli_path,
        "--state-file",
        args.state_file
    ]
    if args.verbose:
        command.append("-v")

    WriteLog("Starting watcher: {}".format(" ".join(command)), "INFO")
    result = RunCommand(command)
    WriteLog("Watcher finished with code {}".format(result.returncode), "INFO")
    if result.returncode != 0:
        WriteLog("Watcher stderr: {}".format(result.stderr.strip()), "ERROR")
        WriteLog("Watcher stdout: {}".format(result.stdout.strip()), "ERROR")
        return False
    return True


def LoadAlertPackages(args):
    if not os.path.exists(args.cli_path):
        WriteLog("CLI file was not found: {}".format(args.cli_path), "ERROR")
        return None

    command = [sys.executable, args.cli_path, "select", "--state-file", args.state_file, "--path", "$"]
    WriteLog("Loading alert packages with CLI select", "INFO")
    result = RunCommand(command)
    if result.returncode != 0:
        WriteLog("CLI select failed with code {}".format(result.returncode), "ERROR")
        WriteLog("CLI select stderr: {}".format(result.stderr.strip()), "ERROR")
        WriteLog("CLI select stdout: {}".format(result.stdout.strip()), "ERROR")
        return None

    try:
        alert_dictionary_list = json.loads(result.stdout)
    except ValueError as error:
        WriteLog("CLI select stdout is not valid JSON: {}".format(error), "ERROR")
        return None

    if not isinstance(alert_dictionary_list, list):
        WriteLog("CLI select root result is not a list", "ERROR")
        return None

    for alert_dictionary in alert_dictionary_list:
        if not isinstance(alert_dictionary, dict):
            WriteLog("CLI select list item is not a dictionary", "ERROR")
            return None

    WriteLog("Loaded alert packages: {}".format(len(alert_dictionary_list)), "INFO")
    return alert_dictionary_list


def UpdateAction(args, root_key, action_name, action_data):
    command = [
        sys.executable,
        args.cli_path,
        "update",
        "--state-file",
        args.state_file,
        "--path",
        "$.{}.action.{}".format(root_key, action_name),
        "--json-data",
        json.dumps(action_data, ensure_ascii=False)
    ]
    result = RunCommand(command)
    if result.returncode != 0:
        WriteLog("CLI update failed for root key {} action {} with code {}".format(root_key, action_name, result.returncode), "ERROR")
        WriteLog("CLI update stderr: {}".format(result.stderr.strip()), "ERROR")
        WriteLog("CLI update stdout: {}".format(result.stdout.strip()), "ERROR")
        return False
    WriteLog("Action {} updated through CLI for root key {}".format(action_name, root_key), "INFO")
    return True


def HandleInsightID(root_key, action_data):
    retry_number = action_data.get("retryNumber", 0)
    try:
        retry_number = int(retry_number)
    except (TypeError, ValueError):
        retry_number = 0

    result = db.GetInsightIdByShortName(root_key)
    WriteLog("InsightID DB result for root key {}: success={}, error={}".format(
        root_key,
        result.get("success"),
        result.get("errorMessage", "")
    ), "INFO")

    if result.get("success") is True:
        return True, {
            "stepSate": 1,
            "errorMessage": "",
            "retryNumber": retry_number,
            "insightId": result.get("insightId", "")
        }

    return False, {
        "stepSate": 2,
        "errorMessage": result.get("errorMessage", "Unknown InsightID error"),
        "retryNumber": retry_number + 1,
        "insightId": ""
    }


def GetActionOrder(alert_data):
    severity_key = str(alert_data.get("severity"))
    if severity_key not in alios.SEVERITY_ACTION:
        raise ValueError("Unknown severity: {}".format(severity_key))
    return alios.SEVERITY_ACTION[severity_key]


def ProcessPackage(args, root_key, alert_data, counters, handlers):
    counters["processed"] = counters["processed"] + 1
    WriteLog("Processing root key: {}".format(root_key), "INFO")

    if not isinstance(alert_data, dict):
        WriteLog("Alert data is not a dictionary for root key {}".format(root_key), "ERROR")
        counters["structure_errors"] = counters["structure_errors"] + 1
        return

    action_dictionary = alert_data.get("action")
    if not isinstance(action_dictionary, dict):
        WriteLog("Action value is not a dictionary for root key {}".format(root_key), "ERROR")
        counters["structure_errors"] = counters["structure_errors"] + 1
        return

    try:
        action_order = GetActionOrder(alert_data)
    except ValueError as error:
        WriteLog("Action order error for root key {}: {}".format(root_key, error), "ERROR")
        counters["structure_errors"] = counters["structure_errors"] + 1
        return

    previous_actions_successful = True
    for action_name in action_order:
        WriteLog("Current action for root key {}: {}".format(root_key, action_name), "INFO")
        if not previous_actions_successful:
            WriteLog("Previous action is not successful, skipping {} for root key {}".format(action_name, root_key), "ERROR")
            return
        if action_name not in action_dictionary:
            WriteLog("Action {} is missing for root key {}".format(action_name, root_key), "ERROR")
            counters["structure_errors"] = counters["structure_errors"] + 1
            return
        if action_name not in handlers:
            WriteLog("Handler is missing for action {} root key {}".format(action_name, root_key), "ERROR")
            counters["structure_errors"] = counters["structure_errors"] + 1
            return

        action_data = action_dictionary[action_name]
        if not isinstance(action_data, dict):
            WriteLog("Action {} is not a dictionary for root key {}".format(action_name, root_key), "ERROR")
            counters["structure_errors"] = counters["structure_errors"] + 1
            return

        step_state = action_data.get("stepSate")
        if step_state == 1:
            counters["skipped_done"] = counters["skipped_done"] + 1
            WriteLog("Action {} already completed for root key {}, skipped".format(action_name, root_key), "INFO")
            continue
        if step_state not in (0, 2):
            WriteLog("Invalid stepSate for action {} root key {}: {}".format(action_name, root_key, step_state), "ERROR")
            counters["structure_errors"] = counters["structure_errors"] + 1
            return

        success, new_action_data = handlers[action_name](root_key, action_data)
        if not UpdateAction(args, root_key, action_name, new_action_data):
            counters["cli_write_errors"] = counters["cli_write_errors"] + 1
            return

        if success:
            counters["actions_success"] = counters["actions_success"] + 1
            action_dictionary[action_name] = new_action_data
            previous_actions_successful = True
        else:
            counters["actions_error"] = counters["actions_error"] + 1
            action_dictionary[action_name] = new_action_data
            WriteLog("Action {} failed for root key {}".format(action_name, root_key), "ERROR")
            return


def ProcessAlertPackages(args, alert_dictionary_list):
    handlers = {"InsightID": HandleInsightID}
    counters = {
        "processed": 0,
        "actions_success": 0,
        "skipped_done": 0,
        "actions_error": 0,
        "structure_errors": 0,
        "cli_write_errors": 0
    }

    for alert_dictionary in alert_dictionary_list:
        for root_key in alert_dictionary:
            ProcessPackage(args, root_key, alert_dictionary[root_key], counters, handlers)

    return counters


def Main():
    global VERBOSE
    args = GetArgs()
    VERBOSE = args.verbose

    WriteLog("Actor started", "INFO")
    WriteLog("CLI path: {}".format(args.cli_path), "INFO")
    WriteLog("Watcher path: {}".format(args.watcher_path), "INFO")
    WriteLog("State file path: {}".format(args.state_file), "INFO")

    if not os.path.exists(args.cli_path):
        WriteLog("CLI file was not found: {}".format(args.cli_path), "ERROR")
        sys.exit(1)

    if not RunWatcher(args):
        WriteLog("Actor finished with watcher error", "ERROR")
        sys.exit(1)

    alert_dictionary_list = LoadAlertPackages(args)
    if alert_dictionary_list is None:
        WriteLog("Actor finished with package loading error", "ERROR")
        sys.exit(1)

    counters = ProcessAlertPackages(args, alert_dictionary_list)

    WriteLog("Actor finished", "INFO")
    WriteLog("Processed packages: {}".format(counters["processed"]), "INFO")
    WriteLog("Successful actions: {}".format(counters["actions_success"]), "INFO")
    WriteLog("Skipped completed actions: {}".format(counters["skipped_done"]), "INFO")
    WriteLog("Actions with errors: {}".format(counters["actions_error"]), "INFO")
    WriteLog("Packages with structure errors: {}".format(counters["structure_errors"]), "INFO")
    WriteLog("CLI write errors: {}".format(counters["cli_write_errors"]), "INFO")
    sys.exit(0)


if __name__ == "__main__":
    Main()
