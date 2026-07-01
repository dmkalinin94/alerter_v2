#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import fcntl
import datetime
import json
import os
import signal
import time
import traceback
import subprocess
import sys

import alios
import db
import insight

try:
    from config.local_settings_and_secrets import (
        ACTOR_LOCK_FILE, ACTOR_LOCK_RETRY_INTERVAL_SECONDS, ACTOR_LOCK_TIMEOUT_SECONDS,
        ACTOR_MAX_RUNTIME_SECONDS, CLI_COMMAND_TIMEOUT_SECONDS, LOG_KEEP_SIZE_BYTES,
        LOG_MAX_SIZE_BYTES, WATCHER_COMMAND_TIMEOUT_SECONDS
    )
except ImportError:
    ACTOR_LOCK_FILE = "/tmp/alerter_actor.lock"
    ACTOR_LOCK_TIMEOUT_SECONDS = 10
    ACTOR_LOCK_RETRY_INTERVAL_SECONDS = 0.2
    ACTOR_MAX_RUNTIME_SECONDS = 30
    CLI_COMMAND_TIMEOUT_SECONDS = 10
    WATCHER_COMMAND_TIMEOUT_SECONDS = 20
    LOG_MAX_SIZE_BYTES = 104857600
    LOG_KEEP_SIZE_BYTES = 83886080


CLI_PATH_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alios.py")
WATCHER_PATH_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alerts_watcher.py")
STATE_FILE_DEFAULT = "/tmp/alerts.json"
LOG_FILE = "/tmp/actor.log"
VERBOSE = False


############################### ARGS ###############################


def GetArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli-path", dest="cli_path", default=CLI_PATH_DEFAULT)
    parser.add_argument("--watcher-path", dest="watcher_path", default=WATCHER_PATH_DEFAULT)
    parser.add_argument("--state-file", dest="state_file", default=STATE_FILE_DEFAULT)
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args()


############################### LOGS ###############################


def TrimLogFileIfNeeded(log_file):
    try:
        if not os.path.exists(log_file) or os.path.getsize(log_file) < LOG_MAX_SIZE_BYTES:
            return
        with open(log_file, "rb") as file:
            if os.path.getsize(log_file) > LOG_KEEP_SIZE_BYTES:
                file.seek(-LOG_KEEP_SIZE_BYTES, os.SEEK_END)
            data = file.read()
        newline_index = data.find(b"\n")
        if newline_index >= 0:
            data = data[newline_index + 1:]
        with open(log_file, "wb") as file:
            file.write(data)
    except Exception as error:
        print("Failed to trim log file {}: {}".format(log_file, error), file=sys.stderr)


def WriteLog(message, level, component="actor"):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = "{} [{}] {}: {}".format(now, level, component, message)
    try:
        TrimLogFileIfNeeded(LOG_FILE)
        file = open(LOG_FILE, "a", encoding="utf-8")
        file.write(log_message + "\n")
        file.close()
    except Exception as error:
        print("Failed to write log file {}: {}".format(LOG_FILE, error), file=sys.stderr)
    if VERBOSE:
        print(log_message)


def WriteComponentOutput(component, output, default_level):
    for line in output.splitlines():
        stripped_line = line.strip()
        if stripped_line == "":
            continue

        level = default_level
        message = stripped_line
        marker_start = stripped_line.find("[")
        marker_end = stripped_line.find("]")
        if marker_start >= 0 and marker_end > marker_start:
            level = stripped_line[marker_start + 1:marker_end]
            message = stripped_line[marker_end + 1:].strip()

        WriteLog(message, level, component)


############################### FUNCTIONS ###############################


def RunCommand(command, timeout_seconds):
    return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout_seconds)


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
    command.append("-v")

    WriteLog("Starting watcher: {}".format(" ".join(command)), "INFO")
    result = RunCommand(command, WATCHER_COMMAND_TIMEOUT_SECONDS)
    WriteComponentOutput("watcher", result.stdout, "INFO")
    WriteComponentOutput("watcher", result.stderr, "ERROR")
    WriteLog("Watcher finished with code {}".format(result.returncode), "INFO")
    if result.returncode != 0:
        return False
    return True


def LoadAlertPackages(args):
    if not os.path.exists(args.cli_path):
        WriteLog("CLI file was not found: {}".format(args.cli_path), "ERROR")
        return None

    command = [sys.executable, args.cli_path, "select", "--state-file", args.state_file, "--path", "$"]
    WriteLog("Loading alert packages with CLI select", "INFO")
    try:
        result = RunCommand(command, CLI_COMMAND_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        WriteLog("CLI select timed out after {} seconds: {}".format(CLI_COMMAND_TIMEOUT_SECONDS, error), "ERROR")
        return None
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
    try:
        result = RunCommand(command, CLI_COMMAND_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        WriteLog("CLI update timed out after {} seconds for root key {} action {}: {}".format(CLI_COMMAND_TIMEOUT_SECONDS, root_key, action_name, error), "ERROR")
        return False
    if result.returncode != 0:
        WriteLog("CLI update failed for root key {} action {} with code {}".format(root_key, action_name, result.returncode), "ERROR")
        WriteLog("CLI update stderr: {}".format(result.stderr.strip()), "ERROR")
        WriteLog("CLI update stdout: {}".format(result.stdout.strip()), "ERROR")
        return False
    WriteLog("Action {} updated through CLI for root key {}".format(action_name, root_key), "INFO")
    return True


def GetRetryNumber(action_data):
    try:
        return int(action_data.get("retryNumber", 0))
    except (TypeError, ValueError):
        return 0

def HandleInsightID(root_key, alert_data, action_data):
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
    ), "INFO", "db")

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


def HandleInsightData(root_key, alert_data, action_data):
    retry_number = GetRetryNumber(action_data)
    WriteLog("InsightData started for root key {}".format(root_key), "INFO")
    try:
        insight_id_data = alert_data["action"]["InsightID"]
        if insight_id_data.get("stepSate") != 1:
            raise ValueError("InsightID action is not completed")
        insight_id = insight_id_data.get("insightId")
        if not isinstance(insight_id, str) or insight_id.strip() == "":
            raise ValueError("InsightID insightId is empty")
        insight_id = insight_id.strip()
    except Exception as error:
        error_message = str(error)[:2000]
        WriteLog("InsightData structure error for root key {}: {}".format(root_key, error_message), "ERROR")
        return False, {"stepSate": 2, "errorMessage": error_message, "retryNumber": retry_number + 1, "isActiv": 0, "recipientADUserList": []}

    WriteLog("InsightData uses insight_id {} for root key {}".format(insight_id, root_key), "INFO")
    result = insight.GetInsightData(insight_id, lambda message, level: WriteLog(message, level, "insight"))
    error_message = insight.MaskSensitiveText(result.get("errorMessage", ""))[:2000]
    if result.get("success") is True:
        WriteLog("InsightData completed for root key {} isActiv={} recipients={}".format(root_key, result.get("isActiv", 0), len(result.get("recipientADUserList", []))), "INFO")
        return True, {"stepSate": 1, "errorMessage": "", "retryNumber": retry_number, "isActiv": int(result.get("isActiv", 0)), "recipientADUserList": result.get("recipientADUserList", [])}

    WriteLog("InsightData error for root key {}: {}".format(root_key, error_message), "ERROR")
    return False, {"stepSate": 2, "errorMessage": error_message, "retryNumber": retry_number + 1, "isActiv": 0, "recipientADUserList": []}


def GetActionOrder(alert_data):
    return alios.GetRequiredActionKeys(alert_data)


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

        try:
            success, new_action_data = handlers[action_name](root_key, alert_data, action_data)
        except Exception as error:
            WriteLog("Action {} raised exception for root key {}: {}".format(action_name, root_key, error), "ERROR")
            WriteLog(traceback.format_exc(), "ERROR")
            retry_number = GetRetryNumber(action_data)
            new_action_data = action_data.copy()
            new_action_data["stepSate"] = 2
            new_action_data["retryNumber"] = retry_number + 1
            new_action_data["errorMessage"] = ("{}: {}".format(type(error).__name__, str(error)))[:2000]
            success = False
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
    handlers = {"InsightID": HandleInsightID, "InsightData": HandleInsightData}
    counters = {
        "processed": 0,
        "actions_success": 0,
        "skipped_done": 0,
        "actions_error": 0,
        "structure_errors": 0,
        "cli_write_errors": 0
    }

    counters["package_errors"] = 0
    for alert_dictionary in alert_dictionary_list:
        if not isinstance(alert_dictionary, dict):
            counters["package_errors"] = counters["package_errors"] + 1
            WriteLog("Alert package list item is not a dictionary", "ERROR")
            continue
        for root_key in alert_dictionary:
            try:
                ProcessPackage(args, root_key, alert_dictionary[root_key], counters, handlers)
            except Exception as error:
                counters["package_errors"] = counters["package_errors"] + 1
                WriteLog("Package processing error for root key {}: {}: {}".format(root_key, type(error).__name__, error), "ERROR")
                WriteLog(traceback.format_exc(), "ERROR")

    return counters


def AcquireActorLock():
    deadline = time.time() + ACTOR_LOCK_TIMEOUT_SECONDS
    lock_file = open(ACTOR_LOCK_FILE, "a+", encoding="utf-8")
    while True:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            WriteLog("Actor lock acquired: {}".format(ACTOR_LOCK_FILE), "INFO")
            return lock_file
        except BlockingIOError:
            if time.time() >= deadline:
                WriteLog("Actor lock timeout. Another actor process is still running.", "WARNING")
                lock_file.close()
                return None
            time.sleep(ACTOR_LOCK_RETRY_INTERVAL_SECONDS)

def ReleaseActorLock(lock_file):
    if lock_file is None:
        return
    try:
        fcntl.flock(lock_file, fcntl.LOCK_UN)
        lock_file.close()
        WriteLog("Actor lock released: {}".format(ACTOR_LOCK_FILE), "INFO")
    except Exception as error:
        WriteLog("Failed to release actor lock: {}".format(error), "ERROR")

def ActorTimeoutHandler(signum, frame):
    WriteLog("Actor maximum runtime exceeded: {} seconds".format(ACTOR_MAX_RUNTIME_SECONDS), "ERROR")
    os._exit(124)

def Main():
    global VERBOSE
    args = GetArgs()
    VERBOSE = args.verbose

    lock_file = AcquireActorLock()
    if lock_file is None:
        sys.exit(0)

    signal.signal(signal.SIGALRM, ActorTimeoutHandler)
    signal.alarm(ACTOR_MAX_RUNTIME_SECONDS)
    try:
        WriteLog("Actor started", "INFO")
        WriteLog("CLI path: {}".format(args.cli_path), "INFO")
        WriteLog("Watcher path: {}".format(args.watcher_path), "INFO")
        WriteLog("State file path: {}".format(args.state_file), "INFO")

        if not os.path.exists(args.cli_path):
            WriteLog("CLI file was not found: {}".format(args.cli_path), "ERROR")
            sys.exit(1)

        try:
            watcher_ok = RunWatcher(args)
        except subprocess.TimeoutExpired as error:
            WriteLog("Watcher timed out after {} seconds: {}".format(WATCHER_COMMAND_TIMEOUT_SECONDS, error), "ERROR")
            sys.exit(1)
        if not watcher_ok:
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
        WriteLog("Package processing errors: {}".format(counters.get("package_errors", 0)), "INFO")
        WriteLog("CLI write errors: {}".format(counters["cli_write_errors"]), "INFO")
        sys.exit(0)
    finally:
        signal.alarm(0)
        ReleaseActorLock(lock_file)


############################### BODY ###############################


if __name__ == "__main__":
    Main()
