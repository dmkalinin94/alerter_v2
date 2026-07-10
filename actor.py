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
import mktapi
import jira_inc
import ktalk_message

from config.config_check import ValidateConfig
from config.secret_masking import MaskSensitiveText
from config.local_settings_and_secrets import (
    ACTOR_LOCK_FILE, ACTOR_LOCK_RETRY_INTERVAL_SECONDS, ACTOR_LOCK_TIMEOUT_SECONDS,
    ACTOR_MAX_RUNTIME_SECONDS, CLI_COMMAND_TIMEOUT_SECONDS, LOG_KEEP_SIZE_BYTES,
    LOG_MAX_SIZE_BYTES, WATCHER_COMMAND_TIMEOUT_SECONDS
)


CLI_PATH_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alios.py")
WATCHER_PATH_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "watcher.py")
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
    log_message = "{} [{}] {}: {}".format(now, level, component, MaskSensitiveText(message))
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


def UpdateStep(args, root_key, step_name, step_data):
    command = [
        sys.executable,
        args.cli_path,
        "update",
        "--state-file",
        args.state_file,
        "--rootkey",
        root_key,
        "--path",
        "$.steps.{}".format(step_name),
        "--json-data",
        json.dumps(step_data, ensure_ascii=False)
    ]
    try:
        result = RunCommand(command, CLI_COMMAND_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        WriteLog("CLI update timed out after {} seconds for root key {} step {}: {}".format(CLI_COMMAND_TIMEOUT_SECONDS, root_key, step_name, error), "ERROR")
        return False
    if result.returncode != 0:
        WriteLog("CLI update failed for root key {} step {} with code {}".format(root_key, step_name, result.returncode), "ERROR")
        WriteLog("CLI update stderr: {}".format(result.stderr.strip()), "ERROR")
        WriteLog("CLI update stdout: {}".format(result.stdout.strip()), "ERROR")
        return False
    WriteLog("Step {} updated through CLI for root key {}".format(step_name, root_key), "INFO")
    return True


def GetRetryNumber(step_data):
    try:
        return int(step_data.get("retryNumber", 0))
    except (TypeError, ValueError):
        return 0

def HandleResolveInsightId(root_key, alert_data, step_data):
    retry_number = step_data.get("retryNumber", 0)
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
        new_data = step_data.copy()
        new_data.update({"stepState": 1, "errorMessage": "", "retryNumber": retry_number, "insightId": result.get("insightId", "")})
        return True, new_data

    new_data = step_data.copy()
    new_data.update({"stepState": 2, "errorMessage": result.get("errorMessage", "Unknown InsightID error"), "retryNumber": retry_number + 1, "insightId": ""})
    return False, new_data


def HandleLoadInsightData(root_key, alert_data, step_data):
    retry_number = GetRetryNumber(step_data)
    WriteLog("InsightData started for root key {}".format(root_key), "INFO")
    try:
        insight_id_data = alert_data.get("steps", {}).get("resolveInsightId")
        if not isinstance(insight_id_data, dict) or insight_id_data.get("stepState") != 1:
            raise ValueError("InsightID step is not completed")
        insight_id = insight_id_data.get("insightId")
        if not isinstance(insight_id, str) or insight_id.strip() == "":
            raise ValueError("InsightID insightId is empty")
        insight_id = insight_id.strip()
    except Exception as error:
        error_message = str(error)[:2000]
        WriteLog("InsightData structure error for root key {}: {}".format(root_key, error_message), "ERROR")
        new_data = step_data.copy(); new_data.update({"stepState": 2, "errorMessage": error_message, "retryNumber": retry_number + 1, "isActiv": 0, "recipientADUserList": []}); return False, new_data

    WriteLog("InsightData uses insight_id {} for root key {}".format(insight_id, root_key), "INFO")
    result = insight.GetInsightData(insight_id, lambda message, level: WriteLog(message, level, "insight"))
    error_message = insight.MaskSensitiveText(result.get("errorMessage", ""))[:2000]
    if result.get("success") is True:
        WriteLog("InsightData completed for root key {} isActiv={} recipients={}".format(root_key, result.get("isActiv", 0), len(result.get("recipientADUserList", []))), "INFO")
        new_data = step_data.copy(); new_data.update({"stepState": 1, "errorMessage": "", "retryNumber": retry_number, "isActiv": int(result.get("isActiv", 0)), "fullName": result.get("fullName", ""), "functionObjectKey": result.get("functionObjectKey", ""), "jiraIncidentTypeKey": result.get("jiraIncidentTypeKey", ""), "recipientADUserList": result.get("recipientADUserList", [])}); return True, new_data

    WriteLog("InsightData error for root key {}: {}".format(root_key, error_message), "ERROR")
    new_data = step_data.copy(); new_data.update({"stepState": 2, "errorMessage": error_message, "retryNumber": retry_number + 1, "isActiv": 0, "recipientADUserList": []}); return False, new_data



def IsMandatoryStep(step_name):
    return step_name in ("resolveInsightId", "loadInsightData", "resolveKTalkUsers", "createLowSeverityJiraIncident", "createCriticalJiraIncident", "sendLowSeverityRootMessage", "sendCriticalRootMessage", "inviteKTalkUsers", "mentionKTalkUsers")


def ProcessPackage(args, root_key, alert_data, counters, handlers):
    counters["processed"] = counters["processed"] + 1
    WriteLog("Processing root key: {}".format(root_key), "INFO")
    if not isinstance(alert_data, dict):
        counters["structure_errors"] += 1
        WriteLog("Alert data is not a dictionary for root key {}".format(root_key), "ERROR")
        return
    step_order = alert_data.get("stepOrder")
    steps = alert_data.get("steps")
    if not isinstance(step_order, list) or not isinstance(steps, dict):
        counters["structure_errors"] += 1
        WriteLog("stepOrder or steps has invalid structure for root key {}".format(root_key), "ERROR")
        return
    for index, step_name in enumerate(step_order, start=1):
        step_data = steps.get(step_name)
        if not isinstance(step_data, dict):
            counters["structure_errors"] += 1
            WriteLog("Step {} from stepOrder is missing or invalid for root key {}".format(step_name, root_key), "ERROR")
            return
        if step_data.get("stepName") != step_name:
            counters["structure_errors"] += 1
            WriteLog("Step key {} does not match stepName for root key {}".format(step_name, root_key), "ERROR")
            return
        module_name = step_data.get("moduleName")
        WriteLog("Current step for root key {}: {}, module {}".format(root_key, step_name, module_name), "INFO")
        if step_data.get("stepState") == 1:
            counters["skipped_done"] += 1
            continue
        handler = handlers.get((module_name, step_name))
        if handler is None:
            counters["structure_errors"] += 1
            WriteLog("Handler is missing for step {}.{} root key {}".format(module_name, step_name, root_key), "ERROR")
            return
        try:
            success, new_step_data = handler(root_key, alert_data, step_data)
        except Exception as error:
            WriteLog("Step {} raised exception for root key {}: {}".format(step_name, root_key, error), "ERROR")
            WriteLog(traceback.format_exc(), "ERROR")
            retry_number = GetRetryNumber(step_data)
            new_step_data = step_data.copy()
            new_step_data["retryNumber"] = retry_number + 1
            new_step_data["errorMessage"] = ("{}: {}".format(type(error).__name__, str(error)))[:2000]
            new_step_data["stepState"] = 2 if IsMandatoryStep(step_name) else 0
            success = False
        if not success and not IsMandatoryStep(step_name):
            new_step_data["stepState"] = 0 if int(new_step_data.get("repeatNumber", 0)) < int(new_step_data.get("repeatLimit", 1)) else 1
        if not UpdateStep(args, root_key, step_name, new_step_data):
            counters["cli_write_errors"] += 1
            return
        steps[step_name] = new_step_data
        if success:
            counters["steps_success"] += 1
            if new_step_data.get("stepState") == 0:
                WriteLog("Step {} waits for continuation".format(step_name), "INFO")
            continue
        counters["steps_error"] += 1
        WriteLog("Step {} failed for root key {}".format(step_name, root_key), "ERROR")
        if IsMandatoryStep(step_name):
            return

STEP_HANDLERS = {
    ("InsightID", "resolveInsightId"): HandleResolveInsightId,
    ("InsightData", "loadInsightData"): HandleLoadInsightData,
    ("KTalkUsers", "resolveKTalkUsers"): mktapi.ResolveKTalkUsers,
    ("JiraINC", "createLowSeverityJiraIncident"): jira_inc.CreateLowSeverityJiraIncident,
    ("JiraINC", "createCriticalJiraIncident"): jira_inc.CreateCriticalJiraIncident,
    ("KTalkMessage", "sendLowSeverityRootMessage"): ktalk_message.SendLowSeverityRootMessage,
    ("KTalkMessage", "sendCriticalRootMessage"): ktalk_message.SendCriticalRootMessage,
    ("KTalkMessage", "inviteKTalkUsers"): ktalk_message.InviteKTalkUsers,
    ("KTalkMessage", "mentionKTalkUsers"): ktalk_message.MentionKTalkUsers,
    ("KTalkMessage", "sendLowSeverityAggregateMessage"): ktalk_message.SendLowSeverityAggregateMessage,
    ("KTalkMessage", "sendCriticalAggregateMessage"): ktalk_message.SendCriticalAggregateMessage,
}

def ProcessAlertPackages(args, package_list):
    handlers = STEP_HANDLERS
    counters = {"processed": 0, "steps_success": 0, "skipped_done": 0, "steps_error": 0, "structure_errors": 0, "cli_write_errors": 0, "package_errors": 0}
    for package in package_list:
        if not isinstance(package, dict):
            counters["package_errors"] += 1
            WriteLog("Alert package list item is not a dictionary", "ERROR")
            continue
        root_key = package.get("rootKey")
        if not isinstance(root_key, str) or root_key.strip() == "":
            counters["package_errors"] += 1
            WriteLog("Alert package misses rootKey", "ERROR")
            continue
        try:
            ProcessPackage(args, root_key, package, counters, handlers)
        except Exception as error:
            counters["package_errors"] += 1
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
        try:
            ValidateConfig()
        except RuntimeError as error:
            WriteLog(str(error), "ERROR")
            sys.exit(1)
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
        WriteLog("Successful steps: {}".format(counters["steps_success"]), "INFO")
        WriteLog("Skipped completed steps: {}".format(counters["skipped_done"]), "INFO")
        WriteLog("Steps with errors: {}".format(counters["steps_error"]), "INFO")
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
