#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import datetime
import fcntl
import json
import os
import re
import sys

from config.local_settings_and_secrets import LOG_KEEP_SIZE_BYTES, LOG_MAX_SIZE_BYTES


############################### VARS ###############################

STATE_FILE_DEFAULT = "/tmp/alerts.json"
LOG_FILE = "/tmp/alios.log"
VERBOSE = False
GROUP_PATTERN = r"SG/([^,/]+)"

BASE_STEPS = [
    "resolveInsightId",
    "loadInsightData"
]

SEVERITY_STEPS = {
    "0": [],
    "1": ["resolveKTalkUsers", "createLowSeverityJiraIncident", "sendLowSeverityRootMessage", "inviteKTalkUsers", "mentionKTalkUsers", "sendLowSeverityAggregateMessage"],
    "2": ["resolveKTalkUsers", "createLowSeverityJiraIncident", "sendLowSeverityRootMessage", "inviteKTalkUsers", "mentionKTalkUsers", "sendLowSeverityAggregateMessage"],
    "3": ["resolveKTalkUsers", "createLowSeverityJiraIncident", "sendLowSeverityRootMessage", "inviteKTalkUsers", "mentionKTalkUsers", "sendLowSeverityAggregateMessage"],
    "4": ["resolveKTalkUsers", "createLowSeverityJiraIncident", "sendLowSeverityRootMessage", "inviteKTalkUsers", "mentionKTalkUsers", "sendLowSeverityAggregateMessage"],
    "5": ["resolveKTalkUsers", "createCriticalJiraIncident", "sendCriticalRootMessage", "inviteKTalkUsers", "mentionKTalkUsers", "sendCriticalAggregateMessage"]
}

from config.local_settings_and_secrets import KTALK_AGGREGATE_MESSAGE_REPEAT_COUNT

STEP_TEMPLATES = {
    "resolveInsightId": {
        "stepName": "resolveInsightId", "moduleName": "InsightID", "stepState": 0,
        "errorMessage": "", "retryNumber": 0, "insightId": ""
    },
    "loadInsightData": {
        "stepName": "loadInsightData", "moduleName": "InsightData", "stepState": 0,
        "errorMessage": "", "retryNumber": 0, "isActiv": 0, "fullName": "",
        "functionObjectKey": "", "jiraIncidentTypeKey": "", "recipientADUserList": []
    },
    "resolveKTalkUsers": {
        "stepName": "resolveKTalkUsers", "moduleName": "KTalkUsers", "stepState": 0,
        "errorMessage": "", "retryNumber": 0, "recipientList": [],
        "notFoundADUserList": [], "withoutMentionIdList": []
    },
    "createLowSeverityJiraIncident": {
        "stepName": "createLowSeverityJiraIncident", "moduleName": "JiraINC", "stepState": 0,
        "errorMessage": "", "retryNumber": 0, "jiraKey": "", "jiraUrl": ""
    },
    "createCriticalJiraIncident": {
        "stepName": "createCriticalJiraIncident", "moduleName": "JiraINC", "stepState": 0,
        "errorMessage": "", "retryNumber": 0, "jiraKey": "", "jiraUrl": ""
    },
    "sendLowSeverityRootMessage": {
        "stepName": "sendLowSeverityRootMessage", "moduleName": "KTalkMessage", "stepState": 0,
        "errorMessage": "", "retryNumber": 0, "messageAttributes": "",
        "messageID": "", "messageDeliveryTime": "", "sended": 0
    },
    "sendCriticalRootMessage": {
        "stepName": "sendCriticalRootMessage", "moduleName": "KTalkMessage", "stepState": 0,
        "errorMessage": "", "retryNumber": 0, "messageAttributes": "",
        "messageID": "", "messageDeliveryTime": "", "sended": 0
    },

    "inviteKTalkUsers": {
        "stepName": "inviteKTalkUsers", "moduleName": "KTalkMessage", "stepState": 0,
        "errorMessage": "", "retryNumber": 0, "sended": 0
    },
    "mentionKTalkUsers": {
        "stepName": "mentionKTalkUsers", "moduleName": "KTalkMessage", "stepState": 0,
        "errorMessage": "", "retryNumber": 0, "sended": 0
    },
    "sendLowSeverityAggregateMessage": {
        "stepName": "sendLowSeverityAggregateMessage", "moduleName": "KTalkMessage", "stepState": 1,
        "errorMessage": "", "retryNumber": 0, "targetEventBalance": 1, "deliveredEventBalance": 1,
        "repeatNumber": 0, "repeatLimit": KTALK_AGGREGATE_MESSAGE_REPEAT_COUNT, "successfulDeliveryNumber": 0,
        "messageAttributes": "", "lastMessageID": "", "lastMessageDeliveryTime": "", "nextDeliveryTime": "", "sended": 0
    },
    "sendCriticalAggregateMessage": {
        "stepName": "sendCriticalAggregateMessage", "moduleName": "KTalkMessage", "stepState": 1,
        "errorMessage": "", "retryNumber": 0, "targetEventBalance": 1, "deliveredEventBalance": 1,
        "repeatNumber": 0, "repeatLimit": KTALK_AGGREGATE_MESSAGE_REPEAT_COUNT, "successfulDeliveryNumber": 0,
        "messageAttributes": "", "lastMessageID": "", "lastMessageDeliveryTime": "", "nextDeliveryTime": "", "sended": 0
    }
}
STEP_TEMPLATE_INC = STEP_TEMPLATES




############################### ARGS ###############################


def GetArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode")
    parser.add_argument("--event")
    parser.add_argument("--groups")
    parser.add_argument("--triggerTime", dest="trigger_time")
    parser.add_argument("--eventRecoveryTime", dest="event_recovery_time")
    parser.add_argument("--trigName", dest="trig_name")
    parser.add_argument("--message")
    parser.add_argument("--severity")
    parser.add_argument("--eventid")
    parser.add_argument("--template", default="inc")
    parser.add_argument("--state-file", dest="state_file", default=STATE_FILE_DEFAULT)
    parser.add_argument("--path", default="$")
    parser.add_argument("--rootkey", dest="rootkey")
    parser.add_argument("--tags", default="")
    parser.add_argument("--data")
    parser.add_argument("--json-data", dest="json_data")
    parser.add_argument("-a", dest="step_keys")
    parser.add_argument("--required-steps", dest="required_steps", action="store_true")
    parser.add_argument("-l", dest="list_key")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


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


def WriteLog(message, level):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = "{} [{}] {}".format(now, level, message)

    try:
        TrimLogFileIfNeeded(LOG_FILE)
        file = open(LOG_FILE, "a", encoding="utf-8")
        file.write(log_message + "\n")
        file.close()
    except Exception as error:
        print("Failed to write log file {}: {}".format(LOG_FILE, error), file=sys.stderr)

    if VERBOSE:
        print(log_message)


############################### FUNCTIONS ###############################


def OpenStateFileLock(state_file):
    try:
        lock_file = open(state_file, "a+", encoding="utf-8")
        fcntl.flock(lock_file, fcntl.LOCK_EX)
    except OSError as error:
        WriteLog("Failed to lock state file {}: {}".format(state_file, error), "ERROR")
        raise

    WriteLog("State file locked: {}".format(state_file), "INFO")
    return lock_file


def CloseStateFileLock(lock_file, state_file):
    if lock_file is None:
        return

    try:
        fcntl.flock(lock_file, fcntl.LOCK_UN)
        lock_file.close()
    except OSError as error:
        WriteLog("Failed to unlock state file {}: {}".format(state_file, error), "ERROR")
        raise

    WriteLog("State file unlocked: {}".format(state_file), "INFO")


def ExtractRootKeysFromGroups(groups):
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



def RecoverInvalidStateFile(state_file, reason):
    backup_file = state_file + ".back"
    WriteLog("Invalid state JSON detected in {}: {}".format(state_file, reason), "ERROR")
    try:
        if os.path.exists(backup_file):
            os.remove(backup_file)
        os.replace(state_file, backup_file)
        with open(state_file, "w", encoding="utf-8") as file:
            json.dump([], file, ensure_ascii=False, indent=4)
            file.write("\n")
    except OSError as error:
        WriteLog("Failed to recover invalid state file {}: {}".format(state_file, error), "ERROR")
        raise
    WriteLog("Invalid state JSON moved to {}".format(backup_file), "ERROR")
    WriteLog("New empty state file created", "ERROR")
    return []


def ValidateCriticalEventTime(value, field_name, root_key, event_id):
    if value != "":
        try:
            datetime.datetime.strptime(value, "%Y.%m.%d %H:%M:%S")
        except ValueError:
            raise ValueError("Invalid {} for criticalEvent {} root key {}".format(field_name, event_id, root_key))


def ValidateCriticalEventStructure(alert_data, root_key):
    critical_event = alert_data.get("criticalEvent")
    if not isinstance(critical_event, dict):
        raise ValueError("criticalEvent is not a dictionary for root key {}".format(root_key))
    for event_id, event_data in critical_event.items():
        if not isinstance(event_id, str) or event_id.strip() == "":
            raise ValueError("Invalid criticalEvent eventId for root key {}".format(root_key))
        if not isinstance(event_data, dict):
            raise ValueError("criticalEvent {} is not a dictionary for root key {}".format(event_id, root_key))
        if "startTime" not in event_data or "endTime" not in event_data:
            raise ValueError("criticalEvent {} misses startTime or endTime for root key {}".format(event_id, root_key))
        start_time = event_data.get("startTime")
        end_time = event_data.get("endTime")
        if not isinstance(start_time, str) or start_time.strip() == "":
            raise ValueError("Invalid startTime for criticalEvent {} root key {}".format(event_id, root_key))
        if not isinstance(end_time, str):
            raise ValueError("Invalid endTime for criticalEvent {} root key {}".format(event_id, root_key))
        ValidateCriticalEventTime(start_time, "startTime", root_key, event_id)
        ValidateCriticalEventTime(end_time.strip(), "endTime", root_key, event_id)


def GetCriticalEvent(alert_data, root_key):
    critical_event = alert_data.get("criticalEvent")
    if not isinstance(critical_event, dict):
        raise ValueError("criticalEvent is not a dictionary for root key {}".format(root_key))
    return critical_event


def IsCriticalEventActive(event_data):
    if not isinstance(event_data, dict):
        return True
    end_time = event_data.get("endTime")
    if end_time is None:
        return True
    if not isinstance(end_time, str):
        return True
    return end_time.strip() == ""


def FindActiveCriticalEventId(alert_data, root_key=None):
    critical_event = alert_data.get("criticalEvent")
    if not isinstance(critical_event, dict):
        if root_key is not None:
            WriteLog("criticalEvent is missing or invalid for root key {}".format(root_key), "ERROR")
        return None
    for event_id, event_data in critical_event.items():
        if IsCriticalEventActive(event_data):
            return event_id
    return None

def IsPositiveIntegerString(value):
    return isinstance(value, str) and value.isdigit() and int(value) > 0


def RequireType(dictionary, key, expected_type, root_key, step_name):
    if key not in dictionary or not isinstance(dictionary.get(key), expected_type):
        raise ValueError("Invalid {} for step {} root key {}".format(key, step_name, root_key))


def ValidateStepSpecificFields(step_data, root_key):
    step_name = step_data.get("stepName")
    if step_name == "resolveInsightId":
        RequireType(step_data, "insightId", str, root_key, step_name)
    elif step_name == "loadInsightData":
        if int(step_data.get("isActiv", 0)) not in (0, 1):
            raise ValueError("Invalid isActiv for step {} root key {}".format(step_name, root_key))
        for field in ("fullName", "functionObjectKey", "jiraIncidentTypeKey"):
            RequireType(step_data, field, str, root_key, step_name)
        RequireType(step_data, "recipientADUserList", list, root_key, step_name)
    elif step_name == "resolveKTalkUsers":
        for field in ("recipientList", "notFoundADUserList", "withoutMentionIdList"):
            RequireType(step_data, field, list, root_key, step_name)
    elif step_name in ("sendLowSeverityRootMessage", "sendCriticalRootMessage"):
        for field in ("messageAttributes", "messageID", "messageDeliveryTime"):
            RequireType(step_data, field, str, root_key, step_name)
        if int(step_data.get("sended", 0)) not in (0, 1):
            raise ValueError("Invalid sended for step {} root key {}".format(step_name, root_key))
    elif step_name in ("inviteKTalkUsers", "mentionKTalkUsers"):
        if int(step_data.get("sended", 0)) not in (0, 1):
            raise ValueError("Invalid sended for step {} root key {}".format(step_name, root_key))
    elif step_name in ("sendLowSeverityAggregateMessage", "sendCriticalAggregateMessage"):
        for field in ("targetEventBalance", "deliveredEventBalance", "repeatNumber", "repeatLimit", "successfulDeliveryNumber"):
            if not isinstance(step_data.get(field), int) or step_data.get(field) < 0:
                raise ValueError("Invalid {} for step {} root key {}".format(field, step_name, root_key))
        for field in ("messageAttributes", "lastMessageID", "lastMessageDeliveryTime", "nextDeliveryTime"):
            RequireType(step_data, field, str, root_key, step_name)
        if int(step_data.get("sended", 0)) not in (0, 1):
            raise ValueError("Invalid sended for step {} root key {}".format(step_name, root_key))
    elif step_name in ("createLowSeverityJiraIncident", "createCriticalJiraIncident"):
        for field in ("jiraKey", "jiraUrl"):
            RequireType(step_data, field, str, root_key, step_name)


def DetectOldAlertFormat(alert_dictionary_list):
    if not isinstance(alert_dictionary_list, list):
        return False
    for item in alert_dictionary_list:
        if isinstance(item, dict) and "rootKey" not in item and len(item) == 1:
            value = next(iter(item.values()))
            if isinstance(value, dict) and "action" in value:
                return True
    return False


def ValidateAlertDictionaryList(alert_dictionary_list, recover_whole_file=False):
    if not isinstance(alert_dictionary_list, list):
        raise ValueError("Invalid state structure: root element must be a list")
    if DetectOldAlertFormat(alert_dictionary_list):
        raise ValueError("Incompatible old state structure detected: one-key package dictionaries with action are not supported")
    seen_root_keys = set()
    for alert_data in alert_dictionary_list:
        if not isinstance(alert_data, dict):
            raise ValueError("Invalid package structure: each list item must be a dictionary")
        if "action" in alert_data:
            raise ValueError("Incompatible old action field for root key {}".format(alert_data.get("rootKey", "<unknown>")))
        root_key = alert_data.get("rootKey")
        if not isinstance(root_key, str) or root_key.strip() == "":
            raise ValueError("Invalid rootKey in package")
        if root_key in seen_root_keys:
            raise ValueError("Duplicate rootKey: {}".format(root_key))
        seen_root_keys.add(root_key)
        value = int(alert_data.get("eventBalance", 0))
        if value < 0:
            raise ValueError("eventBalance is negative for root key {}".format(root_key))
        ValidateCriticalEventStructure(alert_data, root_key)
        severity_value = int(alert_data.get("severity", 0))
        if severity_value < 0 or severity_value > 5:
            raise ValueError("Invalid severity for root key {}".format(root_key))
        step_order = alert_data.get("stepOrder")
        if not isinstance(step_order, list) or any(not isinstance(x, str) or x.strip() == "" for x in step_order):
            raise ValueError("Invalid stepOrder for root key {}".format(root_key))
        if len(step_order) != len(set(step_order)):
            raise ValueError("Duplicate step names in stepOrder for root key {}".format(root_key))
        steps_dictionary = alert_data.get("steps")
        if not isinstance(steps_dictionary, dict):
            raise ValueError("Invalid steps dictionary for root key {}".format(root_key))
        for step_name in step_order:
            if step_name not in steps_dictionary:
                raise ValueError("stepOrder references missing step {} for root key {}".format(step_name, root_key))
        for step_key, step_data in steps_dictionary.items():
            if not isinstance(step_data, dict):
                raise ValueError("Invalid step {} for root key {}".format(step_key, root_key))
            step_name = step_data.get("stepName")
            module_name = step_data.get("moduleName")
            if not isinstance(step_name, str) or step_name.strip() == "":
                raise ValueError("Invalid stepName for step {} root key {}".format(step_key, root_key))
            if step_key != step_name:
                raise ValueError("Step key {} does not match stepName {} for root key {}".format(step_key, step_name, root_key))
            if not isinstance(module_name, str) or module_name.strip() == "":
                raise ValueError("Invalid moduleName for step {} root key {}".format(step_key, root_key))
            if int(step_data.get("stepState", 0)) not in (0, 1, 2):
                raise ValueError("Invalid stepState for step {} root key {}".format(step_key, root_key))
            if int(step_data.get("retryNumber", 0)) < 0:
                raise ValueError("Invalid retryNumber for step {} root key {}".format(step_key, root_key))
            ValidateStepSpecificFields(step_data, root_key)
    return True

def LoadAlertDictionaryList(state_file):
    if not os.path.exists(state_file):
        WriteLog("State file does not exist, a new one will be created: {}".format(state_file), "INFO")
        return []

    try:
        file = open(state_file, "r", encoding="utf-8")
        content = file.read()
        file.close()
    except OSError as error:
        WriteLog("Failed to read state file {}: {}".format(state_file, error), "ERROR")
        raise

    if content.strip() == "":
        return []

    try:
        alert_dictionary_list = json.loads(content)
    except ValueError as error:
        return RecoverInvalidStateFile(state_file, error)

    try:
        ValidateAlertDictionaryList(alert_dictionary_list)
    except ValueError as error:
        if not isinstance(alert_dictionary_list, list):
            return RecoverInvalidStateFile(state_file, error)
        raise

    return alert_dictionary_list

def SaveAlertDictionaryList(state_file, alert_dictionary_list):
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
        WriteLog("Failed to write state file {}: {}".format(state_file, error), "ERROR")
        raise

    WriteLog("State saved to {}".format(state_file), "INFO")


def FindPackageByRootKey(package_list, root_key):
    for package in package_list:
        if isinstance(package, dict) and package.get("rootKey") == root_key:
            return package
    return None


def FindAlertDictionaryByRootKey(package_list, root_key):
    return FindPackageByRootKey(package_list, root_key)


def GetRootKeyArg(args):
    return getattr(args, "rootkey", None)

def GetIntegerValue(value, field_name):
    try:
        return int(value)
    except ValueError:
        raise ValueError("Invalid integer value for {}: {}".format(field_name, value))


def CopyDictionary(source_dictionary):
    return json.loads(json.dumps(source_dictionary))


def GetActionTemplate(template_name):
    if template_name == "inc":
        return {}

    raise ValueError("Unsupported template: {}".format(template_name))


def CheckRequiredValue(value, argument_name):
    if value is None:
        raise ValueError("Required argument is missing: {}".format(argument_name))
    if value == "":
        raise ValueError("Required argument is empty: {}".format(argument_name))


def CheckAddArgs(args):
    CheckRequiredValue(args.event, "--event")
    CheckRequiredValue(args.groups, "--groups")
    CheckRequiredValue(args.trigger_time, "--triggerTime")
    CheckRequiredValue(args.trig_name, "--trigName")
    CheckRequiredValue(args.message, "--message")
    CheckRequiredValue(args.severity, "--severity")
    if str(args.severity) == "5":
        CheckRequiredValue(args.eventid, "--eventid")


def CheckSelectArgs(args):
    CheckRequiredValue(args.path, "--path")


def CheckUpdateArgs(args):
    CheckRequiredValue(args.path, "--path")
    if args.data is None and args.json_data is None and args.step_keys is None and not args.required_steps:
        raise ValueError("Required argument is missing: --data, --json-data, -a, --required-steps")


def CreateEventOneAlertData(args, root_key):
    alert_data = {
        "rootKey": root_key,
        "event": "1",
        "groups": args.groups,
        "triggerTime": args.trigger_time,
        "trigName": args.trig_name,
        "tags": getattr(args, "tags", "") or "",
        "message": args.message,
        "severity": args.severity,
        "eventBalance": 1,
        "criticalEvent": {},
        "zeroRecaveryBalance": "",
        "stepOrder": [],
        "steps": {}
    }
    return alert_data

def RemoveUnusedBalanceKey(alert_data):
    if "balance" in alert_data:
        del alert_data["balance"]


def GetExistingEventBalance(alert_data):
    return GetIntegerValue(alert_data.get("eventBalance", 0), "eventBalance")



def ApplyEventOneToAlertList(alert_dictionary_list, root_key, args):
    alert_dictionary = FindAlertDictionaryByRootKey(alert_dictionary_list, root_key)
    new_severity = GetIntegerValue(args.severity, "severity")
    event_id = str(args.eventid)

    if alert_dictionary is None:
        alert_data = CreateEventOneAlertData(args, root_key)
        if new_severity == 5:
            alert_data["criticalEvent"][event_id] = {"startTime": args.trigger_time, "endTime": ""}
        alert_dictionary_list.append(alert_data.copy())
        WriteLog("Root key {} added with event balance {}".format(root_key, alert_data["eventBalance"]), "INFO")
        if new_severity == 5:
            WriteLog("Critical event opened for root key {} eventId {} startTime {} eventBalance {}".format(root_key, event_id, args.trigger_time, alert_data["eventBalance"]), "INFO")
        return

    alert_data = alert_dictionary
    if not isinstance(alert_data, dict):
        raise ValueError("Invalid alert data for root key {}".format(root_key))

    RemoveUnusedBalanceKey(alert_data)
    old_event_balance = GetExistingEventBalance(alert_data)
    old_severity = GetIntegerValue(alert_data.get("severity", "0"), "severity")

    if new_severity == 5:
        critical_event = GetCriticalEvent(alert_data, root_key)
        if event_id in critical_event:
            WriteLog("Critical event {} already exists for root key {}, eventBalance unchanged".format(event_id, root_key), "WARNING")
        else:
            critical_event[event_id] = {"startTime": args.trigger_time, "endTime": ""}
            alert_data["eventBalance"] = old_event_balance + 1
            alert_data["zeroRecaveryBalance"] = ""
            WriteLog("Critical event opened for root key {} eventId {} startTime {} eventBalance {}".format(root_key, event_id, args.trigger_time, alert_data["eventBalance"]), "INFO")
    else:
        alert_data["eventBalance"] = old_event_balance + 1
        alert_data["zeroRecaveryBalance"] = ""

    if new_severity > old_severity:
        alert_data["severity"] = args.severity

    ResetAggregateStepForBalanceIfNeeded(alert_data)
    WriteLog("Root key {} updated, event balance is {}".format(root_key, alert_data["eventBalance"]), "INFO")


def GetZeroRecaveryBalanceTimeValue(args):
    if args.event_recovery_time is None or str(args.event_recovery_time).strip() == "":
        return args.trigger_time
    return args.event_recovery_time


def ApplyEventZeroToAlertList(alert_dictionary_list, root_key, args):
    alert_dictionary = FindAlertDictionaryByRootKey(alert_dictionary_list, root_key)
    severity_value = GetIntegerValue(args.severity, "severity")
    event_id = str(args.eventid)

    if alert_dictionary is None:
        WriteLog("Root key {} was not found for event 0, nothing changed".format(root_key), "INFO")
        return

    alert_data = alert_dictionary
    if not isinstance(alert_data, dict):
        raise ValueError("Invalid alert data for root key {}".format(root_key))

    RemoveUnusedBalanceKey(alert_data)
    old_event_balance = GetExistingEventBalance(alert_data)

    if severity_value == 5:
        critical_event = GetCriticalEvent(alert_data, root_key)
        if event_id not in critical_event:
            WriteLog("Critical event {} was not found for root key {}, eventBalance unchanged".format(event_id, root_key), "WARNING")
            return
        event_data = critical_event[event_id]
        if not IsCriticalEventActive(event_data):
            WriteLog("Critical event {} for root key {} is already closed, eventBalance unchanged".format(event_id, root_key), "WARNING")
            return
        end_time = args.event_recovery_time
        if end_time is None or str(end_time).strip() == "":
            end_time = args.trigger_time
            WriteLog("eventRecoveryTime is empty for critical event {} root key {}, triggerTime will be used".format(event_id, root_key), "WARNING")
        event_data["endTime"] = end_time
        alert_data["eventBalance"] = max(0, old_event_balance - 1)
        WriteLog("Critical event closed for root key {} eventId {} endTime {} eventBalance {}".format(root_key, event_id, end_time, alert_data["eventBalance"]), "INFO")
    else:
        if old_event_balance == 0:
            WriteLog("Event balance is already zero for root key {}, nothing changed".format(root_key), "ERROR")
            return
        alert_data["eventBalance"] = max(0, old_event_balance - 1)

    if alert_data["eventBalance"] == 0:
        alert_data["zeroRecaveryBalance"] = GetZeroRecaveryBalanceTimeValue(args)

    ResetAggregateStepForBalanceIfNeeded(alert_data)
    WriteLog("Root key {} decreased, event balance is {}".format(root_key, alert_data["eventBalance"]), "INFO")


def GetTopLevelValueByKey(package_list, root_key):
    package = FindPackageByRootKey(package_list, root_key)
    if package is None:
        raise ValueError("Root key was not found: {}".format(root_key))
    return package

def GetWildcardValues(current_value):
    result = []

    if isinstance(current_value, list):
        for item in current_value:
            if isinstance(item, dict):
                for item_key in item:
                    result.append(item[item_key])
            else:
                result.append(item)
        return result

    if isinstance(current_value, dict):
        for item_key in current_value:
            result.append(current_value[item_key])
        return result

    return result


def GetTopLevelKeyFromPathParts(alert_dictionary_list, path_parts):
    part_count = len(path_parts)

    while part_count > 0:
        possible_root_key = ".".join(path_parts[0:part_count])
        alert_dictionary = FindAlertDictionaryByRootKey(alert_dictionary_list, possible_root_key)
        if alert_dictionary is not None:
            return possible_root_key, part_count
        part_count = part_count - 1

    raise ValueError("Root key was not found in JSON path")


def SelectValueByJsonPath(alert_dictionary_list, json_path):
    if json_path == "$":
        return alert_dictionary_list
    if isinstance(alert_dictionary_list, dict):
        if not json_path.startswith("$."):
            raise ValueError("JSON path must start with $ or $.")
        current_value = alert_dictionary_list
        for path_part in json_path[2:].split("."):
            if not isinstance(current_value, dict) or path_part not in current_value:
                raise ValueError("JSON path key was not found: {}".format(path_part))
            current_value = current_value[path_part]
        return current_value

    if not json_path.startswith("$."):
        raise ValueError("JSON path must start with $ or $.")

    path_parts = json_path[2:].split(".")
    current_value = alert_dictionary_list
    part_index = 0

    while part_index < len(path_parts):
        path_part = path_parts[part_index]

        if path_part == "":
            raise ValueError("JSON path contains an empty part")

        if path_part == "?":
            current_value = GetWildcardValues(current_value)
            part_index = part_index + 1
            continue

        if part_index == 0:
            root_key, used_parts = GetTopLevelKeyFromPathParts(alert_dictionary_list, path_parts)
            current_value = GetTopLevelValueByKey(alert_dictionary_list, root_key)
            part_index = used_parts
            continue

        if isinstance(current_value, dict):
            if path_part not in current_value:
                raise ValueError("JSON path key was not found: {}".format(path_part))
            current_value = current_value[path_part]
            part_index = part_index + 1
            continue

        raise ValueError("JSON path cannot continue after non-dictionary value: {}".format(path_part))

    return current_value


def GetRootKeysForListOutput(package_list, json_path):
    root_keys = []

    if json_path == "$" or json_path == "$.?":
        for package in package_list:
            if isinstance(package, dict) and isinstance(package.get("rootKey"), str):
                root_keys.append(package.get("rootKey"))
        return root_keys

    if not json_path.startswith("$."):
        raise ValueError("JSON path must start with $ or $.")

    path_parts = json_path[2:].split(".")
    root_key, used_parts = GetTopLevelKeyFromPathParts(package_list, path_parts)

    if used_parts != len(path_parts):
        raise ValueError("List output path must point to a package rootKey")

    root_keys.append(root_key)
    return root_keys


def SelectListValuesByKey(alert_dictionary_list, json_path, list_key):
    result = {}
    root_keys = GetRootKeysForListOutput(alert_dictionary_list, json_path)

    for root_key in root_keys:
        selected_value = GetTopLevelValueByKey(alert_dictionary_list, root_key)
        if not isinstance(selected_value, dict):
            raise ValueError("Selected root value is not a dictionary: {}".format(root_key))
        if list_key not in selected_value:
            raise ValueError("List key was not found for root key {}: {}".format(root_key, list_key))
        result[root_key] = selected_value[list_key]

    return result


def SelectAlertDictionaryList(args):
    CheckSelectArgs(args)
    alert_dictionary_list = LoadAlertDictionaryList(args.state_file)
    if args.rootkey is not None:
        package = GetTopLevelValueByKey(alert_dictionary_list, args.rootkey)
        selected_value = package if args.path == "$" else SelectValueByJsonPath(package, args.path)
    elif args.list_key is not None:
        selected_value = SelectListValuesByKey(alert_dictionary_list, args.path, args.list_key)
    else:
        selected_value = SelectValueByJsonPath(alert_dictionary_list, args.path)

    print(json.dumps(selected_value, ensure_ascii=False, indent=4))


def DeleteAlertDictionaryByRootKey(args):
    root_key = GetRootKeyArg(args)
    CheckRequiredValue(root_key, "--rootkey")
    package_list = LoadAlertDictionaryList(args.state_file)
    new_package_list = [package for package in package_list if not (isinstance(package, dict) and package.get("rootKey") == root_key)]
    if len(new_package_list) == len(package_list):
        raise ValueError("Root key was not found: {}".format(root_key))
    WriteLog("Root key {} deleted".format(root_key), "INFO")
    SaveAlertDictionaryList(args.state_file, new_package_list)

def LogAddArguments(args):
    argument_dictionary = vars(args)
    for argument_name in sorted(argument_dictionary):
        WriteLog("add argument {}: {}".format(argument_name, argument_dictionary[argument_name]), "INFO")


def UpdateAlertDictionaryList(args):
    LogAddArguments(args)
    CheckAddArgs(args)
    root_keys = ExtractRootKeysFromGroups(args.groups)

    if len(root_keys) == 0:
        raise ValueError("No groups starting with SG/ were found")

    WriteLog("Extracted root keys: {}".format(", ".join(root_keys)), "INFO")

    event_value = GetIntegerValue(args.event, "event")
    if event_value != 0 and event_value != 1:
        raise ValueError("Unsupported event value: {}".format(args.event))

    severity_value = GetIntegerValue(args.severity, "severity")
    if severity_value < 0 or severity_value > 5:
        raise ValueError("Unsupported severity value: {}".format(args.severity))

    alert_dictionary_list = LoadAlertDictionaryList(args.state_file)

    for root_key in root_keys:
        if event_value == 1:
            ApplyEventOneToAlertList(alert_dictionary_list, root_key, args)
        else:
            ApplyEventZeroToAlertList(alert_dictionary_list, root_key, args)

    SaveAlertDictionaryList(args.state_file, alert_dictionary_list)


def GetPathParts(json_path):
    if json_path == "$":
        raise ValueError("JSON path must point to a first-level dictionary or nested key")

    if not json_path.startswith("$."):
        raise ValueError("JSON path must start with $ or $.")

    path_parts = json_path[2:].split(".")
    for path_part in path_parts:
        if path_part == "":
            raise ValueError("JSON path contains an empty part")

    return path_parts


def GetRootKeyAndNestedPath(alert_dictionary_list, json_path):
    path_parts = GetPathParts(json_path)
    root_key, used_parts = GetTopLevelKeyFromPathParts(alert_dictionary_list, path_parts)
    nested_path = path_parts[used_parts:]
    return root_key, nested_path


def GetDictionaryByNestedPath(root_value, nested_path):
    current_value = root_value
    part_index = 0

    while part_index < len(nested_path):
        path_part = nested_path[part_index]
        if not isinstance(current_value, dict):
            raise ValueError("JSON path cannot continue after non-dictionary value: {}".format(path_part))
        if path_part not in current_value:
            raise ValueError("JSON path key was not found: {}".format(path_part))
        current_value = current_value[path_part]
        part_index = part_index + 1

    if not isinstance(current_value, dict):
        raise ValueError("Selected JSON path value is not a dictionary")

    return current_value


def GetStepKeys(step_keys):
    result = []
    key_parts = step_keys.split(",")
    for key_part in key_parts:
        step_key = key_part.strip()
        if step_key:
            result.append(step_key)
    if not result:
        raise ValueError("No step keys were provided")
    return result


def MakeStepByName(step_name, alert_data=None):
    if step_name not in STEP_TEMPLATES:
        raise ValueError("Step template key was not found: {}".format(step_name))
    step_data = CopyDictionary(STEP_TEMPLATES[step_name])
    if step_name in ("sendLowSeverityAggregateMessage", "sendCriticalAggregateMessage") and isinstance(alert_data, dict):
        event_balance = int(alert_data.get("eventBalance", 1))
        step_data["targetEventBalance"] = event_balance
        step_data["deliveredEventBalance"] = 1
        step_data["repeatNumber"] = 0
        step_data["successfulDeliveryNumber"] = 0
        step_data["repeatLimit"] = KTALK_AGGREGATE_MESSAGE_REPEAT_COUNT
        step_data["stepState"] = 1 if event_balance == 1 else 0
    return step_data


def GetSeverityStepKeys(root_value):
    severity_key = str(root_value.get("severity"))
    if severity_key not in SEVERITY_STEPS:
        raise ValueError("Unknown severity: {}".format(severity_key))
    WriteLog("Package severity: {}".format(severity_key), "INFO")
    return SEVERITY_STEPS[severity_key]


def GetStepStage(alert_data):
    load_insight_data = alert_data.get("steps", {}).get("loadInsightData")
    if not isinstance(load_insight_data, dict):
        return "insight_check"
    if int(load_insight_data.get("stepState", 0)) != 1:
        return "insight_check"
    if int(load_insight_data.get("isActiv", 0)) == 1:
        return "active_service"
    return "inactive_service"


def GetRequiredStepKeys(alert_data):
    required = list(BASE_STEPS)
    if GetStepStage(alert_data) == "active_service":
        for step_name in GetSeverityStepKeys(alert_data):
            if step_name not in required:
                required.append(step_name)
    return required


def AddStepsToPackage(package, required_step_keys, reset_existing=False):
    if "steps" not in package or package["steps"] is None:
        package["steps"] = {}
    if "stepOrder" not in package or package["stepOrder"] is None:
        package["stepOrder"] = []
    if not isinstance(package["steps"], dict) or not isinstance(package["stepOrder"], list):
        raise ValueError("Invalid steps or stepOrder for root key {}".format(package.get("rootKey")))
    added = []
    if reset_existing:
        package["stepOrder"] = list(required_step_keys)
        for step_name in required_step_keys:
            package["steps"][step_name] = MakeStepByName(step_name, package)
            added.append(step_name)
        return added
    for step_name in required_step_keys:
        if step_name not in package["steps"]:
            package["steps"][step_name] = MakeStepByName(step_name, package)
            added.append(step_name)
        if step_name not in package["stepOrder"]:
            package["stepOrder"].append(step_name)
    return added


def IsLowSeverityRoute(package):
    low_steps = {"createLowSeverityJiraIncident", "sendLowSeverityRootMessage", "sendLowSeverityAggregateMessage"}
    return any(step_name in package.get("stepOrder", []) or step_name in package.get("steps", {}) for step_name in low_steps)


def ResetAggregateStepForBalanceIfNeeded(alert_data):
    steps = alert_data.get("steps")
    if not isinstance(steps, dict):
        return False
    severity = str(alert_data.get("severity"))
    aggregate_step_name = "sendCriticalAggregateMessage" if severity == "5" and "sendCriticalAggregateMessage" in alert_data.get("stepOrder", []) else "sendLowSeverityAggregateMessage"
    aggregate_step = steps.get(aggregate_step_name)
    if not isinstance(aggregate_step, dict):
        return False
    event_balance = int(alert_data.get("eventBalance", 0))
    if int(aggregate_step.get("targetEventBalance", -1)) == event_balance:
        return False
    aggregate_step["stepState"] = 0
    aggregate_step["errorMessage"] = ""
    aggregate_step["retryNumber"] = 0
    aggregate_step["targetEventBalance"] = event_balance
    aggregate_step["repeatNumber"] = 0
    aggregate_step["repeatLimit"] = KTALK_AGGREGATE_MESSAGE_REPEAT_COUNT
    aggregate_step["successfulDeliveryNumber"] = 0
    aggregate_step["messageAttributes"] = ""
    aggregate_step["lastMessageID"] = ""
    aggregate_step["lastMessageDeliveryTime"] = ""
    aggregate_step["nextDeliveryTime"] = ""
    aggregate_step["sended"] = 0
    return True


def AddRequiredStepTemplateKeys(package_list, root_key):
    package = GetTopLevelValueByKey(package_list, root_key)
    required_step_keys = GetRequiredStepKeys(package)
    critical_route = list(BASE_STEPS) + SEVERITY_STEPS["5"]
    severity_escalated = str(package.get("severity")) == "5" and package.get("stepOrder") != critical_route and IsLowSeverityRoute(package)
    route_changed = False
    if severity_escalated:
        required_step_keys = critical_route
        added = AddStepsToPackage(package, required_step_keys, reset_existing=True)
        route_changed = True
    else:
        before = list(package.get("stepOrder", []))
        added = AddStepsToPackage(package, required_step_keys, reset_existing=False)
        route_changed = before != package.get("stepOrder", [])
    return {"added": added, "required": required_step_keys, "stage": GetStepStage(package), "routeChanged": route_changed, "severityEscalatedToCritical": severity_escalated}


def UpdateValueByJsonPath(alert_dictionary_list, json_path, data, root_key=None):
    if root_key is None:
        raise ValueError("--rootkey is required for update")
    root_value = GetTopLevelValueByKey(alert_dictionary_list, root_key)
    nested_path = [] if json_path == "$" else GetPathParts(json_path)
    if len(nested_path) == 0:
        raise ValueError("Update JSON path must point to a nested key")
    parent_path = nested_path[0:len(nested_path) - 1]
    update_key = nested_path[len(nested_path) - 1]
    parent_dictionary = GetDictionaryByNestedPath(root_value, parent_path)
    if update_key not in parent_dictionary:
        raise ValueError("JSON path key was not found: {}".format(update_key))
    parent_dictionary[update_key] = data
    WriteLog("JSON path {} updated for root key {}".format(json_path, root_key), "INFO")

def UpdateAlertDictionaryValue(args):
    CheckUpdateArgs(args)
    alert_dictionary_list = LoadAlertDictionaryList(args.state_file)

    if args.data is not None:
        UpdateValueByJsonPath(alert_dictionary_list, args.path, args.data, args.rootkey)

    if args.json_data is not None:
        try:
            json_data = json.loads(args.json_data)
        except ValueError as error:
            raise ValueError("Invalid JSON in --json-data: {}".format(error))
        if not isinstance(json_data, dict):
            raise ValueError("--json-data must be a JSON dictionary")
        UpdateValueByJsonPath(alert_dictionary_list, args.path, json_data, args.rootkey)

    if args.step_keys is not None:
        AddStepsToPackage(GetTopLevelValueByKey(alert_dictionary_list, args.rootkey), GetStepKeys(args.step_keys))

    required_steps_result = None
    if args.required_steps:
        required_steps_result = AddRequiredStepTemplateKeys(alert_dictionary_list, args.rootkey)

    SaveAlertDictionaryList(args.state_file, alert_dictionary_list)

    if args.required_steps:
        print(json.dumps(required_steps_result, ensure_ascii=False))


DATETIME_FORMAT = "%Y.%m.%d %H:%M:%S"
DEFAULT_DELETE_DELAY_MINUTES = 30
DELETE_DELAY_RULES = [
    {"name": "night_period", "weekdays": None, "start_time": "21:00", "end_time": "09:00", "delay_minutes": 180},
    {"name": "weekend", "weekdays": [5, 6], "start_time": None, "end_time": None, "delay_minutes": 180}
]

def ParseTimeValue(value):
    return datetime.datetime.strptime(value, DATETIME_FORMAT)

def CheckTimeRangeForDelete(check_time, start_value, end_value):
    if start_value is None and end_value is None:
        return True
    start_time = datetime.datetime.strptime(start_value, "%H:%M").time() if start_value is not None else None
    end_time = datetime.datetime.strptime(end_value, "%H:%M").time() if end_value is not None else None
    if start_time is not None and end_time is None:
        return check_time >= start_time
    if start_time is None and end_time is not None:
        return check_time < end_time
    if start_time <= end_time:
        return start_time <= check_time < end_time
    return check_time >= start_time or check_time < end_time

def GetDeleteDelayMinutes(zero_recavery_balance_datetime):
    delays = []
    for rule in DELETE_DELAY_RULES:
        weekdays = rule.get("weekdays")
        if weekdays is not None and zero_recavery_balance_datetime.weekday() not in weekdays:
            continue
        if CheckTimeRangeForDelete(zero_recavery_balance_datetime.time(), rule.get("start_time"), rule.get("end_time")):
            delays.append(rule.get("delay_minutes", DEFAULT_DELETE_DELAY_MINUTES))
    if not delays:
        return DEFAULT_DELETE_DELAY_MINUTES
    return max(delays)

def MakeDeleteReadyResponse(deleted, key, reason):
    return {"deleted": deleted, "key": key, "reason": reason}

def DeleteReadyAlertDictionaryByRootKey(args):
    root_key = GetRootKeyArg(args)
    CheckRequiredValue(root_key, "--rootkey")
    package_list = LoadAlertDictionaryList(args.state_file)
    alert_data = FindPackageByRootKey(package_list, root_key)
    if alert_data is None:
        response = MakeDeleteReadyResponse(False, root_key, "root key was not found")
        print(json.dumps(response, ensure_ascii=False, indent=4))
        return
    steps = alert_data.get("steps")
    step_order = alert_data.get("stepOrder")
    if not isinstance(steps, dict) or not isinstance(step_order, list):
        raise ValueError("steps or stepOrder has invalid structure for root key {}".format(root_key))
    for step_name in step_order:
        step_data = steps.get(step_name)
        if not isinstance(step_data, dict):
            raise ValueError("step {} has invalid structure".format(step_name))
        if step_data.get("stepName") != step_name:
            raise ValueError("step {} has mismatched stepName".format(step_name))
        step_state = int(step_data.get("stepState", 0))
        if step_state != 1:
            print(json.dumps(MakeDeleteReadyResponse(False, root_key, "step {} has stepState {}".format(step_name, step_state)), ensure_ascii=False, indent=4))
            return
    if int(alert_data.get("eventBalance", 0)) != 0:
        print(json.dumps(MakeDeleteReadyResponse(False, root_key, "eventBalance is not zero"), ensure_ascii=False, indent=4))
        return
    active_critical_event_id = FindActiveCriticalEventId(alert_data, root_key)
    if not isinstance(alert_data.get("criticalEvent"), dict):
        print(json.dumps(MakeDeleteReadyResponse(False, root_key, "criticalEvent is missing or invalid"), ensure_ascii=False, indent=4))
        return
    if active_critical_event_id is not None:
        print(json.dumps(MakeDeleteReadyResponse(False, root_key, "criticalEvent contains active event {}".format(active_critical_event_id)), ensure_ascii=False, indent=4))
        return
    zero_recavery_balance = alert_data.get("zeroRecaveryBalance")
    if zero_recavery_balance is None or str(zero_recavery_balance).strip() == "":
        print(json.dumps(MakeDeleteReadyResponse(False, root_key, "zeroRecaveryBalance is empty"), ensure_ascii=False, indent=4))
        return
    zero_recavery_balance_datetime = ParseTimeValue(zero_recavery_balance)
    delay_minutes = GetDeleteDelayMinutes(zero_recavery_balance_datetime)
    age_minutes = int((datetime.datetime.now() - zero_recavery_balance_datetime).total_seconds() / 60)
    if age_minutes < delay_minutes:
        print(json.dumps(MakeDeleteReadyResponse(False, root_key, "package age is less than delete delay"), ensure_ascii=False, indent=4))
        return
    new_list = [item for item in package_list if not (isinstance(item, dict) and item.get("rootKey") == root_key)]
    SaveAlertDictionaryList(args.state_file, new_list)
    print(json.dumps(MakeDeleteReadyResponse(True, root_key, ""), ensure_ascii=False, indent=4))

############################### BODY ###############################


def Main():
    global VERBOSE

    parser = GetArgs()
    args = parser.parse_args()
    VERBOSE = args.verbose

    lock_file = None

    try:
        WriteLog("Script started in mode {}".format(args.mode), "INFO")
        WriteLog("Selected mode: {}".format(args.mode), "INFO")

        lock_file = OpenStateFileLock(args.state_file)

        if args.mode == "add":
            UpdateAlertDictionaryList(args)
        elif args.mode == "select":
            SelectAlertDictionaryList(args)
        elif args.mode == "del":
            DeleteAlertDictionaryByRootKey(args)
        elif args.mode == "del-ready":
            DeleteReadyAlertDictionaryByRootKey(args)
        elif args.mode == "update":
            UpdateAlertDictionaryValue(args)
        else:
            raise ValueError("Unsupported mode: {}".format(args.mode))

        CloseStateFileLock(lock_file, args.state_file)
        lock_file = None

        WriteLog("Script finished successfully", "INFO")
        sys.exit(0)
    except Exception as error:
        try:
            CloseStateFileLock(lock_file, args.state_file)
        except Exception as unlock_error:
            WriteLog("Execution failed while unlocking: {}".format(unlock_error), "ERROR")
        WriteLog("Execution failed: {}".format(error), "ERROR")
        sys.exit(1)


if __name__ == "__main__":
    Main()
