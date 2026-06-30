#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import datetime
import fcntl
import json
import os
import re
import sys

try:
    from config.local_settings_and_secrets import LOG_MAX_SIZE_BYTES, LOG_KEEP_SIZE_BYTES
except ImportError:
    LOG_MAX_SIZE_BYTES = 104857600
    LOG_KEEP_SIZE_BYTES = 83886080


############################### VARS ###############################

STATE_FILE_DEFAULT = "/tmp/alerts.json"
LOG_FILE = "/tmp/alios.log"
VERBOSE = False
GROUP_PATTERN = r"SG/([^,/]+)"

SEVERITY_ACTION = {
    "0": [
        "InsightID"
    ],
    "1": [
        "InsightID"
    ],
    "2": [
        "InsightID"
    ],
    "3": [
        "InsightID"
    ],
    "4": [
        "InsightID"
    ],
    "5": [
        "InsightID"
    ]
}
ACTION_TEMPLATE_INC = {
    "InsightID": {
        "stepSate": 0,
        "errorMessage": "",
        "retryNumber": 0,
        "insightId": ""
    }
}



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
    parser.add_argument("--key")
    parser.add_argument("--data")
    parser.add_argument("--json-data", dest="json_data")
    parser.add_argument("-a", dest="action_keys")
    parser.add_argument("--severity-actions", dest="severity_actions", action="store_true")
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


def ValidateAlertDictionaryList(alert_dictionary_list, recover_whole_file=False):
    if not isinstance(alert_dictionary_list, list):
        raise ValueError("Invalid state structure: root element must be a list")
    seen_root_keys = set()
    for alert_dictionary in alert_dictionary_list:
        if not isinstance(alert_dictionary, dict) or len(alert_dictionary) != 1:
            raise ValueError("Invalid package structure: each list item must be a one-key dictionary")
        root_key = next(iter(alert_dictionary))
        if str(root_key).strip() == "" or root_key in seen_root_keys:
            raise ValueError("Invalid or duplicate root key: {}".format(root_key))
        seen_root_keys.add(root_key)
        alert_data = alert_dictionary[root_key]
        if not isinstance(alert_data, dict):
            raise ValueError("Invalid alert data for root key {}".format(root_key))
        action_dictionary = alert_data.get("action", {})
        if action_dictionary is not None and not isinstance(action_dictionary, dict):
            raise ValueError("Invalid action dictionary for root key {}".format(root_key))
        for field_name in ("eventBalance", "criticalEventBalance"):
            value = int(alert_data.get(field_name, 0))
            if value < 0:
                raise ValueError("{} is negative for root key {}".format(field_name, root_key))
        severity_value = int(alert_data.get("severity", 0))
        if severity_value < 0 or severity_value > 5:
            raise ValueError("Invalid severity for root key {}".format(root_key))
        for action_name, action_data in action_dictionary.items():
            if not isinstance(action_data, dict):
                raise ValueError("Invalid action {} for root key {}".format(action_name, root_key))
            if int(action_data.get("stepSate", 0)) not in (0, 1, 2):
                raise ValueError("Invalid stepSate for action {} root key {}".format(action_name, root_key))
            if int(action_data.get("retryNumber", 0)) < 0:
                raise ValueError("Invalid retryNumber for action {} root key {}".format(action_name, root_key))
        if "criticalEventIds" in alert_data and not isinstance(alert_data["criticalEventIds"], list):
            raise ValueError("criticalEventIds is not a list for root key {}".format(root_key))
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


def FindAlertDictionaryByRootKey(alert_dictionary_list, root_key):
    for alert_dictionary in alert_dictionary_list:
        if root_key in alert_dictionary:
            return alert_dictionary
    return None


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


def CheckDeleteArgs(args):
    CheckRequiredValue(args.key, "--key")


def CheckUpdateArgs(args):
    CheckRequiredValue(args.path, "--path")
    if args.data is None and args.json_data is None and args.action_keys is None and not args.severity_actions:
        raise ValueError("Required argument is missing: --data, --json-data, -a or --severity-actions")


def CreateEventOneAlertData(args):
    action_template = GetActionTemplate(args.template)

    alert_data = {
        "event": "1",
        "groups": args.groups,
        "triggerTime": args.trigger_time,
        "trigName": args.trig_name,
        "message": args.message,
        "severity": args.severity,
        "action": CopyDictionary(action_template),
        "eventBalance": 1,
        "criticalEventBalance": 0,
        "zeroBalanceTime": ""
    }
    return alert_data


def RemoveUnusedBalanceKey(alert_data):
    if "balance" in alert_data:
        del alert_data["balance"]


def GetExistingEventBalance(alert_data):
    return GetIntegerValue(alert_data.get("eventBalance", 0), "eventBalance")


def GetExistingCriticalEventBalance(alert_data):
    return GetIntegerValue(alert_data.get("criticalEventBalance", 0), "criticalEventBalance")


def ApplyEventOneToAlertList(alert_dictionary_list, root_key, args):
    alert_dictionary = FindAlertDictionaryByRootKey(alert_dictionary_list, root_key)
    new_severity = GetIntegerValue(args.severity, "severity")

    if alert_dictionary is None:
        alert_data = CreateEventOneAlertData(args)
        if new_severity == 5:
            alert_data["criticalEventIds"] = [str(args.eventid)]
            alert_data["criticalEventBalance"] = 1
        alert_dictionary_list.append({root_key: alert_data.copy()})
        WriteLog("Root key {} added with event balance {} and critical event balance {}".format(
            root_key,
            alert_data["eventBalance"],
            alert_data["criticalEventBalance"]
        ), "INFO")
        return

    alert_data = alert_dictionary[root_key]
    if not isinstance(alert_data, dict):
        raise ValueError("Invalid alert data for root key {}".format(root_key))

    RemoveUnusedBalanceKey(alert_data)
    old_event_balance = GetExistingEventBalance(alert_data)
    old_critical_event_balance = GetExistingCriticalEventBalance(alert_data)
    old_severity = alert_data.get("severity", "0")
    old_severity = GetIntegerValue(old_severity, "severity")

    if new_severity == 5:
        critical_event_ids = alert_data.setdefault("criticalEventIds", [])
        if str(args.eventid) in critical_event_ids:
            WriteLog("Event id {} already exists for root key {}, balances unchanged".format(args.eventid, root_key), "INFO")
        else:
            critical_event_ids.append(str(args.eventid))
            alert_data["eventBalance"] = old_event_balance + 1
            alert_data["criticalEventBalance"] = old_critical_event_balance + 1
            alert_data["zeroBalanceTime"] = ""
    else:
        alert_data["eventBalance"] = old_event_balance + 1
        alert_data["criticalEventBalance"] = old_critical_event_balance
        alert_data["zeroBalanceTime"] = ""

    if "action" not in alert_data:
        alert_data["action"] = GetActionTemplate(args.template)
    if new_severity > old_severity:
        alert_data["severity"] = args.severity

    WriteLog("Root key {} updated, event balance is {}, critical event balance is {}".format(
        root_key,
        alert_data["eventBalance"],
        alert_data["criticalEventBalance"]
    ), "INFO")


def GetZeroBalanceTimeValue(args):
    if args.event_recovery_time is None or str(args.event_recovery_time).strip() == "":
        return args.trigger_time
    return args.event_recovery_time


def ApplyEventZeroToAlertList(alert_dictionary_list, root_key, args):
    alert_dictionary = FindAlertDictionaryByRootKey(alert_dictionary_list, root_key)
    severity_value = GetIntegerValue(args.severity, "severity")

    if alert_dictionary is None:
        WriteLog("Root key {} was not found for event 0, nothing changed".format(root_key), "INFO")
        return

    alert_data = alert_dictionary[root_key]
    if not isinstance(alert_data, dict):
        raise ValueError("Invalid alert data for root key {}".format(root_key))

    RemoveUnusedBalanceKey(alert_data)
    old_event_balance = GetExistingEventBalance(alert_data)
    old_critical_event_balance = GetExistingCriticalEventBalance(alert_data)

    if severity_value == 5:
        critical_event_ids = alert_data.setdefault("criticalEventIds", [])
        if str(args.eventid) not in critical_event_ids:
            WriteLog("Event id {} was not found for root key {}, balances unchanged".format(args.eventid, root_key), "WARNING")
            return
        critical_event_ids.remove(str(args.eventid))
        alert_data["eventBalance"] = max(0, old_event_balance - 1)
        alert_data["criticalEventBalance"] = max(0, old_critical_event_balance - 1)
    else:
        if old_event_balance == 0:
            WriteLog("Event balance is already zero for root key {}, nothing changed".format(root_key), "ERROR")
            return
        alert_data["eventBalance"] = max(0, old_event_balance - 1)
        alert_data["criticalEventBalance"] = old_critical_event_balance

    if alert_data["eventBalance"] == 0:
        alert_data["zeroBalanceTime"] = GetZeroBalanceTimeValue(args)

    WriteLog("Root key {} decreased, event balance is {}, critical event balance is {}".format(
        root_key,
        alert_data["eventBalance"],
        alert_data["criticalEventBalance"]
    ), "INFO")


def GetTopLevelValueByKey(alert_dictionary_list, root_key):
    alert_dictionary = FindAlertDictionaryByRootKey(alert_dictionary_list, root_key)
    if alert_dictionary is None:
        raise ValueError("Root key was not found: {}".format(root_key))

    return alert_dictionary[root_key]


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


def GetRootKeysForListOutput(alert_dictionary_list, json_path):
    root_keys = []

    if json_path == "$" or json_path == "$.?":
        for alert_dictionary in alert_dictionary_list:
            for root_key in alert_dictionary:
                root_keys.append(root_key)
        return root_keys

    if not json_path.startswith("$."):
        raise ValueError("JSON path must start with $ or $.")

    path_parts = json_path[2:].split(".")
    root_key, used_parts = GetTopLevelKeyFromPathParts(alert_dictionary_list, path_parts)

    if used_parts != len(path_parts):
        raise ValueError("List output path must point to a first-level dictionary")

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
    if args.list_key is not None:
        selected_value = SelectListValuesByKey(alert_dictionary_list, args.path, args.list_key)
    else:
        selected_value = SelectValueByJsonPath(alert_dictionary_list, args.path)

    print(json.dumps(selected_value, ensure_ascii=False, indent=4))


def DeleteAlertDictionaryByRootKey(args):
    CheckDeleteArgs(args)
    alert_dictionary_list = LoadAlertDictionaryList(args.state_file)
    new_alert_dictionary_list = []
    deleted = False

    for alert_dictionary in alert_dictionary_list:
        if args.key in alert_dictionary:
            deleted = True
            WriteLog("Root key {} deleted".format(args.key), "INFO")
        else:
            new_alert_dictionary_list.append(alert_dictionary)

    if not deleted:
        raise ValueError("Root key was not found: {}".format(args.key))

    SaveAlertDictionaryList(args.state_file, new_alert_dictionary_list)


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


def UpdateValueByJsonPath(alert_dictionary_list, json_path, data):
    root_key, nested_path = GetRootKeyAndNestedPath(alert_dictionary_list, json_path)

    if len(nested_path) == 0:
        raise ValueError("Update JSON path must point to a nested key")

    root_value = GetTopLevelValueByKey(alert_dictionary_list, root_key)
    parent_path = nested_path[0:len(nested_path) - 1]
    update_key = nested_path[len(nested_path) - 1]
    parent_dictionary = GetDictionaryByNestedPath(root_value, parent_path)

    if update_key not in parent_dictionary:
        raise ValueError("JSON path key was not found: {}".format(update_key))

    parent_dictionary[update_key] = data
    WriteLog("JSON path {} updated".format(json_path), "INFO")


def GetActionKeys(action_keys):
    result = []
    key_parts = action_keys.split(",")

    for key_part in key_parts:
        action_key = key_part.strip()
        if action_key == "":
            continue
        result.append(action_key)

    if len(result) == 0:
        raise ValueError("No action keys were provided")

    return result


def AddActionTemplateKeysByJsonPath(alert_dictionary_list, json_path, action_keys):
    root_key, nested_path = GetRootKeyAndNestedPath(alert_dictionary_list, json_path)

    if len(nested_path) != 0:
        raise ValueError("Action keys can be added only to a first-level dictionary")

    root_value = GetTopLevelValueByKey(alert_dictionary_list, root_key)
    if not isinstance(root_value, dict):
        raise ValueError("Selected root value is not a dictionary: {}".format(root_key))

    if "action" not in root_value:
        root_value["action"] = {}

    if not isinstance(root_value["action"], dict):
        raise ValueError("Action value is not a dictionary for root key {}".format(root_key))

    requested_action_keys = GetActionKeys(action_keys)

    for action_key in requested_action_keys:
        if action_key not in ACTION_TEMPLATE_INC:
            raise ValueError("Action template key was not found: {}".format(action_key))
        if action_key in root_value["action"]:
            WriteLog("Action key {} already exists for root key {}, nothing changed".format(action_key, root_key), "INFO")
            continue
        root_value["action"][action_key] = CopyDictionary(ACTION_TEMPLATE_INC[action_key])
        WriteLog("Action key {} added to root key {}".format(action_key, root_key), "INFO")


def GetSeverityActionKeys(root_value):
    severity_value = root_value.get("severity")
    if severity_value is None:
        raise ValueError("Severity is missing")

    severity_key = str(severity_value)
    if severity_key not in SEVERITY_ACTION:
        raise ValueError("Unknown severity: {}".format(severity_key))

    WriteLog("Package severity: {}".format(severity_key), "INFO")
    return SEVERITY_ACTION[severity_key]


def AddSeverityActionTemplateKeysByJsonPath(alert_dictionary_list, json_path):
    root_key, nested_path = GetRootKeyAndNestedPath(alert_dictionary_list, json_path)

    if len(nested_path) != 0:
        raise ValueError("Severity action keys can be added only to a first-level dictionary")

    root_value = GetTopLevelValueByKey(alert_dictionary_list, root_key)
    if not isinstance(root_value, dict):
        raise ValueError("Selected root value is not a dictionary: {}".format(root_key))

    if "action" not in root_value or root_value["action"] is None:
        root_value["action"] = {}

    if not isinstance(root_value["action"], dict):
        raise ValueError("Action value is not a dictionary for root key {}".format(root_key))

    required_action_keys = GetSeverityActionKeys(root_value)
    added_action_keys = []

    for action_key in required_action_keys:
        if action_key not in ACTION_TEMPLATE_INC:
            raise ValueError("Action template key was not found: {}".format(action_key))
        if action_key in root_value["action"]:
            WriteLog("Severity action key {} already exists for root key {}, nothing changed".format(action_key, root_key), "INFO")
            continue
        root_value["action"][action_key] = CopyDictionary(ACTION_TEMPLATE_INC[action_key])
        added_action_keys.append(action_key)
        WriteLog("Severity action key {} added to root key {}".format(action_key, root_key), "INFO")

    WriteLog("Added severity action keys for root key {}: {}".format(root_key, ", ".join(added_action_keys)), "INFO")
    return added_action_keys


def UpdateAlertDictionaryValue(args):
    CheckUpdateArgs(args)
    alert_dictionary_list = LoadAlertDictionaryList(args.state_file)

    if args.data is not None:
        UpdateValueByJsonPath(alert_dictionary_list, args.path, args.data)

    if args.json_data is not None:
        try:
            json_data = json.loads(args.json_data)
        except ValueError as error:
            raise ValueError("Invalid JSON in --json-data: {}".format(error))
        if not isinstance(json_data, dict):
            raise ValueError("--json-data must be a JSON dictionary")
        UpdateValueByJsonPath(alert_dictionary_list, args.path, json_data)

    if args.action_keys is not None:
        AddActionTemplateKeysByJsonPath(alert_dictionary_list, args.path, args.action_keys)

    added_severity_action_keys = []
    if args.severity_actions:
        added_severity_action_keys = AddSeverityActionTemplateKeysByJsonPath(alert_dictionary_list, args.path)

    SaveAlertDictionaryList(args.state_file, alert_dictionary_list)

    if args.severity_actions:
        print(json.dumps({"added": added_severity_action_keys}, ensure_ascii=False))


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

def GetDeleteDelayMinutes(zero_balance_datetime):
    delays = []
    for rule in DELETE_DELAY_RULES:
        weekdays = rule.get("weekdays")
        if weekdays is not None and zero_balance_datetime.weekday() not in weekdays:
            continue
        if CheckTimeRangeForDelete(zero_balance_datetime.time(), rule.get("start_time"), rule.get("end_time")):
            delays.append(rule.get("delay_minutes", DEFAULT_DELETE_DELAY_MINUTES))
    if not delays:
        return DEFAULT_DELETE_DELAY_MINUTES
    return max(delays)

def MakeDeleteReadyResponse(deleted, key, reason):
    return {"deleted": deleted, "key": key, "reason": reason}

def DeleteReadyAlertDictionaryByRootKey(args):
    CheckDeleteArgs(args)
    alert_dictionary_list = LoadAlertDictionaryList(args.state_file)
    alert_dictionary = FindAlertDictionaryByRootKey(alert_dictionary_list, args.key)
    if alert_dictionary is None:
        response = MakeDeleteReadyResponse(False, args.key, "root key was not found")
        print(json.dumps(response, ensure_ascii=False, indent=4))
        return
    alert_data = alert_dictionary[args.key]
    added = AddSeverityActionTemplateKeysByJsonPath(alert_dictionary_list, "$." + args.key)
    if added:
        SaveAlertDictionaryList(args.state_file, alert_dictionary_list)
    action_dictionary = alert_data.get("action")
    if not isinstance(action_dictionary, dict):
        raise ValueError("Action value is not a dictionary for root key {}".format(args.key))
    for action_name in GetSeverityActionKeys(alert_data):
        action_data = action_dictionary.get(action_name)
        if not isinstance(action_data, dict):
            raise ValueError("action {} has invalid structure".format(action_name))
        step_state = int(action_data.get("stepSate", 0))
        if step_state != 1:
            print(json.dumps(MakeDeleteReadyResponse(False, args.key, "action {} has stepSate {}".format(action_name, step_state)), ensure_ascii=False, indent=4))
            return
    if int(alert_data.get("eventBalance", 0)) != 0:
        print(json.dumps(MakeDeleteReadyResponse(False, args.key, "eventBalance is not zero"), ensure_ascii=False, indent=4))
        return
    if int(alert_data.get("criticalEventBalance", 0)) != 0:
        print(json.dumps(MakeDeleteReadyResponse(False, args.key, "criticalEventBalance is not zero"), ensure_ascii=False, indent=4))
        return
    zero_balance_time = alert_data.get("zeroBalanceTime")
    if zero_balance_time is None or str(zero_balance_time).strip() == "":
        print(json.dumps(MakeDeleteReadyResponse(False, args.key, "zeroBalanceTime is empty"), ensure_ascii=False, indent=4))
        return
    zero_balance_datetime = ParseTimeValue(zero_balance_time)
    delay_minutes = GetDeleteDelayMinutes(zero_balance_datetime)
    age_minutes = int((datetime.datetime.now() - zero_balance_datetime).total_seconds() / 60)
    if age_minutes < delay_minutes:
        print(json.dumps(MakeDeleteReadyResponse(False, args.key, "package age is less than delete delay"), ensure_ascii=False, indent=4))
        return
    new_list = [item for item in alert_dictionary_list if args.key not in item]
    SaveAlertDictionaryList(args.state_file, new_list)
    print(json.dumps(MakeDeleteReadyResponse(True, args.key, ""), ensure_ascii=False, indent=4))

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
