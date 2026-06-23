#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import datetime
import json
import os
import re
import sys


############################### VARS ###############################

STATE_FILE_DEFAULT = "/tmp/alerts.json"
LOG_FILE = "/tmp/alerts.log"
VERBOSE = False
GROUP_PATTERN = r"SG/([^,/]+)"
ACTION_TEMPLATE_INC = {
    "ktalkUserMessage": {
        "ktalkUsersList": [],
        "stepSate": "",
        "errorMessage": "",
        "retryNumber": ""
    },
    "ktalkBot": {
        "stepSate": "",
        "errorMessage": "",
        "retryNumber": ""
    }
}


############################### ARGS ###############################


def GetArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode")
    parser.add_argument("--event")
    parser.add_argument("--groups")
    parser.add_argument("--triggerTime", dest="trigger_time")
    parser.add_argument("--trigName", dest="trig_name")
    parser.add_argument("--message")
    parser.add_argument("--severity")
    parser.add_argument("--template", default="inc")
    parser.add_argument("--state-file", dest="state_file", default=STATE_FILE_DEFAULT)
    parser.add_argument("--path", default="$")
    parser.add_argument("--key")
    parser.add_argument("--data")
    parser.add_argument("-a", dest="action_keys")
    parser.add_argument("-l", dest="list_key")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


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
        WriteLog("Failed to parse state file {}: {}".format(state_file, error), "ERROR")
        raise

    if not isinstance(alert_dictionary_list, list):
        raise ValueError("Invalid state structure: root element must be a list")

    for alert_dictionary in alert_dictionary_list:
        if not isinstance(alert_dictionary, dict):
            raise ValueError("Invalid state structure: each list item must be a dictionary")

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


def CheckSelectArgs(args):
    CheckRequiredValue(args.path, "--path")


def CheckDeleteArgs(args):
    CheckRequiredValue(args.key, "--key")


def CheckUpdateArgs(args):
    CheckRequiredValue(args.path, "--path")
    if args.data is None and args.action_keys is None:
        raise ValueError("Required argument is missing: --data or -a")


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
        "criticalEventBalance": 0
    }
    return alert_data


def GetExistingEventBalance(alert_data):
    if "eventBalance" in alert_data:
        return GetIntegerValue(alert_data.get("eventBalance"), "eventBalance")

    return GetIntegerValue(alert_data.get("balance", 0), "balance")


def GetExistingCriticalEventBalance(alert_data):
    return GetIntegerValue(alert_data.get("criticalEventBalance", 0), "criticalEventBalance")


def ApplyEventOneToAlertList(alert_dictionary_list, root_key, args):
    alert_dictionary = FindAlertDictionaryByRootKey(alert_dictionary_list, root_key)
    new_severity = GetIntegerValue(args.severity, "severity")

    if alert_dictionary is None:
        alert_data = CreateEventOneAlertData(args)
        if new_severity == 5:
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

    old_event_balance = GetExistingEventBalance(alert_data)
    old_critical_event_balance = GetExistingCriticalEventBalance(alert_data)
    old_severity = alert_data.get("severity", "0")
    old_severity = GetIntegerValue(old_severity, "severity")

    alert_data["eventBalance"] = old_event_balance + 1
    if new_severity == 5:
        alert_data["criticalEventBalance"] = old_critical_event_balance + 1
    else:
        alert_data["criticalEventBalance"] = old_critical_event_balance

    if "action" not in alert_data:
        alert_data["action"] = GetActionTemplate(args.template)
    if new_severity > old_severity:
        alert_data["severity"] = args.severity

    WriteLog("Root key {} updated, event balance is {}, critical event balance is {}".format(
        root_key,
        alert_data["eventBalance"],
        alert_data["criticalEventBalance"]
    ), "INFO")


def ApplyEventZeroToAlertList(alert_dictionary_list, root_key, args):
    alert_dictionary = FindAlertDictionaryByRootKey(alert_dictionary_list, root_key)
    severity_value = GetIntegerValue(args.severity, "severity")

    if alert_dictionary is None:
        WriteLog("Root key {} was not found for event 0, nothing changed".format(root_key), "INFO")
        return

    alert_data = alert_dictionary[root_key]
    if not isinstance(alert_data, dict):
        raise ValueError("Invalid alert data for root key {}".format(root_key))

    old_event_balance = GetExistingEventBalance(alert_data)
    old_critical_event_balance = GetExistingCriticalEventBalance(alert_data)

    alert_data["eventBalance"] = old_event_balance - 1
    if severity_value == 5:
        alert_data["criticalEventBalance"] = old_critical_event_balance - 1
    else:
        alert_data["criticalEventBalance"] = old_critical_event_balance

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


def UpdateAlertDictionaryList(args):
    CheckAddArgs(args)
    root_keys = ExtractRootKeysFromGroups(args.groups)

    if len(root_keys) == 0:
        raise ValueError("No groups starting with SG/ were found")

    WriteLog("Extracted root keys: {}".format(", ".join(root_keys)), "INFO")

    event_value = GetIntegerValue(args.event, "event")
    if event_value != 0 and event_value != 1:
        raise ValueError("Unsupported event value: {}".format(args.event))

    severity_value = GetIntegerValue(args.severity, "severity")
    if severity_value == 0:
        WriteLog("Severity is 0, no action is required", "INFO")
        return
    if severity_value < 1 or severity_value > 5:
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


def UpdateAlertDictionaryValue(args):
    CheckUpdateArgs(args)
    alert_dictionary_list = LoadAlertDictionaryList(args.state_file)

    if args.data is not None:
        UpdateValueByJsonPath(alert_dictionary_list, args.path, args.data)

    if args.action_keys is not None:
        AddActionTemplateKeysByJsonPath(alert_dictionary_list, args.path, args.action_keys)

    SaveAlertDictionaryList(args.state_file, alert_dictionary_list)


############################### BODY ###############################


parser = GetArgs()
args = parser.parse_args()
VERBOSE = args.verbose

try:
    WriteLog("Script started in mode {}".format(args.mode), "INFO")
    WriteLog("Selected mode: {}".format(args.mode), "INFO")

    if args.mode == "add":
        UpdateAlertDictionaryList(args)
    elif args.mode == "select":
        SelectAlertDictionaryList(args)
    elif args.mode == "del":
        DeleteAlertDictionaryByRootKey(args)
    elif args.mode == "update":
        UpdateAlertDictionaryValue(args)
    else:
        raise ValueError("Unsupported mode: {}".format(args.mode))

    WriteLog("Script finished successfully", "INFO")
    sys.exit(0)
except Exception as error:
    WriteLog("Execution failed: {}".format(error), "ERROR")
    sys.exit(1)
