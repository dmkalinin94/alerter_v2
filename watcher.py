#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import datetime
import json
import os
import subprocess
import sys

from config.local_settings_and_secrets import CLI_COMMAND_TIMEOUT_SECONDS


############################### VARS ###############################

CLI_PATH_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alios.py")
STATE_FILE_DEFAULT = "/tmp/alerts.json"
VERBOSE = False


############################### ARGS ###############################


def GetArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli-path", dest="cli_path", default=CLI_PATH_DEFAULT)
    parser.add_argument("--state-file", dest="state_file", default=STATE_FILE_DEFAULT)
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args()


############################### LOGS ###############################


def WriteLog(message, level):
    if not VERBOSE:
        return

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = "{} [{}] {}".format(now, level, message)
    print(log_message)


############################### CLI ###############################


def RunCliCommand(command):
    try:
        return subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=CLI_COMMAND_TIMEOUT_SECONDS
        )
    except subprocess.TimeoutExpired as error:
        WriteLog("CLI command timed out after {} seconds: {}".format(CLI_COMMAND_TIMEOUT_SECONDS, error), "ERROR")
        return subprocess.CompletedProcess(command, 1, "", str(error))
    except OSError as error:
        WriteLog("Failed to run CLI command: {}".format(error), "ERROR")
        raise


def CheckCliPath(cli_path):
    if os.path.exists(cli_path):
        return True
    WriteLog("CLI file was not found: {}".format(cli_path), "ERROR")
    return False


def BuildCliCommand(args, mode, root_key=None, extra_arguments=None):
    command = [
        sys.executable,
        args.cli_path,
        mode,
        "--state-file",
        args.state_file
    ]
    if root_key is not None:
        command.extend(["--rootkey", root_key])
    if extra_arguments:
        command.extend(extra_arguments)
    return command


def ParseJsonOutput(result, context):
    try:
        return json.loads(result.stdout)
    except ValueError as error:
        WriteLog("{} stdout is not valid JSON: {}".format(context, error), "ERROR")
        WriteLog("{} stdout: {}".format(context, result.stdout.strip()), "ERROR")
        return None


def LogFailedCliResult(context, result):
    WriteLog("{} failed with code {}".format(context, result.returncode), "ERROR")
    WriteLog("{} stderr: {}".format(context, result.stderr.strip()), "ERROR")
    WriteLog("{} stdout: {}".format(context, result.stdout.strip()), "ERROR")


############################### FUNCTIONS ###############################


def LoadAlertPackages(args):
    command = BuildCliCommand(args, "select", extra_arguments=["--path", "$"])
    WriteLog("Loading alert packages with CLI select", "INFO")
    result = RunCliCommand(command)

    if result.returncode != 0:
        LogFailedCliResult("CLI select", result)
        return None

    alert_dictionary_list = ParseJsonOutput(result, "CLI select")
    if not isinstance(alert_dictionary_list, list):
        WriteLog("CLI select root result is not a list", "ERROR")
        return None

    for alert_dictionary in alert_dictionary_list:
        if not isinstance(alert_dictionary, dict):
            WriteLog("CLI select list item is not a dictionary", "ERROR")
            return None

    WriteLog("Loaded alert packages: {}".format(len(alert_dictionary_list)), "INFO")
    return alert_dictionary_list


def AddRequiredSteps(args, root_key):
    command = BuildCliCommand(args, "update", root_key=root_key, extra_arguments=["--required-steps"])
    result = RunCliCommand(command)

    if result.returncode != 0:
        LogFailedCliResult("CLI update required steps for root key {}".format(root_key), result)
        return None

    result_data = ParseJsonOutput(result, "CLI update required steps for root key {}".format(root_key))
    if not isinstance(result_data, dict):
        WriteLog("CLI update required steps result is not a dictionary for root key {}".format(root_key), "ERROR")
        return None

    added_steps = result_data.get("added", [])
    if not isinstance(added_steps, list):
        WriteLog("CLI update required steps returned invalid added list for root key {}".format(root_key), "ERROR")
        return None

    WriteLog(
        "Required steps result for root key {}: stage={}, added={}, count={}, routeChanged={}".format(
            root_key,
            result_data.get("stage", ""),
            ", ".join(added_steps),
            len(added_steps),
            result_data.get("routeChanged", False)
        ),
        "INFO"
    )
    return result_data


def DeleteReadyPackage(args, root_key):
    command = BuildCliCommand(args, "del-ready", root_key=root_key)
    result = RunCliCommand(command)

    if result.returncode != 0:
        LogFailedCliResult("CLI del-ready for root key {}".format(root_key), result)
        return None

    response = ParseJsonOutput(result, "CLI del-ready for root key {}".format(root_key))
    if not isinstance(response, dict):
        WriteLog("CLI del-ready result is not a dictionary for root key {}".format(root_key), "ERROR")
        return None

    return response


def ProcessPackage(args, root_key, alert_data, counters):
    counters["processed"] = counters["processed"] + 1
    WriteLog("Processing root key: {}".format(root_key), "INFO")

    if not isinstance(alert_data, dict):
        WriteLog("Alert data is not a dictionary for root key {}".format(root_key), "ERROR")
        counters["errors"] = counters["errors"] + 1
        return

    required_steps_result = AddRequiredSteps(args, root_key)
    if required_steps_result is None:
        counters["errors"] = counters["errors"] + 1
        return
    counters["steps_added"] = counters["steps_added"] + len(required_steps_result.get("added", []))

    response = DeleteReadyPackage(args, root_key)
    if response is None:
        counters["errors"] = counters["errors"] + 1
        return
    if response.get("deleted") is True:
        counters["deleted"] = counters["deleted"] + 1
        WriteLog("Deleted root key {}".format(root_key), "INFO")
        return

    counters["skipped"] = counters["skipped"] + 1
    WriteLog("Root key {} was not deleted: {}".format(root_key, response.get("reason", "")), "INFO")


def ProcessAlertPackages(args, package_list):
    counters = {"processed": 0, "steps_added": 0, "deleted": 0, "skipped": 0, "errors": 0}

    if len(package_list) == 0:
        WriteLog("No alert packages found", "INFO")
        return counters

    for alert_package in package_list:
        root_key = alert_package.get("rootKey")
        if not isinstance(root_key, str) or root_key.strip() == "":
            WriteLog("Alert package misses rootKey", "ERROR")
            counters["skipped"] = counters["skipped"] + 1
            counters["errors"] = counters["errors"] + 1
            continue
        ProcessPackage(args, root_key, alert_package, counters)

    return counters


def Main():
    global VERBOSE

    args = GetArgs()
    VERBOSE = args.verbose

    WriteLog("Script started", "INFO")
    WriteLog("CLI path: {}".format(args.cli_path), "INFO")
    WriteLog("State file path: {}".format(args.state_file), "INFO")

    if not CheckCliPath(args.cli_path):
        sys.exit(1)

    alert_dictionary_list = LoadAlertPackages(args)
    if alert_dictionary_list is None:
        sys.exit(1)

    counters = ProcessAlertPackages(args, alert_dictionary_list)

    WriteLog("Script finished", "INFO")
    WriteLog("Processed packages: {}".format(counters["processed"]), "INFO")
    WriteLog("Packages with added steps: {}".format(counters["steps_added"]), "INFO")
    WriteLog("Deleted packages: {}".format(counters["deleted"]), "INFO")
    WriteLog("Skipped packages: {}".format(counters["skipped"]), "INFO")
    WriteLog("Packages with errors: {}".format(counters["errors"]), "INFO")

    if counters["errors"] > 0:
        sys.exit(1)
    sys.exit(0)


############################### BODY ###############################


if __name__ == "__main__":
    Main()
