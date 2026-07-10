#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
try:
    import requests
except ImportError:
    requests = None

from config.secret_masking import MaskSensitiveText as CommonMaskSensitiveText
from config.local_settings_and_secrets import (
    JIRA_CREATE_INC_URL, JIRA_FIXED_OBJECT_CUSTOM_FIELD,
    JIRA_FIXED_OBJECT_KEY, JIRA_FUNCTION_CUSTOM_FIELD,
    JIRA_DEFAULT_INCIDENT_TYPE_KEY, JIRA_INCIDENT_TYPE_CUSTOM_FIELD,
    JIRA_INSIGHT_CUSTOM_FIELD, JIRA_ISSUE_BROWSE_URL, JIRA_ISSUE_TYPE_ID,
    JIRA_PRIORITY_NAME, JIRA_PROJECT_ID, JIRA_REQUEST_TIMEOUT_SECONDS,
    JIRA_TOKEN, JIRA_VERIFY_SSL
)


def MaskSensitiveText(text):
    return CommonMaskSensitiveText(text)


def GetStep(alert_data, step_name):
    return alert_data.get("steps", {}).get(step_name, {})


def BuildJiraBrowseUrl(jira_key):
    if "{}" in JIRA_ISSUE_BROWSE_URL:
        return JIRA_ISSUE_BROWSE_URL.format(jira_key)
    return JIRA_ISSUE_BROWSE_URL.rstrip("/") + "/" + jira_key


def CreateLowSeverityJiraIncident(root_key, alert_data, step_data):
    return CreateJiraIncident(root_key, alert_data, step_data)


def CreateCriticalJiraIncident(root_key, alert_data, step_data):
    return CreateJiraIncident(root_key, alert_data, step_data)


def CreateJiraIncident(root_key, alert_data, step_data):
    new_step = step_data.copy()
    if requests is None:
        new_step.update({"stepState": 2, "errorMessage": "requests module is not available"})
        return False, new_step
    insight_id = str(GetStep(alert_data, "resolveInsightId").get("insightId", "")).strip()
    if not insight_id:
        new_step.update({"stepState": 2, "errorMessage": "Jira incident was not created: resolveInsightId did not provide insightId"})
        return False, new_step
    if not str(JIRA_FIXED_OBJECT_KEY).strip():
        new_step.update({"stepState": 2, "errorMessage": "Jira incident was not created: JIRA_FIXED_OBJECT_KEY is empty"})
        return False, new_step
    incident_type_key = str(GetStep(alert_data, "loadInsightData").get("jiraIncidentTypeKey", "")).strip() or str(JIRA_DEFAULT_INCIDENT_TYPE_KEY).strip()
    if not incident_type_key:
        new_step.update({"stepState": 2, "errorMessage": "Jira incident was not created: incident type key is empty"})
        return False, new_step
    function_object_key = str(GetStep(alert_data, "loadInsightData").get("functionObjectKey", "")).strip()
    fields = {
        "project": {"id": JIRA_PROJECT_ID},
        "issuetype": {"id": JIRA_ISSUE_TYPE_ID},
        "priority": {"name": JIRA_PRIORITY_NAME},
        "summary": "Автоматический инцидент Zabbix: {} {}".format(root_key, alert_data.get("trigName", "")),
        "description": alert_data.get("trigName", ""),
        JIRA_INSIGHT_CUSTOM_FIELD: [{"key": insight_id}],
        JIRA_INCIDENT_TYPE_CUSTOM_FIELD: [{"key": incident_type_key}],
        JIRA_FUNCTION_CUSTOM_FIELD: [{"key": function_object_key}] if function_object_key else [],
        JIRA_FIXED_OBJECT_CUSTOM_FIELD: [{"key": JIRA_FIXED_OBJECT_KEY}],
    }
    try:
        response = requests.post(JIRA_CREATE_INC_URL, headers={"Authorization": JIRA_TOKEN, "Accept": "application/json", "Content-Type": "application/json"}, json={"fields": fields}, timeout=JIRA_REQUEST_TIMEOUT_SECONDS, verify=JIRA_VERIFY_SSL)
        response.raise_for_status()
        data = response.json()
        jira_key = data.get("key")
        if not jira_key:
            raise ValueError("Jira response does not contain issue key")
        new_step.update({"stepState": 1, "errorMessage": "", "jiraKey": jira_key, "jiraUrl": BuildJiraBrowseUrl(jira_key)})
        return True, new_step
    except Exception as error:
        status = getattr(getattr(error, "response", None), "status_code", "")
        body = getattr(getattr(error, "response", None), "text", "")[:500]
        detail = "{}: {}".format(type(error).__name__, error)
        if status:
            detail += " HTTP {}".format(status)
        if body:
            detail += " {}".format(body)
        new_step.update({"stepState": 2, "errorMessage": MaskSensitiveText(detail)})
        return False, new_step
