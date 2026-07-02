#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
try:
    import requests
except ImportError:
    requests = None

from config.local_settings_and_secrets import (
    JIRA_CREATE_INC_URL, JIRA_FIXED_OBJECT_CUSTOM_FIELD,
    JIRA_FIXED_OBJECT_KEY, JIRA_FUNCTION_CUSTOM_FIELD,
    JIRA_INCIDENT_TYPE_CUSTOM_FIELD, JIRA_INSIGHT_CUSTOM_FIELD,
    JIRA_ISSUE_BROWSE_URL, JIRA_ISSUE_TYPE_ID, JIRA_PRIORITY_NAME,
    JIRA_PROJECT_ID, JIRA_REQUEST_TIMEOUT_SECONDS, JIRA_TOKEN,
    JIRA_VERIFY_SSL
)


def MaskSensitiveText(text):
    safe = str(text)
    for secret in (globals().get("JIRA_TOKEN", ""),):
        if secret:
            safe = safe.replace(secret, "***")
    safe = re.sub(r"\b(Bearer|Basic)\s+[^\s,;]+", r"\1 ***", safe)
    return safe[:2000]


def FindStep(alert_data, step_name):
    for step in alert_data.get("action", {}).values():
        if isinstance(step, dict) and step.get("stepName") == step_name:
            return step
    return {}


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
        new_step.update({"stepSate": 2, "errorMessage": "requests module is not available"})
        return False, new_step
    insight_id = FindStep(alert_data, "resolveInsightId").get("insightId", "")
    insight_data = FindStep(alert_data, "loadInsightData")
    fields = {
        "project": {"id": JIRA_PROJECT_ID},
        "issuetype": {"id": JIRA_ISSUE_TYPE_ID},
        "priority": {"name": JIRA_PRIORITY_NAME},
        "summary": "Автоматический инцидент Zabbix: {} {}".format(root_key, alert_data.get("trigName", "")),
        "description": alert_data.get("trigName", ""),
        JIRA_INSIGHT_CUSTOM_FIELD: [{"key": insight_id}] if insight_id else [],
        JIRA_INCIDENT_TYPE_CUSTOM_FIELD: [{"key": insight_data.get("jiraIncidentTypeKey", "")}],
        JIRA_FUNCTION_CUSTOM_FIELD: [{"key": insight_data.get("functionObjectKey", "")}],
    }
    if JIRA_FIXED_OBJECT_KEY:
        fields[JIRA_FIXED_OBJECT_CUSTOM_FIELD] = [{"key": JIRA_FIXED_OBJECT_KEY}]
    try:
        response = requests.post(JIRA_CREATE_INC_URL, headers={"Authorization": JIRA_TOKEN, "Content-Type": "application/json"}, json={"fields": fields}, timeout=JIRA_REQUEST_TIMEOUT_SECONDS, verify=JIRA_VERIFY_SSL)
        response.raise_for_status()
        data = response.json()
        jira_key = data.get("key")
        if not jira_key:
            raise ValueError("Jira response does not contain issue key")
        new_step.update({"stepSate": 1, "errorMessage": "", "jiraKey": jira_key, "jiraUrl": BuildJiraBrowseUrl(jira_key)})
        return True, new_step
    except Exception as error:
        new_step.update({"stepSate": 2, "errorMessage": MaskSensitiveText("{}: {}".format(type(error).__name__, error))})
        return False, new_step
