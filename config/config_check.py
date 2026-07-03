#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from config import local_settings_and_secrets as settings

EMPTY_PLACEHOLDERS = {"<token>", "<ktalk_bearer_token>", "changeme"}

REQUIRED_CONFIG_NAMES = (
    "JIRA_TOKEN", "JIRA_CREATE_INC_URL", "JIRA_ISSUE_BROWSE_URL", "JIRA_PROJECT_ID",
    "JIRA_ISSUE_TYPE_ID", "JIRA_PRIORITY_NAME", "JIRA_FIXED_OBJECT_KEY",
    "JIRA_DEFAULT_INCIDENT_TYPE_KEY", "INSIGHT_SERVICE_URL", "INSIGHT_GROUP_URL",
    "INSIGHT_AUTH_TOKEN", "INSIGHT_FULL_NAME_ATTRIBUTE_ID", "INSIGHT_STATUS_ATTRIBUTE_ID",
    "INSIGHT_FUNCTION_OBJECT_ATTRIBUTE_ID", "INSIGHT_RESPONSIBLE_GROUP_ATTRIBUTE_ID",
    "INSIGHT_JIRA_INCIDENT_TYPE_ATTRIBUTE_ID", "INSIGHT_RECIPIENT_ATTRIBUTE_IDS",
    "KTALK_BASE_URL", "KTALK_ROOM_ID", "KTALK_BEARER_TOKEN", "KTALK_HOST", "KTALK_TALK_HOST", "RECIPIENT_RESOLVER_URL",
    "DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD", "DB_PORT",
)


def IsEmptyConfigValue(value):
    if value is None:
        return True
    if isinstance(value, str):
        stripped = value.strip()
        return stripped == "" or stripped.lower() in EMPTY_PLACEHOLDERS
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) == 0
    return False


def ValidateConfig():
    missing = []
    for name in REQUIRED_CONFIG_NAMES:
        if not hasattr(settings, name) or IsEmptyConfigValue(getattr(settings, name)):
            missing.append(name)
    if missing:
        raise RuntimeError("Configuration validation failed: {}".format(", ".join(missing)))
    return True
