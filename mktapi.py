#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
try:
    import requests
except ImportError:
    requests = None

from config.secret_masking import MaskSensitiveText as CommonMaskSensitiveText
from config.local_settings_and_secrets import (
    RECIPIENT_RESOLVER_URL, RECIPIENT_RESOLVER_TIMEOUT_SECONDS,
    RECIPIENT_RESOLVER_VERIFY_SSL, RECIPIENT_RESOLVER_TOKEN
)


def MaskSensitiveText(text):
    return CommonMaskSensitiveText(text)


def NormalizeADLogin(login):
    value = str(login).strip().lower()
    if value.startswith("@"):
        value = value[1:]
    if ":" in value:
        value = value.split(":", 1)[0]
    return value.strip()


def GetLoadInsightDataStep(alert_data):
    for step in alert_data.get("action", {}).values():
        if isinstance(step, dict) and step.get("stepName") == "loadInsightData":
            return step
    return {}


def ParseResolverData(data, requested_logins):
    items = data.get("users") if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise ValueError("resolver response root is not a list")
    found = []
    without = []
    found_logins = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        ad_login = NormalizeADLogin(item.get("adLogin", item.get("ad_login", item.get("login", ""))))
        mention_id = str(item.get("mentionId", item.get("mention_id", item.get("user_id", "")))).strip()
        display_name = str(item.get("displayName", item.get("display_name", ad_login))).strip()
        if not ad_login:
            continue
        found_logins.add(ad_login)
        if mention_id:
            found.append({"adLogin": ad_login, "mentionId": mention_id, "displayName": display_name or ad_login})
        else:
            without.append(ad_login)
    not_found = [login for login in requested_logins if login not in found_logins]
    return found, not_found, without


def ResolveKTalkUsers(root_key, alert_data, step_data):
    new_step = step_data.copy()
    insight_step = GetLoadInsightDataStep(alert_data)
    raw_logins = insight_step.get("recipientADUserList", []) if isinstance(insight_step, dict) else []
    requested = []
    for login in raw_logins:
        normalized = NormalizeADLogin(login)
        if normalized and normalized not in requested:
            requested.append(normalized)
    if not requested:
        new_step.update({"stepSate": 1, "errorMessage": "", "recipientList": [], "notFoundADUserList": [], "withoutMentionIdList": []})
        return True, new_step
    if requests is None:
        new_step.update({"stepSate": 2, "errorMessage": "requests module is not available"})
        return False, new_step
    try:
        headers = {}
        if RECIPIENT_RESOLVER_TOKEN:
            headers["Authorization"] = "Bearer {}".format(RECIPIENT_RESOLVER_TOKEN)
        params = [("ad_login", login) for login in requested]
        response = requests.get(RECIPIENT_RESOLVER_URL, headers=headers, params=params, timeout=RECIPIENT_RESOLVER_TIMEOUT_SECONDS, verify=RECIPIENT_RESOLVER_VERIFY_SSL)
        response.raise_for_status()
        found, not_found, without = ParseResolverData(response.json(), requested)
        if not found and requested:
            raise ValueError("resolver returned empty result for non-empty input")
        new_step.update({"stepSate": 1, "errorMessage": "", "recipientList": found, "notFoundADUserList": not_found, "withoutMentionIdList": without})
        return True, new_step
    except Exception as error:
        new_step.update({"stepSate": 2, "errorMessage": MaskSensitiveText("{}: {}".format(type(error).__name__, error))})
        return False, new_step
