#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
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


LOGGER = logging.getLogger(__name__)


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


def BuildNormalizedUniqueADLoginList(values, field_name=None):
    result = []
    if not isinstance(values, list):
        if field_name:
            raise ValueError("resolver response {} field is not a list".format(field_name))
        return result
    for value in values:
        normalized = NormalizeADLogin(value)
        if normalized and normalized not in result:
            result.append(normalized)
    return result


def ParseResolverCountFound(data):
    if "count_found" not in data:
        return None
    try:
        return int(data.get("count_found"))
    except (TypeError, ValueError):
        raise ValueError("resolver response count_found is not an integer")


def ParseResolverData(data, requested_logins):
    if not isinstance(data, dict):
        raise ValueError("resolver response root is not a dict")

    items = data.get("users")
    if not isinstance(items, list):
        raise ValueError("resolver response users field is missing or is not a list")

    count_found = ParseResolverCountFound(data)
    if count_found is not None and count_found > 0 and not items:
        raise ValueError("resolver response count_found is greater than zero, but users list is empty")

    found = []
    without = []
    found_logins = set()
    for item in items:
        if not isinstance(item, dict):
            continue

        ad_login = NormalizeADLogin(
            item.get(
                "ad_login",
                item.get("adLogin", item.get("login", ""))
            )
        )
        mention_value = item.get(
            "ktalk_mention_id",
            item.get(
                "mentionId",
                item.get("mention_id", item.get("user_id", ""))
            )
        )
        if mention_value is not None and not isinstance(mention_value, (str, int, float, bool)):
            raise ValueError("resolver response user contains invalid ktalk_mention_id value")
        mention_id = str(mention_value or "").strip()
        display_name = str(
            item.get(
                "ad_name",
                item.get(
                    "displayName",
                    item.get("display_name", ad_login)
                )
            ) or ""
        ).strip()

        if not ad_login:
            raise ValueError("resolver response user does not contain ad_login")

        found_logins.add(ad_login)
        if mention_id:
            found.append({"adLogin": ad_login, "mentionId": mention_id, "displayName": display_name or ad_login})
        else:
            without.append(ad_login)

    if count_found is not None and count_found > 0 and not found:
        raise ValueError("resolver response count_found is greater than zero, but no users with ktalk_mention_id were parsed")

    if "not_found_ad_logins" in data:
        not_found = BuildNormalizedUniqueADLoginList(data.get("not_found_ad_logins"), "not_found_ad_logins")
    else:
        not_found = [login for login in requested_logins if login not in found_logins]

    if "without_ktalk_mention_id" in data:
        without = BuildNormalizedUniqueADLoginList(data.get("without_ktalk_mention_id"), "without_ktalk_mention_id")
    else:
        without = BuildNormalizedUniqueADLoginList(without)

    LOGGER.info(
        "resolver API result: requested users=%s, resolved users=%s, not found users=%s, users without mention id=%s",
        len(requested_logins),
        len(found),
        len(not_found),
        len(without),
    )

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
        new_step.update({"stepSate": 1, "errorMessage": "", "recipientList": found, "notFoundADUserList": not_found, "withoutMentionIdList": without})
        return True, new_step
    except Exception as error:
        new_step.update({"stepSate": 2, "errorMessage": MaskSensitiveText("{}: {}".format(type(error).__name__, error))})
        return False, new_step
