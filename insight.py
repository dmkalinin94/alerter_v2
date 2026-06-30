#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re

from config.local_settings_and_secrets import (
    INSIGHT_ACTUAL_STATUS_VALUE, INSIGHT_AUTH_TOKEN, INSIGHT_GROUP_URL,
    INSIGHT_MANDATORY_RECIPIENTS, INSIGHT_RECIPIENT_ATTRIBUTE_IDS,
    INSIGHT_REQUEST_TIMEOUT_SECONDS, INSIGHT_RESPONSIBLE_GROUP_ATTRIBUTE_ID,
    INSIGHT_SERVICE_URL, INSIGHT_STATUS_ATTRIBUTE_ID, INSIGHT_VERIFY_SSL
)


def MaskSensitiveText(text):
    try:
        safe_text = str(text)
        if INSIGHT_AUTH_TOKEN:
            safe_text = safe_text.replace(INSIGHT_AUTH_TOKEN, "***")
        safe_text = re.sub(r"\bBearer\s+[^\s,;]+", "Bearer ***", safe_text)
        safe_text = re.sub(r"\bBasic\s+[^\s,;]+", "Basic ***", safe_text)
        return safe_text
    except Exception:
        return "Insight error details were hidden"


def MakeResult(success, is_activ, recipients, error_message):
    return {
        "success": success,
        "isActiv": is_activ,
        "recipientADUserList": recipients,
        "errorMessage": MaskSensitiveText(error_message)
    }


def GetAttributeById(attribute_list, attribute_id):
    for attribute in attribute_list:
        try:
            if int(attribute.get("objectTypeAttributeId")) == int(attribute_id):
                return attribute
        except (TypeError, ValueError, AttributeError):
            continue
    return None


def FormatUrlTemplate(url_template, parameter_name, parameter_value):
    try:
        return url_template.format(**{parameter_name: parameter_value})
    except (KeyError, IndexError):
        return url_template.format(parameter_value)


def GetJsonList(url, headers, verify, timeout):
    import requests
    response = requests.get(url, headers=headers, verify=verify, timeout=timeout)
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, list):
        raise ValueError("Insight response root object is not a list")
    return response.status_code, data


def ExtractServiceStatus(attribute_list):
    status_attribute = GetAttributeById(attribute_list, INSIGHT_STATUS_ATTRIBUTE_ID)
    if not isinstance(status_attribute, dict):
        return None, "Insight status attribute was not found"
    values = status_attribute.get("objectAttributeValues")
    if not isinstance(values, list) or len(values) == 0:
        return None, "Insight status attribute has no values"
    value = values[0].get("value") if isinstance(values[0], dict) else None
    if not isinstance(value, str) or value.strip() == "":
        return None, "Insight status attribute value is empty"
    return value.strip(), ""


def ExtractResponsibleGroupId(attribute_list):
    group_attribute = GetAttributeById(attribute_list, INSIGHT_RESPONSIBLE_GROUP_ATTRIBUTE_ID)
    if not isinstance(group_attribute, dict):
        return None, "Insight responsible group attribute was not found"
    values = group_attribute.get("objectAttributeValues")
    if not isinstance(values, list) or len(values) == 0:
        return None, "Insight responsible group attribute has no values"
    for value in values:
        referenced_object = value.get("referencedObject") if isinstance(value, dict) else None
        if not isinstance(referenced_object, dict):
            continue
        try:
            return int(referenced_object.get("id")), ""
        except (TypeError, ValueError):
            continue
    return None, "Insight responsible group id was not found"


def AppendUniqueRecipient(recipient_list, recipient):
    if not isinstance(recipient, str):
        return False
    normalized_recipient = recipient.strip()
    if normalized_recipient == "" or normalized_recipient in recipient_list:
        return False
    recipient_list.append(normalized_recipient)
    return True


def ExtractRecipients(attribute_list):
    recipient_list = []
    recipient_attribute_ids = set([int(value) for value in INSIGHT_RECIPIENT_ATTRIBUTE_IDS])
    insight_recipient_count = 0
    for attribute in attribute_list:
        try:
            attribute_id = int(attribute.get("objectTypeAttributeId"))
        except (TypeError, ValueError, AttributeError):
            continue
        if attribute_id not in recipient_attribute_ids:
            continue
        values = attribute.get("objectAttributeValues")
        if not isinstance(values, list):
            continue
        for value in values:
            user = value.get("user", {}) if isinstance(value, dict) else {}
            name = user.get("name") if isinstance(user, dict) else None
            if AppendUniqueRecipient(recipient_list, name):
                insight_recipient_count = insight_recipient_count + 1
    mandatory_added_count = 0
    for recipient in INSIGHT_MANDATORY_RECIPIENTS:
        if AppendUniqueRecipient(recipient_list, recipient):
            mandatory_added_count = mandatory_added_count + 1
    return recipient_list, insight_recipient_count, mandatory_added_count


def GetInsightData(insight_id):
    try:
        service_headers = {"Content-Type": "application/json;charset=UTF-8", "Authorization": INSIGHT_AUTH_TOKEN}
        service_url = FormatUrlTemplate(INSIGHT_SERVICE_URL, "insight_id", insight_id)
        service_status_code, service_attributes = GetJsonList(
            service_url,
            service_headers,
            INSIGHT_VERIFY_SSL,
            INSIGHT_REQUEST_TIMEOUT_SECONDS
        )
        print("Insight service HTTP status: {}".format(service_status_code))

        service_status, error_message = ExtractServiceStatus(service_attributes)
        if error_message:
            return MakeResult(False, 0, [], error_message)
        print("Insight service status value: {}".format(service_status))
        if service_status != INSIGHT_ACTUAL_STATUS_VALUE:
            print('Service {} is not in status "{}"; responsible users loading skipped'.format(insight_id, INSIGHT_ACTUAL_STATUS_VALUE))
            return MakeResult(True, 0, [], "")

        group_id, error_message = ExtractResponsibleGroupId(service_attributes)
        if error_message:
            return MakeResult(False, 0, [], error_message)
        print("Insight responsible group id: {}".format(group_id))

        group_headers = {"Content-Type": "application/json", "Authorization": INSIGHT_AUTH_TOKEN}
        group_url = FormatUrlTemplate(INSIGHT_GROUP_URL, "group_id", group_id)
        group_status_code, group_attributes = GetJsonList(
            group_url,
            group_headers,
            INSIGHT_VERIFY_SSL,
            INSIGHT_REQUEST_TIMEOUT_SECONDS
        )
        print("Insight group HTTP status: {}".format(group_status_code))

        recipients, insight_count, mandatory_count = ExtractRecipients(group_attributes)
        print("Insight recipient users found: {}".format(insight_count))
        print("Mandatory recipient users added: {}".format(mandatory_count))
        if len(recipients) == 0:
            return MakeResult(False, 0, [], "Insight recipient list is empty")
        return MakeResult(True, 1, recipients, "")
    except Exception as error:
        return MakeResult(False, 0, [], "{}: {}".format(type(error).__name__, MaskSensitiveText(error)))
