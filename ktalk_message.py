#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import datetime
import hashlib
import html
import importlib
import importlib.util
import re
import logging
import time
import uuid
from urllib.parse import quote

from config.secret_masking import MaskSensitiveText as CommonMaskSensitiveText
from config.local_settings_and_secrets import (
    JIRA_THREAD_LINK_CUSTOM_FIELD, JIRA_THREAD_LINK_TRANSITION_ENABLED,
    JIRA_THREAD_LINK_TRANSITION_ID, JIRA_THREAD_LINK_TRANSITION_STRICT,
    JIRA_THREAD_LINK_TRANSITION_URL, JIRA_TOKEN, KTALK_AGGREGATE_MESSAGE_REPEAT_COUNT,
    KTALK_AGGREGATE_MESSAGE_REPEAT_INTERVAL_SECONDS, KTALK_BASE_URL,
    KTALK_BEARER_TOKEN, KTALK_HOST,
    KTALK_MESSAGE_SEARCH_ATTEMPTS, KTALK_MESSAGE_SEARCH_DELAY_SECONDS,
    KTALK_MESSAGE_SEARCH_LIMIT, KTALK_RETRY_DELAY_SECONDS, KTALK_ROOM_ID,
    KTALK_SAFE_REQUEST_RETRIES, KTALK_SAFE_REQUEST_TIMEOUT, KTALK_SEND_MESSAGE_RETRIES,
    KTALK_SEND_MESSAGE_TIMEOUT, KTALK_TALK_HOST, KTALK_THREAD_LINK_REQUIRED_PREFIX,
    KTALK_THREAD_WEB_URL_TEMPLATE, KTALK_VERIFY_SSL
)

DATETIME_FORMAT = "%Y.%m.%d %H:%M:%S"
ATTR_KEY = "alerter_v2.messageAttributes"
ERROR_TEXT_LIMIT = 1000
LOGGER = logging.getLogger(__name__)
requests = None



def RequestsModule():
    global requests
    if requests is None:
        requests = importlib.import_module("requests")
    return requests


def NowString():
    return datetime.datetime.now().strftime(DATETIME_FORMAT)


def MaskSensitiveText(text):
    return CommonMaskSensitiveText(text)


def FindStep(alert_data, names):
    if isinstance(names, str):
        names = (names,)
    for step in alert_data.get("action", {}).values():
        if isinstance(step, dict) and step.get("stepName") in names:
            return step
    return {}


def BuildMessageAttributes(root_key, step_data, message_type):
    if step_data.get("messageAttributes"):
        return step_data["messageAttributes"]
    created = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    step_number = step_data.get("stepNumber", "")
    if message_type == "aggregate":
        return "alerter_v2|root={}|step={}|type=aggregate|balance={}|repeat={}|created={}".format(root_key, step_number, step_data.get("targetEventBalance", 0), step_data.get("repeatNumber", 0), created)
    return "alerter_v2|root={}|step={}|type=root|created={}".format(root_key, step_number, created)


def BuildTransactionId(message_attributes):
    return str(uuid.UUID(hashlib.md5(message_attributes.encode("utf-8")).hexdigest()))


def BuildMessageAttributesPayload(body, message_attributes, root_event_id=None, mentions=None, formatted_body=None):
    payload = {"msgtype": "m.text", "body": body, "m.mentions": mentions or {}, ATTR_KEY: message_attributes}
    if formatted_body:
        payload["format"] = "org.matrix.custom.html"; payload["formatted_body"] = formatted_body
    if root_event_id:
        payload["m.relates_to"] = {"rel_type": "m.thread", "event_id": root_event_id}
    return payload


def BuildRootMessage(root_key, alert_data, step_data):
    insight_data = FindStep(alert_data, "loadInsightData")
    jira_step = FindStep(alert_data, ("createLowSeverityJiraIncident", "createCriticalJiraIncident"))
    send_time = step_data.get("sendTime") or NowString()
    return "Сервис: {}\nКороткое имя: {}\nСеверити: {}\nТриггер: {}\nВремя события: {}\nИнцидент Jira: {}\nСсылка на инцидент: {}\n\n{}\n\nВремя отправки: {}".format(insight_data.get("fullName", ""), root_key, alert_data.get("severity", ""), alert_data.get("trigName", ""), alert_data.get("triggerTime", ""), jira_step.get("jiraKey", ""), jira_step.get("jiraUrl", ""), alert_data.get("message", ""), send_time)


def BuildAggregateMessage(root_key, alert_data, step_data):
    target = int(step_data.get("targetEventBalance", 0))
    delivered = int(step_data.get("deliveredEventBalance", 1))
    now = NowString()
    if target == 0:
        return "Все алерты в пачке восстановлены.\n\nАктивных алертов: 0.\nВремя отправки: {}.".format(now)
    if target > delivered:
        return "Также фиксируется ещё {} алертов.\n\nОбщее количество активных алертов: {}.\nВремя отправки: {}.".format(max(0, target - 1), target, now)
    return "Количество активных алертов изменилось.\n\nСейчас фиксируется {} активных алертов.\nВремя отправки: {}.".format(target, now)


def KTalkHeaders():
    bearer_token = str(KTALK_BEARER_TOKEN).strip()
    if not bearer_token.lower().startswith("bearer "):
        bearer_token = "Bearer {}".format(bearer_token)
    return {"authorization": bearer_token, "content-type": "application/json", "host": KTALK_HOST, "origin": KTALK_TALK_HOST, "talk-host": KTALK_TALK_HOST, "accept": "application/json"}


def SafeRequest(method, url, **kwargs):
    attempts = max(1, int(KTALK_SAFE_REQUEST_RETRIES))
    kwargs.setdefault("timeout", KTALK_SAFE_REQUEST_TIMEOUT)
    kwargs.setdefault("verify", KTALK_VERIFY_SSL)
    for attempt in range(attempts):
        try:
            return RequestsModule().request(method, url, **kwargs)
        except (RequestsModule().exceptions.Timeout, RequestsModule().exceptions.ConnectionError):
            if attempt + 1 >= attempts:
                raise
            time.sleep(float(KTALK_RETRY_DELAY_SECONDS))


def LimitedMaskedError(text):
    return MaskSensitiveText(str(text)[:ERROR_TEXT_LIMIT])


def SendMatrixMessageResult(room_id, message_attributes, payload):
    txn_id = BuildTransactionId(message_attributes)
    url = "{}/_matrix/client/r0/rooms/{}/send/m.room.message/{}".format(KTALK_BASE_URL.rstrip("/"), room_id, txn_id)
    attempts = max(1, int(KTALK_SEND_MESSAGE_RETRIES))
    root_event_id = payload.get("m.relates_to", {}).get("event_id", "") if isinstance(payload.get("m.relates_to"), dict) else ""
    for attempt in range(attempts):
        try:
            response = SafeRequest("put", url, headers=KTalkHeaders(), json=payload, timeout=KTALK_SEND_MESSAGE_TIMEOUT)
            status = response.status_code
            ambiguous = 500 <= status <= 599
            LOGGER.info("Matrix message send: room_id=%s root_event_id_present=%s attempt=%s/%s http_status=%s ambiguous=%s", room_id, bool(root_event_id), attempt + 1, attempts, status, ambiguous)
            if 200 <= status <= 299:
                try:
                    data = response.json()
                except ValueError as error:
                    return "", LimitedMaskedError("ambiguous Matrix response JSON error: {}".format(error)), True
                event_id = data.get("event_id", "")
                if event_id:
                    return event_id, "", False
                return "", "Matrix message delivery was not confirmed: response without event_id", True
            if ambiguous:
                return "", LimitedMaskedError("ambiguous HTTP {} from KTalk Matrix API: {}".format(status, response.text[:ERROR_TEXT_LIMIT])), True
            if status in (408, 429):
                error = LimitedMaskedError("temporary HTTP {} from KTalk Matrix API: {}".format(status, response.text[:ERROR_TEXT_LIMIT]))
                if attempt + 1 < attempts:
                    time.sleep(float(KTALK_RETRY_DELAY_SECONDS))
                    continue
                return "", error, False
            return "", LimitedMaskedError("HTTP {} from KTalk Matrix API: {}".format(status, response.text[:ERROR_TEXT_LIMIT])), False
        except (RequestsModule().exceptions.Timeout, RequestsModule().exceptions.ConnectionError) as error:
            LOGGER.info("Matrix message send: room_id=%s root_event_id_present=%s attempt=%s/%s http_status=none ambiguous=True", room_id, bool(root_event_id), attempt + 1, attempts)
            return "", LimitedMaskedError("ambiguous {} during KTalk Matrix API request: {}".format(type(error).__name__, error)), True
        except Exception as error:
            return "", LimitedMaskedError("{} during KTalk Matrix API request: {}".format(type(error).__name__, error)), False
    return "", "Matrix message delivery was not confirmed", True


def SendMatrixMessage(room_id, message_attributes, payload):
    event_id, error, ambiguous = SendMatrixMessageResult(room_id, message_attributes, payload)
    return event_id, error


def EventsFromMessagesData(data):
    chunks = []
    if isinstance(data, dict):
        for key in ("chunk", "events"):
            if isinstance(data.get(key), list):
                chunks.extend(data[key])
        rooms = data.get("rooms", {}).get("join", {}) if isinstance(data.get("rooms"), dict) else {}
        for room in rooms.values():
            timeline = room.get("timeline", {}) if isinstance(room, dict) else {}
            if isinstance(timeline.get("events"), list):
                chunks.extend(timeline["events"])
    return chunks


def MatchEvent(event, message_attributes, body):
    content = event.get("content", {}) if isinstance(event, dict) else {}
    return content.get(ATTR_KEY) == message_attributes or (body and content.get("body") == body)


def FindMessageByAttributes(room_id, message_attributes, body=""):
    base = KTALK_BASE_URL.rstrip("/")
    urls = ["{}/_matrix/client/r0/rooms/{}/messages?dir=b&limit={}".format(base, room_id, KTALK_MESSAGE_SEARCH_LIMIT), "{}/_matrix/client/r0/sync?timeout=0".format(base)]
    for url in urls:
        response = SafeRequest("get", url, headers=KTalkHeaders())
        if response.status_code != 200:
            continue
        for event in EventsFromMessagesData(response.json()):
            if MatchEvent(event, message_attributes, body):
                return event.get("event_id", "")
    return ""


def SendMessageAndGetId(room_id, body, message_attributes, root_event_id=None):
    found = FindMessageByAttributes(room_id, message_attributes, body)
    if found:
        LOGGER.info("Matrix message send skipped: room_id=%s root_event_id_present=%s existing_event_id_found=True", room_id, bool(root_event_id))
        return found, ""

    payload = BuildMessageAttributesPayload(body, message_attributes, root_event_id)
    event_id, error, ambiguous = SendMatrixMessageResult(room_id, message_attributes, payload)
    if event_id:
        return event_id, ""

    if ambiguous:
        attempts = max(1, int(KTALK_MESSAGE_SEARCH_ATTEMPTS))
        for attempt in range(attempts):
            if float(KTALK_MESSAGE_SEARCH_DELAY_SECONDS) > 0:
                time.sleep(min(float(KTALK_MESSAGE_SEARCH_DELAY_SECONDS), 2.0))
            found = FindMessageByAttributes(room_id, message_attributes, body)
            LOGGER.info("Matrix message confirmation search: room_id=%s root_event_id_present=%s attempt=%s/%s existing_event_id_found=%s", room_id, bool(root_event_id), attempt + 1, attempts, bool(found))
            if found:
                return found, ""
    return "", MaskSensitiveText(error or "Matrix message delivery was not confirmed")


def SendThreadReply(root_message_id, body, message_attributes=""):
    if not message_attributes:
        message_attributes = "alerter_v2|service|{}".format(hashlib.sha1(body.encode("utf-8")).hexdigest())
    return SendMessageAndGetId(KTALK_ROOM_ID, body, message_attributes, root_message_id)


def InviteUser(user):
    response = SafeRequest("post", "{}/_matrix/client/v3/rooms/{}/invite".format(KTALK_BASE_URL.rstrip("/"), KTALK_ROOM_ID), headers=KTalkHeaders(), json={"user_id": user.get("mentionId", "")})
    if response.status_code in (200, 403):
        return ""
    return "HTTP {}".format(response.status_code)


def InviteAllUsers(recipients):
    errors = []
    for user in recipients:
        error = InviteUser(user)
        if error:
            errors.append({"operation": "invite", "user": user.get("adLogin", ""), "error": MaskSensitiveText(error)})
    return errors


def MentionUser(root_message_id, user):
    display = user.get("displayName") or user.get("adLogin") or user.get("mentionId")
    mention_id = user.get("mentionId", "")
    encoded_mention_id = quote(mention_id, safe="@:$")
    user_url = "{}/app/messenger/#/user/{}".format(KTALK_TALK_HOST.rstrip("/"), encoded_mention_id)
    escaped_display = html.escape(display, quote=True)
    escaped_user_url = html.escape(user_url, quote=True)
    payload = BuildMessageAttributesPayload(display + " ", "alerter_v2|mention|{}|{}".format(root_message_id, mention_id), root_message_id, {"user_ids": [mention_id]}, '<a href="{}">{}</a>'.format(escaped_user_url, escaped_display))
    event_id, error = SendMatrixMessage(KTALK_ROOM_ID, payload[ATTR_KEY], payload)
    return "" if event_id else error


def MentionAllUsers(root_message_id, recipients):
    errors = []
    for user in recipients:
        error = MentionUser(root_message_id, user)
        if error:
            errors.append({"operation": "mention", "user": user.get("adLogin", ""), "error": MaskSensitiveText(error)})
    return errors


def BuildNotificationErrorsMessage(errors):
    invites = [e.get("user", "") for e in errors if e.get("operation") == "invite"]
    mentions = [e.get("user", "") for e in errors if e.get("operation") == "mention"]
    lines = ["Не удалось выполнить часть операций уведомления."]
    if invites:
        lines += ["", "Не отправлены инвайты:"] + ["- " + u for u in invites]
    if mentions:
        lines += ["", "Не выполнены упоминания:"] + ["- " + u for u in mentions]
    return "\n".join(lines)


def GetRecipients(alert_data):
    return FindStep(alert_data, "resolveKTalkUsers").get("recipientList", [])



def BuildKTalkThreadLink(room_id, thread_root_event_id):
    thread_link = KTALK_THREAD_WEB_URL_TEMPLATE.format(room_id=quote(room_id, safe=""), thread_root_event_id=quote(thread_root_event_id, safe=""))
    if not thread_link.startswith(KTALK_THREAD_LINK_REQUIRED_PREFIX):
        raise ValueError("KTalk thread link does not have required prefix")
    return thread_link


def AttachKTalkThreadLinkToJira(alert_data, thread_root_event_id):
    if not JIRA_THREAD_LINK_TRANSITION_ENABLED:
        return ""
    jira_step = FindStep(alert_data, ("createLowSeverityJiraIncident", "createCriticalJiraIncident"))
    jira_key = jira_step.get("jiraKey", "")
    if not jira_key:
        return "Jira thread-link transition skipped: jiraKey is empty"
    thread_link = BuildKTalkThreadLink(KTALK_ROOM_ID, thread_root_event_id)
    payload = {"transition": {"id": JIRA_THREAD_LINK_TRANSITION_ID}, "fields": {JIRA_THREAD_LINK_CUSTOM_FIELD: thread_link}}
    response = RequestsModule().post(JIRA_THREAD_LINK_TRANSITION_URL.format(jira_key), headers={"Authorization": JIRA_TOKEN, "Accept": "application/json", "Content-Type": "application/json"}, json=payload, timeout=KTALK_SAFE_REQUEST_TIMEOUT, verify=KTALK_VERIFY_SSL)
    if response.status_code == 204:
        return ""
    return "Jira thread-link transition failed: HTTP {} {}".format(response.status_code, response.text[:500])

def SendRoot(root_key, alert_data, step_data):
    new_step = step_data.copy(); new_step.setdefault("notificationErrors", [])
    if new_step.get("messageID"):
        new_step.update({"stepSate": 1, "errorMessage": "", "sended": 1}); return True, new_step
    if importlib.util.find_spec("requests") is None:
        new_step.update({"stepSate": 2, "errorMessage": "requests module is not available", "sended": 0}); return False, new_step
    if not new_step.get("sendTime"):
        new_step["sendTime"] = NowString()
    attrs = BuildMessageAttributes(root_key, new_step, "root"); new_step["messageAttributes"] = attrs
    body = BuildRootMessage(root_key, alert_data, new_step)
    event_id, error = SendMessageAndGetId(KTALK_ROOM_ID, body, attrs)
    if not event_id:
        new_step.update({"stepSate": 2, "errorMessage": error, "sended": 0}); return False, new_step
    transition_error = AttachKTalkThreadLinkToJira(alert_data, event_id)
    if transition_error and JIRA_THREAD_LINK_TRANSITION_STRICT:
        new_step.update({"stepSate": 2, "errorMessage": MaskSensitiveText(transition_error), "sended": 0}); return False, new_step
    if transition_error:
        new_step["threadLinkTransitionError"] = MaskSensitiveText(transition_error)
    new_step.update({"stepSate": 1, "errorMessage": "", "messageID": event_id, "messageDeliveryTime": NowString(), "sended": 1})
    errors = InviteAllUsers(GetRecipients(alert_data)) + MentionAllUsers(event_id, GetRecipients(alert_data))
    if errors:
        new_step["notificationErrors"] = errors
        msg = BuildNotificationErrorsMessage(errors)
        service_id, service_error = SendThreadReply(event_id, msg)
        if service_error:
            new_step["notificationErrors"].append({"operation": "notification_errors_message", "user": "", "error": service_error})
    return True, new_step


def SendLowSeverityRootMessage(root_key, alert_data, step_data):
    return SendRoot(root_key, alert_data, step_data)


def SendCriticalRootMessage(root_key, alert_data, step_data):
    return SendRoot(root_key, alert_data, step_data)


def SendAggregate(root_key, alert_data, step_data):
    new_step = step_data.copy()
    root_step = FindStep(alert_data, ("sendCriticalRootMessage", "sendLowSeverityRootMessage"))
    root_message_id = root_step.get("messageID", "")
    if not root_message_id:
        new_step.update({"errorMessage": "root message is not completed"}); return False, new_step
    repeat_limit = int(new_step.get("repeatLimit", KTALK_AGGREGATE_MESSAGE_REPEAT_COUNT))
    repeat_number = int(new_step.get("repeatNumber", 0))
    if repeat_number >= repeat_limit:
        new_step.update({"stepSate": 1, "deliveredEventBalance": int(new_step.get("targetEventBalance", 0)), "nextDeliveryTime": "", "messageAttributes": ""}); return True, new_step
    next_time = new_step.get("nextDeliveryTime", "")
    if next_time and datetime.datetime.now() < datetime.datetime.strptime(next_time, DATETIME_FORMAT):
        new_step["stepSate"] = 0; return True, new_step
    attrs = BuildMessageAttributes(root_key, new_step, "aggregate"); new_step["messageAttributes"] = attrs
    body = BuildAggregateMessage(root_key, alert_data, new_step)
    event_id, error = SendMessageAndGetId(KTALK_ROOM_ID, body, attrs, root_message_id)
    repeat_number += 1; new_step["repeatNumber"] = repeat_number
    if event_id:
        new_step["successfulDeliveryNumber"] = int(new_step.get("successfulDeliveryNumber", 0)) + 1
        new_step["lastMessageID"] = event_id; new_step["lastMessageDeliveryTime"] = NowString(); new_step["errorMessage"] = ""; new_step["sended"] = 1
    else:
        new_step["retryNumber"] = int(new_step.get("retryNumber", 0)) + 1; new_step["errorMessage"] = error; new_step["sended"] = 0
    if repeat_number >= repeat_limit:
        new_step.update({"stepSate": 1, "deliveredEventBalance": int(new_step.get("targetEventBalance", 0)), "nextDeliveryTime": "", "messageAttributes": ""})
    else:
        new_step["stepSate"] = 0
        new_step["nextDeliveryTime"] = (datetime.datetime.now() + datetime.timedelta(seconds=int(KTALK_AGGREGATE_MESSAGE_REPEAT_INTERVAL_SECONDS))).strftime(DATETIME_FORMAT)
    return True, new_step


def SendLowSeverityAggregateMessage(root_key, alert_data, step_data):
    return SendAggregate(root_key, alert_data, step_data)


def SendCriticalAggregateMessage(root_key, alert_data, step_data):
    return SendAggregate(root_key, alert_data, step_data)
