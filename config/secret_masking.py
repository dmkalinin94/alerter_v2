#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

SECRET_NAMES = (
    "JIRA_TOKEN", "INSIGHT_AUTH_TOKEN", "KTALK_BEARER_TOKEN",
    "RECIPIENT_RESOLVER_TOKEN", "DB_PASSWORD",
)


def MaskSensitiveText(text, settings_module=None):
    safe = str(text)
    if settings_module is None:
        try:
            from config import local_settings_and_secrets as settings_module
        except ImportError:
            settings_module = None
    if settings_module is not None:
        for name in SECRET_NAMES:
            secret = getattr(settings_module, name, "")
            if secret:
                safe = safe.replace(str(secret), "***")
    safe = re.sub(r"Authorization\s*[:=]\s*[^\n,;]+", "Authorization: ***", safe, flags=re.IGNORECASE)
    safe = re.sub(r"\b(Bearer|Basic)\s+[^\s,;]+", r"\1 ***", safe)
    safe = re.sub(r"(token|password)\s*=\s*[^\s,;&]+", r"\1=***", safe, flags=re.IGNORECASE)
    return safe[:2000]
