#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import psycopg2

from config.local_settings_and_secrets import DB_HOST, DB_NAME, DB_PASSWORD, DB_PORT, DB_USER, DB_CONNECT_TIMEOUT_SECONDS, DB_STATEMENT_TIMEOUT_MS


############################### FUNCTIONS ###############################


def MakeSuccessResult(insight_id):
    return {
        "success": True,
        "insightId": insight_id,
        "errorMessage": ""
    }


def MakeErrorResult(error_message):
    return {
        "success": False,
        "insightId": "",
        "errorMessage": error_message
    }


def GetInsightIdByShortName(short_name):
    connection = None
    cursor = None

    if short_name is None or str(short_name).strip() == "":
        return MakeErrorResult("short_name is empty")

    try:
        connection = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            connect_timeout=DB_CONNECT_TIMEOUT_SECONDS,
            options="-c statement_timeout={}".format(DB_STATEMENT_TIMEOUT_MS)
        )
        cursor = connection.cursor()
        cursor.execute(
            "SELECT insight_id FROM availconf.insight_id WHERE short_name = %s;",
            (short_name,)
        )
        rows = cursor.fetchall()

        if len(rows) == 0:
            return MakeErrorResult("Insight ID was not found for short_name {}".format(short_name))

        if len(rows) > 1:
            return MakeErrorResult("More than one Insight ID was found for short_name {}".format(short_name))

        insight_id = rows[0][0]
        if insight_id is None:
            return MakeErrorResult("Insight ID is NULL for short_name {}".format(short_name))

        insight_id = str(insight_id)
        if insight_id == "":
            return MakeErrorResult("Insight ID is empty for short_name {}".format(short_name))

        return MakeSuccessResult(insight_id)
    except Exception as error:
        return MakeErrorResult("PostgreSQL error for short_name {}: {}".format(short_name, error))
    finally:
        if cursor is not None:
            try:
                cursor.close()
            except Exception:
                pass
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
