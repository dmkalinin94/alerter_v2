#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import psycopg2

from env import DB_HOST, DB_NAME, DB_PASSWORD, DB_PORT, DB_USER


def GetInsightIdByShortName(short_name):
    connection = None
    cursor = None

    if short_name is None or str(short_name).strip() == "":
        return {
            "success": False,
            "insightId": "",
            "errorMessage": "short_name is empty"
        }

    try:
        connection = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        cursor = connection.cursor()
        cursor.execute(
            "SELECT insight_id\nFROM availconf.insight_id\nWHERE short_name = %s;",
            (short_name,)
        )
        rows = cursor.fetchall()

        if len(rows) == 0:
            return {
                "success": False,
                "insightId": "",
                "errorMessage": "Insight ID was not found for short_name {}".format(short_name)
            }

        if len(rows) > 1:
            return {
                "success": False,
                "insightId": "",
                "errorMessage": "More than one Insight ID was found for short_name {}".format(short_name)
            }

        insight_id = rows[0][0]
        if insight_id is None:
            return {
                "success": False,
                "insightId": "",
                "errorMessage": "Insight ID is NULL for short_name {}".format(short_name)
            }

        insight_id = str(insight_id)
        if insight_id == "":
            return {
                "success": False,
                "insightId": "",
                "errorMessage": "Insight ID is empty for short_name {}".format(short_name)
            }

        return {
            "success": True,
            "insightId": insight_id,
            "errorMessage": ""
        }
    except Exception as error:
        return {
            "success": False,
            "insightId": "",
            "errorMessage": "PostgreSQL error for short_name {}: {}".format(short_name, error)
        }
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
