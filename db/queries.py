#!/usr/bin/python
import psycopg2
from db.config import config, startDate
import pdb
import sys
from datetime import date

params = config()
start_date = startDate()

# Gets most recent entry in database
def getLastCVE(conn):
    cur = conn.cursor()
    cur.execute("SELECT MAX(modified) FROM cve")
    latest = cur.fetchone()

    today = date.today()
    today = today.strftime("%d-%m-%Y")

    if latest[0] is None:
        dates = {
            "min_date": start_date,
            "max_date": today
        }
        return dates
    else:
        last_date = latest[0].strftime("%d-%m-%Y")

        dates = {
            "min_date": last_date,
            "max_date": today
        }
        return dates
