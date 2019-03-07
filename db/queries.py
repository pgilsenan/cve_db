#!/usr/bin/python
import psycopg2
import psycopg2.extras
from db.config import config, startDate
import pdb
import sys
from datetime import datetime, date
import pandas as pd


params = config()
start_date = startDate()


# Gets most recent entry in database
def getLastCVE(conn):
    cur = conn.cursor()
    cur.execute("SELECT MAX(published) FROM cve")
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


def addToTable(conn, data, latest_date):
    df = pd.DataFrame(data=data)
    new_entries = df[df['Published'] > latest_date]
    update_entries = df[df['Published'] <= latest_date]

    insertIntoTable(conn, new_entries)


def insertIntoTable(conn, data):
    cur = conn.cursor()

    insert_fields = data[['id', 'Published', 'Modified', 'references', 'summary', 'cvss', 'cwe']]
    insert_data = insert_fields.values.tolist()

    insert_query = 'INSERT INTO cve (cve_id, published, modified, refs, summary, cvss, cwe) values %s'
    psycopg2.extras.execute_values (
        cur, insert_query, insert_data
    )
    conn.commit()

    # for index, row in data.iterrows():
        # print(row['id'], row['Published'])
