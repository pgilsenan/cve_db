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


def addToTable(conn, data):
    df = pd.DataFrame(data=data)
    ids = checkIDs(conn, df)

    update_entries = df[df['id'].isin(ids)]
    new_entries = df[~df['id'].isin(ids)]

    if(len(new_entries) > 0):
        insertIntoTable(conn, new_entries)

    if(len(update_entries) > 0):
        updateTable(conn, update_entries)


def checkIDs(conn, data):
    ids = data['id'].to_list()
    id_list = ", ".join("'{0}'".format(i) for i in ids)
    cur = conn.cursor()
    cur.execute("SELECT cve_id FROM cve WHERE cve_id IN ("+id_list+")")
    tmp = cur.fetchall()

    already_exists = []
    for id_pair in tmp:
        already_exists.append(id_pair[0])

    return already_exists


def insertIntoTable(conn, data):
    cur = conn.cursor()

    insert_fields = data[['id', 'Published', 'Modified', 'references', 'summary', 'cvss', 'cwe']]
    insert_data = insert_fields.values.tolist()

    insert_query = 'INSERT INTO cve (cve_id, published, modified, refs, summary, cvss, cwe) VALUES %s'
    psycopg2.extras.execute_values (
        cur, insert_query, insert_data
    )
    conn.commit()


def updateTable(conn, data):
    cur = conn.cursor()

    if 'id' in data.index:
        update_fields = data[['id', 'Modified', 'references', 'summary', 'cvss', 'cwe']]
        update_fields['Modified'] = pd.to_datetime(update_fields['Modified'])
        # update_fields['cwe'] = update_fields['cwe'].fillna('')
        update_fields.rename(index=str, columns={"references": "refs"}, inplace=True)
        update_data = update_fields.values.tolist()

        try:
            update_query = 'UPDATE cve SET modified=data.Modified, refs=data.refs, summary=data.summary, cvss=data.cvss, cwe=data.cwe, last_modified=NOW() FROM (VALUES %s) AS data (id, Modified, refs, summary, cvss, cwe) WHERE cve.cve_id = data.id '
            psycopg2.extras.execute_values (
                cur, update_query, update_data
            )
            conn.commit()
        except:
            print ("ERROR: couldn't update CVEs")
