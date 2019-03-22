#!/usr/bin/python
import psycopg2
from db.config import config
import pdb
import sys
from db.cve_structure import create_cve

params = config()

def connect():
    conn = None

    try:
        # Create a new database session and return a new connection object.
        conn = psycopg2.connect(**params)
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        sys.exit(1)

    return conn


def checkCVEExists(conn):
    cur = conn.cursor()
    cur.execute("SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_catalog=%s AND table_schema='public' AND table_name=%s)", (params['database'], 'cve' ))
    exists = cur.fetchone()
    if exists[0] is True:
        return True
    else:
        return False


def createTable(conn):
    cur = conn.cursor()
    try:
        print("WARNING: cve table does not exist")
        print("Creating cve table")
        # Get command to create cve table and create table
        command = create_cve()
        cur.execute(command)
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        if conn is not None:
            conn.close()
        sys.exit(1)

    conn.commit()
    return cur
