#!/usr/bin/python
import json
import logging
import pdb
import requests
import sys
import dbConnect as db
import db.queries as q
from datetime import datetime, date, timedelta
import urllib3
urllib3.disable_warnings()

today = date.today()
today = today.strftime("%d-%m-%Y")
TEST_CUT_OFF_DATE = datetime.strptime(today, '%d-%m-%Y')
COUNT = 0
MAX_COUNT = 500
FIELD = ""

FORMAT = '%(asctime)-15s  %(message)s'
logging.basicConfig(filename='cve.log',format=FORMAT)
logger = logging.getLogger('vce_log')

conn = db.connect()


def getNewCVEs(min_date, max_date):
    headers = {
        "time_modifier": "between",
        "time_start": min_date,
        "time_end": max_date,
        "time_type": FIELD,
        "cvss_modifier": "above",
        "cvss_score": "4",
        "limit": "100",
        "data": "json"
    }
    r = requests.get('https://cve.circl.lu/api/query', headers=headers, verify=False)

    try:
        j = r.json()
        if j is not []:
            checkResult(j, min_date, max_date)
    except Exception as e:
        logger.warning('Request returned no data')
        print (e)
        sys.exit(1)


def checkResult(j, min_date, max_date):
    global COUNT
    if len(j) == 100:
        # Too many results returned for period
        # Cut number of days between dates in two
        min_date_dt = datetime.strptime(min_date, '%d-%m-%Y')
        max_date_dt = datetime.strptime(max_date, '%d-%m-%Y')

        day_diff = (max_date_dt - min_date_dt)/2
        new_max_date = min_date_dt + day_diff
        max_date = new_max_date.strftime("%d-%m-%Y")

        getNewCVEs(min_date, max_date)
    else:
        if len(j) > 0:
            q.addToTable(conn, j)
            COUNT = COUNT + len(j)
            print ("Pulled %d CVEs from %s to %s" % (len(j), min_date, max_date))
        getNextBatch(min_date, max_date)


def getNextBatch(min_date, max_date):
    min_date_dt = datetime.strptime(max_date, '%d-%m-%Y') + timedelta(days=1)
    max_date_dt = datetime.strptime(max_date, '%d-%m-%Y') + timedelta(days=30)
    min_date = min_date_dt.strftime("%d-%m-%Y")
    max_date = max_date_dt.strftime("%d-%m-%Y")

    if COUNT >= MAX_COUNT or min_date_dt > TEST_CUT_OFF_DATE:
        print ("\nPulled %d CVEs" % COUNT)
        print ("Last date: %s "% max_date)
        sys.exit(1)
    else:
        getNewCVEs(min_date, max_date)


if __name__ == '__main__':
    cve_exists = db.checkCVEExists(conn)
    if(cve_exists is False):
        db.createTable(conn)

    dates = q.getLastCVE(conn)
    FIELD = "Published" if cve_exists is False else "Modified"
    getNewCVEs(dates['min_date'], dates['max_date'])
