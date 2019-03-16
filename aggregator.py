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

TEST_CUT_OFF_DATE = datetime.strptime('01-06-2010', '%d-%m-%Y')

FORMAT = '%(asctime)-15s  %(message)s'
logging.basicConfig(filename='cve.log',format=FORMAT)
logger = logging.getLogger('vce_log')

conn = db.connect()


def getAllCVEQuery():
    try:
        r = requests.get('http://cve.circl.lu/api/search/microsoft/office')
        logger.warning('Request ok')
        return r
    except requests.exceptions.RequestException as e:
        logger.warning('Issue with request')
        sys.exit(1)


def checkQuery(r):
    if r:
        r_json = r.json()

        if r_json == []:
            logger.warning('Request returned no data')
            sys.exit(1)

        logger.warning('Request returned result')
        return r_json


def getNewCVEs(min_date, max_date):
    headers = {
        "time_modifier": "between",
        "time_start": min_date,
        "time_end": max_date,
        "time_type": "Published",
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
    min_date_dt = datetime.strptime(min_date, '%d-%m-%Y')
    max_date_dt = datetime.strptime(max_date, '%d-%m-%Y')
    day_diff = (max_date_dt - min_date_dt)/2
    new_max_date = min_date_dt + day_diff

    max_date = new_max_date.strftime("%d-%m-%Y")
    print ("New max date %s" % (max_date))

    if len(j) == 100:
        getNewCVEs(min_date, max_date)
    else:
        if new_max_date < TEST_CUT_OFF_DATE:
            # Date under cut off - add to table
            q.addToTable(conn, j, min_date)
            getNextBatch(min_date, max_date)


def getNextBatch(min_date, max_date):
    print ("OLD getNext - start: %s, end: %s" % (min_date, max_date))
    min_date_dt = datetime.strptime(max_date, '%d-%m-%Y') + timedelta(days=1)
    max_date_dt = datetime.strptime(max_date, '%d-%m-%Y') + timedelta(days=30)

    min_date = min_date_dt.strftime("%d-%m-%Y")
    max_date = max_date_dt.strftime("%d-%m-%Y")
    print ("NEW getNext - start: %s, end: %s" %(min_date, max_date))

    getNewCVEs(min_date, max_date)


if __name__ == '__main__':
    cve_exists = db.checkCVEExists(conn)
    if(cve_exists is False):
        db.createTable(conn)

    dates = q.getLastCVE(conn)
    # getNewCVEs(dates['min_date'], dates['max_date'])
    getNewCVEs('01-01-2010', '01-06-2010')
