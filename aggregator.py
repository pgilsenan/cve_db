#!/usr/bin/python
import json
import logging
import pdb
import requests
import sys
import dbConnect as db
import db.queries as q


FORMAT = '%(asctime)-15s  %(message)s'
logging.basicConfig(filename='cve.log',format=FORMAT)
logger = logging.getLogger('vce_log')


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
        "cvss_modifier": "above",
        "cvss_score": "6.8"
    }

    headers = {
        "time_modifier": "between",
        "time_start": min_date,
        "time_end": max_date,
        "time_type": "Published",
        "limit": "5"
    }

    r = requests.get('https://cve.circl.lu/api/query', headers=headers, verify=False)
    try:
        j = r.json()
        print (j)
    except Exception as e:
        logger.warning('Request returned no data')
        print (e)
        sys.exit(1)


if __name__ == '__main__':
    conn = db.connect()

    cve_exists = db.checkCVEExists(conn)
    if(cve_exists is False):
        db.createTable(conn)

    dates = q.getLastCVE(conn)
    getNewCVEs(dates['min_date'], dates['max_date'])
