#!/usr/bin/python
import json
import logging
import pdb
import requests
import sys
import dbConnect as db


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


def testQuery():
    r = requests.get('http://cve.circl.lu/api/query?time_start=2019-02-28').json()
    print(r)


if __name__ == '__main__':
    conn = db.connect()

    cve_exists = db.checkCVEExists(conn)
    if(cve_exists is False):
        from_start = True
        db.createTable(conn)
    else:
        from_start = False

        print("Table exists")


    testQuery()
    # r = getAllCVEQuery()
    # r = checkQuery(r)
