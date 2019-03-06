#!/usr/bin/python
from configparser import ConfigParser


def config(filename='db/database.ini', section='postgresql'):
    # create a parser
    parser = ConfigParser()
    # read config file
    parser.read(filename)

    # get section, default to postgresql
    db = {}
    if parser.has_section(section):
        params = parser.items(section)
        for param in params:
            db[param[0]] = param[1]
    else:
        raise Exception('Section {0} not found in the {1} file'.format(section, filename))

    return db


def startDate(filename='db/database.ini', section='cve'):
    # create a parser
    parser = ConfigParser()
    # read config file
    parser.read(filename)

    if parser.has_section(section):
        params = parser.items(section)
        for param in params:
            if param[0] == "mindate":
                return param[1]

    # User didn't specify oldest date to pull data from
    default_min_date = '01-01-2014'
    return default_min_date
