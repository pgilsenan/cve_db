#!/usr/bin/python

def create_cve():
    command = (
        """
        CREATE TABLE cve (
            id SERIAL PRIMARY KEY,
            modified TIMESTAMPTZ,
            published TIMESTAMPTZ NOT NULL,
            cvss TEXT,
            c_id TEXT,
            refs TEXT,
            summary TEXT,
            vulnerable_configuration TEXT
        )
        """)

    return command
