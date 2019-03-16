#!/usr/bin/python

def create_cve():
    command = (
        """
        CREATE TABLE cve (
            id SERIAL PRIMARY KEY,
            modified TIMESTAMPTZ,
            last_modified TIMESTAMPTZ,
            published TIMESTAMPTZ NOT NULL,
            cvss TEXT,
            cve_id TEXT,
            cwe TEXT,
            refs TEXT,
            summary TEXT,
            acknowledged BOOLEAN,
            escalated BOOLEAN
            -- vulnerable_configuration TEXT
        )
        """)

    return command
