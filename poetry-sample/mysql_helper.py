"""The mysql_helper: A util to perform operation with MySQL and secrets manager."""

import logging
import os
from typing import Optional

import pymysql

SSL_CA_CERTIFICATE_FILENAME = "rds-combined-ca-bundle.pem"


def get_connection(
    host: str, password: str, username: str, db_name: str, port: int, use_ssl=False
) -> Optional[pymysql.connections.Connection]:
    """Get a connection to MySQL DB

    Tries to connect to the DB.
    :return: The connection or None
    """
    current_directory = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))

    try:
        logging.info("Opening a connection to %s", host)

        ssl = {"ca": os.path.join(current_directory, SSL_CA_CERTIFICATE_FILENAME)} if use_ssl else None

        return pymysql.connect(host, user=username, passwd=password, port=port, db=db_name, connect_timeout=5, ssl=ssl)
    except pymysql.OperationalError:
        logging.warning("Unable to connect to %s", host)
        return None


def get_password_option(version: str) -> str:
    """Get the password option template string to use for the SET PASSWORD sql query

    Based on the MySQL version, returns the password option template string used in the SET PASSWORD query.
    :param version: The mysql database version
    :return:The password option string
    """
    if version.startswith("8"):
        return "%s"
    return "PASSWORD(%s)"
