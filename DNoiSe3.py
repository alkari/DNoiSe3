#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
DNoiSe2.py: A script to monitor DNS queries from a Pi-hole server,
calculate query rates, and randomly resolve domains from a top 1M list.
"""

import os
import sys
import time
import json
import random
import sqlite3
import datetime
import requests
import dns.resolver
import logging
import pandas
from urllib.request import urlretrieve
from typing import Optional, Tuple, List
from dotenv import load_dotenv

# Configuration Constants
WORKING_DIRECTORY = "/opt/DNoiSe/"
CLIENT_IP = "127.0.0.1"
DNS_SERVER_IP = "127.0.0.1"
LOG_FILE_PATH = "/var/log/DNoiSe.log"
DEBUG_LOG_ENABLED = True  # Set to False for production

# Constants from .env
load_dotenv()
APP_PASSWORD = os.getenv("APP_PASSWORD")
if not APP_PASSWORD:
    print("APP_PASSWORD not found in the .env file.")
    sys.exit(1)

# Internet Check Constants
INTERNET_CHECK_URL = "http://example.com"
RETRY_DELAY_SECONDS = 10
MAX_RETRIES = 6

# Time Constants
FIVE_MINUTES_SECONDS = 300
ONE_MINUTE_SECONDS = 60
SLEEP_MULTIPLIER = 10
RANDOM_DELAY_MAX_SECONDS = 2

# Database Constants
DOMAIN_LIST_ZIP_URL = "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
DOMAIN_LIST_ZIP_FILENAME = "domains.zip"
DOMAIN_LIST_SQLITE_FILENAME = "domains.sqlite"
DOMAINS_TABLE_NAME = "Domains"

# Initialize logging
logging.basicConfig(filename=LOG_FILE_PATH, level=logging.DEBUG if DEBUG_LOG_ENABLED else logging.INFO,
                    format='%(asctime)s %(levelname)s: %(message)s')

# Initialize DNS resolver
resolver = dns.resolver.Resolver()
resolver.nameservers = [DNS_SERVER_IP]


def get_timestamp() -> str:
    """Returns the current timestamp in the format YYYY-MM-DD HH:MM:SS."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def log_message(level: int, message: str) -> None:
    """Logs a message with the specified level if debugging is enabled or if it's an error/critical message."""
    if DEBUG_LOG_ENABLED or level in (logging.ERROR, logging.CRITICAL):
        logging.log(level, message)


def download_domains() -> None:
    """Downloads the top 1M domain list and imports it into a SQLite database."""
    start_time = time.time()
    zip_file_path = os.path.join(WORKING_DIRECTORY, DOMAIN_LIST_ZIP_FILENAME)
    db_file_path = os.path.join(WORKING_DIRECTORY, DOMAIN_LIST_SQLITE_FILENAME)

    log_message(logging.INFO, "Downloading the domain list…")
    try:
        urlretrieve(DOMAIN_LIST_ZIP_URL, filename=zip_file_path)
    except Exception as e:
        log_message(logging.ERROR, f"Can't download the domain list: {e}. Quitting.")
        sys.exit(64)

    log_message(logging.INFO, "Importing domain list to sqlite…")
    try:
        with sqlite3.connect(db_file_path) as db:
            cursor = db.cursor()
            cursor.execute(f"CREATE TABLE IF NOT EXISTS {DOMAINS_TABLE_NAME} (ID INTEGER PRIMARY KEY, Domain TEXT)")

            df = pandas.read_csv(zip_file_path, compression='zip', names=["ID", "Domain"])
            df.to_sql(DOMAINS_TABLE_NAME, db, if_exists="append", index=False)

            db.commit()
        os.remove(zip_file_path)
        log_message(logging.INFO, f"Domain list imported. Took {round(time.time() - start_time, 1)} seconds.")
    except sqlite3.Error as e:
        log_message(logging.ERROR, f"SQLite error during import: {e}. Quitting.")
        if os.path.exists(db_file_path):
            os.remove(db_file_path)
        sys.exit(65)
    except pandas.errors.EmptyDataError as e:
        log_message(logging.ERROR, f"Pandas error during import: {e}. Quitting.")
        if os.path.exists(db_file_path):
            os.remove(db_file_path)
        sys.exit(65)
    except Exception as e:
        log_message(logging.ERROR, f"Import failed: {e}. Quitting.")
        if os.path.exists(db_file_path):
            os.remove(db_file_path)
        sys.exit(65)


def check_internet_connection(url: str = INTERNET_CHECK_URL, timeout: int = 10) -> bool:
    """Checks for Internet connectivity by making a GET request to a test URL."""
    try:
        requests.get(url, timeout=timeout)
        return True
    except requests.exceptions.RequestException:
        return False


def ensure_internet_connection() -> None:
    """Ensures internet connection is established before proceeding with the script."""
    retry_delay = RETRY_DELAY_SECONDS
    for attempt in range(MAX_RETRIES):
        if check_internet_connection():
            log_message(logging.INFO, "SUCCESS! Internet connection established.")
            return
        else:
            log_message(logging.DEBUG, f"Internet not connected yet, retrying in {retry_delay} seconds.")
            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 60)  # Exponential backoff, max 60 seconds
    log_message(logging.ERROR, "Failed to establish Internet connection after multiple attempts. Exiting")
    sys.exit(66)


def authenticate_pihole(pihole_ip: str, auth_token: str) -> Tuple[Optional[str], Optional[str]]:
    """Authenticates with the Pi-hole API and returns the session ID and CSRF token."""
    auth_url = f"http://{pihole_ip}/api/auth"
    headers = {'Content-Type': 'application/json'}
    payload = {"password": auth_token}
    try:
        auth_response = requests.post(auth_url, json=payload, headers=headers, verify=False).json()
        sid = auth_response.get('session', {}).get('sid')
        csrf = auth_response.get('session', {}).get('csrf')
        if sid and csrf:
            log_message(logging.INFO, "Successfully authenticated with Pi-hole API.")
            return sid, csrf
        else:
            log_message(logging.ERROR, f"Authentication failed. Response: {auth_response}")
            return None, None
    except requests.exceptions.RequestException as e:
        log_message(logging.ERROR, f"Authentication request failed: {e}")
        return None, None
    except (json.JSONDecodeError, KeyError) as e:
        log_message(logging.ERROR, f"Error processing authentication response: {e}")
        return None, None


def fetch_queries(pihole_ip: str, time_from: int, time_until: int, sid: str, csrf: str) -> dict:
    """Fetches DNS queries from the Pi-hole API using the provided session."""
    if not sid or not csrf:
        log_message(logging.ERROR, "Session ID or CSRF token is missing. Cannot fetch queries.")
        return {}

    queries_url = f"http://{pihole_ip}/api/queries/"
    queries_headers = {
        "X-FTL-SID": sid,
        "X-FTL-CSRF": csrf,
        "X-From": str(time_from),
        "X-Until": str(time_until)
    }
    try:
        response = requests.get(queries_url, headers=queries_headers, verify=False)
        response.raise_for_status()  # Raise an exception for bad status codes
        return response.json()
    except requests.exceptions.RequestException as e:
        log_message(logging.DEBUG, f"API request failed: {e}")
        return {}
    except json.JSONDecodeError as e:
        log_message(logging.ERROR, f"Error decoding API response: {e}")
        return {}


def filter_queries(parsed_queries_data: dict, local_client_ip: str) -> Tuple[List, List]:
    """Filters out DNS queries originating from the local client."""
    genuine_queries = []
    query_types = []
    local_client_address = local_client_ip.replace("127.0.0.1", "localhost")

    try:
        for query in parsed_queries_data.get("queries", []):
            client_ip = query.get("client", {}).get("ip")
            query_type = query.get("type")
            if client_ip and query_type and client_ip != local_client_address:
                genuine_queries.append(query)
                query_types.append(query_type)
    except (KeyError, TypeError) as e:
        log_message(logging.ERROR, f"Error parsing Pi-hole API query data: {e}. Data: {parsed_queries_data}")
        return [], []  # Return empty lists in case of error

    if not genuine_queries:
        genuine_queries.append("Placeholder")  # To avoid division by zero later
    if not query_types:
        query_types.append("A")  # Default query type

    return genuine_queries, query_types


def resolve_domain(domain: str, query_type: str) -> None:
    """Attempts to resolve a given domain with the specified query type using the configured DNS resolver."""
    try:
        answers = resolver.resolve(domain, query_type)
        for answer in answers:
            log_message(logging.INFO, f"Domain {domain}. resolved to ({answer})")
    except dns.resolver.NXDOMAIN:
        log_message(logging.DEBUG, f"Failed to resolve {domain}. Error: No such domain (NXDOMAIN)")
    except dns.resolver.Timeout:
        log_message(logging.DEBUG, f"Failed to resolve {domain}. Error: Query timed out")
    except dns.exception.DNSException as e:
        log_message(logging.ERROR, f"Failed to resolve {domain}. Error: Unhandled DNS exception: {e}")
    except Exception as e:
        log_message(logging.CRITICAL, f"Unexpected error while resolving {domain}. Error: {e}")

def process_dns_queries(client_ip: str, app_password: str, db_connection: sqlite3.Connection) -> Tuple[Optional[int], int]:
    """
    Fetches DNS queries from the Pi-hole API, filters local client queries,
    logs query statistics, and resolves a random domain.

    Args:
        client_ip: The IP address of the Pi-hole server.
        app_password: The application password for the Pi-hole API.
        db_connection: The SQLite database connection object.

    Returns:
        A tuple containing the end timestamp of the query window (or None) and the count of genuine queries.
    """
    time_until = int(time.time())
    time_from = time_until - FIVE_MINUTES_SECONDS

    sid, csrf = authenticate_pihole(client_ip, app_password)
    if not sid or not csrf:
        log_message(logging.ERROR, "Authentication failed, skipping this iteration.")
        return None, 0

    parsed_queries = fetch_queries(client_ip, time_from, time_until, sid, csrf)
    genuine_queries, query_types = filter_queries(parsed_queries, client_ip)

    total_queries = parsed_queries.get("recordsTotal", 0)
    local_query_count = sum(1 for q in parsed_queries.get("queries", [])
                             if q.get("client", {}).get("ip") == client_ip.replace("127.0.0.1", "localhost"))

    genuine_query_count = len(genuine_queries) - (1 if "Placeholder" in genuine_queries else 0)

    if genuine_query_count > 0:
        average_interval = FIVE_MINUTES_SECONDS / genuine_query_count
    else:
        average_interval = FIVE_MINUTES_SECONDS

    log_message(logging.INFO,
                f"Between {datetime.datetime.fromtimestamp(time_from).strftime('%Y-%m-%d %H:%M:%S')} and "
                f"{datetime.datetime.fromtimestamp(time_until).strftime('%Y-%m-%d %H:%M:%S')}, there was on average 1 request every "
                f"{round(average_interval, 2)}s. Total queries: {total_queries}, of those {local_query_count} are local queries (excluded).")

    # Pick a random domain from the top 1M list and resolve it
    random_id = random.randint(1, 1000000)
    try:
        cursor = db_connection.cursor() # Create cursor here
        cursor.execute(f"SELECT Domain FROM {DOMAINS_TABLE_NAME} WHERE ID=?", (random_id,))
        result = cursor.fetchone()
        if result:
            domain_to_resolve = result[0]
            resolve_domain(domain_to_resolve, random.choice(query_types))
        else:
            log_message(logging.WARNING, f"Could not retrieve domain with ID {random_id} from the database.")
    except sqlite3.Error as e:
        log_message(logging.ERROR, f"Database error in process_dns_queries: {e}")
    except Exception as e:
        log_message(logging.ERROR, f"Unexpected error in process_dns_queries: {e}") # Catch any other exceptions
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()

    return time_until, genuine_query_count


if __name__ == "__main__":
    ensure_internet_connection()

    db_file_exists = os.path.isfile(os.path.join(WORKING_DIRECTORY, DOMAIN_LIST_SQLITE_FILENAME))
    if not db_file_exists:
        download_domains()

    db_connection = sqlite3.connect(os.path.join(WORKING_DIRECTORY, DOMAIN_LIST_SQLITE_FILENAME))
    cursor = db_connection.cursor() # Create cursor here

    try:
        time_until_last_sample = int(time.time()) - ONE_MINUTE_SECONDS  # Initialize to ensure first run
        while True:
            try:
                current_time_until, genuine_query_count = process_dns_queries(CLIENT_IP, APP_PASSWORD, db_connection)

                if current_time_until is None:
                    log_message(logging.WARNING, "Authentication failed. Waiting a bit before trying again.")
                    time.sleep(60)  # Wait for 60 seconds before next attempt
                    continue  # Skip the rest of the loop

                # Re-sample query rate every minute
                if time.time() - time_until_last_sample > ONE_MINUTE_SECONDS:
                    time_until_last_sample = current_time_until

                # Wait time based on observed query rate
                if genuine_query_count > 0:
                    sleep_time = (FIVE_MINUTES_SECONDS / genuine_query_count * SLEEP_MULTIPLIER) + random.uniform(0, RANDOM_DELAY_MAX_SECONDS)
                else:
                    sleep_time = 30 + random.uniform(0, RANDOM_DELAY_MAX_SECONDS)

                time.sleep(sleep_time)
            except Exception as e:
                log_message(logging.ERROR, f"An unexpected error occurred in the main loop: {e}")
                time.sleep(10)  # Wait a bit before trying again
    finally:
        db_connection.close() # Close the connection at the end
