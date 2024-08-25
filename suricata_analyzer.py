import os
from groq import Groq
import json
from datetime import datetime
import time
import ipaddress
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import psycopg2
from psycopg2 import sql
import logging
import sys

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
sys.stdout.reconfigure(line_buffering=True)

# Configuration from environment variables
GROQ_API_KEY = os.getenv('GROQ_API_KEY')
EVE_JSON_LOG_PATH = os.getenv('EVE_JSON_LOG_PATH')
OUTPUT_DIR = os.getenv('OUTPUT_DIR')

# Database connection details
DB_HOST = os.getenv('DB_HOST')
DB_PORT = os.getenv('DB_PORT')
DB_NAME = os.getenv('DB_NAME')
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')

client = Groq(api_key=GROQ_API_KEY)

# Custom private IP ranges and common DNS servers
CUSTOM_PRIVATE_RANGES = [
    ipaddress.ip_network('20.20.20.0/24'),
    ipaddress.ip_network('192.168.0.0/16'),
]

COMMON_DNS_SERVERS = [
    '1.1.1.1', '1.1.1.3', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '149.112.112.112',
    '208.67.222.222', '208.67.220.220', '64.6.64.6', '64.6.65.6', '185.228.168.9',
    '185.228.169.9', '76.76.19.19', '76.76.2.0',
]

# Function to read IP blacklist from file
def read_ip_blacklist(filename):
    logging.debug(f"Attempting to read blacklist from {filename}")
    blacklist = set()
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            for line in f:
                ip = line.strip()
                if ip:
                    blacklist.add(ip)
    else:
        logging.warning(f"Blacklist file {filename} not found")
    logging.debug(f"Loaded {len(blacklist)} IPs to blacklist: {', '.join(blacklist)}")
    return blacklist

# Load the blacklist
IP_BLACKLIST_FILE = '/app/ip_blacklist.txt'
ALL_IPS_TO_IGNORE = read_ip_blacklist(IP_BLACKLIST_FILE)

def is_public_ip(ip_string):
    try:
        ip = ipaddress.ip_address(ip_string)
        if any(ip in network for network in CUSTOM_PRIVATE_RANGES):
            return False
        if str(ip) in COMMON_DNS_SERVERS or str(ip) in ALL_IPS_TO_IGNORE:
            return False
        return not (ip.is_private or ip.is_loopback or ip.is_link_local)
    except ValueError:
        return False

def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )

def create_table_if_not_exists(conn):
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS suricata_events (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP,
                event_type VARCHAR(255),
                src_ip VARCHAR(45),
                src_port INTEGER,
                dest_ip VARCHAR(45),
                dest_port INTEGER,
                proto VARCHAR(20),
                app_proto VARCHAR(50),
                alert JSONB,
                analysis TEXT
            )
        """)
    conn.commit()

def insert_event(conn, event, analysis):
    with conn.cursor() as cur:
        cur.execute(
            sql.SQL("""
                INSERT INTO suricata_events (
                    timestamp, event_type, src_ip, src_port, dest_ip, dest_port,
                    proto, app_proto, alert, analysis
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """),
            (
                event['timestamp'],
                event['event_type'],
                event['src_ip'],
                event['src_port'],
                event['dest_ip'],
                event['dest_port'],
                event['proto'],
                event['app_proto'],
                json.dumps(event['alert']),
                analysis
            )
        )
    conn.commit()

def analyze_event(event):
    src_ip = event.get("src_ip", "")
    dest_ip = event.get("dest_ip", "")

    logging.debug(f"Analyzing event with src_ip: {src_ip}, dest_ip: {dest_ip}")

    if src_ip in ALL_IPS_TO_IGNORE or dest_ip in ALL_IPS_TO_IGNORE:
        logging.info(f"Ignoring event due to blacklisted IP: {src_ip if src_ip in ALL_IPS_TO_IGNORE else dest_ip}")
        return None

    if not (is_public_ip(src_ip) or is_public_ip(dest_ip)):
        logging.debug(f"Ignoring event due to non-public IPs: {src_ip}, {dest_ip}")
        return None

    event_data = {
        "timestamp": event.get("timestamp", ""),
        "event_type": event.get("event_type", ""),
        "src_ip": src_ip,
        "src_port": event.get("src_port", ""),
        "dest_ip": dest_ip,
        "dest_port": event.get("dest_port", ""),
        "proto": event.get("proto", ""),
        "app_proto": event.get("app_proto", ""),
        "alert": event.get("alert", {}),
    }

    prompt = f"""Analyze the following Suricata event involving at least one public IP address and provide a brief security assessment:
    {json.dumps(event_data, indent=2)}

    Consider the following in your analysis:
    1. Is there any suspicious activity related to the public IP(s)?
    2. What is the nature of the communication (e.g., incoming connection, outgoing connection)?
    3. Are there any potential security risks or indicators of compromise?
    4. What recommendations would you make for further investigation or action?
    """

    try:
        response = client.chat.completions.create(
            model="mixtral-8x7b-32768",
            messages=[
                {"role": "system", "content": "You are a cybersecurity analyst specializing in network security, threat detection, and Suricata logs."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=200,
            temperature=0.5,
        )

        analysis = response.choices[0].message.content.strip()
        return {"event": event_data, "analysis": analysis}
    except Exception as e:
        logging.error(f"API request failed: {e}")
        return None

class LogHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_position = 0
        self.output_file = os.path.join(OUTPUT_DIR, f"suricata_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        self.db_conn = get_db_connection()
        create_table_if_not_exists(self.db_conn)

    def on_modified(self, event):
        if event.src_path == EVE_JSON_LOG_PATH:
            self.process_new_events()

    def process_new_events(self):
        logging.debug(f"Processing new events at {datetime.now()}")
        with open(EVE_JSON_LOG_PATH, 'r') as log_file:
            log_file.seek(self.last_position)
            for line in log_file:
                logging.debug(f"Processing line: {line[:50]}...")
                try:
                    event = json.loads(line.strip())
                    result = analyze_event(event)
                    if result:
                        self.save_result(result)
                        insert_event(self.db_conn, result['event'], result['analysis'])
                        logging.debug(f"Saved result for event at {result['event']['timestamp']}")
                except json.JSONDecodeError:
                    logging.error(f"Error decoding JSON: {line[:50]}...")
                    continue
            self.last_position = log_file.tell()
        logging.debug(f"Finished processing events at {datetime.now()}")

    def save_result(self, result):
        with open(self.output_file, 'a') as f:
            f.write(f"Event: {json.dumps(result['event'], indent=2)}\n")
            f.write(f"Analysis: {result['analysis']}\n\n")

def main():
    if not all([GROQ_API_KEY, EVE_JSON_LOG_PATH, OUTPUT_DIR, DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD]):
        logging.error("Error: Missing required environment variables.")
        return

    logging.info(f"Starting Suricata log analysis.")
    logging.info(f"Watching log file: {EVE_JSON_LOG_PATH}")
    logging.info(f"Saving results to: {OUTPUT_DIR}")
    logging.info(f"Number of IPs in blacklist: {len(ALL_IPS_TO_IGNORE)}")

    event_handler = LogHandler()
    observer = Observer()
    observer.schedule(event_handler, path=os.path.dirname(EVE_JSON_LOG_PATH), recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()
