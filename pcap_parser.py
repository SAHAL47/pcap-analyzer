import datetime
import time
import sqlite3
import requests
from scapy.all import rdpcap, IP

# Paste your VirusTotal API key here
VT_API_KEY = 'f736d2ba49d6bdde4077c2f7058ff69a90aeadb918de666633ddd2b89a9119b9'
DB_NAME = 'cyber_telemetry.db'

def init_database():
    """Creates a local SQLite database and the telemetry table if they don't exist."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            pcap_source TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            vt_status TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def log_to_database(pcap_source, ip_address, status):
    """Inserts a structured log record into the local database."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    cursor.execute('''
        INSERT INTO ip_intel (timestamp, pcap_source, destination_ip, vt_status)
        VALUES (?, ?, ?, ?)
    ''', (current_time, pcap_source, ip_address, status))
    
    conn.commit()
    conn.close()

def check_vt_ip(ip_address):
    """Queries the VirusTotal API v3 for a single IP address."""
    if ip_address.startswith(('10.', '172.16.', '192.168.', '127.')):
        return "Internal IP (Skipped)"

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious_count = stats['malicious']
            
            if malicious_count > 0:
                return f"MALICIOUS ({malicious_count} flags)"
            return "Clean / Safe"
        elif response.status_code == 401:
            return "Error: Invalid API Key"
        else:
            return f"Error (Status Code: {response.status_code})"
    except Exception as e:
        return f"Connection Error: {str(e)}"

def extract_analyze_and_store(pcap_file):
    # Initialize the database table first
    init_database()
    
    print(f"Opening and reading {pcap_file}...")
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"Error: Could not find the file '{pcap_file}'.")
        return

    destination_ips = set()
    for packet in packets:
        if packet.haslayer(IP):
            destination_ips.add(packet[IP].dst)

    print(f"\n[+] Extracted {len(destination_ips)} unique destination IPs. Processing pipeline...")
    print("-" * 75)
    print(f"{'IP Address':<20} | {'Threat Intel Status':<25} | {'Database Storage'}")
    print("-" * 75)

    for ip in destination_ips:
        status = check_vt_ip(ip)
        
        # Save to database
        log_to_database(pcap_file, ip, status)
        
        print(f"{ip:<20} | {status:<25} | SAVED TO SQLITE")
        
        # Rate limit control for free tier API
        if not ip.startswith(('10.', '172.16.', '192.168.', '127.')):
            time.sleep(15)
            
    print(f"\n[+] Pipeline execution finished successfully. Database '{DB_NAME}' updated.")

# Execute the complete production pipeline
extract_analyze_and_store('malware_test.pcap')