import sqlite3
import time
from datetime import datetime
from collections import defaultdict

DB_NAME = "../packet_log.db"

syn_attempts = defaultdict(list) # {IP: [timestamps]}

ATTEMPT_LIMIT = 5
TIME_WINDOW = 10
AUTH_PORTS = {22}

def detect_attacks(src_ip, timestamp):
    try:
        timestamp_obj = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        print(f"[-] Invalid timestamp format: {timestamp}")
        return
        
    timestamp_seconds = timestamp_obj.timestamp()
    syn_attempts[src_ip].append(timestamp_seconds)

    valid_timestamps = []
    for t in syn_attempts[src_ip]:
        if timestamp_seconds <= TIME_WINDOW:
            valid_timestamps.append(t)
    syn_attempts[src_ip] = valid_timestamps

    if len(syn_attempts[src_ip]) > ATTEMPT_LIMIT:
        print(f"Brute Force Attack detected! IP {src_ip} sent {len(syn_attempts[src_ip])} SYN packets in {TIME_WINDOW} seconds.")

def fetch_packet_data():
    try:
        conn = sqlite3.connect(DB_NAME)
        cur = conn.cursor()
        cur.execute("SELECT src_ip, tcp_flags, timestamp FROM packets WHERE dest_port = 22 AND tcp_flags = '10'")
        packets = cur.fetchall()
        conn.close()

        for packet in packets:
            src_ip = packet[0]
            tcp_flags = packet[1]
            timestamp = packet[2]
            if str(tcp_flags) == "10":
                detect_attacks(src_ip, timestamp)
    
    except sqlite3.Error as e:
        print(f"[-] Database error: {e}")

if __name__ == "__main__":
    print("[+] Brute Force Detector Started. Monitoring SYN Packets...\n")
    while True:
        fetch_packet_data()