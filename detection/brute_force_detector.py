import sqlite3
import db_utils
import time
from datetime import datetime, timedelta
from collections import defaultdict
import iptables_handler
DB_NAME = "../packet_log.db"

syn_attempts = defaultdict(list)

ATTEMPT_LIMIT = 10
TIME_WINDOW = 10
MONITOR_PORTS = {22}


def detect_attacks(src_ip, timestamp):
    try:
        timestamp_obj = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        print(f"[-] Invalid timestamp format: {timestamp}")
        return

    timestamp_seconds = timestamp_obj.timestamp()
    syn_attempts[src_ip].append(timestamp_seconds)

    valid_timestamps = [t for t in syn_attempts[src_ip]
                        if timestamp_seconds - t <= TIME_WINDOW]
    syn_attempts[src_ip] = valid_timestamps

    if len(valid_timestamps) > ATTEMPT_LIMIT:
        already_blocked = src_ip in db_utils.get_blocked_ips()
        if already_blocked:
            return
        print(
            f"[!] Brute Force Attack Detected! {src_ip} sent {len(valid_timestamps)} SYN packets in {TIME_WINDOW}s.")
        iptables_handler.block_ip(src_ip)
        print(f"{src_ip} blocked by iptables!")
        db_utils.insert_blocked_ip(src_ip)
        syn_attempts[src_ip] = []


def fetch_packet_data():
    try:
        cutoff_time = datetime.now() - timedelta(seconds=TIME_WINDOW)
        cutoff_str = cutoff_time.strftime('%Y-%m-%d %H:%M:%S')

        conn = sqlite3.connect(DB_NAME)
        cur = conn.cursor()

        for port in MONITOR_PORTS:
            query = """
            SELECT src_ip, tcp_flags, timestamp
            FROM tcp_packets
            WHERE dest_port = ? AND tcp_flags = 2 AND timestamp >= ?
            """
            cur.execute(query, (port, cutoff_str))
            packets = cur.fetchall()

            for src_ip, tcp_flags, timestamp in packets:
                detect_attacks(src_ip, timestamp)

        conn.close()

    except sqlite3.Error as e:
        print(f"[-] Database error: {e}")


if __name__ == "__main__":
    print("[+] Brute Force Detector Started. Monitoring TCP SYN packets...\n")
    while True:
        fetch_packet_data()
        time.sleep(1)
