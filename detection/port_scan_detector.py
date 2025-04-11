import sqlite3
import time
from datetime import datetime
from collections import defaultdict

DB_NAME = "../packet_log.db"

icmp_requests = defaultdict(list)  # {IP: [timestamps]}
tcp_connect_attempts = defaultdict(list)  # {IP: [timestamps]}
syn_attempts = defaultdict(list)  # {IP: [timestamps]}
sweep_attempts = defaultdict(lambda: defaultdict(list))  # {Port: {IP: [timestamps]}}

ATTEMPT_LIMIT = 10
TIME_WINDOW = 10

# Detects Ping Scan
def detect_icmp_scan(src_ip, timestamp):
    timestamp_seconds = convert_to_seconds(timestamp)
    if timestamp_seconds is None:
        return

    icmp_requests[src_ip].append(timestamp_seconds)

    valid_timestamps = []
    for t in icmp_requests[src_ip]:
        if timestamp_seconds - t <= TIME_WINDOW:
            valid_timestamps.append(t)
    icmp_requests[src_ip] = valid_timestamps

    if len(icmp_requests[src_ip]) > ATTEMPT_LIMIT:
        print(f"[ALERT] Ping Scan detected! IP {src_ip} sent {len(icmp_requests[src_ip])} ICMP requests in {TIME_WINDOW} seconds.")

# Detects Vanilla Scan, SYN Scan and Sweep Scan
def detect_tcp_scan(src_ip, dest_port, tcp_flags, timestamp):
    timestamp_seconds = convert_to_seconds(timestamp)
    if timestamp_seconds is None:
        return

# SYN Scan
    if str(tcp_flags) == "10":
        syn_attempts[src_ip].append(timestamp_seconds)

        valid_timestamps = []
        for t in syn_attempts[src_ip]:
            if timestamp_seconds - t <= TIME_WINDOW:
                valid_timestamps.append(t)
        syn_attempts[src_ip] = valid_timestamps

        if len(syn_attempts[src_ip]) > ATTEMPT_LIMIT:
            print(f"[ALERT] SYN Scan detected! IP {src_ip} sent {len(syn_attempts[src_ip])} SYN packets in {TIME_WINDOW} seconds.")

# Vanilla Scan
    elif str(tcp_flags) == "10010":
        tcp_connect_attempts[src_ip].append(timestamp_seconds)

        valid_timestamps = []
        for t in tcp_connect_attempts[src_ip]:
            if timestamp_seconds - t <= TIME_WINDOW:
                valid_timestamps.append(t)
        tcp_connect_attempts[src_ip] = valid_timestamps

        if len(tcp_connect_attempts[src_ip]) > ATTEMPT_LIMIT:
            print(f"[ALERT] Vanilla Scan detected! IP {src_ip} established {len(tcp_connect_attempts[src_ip])} full connections in {TIME_WINDOW} seconds.")

# Sweep Scan
    sweep_attempts[dest_port][src_ip].append(timestamp_seconds)

    valid_timestamps = []
    for t in sweep_attempts[dest_port][src_ip]:
        if timestamp_seconds - t <= TIME_WINDOW:
            valid_timestamps.append(t)
    sweep_attempts[dest_port][src_ip] = valid_timestamps

    active_ips = len(sweep_attempts[dest_port])
    if active_ips > ATTEMPT_LIMIT:
        print(f"[ALERT] Sweep Scan detected! {active_ips} different IPs accessed port {dest_port} within {TIME_WINDOW} seconds.")


def fetch_packet_data():
    try:
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn = sqlite3.connect(DB_NAME)
        cur = conn.cursor()

        # Fetch ICMP packets (Ping Scan Detection)
        cur.execute("SELECT src_ip, timestamp FROM icmp_packets WHERE timestamp >= ?", (current_time,))
        icmp_packets = cur.fetchall()

        # Fetch TCP packets (Vanilla Scan, SYN Scan, Sweep Scan Detection)
        cur.execute("SELECT src_ip, dest_port, tcp_flags, timestamp FROM tcp_packets WHERE protocol = 6 AND timestamp >= ?", (current_time,))
        tcp_packets = cur.fetchall()

        conn.close()

        for packet in icmp_packets:
            src_ip = packet[0]
            timestamp = packet[1]
            detect_icmp_scan(src_ip, timestamp)
        
        for packet in tcp_packets:
            src_ip = packet[0]
            dest_port = packet[1]
            tcp_flags = packet[2]
            timestamp = packet[3]
            detect_tcp_scan(src_ip, dest_port, tcp_flags, timestamp)

    except sqlite3.Error as e:
        print(f"[-] Database error: {e}")

def convert_to_seconds(timestamp):
    try:
        return datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S").timestamp()
    except ValueError:
        return None

if __name__ == "__main__":
    print("[+] Port Scan Detector Started. Monitoring scan attempts...\n")
    while True:
        fetch_packet_data()