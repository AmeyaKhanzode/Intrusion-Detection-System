import sqlite3
import time
from datetime import datetime
from collections import defaultdict

DB_NAME = "../packet_log.db"

icmp_requests = defaultdict(list)
syn_attempts = defaultdict(list)
fin_attempts = defaultdict(list)
null_attempts = defaultdict(list)
xmas_attempts = defaultdict(list)

ATTEMPT_LIMIT = 10
TIME_WINDOW = 10


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
        print(
            f"[ALERT] Ping Scan detected! IP {src_ip} sent {len(icmp_requests[src_ip])} ICMP requests in {TIME_WINDOW} seconds.")


def detect_tcp_scan(src_ip, dest_port, tcp_flags, timestamp):
    timestamp_seconds = convert_to_seconds(timestamp)
    if timestamp_seconds is None:
        return

    # SYN Scan
    if tcp_flags == 2:
        syn_attempts[src_ip].append(timestamp_seconds)

        valid_timestamps = []
        for t in syn_attempts[src_ip]:
            if timestamp_seconds - t <= TIME_WINDOW:
                valid_timestamps.append(t)
        syn_attempts[src_ip] = valid_timestamps

        if len(syn_attempts[src_ip]) > ATTEMPT_LIMIT:
            print(
                f"[ALERT] SYN Scan detected! IP {src_ip} sent {len(syn_attempts[src_ip])} SYN packets in {TIME_WINDOW} seconds.")

    # FIN Scan
    elif tcp_flags == 1:
        fin_attempts[src_ip].append(timestamp_seconds)

        valid_timestamps = []
        for t in fin_attempts[src_ip]:
            if timestamp_seconds - t <= TIME_WINDOW:
                valid_timestamps.append(t)
        fin_attempts[src_ip] = valid_timestamps

        if len(fin_attempts[src_ip]) > ATTEMPT_LIMIT:
            print(
                f"[ALERT] FIN Scan detected! IP {src_ip} sent {len(fin_attempts[src_ip])} FIN packets in {TIME_WINDOW} seconds.")

    # NULL Scan
    elif tcp_flags == 20:
        null_attempts[src_ip].append(timestamp_seconds)

        valid_timestamps = []
        for t in null_attempts[src_ip]:
            if timestamp_seconds - t <= TIME_WINDOW:
                valid_timestamps.append(t)
        null_attempts[src_ip] = valid_timestamps

        if len(null_attempts[src_ip]) > ATTEMPT_LIMIT:
            print(
                f"[ALERT] NULL Scan detected! IP {src_ip} sent {len(null_attempts[src_ip])} NULL packets in {TIME_WINDOW} seconds.")

    # Xmas Scan
    elif tcp_flags == 41:
        xmas_attempts[src_ip].append(timestamp_seconds)

        valid_timestamps = []
        for t in xmas_attempts[src_ip]:
            if timestamp_seconds - t <= TIME_WINDOW:
                valid_timestamps.append(t)
        xmas_attempts[src_ip] = valid_timestamps

        if len(xmas_attempts[src_ip]) > ATTEMPT_LIMIT:
            print(
                f"[ALERT] Xmas Scan detected! IP {src_ip} sent {len(xmas_attempts[src_ip])} Xmas packets in {TIME_WINDOW} seconds.")


def fetch_packet_data():
    try:
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn = sqlite3.connect(DB_NAME)
        cur = conn.cursor()

        cur.execute(
            "SELECT src_ip, timestamp FROM icmp_packets WHERE timestamp >= ?", (current_time,))
        icmp_packets = cur.fetchall()

        cur.execute(
            "SELECT src_ip, dest_port, tcp_flags, timestamp FROM tcp_packets WHERE protocol = 6 AND timestamp >= ?", (current_time,))
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
