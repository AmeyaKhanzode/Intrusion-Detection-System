import sqlite3
import time
from collections import defaultdict

DB_NAME = "../packet_log.db"

syn_attempts = defaultdict(list) # {IP: [timestamps]}

ATTEMPT_LIMIT = 5
TIME_WINDOW = 10
AUTH_PORTS = {22, 21, 23, 3389}
CHECK_INTERVAL = 5

def detect_attacks(src_ip, timestamp):
    syn_attempts[src_ip].append(timestamp)
    syn_attempts["attempts"] = 0
    timestamp_seconds = int(timestamp[-2:])
    # syn_attempts[src_ip] = [t for t in syn_attempts[src_ip] 
    #                             if timestamp_seconds - int(t[-2:]) <= TIME_WINDOW: 
    #                                 syn_attempts["attempts"] += 1]


    for t in syn_attempts[src_ip]:
        if timestamp_seconds - int(t[-2:]) <= TIME_WINDOW:
            syn_attempts[src_ip].append(t)
            syn_attempts["attempts"] += 1

    print(f"[DEBUG] syn_attempts : {syn_attempts}")
    if (syn_attempts[src_ip] > ATTEMPT_LIMIT):
        print(f"Brute Force Attack detected! IP {src_ip} sent {len(syn_attempts[src_ip])} SYN packets in {TIME_WINDOW} seconds.")

def fetch_packet_data():
    try:
        conn = sqlite3.connect(DB_NAME)
        cur = conn.cursor()
        cur.execute("SELECT src_ip, tcp_flags, timestamp FROM packets WHERE dest_port IN (22, 21, 23, 3389)")
        packets = cur.fetchall()
        conn.close()

        for packet in packets:
            src_ip = packet[0]
            tcp_flags = packet[1]
            timestamp = packet[2]
            print(type(tcp_flags))
            if tcp_flags == '11000':
                detect_attacks(src_ip, timestamp)
    
    except sqlite3.Error as e:
        print(f"[-] Database error: {e}")

if __name__ == "__main__":
    print("[+] Brute Force Detector Started. Monitoring SYN Packets...\n")
    while True:
        fetch_packet_data()
        time.sleep(CHECK_INTERVAL)