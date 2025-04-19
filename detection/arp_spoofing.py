import sqlite3
import time
import datetime
from datetime import datetime, timedelta

DB_NAME = "../packet_log.db"

ip_mac_map = {}
mac_ip_map = {}
last_checked = None
TIME_WINDOW = 10


def detect_attack(packets):
    for packet in packets:
        if packet[2] == "request":
            mac_addr = packet[3]
            ip_addr = packet[4]

            if mac_addr not in ip_mac_map:
                ip_mac_map[mac_addr] = set()
            ip_mac_map[mac_addr].add(ip_addr)

            if ip_addr not in mac_ip_map:
                mac_ip_map[ip_addr] = set()
            mac_ip_map[ip_addr].add(mac_addr)

    for mac, ips in ip_mac_map.items():
        if len(ips) > 1:
            print(f"[!] Possible ARP spoofing: {mac} has multiple IPs: {ips}")

    for ip, macs in mac_ip_map.items():
        if len(macs) > 1:
            print(f"[!] Possible ARP spoofing: {ip} has multiple MACs: {macs}")

    print(ip_mac_map)
    print(mac_ip_map)


def fetch_from_db():
    try:
        conn = sqlite3.connect(DB_NAME)
        cur = conn.cursor()

        cutoff_time = datetime.now() - timedelta(seconds=TIME_WINDOW)
        cutoff_str = cutoff_time.strftime('%Y-%m-%d %H:%M:%S')

        cur.execute("""
            SELECT * FROM arp_packets
            WHERE timestamp >= ?
        """, (cutoff_str,))

        packets = cur.fetchall()

        if packets:
            detect_attack(packets)

        conn.close()

    except sqlite3.Error as e:
        print(f"[-] Database error: {e}")


if __name__ == "__main__":
    print("[+] ARP Spoofing Detector started...")
    while True:
        fetch_from_db()
