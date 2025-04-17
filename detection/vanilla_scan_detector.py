from datetime import datetime
from collections import defaultdict

ATTEMPT_LIMIT = 10
TIME_WINDOW = 10

handshakes = {}
tcp_connect_attempts = defaultdict(list)

def convert_to_seconds(timestamp):
    if isinstance(timestamp, float):
        return timestamp
    try:
        return datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S").timestamp()
    except ValueError:
        return None

def detect_vanilla_scan(src_ip, dest_port, tcp_flags, timestamp):
    timestamp_seconds = convert_to_seconds(timestamp)
    if timestamp_seconds is None:
        return

    key = (src_ip, dest_port)
    reverse_key = (dest_port, src_ip)

    if str(tcp_flags) == "00010":
        handshakes[key] = 1

    elif str(tcp_flags) == "00011":
        if reverse_key in handshakes and handshakes[reverse_key] == 1:
            handshakes[reverse_key] = 2

    elif str(tcp_flags) == "00110":
        if key in handshakes and handshakes[key] == 2:
            tcp_connect_attempts[src_ip].append(timestamp_seconds)
            del handshakes[key]
            
            tcp_connect_attempts[src_ip] = [
                t for t in tcp_connect_attempts[src_ip]
                if timestamp_seconds - t <= TIME_WINDOW
            ]

            if len(tcp_connect_attempts[src_ip]) > ATTEMPT_LIMIT:
                print(f"[ALERT] Vanilla Scan detected! IP {src_ip} established {len(tcp_connect_attempts[src_ip])} full connections in {TIME_WINDOW} seconds.")