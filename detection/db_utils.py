import sqlite3

DB_NAME = "packet_log.db"


def init_db():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS tcp_packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        src_ip TEXT,
        dest_ip TEXT,
        src_port INTEGER,
        dest_port INTEGER,
        tcp_flags INTEGER,
        protocol INTEGER,
        payload TEXT
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS icmp_packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        src_ip TEXT,
        dest_ip TEXT,
        type INTEGER,
        code INTEGER,
        identifier INTEGER,
        sequence INTEGER,
        payload TEXT
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS udp_packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        src_ip TEXT,
        dest_ip TEXT,
        src_port INTEGER,
        dest_port INTEGER,
        payload TEXT
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS arp_packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        opcode TEXT,
        sender_mac TEXT,
        sender_ip TEXT,
        target_mac TEXT,
        target_ip TEXT
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")

    conn.commit()
    conn.close()


def insert_packet(ip_header_details, packet_details, timestamp):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    if ip_header_details["protocol"] == 6:
        cur.execute("""
            INSERT INTO tcp_packets(timestamp, src_ip, dest_ip, src_port, dest_port, tcp_flags, protocol, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp,
            ip_header_details["src_ip"],
            ip_header_details["dest_ip"],
            packet_details["src_port"],
            packet_details["dest_port"],
            packet_details["tcp_flags"],  # store as int
            ip_header_details["protocol"],
            packet_details["payload"].hex()
        ))

    elif ip_header_details["protocol"] == 1:
        cur.execute("""
            INSERT INTO icmp_packets(timestamp, src_ip, dest_ip, type, code, identifier, sequence, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp,
            ip_header_details["src_ip"],
            ip_header_details["dest_ip"],
            packet_details["type"],
            packet_details["code"],
            packet_details["identifier"],
            packet_details["sequence"],
            packet_details["payload"].hex()
        ))

    elif ip_header_details["protocol"] == 17:
        cur.execute("""
            INSERT INTO udp_packets(timestamp, src_ip, dest_ip, src_port, dest_port, payload)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            timestamp,
            ip_header_details["src_ip"],
            ip_header_details["dest_ip"],
            packet_details["src_port"],
            packet_details["dest_port"],
            packet_details["payload"].hex()
        ))

    conn.commit()
    conn.close()


def insert_arp_packet(arp_details, timestamp):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO arp_packets(timestamp, opcode, sender_mac, sender_ip, target_mac, target_ip)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        "request" if arp_details["opcode"] == 1 else "reply",
        arp_details["sender_mac"],
        arp_details["sender_ip"],
        arp_details["target_mac"],
        arp_details["target_ip"]
    ))

    conn.commit()
    conn.close()


def insert_blocked_ip(ip):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute("""
        INSERT OR IGNORE INTO blocked_ips(ip)
        VALUES (?)
    """, (ip,))

    conn.commit()
    conn.close()


def get_blocked_ips():
    init_db()
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute("SELECT ip FROM blocked_ips")
    rows = cur.fetchall()
    conn.close()

    return [row[0] for row in rows]


def clear_all_blocked_ips():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute("DELETE FROM blocked_ips")

    conn.commit()
    conn.close()
