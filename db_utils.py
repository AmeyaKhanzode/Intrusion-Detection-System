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
        tcp_flags TEXT,
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
        sender_ip INTEGER,
        target_mac INTEGER,
        target_ip INTEGER
    )""")

    conn.commit()
    conn.close()


def insert_packet(ip_header_details, packet_details):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    if ip_header_details["protocol"] == 6:
        cur.execute("""
            INSERT INTO tcp_packets(src_ip, dest_ip, src_port, dest_port, tcp_flags, protocol, payload)
            VALUES (?,?,?,?,?,?,?)""", (
                    ip_header_details["src_ip"],
                    ip_header_details["dest_ip"],
                    packet_details["src_port"],
                    packet_details["dest_port"],
                    str(bin(packet_details["tcp_flags"]))[2:],
                    ip_header_details["protocol"],
                    packet_details["payload"].hex()
                    ))
    elif ip_header_details["protocol"] == 1:
        cur.execute("""
            INSERT INTO icmp_packets(src_ip, dest_ip, type, code, identifier, sequence, payload)
            VALUES (?,?,?,?,?,?,?)""", (
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
                INSERT INTO udp_packets(src_ip, dest_ip, src_port, dest_port, payload)
                VALUES (?,?,?,?,?)""", (
                    ip_header_details["src_ip"],
                    ip_header_details["dest_ip"],
                    packet_details["src_port"],
                    packet_details["dest_port"],
                    packet_details["payload"].hex()
                    ))

    conn.commit()
    conn.close()


def insert_arp_packet(arp_details):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO arp_packets(opcode, sender_mac, sender_ip, target_mac, target_ip)
        VALUES (?, ?, ?, ?, ?)
    """, (
        "request" if arp_details["opcode"] == 1 else "reply",
        arp_details["sender_mac"],
        arp_details["sender_ip"],
        arp_details["target_mac"],
        arp_details["target_ip"]
    ))

    conn.commit()
    conn.close()
