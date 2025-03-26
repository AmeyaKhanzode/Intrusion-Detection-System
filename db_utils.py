import sqlite3

DB_NAME = "packet_log.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    
    cur.execute("""
    CREATE TABLE IF NOT EXISTS packets (
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

    conn.commit()
    conn.close()

def insert_packet(ip_header_details, packet_details):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO packets(src_ip, dest_ip, src_port, dest_port, tcp_flags, protocol, payload)
        VALUES (?,?,?,?,?,?,?)""", (
                ip_header_details["src_ip"], 
                ip_header_details["dest_ip"], 
                packet_details["src_port"], 
                packet_details["dest_port"], 
                str(bin(packet_details["tcp_flags"]))[2:],
                ip_header_details["protocol"], 
                packet_details["payload"].hex()
            ))

    conn.commit()
    conn.close()
