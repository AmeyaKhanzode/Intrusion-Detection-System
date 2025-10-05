from socket import *
from db_utils import get_blocked_ips
import datetime
import db_utils
import time
import struct
from colorama import Fore, Style

# Packet counting variables
packet_count = 0
tcp_count = 0
udp_count = 0
icmp_count = 0
arp_count = 0
blocked_count = 0
dropped_count = 0  # Track dropped packets
start_time = None

# Performance optimization flags
ENABLE_DB_LOGGING = False  # Set to True for database logging (MUCH SLOWER)
ENABLE_PACKET_DETAILS = False  # Set to True to see packet details

# db_utils.clear_all_blocked_ips()
# db_utils.init_db()

try:
    sock = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))  # ipv4, tcp

    # Increase socket buffer size to handle high packet rates
    sock.setsockopt(SOL_SOCKET, SO_RCVBUF, 67108864)  # 64MB buffer

    # Make socket non-blocking for better performance
    sock.setblocking(False)

    # Bind to all interfaces (use "any" or specific interface like "eth0")
    # For loopback only, use "lo". For all interfaces, use empty string or specific interface
    interface = input(
        "Enter interface (press Enter for 'lo', or type 'any' for all interfaces): ").strip()
    if not interface:
        interface = "lo"
    elif interface == "any":
        interface = ""

    if interface:
        sock.bind((interface, 0))
        print(
            Fore.GREEN + f"[+] Socket created and bound to interface: {interface}" + Style.RESET_ALL)
    else:
        print(Fore.GREEN +
              "[+] Socket created for all interfaces" + Style.RESET_ALL)

except error as err:
    print(Fore.RED + "[-] Couldn't create socket", err, Style.RESET_ALL)
    exit(1)

print(Fore.BLUE + "[*] Listening for packets...\n" + Style.RESET_ALL)


def extract_ip_header(packet):
    eth_header_size = 14
    ip_header = packet[eth_header_size:eth_header_size + 20]
    ip_header_unpacked = struct.unpack("!BBHHHBBH4s4s", ip_header)

    '''
        struct unpacked returns a tuple:
        0: ip version, header length
        2: size of packet (header + payload)
        4: 3 bit flags
        5: ttl
        6: protocol (6 for TCP 17 for UDP)
        8: source ip
        9: destination ip
    '''

    ip_header_length = (ip_header_unpacked[0] & 0x0F) * 4
    src_ip = inet_ntoa(ip_header_unpacked[8])
    dest_ip = inet_ntoa(ip_header_unpacked[9])
    protocol = ip_header_unpacked[6]
    packet_size = ip_header_unpacked[2]
    ttl = ip_header_unpacked[5]

    return {
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "protocol": protocol,
        "ttl": ttl,
        "packet_size": packet_size,
        "ip_header_length": ip_header_length
    }


def extract_packet_details(ip_header_details, protocol, packet):
    if protocol == 6:
        ip_header_length = ip_header_details['ip_header_length']
        tcp_header = packet[ip_header_length + 14: ip_header_length + 34]
        tcp_header_unpacked = struct.unpack("!HHIIHHHH", tcp_header)

        src_port = tcp_header_unpacked[0]
        dest_port = tcp_header_unpacked[1]
        raw_flags = tcp_header_unpacked[4]
        tcp_flags = raw_flags & 0xFF
        seq_num = tcp_header_unpacked[2]
        tcp_header_length = (tcp_header_unpacked[4] >> 12) * 4

        payload_offset = ip_header_length + tcp_header_length + 14
        payload = packet[payload_offset:]

        return {
            "src_ip": ip_header_details["src_ip"],
            "dest_ip": ip_header_details["dest_ip"],
            "src_port": src_port,
            "dest_port": dest_port,
            "tcp_flags": tcp_flags,
            "seq_num": seq_num,
            "tcp_header_length": tcp_header_length,
            "payload": payload
        }

    elif protocol == 1:
        ip_header_length = ip_header_details['ip_header_length']
        icmp_header = packet[ip_header_length + 14:ip_header_length + 22]

        icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq = struct.unpack(
            '!BBHHH', icmp_header)

        icmp_payload = packet[ip_header_length + 22:]

        return {
            "src_ip": ip_header_details["src_ip"],
            "dest_ip": ip_header_details["dest_ip"],
            "type": icmp_type,
            "code": icmp_code,
            "checksum": icmp_checksum,
            "identifier": icmp_id,
            "sequence": icmp_seq,
            "payload": icmp_payload
        }

    elif protocol == 17:
        ip_header_length = ip_header_details['ip_header_length']
        udp_header = packet[ip_header_length + 14: ip_header_length + 22]
        src_port, dest_port, length, checksum = struct.unpack(
            '!HHHH', udp_header)

        udp_payload = packet[ip_header_length + 22:]

        return {
            "src_ip": ip_header_details["src_ip"],
            "dest_ip": ip_header_details["dest_ip"],
            "src_port": src_port,
            "dest_port": dest_port,
            "length": length,
            "checksum": checksum,
            "payload": udp_payload
        }


def print_packet_details(ip_header_details, packet_details):
    if ip_header_details['protocol'] == 6:
        print(Fore.LIGHTCYAN_EX + "==========TCP PACKET==========" + Style.RESET_ALL)
        print(f"{Fore.LIGHTRED_EX}{'Protocol':<15}{Style.RESET_ALL}: TCP (6)")
        print(
            f"{Fore.LIGHTRED_EX}{'Source IP':<15}{Style.RESET_ALL}: {ip_header_details['src_ip']}")
        print(
            f"{Fore.LIGHTRED_EX}{'Destination IP':<15}{Style.RESET_ALL}: {ip_header_details['dest_ip']}")
        print(
            f"{Fore.LIGHTRED_EX}{'Source Port':<15}{Style.RESET_ALL}: {packet_details['src_port']}")
        print(
            f"{Fore.LIGHTRED_EX}{'Destination Port':<15}{Style.RESET_ALL}: {packet_details['dest_port']}")
        print(
            f"{Fore.LIGHTRED_EX}{'Sequence Number':<15}{Style.RESET_ALL}: {packet_details['seq_num']}")
        print(
            f"{Fore.LIGHTRED_EX}{'TTL':<15}{Style.RESET_ALL}: {ip_header_details['ttl']}")
        print(
            f"{Fore.LIGHTRED_EX}{'Packet Size':<15}{Style.RESET_ALL}: {ip_header_details['packet_size']} bytes")
        print(
            f"{Fore.LIGHTRED_EX}{'TCP Flags':<15}{Style.RESET_ALL}: {bin(packet_details['tcp_flags'])}")
        if packet_details.get("payload"):
            print(
                f"{Fore.LIGHTRED_EX}{'Payload':<15}{Style.RESET_ALL}: {packet_details['payload'].hex()[:50]}...")
        print(Fore.LIGHTCYAN_EX +
              "==============================\n" + Style.RESET_ALL)

    elif ip_header_details['protocol'] == 1:
        print(Fore.LIGHTCYAN_EX + "==========ICMP PACKET=========" + Style.RESET_ALL)
        print(f"{Fore.LIGHTRED_EX}{'Protocol':<15}{Style.RESET_ALL}: ICMP (1)")
        print(
            f"{Fore.LIGHTRED_EX}{'Source IP':<15}{Style.RESET_ALL}: {ip_header_details['src_ip']}")
        print(
            f"{Fore.LIGHTRED_EX}{'Destination IP':<15}{Style.RESET_ALL}: {ip_header_details['dest_ip']}")

        icmp_type = packet_details['type']
        icmp_code = packet_details['code']
        if icmp_type == 8 and icmp_code == 0:
            print(
                f"{Fore.LIGHTRED_EX}{'ICMP Type':<15}{Style.RESET_ALL}: Echo Request (PING)")
        elif icmp_code == 0 and icmp_type == 0:
            print(
                f"{Fore.LIGHTRED_EX}{'ICMP Type':<15}{Style.RESET_ALL}: Echo Reply (PING)")

        if packet_details["payload"]:
            print(
                f"{Fore.LIGHTRED_EX}{'Payload':<15}{Style.RESET_ALL}: {packet_details['payload'].hex()[:50]}...")

        print(Fore.LIGHTCYAN_EX +
              "==============================\n" + Style.RESET_ALL)

    elif ip_header_details['protocol'] == 17:
        print(Fore.LIGHTCYAN_EX + "==========UDP PACKET=========" + Style.RESET_ALL)
        print(f"{Fore.LIGHTRED_EX}{'Protocol':<15}{Style.RESET_ALL}: UDP (17)")
        print(
            f"{Fore.LIGHTRED_EX}{'Source IP':<15}{Style.RESET_ALL}: {ip_header_details['src_ip']}")
        print(
            f"{Fore.LIGHTRED_EX}{'Destination IP':<15}{Style.RESET_ALL}: {ip_header_details['dest_ip']}")
        print(
            f"{Fore.LIGHTRED_EX}{'Source Port':<15}{Style.RESET_ALL}: {packet_details['src_port']}")
        print(
            f"{Fore.LIGHTRED_EX}{'Destination Port':<15}{Style.RESET_ALL}: {packet_details['dest_port']}")
        if packet_details["payload"]:
            print(
                f"{Fore.LIGHTRED_EX}{'Payload':<15}{Style.RESET_ALL}: {packet_details['payload'].hex()[:50]}...")

        print(Fore.LIGHTCYAN_EX +
              "==============================\n" + Style.RESET_ALL)


def format_mac(raw_mac):
    return ':'.join('%02x' % b for b in raw_mac)


def extract_arp_details(packet):
    print(packet)
    arp_header = struct.unpack("!HHBBH6s4s6s4s", packet[14:42])
    print(arp_header)
    return {
        "opcode": arp_header[4],
        "sender_mac": format_mac(arp_header[5]),
        "sender_ip": inet_ntoa(arp_header[6]),
        "target_mac": format_mac(arp_header[7]),
        "target_ip": inet_ntoa(arp_header[8])
    }


def print_arp_packet(arp_header_details):
    print(Fore.LIGHTCYAN_EX + "==========ARP PACKET=========" + Style.RESET_ALL)
    print(
        f"{Fore.LIGHTRED_EX}{'Source IP':<15}{Style.RESET_ALL}: {arp_header_details['sender_ip']}")
    print(
        f"{Fore.LIGHTRED_EX}{'Targer IP':<15}{Style.RESET_ALL}: {arp_header_details['target_ip']}")
    print(
        f"{Fore.LIGHTRED_EX}{'Sender MAC':<15}{Style.RESET_ALL}: {arp_header_details['sender_mac']}")
    print(
        f"{Fore.LIGHTRED_EX}{'Target MAC':<15}{Style.RESET_ALL}: {arp_header_details['target_mac']}")
    print(Fore.LIGHTCYAN_EX +
          "==============================\n" + Style.RESET_ALL)


def print_benchmark_stats():
    """Print detailed benchmark statistics - PURE PARSING PERFORMANCE"""
    total_packets = tcp_count + udp_count + icmp_count + arp_count
    print(Fore.YELLOW +
          f"[PURE PARSING BENCHMARK] Total packets parsed: {total_packets}/sec" + Style.RESET_ALL)
    print(Fore.CYAN + f"  ├─ TCP:  {tcp_count}" + Style.RESET_ALL)
    print(Fore.CYAN + f"  ├─ UDP:  {udp_count}" + Style.RESET_ALL)
    print(Fore.CYAN + f"  ├─ ICMP: {icmp_count}" + Style.RESET_ALL)
    print(Fore.CYAN + f"  ├─ ARP:  {arp_count}" + Style.RESET_ALL)
    print(Fore.CYAN + f"  ├─ Blocked: {blocked_count}" + Style.RESET_ALL)
    print(Fore.CYAN + f"  └─ Dropped: {dropped_count}" + Style.RESET_ALL)


while True:
    try:
        # blocked_ips = set(get_blocked_ips()) if ENABLE_DB_LOGGING else set()
        blocked_ips = set()  # Skip DB lookup for pure parsing benchmark

        # Use non-blocking receive with exception handling
        try:
            packet, addr = sock.recvfrom(65565)
        except BlockingIOError:
            # No packet available right now, continue
            continue

        timestamp = None  # Skip timestamp generation for pure parsing benchmark

        eth_header = packet[:14]
        dest_mac, src_mac, eth_protocol = struct.unpack("!6s6sH", eth_header)

        packet_details = None
        arp_header_details = None
        is_blocked = False

        # Initialize start time on first packet
        if start_time is None:
            start_time = time.time()

        if eth_protocol == 0x0800:  # IPv4
            ip_header_details = extract_ip_header(packet)
            if ip_header_details:
                if not blocked_ips or ip_header_details["src_ip"] not in blocked_ips:
                    packet_details = extract_packet_details(
                        ip_header_details, ip_header_details['protocol'], packet)

                    # Count by protocol type
                    if ip_header_details['protocol'] == 6:  # TCP
                        tcp_count += 1
                    elif ip_header_details['protocol'] == 17:  # UDP
                        udp_count += 1
                    elif ip_header_details['protocol'] == 1:  # ICMP
                        icmp_count += 1
                else:
                    is_blocked = True
                    blocked_count += 1

        elif eth_protocol == 0x0806:  # ARP
            arp_header_details = extract_arp_details(packet)
            arp_count += 1

        # Process packets - ALL DB OPERATIONS COMMENTED OUT FOR PURE PARSING BENCHMARK
        # if packet_details and ENABLE_DB_LOGGING:
        #     if ENABLE_PACKET_DETAILS:
        #         print_packet_details(ip_header_details, packet_details)
        #     db_utils.insert_packet(
        #         ip_header_details, packet_details, timestamp)

        # elif arp_header_details and ENABLE_DB_LOGGING:
        #     if ENABLE_PACKET_DETAILS:
        #         print_arp_packet(arp_header_details)
        #     db_utils.insert_arp_packet(arp_header_details, timestamp)

        # Increment total packet count
        packet_count += 1

        # Check if 1 second has elapsed
        now = time.time()
        if now - start_time >= 1:
            print_benchmark_stats()

            # Reset counters
            packet_count = 0
            tcp_count = 0
            udp_count = 0
            icmp_count = 0
            arp_count = 0
            blocked_count = 0
            dropped_count = 0
            start_time = now

    except KeyboardInterrupt:
        print("\nExiting... bye bye")
        exit(0)
    except Exception as e:
        print(Fore.YELLOW + f"[!] Error parsing packet: {e}" + Style.RESET_ALL)
        dropped_count += 1
