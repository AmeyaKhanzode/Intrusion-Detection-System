from socket import *
import time
import struct
from colorama import Fore, Style
try:
    sock = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))  # ipv4, tcp
    sock.bind(("lo", 0))
    print(Fore.GREEN + "[+] Socket created Succesfully." + Style.RESET_ALL)
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
        tcp_flags = tcp_header_unpacked[5]
        seq_num = tcp_header_unpacked[2]
        tcp_header_length = (tcp_header_unpacked[4] >> 12) * 4
        return {
            "src_port": src_port,
            "dest_port": dest_port,
            "tcp_flags": tcp_flags,
            "seq_num": seq_num,
            "tcp_header_length": tcp_header_length
        }


def print_packet_details(ip_header_details, packet_details):
    if ip_header_details['protocol'] == 6:
        print(Fore.YELLOW + "==========TCP PACKET==========" + Style.RESET_ALL)
        print(f"{Fore.BLUE}{'Protocol':<15}{Style.RESET_ALL}: TCP (6)")
        print(
            f"{Fore.BLUE}{'Source IP':<15}{Style.RESET_ALL}: {ip_header_details['src_ip']}")
        print(
            f"{Fore.BLUE}{'Destination IP':<15}{Style.RESET_ALL}: {ip_header_details['dest_ip']}")
        print(
            f"{Fore.BLUE}{'Source Port':<15}{Style.RESET_ALL}: {packet_details['src_port']}")
        print(
            f"{Fore.BLUE}{'Destination Port':<15}{Style.RESET_ALL}: {packet_details['dest_port']}")
        print(
            f"{Fore.BLUE}{'Sequence Number':<15}{Style.RESET_ALL}: {packet_details['seq_num']}")
        print(
            f"{Fore.BLUE}{'TTL':<15}{Style.RESET_ALL}: {ip_header_details['ttl']}")
        print(
            f"{Fore.BLUE}{'Packet Size':<15}{Style.RESET_ALL}: {ip_header_details['packet_size']} bytes")
        print(
            f"{Fore.BLUE}{'TCP Flags':<15}{Style.RESET_ALL}: {bin(packet_details['tcp_flags'])}")
        print(Fore.YELLOW + "=======================================\n" + Style.RESET_ALL)


while True:
    packet, addr = sock.recvfrom(65565)  # for packets upto size 65565

    ip_header_details = extract_ip_header(packet)
    packet_details = extract_packet_details(
        ip_header_details, ip_header_details['protocol'], packet)
    if packet_details and packet_details['dest_port'] == 4445:
        print_packet_details(ip_header_details, packet_details)
    else:
        continue
