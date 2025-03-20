from socket import *
import time
import struct

try:
    sock = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))  # ipv4, tcp
    sock.bind(("wlan0", 0))
    print("Socket created.")
except error as err:
    print("Couldn't create socket:", err)

print("Socket is listening...\n")

while True:
    packet, addr = sock.recvfrom(65565)  # for packets upto size 65565
    print("Got tcp packet from:", addr)
    print("Raw Packet:", packet)
    print()

    # IP Header Unpacking
    ip_header = packet[:20]
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

    if protocol == 6:
        print("Protocol: TCP")
    elif protocol == 17:
        print("Protocol: UDP")

    print("TTL: ", ttl)
    print("Packet size: ", packet_size)

    print("Source IP: ", src_ip)
    print("Destination IP: ", dest_ip)

    # TCP Header Unpacking
    tcp_header = packet[ip_header_length: ip_header_length + 20]
    tcp_header_unpacked = struct.unpack("!HHIIHHHH", tcp_header)

    src_port = tcp_header_unpacked[0]
    dest_port = tcp_header_unpacked[1]
    tcp_flags = tcp_header_unpacked[5]
    seq_num = tcp_header_unpacked[2]
    tcp_header_length = tcp_header_unpacked[4]

    print("tcp flags: ", bin(tcp_flags))
    print("Protocol: ", protocol)
    print("src port: ", src_port)
    print("dest port: ", dest_port)

    payload = packet[tcp_header_length + 20:]
    print("Payload: ", payload)
    time.sleep(1)
