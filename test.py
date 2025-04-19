from scapy.all import ARP, Ether, sendp

# Create the ARP packet


def send_arp_request(target_ip):
    arp = ARP(op=1, pdst=target_ip)  # ARP request (op=1)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast Ethernet frame
    packet = ether / arp  # Combine Ethernet and ARP layers
    # Send on the loopback interface
    sendp(packet, iface="lo", verbose=True)


# Send ARP request to 127.0.0.1 (localhost)
send_arp_request("127.0.0.1")
