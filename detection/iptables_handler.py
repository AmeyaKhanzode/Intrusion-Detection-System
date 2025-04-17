import subprocess

blocked_ips = set()

def block_ip(ip_address):
    if ip_address not in blocked_ips:
        try:
            subprocess.run(
                ["sudo", "iptables", "-I", "INPUT", "1", "-s", ip_address, "-j", "DROP"],
                check=True
            )
            print(f"[+] Blocked IP: {ip_address} using iptables.")

            blocked_ips.add(ip_address)
        except subprocess.CalledProcessError as e:
            print(f"[-] Failed to block IP {ip_address}: {e}")