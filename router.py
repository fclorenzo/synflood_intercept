from scapy.all import *
from collections import defaultdict
import threading
import time

# Data structures
syn_to_synack = defaultdict(lambda: [0, 0])  # SYN to SYN-ACK ratio tracker
blocked_ips = set()  # Blocked IPs

# Thresholds
SYN_SYNACK_RATIO_THRESHOLD = 3  # Lower ratio for easier detection during testing
CHECK_INTERVAL = 1  # Interval in seconds to check thresholds


def monitor_packets(packet):
    """
    Function to process sniffed packets and update tracking data.
    """
    global blocked_ips

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        ip = packet[IP]

        # If the source IP is blocked, drop the packet
        if ip.src in blocked_ips:
            print(f"[BLOCKED] Dropping packet from {ip.src}")
            return

        # Track SYN packets
        if tcp.flags == "S":
            syn_to_synack[(ip.src, tcp.dport)][0] += 1  # Increment SYN count
            time.sleep(0.01)  # Artificial delay for debugging
            print(f"[INFO] SYN packet tracked: {ip.src} -> {ip.dst}:{tcp.dport}")
            print(f"[DEBUG] Updated syn_to_synack: {dict(syn_to_synack)}")


        # Track SYN-ACK packets
        if tcp.flags == "SA":
            syn_to_synack[(ip.dst, tcp.sport)][1] += 1  # Increment SYN-ACK count
            time.sleep(0.01)  # Artificial delay for debugging
            print(f"[INFO] SYN-ACK packet tracked: {ip.src} -> {ip.dst}:{tcp.dport}")
            print(f"[DEBUG] Updated syn_to_synack: {dict(syn_to_synack)}")


def sniff_packets():
    """
    Function to run sniffing in a separate thread.
    """
    print("[*] Starting packet sniffing...")
    sniff(filter="tcp", prn=monitor_packets, store=False, timeout=0.1)


def check_thresholds():
    """
    Function to check thresholds for SYN flood detection and block offending IPs.
    """
    global blocked_ips

    print(f"[DEBUG] Checking thresholds...")
    print(f"[DEBUG] Current syn_to_synack state: {dict(syn_to_synack)}")
    print(f"[DEBUG] Current blocked IPs: {blocked_ips}")

    # Check SYN to SYN-ACK ratio
    for key, counts in syn_to_synack.items():
        syn_count, synack_count = counts
        print(f"[DEBUG] Evaluating key: {key}, SYN count: {syn_count}, SYN-ACK count: {synack_count}")
        
        if synack_count == 0 or (syn_count / synack_count) > SYN_SYNACK_RATIO_THRESHOLD:
            print(f"[ALERT] High SYN/SYN-ACK ratio for {key}: {syn_count}/{synack_count}")
            src_ip = key[0]  # Extract the source IP from the key
            print(f"[DEBUG] src_ip extracted: {src_ip}")
            print(f"[DEBUG] Checking if {src_ip} is already blocked...")
            if src_ip not in blocked_ips:  # Block the source IP based on the ratio
                print(f"[ACTION] Blocking IP: {src_ip}")
                blocked_ips.add(src_ip)  # Block the IP
                time.sleep(0.1)
            else:
                print(f"[DEBUG] {src_ip} is already blocked.")


if __name__ == "__main__":
    print("[*] Starting SYN flood detection with enhanced debugging...")
    try:
        # Start sniffing in a separate thread
        sniff_thread = threading.Thread(target=sniff_packets, daemon=True)
        sniff_thread.start()

        # Run the threshold checking loop
        while True:
            time.sleep(CHECK_INTERVAL)
            print("running treshold loop...")
            check_thresholds()
    except KeyboardInterrupt:
        print("\n[!] Stopping SYN flood detection.")
