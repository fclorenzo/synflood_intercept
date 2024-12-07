from scapy.all import *
from collections import defaultdict
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
            syn_to_synack[(ip.dst, tcp.dport)][0] += 1  # Increment SYN count
            print(f"[INFO] SYN from {ip.src} to {ip.dst}:{tcp.dport}")

        # Track SYN-ACK packets
        if tcp.flags == "SA":
            syn_to_synack[(ip.src, tcp.sport)][1] += 1  # Increment SYN-ACK count
            print(f"[INFO] SYN-ACK from {ip.src} to {ip.dst}:{tcp.dport}")


def check_thresholds():
    """
    Function to check thresholds for SYN flood detection and block offending IPs.
    """
    global blocked_ips

    # Check SYN to SYN-ACK ratio
    for key, counts in syn_to_synack.items():
        syn_count, synack_count = counts
        if synack_count == 0 or (syn_count / synack_count) > SYN_SYNACK_RATIO_THRESHOLD:
            print(f"[ALERT] High SYN/SYN-ACK ratio for {key}: {syn_count}/{synack_count}")
            #if key[0] not in blocked_ips:  # Block the source IP based on destination ratio
            print(f"[ACTION] Blocking IP: {key[0]}")
            blocked_ips.add(key[0])  # Block the IP

    # Log current blocked IPs
    if blocked_ips:
        print(f"[INFO] Currently blocked IPs: {blocked_ips}")


if __name__ == "__main__":
    print("[*] Starting SYN flood detection using only SYN/SYN-ACK ratio...")
    try:
        # Start packet sniffing in the background
        sniff(filter="tcp", prn=monitor_packets, store=False, timeout=CHECK_INTERVAL)
        while True:
            time.sleep(CHECK_INTERVAL)
            check_thresholds()
    except KeyboardInterrupt:
        print("\n[!] Stopping SYN flood detection.")
