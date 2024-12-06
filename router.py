from scapy.all import *
from collections import defaultdict
import time

# Data structures
syn_to_synack = defaultdict(lambda: [0, 0])  # SYN to SYN-ACK ratio tracker
syn_rate = defaultdict(int)  # SYN packet rate per source IP
half_open = defaultdict(int)  # Half-open connections per source IP
blocked_ips = set()  # Blocked IPs

# Thresholds
SYN_SYNACK_RATIO_THRESHOLD = 5  # SYNs to SYN-ACKs
SYN_RATE_THRESHOLD = 100  # SYNs per second per source IP
HALF_OPEN_THRESHOLD = 50  # Half-open connections per source IP
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

        # Count SYN packets
        if tcp.flags == "S":
            syn_rate[ip.src] += 1
            syn_to_synack[(ip.dst, tcp.dport)][0] += 1  # Increment SYN count
            half_open[(ip.src, tcp.dport)] += 1  # Increment half-open count

        # Count SYN-ACK packets
        if tcp.flags == "SA":
            syn_to_synack[(ip.src, tcp.sport)][1] += 1  # Increment SYN-ACK count

        # Count ACK packets to close connections
        if tcp.flags == "A":
            if (ip.src, tcp.sport) in half_open:
                half_open[(ip.src, tcp.sport)] -= 1  # Decrement half-open count


def check_thresholds():
    """
    Function to check thresholds for SYN flood detection and block offending IPs.
    """
    global blocked_ips

    # Check SYN rate and reset counter
    for ip, count in syn_rate.items():
        if count > SYN_RATE_THRESHOLD:
            print(f"[ALERT] High SYN rate detected for {ip} ({count} SYNs/sec)")

    syn_rate.clear()  # Reset SYN rate counter

    # Check SYN to SYN-ACK ratio
    for key, counts in syn_to_synack.items():
        syn_count, synack_count = counts
        if synack_count == 0 or (syn_count / synack_count) > SYN_SYNACK_RATIO_THRESHOLD:
            print(f"[ALERT] High SYN/SYN-ACK ratio for {key}: {syn_count}/{synack_count}")

    # Check half-open connections
    for (ip, port), count in half_open.items():
        if count > HALF_OPEN_THRESHOLD:
            print(f"[ALERT] High half-open connections for {ip}:{port} ({count} connections)")
            if ip not in blocked_ips:
                print(f"[ACTION] Blocking IP: {ip}")
                blocked_ips.add(ip)  # Add IP to blocked list

    # Log current blocked IPs
    if blocked_ips:
        print(f"[INFO] Currently blocked IPs: {blocked_ips}")


if __name__ == "__main__":
    print("[*] Starting SYN flood detection...")
    try:
        # Start packet sniffing in the background
        sniff(filter="tcp", prn=monitor_packets, store=False, timeout=CHECK_INTERVAL)
        while True:
            time.sleep(CHECK_INTERVAL)
            check_thresholds()
    except KeyboardInterrupt:
        print("\n[!] Stopping SYN flood detection.")
