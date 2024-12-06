from scapy.all import *
from collections import defaultdict
import time

# Data structures
syn_to_synack = defaultdict(lambda: [0, 0])  # SYN to SYN-ACK ratio tracker
syn_rate = defaultdict(int)  # SYN packet rate per source IP
flag_tracker = defaultdict(lambda: {"syn_rate_flag": False, "syn_ratio_flag": False})  # Tracks flags for each IP
blocked_ips = set()  # Blocked IPs

# Thresholds
SYN_SYNACK_RATIO_THRESHOLD = 3  # Lower ratio for easier detection during testing
SYN_RATE_THRESHOLD = 5  # Very low threshold for SYN rate (testing only)
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
            syn_rate[ip.src] += 1
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

    # Check SYN rate and reset counter
    for ip, count in syn_rate.items():
        if count > SYN_RATE_THRESHOLD:
            print(f"[ALERT] High SYN rate detected for {ip} ({count} SYNs/sec)")
            flag_tracker[ip]["syn_rate_flag"] = True  # Set the SYN rate flag
        else:
            flag_tracker[ip]["syn_rate_flag"] = False  # Reset the flag if not met
    syn_rate.clear()  # Reset SYN rate counter

    # Check SYN to SYN-ACK ratio
    for key, counts in syn_to_synack.items():
        syn_count, synack_count = counts
        if synack_count == 0 or (syn_count / synack_count) > SYN_SYNACK_RATIO_THRESHOLD:
            print(f"[ALERT] High SYN/SYN-ACK ratio for {key}: {syn_count}/{synack_count}")
            flag_tracker[key[0]]["syn_ratio_flag"] = True  # Set the SYN ratio flag
        else:
            flag_tracker[key[0]]["syn_ratio_flag"] = False  # Reset the flag if not met

    # Block IPs if both flags are true
    for ip, flags in flag_tracker.items():
        if flags["syn_rate_flag"] and flags["syn_ratio_flag"] and ip not in blocked_ips:
            print(f"[ACTION] Blocking IP: {ip}")
            blocked_ips.add(ip)  # Block the IP

    # Log current blocked IPs
    if blocked_ips:
        print(f"[INFO] Currently blocked IPs: {blocked_ips}")


if __name__ == "__main__":
    print("[*] Starting SYN flood detection with dual-flag logic...")
    try:
        # Start packet sniffing in the background
        sniff(filter="tcp", prn=monitor_packets, store=False, timeout=CHECK_INTERVAL)
        while True:
            time.sleep(CHECK_INTERVAL)
            check_thresholds()
    except KeyboardInterrupt:
        print("\n[!] Stopping SYN flood detection.")
