from scapy.all import *
from collections import defaultdict
import threading
import time
import sys

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
        print("f{ip.type}")

        # If the source IP is blocked, drop the packet
        if ip.src in blocked_ips:
            print(f"[BLOCKED] Dropping packet from {ip.src}", flush=True)
            return

        # Track SYN packets
        if tcp.flags == "S":
            syn_to_synack[(ip.src, tcp.dport)][0] += 1  # Increment SYN count
            time.sleep(0.01)  # Artificial delay for debugging
            print(f"[INFO_DEBUG] SYN packet tracked: {ip.src} -> {ip.dst}:{tcp.dport}", flush=True)
            print(f"[INFO_DEBUG] Updated syn_to_synack: {dict(syn_to_synack)}", file=sys.stderr)


        # Track SYN-ACK packets
        if tcp.flags == "SA":
            syn_to_synack[(ip.src, tcp.sport)][1] += 1  # Increment SYN-ACK count
            time.sleep(0.01)  # Artificial delay for debugging
            print(f"[INFO_DEBUG] SYN-ACK packet tracked: {ip.src} -> {ip.dst}:{tcp.dport}", flush=True)
            print(f"[INFO_DEBUG] Updated syn_to_synack: {dict(syn_to_synack)}", file=sys.stderr)


def sniff_packets():
    """
    Function to run sniffing in a separate thread.
    """
    print("[*] Starting packet sniffing...", flush=True)
    sniff(filter="tcp", prn=monitor_packets, store=False, timeout=0.1)


def check_thresholds():
    """
    Function to check thresholds for SYN flood detection and block offending IPs.
    """
    global blocked_ips

    print(f"[INFO_DEBUG] Checking thresholds...", flush=True)
    print(f"[INFO_DEBUG] Current syn_to_synack state: {dict(syn_to_synack)}", file=sys.stderr)
    print(f"[INFO_DEBUG] Current blocked IPs: {blocked_ips}", flush=True)

    # Check SYN to SYN-ACK ratio
    for key, counts in syn_to_synack.items():
        syn_count, synack_count = counts
        print(f"[INFO_DEBUG] Evaluating key: {key}, SYN count: {syn_count}, SYN-ACK count: {synack_count}", flush=True)
        
        if synack_count == 0 or (syn_count / synack_count) > SYN_SYNACK_RATIO_THRESHOLD:
            print(f"[ALERT] High SYN/SYN-ACK ratio for {key}: {syn_count}/{synack_count}", flush=True)
            src_ip = key[0]  # Extract the source IP from the key
            print(f"[INFO_DEBUG] src_ip extracted: {src_ip}", flush=True)
            print(f"[INFO_DEBUG] Checking if {src_ip} is already blocked...", flush=True)
            if src_ip not in blocked_ips:  # Block the source IP based on the ratio
                print(f"[ACTION] Blocking IP: {src_ip}", flush=True)
                blocked_ips.add(src_ip)  # Block the IP
                time.sleep(0.1)
            else:
                print(f"[INFO_DEBUG] {src_ip} is already blocked.", flush=True)


if __name__ == "__main__":
    print("[*] Starting SYN flood detection with enhanced debugging...", flush=True)
    try:
        # Start sniffing in a separate thread
        sniff_thread = threading.Thread(target=sniff_packets, daemon=True)
        sniff_thread.start()

        # Run the threshold checking loop
        while True:
            time.sleep(CHECK_INTERVAL)
            print("[INFO_DEBUG] running threshold loop...", flush=True)
            check_thresholds()
    except KeyboardInterrupt:
        print("\n[!] Stopping SYN flood detection.", flush=True)
