from scapy.all import *
from collections import defaultdict
import threading
import time

# Data structures
blocked_ips = []  # List to store blocked IPs
SYN_SYNACK_RATIO_THRESHOLD = 3  # Lower ratio for easier detection during testing
CHECK_INTERVAL = 1  # Interval in seconds to check thresholds
syn_to_synack = defaultdict(lambda: [0, 0])  # Default value: [SYN count, SYN-ACK count]


def send_rst(src_ip, dst_ip, sport, dport):
    """
    Send a TCP RST packet to terminate the connection.
    """
    rst_packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="R")
    send(rst_packet, verbose=False)
    print(f"[ACTION] Sent RST packet: {src_ip}:{sport} -> {dst_ip}:{dport}")


def monitor_packets(packet):
    """
    Function to process sniffed packets and update tracking data.
    """
    global blocked_ips

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        ip = packet[IP]

        # If the source IP is blocked, send RST packets and drop the packet
        if ip.src in blocked_ips:
            print(f"[BLOCKED] Dropping packet from {ip.src}", flush=True)
            # Send RST to the client
            send_rst("192.168.1.1", ip.src, tcp.dport, tcp.sport)
            # Send RST to the server
            send_rst(ip.src, ip.dst, tcp.sport, tcp.dport)
            return

        # Track SYN packets
        if tcp.flags == "S":
            syn_to_synack[ip.src][0] += 1  # Increment SYN count
            print(f"[INFO] SYN packet tracked: {ip.src} -> {ip.dst}:{tcp.dport}", flush=True)
            print(f"[INFO] Updated syn_to_synack: {dict(syn_to_synack)}", flush=True)

        # Track SYN-ACK packets
        if tcp.flags == "SA":
            syn_to_synack[ip.src][1] += 1  # Increment SYN-ACK count
            print(f"[INFO] SYN-ACK packet tracked: {ip.src} -> {ip.dst}:{tcp.dport}", flush=True)
            print(f"[INFO] Updated syn_to_synack: {dict(syn_to_synack)}", flush=True)


def check_thresholds():
    """
    Function to check thresholds for SYN flood detection and block offending IPs.
    """
    global blocked_ips

    print(f"[INFO] Checking thresholds...", flush=True)
    print(f"[INFO] Current syn_to_synack state: {dict(syn_to_synack)}", flush=True)
    print(f"[INFO] Current blocked IPs: {blocked_ips}", flush=True)

    # Check SYN to SYN-ACK ratio
    for src_ip, counts in syn_to_synack.items():
        syn_count, synack_count = counts

        print(f"[INFO] Evaluating IP: {src_ip}, SYN count: {syn_count}, SYN-ACK count: {synack_count}", flush=True)

        if synack_count == 0 or (syn_count / synack_count) > SYN_SYNACK_RATIO_THRESHOLD:
            print(f"[ALERT] High SYN/SYN-ACK ratio for {src_ip}: {syn_count}/{synack_count}", flush=True)

            if src_ip not in blocked_ips:
                print(f"[ACTION] Blocking IP: {src_ip}", flush=True)
                blocked_ips.append(src_ip)  # Append to list
            else:
                print(f"[INFO] {src_ip} is already blocked.", flush=True)


if __name__ == "__main__":
    """
    Main script execution: Start the sniffing thread and continuously check thresholds.
    """
    sniff_thread = threading.Thread(
        target=lambda: sniff(filter="tcp", prn=monitor_packets, store=False), daemon=True
    )
    sniff_thread.start()  # Start the sniffing thread
    while True:
        check_thresholds()  # Check thresholds periodically
        time.sleep(CHECK_INTERVAL)  # Wait before rechecking
