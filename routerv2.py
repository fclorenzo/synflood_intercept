from scapy.all import *
import threading

blocked_ips = []
SYN_SYNACK_RATIO_THRESHOLD = 3  # Lower ratio for easier detection during testing
CHECK_INTERVAL = 1  # Interval in seconds to check thresholds
syn_to_synack = {}  # Dictionary to store each host ip and it's syn count and syn-ack ratio


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
            print(f"[BLOCKED] Dropping packet from {ip.src}", flush=True)
            return

        # Track SYN packets
        if tcp.flags == "S":
            syn_to_synack[ip.src][0] += 1  # Increment SYN count
            print(
                f"[info] SYN packet tracked: {ip.src} -> {ip.dst}:{tcp.dport}",
                flush=True,
            )
            print(
                f"[info] Updated syn_to_synack: {dict(syn_to_synack)}", file=sys.stderr
            )

        # Track SYN-ACK packets
        if tcp.flags == "SA":
            syn_to_synack[ip.src][1] += 1  # Increment SYN-ACK count
            print(
                f"[info] SYN-ACK packet tracked: {ip.src} -> {ip.dst}:{tcp.dport}",
                flush=True,
            )
            print(
                f"[info] Updated syn_to_synack: {dict(syn_to_synack)}", file=sys.stderr
            )


def check_thresholds():
    """
    Function to check thresholds for SYN flood detection and block offending IPs.
    """
    global blocked_ips

    print(f"[info] Checking thresholds...", flush=True)
    print(f"[info] Current syn_to_synack state: {dict(syn_to_synack)}", file=sys.stderr)
    print(f"[info] Current blocked IPs: {blocked_ips}", flush=True)

    # Check SYN to SYN-ACK ratio
    for key, counts in syn_to_synack.items():
        syn_count, synack_count = counts

        print(
            f"[info] Evaluating key: {key}, SYN count: {syn_count}, SYN-ACK count: {synack_count}",
            flush=True,
        )

        if synack_count == 0 or (syn_count / synack_count) > SYN_SYNACK_RATIO_THRESHOLD:
            print(
                f"[ALERT] High SYN/SYN-ACK ratio for {key}: {syn_count}/{synack_count}",
                flush=True,
            )
            src_ip = key[0]  # Extract the source IP from the key
            print(f"[info] src_ip extracted: {src_ip}", flush=True)
            print(f"[info] Checking if {src_ip} is already blocked...", flush=True)

            if src_ip not in blocked_ips:
                print(f"[ACTION] Blocking IP: {src_ip}", flush=True)
                blocked_ips.add(src_ip)  # Block the IP
                time.sleep(0.1)
            else:
                print(f"[info] {src_ip} is already blocked.", flush=True)


if __name__ == "__main__":
    sniff_thread = threading.Thread(
        target=sniff(filter="tcp", prn=monitor_packets, store=False), daemon=True
    )
    sniff_thread.start
    while True:
        check_thresholds()
