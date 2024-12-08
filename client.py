from scapy.all import *
import threading
import time

server_ip = "192.168.2.2"  # Server IP address
server_port = 12345  # Server port


def send_legit_tcp_connections():
    """
    Function to send legitimate TCP connections to the server.
    """
    print("[*] Starting legit TCP connection sender...")

    while True:
        try:
            # Step 1: Send SYN packet to initiate connection
            seq = random.randint(1000, 9000)  # Random initial sequence number
            syn = IP(dst=server_ip) / TCP(sport=1234, dport=server_port, flags="S", seq=seq)
            syn_ack = sr1(syn, verbose=False, timeout=1)

            if syn_ack and syn_ack.haslayer(TCP) and syn_ack[TCP].flags == "SA":
                # Step 2: Send ACK packet to complete the handshake
                ack = IP(dst=server_ip) / TCP(sport=1234, dport=server_port, flags="A",
                                              seq=syn_ack.ack, ack=syn_ack.seq + 1)
                send(ack, verbose=False)

                print("[INFO] Legitimate connection established.")

                # Step 3: Gracefully terminate the connection with FIN
                fin = IP(dst=server_ip) / TCP(sport=1234, dport=server_port, flags="FA",
                                              seq=ack.seq + 1, ack=ack.ack)
                fin_ack = sr1(fin, verbose=False, timeout=1)

                if fin_ack and fin_ack.haslayer(TCP) and fin_ack[TCP].flags == "FA":
                    # Send final ACK to complete termination
                    final_ack = IP(dst=server_ip) / TCP(sport=1234, dport=server_port, flags="A",
                                                        seq=fin_ack.ack, ack=fin_ack.seq + 1)
                    send(final_ack, verbose=False)
                    print("[INFO] Connection terminated gracefully.")

            time.sleep(1)  # Wait before sending the next connection
        except Exception as e:
            print(f"[ERROR] Error sending legitimate connection: {e}")


def sniff_rst_packets():
    """
    Sniff for RST packets and log their details.
    """
    print("[*] Starting RST packet sniffer...")

    def handle_packet(packet):
        if packet.haslayer(TCP) and packet[TCP].flags == "R":
            print(f"[RST] RST packet detected: {packet[IP].src} -> {packet[IP].dst}:{packet[TCP].dport}")

    # Sniff packets with the TCP RST flag set
    sniff(filter="tcp[tcpflags] & tcp-rst != 0", prn=handle_packet, store=False)


if __name__ == "__main__":
    # Start RST sniffer in a separate thread
    rst_sniffer_thread = threading.Thread(target=sniff_rst_packets, daemon=True)
    rst_sniffer_thread.start()

    # Send legitimate TCP connections
    send_legit_tcp_connections()
