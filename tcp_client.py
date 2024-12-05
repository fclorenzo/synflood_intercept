from scapy.all import *
import time

def tcp_client():
    server_ip = "192.168.2.2"  # h2's IP address
    server_port = 12345  # Port to connect to on the server
    client_ip = "192.168.1.2"  # h1's IP address

    print(f"[*] Starting TCP client to {server_ip}:{server_port}...")
    
    # Simulate a TCP handshake
    seq = 1000  # Initial sequence number
    syn = IP(dst=server_ip) / TCP(sport=1234, dport=server_port, flags="S", seq=seq)
    syn_ack = sr1(syn, verbose=False)

    ack = IP(dst=server_ip) / TCP(sport=1234, dport=server_port, flags="A", seq=syn_ack.ack, ack=syn_ack.seq + 1)
    send(ack, verbose=False)
    print("[+] Handshake completed.")
    
    # Send data to the server
    data = "Hello from h1!"
    print(f"[*] Sending data: {data}")
    pkt = IP(dst=server_ip) / TCP(sport=1234, dport=server_port, flags="PA", seq=ack.seq, ack=ack.ack) / data
    response = sr1(pkt, verbose=False)
    
    if response and response.haslayer(TCP):
        print(f"[+] Server response: {bytes(response[TCP].payload).decode('utf-8', errors='ignore')}")
    
    # Close connection
    fin = IP(dst=server_ip) / TCP(sport=1234, dport=server_port, flags="FA", seq=response.ack, ack=response.seq + len(response[TCP].payload))
    send(fin, verbose=False)
    print("[+] Connection closed.")

if __name__ == "__main__":
    tcp_client()
