from scapy.all import *

def tcp_server():
    server_ip = "192.168.2.2"  # h2's IP address
    server_port = 12345  # Port for the server to listen on

    print(f"[*] Starting TCP server on {server_ip}:{server_port}...")

    # Sniff incoming packets to simulate TCP server
    def handle_packet(packet):
        if packet.haslayer(TCP) and packet[TCP].dport == server_port:
            if packet.haslayer(Raw):  # Ensure there's a payload
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
            else:
                payload = ""
            
            print(f"[+] Received data: {payload}")
            
            # Send back an acknowledgment
            response_data = "ACK: " + payload
            response = IP(dst=packet[IP].src) / TCP(
                dport=packet[TCP].sport,
                sport=server_port,
                flags="PA",
                seq=packet[TCP].ack,
                ack=packet[TCP].seq + len(packet[Raw].load) if packet.haslayer(Raw) else 1
            ) / response_data
            send(response, verbose=False)
            print(f"[+] Sent response: {response_data}")
    
    sniff(filter=f"tcp port {server_port}", prn=handle_packet)

if __name__ == "__main__":
    tcp_server()
