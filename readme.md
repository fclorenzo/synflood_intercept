# README

## **SYN Flood Detection and Prevention System**

This repository contains a computer networks assignment project for detecting and mitigating SYN flood attacks at the network level using a custom Python implementation. The system is designed to run on a router configured in a Mininet topology and provides functionality to block malicious traffic while allowing legitimate connections to pass.

---

### **Table of Contents**

1. [Introduction](#1-introduction)  
2. [Implemented Features](#2-implemented-features)  
3. [System Requirements](#3-system-requirements)  
4. [How to Run](#4-how-to-run)  
5. [Configuration Parameters](#5-configuration-parameters)  
6. [Statistics and Performance](#6-statistics-and-performance)  
7. [Known Issues and Limitations](#7-known-issues-and-limitations)  
8. [Credits](#8-credits)  

---

### **1. Introduction**

A **SYN flood attack** is a type of denial-of-service (DoS) attack that exploits the TCP three-way handshake by overwhelming a server with a high number of incomplete connection requests. This attack can exhaust server resources, making it unable to handle legitimate traffic (see <https://en.wikipedia.org/wiki/SYN_flood>).

This project aims to detect and prevent SYN flood attacks at the network level by implementing a router-based mitigation system. The system operates in a Mininet-emulated topology and uses Scapy to analyze TCP traffic. By tracking packet behavior and employing dynamic IP blocking, the system effectively mitigates SYN flood attacks while maintaining the integrity of legitimate connections.

---

### **2. Implemented Features**

1. **Router Script** (`router.py`):  
   - Monitors TCP traffic for potential SYN flood attacks.  
   - Tracks SYN and SYN-ACK packets for each source IP.  
   - Resets counts for legitimate connections when an ACK packet is received.  
   - Blocks malicious IPs that exceed a predefined SYN-to-SYN-ACK ratio threshold.  
   - Sends TCP RST packets to terminate malicious connections.  

2. **SYN Flood Attack Script** (`synflood.py`):  
   - Simulates a SYN flood attack by continuously sending SYN packets to the server.  

3. **Legitimate TCP Client Script** (`client.py`):  
   - Sends legitimate TCP connections to the server using the proper three-way handshake and gracefully terminates the connection.  

4. **Server Script** (`server.py`):  
   - Hosts a simple TCP server to respond to incoming connections.  

5. **RST Packet Sniffer**:  
   - Integrated into the scripts to monitor for RST packets and validate the router's behavior.  

6. **Mininet Topology Script** (`topo.py`):  
   - Configures a Mininet topology with a router (`r1`) and two hosts (`h1` and `h2`) connected via the router.

---

### **3. System Requirements**

- **Python**: Version 3.6 or higher.  
- **Scapy**: A Python library for packet manipulation. Install using:  

  ```bash
  pip install scapy
  ```  

- **Mininet**: A network emulation tool. Download the virtual machine image at:  
  <https://github.com/mininet/mininet/releases/>  

- **Virtualization Software**:  
  - Install software such as VirtualBox to run the Mininet virtual machine:  
    <https://www.virtualbox.org/wiki/Downloads>  

- **Root Privileges**:  
  - Required to execute the router and attack scripts since they interact with the network stack.  

---

### **4. How to Run**

1. **Clone the Repository**:  
   Navigate to the `custom` folder inside the Mininet VM and clone this repository:  

   ```bash
   cd /home/mininet/mininet/custom
   git clone https://github.com/fclorenzo/synflood_intercept.git
   ```

2. **Set Up Mininet Topology**:  
   Launch the topology using the provided `topo.py` script:  

   ```bash
   sudo python3 topo.py
   ```

3. **Start the TCP Server**:  
   On `h2`, run the `server.py` script:  

   ```bash
   h2 python3 server.py
   ```

4. **Simulate a SYN Flood Attack**:  
   On `h1`, run the `synflood.py` script to launch a SYN flood attack:  

   ```bash
   h1 python3 synflood.py
   ```

5. **Optional: Run the Legitimate TCP Connections Script Instead of the SYN Flood Script**:  
   On `h1`, run the `client.py` script to send legitimate TCP connections:  

   ```bash
   h1 python3 client.py
   ```

6. **Run the Router Script**:  
   On `r1`, run the `router.py` script to detect SYN floods:  

   ```bash
   r1 python3 router.py
   ```

7. **Monitor Logs**:  
   - Observe the output on the router (`r1`) to see alerts, blocked IPs, and RST packet handling.  
   - Recommended: Redirect the output of each script to a file to observe the outputs of the different scripts after exiting the Mininet CLI or use xterm:  
     <https://mininet.org/walkthrough/#xterm-display-1>  

---

### **5. Configuration Parameters**

The following parameters can be adjusted in `router.py` to fine-tune the detection system:

#### **SYN-to-SYN-ACK Ratio Threshold**

Defines the maximum ratio of SYN to SYN-ACK packets before an IP is flagged as malicious:

```python
SYN_SYNACK_RATIO_THRESHOLD = 3
```

#### **Check Interval**

Specifies how frequently the router evaluates SYN flood patterns:

```python
CHECK_INTERVAL = 1
```

---

### **6. Statistics and Performance**

#### **Methodology**

1. **Setup**:
   - A Mininet topology was configured with a router (`r1`), attacker (`h1`), and server (`h2`).
   - Scripts were run to simulate both SYN flood attacks and legitimate traffic.
   - The simulations were run by a fixed time period of 1 minute and a total of 5 times.
   - Average values were extracted to measure the statistics.

2. **Traffic Capture**:
   - Traffic was captured using `tcpdump` and analyzed using `tshark` to measure:
     - Number of RST packets generated by the router.
     - Total SYN packets sent during the test.
     - Total network traffic volume.

3. **Performance Metrics**:
   - **RST-to-SYN Ratio**: Measures how many RST packets are generated per SYN packet.
   - **Bandwidth Overhead**: Percentage of total network traffic generated by RST packets.

#### **Findings**

1. **RST-to-SYN Ratio**:
   - The router generated ~2.87 RST packets for each SYN packet during the test period.

2. **Bandwidth Overhead**:
   - **63.1%** of the total bandwidth was consumed by RST packets, indicating a significant impact on network traffic.

3. **Total Traffic Analysis**:
   - **RST Packets**: 411
   - **SYN Packets**: 143
   - **RST Traffic Volume**: 28 KB (out of 45 KB total traffic)

#### **Conclusion**

The system effectively detects and blocks malicious SYN flood traffic but incurs a high bandwidth overhead due to the RST packet generation strategy. This trade-off is suitable for testing environments but not for real-world deployment.

---

### **7. Known Issues and Limitations**

1. **Out-of-Order Packets**:
   - SYN and SYN-ACK packets arriving out of order may temporarily increase the SYN-to-SYN-ACK ratio, potentially causing false positives.

2. **Legitimate High SYN Traffic**:
   - Applications with high connection rates (e.g., load testing tools) may inadvertently be flagged as malicious.

3. **Advanced SYN Flood Techniques**:
   - This implementation does not detect sophisticated SYN flood attacks that complete the three-way handshake (e.g., ACK flooding).

4. **Mininet Emulation**:
   - The system assumes the topology and routing rules provided by Mininet. Real-world networks may require additional adjustments.

5. **Sending of Reset TCP Packets**:
   - The choice to send TCP packets with the reset flag was made for simplicity, as it avoids modifying system configurations (e.g., iptables). It also makes observing the implementation's behavior straightforward by tracking RST packets. However, this solution is unsuitable for real-world scenarios because it generates additional network traffic and processing overhead for the router.

---

### **8. Credits**

This project uses the following tools and technologies:

1. **Scapy**:
   - A Python library for crafting and analyzing network packets.
   - Documentation: <https://scapy.readthedocs.io/>

2. **Mininet**:
   - A tool for creating virtual networks for development and testing.
   - Documentation: <https://mininet.org/>

3. **VirtualBox**:
   - A virtualization platform for running the Mininet VM.
   - Download: <https://www.virtualbox.org/>

Special thanks to the open-source community for the tools that made this project possible.
