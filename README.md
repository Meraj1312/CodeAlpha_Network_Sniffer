# CodeAlpha Network Sniffer

## Overview
This project is a Python-based **network packet sniffer** developed as part of the CodeAlpha cybersecurity internship tasks.  
The tool captures and analyzes live network traffic to understand how data flows across a network at the packet level.

It is designed **strictly for educational and ethical purposes**, focusing on traffic inspection, protocol analysis, and packet structure awareness.

---

## Key Concepts Covered
- Packet sniffing and traffic analysis
- TCP/IP protocol stack
- Network-layer vs transport-layer data
- Raw payload inspection
- Ethical use of packet capture tools

---

## Features
- IP-based filtering
- Port-based filtering
- Protocol filtering (HTTP / DNS)
- PCAP export for Wireshark analysis
- Command-line argument handling
- Plaintext credential pattern detection
- Suspicious port highlighting
- Encrypted vs unencrypted traffic comparison
- MITM attack explanation (theory only)


## Technologies Used
- Python 3
- Scapy library
- TCP / UDP / IP protocols

---

## Features
- Captures live network packets
- Displays source & destination IP addresses
- Identifies TCP and UDP traffic
- Extracts and previews raw packet payloads
- Lightweight and terminal-based

---

## How to Run

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Run the Sniffer (Requires Admin Privileges)
```bash
sudo python sniffer.py
```

---

## Sample Output
```
[+] New Packet
    Source IP      : 192.168.1.5
    Destination IP : 142.250.183.78
    Protocol       : TCP
    TCP Sport      : 51532
    TCP Dport      : 443
```

---

## Disclaimer
This project is intended **only for learning and authorized testing**.  
Capturing network traffic without permission is illegal and unethical.

The author is **not responsible for misuse** of this tool.

---

## What I Learned
- How packet sniffers work internally
- Real-world packet structures
- Limitations and risks of plaintext traffic
- Why encryption (HTTPS, TLS) is critical

---

## Author
**Mohammad Meraj**  
Aspiring Penetration Tester  
GitHub: https://github.com/Meraj1312
