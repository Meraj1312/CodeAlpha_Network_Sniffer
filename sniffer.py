import argparse
from scapy.all import sniff, IP, TCP, UDP, Raw, wrpcap
from datetime import datetime

SUSPICIOUS_PORTS = [21, 23, 25, 53, 110, 143, 445]
captured_packets = []

def detect_credentials(payload):
    keywords = ["username", "user", "password", "pass", "login"]
    payload_lower = payload.lower()
    return any(keyword in payload_lower for keyword in keywords)

def process_packet(packet, args):
    if packet.haslayer(IP):
        ip = packet(IP)
        if args.ip and args.ip not in (ip.src, ip.dst):
            return
        
        proto = "OTHER"

        if packet.haslayer(TCP):
            proto = "TCP"
            port = packet(TCP).dport
        elif packet.haslayer(UDP):
            proto = "UDP"
            port = packet(UDP).dport
        else:
            port = None

        if args.port and port != args.port:
            return
        if args.protocol:
            if args.protocol == "http" and port not in [80, 8080]:
                return
            if args.protocol == "dns" and port != 53:
                return
            
        print ("\n[+]  Packet captured")
        print (f"{ip.src} -> {ip.dst} | {proto}")

        if port:
            alert = " ❗" if port in SUSPICIOUS_PORTS else ""
            print (f" Port: {port}{alert}")

        if packet.haslayer[Raw]:
            payload = packet[Raw].load.decode(errors="ignore")

        if detect_credentials(payload):
            print ("    🔴 Possible Plain Text Credentials Detected")
            
        encrypted = "YES" if port == 443 else "NO"
        print (f"    Encrypted traffic: {encrypted}")

        if args.pcap:
            captured_packets.append(packet)

def main():
    parser = argparse.ArgumentParser(description="Network Sniffer")
    parser.add_argument("--ip", help="Filter by IP")
    parser.add_argument("--port", type=int, help="Filter by Port")
    parser.add_argument("--protocol", choices=["http", "dns"], help="Protocol Filter")
    parser.add_argument("--pcap", action="store_true", help="Save packet in PCAP")

    args = parser.parse_args()

    print("[+] Starting NETWORK SNIFFER")
    print("Press Ctrl + C to stop")

    try:
        sniff(prn=lambda pkt: process_packet(pkt, args), store=False)
    except KeyboardInterrupt:
        if args.pcap and captured_packets:
            filename = f"captures/traffic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
            wrpcap(filename, captured_packets)
            print(f"\n[+]PCAP saved to {filename}")

if __name__ == "__main__":
    main()

