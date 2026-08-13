import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP

def inspect_packet(packet):
    # We only care about IP packets for our firewall project
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        proto_name = "UNKNOWN"
        src_port = "-"
        dst_port = "-"
        
        # Extract Layer 4 Transport Layer details
        if TCP in packet:
            proto_name = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            proto_name = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            proto_name = "ICMP"
            src_port = "N/A"
            dst_port = "N/A"
            
        print(f"[PACKET] Proto: {proto_name:<5} | Src: {src_ip:<15} ({src_port}) -> Dst: {dst_ip:<15} ({dst_port})")

print("[*] Starting packet inspection on eth0 (Capturing 5 IP packets)...")
try:
    sniff(iface="eth0", filter="ip", prn=inspect_packet, count=5, store=False)
    print("[*] Inspection test complete.")
except Exception as e:
    print(f"[-] Error: {e}", file=sys.stderr)
