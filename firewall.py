import json
import os
import sys
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP

RULES_FILE = "rules.json"
LOG_FILE = "firewall.log"

def load_rules():
    if not os.path.exists(RULES_FILE):
        print(f"[-] Error: {RULES_FILE} not found!")
        sys.exit(1)
    with open(RULES_FILE, "r") as f:
        return json.load(f)

def write_log(timestamp, src, dst, proto, port, action, rule_id):
    log_line = f"[{timestamp}] ACTION={action} | RULE_ID={rule_id} | PROTO={proto} | SRC={src} -> DST={dst} | PORT={port}\n"
    with open(LOG_FILE, "a") as f:
        f.write(log_line)

def evaluate_packet(packet):
    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto_num = packet[IP].proto
    
    proto_name = "UNKNOWN"
    src_port = "N/A"
    dst_port = "N/A"
    
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

    config = load_rules()
    rules = config.get("rules", [])
    default_policy = config.get("default_policy", "ALLOW")
    
    matched_rule = None
    final_action = default_policy
    rule_id_str = "DEFAULT"

    for rule in rules:
        rule_ip = rule.get("ip")
        rule_proto = rule.get("protocol")
        rule_port = rule.get("port")
        
        ip_match = (rule_ip == "any" or src_ip == rule_ip or dst_ip == rule_ip)
        proto_match = (rule_proto == "any" or proto_name == rule_proto)
        
        port_match = False
        if rule_port == "any" or rule_port == "N/A":
            port_match = True
        elif proto_name in ["TCP", "UDP"]:
            if str(src_port) == str(rule_port) or str(dst_port) == str(rule_port):
                port_match = True

        if ip_match and proto_match and port_match:
            matched_rule = rule
            final_action = rule.get("action")
            rule_id_str = str(rule.get("rule_id"))
            break

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target_port = dst_port if proto_name in ["TCP", "UDP"] else "N/A"
    
    print(f"[{timestamp}] [{final_action}] Proto: {proto_name:<4} | {src_ip} -> {dst_ip} | Port: {target_port} | Rule: {rule_id_str}")
    write_log(timestamp, src_ip, dst_ip, proto_name, target_port, final_action, rule_id_str)

print("[*] Launching Educational Python Firewall Prototype...")
print(f"[*] Monitoring interface: eth0")
print("[*] Press Ctrl+C to terminate.")

try:
    sniff(iface="eth0", filter="ip", prn=evaluate_packet, store=False)
except KeyboardInterrupt:
    print("\n[*] Firewall stopped safely.")
except Exception as e:
    print(f"[-] Critical Error: {e}", file=sys.stderr)
