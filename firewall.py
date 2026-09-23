import json
import os
import sys
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_addr


RULES_FILE = "rules.json"
LOG_FILE = "firewall.log"
INTERFACE = "eth0"


def load_rules():
    """Load firewall rules once at startup."""
    if not os.path.exists(RULES_FILE):
        raise FileNotFoundError(f"{RULES_FILE} not found.")

    with open(RULES_FILE, "r") as file:
        config = json.load(file)

    rules = config.get("rules", [])
    default_policy = config.get("default_policy", "ALLOW").upper()

    if default_policy not in ("ALLOW", "BLOCK"):
        raise ValueError("default_policy must be ALLOW or BLOCK.")

    return rules, default_policy


def inspect_packet(packet):
    """
    Extract Layer 3 and Layer 4 information from an IP packet.
    """
    if IP not in packet:
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = "UNKNOWN"
    src_port = "N/A"
    dst_port = "N/A"

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    elif ICMP in packet:
        protocol = "ICMP"

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
    }


def determine_direction(packet_info, local_ip):
    """
    Determine whether the packet is entering or leaving this host.
    """
    if packet_info["src_ip"] == local_ip:
        return "OUTPUT"

    if packet_info["dst_ip"] == local_ip:
        return "INPUT"

    return "OTHER"


def rule_matches(rule, packet_info, direction):
    """
    Check whether a rule matches the inspected packet.

    IP matching follows the same directional model used by nftables:
    INPUT  -> source IP
    OUTPUT -> destination IP
    """

    rule_ip = str(rule.get("ip", "any"))
    rule_protocol = str(rule.get("protocol", "any")).upper()
    rule_port = str(rule.get("port", "any"))

    src_ip = packet_info["src_ip"]
    dst_ip = packet_info["dst_ip"]
    protocol = packet_info["protocol"]
    dst_port = packet_info["dst_port"]

    # IP matching
    if rule_ip != "any":
        if direction == "INPUT":
            if src_ip != rule_ip:
                return False

        elif direction == "OUTPUT":
            if dst_ip != rule_ip:
                return False

        else:
            return False

    # Protocol matching
    if rule_protocol != "ANY" and protocol != rule_protocol:
        return False

    # Port matching
    if rule_port not in ("any", "ANY", "N/A"):
        if protocol not in ("TCP", "UDP"):
            return False

        if str(dst_port) != rule_port:
            return False

    return True


def evaluate_packet(packet_info, rules, default_policy, direction):
    """
    Evaluate a packet using first-match-wins rule processing.
    """
    for rule in rules:
        if rule_matches(rule, packet_info, direction):
            return (
                str(rule.get("action", default_policy)).upper(),
                str(rule.get("rule_id", "UNKNOWN")),
                str(rule.get("description", "")),
            )

    return default_policy, "DEFAULT", "No matching rule"


def write_log(packet_info, direction, action, rule_id, description):
    """
    Write a structured firewall decision to firewall.log.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_line = (
        f"[{timestamp}] "
        f"DIRECTION={direction} | "
        f"ACTION={action} | "
        f"RULE_ID={rule_id} | "
        f"PROTO={packet_info['protocol']} | "
        f"SRC={packet_info['src_ip']}:{packet_info['src_port']} | "
        f"DST={packet_info['dst_ip']}:{packet_info['dst_port']} | "
        f"DESCRIPTION={description}\n"
    )

    with open(LOG_FILE, "a") as file:
        file.write(log_line)


def process_packet(packet, rules, default_policy, local_ip):
    """
    Inspect, evaluate and log a captured packet.

    Actual packet enforcement is handled separately by nftables.
    """
    packet_info = inspect_packet(packet)

    if packet_info is None:
        return

    direction = determine_direction(packet_info, local_ip)

    if direction == "OTHER":
        return

    action, rule_id, description = evaluate_packet(
        packet_info,
        rules,
        default_policy,
        direction,
    )

    timestamp = datetime.now().strftime("%H:%M:%S")

    print(
        f"[{timestamp}] "
        f"[{direction}] "
        f"[{action}] "
        f"Rule={rule_id} | "
        f"{packet_info['protocol']} "
        f"{packet_info['src_ip']}:{packet_info['src_port']} -> "
        f"{packet_info['dst_ip']}:{packet_info['dst_port']}"
    )

    write_log(
        packet_info,
        direction,
        action,
        rule_id,
        description,
    )


def main():
    print("========== PYFIREWALL ==========")
    print("[*] Starting Python packet inspection engine")
    print(f"[*] Interface: {INTERFACE}")

    try:
        rules, default_policy = load_rules()
        local_ip = get_if_addr(INTERFACE)

        if local_ip == "0.0.0.0":
            raise RuntimeError(
                f"No IPv4 address detected on interface {INTERFACE}."
            )

        print(f"[*] Local IP: {local_ip}")
        print(f"[*] Rules loaded: {len(rules)}")
        print(f"[*] Default policy: {default_policy}")
        print("[*] Enforcement: nftables")
        print("[*] Capture filter: IPv4 traffic")
        print("[*] Press Ctrl+C to stop.")
        print("================================\n")

        sniff(
            iface=INTERFACE,
            filter="ip",
            prn=lambda packet: process_packet(
                packet,
                rules,
                default_policy,
                local_ip,
            ),
            store=False,
        )

    except KeyboardInterrupt:
        print("\n[*] Firewall inspection stopped safely.")

    except Exception as error:
        print(f"[-] Error: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
