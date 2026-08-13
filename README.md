# Educational Python & Scapy Firewall Prototype

An educational network security prototype designed to demonstrate software-defined packet filtering concepts using Python 3 and the Scapy packet manipulation engine. The system operates by dynamically parsing Layer 3 (IPv4) and Layer 4 (TCP/UDP/ICMP) headers, running them against a decoupled ruleset, and writing an audit trail to disk.

## Target Architecture

Network Traffic -> Scapy Sniff Engine -> Header Extraction -> JSON Rule Matching Engine -> Decision (ALLOW/BLOCK) -> Persistent Log Generation

## Project Files
* `firewall.py`: Core application containing the sniffer loop, dynamic evaluation engine, and persistent logging mechanics.
* `rules.json`: Decoupled firewall configuration file defining explicit blocking rules and the system default policy.
* `inspect_packets.py`: Foundational network data inspection diagnostic script.
* `firewall.log`: Automated, persistent runtime audit trail log.

## Verification & Testing
The system was validated within a controlled virtual testbed across two distinct vectors:
1. **Explicit Rule Matching (BLOCK)**: Enforced a drop condition on ICMP echo traffic explicitly sourced from/directed to targeted lab endpoints.
2. **Default Fallback Logic (ALLOW)**: Allowed miscellaneous web communication (HTTP port 80) and DNS traffic to pass via the default fallback configuration policy.

## Operational Constraints & Disclaimer
This software is intended as an educational prototype for network security validation. It operates as a passive network traffic engine and does not alter system kernel-level iptables or routing entries. It should not be used as a replacement for enterprise-grade firewalls.
