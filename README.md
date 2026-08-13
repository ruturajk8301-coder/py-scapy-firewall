# 🛡️ Basic Firewall Using Python

A Python-based educational firewall prototype designed to demonstrate **network packet inspection, rule-based traffic filtering, and security logging** using Python and Scapy.

> 🎓 **Project Type:** Cybersecurity Minor Project  
> 🐍 **Language:** Python 3  
> 📡 **Library:** Scapy  
> 🐧 **Environment:** Kali Linux  

## 📌 Overview

A firewall monitors and filters network traffic according to predefined security rules. 

This project implements a simplified firewall which can captures and analyzes the network packets, extracts information such as IP addresses, protocols, and ports, evaluates packets against configured rules, and also generates **ALLOW/BLOCK** decisions.

The project is ONLY intended for educational purposes and demonstrates the basic principles of network packet filtering.

## 🎯 Objectives

* 📡 Capture and inspect network packets using Scapy Library.
* 🔎 It helps in Analyzing IP addresses, protocols, and ports.
* 📋 Define configurable firewall rules.
* ⚙️ Match the packets against predefined rules.
* ✅ Generate ALLOW decisions for permitted traffic.
* 🚫 Generate BLOCK decisions for restricted traffic.
* 📝 Record firewall decisions through logging.
* 🔐 Understand fundamental network security and packet-filtering concepts.

## 🏗️ Architecture

```text
🌐 Network Traffic
        ↓
📡 Scapy Packet Capture
        ↓
🔎 Packet Inspection
        ↓
⚙️ Rule Matching
        ↓
✅ ALLOW / 🚫 BLOCK
        ↓
📝 Event Logging
```

## 📂 Project Files

| File                | Purpose                                     |
| ------------------- | ------------------------------------------- |
| `firewall.py`       | 🛡️ Core firewall and rule-processing logic |
| `inspect_packets.py`| 🔎 Packet inspection and analysis utility   |
| `rules.json`        | 📋 Configurable firewall rules              |
| `README.md`         | 📖 Project documentation                    |
| `.gitignore`        | 🚫 Git-excluded files                       |

## 🧰 Technologies

* 🐍 **Python 3** — Firewall logic and processing
* 📡 **Scapy** — Packet capture and inspection.
* 📋 **JSON** — Firewall rule configuration
* 🐧 **Kali Linux** — Development and testing environment

## 🧪 Testing

The firewall is tested in a controlled environment to verify:

* 📡 Packet capture and inspection
* 📋 Rule matching
* ✅ Allowed traffic
* 🚫 Blocked traffic
* 📝 Logging of firewall decisions
* ⚙️ Default-policy behaviour

## ⚠️ Limitations

This is an **educational firewall prototype**, not a replacement for production or enterprise firewall technologies. 

It focuses on demonstrating the fundamental workflow:

**Packet Capture → Inspection → Rule Matching → Decision → Logging**

## 🔒 Disclaimer

This project is developed strictly for **educational and authorized testing purposes**. Isnt its like Network traffic should only be captured, analyzed, or filtered on systems and networks for which appropriate authorization has been obtained,..

---

### 🚀 Project Status

**Completed & Verified** ✅
