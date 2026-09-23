
import subprocess
import sys
import json

TABLE_FAMILY = "inet"
TABLE_NAME = "pyfirewall"

def load_rules():
    """Load firewall rules from rules.json."""
    with open("rules.json", "r") as file:
        return json.load(file)

def run_nft(*args):
    """Run an nft command and return its output."""
    result = subprocess.run(
        ["sudo", "nft", *args],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"[-] nftables error: {result.stderr.strip()}", file=sys.stderr)
        return False

    return True


def clear_firewall():
    """Remove the firewall table if it already exists."""
    subprocess.run(
        ["sudo", "nft", "delete", "table", TABLE_FAMILY, TABLE_NAME],
        capture_output=True,
        text=True
    )

    print("[+] Existing pyfirewall table cleared.")


def create_firewall():
    """Create the base nftables firewall table and chains."""

    if not run_nft("add", "table", TABLE_FAMILY, TABLE_NAME):
        return False

    if not run_nft(
        "add", "chain", TABLE_FAMILY, TABLE_NAME, "input",
        "{ type filter hook input priority 0; policy accept; }"
    ):
        return False

    if not run_nft(
        "add", "chain", TABLE_FAMILY, TABLE_NAME, "output",
        "{ type filter hook output priority 0; policy accept; }"
    ):
        return False

    print("[+] nftables firewall table created.")
    print("[+] INPUT chain created.")
    print("[+] OUTPUT chain created.")

    return True

def install_block_rules(config):
    """Install BLOCK rules from rules.json into nftables."""
    for rule in config.get("rules", []):
        if rule.get("action", "").upper() != "BLOCK":
            continue

        rule_id = rule["rule_id"]
        ip = rule["ip"]
        protocol = rule["protocol"].upper()
        port = rule["port"]

        # Build INPUT rule
        input_args = ["add", "rule", TABLE_FAMILY, TABLE_NAME, "input"]

        if ip != "any":
            input_args += ["ip", "saddr", ip]

        if protocol == "TCP":
            input_args += ["tcp"]
        elif protocol == "UDP":
            input_args += ["udp"]
        elif protocol == "ICMP":
            input_args += ["ip", "protocol", "icmp"]

        if port not in ("any", "N/A") and protocol in ("TCP", "UDP"):
            input_args += ["dport", str(port)]

        input_args += ["counter", "drop"]

        if not run_nft(*input_args):
            print(f"[-] Failed to install INPUT rule {rule_id}")
            return False

        # Build OUTPUT rule
        output_args = ["add", "rule", TABLE_FAMILY, TABLE_NAME, "output"]

        if ip != "any":
            output_args += ["ip", "daddr", ip]

        if protocol == "TCP":
            output_args += ["tcp"]
        elif protocol == "UDP":
            output_args += ["udp"]
        elif protocol == "ICMP":
            output_args += ["ip", "protocol", "icmp"]

        if port not in ("any", "N/A") and protocol in ("TCP", "UDP"):
            output_args += ["dport", str(port)]

        output_args += ["counter", "drop"]

        if not run_nft(*output_args):
            print(f"[-] Failed to install OUTPUT rule {rule_id}")
            return False

        print(f"[+] Installed BLOCK rule {rule_id}")

    return True

def show_firewall():
    """Display the current pyfirewall nftables configuration."""
    result = subprocess.run(
        ["sudo", "nft", "list", "table", TABLE_FAMILY, TABLE_NAME],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("[-] pyfirewall table does not exist.")
        return

    print("\n========== PYFIREWALL NFTABLES ==========")
    print(result.stdout)
    print("==========================================")


if __name__ == "__main__":
    print("[*] Testing nftables controller...")

    clear_firewall()

    if create_firewall():
        config = load_rules()

        if install_block_rules(config):
            show_firewall()
            print("[+] Firewall rules installed successfully.")
        else:
            print("[-] Failed to install firewall rules.")
    else:
        print("[-] Failed to create firewall.")
