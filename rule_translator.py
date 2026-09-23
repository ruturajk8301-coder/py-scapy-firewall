import json

RULES_FILE = "rules.json"


def load_rules():
    """Load firewall rules from rules.json."""
    with open(RULES_FILE, "r") as file:
        return json.load(file)


def build_match_parts(rule, direction):
    """
    Build the nftables match expression for a rule.

    INPUT:
        IP rules match source addresses.

    OUTPUT:
        IP rules match destination addresses.
    """

    ip = rule.get("ip", "any")
    protocol = str(rule.get("protocol", "any")).upper()
    port = str(rule.get("port", "any"))

    parts = []

    if ip != "any":
        if direction == "INPUT":
            parts.append(f"ip saddr {ip}")
        else:
            parts.append(f"ip daddr {ip}")

    if protocol != "ANY":
        if protocol == "TCP":
            parts.append("tcp")
        elif protocol == "UDP":
            parts.append("udp")
        elif protocol == "ICMP":
            parts.append("ip protocol icmp")

    if (
        port not in ("any", "ANY", "N/A")
        and protocol in ("TCP", "UDP")
    ):
        parts.append(f"dport {port}")

    return " ".join(parts)


def build_rule_commands(rule):
    """
    Generate human-readable nftables rules for both directions.
    """

    rule_id = rule["rule_id"]
    action = str(rule.get("action", "ALLOW")).lower()

    if action == "block":
        nft_action = "drop"
    elif action == "allow":
        nft_action = "accept"
    else:
        raise ValueError(f"Unknown action: {action}")

    input_match = build_match_parts(rule, "INPUT")
    output_match = build_match_parts(rule, "OUTPUT")

    input_rule = (
        f"INPUT  Rule {rule_id}: "
        f"{input_match} {nft_action}".strip()
    )

    output_rule = (
        f"OUTPUT Rule {rule_id}: "
        f"{output_match} {nft_action}".strip()
    )

    return [input_rule, output_rule]


def main():
    config = load_rules()

    print("\n========== GENERATED NFTABLES RULES ==========\n")

    print(
        f"Default policy: "
        f"{config.get('default_policy', 'ALLOW').upper()}"
    )

    for rule in config.get("rules", []):
        description = rule.get("description", "")

        print(f"\nRule {rule['rule_id']}: {description}")

        for command in build_rule_commands(rule):
            print(f"  {command}")

    print("\n===============================================\n")


if __name__ == "__main__":
    main()
