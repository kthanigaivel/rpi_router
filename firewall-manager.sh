#!/bin/bash
# Raspberry Pi Router - Strict Whitelist Firewall Manager

# Interfaces
LAN_IF="eth0"
WAN_IF="eth1"

# Arguments
ACTION=$1
TYPE=$2   # f=forward, o=output
PROTO=$3
PORT=$4
IP=$5

rule_exists() {
    iptables -C "$@" &>/dev/null
}

load_rules() {
    iptables -F
    iptables -t nat -F
    iptables -X

    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP

    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # Allow SSH from LAN
    iptables -A INPUT -i $LAN_IF -p tcp --dport 22 -j ACCEPT

    # DHCP (Client <-> Server)
    iptables -A INPUT  -i $LAN_IF -p udp --dport 67 --sport 68 -j ACCEPT
    iptables -A OUTPUT -o $LAN_IF -p udp --sport 67 --dport 68 -j ACCEPT

    # DNS
    iptables -A INPUT  -i $LAN_IF -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

    # NTP
    iptables -A OUTPUT -p udp --dport 123 -j ACCEPT

    # Pi → WAN Web
    iptables -A OUTPUT -p tcp -m multiport --dports 80,443 -j ACCEPT

    # Connection tracking
    iptables -A INPUT   -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Default FORWARD whitelist
    iptables -A FORWARD -i $LAN_IF -o $WAN_IF -p udp --dport 53 -j ACCEPT
    iptables -A FORWARD -i $LAN_IF -o $WAN_IF -p tcp --dport 53 -j ACCEPT
    iptables -A FORWARD -i $LAN_IF -o $WAN_IF -p udp --dport 123 -j ACCEPT
    iptables -A FORWARD -i $LAN_IF -o $WAN_IF -p tcp -m multiport --dports 80,443 -j ACCEPT
    iptables -A FORWARD -i $LAN_IF -o $WAN_IF -p tcp -m multiport --dports 587,465,993,995 -j ACCEPT
    iptables -A FORWARD -i $LAN_IF -o $WAN_IF -p udp -m multiport --dports 3478,5349 -j ACCEPT
    iptables -A FORWARD -i $LAN_IF -o $WAN_IF -p tcp -m multiport --dports 5222,5228,5242 -j ACCEPT

    # NEW: Allow ephemeral UDP ports 1024–65535 (LAN → WAN)
    iptables -A FORWARD -i $LAN_IF -o $WAN_IF -p tcp --dport 1024:65535 -j ACCEPT

    # NAT Masquerade
    iptables -t nat -A POSTROUTING -o $WAN_IF -j MASQUERADE

    # Logging & final drops
    iptables -A FORWARD -i $LAN_IF -j LOG --log-prefix "BLOCKED-LAN: "
    iptables -A FORWARD -i $LAN_IF -j DROP
    iptables -A OUTPUT -j LOG --log-prefix "BLOCKED-PI: "
    iptables -A OUTPUT -j DROP

    # ICMP (ping, limited)
    iptables -A INPUT  -p icmp --icmp-type echo-request -m limit --limit 10/s -j ACCEPT
    iptables -A OUTPUT -p icmp --icmp-type echo-request -m limit --limit 10/s -j ACCEPT

    echo "✅ Whitelist rules loaded."
}

add_rule() {
    if [[ "$TYPE" == "f" ]]; then
        RULE=(-i $LAN_IF -o $WAN_IF -p $PROTO --dport $PORT)
        [[ -n "$IP" ]] && RULE=(-s $IP "${RULE[@]}")
        if rule_exists FORWARD "${RULE[@]}" -j ACCEPT; then
            echo "⚠ Rule already exists."
        else
            iptables -I FORWARD 1 "${RULE[@]}" -j ACCEPT
            echo "✅ Forward rule added."
        fi
    elif [[ "$TYPE" == "o" ]]; then
        RULE=(-p $PROTO --dport $PORT)
        if rule_exists OUTPUT "${RULE[@]}" -j ACCEPT; then
            echo "⚠ Rule already exists."
        else
            iptables -I OUTPUT 1 "${RULE[@]}" -j ACCEPT
            echo "✅ Output rule added."
        fi
    else
        echo "❌ Invalid type. Use f=forward, o=output"
    fi
}

remove_rule() {
    if [[ "$TYPE" == "f" ]]; then
        RULE=(-i $LAN_IF -o $WAN_IF -p $PROTO --dport $PORT)
        [[ -n "$IP" ]] && RULE=(-s $IP "${RULE[@]}")
        if rule_exists FORWARD "${RULE[@]}" -j ACCEPT; then
            iptables -D FORWARD "${RULE[@]}" -j ACCEPT
            echo "🗑 Forward rule removed."
        else
            echo "⚠ Rule not found."
        fi
    elif [[ "$TYPE" == "o" ]]; then
        RULE=(-p $PROTO --dport $PORT)
        if rule_exists OUTPUT "${RULE[@]}" -j ACCEPT; then
            iptables -D OUTPUT "${RULE[@]}" -j ACCEPT
            echo "🗑 Output rule removed."
        else
            echo "⚠ Rule not found."
        fi
    else
        echo "❌ Invalid type. Use f=forward, o=output"
    fi
}

list_rules() {
    echo "==========================================="
    echo " Whitelisted LAN → WAN Rules (FORWARD)"
    echo "==========================================="
    iptables -L FORWARD -n --line-numbers | grep "ACCEPT" | grep -v "ESTABLISHED"

    echo
    echo "==========================================="
    echo " Whitelisted Pi → WAN Rules (OUTPUT)"
    echo "==========================================="
    iptables -L OUTPUT -n --line-numbers | grep "ACCEPT" | grep -v "ESTABLISHED"

    echo
    echo "==========================================="
    echo " Active NAT (POSTROUTING)"
    echo "==========================================="
    iptables -t nat -L POSTROUTING -n --line-numbers | grep "MASQUERADE"
}

save_rules() {
    iptables-save > /etc/iptables/rules.v4
    echo "💾 Rules saved to /etc/iptables/rules.v4"
}

restore_rules() {
    if [[ -f /etc/iptables/rules.v4 ]]; then
        iptables-restore < /etc/iptables/rules.v4
        echo "♻️ Rules restored from /etc/iptables/rules.v4"
    else
        echo "⚠ No saved rules found."
    fi
}

case "$ACTION" in
    load)    load_rules ;;
    add)     add_rule ;;
    remove)  remove_rule ;;
    list)    list_rules ;;
    save)    save_rules ;;
    restore) restore_rules ;;
    *)
        echo "Usage:"
        echo "  $0 load                      # Load default whitelist rules"
        echo "  $0 add f tcp 80 [ip]          # Add FORWARD rule (LAN→WAN)"
        echo "  $0 add o tcp 80               # Add OUTPUT rule (Pi→WAN)"
        echo "  $0 remove f tcp 80 [ip]       # Remove FORWARD rule"
        echo "  $0 remove o tcp 80            # Remove OUTPUT rule"
        echo "  $0 list                       # List current rules"
        echo "  $0 save                       # Save current rules"
        echo "  $0 restore                    # Restore saved rules"
        ;;
esac
