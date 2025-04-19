#!/bin/bash
set -euo pipefail

EASYRSA_DIR="${OPENVPN_DIR}/easy-rsa"
SERVER_CONF="${SECRET_DIR}/server.conf"
SERVER_TMPL_CONF="${CONFIG_DIR}/server.conf"

echo "[INFO] Starting OpenVPN server update process..."

echo "[INFO] Generating ${SERVER_CONF} from template…"
envsubst < "${SERVER_TMPL_CONF}" > "${SERVER_CONF}"

echo "[INFO] Resetting all iptables rules…"
iptables -F             || true
iptables -t nat -F      || true
iptables -t mangle -F   || true
iptables -X             || true
iptables -t nat -X      || true
iptables -t mangle -X   || true
echo "[INFO] iptables flush complete."

echo "[INFO] Applying iptables rules for all push \"route …\" entries…"
# Parse every push "route TARGET MASK" line

if grep -q '^push "route ' "${SERVER_CONF}"; then
  while read -r _ _ target mask _; do
    mask=${mask%\"}
    if [[ $target =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      dest="$target"
    else
      dest=$(getent ahostsv4 "$target" \
        | awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $1; exit}')

      if [[ -z "$dest" ]]; then
        echo "[WARN] Could not resolve IPv4 for ${target}, skipping"
        continue
      fi
    fi

    # Insert logging rules
    iptables -I INPUT   -i tun0 -d "$dest" -m comment --comment "VPN-TRAFFIC" \
            -j LOG --log-prefix "VPN-TRAFFIC: " \
      || echo "[WARN] Failed to insert INPUT rule for $dest"
    iptables -I FORWARD -i tun0 -d "$dest" -m comment --comment "VPN-TRAFFIC" \
            -j LOG --log-prefix "VPN-TRAFFIC: " \
      || echo "[WARN] Failed to insert FORWARD rule for $dest"
    # Add masquerade for split-tunnel traffic
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -d "$dest" -o eth0 \
            -j MASQUERADE \
      || echo "[WARN] Failed to add NAT rule for $dest"
  done < <(grep '^push "route ' "${SERVER_CONF}")
else
  echo "[INFO] No push \"route …\" entries found; skipping iptables."
fi

echo "[INFO] iptables rules updated."

# Reload OpenVPN server if running
if [ -f /var/run/openvpn.pid ]; then
  kill -HUP "$(cat /var/run/openvpn.pid)"
  echo "[INFO] OpenVPN configuration reloaded."
fi
