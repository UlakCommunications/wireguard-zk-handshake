#!/bin/bash
# Provision the GATEWAY (RIGHT) VM.
# Env vars from Vagrantfile: PEER_IP (client's underlay IP)
set -euo pipefail

PEER_IP="${PEER_IP:-192.168.100.2}"
KEYS_DIR="/vagrant/vagrant/keys"
DAEMON="/vagrant/userspace/wg-zk-daemon/target/release/wg-zk-daemon"

mkdir -p "$KEYS_DIR"

# ── WireGuard keys ────────────────────────────────────────────────────────────
WG_PRIV="/etc/wireguard/private_right"
WG_PUB="$KEYS_DIR/pubright"
umask 077
mkdir -p /etc/wireguard
wg genkey > "$WG_PRIV"
wg pubkey < "$WG_PRIV" > "$WG_PUB"
echo "==> WireGuard public key (gateway): $(cat $WG_PUB)"

# ── ZK keys (generate once, client will read) ─────────────────────────────────
ZK_ENV="$KEYS_DIR/zk.env"
if [ ! -f "$ZK_ENV" ]; then
    GEN_PK="/vagrant/userspace/gen-pk/target/release/gen-pk"
    if [ ! -f "$GEN_PK" ]; then
        echo "ERROR: $GEN_PK not found. Build it: cd userspace/gen-pk && cargo build --release"
        exit 1
    fi
    "$GEN_PK" | grep -E "WGZK_(SK|PK)_HEX" > "$ZK_ENV"
    echo "==> ZK key pair generated: $ZK_ENV"
fi
source "$ZK_ENV"

# ── WireGuard interface (wait for client pubkey) ───────────────────────────────
echo "==> Waiting for client public key at $KEYS_DIR/publeft ..."
for i in $(seq 1 60); do
    [ -f "$KEYS_DIR/publeft" ] && break
    sleep 2
done
[ -f "$KEYS_DIR/publeft" ] || { echo "ERROR: client pubkey not found after 120s"; exit 1; }

ip link add wg1r type wireguard 2>/dev/null || true
ip addr add 192.168.1.2/32 dev wg1r 2>/dev/null || true
ip link set wg1r up
wg set wg1r private-key "$WG_PRIV" listen-port 51921
ip link set wg1r mtu 1380
wg set wg1r \
    peer "$(cat $KEYS_DIR/publeft)" \
    allowed-ips 10.10.10.0/24 \
    endpoint "${PEER_IP}:51821" \
    persistent-keepalive 5
ip route replace 10.10.10.0/24 dev wg1r

# ── Dummy interface ───────────────────────────────────────────────────────────
ip link add dum0r type dummy 2>/dev/null || true
ip addr add 10.20.10.10/24 dev dum0r 2>/dev/null || true
ip link set dum0r up

# ── rp_filter ─────────────────────────────────────────────────────────────────
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
sysctl -w net.ipv4.conf.wg1r.rp_filter=0 >/dev/null || true
sysctl -w net.ipv4.conf.dum0r.rp_filter=0 >/dev/null || true

# ── Daemon ────────────────────────────────────────────────────────────────────
if [ ! -f "$DAEMON" ]; then
    echo "ERROR: $DAEMON not found. Build it: cd userspace/wg-zk-daemon && cargo build --release"
    exit 1
fi
chmod +x "$DAEMON"
cat > /etc/wgzk-gateway.env <<EOF
WGZK_MODE=gateway
WGZK_PK_HEX=${WGZK_PK_HEX}
EOF

cat > /etc/systemd/system/wgzk.service <<EOF
[Unit]
Description=WireGuard ZK Daemon (gateway)
After=network.target

[Service]
EnvironmentFile=/etc/wgzk-gateway.env
ExecStart=${DAEMON}
Restart=on-failure
RestartSec=1

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wgzk
systemctl start wgzk
sleep 2
systemctl is-active wgzk && echo "==> wgzk daemon running (gateway)" || {
    journalctl -u wgzk --no-pager -n 20
    exit 1
}

echo "==> Gateway provisioning complete"
wg show wg1r
