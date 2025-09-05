#!/bin/bash
# RIGHT VM: WireGuard + dummy for tunnel testing
# Usage:
#   sudo ./wg_vm_right.sh up
#   sudo ./wg_vm_right.sh iperf-server
#   sudo ./wg_vm_right.sh iperf-client  # runs client toward LEFT's dummy
#   sudo ./wg_vm_right.sh down
set -euo pipefail

# ---------- EDIT THESE ----------
PEER_ENDPOINT="10.0.2.8:51821"   # LEFT VM's reachable underlay IP:port (UDP)
LISTEN_PORT=51921                  # RIGHT WG listen port
# --------------------------------

WG_IF="wg1r"
WG_ADDR="192.168.1.2/32"

DUM_IF="dum0r"
DUM_IP="10.20.10.10/24"
DUM_HOST="10.20.10.10"

PEER_SUBNET="10.10.10.0/24"        # LEFT dummy subnet
SELF_SUBNET="10.20.10.0/24"        # RIGHT dummy subnet

KEY_PRIV="private_right0"
KEY_PUB="pubright0"
PEER_PUB_FILE="publeft0"     # <-- copy RIGHT's pubkey here (from right.pub)
     # <-- copy RIGHT's pubkey here (from right.pub)

copy() {
  sudo modprobe -r wireguard
  sudo install -D -m 644 "/home/m/wireguard.ko"  /lib/modules/$(uname -r)/extra/wireguard.ko
  sudo insmod /lib/modules/$(uname -r)/extra/wireguard.ko
  sudo modprobe libchacha20poly1305
  sudo modprobe libcurve25519
  sudo modprobe udp_tunnel
  sudo modprobe ip6_udp_tunnel
  sudo modprobe curve25519-x86_64
  sudo modprobe libcurve25519-generic
  sudo modprobe libchacha20poly1305
  sudo modprobe udp_tunnel
  sudo modprobe ip6_udp_tunnel
  sudo modprobe chacha20poly1305
  sudo modprobe gcm
  sudo modprobe aes_generic
  sudo modprobe aesni_intel
  sudo modprobe af_alg
  sudo insmod /lib/modules/$(uname -r)/extra/wireguard.ko
}

ensure_keys() {
  umask 077
  [[ -f "$KEY_PRIV" ]] || wg genkey > "$KEY_PRIV"
  wg pubkey < "$KEY_PRIV" > "$KEY_PUB"
  if [[ ! -f "$PEER_PUB_FILE" ]]; then
    echo ">> Missing $PEER_PUB_FILE"
    echo "   1) Run LEFT VM script to generate left.pub"
    echo "   2) Copy left.pub to RIGHT VM as $PEER_PUB_FILE"
    echo "   3) Re-run: sudo ./wg_vm_right.sh up"
    exit 1
  fi
}

rp_off() {
  for IF in "$WG_IF" "$DUM_IF"; do
    sysctl -w "net.ipv4.conf.${IF}.rp_filter=0" >/dev/null || true
  done
}

up() {
  ensure_keys

  # WireGuard iface
  ip link add "$WG_IF" type wireguard 2>/dev/null|| true
  ip addr add "$WG_ADDR" dev "$WG_IF" 2>/dev/null || true
  ip link set "$WG_IF" up
  wg set "$WG_IF" private-key "$KEY_PRIV"
  ip link set "$WG_IF" mtu 1380
  wg set "$WG_IF" listen-port "$LISTEN_PORT"

  # Dummy iface (app endpoint)
  ip link add "$DUM_IF" type dummy 2>/dev/null || true
  ip addr add "$DUM_IP" dev "$DUM_IF" 2>/dev/null || true
  ip link set "$DUM_IF" up

  # Peer config
  PEER_PUB="$(cat "$PEER_PUB_FILE")"
  wg set "$WG_IF" \
    peer "$PEER_PUB" \
    allowed-ips "$PEER_SUBNET" \
    endpoint "$PEER_ENDPOINT" \
    persistent-keepalive 5

  # Explicit overlay route (idempotent)
  ip route replace "$PEER_SUBNET" dev "$WG_IF"

  rp_off

  echo "== RIGHT UP =="
  wg show "$WG_IF"
  ip route get 10.10.10.10 || true
}

down() {
  # remove overlay route
  ip route del "$PEER_SUBNET" dev "$WG_IF" 2>/dev/null || true

  # tear down ifaces
  ip link del "$WG_IF" 2>/dev/null || true
  ip link del "$DUM_IF" 2>/dev/null || true

  echo "== RIGHT DOWN =="
}

iperf_server() {
  copy
  up
  echo 1 > sudo tee /sys/kernel/debug/wireguard/wg0/zk_require_proof
  echo "Starting iperf3 server on $DUM_HOST"
  iperf3 -s -B "$DUM_HOST" --forceflush --interval 1
}

iperf_client() {
  copy
  up
  echo 0 > sudo tee /sys/kernel/debug/wireguard/wg0/zk_require_proof
  # Talk to LEFT dummy from RIGHT dummy; ensure LEFT has server running
  echo "Running iperf3 client: src=$DUM_HOST dst=10.10.10.10"
  iperf3 -c 10.10.10.10 -B "$DUM_HOST" -t 20 -P 1 -M 1310 --interval 1
}



case "${1:-}" in
  up) up ;;
  down) down ;;
  iperf-server) iperf_server ;;
  iperf-client) iperf_client ;;
  *) echo "usage: $0 {up|down|iperf-server|iperf-client}"; exit 1 ;;
esac
