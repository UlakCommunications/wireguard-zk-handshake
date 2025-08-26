#!/bin/bash
# test_generic_no_ns.sh
# Usage: sudo ./test_generic_no_ns.sh <cnt>
# Example: sudo ./test_generic_no_ns.sh 1

set -euo pipefail
set -x

cnt="${1:?usage: $0 <cnt>}"

# ---- names & addressing ----
leftveth="veth${cnt}_1"
rightveth="veth${cnt}_2"

# Underlay (point-to-point /30 carried by the veth pair)
u_left="10.255.${cnt}.1/30"
u_right="10.255.${cnt}.2/30"
u_left_ip="10.255.${cnt}.1"
u_right_ip="10.255.${cnt}.2"

# WireGuard iface names
wg_left="wg$((cnt+1))l"
wg_right="wg$((cnt+1))r"

# Optional overlay IPs on wg ifaces (not strictly needed for the test)
wg_left_ip="192.168.$((cnt+1)).$((cnt+1))/24"
wg_right_ip="192.168.$((cnt+1)).$((cnt+2))/24"

# Dummy subnets we’ll use as “application” endpoints over the WG tunnel
dum_left="dum${cnt}l"
dum_right="dum${cnt}r"
dum_left_ip="10.10.$((cnt+10)).10/24"
dum_right_ip="10.20.$((cnt+10)).10/24"
dum_left_ip_host="10.10.$((cnt+10)).10"
dum_right_ip_host="10.20.$((cnt+10)).10"

# Ports (two distinct to avoid accidental reuse)
port_left=$((51820 + cnt + 1))   # right peer will dial this
port_right=$((51920 + cnt + 1))  # left peer will dial this

# ---- helpers ----
cleanup() {
  set +e
  # stop iperf3 server if running
  pkill -f "iperf3 -s -B ${dum_left_ip_host}" || true

  # tear down wg ifaces
  ip link del "${wg_left}" 2>/dev/null || true
  ip link del "${wg_right}" 2>/dev/null || true

  # tear down dummy ifaces
  ip link del "${dum_left}" 2>/dev/null || true
  ip link del "${dum_right}" 2>/dev/null || true

  # tear down veth
  ip link del "${leftveth}" 2>/dev/null || true

  # (keys left on disk by design; uncomment if you want auto-delete)
  # rm -f "private_left${cnt}" "private_right${cnt}" "publeft${cnt}" "pubright${cnt}" 2>/dev/null || true
}
trap cleanup EXIT

wait_for_iperf() {
  # wait until iperf3 server has bound to the port
  for _ in $(seq 1 50); do
    ss -lntp | grep -q "iperf3" && return 0
    sleep 0.1
  done
  return 1
}

# ---- key material ----
umask 077
if [[ ! -f "private_left${cnt}" ]]; then wg genkey > "private_left${cnt}"; fi
if [[ ! -f "private_right${cnt}" ]]; then wg genkey > "private_right${cnt}"; fi
wg pubkey < "private_left${cnt}"  > "publeft${cnt}"
wg pubkey < "private_right${cnt}" > "pubright${cnt}"
pbl_left="$(cat "publeft${cnt}")"
pbl_right="$(cat "pubright${cnt}")"

# ---- underlay: veth point-to-point ----
ip link add "${leftveth}" type veth peer name "${rightveth}"
ip addr add "${u_left}"  dev "${leftveth}"
ip addr add "${u_right}" dev "${rightveth}"
ip link set "${leftveth}" up
ip link set "${rightveth}" up

# sanity: ensure underlay routes go via veth, not wg
ip r get "${u_right_ip}" >/dev/null
ip r get "${u_left_ip}"  >/dev/null

# ---- left side WG ----
ip link add dev "${wg_left}" type wireguard
ip addr add "${wg_left_ip}" dev "${wg_left}" || true
ip link set "${wg_left}" up
wg set "${wg_left}" private-key "private_left${cnt}"

# left “app” iface
ip link add "${dum_left}" type dummy
ip addr add "${dum_left_ip}" dev "${dum_left}"
ip link set "${dum_left}" up

# Route only the RIGHT dummy subnet through the tunnel (not default!)
# AllowedIPs on the peer will install these routes automatically in most setups,
# but we keep it narrow either way.
wg set "${wg_left}" \
  listen-port "${port_left}" \
  peer "${pbl_right}" \
  allowed-ips "10.20.$((cnt+10)).0/24" \
  endpoint "${u_right_ip}:${port_right}" \
  persistent-keepalive 5

# ---- right side WG ----
ip link add dev "${wg_right}" type wireguard
ip addr add "${wg_right_ip}" dev "${wg_right}" || true
ip link set "${wg_right}" up
wg set "${wg_right}" private-key "private_right${cnt}"

# right “app” iface
ip link add "${dum_right}" type dummy
ip addr add "${dum_right_ip}" dev "${dum_right}"
ip link set "${dum_right}" up

wg set "${wg_right}" \
  listen-port "${port_right}" \
  peer "${pbl_left}" \
  allowed-ips "10.10.$((cnt+10)).0/24" \
  endpoint "${u_left_ip}:${port_left}" \
  persistent-keepalive 5

# ---- quick checks ----
wg show "${wg_left}"
wg show "${wg_right}"

# give handshake a moment
sleep $((cnt+3))

# test connectivity over the overlay (dummy↔dummy)
ping -c 1 "${dum_left_ip_host}" -I "${dum_right_ip_host}"

# ---- iperf test ----
iperf3 -s -B "${dum_left_ip_host}" --forceflush --interval 1 2>&1 | tee "output_receive_${cnt}.txt" &
wait_for_iperf
iperf3 -c "${dum_left_ip_host}" -B "${dum_right_ip_host}" -t 10 -P 1 -M 1310 --interval 1 2>&1 | tee "output_send_${cnt}.txt"
