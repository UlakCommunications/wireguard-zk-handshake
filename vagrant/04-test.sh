#!/bin/bash
# End-to-end test: ping from client dummy (10.10.10.10) to gateway dummy (10.20.10.10)
# Runs on the CLIENT VM after provisioning.
set -euo pipefail

echo ""
echo "══════════════════════════════════════════════════════"
echo "  WireGuard ZK Handshake — End-to-End Test"
echo "══════════════════════════════════════════════════════"

# Give daemons a moment to settle
sleep 3

echo ""
echo "── Ping test (5 packets) ────────────────────────────"
ping -I 10.10.10.10 10.20.10.10 -c 5 -W 5

echo ""
echo "── Client daemon log ────────────────────────────────"
journalctl -u wgzk --no-pager -n 20

echo ""
echo "── WireGuard status ─────────────────────────────────"
wg show wg1l

echo ""
echo "══════════════════════════════════════════════════════"
echo "  TEST PASSED — Schnorr++ ZK tunnel working"
echo "══════════════════════════════════════════════════════"
