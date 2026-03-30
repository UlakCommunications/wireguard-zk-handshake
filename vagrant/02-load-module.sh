#!/bin/bash
# Load the pre-built wireguard.ko (compiled on host for 6.8.0-59-generic).
set -euo pipefail

KERNEL="6.8.0-59-generic"
KO="/vagrant/wireguard-6.8/wireguard.ko"

echo "==> Kernel: $(uname -r)"
if [ "$(uname -r)" != "$KERNEL" ]; then
    echo "ERROR: expected kernel $KERNEL but running $(uname -r)"
    echo "       The pre-built wireguard.ko will not load on a different kernel."
    exit 1
fi

if [ ! -f "$KO" ]; then
    echo "ERROR: $KO not found."
    echo "       Build it on the host first:"
    echo "         cd wireguard-6.8"
    echo "         make -C /lib/modules/${KERNEL}/build M=\$(pwd) modules"
    exit 1
fi

# Remove stock wireguard if loaded
rmmod wireguard 2>/dev/null || true

# Load dependencies (order matters)
for mod in libchacha20poly1305 libcurve25519 udp_tunnel ip6_udp_tunnel \
           curve25519-x86_64 libcurve25519-generic chacha20poly1305 \
           gcm aes_generic aesni_intel af_alg; do
    modprobe "$mod" 2>/dev/null || true
done

# Install and load our module
install -D -m 644 "$KO" /lib/modules/${KERNEL}/extra/wireguard.ko
insmod /lib/modules/${KERNEL}/extra/wireguard.ko

# Verify wgzk genl family is registered
if grep -q wgzk /proc/net/genetlink; then
    echo "==> wireguard.ko loaded OK — wgzk genl family registered"
    grep wgzk /proc/net/genetlink
else
    echo "ERROR: wireguard.ko loaded but wgzk genl family not found in /proc/net/genetlink"
    exit 1
fi
