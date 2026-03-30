#!/bin/bash
# Install exact kernel version required by the pre-built wireguard.ko.
# Vagrant reboots automatically after this script (reboot: true in Vagrantfile).
set -euo pipefail

KERNEL="6.8.0-59-generic"

echo "==> Current kernel: $(uname -r)"
if [ "$(uname -r)" = "$KERNEL" ]; then
    echo "==> Already on $KERNEL, skipping."
    exit 0
fi

echo "==> Installing kernel $KERNEL"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y \
    linux-image-${KERNEL} \
    linux-modules-${KERNEL} \
    linux-modules-extra-${KERNEL} \
    wireguard-tools \
    iproute2 \
    iputils-ping

# Ubuntu GRUB uses predictable submenu/entry names.
# "1>N" syntax: 1 = "Advanced options for Ubuntu" submenu, N = entry index.
# After update-grub, find the non-recovery entry index for our kernel.
update-grub 2>/dev/null || true

NTH=$(awk '/menuentry.*'"${KERNEL}"'/{if($0 !~ /recovery/){print NR; exit}}' \
      /boot/grub/grub.cfg 2>/dev/null || echo "")
TOTAL=$(grep -c 'menuentry ' /boot/grub/grub.cfg 2>/dev/null || echo "0")

# Count position inside the Advanced submenu (0-based)
SUBMENU_POS=$(awk '
  /submenu.*Advanced options/{ in_sub=1; pos=0; next }
  in_sub && /menuentry.*'"${KERNEL}"'/ && !/recovery/ { print pos; exit }
  in_sub && /menuentry / { pos++ }
' /boot/grub/grub.cfg 2>/dev/null || echo "")

if [ -n "$SUBMENU_POS" ]; then
    GRUB_ENTRY="1>${SUBMENU_POS}"
else
    # Fallback to full name (Ubuntu standard, works in most cases)
    GRUB_ENTRY="Advanced options for Ubuntu>Ubuntu, with Linux ${KERNEL}"
fi

sed -i "s|^GRUB_DEFAULT=.*|GRUB_DEFAULT=\"${GRUB_ENTRY}\"|" /etc/default/grub
update-grub

echo "==> GRUB_DEFAULT set to: $GRUB_ENTRY"
echo "==> Kernel $KERNEL installed. Vagrant will reboot now."
