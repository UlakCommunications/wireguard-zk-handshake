#!/bin/bash
# Install exact kernel version required by the pre-built wireguard.ko.
# Vagrant reboots automatically after this script (reboot: true in Vagrantfile).
set -euo pipefail

KERNEL="6.8.0-59-generic"

echo "==> Current kernel: $(uname -r)"
if [ "$(uname -r)" = "$KERNEL" ]; then
    echo "==> Already on $KERNEL, nothing to do."
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

# Tell GRUB to boot this specific kernel by default
GRUB_ENTRY="Advanced options for Ubuntu>Ubuntu, with Linux ${KERNEL}"
sed -i "s|^GRUB_DEFAULT=.*|GRUB_DEFAULT=\"${GRUB_ENTRY}\"|" /etc/default/grub
update-grub

echo "==> Kernel $KERNEL installed. Vagrant will reboot now."
