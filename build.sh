#!/bin/bash
#clear
#sudo make -C /lib/modules/5.10.55-amd64-vyos/build M=$(pwd) modules
#sudo make -C /lib/modules/5.10.55-amd64-vyos/build M=$(pwd) modules
#sudo make -C /lib/modules/6.8.0-59-generic M=$(pwd) modules
set -x
set -e
# adjust SRCDIR to your path
SRCDIR="`pwd`/tmp/linux-signed-hwe-6.8-6.8.0/linux-hwe-6.8-6.8.0"
cd ${SRCDIR}
cp /lib/modules/$(uname -r)/build/.config .config  # better than /boot/config-...
make olddefconfig
make prepare modules_prepare

scripts/config --disable SYSTEM_TRUSTED_KEYS
scripts/config --disable SYSTEM_REVOCATION_KEYS

# 1) Clean any previous artifacts in that subdir
make -C /lib/modules/$(uname -r)/build M="$SRCDIR/drivers/net/wireguard" clean

# 2) Build the module *using the running kernel's headers*
make -C /lib/modules/$(uname -r)/build M="$SRCDIR/drivers/net/wireguard" modules

# 3) Verify vermagic now matches 6.8.0-59-generic
modinfo -F vermagic "$SRCDIR/drivers/net/wireguard/wireguard.ko"

# 4) Install and load
sudo install -D -m 644 "$SRCDIR/drivers/net/wireguard/wireguard.ko" \
  /lib/modules/$(uname -r)/extra/wireguard.ko
sudo depmod -a
sudo rmmod wireguard && true
# Load related modules

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
modprobe aesni_intel
modprobe af_alg

#sudo modprobe wireguard   # or:
sudo insmod /lib/modules/$(uname -r)/extra/wireguard.ko
sudo dmesg | grep wireguard
