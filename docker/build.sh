#!/bin/bash

set -e

echo "Building WireGuard kernel module with ZK extensions..."

cd /root/kernel
make clean
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules

echo "Inserting kernel module..."
rmmod wireguard || true
insmod ./wireguard.ko

echo "Module loaded!"

echo "Starting ZK verifier daemon..."
cd /root/userspace/wg-zk-daemon
cargo build --release
./target/release/wg-zk-daemon
