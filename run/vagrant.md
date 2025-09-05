apt list --all-versions linux-image-6.8.0-59-generic
sudo apt update
sudo apt install linux-image-6.8.0-59-generic linux-headers-6.8.0-59-generic
sudo update-grub
sudo reboot
sudo apt update
sudo apt install -y wireguard-tools iproute2 iperf3
sudo ./wg_vm_left.sh up
sudo ./wg_vm_right.sh up


scp -P 2222 /home/fatihyuce/work/projects/tmp/enes/wireguard-zk-handshake/tmp/linux-signed-hwe-6.8-6.8.0/linux-hwe-6.8-6.8.0/drivers/net/wireguard/wireguard.ko m@127.0.0.1:/home/m/
scp -P 2223 /home/fatihyuce/work/projects/tmp/enes/wireguard-zk-handshake/tmp/linux-signed-hwe-6.8-6.8.0/linux-hwe-6.8-6.8.0/drivers/net/wireguard/wireguard.ko m@127.0.0.1:/home/m/


scp -P 2222 /home/fatihyuce/work/projects/tmp/enes/wireguard-zk-handshake/userspace/wg-zk-daemon/target/debug/wg-zk-daemon m@127.0.0.1:/home/m/
scp -P 2223 /home/fatihyuce/work/projects/tmp/enes/wireguard-zk-handshake/userspace/wg-zk-daemon/target/debug/wg-zk-daemon m@127.0.0.1:/home/m/


#ssh
sudo install -D -m 644 "/home/m/wireguard.ko"  /lib/modules/$(uname -r)/extra/wireguard.ko
sudo depmod -a
sudo rmmod wireguard
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
sudo modprobe aesni_intel
sudo modprobe af_alg

#sudo modprobe wireguard   # or:
sudo insmod /lib/modules/$(uname -r)/extra/wireguard.ko
sudo dmesg | grep wireguard



echo 1 > sudo tee /sys/kernel/debug/wireguard/wg0/zk_require_proof   # gateway
echo 0 > sudo tee /sys/kernel/debug/wireguard/wg0/zk_require_proof   # client