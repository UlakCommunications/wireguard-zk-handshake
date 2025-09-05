
# currently here ************************************************
ls -l Module.symvers
make M=drivers/net/wireguard -j$(nproc)


********************************
test to try later
sudo make modules_install
sudo depmod -a
sudo modprobe wireguard
dmesg | grep -i wg

Once you confirm the intree build links without unresolveds, we can move on to runtime testing:

check /sys/kernel/debug/zk_pending

confirm the wgzk Generic Netlink family exists

try a dummy handshake with your userspace wg-zk-daemon

 
-------------------
sudo insmod ./wireguard.ko
dmesg | egrep -i 'wireguard|wg-zk'

# ensure debugfs is mounted
sudo mount -t debugfs none /sys/kernel/debug 2>/dev/null || true

# list your files
ls -l /sys/kernel/debug/zk_handshake /sys/kernel/debug/zk_pending
# read them
sudo head -n 50 /sys/kernel/debug/zk_pending




ls -l /proc | egrep 'wg|zk'
# e.g., if you created /proc/wg_zk:
sudo cat /proc/wg_zk


# either:
sudo nldev list | grep wgzk 2>/dev/null || true
# or:
sudo nlmon add nlmon0 2>/dev/null || true
# or with iproute2 if it has genl:
sudo genl ctrl-list | grep wgzk 2>/dev/null || true

***********************************



cat /proc/net/genetlink | grep -A2 wgzk




scp -P 2223 /home/fatihyuce/work/projects/tmp/enes/wireguard-zk-handshake/tmp/linux-signed-hwe-6.8-6.8.0/linux-hwe-6.8-6.8.0/drivers/net/wireguard/wireguard.ko m@127.0.0.1:/home/m/
scp -P 2222 /home/fatihyuce/work/projects/tmp/enes/wireguard-zk-handshake/tmp/linux-signed-hwe-6.8-6.8.0/linux-hwe-6.8-6.8.0/drivers/net/wireguard/wireguard.ko m@127.0.0.1:/home/m/

scp -P 2223 /home/fatihyuce/work/projects/tmp/enes/wireguard-zk-handshake/userspace/wg-zk-daemon/target/debug/wg-zk-daemon m@127.0.0.1:/home/m/
scp -P 2222 /home/fatihyuce/work/projects/tmp/enes/wireguard-zk-handshake/userspace/wg-zk-daemon/target/debug/wg-zk-daemon m@127.0.0.1:/home/m/

