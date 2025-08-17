# Wireguard with AES Support

WireGuard, a high-performance VPN integrated into the Linux kernel, is renowned
for its speed and reliance on software-based encryption. However, it faces
limitations as a VPN Gateway (VPNGW), particularly in software-defined networks
(SDNs), where its throughput drops significantly with multiple client
connections and hardware encryption remains underutilized. This study presents
an enhanced WireGuard implementation that incorporates AES encryption with
hardware acceleration to boost efficiency. Using kernel-based AES results in an
11% increase in throughput, a 5.5% decrease in retransmissions, and a 10%
reduction in CPU usage. Meanwhile, user-space AES (implementation
[[here](https://github.com/mfyuce/boringtun/tree/registry-trait-with-fast)] )
can deliver up to 19.47% higher throughput on modern CPUs, achieving
terabit-per-second speeds and greater efficiency with larger MTUs.

# Building

**More information may be found at
[WireGuard.com](https://www.wireguard.com/).**


## Tools Required for the Kernel
```bash
sudo apt-get install git fakeroot build-essential ncurses-dev xz-utils libssl-dev bc flex libelf-dev bison
```
## Building on the Host Machine

## out of tree (may fail)
```bash

wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.8.tar.xz
tar -xf linux-6.8.tar.xz

cd linux-6.8/drivers/net/wireguard
sudo cp -r linux-6.8/drivers/net/wireguard <your folder>
cd <your folder>
#arrange your makefile e.g. like the one in wireguard-6.8 
make 
#backup old one 
sudo cp  /lib/modules/$(uname -r)/kernel/drivers/net/wireguard/wireguard.ko /lib/modules/$(uname -r)/kernel/drivers/net/wireguard/wireguard.ko.bck
# romove if it is already loaded
sudo rmmod wireguard
# Load dependencies
sudo modprobe udp_tunnel
sudo modprobe ip6_udp_tunnel
sudo modprobe libchacha
sudo modprobe libcurve25519
sudo modprobe libblake2s




sudo insmod ./wireguard.ko
```




```bash
ls /lib/modules/
uname -a

#>>>>Linux 483-LNX 6.8.0-59-generic #61~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Tue Apr 15 17:03:15 UTC 2 x86_64 x86_64 x86_64 GNU/Linux

ls /lib/modules/6.8.0-59-generic
 
```



## in tree

```
sudo apt install linux-source
sudo apt install ubuntu-dev-tools
#dpkg-query -S $(readlink -f /boot/vmlinuz-$(uname -r))
##→ linux-image-6.8.0-59-generic
wget https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/linux-signed-hwe-6.8/6.8.0-59.61~22.04.1/linux-signed-hwe-6.8_6.8.0-59.61~22.04.1.dsc
wget https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/linux-signed-hwe-6.8/6.8.0-59.61~22.04.1/linux-signed-hwe-6.8_6.8.0-59.61~22.04.1.tar.xz
sudo dpkg-source -x linux-signed-hwe-6.8_6.8.0-59.61~22.04.1.dsc
cd linux-signed-hwe-6.8-6.8.0/
sudo pull-lp-source linux-hwe-6.8
cd linux-hwe-6.8-6.8.0
#sync your wg codes
sudo chmod -R 777 .
mv drivers/net/wireguard drivers/net/wireguard.bck
cp -r /home/fatihyuce/work/projects/tmp/enes/wireguard-zk-handshake/wireguard-6.8 drivers/net/wireguard

make mrproper

make M=drivers/net/wireguard clean

cp /boot/config-$(uname -r) .config
make olddefconfig
make modules_prepare
make -j$(nproc) modules
#/path/to/wireguard-6.8
cd ~/work/projects/tmp/enes/wireguard-zk-handshake/tmp/linux-signed-hwe-6.8-6.8.0/linux-hwe-6.8-6.8.0/drivers/net/wireguard 
sudo apt-get install --reinstall linux-headers-$(uname -r)
make -C /lib/modules/$(uname -r)/build M=$(pwd) clean
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules

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


sudo rmmod wireguard
sudo cp /home/fatihyuce/work/projects/tmp/enes/wireguard-zk-handshake/tmp/linux-signed-hwe-6.8-6.8.0/linux-hwe-6.8-6.8.0/drivers/net/wireguard/wireguard.ko /lib/modules/6.8.0-59-generic/kernel/drivers/net/wireguard/wireguard.ko
sudo modprobe wireguard
lsmod | grep wireguard



# needs libnl cli tools (package: libnl-genl-3-200 / libnl-3-bin on Ubuntu)
genl ctrl list | grep -i wgzk
>>>Name: wgzk

genl ctrl get name wgzk

>>>>>Name: wgzk
>>>>>        ID: 0x29  Version: 0x1  header size: 0  max attribs: 2 
>>>>>        commands supported: 
>>>>>                #1:  ID-0x1 
>>>>>


```

to remove

```bash
lsmod | grep wireguard
sudo modinfo wireguard
sudo modprobe -r wireguard
sudo rmmod wireguard
sudo rmmod -f wireguard
sudo modprobe -r wireguard 

```
```bash
cd 
mv tmp/linux-6.8/drivers/net/wireguard tmp/linux-6.8/drivers/net/wireguard.bck
#ln -s <your_wireguard_folder_full_path> <full_path_to>/tmp/linux-6.8/drivers/net/wireguard
#  ln -s /home/fatihyuce/work/projects/tmp/enes/wireguard-5.10.55/tmp/linux-6.8  /home/fatihyuce/work/projects/tmp/enes/wireguard-5.10.55/tmp/linux-6.8/drivers/net/wireguard
cd tmp/linux-6.8

cp /boot/config-$(uname -r) .config
# This error is caused by 
# CONFIG_SYSTEM_TRUSTED_KEYS still being set to debian/canonical-certs.pem, 
# but that file doesn't exist - it's used by Ubuntu/Debian's 
# kernel packaging system, not our in-tree build.
# CONFIG_SYSTEM_TRUSTED_KEYS=""
# CONFIG_SYSTEM_REVOCATION_KEYS=""
scripts/config --disable SYSTEM_TRUSTED_KEYS
scripts/config --disable SYSTEM_REVOCATION_KEYS
make olddefconfig

make modules_prepare
make modules -j$(nproc)


# make menuconfig # end save. wg is by default module [m]
#make prepare
#make modules_prepare
make M=drivers/net/wireguard -j$(nproc) modules

```
`ko` file generated will be in kernel folder and will not be synced back to original folder [interesting, yes :)]. 
### Result
* If you provide the MayaOS headers to the `./build.sh` script (by extracting the `ci/5.10.55-amd64-vyos.zip` file to the same directory), it can be built for MayaOS (kernel version 5.15.55).
* If you want to build it for another version, run `build_generic.sh` and make sure to obtain the corresponding kernel headers for that version.

## Verifying the Build
To check if the built code works:

* Edit the `description` in `main.c`.
* After loading the module, you can verify the change with:
```bash
moninfo wireguard 
```

## Build Command
```bash
./build.sh
```


# License

This project is released under the [GPLv2](COPYING).

# TEST

```bash
cd run
./test_generic_single.sh <how_many_tunnels>
```

# Charts

```bash
cd experimentation/experiment_archieve
cat aes.tar.xz.part.* > aes.tar.xz
tar -xf aes.tar.xz
mv aes ../

cat chacha.tar.xz.part.* > chacha.tar.xz
tar -xf chacha.tar.xz
mv chacha ../

docker compose up
```

After all dockers started, to insert all the experimentation output to DB;

```python
python3 ./pg.py
```

## Grafana

```python
http://localhost:33000/d/67_Z9zHIz1/localdash?orgId=1&
```

![retransmission_tcp.png](experimentation/retransmission_tcp.png)
