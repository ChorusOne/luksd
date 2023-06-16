#!/bin/bash -e

# 5.4.0-135-generic
KERNEL_VERSION=$1

export DEBIAN_FRONTEND=noninteractive

apt update
apt install -y linux-image-${KERNEL_VERSION} initramfs-tools \
               grub2 grub-pc-bin \
               mdadm lsof rsync parted hdparm lvm2 \
               zstd p7zip\
               dnsutils curl iproute2 \
               vim git \
               openssh-server busybox cryptsetup

[ ! -d ./debian-package-openssh-initramfs ] && git clone https://github.com/Aisbergg/debian-package-openssh-initramfs.git

if [[ ! $(dpkg -s openssh-initramfs) ]]; then
    (
    cd debian-package-openssh-initramfs
    dpkg-deb --build openssh-initramfs/ "openssh-initramfs_$(sed -nE 's/^Version: (.*)/\1/p' openssh-initramfs/DEBIAN/control)_all.deb"
    dpkg -i openssh-initramfs_*_all.deb
    )
fi

sed -i 's/DEVICE=.*/DEVICE=enp1s0/' /etc/initramfs-tools/initramfs.conf
grep -q 'IP=' /etc/initramfs-tools/initramfs.conf || sed -i '/^DEVICE=enp1s0/a IP=:::::enp1s0:dhcp' /etc/initramfs-tools/initramfs.conf

[ ! -f /etc/openssh-initramfs/ssh_host_ed25519_key ] && ssh-keygen -t ed25519 -f /etc/openssh-initramfs/ssh_host_ed25519_key -q -N ""
[ ! -f /etc/openssh-initramfs/ssh_host_ecdsa_key ]   && ssh-keygen -t ecdsa -f /etc/openssh-initramfs/ssh_host_ecdsa_key -q -N ""
[ ! -f /etc/openssh-initramfs/ssh_host_rsa_key ]     && ssh-keygen -t rsa -b 4096 -f /etc/openssh-initramfs/ssh_host_rsa_key -q -N ""


mkdir -p -m 700 /root/.ssh
[ ! -f /root/.ssh/authorized_keys ] && install -m 600 -o root -g root /dev/null /root/.ssh/authorized_keys


echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINeV5n3ZIf21R4crbYfi/VrrSwplcjlHA7qIiKKMS8Dr chorusone-openssh-key-2023q1" > /root/.ssh/authorized_keys

mkdir -p /etc/initramfs-tools/bin
cp -p custom.sh /usr/share/initramfs-tools/scripts/init-premount/custom && if [ ! -x /usr/share/initramfs-tools/scripts/init-premount/custom ]; then chmod +x /usr/share/initramfs-tools/scripts/init-premount/custom; fi

cp -p hooks.sh /etc/initramfs-tools/hooks/ && if [ ! -x /etc/initramfs-tools/hooks/initramfs_hook.sh ]; then chmod +x /etc/initramfs-tools/hooks/hooks.sh ; fi

update-initramfs -u
