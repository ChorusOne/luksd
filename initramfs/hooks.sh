#!/bin/sh -e

case $1 in
prereqs)
        exit 0
        ;;
esac

# Include the hook functions
. /usr/share/initramfs-tools/hook-functions

for bin in ext2 ext3 fat vfat ntfs xfs brtfs; do
  ln -s mke2fs "${DESTDIR}/sbin/mkfs.${bin}"
done

for bin in lsof rsync dd lsblk vim; do
  copy_exec "/usr/bin/${bin}" "/bin"
done

for bin in fdisk sfdisk parted hdparm wipefs mdadm lvm cryptsetup; do
  copy_exec "/usr/sbin/${bin}"  "/sbin/"
done

copy_exec "/sbin/mke2fs" "/sbin/"

for bin in tar gzip bzip2 zstd p7zip cpio; do
  copy_exec "/usr/bin/${bin}"   "/bin/"
done

for bin in curl wget scp dig nslookup ss; do
  copy_exec "/usr/bin/${bin}"      "/bin/"
done

# Copy terminal info for screen
mkdir -p ${DESTDIR}/lib/terminfo
for i in $(ls /lib/terminfo); do
  cp -a /lib/terminfo/${i} ${DESTDIR}/lib/terminfo
done

# Fix DNS resolver
cp -a /lib/x86_64-linux-gnu/libnss_dns* ${DESTDIR}/lib/x86_64-linux-gnu/
echo "nameserver 8.8.8.8" > ${DESTDIR}/etc/resolv.conf
