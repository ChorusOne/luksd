#!/bin/sh

PREREQ="udev"

prereqs() {
    echo "$PREREQ"
}

case "$1" in
    prereqs)
        prereqs
        exit 0
    ;;
esac


mkdir -p /luks
#curl 192.168.122.173/machine/key > response.json
#cat response.json | jq -r '.header' | base64 -d > /luks/hdr.img
#cat response.json | jq -r '.key' | base64 -d > /luks/password.key
luksclient decrypt --encrypted-device /dev/vdb1
#cryptsetup open /dev/vdc1 first -d /luks/password.key --header /luks/hdr.img  -v
#cryptsetup open /dev/vdd1 second -d /luks/password.key --header /luks/hdr.img  -v
