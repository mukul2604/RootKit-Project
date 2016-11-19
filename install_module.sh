#! /bin/sh
set -x
rmmod rootkit
insmod rootkit.ko
lsmod | grep rootkit
