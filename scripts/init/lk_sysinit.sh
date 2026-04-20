#!/bin/sh

# Configure the default QEMU user-networking guest setup before login shell.
ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up
route add default gw 10.0.2.2 eth0
echo "nameserver 10.0.2.3" > /etc/resolv.conf
