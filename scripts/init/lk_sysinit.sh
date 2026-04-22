#!/bin/sh

mount_once() {
	fstype="$1"
	target="$2"
	opts="$3"

	mkdir -p "$target"
	if mountpoint -q "$target" 2>/dev/null; then
		return 0
	fi

	if [ -n "$opts" ]; then
		mount -t "$fstype" -o "$opts" "$fstype" "$target" >/dev/null 2>&1 || true
	else
		mount -t "$fstype" "$fstype" "$target" >/dev/null 2>&1 || true
	fi
}

sync_time_once() {
	if ! command -v ntpd >/dev/null 2>&1; then
		return 0
	fi

	timeout 15 ntpd -q -n -p time.cloudflare.com >/dev/null 2>&1 ||
	timeout 15 ntpd -q -n -p 0.pool.ntp.org >/dev/null 2>&1 ||
	timeout 15 ntpd -q -n -p 1.pool.ntp.org >/dev/null 2>&1 ||
	true
}

mount_once proc /proc ""
mount_once sysfs /sys ""
mount_once devpts /dev/pts "mode=0620,ptmxmode=0666"
mount_once tmpfs /run "mode=0755,nodev,nosuid"
mkdir -p /run/lock

# Configure the default QEMU user-networking guest setup before login shell.
ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up
route add default gw 10.0.2.2 eth0 >/dev/null 2>&1 || true
echo "nameserver 10.0.2.3" > /etc/resolv.conf

sync_time_once
