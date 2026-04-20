#!/bin/sh

export HOME=/root
MARKER=/run/lk_init.done

if [ ! -e "$MARKER" ]; then
	echo
	echo -e "Welcome to \e[96m\e[1mLK\e[0m!"
	env
	echo

	echo -e "Use \e[1m\e[3mapk\e[0m to install packages."
	echo

	# Do your initialization here once per boot.
	echo "LK_APK_PROBE: route"
	route -n || true
	echo "LK_APK_PROBE: resolv"
	while IFS= read -r line; do
		echo "$line"
	done < /etc/resolv.conf || true
	echo "LK_APK_PROBE: ifconfig"
	ifconfig eth0 || true
	echo "LK_APK_PROBE: nslookup"
	nslookup dl-cdn.alpinelinux.org 10.0.2.3 || true
	echo "LK_APK_PROBE: wget"
	wget -T 10 -O /dev/null https://dl-cdn.alpinelinux.org/alpine/v3.23/main/riscv64/APKINDEX.tar.gz || true
	echo "LK_APK_PROBE: apk update start"
	apk update
	echo "LK_APK_PROBE: apk update done:$?"
	touch "$MARKER"
fi

cd "$HOME" || cd /
exec /bin/sh --login
