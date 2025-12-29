#!/bin/sh
make defconfig ARCH=riscv64 MYPLAT=axplat-riscv64-dp1000
make run ARCH=riscv64 MYPLAT=axplat-riscv64-dp1000 A=examples/fstest
