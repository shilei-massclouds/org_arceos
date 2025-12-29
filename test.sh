#!/bin/sh

make clippy
make clippy ARCH=x86_64
make clippy ARCH=aarch64
make clippy ARCH=riscv64
make clippy ARCH=loongarch64
