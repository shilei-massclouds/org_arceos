#!/bin/sh

make ARCH=riscv64 defconfig
make ARCH=riscv64 A=examples/task/affinity  run SMP=8
make ARCH=riscv64 A=examples/task/irq       run SMP=8
make ARCH=riscv64 A=examples/task/parallel  run SMP=8
make ARCH=riscv64 A=examples/task/priority  run SMP=8
make ARCH=riscv64 A=examples/task/sleep     run SMP=8
make ARCH=riscv64 A=examples/task/tls       run SMP=8
make ARCH=riscv64 A=examples/task/wait_queue run SMP=8
make ARCH=riscv64 A=examples/task/yield     run SMP=8
