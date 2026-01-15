#!/bin/bash

# affinity  irq  parallel  priority  sleep  tls  wait_queue  yield

TEST_NUM=100
for ((i=0;i<$TEST_NUM;i++))
do
    make ARCH=riscv64 A=examples/task/affinity run FEATURES="sched-rr" SMP=8
    make ARCH=riscv64 A=examples/task/irq run FEATURES="sched-rr" SMP=8
    make ARCH=riscv64 A=examples/task/parallel run FEATURES="sched-rr" SMP=8
    make ARCH=riscv64 A=examples/task/priority run FEATURES="sched-rr" SMP=8
    make ARCH=riscv64 A=examples/task/sleep run FEATURES="sched-rr" SMP=8
    make ARCH=riscv64 A=examples/task/wait_queue run FEATURES="sched-rr" SMP=8
    make ARCH=riscv64 A=examples/task/yield run FEATURES="sched-rr" SMP=8
done
