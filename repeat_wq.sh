#!/bin/bash

TEST_NUM=10
for ((i=0;i<$TEST_NUM;i++))
do
    make ARCH=riscv64 A=examples/task/wait_queue run SMP=8
done
