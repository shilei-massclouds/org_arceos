#!/bin/bash

TEST_ID=1

# Replace testcase file
rm -f examples/task/brute_force/src/bf.rs
ln -rs tools/brute_force/testfiles/$TEST_ID.rs examples/task/brute_force/src/bf.rs
ls -l examples/task/brute_force/src/bf.rs

# Do test
make ARCH=riscv64 A=examples/task/brute_force run FEATURES="sched-rr" SMP=8
