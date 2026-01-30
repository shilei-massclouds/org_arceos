#!/bin/bash

for testcase in tools/brute_force/testfiles/*.rs; do

  echo "Do test: [$f]"

  # Replace testcase file
  rm -f examples/task/brute_force/src/bf.rs
  ln -rs $testcase examples/task/brute_force/src/bf.rs
  ls -l examples/task/brute_force/src/bf.rs

  # Do test
  make ARCH=riscv64 A=examples/task/brute_force run FEATURES="sched-rr" SMP=8

done
