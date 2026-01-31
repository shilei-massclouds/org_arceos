#!/bin/bash

printf "Make test ...\n"
pushd tools/brute_force/
cargo run
popd
printf "Make test ok!\n"

for testcase in tools/brute_force/testfiles/*.rs; do

  printf "Do test: [$testcase]\n"

  # Replace testcase file
  rm -f examples/task/brute_force/src/bf.rs
  ln -rs $testcase examples/task/brute_force/src/bf.rs
  ls -l examples/task/brute_force/src/bf.rs
  # Note: we must touch it to REALLY rebuild & run this test.
  touch examples/task/brute_force/src/bf.rs

  # Do test
  make ARCH=riscv64 A=examples/task/brute_force run FEATURES="sched-rr" SMP=8

done
