savedcmd_include/generated/vdso-offsets.h := riscv64-linux-gnu-nm arch/riscv/kernel/vdso/vdso.so.dbg | arch/riscv/kernel/vdso/gen_vdso_offsets.sh | LC_ALL=C sort > include/generated/vdso-offsets.h
