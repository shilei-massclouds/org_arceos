# Makefile for `arch/riscv/kernel/vdso`

obj-vdso =

obj-y += vdso.o

# Force vdso.so to be materialized before assembling vdso.o.
$(curdir)vdso.o: $(curdir)vdso.so

# strip rule for the .so file
$(curdir)vdso.so: $(curdir)vdso.so.dbg FORCE
	$(OBJCOPY) -S $< $@

# link rule for the .so file, .lds has to be first
$(curdir)vdso.so.dbg: $(curdir)vdso.lds $(obj-vdso) FORCE
	riscv64-linux-gnu-ld -melf64lriscv -z noexecstack  -shared -soname=linux-vdso.so.1 --build-id=sha1 --hash-style=both --eh-frame-hdr -T arch/riscv/kernel/vdso/vdso.lds arch/riscv/kernel/vdso/rt_sigreturn.o arch/riscv/kernel/vdso/vgettimeofday.o arch/riscv/kernel/vdso/getcpu.o arch/riscv/kernel/vdso/flush_icache.o arch/riscv/kernel/vdso/hwprobe.o arch/riscv/kernel/vdso/sys_hwprobe.o arch/riscv/kernel/vdso/note.o -o arch/riscv/kernel/vdso/vdso.so.dbg.tmp && riscv64-linux-gnu-objcopy  -G __vdso_rt_sigreturn  -G __vdso_vgettimeofday  -G __vdso_getcpu  -G __vdso_flush_icache  -G __vdso_hwprobe  -G __vdso_sys_hwprobe arch/riscv/kernel/vdso/vdso.so.dbg.tmp arch/riscv/kernel/vdso/vdso.so.dbg && rm arch/riscv/kernel/vdso/vdso.so.dbg.tmp
