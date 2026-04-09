# Makefile for `arch/riscv/kernel/compat_vdso`

obj-compat_vdso = $(curdir)rt_sigreturn.o $(curdir)getcpu.o $(curdir)flush_icache.o $(curdir)note.o

obj-y += compat_vdso.o

# Force dependency
$(curdir)compat_vdso.o: $(curdir)compat_vdso.so

# strip rule for the .so file
$(curdir)compat_vdso.so: $(curdir)compat_vdso.so.dbg FORCE
	$(OBJCOPY) -S $< $@

# link rule for the .so file, .lds has to be first
$(curdir)compat_vdso.so.dbg: $(curdir)compat_vdso.lds $(obj-compat_vdso) FORCE
	riscv64-linux-gnu-ld -melf64lriscv -z noexecstack  -shared -S -soname=linux-compat_vdso.so.1 --build-id=sha1 --hash-style=both --eh-frame-hdr -melf32lriscv -T arch/riscv/kernel/compat_vdso/compat_vdso.lds arch/riscv/kernel/compat_vdso/rt_sigreturn.o arch/riscv/kernel/compat_vdso/getcpu.o arch/riscv/kernel/compat_vdso/flush_icache.o arch/riscv/kernel/compat_vdso/note.o -o arch/riscv/kernel/compat_vdso/compat_vdso.so.dbg.tmp && riscv64-linux-gnu-objcopy  -G __compat_vdso_rt_sigreturn  -G __compat_vdso_getcpu  -G __compat_vdso_flush_icache arch/riscv/kernel/compat_vdso/compat_vdso.so.dbg.tmp arch/riscv/kernel/compat_vdso/compat_vdso.so.dbg && rm arch/riscv/kernel/compat_vdso/compat_vdso.so.dbg.tmp

$(curdir)rt_sigreturn.o: $(curdir)rt_sigreturn.S
	riscv64-linux-gnu-gcc -Wp,-MMD,arch/riscv/kernel/compat_vdso/.rt_sigreturn.o.d -nostdinc -I./arch/riscv/include -I./arch/riscv/include/generated  -I./include -I./arch/riscv/include/uapi -I./arch/riscv/include/generated/uapi -I./include/uapi -I./include/generated/uapi -include ./include/linux/compiler-version.h -include ./include/linux/kconfig.h -D__KERNEL__ -fmacro-prefix-map=./= -D__ASSEMBLY__ -fno-PIE -mabi=lp64 -march=rv64imafdcv_zicsr_zifencei -mno-riscv-attribute -Wa,-mno-arch-attr    -DKBUILD_MODFILE='"arch/riscv/kernel/compat_vdso/rt_sigreturn"' -DKBUILD_MODNAME='"rt_sigreturn"' -D__KBUILD_MODNAME=kmod_rt_sigreturn -march=rv32g -mabi=ilp32 -mno-riscv-attribute -Wa,-mno-arch-attr -c -o arch/riscv/kernel/compat_vdso/rt_sigreturn.o arch/riscv/kernel/compat_vdso/rt_sigreturn.S

$(curdir)getcpu.o: $(curdir)getcpu.S
	riscv64-linux-gnu-gcc -Wp,-MMD,arch/riscv/kernel/compat_vdso/.getcpu.o.d -nostdinc -I./arch/riscv/include -I./arch/riscv/include/generated  -I./include -I./arch/riscv/include/uapi -I./arch/riscv/include/generated/uapi -I./include/uapi -I./include/generated/uapi -include ./include/linux/compiler-version.h -include ./include/linux/kconfig.h -D__KERNEL__ -fmacro-prefix-map=./= -D__ASSEMBLY__ -fno-PIE -mabi=lp64 -march=rv64imafdcv_zicsr_zifencei -mno-riscv-attribute -Wa,-mno-arch-attr    -DKBUILD_MODFILE='"arch/riscv/kernel/compat_vdso/getcpu"' -DKBUILD_MODNAME='"getcpu"' -D__KBUILD_MODNAME=kmod_getcpu -march=rv32g -mabi=ilp32 -mno-riscv-attribute -Wa,-mno-arch-attr -c -o arch/riscv/kernel/compat_vdso/getcpu.o arch/riscv/kernel/compat_vdso/getcpu.S

$(curdir)flush_icache.o: $(curdir)flush_icache.S
	riscv64-linux-gnu-gcc -Wp,-MMD,arch/riscv/kernel/compat_vdso/.flush_icache.o.d -nostdinc -I./arch/riscv/include -I./arch/riscv/include/generated  -I./include -I./arch/riscv/include/uapi -I./arch/riscv/include/generated/uapi -I./include/uapi -I./include/generated/uapi -include ./include/linux/compiler-version.h -include ./include/linux/kconfig.h -D__KERNEL__ -fmacro-prefix-map=./= -D__ASSEMBLY__ -fno-PIE -mabi=lp64 -march=rv64imafdcv_zicsr_zifencei -mno-riscv-attribute -Wa,-mno-arch-attr    -DKBUILD_MODFILE='"arch/riscv/kernel/compat_vdso/flush_icache"' -DKBUILD_MODNAME='"flush_icache"' -D__KBUILD_MODNAME=kmod_flush_icache -march=rv32g -mabi=ilp32 -mno-riscv-attribute -Wa,-mno-arch-attr -c -o arch/riscv/kernel/compat_vdso/flush_icache.o arch/riscv/kernel/compat_vdso/flush_icache.S

$(curdir)note.o: $(curdir)note.S
	riscv64-linux-gnu-gcc -Wp,-MMD,arch/riscv/kernel/compat_vdso/.note.o.d -nostdinc -I./arch/riscv/include -I./arch/riscv/include/generated  -I./include -I./arch/riscv/include/uapi -I./arch/riscv/include/generated/uapi -I./include/uapi -I./include/generated/uapi -include ./include/linux/compiler-version.h -include ./include/linux/kconfig.h -D__KERNEL__ -fmacro-prefix-map=./= -D__ASSEMBLY__ -fno-PIE -mabi=lp64 -march=rv64imafdcv_zicsr_zifencei -mno-riscv-attribute -Wa,-mno-arch-attr    -DKBUILD_MODFILE='"arch/riscv/kernel/compat_vdso/note"' -DKBUILD_MODNAME='"note"' -D__KBUILD_MODNAME=kmod_note -march=rv32g -mabi=ilp32 -mno-riscv-attribute -Wa,-mno-arch-attr -c -o arch/riscv/kernel/compat_vdso/note.o arch/riscv/kernel/compat_vdso/note.S
