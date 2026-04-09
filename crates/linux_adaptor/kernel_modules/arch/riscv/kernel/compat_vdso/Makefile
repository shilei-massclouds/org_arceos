# Makefile for `arch/riscv/kernel/compat_vdso`

compat_vdso-objs := rt_sigreturn getcpu flush_icache note
compat_vdso-export-syms := __compat_vdso_rt_sigreturn __compat_vdso_getcpu __compat_vdso_flush_icache

obj-compat_vdso = $(addprefix $(curdir),$(addsuffix .o,$(compat_vdso-objs)))

obj-y += compat_vdso.o

compat_vdso-cross-prefix := riscv64-linux-gnu-
compat_vdso-ld = $(compat_vdso-cross-prefix)ld
compat_vdso-objcopy = $(compat_vdso-cross-prefix)objcopy
compat_vdso-cc = $(compat_vdso-cross-prefix)gcc

compat_vdso-lds = $(curdir)compat_vdso.lds
compat_vdso-so = $(curdir)compat_vdso.so
compat_vdso-so-dbg = $(curdir)compat_vdso.so.dbg

compat_vdso-ldflags = -melf64lriscv -z noexecstack -shared -S -soname=linux-compat_vdso.so.1 \
	--build-id=sha1 --hash-style=both --eh-frame-hdr -melf32lriscv
compat_vdso-export-flags = $(addprefix -G ,$(compat_vdso-export-syms))

compat_vdso-noarch-attr = -mno-riscv-attribute -Wa,-mno-arch-attr
compat_vdso-common-cflags = -nostdinc -I./arch/riscv/include -I./arch/riscv/include/generated \
	-I./include -I./arch/riscv/include/uapi -I./arch/riscv/include/generated/uapi \
	-I./include/uapi -I./include/generated/uapi \
	-include ./include/linux/compiler-version.h -include ./include/linux/kconfig.h \
	-D__KERNEL__ -fmacro-prefix-map=./= -D__ASSEMBLY__ -fno-PIE \
	-mabi=lp64 -march=rv64imafdcv_zicsr_zifencei $(compat_vdso-noarch-attr)
compat_vdso-compat-cflags = -march=rv32g -mabi=ilp32 $(compat_vdso-noarch-attr)

# Force dependency
$(curdir)compat_vdso.o: $(compat_vdso-so)

# strip rule for the .so file
$(compat_vdso-so): $(compat_vdso-so-dbg) FORCE
	$(OBJCOPY) -S $< $@

# link rule for the .so file, .lds has to be first
$(compat_vdso-so-dbg): $(compat_vdso-lds) $(obj-compat_vdso) FORCE
	$(compat_vdso-ld) $(compat_vdso-ldflags) -T $(compat_vdso-lds) $(obj-compat_vdso) \
		-o $@.tmp && \
	$(compat_vdso-objcopy) $(compat_vdso-export-flags) $@.tmp $@ && \
	rm $@.tmp

$(curdir)%.o: $(curdir)%.S
	$(compat_vdso-cc) -Wp,-MMD,$(curdir).$(@F).d $(compat_vdso-common-cflags) \
		-DKBUILD_MODFILE='"$(curdir)$*"' -DKBUILD_MODNAME='"$*"' \
		-D__KBUILD_MODNAME=kmod_$* $(compat_vdso-compat-cflags) -c -o $@ $<
