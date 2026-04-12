# Makefile for `arch/riscv/kernel/vdso`

vdso-asm-objs := rt_sigreturn getcpu flush_icache sys_hwprobe note
vdso-c-objs := vgettimeofday hwprobe
vdso-built-objs := $(vdso-asm-objs) $(vdso-c-objs)
vdso-link-objs := $(vdso-built-objs)
vdso-export-syms := __vdso_rt_sigreturn __vdso_gettimeofday \
	__vdso_clock_gettime __vdso_clock_getres __vdso_getcpu \
	__vdso_flush_icache __vdso_riscv_hwprobe

obj-vdso = $(addprefix $(curdir),$(addsuffix .o,$(vdso-built-objs)))

obj-y += vdso.o

vdso-cross-prefix := riscv64-linux-gnu-
vdso-ld = $(vdso-cross-prefix)ld
vdso-objcopy = $(vdso-cross-prefix)objcopy
vdso-cc = $(vdso-cross-prefix)gcc

vdso-lds = $(curdir)vdso.lds
vdso-lds-src = $(vdso-lds).S
vdso-so = $(curdir)vdso.so
vdso-so-dbg = $(curdir)vdso.so.dbg
vdso-asm-objs-full = $(addprefix $(curdir),$(addsuffix .o,$(vdso-asm-objs)))
vdso-c-objs-full = $(addprefix $(curdir),$(addsuffix .o,$(vdso-c-objs)))
vdso-link-objs-full = $(addprefix $(curdir),$(addsuffix .o,$(vdso-link-objs)))

vdso-ldflags = -melf64lriscv -z noexecstack -shared -soname=linux-vdso.so.1 \
	--build-id=sha1 --hash-style=both --eh-frame-hdr
vdso-export-flags = $(addprefix -G ,$(vdso-export-syms))

vdso-noarch-attr = -mno-riscv-attribute -Wa,-mno-arch-attr
vdso-common-cppflags = -nostdinc -I./arch/riscv/include -I./arch/riscv/include/generated \
	-I./include -I./arch/riscv/include/uapi -I./arch/riscv/include/generated/uapi \
	-I./include/uapi -I./include/generated/uapi
vdso-common-include-flags = -include ./include/linux/compiler-version.h \
	-include ./include/linux/kconfig.h
vdso-common-kbuild-flags = -D__KERNEL__ -fmacro-prefix-map=./=
vdso-kbuild-modflags = -DKBUILD_MODFILE='"$(curdir)$1"' -DKBUILD_MODNAME='"$1"' \
	-D__KBUILD_MODNAME=kmod_$1

vdso-asm-cflags = $(vdso-common-cppflags) $(vdso-common-include-flags) \
	$(vdso-common-kbuild-flags) -D__ASSEMBLY__ -fno-PIE -mabi=lp64 \
	-march=rv64imafdcv_zicsr_zifencei $(vdso-noarch-attr)
vdso-lds-cflags = $(vdso-common-cppflags) $(vdso-common-include-flags) \
	$(vdso-common-kbuild-flags) -D__ASSEMBLY__
vdso-lds-cflags += -DHAS_VGETTIMEOFDAY
vdso-vgettimeofday-src-include := /home/cloud/gitStudy/linux-6.12.37/lib/vdso/gettimeofday.c
vdso-c-common-cflags = $(vdso-common-cppflags) $(vdso-common-include-flags) \
	-include ./include/linux/compiler_types.h $(vdso-common-kbuild-flags) \
	-std=gnu11 -fshort-wchar -funsigned-char -fno-common -fno-PIE \
	-fno-strict-aliasing -mabi=lp64 -march=rv64imac_zicsr_zifencei \
	-mno-save-restore -DCONFIG_PAGE_OFFSET=0xff60000000000000 -mcmodel=medany \
	-fno-asynchronous-unwind-tables -fno-unwind-tables $(vdso-noarch-attr) \
	-mstrict-align -fno-delete-null-pointer-checks -O2 \
	-fno-allow-store-data-races -fstack-protector-strong \
	-fno-omit-frame-pointer -fno-optimize-sibling-calls \
	-fno-stack-clash-protection -fno-strict-overflow -fno-stack-check \
	-fconserve-stack -fno-builtin-wcslen -fno-builtin-wcslen -Wall -Wextra \
	-Wundef -Werror=implicit-function-declaration -Werror=implicit-int \
	-Werror=return-type -Werror=strict-prototypes -Wno-format-security \
	-Wno-trigraphs -Wno-frame-address -Wno-address-of-packed-member \
	-Wmissing-declarations -Wmissing-prototypes -Wframe-larger-than=2048 \
	-Wno-main -Wvla -Wno-pointer-sign -Wcast-function-type \
	-Wno-array-bounds -Wno-stringop-overflow -Wno-alloc-size-larger-than \
	-Wimplicit-fallthrough=5 -Werror=date-time \
	-Werror=incompatible-pointer-types -Werror=designated-init \
	-Wenum-conversion -Wunused -Wno-unused-but-set-variable \
	-Wno-unused-const-variable -Wno-packed-not-aligned -Wno-format-overflow \
	-Wno-format-truncation -Wno-stringop-truncation -Wno-override-init \
	-Wno-missing-field-initializers -Wno-type-limits \
	-Wno-shift-negative-value -Wno-maybe-uninitialized -Wno-sign-compare \
	-Wno-unused-parameter -mstack-protector-guard=tls \
	-mstack-protector-guard-reg=tp -mstack-protector-guard-offset=1232 \
	-fno-stack-protector -DDISABLE_BRANCH_PROFILING -fno-builtin -fPIC
vdso-vgettimeofday-extra-cflags = -include $(vdso-vgettimeofday-src-include)

# Force vdso.so to be materialized before assembling vdso.o.
$(curdir)vdso.o: $(vdso-so)

# preprocess rule for the linker script
$(vdso-lds): $(vdso-lds-src)
	$(vdso-cc) -E -P -C $(vdso-lds-cflags) -o $@ $<

# strip rule for the .so file
$(vdso-so): $(vdso-so-dbg) FORCE
	$(OBJCOPY) -S $< $@

# link rule for the .so file, .lds has to be first
$(vdso-so-dbg): $(vdso-lds) $(obj-vdso) FORCE
	$(vdso-ld) $(vdso-ldflags) -T $(vdso-lds) $(vdso-link-objs-full) -o $@.tmp && \
		$(vdso-objcopy) $(vdso-export-flags) $@.tmp $@ && \
		rm $@.tmp

gen-vdsosym := $(curdir)gen_vdso_offsets.sh
quiet_cmd_vdsosym = VDSOSYM $@
	cmd_vdsosym = $(NM) $< | $(gen-vdsosym) | LC_ALL=C sort > $@

include/generated/vdso-offsets.h: $(vdso-so-dbg) FORCE
	$(call if_changed,vdsosym)

$(vdso-asm-objs-full): $(curdir)%.o: $(curdir)%.S
	$(vdso-cc) -Wp,-MMD,$(curdir).$(@F).d $(vdso-asm-cflags) \
		$(call vdso-kbuild-modflags,$*) -c -o $@ $<

$(vdso-c-objs-full): $(curdir)%.o: $(curdir)%.c
	$(vdso-cc) -Wp,-MMD,$(curdir).$(@F).d $(vdso-c-common-cflags) \
		$(vdso-$*-extra-cflags) -DKBUILD_BASENAME='"$*"' \
		$(call vdso-kbuild-modflags,$*) \
		-c -o $@ $<
