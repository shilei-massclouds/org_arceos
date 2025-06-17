# For Aarch64

CFLAGS := -nostdinc -isystem /usr/lib/gcc-cross/aarch64-linux-gnu/11/include \
          -I./arch/arm64/include -I./arch/arm64/include/generated -I./include -I./arch/arm64/include/uapi \
          -I./arch/arm64/include/generated/uapi -I./include/uapi -I./include/arm64_generated/uapi \
          -include ./include/linux/kconfig.h -include ./include/linux/compiler_types.h \
          -D__KERNEL__ -mlittle-endian -DKASAN_SHADOW_SCALE_SHIFT=3 -Wall -Wundef -Wno-trigraphs \
          -fno-strict-aliasing -fno-common -fshort-wchar -fno-PIE -Werror=implicit-function-declaration \
          -Werror=implicit-int -Wno-format-security -std=gnu89 -mgeneral-regs-only -DCONFIG_CC_HAS_K_CONSTRAINT=1 \
          -fno-asynchronous-unwind-tables -Wno-psabi -mabi=lp64 -mbranch-protection=pac-ret+leaf+bti \
          -Wa,-march=armv8.4-a -DARM64_ASM_ARCH='"armv8.4-a"' -DKASAN_SHADOW_SCALE_SHIFT=3 \
          -fno-delete-null-pointer-checks -Wno-frame-address -Wno-format-truncation -Wno-format-overflow \
          -Wno-address-of-packed-member -O2 -fno-allow-store-data-races -Wframe-larger-than=2048 \
          -fstack-protector-strong -Wno-unused-but-set-variable -Wimplicit-fallthrough -Wno-unused-const-variable \
          -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-var-tracking-assignments \
          -g -Wvla -Wno-pointer-sign -Wno-stringop-truncation \
          -Wno-zero-length-bounds -Wno-array-bounds -Wno-stringop-overflow -Wno-restrict \
          -Wno-maybe-uninitialized -fno-strict-overflow -fno-merge-all-constants -fmerge-constants \
          -fno-stack-check -fconserve-stack -Werror=date-time -Werror=incompatible-pointer-types \
          -Werror=designated-init -fmacro-prefix-map=./= -Wno-packed-not-aligned -mstack-protector-guard=sysreg \
          -mstack-protector-guard-reg=sp_el0 -mstack-protector-guard-offset=1136 -Idrivers/block -DARCH_AARCH64

OBJS += cl_mine_aarch64.o
