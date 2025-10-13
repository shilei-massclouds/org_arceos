# Top Makefile

include $(CURDIR)/scripts/Makefile.include

TARGET = libclinux.a

OBJS :=
# Original linux modules

OBJS += math/reciprocal_div.o
OBJS += crypto/api.o crypto/algapi.o crypto/blake2s.o crypto/blake2s-generic.o
OBJS += crypto/chacha.o
OBJS += crypto/shash.o crypto/crc32_generic.o crypto/crc32c_generic.o
OBJS += time/timekeeping.o time/timer.o time/hrtimer.o time/time.o
OBJS += of/base.o of/property.o of/address.o of/irq.o of/fdt.o
OBJS += of/of_reserved_mem.o of/kobj.o of/platform.o of/device.o
OBJS += proc/generic.o

# Adaptor files, we will re-write them in Rust in future.
OBJS += cl_mine.o main.o softirq.o \
		cl_dummy.o \
		mount_ops.o cl_syscalls.o \
		test_block.o test_fs.o

obj-y := init/ arch/ kernel/ mm/ fs/ block/ lib/ libfdt/ drivers/

OBJ_LIST := $(patsubst %/, %/obj_list.txt, $(obj-y))

_OBJS = $(shell cat $(OBJ_LIST) | xargs)

include include/config/auto.conf

all: $(TARGET)

$(TARGET): $(OBJS) $(OBJ_LIST)
	$(Q)rm -f $@
	$(Q)$(AR) r $@ $(OBJS) $(_OBJS)

$(OBJ_LIST): FORCE
	$(Q)$(MAKE) --no-print-directory -f ./scripts/Makefile.build obj=$@

%.o: %.c
	$(CC) $(CFLAGS) -DKBUILD_MODFILE='"$@"' -DKBUILD_BASENAME='"$@"' -DKBUILD_MODNAME='"$@"' -c -o $@ $<

%/%.o: %/%.c
	$(CC) $(CFLAGS) -DKBUILD_MODFILE='"$@"' -DKBUILD_BASENAME='"$@"' -DKBUILD_MODNAME='"$@"' -c -o $@ $<

clean:
	$(Q)rm -f libclinux.a
	$(Q)find . -name "*.o" | xargs rm -f
	$(Q)find . -name "*.txt" | xargs rm -f

FORCE:

.PHONY: all clean FORCE
