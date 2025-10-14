# Top Makefile

include $(CURDIR)/scripts/Makefile.include

TARGET = libclinux.a

OBJS :=

obj-y := cl/ init/ arch/ kernel/ mm/ fs/ crypto/ block/ lib/ libfdt/ drivers/

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

clean:
	$(Q)rm -f libclinux.a
	$(Q)find . -name "*.o" | xargs rm -f
	$(Q)find . -name "*.txt" | xargs rm -f

FORCE:

.PHONY: all clean FORCE
