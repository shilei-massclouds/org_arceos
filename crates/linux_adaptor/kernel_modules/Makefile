# Top Makefile

include $(CURDIR)/scripts/Makefile.include

TARGET = libclinux.a

obj-y := cl/ init/ arch/ kernel/ mm/ fs/ crypto/ block/ lib/ libfdt/ drivers/ ipc/

OBJ_LIST := $(patsubst %/, %/obj_list.txt, $(obj-y))

include include/config/auto.conf

all: $(TARGET)

$(TARGET): $(OBJ_LIST)
	$(Q)rm -f $@
	$(Q)$(AR) r $@ $(_OBJS)

$(OBJ_LIST): FORCE
	$(Q)$(MAKE) --no-print-directory -f ./scripts/Makefile.build obj=$@

clean:
	$(Q)rm -f libclinux.a
	$(Q)find . -name "*.o" | xargs rm -f
	$(Q)find . -name "*.txt" | xargs rm -f
	$(Q)find . -name "*.so" | xargs rm -f
	$(Q)find . -name "*.so.dbg" | xargs rm -f

FORCE:

.PHONY: all clean FORCE
