TARGETS := init vfork execl run signal

CC := $(AX_ARCH)-linux-gnu-gcc
STRIP := $(AX_ARCH)-linux-gnu-strip
DST_DIR := $(AX_ARCH)/sbin
PREFIX_TARGETS := $(addprefix $(DST_DIR)/,$(TARGETS))

all: $(PREFIX_TARGETS)

$(DST_DIR)/%: %.c
	@mkdir -p $(DST_DIR)
	$(CC) $< -o $@
	$(STRIP) $@
