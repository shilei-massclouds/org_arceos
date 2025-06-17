# Main makefile

TARGET = libclinux.a

# Original linux modules
OBJS := virtio_blk.o virtio.o virtio_mmio.o virtio_ring.o

# Adaptor files, we will re-write them in Rust in future.
OBJS += cl_mine.o main.o workqueue.o \
		printk.o vsprintf.o ctype.o kstrtox.o \
		alloc.o genhd.o bus.o klist.o locking.o \
		driver.o of_platform.o dma.o string.o \
		device.o ida.o sched.o blk_mq.o \
		string_helpers.o block_ops.o bio.o \
		scatterlist.o paging.o

include scripts/$(AX_ARCH).make

CROSS_ = $(AX_ARCH)-linux-musl-
CC = $(CROSS_)gcc
AR = $(CROSS_)ar

all: prepare $(TARGET)

$(TARGET): $(OBJS)
	$(AR) r $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -DKBUILD_MODFILE='"$@"' -DKBUILD_BASENAME='"$@"' -DKBUILD_MODNAME='"$@"' -c -o $@ $<

prepare:
	printf "Prepare\n"
	rm -f ./include/generated
	ln -rs ./include/$(AX_ARCH)_generated ./include/generated

clean:
	rm -f *.o libclinux.a

.PHONY: all clean prepare
