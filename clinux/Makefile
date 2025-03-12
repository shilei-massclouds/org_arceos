CFLAGS := -isystem -nostdinc -fno-PIE -mabi=lp64d -march=rv64imafdc \
    -fno-asynchronous-unwind-tables -fno-unwind-tables \
    -fno-common -fno-stack-protector -mcmodel=medany -D__KERNEL__ \
    -O2 -Wno-stringop-overflow -Wno-format-truncation -Wno-format-security \
    -Werror=implicit-function-declaration -Wno-address-of-packed-member -Werror=implicit-function-declaration

TARGET = libhello.a
OBJS := hello.o mine.o
OBJS += origin/sbi.o
OBJS += origin/virtio_blk.ko

CROSS_ = riscv64-linux-gnu-
CC = $(CROSS_)gcc
AR = $(CROSS_)ar

all: clean $(TARGET)

$(TARGET): $(OBJS)
	$(AR) r $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o libhello.a
