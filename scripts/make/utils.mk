# Utility definitions and functions

GREEN_C := \033[92;1m
CYAN_C := \033[96;1m
YELLOW_C := \033[93;1m
GRAY_C := \033[90m
WHITE_C := \033[37m
END_C := \033[0m

define run_cmd
  @printf '$(WHITE_C)$(1)$(END_C) $(GRAY_C)$(2)$(END_C)\n'
  @$(1) $(2)
endef

define make_disk_image_fat32
  @printf "    $(GREEN_C)Creating$(END_C) FAT32 disk image \"$(1)\" ...\n"
  @dd if=/dev/zero of=$(1) bs=1M count=64
  @mkfs.fat -F 32 $(1)
endef

define make_disk_image
  $(if $(filter $(1),fat32), $(call make_disk_image_fat32,$(2)))
endef

define build_linux_image
  @mkdir -p ./mnt
  @sudo mount $(1) ./mnt
  @sudo mkdir -p ./mnt/opt
  @sudo mkdir -p ./mnt/lib
  @sudo mkdir -p ./mnt/lib64
  @sudo mkdir -p ./mnt/sbin
  @sudo mkdir -p ./mnt/bin
  @sudo mkdir -p ./mnt/testcases
  @sudo cp ./payload/syscalls ./mnt/opt/
  @sudo cp ./payload/$(AX_ARCH)/*.so.* ./mnt/lib/
  @sudo cp ./payload/$(AX_ARCH)/*.so.* ./mnt/lib64/
  @sudo cp ./payload/$(AX_ARCH)/sbin/* ./mnt/sbin/
  -@sudo cp ./payload/$(AX_ARCH)/busybox ./mnt/bin/sh
  -@sudo cp ./payload/$(AX_ARCH)/busybox ./mnt/bin/grep
  -@sudo cp ./payload/$(AX_ARCH)/testcases/* ./mnt/testcases/
  ls -l ./mnt/sbin
  ls -l ./mnt/lib
  ls -l ./mnt/testcases
  @sudo umount ./mnt
  @rm -rf mnt
endef
