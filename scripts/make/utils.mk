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
  @truncate -s $(DISK_SIZE) $(1)
  @mkfs.fat -F 32 $(1)
endef

define make_disk_image_ext4
  @printf "    $(GREEN_C)Creating$(END_C) EXT4 disk image \"$(1)\" ...\n"
  @rm -f $(1)
  @truncate -s $(DISK_SIZE) $(1)
  @mkfs.ext4 $(1)
endef

define make_disk_image
  $(if $(filter $(1),fat32), $(call make_disk_image_fat32,$(2)))
  $(if $(filter $(1),ext4), $(call make_disk_image_ext4,$(2)))
endef

define make_rootfs_image_ext4_from_tarball
  @set -e; \
    img="$(1)"; \
    tarball="$(2)"; \
    sysinit="scripts/init/lk_sysinit.sh"; \
    script="scripts/init/lk_init.sh"; \
    inittab="scripts/init/lk_inittab"; \
    mnt_dir=$$(mktemp -d /tmp/lk-rootfs.XXXXXX); \
    cleanup() { \
      if mountpoint -q "$$mnt_dir"; then \
        sudo umount "$$mnt_dir"; \
      fi; \
      rm -rf "$$mnt_dir"; \
    }; \
    trap cleanup EXIT; \
    if [ ! -f "$$tarball" ]; then \
      echo "rootfs tarball not found: $$tarball" >&2; \
      exit 1; \
    fi; \
    if [ ! -f "$$sysinit" ]; then \
      echo "lk sysinit script not found: $$sysinit" >&2; \
      exit 1; \
    fi; \
    if [ ! -f "$$script" ]; then \
      echo "lk init script not found: $$script" >&2; \
      exit 1; \
    fi; \
    if [ ! -f "$$inittab" ]; then \
      echo "lk inittab not found: $$inittab" >&2; \
      exit 1; \
    fi; \
    printf "    $(GREEN_C)Creating$(END_C) rootfs image \"$$img\" from tarball \"$$tarball\" ...\n"; \
    rm -f "$$img"; \
    truncate -s "$(DISK_SIZE)" "$$img"; \
    mkfs.ext4 "$$img"; \
    sudo mount -o loop "$$img" "$$mnt_dir"; \
    printf "    $(GREEN_C)Populating$(END_C) rootfs image \"$$img\" from tarball \"$$tarball\" ...\n"; \
    sudo tar -xzf "$$tarball" -C "$$mnt_dir"; \
    printf "    $(GREEN_C)Populated!$(END_C)\n"; \
    printf "    $(GREEN_C)Installing$(END_C) lk init files into \"$$img\" ...\n"; \
    sudo install -D -m 0755 "$$sysinit" "$$mnt_dir/etc/lk_sysinit.sh"; \
    sudo install -D -m 0755 "$$script" "$$mnt_dir/etc/lk_init.sh"; \
    sudo install -D -m 0644 "$$inittab" "$$mnt_dir/etc/inittab"; \
    printf "    $(GREEN_C)Updated!$(END_C)\n"
endef
