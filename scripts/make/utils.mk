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
  @truncate -s $(DISK_SIZE) $(1)
  @mkfs.ext4 $(1)
endef

define make_disk_image
  $(if $(filter $(1),fat32), $(call make_disk_image_fat32,$(2)))
  $(if $(filter $(1),ext4), $(call make_disk_image_ext4,$(2)))
endef

define make_rootfs_image_ext4_from_tarball
  @if [ ! -f "$(1)" ]; then \
    set -e; \
    img="$(1)"; \
    tarball="$(2)"; \
    script="scripts/init/lk_init.sh"; \
    mnt_dir=$$(mktemp -d /tmp/lk-rootfs.XXXXXX); \
    cleanup() { \
      if mountpoint -q "$$mnt_dir"; then \
        sudo umount "$$mnt_dir"; \
      fi; \
      rm -rf "$$mnt_dir"; \
    }; \
    trap cleanup EXIT; \
    printf "    $(GREEN_C)Creating$(END_C) rootfs image \"$$img\" from tarball \"$$tarball\" ...\n"; \
    if [ ! -f "$$tarball" ]; then \
      echo "rootfs tarball not found: $$tarball" >&2; \
      exit 1; \
    fi; \
    if [ ! -f "$$script" ]; then \
      echo "lk init script not found: $$script" >&2; \
      exit 1; \
    fi; \
    truncate -s "$(DISK_SIZE)" "$$img"; \
    mkfs.ext4 "$$img"; \
	    sudo mount -o loop "$$img" "$$mnt_dir"; \
	    printf "    $(GREEN_C)Populating$(END_C) rootfs image \"$$img\" from tarball \"$$tarball\" ...\n"; \
	    sudo tar -xzf "$$tarball" -C "$$mnt_dir"; \
	    printf "    $(GREEN_C)Populated!$(END_C)\n"; \
	    printf "    $(GREEN_C)Updating$(END_C) rootfs image \"$$img\" with lk init script ...\n"; \
	    sudo install -D -m 0755 "$$script" "$$mnt_dir/etc/lk_init.sh"; \
	    printf "    $(GREEN_C)Updating$(END_C) rootfs image \"$$img\" with DNS config ...\n"; \
	    printf "nameserver 10.0.2.3\n" | sudo tee "$$mnt_dir/etc/resolv.conf" >/dev/null; \
	    printf "    $(GREEN_C)Updated!$(END_C)\n"; \
	  fi
endef
