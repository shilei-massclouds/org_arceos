#![no_std]

#[macro_use]
extern crate log;
extern crate alloc;

mod dev;
mod fs;
mod mounts;

use axdriver::{prelude::*, AxDeviceContainer};
use alloc::sync::Arc;
use lazy_init::LazyInit;
use axfs_vfs::VfsOps;
use fstree::RootDirectory;

cfg_if::cfg_if! {
    if #[cfg(feature = "myfs")] { // override the default filesystem
        type FsType = Arc<RamFileSystem>;
    } else if #[cfg(feature = "fatfs")] {
        use crate::fs::fatfs::FatFileSystem;
        type FsType = Arc<FatFileSystem>;
    }
}

/// Initializes filesystems by block devices.
pub fn init_filesystems(mut blk_devs: AxDeviceContainer<AxBlockDevice>) -> FsType {
    error!("Initialize filesystems...");

    let dev = blk_devs.take_one().expect("No block device found!");
    info!("  use block device 0: {:?}", dev.device_name());
    let disk = self::dev::Disk::new(dev);

    cfg_if::cfg_if! {
        if #[cfg(feature = "myfs")] { // override the default filesystem
            let main_fs = fs::myfs::new_myfs(disk);
        } else if #[cfg(feature = "fatfs")] {
            static FAT_FS: LazyInit<Arc<fs::fatfs::FatFileSystem>> = LazyInit::new();
            FAT_FS.init_by(Arc::new(fs::fatfs::FatFileSystem::new(disk)));
            FAT_FS.init();
            let main_fs = FAT_FS.clone();
        }
    }

    main_fs
}

pub fn init_rootfs(main_fs: Arc<dyn VfsOps>) -> Arc<RootDirectory> {
    let mut root_dir = RootDirectory::new(main_fs);

    #[cfg(feature = "devfs")]
    root_dir
        .mount("/dev", mounts::devfs())
        .expect("failed to mount devfs at /dev");

    root_dir
        .mount("/dev/shm", mounts::ramfs())
        .expect("failed to mount ramfs at /dev/shm");

    #[cfg(feature = "ramfs")]
    root_dir
        .mount("/tmp", mounts::ramfs())
        .expect("failed to mount ramfs at /tmp");

    // Mount another ramfs as procfs
    #[cfg(feature = "procfs")]
    root_dir // should not fail
        .mount("/proc", mounts::procfs().unwrap())
        .expect("fail to mount procfs at /proc");

    // Mount another ramfs as sysfs
    #[cfg(feature = "sysfs")]
    root_dir // should not fail
        .mount("/sys", mounts::sysfs().unwrap())
        .expect("fail to mount sysfs at /sys");

    Arc::new(root_dir)
}
