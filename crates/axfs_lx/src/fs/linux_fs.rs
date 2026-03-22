use alloc::sync::Arc;

use axfs_vfs::{VfsNodeAttr, VfsNodeOps, VfsNodeRef, VfsNodeType, VfsOps};

use crate::dev::Disk;

pub struct LinuxFileSystem;

impl LinuxFileSystem {
    pub fn new(mut disk: Disk) -> Arc<Self> {
        Arc::new(Self)
    }
}

impl VfsOps for LinuxFileSystem {
    fn root_dir(&self) -> VfsNodeRef {
        todo!();
    }
}
