use alloc::ffi::CString;
use alloc::format;
use alloc::string::{String, ToString};
use core::ffi::c_char;
use axfs_vfs::{VfsNodeAttr, VfsNodeOps, VfsNodePerm, VfsNodeType, VfsResult, VfsError};

/// A virtual block device behaves like `/dev/vdx`.
pub struct VdxDev {
    devt: usize,
}

impl VdxDev {
    pub fn new(name: &str) -> Self {
        let name = format!("/dev/{}", name);
        let c_name = CString::new(name).unwrap();
        let devt = unsafe {
            cl_early_lookup_bdev(c_name.as_ptr())
        };
        Self { devt }
    }
}

impl VfsNodeOps for VdxDev {
    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        if self.devt == 0 {
            return Err(VfsError::NotFound);
        }
        let size = unsafe {
            cl_bdev_size(self.devt)
        };
        let blk_size = unsafe {
            cl_bdev_logic_block_size(self.devt)
        };

        Ok(VfsNodeAttr::new(
            VfsNodePerm::default_file(),
            VfsNodeType::BlockDevice,
            size as u64,
            (size / blk_size) as u64,
        ))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let ret = unsafe {
            cl_read_block(self.devt, buf.as_mut_ptr(), buf.len(), offset as usize)
        };
        log::error!("offset: {}, buf.len: {}, ret = {}", offset, buf.len(), ret);
        Ok(ret)
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> VfsResult<usize> {
        let ret = unsafe {
            cl_write_block(self.devt, buf.as_ptr(), buf.len(), offset as usize)
        };
        log::error!("offset: {}, buf.len: {}, ret = {}", offset, buf.len(), ret);
        Ok(ret)
    }

    axfs_vfs::impl_vfs_non_dir_default! {}
}

unsafe extern "C" {
    fn cl_early_lookup_bdev(name: *const c_char) -> usize;
    fn cl_bdev_size(devt: usize) -> usize;
    fn cl_bdev_logic_block_size(devt: usize) -> usize;
    fn cl_read_block(devt: usize, buf: *mut u8, buf_size: usize, offset: usize) -> usize;
    fn cl_write_block(devt: usize, buf: *const u8, buf_size: usize, offset: usize) -> usize;
}

/*
use axfs_vfs::{VfsNodeAttr, VfsNodeOps, VfsNodePerm, VfsNodeType, VfsResult};


impl VfsNodeOps for NullDev {

    fn truncate(&self, _size: u64) -> VfsResult {
        Ok(())
    }

    axfs_vfs::impl_vfs_non_dir_default! {}
}
*/
