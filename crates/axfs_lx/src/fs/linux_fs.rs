use alloc::format;
use alloc::sync::Arc;
use alloc::string::String;
use alloc::ffi::CString;
use core::ffi::{c_char, CStr};
use core::sync::atomic::{AtomicUsize, Ordering};

use axerrno::{AxError, LinuxError, ax_err};
use axfs_vfs::{VfsNodeAttr, VfsNodeOps, VfsNodeRef, VfsNodeType, VfsOps, VfsResult, VfsError, VfsDirEntry};

use crate::dev::Disk;
use linux_adaptor::LinuxAdaptorState;

//
// Open flags in linux
//
const O_RDONLY: usize   = 0o000;
const O_WRONLY: usize   = 0o001;
const O_CREAT: usize    = 0o100;
const O_DIRECTORY: usize = 0o200000;

const S_IRUSR: usize = 0o400;
const S_IWUSR: usize = 0o200;
//const S_IXUSR: usize = 0o100;

/// seek relative to beginning of file
const SEEK_SET: usize = 0;

pub struct LinuxFileSystem {
    root: Arc<DirNode>,
}

impl LinuxFileSystem {
    pub fn new(mut _disk: Disk) -> Arc<Self> {
        linux_adaptor::advance_to(LinuxAdaptorState::PrepareNamespace);
        Arc::new(Self {
            root: DirNode::new("/"),
        })
    }
}

impl VfsOps for LinuxFileSystem {
    fn root_dir(&self) -> VfsNodeRef {
        self.root.clone()
    }
}

///
/// The directory node for Linux filesystem.
///
struct DirNode {
    path: String,
    last_count: AtomicUsize,
}

impl DirNode {
    pub(super) fn new(path: &str) -> Arc<Self> {
        Arc::new(Self {
            path: String::from(path),
            last_count: AtomicUsize::new(0),
        })
    }

    /// Construct full path based on 'self.path'
    fn full_path(&self, path: &str) -> String {
        let formal_path = path.trim_start_matches('/');
        if self.path == "/" {
            format!("/{}", formal_path)
        } else {
            format!("{}/{}", self.path, formal_path)
        }
    }

    /// Checks whether a node with the given name exists in this directory.
    pub fn exist(&self, path: &str) -> Option<(VfsNodeType, usize)> {
        let c_path = CString::new(path).unwrap();
        let mut ty = 0;
        let mut size = 0;
        let ret = unsafe {
            cl_sys_exist(c_path.as_ptr(), &mut ty, &mut size)
        };

        if ret < 0 {
            if ret == -LinuxError::ENOENT.code() {
                return None;
            }
            panic!("unknown err for checking existence.");
        }

        let r_type = match ty as u8 {
            DT_REG => VfsNodeType::File,
            DT_DIR => VfsNodeType::Dir,
            _ => unimplemented!("{}", ty),
        };
        Some((r_type, size))
    }
}

impl VfsNodeOps for DirNode {
    fn create(&self, path: &str, ty: VfsNodeType) -> VfsResult {
        let path = self.full_path(path);
        error!("create {ty:?} '{path}'");
        let c_path = CString::new(path).unwrap();
        match ty {
            VfsNodeType::Dir => {
                let ret = unsafe {
                    cl_sys_mkdir(c_path.as_ptr(), 0o700)
                };
                if ret < 0 {
                    if -ret == LinuxError::EEXIST as i32 {
                        return Err(AxError::AlreadyExists);
                    }
                    return ax_err!(Io);
                }
                return Ok(());
            },
            VfsNodeType::File => {
                unsafe {
                    let fd = cl_sys_open(c_path.as_ptr(), O_CREAT, S_IRUSR|S_IWUSR);
                    if fd < 0 {
                        return ax_err!(Io);
                    }
                    cl_sys_close(fd as usize);
                }
                return Ok(());
            },
            _ => return Err(VfsError::Unsupported),
        }
    }

    fn remove(&self, path: &str) -> VfsResult {
        let path = self.full_path(path);
        let c_path = CString::new(path.clone()).unwrap();

        if let Some((ty, _sz)) = self.exist(&path) {
            let ret = match ty {
                VfsNodeType::File => unsafe { cl_sys_unlink(c_path.as_ptr()) },
                VfsNodeType::Dir => unsafe { cl_sys_rmdir(c_path.as_ptr()) },
                _ => {
                    return Err(VfsError::Unsupported);
                },
            };
            if ret < 0 {
                ax_err!(Io)
            } else {
                Ok(())
            }
        } else {
            Err(VfsError::NotFound)
        }
    }

    fn read_dir(&self, start_idx: usize, dirents: &mut [VfsDirEntry]) -> VfsResult<usize> {
        todo!();
    }

    fn parent(&self) -> Option<VfsNodeRef> {
        todo!();
    }

    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        todo!();
    }

    fn lookup(self: Arc<Self>, path: &str) -> VfsResult<VfsNodeRef> {
        let path = self.full_path(path);
        error!("lookup {}", path);
        if let Some((ty, _sz)) = self.exist(&path) {
            match ty {
                VfsNodeType::File => Ok(FileNode::new(&path) as VfsNodeRef),
                VfsNodeType::Dir => Ok(DirNode::new(&path) as VfsNodeRef),
                _ => Err(VfsError::Unsupported),
            }
        } else {
            Err(VfsError::NotFound)
        }
    }

    axfs_vfs::impl_vfs_dir_default! {}
}

/// The file node in the Linux Ext4 filesystem.
///
/// It implements [`axfs_vfs::VfsNodeOps`].
pub struct FileNode {
    path: String,
}

impl VfsNodeOps for FileNode {
    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        let c_path = CString::new(self.path.clone()).unwrap();
        let mut _ty = 0;
        let mut size = 0;
        let ret = unsafe {
            cl_sys_exist(c_path.as_ptr(), &mut _ty, &mut size)
        };
        assert_eq!(ret, 0);
        Ok(VfsNodeAttr::new_file(size as _, 0))
    }

    fn truncate(&self, size: u64) -> VfsResult {
        let c_path = CString::new(self.path.clone()).unwrap();
        let ret = unsafe {
            cl_sys_truncate(c_path.as_ptr(), size as usize)
        };
        assert_eq!(ret, 0);
        Ok(())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let c_path = CString::new(self.path.clone()).unwrap();
        let fd = unsafe {
            cl_sys_open(c_path.as_ptr(), O_RDONLY, 0)
        };

        let ret = unsafe {
            cl_sys_lseek(fd as usize, offset as usize, SEEK_SET);
            cl_sys_read(fd as usize, buf.as_mut_ptr(), buf.len())
        };
        if ret < 0 {
            ax_err!(Io)
        } else {
            if fd >= 0 {
                unsafe { cl_sys_close(fd as usize); }
            }
            Ok(ret as usize)
        }
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> VfsResult<usize> {
        let c_path = CString::new(self.path.clone()).unwrap();
        let fd = unsafe {
            cl_sys_open(c_path.as_ptr(), O_WRONLY, 0)
        };

        let ret = unsafe {
            cl_sys_lseek(fd as usize, offset as usize, SEEK_SET);
            cl_sys_write(fd as usize, buf.as_ptr(), buf.len())
        };
        if ret < 0 {
            ax_err!(Io)
        } else {
            if fd >= 0 {
                unsafe { cl_sys_close(fd as usize); }
            }
            Ok(ret as usize)
        }
    }

    axfs_vfs::impl_vfs_non_dir_default! {}
}

impl FileNode {
    pub(super) fn new(path: &str) -> Arc<Self> {
        Arc::new(Self {
            path: String::from(path),
        })
    }
}

unsafe extern "C" {
    fn cl_sys_mkdir(path: *const c_char, mode: usize) -> i32;
    fn cl_sys_exist(
        path: *const c_char,
        r_type: *mut usize,
        r_size: *mut usize,
    ) -> i32;

    fn cl_sys_open(fname: *const c_char, flags: usize, mode: usize) -> i32;
    fn cl_sys_close(fd: usize) -> i32;
    fn cl_sys_truncate(path: *const c_char, len: usize) -> i32;

    fn cl_sys_lseek(fd: usize, offset: usize, whence: usize);
    fn cl_sys_write(fd: usize, buf: *const u8, count: usize) -> i32;
    fn cl_sys_read(fd: usize, buf: *mut u8, count: usize) -> i32;

    fn cl_sys_unlink(path: *const c_char) -> i32;
    fn cl_sys_rmdir(path: *const c_char) -> i32;
}

/*
unsafe extern "C" {

    fn cl_sys_getdents64(fd: usize, buf: *mut u8, len: usize) -> i32;



}
*/

/*

fn split_path_reverse(path: &str) -> (Option<&str>, &str) {
    let trimmed_path = path.trim_end_matches('/');
    trimmed_path.rfind('/').map_or((None, trimmed_path), |n| {
        (Some(&trimmed_path[..n]), &trimmed_path[n + 1..])
    })
}
*/
/*
#[repr(C)]
struct LinuxDirent64 {
    d_ino:      u64,
    d_off:      i64,
    d_reclen:   u16,
    d_type:     u8,

    /* followed by d_name[] */
}

/// LinuxDirent64.d_name offset
const NAME_OFFSET: isize = 8 + 8 + 2 + 1;

/// Type for LinuxDirent64.d_type
const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;

*/
