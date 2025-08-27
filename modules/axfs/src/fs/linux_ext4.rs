use crate::dev::Disk;
use core::mem;
use core::ffi::{c_char, CStr};
use alloc::sync::Arc;
use axfs_vfs::{VfsOps, VfsNodeRef, VfsNodeOps, VfsResult, VfsNodeType};
use axfs_vfs::{VfsError, VfsDirEntry, VfsNodeAttr};
use axfs_vfs::impl_vfs_non_dir_default;
use alloc::ffi::CString;
use alloc::string::String;
use alloc::format;
use axerrno::ax_err;
use axerrno::LinuxError;
use core::sync::atomic::{AtomicUsize, Ordering};

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

const O_RDONLY: usize   = 0o000;
const O_WRONLY: usize   = 0o001;
const O_CREAT: usize    = 0o100;
const O_DIRECTORY: usize = 0o200000;

const S_IRUSR: usize = 0o400;
const S_IWUSR: usize = 0o200;
//const S_IXUSR: usize = 0o100;

/// seek relative to beginning of file
const SEEK_SET: usize = 0;

pub struct LinuxExt4 {
    root: Arc<DirNode>,
}

impl LinuxExt4 {
    /// Create a new instance.
    pub fn new() -> Self {
        Self {
            root: DirNode::new("/"),
        }
    }
}

/// Adaptor for linux ext4 module.
pub(crate) fn new(_disk: Disk) -> Arc<dyn VfsOps> {
    /*
     * Of cause we can use NATIVE disk, but it is inefficent.
     * So now just use linux-disk directly.
     * In future, we can introduce a feature as a choice
     * for native or linux.
     */
    Arc::new(LinuxExt4::new())
}

impl VfsOps for LinuxExt4 {
    fn mount(&self, _path: &str, _mount_point: VfsNodeRef) -> VfsResult {
        unimplemented!();
    }

    fn root_dir(&self) -> VfsNodeRef {
        self.root.clone()
    }
}

///
/// The directory node for Linux Ext4 filesystem.
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

    /// Checks whether a node with the given name exists in this directory.
    pub fn exist(&self, path: &str) -> Option<(VfsNodeType, usize)> {
        debug!("exist at ext4: {path}");
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

    /// Construct full path based on 'self.path'
    fn full_path(&self, path: &str) -> String {
        if self.path == "/" {
            format!("/{}", path)
        } else {
            format!("{}/{}", self.path, path)
        }
    }
}

impl VfsNodeOps for DirNode {
    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        Ok(VfsNodeAttr::new_dir(4096, 0))
    }

    fn parent(&self) -> Option<VfsNodeRef> {
        debug!("parent of {} ..", self.path);
        let (prefix, _self) = split_path_reverse(&self.path);
        let prefix = prefix?;
        let parent = if prefix.len() == 0 {
            "/"
        } else {
            prefix
        };
        debug!("parent of {}: {}", self.path, parent);
        Some(DirNode::new(parent) as VfsNodeRef)
    }

    fn lookup(self: Arc<Self>, path: &str) -> VfsResult<VfsNodeRef> {
        let path = self.full_path(path);
        debug!("lookup at ext4: {}", path);
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

    fn create(&self, path: &str, ty: VfsNodeType) -> VfsResult {
        let path = self.full_path(path);
        debug!("create {ty:?} at ext4: {path}");

        let c_path = CString::new(path).unwrap();
        match ty {
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
            VfsNodeType::Dir => {
                let ret = unsafe {
                    cl_sys_mkdir(c_path.as_ptr(), 0o700)
                };
                if ret < 0 {
                    return ax_err!(Io);
                }
                return Ok(());
            },
            _ => return Err(VfsError::Unsupported),
        };
    }

    fn remove(&self, path: &str) -> VfsResult {
        let path = self.full_path(path);
        debug!("remove at ext4: {path}");
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
        debug!("read_dir: start_idx[{start_idx}] path: {}", self.path);
        let last_count = self.last_count.load(Ordering::Relaxed);
        assert!(start_idx == 0 || start_idx == last_count);
        if start_idx != 0 {
            debug!("Note: alread used all entries and reset 'last_count' to zero.");
            self.last_count.store(0, Ordering::Relaxed);
            return Ok(0);
        }

        let c_path = CString::new(self.path.clone()).unwrap();

        let mut buf: [u8; 512] = [0; 512];
        let fd = unsafe { cl_sys_open(c_path.as_ptr(), O_DIRECTORY, 0) };
        if fd < 0 {
            panic!("bad dir fd.");
        }

        let count = unsafe {
            cl_sys_getdents64(fd as usize, buf.as_mut_ptr(), buf.len())
        };
        if count < 0 {
            panic!("get dents64 err: {}", count);
        }

        let mut count = count as usize;
        assert!(count < buf.len());
        debug!("sizeof {}", mem::size_of::<LinuxDirent64>());
        let mut idx = 0;
        let mut ptr = buf.as_ptr();
        while count > 0 {
            let de_ptr = ptr as *const LinuxDirent64;
            unsafe {
                debug!("LinuxDirent64: ino {}, off {:#x}, reclen {}, type {}",
                   (*de_ptr).d_ino,
                   (*de_ptr).d_off,
                   (*de_ptr).d_reclen,
                   (*de_ptr).d_type);
            }
            let reclen = unsafe { (*de_ptr).d_reclen } as usize;
            let d_type = unsafe { (*de_ptr).d_type };
            let d_name = unsafe { ptr.offset(NAME_OFFSET) };
            let d_name = unsafe {
                CStr::from_ptr(d_name)
            };

            debug!("name: {}", d_name.to_str().unwrap());
            let r_type = match d_type {
                DT_REG => VfsNodeType::File,
                DT_DIR => VfsNodeType::Dir,
                _ => unimplemented!("{}", d_type),
            };
            dirents[idx] = VfsDirEntry::new(d_name.to_str().unwrap(), r_type);
            idx += 1;

            ptr = unsafe { ptr.offset(reclen as isize) };
            count -= reclen;
        }

        if unsafe { cl_sys_close(fd as usize) } < 0 {
            panic!("close dir fd err.");
        }

        self.last_count.store(idx, Ordering::Relaxed);
        Ok(idx)
    }

    axfs_vfs::impl_vfs_dir_default! {}
}

/// The file node in the Linux Ext4 filesystem.
///
/// It implements [`axfs_vfs::VfsNodeOps`].
pub struct FileNode {
    path: String,
}

impl FileNode {
    pub(super) fn new(path: &str) -> Arc<Self> {
        Arc::new(Self {
            path: String::from(path),
        })
    }
}

impl VfsNodeOps for FileNode {
    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        debug!("get_attr path {}", self.path);
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
        debug!("truncate '{}' to {}", self.path, size);
        let c_path = CString::new(self.path.clone()).unwrap();
        let ret = unsafe {
            cl_sys_truncate(c_path.as_ptr(), size as usize)
        };
        assert_eq!(ret, 0);
        Ok(())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        debug!("read '{}'", self.path);
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
        debug!("write '{}'", self.path);
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

    impl_vfs_non_dir_default! {}
}

fn split_path_reverse(path: &str) -> (Option<&str>, &str) {
    let trimmed_path = path.trim_end_matches('/');
    trimmed_path.rfind('/').map_or((None, trimmed_path), |n| {
        (Some(&trimmed_path[..n]), &trimmed_path[n + 1..])
    })
}

unsafe extern "C" {
    fn cl_sys_open(fname: *const c_char, flags: usize, mode: usize) -> i32;
    fn cl_sys_close(fd: usize) -> i32;

    fn cl_sys_truncate(path: *const c_char, len: usize) -> i32;
    fn cl_sys_unlink(path: *const c_char) -> i32;

    fn cl_sys_lseek(fd: usize, offset: usize, whence: usize);

    fn cl_sys_mkdir(path: *const c_char, mode: usize) -> i32;
    fn cl_sys_rmdir(path: *const c_char) -> i32;

    fn cl_sys_getdents64(fd: usize, buf: *mut u8, len: usize) -> i32;

    fn cl_sys_read(fd: usize, buf: *mut u8, count: usize) -> i32;

    fn cl_sys_write(fd: usize, buf: *const u8, count: usize) -> i32;

    fn cl_sys_exist(
        path: *const c_char, r_type: *mut usize, r_size: *mut usize
    ) -> i32;
}
