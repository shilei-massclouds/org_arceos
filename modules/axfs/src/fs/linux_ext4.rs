use crate::dev::Disk;
use core::mem;
use core::ffi::{c_char, CStr};
use alloc::sync::{Arc, Weak};
use axfs_vfs::{VfsOps, VfsNodeRef, VfsNodeOps, VfsResult, VfsNodeType};
use axfs_vfs::{VfsError, VfsDirEntry, VfsNodeAttr};
use axfs_vfs::impl_vfs_non_dir_default;
use spin::once::Once;
use spin::RwLock;
use alloc::collections::BTreeMap;
use alloc::{string::String, vec::Vec};
use alloc::ffi::CString;

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

pub struct LinuxExt4 {
    parent: Once<VfsNodeRef>,
    root: Arc<DirNode>,
}

impl LinuxExt4 {
    /// Create a new instance.
    pub fn new() -> Self {
        let handle = unsafe { cl_ext4_root_handle() };
        Self {
            parent: Once::new(),
            root: DirNode::new(handle),
        }
    }

    /// Returns the root directory node in [`Arc<DirNode>`](DirNode).
    pub fn root_dir_node(&self) -> Arc<DirNode> {
        self.root.clone()
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
    fn mount(&self, _path: &str, mount_point: VfsNodeRef) -> VfsResult {
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
    handle: usize,  /* linux dir node handle */
}

impl DirNode {
    pub(super) fn new(handle: usize) -> Arc<Self> {
        Arc::new(Self {
            handle
        })
    }

    /// Checks whether a node with the given name exists in this directory.
    pub fn exist(&self, name: &str) -> bool {
        let c_name = CString::new(name).unwrap();
        let ret = unsafe { cl_vfs_exists(self.handle, c_name.as_ptr()) };
        if ret == 0 {
            false
        } else {
            true
        }
    }

    /// Creates a new node with the given name and type in this directory.
    pub fn create_node(&self, name: &str, ty: VfsNodeType) -> VfsResult {
        error!("create node: {name} {ty:?}");
        if self.exist(name) {
            error!("AlreadyExists {name}");
            return Err(VfsError::AlreadyExists);
        }
        let c_name = CString::new(name).unwrap();
        match ty {
            VfsNodeType::File => {
                let _ = unsafe {
                    cl_vfs_create_file(self.handle, c_name.as_ptr())
                };
            },
            VfsNodeType::Dir => {
                let _ = unsafe {
                    cl_vfs_create_dir(self.handle, c_name.as_ptr())
                };
            },
            _ => return Err(VfsError::Unsupported),
        };
        Ok(())
    }

    /// Removes a node by the given name in this directory.
    pub fn remove_node(&self, name: &str) -> VfsResult {
        let c_name = CString::new(name).unwrap();
        let _ = unsafe {
            cl_vfs_remove(self.handle, c_name.as_ptr())
        };
        Ok(())
    }
}

impl VfsNodeOps for DirNode {
    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        Ok(VfsNodeAttr::new_dir(4096, 0))
    }

    fn parent(&self) -> Option<VfsNodeRef> {
        let handle = unsafe { cl_vfs_parent(self.handle) };
        if handle != 0 {
            Some(DirNode::new(handle) as VfsNodeRef)
        } else {
            None
        }
    }

    fn lookup(self: Arc<Self>, path: &str) -> VfsResult<VfsNodeRef> {
        let (name, rest) = split_path(path);
        let node = match name {
            "" | "." => Ok(self.clone() as VfsNodeRef),
            ".." => self.parent().ok_or(VfsError::NotFound),
            _ => {
                let c_name = CString::new(name).unwrap();
                let mut d_type: u8 = 0;
                let handle = unsafe {
                    cl_vfs_lookup(self.handle, c_name.as_ptr(), &mut d_type)
                };
                if handle == 0 {
                    return Err(VfsError::NotFound);
                }
                error!("lookup {:#X} type {}", handle, d_type);
                match d_type {
                    DT_REG => Ok(FileNode::new(handle) as VfsNodeRef),
                    DT_DIR => Ok(DirNode::new(handle) as VfsNodeRef),
                    _ => unimplemented!("{}", d_type),
                }
            },
        }?;

        if let Some(rest) = rest {
            node.lookup(rest)
        } else {
            Ok(node)
        }
    }

    fn create(&self, path: &str, ty: VfsNodeType) -> VfsResult {
        error!("create {ty:?} at ext4: {path}");
        let (name, rest) = split_path(path);
        if let Some(rest) = rest {
            panic!("{name} {rest}");
        } else if name.is_empty() || name == "." || name == ".." {
            panic!("already exists: {name}");
        } else {
            self.create_node(name, ty)
        }
    }

    fn remove(&self, path: &str) -> VfsResult {
        error!("remove at ext4: {path}");
        let (name, rest) = split_path(path);
        if let Some(rest) = rest {
            panic!("{name} {rest}");
        } else if name.is_empty() || name == "." || name == ".." {
            Err(VfsError::InvalidInput) // remove '.' or '..
        } else {
            self.remove_node(name)
        }
    }

    fn read_dir(&self, start_idx: usize, dirents: &mut [VfsDirEntry]) -> VfsResult<usize> {
        if start_idx != 0 {
            error!("Note: we must handle read_dir properly.");
            return Ok(0);
        }

        let buf: [u8; 512] = [0; 512];
        let mut ret = unsafe {
            cl_vfs_read_dir(self.handle, buf.as_ptr(), buf.len())
        };
        assert!(ret < buf.len());
        error!("sizeof {}", mem::size_of::<LinuxDirent64>());
        let mut idx = 0;
        let mut ptr = buf.as_ptr();
        while ret > 0 {
            let de_ptr = ptr as *const LinuxDirent64;
            unsafe {
                error!("LinuxDirent64: ino {}, off {:#x}, reclen {}, type {}",
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

            error!("name: {}", d_name.to_str().unwrap());
            let r_type = match d_type {
                DT_REG => VfsNodeType::File,
                DT_DIR => VfsNodeType::Dir,
                _ => unimplemented!("{}", d_type),
            };
            dirents[idx] = VfsDirEntry::new(d_name.to_str().unwrap(), r_type);
            idx += 1;

            ptr = unsafe { ptr.offset(reclen as isize) };
            ret -= reclen;
        }
        Ok(idx)
    }

    axfs_vfs::impl_vfs_dir_default! {}
}

/// The file node in the Linux Ext4 filesystem.
///
/// It implements [`axfs_vfs::VfsNodeOps`].
pub struct FileNode {
    handle: usize,  /* linux dir node handle */
}

impl FileNode {
    pub(super) fn new(handle: usize) -> Arc<Self> {
        Arc::new(Self {
            handle
        })
    }
}

impl VfsNodeOps for FileNode {
    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        let size = unsafe { cl_vfs_file_size(self.handle) };
        Ok(VfsNodeAttr::new_file(size as _, 0))
    }

    fn truncate(&self, size: u64) -> VfsResult {
        error!("Note: No impl. size: {}", size);
        Ok(())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let ret = unsafe {
            cl_vfs_read(self.handle, offset as usize, buf.as_mut_ptr(), buf.len())
        };
        Ok(ret)
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> VfsResult<usize> {
        let ret = unsafe {
            cl_vfs_write(self.handle, offset as usize, buf.as_ptr(), buf.len())
        };
        Ok(ret)
    }

    impl_vfs_non_dir_default! {}
}

fn split_path(path: &str) -> (&str, Option<&str>) {
    let trimmed_path = path.trim_start_matches('/');
    trimmed_path.find('/').map_or((trimmed_path, None), |n| {
        (&trimmed_path[..n], Some(&trimmed_path[n + 1..]))
    })
}

unsafe extern "C" {
    fn cl_ext4_root_handle() -> usize;
    fn cl_vfs_parent(curr: usize) -> usize;

    fn cl_vfs_lookup(
        parent: usize, name: *const c_char, ret_type: *mut u8
    ) -> usize;

    fn cl_vfs_file_size(handle: usize) -> usize;
    fn cl_vfs_exists(parent: usize, name: *const c_char) -> usize;
    fn cl_vfs_create_dir(parent: usize, dname: *const c_char) -> usize;
    fn cl_vfs_create_file(parent: usize, fname: *const c_char) -> usize;
    fn cl_vfs_remove(parent: usize, name: *const c_char) -> usize;
    fn cl_vfs_read_dir(handle: usize, buf: *const u8, len: usize) -> usize;

    fn cl_vfs_read(
        handle: usize, offset: usize, buf: *mut u8, len: usize
    ) -> usize;

    fn cl_vfs_write(
        handle: usize, offset: usize, buf: *const u8, len: usize
    ) -> usize;
}
