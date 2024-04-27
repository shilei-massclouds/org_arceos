#![no_std]

#[macro_use]
extern crate log;
extern crate alloc;

use axerrno::{ax_err, AxError, AxResult};
use alloc::{string::String, sync::Arc, vec::Vec};
use axfs_vfs::{VfsNodeAttr, VfsNodeOps, VfsNodeRef, VfsNodeType, VfsOps, VfsResult};
use spinpreempt::SpinLock;

pub type FileType = axfs_vfs::VfsNodeType;

struct MountPoint {
    path: &'static str,
    fs: Arc<dyn VfsOps>,
}

impl MountPoint {
    pub fn new(path: &'static str, fs: Arc<dyn VfsOps>) -> Self {
        Self { path, fs }
    }
}

impl Drop for MountPoint {
    fn drop(&mut self) {
        self.fs.umount().ok();
    }
}

pub struct RootDirectory {
    main_fs: Arc<dyn VfsOps>,
    mounts: Vec<MountPoint>,
}

pub struct FsStruct {
    pub users: i32,
    pub in_exec: bool,
    curr_path: String,
    curr_dir: Option<VfsNodeRef>,
    root_dir: Option<Arc<RootDirectory>>,
}

impl FsStruct {
    pub fn new() -> Self {
        Self {
            users: 1,
            in_exec: false,
            curr_path: String::from("/"),
            curr_dir: None,
            root_dir: None,
        }
    }

    pub fn init(&mut self, root_dir: Arc<RootDirectory>) {
        self.root_dir = Some(root_dir);
        self.curr_dir = Some(self.root_dir.as_ref().unwrap().clone());
        self.curr_path = "/".into();
    }

    pub fn copy_fs_struct(&mut self, fs: Arc<SpinLock<FsStruct>>) {
        let locked_fs = &fs.lock();
        self.root_dir = locked_fs.root_dir.as_ref().map(|root_dir| root_dir.clone());
        self.curr_dir = locked_fs.curr_dir.as_ref().map(|curr_dir| curr_dir.clone());
        self.curr_path = locked_fs.curr_path.clone();
    }
}

impl FsStruct {
    fn parent_node_of(&self, dir: Option<&VfsNodeRef>, path: &str) -> VfsNodeRef {
        if path.starts_with('/') {
            assert!(self.root_dir.is_some());
            self.root_dir.clone().unwrap()
        } else {
            dir.cloned().unwrap_or_else(|| self.curr_dir.clone().unwrap())
        }
    }

    pub fn lookup(&self, dir: Option<&VfsNodeRef>, path: &str) -> AxResult<VfsNodeRef> {
        if path.is_empty() {
            return ax_err!(NotFound);
        }
        let node = self.parent_node_of(dir, path).lookup(path)?;
        if path.ends_with('/') && !node.get_attr()?.is_dir() {
            ax_err!(NotADirectory)
        } else {
            Ok(node)
        }
    }

    pub fn create_file(&self, dir: Option<&VfsNodeRef>, path: &str) -> AxResult<VfsNodeRef> {
        if path.is_empty() {
            return ax_err!(NotFound);
        } else if path.ends_with('/') {
            return ax_err!(NotADirectory);
        }
        let parent = self.parent_node_of(dir, path);
        parent.create(path, VfsNodeType::File)?;
        parent.lookup(path)
    }

    pub fn create_dir(&self, dir: Option<&VfsNodeRef>, path: &str) -> AxResult {
        match self.lookup(dir, path) {
            Ok(_) => ax_err!(AlreadyExists),
            Err(AxError::NotFound) => self.parent_node_of(dir, path).create(path, VfsNodeType::Dir),
            Err(e) => Err(e),
        }
    }

    pub fn current_dir(&self) -> AxResult<String> {
        Ok(self.curr_path.clone())
    }

    pub fn absolute_path(&self, path: &str) -> AxResult<String> {
        if path.starts_with('/') {
            Ok(axfs_vfs::path::canonicalize(path))
        } else {
            let path = self.curr_path.clone() + path;
            Ok(axfs_vfs::path::canonicalize(&path))
        }
    }

    pub fn set_current_dir(&mut self, path: &str) -> AxResult {
        let mut abs_path = self.absolute_path(path)?;
        if !abs_path.ends_with('/') {
            abs_path += "/";
        }
        if abs_path == "/" {
            self.curr_dir = Some(self.root_dir.as_ref().unwrap().clone());
            self.curr_path = "/".into();
            return Ok(());
        }

        let node = self.lookup(None, &abs_path)?;
        let attr = node.get_attr()?;
        if !attr.is_dir() {
            ax_err!(NotADirectory)
        } else if !attr.perm().owner_executable() {
            ax_err!(PermissionDenied)
        } else {
            self.curr_dir = Some(node);
            self.curr_path = abs_path;
            Ok(())
        }
    }
    pub fn remove_file(&self, dir: Option<&VfsNodeRef>, path: &str) -> AxResult {
        let node = self.lookup(dir, path)?;
        let attr = node.get_attr()?;
        if attr.is_dir() {
            ax_err!(IsADirectory)
        } else if !attr.perm().owner_writable() {
            ax_err!(PermissionDenied)
        } else {
            self.parent_node_of(dir, path).remove(path)
        }
    }
    pub fn remove_dir(&self, dir: Option<&VfsNodeRef>, path: &str) -> AxResult {
        if path.is_empty() {
            return ax_err!(NotFound);
        }
        let path_check = path.trim_matches('/');
        if path_check.is_empty() {
            return ax_err!(DirectoryNotEmpty); // rm -d '/'
        } else if path_check == "."
            || path_check == ".."
            || path_check.ends_with("/.")
            || path_check.ends_with("/..")
        {
            return ax_err!(InvalidInput);
        }
        if self.root_dir.as_ref().unwrap().contains(&self.absolute_path(path)?) {
            return ax_err!(PermissionDenied);
        }

        let node = self.lookup(dir, path)?;
        let attr = node.get_attr()?;
        if !attr.is_dir() {
            ax_err!(NotADirectory)
        } else if !attr.perm().owner_writable() {
            ax_err!(PermissionDenied)
        } else {
            self.parent_node_of(dir, path).remove(path)
        }
    }
    pub fn rename(&self, old: &str, new: &str) -> AxResult {
        if self.parent_node_of(None, new).lookup(new).is_ok() {
            warn!("dst file already exist, now remove it");
            self.remove_file(None, new)?;
        }
        self.parent_node_of(None, old).rename(old, new)
    }
}

impl RootDirectory {
    pub const fn new(main_fs: Arc<dyn VfsOps>) -> Self {
        Self {
            main_fs,
            mounts: Vec::new(),
        }
    }

    pub fn mount(&mut self, path: &'static str, fs: Arc<dyn VfsOps>) -> AxResult {
        info!("============== mount ...");
        if path == "/" {
            return ax_err!(InvalidInput, "cannot mount root filesystem");
        }
        if !path.starts_with('/') {
            return ax_err!(InvalidInput, "mount path must start with '/'");
        }
        if self.mounts.iter().any(|mp| mp.path == path) {
            return ax_err!(InvalidInput, "mount point already exists");
        }
        // create the mount point in the main filesystem if it does not exist
        self.main_fs.root_dir().create(path, FileType::Dir)?;
        fs.mount(path, self.main_fs.root_dir().lookup(path)?)?;
        self.mounts.push(MountPoint::new(path, fs));
        Ok(())
    }

    pub fn _umount(&mut self, path: &str) {
        self.mounts.retain(|mp| mp.path != path);
    }

    pub fn contains(&self, path: &str) -> bool {
        self.mounts.iter().any(|mp| mp.path == path)
    }

    fn lookup_mounted_fs<F, T>(&self, path: &str, f: F) -> AxResult<T>
    where
        F: FnOnce(Arc<dyn VfsOps>, &str) -> AxResult<T>,
    {
        debug!("lookup at root: {}", path);
        let path = path.trim_matches('/');
        if let Some(rest) = path.strip_prefix("./") {
            return self.lookup_mounted_fs(rest, f);
        }

        let mut idx = 0;
        let mut max_len = 0;

        // Find the filesystem that has the longest mounted path match
        // TODO: more efficient, e.g. trie
        for (i, mp) in self.mounts.iter().enumerate() {
            // skip the first '/'
            if path.starts_with(&mp.path[1..]) && mp.path.len() - 1 > max_len {
                max_len = mp.path.len() - 1;
                idx = i;
            }
        }

        if max_len == 0 {
            f(self.main_fs.clone(), path) // not matched any mount point
        } else {
            f(self.mounts[idx].fs.clone(), &path[max_len..]) // matched at `idx`
        }
    }
}

impl VfsNodeOps for RootDirectory {
    axfs_vfs::impl_vfs_dir_default! {}

    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        self.main_fs.root_dir().get_attr()
    }

    fn lookup(self: Arc<Self>, path: &str) -> VfsResult<VfsNodeRef> {
        self.lookup_mounted_fs(path, |fs, rest_path| fs.root_dir().lookup(rest_path))
    }

    fn create(&self, path: &str, ty: VfsNodeType) -> VfsResult {
        self.lookup_mounted_fs(path, |fs, rest_path| {
            if rest_path.is_empty() {
                Ok(()) // already exists
            } else {
                fs.root_dir().create(rest_path, ty)
            }
        })
    }

    fn remove(&self, path: &str) -> VfsResult {
        self.lookup_mounted_fs(path, |fs, rest_path| {
            if rest_path.is_empty() {
                ax_err!(PermissionDenied) // cannot remove mount points
            } else {
                fs.root_dir().remove(rest_path)
            }
        })
    }

    fn rename(&self, src_path: &str, dst_path: &str) -> VfsResult {
        self.lookup_mounted_fs(src_path, |fs, rest_path| {
            if rest_path.is_empty() {
                ax_err!(PermissionDenied) // cannot rename mount points
            } else {
                fs.root_dir().rename(rest_path, dst_path)
            }
        })
    }
}

pub fn init_fs() -> Arc<SpinLock<FsStruct>> {
    Arc::new(SpinLock::new(FsStruct::new()))
}
