#![cfg_attr(not(test), no_std)]

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use axfile::fops::File;
use mutex::Mutex;
use spinpreempt::SpinLock;

pub struct FileTable {
    table: SlotVec<FileTableEntry>,
}

impl FileTable {
    pub const fn new() -> Self {
        Self {
            table: SlotVec::new(),
        }
    }

    pub fn get_file(&self, fd: usize) -> Option<Arc<Mutex<File>>> {
        self.table
            .get(fd-3)
            .map(|entry| entry.file.clone())
    }

    pub fn insert(&mut self, item: Arc<Mutex<File>>) -> usize {
        let entry = FileTableEntry::new(item);
        self.table.put(entry) + 3
    }

    pub fn remove(&mut self, fd: usize) {
        self.table.remove(fd-3);
    }
}

pub struct FileTableEntry {
    file: Arc<Mutex<File>>,
}

impl FileTableEntry {
    pub fn new(file: Arc<Mutex<File>>) -> Self {
        Self {
            file,
        }
    }
}

pub struct SlotVec<T> {
    // The slots to store items.
    slots: Vec<Option<T>>,
    // The number of occupied slots.
    // The i-th slot is occupied if `self.slots[i].is_some()`.
    num_occupied: usize,
}

impl<T> SlotVec<T> {
    /// New an empty vector.
    pub const fn new() -> Self {
        Self {
            slots: Vec::new(),
            num_occupied: 0,
        }
    }
    pub fn get(&self, idx: usize) -> Option<&T> {
        if idx >= self.slots.len() {
            return None;
        }
        self.slots[idx].as_ref()
    }
    /// Put an item into the vector.
    /// It may be put into any existing empty slots or the back of the vector.
    ///
    /// Return the index of the inserted item.
    pub fn put(&mut self, entry: T) -> usize {
        let idx = if self.num_occupied == self.slots.len() {
            self.slots.push(Some(entry));
            self.slots.len() - 1
        } else {
            let idx = self.slots.iter().position(|x| x.is_none()).unwrap();
            self.slots[idx] = Some(entry);
            idx
        };
        self.num_occupied += 1;
        idx
    }

    /// Remove and return the item at position `idx`.
    ///
    /// Return `None` if `idx` is out of bounds or the item has been removed.
    pub fn remove(&mut self, idx: usize) -> Option<T> {
        if idx >= self.slots.len() {
            return None;
        }
        let mut del_item = None;
        core::mem::swap(&mut del_item, &mut self.slots[idx]);
        if del_item.is_some() {
            debug_assert!(self.num_occupied > 0);
            self.num_occupied -= 1;
        }
        del_item
    }
}

pub fn init_files() -> Arc<SpinLock<FileTable>> {
    Arc::new(SpinLock::new(FileTable::new()))
}
