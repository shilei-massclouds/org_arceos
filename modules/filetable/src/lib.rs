#![cfg_attr(not(test), no_std)]

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use axfile::fops::File;
use mutex::AxMutex;

pub struct FileTable {
    table: SlotVec<FileTableEntry>,
}

impl FileTable {
    pub const fn new() -> Self {
        Self {
            table: SlotVec::new(),
        }
    }

    pub fn get_file(&self, fd: usize) -> Option<Arc<AxMutex<File>>> {
        self.table
            .get(fd-3)
            .map(|entry| entry.file.clone())
    }

    pub fn insert(&mut self, item: Arc<AxMutex<File>>) -> usize {
        let entry = FileTableEntry::new(item);
        self.table.put(entry) + 3
    }
}

pub struct FileTableEntry {
    file: Arc<AxMutex<File>>,
}

impl FileTableEntry {
    pub fn new(file: Arc<AxMutex<File>>) -> Self {
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
}
