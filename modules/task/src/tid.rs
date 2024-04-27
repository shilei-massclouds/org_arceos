/// Pid Allocator
/// Pids never repeat.

use core::sync::atomic::{AtomicUsize, Ordering};

static NEXT_TID: AtomicUsize = AtomicUsize::new(0);

pub fn alloc_tid() -> usize {
    NEXT_TID.fetch_add(1, Ordering::Relaxed)
}
