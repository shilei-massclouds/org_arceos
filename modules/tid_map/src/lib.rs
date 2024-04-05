#![no_std]

extern crate alloc;
use alloc::collections::BTreeMap;
use spinlock::SpinNoIrq;
use task::TaskRef;

type TaskId = usize;

static TID_MAP: SpinNoIrq<BTreeMap<TaskId, TaskRef>> = SpinNoIrq::new(BTreeMap::new());

pub fn get_task(tid: TaskId) -> Option<TaskRef> {
    TID_MAP.lock().get(&tid).cloned()
}

pub fn register_task(tid: TaskId, task: TaskRef) {
    TID_MAP.lock().insert(tid, task);
}
