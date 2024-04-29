use task::{Tid, TaskStruct};
use axerrno::LinuxResult;

pub fn copy_thread(
    _task: &mut TaskStruct,
    _entry: Option<*mut dyn FnOnce()>,
    _stack: Option<usize>,
    _tid: Tid
) -> LinuxResult {
    unimplemented!("x86_64: copy_thread");
}
