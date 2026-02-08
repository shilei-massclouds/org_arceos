#[repr(C)]
pub(crate) struct TaskStruct {
    _padding: [u8; 1224],
    pub pid: i32,
}

pub(crate) fn _current() -> &'static TaskStruct {
    unsafe { &(*linux_current()) }
}

unsafe extern "C" {
    fn linux_current() -> *const TaskStruct;
}
