use alloc::ffi::CString;
use alloc::vec::Vec;
use core::ffi::c_char;
use core::ptr;

pub struct CStringArray {
    inner: Vec<CString>,
}

impl CStringArray {
    pub fn new(first: Option<&str>, params: &[&str]) -> Self {
        let mut inner = Vec::with_capacity(params.len() + first.map_or(0, |_| 1));
        if let Some(first) = first {
            inner.push(CString::new(first).expect("bad init arg"));
        }
        inner.extend(
            params
                .iter()
                .map(|&item| CString::new(item).expect("bad init env")),
        );
        Self { inner }
    }

    pub fn as_cstr_array(&self) -> Vec<*const c_char> {
        let mut array = self
            .inner
            .iter()
            .map(|item| item.as_ptr())
            .collect::<Vec<*const c_char>>();
        array.push(ptr::null());
        array
    }
}
