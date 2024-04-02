#![no_std]
#![feature(asm_const)]
#![feature(naked_functions)]
#![feature(const_option)]

mod arch;

/// Fills the `.bss` section with zeros.
#[allow(dead_code)]
pub(crate) fn clear_bss() {
    unsafe {
        core::slice::from_raw_parts_mut(_sbss as usize as *mut u8, _ebss as usize - _sbss as usize)
            .fill(0);
    }
}

pub fn hack_link() {
}

extern "C" {
    fn _stext();
    fn _etext();
    fn _srodata();
    fn _erodata();
    fn _sdata();
    fn _edata();
    fn _sbss();
    fn _ebss();
    fn _ekernel();
}

