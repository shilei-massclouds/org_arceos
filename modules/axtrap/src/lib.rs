#![cfg_attr(not(test), no_std)]
#![feature(asm_const)]

#[macro_use]
extern crate log;

mod arch;

pub fn init_trap_vector() {
    arch::set_trap_vector_base(trap_vector_base as usize);
}

extern "C" {
    fn trap_vector_base();
}
