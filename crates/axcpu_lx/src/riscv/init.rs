//! Helper functions to initialize the CPU states on systems bootstrapping.

use axstage::{AxPlugin, AxStage};

/// Initializes trap handling on the current CPU.
///
/// In detail, it initializes the trap vector on RISC-V platforms.
fn init_trap() {
    unsafe extern "C" {
        fn handle_exception();
    }
    unsafe {
        crate::asm::write_trap_vector_base(handle_exception as usize);
    }
}

axstage::register!("AxTrap", AxStage::InitTrap, |_, _| {
    init_trap();
});
