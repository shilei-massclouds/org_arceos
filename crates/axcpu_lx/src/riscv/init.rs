//! Helper functions to initialize the CPU states on systems bootstrapping.

/// Initializes trap handling on the current CPU.
///
/// In detail, it initializes the trap vector on RISC-V platforms.
pub fn init_trap() {
    unsafe extern "C" {
        fn handle_exception();
    }
    unsafe {
        crate::asm::write_trap_vector_base(handle_exception as usize);
    }
}
