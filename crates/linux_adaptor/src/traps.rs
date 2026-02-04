//! Traps exported to Linux

use linux_config::PtRegs;

#[unsafe(no_mangle)]
fn ax_handle_ebreak(ptr_regs: usize)
{
    let ptr_regs = ptr_regs as *const PtRegs;
    unimplemented!("regs ptr: {:?}", ptr_regs);
}
