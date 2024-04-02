mod boot;
extern "C" {
    fn rust_main(cpu_id: usize, dtb: usize);
    #[cfg(feature = "smp")]
    fn rust_main_secondary(cpu_id: usize);
}

unsafe extern "C" fn rust_entry(cpu_id: usize, dtb: usize) {
    crate::clear_bss();
    axhal::cpu::init_primary(cpu_id);
    axtrap::init_trap_vector();
    rust_main(cpu_id, dtb);
}

#[cfg(feature = "smp")]
unsafe extern "C" fn rust_entry_secondary(cpu_id: usize) {
    axtrap::init_trap_vector();
    axhal::cpu::init_secondary(cpu_id);
    rust_main_secondary(cpu_id);
}
