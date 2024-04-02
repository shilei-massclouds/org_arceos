extern "C" {
    fn rust_main(cpu_id: usize, dtb: usize);
    #[cfg(feature = "smp")]
    fn rust_main_secondary(cpu_id: usize);
}

/// The earliest entry point for the secondary CPUs.
pub(crate) unsafe extern "C" fn rust_entry(cpu_id: usize, dtb: usize) {
    use axhal::mem::phys_to_virt;
    crate::clear_bss();
    axtrap::init_trap_vector();
    axhal::cpu::init_primary(cpu_id);

    // init fdt
    axhal::platform::mem::idmap_device(dtb);
    of::init_fdt_ptr(phys_to_virt(dtb.into()).as_usize() as *const u8);

    // HugeMap all device memory for allocator
    for m in of::memory_nodes() {
        for r in m.regions() {
            crate::platform::mem::idmap_device(r.starting_address as usize);
        }
    }

    axhal::platform::console::init_early();
    axhal::platform::time::init_early();
    // disable low address access
    axhal::arch::write_page_table_root0(0.into());
    rust_main(cpu_id, dtb);
}

#[cfg(feature = "smp")]
pub(crate) unsafe extern "C" fn rust_entry_secondary(cpu_id: usize) {
    axtrap::init_trap_vector();
    axhal::arch::write_page_table_root0(0.into()); // disable low address access
    axhal::cpu::init_secondary(cpu_id);
    rust_main_secondary(cpu_id);
}
