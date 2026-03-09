use linux_adaptor::LinuxAdaptorState;

#[allow(clippy::absurd_extreme_comparisons)]
pub fn start_secondary_cpus() {
    linux_adaptor::advance_to(LinuxAdaptorState::InitSmp);
}

/// The main entry point of the ArceOS runtime for secondary cores.
///
/// It is called from the bootstrapping code in the specific platform crate.
#[axplat::secondary_main]
pub fn rust_main_secondary(_cpu_id: usize) -> ! {
    /*
    axhal::init_percpu_secondary(cpu_id);
    axhal::init_early_secondary(cpu_id);

    ENTERED_CPUS.fetch_add(1, Ordering::Release);
    info!("Secondary CPU {} started.", cpu_id);

    #[cfg(feature = "paging")]
    axmm::init_memory_management_secondary();

    axhal::init_later_secondary(cpu_id);

    #[cfg(feature = "multitask")]
    axtask::init_scheduler_secondary();

    #[cfg(feature = "ipi")]
    axipi::init();

    info!("Secondary CPU {:x} init OK.", cpu_id);
    super::INITED_CPUS.fetch_add(1, Ordering::Release);

    while !super::is_init_ok() {
        core::hint::spin_loop();
    }

    #[cfg(feature = "irq")]
    axhal::asm::enable_irqs();

    #[cfg(all(feature = "tls", not(feature = "multitask")))]
    super::init_tls();

    #[cfg(feature = "multitask")]
    axtask::run_idle();
    #[cfg(not(feature = "multitask"))]
    loop {
        axhal::asm::wait_for_irqs();
    }
    */
    todo!();
}
