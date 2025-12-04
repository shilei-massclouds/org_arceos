/// Shutdown the whole system, including all CPUs.
pub fn terminate() -> ! {
    info!("Shutting down...");

    #[cfg(linux_adaptor)]
    unsafe {
        machine_power_off();
    }

    #[cfg(not(linux_adaptor))]
    sbi_rt::system_reset(sbi_rt::Shutdown, sbi_rt::NoReason);

    warn!("It should shutdown!");
    loop {
        crate::arch::halt();
    }
}

unsafe extern "C" {
    fn machine_power_off();
}
