/// Shutdown the whole system, including all CPUs.
pub fn terminate() -> ! {
    info!("Shutting down...");

    sbi_rt::system_reset(sbi_rt::Shutdown, sbi_rt::NoReason);

    #[cfg(linux_adaptor)]
    unsafe {
        machine_power_off();
    }

    warn!("It should shutdown!");
    loop {
        crate::arch::halt();
    }
}

unsafe extern "C" {
    fn machine_power_off();
}
