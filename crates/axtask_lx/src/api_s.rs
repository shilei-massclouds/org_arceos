//! Task APIs for single-task configuration.

use axstage::{AxPlugin, AxStage};

/// For single-task situation, we just relax the CPU and wait for incoming
/// interrupts.
pub fn yield_now() {
    if cfg!(feature = "irq") {
        axhal::asm::wait_for_irqs();
    } else {
        core::hint::spin_loop();
    }
}

/// For single-task situation, we just busy wait for the given duration.
pub fn sleep(dur: core::time::Duration) {
    axhal::time::busy_wait(dur);
}

/// For single-task situation, we just busy wait until reaching the given
/// deadline.
pub fn sleep_until(deadline: axhal::time::TimeValue) {
    axhal::time::busy_wait_until(deadline);
}

axstage::register!("AxCallMain", AxStage::StartKInitd, |hartid, dtb_pa| {
    while axstage::advance(hartid, dtb_pa) {}
});

pub fn system_exit() -> ! {
    debug!("main task exited: exit_code={}", 0);
    axhal::power::system_off();
}
