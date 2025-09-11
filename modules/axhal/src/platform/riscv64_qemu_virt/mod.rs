mod boot;

pub mod console;
pub mod mem;
pub mod misc;
pub mod time;

#[cfg(feature = "irq")]
pub mod irq;

#[cfg(feature = "smp")]
pub mod mp;

unsafe extern "C" {
    fn rust_main(cpu_id: usize, dtb: usize);
    #[cfg(feature = "smp")]
    fn rust_main_secondary(cpu_id: usize);
}

/// Convert Hardware CPU-ID to Logical CPU-ID
/// Logical CPU-ID is a consecutive sequence starting from ZERO.
#[inline]
fn hartid_to_logical_id(hartid: usize) -> usize {
    use core::sync::atomic::{AtomicUsize, Ordering};

    // Array which is indexed by hartid.
    const ARRAY_MAX_SIZE: usize = 64;
    static mut CPUID_ARRAY: [usize; ARRAY_MAX_SIZE] = [usize::MAX; ARRAY_MAX_SIZE];
    static SEQ_NUM: AtomicUsize = AtomicUsize::new(0);

    assert!(hartid < ARRAY_MAX_SIZE);
    // SAFETY: this is just like percpu, each hart can only touch its own element.
    unsafe {
        if CPUID_ARRAY[hartid] != usize::MAX {
            return CPUID_ARRAY[hartid];
        }

        let cpuid = SEQ_NUM.fetch_add(1, Ordering::SeqCst);
        CPUID_ARRAY[hartid] = cpuid;
        cpuid
    }
}

unsafe extern "C" fn rust_entry(cpu_id: usize, dtb: usize) {
    let cpu_id = hartid_to_logical_id(cpu_id);
    assert_eq!(cpu_id, 0);
    crate::mem::clear_bss();
    crate::cpu::init_primary(cpu_id);
    self::time::init_early();
    rust_main(cpu_id, dtb);
}

#[cfg(feature = "smp")]
unsafe extern "C" fn rust_entry_secondary(cpu_id: usize) {
    crate::cpu::init_secondary(cpu_id);
    rust_main_secondary(cpu_id);
}

/// Initializes the platform devices for the primary CPU.
///
/// For example, the interrupt controller and the timer.
pub fn platform_init() {
    #[cfg(feature = "irq")]
    self::irq::init_percpu();
    self::time::init_percpu();
}

/// Initializes the platform devices for secondary CPUs.
#[cfg(feature = "smp")]
pub fn platform_init_secondary() {
    #[cfg(feature = "irq")]
    self::irq::init_percpu();
    self::time::init_percpu();
}
