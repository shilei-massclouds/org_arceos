use axplat::init::InitIf;

struct InitIfImpl;

#[impl_plat_interface]
impl InitIf for InitIfImpl {
    /// Initializes the platform at the early stage for the primary core.
    ///
    /// This function should be called immediately after the kernel has booted,
    /// and performed earliest platform configuration and initialization (e.g.,
    /// early console, clocking).
    ///
    /// # Arguments
    ///
    /// * `hartid` is the physical CPU ID (just for riscv64).
    /// * `dtb_pa` is passed from the bootloader (typically the device tree blob
    /// address).
    ///
    /// # Before calling this function
    ///
    /// * CPU is booted in the kernel mode.
    /// * Early page table is set up, virtual memory is enabled.
    /// * CPU-local data is initialized.
    ///
    /// # After calling this function
    ///
    /// * Exception & interrupt handlers are set up.
    /// * Early console is initialized.
    /// * Current monotonic time and wall time can be obtained.
    fn init_early(hartid: usize, dtb_pa: usize) {
        linux_adaptor::init_early(hartid, dtb_pa);
        axcpu::init::init_trap();
        //crate::time::init_early();
    }

    /// Initializes the platform at the early stage for secondary cores.
    ///
    /// See [`init_early`] for details.
    #[cfg(feature = "smp")]
    fn init_early_secondary(_cpu_id: usize) {
        unimplemented!("init_early_secondary");
    }

    /// Initializes the platform at the later stage for the primary core.
    ///
    /// This function should be called after the kernel has done part of its
    /// initialization (e.g, logging, memory management), and finalized the rest of
    /// platform configuration and initialization.
    ///
    /// # Arguments
    ///
    /// * `hartid` is the physical CPU ID.
    /// * `dtb_pa` is passed from the bootloader (typically the device tree blob
    /// address).
    ///
    /// # Before calling this function
    ///
    /// * Kernel logging is initialized.
    /// * Fine-grained kernel page table is set up (if applicable).
    /// * Physical memory allocation is initialized (if applicable).
    ///
    /// # After calling this function
    ///
    /// * Interrupt controller is initialized (if applicable).
    /// * Timer interrupts are enabled (if applicable).
    /// * Other essential peripherals are initialized.
    fn init_later(hartid: usize, dtb_pa: usize) {
        linux_adaptor::init_later(hartid, dtb_pa);
        //#[cfg(feature = "irq")]
        //crate::irq::init_percpu();
        //crate::time::init_percpu();
    }

    /// Initializes the platform at the later stage for secondary cores.
    ///
    /// See [`init_later`] for details.
    #[cfg(feature = "smp")]
    fn init_later_secondary(_cpu_id: usize) {
        todo!()
    }
}
