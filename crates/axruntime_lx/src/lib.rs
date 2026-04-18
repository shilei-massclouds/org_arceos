//! Alternative runtime library for platform riscv64-dp1000.

#![cfg_attr(not(test), no_std)]
#![feature(doc_auto_cfg)]

#[macro_use]
extern crate axlog;

#[cfg(all(target_os = "none", not(test)))]
mod lang_items;

#[cfg(feature = "smp")]
mod mp;

use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "irq")]
use linux_adaptor::LinuxAdaptorState;
use axstage::{AxStage, AxPlugin};

static INITED: AtomicBool = AtomicBool::new(false);

const LOGO: &str = r#"
       d8888                            .d88888b.   .d8888b.
      d88888                           d88P" "Y88b d88P  Y88b
     d88P888                           888     888 Y88b.
    d88P 888 888d888  .d8888b  .d88b.  888     888  "Y888b.
   d88P  888 888P"   d88P"    d8P  Y8b 888     888     "Y88b.
  d88P   888 888     888      88888888 888     888       "888
 d8888888888 888     Y88b.    Y8b.     Y88b. .d88P Y88b  d88P
d88P     888 888      "Y8888P  "Y8888   "Y88888P"   "Y8888P"
"#;

/// The main entry point of the ArceOS runtime.
///
/// It is called from the bootstrapping code in the specific platform crate (see
/// [`axplat::main`]).
///
/// `cpu_id` is the logic ID of the current CPU, and `arg` is passed from the
/// bootloader (typically the device tree blob address).
///
/// In multi-core environment, this function is called on the primary core, and
/// secondary cores call [`rust_main_secondary`].
#[cfg_attr(not(test), axplat::main)]
pub fn rust_main(hartid: usize, dtb_pa: usize) -> ! {
    axstage::init();

    //
    // Stages:
    //
    // [Task0]
    // PrepareSystem
    // InitTrap
    // SetupEarlyConsole
    // SetupArchPre
    // ShowBanner
    // SetupArch
    // SetupEarlyAlloc
    // SetupVM
    // InitPerCPU
    // SetupAlloc
    // InitSched
    // InitIRQ
    // StartKInitdPre
    // StartKInitd
    // StartKThreadd
    // EnterIdle
    //
    // [Task1]
    // InitSMPPre
    // InitSMP
    // InitSMPPost
    // SetupAllocLate
    // InitDriver
    // InitFS
    // BootAppPre
    // BootApp
    //
    while axstage::advance(hartid, dtb_pa) {}

    axtask::system_exit();
}

axstage::register!("AxBanner", AxStage::ShowBanner, |hartid, dtb_pa| {
    ax_println!("{}", LOGO);

    ax_println!(
        "\
        arch = {}\n\
        platform = {}\n\
        target = {}\n\
        build_mode = {}\n\
        log_level = {}\n\
        ",
        axconfig::ARCH,
        axconfig::PLATFORM,
        option_env!("AX_TARGET").unwrap_or(""),
        option_env!("AX_MODE").unwrap_or(""),
        option_env!("AX_LOG").unwrap_or(""),
    );

    info!("Primary hartid {} started, dtb_pa = {:#x}.", hartid, dtb_pa);
});

axstage::register!("AxInitSMPPost", AxStage::InitSMPPost, |_, _| {
    INITED.store(true, Ordering::Release);
});

axstage::register!("AxBootAppPre", AxStage::BootAppPre, |_, _| {
    // free init mem and then set system_state to running
    linux_adaptor::advance_to(LinuxAdaptorState::FreeInitMem);
});

axstage::register!("AxBootApp", AxStage::BootApp, |_, _| {
    // Invoke app's main()
    unsafe { main(); }
});

struct LogIfImpl;

#[crate_interface::impl_interface]
impl axlog::LogIf for LogIfImpl {
    fn console_write_str(s: &str) {
        axhal::console::write_bytes(s.as_bytes());
    }

    fn current_time() -> core::time::Duration {
        axhal::time::monotonic_time()
    }

    fn current_cpu_id() -> Option<usize> {
        #[cfg(feature = "smp")]
        if is_init_ok() {
            Some(axhal::percpu::this_cpu_id())
        } else {
            None
        }
        #[cfg(not(feature = "smp"))]
        Some(0)
    }

    fn current_task_id() -> Option<u64> {
        if is_init_ok() {
            #[cfg(feature = "multitask")]
            {
                axtask::current_may_uninit().map(|curr| curr.id().as_u64())
            }
            #[cfg(not(feature = "multitask"))]
            None
        } else {
            None
        }
    }
}

fn is_init_ok() -> bool {
    INITED.load(Ordering::Acquire)
}

unsafe extern "C" {
    /// Application's entry point.
    fn main();
}
