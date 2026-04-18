//! ArceOS boot and init stages management
//! Enlightened by Inventory (https://github.com/dtolnay/inventory)

#![no_std]

use core::sync::atomic::{AtomicUsize, Ordering};

#[derive(PartialEq)]
#[derive(Debug)]
pub enum AxStage {
    // [Task0]
    PrepareSystem,
    InitTrap,
    SetupEarlyConsole,
    SetupArchPre,
    ShowBanner,
    DetectPhysMem,
    SetupArch,
    SetupEarlyAlloc,
    SetupVM,
    InitPerCPU,
    SetupAlloc,
    InitSched,
    InitIRQ,
    StartKInitdPre,
    StartKInitd,
    StartKThreadd,
    EnterIdle,

    // [Task1]
    InitSMPPre,
    InitSMP,
    InitSMPPost,
    SetupAllocLate,
    InitDriver,
    InitFS,
    BootAppPre,
    BootApp,

    NumberOfStages,
}

type AxPluginInitFn = fn(arg0: usize, arg1: usize);

pub struct AxPlugin {
    stage: AxStage,
    name: &'static str,
    init_fn: AxPluginInitFn,
}

impl AxPlugin {
    pub const fn new(
        name: &'static str, stage: AxStage, init_fn: AxPluginInitFn
    ) -> Self {
        Self {
            stage,
            name,
            init_fn,
        }
    }
}

inventory::collect!(AxPlugin);

#[macro_export]
macro_rules! register {
    ($name:expr, $stage:expr, $init_fn:expr) => {
        inventory::submit! {
            AxPlugin::new($name, $stage, $init_fn)
        }
    };
}

static CUR_STAGE: AtomicUsize = AtomicUsize::new(AxStage::PrepareSystem as usize);

/// Call plugin on current stage and advance
pub fn advance(arg0: usize, arg1: usize) -> bool {
    let stage = CUR_STAGE.fetch_add(1, Ordering::SeqCst);
    if stage == AxStage::NumberOfStages as usize {
        return false;
    }
    // Safety: stage is always a valid AxStage value (from AxStage as usize)
    let stage = unsafe { core::mem::transmute_copy(&stage) };
    call(stage, arg0, arg1);
    true
}

/// Call all plugins registered on the `stage`
/// Note: The order is not guaranteed.
pub fn call(stage: AxStage, arg0: usize, arg1: usize) {
    let mut found = false;
    for plugin in inventory::iter::<AxPlugin> {
        if plugin.stage == stage {
            log::debug!("[{:?}]: '{}'", stage, plugin.name);
            (plugin.init_fn)(arg0, arg1);
            found = true;
        }
    }
    if !found {
        log::debug!("[{:?}]: No plugin", stage);
    }
}

/// Call the plugin by 'name'
pub fn call_exact(name: &str, arg0: usize, arg1: usize) {
    for plugin in inventory::iter::<AxPlugin> {
        if plugin.name == name {
            log::debug!("[{:?}]: '{}'", plugin.stage, plugin.name);
            return (plugin.init_fn)(arg0, arg1);
        }
    }
    panic!("No plugin '{}'", name);
}

/// Call each constructor in the .init_array section
pub fn init() {
    let mut ctor_ptr = __init_array_start as *const fn();
    let end_ptr = __init_array_end as *const fn();
    while ctor_ptr < end_ptr {
        unsafe {
            (*ctor_ptr)();
            ctor_ptr = ctor_ptr.add(1);
        }
    }
}

unsafe extern "C" {
    // Range of the .init_array section
    fn __init_array_start();
    fn __init_array_end();
}
