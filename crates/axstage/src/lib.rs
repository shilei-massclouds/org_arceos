//! ArceOS boot and init stages management
//! Enlightened by Inventory (https://github.com/dtolnay/inventory)

#![no_std]

pub enum AxStage {
    SetupEarlyConsole,
    ShowBanner,
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

pub fn call() {
    for plugin in inventory::iter::<AxPlugin> {
        (plugin.init_fn)(0, 0);
    }
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
