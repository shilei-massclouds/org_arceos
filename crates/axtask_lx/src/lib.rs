//! Linux sched module which is compatible with ArceOS `axtask`

#![cfg_attr(not(test), no_std)]
#![feature(doc_cfg)]

mod api;
pub use self::api::*;

#[macro_use]
extern crate log;

mod task;
mod linux;

/*
#![feature(doc_auto_cfg)]
#![feature(linkage)]

#[cfg(test)]
mod tests;

cfg_if::cfg_if! {
    if #[cfg(feature = "multitask")] {
        #[macro_use]
        extern crate log;
        extern crate alloc;

        #[macro_use]
        mod run_queue;
        mod task;
        mod task_ext;
        mod api;
        mod wait_queue;

        #[cfg(feature = "irq")]
        mod timers;

        #[doc(cfg(feature = "multitask"))]
        pub use self::api::*;
        pub use self::api::{sleep, sleep_until, yield_now};
    } else {
        mod api_s;
        pub use self::api_s::{sleep, sleep_until, yield_now};
    }
}
*/
