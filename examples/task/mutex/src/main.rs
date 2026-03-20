#![cfg_attr(feature = "axstd", no_std)]
#![cfg_attr(feature = "axstd", no_main)]

#[macro_use]
#[cfg(feature = "axstd")]
extern crate axstd as std;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

#[cfg(feature = "axstd")]
use std::os::arceos::api::task::{self as api};

const NUM_TASKS: usize = 16;

#[cfg(feature = "axstd")]
fn test_basic() {
    static LOCK: Mutex<usize> = Mutex::new(0);
    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    println!("mutex test: ");

    let lock = LOCK.lock();

    for _ in 0..NUM_TASKS {
        thread::spawn(move || {
            println!("Task: {}", api::ax_current_task_id());
            let mut lock = LOCK.lock();

            *lock += 1;
            println!("Task: {} step1", api::ax_current_task_id());
            COUNTER.fetch_add(1, Ordering::SeqCst);
            println!("Task: {} step2", api::ax_current_task_id());
        });
    }

    println!("wait for threads ..");
    api::ax_yield_now();
    thread::sleep(Duration::from_millis(100));
    drop(lock);

    loop {
        let lock = LOCK.lock();
        println!("Now threads count: {}", *lock);
        let counter = COUNTER.load(Ordering::Acquire);
        //println!("threads started [{}].", counter);
        if counter == NUM_TASKS {
            break;
        }
        api::ax_yield_now();
    }

    println!("mutex: test OK!");
}

#[cfg_attr(feature = "axstd", no_mangle)]
fn main() {
    #[cfg(feature = "axstd")]
    test_basic();
}
