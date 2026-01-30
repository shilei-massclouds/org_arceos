use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use std::os::arceos::api::task::{self as api};

extern crate alloc;
use alloc::vec::Vec;

//
// Parameters
//
const TEST_ID: usize = %%TEST_ID%%;
const NUM_TASK_A: usize = %%NUM_TASK_A%%;
const NUM_TASK_B: usize = 1;

pub fn do_test() {
    println!("Test: {} ...", TEST_ID);

    let mut tasks = Vec::with_capacity(NUM_TASK_A + NUM_TASK_B);

    static LOCK: Mutex<usize> = Mutex::new(0);

    // TaskB Group
    for _ in 0..NUM_TASK_B {
        tasks.push(thread::spawn(move || {
            println!("TaskB: {}", api::ax_current_task_id());
            loop {
                let lock = LOCK.lock();
                thread::sleep(Duration::from_millis(100));
                println!("Got notify: {}", *lock);
                if *lock == NUM_TASK_A { break; }
            }
        }));
    }

    api::ax_yield_now();
    thread::sleep(Duration::from_millis(100));

    // TaskA Group
    for _ in 0..NUM_TASK_A {
        tasks.push(thread::spawn(move || {
            println!("TaskA: {}", api::ax_current_task_id());
            {
                let mut lock = LOCK.lock();
                *lock += 1;
            }
        }));
    }

    // Wait for all tasks exit.
    for task in tasks {
        let _ = task.join();
    }

    println!("Test: {} ok!", TEST_ID);
}
