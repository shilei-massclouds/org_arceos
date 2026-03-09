//! State management of LinuxAdaptor

use core::sync::atomic::{AtomicUsize, Ordering};
use linux_adaptor_macro::generate_state_callbacks;

/// Linux Adaptor State
#[generate_state_callbacks]
#[derive(PartialEq, PartialOrd)]
pub enum LinuxAdaptorState {
    Initial,
    SetupArch,
    SetupBootMem,
    SetupVMFinal,
    SetupVMFinalLater,
    SetupArchLater,
    SetupBuddy,
    SetupSlub,
    InitSched,
    InitIrq,
    UserBootEarlier,
    NumberOfStates,
}

//
// Note: `generate_state_callbacks` on LinuxAdaptorState will create an array:
//
//   static StateCallbacks: [fn(); LinuxAdaptorState::NumberOfStates as usize] = [
//      `State0`CB,
//      `State1`CB,
//      ... ...
//      `StateN`CB,
//   ];
//

/// Indicator of LinuxAdaptor's State.
/// Since there's no atomic enum, convert LinuxAdaptorState to usize first
/// and then to set or compare with it.
static CURRENT_STATE: AtomicUsize = AtomicUsize::new(0);

/// Adavance to the target `state` for LinuxAdaptor.
///
/// The states defined in LinuxAdaptorState is a continuous flow.
/// LinuxAdaptor invokes the corresponding CBs step by step from
/// `CURRENT_STATE` to the target `state` and update `CURRENT_STATE`.
/// If the target `state` is already later than `CURRENT_STATE`, just
/// do nothing.
pub fn advance_to(state: LinuxAdaptorState) {
    assert!(state > LinuxAdaptorState::Initial);
    assert!(state < LinuxAdaptorState::NumberOfStates);

    let state = state as usize;
    let cur = CURRENT_STATE.fetch_max(state, Ordering::SeqCst);
    if state <= cur {
        return;
    }

    for index in cur..state {
        // Note: index + 1 because the real range is (cur, state].
        StateCallbacks[index + 1]();
        ax_println!("############## {:?} #########", index+1);
    }
}

#[allow(non_snake_case)]
fn InitialCB() {
    unreachable!();
}

#[allow(non_snake_case)]
fn SetupArchCB() {
    unsafe {
        cl_setup_arch_earlier();
    }
}

#[allow(non_snake_case)]
fn SetupBootMemCB() {
    unsafe {
        cl_setup_bootmem();
    }
}

#[allow(non_snake_case)]
fn SetupVMFinalCB() {
    unsafe {
        setup_vm_final();
    }
}

#[allow(non_snake_case)]
fn SetupVMFinalLaterCB() {
    unsafe {
        /* Depend on that Linear Mapping is ready */
        memblock_allow_resize();
    }
}

#[allow(non_snake_case)]
fn SetupArchLaterCB() {
    unsafe {
        cl_setup_arch_later();
    }
}

#[allow(non_snake_case)]
fn SetupBuddyCB() {
    //
    // mm_core_init_first_part() [mm/mm_init.c]
    //   - set up kernel memory allocators
    //
    unsafe {
        mm_core_init_first_part();
    }
}

#[allow(non_snake_case)]
fn SetupSlubCB() {
    //
    // mm_core_init_second_part() [mm/mm_init.c]
    //   - set up kernel memory allocators
    //
    unsafe {
        mm_core_init_second_part();
    }
}

#[allow(non_snake_case)]
fn InitSchedCB() {
    unsafe {
        sched_init();
    }
}

#[allow(non_snake_case)]
fn InitIrqCB() {
    unsafe {
        cl_init_irq();
    }
}

#[allow(non_snake_case)]
fn UserBootEarlierCB() {
    unsafe {
        userboot_earlier();
    }
}

unsafe extern "C" {
    fn cl_setup_arch_earlier();
    fn cl_setup_bootmem();
    fn setup_vm_final();
    fn memblock_allow_resize();
    fn cl_setup_arch_later();
    fn mm_core_init_first_part();
    fn mm_core_init_second_part();
    fn sched_init();
    fn cl_init_irq();
    fn userboot_earlier();
}
