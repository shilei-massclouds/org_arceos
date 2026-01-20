use crate::config::plat::PHYS_VIRT_OFFSET;
use axplat::mem::{PAGE_SIZE_4K, Aligned4K, pa};

/// Floating-point Status
const SR_FS: usize = 0x00006000;
/// Vector Status
const SR_VS: usize = 0x00000600;
/// Vector and Floating-Point Unit
const SR_FS_VS: usize = SR_FS | SR_VS;

// FixMe: This should be a valid value.
// Defined in [include/generated/asm-offsets.h]
const PT_SIZE_ON_STACK: usize = 0;

/// Boot hart id.
pub static BOOT_CPU_HARTID: usize = 0;

const CONFIG_THREAD_SIZE_ORDER: usize = 2;
const THREAD_SIZE_ORDER: usize = CONFIG_THREAD_SIZE_ORDER;
const THREAD_SIZE: usize = PAGE_SIZE_4K << THREAD_SIZE_ORDER;

/*
#[unsafe(link_section = ".bss.stack")]
static mut BOOT_STACK: [u8; BOOT_STACK_SIZE] = [0; BOOT_STACK_SIZE];
*/

#[unsafe(link_section = ".data")]
static mut BOOT_PT_SV39: Aligned4K<[u64; 512]> = Aligned4K::new([0; 512]);

/// The earliest entry point for the primary CPU.
#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".head.text")]
unsafe extern "C" fn _start() -> ! {
    // PC = 0x8020_0000
    // a0 = hartid
    // a1 = dtb
    core::arch::naked_asm!("
        /* Mask all interrupts */
        csrw sie, zero
        csrw sip, zero

        /* Load the global pointer */
    .option push
    .option norelax
        la gp, __global_pointer$
    .option pop

        /*
         * Disable FPU & VECTOR to detect illegal usage of
         * floating point or vector in kernel space
         */
        li t0, {SR_FS_VS}
        csrc sstatus, t0

        /* Clear BSS for flat non-ELF images */
        la a3, __bss_start
        la a4, __bss_stop
        ble a4, a3, 2f
    1:  /* .Lclear_bss: */
        sd zero, (a3)
        add a3, a3, 8
        blt a3, a4, 1b
    2:  /* .Lclear_bss_done: */

        la a2, {boot_cpu_hartid}
        sd a0, (a2)

        /* Initialize page tables and relocate to virtual addresses */
        la tp, init_task
        la sp, init_thread_union + {THREAD_SIZE}
        addi sp, sp, -{PT_SIZE_ON_STACK}

        mv a0, a1

        /* Set trap vector to spin forever to help debug */
        la a3, 3f
        csrw stvec, a3
        call setup_vm

        /* *** Debug: Reach here! */
        li a7, 1
        li a0, '0'
        ecall
        li a0, '\n'
        ecall
        j .
        /* *** Debug: Reach here! */

        mv      s0, a0                  // save hartid
        mv      s1, a1                  // save DTB pointer

        li      s2, {phys_virt_offset}  // fix up virtual high address
        add     sp, sp, s2

        mv      a0, s0
        mv      a1, s1
        la      a2, {entry}
        add     a2, a2, s2
        jalr    a2                      // call_main(cpu_id, dtb)

    .align 2
    3:  /* .Lsecondary_park: */
        /*
         * Park this hart if we:
         *  - have too many harts on CONFIG_RISCV_BOOT_SPINWAIT
         *  - receive an early trap, before setup_trap_vector finished
         *  - fail in smp_callin(), as a successful one wouldn't return
         */
        wfi
        j 3b
        ",
        SR_FS_VS = const SR_FS_VS,
        boot_cpu_hartid = sym BOOT_CPU_HARTID,
        phys_virt_offset = const PHYS_VIRT_OFFSET,
        THREAD_SIZE = const THREAD_SIZE,
        PT_SIZE_ON_STACK = const PT_SIZE_ON_STACK,
        entry = sym axplat::call_main,
    )
}

/// The earliest entry point for secondary CPUs.
#[cfg(feature = "smp")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "C" fn _start_secondary() -> ! {
    // a0 = hartid
    // a1 = SP
    core::arch::naked_asm!("
        j       .",
    )
}
