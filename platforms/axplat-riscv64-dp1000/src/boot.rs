//! Risc-V boot on qemu.

use linux_config::*;

#[unsafe(no_mangle)]
fn start_kernel(hartid: usize, dtb_pa: usize)
{
    axplat::call_main(hartid, dtb_pa);
}

/// The earliest entry point for the primary CPU.
#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".head.text")]
unsafe extern "C" fn _start() -> ! {
    // PC = 0x8020_0000
    // a0 = hartid
    // a1 = dtb
    core::arch::naked_asm!("
        mv      s0, a0
        mv      s1, a1

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

        la a2, boot_cpu_hartid
        sd a0, (a2)

        /* Initialize page tables and relocate to virtual addresses */
        la tp, init_task
        la sp, init_thread_union + {THREAD_SIZE}
        addi sp, sp, -{PT_SIZE_ON_STACK}

        mv a0, a1

        /* Set trap vector to spin forever to help debug */
        la a3, secondary_park
        csrw stvec, a3
        call setup_vm

        la a0, early_pg_dir
        call relocate_enable_mmu

        call setup_trap_vector

        /* Restore C environment */
        la tp, init_task
        la sp, init_thread_union + {THREAD_SIZE}
        addi sp, sp, -{PT_SIZE_ON_STACK}

        /* Start the kernel */
        mv      a0, s0
        mv      a1, s1
        call soc_early_init
        tail start_kernel
        ",
        SR_FS_VS = const SR_FS_VS,
        THREAD_SIZE = const THREAD_SIZE,
        PT_SIZE_ON_STACK = const PT_SIZE_ON_STACK,
    )
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".head.text2")]
unsafe extern "C" fn secondary_park() -> ! {
    core::arch::naked_asm!("
    .align 2
    1:
        /*
         * Park this hart if we:
         *  - have too many harts on CONFIG_RISCV_BOOT_SPINWAIT
         *  - receive an early trap, before setup_trap_vector finished
         *  - fail in smp_callin(), as a successful one wouldn't return
         */
        wfi
        j 1b
    ")
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".head.text2")]
unsafe extern "C" fn setup_trap_vector() -> ! {
    core::arch::naked_asm!("
    .align 2
        /* Set trap vector to exception handler */
        la a0, handle_exception_early
        csrw stvec, a0

        /*
         * Set sup0 scratch register to 0, indicating to exception vector that
         * we are presently executing in kernel.
         */
        csrw sscratch, zero
        ret
    ")
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".head.text2")]
unsafe extern "C" fn secondary_setup_trap_vector() -> ! {
    core::arch::naked_asm!("
    .align 2
        /* Set trap vector to exception handler */
        la a0, handle_exception
        csrw stvec, a0

        /*
         * Set sup0 scratch register to 0, indicating to exception vector that
         * we are presently executing in kernel.
         */
        csrw sscratch, zero
        ret
    ")
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".head.text2")]
unsafe extern "C" fn relocate_enable_mmu() -> ! {
    core::arch::naked_asm!("
    .align 2
        /* Relocate return address */
        la a1, kernel_map
        ld a1, {KERNEL_MAP_VIRT_ADDR}(a1)

        la a2, _start
        sub a1, a1, a2
        add ra, ra, a1

        /* Point stvec to virtual address of intruction after satp write */
        la a2, 1f
        add a2, a2, a1
        csrw stvec, a2

        /* Compute satp for kernel page tables, but don't load it yet */
        srl a2, a0, {PAGE_SHIFT}
        la a1, satp_mode
        ld a1, 0(a1)
        or a2, a2, a1

        /*
         * Load trampoline page directory, which will cause us to trap to
         * stvec if VA != PA, or simply fall through if VA == PA.  We need a
         * full fence here because setup_vm() just wrote these PTEs and we need
         * to ensure the new translations are in use.
         */
        la a0, trampoline_pg_dir
        srl a0, a0, {PAGE_SHIFT}
        or a0, a0, a1
        sfence.vma
        csrw satp, a0

    .align 2
    1:
        /* Set trap vector to spin forever to help debug */
        la a0, secondary_park
        csrw stvec, a0

        /* Reload the global pointer */
    .option push
    .option norelax
        la gp, __global_pointer$
    .option pop

        /*
         * Switch to kernel page tables.  A full fence is necessary in order to
         * avoid using the trampoline translations, which are only correct for
         * the first superpage.  Fetching the fence is guaranteed to work
         * because that first superpage is translated the same way.
         */
        csrw satp, a2
        sfence.vma

        ret
        ",
        KERNEL_MAP_VIRT_ADDR = const KERNEL_MAP_VIRT_ADDR,
        PAGE_SHIFT = const PAGE_SHIFT,
    )
}

/// The earliest entry point for secondary CPUs.
#[cfg(feature = "smp")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "C" fn secondary_start_sbi() -> ! {
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

        /* Set trap vector to spin forever to help debug */
        la a3, secondary_park
        csrw stvec, a3

        /* a0 contains the hartid & a1 contains boot data */
        li a2, {SBI_HART_BOOT_TASK_PTR_OFFSET}
        add a2, a2, a1
        ld tp, (a2)
        li a3, {SBI_HART_BOOT_STACK_PTR_OFFSET}
        add a3, a3, a1
        ld sp, (a3)

        /* Enable virtual memory and relocate to virtual address */
        la a0, swapper_pg_dir
        call relocate_enable_mmu
        call secondary_setup_trap_vector
        call smp_callin
        ",
        SR_FS_VS = const SR_FS_VS,
        SBI_HART_BOOT_TASK_PTR_OFFSET = const SBI_HART_BOOT_TASK_PTR_OFFSET,
        SBI_HART_BOOT_STACK_PTR_OFFSET = const SBI_HART_BOOT_STACK_PTR_OFFSET,
    )
}
