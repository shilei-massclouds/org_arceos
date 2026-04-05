//! Linux Kernel Configurations
//! These values come from '.config' under linux-6.12.37

#![cfg_attr(not(test), no_std)]

pub const PAGE_SHIFT: usize = 12;
pub const PAGE_SIZE: usize = 1 << PAGE_SHIFT;

pub const CONFIG_THREAD_SIZE_ORDER: usize = 2;
pub const THREAD_SIZE_ORDER: usize = CONFIG_THREAD_SIZE_ORDER;
pub const THREAD_SIZE: usize = PAGE_SIZE << THREAD_SIZE_ORDER;

/// Floating-point Status
pub const SR_FS:    usize = 0x00006000;

/// Previously Supervisor
pub const SR_SPP:   usize = 0x00000100;
/// Vector Status
pub const SR_VS:    usize = 0x00000600;

/// Vector and Floating-Point Unit
pub const SR_FS_VS: usize = SR_FS | SR_VS;
 
/// Supervisor User Memory Access
pub const SR_SUM: usize = 0x00040000;

// Risc-V Pointer size for ASM code
pub const RISCV_SZPTR: usize = 8;
pub const RISCV_LGPTR: usize = 3;

// FixMe:
// Defined in [include/generated/asm-offsets.h]
pub const KERNEL_MAP_VIRT_ADDR: usize = 8;

// FixMe:
// Defined in [include/generated/asm-offsets.h]
pub const SBI_HART_BOOT_TASK_PTR_OFFSET: usize = 0;
pub const SBI_HART_BOOT_STACK_PTR_OFFSET: usize = 8;

/*
 * Cloning flags [include/uapi/linux/sched.h]
 */

/* set if fs info shared between processes */
pub const CLONE_FS: usize = 0x00000200;

/*
 *  All offsets prefixed by PT_ according to struct pt_regs.
 *
 *  struct pt_regs {
 *      unsigned long epc;
 *      unsigned long ra;
 *      unsigned long sp;
 *      unsigned long gp;
 *      unsigned long tp;
 *      unsigned long t0;
 *      unsigned long t1;
 *      unsigned long t2;
 *      unsigned long s0;
 *      unsigned long s1;
 *      unsigned long a0;
 *      unsigned long a1;
 *      unsigned long a2;
 *      unsigned long a3;
 *      unsigned long a4;
 *      unsigned long a5;
 *      unsigned long a6;
 *      unsigned long a7;
 *      unsigned long s2;
 *      unsigned long s3;
 *      unsigned long s4;
 *      unsigned long s5;
 *      unsigned long s6;
 *      unsigned long s7;
 *      unsigned long s8;
 *      unsigned long s9;
 *      unsigned long s10;
 *      unsigned long s11;
 *      unsigned long t3;
 *      unsigned long t4;
 *      unsigned long t5;
 *      unsigned long t6;
 *      /* Supervisor/Machine CSRs */
 *      unsigned long status;
 *      unsigned long badaddr;
 *      unsigned long cause;
 *      /* a0 value before the syscall */
 *      unsigned long orig_a0;
 *  };
 */

pub const PT_SIZE_ON_STACK : usize = 288;

#[allow(dead_code)]
#[derive(Debug)]
pub struct PtRegs {
    pub epc: usize,
    pub ra: usize,
    pub sp: usize,
    pub gp: usize,
    pub tp: usize,
    pub t0: usize,
    pub t1: usize,
    pub t2: usize,
    pub s0: usize,
    pub s1: usize,
    pub a0: usize,
    pub a1: usize,
    pub a2: usize,
    pub a3: usize,
    pub a4: usize,
    pub a5: usize,
    pub a6: usize,
    pub a7: usize,
    pub s2: usize,
    pub s3: usize,
    pub s4: usize,
    pub s5: usize,
    pub s6: usize,
    pub s7: usize,
    pub s8: usize,
    pub s9: usize,
    pub s10: usize,
    pub s11: usize,
    pub t3: usize,
    pub t4: usize,
    pub t5: usize,
    pub t6: usize,
    /* Supervisor/Machine CSRs */
    pub status: usize,
    pub badaddr: usize,
    pub cause: usize,
    /* a0 value before the syscall */
    pub orig_a0: usize,
}
