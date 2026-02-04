//! Linux Kernel Configurations
//! These values come from '.config' under linux-6.12.37

#![cfg_attr(not(test), no_std)]

pub const PAGE_SHIFT: usize = 12;
pub const PAGE_SIZE: usize = 1 << PAGE_SHIFT;

pub const CONFIG_THREAD_SIZE_ORDER: usize = 2;
pub const THREAD_SIZE_ORDER: usize = CONFIG_THREAD_SIZE_ORDER;
pub const THREAD_SIZE: usize = PAGE_SIZE << THREAD_SIZE_ORDER;

/// Floating-point Status
pub const SR_FS: usize = 0x00006000;
/// Vector Status
pub const SR_VS: usize = 0x00000600;
/// Vector and Floating-Point Unit
pub const SR_FS_VS: usize = SR_FS | SR_VS;

// FixMe:
// Defined in [include/generated/asm-offsets.h]
pub const KERNEL_MAP_VIRT_ADDR: usize = 8;

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
