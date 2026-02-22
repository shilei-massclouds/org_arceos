.section .irqentry.text, "ax"

.macro asm_per_cpu dst sym tmp
    ld    \tmp, {TASK_TI_CPU}(tp)
    slli  \tmp, \tmp, {RISCV_LGPTR}
    la    \dst, __per_cpu_offset
    add   \dst, \dst, \tmp
    ld    \tmp, 0(\dst)
    la    \dst, \sym
    add   \dst, \dst, \tmp
.endm

.macro load_per_cpu dst ptr tmp
    asm_per_cpu \dst \ptr \tmp
    ld \dst, 0(\dst)
.endm

/* save all GPs except x1 ~ x5 */
.macro save_from_x6_to_x31
    sd x6,  {PT_T1}(sp)
    sd x7,  {PT_T2}(sp)
    sd x8,  {PT_S0}(sp)
    sd x9,  {PT_S1}(sp)
    sd x10, {PT_A0}(sp)
    sd x11, {PT_A1}(sp)
    sd x12, {PT_A2}(sp)
    sd x13, {PT_A3}(sp)
    sd x14, {PT_A4}(sp)
    sd x15, {PT_A5}(sp)
    sd x16, {PT_A6}(sp)
    sd x17, {PT_A7}(sp)
    sd x18, {PT_S2}(sp)
    sd x19, {PT_S3}(sp)
    sd x20, {PT_S4}(sp)
    sd x21, {PT_S5}(sp)
    sd x22, {PT_S6}(sp)
    sd x23, {PT_S7}(sp)
    sd x24, {PT_S8}(sp)
    sd x25, {PT_S9}(sp)
    sd x26, {PT_S10}(sp)
    sd x27, {PT_S11}(sp)
    sd x28, {PT_T3}(sp)
    sd x29, {PT_T4}(sp)
    sd x30, {PT_T5}(sp)
    sd x31, {PT_T6}(sp)
.endm

/* restore all GPs except x1 ~ x5 */
.macro restore_from_x6_to_x31
    ld x6,  {PT_T1}(sp)
    ld x7,  {PT_T2}(sp)
    ld x8,  {PT_S0}(sp)
    ld x9,  {PT_S1}(sp)
    ld x10, {PT_A0}(sp)
    ld x11, {PT_A1}(sp)
    ld x12, {PT_A2}(sp)
    ld x13, {PT_A3}(sp)
    ld x14, {PT_A4}(sp)
    ld x15, {PT_A5}(sp)
    ld x16, {PT_A6}(sp)
    ld x17, {PT_A7}(sp)
    ld x18, {PT_S2}(sp)
    ld x19, {PT_S3}(sp)
    ld x20, {PT_S4}(sp)
    ld x21, {PT_S5}(sp)
    ld x22, {PT_S6}(sp)
    ld x23, {PT_S7}(sp)
    ld x24, {PT_S8}(sp)
    ld x25, {PT_S9}(sp)
    ld x26, {PT_S10}(sp)
    ld x27, {PT_S11}(sp)
    ld x28, {PT_T3}(sp)
    ld x29, {PT_T4}(sp)
    ld x30, {PT_T5}(sp)
    ld x31, {PT_T6}(sp)
.endm

.macro new_vmalloc_check
    sd      a0, {TASK_TI_A0}(tp)
    csrr    a0, scause
    /* Exclude IRQs */
    blt     a0, zero, .Lnew_vmalloc_restore_context_a0

    sd      a1, {TASK_TI_A1}(tp)
    /* Only check new_vmalloc if we are in page/protection fault */
    li      a1, {EXC_LOAD_PAGE_FAULT}
    beq     a0, a1, .Lnew_vmalloc_kernel_address
    li      a1, {EXC_STORE_PAGE_FAULT}
    beq     a0, a1, .Lnew_vmalloc_kernel_address
    li      a1, {EXC_INST_PAGE_FAULT}
    bne     a0, a1, .Lnew_vmalloc_restore_context_a1

.Lnew_vmalloc_kernel_address:
    /* Is it a kernel address? */
    csrr    a0, stval
    bge     a0, zero, .Lnew_vmalloc_restore_context_a1

    /* Check if a new vmalloc mapping appeared that could explain the trap */
    sd      a2, {TASK_TI_A2}(tp)
    /*
     * Computes:
     * a0 = &new_vmalloc[BIT_WORD(cpu)]
     * a1 = BIT_MASK(cpu)
     */
    ld      a2, {TASK_TI_CPU}(tp)
    /*
     * Compute the new_vmalloc element position:
     * (cpu / 64) * 8 = (cpu >> 6) << 3
     */
    srli    a1, a2, 6
    slli    a1, a1, 3
    la  a0, new_vmalloc
    add a0, a0, a1
    /*
     * Compute the bit position in the new_vmalloc element:
     * bit_pos = cpu % 64 = cpu - (cpu / 64) * 64 = cpu - (cpu >> 6) << 6
     *     = cpu - ((cpu >> 6) << 3) << 3
     */
    slli    a1, a1, 3
    sub a1, a2, a1
    /* Compute the "get mask": 1 << bit_pos */
    li  a2, 1
    sll a1, a2, a1

    /* Check the value of new_vmalloc for this cpu */
    ld      a2, 0(a0)
    and a2, a2, a1
    beq a2, zero, .Lnew_vmalloc_restore_context

    /* Atomically reset the current cpu bit in new_vmalloc */
    //amoxor.d    a0, a1, (a0)
    // Now 'amoxor.d' is unsupported in ArceOS asm.
    // FixMe: use amoxor.d ===
    ld  a2, 0(a0)
    xor a2, a2, a1
    sd  a2, 0(a0)
    // FixMe: use amoxor.d ===

    /* Only emit a sfence.vma if the uarch caches invalid entries */
    //ALTERNATIVE("sfence.vma", "nop", 0, RISCV_ISA_EXT_SVVPTC, 1)
    /* FixMe: support ALTERNATIVE(..) in ArceOS. */
    sfence.vma

    ld   a0, {TASK_TI_A0}(tp)
    ld   a1, {TASK_TI_A1}(tp)
    ld   a2, {TASK_TI_A2}(tp)
    csrw sscratch, x0
    sret

.Lnew_vmalloc_restore_context:
    ld      a2, {TASK_TI_A2}(tp)
.Lnew_vmalloc_restore_context_a1:
    ld      a1, {TASK_TI_A1}(tp)
.Lnew_vmalloc_restore_context_a0:
    ld      a0, {TASK_TI_A0}(tp)
.endm

.balign 4
.global handle_exception
handle_exception:
    /*
     * If coming from userspace, preserve the user thread pointer and load
     * the kernel thread pointer.  If we came from the kernel, the scratch
     * register will contain 0, and we should continue on the current TP.
     */
    csrrw tp, sscratch, tp
    bnez tp, .Lsave_context

.Lrestore_kernel_tpsp:
    csrr tp, sscratch

    /*
     * The RISC-V kernel does not eagerly emit a sfence.vma after each
     * new vmalloc mapping, which may result in exceptions:
     * - if the uarch caches invalid entries, the new mapping would not be
     *   observed by the page table walker and an invalidation is needed.
     * - if the uarch does not cache invalid entries, a reordered access
     *   could "miss" the new mapping and traps: in that case, we only need
     *   to retry the access, no sfence.vma is required.
     */
    new_vmalloc_check

    sd sp, {TASK_TI_KERNEL_SP}(tp)

    /* skip CONFIG_VMAP_STACK */

.Lsave_context:
    sd sp, {TASK_TI_USER_SP}(tp)
    ld sp, {TASK_TI_KERNEL_SP}(tp)
    addi sp, sp, -{PT_SIZE_ON_STACK}
    sd x1,  {PT_RA}(sp)
    sd x3,  {PT_GP}(sp)
    sd x5,  {PT_T0}(sp)
    save_from_x6_to_x31

    /*
     * Disable user-mode memory access as it should only be set in the
     * actual user copy routines.
     *
     * Disable the FPU/Vector to detect illegal usage of floating point
     * or vector in kernel space.
     */
    li t0, {SR_SUM} | {SR_FS_VS}

    ld s0, {TASK_TI_USER_SP}(tp)
    csrrc s1, sstatus, t0
    csrr s2, sepc
    csrr s3, stval
    csrr s4, scause
    csrr s5, sscratch
    sd s0, {PT_SP}(sp)
    sd s1, {PT_STATUS}(sp)
    sd s2, {PT_EPC}(sp)
    sd s3, {PT_BADADDR}(sp)
    sd s4, {PT_CAUSE}(sp)
    sd s5, {PT_TP}(sp)

    /*
     * Set the scratch register to 0, so that if a recursive exception
     * occurs, the exception vector knows it came from the kernel
     */
    csrw sscratch, x0

    /* Load the global pointer */
.option push
.option norelax
    la gp, __global_pointer$
.option pop

    /* pt_regs */
    mv a0, sp

    /*
     * MSB of cause differentiates between
     * interrupts and exceptions
     */
    bge s4, zero, 1f

    /* Handle interrupts */
    call do_irq
    j ret_from_exception
1:
    /* Handle other exceptions */
    slli t0, s4, {RISCV_LGPTR}
    la t1, excp_vect_table
    la t2, excp_vect_table_end
    add t0, t1, t0
    /* Check if exception code lies within bounds */
    bgeu t0, t2, 3f
    ld t1, 0(t0)
2:  jalr t1
    j ret_from_exception
3:

    la t1, do_trap_unknown
    j 2b

/*
 * The ret_from_exception must be called with interrupt disabled. Here is the
 * caller list:
 *  - handle_exception
 *  - ret_from_fork
 */
.global ret_from_exception
ret_from_exception:
    ld s0, {PT_STATUS}(sp)
    andi s0, s0, {SR_SPP}
    bnez s0, 1f

    /* Save unwound kernel stack pointer in thread_info */
    addi s0, sp, {PT_SIZE_ON_STACK}
    sd s0, {TASK_TI_KERNEL_SP}(tp)

    /*
     * Save TP into the scratch register , so we can find the kernel data
     * structures again.
     */
    csrw sscratch, tp
1:
    ld a0, {PT_STATUS}(sp)
    /*
     * The current load reservation is effectively part of the processor's
     * state, in the sense that load reservations cannot be shared between
     * different hart contexts.  We can't actually save and restore a load
     * reservation, so instead here we clear any existing reservation --
     * it's always legal for implementations to clear load reservations at
     * any point (as long as the forward progress guarantee is kept, but
     * we'll ignore that here).
     *
     * Dangling load reservations can be the result of taking a trap in the
     * middle of an LR/SC sequence, but can also be the result of a taken
     * forward branch around an SC -- which is how we implement CAS.  As a
     * result we need to clear reservations between the last CAS and the
     * jump back to the new context.  While it is unlikely the store
     * completes, implementations are allowed to expand reservations to be
     * arbitrarily large.
     */
    ld  a2, {PT_EPC}(sp)
    // FixMe: Now 'sc.d' is unsupported in ArceOS asm.
    //sc.d x0, a2, {PT_EPC}(sp)

    csrw sstatus, a0
    csrw sepc, a2

    ld x1,  {PT_RA}(sp)
    ld x3,  {PT_GP}(sp)
    ld x4,  {PT_TP}(sp)
    ld x5,  {PT_T0}(sp)
    restore_from_x6_to_x31

    ld x2,  {PT_SP}(sp)

    sret

.type ret_from_exception_end STT_NOTYPE
.global ret_from_exception_end
ret_from_exception_end:

/*
 * void call_on_irq_stack(struct pt_regs *regs,
 *                        void (*func)(struct pt_regs *));
 *
 * Calls func(regs) using the per-CPU IRQ stack.
 */
.balign 4
.global call_on_irq_stack
call_on_irq_stack:
    /* Create a frame record to save ra and s0 (fp) */
    addi sp, sp, -{STACKFRAME_SIZE_ON_STACK}
    sd   ra, {STACKFRAME_RA}(sp)
    sd   s0, {STACKFRAME_FP}(sp)
    addi s0, sp, {STACKFRAME_SIZE_ON_STACK}

    /* Switch to the per-CPU IRQ stack and call the handler */
    load_per_cpu t0, irq_stack_ptr, t1
    li  t1, {IRQ_STACK_SIZE}
    add sp, t0, t1
    jalr    a1

    /* Switch back to the thread stack and restore ra and s0 */
    addi sp, s0, -{STACKFRAME_SIZE_ON_STACK}
    ld   ra, {STACKFRAME_RA}(sp)
    ld   s0, {STACKFRAME_FP}(sp)
    addi sp, sp, {STACKFRAME_SIZE_ON_STACK}

    ret

/*
 * Integer register context switch
 * The callee-saved registers must be saved and restored.
 *
 *   a0: previous task_struct (must be preserved across the switch)
 *   a1: next task_struct
 *
 * The value of a0 and a1 must be preserved by this function, as that's how
 * arguments are passed to schedule_tail.
 */
.balign 4
.global __switch_to
__switch_to:
    /* Save context into prev->thread */
    li    a4,  {TASK_THREAD_RA}
    add   a3, a0, a4
    add   a4, a1, a4
    sd ra,  {TASK_THREAD_RA_RA}(a3)
    sd sp,  {TASK_THREAD_SP_RA}(a3)
    sd s0,  {TASK_THREAD_S0_RA}(a3)
    sd s1,  {TASK_THREAD_S1_RA}(a3)
    sd s2,  {TASK_THREAD_S2_RA}(a3)
    sd s3,  {TASK_THREAD_S3_RA}(a3)
    sd s4,  {TASK_THREAD_S4_RA}(a3)
    sd s5,  {TASK_THREAD_S5_RA}(a3)
    sd s6,  {TASK_THREAD_S6_RA}(a3)
    sd s7,  {TASK_THREAD_S7_RA}(a3)
    sd s8,  {TASK_THREAD_S8_RA}(a3)
    sd s9,  {TASK_THREAD_S9_RA}(a3)
    sd s10, {TASK_THREAD_S10_RA}(a3)
    sd s11, {TASK_THREAD_S11_RA}(a3)
    /* Restore context from next->thread */
    ld ra,  {TASK_THREAD_RA_RA}(a4)
    ld sp,  {TASK_THREAD_SP_RA}(a4)
    ld s0,  {TASK_THREAD_S0_RA}(a4)
    ld s1,  {TASK_THREAD_S1_RA}(a4)
    ld s2,  {TASK_THREAD_S2_RA}(a4)
    ld s3,  {TASK_THREAD_S3_RA}(a4)
    ld s4,  {TASK_THREAD_S4_RA}(a4)
    ld s5,  {TASK_THREAD_S5_RA}(a4)
    ld s6,  {TASK_THREAD_S6_RA}(a4)
    ld s7,  {TASK_THREAD_S7_RA}(a4)
    ld s8,  {TASK_THREAD_S8_RA}(a4)
    ld s9,  {TASK_THREAD_S9_RA}(a4)
    ld s10, {TASK_THREAD_S10_RA}(a4)
    ld s11, {TASK_THREAD_S11_RA}(a4)
    /* The offset of thread_info in task_struct is zero. */
    move tp, a1
    ret

/* Exception vector table */
.section ".rodata"
.align {RISCV_LGPTR}
excp_vect_table:
    .dword do_trap_insn_misaligned
    .dword do_trap_insn_fault
    .dword do_trap_insn_illegal
    .dword do_trap_break
    .dword do_trap_load_misaligned
    .dword do_trap_load_fault
    .dword do_trap_store_misaligned
    .dword do_trap_store_fault
    /* system call */
    .dword do_trap_ecall_u
    .dword do_trap_ecall_s
    .dword do_trap_unknown
    .dword do_trap_ecall_m
    /* instruciton page fault */
    .dword do_page_fault
    /* load page fault */
    .dword do_page_fault
    .dword do_trap_unknown
    /* store page fault */
    .dword do_page_fault
excp_vect_table_end:
