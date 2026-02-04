.section .irqentry.text, "ax"

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
    // Now 'amoxor.d' is unsupported in ArceOS asm. Why?
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
