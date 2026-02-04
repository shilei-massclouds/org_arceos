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

.macro SAVE_REGS, from_user
    addi    sp, sp, -{trapframe_size}
    PUSH_GENERAL_REGS

    csrr    t0, sepc
    csrr    t1, sstatus
    csrrw   t2, sscratch, zero          // save sscratch (sp) and zero it
    STR     t0, sp, 32                  // tf.sepc
    STR     t1, sp, 33                  // tf.sstatus
    STR     t2, sp, 2                   // tf.regs.sp

.if \from_user == 1
    LDR     t0, sp, 3                   // load supervisor gp
    LDR     t1, sp, 4                   // load supervisor tp
    STR     gp, sp, 3                   // save user gp
    STR     tp, sp, 4                   // save user tp
    mv      gp, t0
    mv      tp, t1
.endif
.endm

.macro RESTORE_REGS, from_user
.if \from_user == 1
    LDR     t1, sp, 3                   // load user gp
    LDR     t0, sp, 4                   // load user tp
    STR     gp, sp, 3                   // save supervisor gp
    STR     tp, sp, 4                   // save supervisor tp
    mv      gp, t1
    mv      tp, t0
    addi    t0, sp, {trapframe_size}    // put supervisor sp to scratch
    csrw    sscratch, t0
.endif

    LDR     t0, sp, 32
    LDR     t1, sp, 33
    csrw    sepc, t0                    // restore sepc
    csrw    sstatus, t1                 // restore sstatus, except FS state (already handled in trap handler)

    POP_GENERAL_REGS
    LDR     sp, sp, 2                   // load sp from tf.regs.sp
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
    //li t0, SR_SUM | SR_FS_VS

    /*
    REG_L s0, TASK_TI_USER_SP(tp)
    csrrc s1, CSR_STATUS, t0
    csrr s2, CSR_EPC
    csrr s3, CSR_TVAL
    csrr s4, CSR_CAUSE
    csrr s5, CSR_SCRATCH
    REG_S s0, PT_SP(sp)
    REG_S s1, PT_STATUS(sp)
    REG_S s2, PT_EPC(sp)
    REG_S s3, PT_BADADDR(sp)
    REG_S s4, PT_CAUSE(sp)
    REG_S s5, PT_TP(sp)
    */

j .

///////////////////////////////////////////////
    // sscratch == 0: trap from S mode
    // sscratch != 0: trap from U mode
//    csrrw   sp, sscratch, sp            // swap sscratch and sp
//    bnez    sp, .Ltrap_entry_u
//
//    csrr    sp, sscratch                // put supervisor sp back
//    j       .Ltrap_entry_s
//
//.Ltrap_entry_s:
//    SAVE_REGS 0
//    mv      a0, sp
//    li      a1, 0
//    call    riscv_trap_handler
//    RESTORE_REGS 0
//    sret
//
//.Ltrap_entry_u:
//    SAVE_REGS 1
//    mv      a0, sp
//    li      a1, 1
//    call    riscv_trap_handler
//    RESTORE_REGS 1
//    sret
