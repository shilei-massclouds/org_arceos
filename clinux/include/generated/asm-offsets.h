#ifndef __ASM_OFFSETS_H__
#define __ASM_OFFSETS_H__
/*
 * DO NOT MODIFY.
 *
 * This file was generated by Kbuild
 */

#define TASK_THREAD_RA 1768 /* offsetof(struct task_struct, thread.ra) */
#define TASK_THREAD_SP 1776 /* offsetof(struct task_struct, thread.sp) */
#define TASK_THREAD_S0 1784 /* offsetof(struct task_struct, thread.s[0]) */
#define TASK_THREAD_S1 1792 /* offsetof(struct task_struct, thread.s[1]) */
#define TASK_THREAD_S2 1800 /* offsetof(struct task_struct, thread.s[2]) */
#define TASK_THREAD_S3 1808 /* offsetof(struct task_struct, thread.s[3]) */
#define TASK_THREAD_S4 1816 /* offsetof(struct task_struct, thread.s[4]) */
#define TASK_THREAD_S5 1824 /* offsetof(struct task_struct, thread.s[5]) */
#define TASK_THREAD_S6 1832 /* offsetof(struct task_struct, thread.s[6]) */
#define TASK_THREAD_S7 1840 /* offsetof(struct task_struct, thread.s[7]) */
#define TASK_THREAD_S8 1848 /* offsetof(struct task_struct, thread.s[8]) */
#define TASK_THREAD_S9 1856 /* offsetof(struct task_struct, thread.s[9]) */
#define TASK_THREAD_S10 1864 /* offsetof(struct task_struct, thread.s[10]) */
#define TASK_THREAD_S11 1872 /* offsetof(struct task_struct, thread.s[11]) */
#define TASK_TI_FLAGS 0 /* offsetof(struct task_struct, thread_info.flags) */
#define TASK_TI_PREEMPT_COUNT 8 /* offsetof(struct task_struct, thread_info.preempt_count) */
#define TASK_TI_KERNEL_SP 24 /* offsetof(struct task_struct, thread_info.kernel_sp) */
#define TASK_TI_USER_SP 32 /* offsetof(struct task_struct, thread_info.user_sp) */
#define TASK_TI_CPU 40 /* offsetof(struct task_struct, thread_info.cpu) */
#define TASK_THREAD_F0 1880 /* offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F1 1888 /* offsetof(struct task_struct, thread.fstate.f[1]) */
#define TASK_THREAD_F2 1896 /* offsetof(struct task_struct, thread.fstate.f[2]) */
#define TASK_THREAD_F3 1904 /* offsetof(struct task_struct, thread.fstate.f[3]) */
#define TASK_THREAD_F4 1912 /* offsetof(struct task_struct, thread.fstate.f[4]) */
#define TASK_THREAD_F5 1920 /* offsetof(struct task_struct, thread.fstate.f[5]) */
#define TASK_THREAD_F6 1928 /* offsetof(struct task_struct, thread.fstate.f[6]) */
#define TASK_THREAD_F7 1936 /* offsetof(struct task_struct, thread.fstate.f[7]) */
#define TASK_THREAD_F8 1944 /* offsetof(struct task_struct, thread.fstate.f[8]) */
#define TASK_THREAD_F9 1952 /* offsetof(struct task_struct, thread.fstate.f[9]) */
#define TASK_THREAD_F10 1960 /* offsetof(struct task_struct, thread.fstate.f[10]) */
#define TASK_THREAD_F11 1968 /* offsetof(struct task_struct, thread.fstate.f[11]) */
#define TASK_THREAD_F12 1976 /* offsetof(struct task_struct, thread.fstate.f[12]) */
#define TASK_THREAD_F13 1984 /* offsetof(struct task_struct, thread.fstate.f[13]) */
#define TASK_THREAD_F14 1992 /* offsetof(struct task_struct, thread.fstate.f[14]) */
#define TASK_THREAD_F15 2000 /* offsetof(struct task_struct, thread.fstate.f[15]) */
#define TASK_THREAD_F16 2008 /* offsetof(struct task_struct, thread.fstate.f[16]) */
#define TASK_THREAD_F17 2016 /* offsetof(struct task_struct, thread.fstate.f[17]) */
#define TASK_THREAD_F18 2024 /* offsetof(struct task_struct, thread.fstate.f[18]) */
#define TASK_THREAD_F19 2032 /* offsetof(struct task_struct, thread.fstate.f[19]) */
#define TASK_THREAD_F20 2040 /* offsetof(struct task_struct, thread.fstate.f[20]) */
#define TASK_THREAD_F21 2048 /* offsetof(struct task_struct, thread.fstate.f[21]) */
#define TASK_THREAD_F22 2056 /* offsetof(struct task_struct, thread.fstate.f[22]) */
#define TASK_THREAD_F23 2064 /* offsetof(struct task_struct, thread.fstate.f[23]) */
#define TASK_THREAD_F24 2072 /* offsetof(struct task_struct, thread.fstate.f[24]) */
#define TASK_THREAD_F25 2080 /* offsetof(struct task_struct, thread.fstate.f[25]) */
#define TASK_THREAD_F26 2088 /* offsetof(struct task_struct, thread.fstate.f[26]) */
#define TASK_THREAD_F27 2096 /* offsetof(struct task_struct, thread.fstate.f[27]) */
#define TASK_THREAD_F28 2104 /* offsetof(struct task_struct, thread.fstate.f[28]) */
#define TASK_THREAD_F29 2112 /* offsetof(struct task_struct, thread.fstate.f[29]) */
#define TASK_THREAD_F30 2120 /* offsetof(struct task_struct, thread.fstate.f[30]) */
#define TASK_THREAD_F31 2128 /* offsetof(struct task_struct, thread.fstate.f[31]) */
#define TASK_THREAD_FCSR 2136 /* offsetof(struct task_struct, thread.fstate.fcsr) */
#define PT_SIZE 288 /* sizeof(struct pt_regs) */
#define PT_EPC 0 /* offsetof(struct pt_regs, epc) */
#define PT_RA 8 /* offsetof(struct pt_regs, ra) */
#define PT_FP 64 /* offsetof(struct pt_regs, s0) */
#define PT_S0 64 /* offsetof(struct pt_regs, s0) */
#define PT_S1 72 /* offsetof(struct pt_regs, s1) */
#define PT_S2 144 /* offsetof(struct pt_regs, s2) */
#define PT_S3 152 /* offsetof(struct pt_regs, s3) */
#define PT_S4 160 /* offsetof(struct pt_regs, s4) */
#define PT_S5 168 /* offsetof(struct pt_regs, s5) */
#define PT_S6 176 /* offsetof(struct pt_regs, s6) */
#define PT_S7 184 /* offsetof(struct pt_regs, s7) */
#define PT_S8 192 /* offsetof(struct pt_regs, s8) */
#define PT_S9 200 /* offsetof(struct pt_regs, s9) */
#define PT_S10 208 /* offsetof(struct pt_regs, s10) */
#define PT_S11 216 /* offsetof(struct pt_regs, s11) */
#define PT_SP 16 /* offsetof(struct pt_regs, sp) */
#define PT_TP 32 /* offsetof(struct pt_regs, tp) */
#define PT_A0 80 /* offsetof(struct pt_regs, a0) */
#define PT_A1 88 /* offsetof(struct pt_regs, a1) */
#define PT_A2 96 /* offsetof(struct pt_regs, a2) */
#define PT_A3 104 /* offsetof(struct pt_regs, a3) */
#define PT_A4 112 /* offsetof(struct pt_regs, a4) */
#define PT_A5 120 /* offsetof(struct pt_regs, a5) */
#define PT_A6 128 /* offsetof(struct pt_regs, a6) */
#define PT_A7 136 /* offsetof(struct pt_regs, a7) */
#define PT_T0 40 /* offsetof(struct pt_regs, t0) */
#define PT_T1 48 /* offsetof(struct pt_regs, t1) */
#define PT_T2 56 /* offsetof(struct pt_regs, t2) */
#define PT_T3 224 /* offsetof(struct pt_regs, t3) */
#define PT_T4 232 /* offsetof(struct pt_regs, t4) */
#define PT_T5 240 /* offsetof(struct pt_regs, t5) */
#define PT_T6 248 /* offsetof(struct pt_regs, t6) */
#define PT_GP 24 /* offsetof(struct pt_regs, gp) */
#define PT_ORIG_A0 280 /* offsetof(struct pt_regs, orig_a0) */
#define PT_STATUS 256 /* offsetof(struct pt_regs, status) */
#define PT_BADADDR 264 /* offsetof(struct pt_regs, badaddr) */
#define PT_CAUSE 272 /* offsetof(struct pt_regs, cause) */
#define TASK_THREAD_RA_RA 0 /* offsetof(struct task_struct, thread.ra) - offsetof(struct task_struct, thread.ra) */
#define TASK_THREAD_SP_RA 8 /* offsetof(struct task_struct, thread.sp) - offsetof(struct task_struct, thread.ra) */
#define TASK_THREAD_S0_RA 16 /* offsetof(struct task_struct, thread.s[0]) - offsetof(struct task_struct, thread.ra) */
#define TASK_THREAD_S1_RA 24 /* offsetof(struct task_struct, thread.s[1]) - offsetof(struct task_struct, thread.ra) */
#define TASK_THREAD_S2_RA 32 /* offsetof(struct task_struct, thread.s[2]) - offsetof(struct task_struct, thread.ra) */
#define TASK_THREAD_S3_RA 40 /* offsetof(struct task_struct, thread.s[3]) - offsetof(struct task_struct, thread.ra) */
#define TASK_THREAD_S4_RA 48 /* offsetof(struct task_struct, thread.s[4]) - offsetof(struct task_struct, thread.ra) */
#define TASK_THREAD_S5_RA 56 /* offsetof(struct task_struct, thread.s[5]) - offsetof(struct task_struct, thread.ra) */
#define TASK_THREAD_S6_RA 64 /* offsetof(struct task_struct, thread.s[6]) - offsetof(struct task_struct, thread.ra) */
#define TASK_THREAD_S7_RA 72 /* offsetof(struct task_struct, thread.s[7]) - offsetof(struct task_struct, thread.ra) */
#define TASK_THREAD_S8_RA 80 /* offsetof(struct task_struct, thread.s[8]) - offsetof(struct task_struct, thread.ra) */
#define TASK_THREAD_S9_RA 88 /* offsetof(struct task_struct, thread.s[9]) - offsetof(struct task_struct, thread.ra) */
#define TASK_THREAD_S10_RA 96 /* offsetof(struct task_struct, thread.s[10]) - offsetof(struct task_struct, thread.ra) */
#define TASK_THREAD_S11_RA 104 /* offsetof(struct task_struct, thread.s[11]) - offsetof(struct task_struct, thread.ra) */
#define TASK_THREAD_F0_F0 0 /* offsetof(struct task_struct, thread.fstate.f[0]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F1_F0 8 /* offsetof(struct task_struct, thread.fstate.f[1]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F2_F0 16 /* offsetof(struct task_struct, thread.fstate.f[2]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F3_F0 24 /* offsetof(struct task_struct, thread.fstate.f[3]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F4_F0 32 /* offsetof(struct task_struct, thread.fstate.f[4]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F5_F0 40 /* offsetof(struct task_struct, thread.fstate.f[5]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F6_F0 48 /* offsetof(struct task_struct, thread.fstate.f[6]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F7_F0 56 /* offsetof(struct task_struct, thread.fstate.f[7]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F8_F0 64 /* offsetof(struct task_struct, thread.fstate.f[8]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F9_F0 72 /* offsetof(struct task_struct, thread.fstate.f[9]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F10_F0 80 /* offsetof(struct task_struct, thread.fstate.f[10]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F11_F0 88 /* offsetof(struct task_struct, thread.fstate.f[11]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F12_F0 96 /* offsetof(struct task_struct, thread.fstate.f[12]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F13_F0 104 /* offsetof(struct task_struct, thread.fstate.f[13]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F14_F0 112 /* offsetof(struct task_struct, thread.fstate.f[14]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F15_F0 120 /* offsetof(struct task_struct, thread.fstate.f[15]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F16_F0 128 /* offsetof(struct task_struct, thread.fstate.f[16]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F17_F0 136 /* offsetof(struct task_struct, thread.fstate.f[17]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F18_F0 144 /* offsetof(struct task_struct, thread.fstate.f[18]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F19_F0 152 /* offsetof(struct task_struct, thread.fstate.f[19]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F20_F0 160 /* offsetof(struct task_struct, thread.fstate.f[20]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F21_F0 168 /* offsetof(struct task_struct, thread.fstate.f[21]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F22_F0 176 /* offsetof(struct task_struct, thread.fstate.f[22]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F23_F0 184 /* offsetof(struct task_struct, thread.fstate.f[23]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F24_F0 192 /* offsetof(struct task_struct, thread.fstate.f[24]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F25_F0 200 /* offsetof(struct task_struct, thread.fstate.f[25]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F26_F0 208 /* offsetof(struct task_struct, thread.fstate.f[26]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F27_F0 216 /* offsetof(struct task_struct, thread.fstate.f[27]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F28_F0 224 /* offsetof(struct task_struct, thread.fstate.f[28]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F29_F0 232 /* offsetof(struct task_struct, thread.fstate.f[29]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F30_F0 240 /* offsetof(struct task_struct, thread.fstate.f[30]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_F31_F0 248 /* offsetof(struct task_struct, thread.fstate.f[31]) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define TASK_THREAD_FCSR_F0 256 /* offsetof(struct task_struct, thread.fstate.fcsr) - offsetof(struct task_struct, thread.fstate.f[0]) */
#define PT_SIZE_ON_STACK 288 /* ALIGN(sizeof(struct pt_regs), STACK_ALIGN) */

#endif
