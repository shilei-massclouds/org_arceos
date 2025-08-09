// SPDX-License-Identifier: GPL-2.0-only

#ifndef _CL_SYSCALLS_H_
#define _CL_SYSCALLS_H_

/*
 * Syscalls in unikernel mode.
 *
 * Same form with standard Linux syscalls.
 *
 */

extern int cl_sys_open(const char *filename, int flags, umode_t mode);

#endif /* _CL_SYSCALLS_H_ */
