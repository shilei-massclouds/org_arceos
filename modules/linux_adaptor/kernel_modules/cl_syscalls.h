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
extern int cl_sys_close(int fd);

extern int cl_sys_unlink(const char *pathname);

extern int cl_sys_getdents64(unsigned int fd,
                             struct linux_dirent64 *dirent,
                             unsigned int count);

extern int cl_sys_newstat(const char *filename, struct stat *statbuf);

#endif /* _CL_SYSCALLS_H_ */
