// SPDX-License-Identifier: GPL-2.0-only

#include <linux/printk.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/string.h>

#include <asm/syscall.h>
#include <asm/unistd.h>

#define SYSCALL_PREFIX "sys_"
#define COMPAT_SYSCALL_PREFIX "compat_sys_"
#define SYSCALL_REPORT_BANNER \
	"++++++++" "++++++++" "++++++++" "++++++++" \
	"++++++++" "++++++++" "++++++++" "++++++++"

#define __SYSCALL(nr, call) [nr] = #call,
#define __SYSCALL_WITH_COMPAT(nr, native, compat) [nr] = #native,
static const char * const native_syscall_names[__NR_syscalls] = {
	[0 ... __NR_syscalls - 1] = NULL,
#include <asm/syscall_table.h>
};
#undef __SYSCALL_WITH_COMPAT
#undef __SYSCALL

#ifdef CONFIG_COMPAT
#define __SYSCALL(nr, call) [nr] = #call,
#define __SYSCALL_WITH_COMPAT(nr, native, compat) [nr] = #compat,
static const char * const compat_syscall_names[__NR_syscalls] = {
	[0 ... __NR_syscalls - 1] = NULL,
#include <asm/syscall_table_32.h>
};
#undef __SYSCALL_WITH_COMPAT
#undef __SYSCALL
#endif

static const char *syscall_name_for_log(struct pt_regs *regs, unsigned long nr,
					bool *compat_mode)
{
	const char *name = NULL;
	bool compat = false;

	if (nr < __NR_syscalls)
		name = native_syscall_names[nr];

#ifdef CONFIG_COMPAT
	if ((regs->status & SR_UXL) == SR_UXL_32) {
		compat = true;
		if (nr < __NR_syscalls)
			name = compat_syscall_names[nr];
	}
#endif

	if (compat_mode)
		*compat_mode = compat;

	if (!name || !strcmp(name, "sys_ni_syscall"))
		return NULL;
	if (!strncmp(name, COMPAT_SYSCALL_PREFIX,
		     sizeof(COMPAT_SYSCALL_PREFIX) - 1))
		return name + sizeof(COMPAT_SYSCALL_PREFIX) - 1;
	if (!strncmp(name, SYSCALL_PREFIX, sizeof(SYSCALL_PREFIX) - 1))
		return name + sizeof(SYSCALL_PREFIX) - 1;
	return name;
}

void report_unimplemented_syscall(void)
{
	struct pt_regs *regs = current_pt_regs();
	unsigned long args[6] = { 0 };
	unsigned long nr;
	const char *name;
	bool compat = false;

	if (!regs)
		return;

	nr = syscall_get_nr(current, regs);
	syscall_get_arguments(current, regs, args);
	name = syscall_name_for_log(regs, nr, &compat);

	if (name) {
		pr_warn_ratelimited(
			"\r\n"
			SYSCALL_REPORT_BANNER "\n"
			"%s[%d]: ENOSYS for unimplemented %ssyscall %lu (%s), args=[0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx]\n"
			SYSCALL_REPORT_BANNER
			"\n",
			current->comm, current->pid, compat ? "compat " : "", nr,
			name, args[0], args[1], args[2], args[3], args[4], args[5]);
	} else {
		pr_warn_ratelimited(
			"\r\n"
			SYSCALL_REPORT_BANNER "\n"
			"%s[%d]: ENOSYS for unimplemented %ssyscall %lu, args=[0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx]\n"
			SYSCALL_REPORT_BANNER
			"\n",
			current->comm, current->pid, compat ? "compat " : "", nr,
			args[0], args[1], args[2], args[3], args[4], args[5]);
	}
}
