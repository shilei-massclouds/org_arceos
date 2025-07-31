// SPDX-License-Identifier: GPL-2.0-only

#ifndef _ADAPTOR_H_
#define _ADAPTOR_H_

extern void cl_printk(char level, const char *s);
extern void cl_terminate(void);

extern void *cl_rust_alloc(unsigned long size, unsigned long align);
extern void cl_rust_dealloc(const void *addr);

extern void *cl_alloc_pages(unsigned long size, unsigned long align);
extern void *cl_free_pages(const void *addr, size_t count);

extern int _vprintk(const char *fmt, va_list args);

extern void cl_resched(unsigned long back_to_runq);
extern void cl_wake_up(unsigned long tid);

extern struct dentry *
cl_mount(const char *fstype, const char *source);

extern unsigned long
cl_kthread_run(unsigned long task_ptr,
               unsigned long threadfn_ptr,
               unsigned long arg_ptr);


#define PANIC(args...) \
do { \
    printk("\n########################\n"); \
    printk("\nPANIC: %s(%s:%d) %s\n", __FUNCTION__, __FILE__, __LINE__, args); \
    printk("\n########################\n"); \
    cl_terminate(); \
} while (0);

//
// Helper for decomposing components.
//
#define CL_MINE(name) \
    void name() { PANIC("No impl."); }

#endif /* _ADAPTOR_H_ */
