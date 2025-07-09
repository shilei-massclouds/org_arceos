// SPDX-License-Identifier: GPL-2.0-only

#ifndef _BOOTER_H_
#define _BOOTER_H_

typedef unsigned long size_t;
typedef _Bool bool;

extern void *cl_rust_alloc(unsigned long size, unsigned long align);
extern void cl_rust_dealloc(const void *addr);
extern void *cl_alloc_pages(unsigned long size, unsigned long align);

extern void cl_printk(const char *s);
extern void cl_log_debug(const char *s);
extern void cl_log_error(const char *s);

extern unsigned long
cl_kthread_run(unsigned long task_ptr,
               unsigned long threadfn_ptr,
               unsigned long arg_ptr);

extern void cl_resched(unsigned long back_to_runq);
extern void cl_wake_up(unsigned long tid);

extern void cl_terminate(void);

extern int log_debug(const char *fmt, ...);
extern int log_error(const char *fmt, ...);

typedef int (*init_module_t)(void);
typedef void (*exit_module_t)(void);

extern int hex_to_str(unsigned long n, char *str, size_t len);
extern int dec_to_str(unsigned long n, char *str, size_t len);

extern int printk(const char *fmt, ...);

/* For Block */
extern int cl_read_block(int blk_nr, void *rbuf, int count);

#define UL_STR_SIZE 19  /* prefix with '0x' and end with '\0' */

#define booter_panic(args...) \
do { \
    printk("\n########################\n"); \
    printk("PANIC: %s(%s:%d) %s\n", __FUNCTION__, __FILE__, __LINE__, args); \
    printk("\n########################\n"); \
    cl_terminate(); \
} while (0);

//
// Helper for decomposing components.
//
#define CL_MINE(name) \
    void name() { booter_panic("No impl.\n"); }

#endif /* _BOOTER_H_ */
