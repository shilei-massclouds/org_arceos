// SPDX-License-Identifier: GPL-2.0-only

#ifndef _ADAPTOR_H_
#define _ADAPTOR_H_

extern void legacy_puts(const char *s);
extern void legacy_put_hex(unsigned long hex);
extern void legacy_shutdown(void);

extern void *cl_alloc_pages(unsigned long size, unsigned long align);
extern void *cl_free_pages(const void *addr, size_t count);

extern int _vprintk(const char *fmt, va_list args);

extern void cl_resched(unsigned long back_to_runq);
extern void cl_wake_up(unsigned long tid);

extern int cl_mount(const char *fstype, const char *source);

extern unsigned long
cl_kthread_new(unsigned long task_ptr,
               unsigned long threadfn_ptr,
               unsigned long arg_ptr);

extern unsigned long
cl_kthread_activate(unsigned long task_id);

extern void
cl_get_ksym(unsigned long addr, char *name, unsigned long size);

extern void end_global_trace(void);

extern int clinux_starting;
extern int clinux_started;

#define RAW_PANIC(args...) \
do { \
    legacy_puts("\n########################\n"); \
    legacy_puts("\nRAW_PANIC: "); \
    legacy_puts(__FUNCTION__); \
    legacy_puts(" in ["); \
    legacy_puts(__FILE__); \
    legacy_puts("]\n"); \
    legacy_puts("\n########################\n"); \
    legacy_shutdown(); \
} while (0)

#define PANIC(args...) \
do { \
    printk("\n########################\n"); \
    printk("\nPANIC: %s(%s:%d) %s\n", __FUNCTION__, __FILE__, __LINE__, args); \
    printk("\n########################\n"); \
    legacy_shutdown(); \
} while (0)

#define CL_ASSERT(cond, msg) \
do {                        \
    if (!cond) {            \
        PANIC(msg);         \
    }                       \
} while (0)

//
// Helper for decomposing components.
//
#define CL_MINE(name) \
    void name() { RAW_PANIC("No impl."); }

/*
 * Trace Buffer
 *
 * Map of Share Memory for trace buffer. There're two parts:
 * 1) Trace Events Channel
 *   Kernel writes trace events through this channel to qemu's host.
 *   User tool at host can read these events from channel.
 * 2) Trace Events Registration Area
 *   Kernel registers event type and name into this area.
 *   User tool at host builds a map between event'name and event's type.
 *
 */
#define CL_TRACE_BUFFER_START   0xffffffc006000000

#define CL_TRACE_CHANNEL_START  CL_TRACE_BUFFER_START
#define CL_TRACE_CHANNEL_SIZE   0x160000UL

#define CL_TRACE_META_START (CL_TRACE_CHANNEL_START + CL_TRACE_CHANNEL_SIZE)
#define CL_TRACE_META_SIZE  0xa0000UL

/*
 * Trap handler provided by ArceOS
 */

void ax_handle_ebreak(void *regs);
void ax_handle_page_fault(void *regs);

#endif /* _ADAPTOR_H_ */
