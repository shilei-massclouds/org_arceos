// SPDX-License-Identifier: GPL-2.0-only

#ifndef _CLINUX_H_
#define _CLINUX_H_

typedef unsigned long size_t;
typedef _Bool bool;

extern void *cl_rust_alloc(unsigned long size, unsigned long align);
extern void cl_rust_dealloc(const void *addr);
extern void *cl_alloc_pages(unsigned long size, unsigned long align);

extern void sbi_puts(const char *s);
extern void sbi_put_u64(unsigned long n);
extern void sbi_put_dec(unsigned long n);
extern void sbi_console_putchar(int ch);

typedef int (*init_module_t)(void);
typedef void (*exit_module_t)(void);

extern int hex_to_str(unsigned long n, char *str, size_t len);
extern int dec_to_str(unsigned long n, char *str, size_t len);

extern void sbi_shutdown(void);

#define UL_STR_SIZE 19  /* prefix with '0x' and end with '\0' */

#define booter_panic(args...) \
do { \
    sbi_puts("\n########################\n"); \
    sbi_puts("PANIC: "); \
    sbi_puts(__FUNCTION__); \
    sbi_puts(" ("); \
    sbi_puts(__FILE__); \
    sbi_puts(":"); \
    sbi_put_dec(__LINE__); \
    sbi_puts(")\n" args ""); \
    sbi_puts("\n########################\n"); \
    sbi_shutdown(); \
} while (0);

//
// Helper for decomposing components.
//
#define CL_MINE(name) \
    void name() { booter_panic("No impl.\n"); }

#endif /* _CLINUX_H_ */
