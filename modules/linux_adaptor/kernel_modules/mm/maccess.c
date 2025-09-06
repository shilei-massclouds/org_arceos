#include <linux/export.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <asm/tlb.h>
#include "../adaptor.h"

#define copy_to_kernel_nofault_loop(dst, src, len, type, err_label) \
    while (len >= sizeof(type)) {                   \
        __put_kernel_nofault(dst, src, type, err_label);        \
        dst += sizeof(type);                    \
        src += sizeof(type);                    \
        len -= sizeof(type);                    \
    }

long copy_to_kernel_nofault(void *dst, const void *src, size_t size)
{
    unsigned long align = 0;

    if (!IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS))
        align = (unsigned long)dst | (unsigned long)src;

    pagefault_disable();
    if (!(align & 7))
        copy_to_kernel_nofault_loop(dst, src, size, u64, Efault);
    if (!(align & 3))
        copy_to_kernel_nofault_loop(dst, src, size, u32, Efault);
    if (!(align & 1))
        copy_to_kernel_nofault_loop(dst, src, size, u16, Efault);
    copy_to_kernel_nofault_loop(dst, src, size, u8, Efault);
    pagefault_enable();
    return 0;
Efault:
    pagefault_enable();
    return -EFAULT;
}
