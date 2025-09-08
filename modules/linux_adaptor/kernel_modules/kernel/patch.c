#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/memory.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/stop_machine.h>
#include <asm/kprobes.h>
#include <asm/cacheflush.h>
#include <asm/fixmap.h>
#include <asm/ftrace.h>
#include <asm/patch.h>
#include <asm/sections.h>
#include "../adaptor.h"

extern void *
cl_set_fixmap(unsigned int idx, phys_addr_t phys, pgprot_t prot);

static inline bool is_kernel_exittext(uintptr_t addr)
{
    return system_state < SYSTEM_RUNNING &&
        addr >= (uintptr_t)__exittext_begin &&
        addr < (uintptr_t)__exittext_end;
}

/*
 * The fix_to_virt(, idx) needs a const value (not a dynamic variable of
 * reg-a0) or BUILD_BUG_ON failed with "idx >= __end_of_fixed_addresses".
 * So use '__always_inline' and 'const unsigned int fixmap' here.
 */
static __always_inline void *patch_map(void *addr, const unsigned int fixmap)
{
    uintptr_t uintaddr = (uintptr_t) addr;
    struct page *page;

    if (core_kernel_text(uintaddr) || is_kernel_exittext(uintaddr))
        page = phys_to_page(__pa_symbol(addr));
    else if (IS_ENABLED(CONFIG_STRICT_MODULE_RWX))
        page = vmalloc_to_page(addr);
    else
        return addr;

    BUG_ON(!page);

    printk("%s: addr(%lx) fixmap(%u)\n", __func__, addr, fixmap);
	return cl_set_fixmap(fixmap,
                         page_to_phys(page) + offset_in_page(addr),
                         FIXMAP_PAGE_NORMAL);
}

static void patch_unmap(int fixmap)
{
    printk("%s: ..\n", __func__);
	cl_set_fixmap(fixmap, 0, FIXMAP_PAGE_CLEAR);
}

static int __patch_insn_write(void *addr, const void *insn, size_t len)
{
    bool across_pages = (offset_in_page(addr) + len) > PAGE_SIZE;
    void *waddr = addr;
    int ret;

    printk("%s: addr(%lx) insn(%lx) len(%u)\n", __func__, addr, insn, len);
    /*
     * Only two pages can be mapped at a time for writing.
     */
    if (len + offset_in_page(addr) > 2 * PAGE_SIZE)
        return -EINVAL;

    /*
     * Before reaching here, it was expected to lock the text_mutex
     * already, so we don't need to give another lock here and could
     * ensure that it was safe between each cores.
     *
     * We're currently using stop_machine() for ftrace & kprobes, and while
     * that ensures text_mutex is held before installing the mappings it
     * does not ensure text_mutex is held by the calling thread.  That's
     * safe but triggers a lockdep failure, so just elide it for that
     * specific case.
     */
    if (!riscv_patch_in_stop_machine)
        lockdep_assert_held(&text_mutex);

    preempt_disable();

    if (across_pages)
        patch_map(addr + PAGE_SIZE, FIX_TEXT_POKE1);

    waddr = patch_map(addr, FIX_TEXT_POKE0);

    ret = copy_to_kernel_nofault(waddr, insn, len);

    /*
     * We could have just patched a function that is about to be
     * called so make sure we don't execute partially patched
     * instructions by flushing the icache as soon as possible.
     */
    local_flush_icache_range((unsigned long)waddr,
                 (unsigned long)waddr + len);

    patch_unmap(FIX_TEXT_POKE0);

    if (across_pages)
        patch_unmap(FIX_TEXT_POKE1);

    preempt_enable();

    return ret;
}

int patch_insn_write(void *addr, const void *insn, size_t len)
{
    size_t size;
    int ret;

    /*
     * Copy the instructions to the destination address, two pages at a time
     * because __patch_insn_write() can only handle len <= 2 * PAGE_SIZE.
     */
    while (len) {
        size = min(len, PAGE_SIZE * 2 - offset_in_page(addr));
        ret = __patch_insn_write(addr, insn, size);
        if (ret)
            return ret;

        addr += size;
        insn += size;
        len -= size;
    }

    return 0;
}
