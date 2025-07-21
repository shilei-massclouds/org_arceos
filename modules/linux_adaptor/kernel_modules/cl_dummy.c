#include <linux/of.h>

#include "../adaptor.h"

#ifdef CONFIG_SPARSEMEM_VMEMMAP
#define VMEMMAP_ADDR_ALIGN  (1ULL << SECTION_SIZE_BITS)

unsigned long vmemmap_start_pfn __ro_after_init;
#endif

#ifdef CONFIG_64BIT
bool pgtable_l4_enabled __ro_after_init;
bool pgtable_l5_enabled __ro_after_init;
#endif

bool __riscv_isa_extension_available(const unsigned long *isa_bitmap, unsigned int bit)
{
    pr_err("%s: No impl.", __func__);
    return false;
}

bool is_acpi_device_node(const struct fwnode_handle *fwnode)
{
    pr_err("%s: No impl.", __func__);
    return false;
}

bool is_software_node(const struct fwnode_handle *fwnode)
{
    pr_err("%s: No impl.", __func__);
    return false;
}

/**
 * dump_stack_lvl - dump the current task information and its stack trace
 * @log_lvl: log level
 *
 * Architectures can override this implementation by implementing its own.
 */
asmlinkage __visible void dump_stack_lvl(const char *log_lvl)
{
    printk("%s", log_lvl);
}

/**
 * is_swiotlb_allocated() - check if the default software IO TLB is initialized
 */
bool is_swiotlb_allocated(void)
{
    pr_err("%s: No impl.", __func__);
    return false;
    //return io_tlb_default_mem.nslabs;
}

// Defined in arch/riscv/mm/dma-noncoherent.c
int dma_cache_alignment __ro_after_init = ARCH_DMA_MINALIGN;
