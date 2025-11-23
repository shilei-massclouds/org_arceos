#include <linux/dma-direct.h>
#include <linux/dma-map-ops.h>
#include <linux/mm.h>
#include <asm/cacheflush.h>
#include <asm/dma-noncoherent.h>
#include "adaptor.h"

static bool noncoherent_supported __ro_after_init;
int dma_cache_alignment __ro_after_init = ARCH_DMA_MINALIGN;

void arch_setup_dma_ops(struct device *dev, bool coherent)
{
    WARN_TAINT(!coherent && riscv_cbom_block_size > ARCH_DMA_MINALIGN,
           TAINT_CPU_OUT_OF_SPEC,
           "%s %s: ARCH_DMA_MINALIGN smaller than riscv,cbom-block-size (%d < %d)",
           dev_driver_string(dev), dev_name(dev),
           ARCH_DMA_MINALIGN, riscv_cbom_block_size);

    WARN_TAINT(!coherent && !noncoherent_supported, TAINT_CPU_OUT_OF_SPEC,
           "%s %s: device non-coherent but no non-coherent operations supported",
           dev_driver_string(dev), dev_name(dev));

    dev->dma_coherent = coherent;
}

void arch_dma_prep_coherent(struct page *page, size_t size)
{
    void *flush_addr = page_address(page);

#ifdef CONFIG_RISCV_NONSTANDARD_CACHE_OPS
    pr_err("%s: Fix config 'CONFIG_RISCV_NONSTANDARD_CACHE_OPS'\n", __func__);
    if (unlikely(noncoherent_cache_ops.wback_inv)) {
        noncoherent_cache_ops.wback_inv(page_to_phys(page), size);
        return;
    }
#endif

    ALT_CMO_OP(FLUSH, flush_addr, size, riscv_cbom_block_size);
}
