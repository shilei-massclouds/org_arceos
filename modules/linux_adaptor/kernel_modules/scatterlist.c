#include <linux/printk.h>
#include <linux/scatterlist.h>
#include "booter.h"

void sg_init_table(struct scatterlist *sgl, unsigned int nents)
{
    memset(sgl, 0, sizeof(*sgl) * nents);
    sg_init_marker(sgl, nents);
}

struct scatterlist *sg_next(struct scatterlist *sg)
{
    if (sg_is_last(sg))
        return NULL;

    sg++;
    if (unlikely(sg_is_chain(sg)))
        sg = sg_chain_ptr(sg);

    return sg;
}

void sg_init_one(struct scatterlist *sg, const void *buf, unsigned int buflen)
{
    sg_init_table(sg, 1);
    log_debug("=====> %s: buf (%lx) -> (%lx)", __func__, buf, virt_to_pfn(buf));
    BUG_ON(!virt_addr_valid(buf));
    sg_set_buf(sg, buf, buflen);
}
