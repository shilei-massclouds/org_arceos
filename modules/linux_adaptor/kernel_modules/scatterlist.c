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

static inline void _sg_assign_page(struct scatterlist *sg, const void *buf)
{
    unsigned long page_link = sg->page_link & (SG_CHAIN | SG_END);

    /*
     * In order for the low bit stealing approach to work, pages
     * must be aligned at a 32-bit boundary as a minimum.
     */
    BUG_ON((unsigned long) buf & (SG_CHAIN | SG_END));
    sg->page_link = page_link | (unsigned long) buf;
}

static inline void _sg_set_page(struct scatterlist *sg, const void *buf,
                   unsigned int len, unsigned int offset)
{
    _sg_assign_page(sg, buf);
    sg->offset = offset;
    sg->length = len;
}

static inline void _sg_set_buf(struct scatterlist *sg, const void *buf,
                  unsigned int buflen)
{
    _sg_set_page(sg, buf, buflen, offset_in_page(buf));
}

void sg_init_one(struct scatterlist *sg, const void *buf, unsigned int buflen)
{
    sg_init_table(sg, 1);
    _sg_set_buf(sg, buf, buflen);
    log_debug("%s: ===========> \n", __func__);
}
