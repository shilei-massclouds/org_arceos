#include <linux/bio.h>
#include <linux/slab.h>
#include "booter.h"

void bio_init(struct bio *bio, struct bio_vec *table,
          unsigned short max_vecs)
{
    memset(bio, 0, sizeof(*bio));
    atomic_set(&bio->__bi_remaining, 1);
    atomic_set(&bio->__bi_cnt, 1);

    bio->bi_io_vec = table;
    bio->bi_max_vecs = max_vecs;
}

struct bio *cl_bio_alloc(unsigned int nr_iovecs)
{
    struct bio *bio;

    bio = kmalloc(struct_size(bio, bi_inline_vecs, nr_iovecs), 0);
    bio_init(bio, NULL, 0);
    bio->bi_max_vecs = nr_iovecs;
    bio->bi_io_vec = bio->bi_inline_vecs;
    return bio;
}

void __bio_add_page(struct bio *bio, struct page *page,
        unsigned int len, unsigned int off)
{
    struct bio_vec *bv = &bio->bi_io_vec[bio->bi_vcnt];

    log_debug("%s: (%lx) len(%u) off(%u)\n", __func__, (unsigned long)page, len, off);
    WARN_ON_ONCE(bio_flagged(bio, BIO_CLONED));
    WARN_ON_ONCE(bio_full(bio, len));

    bv->bv_page = page;
    bv->bv_offset = off;
    bv->bv_len = len;

    bio->bi_iter.bi_size += len;
    bio->bi_vcnt++;

    if (!bio_flagged(bio, BIO_WORKINGSET) && unlikely(PageWorkingset(page)))
        bio_set_flag(bio, BIO_WORKINGSET);
}
