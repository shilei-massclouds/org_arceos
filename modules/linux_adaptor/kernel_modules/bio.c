#include <linux/bio.h>
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

struct bio *bio_alloc_bioset(gfp_t gfp_mask, unsigned int nr_iovecs,
                 struct bio_set *bs)
{
    return cl_bio_alloc(nr_iovecs);
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

/**
 *  bio_add_page    -   attempt to add page(s) to bio
 *  @bio: destination bio
 *  @page: start page to add
 *  @len: vec entry length, may cross pages
 *  @offset: vec entry offset relative to @page, may cross pages
 *
 *  Attempt to add page(s) to the bio_vec maplist. This will only fail
 *  if either bio->bi_vcnt == bio->bi_max_vecs or it's a cloned bio.
 */
int bio_add_page(struct bio *bio, struct page *page,
         unsigned int len, unsigned int offset)
{
    __bio_add_page(bio, page, len, offset);
    return len;
}

/**
 * submit_bio - submit a bio to the block device layer for I/O
 * @bio: The &struct bio which describes the I/O
 *
 * submit_bio() is used to submit I/O requests to block devices.  It is passed a
 * fully set up &struct bio that describes the I/O that needs to be done.  The
 * bio will be send to the device described by the bi_disk and bi_partno fields.
 *
 * The success/failure status of the request, along with notification of
 * completion, is delivered asynchronously through the ->bi_end_io() callback
 * in @bio.  The bio must NOT be touched by thecaller until ->bi_end_io() has
 * been called.
 */
blk_qc_t submit_bio(struct bio *bio)
{
    if (bio == NULL || bio->bi_vcnt != 1) {
        booter_panic("bad bio!");
    }

    if (bio_op(bio) != REQ_OP_READ) {
        booter_panic("No support for WRITE!");
    }

    log_error("%s: bi_vcnt(%u) bi_sector(%u)\n",
              __func__, bio->bi_vcnt, bio->bi_iter.bi_sector);

    struct bio_vec *bv = &bio->bi_io_vec[0];
    log_error("bv_page(%lx) bv_len(%u) bv_offset(%u)\n",
              bv->bv_page, bv->bv_len, bv->bv_offset);

    int blkid;

    if (bv->bv_len == PAGE_SIZE) {
        blkid = bio->bi_iter.bi_sector * 8;
    } else {
        blkid = bio->bi_iter.bi_sector * 2;
    }

    void *buf = page_to_virt(bv->bv_page);
    cl_read_block(blkid, buf, PAGE_SIZE);
    return 0;
}
