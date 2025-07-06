#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/sched/sysctl.h>

#include "block/blk.h"
#include "booter.h"

extern int cl_submit_bio(struct bio *bio);

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
    log_error("%s: bi_vcnt(%u) bi_sector(%u) bi_size(%u) bi_end_io(%lx)\n",
              __func__, bio->bi_vcnt,
              bio->bi_iter.bi_sector,
              bio->bi_iter.bi_size,
              bio->bi_end_io);

    if (bio->bi_vcnt) {
        struct bio_vec *bv = &bio->bi_io_vec[0];
        log_error("bv_page(%lx) bv_len(%u) bv_offset(%u)\n",
                  bv->bv_page, bv->bv_len, bv->bv_offset);
    }

    cl_submit_bio(bio);
    return 0;
}

/**
 * bio_advance - increment/complete a bio by some number of bytes
 * @bio:    bio to advance
 * @bytes:  number of bytes to complete
 *
 * This updates bi_sector, bi_size and bi_idx; if the number of bytes to
 * complete doesn't align with a bvec boundary, then bv_len and bv_offset will
 * be updated on the last bvec as well.
 *
 * @bio will then represent the remaining, uncompleted portion of the io.
 */
void bio_advance(struct bio *bio, unsigned bytes)
{
    if (bio_integrity(bio))
        bio_integrity_advance(bio, bytes);

    //bio_crypt_advance(bio, bytes);
    bio_advance_iter(bio, &bio->bi_iter, bytes);
}

/**
 * bio_endio - end I/O on a bio
 * @bio:    bio
 *
 * Description:
 *   bio_endio() will end I/O on the whole bio. bio_endio() is the preferred
 *   way to end I/O on a bio. No one should call bi_end_io() directly on a
 *   bio unless they own it and thus know that it has an end_io function.
 *
 *   bio_endio() can be called several times on a bio that has been chained
 *   using bio_chain().  The ->bi_end_io() function will only be called the
 *   last time.  At this point the BLK_TA_COMPLETE tracing event will be
 *   generated if BIO_TRACE_COMPLETION is set.
 **/
void bio_endio(struct bio *bio)
{
    printk("%s: before\n", __func__);
    if (bio->bi_end_io)
        bio->bi_end_io(bio);
    printk("%s: after\n", __func__);
}

/**
 * bio_put - release a reference to a bio
 * @bio:   bio to release reference to
 *
 * Description:
 *   Put a reference to a &struct bio, either one you have gotten with
 *   bio_alloc, bio_get or bio_clone_*. The last put of a bio will free it.
 **/
void bio_put(struct bio *bio)
{
    log_error("%s: No impl.", __func__);
}

static void submit_bio_wait_endio(struct bio *bio)
{
    log_error("%s: ...", __func__);
    complete(bio->bi_private);
}

/**
 * submit_bio_wait - submit a bio, and wait until it completes
 * @bio: The &struct bio which describes the I/O
 *
 * Simple wrapper around submit_bio(). Returns 0 on success, or the error from
 * bio_endio() on failure.
 *
 * WARNING: Unlike to how submit_bio() is usually used, this function does not
 * result in bio reference to be consumed. The caller must drop the reference
 * on his own.
 */
int submit_bio_wait(struct bio *bio)
{
    DECLARE_COMPLETION_ONSTACK_MAP(done, bio->bi_disk->lockdep_map);
    unsigned long hang_check;

    bio->bi_private = &done;
    bio->bi_end_io = submit_bio_wait_endio;
    bio->bi_opf |= REQ_SYNC;
    submit_bio(bio);

    /* Prevent hang_check timer from firing at us during very long I/O */
    hang_check = sysctl_hung_task_timeout_secs;
    if (hang_check)
        while (!wait_for_completion_io_timeout(&done,
                    hang_check * (HZ/2)))
            ;
    else
        wait_for_completion_io(&done);

    return blk_status_to_errno(bio->bi_status);
}

/**
 * guard_bio_eod - truncate a BIO to fit the block device
 * @bio:    bio to truncate
 *
 * This allows us to do IO even on the odd last sectors of a device, even if the
 * block size is some multiple of the physical sector size.
 *
 * We'll just truncate the bio to the size of the device, and clear the end of
 * the buffer head manually.  Truly out-of-range accesses will turn into actual
 * I/O errors, this only handles the "we need to be able to do I/O at the final
 * sector" case.
 */
void guard_bio_eod(struct bio *bio)
{
    sector_t maxsector;
    struct hd_struct *part;

    rcu_read_lock();
    part = __disk_get_part(bio->bi_disk, bio->bi_partno);
    if (part)
        maxsector = part_nr_sects_read(part);
    else
        maxsector = get_capacity(bio->bi_disk);
    rcu_read_unlock();

    if (!maxsector)
        return;

    /*
     * If the *whole* IO is past the end of the device,
     * let it through, and the IO layer will turn it into
     * an EIO.
     */
    if (unlikely(bio->bi_iter.bi_sector >= maxsector))
        return;

    maxsector -= bio->bi_iter.bi_sector;
    if (likely((bio->bi_iter.bi_size >> 9) <= maxsector))
        return;

    bio_truncate(bio, maxsector << 9);
}
