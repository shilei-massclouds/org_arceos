#include <linux/kernel.h>
#include <linux/sched/task_stack.h>
#include <linux/module.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/uio.h>

#include "blk.h"
#include "../adaptor.h"

static void bio_copy_kern_endio(struct bio *bio)
{
    bio_free_pages(bio);
    bio_uninit(bio);
    kfree(bio);
}

static void bio_copy_kern_endio_read(struct bio *bio)
{
    char *p = bio->bi_private;
    struct bio_vec *bvec;
    struct bvec_iter_all iter_all;

    bio_for_each_segment_all(bvec, bio, iter_all) {
        memcpy_from_bvec(p, bvec);
        p += bvec->bv_len;
    }

    bio_copy_kern_endio(bio);
}

/**
 *  bio_copy_kern   -   copy kernel address into bio
 *  @q: the struct request_queue for the bio
 *  @data: pointer to buffer to copy
 *  @len: length in bytes
 *  @gfp_mask: allocation flags for bio and page allocation
 *  @reading: data direction is READ
 *
 *  copy the kernel address into a bio suitable for io to a block
 *  device. Returns an error pointer in case of error.
 */
static struct bio *bio_copy_kern(struct request_queue *q, void *data,
        unsigned int len, gfp_t gfp_mask, int reading)
{
    unsigned long kaddr = (unsigned long)data;
    unsigned long end = (kaddr + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
    unsigned long start = kaddr >> PAGE_SHIFT;
    struct bio *bio;
    void *p = data;
    int nr_pages = 0;

    /*
     * Overflow, abort
     */
    if (end < start)
        return ERR_PTR(-EINVAL);

    nr_pages = end - start;
    bio = bio_kmalloc(nr_pages, gfp_mask);
    if (!bio)
        return ERR_PTR(-ENOMEM);
    bio_init(bio, NULL, bio->bi_inline_vecs, nr_pages, 0);

    while (len) {
        struct page *page;
        unsigned int bytes = PAGE_SIZE;

        if (bytes > len)
            bytes = len;

        page = alloc_page(GFP_NOIO | __GFP_ZERO | gfp_mask);
        if (!page)
            goto cleanup;

        if (!reading)
            memcpy(page_address(page), p, bytes);

        if (bio_add_pc_page(q, bio, page, bytes, 0) < bytes)
            break;

        len -= bytes;
        p += bytes;
    }

    if (reading) {
        bio->bi_end_io = bio_copy_kern_endio_read;
        bio->bi_private = data;
    } else {
        bio->bi_end_io = bio_copy_kern_endio;
    }

    return bio;

cleanup:
    bio_free_pages(bio);
    bio_uninit(bio);
    kfree(bio);
    return ERR_PTR(-ENOMEM);
}

static void bio_invalidate_vmalloc_pages(struct bio *bio)
{
#ifdef ARCH_IMPLEMENTS_FLUSH_KERNEL_VMAP_RANGE
    if (bio->bi_private && !op_is_write(bio_op(bio))) {
        unsigned long i, len = 0;

        for (i = 0; i < bio->bi_vcnt; i++)
            len += bio->bi_io_vec[i].bv_len;
        invalidate_kernel_vmap_range(bio->bi_private, len);
    }
#endif
}

static void bio_map_kern_endio(struct bio *bio)
{
    bio_invalidate_vmalloc_pages(bio);
    bio_uninit(bio);
    kfree(bio);
}

/**
 *  bio_map_kern    -   map kernel address into bio
 *  @q: the struct request_queue for the bio
 *  @data: pointer to buffer to map
 *  @len: length in bytes
 *  @gfp_mask: allocation flags for bio allocation
 *
 *  Map the kernel address into a bio suitable for io to a block
 *  device. Returns an error pointer in case of error.
 */
static struct bio *bio_map_kern(struct request_queue *q, void *data,
        unsigned int len, gfp_t gfp_mask)
{
    unsigned long kaddr = (unsigned long)data;
    unsigned long end = (kaddr + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
    unsigned long start = kaddr >> PAGE_SHIFT;
    const int nr_pages = end - start;
    bool is_vmalloc = is_vmalloc_addr(data);
    struct page *page;
    int offset, i;
    struct bio *bio;

    bio = bio_kmalloc(nr_pages, gfp_mask);
    if (!bio)
        return ERR_PTR(-ENOMEM);
    bio_init(bio, NULL, bio->bi_inline_vecs, nr_pages, 0);

    if (is_vmalloc) {
        flush_kernel_vmap_range(data, len);
        bio->bi_private = data;
    }

    offset = offset_in_page(kaddr);
    for (i = 0; i < nr_pages; i++) {
        unsigned int bytes = PAGE_SIZE - offset;

        if (len <= 0)
            break;

        if (bytes > len)
            bytes = len;

        if (!is_vmalloc)
            page = virt_to_page(data);
        else
            page = vmalloc_to_page(data);
        if (bio_add_pc_page(q, bio, page, bytes,
                    offset) < bytes) {
            /* we don't support partial mappings */
            bio_uninit(bio);
            kfree(bio);
            return ERR_PTR(-EINVAL);
        }

        data += bytes;
        len -= bytes;
        offset = 0;
    }

    bio->bi_end_io = bio_map_kern_endio;
    return bio;
}

/**
 * blk_rq_map_kern - map kernel data to a request, for passthrough requests
 * @q:      request queue where request should be inserted
 * @rq:     request to fill
 * @kbuf:   the kernel buffer
 * @len:    length of user data
 * @gfp_mask:   memory allocation flags
 *
 * Description:
 *    Data will be mapped directly if possible. Otherwise a bounce
 *    buffer is used. Can be called multiple times to append multiple
 *    buffers.
 */
int blk_rq_map_kern(struct request_queue *q, struct request *rq, void *kbuf,
            unsigned int len, gfp_t gfp_mask)
{
    int reading = rq_data_dir(rq) == READ;
    unsigned long addr = (unsigned long) kbuf;
    struct bio *bio;
    int ret;

    printk("%s: step1 len(%u) max(%u)\n", __func__, len, queue_max_hw_sectors(q) << 9);
    if (len > (queue_max_hw_sectors(q) << 9))
        return -EINVAL;
    printk("%s: step2\n", __func__);
    if (!len || !kbuf)
        return -EINVAL;
    printk("%s: step3\n", __func__);

    if (!blk_rq_aligned(q, addr, len) || object_is_on_stack(kbuf) ||
        blk_queue_may_bounce(q))
        bio = bio_copy_kern(q, kbuf, len, gfp_mask, reading);
    else
        bio = bio_map_kern(q, kbuf, len, gfp_mask);

    if (IS_ERR(bio))
        return PTR_ERR(bio);

    bio->bi_opf &= ~REQ_OP_MASK;
    bio->bi_opf |= req_op(rq);

    ret = blk_rq_append_bio(rq, bio);
    if (unlikely(ret)) {
        bio_uninit(bio);
        kfree(bio);
    }
    return ret;
}

/*
 * Append a bio to a passthrough request.  Only works if the bio can be merged
 * into the request based on the driver constraints.
 */
int blk_rq_append_bio(struct request *rq, struct bio *bio)
{
    struct bvec_iter iter;
    struct bio_vec bv;
    unsigned int nr_segs = 0;

    bio_for_each_bvec(bv, bio, iter)
        nr_segs++;

    if (!rq->bio) {
        blk_rq_bio_prep(rq, bio, nr_segs);
    } else {
        if (!ll_back_merge_fn(rq, bio, nr_segs))
            return -EINVAL;
        rq->biotail->bi_next = bio;
        rq->biotail = bio;
        rq->__data_len += (bio)->bi_iter.bi_size;
        bio_crypt_free_ctx(bio);
    }

    return 0;
}
