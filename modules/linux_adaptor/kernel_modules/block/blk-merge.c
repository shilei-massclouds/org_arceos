/*
 * Functions related to segment and merge handling
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/blk-integrity.h>
#include <linux/scatterlist.h>
#include <linux/part_stat.h>
#include <linux/blk-cgroup.h>

#include <trace/events/block.h>

#include "blk.h"
#include "blk-mq-sched.h"
#include "blk-rq-qos.h"
#include "blk-throttle.h"

#include "../adaptor.h"

static inline void bio_get_first_bvec(struct bio *bio, struct bio_vec *bv)
{
    *bv = mp_bvec_iter_bvec(bio->bi_io_vec, bio->bi_iter);
}

static inline void bio_get_last_bvec(struct bio *bio, struct bio_vec *bv)
{
    struct bvec_iter iter = bio->bi_iter;
    int idx;

    bio_get_first_bvec(bio, bv);
    if (bv->bv_len == bio->bi_iter.bi_size)
        return;     /* this bio only has a single bvec */

    bio_advance_iter(bio, &iter, iter.bi_size);

    if (!iter.bi_bvec_done)
        idx = iter.bi_idx - 1;
    else    /* in the middle of bvec */
        idx = iter.bi_idx;

    *bv = bio->bi_io_vec[idx];

    /*
     * iter.bi_bvec_done records actual length of the last bvec
     * if this bio ends in the middle of one io vector
     */
    if (iter.bi_bvec_done)
        bv->bv_len = iter.bi_bvec_done;
}

static bool blk_atomic_write_mergeable_rq_bio(struct request *rq,
                          struct bio *bio)
{
    return (rq->cmd_flags & REQ_ATOMIC) == (bio->bi_opf & REQ_ATOMIC);
}

static inline unsigned int blk_boundary_sectors(const struct queue_limits *lim,
                        bool is_atomic)
{
    /*
     * chunk_sectors must be a multiple of atomic_write_boundary_sectors if
     * both non-zero.
     */
    if (is_atomic && lim->atomic_write_boundary_sectors)
        return lim->atomic_write_boundary_sectors;

    return lim->chunk_sectors;
}

static inline bool bio_will_gap(struct request_queue *q,
        struct request *prev_rq, struct bio *prev, struct bio *next)
{
    struct bio_vec pb, nb;

    if (!bio_has_data(prev) || !queue_virt_boundary(q))
        return false;

    /*
     * Don't merge if the 1st bio starts with non-zero offset, otherwise it
     * is quite difficult to respect the sg gap limit.  We work hard to
     * merge a huge number of small single bios in case of mkfs.
     */
    if (prev_rq)
        bio_get_first_bvec(prev_rq->bio, &pb);
    else
        bio_get_first_bvec(prev, &pb);
    if (pb.bv_offset & queue_virt_boundary(q))
        return true;

    /*
     * We don't need to worry about the situation that the merged segment
     * ends in unaligned virt boundary:
     *
     * - if 'pb' ends aligned, the merged segment ends aligned
     * - if 'pb' ends unaligned, the next bio must include
     *   one single bvec of 'nb', otherwise the 'nb' can't
     *   merge with 'pb'
     */
    bio_get_last_bvec(prev, &pb);
    bio_get_first_bvec(next, &nb);
    if (biovec_phys_mergeable(q, &pb, &nb))
        return false;
    return __bvec_gap_to_prev(&q->limits, &pb, nb.bv_offset);
}

static inline bool req_gap_front_merge(struct request *req, struct bio *bio)
{
    return bio_will_gap(req->q, NULL, bio, req->bio);
}

static inline bool req_gap_back_merge(struct request *req, struct bio *bio)
{
    return bio_will_gap(req->q, req, req->biotail, bio);
}

/**
 * get_max_segment_size() - maximum number of bytes to add as a single segment
 * @lim: Request queue limits.
 * @paddr: address of the range to add
 * @len: maximum length available to add at @paddr
 *
 * Returns the maximum number of bytes of the range starting at @paddr that can
 * be added to a single segment.
 */
static inline unsigned get_max_segment_size(const struct queue_limits *lim,
        phys_addr_t paddr, unsigned int len)
{
    /*
     * Prevent an overflow if mask = ULONG_MAX and offset = 0 by adding 1
     * after having calculated the minimum.
     */
    return min_t(unsigned long, len,
        min(lim->seg_boundary_mask - (lim->seg_boundary_mask & paddr),
            (unsigned long)lim->max_segment_size - 1) + 1);
}

static inline blk_opf_t bio_failfast(const struct bio *bio)
{
    if (bio->bi_opf & REQ_RAHEAD)
        return REQ_FAILFAST_MASK;

    return bio->bi_opf & REQ_FAILFAST_MASK;
}

/**
 * blk_rq_set_mixed_merge - mark a request as mixed merge
 * @rq: request to mark as mixed merge
 *
 * Description:
 *     @rq is about to be mixed merged.  Make sure the attributes
 *     which can be mixed are set in each bio and mark @rq as mixed
 *     merged.
 */
static void blk_rq_set_mixed_merge(struct request *rq)
{
    blk_opf_t ff = rq->cmd_flags & REQ_FAILFAST_MASK;
    struct bio *bio;

    if (rq->rq_flags & RQF_MIXED_MERGE)
        return;

    /*
     * @rq will no longer represent mixable attributes for all the
     * contained bios.  It will just track those of the first one.
     * Distributes the attributs to each bio.
     */
    for (bio = rq->bio; bio; bio = bio->bi_next) {
        WARN_ON_ONCE((bio->bi_opf & REQ_FAILFAST_MASK) &&
                 (bio->bi_opf & REQ_FAILFAST_MASK) != ff);
        bio->bi_opf |= ff;
    }
    rq->rq_flags |= RQF_MIXED_MERGE;
}

/*
 * After we are marked as MIXED_MERGE, any new RA bio has to be updated
 * as failfast, and request's failfast has to be updated in case of
 * front merge.
 */
static inline void blk_update_mixed_merge(struct request *req,
        struct bio *bio, bool front_merge)
{
    if (req->rq_flags & RQF_MIXED_MERGE) {
        if (bio->bi_opf & REQ_RAHEAD)
            bio->bi_opf |= REQ_FAILFAST_MASK;

        if (front_merge) {
            req->cmd_flags &= ~REQ_FAILFAST_MASK;
            req->cmd_flags |= bio->bi_opf & REQ_FAILFAST_MASK;
        }
    }
}

static void blk_account_io_merge_bio(struct request *req)
{
    if (!blk_do_io_stat(req))
        return;

    part_stat_lock();
    part_stat_inc(req->part, merges[op_stat_group(req_op(req))]);
    part_stat_unlock();
}

enum bio_merge_status bio_attempt_back_merge(struct request *req,
        struct bio *bio, unsigned int nr_segs)
{
    const blk_opf_t ff = bio_failfast(bio);

    if (!ll_back_merge_fn(req, bio, nr_segs))
        return BIO_MERGE_FAILED;

    trace_block_bio_backmerge(bio);
    rq_qos_merge(req->q, req, bio);

    if ((req->cmd_flags & REQ_FAILFAST_MASK) != ff)
        blk_rq_set_mixed_merge(req);

    blk_update_mixed_merge(req, bio, false);

    if (req->rq_flags & RQF_ZONE_WRITE_PLUGGING)
        blk_zone_write_plug_bio_merged(bio);

    req->biotail->bi_next = bio;
    req->biotail = bio;
    req->__data_len += bio->bi_iter.bi_size;

    bio_crypt_free_ctx(bio);

    blk_account_io_merge_bio(req);
    return BIO_MERGE_OK;
}

static inline int ll_new_hw_segment(struct request *req, struct bio *bio,
        unsigned int nr_phys_segs)
{
    if (!blk_cgroup_mergeable(req, bio))
        goto no_merge;

    if (blk_integrity_merge_bio(req->q, req, bio) == false)
        goto no_merge;

    /* discard request merge won't add new segment */
    if (req_op(req) == REQ_OP_DISCARD)
        return 1;

    if (req->nr_phys_segments + nr_phys_segs > blk_rq_get_max_segments(req))
        goto no_merge;

    /*
     * This will form the start of a new hw segment.  Bump both
     * counters.
     */
    req->nr_phys_segments += nr_phys_segs;
    if (bio_integrity(bio))
        req->nr_integrity_segments += blk_rq_count_integrity_sg(req->q,
                                    bio);
    return 1;

no_merge:
    req_set_nomerge(req->q, req);
    return 0;
}

static inline unsigned int blk_rq_get_max_sectors(struct request *rq,
                          sector_t offset)
{
    struct request_queue *q = rq->q;
    struct queue_limits *lim = &q->limits;
    unsigned int max_sectors, boundary_sectors;
    bool is_atomic = rq->cmd_flags & REQ_ATOMIC;

    if (blk_rq_is_passthrough(rq))
        return q->limits.max_hw_sectors;

    boundary_sectors = blk_boundary_sectors(lim, is_atomic);
    max_sectors = blk_queue_get_max_sectors(rq);

    if (!boundary_sectors ||
        req_op(rq) == REQ_OP_DISCARD ||
        req_op(rq) == REQ_OP_SECURE_ERASE)
        return max_sectors;
#if 0
    return min(max_sectors,
           blk_boundary_sectors_left(offset, boundary_sectors));
#endif
    PANIC("");
}

int ll_back_merge_fn(struct request *req, struct bio *bio, unsigned int nr_segs)
{
    if (req_gap_back_merge(req, bio))
        return 0;
    if (blk_integrity_rq(req) &&
        integrity_req_gap_back_merge(req, bio))
        return 0;
    if (!bio_crypt_ctx_back_mergeable(req, bio))
        return 0;
    if (blk_rq_sectors(req) + bio_sectors(bio) >
        blk_rq_get_max_sectors(req, blk_rq_pos(req))) {
        req_set_nomerge(req->q, req);
        return 0;
    }

    return ll_new_hw_segment(req, bio, nr_segs);
}

static int ll_front_merge_fn(struct request *req, struct bio *bio,
        unsigned int nr_segs)
{
    if (req_gap_front_merge(req, bio))
        return 0;
    if (blk_integrity_rq(req) &&
        integrity_req_gap_front_merge(req, bio))
        return 0;
    if (!bio_crypt_ctx_front_mergeable(req, bio))
        return 0;
    if (blk_rq_sectors(req) + bio_sectors(bio) >
        blk_rq_get_max_sectors(req, bio->bi_iter.bi_sector)) {
        req_set_nomerge(req->q, req);
        return 0;
    }

    return ll_new_hw_segment(req, bio, nr_segs);
}

static enum bio_merge_status bio_attempt_front_merge(struct request *req,
        struct bio *bio, unsigned int nr_segs)
{
    const blk_opf_t ff = bio_failfast(bio);

    /*
     * A front merge for writes to sequential zones of a zoned block device
     * can happen only if the user submitted writes out of order. Do not
     * merge such write to let it fail.
     */
    if (req->rq_flags & RQF_ZONE_WRITE_PLUGGING)
        return BIO_MERGE_FAILED;

    if (!ll_front_merge_fn(req, bio, nr_segs))
        return BIO_MERGE_FAILED;

#if 0
    trace_block_bio_frontmerge(bio);
    rq_qos_merge(req->q, req, bio);

    if ((req->cmd_flags & REQ_FAILFAST_MASK) != ff)
        blk_rq_set_mixed_merge(req);

    blk_update_mixed_merge(req, bio, true);

    bio->bi_next = req->bio;
    req->bio = bio;

    req->__sector = bio->bi_iter.bi_sector;
    req->__data_len += bio->bi_iter.bi_size;

    bio_crypt_do_front_merge(req, bio);

    blk_account_io_merge_bio(req);
    return BIO_MERGE_OK;
#endif

    PANIC("");
}

static enum bio_merge_status bio_attempt_discard_merge(struct request_queue *q,
        struct request *req, struct bio *bio)
{
    PANIC("");
}

enum elv_merge blk_try_merge(struct request *rq, struct bio *bio)
{
    if (blk_discard_mergable(rq))
        return ELEVATOR_DISCARD_MERGE;
    else if (blk_rq_pos(rq) + blk_rq_sectors(rq) == bio->bi_iter.bi_sector)
        return ELEVATOR_BACK_MERGE;
    else if (blk_rq_pos(rq) - bio_sectors(bio) == bio->bi_iter.bi_sector)
        return ELEVATOR_FRONT_MERGE;
    return ELEVATOR_NO_MERGE;
}

static enum bio_merge_status blk_attempt_bio_merge(struct request_queue *q,
                           struct request *rq,
                           struct bio *bio,
                           unsigned int nr_segs,
                           bool sched_allow_merge)
{
    if (!blk_rq_merge_ok(rq, bio))
        return BIO_MERGE_NONE;

    switch (blk_try_merge(rq, bio)) {
    case ELEVATOR_BACK_MERGE:
        if (!sched_allow_merge || blk_mq_sched_allow_merge(q, rq, bio))
            return bio_attempt_back_merge(rq, bio, nr_segs);
        break;
    case ELEVATOR_FRONT_MERGE:
        if (!sched_allow_merge || blk_mq_sched_allow_merge(q, rq, bio))
            return bio_attempt_front_merge(rq, bio, nr_segs);
        break;
    case ELEVATOR_DISCARD_MERGE:
        return bio_attempt_discard_merge(q, rq, bio);
    default:
        return BIO_MERGE_NONE;
    }

    PANIC("");
    return BIO_MERGE_FAILED;
}

bool blk_rq_merge_ok(struct request *rq, struct bio *bio)
{
    if (!rq_mergeable(rq) || !bio_mergeable(bio))
        return false;

    if (req_op(rq) != bio_op(bio))
        return false;

    /* different data direction or already started, don't merge */
    if (bio_data_dir(bio) != rq_data_dir(rq))
        return false;

    /* don't merge across cgroup boundaries */
    if (!blk_cgroup_mergeable(rq, bio))
        return false;

    /* only merge integrity protected bio into ditto rq */
    if (blk_integrity_merge_bio(rq->q, rq, bio) == false)
        return false;

    /* Only merge if the crypt contexts are compatible */
    if (!bio_crypt_rq_ctx_compatible(rq, bio))
        return false;

    if (rq->bio) {
        /* Don't merge requests with different write hints. */
        if (rq->bio->bi_write_hint != bio->bi_write_hint)
            return false;
        if (rq->bio->bi_ioprio != bio->bi_ioprio)
            return false;
    }

    if (blk_atomic_write_mergeable_rq_bio(rq, bio) == false)
        return false;

    return true;
}

/**
 * blk_attempt_plug_merge - try to merge with %current's plugged list
 * @q: request_queue new bio is being queued at
 * @bio: new bio being queued
 * @nr_segs: number of segments in @bio
 * from the passed in @q already in the plug list
 *
 * Determine whether @bio being queued on @q can be merged with the previous
 * request on %current's plugged list.  Returns %true if merge was successful,
 * otherwise %false.
 *
 * Plugging coalesces IOs from the same issuer for the same purpose without
 * going through @q->queue_lock.  As such it's more of an issuing mechanism
 * than scheduling, and the request, while may have elvpriv data, is not
 * added on the elevator at this point.  In addition, we don't have
 * reliable access to the elevator outside queue lock.  Only check basic
 * merging parameters without querying the elevator.
 *
 * Caller must ensure !blk_queue_nomerges(q) beforehand.
 */
bool blk_attempt_plug_merge(struct request_queue *q, struct bio *bio,
        unsigned int nr_segs)
{
    struct blk_plug *plug = current->plug;
    struct request *rq;

    if (!plug || rq_list_empty(&plug->mq_list))
        return false;

    rq = plug->mq_list.tail;
    if (rq->q == q)
        return blk_attempt_bio_merge(q, rq, bio, nr_segs, false) ==
            BIO_MERGE_OK;
    else if (!plug->multiple_queues)
        return false;

#if 0
    rq_list_for_each(&plug->mq_list, rq) {
        if (rq->q != q)
            continue;
        if (blk_attempt_bio_merge(q, rq, bio, nr_segs, false) ==
            BIO_MERGE_OK)
            return true;
        break;
    }
#endif
    PANIC("");
    return false;
}

/*
 * Iterate list of requests and see if we can merge this bio with any
 * of them.
 */
bool blk_bio_list_merge(struct request_queue *q, struct list_head *list,
            struct bio *bio, unsigned int nr_segs)
{
    PANIC("");
}

static inline struct scatterlist *blk_next_sg(struct scatterlist **sg,
        struct scatterlist *sglist)
{
    if (!*sg)
        return sglist;

    /*
     * If the driver previously mapped a shorter list, we could see a
     * termination bit prematurely unless it fully inits the sg table
     * on each mapping. We KNOW that there must be more entries here
     * or the driver would be buggy, so force clear the termination bit
     * to avoid doing a full sg_init_table() in drivers for each command.
     */
    sg_unmark_end(*sg);
    return sg_next(*sg);
}

/* only try to merge bvecs into one sg if they are from two bios */
static inline bool
__blk_segment_map_sg_merge(struct request_queue *q, struct bio_vec *bvec,
               struct bio_vec *bvprv, struct scatterlist **sg)
{

    int nbytes = bvec->bv_len;

    if (!*sg)
        return false;

    if ((*sg)->length + nbytes > queue_max_segment_size(q))
        return false;

    if (!biovec_phys_mergeable(q, bvprv, bvec))
        return false;

    (*sg)->length += nbytes;

    return true;
}

static unsigned blk_bvec_map_sg(struct request_queue *q,
        struct bio_vec *bvec, struct scatterlist *sglist,
        struct scatterlist **sg)
{
    unsigned nbytes = bvec->bv_len;
    unsigned nsegs = 0, total = 0;

    while (nbytes > 0) {
        unsigned offset = bvec->bv_offset + total;
        unsigned len = get_max_segment_size(&q->limits,
                bvec_phys(bvec) + total, nbytes);
        struct page *page = bvec->bv_page;

        /*
         * Unfortunately a fair number of drivers barf on scatterlists
         * that have an offset larger than PAGE_SIZE, despite other
         * subsystems dealing with that invariant just fine.  For now
         * stick to the legacy format where we never present those from
         * the block layer, but the code below should be removed once
         * these offenders (mostly MMC/SD drivers) are fixed.
         */
        page += (offset >> PAGE_SHIFT);
        offset &= ~PAGE_MASK;

        *sg = blk_next_sg(sg, sglist);
        sg_set_page(*sg, page, len, offset);

        total += len;
        nbytes -= len;
        nsegs++;
    }

    return nsegs;
}

static inline int __blk_bvec_map_sg(struct bio_vec bv,
        struct scatterlist *sglist, struct scatterlist **sg)
{
    *sg = blk_next_sg(sg, sglist);
    sg_set_page(*sg, bv.bv_page, bv.bv_len, bv.bv_offset);
    return 1;
}

static int __blk_bios_map_sg(struct request_queue *q, struct bio *bio,
                 struct scatterlist *sglist,
                 struct scatterlist **sg)
{
    struct bio_vec bvec, bvprv = { NULL };
    struct bvec_iter iter;
    int nsegs = 0;
    bool new_bio = false;

    for_each_bio(bio) {
        bio_for_each_bvec(bvec, bio, iter) {
            /*
             * Only try to merge bvecs from two bios given we
             * have done bio internal merge when adding pages
             * to bio
             */
            if (new_bio &&
                __blk_segment_map_sg_merge(q, &bvec, &bvprv, sg))
                goto next_bvec;

            if (bvec.bv_offset + bvec.bv_len <= PAGE_SIZE)
                nsegs += __blk_bvec_map_sg(bvec, sglist, sg);
            else
                nsegs += blk_bvec_map_sg(q, &bvec, sglist, sg);
 next_bvec:
            new_bio = false;
        }
        if (likely(bio->bi_iter.bi_size)) {
            bvprv = bvec;
            new_bio = true;
        }
    }

    return nsegs;
}

/*
 * map a request to scatterlist, return number of sg entries setup. Caller
 * must make sure sg can hold rq->nr_phys_segments entries
 */
int __blk_rq_map_sg(struct request_queue *q, struct request *rq,
        struct scatterlist *sglist, struct scatterlist **last_sg)
{
    int nsegs = 0;

    if (rq->rq_flags & RQF_SPECIAL_PAYLOAD)
        nsegs = __blk_bvec_map_sg(rq->special_vec, sglist, last_sg);
    else if (rq->bio)
        nsegs = __blk_bios_map_sg(q, rq->bio, sglist, last_sg);

    if (*last_sg)
        sg_mark_end(*last_sg);

    /*
     * Something must have been wrong if the figured number of
     * segment is bigger than number of req's physical segments
     */
    WARN_ON(nsegs > blk_rq_nr_phys_segments(rq));

    return nsegs;
}

/*
 * Return the maximum number of sectors from the start of a bio that may be
 * submitted as a single request to a block device. If enough sectors remain,
 * align the end to the physical block size. Otherwise align the end to the
 * logical block size. This approach minimizes the number of non-aligned
 * requests that are submitted to a block device if the start of a bio is not
 * aligned to a physical block boundary.
 */
static inline unsigned get_max_io_size(struct bio *bio,
                       const struct queue_limits *lim)
{
    unsigned pbs = lim->physical_block_size >> SECTOR_SHIFT;
    unsigned lbs = lim->logical_block_size >> SECTOR_SHIFT;
    bool is_atomic = bio->bi_opf & REQ_ATOMIC;
    unsigned boundary_sectors = blk_boundary_sectors(lim, is_atomic);
    unsigned max_sectors, start, end;

    /*
     * We ignore lim->max_sectors for atomic writes because it may less
     * than the actual bio size, which we cannot tolerate.
     */
    if (bio_op(bio) == REQ_OP_WRITE_ZEROES)
        max_sectors = lim->max_write_zeroes_sectors;
    else if (is_atomic)
        max_sectors = lim->atomic_write_max_sectors;
    else
        max_sectors = lim->max_sectors;

    if (boundary_sectors) {
        max_sectors = min(max_sectors,
            blk_boundary_sectors_left(bio->bi_iter.bi_sector,
                          boundary_sectors));
    }

    start = bio->bi_iter.bi_sector & (pbs - 1);
    end = (start + max_sectors) & ~(pbs - 1);
    if (end > start)
        return end - start;
    return max_sectors & ~(lbs - 1);
}

/**
 * bvec_split_segs - verify whether or not a bvec should be split in the middle
 * @lim:      [in] queue limits to split based on
 * @bv:       [in] bvec to examine
 * @nsegs:    [in,out] Number of segments in the bio being built. Incremented
 *            by the number of segments from @bv that may be appended to that
 *            bio without exceeding @max_segs
 * @bytes:    [in,out] Number of bytes in the bio being built. Incremented
 *            by the number of bytes from @bv that may be appended to that
 *            bio without exceeding @max_bytes
 * @max_segs: [in] upper bound for *@nsegs
 * @max_bytes: [in] upper bound for *@bytes
 *
 * When splitting a bio, it can happen that a bvec is encountered that is too
 * big to fit in a single segment and hence that it has to be split in the
 * middle. This function verifies whether or not that should happen. The value
 * %true is returned if and only if appending the entire @bv to a bio with
 * *@nsegs segments and *@sectors sectors would make that bio unacceptable for
 * the block driver.
 */
static bool bvec_split_segs(const struct queue_limits *lim,
        const struct bio_vec *bv, unsigned *nsegs, unsigned *bytes,
        unsigned max_segs, unsigned max_bytes)
{
    PANIC("");
}

/**
 * bio_split_rw_at - check if and where to split a read/write bio
 * @bio:  [in] bio to be split
 * @lim:  [in] queue limits to split based on
 * @segs: [out] number of segments in the bio with the first half of the sectors
 * @max_bytes: [in] maximum number of bytes per bio
 *
 * Find out if @bio needs to be split to fit the queue limits in @lim and a
 * maximum size of @max_bytes.  Returns a negative error number if @bio can't be
 * split, 0 if the bio doesn't have to be split, or a positive sector offset if
 * @bio needs to be split.
 */
int bio_split_rw_at(struct bio *bio, const struct queue_limits *lim,
        unsigned *segs, unsigned max_bytes)
{
    struct bio_vec bv, bvprv, *bvprvp = NULL;
    struct bvec_iter iter;
    unsigned nsegs = 0, bytes = 0;

    bio_for_each_bvec(bv, bio, iter) {
        /*
         * If the queue doesn't support SG gaps and adding this
         * offset would create a gap, disallow it.
         */
        if (bvprvp && bvec_gap_to_prev(lim, bvprvp, bv.bv_offset))
            goto split;

        if (nsegs < lim->max_segments &&
            bytes + bv.bv_len <= max_bytes &&
            bv.bv_offset + bv.bv_len <= PAGE_SIZE) {
            nsegs++;
            bytes += bv.bv_len;
        } else {
            if (bvec_split_segs(lim, &bv, &nsegs, &bytes,
                    lim->max_segments, max_bytes))
                goto split;
        }

        bvprv = bv;
        bvprvp = &bvprv;
    }

    *segs = nsegs;
    return 0;
split:
#if 0
    if (bio->bi_opf & REQ_ATOMIC)
        return -EINVAL;

    /*
     * We can't sanely support splitting for a REQ_NOWAIT bio. End it
     * with EAGAIN if splitting is required and return an error pointer.
     */
    if (bio->bi_opf & REQ_NOWAIT)
        return -EAGAIN;

    *segs = nsegs;

    /*
     * Individual bvecs might not be logical block aligned. Round down the
     * split size so that each bio is properly block size aligned, even if
     * we do not use the full hardware limits.
     */
    bytes = ALIGN_DOWN(bytes, bio_split_alignment(bio, lim));

    /*
     * Bio splitting may cause subtle trouble such as hang when doing sync
     * iopoll in direct IO routine. Given performance gain of iopoll for
     * big IO can be trival, disable iopoll when split needed.
     */
    bio_clear_polled(bio);
#endif
    PANIC("split");
    return bytes >> SECTOR_SHIFT;
}

static struct bio *bio_submit_split(struct bio *bio, int split_sectors)
{
    pr_debug("%s: split_sectors(%d)", __func__, split_sectors);
    if (unlikely(split_sectors < 0)) {
        bio->bi_status = errno_to_blk_status(split_sectors);
        bio_endio(bio);
        return NULL;
    }

    if (split_sectors) {
#if 0
        struct bio *split;

        split = bio_split(bio, split_sectors, GFP_NOIO,
                &bio->bi_bdev->bd_disk->bio_split);
        split->bi_opf |= REQ_NOMERGE;
        blkcg_bio_issue_init(split);
        bio_chain(split, bio);
        trace_block_split(split, bio->bi_iter.bi_sector);
        WARN_ON_ONCE(bio_zone_write_plugging(bio));
        submit_bio_noacct(bio);
        return split;
#endif
        PANIC("split_sectors");
    }

    return bio;
}

struct bio *bio_split_rw(struct bio *bio, const struct queue_limits *lim,
        unsigned *nr_segs)
{
    return bio_submit_split(bio,
        bio_split_rw_at(bio, lim, nr_segs,
            get_max_io_size(bio, lim) << SECTOR_SHIFT));
}
