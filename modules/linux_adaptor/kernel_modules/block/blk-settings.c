#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/bio.h>
#include <linux/blk-integrity.h>
#include <linux/pagemap.h>
#include <linux/backing-dev-defs.h>
#include <linux/gcd.h>
#include <linux/lcm.h>
#include <linux/jiffies.h>
#include <linux/gfp.h>
#include <linux/dma-mapping.h>

#include "blk.h"
#include "blk-rq-qos.h"
#include "blk-wbt.h"

void blk_queue_rq_timeout(struct request_queue *q, unsigned int timeout)
{
    q->rq_timeout = timeout;
}

/*
 * Returns max guaranteed bytes which we can fit in a bio.
 *
 * We request that an atomic_write is ITER_UBUF iov_iter (so a single vector),
 * so we assume that we can fit in at least PAGE_SIZE in a segment, apart from
 * the first and last segments.
 */
static unsigned int blk_queue_max_guaranteed_bio(struct queue_limits *lim)
{
    unsigned int max_segments = min(BIO_MAX_VECS, lim->max_segments);
    unsigned int length;

    length = min(max_segments, 2) * lim->logical_block_size;
    if (max_segments > 2)
        length += (max_segments - 2) * PAGE_SIZE;

    return length;
}

static void blk_atomic_writes_update_limits(struct queue_limits *lim)
{
    unsigned int unit_limit = min(lim->max_hw_sectors << SECTOR_SHIFT,
                    blk_queue_max_guaranteed_bio(lim));

    unit_limit = rounddown_pow_of_two(unit_limit);

    lim->atomic_write_max_sectors =
        min(lim->atomic_write_hw_max >> SECTOR_SHIFT,
            lim->max_hw_sectors);
    lim->atomic_write_unit_min =
        min(lim->atomic_write_hw_unit_min, unit_limit);
    lim->atomic_write_unit_max =
        min(lim->atomic_write_hw_unit_max, unit_limit);
    lim->atomic_write_boundary_sectors =
        lim->atomic_write_hw_boundary >> SECTOR_SHIFT;
}

static void blk_validate_atomic_write_limits(struct queue_limits *lim)
{
    unsigned int boundary_sectors;

    if (!lim->atomic_write_hw_max)
        goto unsupported;

    boundary_sectors = lim->atomic_write_hw_boundary >> SECTOR_SHIFT;

    if (boundary_sectors) {
        /*
         * A feature of boundary support is that it disallows bios to
         * be merged which would result in a merged request which
         * crosses either a chunk sector or atomic write HW boundary,
         * even though chunk sectors may be just set for performance.
         * For simplicity, disallow atomic writes for a chunk sector
         * which is non-zero and smaller than atomic write HW boundary.
         * Furthermore, chunk sectors must be a multiple of atomic
         * write HW boundary. Otherwise boundary support becomes
         * complicated.
         * Devices which do not conform to these rules can be dealt
         * with if and when they show up.
         */
        if (WARN_ON_ONCE(lim->chunk_sectors % boundary_sectors))
            goto unsupported;

        /*
         * The boundary size just needs to be a multiple of unit_max
         * (and not necessarily a power-of-2), so this following check
         * could be relaxed in future.
         * Furthermore, if needed, unit_max could even be reduced so
         * that it is compliant with a !power-of-2 boundary.
         */
        if (!is_power_of_2(boundary_sectors))
            goto unsupported;
    }

    blk_atomic_writes_update_limits(lim);
    return;

unsupported:
    lim->atomic_write_max_sectors = 0;
    lim->atomic_write_boundary_sectors = 0;
    lim->atomic_write_unit_min = 0;
    lim->atomic_write_unit_max = 0;
}

static int blk_validate_zoned_limits(struct queue_limits *lim)
{
    if (!(lim->features & BLK_FEAT_ZONED)) {
        if (WARN_ON_ONCE(lim->max_open_zones) ||
            WARN_ON_ONCE(lim->max_active_zones) ||
            WARN_ON_ONCE(lim->zone_write_granularity) ||
            WARN_ON_ONCE(lim->max_zone_append_sectors))
            return -EINVAL;
        return 0;
    }

    if (WARN_ON_ONCE(!IS_ENABLED(CONFIG_BLK_DEV_ZONED)))
        return -EINVAL;

    /*
     * Given that active zones include open zones, the maximum number of
     * open zones cannot be larger than the maximum number of active zones.
     */
    if (lim->max_active_zones &&
        lim->max_open_zones > lim->max_active_zones)
        return -EINVAL;

    if (lim->zone_write_granularity < lim->logical_block_size)
        lim->zone_write_granularity = lim->logical_block_size;

    if (lim->max_zone_append_sectors) {
        /*
         * The Zone Append size is limited by the maximum I/O size
         * and the zone size given that it can't span zones.
         */
        lim->max_zone_append_sectors =
            min3(lim->max_hw_sectors,
                 lim->max_zone_append_sectors,
                 lim->chunk_sectors);
    }

    return 0;
}

static int blk_validate_integrity_limits(struct queue_limits *lim)
{
    struct blk_integrity *bi = &lim->integrity;

    if (!bi->tuple_size) {
        if (bi->csum_type != BLK_INTEGRITY_CSUM_NONE ||
            bi->tag_size || ((bi->flags & BLK_INTEGRITY_REF_TAG))) {
            pr_warn("invalid PI settings.\n");
            return -EINVAL;
        }
        return 0;
    }

    if (lim->features & BLK_FEAT_BOUNCE_HIGH) {
        pr_warn("no bounce buffer support for integrity metadata\n");
        return -EINVAL;
    }

    if (!IS_ENABLED(CONFIG_BLK_DEV_INTEGRITY)) {
        pr_warn("integrity support disabled.\n");
        return -EINVAL;
    }

    if (bi->csum_type == BLK_INTEGRITY_CSUM_NONE &&
        (bi->flags & BLK_INTEGRITY_REF_TAG)) {
        pr_warn("ref tag not support without checksum.\n");
        return -EINVAL;
    }

    if (!bi->interval_exp)
        bi->interval_exp = ilog2(lim->logical_block_size);

    return 0;
}

/*
 * Check that the limits in lim are valid, initialize defaults for unset
 * values, and cap values based on others where needed.
 */
static int blk_validate_limits(struct queue_limits *lim)
{
    unsigned int max_hw_sectors;
    unsigned int logical_block_sectors;
    int err;

    /*
     * Unless otherwise specified, default to 512 byte logical blocks and a
     * physical block size equal to the logical block size.
     */
    if (!lim->logical_block_size)
        lim->logical_block_size = SECTOR_SIZE;
    else if (blk_validate_block_size(lim->logical_block_size)) {
        pr_warn("Invalid logical block size (%d)\n", lim->logical_block_size);
        return -EINVAL;
    }
    if (lim->physical_block_size < lim->logical_block_size)
        lim->physical_block_size = lim->logical_block_size;

    /*
     * The minimum I/O size defaults to the physical block size unless
     * explicitly overridden.
     */
    if (lim->io_min < lim->physical_block_size)
        lim->io_min = lim->physical_block_size;

    /*
     * The optimal I/O size may not be aligned to physical block size
     * (because it may be limited by dma engines which have no clue about
     * block size of the disks attached to them), so we round it down here.
     */
    lim->io_opt = round_down(lim->io_opt, lim->physical_block_size);

    /*
     * max_hw_sectors has a somewhat weird default for historical reason,
     * but driver really should set their own instead of relying on this
     * value.
     *
     * The block layer relies on the fact that every driver can
     * handle at lest a page worth of data per I/O, and needs the value
     * aligned to the logical block size.
     */
    if (!lim->max_hw_sectors)
        lim->max_hw_sectors = BLK_SAFE_MAX_SECTORS;
    printk("%s: step1 max_hw_sectors(0x%x)\n", __func__, lim->max_hw_sectors);
    if (WARN_ON_ONCE(lim->max_hw_sectors < PAGE_SECTORS))
        return -EINVAL;
    logical_block_sectors = lim->logical_block_size >> SECTOR_SHIFT;
    if (WARN_ON_ONCE(logical_block_sectors > lim->max_hw_sectors))
        return -EINVAL;
    lim->max_hw_sectors = round_down(lim->max_hw_sectors,
            logical_block_sectors);
    printk("%s: step2 max_hw_sectors(0x%x)\n", __func__, lim->max_hw_sectors);

    /*
     * The actual max_sectors value is a complex beast and also takes the
     * max_dev_sectors value (set by SCSI ULPs) and a user configurable
     * value into account.  The ->max_sectors value is always calculated
     * from these, so directly setting it won't have any effect.
     */
    max_hw_sectors = min_not_zero(lim->max_hw_sectors,
                lim->max_dev_sectors);
    if (lim->max_user_sectors) {
        if (lim->max_user_sectors < PAGE_SIZE / SECTOR_SIZE)
            return -EINVAL;
        lim->max_sectors = min(max_hw_sectors, lim->max_user_sectors);
    } else if (lim->io_opt > (BLK_DEF_MAX_SECTORS_CAP << SECTOR_SHIFT)) {
        lim->max_sectors =
            min(max_hw_sectors, lim->io_opt >> SECTOR_SHIFT);
    } else if (lim->io_min > (BLK_DEF_MAX_SECTORS_CAP << SECTOR_SHIFT)) {
        lim->max_sectors =
            min(max_hw_sectors, lim->io_min >> SECTOR_SHIFT);
    } else {
        lim->max_sectors = min(max_hw_sectors, BLK_DEF_MAX_SECTORS_CAP);
    }
    lim->max_sectors = round_down(lim->max_sectors,
            logical_block_sectors);

    /*
     * Random default for the maximum number of segments.  Driver should not
     * rely on this and set their own.
     */
    if (!lim->max_segments)
        lim->max_segments = BLK_MAX_SEGMENTS;

    lim->max_discard_sectors =
        min(lim->max_hw_discard_sectors, lim->max_user_discard_sectors);

    if (!lim->max_discard_segments)
        lim->max_discard_segments = 1;

    if (lim->discard_granularity < lim->physical_block_size)
        lim->discard_granularity = lim->physical_block_size;

    /*
     * By default there is no limit on the segment boundary alignment,
     * but if there is one it can't be smaller than the page size as
     * that would break all the normal I/O patterns.
     */
    if (!lim->seg_boundary_mask)
        lim->seg_boundary_mask = BLK_SEG_BOUNDARY_MASK;
    if (WARN_ON_ONCE(lim->seg_boundary_mask < PAGE_SIZE - 1))
        return -EINVAL;

    /*
     * Stacking device may have both virtual boundary and max segment
     * size limit, so allow this setting now, and long-term the two
     * might need to move out of stacking limits since we have immutable
     * bvec and lower layer bio splitting is supposed to handle the two
     * correctly.
     */
    if (lim->virt_boundary_mask) {
        if (!lim->max_segment_size)
            lim->max_segment_size = UINT_MAX;
    } else {
        /*
         * The maximum segment size has an odd historic 64k default that
         * drivers probably should override.  Just like the I/O size we
         * require drivers to at least handle a full page per segment.
         */
        if (!lim->max_segment_size)
            lim->max_segment_size = BLK_MAX_SEGMENT_SIZE;
        if (WARN_ON_ONCE(lim->max_segment_size < PAGE_SIZE))
            return -EINVAL;
    }

    /*
     * We require drivers to at least do logical block aligned I/O, but
     * historically could not check for that due to the separate calls
     * to set the limits.  Once the transition is finished the check
     * below should be narrowed down to check the logical block size.
     */
    if (!lim->dma_alignment)
        lim->dma_alignment = SECTOR_SIZE - 1;
    if (WARN_ON_ONCE(lim->dma_alignment > PAGE_SIZE))
        return -EINVAL;

    if (lim->alignment_offset) {
        lim->alignment_offset &= (lim->physical_block_size - 1);
        lim->flags &= ~BLK_FLAG_MISALIGNED;
    }

    if (!(lim->features & BLK_FEAT_WRITE_CACHE))
        lim->features &= ~BLK_FEAT_FUA;

    blk_validate_atomic_write_limits(lim);

    err = blk_validate_integrity_limits(lim);
    if (err)
        return err;
    return blk_validate_zoned_limits(lim);
}

/*
 * Set the default limits for a newly allocated queue.  @lim contains the
 * initial limits set by the driver, which could be no limit in which case
 * all fields are cleared to zero.
 */
int blk_set_default_limits(struct queue_limits *lim)
{
    /*
     * Most defaults are set by capping the bounds in blk_validate_limits,
     * but max_user_discard_sectors is special and needs an explicit
     * initialization to the max value here.
     */
    lim->max_user_discard_sectors = UINT_MAX;
    return blk_validate_limits(lim);
}

void blk_apply_bdi_limits(struct backing_dev_info *bdi,
        struct queue_limits *lim)
{
    /*
     * For read-ahead of large files to be effective, we need to read ahead
     * at least twice the optimal I/O size.
     *
     * There is no hardware limitation for the read-ahead size and the user
     * might have increased the read-ahead size through sysfs, so don't ever
     * decrease it.
     */
    bdi->ra_pages = max3(bdi->ra_pages,
                lim->io_opt * 2 / PAGE_SIZE,
                VM_READAHEAD_PAGES);
    bdi->io_pages = lim->max_sectors >> PAGE_SECTORS_SHIFT;
}

/**
 * blk_set_stacking_limits - set default limits for stacking devices
 * @lim:  the queue_limits structure to reset
 *
 * Prepare queue limits for applying limits from underlying devices using
 * blk_stack_limits().
 */
void blk_set_stacking_limits(struct queue_limits *lim)
{
    memset(lim, 0, sizeof(*lim));
    lim->logical_block_size = SECTOR_SIZE;
    lim->physical_block_size = SECTOR_SIZE;
    lim->io_min = SECTOR_SIZE;
    lim->discard_granularity = SECTOR_SIZE;
    lim->dma_alignment = SECTOR_SIZE - 1;
    lim->seg_boundary_mask = BLK_SEG_BOUNDARY_MASK;

    /* Inherit limits from component devices */
    lim->max_segments = USHRT_MAX;
    lim->max_discard_segments = USHRT_MAX;
    lim->max_hw_sectors = UINT_MAX;
    lim->max_segment_size = UINT_MAX;
    lim->max_sectors = UINT_MAX;
    lim->max_dev_sectors = UINT_MAX;
    lim->max_write_zeroes_sectors = UINT_MAX;
    lim->max_zone_append_sectors = UINT_MAX;
    lim->max_user_discard_sectors = UINT_MAX;
}

/**
 * queue_limits_commit_update - commit an atomic update of queue limits
 * @q:      queue to update
 * @lim:    limits to apply
 *
 * Apply the limits in @lim that were obtained from queue_limits_start_update()
 * and updated by the caller to @q.
 *
 * Returns 0 if successful, else a negative error code.
 */
int queue_limits_commit_update(struct request_queue *q,
        struct queue_limits *lim)
{
    int error;

    error = blk_validate_limits(lim);
    if (error)
        goto out_unlock;

#ifdef CONFIG_BLK_INLINE_ENCRYPTION
    if (q->crypto_profile && lim->integrity.tag_size) {
        pr_warn("blk-integrity: Integrity and hardware inline encryption are not supported together.\n");
        error = -EINVAL;
        goto out_unlock;
    }
#endif

    q->limits = *lim;
    if (q->disk)
        blk_apply_bdi_limits(q->disk->bdi, lim);
out_unlock:
    mutex_unlock(&q->limits_lock);
    return error;
}
