#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/bio-integrity.h>
#include <linux/blkdev.h>
#include <linux/uio.h>
#include <linux/iocontext.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/mempool.h>
#include <linux/workqueue.h>
#include <linux/cgroup.h>
#include <linux/highmem.h>
#include <linux/blk-crypto.h>
#include <linux/xarray.h>

#include <trace/events/block.h>
#include "blk.h"
#include "blk-rq-qos.h"
#include "blk-cgroup.h"

/**
 * bioset_init - Initialize a bio_set
 * @bs:     pool to initialize
 * @pool_size:  Number of bio and bio_vecs to cache in the mempool
 * @front_pad:  Number of bytes to allocate in front of the returned bio
 * @flags:  Flags to modify behavior, currently %BIOSET_NEED_BVECS
 *              and %BIOSET_NEED_RESCUER
 *
 * Description:
 *    Set up a bio_set to be used with @bio_alloc_bioset. Allows the caller
 *    to ask for a number of bytes to be allocated in front of the bio.
 *    Front pad allocation is useful for embedding the bio inside
 *    another structure, to avoid allocating extra data to go with the bio.
 *    Note that the bio must be embedded at the END of that structure always,
 *    or things will break badly.
 *    If %BIOSET_NEED_BVECS is set in @flags, a separate pool will be allocated
 *    for allocating iovecs.  This pool is not needed e.g. for bio_init_clone().
 *    If %BIOSET_NEED_RESCUER is set, a workqueue is created which can be used
 *    to dispatch queued requests when the mempool runs out of space.
 *
 */
int bioset_init(struct bio_set *bs,
        unsigned int pool_size,
        unsigned int front_pad,
        int flags)
{
    pr_err("%s: No impl.", __func__);
    return 0;
}
