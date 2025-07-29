#include <linux/init.h>
#include <linux/mm.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/mpage.h>
#include <linux/uio.h>
#include <linux/namei.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/falloc.h>
#include <linux/suspend.h>
#include <linux/fs.h>
#include <linux/iomap.h>
#include <linux/module.h>
#include <linux/io_uring/cmd.h>
#include "blk.h"

#include "../adaptor.h"

struct blkdev_dio {
    union {
        struct kiocb        *iocb;
        struct task_struct  *waiter;
    };
    size_t          size;
    atomic_t        ref;
    unsigned int        flags;
    struct bio      bio ____cacheline_aligned_in_smp;
};

static struct bio_set blkdev_dio_pool;

static int blkdev_get_block(struct inode *inode, sector_t iblock,
		struct buffer_head *bh, int create)
{
	bh->b_bdev = I_BDEV(inode);
	bh->b_blocknr = iblock;
	set_buffer_mapped(bh);
	return 0;
}

/*
 * We cannot call mpage_writepages() as it does not take the buffer lock.
 * We must use block_write_full_folio() directly which holds the buffer
 * lock.  The buffer lock provides the synchronisation with writeback
 * that filesystems rely on when they use the blockdev's mapping.
 */
static int blkdev_writepages(struct address_space *mapping,
		struct writeback_control *wbc)
{
	struct blk_plug plug;
	int err;

	blk_start_plug(&plug);
	err = write_cache_pages(mapping, wbc, block_write_full_folio,
			blkdev_get_block);
	blk_finish_plug(&plug);

	return err;
}

static int blkdev_read_folio(struct file *file, struct folio *folio)
{
	return block_read_full_folio(folio, blkdev_get_block);
}

static void blkdev_readahead(struct readahead_control *rac)
{
	mpage_readahead(rac, blkdev_get_block);
}

static int blkdev_write_begin(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned len, struct folio **foliop, void **fsdata)
{
	return block_write_begin(mapping, pos, len, foliop, blkdev_get_block);
}

static int blkdev_write_end(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned len, unsigned copied, struct folio *folio,
		void *fsdata)
{
	int ret;
	ret = block_write_end(file, mapping, pos, len, copied, folio, fsdata);

	folio_unlock(folio);
	folio_put(folio);

	return ret;
}

const struct address_space_operations def_blk_aops = {
	.dirty_folio	= block_dirty_folio,
	.invalidate_folio = block_invalidate_folio,
	.read_folio	= blkdev_read_folio,
	.readahead	= blkdev_readahead,
	.writepages	= blkdev_writepages,
	.write_begin	= blkdev_write_begin,
	.write_end	= blkdev_write_end,
	.migrate_folio	= buffer_migrate_folio_norefs,
	.is_dirty_writeback = buffer_check_dirty_writeback,
};

static int blkdev_open(struct inode *inode, struct file *filp)
{
    PANIC("");
}

static int blkdev_release(struct inode *inode, struct file *filp)
{
    PANIC("");
}

/*
 * for a block special file file_inode(file)->i_size is zero
 * so we compute the size by hand (just as in block_read/write above)
 */
static loff_t blkdev_llseek(struct file *file, loff_t offset, int whence)
{
    PANIC("");
}

static ssize_t blkdev_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
    PANIC("");
}

/*
 * Write data to the block device.  Only intended for the block device itself
 * and the raw driver which basically is a fake block device.
 *
 * Does not take i_mutex for the write and thus is not for general purpose
 * use.
 */
static ssize_t blkdev_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
    PANIC("");
}

static int blkdev_mmap(struct file *file, struct vm_area_struct *vma)
{
    PANIC("");
}

static int blkdev_fsync(struct file *filp, loff_t start, loff_t end,
        int datasync)
{
    PANIC("");
}

static long blkdev_fallocate(struct file *file, int mode, loff_t start,
                 loff_t len)
{
    PANIC("");
}

const struct file_operations def_blk_fops = {
    .open       = blkdev_open,
    .release    = blkdev_release,
    .llseek     = blkdev_llseek,
    .read_iter  = blkdev_read_iter,
    .write_iter = blkdev_write_iter,
    .iopoll     = iocb_bio_iopoll,
    .mmap       = blkdev_mmap,
    .fsync      = blkdev_fsync,
    .unlocked_ioctl = blkdev_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl   = compat_blkdev_ioctl,
#endif
    .splice_read    = filemap_splice_read,
    .splice_write   = iter_file_splice_write,
    .fallocate  = blkdev_fallocate,
    .uring_cmd  = blkdev_uring_cmd,
    .fop_flags  = FOP_BUFFER_RASYNC,
};

static __init int blkdev_init(void)
{
    return bioset_init(&blkdev_dio_pool, 4,
                offsetof(struct blkdev_dio, bio),
                BIOSET_NEED_BVECS|BIOSET_PERCPU_CACHE);
}
module_init(blkdev_init);

void cl_blkdev_init(void)
{
    blkdev_init();
}
