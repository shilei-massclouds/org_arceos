#include <linux/fs.h>
#include <linux/iomap.h>
#include <linux/fiemap.h>

struct fiemap_ctx {
    struct fiemap_extent_info *fi;
    struct iomap prev;
};

static int iomap_to_fiemap(struct fiemap_extent_info *fi,
        struct iomap *iomap, u32 flags)
{
    switch (iomap->type) {
    case IOMAP_HOLE:
        /* skip holes */
        return 0;
    case IOMAP_DELALLOC:
        flags |= FIEMAP_EXTENT_DELALLOC | FIEMAP_EXTENT_UNKNOWN;
        break;
    case IOMAP_MAPPED:
        break;
    case IOMAP_UNWRITTEN:
        flags |= FIEMAP_EXTENT_UNWRITTEN;
        break;
    case IOMAP_INLINE:
        flags |= FIEMAP_EXTENT_DATA_INLINE;
        break;
    }

    if (iomap->flags & IOMAP_F_MERGED)
        flags |= FIEMAP_EXTENT_MERGED;
    if (iomap->flags & IOMAP_F_SHARED)
        flags |= FIEMAP_EXTENT_SHARED;

    return fiemap_fill_next_extent(fi, iomap->offset,
            iomap->addr != IOMAP_NULL_ADDR ? iomap->addr : 0,
            iomap->length, flags);
}

static loff_t
iomap_fiemap_actor(struct inode *inode, loff_t pos, loff_t length, void *data,
        struct iomap *iomap, struct iomap *srcmap)
{
    struct fiemap_ctx *ctx = data;
    loff_t ret = length;

    if (iomap->type == IOMAP_HOLE)
        return length;

    ret = iomap_to_fiemap(ctx->fi, &ctx->prev, 0);
    ctx->prev = *iomap;
    switch (ret) {
    case 0:     /* success */
        return length;
    case 1:     /* extent array full */
        return 0;
    default:
        return ret;
    }
}

static loff_t
iomap_bmap_actor(struct inode *inode, loff_t pos, loff_t length,
        void *data, struct iomap *iomap, struct iomap *srcmap)
{
    sector_t *bno = data, addr;

    if (iomap->type == IOMAP_MAPPED) {
        addr = (pos - iomap->offset + iomap->addr) >> inode->i_blkbits;
        *bno = addr;
    }
    return 0;
}

/*
 * Execute a iomap write on a segment of the mapping that spans a
 * contiguous range of pages that have identical block mapping state.
 *
 * This avoids the need to map pages individually, do individual allocations
 * for each page and most importantly avoid the need for filesystem specific
 * locking per page. Instead, all the operations are amortised over the entire
 * range of pages. It is assumed that the filesystems will lock whatever
 * resources they require in the iomap_begin call, and release them in the
 * iomap_end call.
 */
loff_t
iomap_apply(struct inode *inode, loff_t pos, loff_t length, unsigned flags,
		const struct iomap_ops *ops, void *data, iomap_actor_t actor)
{
	struct iomap iomap = { .type = IOMAP_HOLE };
	struct iomap srcmap = { .type = IOMAP_HOLE };
	loff_t written = 0, ret;
	u64 end;

	//trace_iomap_apply(inode, pos, length, flags, ops, actor, _RET_IP_);

	/*
	 * Need to map a range from start position for length bytes. This can
	 * span multiple pages - it is only guaranteed to return a range of a
	 * single type of pages (e.g. all into a hole, all mapped or all
	 * unwritten). Failure at this point has nothing to undo.
	 *
	 * If allocation is required for this range, reserve the space now so
	 * that the allocation is guaranteed to succeed later on. Once we copy
	 * the data into the page cache pages, then we cannot fail otherwise we
	 * expose transient stale data. If the reserve fails, we can safely
	 * back out at this point as there is nothing to undo.
	 */
	ret = ops->iomap_begin(inode, pos, length, flags, &iomap, &srcmap);
	if (ret)
		return ret;
	if (WARN_ON(iomap.offset > pos)) {
		written = -EIO;
		goto out;
	}
	if (WARN_ON(iomap.length == 0)) {
		written = -EIO;
		goto out;
	}

	//trace_iomap_apply_dstmap(inode, &iomap);
	//if (srcmap.type != IOMAP_HOLE)
		//trace_iomap_apply_srcmap(inode, &srcmap);

	/*
	 * Cut down the length to the one actually provided by the filesystem,
	 * as it might not be able to give us the whole size that we requested.
	 */
	end = iomap.offset + iomap.length;
	if (srcmap.type != IOMAP_HOLE)
		end = min(end, srcmap.offset + srcmap.length);
	if (pos + length > end)
		length = end - pos;

	/*
	 * Now that we have guaranteed that the space allocation will succeed,
	 * we can do the copy-in page by page without having to worry about
	 * failures exposing transient data.
	 *
	 * To support COW operations, we read in data for partially blocks from
	 * the srcmap if the file system filled it in.  In that case we the
	 * length needs to be limited to the earlier of the ends of the iomaps.
	 * If the file system did not provide a srcmap we pass in the normal
	 * iomap into the actors so that they don't need to have special
	 * handling for the two cases.
	 */
	written = actor(inode, pos, length, data, &iomap,
			srcmap.type != IOMAP_HOLE ? &srcmap : &iomap);

out:
	/*
	 * Now the data has been copied, commit the range we've copied.  This
	 * should not fail unless the filesystem has had a fatal error.
	 */
	if (ops->iomap_end) {
		ret = ops->iomap_end(inode, pos, length,
				     written > 0 ? written : 0,
				     flags, &iomap);
	}

	return written ? written : ret;
}

/* legacy ->bmap interface.  0 is the error return (!) */
sector_t
iomap_bmap(struct address_space *mapping, sector_t bno,
        const struct iomap_ops *ops)
{
    struct inode *inode = mapping->host;
    loff_t pos = bno << inode->i_blkbits;
    unsigned blocksize = i_blocksize(inode);
    int ret;

    if (filemap_write_and_wait(mapping))
        return 0;

    bno = 0;
    ret = iomap_apply(inode, pos, blocksize, 0, ops, &bno,
              iomap_bmap_actor);
    if (ret)
        return 0;
    return bno;
}
