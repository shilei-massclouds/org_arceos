#include <linux/module.h>
#include <linux/compiler.h>
#include <linux/fs.h>
#include <linux/iomap.h>
#include <linux/fiemap.h>
#include <linux/pagemap.h>

/* legacy ->bmap interface.  0 is the error return (!) */
sector_t
iomap_bmap(struct address_space *mapping, sector_t bno,
        const struct iomap_ops *ops)
{
    struct iomap_iter iter = {
        .inode  = mapping->host,
        .pos    = (loff_t)bno << mapping->host->i_blkbits,
        .len    = i_blocksize(mapping->host),
        .flags  = IOMAP_REPORT,
    };
    const unsigned int blkshift = mapping->host->i_blkbits - SECTOR_SHIFT;
    int ret;

    if (filemap_write_and_wait(mapping))
        return 0;

    bno = 0;
    while ((ret = iomap_iter(&iter, ops)) > 0) {
        if (iter.iomap.type == IOMAP_MAPPED)
            bno = iomap_sector(&iter.iomap, iter.pos) >> blkshift;
        /* leave iter.processed unset to abort loop */
    }
    if (ret)
        return 0;

    return bno;
}
