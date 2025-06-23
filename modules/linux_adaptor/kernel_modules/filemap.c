#include <linux/fs.h>

#include "ext2/ext2.h"
#include "booter.h"

struct page *read_cache_page(struct address_space *mapping,
                pgoff_t index,
                int (*filler)(void *, struct page *),
                void *data)
{
    printk("%s: mapping (%lx) index(%d) data(%x)\n",
                 __func__, mapping, index, data);

    // Root inode -> block at sector[8248]
    /*
    void *buf = kmalloc(256, 0);
    cl_read_block(8248, buf, 256);
    return buf;
    */
    log_error("%s: Get real blknr for 8248. \n", __func__);

    char buf[256];
    cl_read_block(8248, buf, sizeof(buf));

    struct ext2_dir_entry *dentry = (struct ext2_dir_entry *)buf;

    printk("Got root dentries: dentry name(%s), inr(%u), rec_len(%u), name_len(%u)\n",
           dentry->name, dentry->inode, dentry->rec_len, dentry->name_len);
    booter_panic("");
}
