#include <linux/fs.h>
#include "booter.h"

extern int cl_read_block(int blk_nr, void *rbuf, int count);

void *kmalloc(size_t size, gfp_t flags);

struct dentry *mount_bdev(struct file_system_type *fs_type,
    int flags, const char *dev_name, void *data,
    int (*fill_super)(struct super_block *, void *, int))
{
    if (fill_super == NULL) {
        booter_panic("No ext2 fill_super!");
    }

    struct super_block *s;
    s = kmalloc(sizeof(struct super_block), 0);
    s->s_blocksize = 1024;
    if (fill_super(s, NULL, 0) != 0) {
        booter_panic("ext2 fill_super error!");
    }

    return s->s_root;
}

struct inode *iget_locked(struct super_block *sb, unsigned long ino)
{
    const struct super_operations *ops = sb->s_op;

    struct inode *inode;
    if (ops->alloc_inode == NULL) {
        booter_panic("no ext2 alloc_inode!");
    }
    inode = ops->alloc_inode(sb);
    inode->i_ino = ino;
    inode->i_state = I_NEW;
    inode->i_sb = sb;

    struct address_space *const mapping = &inode->i_data;
    mapping->host = inode;
    mapping->flags = 0;
    mapping->wb_err = 0;
    atomic_set(&mapping->i_mmap_writable, 0);
    mapping->private_data = NULL;
    mapping->writeback_index = 0;
    inode->i_private = NULL;
    inode->i_mapping = mapping;

    return inode;
}

void unlock_new_inode(struct inode *inode)
{
    inode->i_state &= ~I_NEW & ~I_CREATING;
}

void set_nlink(struct inode *inode, unsigned int nlink)
{
    if (!nlink) {
        clear_nlink(inode);
    } else {
        /* Yes, some filesystems do change nlink from zero to one */
        if (inode->i_nlink == 0)
            atomic_long_dec(&inode->i_sb->s_remove_count);

        inode->__i_nlink = nlink;
    }
}

void clear_nlink(struct inode *inode)
{
    if (inode->i_nlink) {
        inode->__i_nlink = 0;
        atomic_long_inc(&inode->i_sb->s_remove_count);
    }
}

struct ext2_dir_entry {
    int     inode;          /* Inode number */
    short   rec_len;        /* Directory entry length */
    short   name_len;       /* Name length */
    char    name[];         /* File name, up to EXT2_NAME_LEN */
};

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

    char buf[256];
    cl_read_block(8248, buf, sizeof(buf));

    struct ext2_dir_entry *dentry = (struct ext2_dir_entry *)buf;

    printk("Got root dentries: dentry name(%s), inr(%u), rec_len(%u), name_len(%u)\n",
           dentry->name, dentry->inode, dentry->rec_len, dentry->name_len);
    booter_panic("");
}
