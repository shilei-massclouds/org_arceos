#include <linux/blkdev.h>
#include <linux/export.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/highuid.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/cred.h>
#include <linux/syscalls.h>
#include <linux/pagemap.h>
#include <linux/compat.h>
#include <linux/iversion.h>

#include <linux/uaccess.h>
#include <asm/unistd.h>

#include "internal.h"
#include "mount.h"

/* Caller is here responsible for sufficient locking (ie. inode->i_lock) */
void __inode_add_bytes(struct inode *inode, loff_t bytes)
{
    inode->i_blocks += bytes >> 9;
    bytes &= 511;
    inode->i_bytes += bytes;
    if (inode->i_bytes >= 512) {
        inode->i_blocks++;
        inode->i_bytes -= 512;
    }
}
EXPORT_SYMBOL(__inode_add_bytes);

void inode_add_bytes(struct inode *inode, loff_t bytes)
{
    spin_lock(&inode->i_lock);
    __inode_add_bytes(inode, bytes);
    spin_unlock(&inode->i_lock);
}

void __inode_sub_bytes(struct inode *inode, loff_t bytes)
{
    inode->i_blocks -= bytes >> 9;
    bytes &= 511;
    if (inode->i_bytes < bytes) {
        inode->i_blocks--;
        inode->i_bytes += 512;
    }
    inode->i_bytes -= bytes;
}

void inode_sub_bytes(struct inode *inode, loff_t bytes)
{
    spin_lock(&inode->i_lock);
    __inode_sub_bytes(inode, bytes);
    spin_unlock(&inode->i_lock);
}
