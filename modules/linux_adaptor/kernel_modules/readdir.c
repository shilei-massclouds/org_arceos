#include <linux/fs.h>
#include <linux/string.h>

#include "booter.h"

struct lookup_callback {
    struct dir_context ctx;
    const char *target;
    u64 *ret_ino;
};

static int filter(struct dir_context *ctx,
                   const char *name, int namlen,
                   loff_t offset, u64 ino,
                   unsigned int d_type)
{
    struct lookup_callback *buf =
        container_of(ctx, struct lookup_callback, ctx);

    log_debug("%s: name %s(%d) offset(%lx) ino %u dtype %u\n",
           __func__, name, namlen, offset, ino, d_type);

    if (strncmp(name, buf->target, namlen) == 0) {
        *(buf->ret_ino) = ino;
    }
    return 0;
}

int lookup(struct file *dir, const char *target, u64 *ret_ino)
{
    struct lookup_callback buf = {
        .ctx.actor = filter,
        .target = target,
        .ret_ino = ret_ino
    };

    const struct file_operations *dop = dir->f_inode->i_fop;
    if (dop == NULL) {
        booter_panic("ext2 root inode has no fop!");
    }

    if ((*dop->iterate_shared)(dir, &buf.ctx) != 0) {
        booter_panic("ext2 root iterate error!");
    }
    return 0;
}
