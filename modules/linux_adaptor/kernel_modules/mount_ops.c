#include <linux/fs_context.h>
#include <linux/fs.h>
#include <linux/mount.h>

#include "fs/mount.h"
#include "fs/internal.h"

#include "adaptor.h"

void cl_mount(const char *fstype, const char *source)
{
    struct fs_context *fc;
    struct file_system_type *type;
    int err = 0;

    type = get_fs_type(fstype);
    if (type == NULL) {
        PANIC("No filesystem type.");
    }

    fc = fs_context_for_mount(type, SB_SILENT);
    put_filesystem(type);
    if (IS_ERR(fc)) {
        PANIC("Bad fs context.");
    }

    if (source) {
        err = vfs_parse_fs_string(fc, "source", source, strlen(source));
        if (err) {
            PANIC("Bad fs context params 'source'.");
        }
    }

    err = vfs_get_tree(fc);
    if (err) {
        PANIC("get tree error.");
    }
    printk("%s: Mount filesystem on block ok!\n", __func__);
}
