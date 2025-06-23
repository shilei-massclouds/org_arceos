#include <linux/fs.h>

#include "booter.h"

void mark_buffer_dirty(struct buffer_head *bh)
{
    log_error("%s: No impl.\n", __func__);
}

int sync_dirty_buffer(struct buffer_head *bh, int op_flags)
{
    log_error("%s: No impl.\n", __func__);
}
