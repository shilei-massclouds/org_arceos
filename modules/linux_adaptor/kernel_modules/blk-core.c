#include <linux/blk_types.h>

static const struct {
    int     errno;
    const char  *name;
} blk_errors[] = {
    [BLK_STS_OK]        = { 0,      "" },
    [BLK_STS_NOTSUPP]   = { -EOPNOTSUPP, "operation not supported" },
    [BLK_STS_TIMEOUT]   = { -ETIMEDOUT, "timeout" },
    [BLK_STS_NOSPC]     = { -ENOSPC,    "critical space allocation" },
    [BLK_STS_TRANSPORT] = { -ENOLINK,   "recoverable transport" },
    [BLK_STS_TARGET]    = { -EREMOTEIO, "critical target" },
    [BLK_STS_NEXUS]     = { -EBADE, "critical nexus" },
    [BLK_STS_MEDIUM]    = { -ENODATA,   "critical medium" },
    [BLK_STS_PROTECTION]    = { -EILSEQ,    "protection" },
    [BLK_STS_RESOURCE]  = { -ENOMEM,    "kernel resource" },
    [BLK_STS_DEV_RESOURCE]  = { -EBUSY, "device resource" },
    [BLK_STS_AGAIN]     = { -EAGAIN,    "nonblocking retry" },

    /* device mapper special case, should not leak out: */
    [BLK_STS_DM_REQUEUE]    = { -EREMCHG, "dm internal retry" },

    /* everything else not covered above: */
    [BLK_STS_IOERR]     = { -EIO,   "I/O" },
};

int blk_status_to_errno(blk_status_t status)
{
    int idx = (__force int)status;

    if (WARN_ON_ONCE(idx >= ARRAY_SIZE(blk_errors)))
        return -EIO;
    return blk_errors[idx].errno;
}
