#include <linux/fs.h>

/*
 * fs on-disk file type to dirent file type conversion
 */
static const unsigned char fs_dtype_by_ftype[FT_MAX] = {
    [FT_UNKNOWN]    = DT_UNKNOWN,
    [FT_REG_FILE]   = DT_REG,
    [FT_DIR]    = DT_DIR,
    [FT_CHRDEV] = DT_CHR,
    [FT_BLKDEV] = DT_BLK,
    [FT_FIFO]   = DT_FIFO,
    [FT_SOCK]   = DT_SOCK,
    [FT_SYMLINK]    = DT_LNK
};

/**
 * fs_ftype_to_dtype() - fs on-disk file type to dirent type.
 * @filetype: The on-disk file type to convert.
 *
 * This function converts the on-disk file type value (FT_*) to the directory
 * entry type (DT_*).
 *
 * Context: Any context.
 * Return:
 * * DT_UNKNOWN     - Unknown type
 * * DT_FIFO        - FIFO
 * * DT_CHR     - Character device
 * * DT_DIR     - Directory
 * * DT_BLK     - Block device
 * * DT_REG     - Regular file
 * * DT_LNK     - Symbolic link
 * * DT_SOCK        - Local-domain socket
 */
unsigned char fs_ftype_to_dtype(unsigned int filetype)
{
    if (filetype >= FT_MAX)
        return DT_UNKNOWN;

    return fs_dtype_by_ftype[filetype];
}
EXPORT_SYMBOL_GPL(fs_ftype_to_dtype);
