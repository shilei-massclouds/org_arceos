#include <linux/blkdev.h>
#include <linux/ctype.h>

#include "../adaptor.h"

/**
 * devt_from_partuuid - looks up the dev_t of a partition by its UUID
 * @uuid_str:   char array containing ascii UUID
 * @devt:   dev_t result
 *
 * The function will return the first partition which contains a matching
 * UUID value in its partition_meta_info struct.  This does not search
 * by filesystem UUIDs.
 *
 * If @uuid_str is followed by a "/PARTNROFF=%d", then the number will be
 * extracted and used as an offset from the partition identified by the UUID.
 *
 * Returns 0 on success or a negative error code on failure.
 */
static int __init devt_from_partuuid(const char *uuid_str, dev_t *devt)
{
    PANIC("");
}

static int __init devt_from_partlabel(const char *label, dev_t *devt)
{
    PANIC("");
}

extern int cl_lookup_devt(const char *name);

static dev_t __init blk_lookup_devt(const char *name, int partno)
{
    dev_t devt = MKDEV(0, 0);
    struct class_dev_iter iter;
    struct device *dev;

    printk("%s: [%s]\n", __func__, name);
#if 0
    class_dev_iter_init(&iter, &block_class, NULL, &disk_type);
    while ((dev = class_dev_iter_next(&iter))) {
        struct gendisk *disk = dev_to_disk(dev);

        if (strcmp(dev_name(dev), name))
            continue;

        if (partno < disk->minors) {
            /* We need to return the right devno, even
             * if the partition doesn't exist yet.
             */
            devt = MKDEV(MAJOR(dev->devt),
                     MINOR(dev->devt) + partno);
        } else {
            devt = part_devt(disk, partno);
            if (devt)
                break;
        }
    }
    class_dev_iter_exit(&iter);
    return devt;
#endif
    pr_notice("%s: No impl. Simple method.\n", __func__);
    return cl_lookup_devt(name);
}

static int __init devt_from_devnum(const char *name, dev_t *devt)
{
    unsigned maj, min, offset;
    char *p, dummy;

    if (sscanf(name, "%u:%u%c", &maj, &min, &dummy) == 2 ||
        sscanf(name, "%u:%u:%u:%c", &maj, &min, &offset, &dummy) == 3) {
        *devt = MKDEV(maj, min);
        if (maj != MAJOR(*devt) || min != MINOR(*devt))
            return -EINVAL;
    } else {
        *devt = new_decode_dev(simple_strtoul(name, &p, 16));
        if (*p)
            return -EINVAL;
    }

    return 0;
}

static int __init devt_from_devname(const char *name, dev_t *devt)
{
    int part;
    char s[32];
    char *p;

    if (strlen(name) > 31)
        return -EINVAL;
    strcpy(s, name);
    for (p = s; *p; p++) {
        if (*p == '/')
            *p = '!';
    }

    *devt = blk_lookup_devt(s, 0);
    if (*devt)
        return 0;

    /*
     * Try non-existent, but valid partition, which may only exist after
     * opening the device, like partitioned md devices.
     */
    while (p > s && isdigit(p[-1]))
        p--;
    if (p == s || !*p || *p == '0')
        return -ENODEV;

    /* try disk name without <part number> */
    part = simple_strtoul(p, NULL, 10);
    *p = '\0';
    *devt = blk_lookup_devt(s, part);
    if (*devt)
        return 0;

    /* try disk name without p<part number> */
    if (p < s + 2 || !isdigit(p[-2]) || p[-1] != 'p')
        return -ENODEV;
    p[-1] = '\0';
    *devt = blk_lookup_devt(s, part);
    if (*devt)
        return 0;
    return -ENODEV;
}

/*
 *  Convert a name into device number.  We accept the following variants:
 *
 *  1) <hex_major><hex_minor> device number in hexadecimal represents itself
 *         no leading 0x, for example b302.
 *  3) /dev/<disk_name> represents the device number of disk
 *  4) /dev/<disk_name><decimal> represents the device number
 *         of partition - device number of disk plus the partition number
 *  5) /dev/<disk_name>p<decimal> - same as the above, that form is
 *     used when disk name of partitioned disk ends on a digit.
 *  6) PARTUUID=00112233-4455-6677-8899-AABBCCDDEEFF representing the
 *     unique id of a partition if the partition table provides it.
 *     The UUID may be either an EFI/GPT UUID, or refer to an MSDOS
 *     partition using the format SSSSSSSS-PP, where SSSSSSSS is a zero-
 *     filled hex representation of the 32-bit "NT disk signature", and PP
 *     is a zero-filled hex representation of the 1-based partition number.
 *  7) PARTUUID=<UUID>/PARTNROFF=<int> to select a partition in relation to
 *     a partition with a known unique id.
 *  8) <major>:<minor> major and minor number of the device separated by
 *     a colon.
 *  9) PARTLABEL=<name> with name being the GPT partition label.
 *     MSDOS partitions do not support labels!
 *
 *  If name doesn't have fall into the categories above, we return (0,0).
 *  block_class is used to check if something is a disk name. If the disk
 *  name contains slashes, the device name has them replaced with
 *  bangs.
 */
int __init early_lookup_bdev(const char *name, dev_t *devt)
{
    if (strncmp(name, "PARTUUID=", 9) == 0)
        return devt_from_partuuid(name + 9, devt);
    if (strncmp(name, "PARTLABEL=", 10) == 0)
        return devt_from_partlabel(name + 10, devt);
    if (strncmp(name, "/dev/", 5) == 0)
        return devt_from_devname(name + 5, devt);
    return devt_from_devnum(name, devt);
}
