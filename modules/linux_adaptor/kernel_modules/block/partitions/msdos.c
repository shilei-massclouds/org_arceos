// SPDX-License-Identifier: GPL-2.0
/*
 *  fs/partitions/msdos.c
 *
 *  Code extracted from drivers/block/genhd.c
 *  Copyright (C) 1991-1998  Linus Torvalds
 *
 *  Thanks to Branko Lankester, lankeste@fwi.uva.nl, who found a bug
 *  in the early extended-partition checks and added DM partitions
 *
 *  Support for DiskManager v6.0x added by Mark Lord,
 *  with information provided by OnTrack.  This now works for linux fdisk
 *  and LILO, as well as loadlin and bootln.  Note that disks other than
 *  /dev/hda *must* have a "DOS" type 0x51 partition in the first slot (hda1).
 *
 *  More flexible handling of extended partitions - aeb, 950831
 *
 *  Check partition table on IDE disks for common CHS translations
 *
 *  Re-organised Feb 1998 Russell King
 *
 *  BSD disklabel support by Yossi Gottlieb <yogo@math.tau.ac.il>
 *  updated by Marc Espie <Marc.Espie@openbsd.org>
 *
 *  Unixware slices support by Andrzej Krzysztofowicz <ankry@mif.pg.gda.pl>
 *  and Krzysztof G. Baranowski <kgb@knm.org.pl>
 */
#include <linux/msdos_fs.h>
#include <linux/msdos_partition.h>

#include "check.h"
#include "efi.h"

/*
 * Many architectures don't like unaligned accesses, while
 * the nr_sects and start_sect partition table entries are
 * at a 2 (mod 4) address.
 */
#include <linux/unaligned.h>

#include "adaptor.h"

static inline sector_t nr_sects(struct msdos_partition *p)
{
    return (sector_t)get_unaligned_le32(&p->nr_sects);
}

static inline sector_t start_sect(struct msdos_partition *p)
{
    return (sector_t)get_unaligned_le32(&p->start_sect);
}

static inline int is_extended_partition(struct msdos_partition *p)
{
    return (p->sys_ind == DOS_EXTENDED_PARTITION ||
        p->sys_ind == WIN98_EXTENDED_PARTITION ||
        p->sys_ind == LINUX_EXTENDED_PARTITION);
}

#define MSDOS_LABEL_MAGIC1  0x55
#define MSDOS_LABEL_MAGIC2  0xAA

static inline int
msdos_magic_present(unsigned char *p)
{
    return (p[0] == MSDOS_LABEL_MAGIC1 && p[1] == MSDOS_LABEL_MAGIC2);
}

/* Value is EBCDIC 'IBMA' */
#define AIX_LABEL_MAGIC1    0xC9
#define AIX_LABEL_MAGIC2    0xC2
#define AIX_LABEL_MAGIC3    0xD4
#define AIX_LABEL_MAGIC4    0xC1
static int aix_magic_present(struct parsed_partitions *state, unsigned char *p)
{
    struct msdos_partition *pt = (struct msdos_partition *) (p + 0x1be);
    Sector sect;
    unsigned char *d;
    int slot, ret = 0;

    if (!(p[0] == AIX_LABEL_MAGIC1 &&
        p[1] == AIX_LABEL_MAGIC2 &&
        p[2] == AIX_LABEL_MAGIC3 &&
        p[3] == AIX_LABEL_MAGIC4))
        return 0;

    /*
     * Assume the partition table is valid if Linux partitions exists.
     * Note that old Solaris/x86 partitions use the same indicator as
     * Linux swap partitions, so we consider that a Linux partition as
     * well.
     */
    for (slot = 1; slot <= 4; slot++, pt++) {
        if (pt->sys_ind == SOLARIS_X86_PARTITION ||
            pt->sys_ind == LINUX_RAID_PARTITION ||
            pt->sys_ind == LINUX_DATA_PARTITION ||
            pt->sys_ind == LINUX_LVM_PARTITION ||
            is_extended_partition(pt))
            return 0;
    }
    d = read_part_sector(state, 7, &sect);
    if (d) {
        if (d[0] == '_' && d[1] == 'L' && d[2] == 'V' && d[3] == 'M')
            ret = 1;
        put_dev_sector(sect);
    }
    return ret;
}

static void set_info(struct parsed_partitions *state, int slot,
             u32 disksig)
{
    struct partition_meta_info *info = &state->parts[slot].info;

    snprintf(info->uuid, sizeof(info->uuid), "%08x-%02x", disksig,
         slot);
    info->volname[0] = 0;
    state->parts[slot].has_info = true;
}

static void parse_extended(struct parsed_partitions *state,
               sector_t first_sector, sector_t first_size,
               u32 disksig)
{
    struct msdos_partition *p;
    Sector sect;
    unsigned char *data;
    sector_t this_sector, this_size;
    sector_t sector_size;
    int loopct = 0;     /* number of links followed
                   without finding a data partition */
    int i;

    sector_size = queue_logical_block_size(state->disk->queue) / 512;
    this_sector = first_sector;
    this_size = first_size;

    while (1) {
        if (++loopct > 100)
            return;
        if (state->next == state->limit)
            return;
        data = read_part_sector(state, this_sector, &sect);
        if (!data)
            return;

        if (!msdos_magic_present(data + 510))
            goto done;

        p = (struct msdos_partition *) (data + 0x1be);

        /*
         * Usually, the first entry is the real data partition,
         * the 2nd entry is the next extended partition, or empty,
         * and the 3rd and 4th entries are unused.
         * However, DRDOS sometimes has the extended partition as
         * the first entry (when the data partition is empty),
         * and OS/2 seems to use all four entries.
         */

        /*
         * First process the data partition(s)
         */
        for (i = 0; i < 4; i++, p++) {
            sector_t offs, size, next;

            if (!nr_sects(p) || is_extended_partition(p))
                continue;

            /* Check the 3rd and 4th entries -
               these sometimes contain random garbage */
            offs = start_sect(p)*sector_size;
            size = nr_sects(p)*sector_size;
            next = this_sector + offs;
            if (i >= 2) {
                if (offs + size > this_size)
                    continue;
                if (next < first_sector)
                    continue;
                if (next + size > first_sector + first_size)
                    continue;
            }

            put_partition(state, state->next, next, size);
            set_info(state, state->next, disksig);
            if (p->sys_ind == LINUX_RAID_PARTITION)
                state->parts[state->next].flags = ADDPART_FLAG_RAID;
            loopct = 0;
            if (++state->next == state->limit)
                goto done;
        }
        /*
         * Next, process the (first) extended partition, if present.
         * (So far, there seems to be no reason to make
         *  parse_extended()  recursive and allow a tree
         *  of extended partitions.)
         * It should be a link to the next logical partition.
         */
        p -= 4;
        for (i = 0; i < 4; i++, p++)
            if (nr_sects(p) && is_extended_partition(p))
                break;
        if (i == 4)
            goto done;   /* nothing left to do */

        this_sector = first_sector + start_sect(p) * sector_size;
        this_size = nr_sects(p) * sector_size;
        put_dev_sector(sect);
    }
done:
    put_dev_sector(sect);
}

static void parse_freebsd(struct parsed_partitions *state,
              sector_t offset, sector_t size, int origin)
{
#ifdef CONFIG_BSD_DISKLABEL
    parse_bsd(state, offset, size, origin, "bsd", BSD_MAXPARTITIONS);
#endif
}

static void parse_netbsd(struct parsed_partitions *state,
             sector_t offset, sector_t size, int origin)
{
#ifdef CONFIG_BSD_DISKLABEL
    parse_bsd(state, offset, size, origin, "netbsd", BSD_MAXPARTITIONS);
#endif
}

static void parse_openbsd(struct parsed_partitions *state,
              sector_t offset, sector_t size, int origin)
{
#ifdef CONFIG_BSD_DISKLABEL
    parse_bsd(state, offset, size, origin, "openbsd",
          OPENBSD_MAXPARTITIONS);
#endif
}

/*
 * Minix 2.0.0/2.0.2 subpartition support.
 * Anand Krishnamurthy <anandk@wiproge.med.ge.com>
 * Rajeev V. Pillai    <rajeevvp@yahoo.com>
 */
static void parse_minix(struct parsed_partitions *state,
            sector_t offset, sector_t size, int origin)
{
    PANIC("");
}

/*
 * Create devices for Unixware partitions listed in a disklabel, under a
 * dos-like partition. See parse_extended() for more information.
 */
static void parse_unixware(struct parsed_partitions *state,
               sector_t offset, sector_t size, int origin)
{
    PANIC("");
}

/* james@bpgc.com: Solaris has a nasty indicator: 0x82 which also
   indicates linux swap.  Be careful before believing this is Solaris. */

static void parse_solaris_x86(struct parsed_partitions *state,
                  sector_t offset, sector_t size, int origin)
{
    PANIC("");
}

static struct {
    unsigned char id;
    void (*parse)(struct parsed_partitions *, sector_t, sector_t, int);
} subtypes[] = {
    {FREEBSD_PARTITION, parse_freebsd},
    {NETBSD_PARTITION, parse_netbsd},
    {OPENBSD_PARTITION, parse_openbsd},
    {MINIX_PARTITION, parse_minix},
    {UNIXWARE_PARTITION, parse_unixware},
    {SOLARIS_X86_PARTITION, parse_solaris_x86},
    {NEW_SOLARIS_X86_PARTITION, parse_solaris_x86},
    {0, NULL},
};

int msdos_partition(struct parsed_partitions *state)
{
    sector_t sector_size;
    Sector sect;
    unsigned char *data;
    struct msdos_partition *p;
    struct fat_boot_sector *fb;
    int slot;
    u32 disksig;

    printk("MSDOC Partition Table is valid!  Yea!\n");

    sector_size = queue_logical_block_size(state->disk->queue) / 512;
    data = read_part_sector(state, 0, &sect);
    if (!data)
        return -1;

    /*
     * Note order! (some AIX disks, e.g. unbootable kind,
     * have no MSDOS 55aa)
     */
    if (aix_magic_present(state, data)) {
        put_dev_sector(sect);
#ifdef CONFIG_AIX_PARTITION
        return aix_partition(state);
#else
        strlcat(state->pp_buf, " [AIX]", PAGE_SIZE);
        return 0;
#endif
    }

    if (!msdos_magic_present(data + 510)) {
        put_dev_sector(sect);
        return 0;
    }

    /*
     * Now that the 55aa signature is present, this is probably
     * either the boot sector of a FAT filesystem or a DOS-type
     * partition table. Reject this in case the boot indicator
     * is not 0 or 0x80.
     */
    p = (struct msdos_partition *) (data + 0x1be);
    for (slot = 1; slot <= 4; slot++, p++) {
        if (p->boot_ind != 0 && p->boot_ind != 0x80) {
            /*
             * Even without a valid boot indicator value
             * its still possible this is valid FAT filesystem
             * without a partition table.
             */
            fb = (struct fat_boot_sector *) data;
            if (slot == 1 && fb->reserved && fb->fats
                && fat_valid_media(fb->media)) {
                strlcat(state->pp_buf, "\n", PAGE_SIZE);
                put_dev_sector(sect);
                return 1;
            } else {
                put_dev_sector(sect);
                return 0;
            }
        }
    }

#ifdef CONFIG_EFI_PARTITION
    p = (struct msdos_partition *) (data + 0x1be);
    for (slot = 1 ; slot <= 4 ; slot++, p++) {
        /* If this is an EFI GPT disk, msdos should ignore it. */
        if (p->sys_ind == EFI_PMBR_OSTYPE_EFI_GPT) {
            put_dev_sector(sect);
            return 0;
        }
    }
#endif
    p = (struct msdos_partition *) (data + 0x1be);

    disksig = le32_to_cpup((__le32 *)(data + 0x1b8));

    /*
     * Look for partitions in two passes:
     * First find the primary and DOS-type extended partitions.
     * On the second pass look inside *BSD, Unixware and Solaris partitions.
     */

    state->next = 5;
    for (slot = 1 ; slot <= 4 ; slot++, p++) {
        sector_t start = start_sect(p)*sector_size;
        sector_t size = nr_sects(p)*sector_size;

        if (!size)
            continue;
        if (is_extended_partition(p)) {
            /*
             * prevent someone doing mkfs or mkswap on an
             * extended partition, but leave room for LILO
             * FIXME: this uses one logical sector for > 512b
             * sector, although it may not be enough/proper.
             */
            sector_t n = 2;

            n = min(size, max(sector_size, n));
            put_partition(state, slot, start, n);

            strlcat(state->pp_buf, " <", PAGE_SIZE);
            parse_extended(state, start, size, disksig);
            strlcat(state->pp_buf, " >", PAGE_SIZE);
            continue;
        }
        put_partition(state, slot, start, size);
        set_info(state, slot, disksig);
        if (p->sys_ind == LINUX_RAID_PARTITION)
            state->parts[slot].flags = ADDPART_FLAG_RAID;
        if (p->sys_ind == DM6_PARTITION)
            strlcat(state->pp_buf, "[DM]", PAGE_SIZE);
        if (p->sys_ind == EZD_PARTITION)
            strlcat(state->pp_buf, "[EZD]", PAGE_SIZE);
    }

    strlcat(state->pp_buf, "\n", PAGE_SIZE);

    /* second pass - output for each on a separate line */
    p = (struct msdos_partition *) (0x1be + data);
    for (slot = 1 ; slot <= 4 ; slot++, p++) {
        unsigned char id = p->sys_ind;
        int n;

        if (!nr_sects(p))
            continue;

        for (n = 0; subtypes[n].parse && id != subtypes[n].id; n++)
            ;

        if (!subtypes[n].parse)
            continue;
        subtypes[n].parse(state, start_sect(p) * sector_size,
                  nr_sects(p) * sector_size, slot);
    }
    put_dev_sector(sect);
    return 1;
}
