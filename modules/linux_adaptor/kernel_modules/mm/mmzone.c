// SPDX-License-Identifier: GPL-2.0
/*
 * linux/mm/mmzone.c
 *
 * management codes for pgdats, zones and page flags
 */

#include <linux/stddef.h>
#include <linux/mm.h>
#include <linux/mmzone.h>

void lruvec_init(struct lruvec *lruvec)
{
    enum lru_list lru;

    memset(lruvec, 0, sizeof(struct lruvec));
    spin_lock_init(&lruvec->lru_lock);
    zswap_lruvec_state_init(lruvec);

    for_each_lru(lru)
        INIT_LIST_HEAD(&lruvec->lists[lru]);
    /*
     * The "Unevictable LRU" is imaginary: though its size is maintained,
     * it is never scanned, and unevictable pages are not threaded on it
     * (so that their lru fields can be reused to hold mlock_count).
     * Poison its list head, so that any operations on it would crash.
     */
    list_del(&lruvec->lists[LRU_UNEVICTABLE]);

    lru_gen_init_lruvec(lruvec);
}
