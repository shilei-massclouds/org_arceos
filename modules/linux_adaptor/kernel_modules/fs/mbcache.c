#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/list_bl.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/mbcache.h>

/*
 * Mbcache is a simple key-value store. Keys need not be unique, however
 * key-value pairs are expected to be unique (we use this fact in
 * mb_cache_entry_delete_or_get()).
 *
 * Ext2 and ext4 use this cache for deduplication of extended attribute blocks.
 * Ext4 also uses it for deduplication of xattr values stored in inodes.
 * They use hash of data as a key and provide a value that may represent a
 * block or inode number. That's why keys need not be unique (hash of different
 * data may be the same). However user provided value always uniquely
 * identifies a cache entry.
 *
 * We provide functions for creation and removal of entries, search by key,
 * and a special "delete entry with given key-value pair" operation. Fixed
 * size hash table is used for fast key lookups.
 */

struct mb_cache {
    /* Hash table of entries */
    struct hlist_bl_head    *c_hash;
    /* log2 of hash table size */
    int         c_bucket_bits;
    /* Maximum entries in cache to avoid degrading hash too much */
    unsigned long       c_max_entries;
    /* Protects c_list, c_entry_count */
    spinlock_t      c_list_lock;
    struct list_head    c_list;
    /* Number of entries in cache */
    unsigned long       c_entry_count;
    struct shrinker     *c_shrink;
    /* Work for shrinking when the cache has too many entries */
    struct work_struct  c_shrink_work;
};

/*
 * mb_cache_create - create cache
 * @bucket_bits: log2 of the hash table size
 *
 * Create cache for keys with 2^bucket_bits hash entries.
 */
struct mb_cache *mb_cache_create(int bucket_bits)
{
    pr_err("%s: No impl.", __func__);
    return kmalloc(sizeof(struct mb_cache), 0);
}
