#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/list_lru.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/memcontrol.h>
#include "slab.h"
#include "internal.h"

#include "../adaptor.h"

static DEFINE_MUTEX(list_lrus_mutex);

static void memcg_destroy_list_lru(struct list_lru *lru)
{
}

static inline bool list_lru_memcg_aware(struct list_lru *lru)
{
    return false;
}

static inline struct list_lru_one *
list_lru_from_memcg_idx(struct list_lru *lru, int nid, int idx)
{
    return &lru->node[nid].lru;
}

static int lru_shrinker_id(struct list_lru *lru)
{
    return -1;
}

static void init_one_lru(struct list_lru_one *l)
{
    INIT_LIST_HEAD(&l->list);
    l->nr_items = 0;
}

/* The caller must ensure the memcg lifetime. */
bool list_lru_add(struct list_lru *lru, struct list_head *item, int nid,
            struct mem_cgroup *memcg)
{
    struct list_lru_node *nlru = &lru->node[nid];
    struct list_lru_one *l;

    spin_lock(&nlru->lock);
    if (list_empty(item)) {
        l = list_lru_from_memcg_idx(lru, nid, memcg_kmem_id(memcg));
        list_add_tail(item, &l->list);
        /* Set shrinker bit if the first element was added */
        if (!l->nr_items++)
            set_shrinker_bit(memcg, nid, lru_shrinker_id(lru));
        nlru->nr_items++;
        spin_unlock(&nlru->lock);
        return true;
    }
    spin_unlock(&nlru->lock);
    return false;
}

bool list_lru_add_obj(struct list_lru *lru, struct list_head *item)
{
    bool ret;
    int nid = page_to_nid(virt_to_page(item));

    if (list_lru_memcg_aware(lru)) {
        rcu_read_lock();
        ret = list_lru_add(lru, item, nid, mem_cgroup_from_slab_obj(item));
        rcu_read_unlock();
    } else {
        ret = list_lru_add(lru, item, nid, NULL);
    }

    return ret;
}

int __list_lru_init(struct list_lru *lru, bool memcg_aware,
            struct lock_class_key *key, struct shrinker *shrinker)
{
    int i;

#ifdef CONFIG_MEMCG
    if (shrinker)
        lru->shrinker_id = shrinker->id;
    else
        lru->shrinker_id = -1;

    /*
    if (mem_cgroup_kmem_disabled())
        memcg_aware = false;
    */
#endif

    lru->node = kcalloc(nr_node_ids, sizeof(*lru->node), GFP_KERNEL);
    if (!lru->node)
        return -ENOMEM;

    for_each_node(i) {
        spin_lock_init(&lru->node[i].lock);
        if (key)
            lockdep_set_class(&lru->node[i].lock, key);
        init_one_lru(&lru->node[i].lru);
    }

    //memcg_init_list_lru(lru, memcg_aware);
    //list_lru_register(lru);

    return 0;
}

static void list_lru_unregister(struct list_lru *lru)
{
    if (!list_lru_memcg_aware(lru))
        return;

    mutex_lock(&list_lrus_mutex);
    list_del(&lru->list);
    mutex_unlock(&list_lrus_mutex);
}

void list_lru_destroy(struct list_lru *lru)
{
    /* Already destroyed or not yet initialized? */
    if (!lru->node)
        return;

    list_lru_unregister(lru);

    memcg_destroy_list_lru(lru);
    kfree(lru->node);
    lru->node = NULL;

#ifdef CONFIG_MEMCG
    lru->shrinker_id = -1;
#endif
}

/* The caller must ensure the memcg lifetime. */
bool list_lru_del(struct list_lru *lru, struct list_head *item, int nid,
            struct mem_cgroup *memcg)
{
    struct list_lru_node *nlru = &lru->node[nid];
    struct list_lru_one *l;

    spin_lock(&nlru->lock);
    if (!list_empty(item)) {
        l = list_lru_from_memcg_idx(lru, nid, memcg_kmem_id(memcg));
        list_del_init(item);
        l->nr_items--;
        nlru->nr_items--;
        spin_unlock(&nlru->lock);
        return true;
    }
    spin_unlock(&nlru->lock);
    return false;
}

bool list_lru_del_obj(struct list_lru *lru, struct list_head *item)
{
    bool ret;
    int nid = page_to_nid(virt_to_page(item));

    if (list_lru_memcg_aware(lru)) {
        rcu_read_lock();
        ret = list_lru_del(lru, item, nid, mem_cgroup_from_slab_obj(item));
        rcu_read_unlock();
    } else {
        ret = list_lru_del(lru, item, nid, NULL);
    }

    return ret;
}
