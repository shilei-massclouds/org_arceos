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

static void init_one_lru(struct list_lru_one *l)
{
    INIT_LIST_HEAD(&l->list);
    l->nr_items = 0;
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
