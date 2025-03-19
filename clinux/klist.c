#include <linux/types.h>
#include <linux/klist.h>
#include "booter.h"

/*
 * Use the lowest bit of n_klist to mark deleted nodes and exclude
 * dead ones from iteration.
 */
#define KNODE_DEAD      1LU
#define KNODE_KLIST_MASK    ~KNODE_DEAD

static void klist_release(struct kref *kref)
{
    printk("%s: No impl.\n", __func__);
}

static struct klist *knode_klist(struct klist_node *knode)
{
    return (struct klist *)
        ((unsigned long)knode->n_klist & KNODE_KLIST_MASK);
}

static bool knode_dead(struct klist_node *knode)
{
    return (unsigned long)knode->n_klist & KNODE_DEAD;
}

static void knode_kill(struct klist_node *knode)
{
    /* and no knode should die twice ever either, see we're very humane */
    WARN_ON(knode_dead(knode));
    *(unsigned long *)&knode->n_klist |= KNODE_DEAD;
}

static struct klist_node *to_klist_node(struct list_head *n)
{
    return container_of(n, struct klist_node, n_node);
}

static int klist_dec_and_del(struct klist_node *n)
{
    return kref_put(&n->n_ref, klist_release);
}

static void knode_set_klist(struct klist_node *knode, struct klist *klist)
{
    knode->n_klist = klist;
    /* no knode deserves to start its life dead */
    WARN_ON(knode_dead(knode));
}

/**
 * klist_init - Initialize a klist structure.
 * @k: The klist we're initializing.
 * @get: The get function for the embedding object (NULL if none)
 * @put: The put function for the embedding object (NULL if none)
 *
 * Initialises the klist structure.  If the klist_node structures are
 * going to be embedded in refcounted objects (necessary for safe
 * deletion) then the get/put arguments are used to initialise
 * functions that take and release references on the embedding
 * objects.
 */
void klist_init(struct klist *k, void (*get)(struct klist_node *),
        void (*put)(struct klist_node *))
{
    INIT_LIST_HEAD(&k->k_list);
    spin_lock_init(&k->k_lock);
    k->get = get;
    k->put = put;
}

static void add_tail(struct klist *k, struct klist_node *n)
{
    spin_lock(&k->k_lock);
    list_add_tail(&n->n_node, &k->k_list);
    spin_unlock(&k->k_lock);
}

static void klist_node_init(struct klist *k, struct klist_node *n)
{
    INIT_LIST_HEAD(&n->n_node);
    kref_init(&n->n_ref);
    knode_set_klist(n, k);
    if (k->get)
        k->get(n);
}

/**
 * klist_add_tail - Initialize a klist_node and add it to back.
 * @n: node we're adding.
 * @k: klist it's going on.
 */
void klist_add_tail(struct klist_node *n, struct klist *k)
{
    klist_node_init(k, n);
    add_tail(k, n);
}

/**
 * klist_iter_init_node - Initialize a klist_iter structure.
 * @k: klist we're iterating.
 * @i: klist_iter we're filling.
 * @n: node to start with.
 *
 * Similar to klist_iter_init(), but starts the action off with @n,
 * instead of with the list head.
 */
void klist_iter_init_node(struct klist *k, struct klist_iter *i,
              struct klist_node *n)
{
    i->i_klist = k;
    i->i_cur = NULL;
    if (n && kref_get_unless_zero(&n->n_ref))
        i->i_cur = n;
}

/**
 * klist_next - Ante up next node in list.
 * @i: Iterator structure.
 *
 * First grab list lock. Decrement the reference count of the previous
 * node, if there was one. Grab the next node, increment its reference
 * count, drop the lock, and return that next node.
 */
struct klist_node *klist_next(struct klist_iter *i)
{
    void (*put)(struct klist_node *) = i->i_klist->put;
    struct klist_node *last = i->i_cur;
    struct klist_node *next;
    unsigned long flags;

    spin_lock_irqsave(&i->i_klist->k_lock, flags);

    if (last) {
        next = to_klist_node(last->n_node.next);
        if (!klist_dec_and_del(last))
            put = NULL;
    } else
        next = to_klist_node(i->i_klist->k_list.next);

    i->i_cur = NULL;
    while (next != to_klist_node(&i->i_klist->k_list)) {
        if (likely(!knode_dead(next))) {
            kref_get(&next->n_ref);
            i->i_cur = next;
            break;
        }
        next = to_klist_node(next->n_node.next);
    }

    spin_unlock_irqrestore(&i->i_klist->k_lock, flags);

    if (put && last)
        put(last);
    return i->i_cur;
}

static void klist_put(struct klist_node *n, bool kill)
{
    struct klist *k = knode_klist(n);
    void (*put)(struct klist_node *) = k->put;

    spin_lock(&k->k_lock);
    if (kill)
        knode_kill(n);
    if (!klist_dec_and_del(n))
        put = NULL;
    spin_unlock(&k->k_lock);
    if (put)
        put(n);
}

/**
 * klist_iter_exit - Finish a list iteration.
 * @i: Iterator structure.
 *
 * Must be called when done iterating over list, as it decrements the
 * refcount of the current node. Necessary in case iteration exited before
 * the end of the list was reached, and always good form.
 */
void klist_iter_exit(struct klist_iter *i)
{
    if (i->i_cur) {
        klist_put(i->i_cur, false);
        i->i_cur = NULL;
    }
}
