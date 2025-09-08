#include <linux/memory.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/err.h>
#include <linux/static_key.h>
#include <linux/jump_label_ratelimit.h>
#include <linux/bug.h>
#include <linux/cpu.h>
#include <asm/sections.h>
#include "../adaptor.h"

/* mutex to protect coming/going of the jump_label table */
static DEFINE_MUTEX(jump_label_mutex);

void jump_label_lock(void)
{
    mutex_lock(&jump_label_mutex);
}

void jump_label_unlock(void)
{
    mutex_unlock(&jump_label_mutex);
}

static inline struct jump_entry *static_key_entries(struct static_key *key)
{
    WARN_ON_ONCE(key->type & JUMP_TYPE_LINKED);
    return (struct jump_entry *)(key->type & ~JUMP_TYPE_MASK);
}

/***
 * A 'struct static_key' uses a union such that it either points directly
 * to a table of 'struct jump_entry' or to a linked list of modules which in
 * turn point to 'struct jump_entry' tables.
 *
 * The two lower bits of the pointer are used to keep track of which pointer
 * type is in use and to store the initial branch direction, we use an access
 * function which preserves these bits.
 */
static void static_key_set_entries(struct static_key *key,
                   struct jump_entry *entries)
{
    unsigned long type;

    WARN_ON_ONCE((unsigned long)entries & JUMP_TYPE_MASK);
    type = key->type & JUMP_TYPE_MASK;
    key->entries = entries;
    key->type |= type;
}

static enum jump_label_type jump_label_type(struct jump_entry *entry)
{
    struct static_key *key = jump_entry_key(entry);
    bool enabled = static_key_enabled(key);
    bool branch = jump_entry_is_branch(entry);

    /* See the comment in linux/jump_label.h */
    return enabled ^ branch;
}

static bool jump_label_can_update(struct jump_entry *entry, bool init)
{
    /*
     * Cannot update code that was in an init text area.
     */
    if (!init && jump_entry_is_init(entry))
        return false;

    if (!kernel_text_address(jump_entry_code(entry))) {
        /*
         * This skips patching built-in __exit, which
         * is part of init_section_contains() but is
         * not part of kernel_text_address().
         *
         * Skipping built-in __exit is fine since it
         * will never be executed.
         */
        WARN_ONCE(!jump_entry_is_init(entry),
              "can't patch jump_label at %pS",
              (void *)jump_entry_code(entry));
        return false;
    }

    return true;
}

#ifndef HAVE_JUMP_LABEL_BATCH
static void __jump_label_update(struct static_key *key,
                struct jump_entry *entry,
                struct jump_entry *stop,
                bool init)
{
    for (; (entry < stop) && (jump_entry_key(entry) == key); entry++) {
        if (jump_label_can_update(entry, init))
            arch_jump_label_transform(entry, jump_label_type(entry));
    }
}
#else
static void __jump_label_update(struct static_key *key,
                struct jump_entry *entry,
                struct jump_entry *stop,
                bool init)
{
    for (; (entry < stop) && (jump_entry_key(entry) == key); entry++) {

        if (!jump_label_can_update(entry, init))
            continue;

        if (!arch_jump_label_transform_queue(entry, jump_label_type(entry))) {
            /*
             * Queue is full: Apply the current queue and try again.
             */
            arch_jump_label_transform_apply();
            BUG_ON(!arch_jump_label_transform_queue(entry, jump_label_type(entry)));
        }
    }
    arch_jump_label_transform_apply();
}
#endif

static void jump_label_update(struct static_key *key)
{
    struct jump_entry *stop = __stop___jump_table;
    bool init = system_state < SYSTEM_RUNNING;
    struct jump_entry *entry;
#ifdef CONFIG_MODULES
    struct module *mod;

    if (static_key_linked(key)) {
        __jump_label_mod_update(key);
        return;
    }

    preempt_disable();
    mod = __module_address((unsigned long)key);
    if (mod) {
        stop = mod->jump_entries + mod->num_jump_entries;
        init = mod->state == MODULE_STATE_COMING;
    }
    preempt_enable();
#endif
    entry = static_key_entries(key);
    /* if there are no users, entry can be NULL */
    if (entry)
        __jump_label_update(key, entry, stop, init);
}

/*
 * There are similar definitions for the !CONFIG_JUMP_LABEL case in jump_label.h.
 * The use of 'atomic_read()' requires atomic.h and its problematic for some
 * kernel headers such as kernel.h and others. Since static_key_count() is not
 * used in the branch statements as it is for the !CONFIG_JUMP_LABEL case its ok
 * to have it be a function here. Similarly, for 'static_key_enable()' and
 * 'static_key_disable()', which require bug.h. This should allow jump_label.h
 * to be included from most/all places for CONFIG_JUMP_LABEL.
 */
int static_key_count(struct static_key *key)
{
    /*
     * -1 means the first static_key_slow_inc() is in progress.
     *  static_key_enabled() must return true, so return 1 here.
     */
    int n = atomic_read(&key->enabled);

    return n >= 0 ? n : 1;
}

void static_key_enable_cpuslocked(struct static_key *key)
{
    STATIC_KEY_CHECK_USE(key);
    lockdep_assert_cpus_held();

    if (atomic_read(&key->enabled) > 0) {
        WARN_ON_ONCE(atomic_read(&key->enabled) != 1);
        return;
    }

    jump_label_lock();
    if (atomic_read(&key->enabled) == 0) {
        atomic_set(&key->enabled, -1);
        jump_label_update(key);
        /*
         * See static_key_slow_inc().
         */
        atomic_set_release(&key->enabled, 1);
    }
    jump_label_unlock();
}

void static_key_enable(struct static_key *key)
{
    cpus_read_lock();
    static_key_enable_cpuslocked(key);
    cpus_read_unlock();
}

static int jump_label_cmp(const void *a, const void *b)
{
    const struct jump_entry *jea = a;
    const struct jump_entry *jeb = b;

    /*
     * Entrires are sorted by key.
     */
    if (jump_entry_key(jea) < jump_entry_key(jeb))
        return -1;

    if (jump_entry_key(jea) > jump_entry_key(jeb))
        return 1;

    /*
     * In the batching mode, entries should also be sorted by the code
     * inside the already sorted list of entries, enabling a bsearch in
     * the vector.
     */
    if (jump_entry_code(jea) < jump_entry_code(jeb))
        return -1;

    if (jump_entry_code(jea) > jump_entry_code(jeb))
        return 1;

    return 0;
}

static void jump_label_swap(void *a, void *b, int size)
{
    long delta = (unsigned long)a - (unsigned long)b;
    struct jump_entry *jea = a;
    struct jump_entry *jeb = b;
    struct jump_entry tmp = *jea;

    jea->code   = jeb->code - delta;
    jea->target = jeb->target - delta;
    jea->key    = jeb->key - delta;

    jeb->code   = tmp.code + delta;
    jeb->target = tmp.target + delta;
    jeb->key    = tmp.key + delta;
}

static void
jump_label_sort_entries(struct jump_entry *start, struct jump_entry *stop)
{
    unsigned long size;
    void *swapfn = NULL;

    if (IS_ENABLED(CONFIG_HAVE_ARCH_JUMP_LABEL_RELATIVE))
        swapfn = jump_label_swap;

    size = (((unsigned long)stop - (unsigned long)start)
                    / sizeof(struct jump_entry));
    sort(start, size, sizeof(struct jump_entry), jump_label_cmp, swapfn);
}

#ifndef arch_jump_label_transform_static
static void arch_jump_label_transform_static(struct jump_entry *entry,
                         enum jump_label_type type)
{
    /* nothing to do on most architectures */
}
#endif

void __init jump_label_init(void)
{
    struct jump_entry *iter_start = __start___jump_table;
    struct jump_entry *iter_stop = __stop___jump_table;
    struct static_key *key = NULL;
    struct jump_entry *iter;

    /*
     * Since we are initializing the static_key.enabled field with
     * with the 'raw' int values (to avoid pulling in atomic.h) in
     * jump_label.h, let's make sure that is safe. There are only two
     * cases to check since we initialize to 0 or 1.
     */
    BUILD_BUG_ON((int)ATOMIC_INIT(0) != 0);
    BUILD_BUG_ON((int)ATOMIC_INIT(1) != 1);

    if (static_key_initialized)
        return;

#if 0
    cpus_read_lock();
    jump_label_lock();
#endif
    jump_label_sort_entries(iter_start, iter_stop);

    for (iter = iter_start; iter < iter_stop; iter++) {
        struct static_key *iterk;
        bool in_init;

        /* rewrite NOPs */
        if (jump_label_type(iter) == JUMP_LABEL_NOP)
            arch_jump_label_transform_static(iter, JUMP_LABEL_NOP);

        //in_init = init_section_contains((void *)jump_entry_code(iter), 1);
        in_init = false;
        pr_notice("%s: No impl for 'in_init'.", __func__);
        jump_entry_set_init(iter, in_init);

        iterk = jump_entry_key(iter);
        if (iterk == key)
            continue;

        key = iterk;
        static_key_set_entries(key, iter);
    }

    static_key_initialized = true;
#if 0
    jump_label_unlock();
    cpus_read_unlock();
#endif
}
