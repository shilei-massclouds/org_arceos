#include <linux/mm.h>
#include <linux/swap.h> /* mm_account_reclaimed_pages() */
#include <linux/module.h>
#include <linux/bit_spinlock.h>
#include <linux/interrupt.h>
#include <linux/swab.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include "slab.h"
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kasan.h>
#include <linux/kmsan.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/mempolicy.h>
#include <linux/ctype.h>
#include <linux/stackdepot.h>
#include <linux/debugobjects.h>
#include <linux/kallsyms.h>
#include <linux/kfence.h>
#include <linux/memory.h>
#include <linux/math64.h>
#include <linux/fault-inject.h>
#include <linux/kmemleak.h>
#include <linux/stacktrace.h>
#include <linux/prefetch.h>
#include <linux/memcontrol.h>
#include <linux/random.h>
#include <kunit/test.h>
#include <kunit/test-bug.h>
#include <linux/sort.h>

#include <linux/debugfs.h>
#include <trace/events/kmem.h>

#include "internal.h"
#include "adaptor.h"

#ifdef CONFIG_KMSAN
#define pad_check_attributes noinline __no_kmsan_checks
#else
#define pad_check_attributes
#endif

#define slub_get_cpu_ptr(var)       get_cpu_ptr(var)
#define slub_put_cpu_ptr(var)       put_cpu_ptr(var)
#define USE_LOCKLESS_FAST_PATH()    (true)

#ifndef CONFIG_SLUB_TINY
#define __fastpath_inline __always_inline
#else
#define __fastpath_inline
#endif

#ifdef system_has_freelist_aba
#define __CMPXCHG_DOUBLE    __SLAB_FLAG_BIT(_SLAB_CMPXCHG_DOUBLE)
#else
#define __CMPXCHG_DOUBLE    __SLAB_FLAG_UNUSED
#endif

/* Loop over all objects in a slab */
#define for_each_object(__p, __s, __addr, __objects) \
    for (__p = fixup_red_left(__s, __addr); \
        __p < (__addr) + (__objects) * (__s)->size; \
        __p += (__s)->size)

/* Structure holding parameters for get_partial() call chain */
struct partial_context {
    gfp_t flags;
    unsigned int orig_size;
    void *object;
};

static inline bool pfmemalloc_match(struct slab *slab, gfp_t gfpflags)
{
    if (unlikely(slab_test_pfmemalloc(slab)))
        return gfp_pfmemalloc_allowed(gfpflags);

    return true;
}

static struct slab *new_slab(struct kmem_cache *s, gfp_t flags, int node);

/*
 * Check if the objects in a per cpu structure fit numa
 * locality expectations.
 */
static inline int node_match(struct slab *slab, int node)
{
#ifdef CONFIG_NUMA
    if (node != NUMA_NO_NODE && slab_nid(slab) != node)
        return 0;
#endif
    return 1;
}

#ifndef CONFIG_SLUB_TINY
/*
 * Minimum number of partial slabs. These will be left on the partial
 * lists even if they are empty. kmem_cache_shrink may reclaim them.
 */
#define MIN_PARTIAL 5

/*
 * Maximum number of desirable partial slabs.
 * The existence of more partial slabs makes kmem_cache_shrink
 * sort the partial list by the number of objects in use.
 */
#define MAX_PARTIAL 10
#else
#define MIN_PARTIAL 0
#define MAX_PARTIAL 0
#endif

static inline struct kmem_cache_node *get_node(struct kmem_cache *s, int node)
{
    return s->node[node];
}

/*
 * slub is about to manipulate internal object metadata.  This memory lies
 * outside the range of the allocated object, so accessing it would normally
 * be reported by kasan as a bounds error.  metadata_access_enable() is used
 * to tell kasan that these accesses are OK.
 */
static inline void metadata_access_enable(void)
{
    kasan_disable_current();
    kmsan_disable_current();
}

static inline void metadata_access_disable(void)
{
    kmsan_enable_current();
    kasan_enable_current();
}

/*
 * Iterator over all nodes. The body will be executed for each node that has
 * a kmem_cache_node structure allocated (which is true for all online nodes)
 */
#define for_each_kmem_cache_node(__s, __node, __n) \
    for (__node = 0; __node < nr_node_ids; __node++) \
         if ((__n = get_node(__s, __node)))

/* Internal SLUB flags */
/* Poison object */
#define __OBJECT_POISON     __SLAB_FLAG_BIT(_SLAB_OBJECT_POISON)

#ifdef CONFIG_SLUB_DEBUG
#ifdef CONFIG_SLUB_DEBUG_ON
DEFINE_STATIC_KEY_TRUE(slub_debug_enabled);
#else
DEFINE_STATIC_KEY_FALSE(slub_debug_enabled);
#endif
#endif      /* CONFIG_SLUB_DEBUG */

enum stat_item {
    ALLOC_FASTPATH,     /* Allocation from cpu slab */
    ALLOC_SLOWPATH,     /* Allocation by getting a new cpu slab */
    FREE_FASTPATH,      /* Free to cpu slab */
    FREE_SLOWPATH,      /* Freeing not to cpu slab */
    FREE_FROZEN,        /* Freeing to frozen slab */
    FREE_ADD_PARTIAL,   /* Freeing moves slab to partial list */
    FREE_REMOVE_PARTIAL,    /* Freeing removes last object */
    ALLOC_FROM_PARTIAL, /* Cpu slab acquired from node partial list */
    ALLOC_SLAB,     /* Cpu slab acquired from page allocator */
    ALLOC_REFILL,       /* Refill cpu slab from slab freelist */
    ALLOC_NODE_MISMATCH,    /* Switching cpu slab */
    FREE_SLAB,      /* Slab freed to the page allocator */
    CPUSLAB_FLUSH,      /* Abandoning of the cpu slab */
    DEACTIVATE_FULL,    /* Cpu slab was full when deactivated */
    DEACTIVATE_EMPTY,   /* Cpu slab was empty when deactivated */
    DEACTIVATE_TO_HEAD, /* Cpu slab was moved to the head of partials */
    DEACTIVATE_TO_TAIL, /* Cpu slab was moved to the tail of partials */
    DEACTIVATE_REMOTE_FREES,/* Slab contained remotely freed objects */
    DEACTIVATE_BYPASS,  /* Implicit deactivation */
    ORDER_FALLBACK,     /* Number of times fallback was necessary */
    CMPXCHG_DOUBLE_CPU_FAIL,/* Failures of this_cpu_cmpxchg_double */
    CMPXCHG_DOUBLE_FAIL,    /* Failures of slab freelist update */
    CPU_PARTIAL_ALLOC,  /* Used cpu partial on alloc */
    CPU_PARTIAL_FREE,   /* Refill cpu partial on free */
    CPU_PARTIAL_NODE,   /* Refill cpu partial from node partial */
    CPU_PARTIAL_DRAIN,  /* Drain cpu partial to node partial */
    NR_SLUB_STAT_ITEMS
};

#ifndef CONFIG_SLUB_TINY
/*
 * When changing the layout, make sure freelist and tid are still compatible
 * with this_cpu_cmpxchg_double() alignment requirements.
 */
struct kmem_cache_cpu {
    union {
        struct {
            void **freelist;    /* Pointer to next available object */
            unsigned long tid;  /* Globally unique transaction id */
        };
        freelist_aba_t freelist_tid;
    };
    struct slab *slab;  /* The slab from which we are allocating */
#ifdef CONFIG_SLUB_CPU_PARTIAL
    struct slab *partial;   /* Partially allocated slabs */
#endif
    local_lock_t lock;  /* Protects the fields above */
#ifdef CONFIG_SLUB_STATS
    unsigned int stat[NR_SLUB_STAT_ITEMS];
#endif
};
#endif /* CONFIG_SLUB_TINY */

/*
 * No preemption supported therefore also no need to check for
 * different cpus.
 */
#define TID_STEP 1

static inline unsigned long next_tid(unsigned long tid)
{
    return tid + TID_STEP;
}

static inline int init_cache_random_seq(struct kmem_cache *s)
{
    return 0;
}
static inline void init_freelist_randomization(void) { }
static inline bool shuffle_freelist(struct kmem_cache *s, struct slab *slab)
{
    return false;
}

/*
 * Debug settings:
 */
#if defined(CONFIG_SLUB_DEBUG_ON)
static slab_flags_t slub_debug = DEBUG_DEFAULT_FLAGS;
#else
static slab_flags_t slub_debug;
#endif

static char *slub_debug_string;
static int disable_higher_order_debug;

/*
 * Tracks for which NUMA nodes we have kmem_cache_nodes allocated.
 * Corresponds to node_state[N_NORMAL_MEMORY], but can temporarily
 * differ during memory hotplug/hotremove operations.
 * Protected by slab_mutex.
 */
static nodemask_t slab_nodes;

/*
 * The slab lists for all objects.
 */
struct kmem_cache_node {
    spinlock_t list_lock;
    unsigned long nr_partial;
    struct list_head partial;
#ifdef CONFIG_SLUB_DEBUG
    atomic_long_t nr_slabs;
    atomic_long_t total_objects;
    struct list_head full;
#endif
};

static inline unsigned long node_nr_slabs(struct kmem_cache_node *n)
{
    return atomic_long_read(&n->nr_slabs);
}

static inline unsigned long node_nr_objs(struct kmem_cache_node *n)
{
    return atomic_long_read(&n->total_objects);
}

static struct kmem_cache *kmem_cache_node;

/*
 * Minimum / Maximum order of slab pages. This influences locking overhead
 * and slab fragmentation. A higher order reduces the number of partial slabs
 * and increases the number of allocations possible without having to
 * take the list_lock.
 */
static unsigned int slub_min_order;
static unsigned int slub_max_order =
    IS_ENABLED(CONFIG_SLUB_TINY) ? 1 : PAGE_ALLOC_COSTLY_ORDER;
static unsigned int slub_min_objects;

/*
 * Debugging flags that require metadata to be stored in the slab.  These get
 * disabled when slab_debug=O is used and a cache's min order increases with
 * metadata.
 */
#define DEBUG_METADATA_FLAGS (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER)

#define OO_SHIFT    16
#define OO_MASK     ((1 << OO_SHIFT) - 1)
#define MAX_OBJS_PER_PAGE   32767 /* since slab.objects is u15 */

static inline unsigned int oo_order(struct kmem_cache_order_objects x)
{
    return x.x >> OO_SHIFT;
}

static inline unsigned int oo_objects(struct kmem_cache_order_objects x)
{
    return x.x & OO_MASK;
}

/*
 * Tracking user of a slab.
 */
#define TRACK_ADDRS_COUNT 16
struct track {
    unsigned long addr; /* Called from address */
#ifdef CONFIG_STACKDEPOT
    depot_stack_handle_t handle;
#endif
    int cpu;        /* Was running on cpu */
    int pid;        /* Pid context */
    unsigned long when; /* When did the operation occur */
};

enum track_item { TRACK_ALLOC, TRACK_FREE };

static void slub_set_cpu_partial(struct kmem_cache *s, unsigned int nr_objects)
{
    unsigned int nr_slabs;

    s->cpu_partial = nr_objects;

    /*
     * We take the number of objects but actually limit the number of
     * slabs on the per cpu partial list, in order to limit excessive
     * growth of the list. For simplicity we assume that the slabs will
     * be half-full.
     */
    nr_slabs = DIV_ROUND_UP(nr_objects * 2, oo_objects(s->oo));
    s->cpu_partial_slabs = nr_slabs;
}

static inline unsigned int slub_get_cpu_partial(struct kmem_cache *s)
{
    return s->cpu_partial_slabs;
}

static inline bool kmem_cache_debug(struct kmem_cache *s)
{
    return kmem_cache_debug_flags(s, SLAB_DEBUG_FLAGS);
}

static inline bool kmem_cache_has_cpu_partial(struct kmem_cache *s)
{
#ifdef CONFIG_SLUB_CPU_PARTIAL
    return !kmem_cache_debug(s);
#else
    return false;
#endif
}

static void set_cpu_partial(struct kmem_cache *s)
{
#ifdef CONFIG_SLUB_CPU_PARTIAL
    unsigned int nr_objects;

    /*
     * cpu_partial determined the maximum number of objects kept in the
     * per cpu partial lists of a processor.
     *
     * Per cpu partial lists mainly contain slabs that just have one
     * object freed. If they are used for allocation then they can be
     * filled up again with minimal effort. The slab will never hit the
     * per node partial lists and therefore no locking will be required.
     *
     * For backwards compatibility reasons, this is determined as number
     * of objects, even though we now limit maximum number of pages, see
     * slub_set_cpu_partial()
     */
    if (!kmem_cache_has_cpu_partial(s))
        nr_objects = 0;
    else if (s->size >= PAGE_SIZE)
        nr_objects = 6;
    else if (s->size >= 1024)
        nr_objects = 24;
    else if (s->size >= 256)
        nr_objects = 52;
    else
        nr_objects = 120;

    slub_set_cpu_partial(s, nr_objects);
#endif
}

/*
 * Parse a block of slab_debug options. Blocks are delimited by ';'
 *
 * @str:    start of block
 * @flags:  returns parsed flags, or DEBUG_DEFAULT_FLAGS if none specified
 * @slabs:  return start of list of slabs, or NULL when there's no list
 * @init:   assume this is initial parsing and not per-kmem-create parsing
 *
 * returns the start of next block if there's any, or NULL
 */
static char *
parse_slub_debug_flags(char *str, slab_flags_t *flags, char **slabs, bool init)
{
    PANIC("");
}

static inline bool slub_debug_orig_size(struct kmem_cache *s)
{
    return (kmem_cache_debug_flags(s, SLAB_STORE_USER) &&
            (s->flags & SLAB_KMALLOC));
}

static __fastpath_inline
struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s, gfp_t flags)
{
    flags &= gfp_allowed_mask;

    might_alloc(flags);

    if (unlikely(should_failslab(s, flags)))
        return NULL;

    return s;
}

static inline void
alloc_tagging_slab_alloc_hook(struct kmem_cache *s, void *object, gfp_t flags)
{
}

static inline void
alloc_tagging_slab_free_hook(struct kmem_cache *s, struct slab *slab, void **p,
                 int objects)
{
}

static inline bool memcg_slab_post_alloc_hook(struct kmem_cache *s,
                          struct list_lru *lru,
                          gfp_t flags, size_t size,
                          void **p)
{
    return true;
}

static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
                    void **p, int objects)
{
}

static inline bool memcg_slab_post_charge(void *p, gfp_t flags)
{
    return true;
}

static __fastpath_inline
bool slab_post_alloc_hook(struct kmem_cache *s, struct list_lru *lru,
              gfp_t flags, size_t size, void **p, bool init,
              unsigned int orig_size)
{
    unsigned int zero_size = s->object_size;
    bool kasan_init = init;
    size_t i;
    gfp_t init_flags = flags & gfp_allowed_mask;

    /*
     * For kmalloc object, the allocated memory size(object_size) is likely
     * larger than the requested size(orig_size). If redzone check is
     * enabled for the extra space, don't zero it, as it will be redzoned
     * soon. The redzone operation for this extra space could be seen as a
     * replacement of current poisoning under certain debug option, and
     * won't break other sanity checks.
     */
    if (kmem_cache_debug_flags(s, SLAB_STORE_USER | SLAB_RED_ZONE) &&
        (s->flags & SLAB_KMALLOC))
        zero_size = orig_size;

    /*
     * When slab_debug is enabled, avoid memory initialization integrated
     * into KASAN and instead zero out the memory via the memset below with
     * the proper size. Otherwise, KASAN might overwrite SLUB redzones and
     * cause false-positive reports. This does not lead to a performance
     * penalty on production builds, as slab_debug is not intended to be
     * enabled there.
     */
    if (__slub_debug_enabled())
        kasan_init = false;

    /*
     * As memory initialization might be integrated into KASAN,
     * kasan_slab_alloc and initialization memset must be
     * kept together to avoid discrepancies in behavior.
     *
     * As p[i] might get tagged, memset and kmemleak hook come after KASAN.
     */
    for (i = 0; i < size; i++) {
        p[i] = kasan_slab_alloc(s, p[i], init_flags, kasan_init);
        if (p[i] && init && (!kasan_init ||
                     !kasan_has_integrated_init()))
            memset(p[i], 0, zero_size);
        kmemleak_alloc_recursive(p[i], s->object_size, 1,
                     s->flags, init_flags);
        kmsan_slab_alloc(s, p[i], init_flags);
        alloc_tagging_slab_alloc_hook(s, p[i], flags);
    }

    return memcg_slab_post_alloc_hook(s, lru, flags, size, p);
}

static inline void stat(const struct kmem_cache *s, enum stat_item si)
{
#ifdef CONFIG_SLUB_STATS
    /*
     * The rmw is racy on a preemptible kernel but this is acceptable, so
     * avoid this_cpu_add()'s irq-disable overhead.
     */
    raw_cpu_inc(s->cpu_slab->stat[si]);
#endif
}

static inline
void stat_add(const struct kmem_cache *s, enum stat_item si, int v)
{
#ifdef CONFIG_SLUB_STATS
    raw_cpu_add(s->cpu_slab->stat[si], v);
#endif
}

static inline bool
__update_freelist_fast(struct slab *slab,
              void *freelist_old, unsigned long counters_old,
              void *freelist_new, unsigned long counters_new)
{
#ifdef system_has_freelist_aba
    freelist_aba_t old = { .freelist = freelist_old, .counter = counters_old };
    freelist_aba_t new = { .freelist = freelist_new, .counter = counters_new };

    return try_cmpxchg_freelist(&slab->freelist_counter.full, &old.full, new.full);
#else
    return false;
#endif
}

/*
 * Per slab locking using the pagelock
 */
static __always_inline void slab_lock(struct slab *slab)
{
    bit_spin_lock(PG_locked, &slab->__page_flags);
}

static __always_inline void slab_unlock(struct slab *slab)
{
    bit_spin_unlock(PG_locked, &slab->__page_flags);
}

static inline bool
__update_freelist_slow(struct slab *slab,
              void *freelist_old, unsigned long counters_old,
              void *freelist_new, unsigned long counters_new)
{
    bool ret = false;

    slab_lock(slab);
    if (slab->freelist == freelist_old &&
        slab->counters == counters_old) {
        slab->freelist = freelist_new;
        slab->counters = counters_new;
        ret = true;
    }
    slab_unlock(slab);

    return ret;
}

/*
 * Interrupts must be disabled (for the fallback code to work right), typically
 * by an _irqsave() lock variant. On PREEMPT_RT the preempt_disable(), which is
 * part of bit_spin_lock(), is sufficient because the policy is not to allow any
 * allocation/ free operation in hardirq context. Therefore nothing can
 * interrupt the operation.
 */
static inline bool __slab_update_freelist(struct kmem_cache *s, struct slab *slab,
        void *freelist_old, unsigned long counters_old,
        void *freelist_new, unsigned long counters_new,
        const char *n)
{
    bool ret;

    if (USE_LOCKLESS_FAST_PATH())
        lockdep_assert_irqs_disabled();

    if (s->flags & __CMPXCHG_DOUBLE) {
        ret = __update_freelist_fast(slab, freelist_old, counters_old,
                            freelist_new, counters_new);
    } else {
        ret = __update_freelist_slow(slab, freelist_old, counters_old,
                            freelist_new, counters_new);
    }
    if (likely(ret))
        return true;

    cpu_relax();
    stat(s, CMPXCHG_DOUBLE_FAIL);

#ifdef SLUB_DEBUG_CMPXCHG
    pr_info("%s %s: cmpxchg double redo ", n, s->name);
#endif

    return false;
}

static inline bool slab_update_freelist(struct kmem_cache *s, struct slab *slab,
        void *freelist_old, unsigned long counters_old,
        void *freelist_new, unsigned long counters_new,
        const char *n)
{
    bool ret;

    if (s->flags & __CMPXCHG_DOUBLE) {
        ret = __update_freelist_fast(slab, freelist_old, counters_old,
                            freelist_new, counters_new);
    } else {
        unsigned long flags;

        local_irq_save(flags);
        ret = __update_freelist_slow(slab, freelist_old, counters_old,
                            freelist_new, counters_new);
        local_irq_restore(flags);
    }
    if (likely(ret))
        return true;

    cpu_relax();
    stat(s, CMPXCHG_DOUBLE_FAIL);

#ifdef SLUB_DEBUG_CMPXCHG
    pr_info("%s %s: cmpxchg double redo ", n, s->name);
#endif

    return false;
}

/*
 * Check the slab->freelist and either transfer the freelist to the
 * per cpu freelist or deactivate the slab.
 *
 * The slab is still frozen if the return value is not NULL.
 *
 * If this function returns NULL then the slab has been unfrozen.
 */
static inline void *get_freelist(struct kmem_cache *s, struct slab *slab)
{
    struct slab new;
    unsigned long counters;
    void *freelist;

    lockdep_assert_held(this_cpu_ptr(&s->cpu_slab->lock));

    do {
        freelist = slab->freelist;
        counters = slab->counters;

        new.counters = counters;

        new.inuse = slab->objects;
        new.frozen = freelist != NULL;

    } while (!__slab_update_freelist(s, slab,
        freelist, counters,
        NULL, new.counters,
        "get_freelist"));

    return freelist;
}

/*
 * Returns freelist pointer (ptr). With hardening, this is obfuscated
 * with an XOR of the address where the pointer is held and a per-cache
 * random number.
 */
static inline freeptr_t freelist_ptr_encode(const struct kmem_cache *s,
                        void *ptr, unsigned long ptr_addr)
{
    unsigned long encoded;

#ifdef CONFIG_SLAB_FREELIST_HARDENED
    encoded = (unsigned long)ptr ^ s->random ^ swab(ptr_addr);
#else
    encoded = (unsigned long)ptr;
#endif
    return (freeptr_t){.v = encoded};
}

static inline void *freelist_ptr_decode(const struct kmem_cache *s,
                    freeptr_t ptr, unsigned long ptr_addr)
{
    void *decoded;

#ifdef CONFIG_SLAB_FREELIST_HARDENED
    decoded = (void *)(ptr.v ^ s->random ^ swab(ptr_addr));
#else
    decoded = (void *)ptr.v;
#endif
    return decoded;
}

static inline void *get_freepointer(struct kmem_cache *s, void *object)
{
    unsigned long ptr_addr;
    freeptr_t p;

    object = kasan_reset_tag(object);
    ptr_addr = (unsigned long)object + s->offset;
    p = *(freeptr_t *)(ptr_addr);
    return freelist_ptr_decode(s, p, ptr_addr);
}

/*
 * Finishes removing the cpu slab. Merges cpu's freelist with slab's freelist,
 * unfreezes the slabs and puts it on the proper list.
 * Assumes the slab has been already safely taken away from kmem_cache_cpu
 * by the caller.
 */
static void deactivate_slab(struct kmem_cache *s, struct slab *slab,
                void *freelist)
{
    PANIC("");
}

#ifdef CONFIG_SLUB_CPU_PARTIAL
static void __put_partials(struct kmem_cache *s, struct slab *partial_slab)
{
    PANIC("");
}
#endif

static inline bool slab_add_kunit_errors(void) { return false; }

static void print_slab_info(const struct slab *slab)
{
    pr_err("Slab 0x%p objects=%u used=%u fp=0x%p flags=%pGp\n",
           slab, slab->objects, slab->inuse, slab->freelist,
           &slab->__page_flags);
}

static void slab_bug(struct kmem_cache *s, char *fmt, ...)
{
    struct va_format vaf;
    va_list args;

    va_start(args, fmt);
    vaf.fmt = fmt;
    vaf.va = &args;
    pr_err("=============================================================================\n");
    pr_err("BUG %s (%s): %pV\n", s->name, print_tainted(), &vaf);
    pr_err("-----------------------------------------------------------------------------\n\n");
    va_end(args);
}

__printf(2, 3)
static void slab_fix(struct kmem_cache *s, char *fmt, ...)
{
    struct va_format vaf;
    va_list args;

    if (slab_add_kunit_errors())
        return;

    va_start(args, fmt);
    vaf.fmt = fmt;
    vaf.va = &args;
    pr_err("FIX %s: %pV\n", s->name, &vaf);
    va_end(args);
}

static __printf(3, 4) void slab_err(struct kmem_cache *s, struct slab *slab,
            const char *fmt, ...)
{
    va_list args;
    char buf[100];

    if (slab_add_kunit_errors())
        return;

    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    slab_bug(s, "%s", buf);
    print_slab_info(slab);
    dump_stack();
    add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
}

static inline unsigned int order_objects(unsigned int order, unsigned int size)
{
    return ((unsigned int)PAGE_SIZE << order) / size;
}

static inline unsigned int size_from_object(struct kmem_cache *s)
{
    if (s->flags & SLAB_RED_ZONE)
        return s->size - s->red_left_pad;

    return s->size;
}

static inline void *restore_red_left(struct kmem_cache *s, void *p)
{
    if (s->flags & SLAB_RED_ZONE)
        p -= s->red_left_pad;

    return p;
}

/*
 * Object debugging
 */

/* Verify that a pointer has an address that is valid within a slab page */
static inline int check_valid_pointer(struct kmem_cache *s,
                struct slab *slab, void *object)
{
    void *base;

    if (!object)
        return 1;

    base = slab_address(slab);
    object = kasan_reset_tag(object);
    object = restore_red_left(s, object);
    if (object < base || object >= base + slab->objects * s->size ||
        (object - base) % s->size) {
        return 0;
    }

    return 1;
}

static void print_section(char *level, char *text, u8 *addr,
              unsigned int length)
{
    metadata_access_enable();
    print_hex_dump(level, text, DUMP_PREFIX_ADDRESS,
            16, 1, kasan_reset_tag((void *)addr), length, 1);
    metadata_access_disable();
}

static void restore_bytes(struct kmem_cache *s, char *message, u8 data,
                        void *from, void *to)
{
    slab_fix(s, "Restoring %s 0x%p-0x%p=0x%x", message, from, to - 1, data);
    memset(from, data, to - from);
}

/* Check the pad bytes at the end of a slab page */
static pad_check_attributes void
slab_pad_check(struct kmem_cache *s, struct slab *slab)
{
    u8 *start;
    u8 *fault;
    u8 *end;
    u8 *pad;
    int length;
    int remainder;

    if (!(s->flags & SLAB_POISON))
        return;

    start = slab_address(slab);
    length = slab_size(slab);
    end = start + length;
    remainder = length % s->size;
    if (!remainder)
        return;

    pad = end - remainder;
    metadata_access_enable();
    fault = memchr_inv(kasan_reset_tag(pad), POISON_INUSE, remainder);
    metadata_access_disable();
    if (!fault)
        return;
    while (end > fault && end[-1] == POISON_INUSE)
        end--;

    slab_err(s, slab, "Padding overwritten. 0x%p-0x%p @offset=%tu",
            fault, end - 1, fault - start);
    print_section(KERN_ERR, "Padding ", pad, remainder);

    restore_bytes(s, "slab padding", POISON_INUSE, fault, end);
}

static int check_slab(struct kmem_cache *s, struct slab *slab)
{
    int maxobj;

    if (!folio_test_slab(slab_folio(slab))) {
        slab_err(s, slab, "Not a valid slab page");
        return 0;
    }

    maxobj = order_objects(slab_order(slab), s->size);
    if (slab->objects > maxobj) {
        slab_err(s, slab, "objects %u > max %u",
            slab->objects, maxobj);
        return 0;
    }
    if (slab->inuse > slab->objects) {
        slab_err(s, slab, "inuse %u > max %u",
            slab->inuse, slab->objects);
        return 0;
    }
    if (slab->frozen) {
        slab_err(s, slab, "Slab disabled since SLUB metadata consistency check failed");
        return 0;
    }

    /* Slab_pad_check fixes things up after itself */
    slab_pad_check(s, slab);
    return 1;
}

/*
 * See comment in calculate_sizes().
 */
static inline bool freeptr_outside_object(struct kmem_cache *s)
{
    return s->offset >= s->inuse;
}

/*
 * Return offset of the end of info block which is inuse + free pointer if
 * not overlapping with object.
 */
static inline unsigned int get_info_end(struct kmem_cache *s)
{
    if (freeptr_outside_object(s))
        return s->inuse + sizeof(void *);
    else
        return s->inuse;
}

static void print_track(const char *s, struct track *t, unsigned long pr_time)
{
    depot_stack_handle_t handle __maybe_unused;

    if (!t->addr)
        return;

    pr_err("%s in %pS age=%lu cpu=%u pid=%d\n",
           s, (void *)t->addr, pr_time - t->when, t->cpu, t->pid);
#ifdef CONFIG_STACKDEPOT
    handle = READ_ONCE(t->handle);
    if (handle)
        stack_depot_print(handle);
    else
        pr_err("object allocation/free stack trace missing\n");
#endif
}

static struct track *get_track(struct kmem_cache *s, void *object,
    enum track_item alloc)
{
    struct track *p;

    p = object + get_info_end(s);

    return kasan_reset_tag(p + alloc);
}

void print_tracking(struct kmem_cache *s, void *object)
{
    unsigned long pr_time = jiffies;
    if (!(s->flags & SLAB_STORE_USER))
        return;

    print_track("Allocated", get_track(s, object, TRACK_ALLOC), pr_time);
    print_track("Freed", get_track(s, object, TRACK_FREE), pr_time);
}

static void print_trailer(struct kmem_cache *s, struct slab *slab, u8 *p)
{
    unsigned int off;   /* Offset of last byte */
    u8 *addr = slab_address(slab);

    print_tracking(s, p);

    print_slab_info(slab);

    pr_err("Object 0x%p @offset=%tu fp=0x%p\n\n",
           p, p - addr, get_freepointer(s, p));

    if (s->flags & SLAB_RED_ZONE)
        print_section(KERN_ERR, "Redzone  ", p - s->red_left_pad,
                  s->red_left_pad);
    else if (p > addr + 16)
        print_section(KERN_ERR, "Bytes b4 ", p - 16, 16);

    print_section(KERN_ERR,         "Object   ", p,
              min_t(unsigned int, s->object_size, PAGE_SIZE));
    if (s->flags & SLAB_RED_ZONE)
        print_section(KERN_ERR, "Redzone  ", p + s->object_size,
            s->inuse - s->object_size);

    off = get_info_end(s);

    if (s->flags & SLAB_STORE_USER)
        off += 2 * sizeof(struct track);

    if (slub_debug_orig_size(s))
        off += sizeof(unsigned int);

    off += kasan_metadata_size(s, false);

    if (off != size_from_object(s))
        /* Beginning of the filler is the free pointer */
        print_section(KERN_ERR, "Padding  ", p + off,
                  size_from_object(s) - off);

    dump_stack();
}

static void object_err(struct kmem_cache *s, struct slab *slab,
            u8 *object, char *reason)
{
    if (slab_add_kunit_errors())
        return;

    slab_bug(s, "%s", reason);
    print_trailer(s, slab, object);
    add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
}

static pad_check_attributes int
check_bytes_and_report(struct kmem_cache *s, struct slab *slab,
               u8 *object, char *what,
               u8 *start, unsigned int value, unsigned int bytes)
{
    u8 *fault;
    u8 *end;
    u8 *addr = slab_address(slab);

    metadata_access_enable();
    fault = memchr_inv(kasan_reset_tag(start), value, bytes);
    metadata_access_disable();
    if (!fault)
        return 1;

    end = start + bytes;
    while (end > fault && end[-1] == value)
        end--;

    if (slab_add_kunit_errors())
        goto skip_bug_print;

    slab_bug(s, "%s overwritten", what);
    pr_err("0x%p-0x%p @offset=%tu. First byte 0x%x instead of 0x%x\n",
                    fault, end - 1, fault - addr,
                    fault[0], value);

skip_bug_print:
    restore_bytes(s, what, value, fault, end);
    return 0;
}

static inline unsigned int get_orig_size(struct kmem_cache *s, void *object)
{
    void *p = kasan_reset_tag(object);

    if (!slub_debug_orig_size(s))
        return s->object_size;

    p += get_info_end(s);
    p += sizeof(struct track) * 2;

    return *(unsigned int *)p;
}

/*
 * Object layout:
 *
 * object address
 *  Bytes of the object to be managed.
 *  If the freepointer may overlay the object then the free
 *  pointer is at the middle of the object.
 *
 *  Poisoning uses 0x6b (POISON_FREE) and the last byte is
 *  0xa5 (POISON_END)
 *
 * object + s->object_size
 *  Padding to reach word boundary. This is also used for Redzoning.
 *  Padding is extended by another word if Redzoning is enabled and
 *  object_size == inuse.
 *
 *  We fill with 0xbb (SLUB_RED_INACTIVE) for inactive objects and with
 *  0xcc (SLUB_RED_ACTIVE) for objects in use.
 *
 * object + s->inuse
 *  Meta data starts here.
 *
 *  A. Free pointer (if we cannot overwrite object on free)
 *  B. Tracking data for SLAB_STORE_USER
 *  C. Original request size for kmalloc object (SLAB_STORE_USER enabled)
 *  D. Padding to reach required alignment boundary or at minimum
 *      one word if debugging is on to be able to detect writes
 *      before the word boundary.
 *
 *  Padding is done using 0x5a (POISON_INUSE)
 *
 * object + s->size
 *  Nothing is used beyond s->size.
 *
 * If slabcaches are merged then the object_size and inuse boundaries are mostly
 * ignored. And therefore no slab options that rely on these boundaries
 * may be used with merged slabcaches.
 */

static int check_pad_bytes(struct kmem_cache *s, struct slab *slab, u8 *p)
{
    unsigned long off = get_info_end(s);    /* The end of info */

    if (s->flags & SLAB_STORE_USER) {
        /* We also have user information there */
        off += 2 * sizeof(struct track);

        if (s->flags & SLAB_KMALLOC)
            off += sizeof(unsigned int);
    }

    off += kasan_metadata_size(s, false);

    if (size_from_object(s) == off)
        return 1;

    return check_bytes_and_report(s, slab, p, "Object padding",
            p + off, POISON_INUSE, size_from_object(s) - off);
}

static inline void set_freepointer(struct kmem_cache *s, void *object, void *fp)
{
    unsigned long freeptr_addr = (unsigned long)object + s->offset;

#ifdef CONFIG_SLAB_FREELIST_HARDENED
    BUG_ON(object == fp); /* naive detection of double free or corruption */
#endif

    freeptr_addr = (unsigned long)kasan_reset_tag((void *)freeptr_addr);
    *(freeptr_t *)freeptr_addr = freelist_ptr_encode(s, fp, freeptr_addr);
}

static int check_object(struct kmem_cache *s, struct slab *slab,
                    void *object, u8 val)
{
    u8 *p = object;
    u8 *endobject = object + s->object_size;
    unsigned int orig_size, kasan_meta_size;
    int ret = 1;

    if (s->flags & SLAB_RED_ZONE) {
        if (!check_bytes_and_report(s, slab, object, "Left Redzone",
            object - s->red_left_pad, val, s->red_left_pad))
            ret = 0;

        if (!check_bytes_and_report(s, slab, object, "Right Redzone",
            endobject, val, s->inuse - s->object_size))
            ret = 0;

        if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
            orig_size = get_orig_size(s, object);

            if (s->object_size > orig_size  &&
                !check_bytes_and_report(s, slab, object,
                    "kmalloc Redzone", p + orig_size,
                    val, s->object_size - orig_size)) {
                ret = 0;
            }
        }
    } else {
        if ((s->flags & SLAB_POISON) && s->object_size < s->inuse) {
            if (!check_bytes_and_report(s, slab, p, "Alignment padding",
                endobject, POISON_INUSE,
                s->inuse - s->object_size))
                ret = 0;
        }
    }

    if (s->flags & SLAB_POISON) {
        if (val != SLUB_RED_ACTIVE && (s->flags & __OBJECT_POISON)) {
            /*
             * KASAN can save its free meta data inside of the
             * object at offset 0. Thus, skip checking the part of
             * the redzone that overlaps with the meta data.
             */
            kasan_meta_size = kasan_metadata_size(s, true);
            if (kasan_meta_size < s->object_size - 1 &&
                !check_bytes_and_report(s, slab, p, "Poison",
                    p + kasan_meta_size, POISON_FREE,
                    s->object_size - kasan_meta_size - 1))
                ret = 0;
            if (kasan_meta_size < s->object_size &&
                !check_bytes_and_report(s, slab, p, "End Poison",
                    p + s->object_size - 1, POISON_END, 1))
                ret = 0;
        }
        /*
         * check_pad_bytes cleans up on its own.
         */
        if (!check_pad_bytes(s, slab, p))
            ret = 0;
    }

    /*
     * Cannot check freepointer while object is allocated if
     * object and freepointer overlap.
     */
    if ((freeptr_outside_object(s) || val != SLUB_RED_ACTIVE) &&
        !check_valid_pointer(s, slab, get_freepointer(s, p))) {
        object_err(s, slab, p, "Freepointer corrupt");
        /*
         * No choice but to zap it and thus lose the remainder
         * of the free objects in this slab. May cause
         * another error because the object count is now wrong.
         */
        set_freepointer(s, p, NULL);
        ret = 0;
    }

    if (!ret && !slab_in_kunit_test()) {
        print_trailer(s, slab, object);
        add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
    }

    return ret;
}

static inline int alloc_consistency_checks(struct kmem_cache *s,
                    struct slab *slab, void *object)
{
    if (!check_slab(s, slab))
        return 0;

    if (!check_valid_pointer(s, slab, object)) {
        object_err(s, slab, object, "Freelist Pointer check fails");
        return 0;
    }

    if (!check_object(s, slab, object, SLUB_RED_INACTIVE))
        return 0;

    return 1;
}

static void trace(struct kmem_cache *s, struct slab *slab, void *object,
                                int alloc)
{
    if (s->flags & SLAB_TRACE) {
        pr_info("TRACE %s %s 0x%p inuse=%d fp=0x%p\n",
            s->name,
            alloc ? "alloc" : "free",
            object, slab->inuse,
            slab->freelist);

        if (!alloc)
            print_section(KERN_INFO, "Object ", (void *)object,
                    s->object_size);

        dump_stack();
    }
}

/*
 * kmalloc caches has fixed sizes (mostly power of 2), and kmalloc() API
 * family will round up the real request size to these fixed ones, so
 * there could be an extra area than what is requested. Save the original
 * request size in the meta data area, for better debug and sanity check.
 */
static inline void set_orig_size(struct kmem_cache *s,
                void *object, unsigned int orig_size)
{
    void *p = kasan_reset_tag(object);
    unsigned int kasan_meta_size;

    if (!slub_debug_orig_size(s))
        return;

    /*
     * KASAN can save its free meta data inside of the object at offset 0.
     * If this meta data size is larger than 'orig_size', it will overlap
     * the data redzone in [orig_size+1, object_size]. Thus, we adjust
     * 'orig_size' to be as at least as big as KASAN's meta data.
     */
    kasan_meta_size = kasan_metadata_size(s, true);
    if (kasan_meta_size > orig_size)
        orig_size = kasan_meta_size;

    p += get_info_end(s);
    p += sizeof(struct track) * 2;

    *(unsigned int *)p = orig_size;
}

static void init_object(struct kmem_cache *s, void *object, u8 val)
{
    u8 *p = kasan_reset_tag(object);
    unsigned int poison_size = s->object_size;

    if (s->flags & SLAB_RED_ZONE) {
        /*
         * Here and below, avoid overwriting the KMSAN shadow. Keeping
         * the shadow makes it possible to distinguish uninit-value
         * from use-after-free.
         */
        memset_no_sanitize_memory(p - s->red_left_pad, val,
                      s->red_left_pad);

        if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
            /*
             * Redzone the extra allocated space by kmalloc than
             * requested, and the poison size will be limited to
             * the original request size accordingly.
             */
            poison_size = get_orig_size(s, object);
        }
    }

    if (s->flags & __OBJECT_POISON) {
        memset_no_sanitize_memory(p, POISON_FREE, poison_size - 1);
        memset_no_sanitize_memory(p + poison_size - 1, POISON_END, 1);
    }

    if (s->flags & SLAB_RED_ZONE)
        memset_no_sanitize_memory(p + poison_size, val,
                      s->inuse - poison_size);
}

static noinline bool alloc_debug_processing(struct kmem_cache *s,
            struct slab *slab, void *object, int orig_size)
{
    if (s->flags & SLAB_CONSISTENCY_CHECKS) {
        if (!alloc_consistency_checks(s, slab, object))
            goto bad;
    }

    /* Success. Perform special debug activities for allocs */
    trace(s, slab, object, 1);
    set_orig_size(s, object, orig_size);
    init_object(s, object, SLUB_RED_ACTIVE);
    return true;

bad:
    if (folio_test_slab(slab_folio(slab))) {
        /*
         * If this is a slab page then lets do the best we can
         * to avoid issues in the future. Marking all objects
         * as used avoids touching the remaining objects.
         */
        slab_fix(s, "Marking all objects used");
        slab->inuse = slab->objects;
        slab->freelist = NULL;
        slab->frozen = 1; /* mark consistency-failed slab as frozen */
    }
    return false;
}

static inline void slab_set_node_partial(struct slab *slab)
{
    set_bit(PG_workingset, folio_flags(slab_folio(slab), 0));
}

/*
 * Management of partially allocated slabs.
 */
static inline void
__add_partial(struct kmem_cache_node *n, struct slab *slab, int tail)
{
    n->nr_partial++;
    if (tail == DEACTIVATE_TO_TAIL)
        list_add_tail(&slab->slab_list, &n->partial);
    else
        list_add(&slab->slab_list, &n->partial);
    slab_set_node_partial(slab);
}

static inline void add_partial(struct kmem_cache_node *n,
                struct slab *slab, int tail)
{
    lockdep_assert_held(&n->list_lock);
    __add_partial(n, slab, tail);
}

static inline void slab_clear_node_partial(struct slab *slab)
{
    clear_bit(PG_workingset, folio_flags(slab_folio(slab), 0));
}

static inline void remove_partial(struct kmem_cache_node *n,
                    struct slab *slab)
{
    lockdep_assert_held(&n->list_lock);
    list_del(&slab->slab_list);
    slab_clear_node_partial(slab);
    n->nr_partial--;
}

/*
 * Tracking of fully allocated slabs for debugging purposes.
 */
static void add_full(struct kmem_cache *s,
    struct kmem_cache_node *n, struct slab *slab)
{
    if (!(s->flags & SLAB_STORE_USER))
        return;

    lockdep_assert_held(&n->list_lock);
    list_add(&slab->slab_list, &n->full);
}

static void remove_full(struct kmem_cache *s, struct kmem_cache_node *n, struct slab *slab)
{
    if (!(s->flags & SLAB_STORE_USER))
        return;

    lockdep_assert_held(&n->list_lock);
    list_del(&slab->slab_list);
}

/*
 * Called only for kmem_cache_debug() caches instead of remove_partial(), with a
 * slab from the n->partial list. Remove only a single object from the slab, do
 * the alloc_debug_processing() checks and leave the slab on the list, or move
 * it to full list if it was the last free object.
 */
static void *alloc_single_from_partial(struct kmem_cache *s,
        struct kmem_cache_node *n, struct slab *slab, int orig_size)
{
    void *object;

    lockdep_assert_held(&n->list_lock);

    object = slab->freelist;
    slab->freelist = get_freepointer(s, object);
    slab->inuse++;

    if (!alloc_debug_processing(s, slab, object, orig_size)) {
        if (folio_test_slab(slab_folio(slab)))
            remove_partial(n, slab);
        return NULL;
    }

    if (slab->inuse == slab->objects) {
        remove_partial(n, slab);
        add_full(s, n, slab);
    }

    return object;
}

#ifdef CONFIG_SLUB_CPU_PARTIAL
static void put_cpu_partial(struct kmem_cache *s, struct slab *slab, int drain);
#else
static inline void put_cpu_partial(struct kmem_cache *s, struct slab *slab,
                   int drain) { }
#endif

/*
 * Try to allocate a partial slab from a specific node.
 */
static struct slab *get_partial_node(struct kmem_cache *s,
                     struct kmem_cache_node *n,
                     struct partial_context *pc)
{
    struct slab *slab, *slab2, *partial = NULL;
    unsigned long flags;
    unsigned int partial_slabs = 0;

    /*
     * Racy check. If we mistakenly see no partial slabs then we
     * just allocate an empty slab. If we mistakenly try to get a
     * partial slab and there is none available then get_partial()
     * will return NULL.
     */
    if (!n || !n->nr_partial)
        return NULL;

    spin_lock_irqsave(&n->list_lock, flags);
    list_for_each_entry_safe(slab, slab2, &n->partial, slab_list) {
        if (!pfmemalloc_match(slab, pc->flags))
            continue;

        if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
            void *object = alloc_single_from_partial(s, n, slab,
                            pc->orig_size);
            if (object) {
                partial = slab;
                pc->object = object;
                break;
            }
            continue;
        }

        remove_partial(n, slab);

        if (!partial) {
            partial = slab;
            stat(s, ALLOC_FROM_PARTIAL);

            if ((slub_get_cpu_partial(s) == 0)) {
                break;
            }
        } else {
            put_cpu_partial(s, slab, 0);
            stat(s, CPU_PARTIAL_NODE);

            if (++partial_slabs > slub_get_cpu_partial(s) / 2) {
                break;
            }
        }
    }
    spin_unlock_irqrestore(&n->list_lock, flags);
    return partial;
}

/*
 * Get a slab from somewhere. Search in increasing NUMA distances.
 */
static struct slab *get_any_partial(struct kmem_cache *s,
                    struct partial_context *pc)
{
    return NULL;
}

/*
 * Get a partial slab, lock it and return it.
 */
static struct slab *get_partial(struct kmem_cache *s, int node,
                struct partial_context *pc)
{
    struct slab *slab;
    int searchnode = node;

    if (node == NUMA_NO_NODE)
        searchnode = numa_mem_id();

    slab = get_partial_node(s, get_node(s, searchnode), pc);
    if (slab || (node != NUMA_NO_NODE && (pc->flags & __GFP_THISNODE)))
        return slab;

    return get_any_partial(s, pc);
}

static void set_track_update(struct kmem_cache *s, void *object,
                 enum track_item alloc, unsigned long addr,
                 depot_stack_handle_t handle)
{
    struct track *p = get_track(s, object, alloc);

#ifdef CONFIG_STACKDEPOT
    p->handle = handle;
#endif
    p->addr = addr;
    p->cpu = smp_processor_id();
    p->pid = current->pid;
    p->when = jiffies;
}

#ifdef CONFIG_STACKDEPOT
static noinline depot_stack_handle_t set_track_prepare(void)
{
    depot_stack_handle_t handle;
    unsigned long entries[TRACK_ADDRS_COUNT];
    unsigned int nr_entries;

    nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 3);
    handle = stack_depot_save(entries, nr_entries, GFP_NOWAIT);

    return handle;
}
#else
static inline depot_stack_handle_t set_track_prepare(void)
{
    return 0;
}
#endif

static __always_inline void set_track(struct kmem_cache *s, void *object,
                      enum track_item alloc, unsigned long addr)
{
    depot_stack_handle_t handle = set_track_prepare();

    set_track_update(s, object, alloc, addr, handle);
}

/*
 * Freeze the partial slab and return the pointer to the freelist.
 */
static inline void *freeze_slab(struct kmem_cache *s, struct slab *slab)
{
    struct slab new;
    unsigned long counters;
    void *freelist;

    do {
        freelist = slab->freelist;
        counters = slab->counters;

        new.counters = counters;
        VM_BUG_ON(new.frozen);

        new.inuse = slab->objects;
        new.frozen = 1;

    } while (!slab_update_freelist(s, slab,
        freelist, counters,
        NULL, new.counters,
        "freeze_slab"));

    return freelist;
}

#define MAX_PARTIAL_TO_SCAN 10000

static unsigned long count_partial_free_approx(struct kmem_cache_node *n)
{
    unsigned long flags;
    unsigned long x = 0;
    struct slab *slab;

    spin_lock_irqsave(&n->list_lock, flags);
    if (n->nr_partial <= MAX_PARTIAL_TO_SCAN) {
        list_for_each_entry(slab, &n->partial, slab_list)
            x += slab->objects - slab->inuse;
    } else {
        /*
         * For a long list, approximate the total count of objects in
         * it to meet the limit on the number of slabs to scan.
         * Scan from both the list's head and tail for better accuracy.
         */
        unsigned long scanned = 0;

        list_for_each_entry(slab, &n->partial, slab_list) {
            x += slab->objects - slab->inuse;
            if (++scanned == MAX_PARTIAL_TO_SCAN / 2)
                break;
        }
        list_for_each_entry_reverse(slab, &n->partial, slab_list) {
            x += slab->objects - slab->inuse;
            if (++scanned == MAX_PARTIAL_TO_SCAN)
                break;
        }
        x = mult_frac(x, n->nr_partial, scanned);
        x = min(x, node_nr_objs(n));
    }
    spin_unlock_irqrestore(&n->list_lock, flags);
    return x;
}

static noinline void
slab_out_of_memory(struct kmem_cache *s, gfp_t gfpflags, int nid)
{
    static DEFINE_RATELIMIT_STATE(slub_oom_rs, DEFAULT_RATELIMIT_INTERVAL,
                      DEFAULT_RATELIMIT_BURST);
    int cpu = raw_smp_processor_id();
    int node;
    struct kmem_cache_node *n;

    if ((gfpflags & __GFP_NOWARN) || !__ratelimit(&slub_oom_rs))
        return;

    pr_warn("SLUB: Unable to allocate memory on CPU %u (of node %d) on node %d, gfp=%#x(%pGg)\n",
        cpu, cpu_to_node(cpu), nid, gfpflags, &gfpflags);
    pr_warn("  cache: %s, object size: %u, buffer size: %u, default order: %u, min order: %u\n",
        s->name, s->object_size, s->size, oo_order(s->oo),
        oo_order(s->min));

    if (oo_order(s->min) > get_order(s->object_size))
        pr_warn("  %s debugging increased min order, use slab_debug=O to disable.\n",
            s->name);

    for_each_kmem_cache_node(s, node, n) {
        unsigned long nr_slabs;
        unsigned long nr_objs;
        unsigned long nr_free;

        nr_free  = count_partial_free_approx(n);
        nr_slabs = node_nr_slabs(n);
        nr_objs  = node_nr_objs(n);

        pr_warn("  node %d: slabs: %ld, objs: %ld, free: %ld\n",
            node, nr_slabs, nr_objs, nr_free);
    }
}

static inline void inc_slabs_node(struct kmem_cache *s, int node, int objects)
{
    struct kmem_cache_node *n = get_node(s, node);

    atomic_long_inc(&n->nr_slabs);
    atomic_long_add(objects, &n->total_objects);
}
static inline void dec_slabs_node(struct kmem_cache *s, int node, int objects)
{
    struct kmem_cache_node *n = get_node(s, node);

    atomic_long_dec(&n->nr_slabs);
    atomic_long_sub(objects, &n->total_objects);
}

/*
 * Called only for kmem_cache_debug() caches to allocate from a freshly
 * allocated slab. Allocate a single object instead of whole freelist
 * and put the slab to the partial (or full) list.
 */
static void *alloc_single_from_new_slab(struct kmem_cache *s,
                    struct slab *slab, int orig_size)
{
    int nid = slab_nid(slab);
    struct kmem_cache_node *n = get_node(s, nid);
    unsigned long flags;
    void *object;


    object = slab->freelist;
    slab->freelist = get_freepointer(s, object);
    slab->inuse = 1;

    if (!alloc_debug_processing(s, slab, object, orig_size))
        /*
         * It's not really expected that this would fail on a
         * freshly allocated slab, but a concurrent memory
         * corruption in theory could cause that.
         */
        return NULL;

    spin_lock_irqsave(&n->list_lock, flags);

    if (slab->inuse == slab->objects)
        add_full(s, n, slab);
    else
        add_partial(n, slab, DEACTIVATE_TO_HEAD);

    inc_slabs_node(s, nid, slab->objects);
    spin_unlock_irqrestore(&n->list_lock, flags);

    return object;
}

/*
 * Slow path. The lockless freelist is empty or we need to perform
 * debugging duties.
 *
 * Processing is still very fast if new objects have been freed to the
 * regular freelist. In that case we simply take over the regular freelist
 * as the lockless freelist and zap the regular freelist.
 *
 * If that is not working then we fall back to the partial lists. We take the
 * first element of the freelist as the object to allocate now and move the
 * rest of the freelist to the lockless freelist.
 *
 * And if we were unable to get a new slab from the partial slab lists then
 * we need to allocate a new slab. This is the slowest path since it involves
 * a call to the page allocator and the setup of a new slab.
 *
 * Version of __slab_alloc to use when we know that preemption is
 * already disabled (which is the case for bulk allocation).
 */
static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
              unsigned long addr, struct kmem_cache_cpu *c, unsigned int orig_size)
{
    void *freelist;
    struct slab *slab;
    unsigned long flags;
    struct partial_context pc;
    bool try_thisnode = true;

    stat(s, ALLOC_SLOWPATH);

reread_slab:

    slab = READ_ONCE(c->slab);
    if (!slab) {
        /*
         * if the node is not online or has no normal memory, just
         * ignore the node constraint
         */
        if (unlikely(node != NUMA_NO_NODE &&
                 !node_isset(node, slab_nodes)))
            node = NUMA_NO_NODE;
        goto new_slab;
    }

    if (unlikely(!node_match(slab, node))) {
        /*
         * same as above but node_match() being false already
         * implies node != NUMA_NO_NODE
         */
        if (!node_isset(node, slab_nodes)) {
            node = NUMA_NO_NODE;
        } else {
            stat(s, ALLOC_NODE_MISMATCH);
            goto deactivate_slab;
        }
    }

    /*
     * By rights, we should be searching for a slab page that was
     * PFMEMALLOC but right now, we are losing the pfmemalloc
     * information when the page leaves the per-cpu allocator
     */
    if (unlikely(!pfmemalloc_match(slab, gfpflags)))
        goto deactivate_slab;

    /* must check again c->slab in case we got preempted and it changed */
    local_lock_irqsave(&s->cpu_slab->lock, flags);
    if (unlikely(slab != c->slab)) {
        local_unlock_irqrestore(&s->cpu_slab->lock, flags);
        goto reread_slab;
    }
    freelist = c->freelist;
    if (freelist)
        goto load_freelist;

    freelist = get_freelist(s, slab);

    if (!freelist) {
        c->slab = NULL;
        c->tid = next_tid(c->tid);
        local_unlock_irqrestore(&s->cpu_slab->lock, flags);
        stat(s, DEACTIVATE_BYPASS);
        goto new_slab;
    }

    stat(s, ALLOC_REFILL);

load_freelist:

    lockdep_assert_held(this_cpu_ptr(&s->cpu_slab->lock));

    /*
     * freelist is pointing to the list of objects to be used.
     * slab is pointing to the slab from which the objects are obtained.
     * That slab must be frozen for per cpu allocations to work.
     */
    VM_BUG_ON(!c->slab->frozen);
    c->freelist = get_freepointer(s, freelist);
    c->tid = next_tid(c->tid);
    local_unlock_irqrestore(&s->cpu_slab->lock, flags);
    return freelist;

deactivate_slab:

    local_lock_irqsave(&s->cpu_slab->lock, flags);
    if (slab != c->slab) {
        local_unlock_irqrestore(&s->cpu_slab->lock, flags);
        goto reread_slab;
    }
    freelist = c->freelist;
    c->slab = NULL;
    c->freelist = NULL;
    c->tid = next_tid(c->tid);
    local_unlock_irqrestore(&s->cpu_slab->lock, flags);
    deactivate_slab(s, slab, freelist);

new_slab:

#ifdef CONFIG_SLUB_CPU_PARTIAL
    while (slub_percpu_partial(c)) {
        local_lock_irqsave(&s->cpu_slab->lock, flags);
        if (unlikely(c->slab)) {
            local_unlock_irqrestore(&s->cpu_slab->lock, flags);
            goto reread_slab;
        }
        if (unlikely(!slub_percpu_partial(c))) {
            local_unlock_irqrestore(&s->cpu_slab->lock, flags);
            /* we were preempted and partial list got empty */
            goto new_objects;
        }

        slab = slub_percpu_partial(c);
        slub_set_percpu_partial(c, slab);

        if (likely(node_match(slab, node) &&
               pfmemalloc_match(slab, gfpflags))) {
            c->slab = slab;
            freelist = get_freelist(s, slab);
            VM_BUG_ON(!freelist);
            stat(s, CPU_PARTIAL_ALLOC);
            goto load_freelist;
        }

        local_unlock_irqrestore(&s->cpu_slab->lock, flags);

        slab->next = NULL;
        __put_partials(s, slab);
    }
#endif

new_objects:

    pc.flags = gfpflags;
    /*
     * When a preferred node is indicated but no __GFP_THISNODE
     *
     * 1) try to get a partial slab from target node only by having
     *    __GFP_THISNODE in pc.flags for get_partial()
     * 2) if 1) failed, try to allocate a new slab from target node with
     *    GPF_NOWAIT | __GFP_THISNODE opportunistically
     * 3) if 2) failed, retry with original gfpflags which will allow
     *    get_partial() try partial lists of other nodes before potentially
     *    allocating new page from other nodes
     */
    if (unlikely(node != NUMA_NO_NODE && !(gfpflags & __GFP_THISNODE)
             && try_thisnode))
        pc.flags = GFP_NOWAIT | __GFP_THISNODE;

    pc.orig_size = orig_size;
    slab = get_partial(s, node, &pc);
    if (slab) {
        if (kmem_cache_debug(s)) {
            freelist = pc.object;
            /*
             * For debug caches here we had to go through
             * alloc_single_from_partial() so just store the
             * tracking info and return the object.
             */
            if (s->flags & SLAB_STORE_USER)
                set_track(s, freelist, TRACK_ALLOC, addr);

            return freelist;
        }

        freelist = freeze_slab(s, slab);
        goto retry_load_slab;
    }

    slub_put_cpu_ptr(s->cpu_slab);
    slab = new_slab(s, pc.flags, node);
    c = slub_get_cpu_ptr(s->cpu_slab);

    if (unlikely(!slab)) {
        if (node != NUMA_NO_NODE && !(gfpflags & __GFP_THISNODE)
            && try_thisnode) {
            try_thisnode = false;
            goto new_objects;
        }
        slab_out_of_memory(s, gfpflags, node);
        return NULL;
    }

    stat(s, ALLOC_SLAB);


    if (kmem_cache_debug(s)) {
        freelist = alloc_single_from_new_slab(s, slab, orig_size);

        if (unlikely(!freelist))
            goto new_objects;

        if (s->flags & SLAB_STORE_USER)
            set_track(s, freelist, TRACK_ALLOC, addr);

        return freelist;
    }

    /*
     * No other reference to the slab yet so we can
     * muck around with it freely without cmpxchg
     */
    freelist = slab->freelist;
    slab->freelist = NULL;
    slab->inuse = slab->objects;
    slab->frozen = 1;

    inc_slabs_node(s, slab_nid(slab), slab->objects);

    if (unlikely(!pfmemalloc_match(slab, gfpflags))) {
        /*
         * For !pfmemalloc_match() case we don't load freelist so that
         * we don't make further mismatched allocations easier.
         */
        deactivate_slab(s, slab, get_freepointer(s, freelist));
        return freelist;
    }

retry_load_slab:

    local_lock_irqsave(&s->cpu_slab->lock, flags);
    if (unlikely(c->slab)) {
        void *flush_freelist = c->freelist;
        struct slab *flush_slab = c->slab;

        c->slab = NULL;
        c->freelist = NULL;
        c->tid = next_tid(c->tid);

        local_unlock_irqrestore(&s->cpu_slab->lock, flags);

        deactivate_slab(s, flush_slab, flush_freelist);

        stat(s, CPUSLAB_FLUSH);

        goto retry_load_slab;
    }
    c->slab = slab;

    goto load_freelist;
}

/*
 * A wrapper for ___slab_alloc() for contexts where preemption is not yet
 * disabled. Compensates for possible cpu changes by refetching the per cpu area
 * pointer.
 */
static void *__slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
              unsigned long addr, struct kmem_cache_cpu *c, unsigned int orig_size)
{
    void *p;

#ifdef CONFIG_PREEMPT_COUNT
    /*
     * We may have been preempted and rescheduled on a different
     * cpu before disabling preemption. Need to reload cpu area
     * pointer.
     */
    c = slub_get_cpu_ptr(s->cpu_slab);
#endif

    p = ___slab_alloc(s, gfpflags, node, addr, c, orig_size);
#ifdef CONFIG_PREEMPT_COUNT
    slub_put_cpu_ptr(s->cpu_slab);
#endif
    return p;
}

/*
 * When running under KMSAN, get_freepointer_safe() may return an uninitialized
 * pointer value in the case the current thread loses the race for the next
 * memory chunk in the freelist. In that case this_cpu_cmpxchg_double() in
 * slab_alloc_node() will fail, so the uninitialized value won't be used, but
 * KMSAN will still check all arguments of cmpxchg because of imperfect
 * handling of inline assembly.
 * To work around this problem, we apply __no_kmsan_checks to ensure that
 * get_freepointer_safe() returns initialized memory.
 */
__no_kmsan_checks
static inline void *get_freepointer_safe(struct kmem_cache *s, void *object)
{
    unsigned long freepointer_addr;
    freeptr_t p;

    if (!debug_pagealloc_enabled_static())
        return get_freepointer(s, object);

    object = kasan_reset_tag(object);
    freepointer_addr = (unsigned long)object + s->offset;
    copy_from_kernel_nofault(&p, (freeptr_t *)freepointer_addr, sizeof(p));
    return freelist_ptr_decode(s, p, freepointer_addr);
}

static inline bool
__update_cpu_freelist_fast(struct kmem_cache *s,
               void *freelist_old, void *freelist_new,
               unsigned long tid)
{
    freelist_aba_t old = { .freelist = freelist_old, .counter = tid };
    freelist_aba_t new = { .freelist = freelist_new, .counter = next_tid(tid) };

    return this_cpu_try_cmpxchg_freelist(s->cpu_slab->freelist_tid.full,
                         &old.full, new.full);
}

static inline void note_cmpxchg_failure(const char *n,
        const struct kmem_cache *s, unsigned long tid)
{
#ifdef SLUB_DEBUG_CMPXCHG
    unsigned long actual_tid = __this_cpu_read(s->cpu_slab->tid);

    pr_info("%s %s: cmpxchg redo ", n, s->name);

#ifdef CONFIG_PREEMPTION
    if (tid_to_cpu(tid) != tid_to_cpu(actual_tid))
        pr_warn("due to cpu change %d -> %d\n",
            tid_to_cpu(tid), tid_to_cpu(actual_tid));
    else
#endif
    if (tid_to_event(tid) != tid_to_event(actual_tid))
        pr_warn("due to cpu running other code. Event %ld->%ld\n",
            tid_to_event(tid), tid_to_event(actual_tid));
    else
        pr_warn("for unknown reason: actual=%lx was=%lx target=%lx\n",
            actual_tid, tid, next_tid(tid));
#endif
    stat(s, CMPXCHG_DOUBLE_CPU_FAIL);
}

#ifndef CONFIG_SLUB_TINY
static void prefetch_freepointer(const struct kmem_cache *s, void *object)
{
    prefetchw(object + s->offset);
}
#endif

static __always_inline void *__slab_alloc_node(struct kmem_cache *s,
        gfp_t gfpflags, int node, unsigned long addr, size_t orig_size)
{
    struct kmem_cache_cpu *c;
    struct slab *slab;
    unsigned long tid;
    void *object;

redo:
    /*
     * Must read kmem_cache cpu data via this cpu ptr. Preemption is
     * enabled. We may switch back and forth between cpus while
     * reading from one cpu area. That does not matter as long
     * as we end up on the original cpu again when doing the cmpxchg.
     *
     * We must guarantee that tid and kmem_cache_cpu are retrieved on the
     * same cpu. We read first the kmem_cache_cpu pointer and use it to read
     * the tid. If we are preempted and switched to another cpu between the
     * two reads, it's OK as the two are still associated with the same cpu
     * and cmpxchg later will validate the cpu.
     */
    c = raw_cpu_ptr(s->cpu_slab);
    tid = READ_ONCE(c->tid);

    /*
     * Irqless object alloc/free algorithm used here depends on sequence
     * of fetching cpu_slab's data. tid should be fetched before anything
     * on c to guarantee that object and slab associated with previous tid
     * won't be used with current tid. If we fetch tid first, object and
     * slab could be one associated with next tid and our alloc/free
     * request will be failed. In this case, we will retry. So, no problem.
     */
    barrier();

    /*
     * The transaction ids are globally unique per cpu and per operation on
     * a per cpu queue. Thus they can be guarantee that the cmpxchg_double
     * occurs on the right processor and that there was no operation on the
     * linked list in between.
     */

    object = c->freelist;
    slab = c->slab;

    if (!USE_LOCKLESS_FAST_PATH() ||
        unlikely(!object || !slab || !node_match(slab, node))) {
        object = __slab_alloc(s, gfpflags, node, addr, c, orig_size);
    } else {
        void *next_object = get_freepointer_safe(s, object);

        /*
         * The cmpxchg will only match if there was no additional
         * operation and if we are on the right processor.
         *
         * The cmpxchg does the following atomically (without lock
         * semantics!)
         * 1. Relocate first pointer to the current per cpu area.
         * 2. Verify that tid and freelist have not been changed
         * 3. If they were not changed replace tid and freelist
         *
         * Since this is without lock semantics the protection is only
         * against code executing on this cpu *not* from access by
         * other cpus.
         */
        if (unlikely(!__update_cpu_freelist_fast(s, object, next_object, tid))) {
            note_cmpxchg_failure("slab_alloc", s, tid);
            goto redo;
        }
        prefetch_freepointer(s, next_object);
        stat(s, ALLOC_FASTPATH);
    }

    return object;
}

/*
 * If the object has been wiped upon free, make sure it's fully initialized by
 * zeroing out freelist pointer.
 *
 * Note that we also wipe custom freelist pointers.
 */
static __always_inline void maybe_wipe_obj_freeptr(struct kmem_cache *s,
                           void *obj)
{
    if (unlikely(slab_want_init_on_free(s)) && obj &&
        !freeptr_outside_object(s))
        memset((void *)((char *)kasan_reset_tag(obj) + s->offset),
            0, sizeof(void *));
}

/*
 * Inlined fastpath so that allocation functions (kmalloc, kmem_cache_alloc)
 * have the fastpath folded into their functions. So no function call
 * overhead for requests that can be satisfied on the fastpath.
 *
 * The fastpath works by first checking if the lockless freelist can be used.
 * If not then __slab_alloc is called for slow processing.
 *
 * Otherwise we can simply pick the next object from the lockless free list.
 */
static __fastpath_inline void *slab_alloc_node(struct kmem_cache *s, struct list_lru *lru,
        gfp_t gfpflags, int node, unsigned long addr, size_t orig_size)
{
    void *object;
    bool init = false;

    s = slab_pre_alloc_hook(s, gfpflags);
    if (unlikely(!s))
        return NULL;

    object = kfence_alloc(s, orig_size, gfpflags);
    if (unlikely(object))
        goto out;

    object = __slab_alloc_node(s, gfpflags, node, addr, orig_size);

    maybe_wipe_obj_freeptr(s, object);
    init = slab_want_init_on_alloc(gfpflags, s);

out:
    /*
     * When init equals 'true', like for kzalloc() family, only
     * @orig_size bytes might be zeroed instead of s->object_size
     * In case this fails due to memcg_slab_post_alloc_hook(),
     * object is set to NULL
     */
    slab_post_alloc_hook(s, lru, gfpflags, 1, &object, init, orig_size);

    return object;
}

void *__kmalloc_cache_noprof(struct kmem_cache *s, gfp_t gfpflags, size_t size)
{
    void *ret = slab_alloc_node(s, NULL, gfpflags, NUMA_NO_NODE,
                        _RET_IP_, size);

    trace_kmalloc(_RET_IP_, ret, size, s->size, gfpflags, NUMA_NO_NODE);

    ret = kasan_kmalloc(s, ret, size, gfpflags);
    return ret;
}

static __always_inline
void *__do_kmalloc_node(size_t size, kmem_buckets *b, gfp_t flags, int node,
            unsigned long caller)
{
    struct kmem_cache *s;
    void *ret;

    if (unlikely(size > KMALLOC_MAX_CACHE_SIZE)) {
        ret = __kmalloc_large_node_noprof(size, flags, node);
        trace_kmalloc(caller, ret, size,
                  PAGE_SIZE << get_order(size), flags, node);
        return ret;
    }

    if (unlikely(!size))
        return ZERO_SIZE_PTR;

    s = kmalloc_slab(size, b, flags, caller);

    ret = slab_alloc_node(s, NULL, flags, node, caller, size);
    ret = kasan_kmalloc(s, ret, size, flags);
    trace_kmalloc(caller, ret, size, s->size, flags, node);
    return ret;
}

void *__kmalloc_noprof(size_t size, gfp_t flags)
{
    return __do_kmalloc_node(size, NULL, flags, NUMA_NO_NODE, _RET_IP_);
}

void *__kmalloc_node_noprof(DECL_BUCKET_PARAMS(size, b), gfp_t flags, int node)
{
    return __do_kmalloc_node(size, PASS_BUCKET_PARAM(b), flags, node, _RET_IP_);
}

void *__kmalloc_node_track_caller_noprof(DECL_BUCKET_PARAMS(size, b), gfp_t flags,
                     int node, unsigned long caller)
{
    return __do_kmalloc_node(size, PASS_BUCKET_PARAM(b), flags, node, caller);

}

void *__kmalloc_cache_node_noprof(struct kmem_cache *s, gfp_t gfpflags,
                  int node, size_t size)
{
    void *ret = slab_alloc_node(s, NULL, gfpflags, node, _RET_IP_, size);

    trace_kmalloc(_RET_IP_, ret, size, s->size, gfpflags, node);

    ret = kasan_kmalloc(s, ret, size, gfpflags);
    return ret;
}

void *kmem_cache_alloc_node_noprof(struct kmem_cache *s, gfp_t gfpflags, int node)
{
    return kmem_cache_alloc_noprof(s, gfpflags);
}

void *kmem_cache_alloc_noprof(struct kmem_cache *s, gfp_t gfpflags)
{
    if (!s) {
        PANIC("Bad kmem_cache");
    }
    if (s->ctor && (gfpflags & __GFP_ZERO)) {
        PANIC("kmem_cache ctor conflicts with GFP_ZERO.");
    }
    pr_debug("%s: object_size(%u, %u) align(%u)",
             __func__, s->object_size, s->size, s->align);

    int align = s->align;
    if (align == 0) {
        align = 8;
    }
    void *ret = cl_rust_alloc(s->size, align);
    if (s->ctor) {
        s->ctor(ret);
    }
    if (gfpflags & __GFP_ZERO) {
        memset(ret, 0, s->size);
    }
    return ret;
}

void *kmem_cache_alloc_lru_noprof(struct kmem_cache *s, struct list_lru *lru,
               gfp_t gfpflags)
{
    return kmem_cache_alloc_noprof(s, gfpflags);
}

/*
 * Hooks for other subsystems that check memory allocations. In a typical
 * production configuration these hooks all should produce no code at all.
 *
 * Returns true if freeing of the object can proceed, false if its reuse
 * was delayed by CONFIG_SLUB_RCU_DEBUG or KASAN quarantine, or it was returned
 * to KFENCE.
 */
static __always_inline
bool slab_free_hook(struct kmem_cache *s, void *x, bool init,
            bool after_rcu_delay)
{
    /* Are the object contents still accessible? */
    bool still_accessible = (s->flags & SLAB_TYPESAFE_BY_RCU) && !after_rcu_delay;

    kmemleak_free_recursive(x, s->flags);
    kmsan_slab_free(s, x);

    debug_check_no_locks_freed(x, s->object_size);

    if (!(s->flags & SLAB_DEBUG_OBJECTS))
        debug_check_no_obj_freed(x, s->object_size);

    /* Use KCSAN to help debug racy use-after-free. */
    if (!still_accessible)
        __kcsan_check_access(x, s->object_size,
                     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);

    if (kfence_free(x))
        return false;

    /*
     * Give KASAN a chance to notice an invalid free operation before we
     * modify the object.
     */
    if (kasan_slab_pre_free(s, x))
        return false;

#ifdef CONFIG_SLUB_RCU_DEBUG
    if (still_accessible) {
        struct rcu_delayed_free *delayed_free;

        delayed_free = kmalloc(sizeof(*delayed_free), GFP_NOWAIT);
        if (delayed_free) {
            /*
             * Let KASAN track our call stack as a "related work
             * creation", just like if the object had been freed
             * normally via kfree_rcu().
             * We have to do this manually because the rcu_head is
             * not located inside the object.
             */
            kasan_record_aux_stack_noalloc(x);

            delayed_free->object = x;
            call_rcu(&delayed_free->head, slab_free_after_rcu_debug);
            return false;
        }
    }
#endif /* CONFIG_SLUB_RCU_DEBUG */

    /*
     * As memory initialization might be integrated into KASAN,
     * kasan_slab_free and initialization memset's must be
     * kept together to avoid discrepancies in behavior.
     *
     * The initialization memset's clear the object and the metadata,
     * but don't touch the SLAB redzone.
     *
     * The object's freepointer is also avoided if stored outside the
     * object.
     */
    if (unlikely(init)) {
        int rsize;
        unsigned int inuse, orig_size;

        inuse = get_info_end(s);
        orig_size = get_orig_size(s, x);
        if (!kasan_has_integrated_init())
            memset(kasan_reset_tag(x), 0, orig_size);
        rsize = (s->flags & SLAB_RED_ZONE) ? s->red_left_pad : 0;
        memset((char *)kasan_reset_tag(x) + inuse, 0,
               s->size - inuse - rsize);
        /*
         * Restore orig_size, otherwize kmalloc redzone overwritten
         * would be reported
         */
        set_orig_size(s, x, orig_size);

    }
    /* KASAN might put x into memory quarantine, delaying its reuse. */
    return !kasan_slab_free(s, x, init, still_accessible);
}

static noinline void free_to_partial_list(
    struct kmem_cache *s, struct slab *slab,
    void *head, void *tail, int bulk_cnt,
    unsigned long addr)
{
    PANIC("");
}

/*
 * SLUB reuses PG_workingset bit to keep track of whether it's on
 * the per-node partial list.
 */
static inline bool slab_test_node_partial(const struct slab *slab)
{
    return folio_test_workingset(slab_folio(slab));
}

static inline void init_slab_obj_exts(struct slab *slab)
{
}

static int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
                   gfp_t gfp, bool new_slab)
{
    return 0;
}

static inline void free_slab_obj_exts(struct slab *slab)
{
}

static __always_inline void unaccount_slab(struct slab *slab, int order,
                       struct kmem_cache *s)
{
    /*
     * The slab object extensions should now be freed regardless of
     * whether mem_alloc_profiling_enabled() or not because profiling
     * might have been disabled after slab->obj_exts got allocated.
     */
    free_slab_obj_exts(slab);

    mod_node_page_state(slab_pgdat(slab), cache_vmstat_idx(s),
                -(PAGE_SIZE << order));
}

static void __free_slab(struct kmem_cache *s, struct slab *slab)
{
    struct folio *folio = slab_folio(slab);
    int order = folio_order(folio);
    int pages = 1 << order;

    __slab_clear_pfmemalloc(slab);
    folio->mapping = NULL;
    /* Make the mapping reset visible before clearing the flag */
    smp_wmb();
    __folio_clear_slab(folio);
    mm_account_reclaimed_pages(pages);
    unaccount_slab(slab, order, s);
    __free_pages(&folio->page, order);
}

static void rcu_free_slab(struct rcu_head *h)
{
    struct slab *slab = container_of(h, struct slab, rcu_head);

    __free_slab(slab->slab_cache, slab);
}

static void free_slab(struct kmem_cache *s, struct slab *slab)
{
    if (kmem_cache_debug_flags(s, SLAB_CONSISTENCY_CHECKS)) {
        void *p;

        slab_pad_check(s, slab);
        for_each_object(p, s, slab_address(slab), slab->objects)
            check_object(s, slab, p, SLUB_RED_INACTIVE);
    }

    if (unlikely(s->flags & SLAB_TYPESAFE_BY_RCU))
        call_rcu(&slab->rcu_head, rcu_free_slab);
    else
        __free_slab(s, slab);
}

static void discard_slab(struct kmem_cache *s, struct slab *slab)
{
    dec_slabs_node(s, slab_nid(slab), slab->objects);
    free_slab(s, slab);
}

/*
 * Slow path handling. This may still be called frequently since objects
 * have a longer lifetime than the cpu slabs in most processing loads.
 *
 * So we still attempt to reduce cache line usage. Just take the slab
 * lock and free the item. If there is no additional partial slab
 * handling required then we can return immediately.
 */
static void __slab_free(struct kmem_cache *s, struct slab *slab,
            void *head, void *tail, int cnt,
            unsigned long addr)

{
    void *prior;
    int was_frozen;
    struct slab new;
    unsigned long counters;
    struct kmem_cache_node *n = NULL;
    unsigned long flags;
    bool on_node_partial;

    stat(s, FREE_SLOWPATH);

    if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
        free_to_partial_list(s, slab, head, tail, cnt, addr);
        return;
    }

    do {
        if (unlikely(n)) {
            spin_unlock_irqrestore(&n->list_lock, flags);
            n = NULL;
        }
        prior = slab->freelist;
        counters = slab->counters;
        set_freepointer(s, tail, prior);
        new.counters = counters;
        was_frozen = new.frozen;
        new.inuse -= cnt;
        if ((!new.inuse || !prior) && !was_frozen) {
            /* Needs to be taken off a list */
            if (!kmem_cache_has_cpu_partial(s) || prior) {

                n = get_node(s, slab_nid(slab));
                /*
                 * Speculatively acquire the list_lock.
                 * If the cmpxchg does not succeed then we may
                 * drop the list_lock without any processing.
                 *
                 * Otherwise the list_lock will synchronize with
                 * other processors updating the list of slabs.
                 */
                spin_lock_irqsave(&n->list_lock, flags);

                on_node_partial = slab_test_node_partial(slab);
            }
        }

    } while (!slab_update_freelist(s, slab,
        prior, counters,
        head, new.counters,
        "__slab_free"));

    if (likely(!n)) {

        if (likely(was_frozen)) {
            /*
             * The list lock was not taken therefore no list
             * activity can be necessary.
             */
            stat(s, FREE_FROZEN);
        } else if (kmem_cache_has_cpu_partial(s) && !prior) {
            /*
             * If we started with a full slab then put it onto the
             * per cpu partial list.
             */
            put_cpu_partial(s, slab, 1);
            stat(s, CPU_PARTIAL_FREE);
        }

        return;
    }

    /*
     * This slab was partially empty but not on the per-node partial list,
     * in which case we shouldn't manipulate its list, just return.
     */
    if (prior && !on_node_partial) {
        spin_unlock_irqrestore(&n->list_lock, flags);
        return;
    }

    if (unlikely(!new.inuse && n->nr_partial >= s->min_partial))
        goto slab_empty;

    /*
     * Objects left in the slab. If it was not on the partial list before
     * then add it.
     */
    if (!kmem_cache_has_cpu_partial(s) && unlikely(!prior)) {
        add_partial(n, slab, DEACTIVATE_TO_TAIL);
        stat(s, FREE_ADD_PARTIAL);
    }
    spin_unlock_irqrestore(&n->list_lock, flags);
    return;

slab_empty:
    if (prior) {
        /*
         * Slab on the partial list.
         */
        remove_partial(n, slab);
        stat(s, FREE_REMOVE_PARTIAL);
    }

    spin_unlock_irqrestore(&n->list_lock, flags);
    stat(s, FREE_SLAB);
    discard_slab(s, slab);
}

/*
 * Fastpath with forced inlining to produce a kfree and kmem_cache_free that
 * can perform fastpath freeing without additional function calls.
 *
 * The fastpath is only possible if we are freeing to the current cpu slab
 * of this processor. This typically the case if we have just allocated
 * the item before.
 *
 * If fastpath is not possible then fall back to __slab_free where we deal
 * with all sorts of special processing.
 *
 * Bulk free of a freelist with several objects (all pointing to the
 * same slab) possible by specifying head and tail ptr, plus objects
 * count (cnt). Bulk free indicated by tail pointer being set.
 */
static __always_inline void do_slab_free(struct kmem_cache *s,
                struct slab *slab, void *head, void *tail,
                int cnt, unsigned long addr)
{
    struct kmem_cache_cpu *c;
    unsigned long tid;
    void **freelist;

redo:
    /*
     * Determine the currently cpus per cpu slab.
     * The cpu may change afterward. However that does not matter since
     * data is retrieved via this pointer. If we are on the same cpu
     * during the cmpxchg then the free will succeed.
     */
    c = raw_cpu_ptr(s->cpu_slab);
    tid = READ_ONCE(c->tid);

    /* Same with comment on barrier() in __slab_alloc_node() */
    barrier();

    if (unlikely(slab != c->slab)) {
        __slab_free(s, slab, head, tail, cnt, addr);
        return;
    }

    if (USE_LOCKLESS_FAST_PATH()) {
        freelist = READ_ONCE(c->freelist);

        set_freepointer(s, tail, freelist);

        if (unlikely(!__update_cpu_freelist_fast(s, freelist, head, tid))) {
            note_cmpxchg_failure("slab_free", s, tid);
            goto redo;
        }
    } else {
        /* Update the free list under the local lock */
        local_lock(&s->cpu_slab->lock);
        c = this_cpu_ptr(s->cpu_slab);
        if (unlikely(slab != c->slab)) {
            local_unlock(&s->cpu_slab->lock);
            goto redo;
        }
        tid = c->tid;
        freelist = c->freelist;

        set_freepointer(s, tail, freelist);
        c->freelist = head;
        c->tid = next_tid(tid);

        local_unlock(&s->cpu_slab->lock);
    }
    stat_add(s, FREE_FASTPATH, cnt);
}

static __fastpath_inline
void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
           unsigned long addr)
{
    memcg_slab_free_hook(s, slab, &object, 1);
    alloc_tagging_slab_free_hook(s, slab, &object, 1);

    if (likely(slab_free_hook(s, object, slab_want_init_on_free(s), false)))
        do_slab_free(s, slab, object, object, 1, addr);
}

static void free_large_kmalloc(struct folio *folio, void *object)
{
    unsigned int order = folio_order(folio);

    if (WARN_ON_ONCE(order == 0))
        pr_warn_once("object pointer: 0x%p\n", object);

    kmemleak_free(object);
    kasan_kfree_large(object);
    kmsan_kfree_large(object);

    lruvec_stat_mod_folio(folio, NR_SLAB_UNRECLAIMABLE_B,
                  -(PAGE_SIZE << order));
    folio_put(folio);
}

/**
 * kfree - free previously allocated memory
 * @object: pointer returned by kmalloc() or kmem_cache_alloc()
 *
 * If @object is NULL, no operation is performed.
 */
void kfree(const void *object)
{
    struct folio *folio;
    struct slab *slab;
    struct kmem_cache *s;
    void *x = (void *)object;

    trace_kfree(_RET_IP_, object);

    if (unlikely(ZERO_OR_NULL_PTR(object)))
        return;

    folio = virt_to_folio(object);
    if (unlikely(!folio_test_slab(folio))) {
        free_large_kmalloc(folio, (void *)object);
        return;
    }

    slab = folio_slab(folio);
    s = slab->slab_cache;
    slab_free(s, slab, x, _RET_IP_);
}

/**
 * kmem_cache_free - Deallocate an object
 * @s: The cache the allocation was from.
 * @x: The previously allocated object.
 *
 * Free an object which was previously allocated from this
 * cache.
 */
void kmem_cache_free(struct kmem_cache *s, void *x)
{
#if 0
    s = cache_from_obj(s, x);
    if (!s)
        return;
    trace_kmem_cache_free(_RET_IP_, x, s);
    slab_free(s, virt_to_slab(x), x, _RET_IP_);
#endif
    PANIC("%s: No impl.", __func__);
}

void skip_orig_size_check(struct kmem_cache *s, const void *object)
{
    PANIC("%s: No impl.", __func__);
    //set_orig_size(s, (void *)object, s->object_size);
}

static inline
int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
                void **p)
{
    int i;
    for (i = 0; i < size; i++) {
        p[i] = kmem_cache_alloc_noprof(s, flags);
    }
    return i;
}

/* Note that interrupts must be enabled when calling this function. */
int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
                 void **p)
{
    int i;

    if (!size)
        return 0;

    s = slab_pre_alloc_hook(s, flags);
    if (unlikely(!s))
        return 0;

    i = __kmem_cache_alloc_bulk(s, flags, size, p);
    if (unlikely(i == 0))
        return 0;

    /*
     * memcg and kmem_cache debug support and memory initialization.
     * Done outside of the IRQ disabled fastpath loop.
     */
    if (unlikely(!slab_post_alloc_hook(s, NULL, flags, size, p,
            slab_want_init_on_alloc(flags, s), s->object_size))) {
        return 0;
    }
    return i;
}

static inline struct kmem_cache_order_objects oo_make(unsigned int order,
        unsigned int size)
{
    struct kmem_cache_order_objects x = {
        (order << OO_SHIFT) + order_objects(order, size)
    };

    return x;
}

/*
 * Calculate the order of allocation given an slab object size.
 *
 * The order of allocation has significant impact on performance and other
 * system components. Generally order 0 allocations should be preferred since
 * order 0 does not cause fragmentation in the page allocator. Larger objects
 * be problematic to put into order 0 slabs because there may be too much
 * unused space left. We go to a higher order if more than 1/16th of the slab
 * would be wasted.
 *
 * In order to reach satisfactory performance we must ensure that a minimum
 * number of objects is in one slab. Otherwise we may generate too much
 * activity on the partial lists which requires taking the list_lock. This is
 * less a concern for large slabs though which are rarely used.
 *
 * slab_max_order specifies the order where we begin to stop considering the
 * number of objects in a slab as critical. If we reach slab_max_order then
 * we try to keep the page order as low as possible. So we accept more waste
 * of space in favor of a small page order.
 *
 * Higher order allocations also allow the placement of more objects in a
 * slab and thereby reduce object handling overhead. If the user has
 * requested a higher minimum order then we start with that one instead of
 * the smallest order which will fit the object.
 */
static inline unsigned int calc_slab_order(unsigned int size,
        unsigned int min_order, unsigned int max_order,
        unsigned int fract_leftover)
{
    unsigned int order;

    for (order = min_order; order <= max_order; order++) {

        unsigned int slab_size = (unsigned int)PAGE_SIZE << order;
        unsigned int rem;

        rem = slab_size % size;

        if (rem <= slab_size / fract_leftover)
            break;
    }

    return order;
}

static inline int calculate_order(unsigned int size)
{
    unsigned int order;
    unsigned int min_objects;
    unsigned int max_objects;
    unsigned int min_order;

    min_objects = slub_min_objects;
    if (!min_objects) {
        /*
         * Some architectures will only update present cpus when
         * onlining them, so don't trust the number if it's just 1. But
         * we also don't want to use nr_cpu_ids always, as on some other
         * architectures, there can be many possible cpus, but never
         * onlined. Here we compromise between trying to avoid too high
         * order on systems that appear larger than they are, and too
         * low order on systems that appear smaller than they are.
         */
        unsigned int nr_cpus = num_present_cpus();
        if (nr_cpus <= 1)
            nr_cpus = nr_cpu_ids;
        min_objects = 4 * (fls(nr_cpus) + 1);
    }
    /* min_objects can't be 0 because get_order(0) is undefined */
    max_objects = max(order_objects(slub_max_order, size), 1U);
    min_objects = min(min_objects, max_objects);

    min_order = max_t(unsigned int, slub_min_order,
              get_order(min_objects * size));
    if (order_objects(min_order, size) > MAX_OBJS_PER_PAGE)
        return get_order(size * MAX_OBJS_PER_PAGE) - 1;


    /*
     * Attempt to find best configuration for a slab. This works by first
     * attempting to generate a layout with the best possible configuration
     * and backing off gradually.
     *
     * We start with accepting at most 1/16 waste and try to find the
     * smallest order from min_objects-derived/slab_min_order up to
     * slab_max_order that will satisfy the constraint. Note that increasing
     * the order can only result in same or less fractional waste, not more.
     *
     * If that fails, we increase the acceptable fraction of waste and try
     * again. The last iteration with fraction of 1/2 would effectively
     * accept any waste and give us the order determined by min_objects, as
     * long as at least single object fits within slab_max_order.
     */
    for (unsigned int fraction = 16; fraction > 1; fraction /= 2) {
        order = calc_slab_order(size, min_order, slub_max_order,
                    fraction);
        if (order <= slub_max_order)
            return order;
    }

    /*
     * Doh this slab cannot be placed using slab_max_order.
     */
    order = get_order(size);
    if (order <= MAX_PAGE_ORDER)
        return order;
    return -ENOSYS;
}

/*
 * calculate_sizes() determines the order and the distribution of data within
 * a slab object.
 */
static int calculate_sizes(struct kmem_cache_args *args, struct kmem_cache *s)
{
    slab_flags_t flags = s->flags;
    unsigned int size = s->object_size;
    unsigned int order;

    /*
     * Round up object size to the next word boundary. We can only
     * place the free pointer at word boundaries and this determines
     * the possible location of the free pointer.
     */
    size = ALIGN(size, sizeof(void *));

#ifdef CONFIG_SLUB_DEBUG
    /*
     * Determine if we can poison the object itself. If the user of
     * the slab may touch the object after free or before allocation
     * then we should never poison the object itself.
     */
    if ((flags & SLAB_POISON) && !(flags & SLAB_TYPESAFE_BY_RCU) &&
            !s->ctor)
        s->flags |= __OBJECT_POISON;
    else
        s->flags &= ~__OBJECT_POISON;


    /*
     * If we are Redzoning then check if there is some space between the
     * end of the object and the free pointer. If not then add an
     * additional word to have some bytes to store Redzone information.
     */
    if ((flags & SLAB_RED_ZONE) && size == s->object_size)
        size += sizeof(void *);
#endif

    /*
     * With that we have determined the number of bytes in actual use
     * by the object and redzoning.
     */
    s->inuse = size;

    if (((flags & SLAB_TYPESAFE_BY_RCU) && !args->use_freeptr_offset) ||
        (flags & SLAB_POISON) || s->ctor ||
        ((flags & SLAB_RED_ZONE) &&
         (s->object_size < sizeof(void *) || slub_debug_orig_size(s)))) {
        /*
         * Relocate free pointer after the object if it is not
         * permitted to overwrite the first word of the object on
         * kmem_cache_free.
         *
         * This is the case if we do RCU, have a constructor or
         * destructor, are poisoning the objects, or are
         * redzoning an object smaller than sizeof(void *) or are
         * redzoning an object with slub_debug_orig_size() enabled,
         * in which case the right redzone may be extended.
         *
         * The assumption that s->offset >= s->inuse means free
         * pointer is outside of the object is used in the
         * freeptr_outside_object() function. If that is no
         * longer true, the function needs to be modified.
         */
        s->offset = size;
        size += sizeof(void *);
    } else if ((flags & SLAB_TYPESAFE_BY_RCU) && args->use_freeptr_offset) {
        s->offset = args->freeptr_offset;
    } else {
        /*
         * Store freelist pointer near middle of object to keep
         * it away from the edges of the object to avoid small
         * sized over/underflows from neighboring allocations.
         */
        s->offset = ALIGN_DOWN(s->object_size / 2, sizeof(void *));
    }

#ifdef CONFIG_SLUB_DEBUG
    if (flags & SLAB_STORE_USER) {
        /*
         * Need to store information about allocs and frees after
         * the object.
         */
        size += 2 * sizeof(struct track);

        /* Save the original kmalloc request size */
        if (flags & SLAB_KMALLOC)
            size += sizeof(unsigned int);
    }
#endif

    kasan_cache_create(s, &size, &s->flags);
#ifdef CONFIG_SLUB_DEBUG
    if (flags & SLAB_RED_ZONE) {
        /*
         * Add some empty padding so that we can catch
         * overwrites from earlier objects rather than let
         * tracking information or the free pointer be
         * corrupted if a user writes before the start
         * of the object.
         */
        size += sizeof(void *);

        s->red_left_pad = sizeof(void *);
        s->red_left_pad = ALIGN(s->red_left_pad, s->align);
        size += s->red_left_pad;
    }
#endif

    /*
     * SLUB stores one object immediately after another beginning from
     * offset 0. In order to align the objects we have to simply size
     * each object to conform to the alignment.
     */
    size = ALIGN(size, s->align);
    s->size = size;
    s->reciprocal_size = reciprocal_value(size);
    order = calculate_order(size);

    if ((int)order < 0)
        return 0;

    s->allocflags = __GFP_COMP;

    if (s->flags & SLAB_CACHE_DMA)
        s->allocflags |= GFP_DMA;

    if (s->flags & SLAB_CACHE_DMA32)
        s->allocflags |= GFP_DMA32;

    if (s->flags & SLAB_RECLAIM_ACCOUNT)
        s->allocflags |= __GFP_RECLAIMABLE;

    /*
     * Determine the number of objects per slab
     */
    s->oo = oo_make(order, size);
    s->min = oo_make(get_order(size), size);

    return !!oo_objects(s->oo);
}

/*
 * Slab allocation and freeing
 */
static inline struct slab *alloc_slab_page(gfp_t flags, int node,
        struct kmem_cache_order_objects oo)
{
    struct folio *folio;
    struct slab *slab;
    unsigned int order = oo_order(oo);

    if (node == NUMA_NO_NODE)
        folio = (struct folio *)alloc_pages(flags, order);
    else
        folio = (struct folio *)__alloc_pages_node(node, flags, order);

    if (!folio)
        return NULL;

    slab = folio_slab(folio);
    __folio_set_slab(folio);
    /* Make the flag visible before any changes to folio->mapping */
    smp_wmb();
    if (folio_is_pfmemalloc(folio))
        slab_set_pfmemalloc(slab);

    return slab;
}

static __always_inline void account_slab(struct slab *slab, int order,
                     struct kmem_cache *s, gfp_t gfp)
{
    if (memcg_kmem_online() && (s->flags & SLAB_ACCOUNT))
        alloc_slab_obj_exts(slab, s, gfp, true);

    mod_node_page_state(slab_pgdat(slab), cache_vmstat_idx(s),
                PAGE_SIZE << order);
}

static
void setup_slab_debug(struct kmem_cache *s, struct slab *slab, void *addr)
{
    if (!kmem_cache_debug_flags(s, SLAB_POISON))
        return;

    metadata_access_enable();
    memset(kasan_reset_tag(addr), POISON_INUSE, slab_size(slab));
    metadata_access_disable();
}

static void init_tracking(struct kmem_cache *s, void *object)
{
    struct track *p;

    if (!(s->flags & SLAB_STORE_USER))
        return;

    p = get_track(s, object, TRACK_ALLOC);
    memset(p, 0, 2*sizeof(struct track));
}

/* Object debug checks for alloc/free paths */
static void setup_object_debug(struct kmem_cache *s, void *object)
{
    if (!kmem_cache_debug_flags(s, SLAB_STORE_USER|SLAB_RED_ZONE|__OBJECT_POISON))
        return;

    init_object(s, object, SLUB_RED_INACTIVE);
    init_tracking(s, object);
}

static void *setup_object(struct kmem_cache *s, void *object)
{
    setup_object_debug(s, object);
    object = kasan_init_slab_obj(s, object);
    if (unlikely(s->ctor)) {
        kasan_unpoison_new_object(s, object);
        s->ctor(object);
        kasan_poison_new_object(s, object);
    }
    return object;
}

static struct slab *allocate_slab(struct kmem_cache *s, gfp_t flags, int node)
{
    struct slab *slab;
    struct kmem_cache_order_objects oo = s->oo;
    gfp_t alloc_gfp;
    void *start, *p, *next;
    int idx;
    bool shuffle;

    flags &= gfp_allowed_mask;

    flags |= s->allocflags;

    /*
     * Let the initial higher-order allocation fail under memory pressure
     * so we fall-back to the minimum order allocation.
     */
    alloc_gfp = (flags | __GFP_NOWARN | __GFP_NORETRY) & ~__GFP_NOFAIL;
    if ((alloc_gfp & __GFP_DIRECT_RECLAIM) && oo_order(oo) > oo_order(s->min))
        alloc_gfp = (alloc_gfp | __GFP_NOMEMALLOC) & ~__GFP_RECLAIM;

    slab = alloc_slab_page(alloc_gfp, node, oo);
    if (unlikely(!slab)) {
        oo = s->min;
        alloc_gfp = flags;
        /*
         * Allocation may have failed due to fragmentation.
         * Try a lower order alloc if possible
         */
        slab = alloc_slab_page(alloc_gfp, node, oo);
        if (unlikely(!slab))
            return NULL;
        stat(s, ORDER_FALLBACK);
    }

    slab->objects = oo_objects(oo);
    slab->inuse = 0;
    slab->frozen = 0;
    init_slab_obj_exts(slab);

    account_slab(slab, oo_order(oo), s, flags);

    slab->slab_cache = s;

    kasan_poison_slab(slab);

    start = slab_address(slab);

    setup_slab_debug(s, slab, start);

    shuffle = shuffle_freelist(s, slab);

    if (!shuffle) {
        start = fixup_red_left(s, start);
        start = setup_object(s, start);
        slab->freelist = start;
        for (idx = 0, p = start; idx < slab->objects - 1; idx++) {
            next = p + s->size;
            next = setup_object(s, next);
            set_freepointer(s, p, next);
            p = next;
        }
        set_freepointer(s, p, NULL);
    }

    return slab;
}

static struct slab *new_slab(struct kmem_cache *s, gfp_t flags, int node)
{
    if (unlikely(flags & GFP_SLAB_BUG_MASK))
        flags = kmalloc_fix_flags(flags);

    WARN_ON_ONCE(s->ctor && (flags & __GFP_ZERO));

    return allocate_slab(s,
        flags & (GFP_RECLAIM_MASK | GFP_CONSTRAINT_MASK), node);
}

static void
init_kmem_cache_node(struct kmem_cache_node *n)
{
    n->nr_partial = 0;
    spin_lock_init(&n->list_lock);
    INIT_LIST_HEAD(&n->partial);
#ifdef CONFIG_SLUB_DEBUG
    atomic_long_set(&n->nr_slabs, 0);
    atomic_long_set(&n->total_objects, 0);
    INIT_LIST_HEAD(&n->full);
#endif
}

/*
 * No kmalloc_node yet so do it by hand. We know that this is the first
 * slab on the node for this slabcache. There are no concurrent accesses
 * possible.
 *
 * Note that this function only works on the kmem_cache_node
 * when allocating for the kmem_cache_node. This is used for bootstrapping
 * memory on a fresh node that has no slab structures yet.
 */
static void early_kmem_cache_node_alloc(int node)
{
    struct slab *slab;
    struct kmem_cache_node *n;

    BUG_ON(kmem_cache_node->size < sizeof(struct kmem_cache_node));

    slab = new_slab(kmem_cache_node, GFP_NOWAIT, node);

    BUG_ON(!slab);
    if (slab_nid(slab) != node) {
        pr_err("SLUB: Unable to allocate memory from node %d\n", node);
        pr_err("SLUB: Allocating a useless per node structure in order to be able to continue\n");
    }

    n = slab->freelist;
    BUG_ON(!n);
#ifdef CONFIG_SLUB_DEBUG
    init_object(kmem_cache_node, n, SLUB_RED_ACTIVE);
#endif
    n = kasan_slab_alloc(kmem_cache_node, n, GFP_KERNEL, false);
    slab->freelist = get_freepointer(kmem_cache_node, n);
    slab->inuse = 1;
    kmem_cache_node->node[node] = n;
    init_kmem_cache_node(n);
    inc_slabs_node(kmem_cache_node, node, slab->objects);

    /*
     * No locks need to be taken here as it has just been
     * initialized and there is no concurrent access.
     */
    __add_partial(n, slab, DEACTIVATE_TO_HEAD);
}

static void free_kmem_cache_nodes(struct kmem_cache *s)
{
    int node;
    struct kmem_cache_node *n;

    for_each_kmem_cache_node(s, node, n) {
        s->node[node] = NULL;
        kmem_cache_free(kmem_cache_node, n);
    }
}

static int init_kmem_cache_nodes(struct kmem_cache *s)
{
    int node;

    for_each_node_mask(node, slab_nodes) {
        struct kmem_cache_node *n;

        if (slab_state == DOWN) {
            early_kmem_cache_node_alloc(node);
            continue;
        }
        n = kmem_cache_alloc_node(kmem_cache_node,
                        GFP_KERNEL, node);

        if (!n) {
            free_kmem_cache_nodes(s);
            return 0;
        }

        init_kmem_cache_node(n);
        s->node[node] = n;
    }
    return 1;
}

static inline unsigned int init_tid(int cpu)
{
    return cpu;
}

static void init_kmem_cache_cpus(struct kmem_cache *s)
{
    int cpu;
    struct kmem_cache_cpu *c;

    for_each_possible_cpu(cpu) {
        c = per_cpu_ptr(s->cpu_slab, cpu);
        local_lock_init(&c->lock);
        c->tid = init_tid(cpu);
    }
}

#ifndef CONFIG_SLUB_TINY
static inline int alloc_kmem_cache_cpus(struct kmem_cache *s)
{
    BUILD_BUG_ON(PERCPU_DYNAMIC_EARLY_SIZE <
            NR_KMALLOC_TYPES * KMALLOC_SHIFT_HIGH *
            sizeof(struct kmem_cache_cpu));

    /*
     * Must align to double word boundary for the double cmpxchg
     * instructions to work; see __pcpu_double_call_return_bool().
     */
    s->cpu_slab = __alloc_percpu(sizeof(struct kmem_cache_cpu),
                     2 * sizeof(void *));

    if (!s->cpu_slab)
        return 0;

    init_kmem_cache_cpus(s);
    return 1;
}
#else
static inline int alloc_kmem_cache_cpus(struct kmem_cache *s)
{
    return 1;
}
#endif /* CONFIG_SLUB_TINY */

int do_kmem_cache_create(struct kmem_cache *s, const char *name,
             unsigned int size, struct kmem_cache_args *args,
             slab_flags_t flags)
{
    int err = -EINVAL;

    s->name = name;
    s->size = s->object_size = size;

    s->flags = kmem_cache_flags(flags, s->name);
#ifdef CONFIG_SLAB_FREELIST_HARDENED
    s->random = get_random_long();
#endif
    s->align = args->align;
    s->ctor = args->ctor;
#ifdef CONFIG_HARDENED_USERCOPY
    s->useroffset = args->useroffset;
    s->usersize = args->usersize;
#endif

    if (!calculate_sizes(args, s))
        goto out;
    if (disable_higher_order_debug) {
        /*
         * Disable debugging flags that store metadata if the min slab
         * order increased.
         */
        if (get_order(s->size) > get_order(s->object_size)) {
            s->flags &= ~DEBUG_METADATA_FLAGS;
            s->offset = 0;
            if (!calculate_sizes(args, s))
                goto out;
        }
    }

#ifdef system_has_freelist_aba
    if (system_has_freelist_aba() && !(s->flags & SLAB_NO_CMPXCHG)) {
        /* Enable fast mode */
        s->flags |= __CMPXCHG_DOUBLE;
    }
#endif

    /*
     * The larger the object size is, the more slabs we want on the partial
     * list to avoid pounding the page allocator excessively.
     */
    s->min_partial = min_t(unsigned long, MAX_PARTIAL, ilog2(s->size) / 2);
    s->min_partial = max_t(unsigned long, MIN_PARTIAL, s->min_partial);

    set_cpu_partial(s);

#ifdef CONFIG_NUMA
    s->remote_node_defrag_ratio = 1000;
#endif

    /* Initialize the pre-computed randomized freelist if slab is up */
    if (slab_state >= UP) {
        if (init_cache_random_seq(s))
            goto out;
    }

    if (!init_kmem_cache_nodes(s))
        goto out;

    if (!alloc_kmem_cache_cpus(s))
        goto out;

    /* Mutex is not taken during early boot */
    if (slab_state <= UP) {
        err = 0;
        goto out;
    }

#if 0
    err = sysfs_slab_add(s);
    if (err)
        goto out;

    if (s->flags & SLAB_STORE_USER)
        debugfs_slab_add(s);
#endif
    PANIC("");

out:
    if (err)
        __kmem_cache_release(s);
    return err;
}

void *fixup_red_left(struct kmem_cache *s, void *p)
{
    if (kmem_cache_debug_flags(s, SLAB_RED_ZONE))
        p += s->red_left_pad;

    return p;
}

void __kmem_cache_release(struct kmem_cache *s)
{
    cache_random_seq_destroy(s);
#ifndef CONFIG_SLUB_TINY
    free_percpu(s->cpu_slab);
#endif
    free_kmem_cache_nodes(s);
}

/*
 * kmem_cache_flags - apply debugging options to the cache
 * @flags:      flags to set
 * @name:       name of the cache
 *
 * Debug option(s) are applied to @flags. In addition to the debug
 * option(s), if a slab name (or multiple) is specified i.e.
 * slab_debug=<Debug-Options>,<slab name1>,<slab name2> ...
 * then only the select slabs will receive the debug option(s).
 */
slab_flags_t kmem_cache_flags(slab_flags_t flags, const char *name)
{
    char *iter;
    size_t len;
    char *next_block;
    slab_flags_t block_flags;
    slab_flags_t slub_debug_local = slub_debug;

    if (flags & SLAB_NO_USER_FLAGS)
        return flags;

    /*
     * If the slab cache is for debugging (e.g. kmemleak) then
     * don't store user (stack trace) information by default,
     * but let the user enable it via the command line below.
     */
    if (flags & SLAB_NOLEAKTRACE)
        slub_debug_local &= ~SLAB_STORE_USER;

    len = strlen(name);
    next_block = slub_debug_string;
    /* Go through all blocks of debug options, see if any matches our slab's name */
    while (next_block) {
        next_block = parse_slub_debug_flags(next_block, &block_flags, &iter, false);
        if (!iter)
            continue;
        /* Found a block that has a slab list, search it */
        while (*iter) {
            char *end, *glob;
            size_t cmplen;

            end = strchrnul(iter, ',');
            if (next_block && next_block < end)
                end = next_block - 1;

            glob = strnchr(iter, end - iter, '*');
            if (glob)
                cmplen = glob - iter;
            else
                cmplen = max_t(size_t, len, (end - iter));

            if (!strncmp(name, iter, cmplen)) {
                flags |= block_flags;
                return flags;
            }

            if (!*end || *end == ';')
                break;
            iter = end + 1;
        }
    }

    return flags | slub_debug_local;
}

static int slab_mem_going_online_callback(void *arg)
{
    PANIC("");
}

static int slab_mem_going_offline_callback(void *arg)
{
    PANIC("");
}

static void slab_mem_offline_callback(void *arg)
{
    PANIC("");
}

static int slab_memory_callback(struct notifier_block *self,
                unsigned long action, void *arg)
{
    int ret = 0;

    switch (action) {
    case MEM_GOING_ONLINE:
        ret = slab_mem_going_online_callback(arg);
        break;
    case MEM_GOING_OFFLINE:
        ret = slab_mem_going_offline_callback(arg);
        break;
    case MEM_OFFLINE:
    case MEM_CANCEL_ONLINE:
        slab_mem_offline_callback(arg);
        break;
    case MEM_ONLINE:
    case MEM_CANCEL_OFFLINE:
        break;
    }
    if (ret)
        ret = notifier_from_errno(ret);
    else
        ret = NOTIFY_OK;
    return ret;
}

static void put_partials_cpu(struct kmem_cache *s,
                 struct kmem_cache_cpu *c)
{
    struct slab *partial_slab;

    partial_slab = slub_percpu_partial(c);
    c->partial = NULL;

    if (partial_slab)
        __put_partials(s, partial_slab);
}

static inline void __flush_cpu_slab(struct kmem_cache *s, int cpu)
{
    struct kmem_cache_cpu *c = per_cpu_ptr(s->cpu_slab, cpu);
    void *freelist = c->freelist;
    struct slab *slab = c->slab;

    c->slab = NULL;
    c->freelist = NULL;
    c->tid = next_tid(c->tid);

    if (slab) {
        deactivate_slab(s, slab, freelist);
        stat(s, CPUSLAB_FLUSH);
    }

    put_partials_cpu(s, c);
}

/*
 * Use the cpu notifier to insure that the cpu slabs are flushed when
 * necessary.
 */
static int slub_cpu_dead(unsigned int cpu)
{
    struct kmem_cache *s;

    mutex_lock(&slab_mutex);
    list_for_each_entry(s, &slab_caches, list)
        __flush_cpu_slab(s, cpu);
    mutex_unlock(&slab_mutex);
    return 0;
}

/*
 * Used for early kmem_cache structures that were allocated using
 * the page allocator. Allocate them properly then fix up the pointers
 * that may be pointing to the wrong kmem_cache structure.
 */

static struct kmem_cache * __init bootstrap(struct kmem_cache *static_cache)
{
    int node;
    struct kmem_cache *s = kmem_cache_zalloc(kmem_cache, GFP_NOWAIT);
    struct kmem_cache_node *n;

    memcpy(s, static_cache, kmem_cache->object_size);

    /*
     * This runs very early, and only the boot processor is supposed to be
     * up.  Even if it weren't true, IRQs are not up so we couldn't fire
     * IPIs around.
     */
    __flush_cpu_slab(s, smp_processor_id());
    for_each_kmem_cache_node(s, node, n) {
        struct slab *p;

        list_for_each_entry(p, &n->partial, slab_list)
            p->slab_cache = s;

#ifdef CONFIG_SLUB_DEBUG
        list_for_each_entry(p, &n->full, slab_list)
            p->slab_cache = s;
#endif
    }
    list_add(&s->list, &slab_caches);
    return s;
}

void __init kmem_cache_init(void)
{
    static __initdata struct kmem_cache boot_kmem_cache,
        boot_kmem_cache_node;
    int node;

    if (debug_guardpage_minorder())
        slub_max_order = 0;

    /* Print slub debugging pointers without hashing */
    if (__slub_debug_enabled())
        no_hash_pointers_enable(NULL);

    kmem_cache_node = &boot_kmem_cache_node;
    kmem_cache = &boot_kmem_cache;

    /*
     * Initialize the nodemask for which we will allocate per node
     * structures. Here we don't need taking slab_mutex yet.
     */
    for_each_node_state(node, N_NORMAL_MEMORY)
        node_set(node, slab_nodes);

    create_boot_cache(kmem_cache_node, "kmem_cache_node",
            sizeof(struct kmem_cache_node),
            SLAB_HWCACHE_ALIGN | SLAB_NO_OBJ_EXT, 0, 0);

    hotplug_memory_notifier(slab_memory_callback, SLAB_CALLBACK_PRI);

    /* Able to allocate the per node structures */
    slab_state = PARTIAL;

    create_boot_cache(kmem_cache, "kmem_cache",
            offsetof(struct kmem_cache, node) +
                nr_node_ids * sizeof(struct kmem_cache_node *),
            SLAB_HWCACHE_ALIGN | SLAB_NO_OBJ_EXT, 0, 0);

    kmem_cache = bootstrap(&boot_kmem_cache);
    kmem_cache_node = bootstrap(&boot_kmem_cache_node);

    printk("%s: step3\n", __func__);
    /* Now we can use the kmem_cache to allocate kmalloc slabs */
    setup_kmalloc_cache_index_table();
    create_kmalloc_caches();

    /* Setup random freelists for each cache */
    init_freelist_randomization();

    cpuhp_setup_state_nocalls(CPUHP_SLUB_DEAD, "slub:dead", NULL,
                  slub_cpu_dead);

    pr_info("SLUB: HWalign=%d, Order=%u-%u, MinObjects=%u, CPUs=%u, Nodes=%u\n",
        cache_line_size(),
        slub_min_order, slub_max_order, slub_min_objects,
        nr_cpu_ids, nr_node_ids);
}

/*
 * Put a slab into a partial slab slot if available.
 *
 * If we did not find a slot then simply move all the partials to the
 * per node partial list.
 */
static void put_cpu_partial(struct kmem_cache *s, struct slab *slab, int drain)
{
    struct slab *oldslab;
    struct slab *slab_to_put = NULL;
    unsigned long flags;
    int slabs = 0;

    local_lock_irqsave(&s->cpu_slab->lock, flags);

    oldslab = this_cpu_read(s->cpu_slab->partial);

    if (oldslab) {
        if (drain && oldslab->slabs >= s->cpu_partial_slabs) {
            /*
             * Partial array is full. Move the existing set to the
             * per node partial list. Postpone the actual unfreezing
             * outside of the critical section.
             */
            slab_to_put = oldslab;
            oldslab = NULL;
        } else {
            slabs = oldslab->slabs;
        }
    }

    slabs++;

    slab->slabs = slabs;
    slab->next = oldslab;

    this_cpu_write(s->cpu_slab->partial, slab);

    local_unlock_irqrestore(&s->cpu_slab->lock, flags);

    if (slab_to_put) {
        __put_partials(s, slab_to_put);
        stat(s, CPU_PARTIAL_DRAIN);
    }
}

/*
 * To avoid unnecessary overhead, we pass through large allocation requests
 * directly to the page allocator. We use __GFP_COMP, because we will need to
 * know the allocation order to free the pages properly in kfree.
 */
static void *___kmalloc_large_node(size_t size, gfp_t flags, int node)
{
    struct folio *folio;
    void *ptr = NULL;
    unsigned int order = get_order(size);

    if (unlikely(flags & GFP_SLAB_BUG_MASK))
        flags = kmalloc_fix_flags(flags);

    flags |= __GFP_COMP;
    folio = (struct folio *)alloc_pages_node_noprof(node, flags, order);
    if (folio) {
        ptr = folio_address(folio);
        lruvec_stat_mod_folio(folio, NR_SLAB_UNRECLAIMABLE_B,
                      PAGE_SIZE << order);
    }

    ptr = kasan_kmalloc_large(ptr, size, flags);
    /* As ptr might get tagged, call kmemleak hook after KASAN. */
    kmemleak_alloc(ptr, size, 1, flags);
    kmsan_kmalloc_large(ptr, size, flags);

    return ptr;
}

void *__kmalloc_large_node_noprof(size_t size, gfp_t flags, int node)
{
    void *ret = ___kmalloc_large_node(size, flags, node);

    trace_kmalloc(_RET_IP_, ret, size, PAGE_SIZE << get_order(size),
              flags, node);
    return ret;
}
