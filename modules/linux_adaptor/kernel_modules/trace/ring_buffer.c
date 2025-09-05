#include <linux/trace_recursion.h>
#include <linux/trace_events.h>
#include <linux/ring_buffer.h>
#include <linux/trace_clock.h>
#include <linux/sched/clock.h>
#include <linux/cacheflush.h>
#include <linux/trace_seq.h>
#include <linux/spinlock.h>
#include <linux/irq_work.h>
#include <linux/security.h>
#include <linux/uaccess.h>
#include <linux/hardirq.h>
#include <linux/kthread.h>  /* for self test */
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/hash.h>
#include <linux/list.h>
#include <linux/cpu.h>
#include <linux/oom.h>
#include <linux/mm.h>

#include <asm/local64.h>
#include <asm/local.h>

#include "trace.h"
#include "../adaptor.h"

/*
 * The "absolute" timestamp in the buffer is only 59 bits.
 * If a clock has the 5 MSBs set, it needs to be saved and
 * reinserted.
 */
#define TS_MSB      (0xf8ULL << 56)
#define ABS_TS_MASK (~TS_MSB)

static void update_pages_handler(struct work_struct *work);

/*
 * Used for the add_timestamp
 *  NONE
 *  EXTEND - wants a time extend
 *  ABSOLUTE - the buffer requests all events to have absolute time stamps
 *  FORCE - force a full time stamp.
 */
enum {
    RB_ADD_STAMP_NONE       = 0,
    RB_ADD_STAMP_EXTEND     = BIT(1),
    RB_ADD_STAMP_ABSOLUTE       = BIT(2),
    RB_ADD_STAMP_FORCE      = BIT(3)
};

enum {
    RB_LEN_TIME_EXTEND = 8,
    RB_LEN_TIME_STAMP =  8,
};

#define skip_time_extend(event) \
    ((struct ring_buffer_event *)((char *)event + RB_LEN_TIME_EXTEND))

#define extended_time(event) \
    (event->type_len >= RINGBUF_TYPE_TIME_EXTEND)

#define RING_BUFFER_META_MAGIC  0xBADFEED

struct ring_buffer_meta {
    int     magic;
    int     struct_size;
    unsigned long   text_addr;
    unsigned long   data_addr;
    unsigned long   first_buffer;
    unsigned long   head_buffer;
    unsigned long   commit_buffer;
    __u32       subbuf_size;
    __u32       nr_subbufs;
    int     buffers[];
};

#define RB_PAGE_NORMAL      0UL
#define RB_PAGE_HEAD        1UL
#define RB_PAGE_UPDATE      2UL

#define RB_FLAG_MASK        3UL

/* PAGE_MOVED is not part of the mask */
#define RB_PAGE_MOVED       4UL

/* buffer may be either ring_buffer or ring_buffer_per_cpu */
#define RB_WARN_ON(b, cond)                     \
    ({                              \
        int _____ret = unlikely(cond);              \
        if (_____ret) {                     \
            if (__same_type(*(b), struct ring_buffer_per_cpu)) { \
                struct ring_buffer_per_cpu *__b =   \
                    (void *)b;          \
                atomic_inc(&__b->buffer->record_disabled); \
            } else                      \
                atomic_inc(&b->record_disabled);    \
            WARN_ON(1);                 \
        }                           \
        _____ret;                       \
    })

/* Up this if you want to test the TIME_EXTENTS and normalization */
#define DEBUG_SHIFT 0

#define for_each_buffer_cpu(buffer, cpu)        \
    for_each_cpu(cpu, buffer->cpumask)

#define for_each_online_buffer_cpu(buffer, cpu)     \
    for_each_cpu_and(cpu, buffer->cpumask, cpu_online_mask)

#define TS_SHIFT    27
#define TS_MASK     ((1ULL << TS_SHIFT) - 1)
#define TS_DELTA_TEST   (~TS_MASK)

/* Used for individual buffers (after the counter) */
#define RB_BUFFER_OFF       (1 << 20)

#define BUF_PAGE_HDR_SIZE offsetof(struct buffer_data_page, data)

#define RB_EVNT_HDR_SIZE (offsetof(struct ring_buffer_event, array))
#define RB_ALIGNMENT        4U
#define RB_MAX_SMALL_DATA   (RB_ALIGNMENT * RINGBUF_TYPE_DATA_TYPE_LEN_MAX)
#define RB_EVNT_MIN_SIZE    8U  /* two 32bit words */

#ifndef CONFIG_HAVE_64BIT_ALIGNED_ACCESS
# define RB_FORCE_8BYTE_ALIGNMENT   0
# define RB_ARCH_ALIGNMENT      RB_ALIGNMENT
#else
# define RB_FORCE_8BYTE_ALIGNMENT   1
# define RB_ARCH_ALIGNMENT      8U
#endif

#define RB_ALIGN_DATA       __aligned(RB_ARCH_ALIGNMENT)

/* define RINGBUF_TYPE_DATA for 'case RINGBUF_TYPE_DATA:' */
#define RINGBUF_TYPE_DATA 0 ... RINGBUF_TYPE_DATA_TYPE_LEN_MAX

#ifdef CONFIG_RING_BUFFER_RECORD_RECURSION
# define do_ring_buffer_record_recursion()  \
    do_ftrace_record_recursion(_THIS_IP_, _RET_IP_)
#else
# define do_ring_buffer_record_recursion() do { } while (0)
#endif

/*
 * The buffer page counters, write and entries, must be reset
 * atomically when crossing page boundaries. To synchronize this
 * update, two counters are inserted into the number. One is
 * the actual counter for the write position or count on the page.
 *
 * The other is a counter of updaters. Before an update happens
 * the update partition of the counter is incremented. This will
 * allow the updater to update the counter atomically.
 *
 * The counter is 20 bits, and the state data is 12.
 */
#define RB_WRITE_MASK       0xfffff
#define RB_WRITE_INTCNT     (1 << 20)

/*
 * Used for which event context the event is in.
 *  TRANSITION = 0
 *  NMI     = 1
 *  IRQ     = 2
 *  SOFTIRQ = 3
 *  NORMAL  = 4
 *
 * See trace_recursive_lock() comment below for more details.
 */
enum {
    RB_CTX_TRANSITION,
    RB_CTX_NMI,
    RB_CTX_IRQ,
    RB_CTX_SOFTIRQ,
    RB_CTX_NORMAL,
    RB_CTX_MAX
};

struct rb_time_struct {
    local64_t   time;
};
typedef struct rb_time_struct rb_time_t;

struct rb_irq_work {
    struct irq_work         work;
    wait_queue_head_t       waiters;
    wait_queue_head_t       full_waiters;
    atomic_t            seq;
    bool                waiters_pending;
    bool                full_waiters_pending;
    bool                wakeup_full;
};

/*
 * Structure to hold event state and handle nested events.
 */
struct rb_event_info {
    u64         ts;
    u64         delta;
    u64         before;
    u64         after;
    unsigned long       length;
    struct buffer_page  *tail_page;
    int         add_timestamp;
};

static u64 rb_event_time_stamp(struct ring_buffer_event *event)
{
    u64 ts;

    ts = event->array[0];
    ts <<= TS_SHIFT;
    ts += event->time_delta;

    return ts;
}

/*
 * The absolute time stamp drops the 5 MSBs and some clocks may
 * require them. The rb_fix_abs_ts() will take a previous full
 * time stamp, and add the 5 MSB of that time stamp on to the
 * saved absolute time stamp. Then they are compared in case of
 * the unlikely event that the latest time stamp incremented
 * the 5 MSB.
 */
static inline u64 rb_fix_abs_ts(u64 abs, u64 save_ts)
{
    if (save_ts & TS_MSB) {
        abs |= save_ts & TS_MSB;
        /* Check for overflow */
        if (unlikely(abs < save_ts))
            abs += 1ULL << 59;
    }
    return abs;
}

#define RB_MISSED_MASK      (3 << 30)

struct buffer_data_page {
    u64      time_stamp;    /* page time stamp */
    local_t      commit;    /* write committed index */
    unsigned char    data[] RB_ALIGN_DATA;  /* data of buffer page */
};

struct buffer_data_read_page {
    unsigned        order;  /* order of the page */
    struct buffer_data_page *data;  /* actual data, stored in this page */
};

/*
 * Note, the buffer_page list must be first. The buffer pages
 * are allocated in cache lines, which means that each buffer
 * page will be at the beginning of a cache line, and thus
 * the least significant bits will be zero. We use this to
 * add flags in the list struct pointers, to make the ring buffer
 * lockless.
 */
struct buffer_page {
    struct list_head list;      /* list of buffer pages */
    local_t      write;     /* index for next write */
    unsigned     read;      /* index for next read */
    local_t      entries;   /* entries on this page */
    unsigned long    real_end;  /* real end of data */
    unsigned     order;     /* order of the page */
    u32      id:30;     /* ID for external mapping */
    u32      range:1;   /* Mapped via a range */
    struct buffer_data_page *page;  /* Actual data page */
};

#define MAX_NEST    5

/*
 * head_page == tail_page && head == tail then buffer is empty.
 */
struct ring_buffer_per_cpu {
    int             cpu;
    atomic_t            record_disabled;
    atomic_t            resize_disabled;
    struct trace_buffer *buffer;
    raw_spinlock_t          reader_lock;    /* serialize readers */
    arch_spinlock_t         lock;
    struct lock_class_key       lock_key;
    struct buffer_data_page     *free_page;
    unsigned long           nr_pages;
    unsigned int            current_context;
    struct list_head        *pages;
    /* pages generation counter, incremented when the list changes */
    unsigned long           cnt;
    struct buffer_page      *head_page; /* read from head */
    struct buffer_page      *tail_page; /* write to tail */
    struct buffer_page      *commit_page;   /* committed pages */
    struct buffer_page      *reader_page;
    unsigned long           lost_events;
    unsigned long           last_overrun;
    unsigned long           nest;
    local_t             entries_bytes;
    local_t             entries;
    local_t             overrun;
    local_t             commit_overrun;
    local_t             dropped_events;
    local_t             committing;
    local_t             commits;
    local_t             pages_touched;
    local_t             pages_lost;
    local_t             pages_read;
    long                last_pages_touch;
    size_t              shortest_full;
    unsigned long           read;
    unsigned long           read_bytes;
    rb_time_t           write_stamp;
    rb_time_t           before_stamp;
    u64             event_stamp[MAX_NEST];
    u64             read_stamp;
    /* pages removed since last reset */
    unsigned long           pages_removed;

    unsigned int            mapped;
    unsigned int            user_mapped;    /* user space mapping */
    struct mutex            mapping_lock;
    unsigned long           *subbuf_ids;    /* ID to subbuf VA */
    struct trace_buffer_meta    *meta_page;
    struct ring_buffer_meta     *ring_meta;

    /* ring buffer pages to update, > 0 to add, < 0 to remove */
    long                nr_pages_to_update;
    struct list_head        new_pages; /* new pages to add */
    struct work_struct      update_pages_work;
    struct completion       update_done;

    struct rb_irq_work      irq_work;
};

struct trace_buffer {
    unsigned            flags;
    int             cpus;
    atomic_t            record_disabled;
    atomic_t            resizing;
    cpumask_var_t           cpumask;

    struct lock_class_key       *reader_lock_key;

    struct mutex            mutex;

    struct ring_buffer_per_cpu  **buffers;

    struct hlist_node       node;
    u64             (*clock)(void);

    struct rb_irq_work      irq_work;
    bool                time_stamp_abs;

    unsigned long           range_addr_start;
    unsigned long           range_addr_end;

    long                last_text_delta;
    long                last_data_delta;

    unsigned int            subbuf_size;
    unsigned int            subbuf_order;
    unsigned int            max_data_size;
};

struct ring_buffer_iter {
    struct ring_buffer_per_cpu  *cpu_buffer;
    unsigned long           head;
    unsigned long           next_event;
    struct buffer_page      *head_page;
    struct buffer_page      *cache_reader_page;
    unsigned long           cache_read;
    unsigned long           cache_pages_removed;
    u64             read_stamp;
    u64             page_stamp;
    struct ring_buffer_event    *event;
    size_t              event_size;
    int             missed_events;
};

#define RB_PAGE_NORMAL      0UL
#define RB_PAGE_HEAD        1UL
#define RB_PAGE_UPDATE      2UL


#define RB_FLAG_MASK        3UL

/* PAGE_MOVED is not part of the mask */
#define RB_PAGE_MOVED       4UL

static inline bool rb_null_event(struct ring_buffer_event *event)
{
    return event->type_len == RINGBUF_TYPE_PADDING && !event->time_delta;
}

static int rb_lost_events(struct ring_buffer_per_cpu *cpu_buffer)
{
    return cpu_buffer->lost_events;
}

void ring_buffer_normalize_time_stamp(struct trace_buffer *buffer,
                      int cpu, u64 *ts)
{
    /* Just stupid testing the normalize function and deltas */
    *ts >>= DEBUG_SHIFT;
}

/*
 * rb_list_head - remove any bit
 */
static struct list_head *rb_list_head(struct list_head *list)
{
    unsigned long val = (unsigned long)list;

    return (struct list_head *)(val & ~RB_FLAG_MASK);
}

/** ring_buffer_iter_dropped - report if there are dropped events
 * @iter: The ring buffer iterator
 *
 * Returns true if there was dropped events since the last peek.
 */
bool ring_buffer_iter_dropped(struct ring_buffer_iter *iter)
{
    bool ret = iter->missed_events != 0;

    iter->missed_events = 0;
    return ret;
}

static unsigned
rb_event_data_length(struct ring_buffer_event *event)
{
    unsigned length;

    if (event->type_len)
        length = event->type_len * RB_ALIGNMENT;
    else
        length = event->array[0];
    return length + RB_EVNT_HDR_SIZE;
}

static inline bool rb_reader_lock(struct ring_buffer_per_cpu *cpu_buffer)
{
    if (likely(!in_nmi())) {
        raw_spin_lock(&cpu_buffer->reader_lock);
        return true;
    }

    /*
     * If an NMI die dumps out the content of the ring buffer
     * trylock must be used to prevent a deadlock if the NMI
     * preempted a task that holds the ring buffer locks. If
     * we get the lock then all is fine, if not, then continue
     * to do the read, but this can corrupt the ring buffer,
     * so it must be permanently disabled from future writes.
     * Reading from NMI is a oneshot deal.
     */
    if (raw_spin_trylock(&cpu_buffer->reader_lock))
        return true;

    /* Continue without locking, but disable the ring buffer */
    atomic_inc(&cpu_buffer->record_disabled);
    return false;
}

static inline void
rb_reader_unlock(struct ring_buffer_per_cpu *cpu_buffer, bool locked)
{
    if (likely(locked))
        raw_spin_unlock(&cpu_buffer->reader_lock);
}

static __always_inline void *__rb_page_index(struct buffer_page *bpage, unsigned index)
{
    return bpage->page->data + index;
}

static __always_inline struct ring_buffer_event *
rb_reader_event(struct ring_buffer_per_cpu *cpu_buffer)
{
    return __rb_page_index(cpu_buffer->reader_page,
                   cpu_buffer->reader_page->read);
}

static inline unsigned long rb_page_write(struct buffer_page *bpage)
{
    return local_read(&bpage->write) & RB_WRITE_MASK;
}

static __always_inline unsigned int rb_page_commit(struct buffer_page *bpage)
{
    return local_read(&bpage->page->commit);
}

/* Size is determined by what has been committed */
static __always_inline unsigned rb_page_size(struct buffer_page *bpage)
{
    return rb_page_commit(bpage) & ~RB_MISSED_MASK;
}

static inline void rb_inc_page(struct buffer_page **bpage)
{
    struct list_head *p = rb_list_head((*bpage)->list.next);

    *bpage = list_entry(p, struct buffer_page, list);
}

/*
 * rb_is_head_page - test if the given page is the head page
 *
 * Because the reader may move the head_page pointer, we can
 * not trust what the head page is (it may be pointing to
 * the reader page). But if the next page is a header page,
 * its flags will be non zero.
 */
static inline int
rb_is_head_page(struct buffer_page *page, struct list_head *list)
{
    unsigned long val;

    val = (unsigned long)list->next;

    if ((val & ~RB_FLAG_MASK) != (unsigned long)&page->list)
        return RB_PAGE_MOVED;

    return val & RB_FLAG_MASK;
}

/*
 * rb_set_list_to_head - set a list_head to be pointing to head.
 */
static void rb_set_list_to_head(struct list_head *list)
{
    unsigned long *ptr;

    ptr = (unsigned long *)&list->next;
    *ptr |= RB_PAGE_HEAD;
    *ptr &= ~RB_PAGE_UPDATE;
}

static struct buffer_page *
rb_set_head_page(struct ring_buffer_per_cpu *cpu_buffer)
{
    struct buffer_page *head;
    struct buffer_page *page;
    struct list_head *list;
    int i;

    if (RB_WARN_ON(cpu_buffer, !cpu_buffer->head_page))
        return NULL;

    /* sanity check */
    list = cpu_buffer->pages;
    if (RB_WARN_ON(cpu_buffer, rb_list_head(list->prev->next) != list))
        return NULL;

    page = head = cpu_buffer->head_page;
    /*
     * It is possible that the writer moves the header behind
     * where we started, and we miss in one loop.
     * A second loop should grab the header, but we'll do
     * three loops just because I'm paranoid.
     */
    for (i = 0; i < 3; i++) {
        do {
            if (rb_is_head_page(page, page->list.prev)) {
                cpu_buffer->head_page = page;
                return page;
            }
            rb_inc_page(&page);
        } while (page != head);
    }

    RB_WARN_ON(cpu_buffer, 1);

    PANIC("");
    return NULL;
}

/*
 * The total entries in the ring buffer is the running counter
 * of entries entered into the ring buffer, minus the sum of
 * the entries read from the ring buffer and the number of
 * entries that were overwritten.
 */
static inline unsigned long
rb_num_of_entries(struct ring_buffer_per_cpu *cpu_buffer)
{
    return local_read(&cpu_buffer->entries) -
        (local_read(&cpu_buffer->overrun) + cpu_buffer->read);
}

/* Return the index into the sub-buffers for a given sub-buffer */
static int rb_meta_subbuf_idx(struct ring_buffer_meta *meta, void *subbuf)
{
    void *subbuf_array;

    subbuf_array = (void *)meta + sizeof(int) * meta->nr_subbufs;
    subbuf_array = (void *)ALIGN((unsigned long)subbuf_array, meta->subbuf_size);
    return (subbuf - subbuf_array) / meta->subbuf_size;
}

static bool rb_head_page_replace(struct buffer_page *old,
                struct buffer_page *new)
{
    unsigned long *ptr = (unsigned long *)&old->list.prev->next;
    unsigned long val;

    val = *ptr & ~RB_FLAG_MASK;
    val |= RB_PAGE_HEAD;

    return try_cmpxchg(ptr, &val, (unsigned long)&new->list);
}

static void rb_update_meta_head(struct ring_buffer_per_cpu *cpu_buffer,
                struct buffer_page *next_page)
{
    struct ring_buffer_meta *meta = cpu_buffer->ring_meta;
    unsigned long old_head = (unsigned long)next_page->page;
    unsigned long new_head;

    rb_inc_page(&next_page);
    new_head = (unsigned long)next_page->page;

    /*
     * Only move it forward once, if something else came in and
     * moved it forward, then we don't want to touch it.
     */
    (void)cmpxchg(&meta->head_buffer, old_head, new_head);
}

static void rb_update_meta_reader(struct ring_buffer_per_cpu *cpu_buffer,
                  struct buffer_page *reader)
{
    struct ring_buffer_meta *meta = cpu_buffer->ring_meta;
    void *old_reader = cpu_buffer->reader_page->page;
    void *new_reader = reader->page;
    int id;

    id = reader->id;
    cpu_buffer->reader_page->id = id;
    reader->id = 0;

    meta->buffers[0] = rb_meta_subbuf_idx(meta, new_reader);
    meta->buffers[id] = rb_meta_subbuf_idx(meta, old_reader);

    /* The head pointer is the one after the reader */
    rb_update_meta_head(cpu_buffer, reader);
}

static struct buffer_page *
rb_get_reader_page(struct ring_buffer_per_cpu *cpu_buffer)
{
    struct buffer_page *reader = NULL;
    unsigned long bsize = READ_ONCE(cpu_buffer->buffer->subbuf_size);
    unsigned long overwrite;
    unsigned long flags;
    int nr_loops = 0;
    bool ret;

    local_irq_save(flags);
    arch_spin_lock(&cpu_buffer->lock);

 again:
    /*
     * This should normally only loop twice. But because the
     * start of the reader inserts an empty page, it causes
     * a case where we will loop three times. There should be no
     * reason to loop four times (that I know of).
     */
    if (RB_WARN_ON(cpu_buffer, ++nr_loops > 3)) {
        reader = NULL;
        goto out;
    }

    reader = cpu_buffer->reader_page;

    /* If there's more to read, return this page */
    if (cpu_buffer->reader_page->read < rb_page_size(reader))
        goto out;

    /* Never should we have an index greater than the size */
    if (RB_WARN_ON(cpu_buffer,
               cpu_buffer->reader_page->read > rb_page_size(reader)))
        goto out;

    /* check if we caught up to the tail */
    reader = NULL;
    if (cpu_buffer->commit_page == cpu_buffer->reader_page)
        goto out;

    /* Don't bother swapping if the ring buffer is empty */
    if (rb_num_of_entries(cpu_buffer) == 0)
        goto out;

    /*
     * Reset the reader page to size zero.
     */
    local_set(&cpu_buffer->reader_page->write, 0);
    local_set(&cpu_buffer->reader_page->entries, 0);
    local_set(&cpu_buffer->reader_page->page->commit, 0);
    cpu_buffer->reader_page->real_end = 0;

 spin:
    /*
     * Splice the empty reader page into the list around the head.
     */
    reader = rb_set_head_page(cpu_buffer);
    if (!reader)
        goto out;
    cpu_buffer->reader_page->list.next = rb_list_head(reader->list.next);
    cpu_buffer->reader_page->list.prev = reader->list.prev;

    /*
     * cpu_buffer->pages just needs to point to the buffer, it
     *  has no specific buffer page to point to. Lets move it out
     *  of our way so we don't accidentally swap it.
     */
    cpu_buffer->pages = reader->list.prev;

    /* The reader page will be pointing to the new head */
    rb_set_list_to_head(&cpu_buffer->reader_page->list);

    /*
     * We want to make sure we read the overruns after we set up our
     * pointers to the next object. The writer side does a
     * cmpxchg to cross pages which acts as the mb on the writer
     * side. Note, the reader will constantly fail the swap
     * while the writer is updating the pointers, so this
     * guarantees that the overwrite recorded here is the one we
     * want to compare with the last_overrun.
     */
    smp_mb();
    overwrite = local_read(&(cpu_buffer->overrun));

    /*
     * Here's the tricky part.
     *
     * We need to move the pointer past the header page.
     * But we can only do that if a writer is not currently
     * moving it. The page before the header page has the
     * flag bit '1' set if it is pointing to the page we want.
     * but if the writer is in the process of moving it
     * than it will be '2' or already moved '0'.
     */

    ret = rb_head_page_replace(reader, cpu_buffer->reader_page);

    /*
     * If we did not convert it, then we must try again.
     */
    if (!ret)
        goto spin;

    if (cpu_buffer->ring_meta)
        rb_update_meta_reader(cpu_buffer, reader);

    /*
     * Yay! We succeeded in replacing the page.
     *
     * Now make the new head point back to the reader page.
     */
    rb_list_head(reader->list.next)->prev = &cpu_buffer->reader_page->list;
    rb_inc_page(&cpu_buffer->head_page);

    cpu_buffer->cnt++;
    local_inc(&cpu_buffer->pages_read);

    /* Finally update the reader page to the new head */
    cpu_buffer->reader_page = reader;
    cpu_buffer->reader_page->read = 0;

    if (overwrite != cpu_buffer->last_overrun) {
        cpu_buffer->lost_events = overwrite - cpu_buffer->last_overrun;
        cpu_buffer->last_overrun = overwrite;
    }

    goto again;

 out:
    /* Update the read_stamp on the first event */
    if (reader && reader->read == 0)
        cpu_buffer->read_stamp = reader->page->time_stamp;

    arch_spin_unlock(&cpu_buffer->lock);
    local_irq_restore(flags);

    /*
     * The writer has preempt disable, wait for it. But not forever
     * Although, 1 second is pretty much "forever"
     */
#define USECS_WAIT  1000000
        for (nr_loops = 0; nr_loops < USECS_WAIT; nr_loops++) {
        /* If the write is past the end of page, a writer is still updating it */
        if (likely(!reader || rb_page_write(reader) <= bsize))
            break;

        udelay(1);

        /* Get the latest version of the reader write value */
        smp_rmb();
    }

    /* The writer is not moving forward? Something is wrong */
    if (RB_WARN_ON(cpu_buffer, nr_loops == USECS_WAIT))
        reader = NULL;

    /*
     * Make sure we see any padding after the write update
     * (see rb_reset_tail()).
     *
     * In addition, a writer may be writing on the reader page
     * if the page has not been fully filled, so the read barrier
     * is also needed to make sure we see the content of what is
     * committed by the writer (see rb_set_commit_to_write()).
     */
    smp_rmb();

    return reader;
}

/*
 * Return the length of the given event. Will return
 * the length of the time extend if the event is a
 * time extend.
 */
static inline unsigned
rb_event_length(struct ring_buffer_event *event)
{
    switch (event->type_len) {
    case RINGBUF_TYPE_PADDING:
        if (rb_null_event(event))
            /* undefined */
            return -1;
        return  event->array[0] + RB_EVNT_HDR_SIZE;

    case RINGBUF_TYPE_TIME_EXTEND:
        return RB_LEN_TIME_EXTEND;

    case RINGBUF_TYPE_TIME_STAMP:
        return RB_LEN_TIME_STAMP;

    case RINGBUF_TYPE_DATA:
        return rb_event_data_length(event);
    default:
        WARN_ON_ONCE(1);
    }
    /* not hit */
    return 0;
}

static void
rb_update_read_stamp(struct ring_buffer_per_cpu *cpu_buffer,
             struct ring_buffer_event *event)
{
    u64 delta;

    switch (event->type_len) {
    case RINGBUF_TYPE_PADDING:
        return;

    case RINGBUF_TYPE_TIME_EXTEND:
        delta = rb_event_time_stamp(event);
        cpu_buffer->read_stamp += delta;
        return;

    case RINGBUF_TYPE_TIME_STAMP:
        delta = rb_event_time_stamp(event);
        delta = rb_fix_abs_ts(delta, cpu_buffer->read_stamp);
        cpu_buffer->read_stamp = delta;
        return;

    case RINGBUF_TYPE_DATA:
        cpu_buffer->read_stamp += event->time_delta;
        return;

    default:
        RB_WARN_ON(cpu_buffer, 1);
    }
}

static void rb_advance_reader(struct ring_buffer_per_cpu *cpu_buffer)
{
    struct ring_buffer_event *event;
    struct buffer_page *reader;
    unsigned length;

    reader = rb_get_reader_page(cpu_buffer);

    /* This function should not be called when buffer is empty */
    if (RB_WARN_ON(cpu_buffer, !reader))
        return;

    event = rb_reader_event(cpu_buffer);

    if (event->type_len <= RINGBUF_TYPE_DATA_TYPE_LEN_MAX)
        cpu_buffer->read++;

    rb_update_read_stamp(cpu_buffer, event);

    length = rb_event_length(event);
    cpu_buffer->reader_page->read += length;
    cpu_buffer->read_bytes += length;
}

static struct ring_buffer_event *
rb_buffer_peek(struct ring_buffer_per_cpu *cpu_buffer, u64 *ts,
           unsigned long *lost_events)
{
    struct ring_buffer_event *event;
    struct buffer_page *reader;
    int nr_loops = 0;

    if (ts)
        *ts = 0;
 again:
    /*
     * We repeat when a time extend is encountered.
     * Since the time extend is always attached to a data event,
     * we should never loop more than once.
     * (We never hit the following condition more than twice).
     */
    if (RB_WARN_ON(cpu_buffer, ++nr_loops > 2))
        return NULL;

    reader = rb_get_reader_page(cpu_buffer);
    if (!reader)
        return NULL;

    event = rb_reader_event(cpu_buffer);

    switch (event->type_len) {
    case RINGBUF_TYPE_PADDING:
        if (rb_null_event(event))
            RB_WARN_ON(cpu_buffer, 1);
        /*
         * Because the writer could be discarding every
         * event it creates (which would probably be bad)
         * if we were to go back to "again" then we may never
         * catch up, and will trigger the warn on, or lock
         * the box. Return the padding, and we will release
         * the current locks, and try again.
         */
        return event;

    case RINGBUF_TYPE_TIME_EXTEND:
        /* Internal data, OK to advance */
        rb_advance_reader(cpu_buffer);
        goto again;

    case RINGBUF_TYPE_TIME_STAMP:
        if (ts) {
            *ts = rb_event_time_stamp(event);
            *ts = rb_fix_abs_ts(*ts, reader->page->time_stamp);
            ring_buffer_normalize_time_stamp(cpu_buffer->buffer,
                             cpu_buffer->cpu, ts);
        }
        /* Internal data, OK to advance */
        rb_advance_reader(cpu_buffer);
        goto again;

    case RINGBUF_TYPE_DATA:
        if (ts && !(*ts)) {
            *ts = cpu_buffer->read_stamp + event->time_delta;
            ring_buffer_normalize_time_stamp(cpu_buffer->buffer,
                             cpu_buffer->cpu, ts);
        }
        if (lost_events)
            *lost_events = rb_lost_events(cpu_buffer);
        return event;

    default:
        RB_WARN_ON(cpu_buffer, 1);
    }

    PANIC("");
    return NULL;
}

/**
 * ring_buffer_peek - peek at the next event to be read
 * @buffer: The ring buffer to read
 * @cpu: The cpu to peak at
 * @ts: The timestamp counter of this event.
 * @lost_events: a variable to store if events were lost (may be NULL)
 *
 * This will return the event that will be read next, but does
 * not consume the data.
 */
struct ring_buffer_event *
ring_buffer_peek(struct trace_buffer *buffer, int cpu, u64 *ts,
         unsigned long *lost_events)
{
    struct ring_buffer_per_cpu *cpu_buffer = buffer->buffers[cpu];
    struct ring_buffer_event *event;
    unsigned long flags;
    bool dolock;

    if (!cpumask_test_cpu(cpu, buffer->cpumask))
        return NULL;

 again:
    local_irq_save(flags);
    dolock = rb_reader_lock(cpu_buffer);
    event = rb_buffer_peek(cpu_buffer, ts, lost_events);
    if (event && event->type_len == RINGBUF_TYPE_PADDING)
        rb_advance_reader(cpu_buffer);
    rb_reader_unlock(cpu_buffer, dolock);
    local_irq_restore(flags);

    if (event && event->type_len == RINGBUF_TYPE_PADDING)
        goto again;

    return event;
}

bool ring_buffer_time_stamp_abs(struct trace_buffer *buffer)
{
    return buffer->time_stamp_abs;
}

/*
 * rb_wake_up_waiters - wake up tasks waiting for ring buffer input
 *
 * Schedules a delayed work to wake up any task that is blocked on the
 * ring buffer waiters queue.
 */
static void rb_wake_up_waiters(struct irq_work *work)
{
    PANIC("");
}


/*
 * We only allocate new buffers, never free them if the CPU goes down.
 * If we were to free the buffer, then the user would lose any trace that was in
 * the buffer.
 */
int trace_rb_cpu_prepare(unsigned int cpu, struct hlist_node *node)
{
    struct trace_buffer *buffer;
    long nr_pages_same;
    int cpu_i;
    unsigned long nr_pages;

    printk("%s: step1\n", __func__);
    buffer = container_of(node, struct trace_buffer, node);
    printk("%s: step2 buffer(%lx)\n", __func__, buffer);
    if (cpumask_test_cpu(cpu, buffer->cpumask))
        return 0;

    printk("%s: step3\n", __func__);

    PANIC("");
    return 0;
}

static void rb_free_cpu_buffer(struct ring_buffer_per_cpu *cpu_buffer)
{
    PANIC("");
}

static bool
rb_insert_pages(struct ring_buffer_per_cpu *cpu_buffer)
{
    PANIC("");
}

static bool
rb_remove_pages(struct ring_buffer_per_cpu *cpu_buffer, unsigned long nr_pages)
{
    PANIC("");
}

static void rb_update_pages(struct ring_buffer_per_cpu *cpu_buffer)
{
    bool success;

    if (cpu_buffer->nr_pages_to_update > 0)
        success = rb_insert_pages(cpu_buffer);
    else
        success = rb_remove_pages(cpu_buffer,
                    -cpu_buffer->nr_pages_to_update);

    if (success)
        cpu_buffer->nr_pages += cpu_buffer->nr_pages_to_update;
}

static void update_pages_handler(struct work_struct *work)
{
    struct ring_buffer_per_cpu *cpu_buffer = container_of(work,
            struct ring_buffer_per_cpu, update_pages_work);
    rb_update_pages(cpu_buffer);
    complete(&cpu_buffer->update_done);
}

static void free_buffer_page(struct buffer_page *bpage)
{
    /* Range pages are not to be freed */
    if (!bpage->range)
        free_pages((unsigned long)bpage->page, bpage->order);
    kfree(bpage);
}

/*
 * We need to fit the time_stamp delta into 27 bits.
 */
static inline bool test_time_stamp(u64 delta)
{
    return !!(delta & TS_DELTA_TEST);
}

static void rb_check_bpage(struct ring_buffer_per_cpu *cpu_buffer,
              struct buffer_page *bpage)
{
    unsigned long val = (unsigned long)bpage;

    RB_WARN_ON(cpu_buffer, val & RB_FLAG_MASK);
}

static void rb_init_page(struct buffer_data_page *bpage)
{
    local_set(&bpage->commit, 0);
}

/*
 * Return the ring_buffer_meta for a given @cpu.
 */
static void *rb_range_meta(struct trace_buffer *buffer, int nr_pages, int cpu)
{
    int subbuf_size = buffer->subbuf_size + BUF_PAGE_HDR_SIZE;
    unsigned long ptr = buffer->range_addr_start;
    struct ring_buffer_meta *meta;
    int nr_subbufs;

    if (!ptr)
        return NULL;

    PANIC("");
}

/*
 * Return a specific sub-buffer for a given @cpu defined by @idx.
 */
static void *rb_range_buffer(struct ring_buffer_per_cpu *cpu_buffer, int idx)
{
    struct ring_buffer_meta *meta;
    unsigned long ptr;
    int subbuf_size;

    PANIC("");
}

/* Map the buffer_pages to the previous head and commit pages */
static void rb_meta_buffer_update(struct ring_buffer_per_cpu *cpu_buffer,
                  struct buffer_page *bpage)
{
    struct ring_buffer_meta *meta = cpu_buffer->ring_meta;

    if (meta->head_buffer == (unsigned long)bpage->page)
        cpu_buffer->head_page = bpage;

    if (meta->commit_buffer == (unsigned long)bpage->page) {
        cpu_buffer->commit_page = bpage;
        cpu_buffer->tail_page = bpage;
    }
}

static int __rb_allocate_pages(struct ring_buffer_per_cpu *cpu_buffer,
        long nr_pages, struct list_head *pages)
{
    struct trace_buffer *buffer = cpu_buffer->buffer;
    struct ring_buffer_meta *meta = NULL;
    struct buffer_page *bpage, *tmp;
    bool user_thread = current->mm != NULL;
    gfp_t mflags;
    long i;

    /*
     * Check if the available memory is there first.
     * Note, si_mem_available() only gives us a rough estimate of available
     * memory. It may not be accurate. But we don't care, we just want
     * to prevent doing any allocation when it is obvious that it is
     * not going to succeed.
     */
    i = si_mem_available();
    if (i < nr_pages)
        return -ENOMEM;

    /*
     * __GFP_RETRY_MAYFAIL flag makes sure that the allocation fails
     * gracefully without invoking oom-killer and the system is not
     * destabilized.
     */
    mflags = GFP_KERNEL | __GFP_RETRY_MAYFAIL;

    /*
     * If a user thread allocates too much, and si_mem_available()
     * reports there's enough memory, even though there is not.
     * Make sure the OOM killer kills this thread. This can happen
     * even with RETRY_MAYFAIL because another task may be doing
     * an allocation after this task has taken all memory.
     * This is the task the OOM killer needs to take out during this
     * loop, even if it was triggered by an allocation somewhere else.
     */
    if (user_thread)
        set_current_oom_origin();

    if (buffer->range_addr_start)
        meta = rb_range_meta(buffer, nr_pages, cpu_buffer->cpu);

    for (i = 0; i < nr_pages; i++) {
        struct page *page;

        bpage = kzalloc_node(ALIGN(sizeof(*bpage), cache_line_size()),
                    mflags, cpu_to_node(cpu_buffer->cpu));
        if (!bpage)
            goto free_pages;

        rb_check_bpage(cpu_buffer, bpage);

        /*
         * Append the pages as for mapped buffers we want to keep
         * the order
         */
        list_add_tail(&bpage->list, pages);

        if (meta) {
            /* A range was given. Use that for the buffer page */
            bpage->page = rb_range_buffer(cpu_buffer, i + 1);
            if (!bpage->page)
                goto free_pages;
            /* If this is valid from a previous boot */
            if (meta->head_buffer)
                rb_meta_buffer_update(cpu_buffer, bpage);
            bpage->range = 1;
            bpage->id = i + 1;
        } else {
            page = alloc_pages_node(cpu_to_node(cpu_buffer->cpu),
                        mflags | __GFP_COMP | __GFP_ZERO,
                        cpu_buffer->buffer->subbuf_order);
            if (!page)
                goto free_pages;
            bpage->page = page_address(page);
            rb_init_page(bpage->page);
        }
        bpage->order = cpu_buffer->buffer->subbuf_order;

        if (user_thread && fatal_signal_pending(current))
            goto free_pages;
    }
    if (user_thread)
        clear_current_oom_origin();

    return 0;

free_pages:
    list_for_each_entry_safe(bpage, tmp, pages, list) {
        list_del_init(&bpage->list);
        free_buffer_page(bpage);
    }
    if (user_thread)
        clear_current_oom_origin();

    return -ENOMEM;
}

/*
 * rb_head_page_activate - sets up head page
 */
static void rb_head_page_activate(struct ring_buffer_per_cpu *cpu_buffer)
{
    struct buffer_page *head;

    head = cpu_buffer->head_page;
    if (!head)
        return;

    /*
     * Set the previous list pointer to have the HEAD flag.
     */
    rb_set_list_to_head(head->list.prev);

    if (cpu_buffer->ring_meta) {
        struct ring_buffer_meta *meta = cpu_buffer->ring_meta;
        meta->head_buffer = (unsigned long)head->page;
    }
}

/* If the meta data has been validated, now validate the events */
static void rb_meta_validate_events(struct ring_buffer_per_cpu *cpu_buffer)
{
    struct ring_buffer_meta *meta = cpu_buffer->ring_meta;
    struct buffer_page *head_page;
    unsigned long entry_bytes = 0;
    unsigned long entries = 0;
    int ret;
    int i;

    if (!meta || !meta->head_buffer)
        return;

    PANIC("");
}

static bool rb_check_links(struct ring_buffer_per_cpu *cpu_buffer,
               struct list_head *list)
{
    if (RB_WARN_ON(cpu_buffer,
               rb_list_head(rb_list_head(list->next)->prev) != list))
        return false;

    if (RB_WARN_ON(cpu_buffer,
               rb_list_head(rb_list_head(list->prev)->next) != list))
        return false;

    return true;
}

/**
 * rb_check_pages - integrity check of buffer pages
 * @cpu_buffer: CPU buffer with pages to test
 *
 * As a safety measure we check to make sure the data pages have not
 * been corrupted.
 */
static void rb_check_pages(struct ring_buffer_per_cpu *cpu_buffer)
{
    struct list_head *head, *tmp;
    unsigned long buffer_cnt;
    unsigned long flags;
    int nr_loops = 0;

    /*
     * Walk the linked list underpinning the ring buffer and validate all
     * its next and prev links.
     *
     * The check acquires the reader_lock to avoid concurrent processing
     * with code that could be modifying the list. However, the lock cannot
     * be held for the entire duration of the walk, as this would make the
     * time when interrupts are disabled non-deterministic, dependent on the
     * ring buffer size. Therefore, the code releases and re-acquires the
     * lock after checking each page. The ring_buffer_per_cpu.cnt variable
     * is then used to detect if the list was modified while the lock was
     * not held, in which case the check needs to be restarted.
     *
     * The code attempts to perform the check at most three times before
     * giving up. This is acceptable because this is only a self-validation
     * to detect problems early on. In practice, the list modification
     * operations are fairly spaced, and so this check typically succeeds at
     * most on the second try.
     */
again:
    if (++nr_loops > 3)
        return;

    raw_spin_lock_irqsave(&cpu_buffer->reader_lock, flags);
    head = rb_list_head(cpu_buffer->pages);
    if (!rb_check_links(cpu_buffer, head))
        goto out_locked;
    buffer_cnt = cpu_buffer->cnt;
    tmp = head;
    raw_spin_unlock_irqrestore(&cpu_buffer->reader_lock, flags);

    while (true) {
        raw_spin_lock_irqsave(&cpu_buffer->reader_lock, flags);

        if (buffer_cnt != cpu_buffer->cnt) {
            /* The list was updated, try again. */
            raw_spin_unlock_irqrestore(&cpu_buffer->reader_lock, flags);
            goto again;
        }

        tmp = rb_list_head(tmp->next);
        if (tmp == head)
            /* The iteration circled back, all is done. */
            goto out_locked;

        if (!rb_check_links(cpu_buffer, tmp))
            goto out_locked;

        raw_spin_unlock_irqrestore(&cpu_buffer->reader_lock, flags);
    }

    PANIC("");

out_locked:
    raw_spin_unlock_irqrestore(&cpu_buffer->reader_lock, flags);
}

static int rb_allocate_pages(struct ring_buffer_per_cpu *cpu_buffer,
                 unsigned long nr_pages)
{
    LIST_HEAD(pages);

    WARN_ON(!nr_pages);

    if (__rb_allocate_pages(cpu_buffer, nr_pages, &pages))
        return -ENOMEM;

    /*
     * The ring buffer page list is a circular list that does not
     * start and end with a list head. All page list items point to
     * other pages.
     */
    cpu_buffer->pages = pages.next;
    list_del(&pages);

    cpu_buffer->nr_pages = nr_pages;

    rb_check_pages(cpu_buffer);

    return 0;
}

static struct ring_buffer_per_cpu *
rb_allocate_cpu_buffer(struct trace_buffer *buffer, long nr_pages, int cpu)
{
    struct ring_buffer_per_cpu *cpu_buffer;
    struct ring_buffer_meta *meta;
    struct buffer_page *bpage;
    struct page *page;
    int ret;

    cpu_buffer = kzalloc_node(ALIGN(sizeof(*cpu_buffer), cache_line_size()),
                  GFP_KERNEL, cpu_to_node(cpu));
    if (!cpu_buffer)
        return NULL;

    cpu_buffer->cpu = cpu;
    cpu_buffer->buffer = buffer;
    raw_spin_lock_init(&cpu_buffer->reader_lock);
    lockdep_set_class(&cpu_buffer->reader_lock, buffer->reader_lock_key);
    cpu_buffer->lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
    INIT_WORK(&cpu_buffer->update_pages_work, update_pages_handler);
    init_completion(&cpu_buffer->update_done);
    init_irq_work(&cpu_buffer->irq_work.work, rb_wake_up_waiters);
    init_waitqueue_head(&cpu_buffer->irq_work.waiters);
    init_waitqueue_head(&cpu_buffer->irq_work.full_waiters);
    mutex_init(&cpu_buffer->mapping_lock);

    bpage = kzalloc_node(ALIGN(sizeof(*bpage), cache_line_size()),
                GFP_KERNEL, cpu_to_node(cpu));
    if (!bpage)
        goto fail_free_buffer;

    rb_check_bpage(cpu_buffer, bpage);

    cpu_buffer->reader_page = bpage;

    if (buffer->range_addr_start) {
#if 0
        /*
         * Range mapped buffers have the same restrictions as memory
         * mapped ones do.
         */
        cpu_buffer->mapped = 1;
        cpu_buffer->ring_meta = rb_range_meta(buffer, nr_pages, cpu);
        bpage->page = rb_range_buffer(cpu_buffer, 0);
        if (!bpage->page)
            goto fail_free_reader;
        if (cpu_buffer->ring_meta->head_buffer)
            rb_meta_buffer_update(cpu_buffer, bpage);
        bpage->range = 1;
#endif
        PANIC("1");
    } else {
        page = alloc_pages_node(cpu_to_node(cpu),
                    GFP_KERNEL | __GFP_COMP | __GFP_ZERO,
                    cpu_buffer->buffer->subbuf_order);
        if (!page)
            goto fail_free_reader;
        bpage->page = page_address(page);
        rb_init_page(bpage->page);
    }

    INIT_LIST_HEAD(&cpu_buffer->reader_page->list);
    INIT_LIST_HEAD(&cpu_buffer->new_pages);

    ret = rb_allocate_pages(cpu_buffer, nr_pages);
    if (ret < 0)
        goto fail_free_reader;

    rb_meta_validate_events(cpu_buffer);

    /* If the boot meta was valid then this has already been updated */
    meta = cpu_buffer->ring_meta;
    if (!meta || !meta->head_buffer ||
        !cpu_buffer->head_page || !cpu_buffer->commit_page || !cpu_buffer->tail_page) {
        if (meta && meta->head_buffer &&
            (cpu_buffer->head_page || cpu_buffer->commit_page || cpu_buffer->tail_page)) {
            pr_warn("Ring buffer meta buffers not all mapped\n");
            if (!cpu_buffer->head_page)
                pr_warn("   Missing head_page\n");
            if (!cpu_buffer->commit_page)
                pr_warn("   Missing commit_page\n");
            if (!cpu_buffer->tail_page)
                pr_warn("   Missing tail_page\n");
        }

        cpu_buffer->head_page
            = list_entry(cpu_buffer->pages, struct buffer_page, list);
        cpu_buffer->tail_page = cpu_buffer->commit_page = cpu_buffer->head_page;

        rb_head_page_activate(cpu_buffer);

        if (cpu_buffer->ring_meta)
            meta->commit_buffer = meta->head_buffer;
    } else {
        /* The valid meta buffer still needs to activate the head page */
        rb_head_page_activate(cpu_buffer);
    }

    return cpu_buffer;

 fail_free_reader:
    free_buffer_page(cpu_buffer->reader_page);

 fail_free_buffer:
    kfree(cpu_buffer);
    return NULL;
}

static struct trace_buffer *alloc_buffer(unsigned long size, unsigned flags,
                     int order, unsigned long start,
                     unsigned long end,
                     struct lock_class_key *key)
{
    struct trace_buffer *buffer;
    long nr_pages;
    int subbuf_size;
    int bsize;
    int cpu;
    int ret;

    /* keep it in its own cache line */
    buffer = kzalloc(ALIGN(sizeof(*buffer), cache_line_size()),
             GFP_KERNEL);
    if (!buffer)
        return NULL;

    if (!zalloc_cpumask_var(&buffer->cpumask, GFP_KERNEL))
        goto fail_free_buffer;

    buffer->subbuf_order = order;
    subbuf_size = (PAGE_SIZE << order);
    buffer->subbuf_size = subbuf_size - BUF_PAGE_HDR_SIZE;

    /* Max payload is buffer page size - header (8bytes) */
    buffer->max_data_size = buffer->subbuf_size - (sizeof(u32) * 2);

    buffer->flags = flags;
    buffer->clock = trace_clock_local;
    buffer->reader_lock_key = key;

    init_irq_work(&buffer->irq_work.work, rb_wake_up_waiters);
    init_waitqueue_head(&buffer->irq_work.waiters);

    buffer->cpus = nr_cpu_ids;

    bsize = sizeof(void *) * nr_cpu_ids;
    buffer->buffers = kzalloc(ALIGN(bsize, cache_line_size()),
                  GFP_KERNEL);
    if (!buffer->buffers)
        goto fail_free_cpumask;

    /* If start/end are specified, then that overrides size */
    if (start && end) {
        PANIC("stage1");
    } else {

        /* need at least two pages */
        nr_pages = DIV_ROUND_UP(size, buffer->subbuf_size);
        if (nr_pages < 2)
            nr_pages = 2;
    }

    cpu = raw_smp_processor_id();
    cpumask_set_cpu(cpu, buffer->cpumask);
    buffer->buffers[cpu] = rb_allocate_cpu_buffer(buffer, nr_pages, cpu);
    if (!buffer->buffers[cpu])
        goto fail_free_buffers;

    ret = cpuhp_state_add_instance(CPUHP_TRACE_RB_PREPARE, &buffer->node);
    if (ret < 0)
        goto fail_free_buffers;

    mutex_init(&buffer->mutex);

    return buffer;

 fail_free_buffers:
    for_each_buffer_cpu(buffer, cpu) {
        if (buffer->buffers[cpu])
            rb_free_cpu_buffer(buffer->buffers[cpu]);
    }
    kfree(buffer->buffers);

 fail_free_cpumask:
    free_cpumask_var(buffer->cpumask);

 fail_free_buffer:
    kfree(buffer);
    return NULL;
}

/**
 * __ring_buffer_alloc - allocate a new ring_buffer
 * @size: the size in bytes per cpu that is needed.
 * @flags: attributes to set for the ring buffer.
 * @key: ring buffer reader_lock_key.
 *
 * Currently the only flag that is available is the RB_FL_OVERWRITE
 * flag. This flag means that the buffer will overwrite old data
 * when the buffer wraps. If this flag is not set, the buffer will
 * drop data when the tail hits the head.
 */
struct trace_buffer *__ring_buffer_alloc(unsigned long size, unsigned flags,
                    struct lock_class_key *key)
{
    /* Default buffer page size - one system page */
    return alloc_buffer(size, flags, 0, 0, 0,key);

}

/**
 * __ring_buffer_alloc_range - allocate a new ring_buffer from existing memory
 * @size: the size in bytes per cpu that is needed.
 * @flags: attributes to set for the ring buffer.
 * @start: start of allocated range
 * @range_size: size of allocated range
 * @order: sub-buffer order
 * @key: ring buffer reader_lock_key.
 *
 * Currently the only flag that is available is the RB_FL_OVERWRITE
 * flag. This flag means that the buffer will overwrite old data
 * when the buffer wraps. If this flag is not set, the buffer will
 * drop data when the tail hits the head.
 */
struct trace_buffer *__ring_buffer_alloc_range(unsigned long size, unsigned flags,
                           int order, unsigned long start,
                           unsigned long range_size,
                           struct lock_class_key *key)
{
    return alloc_buffer(size, flags, order, start, start + range_size, key);
}

/**
 * ring_buffer_last_boot_delta - return the delta offset from last boot
 * @buffer: The buffer to return the delta from
 * @text: Return text delta
 * @data: Return data delta
 *
 * Returns: The true if the delta is non zero
 */
bool ring_buffer_last_boot_delta(struct trace_buffer *buffer, long *text,
                 long *data)
{
    if (!buffer)
        return false;

    if (!buffer->last_text_delta)
        return false;

    *text = buffer->last_text_delta;
    *data = buffer->last_data_delta;

    return true;
}

/**
 * ring_buffer_size - return the size of the ring buffer (in bytes)
 * @buffer: The ring buffer.
 * @cpu: The CPU to get ring buffer size from.
 */
unsigned long ring_buffer_size(struct trace_buffer *buffer, int cpu)
{
    if (!cpumask_test_cpu(cpu, buffer->cpumask))
        return 0;

    return buffer->subbuf_size * buffer->buffers[cpu]->nr_pages;
}

static __always_inline bool
trace_recursive_lock(struct ring_buffer_per_cpu *cpu_buffer)
{
    unsigned int val = cpu_buffer->current_context;
    int bit = interrupt_context_level();

    bit = RB_CTX_NORMAL - bit;

    if (unlikely(val & (1 << (bit + cpu_buffer->nest)))) {
        /*
         * It is possible that this was called by transitioning
         * between interrupt context, and preempt_count() has not
         * been updated yet. In this case, use the TRANSITION bit.
         */
        bit = RB_CTX_TRANSITION;
        if (val & (1 << (bit + cpu_buffer->nest))) {
            do_ring_buffer_record_recursion();
            return true;
        }
    }

    val |= (1 << (bit + cpu_buffer->nest));
    cpu_buffer->current_context = val;

    return false;
}

static __always_inline void
trace_recursive_unlock(struct ring_buffer_per_cpu *cpu_buffer)
{
    cpu_buffer->current_context &=
        cpu_buffer->current_context - (1 << cpu_buffer->nest);
}

static void rb_start_commit(struct ring_buffer_per_cpu *cpu_buffer)
{
    local_inc(&cpu_buffer->committing);
    local_inc(&cpu_buffer->commits);
}

static unsigned rb_calculate_event_length(unsigned length)
{
    struct ring_buffer_event event; /* Used only for sizeof array */

    /* zero length can cause confusions */
    if (!length)
        length++;

    if (length > RB_MAX_SMALL_DATA || RB_FORCE_8BYTE_ALIGNMENT)
        length += sizeof(event.array[0]);

    length += RB_EVNT_HDR_SIZE;
    length = ALIGN(length, RB_ARCH_ALIGNMENT);

    /*
     * In case the time delta is larger than the 27 bits for it
     * in the header, we need to add a timestamp. If another
     * event comes in when trying to discard this one to increase
     * the length, then the timestamp will be added in the allocated
     * space of this event. If length is bigger than the size needed
     * for the TIME_EXTEND, then padding has to be used. The events
     * length must be either RB_LEN_TIME_EXTEND, or greater than or equal
     * to RB_LEN_TIME_EXTEND + 8, as 8 is the minimum size for padding.
     * As length is a multiple of 4, we only need to worry if it
     * is 12 (RB_LEN_TIME_EXTEND + 4).
     */
    if (length == RB_LEN_TIME_EXTEND + RB_ALIGNMENT)
        length += RB_ALIGNMENT;

    return length;
}

/*
 * rb_is_reader_page
 *
 * The unique thing about the reader page, is that, if the
 * writer is ever on it, the previous pointer never points
 * back to the reader page.
 */
static bool rb_is_reader_page(struct buffer_page *page)
{
    struct list_head *list = page->list.prev;

    return rb_list_head(list->next) != &page->list;
}

static __always_inline unsigned
rb_commit_index(struct ring_buffer_per_cpu *cpu_buffer)
{
    return rb_page_commit(cpu_buffer->commit_page);
}

static __always_inline void
rb_set_commit_to_write(struct ring_buffer_per_cpu *cpu_buffer)
{
    unsigned long max_count;

    /*
     * We only race with interrupts and NMIs on this CPU.
     * If we own the commit event, then we can commit
     * all others that interrupted us, since the interruptions
     * are in stack format (they finish before they come
     * back to us). This allows us to do a simple loop to
     * assign the commit to the tail.
     */
 again:
    max_count = cpu_buffer->nr_pages * 100;

    while (cpu_buffer->commit_page != READ_ONCE(cpu_buffer->tail_page)) {
        if (RB_WARN_ON(cpu_buffer, !(--max_count)))
            return;
        if (RB_WARN_ON(cpu_buffer,
                   rb_is_reader_page(cpu_buffer->tail_page)))
            return;
        /*
         * No need for a memory barrier here, as the update
         * of the tail_page did it for this page.
         */
        local_set(&cpu_buffer->commit_page->page->commit,
              rb_page_write(cpu_buffer->commit_page));
        rb_inc_page(&cpu_buffer->commit_page);
        if (cpu_buffer->ring_meta) {
            struct ring_buffer_meta *meta = cpu_buffer->ring_meta;
            meta->commit_buffer = (unsigned long)cpu_buffer->commit_page->page;
        }
        /* add barrier to keep gcc from optimizing too much */
        barrier();
    }
    while (rb_commit_index(cpu_buffer) !=
           rb_page_write(cpu_buffer->commit_page)) {

        /* Make sure the readers see the content of what is committed. */
        smp_wmb();
        local_set(&cpu_buffer->commit_page->page->commit,
              rb_page_write(cpu_buffer->commit_page));
        RB_WARN_ON(cpu_buffer,
               local_read(&cpu_buffer->commit_page->page->commit) &
               ~RB_WRITE_MASK);
        barrier();
    }

    /* again, keep gcc from optimizing */
    barrier();

    /*
     * If an interrupt came in just after the first while loop
     * and pushed the tail page forward, we will be left with
     * a dangling commit that will never go forward.
     */
    if (unlikely(cpu_buffer->commit_page != READ_ONCE(cpu_buffer->tail_page)))
        goto again;
}

static __always_inline void rb_end_commit(struct ring_buffer_per_cpu *cpu_buffer)
{
    unsigned long commits;

    if (RB_WARN_ON(cpu_buffer,
               !local_read(&cpu_buffer->committing)))
        return;

 again:
    commits = local_read(&cpu_buffer->commits);
    /* synchronize with interrupts */
    barrier();
    if (local_read(&cpu_buffer->committing) == 1)
        rb_set_commit_to_write(cpu_buffer);

    local_dec(&cpu_buffer->committing);

    /* synchronize with interrupts */
    barrier();

    /*
     * Need to account for interrupts coming in between the
     * updating of the commit page and the clearing of the
     * committing counter.
     */
    if (unlikely(local_read(&cpu_buffer->commits) != commits) &&
        !local_read(&cpu_buffer->committing)) {
        local_inc(&cpu_buffer->committing);
        goto again;
    }
}

static inline u64 rb_time_stamp(struct trace_buffer *buffer)
{
    u64 ts;

    /* Skip retpolines :-( */
    if (IS_ENABLED(CONFIG_MITIGATION_RETPOLINE) && likely(buffer->clock == trace_clock_local))
        ts = trace_clock_local();
    else
        ts = buffer->clock();

    /* shift to debug/test normalization and TIME_EXTENTS */
    return ts << DEBUG_SHIFT;
}

static inline void rb_time_read(rb_time_t *t, u64 *ret)
{
    *ret = local64_read(&t->time);
}

static void rb_time_set(rb_time_t *t, u64 val)
{
    local64_set(&t->time, val);
}

/* Special value to validate all deltas on a page. */
#define CHECK_FULL_PAGE     1L

static inline void check_buffer(struct ring_buffer_per_cpu *cpu_buffer,
             struct rb_event_info *info,
             unsigned long tail)
{
}

/*
 * This is the slow path, force gcc not to inline it.
 */
static noinline struct ring_buffer_event *
rb_move_tail(struct ring_buffer_per_cpu *cpu_buffer,
         unsigned long tail, struct rb_event_info *info)
{
    struct buffer_page *tail_page = info->tail_page;
    struct buffer_page *commit_page = cpu_buffer->commit_page;
    struct trace_buffer *buffer = cpu_buffer->buffer;
    struct buffer_page *next_page;
    int ret;

    next_page = tail_page;

    rb_inc_page(&next_page);


    PANIC("");
}

static void rb_add_timestamp(struct ring_buffer_per_cpu *cpu_buffer,
                      struct ring_buffer_event **event,
                      struct rb_event_info *info,
                      u64 *delta,
                      unsigned int *length)
{
    PANIC("");
}

/**
 * rb_update_event - update event type and data
 * @cpu_buffer: The per cpu buffer of the @event
 * @event: the event to update
 * @info: The info to update the @event with (contains length and delta)
 *
 * Update the type and data fields of the @event. The length
 * is the actual size that is written to the ring buffer,
 * and with this, we can determine what to place into the
 * data field.
 */
static void
rb_update_event(struct ring_buffer_per_cpu *cpu_buffer,
        struct ring_buffer_event *event,
        struct rb_event_info *info)
{
    unsigned length = info->length;
    u64 delta = info->delta;
    unsigned int nest = local_read(&cpu_buffer->committing) - 1;

    if (!WARN_ON_ONCE(nest >= MAX_NEST))
        cpu_buffer->event_stamp[nest] = info->ts;

    /*
     * If we need to add a timestamp, then we
     * add it to the start of the reserved space.
     */
    if (unlikely(info->add_timestamp))
        rb_add_timestamp(cpu_buffer, &event, info, &delta, &length);

    event->time_delta = delta;
    length -= RB_EVNT_HDR_SIZE;
    if (length > RB_MAX_SMALL_DATA || RB_FORCE_8BYTE_ALIGNMENT) {
        event->type_len = 0;
        event->array[0] = length;
    } else
        event->type_len = DIV_ROUND_UP(length, RB_ALIGNMENT);
}

static struct ring_buffer_event *
__rb_reserve_next(struct ring_buffer_per_cpu *cpu_buffer,
          struct rb_event_info *info)
{
    struct ring_buffer_event *event;
    struct buffer_page *tail_page;
    unsigned long tail, write, w;

    /* Don't let the compiler play games with cpu_buffer->tail_page */
    tail_page = info->tail_page = READ_ONCE(cpu_buffer->tail_page);

 /*A*/  w = local_read(&tail_page->write) & RB_WRITE_MASK;
    barrier();
    rb_time_read(&cpu_buffer->before_stamp, &info->before);
    rb_time_read(&cpu_buffer->write_stamp, &info->after);
    barrier();
    info->ts = rb_time_stamp(cpu_buffer->buffer);

    if ((info->add_timestamp & RB_ADD_STAMP_ABSOLUTE)) {
        info->delta = info->ts;
    } else {
        /*
         * If interrupting an event time update, we may need an
         * absolute timestamp.
         * Don't bother if this is the start of a new page (w == 0).
         */
        if (!w) {
            /* Use the sub-buffer timestamp */
            info->delta = 0;
        } else if (unlikely(info->before != info->after)) {
            info->add_timestamp |= RB_ADD_STAMP_FORCE | RB_ADD_STAMP_EXTEND;
            info->length += RB_LEN_TIME_EXTEND;
        } else {
            info->delta = info->ts - info->after;
            if (unlikely(test_time_stamp(info->delta))) {
                info->add_timestamp |= RB_ADD_STAMP_EXTEND;
                info->length += RB_LEN_TIME_EXTEND;
            }
        }
    }

 /*B*/  rb_time_set(&cpu_buffer->before_stamp, info->ts);

 /*C*/  write = local_add_return(info->length, &tail_page->write);

    /* set write to only the index of the write */
    write &= RB_WRITE_MASK;

    tail = write - info->length;

    /* See if we shot pass the end of this buffer page */
    if (unlikely(write > cpu_buffer->buffer->subbuf_size)) {
        check_buffer(cpu_buffer, info, CHECK_FULL_PAGE);
        return rb_move_tail(cpu_buffer, tail, info);
    }

    if (likely(tail == w)) {
        /* Nothing interrupted us between A and C */
 /*D*/      rb_time_set(&cpu_buffer->write_stamp, info->ts);
        /*
         * If something came in between C and D, the write stamp
         * may now not be in sync. But that's fine as the before_stamp
         * will be different and then next event will just be forced
         * to use an absolute timestamp.
         */
        if (likely(!(info->add_timestamp &
                 (RB_ADD_STAMP_FORCE | RB_ADD_STAMP_ABSOLUTE))))
            /* This did not interrupt any time update */
            info->delta = info->ts - info->after;
        else
            /* Just use full timestamp for interrupting event */
            info->delta = info->ts;
        check_buffer(cpu_buffer, info, tail);
    } else {
        PANIC("2");
    }

    /*
     * If this is the first commit on the page, then it has the same
     * timestamp as the page itself.
     */
    if (unlikely(!tail && !(info->add_timestamp &
                (RB_ADD_STAMP_FORCE | RB_ADD_STAMP_ABSOLUTE))))
        info->delta = 0;

    /* We reserved something on the buffer */

    event = __rb_page_index(tail_page, tail);
    rb_update_event(cpu_buffer, event, info);

    local_inc(&tail_page->entries);

    /*
     * If this is the first commit on the page, then update
     * its timestamp.
     */
    if (unlikely(!tail))
        tail_page->page->time_stamp = info->ts;

    /* account for these added bytes */
    local_add(info->length, &cpu_buffer->entries_bytes);

    return event;
}

static __always_inline struct ring_buffer_event *
rb_reserve_next_event(struct trace_buffer *buffer,
              struct ring_buffer_per_cpu *cpu_buffer,
              unsigned long length)
{
    struct ring_buffer_event *event;
    struct rb_event_info info;
    int nr_loops = 0;
    int add_ts_default;

    /*
     * ring buffer does cmpxchg as well as atomic64 operations
     * (which some archs use locking for atomic64), make sure this
     * is safe in NMI context
     */
    if ((!IS_ENABLED(CONFIG_ARCH_HAVE_NMI_SAFE_CMPXCHG) ||
         IS_ENABLED(CONFIG_GENERIC_ATOMIC64)) &&
        (unlikely(in_nmi()))) {
        return NULL;
    }

    rb_start_commit(cpu_buffer);
    /* The commit page can not change after this */

#ifdef CONFIG_RING_BUFFER_ALLOW_SWAP
    /*
     * Due to the ability to swap a cpu buffer from a buffer
     * it is possible it was swapped before we committed.
     * (committing stops a swap). We check for it here and
     * if it happened, we have to fail the write.
     */
    barrier();
    if (unlikely(READ_ONCE(cpu_buffer->buffer) != buffer)) {
        local_dec(&cpu_buffer->committing);
        local_dec(&cpu_buffer->commits);
        return NULL;
    }
#endif

    info.length = rb_calculate_event_length(length);

    if (ring_buffer_time_stamp_abs(cpu_buffer->buffer)) {
        add_ts_default = RB_ADD_STAMP_ABSOLUTE;
        info.length += RB_LEN_TIME_EXTEND;
        if (info.length > cpu_buffer->buffer->max_data_size)
            goto out_fail;
    } else {
        add_ts_default = RB_ADD_STAMP_NONE;
    }

 again:
    info.add_timestamp = add_ts_default;
    info.delta = 0;

    /*
     * We allow for interrupts to reenter here and do a trace.
     * If one does, it will cause this original code to loop
     * back here. Even with heavy interrupts happening, this
     * should only happen a few times in a row. If this happens
     * 1000 times in a row, there must be either an interrupt
     * storm or we have something buggy.
     * Bail!
     */
    if (RB_WARN_ON(cpu_buffer, ++nr_loops > 1000))
        goto out_fail;

    event = __rb_reserve_next(cpu_buffer, &info);

    if (unlikely(PTR_ERR(event) == -EAGAIN)) {
        if (info.add_timestamp & (RB_ADD_STAMP_FORCE | RB_ADD_STAMP_EXTEND))
            info.length -= RB_LEN_TIME_EXTEND;
        goto again;
    }

    if (likely(event))
        return event;

    PANIC("");
 out_fail:
    rb_end_commit(cpu_buffer);
    return NULL;
}

/**
 * ring_buffer_lock_reserve - reserve a part of the buffer
 * @buffer: the ring buffer to reserve from
 * @length: the length of the data to reserve (excluding event header)
 *
 * Returns a reserved event on the ring buffer to copy directly to.
 * The user of this interface will need to get the body to write into
 * and can use the ring_buffer_event_data() interface.
 *
 * The length is the length of the data needed, not the event length
 * which also includes the event header.
 *
 * Must be paired with ring_buffer_unlock_commit, unless NULL is returned.
 * If NULL is returned, then nothing has been allocated or locked.
 */
struct ring_buffer_event *
ring_buffer_lock_reserve(struct trace_buffer *buffer, unsigned long length)
{
    struct ring_buffer_per_cpu *cpu_buffer;
    struct ring_buffer_event *event;
    int cpu;

    /* If we are tracing schedule, we don't want to recurse */
    preempt_disable_notrace();

    if (unlikely(atomic_read(&buffer->record_disabled)))
        goto out;

    cpu = raw_smp_processor_id();

    if (unlikely(!cpumask_test_cpu(cpu, buffer->cpumask)))
        goto out;

    cpu_buffer = buffer->buffers[cpu];

    if (unlikely(atomic_read(&cpu_buffer->record_disabled)))
        goto out;

    if (unlikely(length > buffer->max_data_size))
        goto out;

    if (unlikely(trace_recursive_lock(cpu_buffer)))
        goto out;

    event = rb_reserve_next_event(buffer, cpu_buffer, length);
    if (!event)
        goto out_unlock;

    return event;

 out_unlock:
    trace_recursive_unlock(cpu_buffer);
 out:
    preempt_enable_notrace();
    return NULL;
}

/* inline for ring buffer fast paths */
static __always_inline void *
rb_event_data(struct ring_buffer_event *event)
{
    if (extended_time(event))
        event = skip_time_extend(event);
    WARN_ON_ONCE(event->type_len > RINGBUF_TYPE_DATA_TYPE_LEN_MAX);
    /* If length is in len field, then array[0] has the data */
    if (event->type_len)
        return (void *)&event->array[0];
    /* Otherwise length is in array[0] and array[1] has the data */
    return (void *)&event->array[1];
}

/**
 * ring_buffer_event_data - return the data of the event
 * @event: the event to get the data from
 */
void *ring_buffer_event_data(struct ring_buffer_event *event)
{
    return rb_event_data(event);
}

static void rb_commit(struct ring_buffer_per_cpu *cpu_buffer)
{
    local_inc(&cpu_buffer->entries);
    rb_end_commit(cpu_buffer);
}

/**
 * ring_buffer_nr_dirty_pages - get the number of used pages in the ring buffer
 * @buffer: The ring_buffer to get the number of pages from
 * @cpu: The cpu of the ring_buffer to get the number of pages from
 *
 * Returns the number of pages that have content in the ring buffer.
 */
size_t ring_buffer_nr_dirty_pages(struct trace_buffer *buffer, int cpu)
{
    size_t read;
    size_t lost;
    size_t cnt;

    read = local_read(&buffer->buffers[cpu]->pages_read);
    lost = local_read(&buffer->buffers[cpu]->pages_lost);
    cnt = local_read(&buffer->buffers[cpu]->pages_touched);

    if (WARN_ON_ONCE(cnt < lost))
        return 0;

    cnt -= lost;

    /* The reader can read an empty page, but not more than that */
    if (cnt < read) {
        WARN_ON_ONCE(read > cnt + 1);
        return 0;
    }

    return cnt - read;
}

static __always_inline bool full_hit(struct trace_buffer *buffer, int cpu, int full)
{
    struct ring_buffer_per_cpu *cpu_buffer = buffer->buffers[cpu];
    size_t nr_pages;
    size_t dirty;

    nr_pages = cpu_buffer->nr_pages;
    if (!nr_pages || !full)
        return true;

    /*
     * Add one as dirty will never equal nr_pages, as the sub-buffer
     * that the writer is on is not counted as dirty.
     * This is needed if "buffer_percent" is set to 100.
     */
    dirty = ring_buffer_nr_dirty_pages(buffer, cpu) + 1;

    return (dirty * 100) >= (full * nr_pages);
}

static __always_inline void
rb_wakeups(struct trace_buffer *buffer, struct ring_buffer_per_cpu *cpu_buffer)
{
    if (buffer->irq_work.waiters_pending) {
        buffer->irq_work.waiters_pending = false;
        /* irq_work_queue() supplies it's own memory barriers */
        irq_work_queue(&buffer->irq_work.work);
    }

    if (cpu_buffer->irq_work.waiters_pending) {
        cpu_buffer->irq_work.waiters_pending = false;
        /* irq_work_queue() supplies it's own memory barriers */
        irq_work_queue(&cpu_buffer->irq_work.work);
    }

    if (cpu_buffer->last_pages_touch == local_read(&cpu_buffer->pages_touched))
        return;

    if (cpu_buffer->reader_page == cpu_buffer->commit_page)
        return;

    if (!cpu_buffer->irq_work.full_waiters_pending)
        return;

    cpu_buffer->last_pages_touch = local_read(&cpu_buffer->pages_touched);

    if (!full_hit(buffer, cpu_buffer->cpu, cpu_buffer->shortest_full))
        return;

    cpu_buffer->irq_work.wakeup_full = true;
    cpu_buffer->irq_work.full_waiters_pending = false;
    /* irq_work_queue() supplies it's own memory barriers */
    irq_work_queue(&cpu_buffer->irq_work.work);
}

/**
 * ring_buffer_unlock_commit - commit a reserved
 * @buffer: The buffer to commit to
 *
 * This commits the data to the ring buffer, and releases any locks held.
 *
 * Must be paired with ring_buffer_lock_reserve.
 */
int ring_buffer_unlock_commit(struct trace_buffer *buffer)
{
    struct ring_buffer_per_cpu *cpu_buffer;
    int cpu = raw_smp_processor_id();

    cpu_buffer = buffer->buffers[cpu];

    rb_commit(cpu_buffer);

    rb_wakeups(buffer, cpu_buffer);

    trace_recursive_unlock(cpu_buffer);

    preempt_enable_notrace();

    return 0;
}

/**
 * ring_buffer_write - write data to the buffer without reserving
 * @buffer: The ring buffer to write to.
 * @length: The length of the data being written (excluding the event header)
 * @data: The data to write to the buffer.
 *
 * This is like ring_buffer_lock_reserve and ring_buffer_unlock_commit as
 * one function. If you already have the data to write to the buffer, it
 * may be easier to simply call this function.
 *
 * Note, like ring_buffer_lock_reserve, the length is the length of the data
 * and not the length of the event which would hold the header.
 */
int ring_buffer_write(struct trace_buffer *buffer,
              unsigned long length,
              void *data)
{
    struct ring_buffer_per_cpu *cpu_buffer;
    struct ring_buffer_event *event;
    void *body;
    int ret = -EBUSY;
    int cpu;

    PANIC("");
}

/**
 * ring_buffer_record_off - stop all writes into the buffer
 * @buffer: The ring buffer to stop writes to.
 *
 * This prevents all writes to the buffer. Any attempt to write
 * to the buffer after this will fail and return NULL.
 *
 * This is different than ring_buffer_record_disable() as
 * it works like an on/off switch, where as the disable() version
 * must be paired with a enable().
 */
void ring_buffer_record_off(struct trace_buffer *buffer)
{
    unsigned int rd;
    unsigned int new_rd;

    rd = atomic_read(&buffer->record_disabled);
    do {
        new_rd = rd | RB_BUFFER_OFF;
    } while (!atomic_try_cmpxchg(&buffer->record_disabled, &rd, new_rd));
}

/**
 * ring_buffer_overruns - get the number of overruns in buffer
 * @buffer: The ring buffer
 *
 * Returns the total number of overruns in the ring buffer
 * (all CPU entries)
 */
unsigned long ring_buffer_overruns(struct trace_buffer *buffer)
{
    struct ring_buffer_per_cpu *cpu_buffer;
    unsigned long overruns = 0;
    int cpu;

    /* if you care about this being correct, lock the buffer */
    for_each_buffer_cpu(buffer, cpu) {
        cpu_buffer = buffer->buffers[cpu];
        overruns += local_read(&cpu_buffer->overrun);
    }

    return overruns;
}

/**
 * ring_buffer_iter_empty - check if an iterator has no more to read
 * @iter: The iterator to check
 */
int ring_buffer_iter_empty(struct ring_buffer_iter *iter)
{
    PANIC("");
}

static bool rb_per_cpu_empty(struct ring_buffer_per_cpu *cpu_buffer)
{
    struct buffer_page *reader = cpu_buffer->reader_page;
    struct buffer_page *head = rb_set_head_page(cpu_buffer);
    struct buffer_page *commit = cpu_buffer->commit_page;

    /* In case of error, head will be NULL */
    if (unlikely(!head))
        return true;

    /* Reader should exhaust content in reader page */
    if (reader->read != rb_page_size(reader))
        return false;

    /*
     * If writers are committing on the reader page, knowing all
     * committed content has been read, the ring buffer is empty.
     */
    if (commit == reader)
        return true;

    /*
     * If writers are committing on a page other than reader page
     * and head page, there should always be content to read.
     */
    if (commit != head)
        return false;

    /*
     * Writers are committing on the head page, we just need
     * to care about there're committed data, and the reader will
     * swap reader page with head page when it is to read data.
     */
    return rb_page_commit(commit) == 0;
}

/**
 * ring_buffer_empty_cpu - is a cpu buffer of a ring buffer empty?
 * @buffer: The ring buffer
 * @cpu: The CPU buffer to test
 */
bool ring_buffer_empty_cpu(struct trace_buffer *buffer, int cpu)
{
    struct ring_buffer_per_cpu *cpu_buffer;
    unsigned long flags;
    bool dolock;
    bool ret;

    if (!cpumask_test_cpu(cpu, buffer->cpumask))
        return true;

    cpu_buffer = buffer->buffers[cpu];
    local_irq_save(flags);
    dolock = rb_reader_lock(cpu_buffer);
    ret = rb_per_cpu_empty(cpu_buffer);
    rb_reader_unlock(cpu_buffer, dolock);
    local_irq_restore(flags);

    return ret;
}

/**
 * ring_buffer_consume - return an event and consume it
 * @buffer: The ring buffer to get the next event from
 * @cpu: the cpu to read the buffer from
 * @ts: a variable to store the timestamp (may be NULL)
 * @lost_events: a variable to store if events were lost (may be NULL)
 *
 * Returns the next event in the ring buffer, and that event is consumed.
 * Meaning, that sequential reads will keep returning a different event,
 * and eventually empty the ring buffer if the producer is slower.
 */
struct ring_buffer_event *
ring_buffer_consume(struct trace_buffer *buffer, int cpu, u64 *ts,
            unsigned long *lost_events)
{
    struct ring_buffer_per_cpu *cpu_buffer;
    struct ring_buffer_event *event = NULL;
    unsigned long flags;
    bool dolock;

 again:
    /* might be called in atomic */
    preempt_disable();

    if (!cpumask_test_cpu(cpu, buffer->cpumask))
        goto out;

    cpu_buffer = buffer->buffers[cpu];
    local_irq_save(flags);
    dolock = rb_reader_lock(cpu_buffer);

    event = rb_buffer_peek(cpu_buffer, ts, lost_events);
    if (event) {
        cpu_buffer->lost_events = 0;
        rb_advance_reader(cpu_buffer);
    }

    rb_reader_unlock(cpu_buffer, dolock);
    local_irq_restore(flags);

 out:
    preempt_enable();

    if (event && event->type_len == RINGBUF_TYPE_PADDING)
        goto again;

    return event;
}

/**
 * ring_buffer_iter_peek - peek at the next event to be read
 * @iter: The ring buffer iterator
 * @ts: The timestamp counter of this event.
 *
 * This will return the event that will be read next, but does
 * not increment the iterator.
 */
struct ring_buffer_event *
ring_buffer_iter_peek(struct ring_buffer_iter *iter, u64 *ts)
{
    struct ring_buffer_per_cpu *cpu_buffer = iter->cpu_buffer;
    struct ring_buffer_event *event;
    unsigned long flags;

 again:
#if 0
    raw_spin_lock_irqsave(&cpu_buffer->reader_lock, flags);
    event = rb_iter_peek(iter, ts);
    raw_spin_unlock_irqrestore(&cpu_buffer->reader_lock, flags);

    if (event && event->type_len == RINGBUF_TYPE_PADDING)
        goto again;

    return event;
#endif
    PANIC("");
}

/**
 * ring_buffer_event_length - return the length of the event
 * @event: the event to get the length of
 *
 * Returns the size of the data load of a data event.
 * If the event is something other than a data event, it
 * returns the size of the event itself. With the exception
 * of a TIME EXTEND, where it still returns the size of the
 * data load of the data event after it.
 */
unsigned ring_buffer_event_length(struct ring_buffer_event *event)
{
    unsigned length;

    if (extended_time(event))
        event = skip_time_extend(event);

    length = rb_event_length(event);
    if (event->type_len > RINGBUF_TYPE_DATA_TYPE_LEN_MAX)
        return length;
    length -= RB_EVNT_HDR_SIZE;
    if (length > RB_MAX_SMALL_DATA + sizeof(event->array[0]))
                length -= sizeof(event->array[0]);
    return length;
}

static void rb_inc_iter(struct ring_buffer_iter *iter)
{
    struct ring_buffer_per_cpu *cpu_buffer = iter->cpu_buffer;

    /*
     * The iterator could be on the reader page (it starts there).
     * But the head could have moved, since the reader was
     * found. Check for this case and assign the iterator
     * to the head page instead of next.
     */
    if (iter->head_page == cpu_buffer->reader_page)
        iter->head_page = rb_set_head_page(cpu_buffer);
    else
        rb_inc_page(&iter->head_page);

    iter->page_stamp = iter->read_stamp = iter->head_page->page->time_stamp;
    iter->head = 0;
    iter->next_event = 0;
}

static struct ring_buffer_event *
rb_iter_head_event(struct ring_buffer_iter *iter)
{
    PANIC("");
}

static void
rb_update_iter_read_stamp(struct ring_buffer_iter *iter,
              struct ring_buffer_event *event)
{
    u64 delta;

    switch (event->type_len) {
    case RINGBUF_TYPE_PADDING:
        return;

    case RINGBUF_TYPE_TIME_EXTEND:
        delta = rb_event_time_stamp(event);
        iter->read_stamp += delta;
        return;

    case RINGBUF_TYPE_TIME_STAMP:
        delta = rb_event_time_stamp(event);
        delta = rb_fix_abs_ts(delta, iter->read_stamp);
        iter->read_stamp = delta;
        return;

    case RINGBUF_TYPE_DATA:
        iter->read_stamp += event->time_delta;
        return;

    default:
        RB_WARN_ON(iter->cpu_buffer, 1);
    }
}

static void rb_advance_iter(struct ring_buffer_iter *iter)
{
    struct ring_buffer_per_cpu *cpu_buffer;

    cpu_buffer = iter->cpu_buffer;

    /* If head == next_event then we need to jump to the next event */
    if (iter->head == iter->next_event) {
        /* If the event gets overwritten again, there's nothing to do */
        if (rb_iter_head_event(iter) == NULL)
            return;
    }

    iter->head = iter->next_event;

    /*
     * Check if we are at the end of the buffer.
     */
    if (iter->next_event >= rb_page_size(iter->head_page)) {
        /* discarded commits can make the page empty */
        if (iter->head_page == cpu_buffer->commit_page)
            return;
        rb_inc_iter(iter);
        return;
    }

    rb_update_iter_read_stamp(iter, iter->event);
}

/**
 * ring_buffer_iter_advance - advance the iterator to the next location
 * @iter: The ring buffer iterator
 *
 * Move the location of the iterator such that the next read will
 * be the next location of the iterator.
 */
void ring_buffer_iter_advance(struct ring_buffer_iter *iter)
{
    struct ring_buffer_per_cpu *cpu_buffer = iter->cpu_buffer;
    unsigned long flags;

    raw_spin_lock_irqsave(&cpu_buffer->reader_lock, flags);

    rb_advance_iter(iter);

    raw_spin_unlock_irqrestore(&cpu_buffer->reader_lock, flags);
}
