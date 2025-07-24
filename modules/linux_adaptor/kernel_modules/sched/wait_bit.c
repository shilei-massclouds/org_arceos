#include <linux/wait_bit.h>
#include <linux/hash.h>
#include <linux/sched.h>

#define WAIT_TABLE_BITS 8
#define WAIT_TABLE_SIZE (1 << WAIT_TABLE_BITS)

static wait_queue_head_t bit_wait_table[WAIT_TABLE_SIZE] __cacheline_aligned;

void wake_up_var(void *var)
{
    __wake_up_bit(__var_waitqueue(var), var, -1);
}

wait_queue_head_t *__var_waitqueue(void *p)
{
    return bit_wait_table + hash_ptr(p, WAIT_TABLE_BITS);
}

void __wake_up_bit(struct wait_queue_head *wq_head, void *word, int bit)
{
    struct wait_bit_key key = __WAIT_BIT_KEY_INITIALIZER(word, bit);

    if (waitqueue_active(wq_head))
        __wake_up(wq_head, TASK_NORMAL, 1, &key);
}

static int
var_wake_function(struct wait_queue_entry *wq_entry, unsigned int mode,
          int sync, void *arg)
{
    struct wait_bit_key *key = arg;
    struct wait_bit_queue_entry *wbq_entry =
        container_of(wq_entry, struct wait_bit_queue_entry, wq_entry);

    if (wbq_entry->key.flags != key->flags ||
        wbq_entry->key.bit_nr != key->bit_nr)
        return 0;

    return autoremove_wake_function(wq_entry, mode, sync, key);
}

int autoremove_wake_function(struct wait_queue_entry *wq_entry, unsigned mode, int sync, void *key)
{
    int ret = default_wake_function(wq_entry, mode, sync, key);

    if (ret)
        list_del_init_careful(&wq_entry->entry);

    return ret;
}

void init_wait_var_entry(struct wait_bit_queue_entry *wbq_entry, void *var, int flags)
{
    *wbq_entry = (struct wait_bit_queue_entry){
        .key = {
            .flags  = (var),
            .bit_nr = -1,
        },
        .wq_entry = {
            .flags   = flags,
            .private = current,
            .func    = var_wake_function,
            .entry   = LIST_HEAD_INIT(wbq_entry->wq_entry.entry),
        },
    };
}

void __init wait_bit_init(void)
{
    int i;

    for (i = 0; i < WAIT_TABLE_SIZE; i++)
        init_waitqueue_head(bit_wait_table + i);
}
