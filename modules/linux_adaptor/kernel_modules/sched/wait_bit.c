#include <linux/wait_bit.h>

#define WAIT_TABLE_BITS 8
#define WAIT_TABLE_SIZE (1 << WAIT_TABLE_BITS)

static wait_queue_head_t bit_wait_table[WAIT_TABLE_SIZE] __cacheline_aligned;

void __init wait_bit_init(void)
{
    int i;

    for (i = 0; i < WAIT_TABLE_SIZE; i++)
        init_waitqueue_head(bit_wait_table + i);
}
