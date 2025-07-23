#include <linux/kernel.h>
#include <linux/threads.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/cpu.h>
#include <linux/group_cpus.h>
#include <linux/device/bus.h>

#include "blk.h"
#include "blk-mq.h"

void blk_mq_map_queues(struct blk_mq_queue_map *qmap)
{
    const struct cpumask *masks;
    unsigned int queue, cpu;

    masks = group_cpus_evenly(qmap->nr_queues);
    if (!masks) {
        for_each_possible_cpu(cpu)
            qmap->mq_map[cpu] = qmap->queue_offset;
        return;
    }

    for (queue = 0; queue < qmap->nr_queues; queue++) {
        for_each_cpu(cpu, &masks[queue])
            qmap->mq_map[cpu] = qmap->queue_offset + queue;
    }
    kfree(masks);
}
