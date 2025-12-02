// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2016 Thomas Gleixner.
 * Copyright (C) 2016-2017 Christoph Hellwig.
 */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/sort.h>
#include <linux/group_cpus.h>

#include "adaptor.h"

static void grp_spread_init_one(struct cpumask *irqmsk, struct cpumask *nmsk,
                unsigned int cpus_per_grp)
{
    const struct cpumask *siblmsk;
    int cpu, sibl;

    for ( ; cpus_per_grp > 0; ) {
        cpu = cpumask_first(nmsk);

        /* Should not happen, but I'm too lazy to think about it */
        if (cpu >= nr_cpu_ids)
            return;

        cpumask_clear_cpu(cpu, nmsk);
        cpumask_set_cpu(cpu, irqmsk);
        cpus_per_grp--;

        /* If the cpu has siblings, use them first */
        siblmsk = topology_sibling_cpumask(cpu);
        for (sibl = -1; cpus_per_grp > 0; ) {
            sibl = cpumask_next(sibl, siblmsk);
            if (sibl >= nr_cpu_ids)
                break;
            if (!cpumask_test_and_clear_cpu(sibl, nmsk))
                continue;
            cpumask_set_cpu(sibl, irqmsk);
            cpus_per_grp--;
        }
    }
}

struct node_groups {
    unsigned id;

    union {
        unsigned ngroups;
        unsigned ncpus;
    };
};

static cpumask_var_t *alloc_node_to_cpumask(void)
{
    cpumask_var_t *masks;
    int node;

    masks = kcalloc(nr_node_ids, sizeof(cpumask_var_t), GFP_KERNEL);
    if (!masks)
        return NULL;

    for (node = 0; node < nr_node_ids; node++) {
        if (!zalloc_cpumask_var(&masks[node], GFP_KERNEL))
            goto out_unwind;
    }

    return masks;

out_unwind:
    while (--node >= 0)
        free_cpumask_var(masks[node]);
    kfree(masks);
    return NULL;
}

static void free_node_to_cpumask(cpumask_var_t *masks)
{
    int node;

    for (node = 0; node < nr_node_ids; node++)
        free_cpumask_var(masks[node]);
    kfree(masks);
}

static void build_node_to_cpumask(cpumask_var_t *masks)
{
    int cpu;

    for_each_possible_cpu(cpu)
        cpumask_set_cpu(cpu, masks[cpu_to_node(cpu)]);
}

static int get_nodes_in_cpumask(cpumask_var_t *node_to_cpumask,
                const struct cpumask *mask, nodemask_t *nodemsk)
{
    int n, nodes = 0;

    /* Calculate the number of nodes in the supplied affinity mask */
    for_each_node(n) {
        if (cpumask_intersects(mask, node_to_cpumask[n])) {
            node_set(n, *nodemsk);
            nodes++;
        }
    }
    return nodes;
}

/*
 * Allocate group number for each node, so that for each node:
 *
 * 1) the allocated number is >= 1
 *
 * 2) the allocated number is <= active CPU number of this node
 *
 * The actual allocated total groups may be less than @numgrps when
 * active total CPU number is less than @numgrps.
 *
 * Active CPUs means the CPUs in '@cpu_mask AND @node_to_cpumask[]'
 * for each node.
 */
static void alloc_nodes_groups(unsigned int numgrps,
                   cpumask_var_t *node_to_cpumask,
                   const struct cpumask *cpu_mask,
                   const nodemask_t nodemsk,
                   struct cpumask *nmsk,
                   struct node_groups *node_groups)
{

    PANIC("");
}

static int __group_cpus_evenly(unsigned int startgrp, unsigned int numgrps,
                   cpumask_var_t *node_to_cpumask,
                   const struct cpumask *cpu_mask,
                   struct cpumask *nmsk, struct cpumask *masks)
{
    unsigned int i, n, nodes, cpus_per_grp, extra_grps, done = 0;
    unsigned int last_grp = numgrps;
    unsigned int curgrp = startgrp;
    nodemask_t nodemsk = NODE_MASK_NONE;
    struct node_groups *node_groups;

    if (cpumask_empty(cpu_mask))
        return 0;

    nodes = get_nodes_in_cpumask(node_to_cpumask, cpu_mask, &nodemsk);

    /*
     * If the number of nodes in the mask is greater than or equal the
     * number of groups we just spread the groups across the nodes.
     */
    if (numgrps <= nodes) {
        for_each_node_mask(n, nodemsk) {
            /* Ensure that only CPUs which are in both masks are set */
            cpumask_and(nmsk, cpu_mask, node_to_cpumask[n]);
            cpumask_or(&masks[curgrp], &masks[curgrp], nmsk);
            if (++curgrp == last_grp)
                curgrp = 0;
        }
        return numgrps;
    }

    node_groups = kcalloc(nr_node_ids,
                   sizeof(struct node_groups),
                   GFP_KERNEL);
    if (!node_groups)
        return -ENOMEM;

    /* allocate group number for each node */
    alloc_nodes_groups(numgrps, node_to_cpumask, cpu_mask,
               nodemsk, nmsk, node_groups);
    for (i = 0; i < nr_node_ids; i++) {
        unsigned int ncpus, v;
        struct node_groups *nv = &node_groups[i];

        if (nv->ngroups == UINT_MAX)
            continue;

        /* Get the cpus on this node which are in the mask */
        cpumask_and(nmsk, cpu_mask, node_to_cpumask[nv->id]);
        ncpus = cpumask_weight(nmsk);
        if (!ncpus)
            continue;

        WARN_ON_ONCE(nv->ngroups > ncpus);

        /* Account for rounding errors */
        extra_grps = ncpus - nv->ngroups * (ncpus / nv->ngroups);

        /* Spread allocated groups on CPUs of the current node */
        for (v = 0; v < nv->ngroups; v++, curgrp++) {
            cpus_per_grp = ncpus / nv->ngroups;

            /* Account for extra groups to compensate rounding errors */
            if (extra_grps) {
                cpus_per_grp++;
                --extra_grps;
            }

            /*
             * wrapping has to be considered given 'startgrp'
             * may start anywhere
             */
            if (curgrp >= last_grp)
                curgrp = 0;
            grp_spread_init_one(&masks[curgrp], nmsk,
                        cpus_per_grp);
        }
        done += nv->ngroups;
    }
    kfree(node_groups);
    return done;
}

/**
 * group_cpus_evenly - Group all CPUs evenly per NUMA/CPU locality
 * @numgrps: number of groups
 *
 * Return: cpumask array if successful, NULL otherwise. And each element
 * includes CPUs assigned to this group
 *
 * Try to put close CPUs from viewpoint of CPU and NUMA locality into
 * same group, and run two-stage grouping:
 *  1) allocate present CPUs on these groups evenly first
 *  2) allocate other possible CPUs on these groups evenly
 *
 * We guarantee in the resulted grouping that all CPUs are covered, and
 * no same CPU is assigned to multiple groups
 */
struct cpumask *group_cpus_evenly(unsigned int numgrps)
{
    unsigned int curgrp = 0, nr_present = 0, nr_others = 0;
    cpumask_var_t *node_to_cpumask;
    cpumask_var_t nmsk, npresmsk;
    int ret = -ENOMEM;
    struct cpumask *masks = NULL;

    if (numgrps == 0)
        return NULL;

    printk("%s: numgrps(%u)\n", __func__, numgrps);

    if (!zalloc_cpumask_var(&nmsk, GFP_KERNEL))
        return NULL;

    if (!zalloc_cpumask_var(&npresmsk, GFP_KERNEL))
        goto fail_nmsk;

    node_to_cpumask = alloc_node_to_cpumask();
    if (!node_to_cpumask)
        goto fail_npresmsk;

    masks = kcalloc(numgrps, sizeof(*masks), GFP_KERNEL);
    if (!masks)
        goto fail_node_to_cpumask;

    build_node_to_cpumask(node_to_cpumask);

    /*
     * Make a local cache of 'cpu_present_mask', so the two stages
     * spread can observe consistent 'cpu_present_mask' without holding
     * cpu hotplug lock, then we can reduce deadlock risk with cpu
     * hotplug code.
     *
     * Here CPU hotplug may happen when reading `cpu_present_mask`, and
     * we can live with the case because it only affects that hotplug
     * CPU is handled in the 1st or 2nd stage, and either way is correct
     * from API user viewpoint since 2-stage spread is sort of
     * optimization.
     */
    cpumask_copy(npresmsk, data_race(cpu_present_mask));

    /* grouping present CPUs first */
    ret = __group_cpus_evenly(curgrp, numgrps, node_to_cpumask,
                  npresmsk, nmsk, masks);
    if (ret < 0)
        goto fail_build_affinity;
    nr_present = ret;

    /*
     * Allocate non present CPUs starting from the next group to be
     * handled. If the grouping of present CPUs already exhausted the
     * group space, assign the non present CPUs to the already
     * allocated out groups.
     */
    if (nr_present >= numgrps)
        curgrp = 0;
    else
        curgrp = nr_present;
    cpumask_andnot(npresmsk, cpu_possible_mask, npresmsk);
    ret = __group_cpus_evenly(curgrp, numgrps, node_to_cpumask,
                  npresmsk, nmsk, masks);
    if (ret >= 0)
        nr_others = ret;

 fail_build_affinity:
    if (ret >= 0)
        WARN_ON(nr_present + nr_others < numgrps);

 fail_node_to_cpumask:
    free_node_to_cpumask(node_to_cpumask);

 fail_npresmsk:
    free_cpumask_var(npresmsk);

 fail_nmsk:
    free_cpumask_var(nmsk);
    if (ret < 0) {
        kfree(masks);
        return NULL;
    }
    return masks;
}
