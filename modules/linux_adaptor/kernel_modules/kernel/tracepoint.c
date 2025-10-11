#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/tracepoint.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/static_key.h>

#include "../adaptor.h"

enum tp_func_state {
    TP_FUNC_0,
    TP_FUNC_1,
    TP_FUNC_2,
    TP_FUNC_N,
};

DEFINE_SRCU(tracepoint_srcu);
EXPORT_SYMBOL_GPL(tracepoint_srcu);

static struct rcu_head *early_probes;
static bool ok_to_free_tracepoints;

enum tp_transition_sync {
    TP_TRANSITION_SYNC_1_0_1,
    TP_TRANSITION_SYNC_N_2_1,

    _NR_TP_TRANSITION_SYNC,
};

struct tp_transition_snapshot {
    unsigned long rcu;
    unsigned long srcu;
    bool ongoing;
};

/* Protected by tracepoints_mutex */
static struct tp_transition_snapshot tp_transition_snapshot[_NR_TP_TRANSITION_SYNC];

static void tp_rcu_get_state(enum tp_transition_sync sync)
{
    struct tp_transition_snapshot *snapshot = &tp_transition_snapshot[sync];

    /* Keep the latest get_state snapshot. */
    snapshot->rcu = get_state_synchronize_rcu();
    snapshot->srcu = start_poll_synchronize_srcu(&tracepoint_srcu);
    snapshot->ongoing = true;
}

static void tp_rcu_cond_sync(enum tp_transition_sync sync)
{
    struct tp_transition_snapshot *snapshot = &tp_transition_snapshot[sync];

    if (!snapshot->ongoing)
        return;
    cond_synchronize_rcu(snapshot->rcu);
    if (!poll_state_synchronize_srcu(&tracepoint_srcu, snapshot->srcu))
        synchronize_srcu(&tracepoint_srcu);
    snapshot->ongoing = false;
}

/* Set to 1 to enable tracepoint debug output */
static const int tracepoint_debug;

/*
 * Note about RCU :
 * It is used to delay the free of multiple probes array until a quiescent
 * state is reached.
 */
struct tp_probes {
    struct rcu_head rcu;
    struct tracepoint_func probes[];
};

/* Called in removal of a func but failed to allocate a new tp_funcs */
static void tp_stub_func(void)
{
    return;
}

static void srcu_free_old_probes(struct rcu_head *head)
{
    kfree(container_of(head, struct tp_probes, rcu));
}

static void rcu_free_old_probes(struct rcu_head *head)
{
    call_srcu(&tracepoint_srcu, head, srcu_free_old_probes);
}

static inline void *allocate_probes(int count)
{
    struct tp_probes *p  = kmalloc(struct_size(p, probes, count),
                       GFP_KERNEL);
    return p == NULL ? NULL : p->probes;
}

static inline void release_probes(struct tracepoint_func *old)
{
    if (old) {
        struct tp_probes *tp_probes = container_of(old,
            struct tp_probes, probes[0]);

        /*
         * We can't free probes if SRCU is not initialized yet.
         * Postpone the freeing till after SRCU is initialized.
         */
        if (unlikely(!ok_to_free_tracepoints)) {
            tp_probes->rcu.next = early_probes;
            early_probes = &tp_probes->rcu;
            return;
        }

        /*
         * Tracepoint probes are protected by both sched RCU and SRCU,
         * by calling the SRCU callback in the sched RCU callback we
         * cover both cases. So let us chain the SRCU and sched RCU
         * callbacks to wait for both grace periods.
         */
        call_rcu(&tp_probes->rcu, rcu_free_old_probes);
    }
}

static void debug_print_probes(struct tracepoint_func *funcs)
{
    int i;

    if (!tracepoint_debug || !funcs)
        return;

    for (i = 0; funcs[i].func; i++)
        printk(KERN_DEBUG "Probe %d : %p\n", i, funcs[i].func);
}

static struct tracepoint_func *
func_add(struct tracepoint_func **funcs, struct tracepoint_func *tp_func,
     int prio)
{
    struct tracepoint_func *old, *new;
    int iter_probes;    /* Iterate over old probe array. */
    int nr_probes = 0;  /* Counter for probes */
    int pos = -1;       /* Insertion position into new array */

    if (WARN_ON(!tp_func->func))
        return ERR_PTR(-EINVAL);

    debug_print_probes(*funcs);
    old = *funcs;
    if (old) {
        /* (N -> N+1), (N != 0, 1) probes */
        for (iter_probes = 0; old[iter_probes].func; iter_probes++) {
            if (old[iter_probes].func == tp_stub_func)
                continue;   /* Skip stub functions. */
            if (old[iter_probes].func == tp_func->func &&
                old[iter_probes].data == tp_func->data)
                return ERR_PTR(-EEXIST);
            nr_probes++;
        }
    }
    /* + 2 : one for new probe, one for NULL func */
    new = allocate_probes(nr_probes + 2);
    if (new == NULL)
        return ERR_PTR(-ENOMEM);
    if (old) {
        nr_probes = 0;
        for (iter_probes = 0; old[iter_probes].func; iter_probes++) {
            if (old[iter_probes].func == tp_stub_func)
                continue;
            /* Insert before probes of lower priority */
            if (pos < 0 && old[iter_probes].prio < prio)
                pos = nr_probes++;
            new[nr_probes++] = old[iter_probes];
        }
        if (pos < 0)
            pos = nr_probes++;
        /* nr_probes now points to the end of the new array */
    } else {
        pos = 0;
        nr_probes = 1; /* must point at end of array */
    }
    new[pos] = *tp_func;
    new[nr_probes].func = NULL;
    *funcs = new;
    debug_print_probes(*funcs);
    return old;
}

/*
 * tracepoints_mutex protects the builtin and module tracepoints.
 * tracepoints_mutex nests inside tracepoint_module_list_mutex.
 */
static DEFINE_MUTEX(tracepoints_mutex);

/*
 * Count the number of functions (enum tp_func_state) in a tp_funcs array.
 */
static enum tp_func_state nr_func_state(const struct tracepoint_func *tp_funcs)
{
    if (!tp_funcs)
        return TP_FUNC_0;
    if (!tp_funcs[1].func)
        return TP_FUNC_1;
    if (!tp_funcs[2].func)
        return TP_FUNC_2;
    return TP_FUNC_N;   /* 3 or more */
}

static void tracepoint_update_call(struct tracepoint *tp, struct tracepoint_func *tp_funcs)
{
    void *func = tp->iterator;

    /* Synthetic events do not have static call sites */
    if (!tp->static_call_key)
        return;
    if (nr_func_state(tp_funcs) == TP_FUNC_1)
        func = tp_funcs[0].func;
    __static_call_update(tp->static_call_key, tp->static_call_tramp, func);
}

/*
 * Add the probe function to a tracepoint.
 */
static int tracepoint_add_func(struct tracepoint *tp,
                   struct tracepoint_func *func, int prio,
                   bool warn)
{
    struct tracepoint_func *old, *tp_funcs;
    int ret;

    if (tp->regfunc && !static_key_enabled(&tp->key)) {
        ret = tp->regfunc();
        if (ret < 0)
            return ret;
    }

    tp_funcs = rcu_dereference_protected(tp->funcs,
            lockdep_is_held(&tracepoints_mutex));
    old = func_add(&tp_funcs, func, prio);
    if (IS_ERR(old)) {
        WARN_ON_ONCE(warn && PTR_ERR(old) != -ENOMEM);
        return PTR_ERR(old);
    }

    /*
     * rcu_assign_pointer has as smp_store_release() which makes sure
     * that the new probe callbacks array is consistent before setting
     * a pointer to it.  This array is referenced by __DO_TRACE from
     * include/linux/tracepoint.h using rcu_dereference_sched().
     */
    switch (nr_func_state(tp_funcs)) {
    case TP_FUNC_1:     /* 0->1 */
        /*
         * Make sure new static func never uses old data after a
         * 1->0->1 transition sequence.
         */
        tp_rcu_cond_sync(TP_TRANSITION_SYNC_1_0_1);
        /* Set static call to first function */
        tracepoint_update_call(tp, tp_funcs);
        /* Both iterator and static call handle NULL tp->funcs */
        rcu_assign_pointer(tp->funcs, tp_funcs);
        static_key_enable(&tp->key);
        break;
    case TP_FUNC_2:     /* 1->2 */
        /* Set iterator static call */
        tracepoint_update_call(tp, tp_funcs);
        /*
         * Iterator callback installed before updating tp->funcs.
         * Requires ordering between RCU assign/dereference and
         * static call update/call.
         */
        fallthrough;
    case TP_FUNC_N:     /* N->N+1 (N>1) */
        rcu_assign_pointer(tp->funcs, tp_funcs);
        /*
         * Make sure static func never uses incorrect data after a
         * N->...->2->1 (N>1) transition sequence.
         */
        if (tp_funcs[0].data != old[0].data)
            tp_rcu_get_state(TP_TRANSITION_SYNC_N_2_1);
        break;
    default:
        WARN_ON_ONCE(1);
        break;
    }

    release_probes(old);
    return 0;
}

/*
 * Remove a probe function from a tracepoint.
 * Note: only waiting an RCU period after setting elem->call to the empty
 * function insures that the original callback is not used anymore. This insured
 * by preempt_disable around the call site.
 */
static int tracepoint_remove_func(struct tracepoint *tp,
        struct tracepoint_func *func)
{
    PANIC("");
}

/**
 * tracepoint_probe_register -  Connect a probe to a tracepoint
 * @tp: tracepoint
 * @probe: probe handler
 * @data: tracepoint data
 *
 * Returns 0 if ok, error value on error.
 * Note: if @tp is within a module, the caller is responsible for
 * unregistering the probe before the module is gone. This can be
 * performed either with a tracepoint module going notifier, or from
 * within module exit functions.
 */
int tracepoint_probe_register(struct tracepoint *tp, void *probe, void *data)
{
    return tracepoint_probe_register_prio(tp, probe, data, TRACEPOINT_DEFAULT_PRIO);
}

/**
 * tracepoint_probe_unregister -  Disconnect a probe from a tracepoint
 * @tp: tracepoint
 * @probe: probe function pointer
 * @data: tracepoint data
 *
 * Returns 0 if ok, error value on error.
 */
int tracepoint_probe_unregister(struct tracepoint *tp, void *probe, void *data)
{
    struct tracepoint_func tp_func;
    int ret;

    mutex_lock(&tracepoints_mutex);
    tp_func.func = probe;
    tp_func.data = data;
    ret = tracepoint_remove_func(tp, &tp_func);
    mutex_unlock(&tracepoints_mutex);
    return ret;
}

/**
 * tracepoint_probe_register_prio_may_exist -  Connect a probe to a tracepoint with priority
 * @tp: tracepoint
 * @probe: probe handler
 * @data: tracepoint data
 * @prio: priority of this function over other registered functions
 *
 * Same as tracepoint_probe_register_prio() except that it will not warn
 * if the tracepoint is already registered.
 */
int tracepoint_probe_register_prio_may_exist(struct tracepoint *tp, void *probe,
                         void *data, int prio)
{
    struct tracepoint_func tp_func;
    int ret;

    mutex_lock(&tracepoints_mutex);
    tp_func.func = probe;
    tp_func.data = data;
    tp_func.prio = prio;
    ret = tracepoint_add_func(tp, &tp_func, prio, false);
    mutex_unlock(&tracepoints_mutex);
    return ret;
}

/**
 * tracepoint_probe_register_prio -  Connect a probe to a tracepoint with priority
 * @tp: tracepoint
 * @probe: probe handler
 * @data: tracepoint data
 * @prio: priority of this function over other registered functions
 *
 * Returns 0 if ok, error value on error.
 * Note: if @tp is within a module, the caller is responsible for
 * unregistering the probe before the module is gone. This can be
 * performed either with a tracepoint module going notifier, or from
 * within module exit functions.
 */
int tracepoint_probe_register_prio(struct tracepoint *tp, void *probe,
                   void *data, int prio)
{
    struct tracepoint_func tp_func;
    int ret;

    mutex_lock(&tracepoints_mutex);
    tp_func.func = probe;
    tp_func.data = data;
    tp_func.prio = prio;
    ret = tracepoint_add_func(tp, &tp_func, prio, true);
    mutex_unlock(&tracepoints_mutex);
    return ret;
}
