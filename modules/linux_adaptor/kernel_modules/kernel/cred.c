#define pr_fmt(fmt) "CRED: " fmt

#include <linux/export.h>
#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/coredump.h>
#include <linux/key.h>
#include <linux/keyctl.h>
#include <linux/init_task.h>
#include <linux/security.h>
#include <linux/binfmts.h>
#include <linux/cn_proc.h>
#include <linux/uidgid.h>

/* init to 2 - one for init_task, one to ensure it is never freed */
static struct group_info init_groups = { .usage = REFCOUNT_INIT(2) };

/*
 * The initial credentials for the initial task
 */
struct cred init_cred = {
    .usage          = ATOMIC_INIT(4),
    .uid            = GLOBAL_ROOT_UID,
    .gid            = GLOBAL_ROOT_GID,
    .suid           = GLOBAL_ROOT_UID,
    .sgid           = GLOBAL_ROOT_GID,
    .euid           = GLOBAL_ROOT_UID,
    .egid           = GLOBAL_ROOT_GID,
    .fsuid          = GLOBAL_ROOT_UID,
    .fsgid          = GLOBAL_ROOT_GID,
    .securebits     = SECUREBITS_DEFAULT,
    .cap_inheritable    = CAP_EMPTY_SET,
    .cap_permitted      = CAP_FULL_SET,
    .cap_effective      = CAP_FULL_SET,
    .cap_bset       = CAP_FULL_SET,
    //.user           = INIT_USER,
    .user_ns        = &init_user_ns,
    .group_info     = &init_groups,
    //.ucounts        = &init_ucounts,
};
