#include <linux/export.h>
#include <linux/nsproxy.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/user_namespace.h>
#include <linux/proc_ns.h>
#include <linux/highuid.h>
#include <linux/cred.h>
#include <linux/securebits.h>
#include <linux/security.h>
#include <linux/keyctl.h>
#include <linux/key-type.h>
#include <keys/user-type.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/ctype.h>
#include <linux/projid.h>
#include <linux/fs_struct.h>
#include <linux/bsearch.h>
#include <linux/sort.h>

/**
 *  make_kprojid - Map a user-namespace projid pair into a kprojid.
 *  @ns:  User namespace that the projid is in
 *  @projid: Project identifier
 *
 *  Maps a user-namespace uid pair into a kernel internal kuid,
 *  and returns that kuid.
 *
 *  When there is no mapping defined for the user-namespace projid
 *  pair INVALID_PROJID is returned.  Callers are expected to test
 *  for and handle INVALID_PROJID being returned.  INVALID_PROJID
 *  may be tested for using projid_valid().
 */
kprojid_t make_kprojid(struct user_namespace *ns, projid_t projid)
{
#if 0
    /* Map the uid to a global kernel uid */
    return KPROJIDT_INIT(map_id_down(&ns->projid_map, projid));
#endif
    pr_err("%s: No impl.", __func__);
    return KPROJIDT_INIT(0);
}

/**
 *  from_kuid - Create a uid from a kuid user-namespace pair.
 *  @targ: The user namespace we want a uid in.
 *  @kuid: The kernel internal uid to start with.
 *
 *  Map @kuid into the user-namespace specified by @targ and
 *  return the resulting uid.
 *
 *  There is always a mapping into the initial user_namespace.
 *
 *  If @kuid has no mapping in @targ (uid_t)-1 is returned.
 */
uid_t from_kuid(struct user_namespace *targ, kuid_t kuid)
{
    pr_err("%s: No impl.", __func__);
    return 0;
    /* Map the uid from a global kernel uid */
    //return map_id_up(&targ->uid_map, __kuid_val(kuid));
}

/**
 *  from_kgid - Create a gid from a kgid user-namespace pair.
 *  @targ: The user namespace we want a gid in.
 *  @kgid: The kernel internal gid to start with.
 *
 *  Map @kgid into the user-namespace specified by @targ and
 *  return the resulting gid.
 *
 *  There is always a mapping into the initial user_namespace.
 *
 *  If @kgid has no mapping in @targ (gid_t)-1 is returned.
 */
gid_t from_kgid(struct user_namespace *targ, kgid_t kgid)
{
    pr_err("%s: No impl.", __func__);
    return 0;
    /* Map the gid from a global kernel gid */
    //return map_id_up(&targ->gid_map, __kgid_val(kgid));
}

/**
 *  from_kprojid - Create a projid from a kprojid user-namespace pair.
 *  @targ: The user namespace we want a projid in.
 *  @kprojid: The kernel internal project identifier to start with.
 *
 *  Map @kprojid into the user-namespace specified by @targ and
 *  return the resulting projid.
 *
 *  There is always a mapping into the initial user_namespace.
 *
 *  If @kprojid has no mapping in @targ (projid_t)-1 is returned.
 */
projid_t from_kprojid(struct user_namespace *targ, kprojid_t kprojid)
{
    pr_err("%s: No impl.", __func__);
    return kprojid.val;
    /* Map the uid from a global kernel uid */
    //return map_id_up(&targ->projid_map, __kprojid_val(kprojid));
}
