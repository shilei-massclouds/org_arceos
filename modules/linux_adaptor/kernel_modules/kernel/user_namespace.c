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
