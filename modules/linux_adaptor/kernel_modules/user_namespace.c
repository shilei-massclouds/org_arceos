#include <linux/user_namespace.h>
#include <linux/projid.h>

kuid_t make_kuid(struct user_namespace *ns, uid_t uid)
{
    return KUIDT_INIT(0);
}

kgid_t make_kgid(struct user_namespace *ns, gid_t gid)
{
    return KGIDT_INIT(0);
}

uid_t from_kuid(struct user_namespace *targ, kuid_t kuid)
{
    return 0;
}

gid_t from_kgid(struct user_namespace *targ, kgid_t kgid)
{
    return 0;
}

kprojid_t make_kprojid(struct user_namespace *ns, projid_t projid)
{
    return KPROJIDT_INIT(0);
}

projid_t from_kprojid(struct user_namespace *targ, kprojid_t kprojid)
{
    return kprojid.val;
}
