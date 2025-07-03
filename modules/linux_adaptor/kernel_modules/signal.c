#include <linux/sched.h>

#include "booter.h"

int
send_sig(int sig, struct task_struct *p, int priv)
{
    log_debug("%s: No impl.", __func__);
}
