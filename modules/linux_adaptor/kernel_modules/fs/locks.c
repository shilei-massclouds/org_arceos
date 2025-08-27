#include <linux/capability.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/filelock.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/time.h>
#include <linux/rcupdate.h>
#include <linux/pid_namespace.h>
#include <linux/hashtable.h>
#include <linux/percpu.h>
#include <linux/sysctl.h>

#define CREATE_TRACE_POINTS
#include <trace/events/filelock.h>

#include <linux/uaccess.h>

#include "../adaptor.h"

/**
 *  __break_lease   -   revoke all outstanding leases on file
 *  @inode: the inode of the file to return
 *  @mode: O_RDONLY: break only write leases; O_WRONLY or O_RDWR:
 *      break all leases
 *  @type: FL_LEASE: break leases and delegations; FL_DELEG: break
 *      only delegations
 *
 *  break_lease (inlined for speed) has checked there already is at least
 *  some kind of lock (maybe a lease) on this file.  Leases are broken on
 *  a call to open() or truncate().  This function can sleep unless you
 *  specified %O_NONBLOCK to your open().
 */
int __break_lease(struct inode *inode, unsigned int mode, unsigned int type)
{
    PANIC("");
}

/*
 * This function is called when the file is being removed
 * from the task's fd array.  POSIX locks belonging to this task
 * are deleted at this time.
 */
void locks_remove_posix(struct file *filp, fl_owner_t owner)
{
    pr_notice("%s: No impl.", __func__);
}

/*
 * This function is called on the last close of an open file.
 */
void locks_remove_file(struct file *filp)
{
    pr_notice("%s: No impl.", __func__);
}
