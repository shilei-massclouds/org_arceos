// SPDX-License-Identifier: GPL-2.0-only

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/uaccess.h>

#include <asm/sbi.h>

#define CL_CONSOLE_RW_CHUNK 64

static ssize_t cl_console_read(struct file *file, char __user *buf, size_t count,
			       loff_t *ppos)
{
	size_t done = 0;
	char kbuf[CL_CONSOLE_RW_CHUNK];

	if (!count)
		return 0;

	while (done < count) {
		size_t want = min_t(size_t, count - done, sizeof(kbuf));
		int ret = sbi_debug_console_read(kbuf, want);
		int i;

		if (ret == 0) {
			if (done)
				break;
			continue;
		}
		if (ret < 0)
			return done ? (ssize_t)done : ret;

		for (i = 0; i < ret; i++) {
			if (kbuf[i] == '\r')
				kbuf[i] = '\n';
		}
		if (copy_to_user(buf + done, kbuf, ret))
			return done ? (ssize_t)done : -EFAULT;
		done += ret;
	}

	return done;
}

static ssize_t cl_console_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	size_t done = 0;
	char kbuf[CL_CONSOLE_RW_CHUNK];

	while (done < count) {
		size_t want = min_t(size_t, count - done, sizeof(kbuf));
		int ret;

		if (copy_from_user(kbuf, buf + done, want))
			return done ? (ssize_t)done : -EFAULT;

		ret = sbi_debug_console_write(kbuf, want);
		if (ret < 0)
			return done ? (ssize_t)done : ret;
		if (ret == 0)
			break;

		done += ret;
	}

	return done;
}

static __poll_t cl_console_poll(struct file *file, poll_table *wait)
{
	return EPOLLIN | EPOLLRDNORM | EPOLLOUT | EPOLLWRNORM;
}

static const struct file_operations cl_console_fops = {
	.owner = THIS_MODULE,
	.open = stream_open,
	.read = cl_console_read,
	.write = cl_console_write,
	.poll = cl_console_poll,
	.llseek = noop_llseek,
};

int __init cl_console_init(void)
{
	return __register_chrdev(TTYAUX_MAJOR, 1, 1, "console", &cl_console_fops);
}

/*
 * Temporary: cl_do_initcalls() currently walks the regular initcall levels,
 * but not the dedicated .con_initcall section. Keep console registration on a
 * device initcall for now, and switch back to console_initcall() once the
 * con_initcall path is supported.
 */
device_initcall(cl_console_init);
