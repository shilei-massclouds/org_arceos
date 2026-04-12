// SPDX-License-Identifier: GPL-2.0-only

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/uaccess.h>

#include <asm/sbi.h>

static ssize_t cl_console_read(struct file *file, char __user *buf, size_t count,
			       loff_t *ppos)
{
	size_t done = 0;

	if (!count)
		return 0;

	while (done < count) {
		int ch = sbi_console_getchar();

		if (ch == -1) {
			if (done)
				break;
			continue;
		}
		if (ch < 0)
			return done ? (ssize_t)done : ch;

		if (ch == '\r')
			ch = '\n';
		if (put_user((char)ch, buf + done))
			return done ? (ssize_t)done : -EFAULT;
		done++;
	}

	return done;
}

static ssize_t cl_console_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	size_t done = 0;

	while (done < count) {
		char ch;

		if (get_user(ch, buf + done))
			return done ? (ssize_t)done : -EFAULT;
		sbi_console_putchar(ch);
		done++;
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
