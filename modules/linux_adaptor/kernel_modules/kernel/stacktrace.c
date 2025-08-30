#include <linux/export.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/task_stack.h>
#include <linux/stacktrace.h>
#include <linux/ftrace.h>

#include <asm/stacktrace.h>

#include "../adaptor.h"

static inline int fp_is_valid(unsigned long fp, unsigned long sp)
{
    unsigned long low, high;

    low = sp + sizeof(struct stackframe);
    high = ALIGN(sp, THREAD_SIZE);

    return !(fp < low || fp > high || fp & 0x07);
}

void notrace walk_stackframe(struct task_struct *task, struct pt_regs *regs,
                 bool (*fn)(void *, unsigned long), void *arg)
{
    unsigned long fp, sp, pc;
    int graph_idx = 0;
    int level = 0;

    if (regs) {
        fp = frame_pointer(regs);
        sp = user_stack_pointer(regs);
        pc = instruction_pointer(regs);
    } else if (task == NULL || task == current) {
        fp = (unsigned long)__builtin_frame_address(0);
        sp = current_stack_pointer;
        pc = (unsigned long)walk_stackframe;
        level = -1;
    } else {
        /* task blocked in __switch_to */
        fp = task->thread.s[0];
        sp = task->thread.sp;
        pc = task->thread.ra;
    }

    for (;;) {
        struct stackframe *frame;

        if (unlikely(!__kernel_text_address(pc) || (level++ >= 0 && !fn(arg, pc))))
            break;

        if (unlikely(!fp_is_valid(fp, sp)))
            break;

        /* Unwind stack frame */
        frame = (struct stackframe *)fp - 1;
        sp = fp;
        if (regs && (regs->epc == pc) && fp_is_valid(frame->ra, sp)) {
            PANIC("stage1");
        } else {
            fp = frame->fp;
            pc = ftrace_graph_ret_addr(current, &graph_idx, frame->ra,
                           &frame->ra);
        }
    }
}

static bool print_trace_address(void *arg, unsigned long pc)
{
    const char *loglvl = arg;

    //print_ip_sym(loglvl, pc);
    printk("%s[<%lx>] %lx\n", loglvl, (void *) pc, (void *) pc);
    return true;
}

noinline void dump_backtrace(struct pt_regs *regs, struct task_struct *task,
            const char *loglvl)
{
    walk_stackframe(task, regs, print_trace_address, (void *)loglvl);
}

void show_stack(struct task_struct *task, unsigned long *sp, const char *loglvl)
{
    pr_cont("%sCall Trace:\n", loglvl);
    dump_backtrace(NULL, task, loglvl);
}
