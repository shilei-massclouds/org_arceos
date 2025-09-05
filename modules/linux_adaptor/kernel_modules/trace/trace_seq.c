#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/trace_seq.h>
#include "../adaptor.h"

/* How much buffer is left on the trace_seq? */
#define TRACE_SEQ_BUF_LEFT(s) seq_buf_buffer_left(&(s)->seq)

/*
 * trace_seq should work with being initialized with 0s.
 */
static inline void __trace_seq_init(struct trace_seq *s)
{
    if (unlikely(!s->seq.size))
        trace_seq_init(s);
}

/**
 * trace_seq_printf - sequence printing of trace information
 * @s: trace sequence descriptor
 * @fmt: printf format string
 *
 * The tracer may use either sequence operations or its own
 * copy to user routines. To simplify formatting of a trace
 * trace_seq_printf() is used to store strings into a special
 * buffer (@s). Then the output may be either used by
 * the sequencer or pulled into another buffer.
 */
void trace_seq_printf(struct trace_seq *s, const char *fmt, ...)
{
    unsigned int save_len = s->seq.len;
    va_list ap;

    if (s->full)
        return;

    __trace_seq_init(s);

    va_start(ap, fmt);
    seq_buf_vprintf(&s->seq, fmt, ap);
    va_end(ap);

    /* If we can't write it all, don't bother writing anything */
    if (unlikely(seq_buf_has_overflowed(&s->seq))) {
        s->seq.len = save_len;
        s->full = 1;
    }
}

/**
 * trace_seq_putc - trace sequence printing of simple character
 * @s: trace sequence descriptor
 * @c: simple character to record
 *
 * The tracer may use either the sequence operations or its own
 * copy to user routines. This function records a simple character
 * into a special buffer (@s) for later retrieval by a sequencer
 * or other mechanism.
 */
void trace_seq_putc(struct trace_seq *s, unsigned char c)
{
    if (s->full)
        return;

    __trace_seq_init(s);

    if (TRACE_SEQ_BUF_LEFT(s) < 1) {
        s->full = 1;
        return;
    }

    seq_buf_putc(&s->seq, c);
}

/**
 * trace_seq_vprintf - sequence printing of trace information
 * @s: trace sequence descriptor
 * @fmt: printf format string
 * @args: Arguments for the format string
 *
 * The tracer may use either sequence operations or its own
 * copy to user routines. To simplify formatting of a trace
 * trace_seq_printf is used to store strings into a special
 * buffer (@s). Then the output may be either used by
 * the sequencer or pulled into another buffer.
 */
void trace_seq_vprintf(struct trace_seq *s, const char *fmt, va_list args)
{
    unsigned int save_len = s->seq.len;

    if (s->full)
        return;

    __trace_seq_init(s);

    seq_buf_vprintf(&s->seq, fmt, args);

    /* If we can't write it all, don't bother writing anything */
    if (unlikely(seq_buf_has_overflowed(&s->seq))) {
        s->seq.len = save_len;
        s->full = 1;
    }
}
