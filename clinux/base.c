#include <stdarg.h>
#include <linux/printk.h>
#include <linux/ctype.h>
#include <linux/device.h>
#include <linux/blk-mq.h>
#include <linux/blk_types.h>

#include "booter.h"

extern int vscnprintf(char *buf, size_t size, const char *fmt, va_list args);

const char hex_asc[] = "0123456789abcdef";
const char hex_asc_upper[] = "0123456789ABCDEF";

void sbi_console_putchar(int ch);
void cl_virtio_init();
void cl_virtio_mmio_init();
void cl_virtio_blk_init();

extern struct gendisk *cl_disk;

void bio_init(struct bio *bio, struct bio_vec *table,
          unsigned short max_vecs)
{
    memset(bio, 0, sizeof(*bio));
    atomic_set(&bio->__bi_remaining, 1);
    atomic_set(&bio->__bi_cnt, 1);

    bio->bi_io_vec = table;
    bio->bi_max_vecs = max_vecs;
}

static struct bio *cl_bio_alloc(unsigned int nr_iovecs)
{
    struct bio *bio;

    bio = kmalloc(struct_size(bio, bi_inline_vecs, nr_iovecs), 0);
    bio_init(bio, NULL, 0);
    bio->bi_max_vecs = nr_iovecs;
    bio->bi_io_vec = bio->bi_inline_vecs;
    return bio;
}

int clinux_start()
{
    sbi_puts("cLinux base is starting ...\n");
    sbi_puts("for virtio_mmio ...\n");
    cl_virtio_init();
    cl_virtio_mmio_init();
    cl_virtio_blk_init();

    /* Test virtio_blk disk. */
    if (cl_disk == NULL || cl_disk->queue == NULL) {
        booter_panic("cl_disk or its rq is NULL! check device_add_disk.");
    }
    const struct blk_mq_ops *mq_ops = cl_disk->queue->mq_ops;
    if (mq_ops == NULL) {
        booter_panic("mq_ops is NULL!");
    }

    struct blk_mq_hw_ctx hw_ctx;
    hw_ctx.queue = cl_disk->queue;

    struct request rq;
    rq.nr_phys_segments = 1;
    rq.__sector = 0x20;
    rq.ioprio = 0;

    rq.bio = cl_bio_alloc(1);
    rq.bio->bi_iter.bi_sector = rq.__sector;

    void *buf = alloc_pages_exact(4096, 0);
    __bio_add_page(rq.bio, buf, 4096, 0);

    struct blk_mq_queue_data data;
    data.rq = &rq;
    data.last = true;

    printk("mq_ops->queue_rq ...\n");
    blk_status_t status = mq_ops->queue_rq(&hw_ctx, &data);
    printk("mq_ops->queue_rq status (%d)\n", status);
    sbi_puts("cLinux base started!\n");
    return 0;
}

void sbi_puts(const char *s)
{
    for (; *s; s++) {
        if (*s == '\n')
            sbi_console_putchar('\r');
        sbi_console_putchar(*s);
    }
}

int vprintk(const char *fmt, va_list args)
{
    int n;
    char buf[512];
    char *msg;

    n = vscnprintf(buf, sizeof(buf), fmt, args);
    if (printk_get_level(buf)) {
        msg = buf + 2;
        n -= 2;
    } else {
        msg = buf;
    }
    sbi_puts(msg);
    //early_console->write(early_console, msg, n);
}

int printk(const char *fmt, ...)
{
    int ret;
    va_list args;
    va_start(args, fmt);
    ret = vprintk(printk_skip_level(fmt), args);
    va_end(args);
    return ret;
}

void _dev_warn(const struct device *dev, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vprintk(printk_skip_level(fmt), args);
    va_end(args);
}

void _dev_notice(const struct device *dev, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vprintk(printk_skip_level(fmt), args);
    va_end(args);
}

void sbi_put_u64(unsigned long n)
{
    char buf[UL_STR_SIZE];
    hex_to_str(n, buf, sizeof(buf));
    sbi_puts(buf);
}

void sbi_put_dec(unsigned long n)
{
    char buf[UL_STR_SIZE];
    dec_to_str(n, buf, sizeof(buf));
    sbi_puts(buf);
}

int hex_to_str(unsigned long n, char *str, size_t len)
{
    /* prefix with '0x' and end with '\0' */
    if (len != 19)
        return -1;

    str[0] = '0';
    str[1] = 'x';
    for (int i = 3; i <= 18; i++) {
        char c = (n >> ((18 - i)*4)) & 0xF;
        if (c >= 10) {
            c -= 10;
            c += 'A';
        } else {
            c += '0';
        }
        str[i-1] = c;
    }
    str[18] = '\0';

    return 0;
}

int dec_to_str(unsigned long n, char *str, size_t len)
{
    int i;
    int pos = 0;
    char stack[10];

    if (len < 10)
        return -1;

    while (1) {
        stack[pos] = '0' + n % 10;
        if (n < 10) {
            break;
        }
        pos++;
        n /= 10;
    }

    for (i = 0; i <= pos; i++) {
        str[i] = stack[pos - i];
    }
    str[i] = '\0';
    return 0;
}

/**
 * skip_spaces - Removes leading whitespace from @str.
 * @str: The string to be stripped.
 *
 * Returns a pointer to the first non-whitespace character in @str.
 */
char *skip_spaces(const char *str)
{
    while (isspace(*str))
        ++str;
    return (char *)str;
}

__weak void __warn_printk(const char *fmt, ...)
{
    sbi_puts("[RAW_WARN_PRINTK] ");
    sbi_puts(fmt);
    sbi_puts("\n");
    sbi_shutdown();
}

char *strchr(const char *s, int c)
{
    for (; *s != (char)c; ++s)
        if (*s == '\0')
            return NULL;
    return (char *)s;
}

unsigned long page_to_pfn(const struct page *page)
{
    unsigned long ret = virt_to_pfn(page);
    printk("%s: pfn(%lx)\n", __func__, ret);
    return ret;
}

struct page *pfn_to_page(unsigned long pfn)
{
    struct page *ret = pfn_to_virt(pfn);
    printk("%s: page(%lx)\n", __func__, (unsigned long)ret);
    return ret;
}
