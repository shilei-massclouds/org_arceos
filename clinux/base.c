#include "booter.h"

void sbi_console_putchar(int ch);
//void cl_virtio_blk_init();
void virtio_init();

// NOTE: Don't expose these global vars.
//struct page *mem_map;
void *mem_map = 0;
unsigned long pfn_base;
unsigned long va_pa_offset;
int kmalloc_caches[1];

int clinux_start()
{
    sbi_puts("cLinux base is starting ...\n");
    //cl_virtio_blk_init();
    virtio_init();
    sbi_puts("cLinux base started!\n");
    return 303;
}

void sbi_puts(const char *s)
{
    for (; *s; s++) {
        if (*s == '\n')
            sbi_console_putchar('\r');
        sbi_console_putchar(*s);
    }
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

int snprintf(char *buf, size_t size, const char *fmt, ...)
{
    booter_panic("No impl.\n");
}

int sprintf(char *buf, const char *fmt, ...)
{
    booter_panic("No impl.\n");
}
