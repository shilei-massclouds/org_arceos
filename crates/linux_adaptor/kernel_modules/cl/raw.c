// SPDX-License-Identifier: GPL-2.0-only
/*
 * SBI initialilization and all extension implementation.
 *
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 */

#include <asm/sbi.h>

#define UL_STR_SIZE 19  /* prefix with '0x' and end with '\0' */
#define SBI_EXT_0_1_CONSOLE_PUTCHAR 0x1
#define SBI_EXT_0_1_SHUTDOWN        0x8

/**
 * legacy_shutdown() - Remove all the harts from executing supervisor code.
 *
 * Return: None
 */
void legacy_shutdown(void)
{
    sbi_ecall(SBI_EXT_0_1_SHUTDOWN, 0, 0, 0, 0, 0, 0, 0);
}

/**
 * legacy_putchar() - Writes given character to the console device.
 * @ch: The data to be written to the console.
 *
 * Return: None
 */
void legacy_putchar(unsigned char ch)
{
    sbi_ecall(SBI_EXT_0_1_CONSOLE_PUTCHAR, 0, ch, 0, 0, 0, 0, 0);
}

void legacy_puts(const char *str)
{
    while (*str) {
        legacy_putchar(*str);
        str++;
    }
}

static int hex_to_str(unsigned long n, char *str, size_t len)
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

void legacy_put_hex(unsigned long n)
{
    char buf[UL_STR_SIZE];
    hex_to_str(n, buf, sizeof(buf));
    legacy_puts(buf);
}

// FixMe
void handle_exception()
{
}

// FixMe
void soc_early_init(unsigned long hartid, unsigned long dtb_pa)
{
}
