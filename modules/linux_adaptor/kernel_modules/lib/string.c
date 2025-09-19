// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/lib/string.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * This file should be used only for "library" routines that may have
 * alternative implementations on specific architectures (generally
 * found in <asm-xx/string.h>), or get overloaded by FORTIFY_SOURCE.
 * (Specifically, this file is built with __NO_FORTIFY.)
 *
 * Other helper functions should live in string_helpers.c.
 */

#define __NO_FORTIFY
#include <linux/bits.h>
#include <linux/bug.h>
#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/linkage.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/types.h>

#include <asm/page.h>
#include <asm/rwonce.h>
#include <linux/unaligned.h>
#include <asm/word-at-a-time.h>

#ifndef __HAVE_ARCH_STRNCASECMP
/**
 * strncasecmp - Case insensitive, length-limited string comparison
 * @s1: One string
 * @s2: The other string
 * @len: the maximum number of characters to compare
 */
int strncasecmp(const char *s1, const char *s2, size_t len)
{
    /* Yes, Virginia, it had better be unsigned */
    unsigned char c1, c2;

    if (!len)
        return 0;

    do {
        c1 = *s1++;
        c2 = *s2++;
        if (!c1 || !c2)
            break;
        if (c1 == c2)
            continue;
        c1 = tolower(c1);
        c2 = tolower(c2);
        if (c1 != c2)
            break;
    } while (--len);
    return (int)c1 - (int)c2;
}
EXPORT_SYMBOL(strncasecmp);
#endif

#ifndef __HAVE_ARCH_STRCPY
char *strcpy(char *dest, const char *src)
{
    char *tmp = dest;

    while ((*dest++ = *src++) != '\0')
        /* nothing */;
    return tmp;
}
EXPORT_SYMBOL(strcpy);
#endif

#ifndef __HAVE_ARCH_STRCHRNUL
/**
 * strchrnul - Find and return a character in a string, or end of string
 * @s: The string to be searched
 * @c: The character to search for
 *
 * Returns pointer to first occurrence of 'c' in s. If c is not found, then
 * return a pointer to the null byte at the end of s.
 */
char *strchrnul(const char *s, int c)
{
    while (*s && *s != (char)c)
        s++;
    return (char *)s;
}
EXPORT_SYMBOL(strchrnul);
#endif

#ifndef __HAVE_ARCH_STRSPN
/**
 * strspn - Calculate the length of the initial substring of @s which only contain letters in @accept
 * @s: The string to be searched
 * @accept: The string to search for
 */
size_t strspn(const char *s, const char *accept)
{
    const char *p;

    for (p = s; *p != '\0'; ++p) {
        if (!strchr(accept, *p))
            break;
    }
    return p - s;
}
EXPORT_SYMBOL(strspn);
#endif

#ifndef __HAVE_ARCH_STRCSPN
/**
 * strcspn - Calculate the length of the initial substring of @s which does not contain letters in @reject
 * @s: The string to be searched
 * @reject: The string to avoid
 */
size_t strcspn(const char *s, const char *reject)
{
    const char *p;

    for (p = s; *p != '\0'; ++p) {
        if (strchr(reject, *p))
            break;
    }
    return p - s;
}
EXPORT_SYMBOL(strcspn);
#endif

#ifndef __HAVE_ARCH_STRCHR
/**
 * strchr - Find the first occurrence of a character in a string
 * @s: The string to be searched
 * @c: The character to search for
 *
 * Note that the %NUL-terminator is considered part of the string, and can
 * be searched for.
 */
char *strchr(const char *s, int c)
{
    for (; *s != (char)c; ++s)
        if (*s == '\0')
            return NULL;
    return (char *)s;
}
EXPORT_SYMBOL(strchr);
#endif

/**
 * strcmp - Compare two strings
 * @cs: One string
 * @ct: Another string
 */
int strcmp(const char *cs, const char *ct)
{
    unsigned char c1, c2;

    while (1) {
        c1 = *cs++;
        c2 = *ct++;
        if (c1 != c2)
            return c1 < c2 ? -1 : 1;
        if (!c1)
            break;
    }
    return 0;
}
EXPORT_SYMBOL(strcmp);

#ifndef __HAVE_ARCH_STRRCHR
/**
 * strrchr - Find the last occurrence of a character in a string
 * @s: The string to be searched
 * @c: The character to search for
 */
char *strrchr(const char *s, int c)
{
    const char *last = NULL;
    do {
        if (*s == (char)c)
            last = s;
    } while (*s++);
    return (char *)last;
}
EXPORT_SYMBOL(strrchr);
#endif

/**
 * strncmp - Compare two length-limited strings
 * @cs: One string
 * @ct: Another string
 * @count: The maximum number of bytes to compare
 */
int strncmp(const char *cs, const char *ct, size_t count)
{
    unsigned char c1, c2;

    while (count) {
        c1 = *cs++;
        c2 = *ct++;
        if (c1 != c2)
            return c1 < c2 ? -1 : 1;
        if (!c1)
            break;
        count--;
    }
    return 0;
}
EXPORT_SYMBOL(strncmp);

#ifndef __HAVE_ARCH_STRCASECMP
int strcasecmp(const char *s1, const char *s2)
{
    int c1, c2;

    do {
        c1 = tolower(*s1++);
        c2 = tolower(*s2++);
    } while (c1 == c2 && c1 != 0);
    return c1 - c2;
}
EXPORT_SYMBOL(strcasecmp);
#endif

ssize_t sized_strscpy(char *dest, const char *src, size_t count)
{
	const struct word_at_a_time constants = WORD_AT_A_TIME_CONSTANTS;
	size_t max = count;
	long res = 0;

	if (count == 0 || WARN_ON_ONCE(count > INT_MAX))
		return -E2BIG;

#ifndef CONFIG_DCACHE_WORD_ACCESS
#ifdef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
	/*
	 * If src is unaligned, don't cross a page boundary,
	 * since we don't know if the next page is mapped.
	 */
	if ((long)src & (sizeof(long) - 1)) {
		size_t limit = PAGE_SIZE - ((long)src & (PAGE_SIZE - 1));
		if (limit < max)
			max = limit;
	}
#else
	/* If src or dest is unaligned, don't do word-at-a-time. */
	if (((long) dest | (long) src) & (sizeof(long) - 1))
		max = 0;
#endif
#endif

	/*
	 * load_unaligned_zeropad() or read_word_at_a_time() below may read
	 * uninitialized bytes after the trailing zero and use them in
	 * comparisons. Disable this optimization under KMSAN to prevent
	 * false positive reports.
	 */
	if (IS_ENABLED(CONFIG_KMSAN))
		max = 0;

	while (max >= sizeof(unsigned long)) {
		unsigned long c, data;

#ifdef CONFIG_DCACHE_WORD_ACCESS
		c = load_unaligned_zeropad(src+res);
#else
		c = read_word_at_a_time(src+res);
#endif
		if (has_zero(c, &data, &constants)) {
			data = prep_zero_mask(c, data, &constants);
			data = create_zero_mask(data);
			*(unsigned long *)(dest+res) = c & zero_bytemask(data);
			return res + find_zero(data);
		}
		*(unsigned long *)(dest+res) = c;
		res += sizeof(unsigned long);
		count -= sizeof(unsigned long);
		max -= sizeof(unsigned long);
	}

	while (count) {
		char c;

		c = src[res];
		dest[res] = c;
		if (!c)
			return res;
		res++;
		count--;
	}

	/* Hit buffer length without finding a NUL; force NUL-termination. */
	if (res)
		dest[res-1] = '\0';

	return -E2BIG;
}

#ifndef __HAVE_ARCH_STRNLEN
size_t strnlen(const char *s, size_t count)
{
    const char *sc;

    for (sc = s; count-- && *sc != '\0'; ++sc)
        /* nothing */;
    return sc - s;
}
#endif

#ifndef __HAVE_ARCH_MEMCHR
/**
 * memchr - Find a character in an area of memory.
 * @s: The memory area
 * @c: The byte to search for
 * @n: The size of the area.
 *
 * returns the address of the first occurrence of @c, or %NULL
 * if @c is not found
 */
void *memchr(const void *s, int c, size_t n)
{
    const unsigned char *p = s;
    while (n-- != 0) {
            if ((unsigned char)c == *p++) {
            return (void *)(p - 1);
        }
    }
    return NULL;
}
EXPORT_SYMBOL(memchr);
#endif

#ifndef __HAVE_ARCH_STRNCPY
char *strncpy(char *dest, const char *src, size_t count)
{
    char *tmp = dest;

    while (count) {
        if ((*tmp = *src) != 0)
            src++;
        tmp++;
        count--;
    }
    return dest;
}
EXPORT_SYMBOL(strncpy);
#endif

#ifndef __HAVE_ARCH_STRSTR
/**
 * strstr - Find the first substring in a %NUL terminated string
 * @s1: The string to be searched
 * @s2: The string to search for
 */
char *strstr(const char *s1, const char *s2)
{
    size_t l1, l2;

    l2 = strlen(s2);
    if (!l2)
        return (char *)s1;
    l1 = strlen(s1);
    while (l1 >= l2) {
        l1--;
        if (!memcmp(s1, s2, l2))
            return (char *)s1;
        s1++;
    }
    return NULL;
}
EXPORT_SYMBOL(strstr);
#endif

#ifndef __HAVE_ARCH_STRPBRK
/**
 * strpbrk - Find the first occurrence of a set of characters
 * @cs: The string to be searched
 * @ct: The characters to search for
 */
char *strpbrk(const char *cs, const char *ct)
{
    const char *sc;

    for (sc = cs; *sc != '\0'; ++sc) {
        if (strchr(ct, *sc))
            return (char *)sc;
    }
    return NULL;
}
EXPORT_SYMBOL(strpbrk);
#endif

#ifndef __HAVE_ARCH_STRSEP
/**
 * strsep - Split a string into tokens
 * @s: The string to be searched
 * @ct: The characters to search for
 *
 * strsep() updates @s to point after the token, ready for the next call.
 *
 * It returns empty tokens, too, behaving exactly like the libc function
 * of that name. In fact, it was stolen from glibc2 and de-fancy-fied.
 * Same semantics, slimmer shape. ;)
 */
char *strsep(char **s, const char *ct)
{
    char *sbegin = *s;
    char *end;

    if (sbegin == NULL)
        return NULL;

    end = strpbrk(sbegin, ct);
    if (end)
        *end++ = '\0';
    *s = end;
    return sbegin;
}
EXPORT_SYMBOL(strsep);
#endif

#ifndef __HAVE_ARCH_STRNCHR
/**
 * strnchr - Find a character in a length limited string
 * @s: The string to be searched
 * @count: The number of characters to be searched
 * @c: The character to search for
 *
 * Note that the %NUL-terminator is considered part of the string, and can
 * be searched for.
 */
char *strnchr(const char *s, size_t count, int c)
{
    while (count--) {
        if (*s == (char)c)
            return (char *)s;
        if (*s++ == '\0')
            break;
    }
    return NULL;
}
EXPORT_SYMBOL(strnchr);
#endif

static void *check_bytes8(const u8 *start, u8 value, unsigned int bytes)
{
    while (bytes) {
        if (*start != value)
            return (void *)start;
        start++;
        bytes--;
    }
    return NULL;
}

/**
 * memchr_inv - Find an unmatching character in an area of memory.
 * @start: The memory area
 * @c: Find a character other than c
 * @bytes: The size of the area.
 *
 * returns the address of the first character other than @c, or %NULL
 * if the whole buffer contains just @c.
 */
void *memchr_inv(const void *start, int c, size_t bytes)
{
    u8 value = c;
    u64 value64;
    unsigned int words, prefix;

    if (bytes <= 16)
        return check_bytes8(start, value, bytes);

    value64 = value;
#if defined(CONFIG_ARCH_HAS_FAST_MULTIPLIER) && BITS_PER_LONG == 64
    value64 *= 0x0101010101010101ULL;
#elif defined(CONFIG_ARCH_HAS_FAST_MULTIPLIER)
    value64 *= 0x01010101;
    value64 |= value64 << 32;
#else
    value64 |= value64 << 8;
    value64 |= value64 << 16;
    value64 |= value64 << 32;
#endif

    prefix = (unsigned long)start % 8;
    if (prefix) {
        u8 *r;

        prefix = 8 - prefix;
        r = check_bytes8(start, value, prefix);
        if (r)
            return r;
        start += prefix;
        bytes -= prefix;
    }

    words = bytes / 8;

    while (words) {
        if (*(u64 *)start != value64)
            return check_bytes8(start, value, 8);
        start += 8;
        words--;
    }

    return check_bytes8(start, value, bytes % 8);
}
