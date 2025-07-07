// SPDX-License-Identifier: GPL-2.0
#include <linux/err.h>
#include <linux/bug.h>
#include <linux/atomic.h>
#include <linux/errseq.h>

/* The low bits are designated for error code (max of MAX_ERRNO) */
#define ERRSEQ_SHIFT        ilog2(MAX_ERRNO + 1)

/* This bit is used as a flag to indicate whether the value has been seen */
#define ERRSEQ_SEEN     (1 << ERRSEQ_SHIFT)

/* The lowest bit of the counter */
#define ERRSEQ_CTR_INC      (1 << (ERRSEQ_SHIFT + 1))

/**
 * errseq_check() - Has an error occurred since a particular sample point?
 * @eseq: Pointer to errseq_t value to be checked.
 * @since: Previously-sampled errseq_t from which to check.
 *
 * Grab the value that eseq points to, and see if it has changed @since
 * the given value was sampled. The @since value is not advanced, so there
 * is no need to mark the value as seen.
 *
 * Return: The latest error set in the errseq_t or 0 if it hasn't changed.
 */
int errseq_check(errseq_t *eseq, errseq_t since)
{
    errseq_t cur = READ_ONCE(*eseq);

    if (likely(cur == since))
        return 0;
    return -(cur & MAX_ERRNO);
}

/**
 * errseq_check_and_advance() - Check an errseq_t and advance to current value.
 * @eseq: Pointer to value being checked and reported.
 * @since: Pointer to previously-sampled errseq_t to check against and advance.
 *
 * Grab the eseq value, and see whether it matches the value that @since
 * points to. If it does, then just return 0.
 *
 * If it doesn't, then the value has changed. Set the "seen" flag, and try to
 * swap it into place as the new eseq value. Then, set that value as the new
 * "since" value, and return whatever the error portion is set to.
 *
 * Note that no locking is provided here for concurrent updates to the "since"
 * value. The caller must provide that if necessary. Because of this, callers
 * may want to do a lockless errseq_check before taking the lock and calling
 * this.
 *
 * Return: Negative errno if one has been stored, or 0 if no new error has
 * occurred.
 */
int errseq_check_and_advance(errseq_t *eseq, errseq_t *since)
{
    int err = 0;
    errseq_t old, new;

    /*
     * Most callers will want to use the inline wrapper to check this,
     * so that the common case of no error is handled without needing
     * to take the lock that protects the "since" value.
     */
    old = READ_ONCE(*eseq);
    if (old != *since) {
        /*
         * Set the flag and try to swap it into place if it has
         * changed.
         *
         * We don't care about the outcome of the swap here. If the
         * swap doesn't occur, then it has either been updated by a
         * writer who is altering the value in some way (updating
         * counter or resetting the error), or another reader who is
         * just setting the "seen" flag. Either outcome is OK, and we
         * can advance "since" and return an error based on what we
         * have.
         */
        new = old | ERRSEQ_SEEN;
        if (new != old)
            cmpxchg(eseq, old, new);
        *since = new;
        err = -(new & MAX_ERRNO);
    }
    return err;
}
