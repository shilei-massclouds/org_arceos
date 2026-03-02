#include <linux/bug.h>
#include <linux/err.h>
#include <linux/limits.h>
#include <linux/log2.h>
#include <linux/math64.h>
#include <linux/math.h>
#include <linux/minmax.h>
#include <linux/module.h>

#include <linux/clk/analogbits-wrpll-cln28hpc.h>


/**
 * __wrpll_calc_fbdiv() - return feedback fixed divide value
 * @c: ptr to a struct wrpll_cfg record to read from
 *
 * The internal feedback path includes a fixed by-two divider; the
 * external feedback path does not.  Return the appropriate divider
 * value (2 or 1) depending on whether internal or external feedback
 * is enabled.  This code doesn't test for invalid configurations
 * (e.g. both or neither of WRPLL_FLAGS_*_FEEDBACK are set); it relies
 * on the caller to do so.
 *
 * Context: Any context.  Caller must protect the memory pointed to by
 *          @c from simultaneous modification.
 *
 * Return: 2 if internal feedback is enabled or 1 if external feedback
 *         is enabled.
 */
static u8 __wrpll_calc_fbdiv(const struct wrpll_cfg *c)
{
    return (c->flags & WRPLL_FLAGS_INT_FEEDBACK_MASK) ? 2 : 1;
}

/**
 * wrpll_calc_output_rate() - calculate the PLL's target output rate
 * @c: ptr to a struct wrpll_cfg record to read from
 * @parent_rate: PLL refclk rate
 *
 * Given a pointer to the PLL's current input configuration @c and the
 * PLL's input reference clock rate @parent_rate (before the R
 * pre-divider), calculate the PLL's output clock rate (after the Q
 * post-divider).
 *
 * Context: Any context.  Caller must protect the memory pointed to by @c
 *          from simultaneous modification.
 *
 * Return: the PLL's output clock rate, in Hz.  The return value from
 *         this function is intended to be convenient to pass directly
 *         to the Linux clock framework; thus there is no explicit
 *         error return value.
 */
unsigned long wrpll_calc_output_rate(const struct wrpll_cfg *c,
                     unsigned long parent_rate)
{
    u8 fbdiv;
    u64 n;

    if (c->flags & WRPLL_FLAGS_EXT_FEEDBACK_MASK) {
        WARN(1, "external feedback mode not yet supported");
        return ULONG_MAX;
    }

    fbdiv = __wrpll_calc_fbdiv(c);
    n = parent_rate * fbdiv * (c->divf + 1);
    n = div_u64(n, c->divr + 1);
    n >>= c->divq;

    return n;
}
