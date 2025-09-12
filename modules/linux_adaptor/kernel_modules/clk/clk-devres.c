#include <linux/clk.h>
#include <linux/device.h>
#include <linux/export.h>
#include <linux/gfp.h>
#include "../adaptor.h"

struct devm_clk_state {
    struct clk *clk;
    void (*exit)(struct clk *clk);
};

static void devm_clk_release(struct device *dev, void *res)
{
    struct devm_clk_state *state = res;

    if (state->exit)
        state->exit(state->clk);

    clk_put(state->clk);
}

static struct clk *__devm_clk_get(struct device *dev, const char *id,
                  struct clk *(*get)(struct device *dev, const char *id),
                  int (*init)(struct clk *clk),
                  void (*exit)(struct clk *clk))
{
    struct devm_clk_state *state;
    struct clk *clk;
    int ret;

    state = devres_alloc(devm_clk_release, sizeof(*state), GFP_KERNEL);
    if (!state)
        return ERR_PTR(-ENOMEM);

    clk = get(dev, id);
    if (IS_ERR(clk)) {
        ret = PTR_ERR(clk);
        goto err_clk_get;
    }

    if (init) {
        ret = init(clk);
        if (ret)
            goto err_clk_init;
    }

    state->clk = clk;
    state->exit = exit;

    devres_add(dev, state);

    return clk;

err_clk_init:

    clk_put(clk);
err_clk_get:

    devres_free(state);
    return ERR_PTR(ret);
}

struct clk *devm_clk_get(struct device *dev, const char *id)
{
    return __devm_clk_get(dev, id, clk_get, NULL, NULL);
}
