#include <linux/fwnode.h>

static struct fwnode_handle *(*__get_intc_node)(void);

void riscv_set_intc_hwnode_fn(struct fwnode_handle *(*fn)(void))
{
    __get_intc_node = fn;
}

struct fwnode_handle *riscv_get_intc_hwnode(void)
{
    if (__get_intc_node)
        return __get_intc_node();

    return NULL;
}
EXPORT_SYMBOL_GPL(riscv_get_intc_hwnode);
