#include <linux/mm.h>

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
