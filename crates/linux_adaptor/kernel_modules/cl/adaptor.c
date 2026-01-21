#include <linux/mm.h>

unsigned long linux_virt_to_phys(unsigned long va)
{
    return __pa(va);
}

unsigned long linux_phys_to_virt(unsigned long pa)
{
    return (unsigned long) __va(pa);
}
