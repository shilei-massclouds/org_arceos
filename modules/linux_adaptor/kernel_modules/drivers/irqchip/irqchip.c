#include <linux/acpi.h>
#include <linux/init.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/irqchip.h>
#include <linux/platform_device.h>

/*
 * This special of_device_id is the sentinel at the end of the
 * of_device_id[] array of all irqchips. It is automatically placed at
 * the end of the array by the linker, thanks to being part of a
 * special section.
 */
static const struct of_device_id
irqchip_of_match_end __used __section("__irqchip_of_table_end");

extern struct of_device_id __irqchip_of_table[];

void __init irqchip_init(void)
{
    of_irq_init(__irqchip_of_table);
    //acpi_probe_device_table(irqchip);
}
