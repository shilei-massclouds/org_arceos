#include <linux/device.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/msi.h>

#include "../adaptor.h"

/**
 * msi_device_domain_alloc_wired - Allocate a "wired" interrupt on @domain
 * @domain: The domain to allocate on
 * @hwirq:  The hardware interrupt number to allocate for
 * @type:   The interrupt type
 *
 * This weirdness supports wire to MSI controllers like MBIGEN.
 *
 * @hwirq is the hardware interrupt number which is handed in from
 * irq_create_fwspec_mapping(). As the wire to MSI domain is sparse, but
 * sized in firmware, the hardware interrupt number cannot be used as MSI
 * index. For the underlying irq chip the MSI index is irrelevant and
 * all it needs is the hardware interrupt number.
 *
 * To handle this the MSI index is allocated with MSI_ANY_INDEX and the
 * hardware interrupt number is stored along with the type information in
 * msi_desc::cookie so the underlying interrupt chip and domain code can
 * retrieve it.
 *
 * Return: The Linux interrupt number (> 0) or an error code
 */
int msi_device_domain_alloc_wired(struct irq_domain *domain, unsigned int hwirq,
                  unsigned int type)
{
    PANIC("");
}
