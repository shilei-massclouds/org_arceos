#include "booter.h"

// locking
CL_MINE(queued_spin_lock_slowpath)

// panic
CL_MINE(__stack_chk_fail)

// of_device
CL_MINE(of_device_is_compatible)

// irq
CL_MINE(__handle_domain_irq)
CL_MINE(handle_IPI)
CL_MINE(set_handle_irq)
CL_MINE(irq_set_chained_handler_and_data)
CL_MINE(irq_domain_add_legacy)

// cpu
CL_MINE(__cpu_online_mask)
CL_MINE(cpumask_next_and)
CL_MINE(cpu_bit_bitmap)
CL_MINE(__cpu_possible_mask)

// smp
CL_MINE(set_smp_cross_call)

// bitmap
CL_MINE(find_next_bit)

// percpu
CL_MINE(free_percpu)

// key
CL_MINE(static_key_disable)

CL_MINE(acpi_register_gsi)
CL_MINE(acpi_set_irq_model)
CL_MINE(acpi_table_parse_madt)
CL_MINE(__alloc_percpu)
CL_MINE(__bitmap_weight)
CL_MINE(cpumask_next)
CL_MINE(cpu_number)
CL_MINE(cpu_pm_register_notifier)
CL_MINE(gic_configure_irq)
CL_MINE(gic_cpu_config)
CL_MINE(gic_dist_config)
CL_MINE(gic_set_kvm_info)
CL_MINE(gicv2m_init)
CL_MINE(handle_bad_irq)
CL_MINE(handle_percpu_devid_irq)
CL_MINE(__ioremap)
CL_MINE(__irq_alloc_descs)
CL_MINE(irqchip_fwnode_ops)
CL_MINE(__irq_domain_alloc_fwnode)
CL_MINE(irq_domain_free_fwnode)
CL_MINE(irq_set_percpu_devid)
CL_MINE(irq_to_desc)
CL_MINE(is_of_node)
CL_MINE(kasprintf)
CL_MINE(numa_node)
CL_MINE(of_address_to_resource)
CL_MINE(this_cpu_has_cap)
