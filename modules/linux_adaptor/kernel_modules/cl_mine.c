#include "clinux.h"

// virtio_blk
CL_MINE(blk_cleanup_queue)
CL_MINE(blk_execute_rq)
CL_MINE(blk_get_request)
CL_MINE(blk_mq_free_tag_set)
CL_MINE(blk_mq_stop_hw_queue)
CL_MINE(blk_mq_virtio_map_queues)
CL_MINE(blk_put_request)
CL_MINE(blk_queue_alignment_offset)
CL_MINE(blk_queue_io_min)
CL_MINE(blk_queue_io_opt)
CL_MINE(blk_queue_physical_block_size)
CL_MINE(blk_rq_map_kern)
CL_MINE(blk_status_to_errno)
CL_MINE(del_gendisk)
CL_MINE(_dev_err)
CL_MINE(ida_free)
CL_MINE(mutex_destroy)
CL_MINE(mutex_lock)
CL_MINE(mutex_unlock)
CL_MINE(param_ops_uint)
CL_MINE(put_disk)
CL_MINE(refcount_warn_saturate)
CL_MINE(set_disk_ro)
CL_MINE(__sysfs_match_string)
CL_MINE(unregister_blkdev)
CL_MINE(dump_page)

// vsprintf
CL_MINE(siphash_1u64)

// virtio_mmio
CL_MINE(devm_kfree)
CL_MINE(_dev_warn)
CL_MINE(free_irq)
CL_MINE(platform_driver_unregister)
CL_MINE(put_device)

// virtio
CL_MINE(add_uevent_var)
CL_MINE(bus_unregister)
CL_MINE(device_unregister)
CL_MINE(driver_unregister)
CL_MINE(ida_destroy)
CL_MINE(panic)

// virtio_ring
CL_MINE(dev_driver_string)
CL_MINE(dma_alloc_attrs)
CL_MINE(dma_free_attrs)
CL_MINE(dma_map_page_attrs)
CL_MINE(dma_max_mapping_size)
CL_MINE(dma_unmap_page_attrs)
CL_MINE(free_pages_exact)
CL_MINE(is_vmalloc_addr)
CL_MINE(__warn_printk)

// string_helpers
CL_MINE(hex_to_bin)
CL_MINE(strchr)
CL_MINE(get_cmdline)
CL_MINE(file_path)
CL_MINE(kstrdup)

// plic
CL_MINE(disable_percpu_irq)
CL_MINE(handle_fasteoi_irq)
CL_MINE(___ratelimit)
CL_MINE(iounmap)
CL_MINE(irq_domain_free_irqs_top)
