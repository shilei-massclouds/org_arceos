#include "booter.h"

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
CL_MINE(del_gendisk)
CL_MINE(_dev_err)
CL_MINE(ida_free)
CL_MINE(mutex_destroy)
CL_MINE(param_ops_uint)
CL_MINE(put_disk)
CL_MINE(refcount_warn_saturate)
CL_MINE(set_disk_ro)
CL_MINE(__sysfs_match_string)
CL_MINE(unregister_blkdev)

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

// string_helpers
CL_MINE(hex_to_bin)
CL_MINE(get_cmdline)
CL_MINE(file_path)

// plic
CL_MINE(disable_percpu_irq)
CL_MINE(handle_fasteoi_irq)
CL_MINE(iounmap)
CL_MINE(irq_domain_free_irqs_top)

// ext2/inode
CL_MINE(__blockdev_direct_IO)
CL_MINE(block_is_partially_uptodate)
CL_MINE(block_truncate_page)
CL_MINE(block_write_begin)
CL_MINE(buffer_migrate_page)
CL_MINE(clear_inode)
CL_MINE(current_time)
CL_MINE(fs_overflowgid)
CL_MINE(fs_overflowuid)
CL_MINE(generic_block_bmap)
CL_MINE(generic_block_fiemap)
CL_MINE(generic_error_remove_page)
CL_MINE(generic_fillattr)
CL_MINE(iget_failed)
CL_MINE(init_special_inode)
CL_MINE(inode_dio_wait)
CL_MINE(inode_needs_sync)
CL_MINE(inode_nohighmem)
CL_MINE(invalidate_inode_buffers)
CL_MINE(is_bad_inode)
CL_MINE(mark_buffer_dirty_inode)
CL_MINE(mpage_readahead)
CL_MINE(mpage_writepages)
CL_MINE(nobh_truncate_page)
CL_MINE(nobh_write_begin)
CL_MINE(nobh_write_end)
CL_MINE(nobh_writepage)
CL_MINE(posix_acl_chmod)
CL_MINE(__sb_end_write)
CL_MINE(__sb_start_write)
CL_MINE(setattr_copy)
CL_MINE(setattr_prepare)
CL_MINE(sync_inode_metadata)
CL_MINE(sync_mapping_buffers)
CL_MINE(truncate_inode_pages_final)
CL_MINE(truncate_pagecache)
CL_MINE(truncate_setsize)

// ext2/namei
CL_MINE(d_instantiate)
CL_MINE(d_instantiate_new)
CL_MINE(discard_new_inode)
CL_MINE(d_obtain_alias)
CL_MINE(drop_nlink)
CL_MINE(d_tmpfile)
CL_MINE(ihold)
CL_MINE(inc_nlink)
CL_MINE(page_symlink)

// ext2/ioctl
CL_MINE(inode_owner_or_capable)
CL_MINE(mnt_drop_write_file)
CL_MINE(mnt_want_write_file)
CL_MINE(vfs_ioc_setflags_prepare)

// ext2/file
CL_MINE(generic_file_fsync)
CL_MINE(generic_file_llseek)
CL_MINE(generic_file_mmap)
CL_MINE(generic_file_open)
CL_MINE(generic_file_splice_read)
CL_MINE(generic_file_write_iter)
CL_MINE(iter_file_splice_write)

// ext2/balloc
CL_MINE(bh_submit_read)
CL_MINE(bh_uptodate_or_lock)
CL_MINE(capable)
CL_MINE(find_next_zero_bit)
CL_MINE(in_group_p)
CL_MINE(inode_add_bytes)
CL_MINE(inode_sub_bytes)
CL_MINE(memscan)

// ext2/ialloc
CL_MINE(blockdev_superblock)
CL_MINE(__breadahead)
CL_MINE(inode_init_owner)
CL_MINE(insert_inode_locked)
CL_MINE(make_bad_inode)
CL_MINE(prandom_u32)

// ext2/super
CL_MINE(from_kgid_munged)
CL_MINE(from_kuid_munged)
CL_MINE(generic_fh_to_dentry)
CL_MINE(generic_fh_to_parent)
CL_MINE(init_user_ns)
CL_MINE(kill_block_super)
CL_MINE(match_int)
CL_MINE(match_token)
CL_MINE(rcu_barrier)
CL_MINE(seq_printf)
CL_MINE(seq_puts)
CL_MINE(strsep)
CL_MINE(sync_filesystem)
CL_MINE(unregister_filesystem)

// ext2/dir
CL_MINE(generic_read_dir)
CL_MINE(__lock_page)
CL_MINE(fs_umode_to_ftype)
CL_MINE(write_one_page)

// ext2/symlink
CL_MINE(simple_get_link)
CL_MINE(page_get_link)

// ext4
CL_MINE(bio_devname)
CL_MINE(blkdev_get_by_dev)
CL_MINE(__blkdev_issue_discard)
CL_MINE(blkdev_issue_discard)
CL_MINE(blkdev_issue_zeroout)
CL_MINE(blkdev_put)
CL_MINE(block_commit_write)
CL_MINE(block_page_mkwrite)
CL_MINE(block_read_full_page)
CL_MINE(call_rcu)
CL_MINE(complete)
CL_MINE(_copy_from_user)
CL_MINE(_copy_to_user)
CL_MINE(crc16)
CL_MINE(crypto_shash_update)
CL_MINE(d_find_any_alias)
CL_MINE(dget_parent)
CL_MINE(d_mark_dontcache)
CL_MINE(down_write_trylock)
CL_MINE(d_path)
CL_MINE(dput)
CL_MINE(dump_stack)
CL_MINE(errseq_set)
CL_MINE(__fdget)
CL_MINE(fiemap_fill_next_extent)
CL_MINE(fiemap_prep)
CL_MINE(filemap_fault)
CL_MINE(filemap_flush)
CL_MINE(filemap_map_pages)
CL_MINE(__filemap_set_wb_err)
CL_MINE(file_update_time)
CL_MINE(find_inode_by_ino_rcu)
CL_MINE(find_next_bit)
CL_MINE(flush_workqueue)
CL_MINE(fput)
CL_MINE(free_pages)
CL_MINE(free_percpu)
CL_MINE(freeze_bdev)
CL_MINE(fs_bio_set)
CL_MINE(fs_kobj)
CL_MINE(generic_file_llseek_size)
CL_MINE(get_zeroed_page)
CL_MINE(init_uts_ns)
CL_MINE(inode_io_list_del)
CL_MINE(inode_newsize_ok)
CL_MINE(invalidate_bdev)
CL_MINE(invalidate_mapping_pages)
CL_MINE(iomap_dio_iopoll)
CL_MINE(iomap_dio_rw)
CL_MINE(iomap_fiemap)
CL_MINE(iomap_seek_data)
CL_MINE(iomap_seek_hole)
CL_MINE(jiffies)
CL_MINE(kern_path)
CL_MINE(kobject_del)
CL_MINE(kobject_put)
CL_MINE(kstrndup)
CL_MINE(kthread_should_stop)
CL_MINE(kthread_stop)
CL_MINE(kunit_binary_assert_format)
CL_MINE(kunit_do_assertion)
CL_MINE(__kunit_test_suites_exit)
CL_MINE(__kunit_test_suites_init)
CL_MINE(list_sort)
CL_MINE(lock_two_nondirectories)
CL_MINE(match_strdup)
CL_MINE(mb_cache_destroy)
CL_MINE(mb_cache_entry_create)
CL_MINE(mb_cache_entry_delete)
CL_MINE(mb_cache_entry_find_first)
CL_MINE(mb_cache_entry_find_next)
CL_MINE(__mb_cache_entry_free)
CL_MINE(mb_cache_entry_get)
CL_MINE(mb_cache_entry_touch)
CL_MINE(memchr_inv)

CL_MINE(__free_pages)
CL_MINE(io_schedule_timeout)

CL_MINE(memweight)
CL_MINE(noop_backing_dev_info)
CL_MINE(noop_direct_IO)
CL_MINE(pagecache_isize_extended)
CL_MINE(page_cache_readahead_unbounded)
CL_MINE(page_cache_sync_readahead)
CL_MINE(pagecache_write_begin)
CL_MINE(pagecache_write_end)
CL_MINE(__page_symlink)
CL_MINE(pagevec_lookup_range)
CL_MINE(path_put)
CL_MINE(PDE_DATA)
CL_MINE(__percpu_down_read)
CL_MINE(percpu_down_write)
CL_MINE(percpu_free_rwsem)
CL_MINE(percpu_up_write)
CL_MINE(print_hex_dump)
CL_MINE(_raw_write_trylock)
CL_MINE(rcuwait_wake_up)
CL_MINE(remove_proc_subtree)
CL_MINE(schedule_timeout_interruptible)
CL_MINE(schedule_timeout_uninterruptible)
CL_MINE(__set_page_dirty_buffers)
CL_MINE(sort)
CL_MINE(strlcpy)
CL_MINE(synchronize_rcu)
CL_MINE(system_state)
CL_MINE(__task_pid_nr_ns)
CL_MINE(thaw_bdev)
CL_MINE(truncate_pagecache_range)
CL_MINE(try_to_writeback_inodes_sb)
CL_MINE(unlock_two_nondirectories)
CL_MINE(unregister_shrinker)
CL_MINE(vfs_ioc_fssetxattr_check)
CL_MINE(vfs_setpos)
CL_MINE(wait_for_completion)

// jbd2
CL_MINE(__bforget)
CL_MINE(crc32_be)
CL_MINE(crypto_destroy_tfm)
CL_MINE(filemap_fdatawait_range_keep_errors)
CL_MINE(filemap_fdatawrite_range)
CL_MINE(__get_free_pages)
CL_MINE(jiffies_to_msecs)
CL_MINE(remove_proc_entry)
CL_MINE(schedule_hrtimeout)
CL_MINE(seq_lseek)
CL_MINE(seq_open)
CL_MINE(seq_read)
CL_MINE(seq_release)
CL_MINE(write_dirty_buffer)

CL_MINE(__bitmap_clear)

// iov_iter
CL_MINE(kmemdup)
CL_MINE(__clear_user)
CL_MINE(__asm_copy_from_user)
CL_MINE(__asm_copy_to_user)
CL_MINE(page_cache_pipe_buf_ops)
CL_MINE(csum_partial_copy_nocheck)
CL_MINE(get_user_pages_fast)
CL_MINE(rw_copy_check_uvector)
CL_MINE(csum_partial)

CL_MINE(wait_on_page_bit_killable)
CL_MINE(wait_on_page_bit)
CL_MINE(__lock_page_async)

CL_MINE(clean_bdev_aliases)
CL_MINE(page_zero_new_buffers)

CL_MINE(wait_for_completion_io)
CL_MINE(__page_file_index)

CL_MINE(bdi_dev_name)
CL_MINE(rotate_reclaimable_page)
CL_MINE(blk_recalc_rq_segments)
CL_MINE(blk_dump_rq_flags)
CL_MINE(bio_truncate)

CL_MINE(pagevec_remove_exceptionals)
CL_MINE(truncate_inode_page)
CL_MINE(__cancel_dirty_page)
CL_MINE(blk_flush_plug_list)
