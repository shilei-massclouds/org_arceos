// SPDX-License-Identifier: GPL-2.0-only

#include <linux/ethtool.h>
#include <linux/kernel.h>

int ethtool_check_ops(const struct ethtool_ops *ops)
{
	if (WARN_ON(ops->set_coalesce && !ops->supported_coalesce_params))
		return -EINVAL;
	if (WARN_ON(ops->rxfh_max_num_contexts == 1))
		return -EINVAL;
	/*
	 * Drivers may swap ethtool_ops at runtime; checking at registration
	 * time only validates the current instance.
	 */
	return 0;
}
