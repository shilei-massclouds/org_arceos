#include <linux/device.h>
#include <linux/slab.h>
#include <linux/export.h>
#include <linux/mutex.h>
#include <linux/err.h>
#include <linux/property.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/log2.h>
#include <linux/hwspinlock.h>
#include <linux/unaligned.h>

#define CREATE_TRACE_POINTS
#include "trace.h"

#include "internal.h"
#include "../adaptor.h"

static inline bool regmap_should_log(struct regmap *map) { return false; }

static inline void *_regmap_map_get_context(struct regmap *map)
{
    return (map->bus || (!map->bus && map->read)) ? map : map->bus_context;
}

static unsigned int regmap_parse_8(const void *buf)
{
	const u8 *b = buf;

	return b[0];
}

static unsigned int regmap_parse_16_be(const void *buf)
{
	return get_unaligned_be16(buf);
}

static unsigned int regmap_parse_16_le(const void *buf)
{
	return get_unaligned_le16(buf);
}

static void regmap_parse_16_be_inplace(void *buf)
{
	u16 v = get_unaligned_be16(buf);

	memcpy(buf, &v, sizeof(v));
}

static void regmap_parse_16_le_inplace(void *buf)
{
	u16 v = get_unaligned_le16(buf);

	memcpy(buf, &v, sizeof(v));
}

static unsigned int regmap_parse_16_native(const void *buf)
{
	u16 v;

	memcpy(&v, buf, sizeof(v));
	return v;
}

static unsigned int regmap_parse_24_be(const void *buf)
{
	return get_unaligned_be24(buf);
}

static unsigned int regmap_parse_32_be(const void *buf)
{
	return get_unaligned_be32(buf);
}

static unsigned int regmap_parse_32_le(const void *buf)
{
	return get_unaligned_le32(buf);
}

static void regmap_parse_32_be_inplace(void *buf)
{
	u32 v = get_unaligned_be32(buf);

	memcpy(buf, &v, sizeof(v));
}

static void regmap_parse_32_le_inplace(void *buf)
{
	u32 v = get_unaligned_le32(buf);

	memcpy(buf, &v, sizeof(v));
}

static unsigned int regmap_parse_32_native(const void *buf)
{
	u32 v;

	memcpy(&v, buf, sizeof(v));
	return v;
}

static void regmap_lock_hwlock(void *__map)
{
    struct regmap *map = __map;

    hwspin_lock_timeout(map->hwlock, UINT_MAX);
}

static void regmap_lock_hwlock_irq(void *__map)
{
    struct regmap *map = __map;

    hwspin_lock_timeout_irq(map->hwlock, UINT_MAX);
}

static void regmap_lock_hwlock_irqsave(void *__map)
{
    struct regmap *map = __map;

    hwspin_lock_timeout_irqsave(map->hwlock, UINT_MAX,
                    &map->spinlock_flags);
}

static void regmap_unlock_hwlock(void *__map)
{
    struct regmap *map = __map;

    hwspin_unlock(map->hwlock);
}

static void regmap_unlock_hwlock_irq(void *__map)
{
    struct regmap *map = __map;

    hwspin_unlock_irq(map->hwlock);
}

static void regmap_unlock_hwlock_irqrestore(void *__map)
{
    struct regmap *map = __map;

    hwspin_unlock_irqrestore(map->hwlock, &map->spinlock_flags);
}

static void regmap_lock_unlock_none(void *__map)
{

}

static void regmap_lock_mutex(void *__map)
{
    struct regmap *map = __map;
    mutex_lock(&map->mutex);
}

static void regmap_unlock_mutex(void *__map)
{
    struct regmap *map = __map;
    mutex_unlock(&map->mutex);
}

static void regmap_lock_raw_spinlock(void *__map)
__acquires(&map->raw_spinlock)
{
    struct regmap *map = __map;
    unsigned long flags;

    raw_spin_lock_irqsave(&map->raw_spinlock, flags);
    map->raw_spinlock_flags = flags;
}

static void regmap_unlock_raw_spinlock(void *__map)
__releases(&map->raw_spinlock)
{
    struct regmap *map = __map;
    raw_spin_unlock_irqrestore(&map->raw_spinlock, map->raw_spinlock_flags);
}

static void regmap_lock_spinlock(void *__map)
__acquires(&map->spinlock)
{
    struct regmap *map = __map;
    unsigned long flags;

    spin_lock_irqsave(&map->spinlock, flags);
    map->spinlock_flags = flags;
}

static void regmap_unlock_spinlock(void *__map)
__releases(&map->spinlock)
{
    struct regmap *map = __map;
    spin_unlock_irqrestore(&map->spinlock, map->spinlock_flags);
}

static void devm_regmap_release(struct device *dev, void *res)
{
    regmap_exit(*(struct regmap **)res);
}

static void regmap_format_12_20_write(struct regmap *map,
				     unsigned int reg, unsigned int val)
{
	u8 *out = map->work_buf;

	out[0] = reg >> 4;
	out[1] = (reg << 4) | (val >> 16);
	out[2] = val >> 8;
	out[3] = val;
}


static void regmap_format_2_6_write(struct regmap *map,
				     unsigned int reg, unsigned int val)
{
	u8 *out = map->work_buf;

	*out = (reg << 6) | val;
}

static void regmap_format_4_12_write(struct regmap *map,
				     unsigned int reg, unsigned int val)
{
	__be16 *out = map->work_buf;
	*out = cpu_to_be16((reg << 12) | val);
}

static void regmap_format_7_9_write(struct regmap *map,
				    unsigned int reg, unsigned int val)
{
	__be16 *out = map->work_buf;
	*out = cpu_to_be16((reg << 9) | val);
}

static void regmap_format_7_17_write(struct regmap *map,
				    unsigned int reg, unsigned int val)
{
	u8 *out = map->work_buf;

	out[2] = val;
	out[1] = val >> 8;
	out[0] = (val >> 16) | (reg << 1);
}

static void regmap_format_10_14_write(struct regmap *map,
				    unsigned int reg, unsigned int val)
{
	u8 *out = map->work_buf;

	out[2] = val;
	out[1] = (val >> 8) | (reg << 6);
	out[0] = reg >> 2;
}

static void regmap_format_8(void *buf, unsigned int val, unsigned int shift)
{
	u8 *b = buf;

	b[0] = val << shift;
}

static void regmap_format_16_be(void *buf, unsigned int val, unsigned int shift)
{
	put_unaligned_be16(val << shift, buf);
}

static void regmap_format_16_le(void *buf, unsigned int val, unsigned int shift)
{
	put_unaligned_le16(val << shift, buf);
}

static void regmap_format_16_native(void *buf, unsigned int val,
				    unsigned int shift)
{
	u16 v = val << shift;

	memcpy(buf, &v, sizeof(v));
}

static void regmap_format_24_be(void *buf, unsigned int val, unsigned int shift)
{
	put_unaligned_be24(val << shift, buf);
}

static void regmap_format_32_be(void *buf, unsigned int val, unsigned int shift)
{
	put_unaligned_be32(val << shift, buf);
}

static void regmap_format_32_le(void *buf, unsigned int val, unsigned int shift)
{
	put_unaligned_le32(val << shift, buf);
}

static void regmap_format_32_native(void *buf, unsigned int val,
				    unsigned int shift)
{
	u32 v = val << shift;

	memcpy(buf, &v, sizeof(v));
}

static void regmap_parse_inplace_noop(void *buf)
{
}

struct regmap *__devm_regmap_init(struct device *dev,
                  const struct regmap_bus *bus,
                  void *bus_context,
                  const struct regmap_config *config,
                  struct lock_class_key *lock_key,
                  const char *lock_name)
{
    struct regmap **ptr, *regmap;

    ptr = devres_alloc(devm_regmap_release, sizeof(*ptr), GFP_KERNEL);
    if (!ptr)
        return ERR_PTR(-ENOMEM);

    regmap = __regmap_init(dev, bus, bus_context, config,
                   lock_key, lock_name);
    if (!IS_ERR(regmap)) {
        *ptr = regmap;
        devres_add(dev, ptr);
    } else {
        devres_free(ptr);
    }

    return regmap;
}

enum regmap_endian regmap_get_val_endian(struct device *dev,
                     const struct regmap_bus *bus,
                     const struct regmap_config *config)
{
    struct fwnode_handle *fwnode = dev ? dev_fwnode(dev) : NULL;
    enum regmap_endian endian;

    /* Retrieve the endianness specification from the regmap config */
    endian = config->val_format_endian;

    /* If the regmap config specified a non-default value, use that */
    if (endian != REGMAP_ENDIAN_DEFAULT)
        return endian;

    /* If the firmware node exist try to get endianness from it */
    if (fwnode_property_read_bool(fwnode, "big-endian"))
        endian = REGMAP_ENDIAN_BIG;
    else if (fwnode_property_read_bool(fwnode, "little-endian"))
        endian = REGMAP_ENDIAN_LITTLE;
    else if (fwnode_property_read_bool(fwnode, "native-endian"))
        endian = REGMAP_ENDIAN_NATIVE;

    /* If the endianness was specified in fwnode, use that */
    if (endian != REGMAP_ENDIAN_DEFAULT)
        return endian;

    /* Retrieve the endianness specification from the bus config */
    if (bus && bus->val_format_endian_default)
        endian = bus->val_format_endian_default;

    /* If the bus specified a non-default value, use that */
    if (endian != REGMAP_ENDIAN_DEFAULT)
        return endian;

    PANIC("");
    /* Use this if no other value was found */
    return REGMAP_ENDIAN_BIG;
}

static void regmap_range_exit(struct regmap *map)
{
    struct rb_node *next;
    struct regmap_range_node *range_node;

    next = rb_first(&map->range_tree);
    while (next) {
        range_node = rb_entry(next, struct regmap_range_node, node);
        next = rb_next(&range_node->node);
        rb_erase(&range_node->node, &map->range_tree);
        kfree(range_node);
    }

    kfree(map->selector_work_buf);
}

static int regmap_set_name(struct regmap *map, const struct regmap_config *config)
{
    if (config->name) {
        const char *name = kstrdup_const(config->name, GFP_KERNEL);

        if (!name)
            return -ENOMEM;

        kfree_const(map->name);
        map->name = name;
    }

    return 0;
}

static int _regmap_read(struct regmap *map, unsigned int reg,
            unsigned int *val)
{
    int ret;
    void *context = _regmap_map_get_context(map);

    if (!map->cache_bypass) {
        ret = regcache_read(map, reg, val);
        if (ret == 0)
            return 0;
    }

    if (map->cache_only)
        return -EBUSY;

    if (!regmap_readable(map, reg))
        return -EIO;

    ret = map->reg_read(context, reg, val);
    if (ret == 0) {
        if (regmap_should_log(map))
            dev_info(map->dev, "%x => %x\n", reg, *val);

        trace_regmap_reg_read(map, reg, *val);

        if (!map->cache_bypass)
            regcache_write(map, reg, *val);
    }

    return ret;
}

static unsigned int regmap_reg_addr(struct regmap *map, unsigned int reg)
{
    reg += map->reg_base;

    if (map->format.reg_shift > 0)
        reg >>= map->format.reg_shift;
    else if (map->format.reg_shift < 0)
        reg <<= -(map->format.reg_shift);

    return reg;
}

static int _regmap_update_bits(struct regmap *map, unsigned int reg,
                   unsigned int mask, unsigned int val,
                   bool *change, bool force_write)
{
    int ret;
    unsigned int tmp, orig;

    if (change)
        *change = false;

    if (regmap_volatile(map, reg) && map->reg_update_bits) {
        reg = regmap_reg_addr(map, reg);
        ret = map->reg_update_bits(map->bus_context, reg, mask, val);
        if (ret == 0 && change)
            *change = true;
    } else {
        ret = _regmap_read(map, reg, &orig);
        if (ret != 0)
            return ret;

        tmp = orig & ~mask;
        tmp |= val & mask;

        if (force_write || (tmp != orig) || map->force_write_field) {
            ret = _regmap_write(map, reg, tmp);
            if (ret == 0 && change)
                *change = true;
        }
    }

    return ret;
}

static int _regmap_select_page(struct regmap *map, unsigned int *reg,
                   struct regmap_range_node *range,
                   unsigned int val_num)
{
    void *orig_work_buf;
    unsigned int win_offset;
    unsigned int win_page;
    bool page_chg;
    int ret;

    win_offset = (*reg - range->range_min) % range->window_len;
    win_page = (*reg - range->range_min) / range->window_len;

    if (val_num > 1) {
        /* Bulk write shouldn't cross range boundary */
        if (*reg + val_num - 1 > range->range_max)
            return -EINVAL;

        /* ... or single page boundary */
        if (val_num > range->window_len - win_offset)
            return -EINVAL;
    }

    /* It is possible to have selector register inside data window.
       In that case, selector register is located on every page and
       it needs no page switching, when accessed alone. */
    if (val_num > 1 ||
        range->window_start + win_offset != range->selector_reg) {
        /* Use separate work_buf during page switching */
        orig_work_buf = map->work_buf;
        map->work_buf = map->selector_work_buf;

        ret = _regmap_update_bits(map, range->selector_reg,
                      range->selector_mask,
                      win_page << range->selector_shift,
                      &page_chg, false);

        map->work_buf = orig_work_buf;

        if (ret != 0)
            return ret;
    }

    *reg = range->window_start + win_offset;

    return 0;
}

static struct regmap_range_node *_regmap_range_lookup(struct regmap *map,
                              unsigned int reg)
{
    struct rb_node *node = map->range_tree.rb_node;

    while (node) {
        struct regmap_range_node *this =
            rb_entry(node, struct regmap_range_node, node);

        if (reg < this->range_min)
            node = node->rb_left;
        else if (reg > this->range_max)
            node = node->rb_right;
        else
            return this;
    }

    return NULL;
}

static int _regmap_raw_read(struct regmap *map, unsigned int reg, void *val,
                unsigned int val_len, bool noinc)
{
    struct regmap_range_node *range;
    int ret;

    if (!map->read)
        return -EINVAL;

#if 0
    range = _regmap_range_lookup(map, reg);
    if (range) {
        ret = _regmap_select_page(map, &reg, range,
                      noinc ? 1 : val_len / map->format.val_bytes);
        if (ret != 0)
            return ret;
    }

    reg = regmap_reg_addr(map, reg);
    map->format.format_reg(map->work_buf, reg, map->reg_shift);
    regmap_set_work_buf_flag_mask(map, map->format.reg_bytes,
                      map->read_flag_mask);
    trace_regmap_hw_read_start(map, reg, val_len / map->format.val_bytes);

    ret = map->read(map->bus_context, map->work_buf,
            map->format.reg_bytes + map->format.pad_bytes,
            val, val_len);

    trace_regmap_hw_read_done(map, reg, val_len / map->format.val_bytes);
#endif
    PANIC("");

    return ret;
}

static int _regmap_bus_reg_read(void *context, unsigned int reg,
                unsigned int *val)
{
    struct regmap *map = context;
    struct regmap_range_node *range;
    int ret;

#if 0
    range = _regmap_range_lookup(map, reg);
    if (range) {
        ret = _regmap_select_page(map, &reg, range, 1);
        if (ret != 0)
            return ret;
    }

    reg = regmap_reg_addr(map, reg);
    return map->bus->reg_read(map->bus_context, reg, val);
#endif
    PANIC("");
}

static int _regmap_bus_read(void *context, unsigned int reg,
                unsigned int *val)
{
    int ret;
    struct regmap *map = context;
    void *work_val = map->work_buf + map->format.reg_bytes +
        map->format.pad_bytes;

    if (!map->format.parse_val)
        return -EINVAL;

    ret = _regmap_raw_read(map, reg, work_val, map->format.val_bytes, false);
    if (ret == 0)
        *val = map->format.parse_val(work_val);

    return ret;
}

static int _regmap_bus_formatted_write(void *context, unsigned int reg,
                       unsigned int val)
{
    int ret;
    struct regmap_range_node *range;
    struct regmap *map = context;

    WARN_ON(!map->format.format_write);

#if 0
    range = _regmap_range_lookup(map, reg);
    if (range) {
        ret = _regmap_select_page(map, &reg, range, 1);
        if (ret != 0)
            return ret;
    }

    reg = regmap_reg_addr(map, reg);
    map->format.format_write(map, reg, val);

    trace_regmap_hw_write_start(map, reg, 1);

    ret = map->write(map->bus_context, map->work_buf, map->format.buf_size);

    trace_regmap_hw_write_done(map, reg, 1);
#endif

    PANIC("");
    return ret;
}

static int _regmap_bus_reg_write(void *context, unsigned int reg,
                 unsigned int val)
{
    struct regmap *map = context;
    struct regmap_range_node *range;
    int ret;

    range = _regmap_range_lookup(map, reg);
    if (range) {
        ret = _regmap_select_page(map, &reg, range, 1);
        if (ret != 0)
            return ret;
    }

    reg = regmap_reg_addr(map, reg);
    return map->bus->reg_write(map->bus_context, reg, val);
}

static int _regmap_bus_raw_write(void *context, unsigned int reg,
                 unsigned int val)
{
    struct regmap *map = context;

    WARN_ON(!map->format.format_val);

#if 0
    map->format.format_val(map->work_buf + map->format.reg_bytes
                   + map->format.pad_bytes, val, 0);
    return _regmap_raw_write_impl(map, reg,
                      map->work_buf +
                      map->format.reg_bytes +
                      map->format.pad_bytes,
                      map->format.val_bytes,
                      false);
#endif
    PANIC("");
}

static enum regmap_endian regmap_get_reg_endian(const struct regmap_bus *bus,
                    const struct regmap_config *config)
{
    enum regmap_endian endian;

    /* Retrieve the endianness specification from the regmap config */
    endian = config->reg_format_endian;

    /* If the regmap config specified a non-default value, use that */
    if (endian != REGMAP_ENDIAN_DEFAULT)
        return endian;

    /* Retrieve the endianness specification from the bus config */
    if (bus && bus->reg_format_endian_default)
        endian = bus->reg_format_endian_default;

    /* If the bus specified a non-default value, use that */
    if (endian != REGMAP_ENDIAN_DEFAULT)
        return endian;

    /* Use this if no other value was found */
    return REGMAP_ENDIAN_BIG;
}

static bool _regmap_range_add(struct regmap *map,
                  struct regmap_range_node *data)
{
    struct rb_root *root = &map->range_tree;
    struct rb_node **new = &(root->rb_node), *parent = NULL;

    while (*new) {
        struct regmap_range_node *this =
            rb_entry(*new, struct regmap_range_node, node);

        parent = *new;
        if (data->range_max < this->range_min)
            new = &((*new)->rb_left);
        else if (data->range_min > this->range_max)
            new = &((*new)->rb_right);
        else
            return false;
    }

    rb_link_node(&data->node, parent, new);
    rb_insert_color(&data->node, root);

    return true;
}

static void dev_get_regmap_release(struct device *dev, void *res)
{
    /*
     * We don't actually have anything to do here; the goal here
     * is not to manage the regmap but to provide a simple way to
     * get the regmap back given a struct device.
     */
}

int regmap_attach_dev(struct device *dev, struct regmap *map,
              const struct regmap_config *config)
{
    struct regmap **m;
    int ret;

    map->dev = dev;

    ret = regmap_set_name(map, config);
    if (ret)
        return ret;

    regmap_debugfs_exit(map);
    regmap_debugfs_init(map);

    /* Add a devres resource for dev_get_regmap() */
    m = devres_alloc(dev_get_regmap_release, sizeof(*m), GFP_KERNEL);
    if (!m) {
        regmap_debugfs_exit(map);
        return -ENOMEM;
    }
    *m = map;
    devres_add(dev, m);

    return 0;
}

/**
 * regmap_write() - Write a value to a single register
 *
 * @map: Register map to write to
 * @reg: Register to write to
 * @val: Value to be written
 *
 * A value of zero will be returned on success, a negative errno will
 * be returned in error cases.
 */
int regmap_write(struct regmap *map, unsigned int reg, unsigned int val)
{
    int ret;

    if (!IS_ALIGNED(reg, map->reg_stride))
        return -EINVAL;

    map->lock(map->lock_arg);

    ret = _regmap_write(map, reg, val);

    map->unlock(map->lock_arg);

    return ret;
}

int _regmap_write(struct regmap *map, unsigned int reg,
          unsigned int val)
{
    int ret;
    void *context = _regmap_map_get_context(map);

    if (!regmap_writeable(map, reg))
        return -EIO;

    if (!map->cache_bypass && !map->defer_caching) {
        ret = regcache_write(map, reg, val);
        if (ret != 0)
            return ret;
        if (map->cache_only) {
            map->cache_dirty = true;
            return 0;
        }
    }

    ret = map->reg_write(context, reg, val);
    if (ret == 0) {
        if (regmap_should_log(map))
            dev_info(map->dev, "%x <= %x\n", reg, val);

        trace_regmap_reg_write(map, reg, val);
    }

    return ret;
}

bool regmap_reg_in_ranges(unsigned int reg,
              const struct regmap_range *ranges,
              unsigned int nranges)
{
    const struct regmap_range *r;
    int i;

    for (i = 0, r = ranges; i < nranges; i++, r++)
        if (regmap_reg_in_range(reg, r))
            return true;
    return false;
}

bool regmap_check_range_table(struct regmap *map, unsigned int reg,
                  const struct regmap_access_table *table)
{
    /* Check "no ranges" first */
    if (regmap_reg_in_ranges(reg, table->no_ranges, table->n_no_ranges))
        return false;

    /* In case zero "yes ranges" are supplied, any reg is OK */
    if (!table->n_yes_ranges)
        return true;

    return regmap_reg_in_ranges(reg, table->yes_ranges,
                    table->n_yes_ranges);
}

bool regmap_writeable(struct regmap *map, unsigned int reg)
{
    if (map->max_register_is_set && reg > map->max_register)
        return false;

    if (map->writeable_reg)
        return map->writeable_reg(map->dev, reg);

    if (map->wr_table)
        return regmap_check_range_table(map, reg, map->wr_table);

    return true;
}

struct regmap *__regmap_init(struct device *dev,
			     const struct regmap_bus *bus,
			     void *bus_context,
			     const struct regmap_config *config,
			     struct lock_class_key *lock_key,
			     const char *lock_name)
{
	struct regmap *map;
	int ret = -EINVAL;
	enum regmap_endian reg_endian, val_endian;
	int i, j;

	if (!config)
		goto err;

	map = kzalloc(sizeof(*map), GFP_KERNEL);
	if (map == NULL) {
		ret = -ENOMEM;
		goto err;
	}

	ret = regmap_set_name(map, config);
	if (ret)
		goto err_map;

	ret = -EINVAL; /* Later error paths rely on this */

	if (config->disable_locking) {
		map->lock = map->unlock = regmap_lock_unlock_none;
		map->can_sleep = config->can_sleep;
		regmap_debugfs_disable(map);
	} else if (config->lock && config->unlock) {
		map->lock = config->lock;
		map->unlock = config->unlock;
		map->lock_arg = config->lock_arg;
		map->can_sleep = config->can_sleep;
	} else if (config->use_hwlock) {
		map->hwlock = hwspin_lock_request_specific(config->hwlock_id);
		if (!map->hwlock) {
			ret = -ENXIO;
			goto err_name;
		}

		switch (config->hwlock_mode) {
		case HWLOCK_IRQSTATE:
			map->lock = regmap_lock_hwlock_irqsave;
			map->unlock = regmap_unlock_hwlock_irqrestore;
			break;
		case HWLOCK_IRQ:
			map->lock = regmap_lock_hwlock_irq;
			map->unlock = regmap_unlock_hwlock_irq;
			break;
		default:
			map->lock = regmap_lock_hwlock;
			map->unlock = regmap_unlock_hwlock;
			break;
		}

		map->lock_arg = map;
	} else {
		if ((bus && bus->fast_io) ||
		    config->fast_io) {
			if (config->use_raw_spinlock) {
				raw_spin_lock_init(&map->raw_spinlock);
				map->lock = regmap_lock_raw_spinlock;
				map->unlock = regmap_unlock_raw_spinlock;
				lockdep_set_class_and_name(&map->raw_spinlock,
							   lock_key, lock_name);
			} else {
				spin_lock_init(&map->spinlock);
				map->lock = regmap_lock_spinlock;
				map->unlock = regmap_unlock_spinlock;
				lockdep_set_class_and_name(&map->spinlock,
							   lock_key, lock_name);
			}
		} else {
			mutex_init(&map->mutex);
			map->lock = regmap_lock_mutex;
			map->unlock = regmap_unlock_mutex;
			map->can_sleep = true;
			lockdep_set_class_and_name(&map->mutex,
						   lock_key, lock_name);
		}
		map->lock_arg = map;
		map->lock_key = lock_key;
	}

	/*
	 * When we write in fast-paths with regmap_bulk_write() don't allocate
	 * scratch buffers with sleeping allocations.
	 */
	if ((bus && bus->fast_io) || config->fast_io)
		map->alloc_flags = GFP_ATOMIC;
	else
		map->alloc_flags = GFP_KERNEL;

	map->reg_base = config->reg_base;

	map->format.reg_bytes = DIV_ROUND_UP(config->reg_bits, 8);
	map->format.pad_bytes = config->pad_bits / 8;
	map->format.reg_shift = config->reg_shift;
	map->format.val_bytes = DIV_ROUND_UP(config->val_bits, 8);
	map->format.buf_size = DIV_ROUND_UP(config->reg_bits +
			config->val_bits + config->pad_bits, 8);
	map->reg_shift = config->pad_bits % 8;
	if (config->reg_stride)
		map->reg_stride = config->reg_stride;
	else
		map->reg_stride = 1;
	if (is_power_of_2(map->reg_stride))
		map->reg_stride_order = ilog2(map->reg_stride);
	else
		map->reg_stride_order = -1;
	map->use_single_read = config->use_single_read || !(config->read || (bus && bus->read));
	map->use_single_write = config->use_single_write || !(config->write || (bus && bus->write));
	map->can_multi_write = config->can_multi_write && (config->write || (bus && bus->write));
	if (bus) {
		map->max_raw_read = bus->max_raw_read;
		map->max_raw_write = bus->max_raw_write;
	} else if (config->max_raw_read && config->max_raw_write) {
		map->max_raw_read = config->max_raw_read;
		map->max_raw_write = config->max_raw_write;
	}
	map->dev = dev;
	map->bus = bus;
	map->bus_context = bus_context;
	map->max_register = config->max_register;
	map->max_register_is_set = map->max_register ?: config->max_register_is_0;
	map->wr_table = config->wr_table;
	map->rd_table = config->rd_table;
	map->volatile_table = config->volatile_table;
	map->precious_table = config->precious_table;
	map->wr_noinc_table = config->wr_noinc_table;
	map->rd_noinc_table = config->rd_noinc_table;
	map->writeable_reg = config->writeable_reg;
	map->readable_reg = config->readable_reg;
	map->volatile_reg = config->volatile_reg;
	map->precious_reg = config->precious_reg;
	map->writeable_noinc_reg = config->writeable_noinc_reg;
	map->readable_noinc_reg = config->readable_noinc_reg;
	map->cache_type = config->cache_type;

	spin_lock_init(&map->async_lock);
	INIT_LIST_HEAD(&map->async_list);
	INIT_LIST_HEAD(&map->async_free);
	init_waitqueue_head(&map->async_waitq);

	if (config->read_flag_mask ||
	    config->write_flag_mask ||
	    config->zero_flag_mask) {
		map->read_flag_mask = config->read_flag_mask;
		map->write_flag_mask = config->write_flag_mask;
	} else if (bus) {
		map->read_flag_mask = bus->read_flag_mask;
	}

	if (config && config->read && config->write) {
		map->reg_read  = _regmap_bus_read;
		if (config->reg_update_bits)
			map->reg_update_bits = config->reg_update_bits;

		/* Bulk read/write */
		map->read = config->read;
		map->write = config->write;

		reg_endian = REGMAP_ENDIAN_NATIVE;
		val_endian = REGMAP_ENDIAN_NATIVE;
	} else if (!bus) {
		map->reg_read  = config->reg_read;
		map->reg_write = config->reg_write;
		map->reg_update_bits = config->reg_update_bits;

		map->defer_caching = false;
		goto skip_format_initialization;
	} else if (!bus->read || !bus->write) {
		map->reg_read = _regmap_bus_reg_read;
		map->reg_write = _regmap_bus_reg_write;
		map->reg_update_bits = bus->reg_update_bits;

		map->defer_caching = false;
		goto skip_format_initialization;
	} else {
		map->reg_read  = _regmap_bus_read;
		map->reg_update_bits = bus->reg_update_bits;
		/* Bulk read/write */
		map->read = bus->read;
		map->write = bus->write;

		reg_endian = regmap_get_reg_endian(bus, config);
		val_endian = regmap_get_val_endian(dev, bus, config);
	}

	switch (config->reg_bits + map->reg_shift) {
	case 2:
		switch (config->val_bits) {
		case 6:
			map->format.format_write = regmap_format_2_6_write;
			break;
		default:
			goto err_hwlock;
		}
		break;

	case 4:
		switch (config->val_bits) {
		case 12:
			map->format.format_write = regmap_format_4_12_write;
			break;
		default:
			goto err_hwlock;
		}
		break;

	case 7:
		switch (config->val_bits) {
		case 9:
			map->format.format_write = regmap_format_7_9_write;
			break;
		case 17:
			map->format.format_write = regmap_format_7_17_write;
			break;
		default:
			goto err_hwlock;
		}
		break;

	case 10:
		switch (config->val_bits) {
		case 14:
			map->format.format_write = regmap_format_10_14_write;
			break;
		default:
			goto err_hwlock;
		}
		break;

	case 12:
		switch (config->val_bits) {
		case 20:
			map->format.format_write = regmap_format_12_20_write;
			break;
		default:
			goto err_hwlock;
		}
		break;

	case 8:
		map->format.format_reg = regmap_format_8;
		break;

	case 16:
		switch (reg_endian) {
		case REGMAP_ENDIAN_BIG:
			map->format.format_reg = regmap_format_16_be;
			break;
		case REGMAP_ENDIAN_LITTLE:
			map->format.format_reg = regmap_format_16_le;
			break;
		case REGMAP_ENDIAN_NATIVE:
			map->format.format_reg = regmap_format_16_native;
			break;
		default:
			goto err_hwlock;
		}
		break;

	case 24:
		switch (reg_endian) {
		case REGMAP_ENDIAN_BIG:
			map->format.format_reg = regmap_format_24_be;
			break;
		default:
			goto err_hwlock;
		}
		break;

	case 32:
		switch (reg_endian) {
		case REGMAP_ENDIAN_BIG:
			map->format.format_reg = regmap_format_32_be;
			break;
		case REGMAP_ENDIAN_LITTLE:
			map->format.format_reg = regmap_format_32_le;
			break;
		case REGMAP_ENDIAN_NATIVE:
			map->format.format_reg = regmap_format_32_native;
			break;
		default:
			goto err_hwlock;
		}
		break;

	default:
		goto err_hwlock;
	}

	if (val_endian == REGMAP_ENDIAN_NATIVE)
		map->format.parse_inplace = regmap_parse_inplace_noop;

	switch (config->val_bits) {
	case 8:
		map->format.format_val = regmap_format_8;
		map->format.parse_val = regmap_parse_8;
		map->format.parse_inplace = regmap_parse_inplace_noop;
		break;
	case 16:
		switch (val_endian) {
		case REGMAP_ENDIAN_BIG:
			map->format.format_val = regmap_format_16_be;
			map->format.parse_val = regmap_parse_16_be;
			map->format.parse_inplace = regmap_parse_16_be_inplace;
			break;
		case REGMAP_ENDIAN_LITTLE:
			map->format.format_val = regmap_format_16_le;
			map->format.parse_val = regmap_parse_16_le;
			map->format.parse_inplace = regmap_parse_16_le_inplace;
			break;
		case REGMAP_ENDIAN_NATIVE:
			map->format.format_val = regmap_format_16_native;
			map->format.parse_val = regmap_parse_16_native;
			break;
		default:
			goto err_hwlock;
		}
		break;
	case 24:
		switch (val_endian) {
		case REGMAP_ENDIAN_BIG:
			map->format.format_val = regmap_format_24_be;
			map->format.parse_val = regmap_parse_24_be;
			break;
		default:
			goto err_hwlock;
		}
		break;
	case 32:
		switch (val_endian) {
		case REGMAP_ENDIAN_BIG:
			map->format.format_val = regmap_format_32_be;
			map->format.parse_val = regmap_parse_32_be;
			map->format.parse_inplace = regmap_parse_32_be_inplace;
			break;
		case REGMAP_ENDIAN_LITTLE:
			map->format.format_val = regmap_format_32_le;
			map->format.parse_val = regmap_parse_32_le;
			map->format.parse_inplace = regmap_parse_32_le_inplace;
			break;
		case REGMAP_ENDIAN_NATIVE:
			map->format.format_val = regmap_format_32_native;
			map->format.parse_val = regmap_parse_32_native;
			break;
		default:
			goto err_hwlock;
		}
		break;
	}

	if (map->format.format_write) {
		if ((reg_endian != REGMAP_ENDIAN_BIG) ||
		    (val_endian != REGMAP_ENDIAN_BIG))
			goto err_hwlock;
		map->use_single_write = true;
	}

	if (!map->format.format_write &&
	    !(map->format.format_reg && map->format.format_val))
		goto err_hwlock;

	map->work_buf = kzalloc(map->format.buf_size, GFP_KERNEL);
	if (map->work_buf == NULL) {
		ret = -ENOMEM;
		goto err_hwlock;
	}

	if (map->format.format_write) {
		map->defer_caching = false;
		map->reg_write = _regmap_bus_formatted_write;
	} else if (map->format.format_val) {
		map->defer_caching = true;
		map->reg_write = _regmap_bus_raw_write;
	}

skip_format_initialization:

	map->range_tree = RB_ROOT;
	for (i = 0; i < config->num_ranges; i++) {
		const struct regmap_range_cfg *range_cfg = &config->ranges[i];
		struct regmap_range_node *new;

		/* Sanity check */
		if (range_cfg->range_max < range_cfg->range_min) {
			dev_err(map->dev, "Invalid range %d: %u < %u\n", i,
				range_cfg->range_max, range_cfg->range_min);
			goto err_range;
		}

		if (range_cfg->range_max > map->max_register) {
			dev_err(map->dev, "Invalid range %d: %u > %u\n", i,
				range_cfg->range_max, map->max_register);
			goto err_range;
		}

		if (range_cfg->selector_reg > map->max_register) {
			dev_err(map->dev,
				"Invalid range %d: selector out of map\n", i);
			goto err_range;
		}

		if (range_cfg->window_len == 0) {
			dev_err(map->dev, "Invalid range %d: window_len 0\n",
				i);
			goto err_range;
		}

		/* Make sure, that this register range has no selector
		   or data window within its boundary */
		for (j = 0; j < config->num_ranges; j++) {
			unsigned int sel_reg = config->ranges[j].selector_reg;
			unsigned int win_min = config->ranges[j].window_start;
			unsigned int win_max = win_min +
					       config->ranges[j].window_len - 1;

			/* Allow data window inside its own virtual range */
			if (j == i)
				continue;

			if (range_cfg->range_min <= sel_reg &&
			    sel_reg <= range_cfg->range_max) {
				dev_err(map->dev,
					"Range %d: selector for %d in window\n",
					i, j);
				goto err_range;
			}

			if (!(win_max < range_cfg->range_min ||
			      win_min > range_cfg->range_max)) {
				dev_err(map->dev,
					"Range %d: window for %d in window\n",
					i, j);
				goto err_range;
			}
		}

		new = kzalloc(sizeof(*new), GFP_KERNEL);
		if (new == NULL) {
			ret = -ENOMEM;
			goto err_range;
		}

		new->map = map;
		new->name = range_cfg->name;
		new->range_min = range_cfg->range_min;
		new->range_max = range_cfg->range_max;
		new->selector_reg = range_cfg->selector_reg;
		new->selector_mask = range_cfg->selector_mask;
		new->selector_shift = range_cfg->selector_shift;
		new->window_start = range_cfg->window_start;
		new->window_len = range_cfg->window_len;

		if (!_regmap_range_add(map, new)) {
			dev_err(map->dev, "Failed to add range %d\n", i);
			kfree(new);
			goto err_range;
		}

		if (map->selector_work_buf == NULL) {
			map->selector_work_buf =
				kzalloc(map->format.buf_size, GFP_KERNEL);
			if (map->selector_work_buf == NULL) {
				ret = -ENOMEM;
				goto err_range;
			}
		}
	}

	ret = regcache_init(map, config);
	if (ret != 0)
		goto err_range;

	if (dev) {
		ret = regmap_attach_dev(dev, map, config);
		if (ret != 0)
			goto err_regcache;
	} else {
		regmap_debugfs_init(map);
	}

	return map;

err_regcache:
	regcache_exit(map);
err_range:
	regmap_range_exit(map);
	kfree(map->work_buf);
err_hwlock:
	if (map->hwlock)
		hwspin_lock_free(map->hwlock);
err_name:
	kfree_const(map->name);
err_map:
	kfree(map);
err:
	return ERR_PTR(ret);
}
