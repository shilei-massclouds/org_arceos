#include <linux/bsearch.h>
#include <linux/device.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/sort.h>

#include "trace.h"
#include "internal.h"

#include "../adaptor.h"

static const struct regcache_ops *cache_types[] = {
    &regcache_rbtree_ops,
    &regcache_maple_ops,
    &regcache_flat_ops,
};

static int regcache_hw_init(struct regmap *map)
{
    int i, j;
    int ret;
    int count;
    unsigned int reg, val;
    void *tmp_buf;

    if (!map->num_reg_defaults_raw)
        return -EINVAL;

    /* calculate the size of reg_defaults */
    for (count = 0, i = 0; i < map->num_reg_defaults_raw; i++)
        if (regmap_readable(map, i * map->reg_stride) &&
            !regmap_volatile(map, i * map->reg_stride))
            count++;

    /* all registers are unreadable or volatile, so just bypass */
    if (!count) {
        map->cache_bypass = true;
        return 0;
    }

    map->num_reg_defaults = count;
    map->reg_defaults = kmalloc_array(count, sizeof(struct reg_default),
                      GFP_KERNEL);
    if (!map->reg_defaults)
        return -ENOMEM;

    if (!map->reg_defaults_raw) {
        bool cache_bypass = map->cache_bypass;
        dev_warn(map->dev, "No cache defaults, reading back from HW\n");

        /* Bypass the cache access till data read from HW */
        map->cache_bypass = true;
        tmp_buf = kmalloc(map->cache_size_raw, GFP_KERNEL);
        if (!tmp_buf) {
            ret = -ENOMEM;
            goto err_free;
        }
        ret = regmap_raw_read(map, 0, tmp_buf,
                      map->cache_size_raw);
        map->cache_bypass = cache_bypass;
        if (ret == 0) {
            map->reg_defaults_raw = tmp_buf;
            map->cache_free = true;
        } else {
            kfree(tmp_buf);
        }
    }

    /* fill the reg_defaults */
    for (i = 0, j = 0; i < map->num_reg_defaults_raw; i++) {

        PANIC("LOOP");
    }

    return 0;

err_free:
    kfree(map->reg_defaults);

    return ret;
}

int regcache_init(struct regmap *map, const struct regmap_config *config)
{
    int ret;
    int i;
    void *tmp_buf;

    if (map->cache_type == REGCACHE_NONE) {
        if (config->reg_defaults || config->num_reg_defaults_raw)
            dev_warn(map->dev,
                 "No cache used with register defaults set!\n");

        map->cache_bypass = true;
        return 0;
    }

    if (config->reg_defaults && !config->num_reg_defaults) {
        dev_err(map->dev,
             "Register defaults are set without the number!\n");
        return -EINVAL;
    }

    if (config->num_reg_defaults && !config->reg_defaults) {
        dev_err(map->dev,
            "Register defaults number are set without the reg!\n");
        return -EINVAL;
    }

    for (i = 0; i < config->num_reg_defaults; i++)
        if (config->reg_defaults[i].reg % map->reg_stride)
            return -EINVAL;

    for (i = 0; i < ARRAY_SIZE(cache_types); i++)
        if (cache_types[i]->type == map->cache_type)
            break;


    if (i == ARRAY_SIZE(cache_types)) {
        dev_err(map->dev, "Could not match cache type: %d\n",
            map->cache_type);
        return -EINVAL;
    }

    map->num_reg_defaults = config->num_reg_defaults;
    map->num_reg_defaults_raw = config->num_reg_defaults_raw;
    map->reg_defaults_raw = config->reg_defaults_raw;
    map->cache_word_size = DIV_ROUND_UP(config->val_bits, 8);
    map->cache_size_raw = map->cache_word_size * config->num_reg_defaults_raw;

    map->cache = NULL;
    map->cache_ops = cache_types[i];

    if (!map->cache_ops->read ||
        !map->cache_ops->write ||
        !map->cache_ops->name)
        return -EINVAL;

    /* We still need to ensure that the reg_defaults
     * won't vanish from under us.  We'll need to make
     * a copy of it.
     */
    if (config->reg_defaults) {
        tmp_buf = kmemdup_array(config->reg_defaults, map->num_reg_defaults,
                    sizeof(*map->reg_defaults), GFP_KERNEL);
        if (!tmp_buf)
            return -ENOMEM;
        map->reg_defaults = tmp_buf;
    } else if (map->num_reg_defaults_raw) {
        /* Some devices such as PMICs don't have cache defaults,
         * we cope with this by reading back the HW registers and
         * crafting the cache defaults by hand.
         */
        ret = regcache_hw_init(map);
        if (ret < 0)
            return ret;
        if (map->cache_bypass)
            return 0;
    }

    if (!map->max_register_is_set && map->num_reg_defaults_raw) {
        map->max_register = (map->num_reg_defaults_raw  - 1) * map->reg_stride;
        map->max_register_is_set = true;
    }

    if (map->cache_ops->init) {
        dev_dbg(map->dev, "Initializing %s cache\n",
            map->cache_ops->name);
        map->lock(map->lock_arg);
        ret = map->cache_ops->init(map);
        map->unlock(map->lock_arg);
        if (ret)
            goto err_free;
    }
    PANIC("");
    return 0;

err_free:
    kfree(map->reg_defaults);
    if (map->cache_free)
        kfree(map->reg_defaults_raw);

    PANIC("");
    return ret;
}

/**
 * regcache_write - Set the value of a given register in the cache.
 *
 * @map: map to configure.
 * @reg: The register index.
 * @value: The new register value.
 *
 * Return a negative value on failure, 0 on success.
 */
int regcache_write(struct regmap *map,
           unsigned int reg, unsigned int value)
{
    if (map->cache_type == REGCACHE_NONE)
        return 0;

    BUG_ON(!map->cache_ops);

    if (!regmap_volatile(map, reg))
        return map->cache_ops->write(map, reg, value);

    return 0;
}

/**
 * regcache_read - Fetch the value of a given register from the cache.
 *
 * @map: map to configure.
 * @reg: The register index.
 * @value: The value to be returned.
 *
 * Return a negative value on failure, 0 on success.
 */
int regcache_read(struct regmap *map,
          unsigned int reg, unsigned int *value)
{
    int ret;

    if (map->cache_type == REGCACHE_NONE)
        return -EINVAL;

    BUG_ON(!map->cache_ops);

    if (!regmap_volatile(map, reg)) {
        ret = map->cache_ops->read(map, reg, value);

        if (ret == 0)
            trace_regmap_reg_read_cache(map, reg, *value);

        return ret;
    }

    return -EINVAL;
}
