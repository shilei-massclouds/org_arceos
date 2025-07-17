#include <linux/of.h>

/* Impl it. */
const struct fwnode_operations of_fwnode_ops;

/**
 * of_find_property_value_of_size
 *
 * @np:     device node from which the property value is to be read.
 * @propname:   name of the property to be searched.
 * @min:    minimum allowed length of property value
 * @max:    maximum allowed length of property value (0 means unlimited)
 * @len:    if !=NULL, actual length is written to here
 *
 * Search for a property in a device node and valid the requested size.
 *
 * Return: The property value on success, -EINVAL if the property does not
 * exist, -ENODATA if property does not have a value, and -EOVERFLOW if the
 * property data is too small or too large.
 *
 */
static void *of_find_property_value_of_size(const struct device_node *np,
            const char *propname, u32 min, u32 max, size_t *len)
{
    struct property *prop = of_find_property(np, propname, NULL);

    if (!prop)
        return ERR_PTR(-EINVAL);
    if (!prop->value)
        return ERR_PTR(-ENODATA);
    if (prop->length < min)
        return ERR_PTR(-EOVERFLOW);
    if (max && prop->length > max)
        return ERR_PTR(-EOVERFLOW);

    if (len)
        *len = prop->length;

    return prop->value;
}

const char *of_prop_next_string(struct property *prop, const char *cur)
{
    const void *curv = cur;

    if (!prop)
        return NULL;

    if (!cur)
        return prop->value;

    curv += strlen(cur) + 1;
    if (curv >= prop->value + prop->length)
        return NULL;

    return curv;
}

/**
 * of_property_read_variable_u32_array - Find and read an array of 32 bit
 * integers from a property, with bounds on the minimum and maximum array size.
 *
 * @np:     device node from which the property value is to be read.
 * @propname:   name of the property to be searched.
 * @out_values: pointer to return found values.
 * @sz_min: minimum number of array elements to read
 * @sz_max: maximum number of array elements to read, if zero there is no
 *      upper limit on the number of elements in the dts entry but only
 *      sz_min will be read.
 *
 * Search for a property in a device node and read 32-bit value(s) from
 * it.
 *
 * Return: The number of elements read on success, -EINVAL if the property
 * does not exist, -ENODATA if property does not have a value, and -EOVERFLOW
 * if the property data is smaller than sz_min or longer than sz_max.
 *
 * The out_values is modified only if a valid u32 value can be decoded.
 */
int of_property_read_variable_u32_array(const struct device_node *np,
                   const char *propname, u32 *out_values,
                   size_t sz_min, size_t sz_max)
{
    size_t sz, count;
    const __be32 *val = of_find_property_value_of_size(np, propname,
                        (sz_min * sizeof(*out_values)),
                        (sz_max * sizeof(*out_values)),
                        &sz);

    if (IS_ERR(val))
        return PTR_ERR(val);

    if (!sz_max)
        sz = sz_min;
    else
        sz /= sizeof(*out_values);

    count = sz;
    while (count--)
        *out_values++ = be32_to_cpup(val++);

    return sz;
}
