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

/**
 * of_property_read_u32_index - Find and read a u32 from a multi-value property.
 *
 * @np:     device node from which the property value is to be read.
 * @propname:   name of the property to be searched.
 * @index:  index of the u32 in the list of values
 * @out_value:  pointer to return value, modified only if no error.
 *
 * Search for a property in a device node and read nth 32-bit value from
 * it.
 *
 * Return: 0 on success, -EINVAL if the property does not exist,
 * -ENODATA if property does not have a value, and -EOVERFLOW if the
 * property data isn't large enough.
 *
 * The out_value is modified only if a valid u32 value can be decoded.
 */
int of_property_read_u32_index(const struct device_node *np,
                       const char *propname,
                       u32 index, u32 *out_value)
{
    const u32 *val = of_find_property_value_of_size(np, propname,
                    ((index + 1) * sizeof(*out_value)),
                    0,
                    NULL);

    if (IS_ERR(val))
        return PTR_ERR(val);

    *out_value = be32_to_cpup(((__be32 *)val) + index);
    return 0;
}

/**
 * of_property_read_string - Find and read a string from a property
 * @np:     device node from which the property value is to be read.
 * @propname:   name of the property to be searched.
 * @out_string: pointer to null terminated return string, modified only if
 *      return value is 0.
 *
 * Search for a property in a device tree node and retrieve a null
 * terminated string value (pointer to data, not a copy).
 *
 * Return: 0 on success, -EINVAL if the property does not exist, -ENODATA if
 * property does not have a value, and -EILSEQ if the string is not
 * null-terminated within the length of the property data.
 *
 * Note that the empty string "" has length of 1, thus -ENODATA cannot
 * be interpreted as an empty string.
 *
 * The out_string pointer is modified only if a valid string can be decoded.
 */
int of_property_read_string(const struct device_node *np, const char *propname,
                const char **out_string)
{
    const struct property *prop = of_find_property(np, propname, NULL);

    if (!prop)
        return -EINVAL;
    if (!prop->length)
        return -ENODATA;
    if (strnlen(prop->value, prop->length) >= prop->length)
        return -EILSEQ;
    *out_string = prop->value;
    return 0;
}

/**
 * of_property_read_string_helper() - Utility helper for parsing string properties
 * @np:     device node from which the property value is to be read.
 * @propname:   name of the property to be searched.
 * @out_strs:   output array of string pointers.
 * @sz:     number of array elements to read.
 * @skip:   Number of strings to skip over at beginning of list.
 *
 * Don't call this function directly. It is a utility helper for the
 * of_property_read_string*() family of functions.
 */
int of_property_read_string_helper(const struct device_node *np,
                   const char *propname, const char **out_strs,
                   size_t sz, int skip)
{
    const struct property *prop = of_find_property(np, propname, NULL);
    int l = 0, i = 0;
    const char *p, *end;

    if (!prop)
        return -EINVAL;
    if (!prop->value)
        return -ENODATA;
    p = prop->value;
    end = p + prop->length;

    for (i = 0; p < end && (!out_strs || i < skip + sz); i++, p += l) {
        l = strnlen(p, end - p) + 1;
        if (p + l > end)
            return -EILSEQ;
        if (out_strs && i >= skip)
            *out_strs++ = p;
    }
    i -= skip;
    return i <= 0 ? -ENODATA : i;
}

/**
 * of_property_match_string() - Find string in a list and return index
 * @np: pointer to the node containing the string list property
 * @propname: string list property name
 * @string: pointer to the string to search for in the string list
 *
 * Search for an exact match of string in a device node property which is a
 * string of lists.
 *
 * Return: the index of the first occurrence of the string on success, -EINVAL
 * if the property does not exist, -ENODATA if the property does not have a
 * value, and -EILSEQ if the string is not null-terminated within the length of
 * the property data.
 */
int of_property_match_string(const struct device_node *np, const char *propname,
                 const char *string)
{
    const struct property *prop = of_find_property(np, propname, NULL);
    size_t l;
    int i;
    const char *p, *end;

    if (!prop)
        return -EINVAL;
    if (!prop->value)
        return -ENODATA;

    p = prop->value;
    end = p + prop->length;

    for (i = 0; p < end; i++, p += l) {
        l = strnlen(p, end - p) + 1;
        if (p + l > end)
            return -EILSEQ;
        pr_debug("comparing %s with %s\n", string, p);
        if (strcmp(string, p) == 0)
            return i; /* Found it; return index */
    }
    return -ENODATA;
}
