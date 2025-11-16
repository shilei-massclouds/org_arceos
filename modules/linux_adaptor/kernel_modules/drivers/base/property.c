#include <linux/device.h>
#include <linux/property.h>
#include <linux/of.h>

/**
 * fwnode_get_name - Return the name of a node
 * @fwnode: The firmware node
 *
 * Return: a pointer to the node name, or %NULL.
 */
const char *fwnode_get_name(const struct fwnode_handle *fwnode)
{
    return fwnode_call_ptr_op(fwnode, get_name);
}

/**
 * fwnode_handle_get - Obtain a reference to a device node
 * @fwnode: Pointer to the device node to obtain the reference to.
 *
 * The caller is responsible for calling fwnode_handle_put() on the returned
 * fwnode pointer.
 *
 * Return: the fwnode handle.
 */
struct fwnode_handle *fwnode_handle_get(struct fwnode_handle *fwnode)
{
    if (!fwnode_has_op(fwnode, get))
        return fwnode;

    return fwnode_call_ptr_op(fwnode, get);
}

struct fwnode_handle *__dev_fwnode(struct device *dev)
{
    return IS_ENABLED(CONFIG_OF) && dev->of_node ?
        of_fwnode_handle(dev->of_node) : dev->fwnode;
}

/**
 * fwnode_count_parents - Return the number of parents a node has
 * @fwnode: The node the parents of which are to be counted
 *
 * Return: the number of parents a node has.
 */
unsigned int fwnode_count_parents(const struct fwnode_handle *fwnode)
{
    struct fwnode_handle *parent;
    unsigned int count = 0;

    fwnode_for_each_parent_node(fwnode, parent)
        count++;

    return count;
}

/**
 * fwnode_get_next_parent - Iterate to the node's parent
 * @fwnode: Firmware whose parent is retrieved
 *
 * This is like fwnode_get_parent() except that it drops the refcount
 * on the passed node, making it suitable for iterating through a
 * node's parents.
 *
 * The caller is responsible for calling fwnode_handle_put() on the returned
 * fwnode pointer. Note that this function also puts a reference to @fwnode
 * unconditionally.
 *
 * Return: parent firmware node of the given node if possible or %NULL if no
 * parent was available.
 */
struct fwnode_handle *fwnode_get_next_parent(struct fwnode_handle *fwnode)
{
    struct fwnode_handle *parent = fwnode_get_parent(fwnode);

    fwnode_handle_put(fwnode);

    return parent;
}

/**
 * fwnode_get_parent - Return parent firwmare node
 * @fwnode: Firmware whose parent is retrieved
 *
 * The caller is responsible for calling fwnode_handle_put() on the returned
 * fwnode pointer.
 *
 * Return: parent firmware node of the given node if possible or %NULL if no
 * parent was available.
 */
struct fwnode_handle *fwnode_get_parent(const struct fwnode_handle *fwnode)
{
    return fwnode_call_ptr_op(fwnode, get_parent);
}

/**
 * fwnode_get_name_prefix - Return the prefix of node for printing purposes
 * @fwnode: The firmware node
 *
 * Return: the prefix of a node, intended to be printed right before the node.
 * The prefix works also as a separator between the nodes.
 */
const char *fwnode_get_name_prefix(const struct fwnode_handle *fwnode)
{
    return fwnode_call_ptr_op(fwnode, get_name_prefix);
}

const struct fwnode_handle *__dev_fwnode_const(const struct device *dev)
{
    return IS_ENABLED(CONFIG_OF) && dev->of_node ?
        of_fwnode_handle(dev->of_node) : dev->fwnode;
}

/**
 * device_property_present - check if a property of a device is present
 * @dev: Device whose property is being checked
 * @propname: Name of the property
 *
 * Check if property @propname is present in the device firmware description.
 *
 * Return: true if property @propname is present. Otherwise, returns false.
 */
bool device_property_present(const struct device *dev, const char *propname)
{
    return fwnode_property_present(dev_fwnode(dev), propname);
}

/**
 * fwnode_property_present - check if a property of a firmware node is present
 * @fwnode: Firmware node whose property to check
 * @propname: Name of the property
 *
 * Return: true if property @propname is present. Otherwise, returns false.
 */
bool fwnode_property_present(const struct fwnode_handle *fwnode,
                 const char *propname)
{
    bool ret;

    if (IS_ERR_OR_NULL(fwnode))
        return false;

    ret = fwnode_call_bool_op(fwnode, property_present, propname);
    if (ret)
        return ret;

    return fwnode_call_bool_op(fwnode->secondary, property_present, propname);
}

/**
 * device_property_read_u32_array - return a u32 array property of a device
 * @dev: Device to get the property of
 * @propname: Name of the property
 * @val: The values are stored here or %NULL to return the number of values
 * @nval: Size of the @val array
 *
 * Function reads an array of u32 properties with @propname from the device
 * firmware description and stores them to @val if found.
 *
 * It's recommended to call device_property_count_u32() instead of calling
 * this function with @val equals %NULL and @nval equals 0.
 *
 * Return: number of values if @val was %NULL,
 *         %0 if the property was found (success),
 *     %-EINVAL if given arguments are not valid,
 *     %-ENODATA if the property does not have a value,
 *     %-EPROTO if the property is not an array of numbers,
 *     %-EOVERFLOW if the size of the property is not as expected.
 *     %-ENXIO if no suitable firmware interface is present.
 */
int device_property_read_u32_array(const struct device *dev, const char *propname,
                   u32 *val, size_t nval)
{
    return fwnode_property_read_u32_array(dev_fwnode(dev), propname, val, nval);
}

static int fwnode_property_read_int_array(const struct fwnode_handle *fwnode,
                      const char *propname,
                      unsigned int elem_size, void *val,
                      size_t nval)
{
    int ret;

    if (IS_ERR_OR_NULL(fwnode))
        return -EINVAL;

    ret = fwnode_call_int_op(fwnode, property_read_int_array, propname,
                 elem_size, val, nval);
    if (ret != -EINVAL)
        return ret;

    return fwnode_call_int_op(fwnode->secondary, property_read_int_array, propname,
                  elem_size, val, nval);
}

/**
 * fwnode_property_read_u32_array - return a u32 array property of firmware node
 * @fwnode: Firmware node to get the property of
 * @propname: Name of the property
 * @val: The values are stored here or %NULL to return the number of values
 * @nval: Size of the @val array
 *
 * Read an array of u32 properties with @propname from @fwnode store them to
 * @val if found.
 *
 * It's recommended to call fwnode_property_count_u32() instead of calling
 * this function with @val equals %NULL and @nval equals 0.
 *
 * Return: number of values if @val was %NULL,
 *         %0 if the property was found (success),
 *     %-EINVAL if given arguments are not valid,
 *     %-ENODATA if the property does not have a value,
 *     %-EPROTO if the property is not an array of numbers,
 *     %-EOVERFLOW if the size of the property is not as expected,
 *     %-ENXIO if no suitable firmware interface is present.
 */
int fwnode_property_read_u32_array(const struct fwnode_handle *fwnode,
                   const char *propname, u32 *val, size_t nval)
{
    return fwnode_property_read_int_array(fwnode, propname, sizeof(u32),
                          val, nval);
}

/**
 * device_property_read_string_array - return a string array property of device
 * @dev: Device to get the property of
 * @propname: Name of the property
 * @val: The values are stored here or %NULL to return the number of values
 * @nval: Size of the @val array
 *
 * Function reads an array of string properties with @propname from the device
 * firmware description and stores them to @val if found.
 *
 * It's recommended to call device_property_string_array_count() instead of calling
 * this function with @val equals %NULL and @nval equals 0.
 *
 * Return: number of values read on success if @val is non-NULL,
 *     number of values available on success if @val is NULL,
 *     %-EINVAL if given arguments are not valid,
 *     %-ENODATA if the property does not have a value,
 *     %-EPROTO or %-EILSEQ if the property is not an array of strings,
 *     %-EOVERFLOW if the size of the property is not as expected.
 *     %-ENXIO if no suitable firmware interface is present.
 */
int device_property_read_string_array(const struct device *dev, const char *propname,
                      const char **val, size_t nval)
{
    return fwnode_property_read_string_array(dev_fwnode(dev), propname, val, nval);
}

/**
 * fwnode_property_read_string_array - return string array property of a node
 * @fwnode: Firmware node to get the property of
 * @propname: Name of the property
 * @val: The values are stored here or %NULL to return the number of values
 * @nval: Size of the @val array
 *
 * Read an string list property @propname from the given firmware node and store
 * them to @val if found.
 *
 * It's recommended to call fwnode_property_string_array_count() instead of calling
 * this function with @val equals %NULL and @nval equals 0.
 *
 * Return: number of values read on success if @val is non-NULL,
 *     number of values available on success if @val is NULL,
 *     %-EINVAL if given arguments are not valid,
 *     %-ENODATA if the property does not have a value,
 *     %-EPROTO or %-EILSEQ if the property is not an array of strings,
 *     %-EOVERFLOW if the size of the property is not as expected,
 *     %-ENXIO if no suitable firmware interface is present.
 */
int fwnode_property_read_string_array(const struct fwnode_handle *fwnode,
                      const char *propname, const char **val,
                      size_t nval)
{
    int ret;

    if (IS_ERR_OR_NULL(fwnode))
        return -EINVAL;

    ret = fwnode_call_int_op(fwnode, property_read_string_array, propname,
                 val, nval);
    if (ret != -EINVAL)
        return ret;

    return fwnode_call_int_op(fwnode->secondary, property_read_string_array, propname,
                  val, nval);
}

/**
 * fwnode_device_is_available - check if a device is available for use
 * @fwnode: Pointer to the fwnode of the device.
 *
 * Return: true if device is available for use. Otherwise, returns false.
 *
 * For fwnode node types that don't implement the .device_is_available()
 * operation, this function returns true.
 */
bool fwnode_device_is_available(const struct fwnode_handle *fwnode)
{
    if (IS_ERR_OR_NULL(fwnode))
        return false;

    if (!fwnode_has_op(fwnode, device_is_available))
        return true;

    return fwnode_call_bool_op(fwnode, device_is_available);
}

/**
 * fwnode_get_next_child_node - Return the next child node handle for a node
 * @fwnode: Firmware node to find the next child node for.
 * @child: Handle to one of the node's child nodes or a %NULL handle.
 *
 * The caller is responsible for calling fwnode_handle_put() on the returned
 * fwnode pointer. Note that this function also puts a reference to @child
 * unconditionally.
 */
struct fwnode_handle *
fwnode_get_next_child_node(const struct fwnode_handle *fwnode,
               struct fwnode_handle *child)
{
    return fwnode_call_ptr_op(fwnode, get_next_child_node, child);
}

/**
 * fwnode_get_next_available_child_node - Return the next available child node handle for a node
 * @fwnode: Firmware node to find the next child node for.
 * @child: Handle to one of the node's child nodes or a %NULL handle.
 *
 * The caller is responsible for calling fwnode_handle_put() on the returned
 * fwnode pointer. Note that this function also puts a reference to @child
 * unconditionally.
 */
struct fwnode_handle *
fwnode_get_next_available_child_node(const struct fwnode_handle *fwnode,
                     struct fwnode_handle *child)
{
    struct fwnode_handle *next_child = child;

    if (IS_ERR_OR_NULL(fwnode))
        return NULL;

    do {
        next_child = fwnode_get_next_child_node(fwnode, next_child);
        if (!next_child)
            return NULL;
    } while (!fwnode_device_is_available(next_child));

    return next_child;
}

/**
 * fwnode_property_match_string - find a string in an array and return index
 * @fwnode: Firmware node to get the property of
 * @propname: Name of the property holding the array
 * @string: String to look for
 *
 * Find a given string in a string array and if it is found return the
 * index back.
 *
 * Return: index, starting from %0, if the property was found (success),
 *     %-EINVAL if given arguments are not valid,
 *     %-ENODATA if the property does not have a value,
 *     %-EPROTO if the property is not an array of strings,
 *     %-ENXIO if no suitable firmware interface is present.
 */
int fwnode_property_match_string(const struct fwnode_handle *fwnode,
    const char *propname, const char *string)
{
    const char **values;
    int nval, ret;

    nval = fwnode_property_string_array_count(fwnode, propname);
    if (nval < 0)
        return nval;

    if (nval == 0)
        return -ENODATA;

    values = kcalloc(nval, sizeof(*values), GFP_KERNEL);
    if (!values)
        return -ENOMEM;

    ret = fwnode_property_read_string_array(fwnode, propname, values, nval);
    if (ret < 0)
        goto out_free;

    ret = match_string(values, nval, string);
    if (ret < 0)
        ret = -ENODATA;

out_free:
    kfree(values);
    return ret;
}

/**
 * fwnode_irq_get - Get IRQ directly from a fwnode
 * @fwnode: Pointer to the firmware node
 * @index:  Zero-based index of the IRQ
 *
 * Return: Linux IRQ number on success. Negative errno on failure.
 */
int fwnode_irq_get(const struct fwnode_handle *fwnode, unsigned int index)
{
    int ret;

    ret = fwnode_call_int_op(fwnode, irq_get, index);
    /* We treat mapping errors as invalid case */
    if (ret == 0)
        return -EINVAL;

    return ret;
}

/**
 * fwnode_irq_get_byname - Get IRQ from a fwnode using its name
 * @fwnode: Pointer to the firmware node
 * @name:   IRQ name
 *
 * Description:
 * Find a match to the string @name in the 'interrupt-names' string array
 * in _DSD for ACPI, or of_node for Device Tree. Then get the Linux IRQ
 * number of the IRQ resource corresponding to the index of the matched
 * string.
 *
 * Return: Linux IRQ number on success, or negative errno otherwise.
 */
int fwnode_irq_get_byname(const struct fwnode_handle *fwnode, const char *name)
{
    int index;

    if (!name)
        return -EINVAL;

    index = fwnode_property_match_string(fwnode, "interrupt-names",  name);
    if (index < 0)
        return index;

    return fwnode_irq_get(fwnode, index);
}
