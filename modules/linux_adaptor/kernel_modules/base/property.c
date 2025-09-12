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
