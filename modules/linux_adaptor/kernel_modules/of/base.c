#include <linux/of.h>

#include "of_private.h"
#include "../adaptor.h"

#define OF_PHANDLE_CACHE_BITS   7
#define OF_PHANDLE_CACHE_SZ BIT(OF_PHANDLE_CACHE_BITS)

static struct device_node *phandle_cache[OF_PHANDLE_CACHE_SZ];

/* use when traversing tree through the child, sibling,
 * or parent members of struct device_node.
 */
DEFINE_RAW_SPINLOCK(devtree_lock);

void cl_set_phandle_cache(phandle phandle, struct device_node *node)
{
    if (phandle >= OF_PHANDLE_CACHE_SZ || phandle_cache[phandle]) {
        PANIC("Bad or existed phandle.");
    }
    phandle_cache[phandle] = node;
}

static struct property *__of_find_property(const struct device_node *np,
                       const char *name, int *lenp)
{
    struct property *pp;

    if (!np)
        return NULL;

    for (pp = np->properties; pp; pp = pp->next) {
        if (of_prop_cmp(pp->name, name) == 0) {
            if (lenp)
                *lenp = pp->length;
            break;
        }
    }

    return pp;
}

static bool __of_node_is_type(const struct device_node *np, const char *type)
{
    const char *match = __of_get_property(np, "device_type", NULL);

    return np && match && type && !strcmp(match, type);
}

/**
 * __of_device_is_compatible() - Check if the node matches given constraints
 * @device: pointer to node
 * @compat: required compatible string, NULL or "" for any match
 * @type: required device_type value, NULL or "" for any match
 * @name: required node name, NULL or "" for any match
 *
 * Checks if the given @compat, @type and @name strings match the
 * properties of the given @device. A constraints can be skipped by
 * passing NULL or an empty string as the constraint.
 *
 * Returns 0 for no match, and a positive integer on match. The return
 * value is a relative score with larger values indicating better
 * matches. The score is weighted for the most specific compatible value
 * to get the highest score. Matching type is next, followed by matching
 * name. Practically speaking, this results in the following priority
 * order for matches:
 *
 * 1. specific compatible && type && name
 * 2. specific compatible && type
 * 3. specific compatible && name
 * 4. specific compatible
 * 5. general compatible && type && name
 * 6. general compatible && type
 * 7. general compatible && name
 * 8. general compatible
 * 9. type && name
 * 10. type
 * 11. name
 */
static int __of_device_is_compatible(const struct device_node *device,
                     const char *compat, const char *type, const char *name)
{
    struct property *prop;
    const char *cp;
    int index = 0, score = 0;

    /* Compatible match has highest priority */
    if (compat && compat[0]) {
        prop = __of_find_property(device, "compatible", NULL);
        for (cp = of_prop_next_string(prop, NULL); cp;
             cp = of_prop_next_string(prop, cp), index++) {
            if (of_compat_cmp(cp, compat, strlen(compat)) == 0) {
                score = INT_MAX/2 - (index << 2);
                break;
            }
        }
        if (!score)
            return 0;
    }

    /* Matching type is better than matching name */
    if (type && type[0]) {
        if (!__of_node_is_type(device, type))
            return 0;
        score += 2;
    }

    /* Matching name is a bit better than not */
    if (name && name[0]) {
        if (!of_node_name_eq(device, name))
            return 0;
        score++;
    }

    return score;
}

static
const struct of_device_id *__of_match_node(const struct of_device_id *matches,
                       const struct device_node *node)
{
    const struct of_device_id *best_match = NULL;
    int score, best_score = 0;

    if (!matches)
        return NULL;

    for (; matches->name[0] || matches->type[0] || matches->compatible[0]; matches++) {
        score = __of_device_is_compatible(node, matches->compatible,
                          matches->type, matches->name);
        if (score > best_score) {
            best_match = matches;
            best_score = score;
        }
    }

    return best_match;
}

/**
 * of_match_node - Tell if a device_node has a matching of_match structure
 * @matches:    array of of device match structures to search in
 * @node:   the of device structure to match against
 *
 * Low level utility function used by device matching.
 */
const struct of_device_id *of_match_node(const struct of_device_id *matches,
                     const struct device_node *node)
{
    const struct of_device_id *match;
    unsigned long flags;

    raw_spin_lock_irqsave(&devtree_lock, flags);
    match = __of_match_node(matches, node);
    raw_spin_unlock_irqrestore(&devtree_lock, flags);
    return match;
}

/**
 * __of_add_property - Add a property to a node without lock operations
 * @np:     Caller's Device Node
 * @prop:   Property to add
 */
int __of_add_property(struct device_node *np, struct property *prop)
{
    int rc = 0;
    unsigned long flags;
    struct property **next;

    raw_spin_lock_irqsave(&devtree_lock, flags);

    //__of_remove_property_from_list(&np->deadprops, prop);

    prop->next = NULL;
    next = &np->properties;
    while (*next) {
        if (strcmp(prop->name, (*next)->name) == 0) {
            /* duplicate ! don't insert it */
            rc = -EEXIST;
            goto out_unlock;
        }
        next = &(*next)->next;
    }
    *next = prop;

out_unlock:
    raw_spin_unlock_irqrestore(&devtree_lock, flags);
    if (rc)
        return rc;

    //__of_add_property_sysfs(np, prop);
    return 0;
}

/**
 * of_add_property - Add a property to a node
 * @np:     Caller's Device Node
 * @prop:   Property to add
 */
int of_add_property(struct device_node *np, struct property *prop)
{
    int rc;

    //mutex_lock(&of_mutex);
    rc = __of_add_property(np, prop);
    //mutex_unlock(&of_mutex);

    /*
    if (!rc)
        of_property_notify(OF_RECONFIG_ADD_PROPERTY, np, prop, NULL);
        */

    return rc;
}

/*
 * Find a property with a given name for a given node
 * and return the value.
 */
const void *__of_get_property(const struct device_node *np,
                  const char *name, int *lenp)
{
    struct property *pp = __of_find_property(np, name, lenp);

    return pp ? pp->value : NULL;
}

bool of_node_name_eq(const struct device_node *np, const char *name)
{
    const char *node_name;
    size_t len;

    if (!np)
        return false;

    node_name = kbasename(np->full_name);
    len = strchrnul(node_name, '@') - node_name;

    return (strlen(name) == len) && (strncmp(node_name, name, len) == 0);
}

struct property *of_find_property(const struct device_node *np,
                  const char *name,
                  int *lenp)
{
    struct property *pp;
    unsigned long flags;

    raw_spin_lock_irqsave(&devtree_lock, flags);
    pp = __of_find_property(np, name, lenp);
    raw_spin_unlock_irqrestore(&devtree_lock, flags);

    return pp;
}

/** Checks if the given "compat" string matches one of the strings in
 * the device's "compatible" property
 */
int of_device_is_compatible(const struct device_node *device,
        const char *compat)
{
    unsigned long flags;
    int res;

    raw_spin_lock_irqsave(&devtree_lock, flags);
    res = __of_device_is_compatible(device, compat, NULL, NULL);
    raw_spin_unlock_irqrestore(&devtree_lock, flags);
    return res;
}

/*
 * Find a property with a given name for a given node
 * and return the value.
 */
const void *of_get_property(const struct device_node *np, const char *name,
                int *lenp)
{
    struct property *pp = of_find_property(np, name, lenp);

    return pp ? pp->value : NULL;
}

int of_phandle_iterator_init(struct of_phandle_iterator *it,
        const struct device_node *np,
        const char *list_name,
        const char *cells_name,
        int cell_count)
{
    const __be32 *list;
    int size;

    memset(it, 0, sizeof(*it));

    /*
     * one of cell_count or cells_name must be provided to determine the
     * argument length.
     */
    if (cell_count < 0 && !cells_name)
        return -EINVAL;

    list = of_get_property(np, list_name, &size);
    if (!list)
        return -ENOENT;

    it->cells_name = cells_name;
    it->cell_count = cell_count;
    it->parent = np;
    it->list_end = list + size / sizeof(*list);
    it->phandle_end = list;
    it->cur = list;

    return 0;
}

int of_phandle_iterator_next(struct of_phandle_iterator *it)
{
    uint32_t count = 0;

    if (it->node) {
        of_node_put(it->node);
        it->node = NULL;
    }

    if (!it->cur || it->phandle_end >= it->list_end)
        return -ENOENT;

    it->cur = it->phandle_end;

    /* If phandle is 0, then it is an empty entry with no arguments. */
    it->phandle = be32_to_cpup(it->cur++);

    if (it->phandle) {

        /*
         * Find the provider node and parse the #*-cells property to
         * determine the argument length.
         */
        it->node = of_find_node_by_phandle(it->phandle);

        if (it->cells_name) {
            if (!it->node) {
                pr_err("%pOF: could not find phandle %d\n",
                       it->parent, it->phandle);
                goto err;
            }

            if (of_property_read_u32(it->node, it->cells_name, &count)) {
                /*
                 * If both cell_count and cells_name is given,
                 * fall back to cell_count in absence
                 * of the cells_name property
                 */
                if (it->cell_count >= 0) {
                    count = it->cell_count;
                } else {
                    pr_err("%pOF: could not get %s for %pOF\n",
                           it->parent,
                           it->cells_name,
                           it->node);
                    goto err;
                }
            }
        } else {
            count = it->cell_count;
        }

        /*
         * Make sure that the arguments actually fit in the remaining
         * property data length
         */
        if (it->cur + count > it->list_end) {
            if (it->cells_name)
                pr_err("%pOF: %s = %d found %td\n",
                    it->parent, it->cells_name,
                    count, it->list_end - it->cur);
            else
                pr_err("%pOF: phandle %s needs %d, found %td\n",
                    it->parent, of_node_full_name(it->node),
                    count, it->list_end - it->cur);
            goto err;
        }
    }

    it->phandle_end = it->cur + count;
    it->cur_count = count;

    return 0;

err:
    if (it->node) {
        of_node_put(it->node);
        it->node = NULL;
    }

    return -EINVAL;
}

int __of_parse_phandle_with_args(const struct device_node *np,
                 const char *list_name,
                 const char *cells_name,
                 int cell_count, int index,
                 struct of_phandle_args *out_args)
{
    struct of_phandle_iterator it;
    int rc, cur_index = 0;

    if (index < 0)
        return -EINVAL;

    /* Loop over the phandles until all the requested entry is found */
    of_for_each_phandle(&it, rc, np, list_name, cells_name, cell_count) {
        /*
         * All of the error cases bail out of the loop, so at
         * this point, the parsing is successful. If the requested
         * index matches, then fill the out_args structure and return,
         * or return -ENOENT for an empty entry.
         */
        rc = -ENOENT;
        if (cur_index == index) {
            if (!it.phandle)
                goto err;

            if (out_args) {
                int c;

                c = of_phandle_iterator_args(&it,
                                 out_args->args,
                                 MAX_PHANDLE_ARGS);
                out_args->np = it.node;
                out_args->args_count = c;
            } else {
                of_node_put(it.node);
            }

            /* Found it! return success */
            return 0;
        }

        cur_index++;
    }

    /*
     * Unlock node before returning result; will be one of:
     * -ENOENT : index is for empty phandle
     * -EINVAL : parsing error on data
     */

 err:
    of_node_put(it.node);
    return rc;
}

int of_phandle_iterator_args(struct of_phandle_iterator *it,
                 uint32_t *args,
                 int size)
{
    int i, count;

    count = it->cur_count;

    if (WARN_ON(size < count))
        count = size;

    for (i = 0; i < count; i++)
        args[i] = be32_to_cpup(it->cur++);

    return count;
}

/**
 * of_find_node_by_phandle - Find a node given a phandle
 * @handle: phandle of the node to find
 *
 * Return: A node pointer with refcount incremented, use
 * of_node_put() on it when done.
 */
struct device_node *of_find_node_by_phandle(phandle handle)
{
    pr_notice("%s: No impl.", __func__);

    if (handle >= OF_PHANDLE_CACHE_SZ) {
        PANIC("Too big 'handle'.");
    }
    if (phandle_cache[handle] == NULL) {
        PANIC("Bad 'phandle'.");
    }
    return phandle_cache[handle];
}

/**
 * of_get_parent - Get a node's parent if any
 * @node:   Node to get parent
 *
 * Return: A node pointer with refcount incremented, use
 * of_node_put() on it when done.
 */
struct device_node *of_get_parent(const struct device_node *node)
{
    struct device_node *np;
    unsigned long flags;

    if (!node)
        return NULL;

    raw_spin_lock_irqsave(&devtree_lock, flags);
    np = of_node_get(node->parent);
    raw_spin_unlock_irqrestore(&devtree_lock, flags);
    return np;
}
