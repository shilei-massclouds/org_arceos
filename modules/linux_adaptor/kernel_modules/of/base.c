#include <linux/of.h>

#include "of_private.h"
#include "../adaptor.h"

/* use when traversing tree through the child, sibling,
 * or parent members of struct device_node.
 */
DEFINE_RAW_SPINLOCK(devtree_lock);

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
