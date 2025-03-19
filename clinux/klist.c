#include <linux/types.h>
#include <linux/klist.h>
#include "booter.h"

/**
 * klist_init - Initialize a klist structure.
 * @k: The klist we're initializing.
 * @get: The get function for the embedding object (NULL if none)
 * @put: The put function for the embedding object (NULL if none)
 *
 * Initialises the klist structure.  If the klist_node structures are
 * going to be embedded in refcounted objects (necessary for safe
 * deletion) then the get/put arguments are used to initialise
 * functions that take and release references on the embedding
 * objects.
 */
void klist_init(struct klist *k, void (*get)(struct klist_node *),
        void (*put)(struct klist_node *))
{
    INIT_LIST_HEAD(&k->k_list);
    spin_lock_init(&k->k_lock);
    k->get = get;
    k->put = put;
}
