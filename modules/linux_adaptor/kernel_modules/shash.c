#include <crypto/hash.h>

#include "booter.h"

struct crypto_shash *crypto_alloc_shash(const char *alg_name, u32 type,
                    u32 mask)
{
    log_debug("%s: No impl.", __func__);
    return NULL;
}
