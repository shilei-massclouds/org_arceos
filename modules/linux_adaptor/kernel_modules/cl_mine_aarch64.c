#include "booter.h"

// irq
CL_MINE(platform_get_irq)
CL_MINE(cl_enable_irq)
CL_MINE(request_threaded_irq)

// locking
CL_MINE(queued_spin_lock_slowpath)

// panic
CL_MINE(__stack_chk_fail)
