#include <linux/acpi.h>
#include <linux/cpu.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/memblock.h>
#include <linux/sched.h>
#include <linux/console.h>
#include <linux/of_fdt.h>
#include <linux/sched/task.h>
#include <linux/smp.h>
//#include <linux/efi.h>
#include <linux/crash_dump.h>
#include <linux/panic_notifier.h>

#include <asm/acpi.h>
#include <asm/alternative.h>
#include <asm/cacheflush.h>
#include <asm/cpufeature.h>
#include <asm/early_ioremap.h>
#include <asm/pgtable.h>
#include <asm/setup.h>
#include <asm/set_memory.h>
#include <asm/sections.h>
#include <asm/sbi.h>
#include <asm/tlbflush.h>
#include <asm/thread_info.h>
#include <asm/kasan.h>
//#include <asm/efi.h>

//#include "head.h"

unsigned long boot_cpu_hartid;
