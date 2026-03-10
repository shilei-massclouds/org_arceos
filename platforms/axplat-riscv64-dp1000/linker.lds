OUTPUT_ARCH(riscv)

LOAD_OFFSET = ((((-1))) - 0x80000000 + 1);

PAGE_SIZE = 4096;
THREAD_SIZE_ORDER = 2;
THREAD_SIZE = PAGE_SIZE << THREAD_SIZE_ORDER;

ENTRY(_start)

jiffies = jiffies_64;

SECTIONS
{
    . = LOAD_OFFSET;
    _start = .;
    _skernel = _start;
    .head.text : AT(ADDR(.head.text) - LOAD_OFFSET) {
        KEEP(*(.head.text))
        KEEP(*(.head.text2))
    }
    . = ALIGN(4K);

    .text : ALIGN(4K) {
        _text = .;
        _stext = .;
        *(.text.hot .text.hot.*)
        *(.text .text.fixup)
        *(.text.unlikely .text.unlikely.*)
        *(.text.unknown .text.unknown.*)
        __noinstr_text_start = .;
        *(.noinstr.text)
        __cpuidle_text_start = .;
        *(.cpuidle.text)
        __cpuidle_text_end = .;
        __noinstr_text_end = .;
        *(.ref.text)
        *(.text.asan.* .text.tsan.*)
        __sched_text_start = .;
        *(.sched.text)
        __sched_text_end = .;
        __lock_text_start = .;
        *(.spinlock.text)
        __lock_text_end = .;
        __kprobes_text_start = .;
        *(.kprobes.text)
        __kprobes_text_end = .;
        __entry_text_start = .;
        *(.entry.text)
        __entry_text_end = .;
        __irqentry_text_start = .;
        *(.irqentry.text)
        __irqentry_text_end = .;
        __softirqentry_text_start = .;
        *(.softirqentry.text)
        __softirqentry_text_end = .;
        _etext = .;
    }

    . = ALIGN((1 << 21));
    __init_begin = .;
    __init_text_begin = .;
    .init.text : AT(ADDR(.init.text) - LOAD_OFFSET) ALIGN((1 << 21)) {
        _sinittext = .;
        *(.init.text .init.text.*)
        *(.text.startup)
        _einittext = .;
    }

    __exittext_begin = .;
    .exit.text : {
        *(.exit.text) *(.text.exit)
    }
    __exittext_end = .;
    __init_text_end = .;

    . = ALIGN((1 << 21));
    . = ALIGN(4K);

    __init_data_begin = .;
    .init.data : AT(ADDR(.init.data) - LOAD_OFFSET) {
        KEEP(*(SORT(___kentry+*)))
        *(.init.data .init.data.*)
        . = ALIGN(8);
        __clk_of_table = .;
        KEEP(*(__clk_of_table))
        KEEP(*(__clk_of_table_end))
        . = ALIGN(8);
        __reservedmem_of_table = .;
        KEEP(*(__reservedmem_of_table))
        KEEP(*(__reservedmem_of_table_end))
        . = ALIGN(8);
        __timer_of_table = .;
        KEEP(*(__timer_of_table))
        KEEP(*(__timer_of_table_end))
        . = ALIGN(8);
        __irqchip_of_table = .;
        KEEP(*(__irqchip_of_table))
        KEEP(*(__irqchip_of_table_end))

        __initcall_start = .;
        KEEP(*(.initcallearly.init))
        __initcall0_start = .;
        KEEP(*(.initcall0.init)) KEEP(*(.initcall0s.init))
        __initcall1_start = .;
        KEEP(*(.initcall1.init)) KEEP(*(.initcall1s.init))
        __initcall2_start = .;
        KEEP(*(.initcall2.init)) KEEP(*(.initcall2s.init))
        __initcall3_start = .;
        KEEP(*(.initcall3.init)) KEEP(*(.initcall3s.init))
        __initcall4_start = .;
        KEEP(*(.initcall4.init)) KEEP(*(.initcall4s.init))
        __initcall5_start = .;
        KEEP(*(.initcall5.init)) KEEP(*(.initcall5s.init))
        __initcallrootfs_start = .;
        KEEP(*(.initcallrootfs.init)) KEEP(*(.initcallrootfss.init))
        __initcall6_start = .;
        KEEP(*(.initcall6.init)) KEEP(*(.initcall6s.init))
        __initcall7_start = .;
        KEEP(*(.initcall7.init)) KEEP(*(.initcall7s.init))
        __initcall_end = .;
    }

    . = ALIGN(4K);
    .data..percpu : AT(ADDR(.data..percpu) - LOAD_OFFSET) {
        __per_cpu_load = .;
        __per_cpu_start = .;
        *(.data..percpu..first)
        . = ALIGN((1 << 12));
        *(.data..percpu..page_aligned)
        . = ALIGN((1 << 6));
        *(.data..percpu..read_mostly)
        . = ALIGN((1 << 6));
        *(.data..percpu)
        *(.data..percpu..shared_aligned)
        __per_cpu_end = .;

        /* FixMe: Remove these old symbols. */
        _percpu_start = .;
        _percpu_end = .;
        _percpu_load_start = .;
        _percpu_load_end = .;
    }

    __init_data_end = .;
    __init_end = .;

    _srodata = .;
    . = ALIGN((1 << 21));
    .rodata : AT(ADDR(.rodata) - LOAD_OFFSET) {
        __start_rodata = .;
        *(.rodata)
        *(.rodata.*)
        *(.data.rel.ro*)
        . = ALIGN(32);

        __sched_class_highest = .;
        *(__stop_sched_class)
        *(__dl_sched_class)
        *(__rt_sched_class)
        *(__fair_sched_class)
        *(__ext_sched_class)
        *(__idle_sched_class)
        __sched_class_lowest = .;

        __end_rodata = .;
    }
    .srodata : {
        *(.srodata*)
    }

    .init_array : ALIGN(0x10) {
        __init_array_start = .;
        *(.init_array .init_array.*)
        __init_array_end = .;
    }

    . = ALIGN(4K);
    _erodata = .;

    . = ALIGN((1 << 21));
    _data = .;
    . = ALIGN(4K);
    .data : AT(ADDR(.data) - LOAD_OFFSET) {
        . = ALIGN(2 * THREAD_SIZE);
        __start_init_stack = .;
        boot_stack = __start_init_stack;
        init_thread_union = .;
        init_stack = .;
        KEEP(*(.data..init_task))
        KEEP(*(.data..init_thread_info))
        . = __start_init_stack + THREAD_SIZE;
        __end_init_stack = .;
        boot_stack_top = __end_init_stack;

        _sdata = .;
        . = ALIGN(4K);
        *(.data .data.*)
        *(.ref.data)
    }

    . = ALIGN(8);
    __bug_table : AT(ADDR(__bug_table) - LOAD_OFFSET) {
        __start___bug_table = .;
        KEEP(*(__bug_table))
        __stop___bug_table = .;
    }

    .sdata : {
        __global_pointer$ = . + 0x800;
        *(.sdata*)
    }

    .got : { *(.got*) }

    . = ALIGN(4K);
    _edata = .;

    . = ALIGN(4K);
    __bss_start = .;
    _sbss = __bss_start;
    .sbss : AT(ADDR(.sbss) - LOAD_OFFSET) {
        *(.dynsbss)
        *(.sbss)
        *(.scommon)
    }
    . = ALIGN(4K);
    .bss : AT(ADDR(.bss) - LOAD_OFFSET) {
        . = ALIGN(4K);
        *(.bss..page_aligned)
        . = ALIGN(4K);
        *(.dynbss)
        *(.bss)
        *(COMMON)
    }
    __bss_stop = .;
    _ebss = __bss_stop;

    . = ALIGN(4K);
    _end = .;
    _ekernel = _end;

	/DISCARD/ : {
        *(.comment) *(.gnu*) *(.note*) *(.eh_frame*)
    }
}

SECTIONS {
    linkme_IRQ : { *(linkme_IRQ) }
    linkm2_IRQ : { *(linkm2_IRQ) }
    linkme_PAGE_FAULT : { *(linkme_PAGE_FAULT) }
    linkm2_PAGE_FAULT : { *(linkm2_PAGE_FAULT) }
    linkme_SYSCALL : { *(linkme_SYSCALL) }
    linkm2_SYSCALL : { *(linkm2_SYSCALL) }
    axns_resource : { *(axns_resource) }
}
INSERT AFTER .got;
