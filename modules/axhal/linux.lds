OUTPUT_ARCH(riscv)

//LOAD_OFFSET = 0xffffffc080200000;
LOAD_OFFSET = ((((-1))) - 0x80000000 + 1);

PAGE_SIZE = 4096;
THREAD_SIZE_ORDER = 2;
THREAD_SIZE = PAGE_SIZE << THREAD_SIZE_ORDER;

ENTRY(_start)
SECTIONS
{
    . = LOAD_OFFSET;
    _start = .;
    .head.text : AT(ADDR(.head.text) - LOAD_OFFSET) {
        KEEP(*(.head.text))
    }
    . = ALIGN(4K);

    .text : ALIGN(4K) {
        _stext = .;
        *(.text.boot)
        *(.text .text.*)
        . = ALIGN(4K);
        _etext = .;
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

    _srodata = .;
    . = ALIGN((1 << 21));
    .rodata : AT(ADDR(.rodata) - LOAD_OFFSET) {
        __start_rodata = .;
        *(.rodata .rodata.*)
        *(.data.rel.ro*)
        *(.srodata .srodata.*)
        *(.sdata2 .sdata2.*)
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
        _sdata = .;

        . = ALIGN(2 * THREAD_SIZE);
        __start_init_stack = .;
        init_thread_union = .;
        init_stack = .;
        KEEP(*(.data..init_task))
        KEEP(*(.data..init_thread_info))
        . = __start_init_stack + THREAD_SIZE;
        __end_init_stack = .; 

        . = ALIGN(4K);
        *(.data .data.*)
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

    . = ALIGN(4K);
    _end = .;

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
INSERT AFTER .bss;
