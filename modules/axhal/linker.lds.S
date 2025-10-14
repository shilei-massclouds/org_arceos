OUTPUT_ARCH(%ARCH%)

BASE_ADDRESS = %KERNEL_BASE%;

jiffies = jiffies_64;

ENTRY(_start)
SECTIONS
{
    . = BASE_ADDRESS;
    _skernel = .;

    .text : ALIGN(4K) {
        _stext = .;
        *(.text.boot)
        *(.text .text.*)
        . = ALIGN(4K);
        _sinittext = .;
        *(.init.text .init.text.*) *(.text.startup)
        _einittext = .;
    }

    /* we have to discard exit text and such at runtime, not link time */
    __exittext_begin = .;
    .exit.text :
    {
        *(.exit.text)
        *(.text.exit)
    }
    __exittext_end = .;

    . = ALIGN(4K);
    _etext = .;

    _srodata = .;
    __start_rodata = .;
    .rodata : ALIGN(4K) {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
        *(.sdata2 .sdata2.*)
        . = ALIGN(8);
        __start___tracepoints_ptrs = .;
        KEEP(*(__tracepoints_ptrs))
        __stop___tracepoints_ptrs = .;
        *(__tracepoints_strings)
        . = ALIGN(16);
        __start_pci_fixups_early = .;
        KEEP(*(.pci_fixup_early))
        __end_pci_fixups_early = .;
        __start_pci_fixups_header = .;
        KEEP(*(.pci_fixup_header))
        __end_pci_fixups_header = .;
        __start_pci_fixups_final = .;
        KEEP(*(.pci_fixup_final))
        __end_pci_fixups_final = .;
        __start_pci_fixups_enable = .;
        KEEP(*(.pci_fixup_enable))
        __end_pci_fixups_enable = .;
        __start_pci_fixups_resume = .;
        KEEP(*(.pci_fixup_resume))
        __end_pci_fixups_resume = .;
        __start_pci_fixups_suspend = .;
        KEEP(*(.pci_fixup_suspend))
        __end_pci_fixups_suspend = .;
        __start_pci_fixups_resume_early = .;
        KEEP(*(.pci_fixup_resume_early))
        __end_pci_fixups_resume_early = .;
        __start_pci_fixups_suspend_late = .;
        KEEP(*(.pci_fixup_suspend_late))
        __end_pci_fixups_suspend_late = .;
    }

    .init_array : ALIGN(0x10) {
        __init_array_start = .;
        *(.init_array .init_array.*)
        __init_array_end = .;
        . = ALIGN(8);
        __irqchip_of_table = .;
        KEEP(*(__irqchip_of_table))
        KEEP(*(__irqchip_of_table_end))
        __irqchip_of_table_end__ = .;
    }

    . = ALIGN(4K);
    _erodata = .;
    __end_rodata = .;

    .data : ALIGN(4K) {
        _sdata = .;
        *(.data.boot_page_table)
        . = ALIGN(4K);
        *(.data .data.*)
        . = ALIGN(8);
        __start___bug_table = .;
        KEEP(*(__bug_table))
        __stop___bug_table = .;
        . = ALIGN(8);
        __start___jump_table = .;
        KEEP(*(__jump_table))
        __stop___jump_table = .;
        *(.sdata .sdata.*)
        *(.got .got.*)
        *(.ref.data)
        . = ALIGN(32);
        *(__tracepoints)
        . = ALIGN(32);
        __start__bpf_raw_tp = .;
        KEEP(*(__bpf_raw_tp_map))
        __stop__bpf_raw_tp = .;
    }

    .init.data : ALIGN(4K) {
        *(.init.data .init.data.*)
        *(.init.rodata .init.rodata.*)
        . = ALIGN(8);
        __start_ftrace_events = .;
        KEEP(*(_ftrace_events))
        __stop_ftrace_events = .;
        __start_ftrace_eval_maps = .;
        KEEP(*(_ftrace_eval_map))
        __stop_ftrace_eval_maps = .;
        . = ALIGN(16);
        __setup_start = .;
        KEEP(*(.init.setup))
        __setup_end = .;
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

    .tdata : ALIGN(0x10) {
        _stdata = .;
        *(.tdata .tdata.*)
        _etdata = .;
    }

    .tbss : ALIGN(0x10) {
        _stbss = .;
        *(.tbss .tbss.*)
        *(.tcommon)
        _etbss = .;
    }

    . = ALIGN(4K);
    _percpu_start = .;
    _percpu_end = _percpu_start + SIZEOF(.percpu);
    .percpu 0x0 : AT(_percpu_start) {
        _percpu_load_start = .;
        *(.percpu .percpu.*)
        _percpu_load_end = .;
        . = _percpu_load_start + ALIGN(64) * %SMP%;
    }
    . = _percpu_end;

    . = ALIGN(4K);
    _edata = .;

    .bss : AT(.) ALIGN(4K) {
        boot_stack = .;
        *(.bss.stack)
        . = ALIGN(4K);
        boot_stack_top = .;

        _sbss = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        . = ALIGN(4K);
        _ebss = .;
    }

    _ekernel = .;

    /*
     * Put kallsyms segment _OUT_ of [_skernel, _ekernel).
     * Build-Scripts use `objcopy --update-section` to fill in this segment
     * and will not change all symbols' addresses include '_ekernel'.
     */
    _kallsyms = .;
    .kallsyms : { KEEP(*(.kallsyms)) }

	/DISCARD/ : {
        *(.comment) *(.gnu*) *(.note*) *(.eh_frame*) *(.discard) *(.discard.*)
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
INSERT AFTER .tbss;
