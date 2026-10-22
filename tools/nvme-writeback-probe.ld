/* SPDX-License-Identifier: MIT */
ENTRY(nvme_writeback_probe)
SECTIONS {
    . = 0;
    .text : { KEEP(*(.text.entry)) *(.text*) }
    .rodata : { *(.rodata*) }
    .data : { *(.data*) }
    .bss : { *(.bss*) }
    /DISCARD/ : { *(.comment) *(.eh_frame*) }
}
