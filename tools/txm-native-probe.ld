/* SPDX-License-Identifier: MIT */
ENTRY(txm_native_probe_entry)
SECTIONS {
    . = 0xb0780000;
    .text : { KEEP(*(.text.entry)) *(.text*) }
    .rodata : { *(.rodata*) }
    .data : { *(.data*) }
    .bss : { *(.bss*) *(COMMON) }
    /DISCARD/ : { *(.comment) *(.eh_frame*) }
}
