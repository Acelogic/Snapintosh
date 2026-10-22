/* SPDX-License-Identifier: MIT */
ENTRY(txm_image4_bridge)
SECTIONS {
    . = 0x100000;
    .text : { KEEP(*(.text.entry)) *(.text*) }
    /DISCARD/ : { *(.comment) *(.eh_frame*) }
}
