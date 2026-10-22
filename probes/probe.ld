/* SPDX-License-Identifier: MIT */
/* A P_CALL blob is branched to at offset 0, so the entry stub must land first
 * no matter what order the objects are given to the linker. Everything is
 * position-independent by construction (the probes use ADR, not absolute
 * relocations), so there is no load address here -- q1n1 puts the blob wherever
 * it likes and jumps to the front. */
ENTRY(_start)
SECTIONS
{
    . = 0;
    .text : {
        *(.text.entry)
        *(.text .text.*)
        *(.rodata .rodata.*)
    }
    /* Probes keep their state in the caller-provided work area rather than in
     * .data, so anything landing here is a mistake worth failing the build. */
    .data : { *(.data .data.*) }
    .bss  : { *(.bss .bss.*) *(COMMON) }
    ASSERT(SIZEOF(.data) == 0, "probe has initialised data; keep state in the work area")
    ASSERT(SIZEOF(.bss) == 0, "probe has bss; keep state in the work area")
    /DISCARD/ : { *(.comment) *(.note.*) *(.eh_frame*) }
}
