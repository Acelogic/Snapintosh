/* SPDX-License-Identifier: MIT */
/* Use the production exception vectors and exit plumbing verbatim. Only the
 * initial guest setup and CPU0 report are replaced for this bounded probe. */
#define _start guest_stop_unused_xnu_entry
#define xnuboot_report guest_stop_report
#include "../probes/xnuboot.S"
#undef xnuboot_report
#undef _start

.section .text.guest_stop_entry,"ax"
.global guest_stop_entry
guest_stop_entry:
    stp x29,x30,[sp,#-16]!
    stp x19,x20,[sp,#-16]!
    stp x21,x22,[sp,#-16]!
    stp x23,x24,[sp,#-16]!
    stp x25,x26,[sp,#-16]!
    stp x27,x28,[sp,#-16]!
    mov x19,x0
    mrs x28,daif
    msr daifset,#15
    mrs x22,vbar_el2
    mrs x23,hcr_el2
    mrs x24,tpidr_el2
    mrs x25,sctlr_el1
    mrs x26,tcr_el1
    bl guest_stop_setup
    str x0,[x19]
    cbnz x0,guest_stop_reject
    mrs x9,tpidr_el2
    mov x10,sp
    str x10,[x9]
    mov x0,x22
    mov x1,x23
    mov x2,x24
    mov x3,x25
    mov x4,x26
    mov x5,x28
    bl xnuboot_save
    adr x9,xnuboot_vectors
    msr vbar_el2,x9
    isb
    bl guest_stop_prepare
    cbnz x0,exit
    mov x9,#1
    str x9,[x19,#8]
    adr x9,guest_stop_loop
    msr elr_el2,x9
    mov x9,#0x3c5
    msr spsr_el2,x9
    mov x0,#0
    isb
    eret
guest_stop_reject:
    msr tpidr_el2,x24
    msr daif,x28
    ldp x27,x28,[sp],#16
    ldp x25,x26,[sp],#16
    ldp x23,x24,[sp],#16
    ldp x21,x22,[sp],#16
    ldp x19,x20,[sp],#16
    ldp x29,x30,[sp],#16
    ret

.text
.global guest_stop_loop
guest_stop_loop:
    add x0,x0,#1
    b guest_stop_loop
