// SPDX-License-Identifier: MIT
#include "pauth-switch.h"
.text
.balign 4
.macro save_pair crm, op, hi, off
    mrs x9,s3_0_c2_c\crm\()_\op
    mrs x10,s3_0_c2_c\crm\()_\hi
    stp x9,x10,[x0,#(80+\off)]
.endm
.macro load_pair crm, op, hi, off, base
    ldp x9,x10,[x0,#(\base+\off)]
    msr s3_0_c2_c\crm\()_\op,x9
    msr s3_0_c2_c\crm\()_\hi,x10
.endm
.macro check_pair crm, op, hi, off
    ldp x9,x10,[x0,#(80+\off)]
    mrs x11,s3_0_c2_c\crm\()_\op
    mrs x12,s3_0_c2_c\crm\()_\hi
    eor x9,x9,x11
    eor x10,x10,x12
    orr x9,x9,x10
    orr x13,x13,x9
.endm
.global pauth_switch_enter
pauth_switch_enter:
    mrs x9,currentel
    cmp x9,#8
    b.ne .Lfail
    mrs x9,daif
    and x9,x9,#0x3c0
    cmp x9,#0x3c0
    b.ne .Lfail
    ldr x9,[x0,#PAUTH_BANK_ACTIVE]
    cbnz x9,.Lfail
    mrs x14,hcr_el2
    tbnz x14,#34,.Lfail
#if !(defined(SNAP_NATIVE_PACGA) && SNAP_NATIVE_PACGA)
    tbnz x14,#41,.Lfail
#endif
    // SNAP_NATIVE_PACGA: EL1 already runs with API set (native PACGA under
    // the guest kernel's GA key); the bank saved here, and restored by leave,
    // is that EL1 state.
    mrs x15,sctlr_el1
    mov x16,#0x2000
    movk x16,#0xc800,lsl #16
    tst x15,x16
    b.ne .Lfail
    ldr x17,[x0,#PAUTH_BANK_ENABLES]
    bic x9,x17,x16
    cbnz x9,.Lfail
    save_pair 1,0,1,0
    save_pair 1,2,3,16
    save_pair 2,0,1,32
    save_pair 2,2,3,48
    save_pair 3,0,1,64
    stp x14,x15,[x0,#160]
    mov x9,#1
    str x9,[x0,#PAUTH_BANK_ACTIVE]
    load_pair 1,0,1,0,0
    load_pair 1,2,3,16,0
    load_pair 2,0,1,32,0
    load_pair 2,2,3,48,0
    load_pair 3,0,1,64,0
    orr x15,x15,x17
    msr sctlr_el1,x15
    orr x14,x14,#(1<<41)
    msr hcr_el2,x14
    isb
    ldr x9,[x0,#PAUTH_BANK_ENTRIES]
    add x9,x9,#1
    str x9,[x0,#PAUTH_BANK_ENTRIES]
    mov w0,#0
    ret
.Lfail:
    ldr x9,[x0,#PAUTH_BANK_FAILURES]
    add x9,x9,#1
    str x9,[x0,#PAUTH_BANK_FAILURES]
    mov w0,#1
    ret

.global pauth_switch_leave
pauth_switch_leave:
    ldr x9,[x0,#PAUTH_BANK_ACTIVE]
    cbz x9,.Linactive
    // No PAC instruction or C call until all host banks are restored.
    ldp x14,x15,[x0,#160]
    msr hcr_el2,x14
    msr sctlr_el1,x15
    load_pair 1,0,1,0,80
    load_pair 1,2,3,16,80
    load_pair 2,0,1,32,80
    load_pair 2,2,3,48,80
    load_pair 3,0,1,64,80
    isb
    mov x13,#0
    check_pair 1,0,1,0
    check_pair 1,2,3,16
    check_pair 2,0,1,32
    check_pair 2,2,3,48
    check_pair 3,0,1,64
    cmp x13,#0
    cset x13,eq
    mrs x9,hcr_el2
    cmp x9,x14
    cset x9,eq
    orr x13,x13,x9,lsl #1
    mrs x9,sctlr_el1
    cmp x9,x15
    cset x9,eq
    orr x13,x13,x9,lsl #2
    str x13,[x0,#PAUTH_BANK_RESTORED]
    cmp x13,#7
    b.ne .Lfail                     // retain recovery copy if readback fails
    str xzr,[x0,#PAUTH_BANK_ACTIVE]
    stp xzr,xzr,[x0,#80]
    stp xzr,xzr,[x0,#96]
    stp xzr,xzr,[x0,#112]
    stp xzr,xzr,[x0,#128]
    stp xzr,xzr,[x0,#144]
    ldr x9,[x0,#PAUTH_BANK_EXITS]
    add x9,x9,#1
    str x9,[x0,#PAUTH_BANK_EXITS]
.Linactive:
    mov w0,#0
    ret
#if defined(SNAP_PAUTH_EL0_LIVE) && SNAP_PAUTH_EL0_LIVE

// SNAP_PAUTH_EL0_LIVE: sync_lower's entry. With the EL0 bank live and no
// failure latched, the vector fetch abort (EC 0x20 from a lower EL) of an
// UNDEFINED EL0t instruction (ESR_EL1 0x02000000) at slot offset 0x400 may be
// an EL0 read that xnuboot_trap answers without leaving EL0's bank: return 0
// with the bank, SCTLR_EL1 and HCR_EL2 untouched. xnuboot_trap re-checks the
// exact slot and either answers it or calls pauth_switch_leave before any
// other C. Every other entry is pauth_switch_leave, result included.
// Reads only; uses x9 and x10.
.global pauth_switch_live
pauth_switch_live:
    ldr x9,[x0,#PAUTH_BANK_ACTIVE]
    cmp x9,#1
    b.ne pauth_switch_leave
    ldr x9,[x0,#PAUTH_BANK_FAILURES]
    cbnz x9,pauth_switch_leave
    mrs x9,esr_el2
    lsr x9,x9,#26
    cmp x9,#0x20
    b.ne pauth_switch_leave
    mrs x9,esr_el1
    mov x10,#0x2000000
    cmp x9,x10
    b.ne pauth_switch_leave
    mrs x9,spsr_el1
    tst x9,#0xffffffff0000001f
    b.ne pauth_switch_leave
    mrs x9,elr_el2
    and x9,x9,#0x7ff
    cmp x9,#0x400
    b.ne pauth_switch_leave
    mov w0,#0
    ret
#endif
