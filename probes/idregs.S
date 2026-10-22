/* SPDX-License-Identifier: MIT */
// x0 = buffer; fills consecutive u64s with the ID registers we care about.
.globl _start
_start:
    mrs x1, midr_el1;          str x1, [x0, #0]
    mrs x1, id_aa64pfr0_el1;   str x1, [x0, #8]
    mrs x1, id_aa64pfr1_el1;   str x1, [x0, #16]
    mrs x1, id_aa64isar0_el1;  str x1, [x0, #24]
    mrs x1, id_aa64isar1_el1;  str x1, [x0, #32]
    mrs x1, id_aa64isar2_el1;  str x1, [x0, #40]
    mrs x1, id_aa64mmfr0_el1;  str x1, [x0, #48]
    mrs x1, id_aa64mmfr1_el1;  str x1, [x0, #56]
    mrs x1, id_aa64mmfr2_el1;  str x1, [x0, #64]
    mrs x1, id_aa64dfr0_el1;   str x1, [x0, #72]
    mrs x1, currentel;         str x1, [x0, #80]
    mrs x1, mpidr_el1;         str x1, [x0, #88]
    mov x0, #0
    ret
