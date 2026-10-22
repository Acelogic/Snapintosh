/* SPDX-License-Identifier: MIT */
/* Freestanding compiler runtime. Touch exactly n bytes; never overread a
 * page boundary. EL2 may require aligned accesses, so wide accesses are used
 * only after proving both pointers aligned. No SIMD or guest register state. */
.text
.p2align 2
.global memcpy
.type memcpy, %function
memcpy:
    mov x3, x0
    orr x4, x0, x1
    tst x4, #7
    b.ne 2f
1:  cmp x2, #8
    b.lo 2f
    ldr x4, [x1], #8
    str x4, [x3], #8
    sub x2, x2, #8
    b 1b
2:  cbz x2, 4f
3:  ldrb w4, [x1], #1
    strb w4, [x3], #1
    subs x2, x2, #1
    b.ne 3b
4:  ret
.size memcpy, .-memcpy

.p2align 2
.global memset
.type memset, %function
memset:
    mov x3, x0
    and w1, w1, #255
    cbz x2, 4f
1:  tst x3, #7
    b.eq 2f
    strb w1, [x3], #1
    subs x2, x2, #1
    b.ne 1b
    ret
2:  orr x1, x1, x1, lsl #8
    orr x1, x1, x1, lsl #16
    orr x1, x1, x1, lsl #32
3:  cmp x2, #8
    b.lo 5f
    str x1, [x3], #8
    sub x2, x2, #8
    b 3b
4:  ret
5:  cbz x2, 4b
6:  strb w1, [x3], #1
    subs x2, x2, #1
    b.ne 6b
    ret
.size memset, .-memset
