/* SPDX-License-Identifier: MIT */
#ifndef SNAP_STEP_ALU_H
#define SNAP_STEP_ALU_H
#include <stdint.h>

/* Only register arithmetic which cannot fault, change NZCV, access SP, touch
 * memory, or branch. Reject before changing any register. The caller owns the
 * service lock and validates the instruction fetch and exception origin. */
static inline uint64_t step_alu_reg(const uint64_t *x, unsigned r)
{ return r == 31 ? 0 : x[r]; }

static inline uint64_t step_alu_shift(uint64_t v, unsigned kind,
                                      unsigned amount, unsigned width)
{
    uint64_t mask = width == 64 ? UINT64_MAX : UINT32_MAX;
    v &= mask;
    if (!amount) return v;
    if (kind == 0) return (v << amount) & mask;
    if (kind == 1) return v >> amount;
    if (kind == 2) {
        uint64_t high = (v >> (width - 1)) ? mask << (width - amount) : 0;
        return (v >> amount) | (high & mask);
    }
    return ((v >> amount) | (v << (width - amount))) & mask;
}

static inline int step_alu_one(uint32_t w, uint64_t pc, uint64_t *x)
{
    unsigned width = w >> 31 ? 64 : 32, rd = w & 31;
    unsigned rn = (w >> 5) & 31, rm = (w >> 16) & 31;
    uint64_t value, mask = width == 64 ? UINT64_MAX : UINT32_MAX;
    if (w == 0xd503201f) return 1; /* NOP, not other HINTs */
    if ((w & 0x1f800000) == 0x12800000) { /* MOVN/Z/K */
        unsigned op = (w >> 29) & 3, shift = ((w >> 21) & 3) * 16;
        if (op == 1 || shift >= width) return 0;
        value = (uint64_t)((w >> 5) & 0xffff) << shift;
        if (op == 0) value = ~value;
        if (op == 3) value |= step_alu_reg(x, rd) & ~(UINT64_C(0xffff) << shift);
    } else if ((w & 0x3f800000) == 0x11000000) { /* ADD/SUB immediate, S=0 */
        if (rd == 31 || rn == 31) return 0; /* these forms name SP */
        uint64_t imm = (uint64_t)((w >> 10) & 0xfff) << ((w & (1u << 22)) ? 12 : 0);
        value = w & (1u << 30) ? x[rn] - imm : x[rn] + imm;
    } else if ((w & 0x1f000000) == 0x0a000000) { /* logical shifted register */
        unsigned op = (w >> 29) & 3, shift = (w >> 10) & 63;
        if (op == 3 || shift >= width) return 0; /* ANDS/BICS change NZCV */
        uint64_t a = step_alu_reg(x, rn);
        uint64_t b = step_alu_shift(step_alu_reg(x, rm), (w >> 22) & 3, shift, width);
        if (w & (1u << 21)) b = ~b;
        value = op == 0 ? a & b : op == 1 ? a | b : a ^ b;
    } else if ((w & 0x3f200000) == 0x0b000000) { /* ADD/SUB shifted register, S=0 */
        unsigned kind = (w >> 22) & 3, shift = (w >> 10) & 63;
        if (kind == 3 || shift >= width) return 0;
        uint64_t a = step_alu_reg(x, rn);
        uint64_t b = step_alu_shift(step_alu_reg(x, rm), kind, shift, width);
        value = w & (1u << 30) ? a - b : a + b;
    } else if ((w & 0x1f000000) == 0x10000000) { /* ADR/ADRP */
        uint64_t imm = (((uint64_t)w >> 5) & 0x7ffff) * 4 + ((w >> 29) & 3);
        if (imm & (1u << 20)) imm |= UINT64_MAX << 21;
        value = w >> 31 ? (pc & ~UINT64_C(4095)) + (imm << 12) : pc + imm;
        mask = UINT64_MAX; /* both forms always write Xd */
    } else return 0;
    if (rd != 31) x[rd] = value & mask;
    return 1;
}

struct step_alu_state {
    uint64_t resume_pc, resume_generation, armed, prior_native;
    uint64_t batches, instructions, max_batch;
};

static inline void step_alu_enter(struct step_alu_state *s, unsigned category)
{
    s->prior_native = category == 0x32 && s->armed;
    s->armed = 0;
}

static inline void step_alu_resume(struct step_alu_state *s, uint64_t pc,
                                    uint64_t generation)
{
    s->resume_pc = pc;
    s->resume_generation = generation;
    s->armed = 1;
}

static inline int step_alu_ready(const struct step_alu_state *s, uint64_t pc,
                                 uint64_t generation, uint64_t spsr, uint64_t mdscr)
{
    /* A real native instruction just executed in this unchanged translation.
     * That proves instruction-fetch permission, which AT S1E1R alone cannot.
     * Pending steps after an emulated monitor/sysreg call do not provide this
     * proof. Preserve BTI/illegal-state checks and hardware breakpoint behavior. */
    return s->prior_native && (s->resume_pc >> 12) == (pc >> 12) &&
           s->resume_generation == generation &&
           !(spsr & ((3UL << 10) | (1UL << 20))) && !(mdscr & (1UL << 15));
}

/* Leave the final word of the 4K translation to native stepping. This keeps
 * both the next PC and its fetch in the already validated, immutable page. */
static inline unsigned step_alu_batch(const volatile uint32_t *words,
                                      uint64_t *pc, uint64_t *x)
{
    if (*pc & 3) return 0;
    unsigned n = 0, room = (4092 - (*pc & 4095)) / 4;
    while (n < 16 && n < room && step_alu_one(words[n], *pc, x)) {
        ++n;
        *pc += 4;
    }
    return n;
}
#endif
