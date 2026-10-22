/* SPDX-License-Identifier: MIT */
#ifndef SNAP_NATIVE_CALL_H
#define SNAP_NATIVE_CALL_H
#include <stdint.h>

#define NATIVE_CALL_FLAG (UINT64_C(1) << 63)
#define NATIVE_HVC_FLAG (UINT64_C(1) << 62)
#define NATIVE_CALL_FLAGS (NATIVE_CALL_FLAG | NATIVE_HVC_FLAG)
#define NATIVE_HVC_IMMEDIATE 0x5350U
#define NATIVE_HVC_WORD (UINT32_C(0xd4000002) | (NATIVE_HVC_IMMEDIATE << 5))
#define NATIVE_CALL_PAGES 5
#define NATIVE_WRITER_PAGES 2
#define NATIVE_CONTRACT_PAGES (NATIVE_CALL_PAGES + NATIVE_WRITER_PAGES)

/* Virtual pages are pinned by the same whole-kernel digest as the loader's
 * physical page inventory; an executable alias is not a call-site identity. */
static inline uint64_t native_call_page_va(unsigned page)
{
    static const uint64_t pages[NATIVE_CALL_PAGES] = {
        UINT64_C(0xfffffe000c22a000), UINT64_C(0xfffffe000c22b000),
        UINT64_C(0xfffffe000c22c000), UINT64_C(0xfffffe000c22d000),
        UINT64_C(0xfffffe000c264000)
    };
    return page < NATIVE_CALL_PAGES ? pages[page] : 0;
}

/* The selected kernel has 174 instances of each call encoding and ten writes
 * to physical EL1's ELR/SPSR. The loader checks the complete image, not merely
 * these pages. ESR/FAR writes already trap and none occur in this image. */
static inline int native_call_word(uint32_t word)
{ return word == 0x00201420U || word == 0xd4e00000U; }

static inline int native_exception_writer(uint32_t word)
{ return (word & ~31U) == 0xd5184000U || (word & ~31U) == 0xd5184020U; }

/* Direct ELR/SPSR writes execute in stepped writer pages or in admitted groups
 * ending at an exact hardware breakpoint; the terminal write is emulated.
 * Genuine EL1
 * exceptions land in the vector guard (or its step). EL2 MMIO/sysreg/IRQ
 * exits do not themselves change EL1's exception registers. The only explicit
 * remaining writes are the trapped ESR/FAR accessors. A private call already
 * restored the saved state and needs no new snapshot. */
static inline int native_call_snapshot_required(uint64_t syndrome, int private_call)
{
    unsigned ec=(syndrome>>26)&63;
    uint64_t iss=syndrome&0x1ffffff;
    if (ec==0x30 || ec==0x32) return 1;
    if (ec==0x20) return !private_call;
    if (ec!=0x18 || (iss&1)) return 0;
    uint64_t reg=iss&~((UINT64_C(31)<<5)|1);
    return reg==0x301404 || reg==0x301800; /* ESR_EL1 and FAR_EL1 */
}

struct native_call_state {
    uint64_t ready, calls, restores, rejected;
    uint64_t elr, spsr, esr, far;
    uint64_t last_pc, last_word, last_saved, last_physical;
};
/* Separate counters: an HVC call does not overwrite or restore EL1 exception
 * registers, unlike the private-instruction/vector path. */
struct native_hvc_state { uint64_t calls, rejected, last_pc; };
_Static_assert(sizeof(struct native_call_state)==96, "native-call capture ABI");

/* Hardware proof: with NV+NV2 and NV1 clear, a physical EL1 -> EL1 exception
 * saves virtual EL2t/h. Never ERET from real EL2 using that virtual mode. */
static inline int native_call_return(uint64_t vector, uint64_t syndrome,
    uint64_t saved, uint64_t entry, uint64_t pc, uint32_t word,
    uint64_t *physical)
{
    unsigned mode = saved & 31;
    if (!physical || syndrome != (UINT64_C(1) << 25) ||
        (entry & 31) != 5 || (mode != 8 && mode != 9) ||
        vector != (mode == 8 ? 0 : 0x200) ||
        (saved >> 32) || (saved & ((UINT64_C(1) << 20) | (UINT64_C(1) << 21))) ||
        pc < UINT64_C(0xffff800000000000) || (pc & 3) ||
        !native_call_word(word)) return 0;
    *physical = (saved & ~UINT64_C(12)) | 4;
    return 1;
}
#endif
