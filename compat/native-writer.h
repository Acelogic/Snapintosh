/* SPDX-License-Identifier: MIT */
#ifndef SNAP_NATIVE_WRITER_H
#define SNAP_NATIVE_WRITER_H
#include <stdint.h>

#define NATIVE_WRITER_PAGE_COUNT 2u
#define NATIVE_WRITER_SITE_COUNT 6u
#define NATIVE_WRITER_VA_MASK ((UINT64_C(1)<<47)-1)
#define NATIVE_WRITER_PXN (UINT64_C(1)<<53)
#define NATIVE_WRITER_UXN (UINT64_C(1)<<54)

/* This is the already pinned J700 26A428 instruction inventory. The terminal
 * of each group traps before executing; preceding writes run natively. */
struct native_writer_site {
    uint64_t va;
    uint32_t word;
    uint32_t page;
};
static const struct native_writer_site native_writer_sites[NATIVE_WRITER_SITE_COUNT]={
    {UINT64_C(0xfffffe000b86eae8),0xd5184033,0},
    {UINT64_C(0xfffffe000b86eb08),0xd5184032,0},
    {UINT64_C(0xfffffe000b86f9f4),0xd5184002,1},
    {UINT64_C(0xfffffe000b86fc14),0xd5184002,1},
    {UINT64_C(0xfffffe000b86fc70),0xd518402c,1},
    {UINT64_C(0xfffffe000b86fe88),0xd5184002,1},
};

struct native_writer_mapping {
    uint64_t pa[NATIVE_WRITER_PAGE_COUNT];
};
enum native_writer_regime {
    NATIVE_WRITER_KERNEL_HIGH,
    NATIVE_WRITER_KERNEL_LOW,
    NATIVE_WRITER_USER,
};

static inline uint64_t native_writer_page_va(unsigned page)
{
    return (UINT64_C(0xfffffe000b86e000)+(uint64_t)page*4096)&NATIVE_WRITER_VA_MASK;
}

static inline int native_writer_mapping_valid(const struct native_writer_mapping *m)
{
    if(!m)return 0;
    for(unsigned i=0;i<NATIVE_WRITER_PAGE_COUNT;i++)
        if(!m->pa[i] || (m->pa[i]&4095) || m->pa[i]>=(UINT64_C(1)<<48))return 0;
    return m->pa[0]!=m->pa[1];
}

/* Address inputs are normalized 47-bit VA offsets, as consumed by shadow_map.
 * A whole range is checked before any table mutation. A writer page can be
 * executable only in the upper kernel regime at its pinned VA. Both XN bits
 * are required for every other alias: no raw SPRR class with mutable/effective
 * execute permission is accepted as a supposedly data-only exception.
 *
 * Callers must also apply this admission to direct descriptor changes and
 * permission retypes, and preserve it when rebuilding/copying a shadow.
 * This helper alone is not a complete alias-exclusion proof. */
static inline int native_writer_mapping_admit(const struct native_writer_mapping *m,
    enum native_writer_regime regime,uint64_t va,uint64_t pa,uint64_t size,
    uint64_t low,uint64_t upper)
{
    (void)low;
    if(!native_writer_mapping_valid(m) || regime>NATIVE_WRITER_USER ||
       regime<NATIVE_WRITER_KERNEL_HIGH || ((va|pa|size)&4095) ||
       va>NATIVE_WRITER_VA_MASK || size>NATIVE_WRITER_VA_MASK+1-va ||
       pa>=(UINT64_C(1)<<48) || size>(UINT64_C(1)<<48)-pa)return 0;
    if(!size)return 1;
    if((upper&(NATIVE_WRITER_PXN|NATIVE_WRITER_UXN))==
       (NATIVE_WRITER_PXN|NATIVE_WRITER_UXN))return 1;
    for(unsigned i=0;i<NATIVE_WRITER_PAGE_COUNT;i++) {
        if(m->pa[i]<pa || m->pa[i]-pa>=size)continue;
        if(regime!=NATIVE_WRITER_KERNEL_HIGH ||
           va+(m->pa[i]-pa)!=native_writer_page_va(i))return 0;
    }
    return 1;
}

/* SNAP_ERET_SNAPSHOT: exception_return's SPSR write (site 5) and the words
 * after it up to the kernel's only ERET. Nothing in between may enter the
 * monitor through a native call, whose restore would put back a snapshot
 * older than this write: no call (BL, BLR*), no indirect branch or return
 * (the whole unconditional-branch-register class but the plain ERET), no
 * exception generator (SVC, HVC, SMC, BRK, HLT, DCPS, the 0xd4e00000 call
 * word), nothing from the reserved encoding group (UDF, genter 0x00201420)
 * and no other ELR/SPSR writer. Every direct branch (B, B.cond, CBZ/CBNZ,
 * TBZ/TBNZ) goes forward and lands at or before the ERET. Returns the
 * ERET's index (words[0] is the site), or 0. */
#define NATIVE_WRITER_RETURN_SITE 5u
#define NATIVE_WRITER_RETURN_WINDOW 256u
#define NATIVE_WRITER_ERET UINT32_C(0xd69f03e0)
static inline unsigned native_writer_return_window(const uint32_t *words,unsigned count)
{
    if(!words || count<2 || count>NATIVE_WRITER_RETURN_WINDOW ||
       words[0]!=native_writer_sites[NATIVE_WRITER_RETURN_SITE].word)return 0;
    uint64_t reach=0;
    for(unsigned i=1;i<count;i++) {
        uint32_t w=words[i];
        if(w==NATIVE_WRITER_ERET)return reach<=i ? i : 0;
        if((w&UINT32_C(0xfc000000))==UINT32_C(0x94000000) ||   /* BL */
           (w&UINT32_C(0xfe000000))==UINT32_C(0xd6000000) ||   /* BR/BLR/RET/ERET*, PAC forms */
           (w&UINT32_C(0xff000000))==UINT32_C(0xd4000000) ||   /* exception generation */
           !(w&UINT32_C(0x1e000000)) ||                        /* reserved group: UDF, genter */
           (w&~UINT32_C(31))==UINT32_C(0xd5184000) || (w&~UINT32_C(31))==UINT32_C(0xd5184020))
            return 0;
        int64_t offset;
        if((w&UINT32_C(0xfc000000))==UINT32_C(0x14000000))
            offset=(int64_t)((uint64_t)w<<38)>>38;               /* B imm26 */
        else if((w&UINT32_C(0xff000010))==UINT32_C(0x54000000) ||
                (w&UINT32_C(0x7e000000))==UINT32_C(0x34000000))
            offset=(int64_t)((uint64_t)(w>>5)<<45)>>45;          /* B.cond, CBZ/CBNZ imm19 */
        else if((w&UINT32_C(0x7e000000))==UINT32_C(0x36000000))
            offset=(int64_t)((uint64_t)(w>>5)<<50)>>50;          /* TBZ/TBNZ imm14 */
        else continue;
        if(offset<=0 || (uint64_t)offset>=count-i)return 0;
        if(i+(uint64_t)offset>reach)reach=i+(uint64_t)offset;
    }
    return 0;
}

/* Decode only the admitted terminal writer; x31 is the architectural zero
 * source, never an out-of-bounds register-bank access. */
static inline int native_writer_value(uint64_t pc,uint32_t word,
    const uint64_t regs[31],uint64_t *value,int *spsr,unsigned *site)
{
    if(!regs || !value || !spsr || !site)return 0;
    for(unsigned i=0;i<NATIVE_WRITER_SITE_COUNT;i++) {
        if(pc!=native_writer_sites[i].va || word!=native_writer_sites[i].word)continue;
        unsigned reg=word&31;
        *value=reg==31 ? 0 : regs[reg];
        *spsr=(word&~31u)==0xd5184000u;
        *site=i;
        return 1;
    }
    return 0;
}
#endif
