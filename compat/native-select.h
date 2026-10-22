/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>
#include "sprr.h"
/* O(1) permission-variant selection for native page tables
 * (SNAP_NATIVE_TABLES, docs/NATIVE-TABLES-DESIGN-20260929.md section 5).
 *
 * Each address space has two variant trees: w=0 (TPRO pages read-only) and
 * w=1 (TPRO pages writable). Phase 2 adds kernel variants k=0/1 (ROZONE
 * read-only/writable, PPERM bit 8). Every (address space, w, k) has its own
 * hardware ASID, and the monitor keeps every tree exact and invalidates what
 * it changes, so choosing a variant is a TTBR write with no TLB maintenance.
 *
 *   w = bit 36 of (el0 ? UPERM : PPERM),   k = bit 8 of PPERM.
 *
 * Contract for callers (the EL0/EL1 boundary handler and the SPRR write
 * handlers), all under the monitor's per-CPU state, no locks needed:
 *   native_select(n, el0)       at every EL0<->EL1 crossing the monitor
 *                               controls; el0 is the regime about to run.
 *   native_set_uperm(n, value, el0)  after a UPERM write is accepted;
 *   native_set_pperm(n, value, el0)  after a PPERM write is accepted.
 *                               el0 is the regime that resumes: XNU writes
 *                               UPERM from EL1 too, where PPERM governs.
 *   native_install(...)         at SWITCH_ROOT (monitor only).
 * Each returns nonzero on success; zero is terminal (do not resume the
 * guest). A CPU with no native address space installed selects nothing and
 * succeeds, so the calls are safe in every build. */
struct native_cpu {
    uint64_t ttbr0[2][2];     /* [w][k]: variant root | hardware ASID << 48 */
    uint64_t ttbr1[2];        /* [k]: kernel variant root; 0 leaves TTBR1 alone */
    uint64_t uperm,pperm;     /* the SPRR values the variant follows */
    uint32_t el0,w,k,installed;
    uint64_t selects,flips,errors;
};
_Static_assert(sizeof(struct native_cpu)==104,"native per-CPU selection record");
static inline unsigned native_variant_w(uint64_t uperm,uint64_t pperm,int el0)
{return !!((el0 ? uperm : pperm)&SPRR_UPERM_TPRO_WRITE);}
static inline unsigned native_variant_k(uint64_t pperm)
{return !!(pperm&UINT64_C(0x100));}
/* Hardware writes, replaceable for host tests. */
#ifndef NATIVE_WRITE_TTBR0
#define NATIVE_WRITE_TTBR0(v) __asm__ volatile("msr ttbr0_el1, %0; isb" :: "r"(v) : "memory")
#endif
#ifndef NATIVE_WRITE_TTBR1
#define NATIVE_WRITE_TTBR1(v) __asm__ volatile("msr ttbr1_el1, %0; isb" :: "r"(v) : "memory")
#endif
static inline int native_apply(struct native_cpu *n,int el0)
{
    n->selects++;
    unsigned w=native_variant_w(n->uperm,n->pperm,el0),k=native_variant_k(n->pperm);
    n->el0=(uint32_t)!!el0;
    if(!n->installed)return 1;
    uint64_t t0=n->ttbr0[w][k];
    if(!t0) {n->errors++;return 0;}
    if(w==n->w && k==n->k)return 1;
    if(k!=n->k && n->ttbr1[k])NATIVE_WRITE_TTBR1(n->ttbr1[k]);
    NATIVE_WRITE_TTBR0(t0);
    n->w=w;n->k=k;n->flips++;return 1;
}
static inline int native_select(struct native_cpu *n,int el0)
{return native_apply(n,el0);}
static inline int native_set_uperm(struct native_cpu *n,uint64_t uperm,int el0)
{n->uperm=uperm;return native_apply(n,el0);}
static inline int native_set_pperm(struct native_cpu *n,uint64_t pperm,int el0)
{n->pperm=pperm;return native_apply(n,el0);}
/* SWITCH_ROOT: load an address space's variants for the reset SPRR state
 * (el0: the regime the switch returns to) and return the TTBR0 value the
 * caller's own installation sequence writes (it owns the barriers and any
 * flush); 0 refuses, leaving the CPU uninstalled. The caller also writes
 * ttbr1[k] when that is nonzero. ttbr0 values of unused kernel variants may
 * repeat k=0's until phase 2. Loading is not a flip. */
static inline uint64_t native_install(struct native_cpu *n,const uint64_t ttbr0[2][2],
    const uint64_t ttbr1[2],uint64_t uperm,uint64_t pperm,int el0)
{
    for(unsigned w=0;w<2;w++)for(unsigned k=0;k<2;k++)n->ttbr0[w][k]=ttbr0[w][k];
    n->ttbr1[0]=ttbr1 ? ttbr1[0] : 0;n->ttbr1[1]=ttbr1 ? ttbr1[1] : 0;
    n->uperm=uperm;n->pperm=pperm;n->el0=(uint32_t)!!el0;
    n->w=native_variant_w(uperm,pperm,el0);n->k=native_variant_k(pperm);
    uint64_t t0=n->ttbr0[n->w][n->k];
    n->installed=t0!=0;
    if(!t0)n->errors++;
    return t0;
}
/* A switch to the kernel root, or a CPU leaving native mode. */
static inline void native_uninstall(struct native_cpu *n)
{n->installed=0;n->w=0;n->k=0;}
