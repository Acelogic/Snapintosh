/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>
#include "../shadow/mmu.h"

/* Observation of a kmutil-linked AuxKC's kernel mappings. Counters only:
 * nothing here refuses, delays or alters an SPTM call.
 *
 * The loader maps the collection itself (executable segments RX, the rest
 * PXN|UXN) and XNU's arm_auxkc_init slides it in place. Real SPTM/TXM may
 * make kext text executable through MAP_PAGE, UPDATE_REGION/DISJOINT or a
 * RETYPE of its frames; this model applies no CDHash check there, so every
 * such call is counted and the first few execute transitions are logged.
 *
 * EL1 execute is PXN clear on a valid leaf. The kernel shadow passes Apple's
 * AP/PXN/UXN through as Arm permissions for every class but the translated
 * selector 2/9 pages (shadow/sprr-view.c), neither of which is executable.
 * "Gained" means the leaf it replaced did not already allow it.
 *
 * tools/auxkc_counters.py decodes auxkc_exec_state word by word, in this
 * field order; tools/test-auxkc-observe.c pins the layout. */
struct auxkc_range {
    uint64_t va_base, va_end, pa_base, pa_end;   /* [base, end); zero = none */
};
struct auxkc_exec_state {
    uint64_t map_pages, map_exec_gained;          /* MAP_PAGE leaves in the VA range */
    uint64_t update_entries, update_exec_gained;  /* UPDATE_REGION/DISJOINT leaves */
    uint64_t retypes, retype_failed;              /* RETYPE of its physical frames */
    uint64_t last_kind, last_va, last_old, last_new, last_elr;
    uint64_t last_retype_pa, last_retype_types;   /* old << 32 | new */
};
#define AUXKC_KIND_MAP 1u
#define AUXKC_KIND_UPDATE 2u
#define AUXKC_EXEC_LOGGED 8u

static inline int auxkc_el1_exec(uint64_t pte) {return (pte&3)==3 && !(pte&PT_PXN);}

static inline void auxkc_count(uint64_t *n, uint64_t by) {if(*n<=UINT64_MAX-by)*n+=by;}

/* 1 when the caller should record the transition in its event log. */
static inline int auxkc_observe_leaf(struct auxkc_exec_state *s,const struct auxkc_range *r,
    unsigned kind,uint64_t elr,uint64_t va,uint64_t old,uint64_t next)
{
    if(!r->va_end || va<r->va_base || va>=r->va_end)return 0;
    int gained=auxkc_el1_exec(next) && !auxkc_el1_exec(old);
    if(kind==AUXKC_KIND_MAP) {auxkc_count(&s->map_pages,1);auxkc_count(&s->map_exec_gained,(uint64_t)gained);}
    else {auxkc_count(&s->update_entries,1);auxkc_count(&s->update_exec_gained,(uint64_t)gained);}
    if(!gained)return 0;
    s->last_kind=kind;s->last_va=va;s->last_old=old;s->last_new=next;s->last_elr=elr;
    return s->map_exec_gained+s->update_exec_gained<=AUXKC_EXEC_LOGGED;
}

/* Whether a VA run [va, va + pages*16K) may touch the range at all: the
 * UPDATE_REGION hot path skips its per-entry walk otherwise. */
static inline int auxkc_overlaps(const struct auxkc_range *r,uint64_t va,uint64_t pages)
{
    return r->va_end && pages && va<r->va_end && pages<=(UINT64_MAX-va)/0x4000 &&
           va+pages*0x4000>r->va_base;
}

/* Count a RETYPE of an AuxKC frame; returns whether pa is one. */
static inline int auxkc_observe_retype(struct auxkc_exec_state *s,const struct auxkc_range *r,
    uint64_t pa,uint64_t old_type,uint64_t new_type)
{
    if(!r->pa_end || pa<r->pa_base || pa>=r->pa_end)return 0;
    auxkc_count(&s->retypes,1);
    s->last_retype_pa=pa;
    s->last_retype_types=(old_type<<32)|(new_type&0xffffffffu);
    return 1;
}
