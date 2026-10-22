/* SPDX-License-Identifier: MIT */
#include "txm.h"
#include "sptm-access.h"
#include "../shadow/mmu.h"
#include "sprr.h"

static int table_read(void *ctx,uint64_t pa,uint64_t *out)
{
    const struct sptm_memory *m=ctx;
    if(pa&7)return -1;
    volatile uint8_t *p=m->map(m->ctx,pa,8);
    if(!p)return -1;
    uint64_t word=sptm_get64(p);       /* a live kernel descriptor: one load (compat/sptm-access.h) */
    /* Bits 13:12 cannot be output-address bits in this 16K regime. */
    if((word&PT_VALID) && (word&0x3000))return -1;
    *out=word;
    return 0;
}

int txm_resolve_kernel_page(void *ctx,uint64_t va,uint64_t size,uint64_t *pa)
{
    const struct txm_kernel_memory *g=ctx;
    if(!g || !g->memory || !g->memory->map || !pa || !size || size>0x4000 || (va&0x3fff) ||
       (g->root&0x3fff) || (g->root&~PT_OA_MASK) || !g->root ||
       ((g->tcr>>30)&3)!=1 || ((g->tcr>>16)&0x3f)!=17 ||
       (g->tcr&(1UL<<23)) || va<0xffff800000000000UL || va>UINT64_MAX-size)return 0;
    struct mmu_config cfg={14,17,g->root};struct mmu_leaf leaf;
    if(mmu_walk(&cfg,va,table_read,(void *)g->memory,&leaf)<0 || !leaf.valid ||
       leaf.level!=3 || !(leaf.descriptor&PT_AF) || (leaf.pa&0x3fff) ||
       (sprr_pte_class(leaf.descriptor)!=11 && sprr_pte_class(leaf.descriptor)!=4) ||
       !g->memory->map(g->memory->ctx,leaf.pa,0x4000))return 0;
    *pa=leaf.pa;return 1;
}

int txm_copy_kernel_input(void *ctx,uint64_t va,uint8_t *out,uint64_t size)
{
    const struct txm_kernel_memory *g=ctx;
    if(!g || !g->memory || !g->memory->map || !out || !size || size>TXM_LOCAL_KEY_BYTES ||
       (g->root&0x3fff) || (g->root&~PT_OA_MASK) || !g->root ||
       ((g->tcr>>30)&3)!=1 || ((g->tcr>>16)&0x3f)!=17 ||
       (g->tcr&(1UL<<23)) || va<0xffff800000000000UL || va>UINT64_MAX-size)
        return 0;
    struct mmu_config cfg={14,17,g->root};
    uint8_t temporary[TXM_LOCAL_KEY_BYTES];
    uint64_t done=0;
    int ok=1;
    while(done<size) {
        struct mmu_leaf leaf;
        if(mmu_walk(&cfg,va+done,table_read,(void *)g->memory,&leaf)<0 ||
           !leaf.valid || !(leaf.descriptor&PT_AF)) {ok=0;break;}
        uint64_t chunk=0x4000-((va+done)&0x3fff);
        if(chunk>size-done)chunk=size-done;
        volatile uint8_t *p=g->memory->map(g->memory->ctx,leaf.pa,chunk);
        if(!p) {ok=0;break;}
        for(uint64_t i=0;i<chunk;i++)temporary[done+i]=p[i];
        done+=chunk;
    }
    if(ok)for(uint64_t i=0;i<size;i++)out[i]=temporary[i];
    for(unsigned i=0;i<sizeof(temporary);i++)((volatile uint8_t *)temporary)[i]=0;
    return ok;
}
