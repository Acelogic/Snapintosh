/* SPDX-License-Identifier: MIT */
#include "sptm-papt.h"
#include "sptm-access.h"
#include "sprr.h"
#include "../shadow/mmu.h"
/* 8-byte fields: one single-copy-atomic access (compat/sptm-access.h, v67). */
static uint64_t get(volatile uint8_t *p) {return sptm_get64(p);}
static void put(volatile uint8_t *p,uint64_t x) {sptm_put64(p,x);}
/* One aperture leaf of pa at va: its 16K guest descriptor and four 4K shadow
 * descriptors, all holding old_selector. after replaces the clear bits with
 * set. Reads only. */
static enum sptm_result prepare_leaf(const struct sptm_memory *m,
    const struct sptm_update_backend *b,uint64_t va,uint64_t pa,
    unsigned old_selector,uint64_t clear,uint64_t set,struct sptm_papt_leaf *t)
{
    if(!va || (va&0x3fff) || va<0xffff800000000000UL)return SPTM_BAD_ADDRESS;
    uint64_t table=b->kernel_root,path[4];
    for(unsigned level=1;level<=3;level++) {
        for(unsigned n=1;n<level;n++)if(path[n]==table)return SPTM_BAD_TABLE;
        path[level]=table;
        volatile uint8_t *page=m->map(m->ctx,table,0x4000);
        if(!page)return SPTM_MEMORY_UNAVAILABLE;
        uint64_t off=8UL*mmu_index(14,level,va),d=get(page+off);
        if(level==3) {
            if((d&3)!=3 || (d&0x0000ffffffffc000UL)!=pa ||
               sprr_pte_class(d)!=old_selector)return SPTM_BAD_TABLE;
            t->va=va;t->guest_pa=table+off;t->guest=page+off;t->before=d;
            t->after=(d&~clear)|set;
        } else {
            if((d&~0x0000ffffffffc000UL)!=3)return SPTM_BAD_TABLE;
            table=d&0x0000ffffffffc000UL;
        }
    }
    if(b->admit && !b->admit(b->ctx,va&((1UL<<47)-1),pa,0x4000,
            t->after&PT_LEAF_ATTRS,t->after&PT_LEAF_UPPER))return SPTM_SHADOW_FAILED;
    for(unsigned n=0;n<4;n++) {
        table=b->shadow_root;
        for(unsigned level=0;level<4;level++) {
            for(unsigned j=0;j<level;j++)if(path[j]==table)return SPTM_BAD_TABLE;
            path[level]=table;
            volatile uint8_t *page=b->map_shadow(b->ctx,table,4096);
            if(!page)return SPTM_SHADOW_FAILED;
            uint64_t address=(va+n*4096)&((1UL<<47)-1);
            uint64_t off=8UL*mmu_index(12,level,address),d=get(page+off);
            if(level==3) {
                uint64_t expected=pa+n*4096;
                expected|=3|(t->before&(PT_LEAF_ATTRS|PT_LEAF_UPPER));
                if(d!=expected)return SPTM_SHADOW_FAILED;
                t->shadow[n]=page+off;
            } else {
                if((d&~PT_OA_MASK)!=3)return SPTM_SHADOW_FAILED;
                table=d&PT_OA_MASK;
            }
        }
    }
    return SPTM_OK;
}
static int configured(const struct sptm_memory *m,const struct sptm_update_backend *b,
    const struct sptm_aperture *a,const struct sptm_papt_change *t)
{
    return m && m->map && m->publish && b && b->map_shadow && a && t &&
        b->kernel_root && !(b->kernel_root&0x3fff) && b->shadow_root && !(b->shadow_root&4095);
}
/* Both aliases of pa (linear, then the moved one when distinct). */
static enum sptm_result prepare_change(const struct sptm_memory *m,
    const struct sptm_update_backend *b,const struct sptm_aperture *a,
    const struct sptm_moved *moved,uint64_t pa,unsigned old_selector,
    uint64_t clear,uint64_t set,struct sptm_papt_change *t)
{
    uint64_t va=sptm_aperture_pointer(a,pa,0x4000);
    /* XNU's phystokv and Apple's aperture updater both use the moved alias
     * of a SLIDE_REGION frame; otherwise this is the linear pointer again. */
    uint64_t alias=sptm_published_pointer(a,moved,pa,0x4000);
    if((pa&0x3fff) || !va || !alias || !sptm_managed_frame(m,pa))return SPTM_BAD_ADDRESS;
    t->count=alias==va ? 1 : 2;
    for(unsigned i=0;i<t->count;i++) {
        enum sptm_result r=prepare_leaf(m,b,i ? alias : va,pa,old_selector,
                                        clear,set,&t->leaf[i]);
        if(r)return r;
    }
    /* Two aliases must never share a descriptor, or commit would compose. */
    if(t->count==2) {
        if(t->leaf[0].guest==t->leaf[1].guest)return SPTM_BAD_TABLE;
        for(unsigned x=0;x<4;x++)for(unsigned y=0;y<4;y++)
            if(t->leaf[0].shadow[x]==t->leaf[1].shadow[y])return SPTM_SHADOW_FAILED;
    }
    return SPTM_OK;
}
enum sptm_result sptm_papt_prepare(const struct sptm_memory *m,
    const struct sptm_update_backend *b,const struct sptm_aperture *a,
    const struct sptm_moved *moved,uint64_t pa,uint64_t old_type,uint64_t new_type,
    struct sptm_papt_change *t)
{
    if(!configured(m,b,a,t))return SPTM_BAD_CONFIG;
    if(!((old_type==SPTM_MAC_DEFAULT && (new_type==SPTM_MAC_ROZONE ||
           new_type==SPTM_MAC_USER_EXEC || new_type==SPTM_MAC_USER_TPRO ||
           new_type==SPTM_MAC_TXM_DEFAULT)) ||
         ((old_type==SPTM_MAC_ROZONE || old_type==SPTM_MAC_USER_EXEC ||
           old_type==SPTM_MAC_USER_TPRO) && new_type==SPTM_MAC_DEFAULT) ||
         (old_type==SPTM_MAC_TXM_DEFAULT && new_type==SPTM_MAC_TXM_OWNED) ||
         (old_type==SPTM_MAC_TXM_OWNED && new_type==SPTM_MAC_DEFAULT)))
        return SPTM_UNSUPPORTED_RETYPE;
    /* Exact selected SPTM startup replay resolves DEFAULT and USER_TPRO to
     * aperture selector3. The user mapping's selector9 is a separate policy.
     * See tools/replay-sptm-aperture.py, including its negative ACL control. */
    unsigned old_selector=old_type==SPTM_MAC_ROZONE ? 2 :
                          (old_type==SPTM_MAC_USER_EXEC || old_type==SPTM_MAC_TXM_OWNED) ? 11 :
                          old_type==SPTM_MAC_TXM_DEFAULT ? 4 : 3;
    unsigned new_selector=new_type==SPTM_MAC_ROZONE ? 2 :
                          (new_type==SPTM_MAC_USER_EXEC || new_type==SPTM_MAC_TXM_OWNED) ? 11 :
                          new_type==SPTM_MAC_TXM_DEFAULT ? 4 : 3;
    return prepare_change(m,b,a,moved,pa,old_selector,PT_AP|PT_PXN|PT_UXN,
        ((uint64_t)(new_selector&12)<<4)|((uint64_t)(new_selector&3)<<53),t);
}
enum sptm_result sptm_papt_prepare_attr(const struct sptm_memory *m,
    const struct sptm_update_backend *b,const struct sptm_aperture *a,
    const struct sptm_moved *moved,uint64_t pa,unsigned attr,
    struct sptm_papt_change *t)
{
    if(!configured(m,b,a,t) || (m->frame_map_pa&15))return SPTM_BAD_CONFIG;
    if(attr>7)return SPTM_UNSUPPORTED_OPTIONS;                    /* ...dfd64 */
    if(!sptm_managed_frame(m,pa))return SPTM_BAD_ADDRESS;
    uint64_t index=(pa-m->frame_low)>>14;
    if(index>(UINT64_MAX-m->frame_map_pa-15)/16)return SPTM_BAD_CONFIG;
    volatile uint8_t *fm=m->map(m->ctx,m->frame_map_pa+index*16,16);
    if(!fm)return SPTM_MEMORY_UNAVAILABLE;
    if(fm[0] || fm[1])return SPTM_FRAME_BUSY;
    /* DEFAULT's aperture is selector3 (see sptm_papt_prepare); other types'
     * attribute contracts are not modeled. SH and permissions are kept. */
    if(fm[2]!=SPTM_MAC_DEFAULT)return SPTM_TYPE_MISMATCH;
    return prepare_change(m,b,a,moved,pa,3,PT_ATTRINDX,(uint64_t)attr<<2,t);
}
void sptm_papt_commit(const struct sptm_memory *m,const struct sptm_papt_change *t)
{
    for(unsigned i=0;i<t->count && i<2;i++) {
        const struct sptm_papt_leaf *l=&t->leaf[i];
        for(unsigned n=0;n<4;n++) {
            uint64_t d=get(l->shadow[n]),mask=PT_LEAF_ATTRS|PT_LEAF_UPPER;
            put(l->shadow[n],(d&~mask)|(l->after&mask));
        }
        put(l->guest,l->after);m->publish(m->ctx,l->guest_pa,8);
    }
}
