/* SPDX-License-Identifier: MIT */
#include "sptm.h"
#include "sptm-access.h"
#include "sptm-refs.h"
#include "sptm-user.h"
#include "../shadow/shadow.h"

/* 8-byte fields: one single-copy-atomic access (compat/sptm-access.h, v67). */
static uint64_t get64(volatile uint8_t *p) {return sptm_get64(p);}
static void put64(volatile uint8_t *p,uint64_t v) {sptm_put64(p,v);}
static enum sptm_result find_slot(const struct sptm_memory *m,uint64_t root,
    uint64_t va,volatile uint8_t **out,uint64_t *slot_pa)
{
    uint64_t parent=root; *out=0; *slot_pa=0;
    for (unsigned level=1;level<=3;level++) {
        if (parent & 0x3fff) return SPTM_BAD_TABLE;
        volatile uint8_t *page=m->map(m->ctx,parent,0x4000);
        if (!page) return SPTM_MEMORY_UNAVAILABLE;
        uint64_t offset=mmu_index(14,level,va)*8UL;
        if (level==3) { *out=page+offset; *slot_pa=parent+offset; return SPTM_OK; }
        uint64_t desc=get64(page+offset);
        if (!desc) return SPTM_OK; /* no mapping at this level */
        if ((desc&3)!=3) return SPTM_BAD_TABLE;
        parent=desc & 0x0000ffffffffc000UL;
    }
    return SPTM_BAD_TABLE;
}

#define PAGE_MASK 0x0000ffffffffc000UL
struct kernel_unmap_entry {
    uint64_t root,va,requested,pa,old,next,remove;
    volatile uint8_t *slot;
};
static enum sptm_result kernel_unmap_slot(const struct sptm_memory *m,
    struct kernel_unmap_entry *e,uint64_t scratch)
{
    uint64_t table=e->root,path[3];
    for(unsigned level=1;level<=3;level++) {
        for(unsigned j=0;j<level-1;j++)if(path[j]==table)return SPTM_BAD_TABLE;
        path[level-1]=table;
        if((table&0x3fff) || table==scratch)return SPTM_BAD_TABLE;
        volatile uint8_t *page=m->map(m->ctx,table,0x4000);
        if(!page)return SPTM_MEMORY_UNAVAILABLE;
        uint64_t off=mmu_index(14,level,e->va)*8UL,desc=get64(page+off);
        if(level==3) {
            e->slot=page+off;e->pa=table+off;e->old=e->next=desc;return SPTM_OK;
        }
        if(!desc)return SPTM_OK;
        if((desc&~PAGE_MASK)!=3)return SPTM_BAD_TABLE;
        table=desc&PAGE_MASK;
    }
    return SPTM_BAD_TABLE;
}
static void kernel_unmap_witness(struct sptm_user_update_state *s,
    const struct kernel_unmap_entry *e,uint64_t target,uint64_t count,uint64_t changed)
{
    s->calls++;s->entries+=count;s->changed+=changed;s->options=s->result=0;
    s->target=target;s->count=count;s->root=e->root;s->va=e->va;s->slot=e->pa;
    s->old=e->old;s->next=e->next;s->shift=14;s->flags=0;
    s->last_changed=e->remove;s->requested=e->requested;
}

#if SNAP_UNMAP_MIXED
/* A mixed endpoint8 list's kernel record (compat/sptm-user.h SNAP_UNMAP_MIXED):
 * the steps sptm_mac_unmap_kernel_disjoint takes for each record, for the
 * mixed engine to run inside its own reference batch. */
enum sptm_result sptm_kernel_unmap_slot(const struct sptm_memory *m,uint64_t root,
    uint64_t va,uint64_t scratch,volatile uint8_t **slot,uint64_t *slot_pa,uint64_t *old)
{
    struct kernel_unmap_entry e={.root=root,.va=va};
    enum sptm_result r=kernel_unmap_slot(m,&e,scratch);
    *slot=e.slot;*slot_pa=e.pa;*old=e.old;return r;
}
enum sptm_result sptm_kernel_unmap_check(struct shadow *s,uint64_t va,uint64_t target,uint64_t old)
{
    struct mmu_config cfg={.granule_shift=12,.txsz=17,.root=s->root};
    uint64_t low=va&((1UL<<47)-1);
    /* Check all four shadow descriptors before removing the source. */
    for(unsigned j=0;j<4;j++) {
        struct mmu_leaf leaf;
        uint64_t expected=(target+j*0x1000)|(old&(PT_LEAF_ATTRS|PT_LEAF_UPPER))|3;
        if(mmu_walk(&cfg,low+j*0x1000,s->read,s->ctx,&leaf) ||
           !leaf.valid || leaf.level!=3 || leaf.descriptor!=expected)
            return SPTM_SHADOW_FAILED;
    }
    return shadow_unmap(s,low,0x4000,1) ? SPTM_SHADOW_FAILED:SPTM_OK;
}
int sptm_kernel_unmap_commit(struct shadow *s,uint64_t va)
{return !shadow_unmap(s,va&((1UL<<47)-1),0x4000,0);}
#endif

/* Endpoint8 fixes options to zero. Keep kernel geometry separate from user
 * ownership. Caller must refresh all CPU kernel views before returning to XNU
 * and allowing the next TXM transfer. Full-batch preflight precedes mutation. */
enum sptm_result sptm_mac_unmap_kernel_disjoint(const struct sptm_memory *m,
    struct shadow *s,uint64_t root,uint64_t target,uint64_t list,uint64_t count,
    uint64_t scratch,struct sptm_shared_update_state *state)
{
    if(!m || !m->map || !m->publish || !m->refs || !s || !s->read || !s->write ||
       s->txsz!=17 || (s->root&0xfff) || !sptm_boot_memory_valid(m))return SPTM_BAD_CONFIG;
    if(((m->frame_low|m->frame_high|m->alloc_low|m->alloc_high)&0x3fff) ||
       (m->frame_map_pa&15) || m->frame_low>=m->frame_high ||
       m->alloc_low>=m->alloc_high || m->alloc_low<m->frame_low ||
       m->alloc_high>m->frame_high)return SPTM_BAD_CONFIG;
    uint64_t map_size=((m->frame_high-m->frame_low)>>14)*16;
    if(map_size>UINT64_MAX-m->frame_map_pa ||
       (m->frame_map_pa<m->alloc_high && m->frame_map_pa+map_size>m->alloc_low))
        return SPTM_BAD_CONFIG;
    count=(uint32_t)count;
    if(!count || count>64 || ((root|target|scratch)&0x3fff) || (list&7) ||
       !sptm_managed_frame(m,target) || list<m->frame_low || list>=m->frame_high ||
       count*24>m->frame_high-list || (list&0x3fff)+count*24>0x4000 ||
       scratch>UINT64_MAX-2048)return SPTM_BAD_ADDRESS;
    uint64_t bytes=512+count*24;
    if(sptm_managed_frame(m,scratch) || scratch==(list&~0x3fffUL) ||
       (scratch<m->frame_map_pa+map_size && scratch+bytes>m->frame_map_pa))
        return SPTM_BAD_ADDRESS;
    volatile uint8_t *data=m->map(m->ctx,
        m->frame_map_pa+((target-m->frame_low)>>14)*16,16);
    volatile uint8_t *im=m->map(m->ctx,
        m->frame_map_pa+((list-m->frame_low)>>14)*16,16);
    if(!data || !im)return SPTM_MEMORY_UNAVAILABLE;
    unsigned lock=(unsigned)im[0]|((unsigned)im[1]<<8);
    if(data[0] || data[1] || (lock&1) || lock>0xfff1)return SPTM_FRAME_BUSY;
    if(data[2]!=SPTM_MAC_DEFAULT && data[2]!=SPTM_MAC_USER_EXEC &&
       data[2]!=SPTM_MAC_USER_TPRO)return SPTM_TYPE_MISMATCH;
    if(im[2]!=SPTM_MAC_DEFAULT && im[2]!=SPTM_MAC_KERNEL_RESTRICTED)
        return SPTM_TYPE_MISMATCH;
    volatile uint8_t *input=m->map(m->ctx,list,count*24),*out=m->map(m->ctx,scratch,bytes);
    if(!input || !out)return SPTM_MEMORY_UNAVAILABLE;
    struct kernel_unmap_entry plan[64]={0};
    for(uint64_t i=0;i<count;i++) {
        plan[i].root=get64(input+i*24);plan[i].va=get64(input+i*24+8);
        plan[i].requested=get64(input+i*24+16);
        if(plan[i].root!=root || plan[i].va<0xffff800000000000UL || (plan[i].va&0x3fff))
            return SPTM_BAD_ADDRESS; /* mixed kernel/user batches are not qualified */
    }
    uint64_t changed=0,last_changed=0;sptm_refs_begin(m->refs);
    struct mmu_config cfg={.granule_shift=12,.txsz=17,.root=s->root};
    for(uint64_t i=0;i<count;i++) {
        struct kernel_unmap_entry *e=&plan[i];
        enum sptm_result r=kernel_unmap_slot(m,e,scratch);if(r)return r;
        for(uint64_t j=0;j<i;j++)if(e->slot && e->slot==plan[j].slot) {
            if(e->va!=plan[j].va)return SPTM_BAD_TABLE;
            if(plan[j].remove)e->old=e->next=plan[j].next|0x80;
        }
        if((e->old&3)!=3 || (e->old&PAGE_MASK)!=target)continue;
        e->next=e->requested&0xe000000000000000UL;
        /* Check all four shadow descriptors before removing the source. */
        uint64_t va=e->va&((1UL<<47)-1);
        for(unsigned j=0;j<4;j++) {
            struct mmu_leaf leaf;
            uint64_t expected=(target+j*0x1000)|(e->old&(PT_LEAF_ATTRS|PT_LEAF_UPPER))|3;
            if(mmu_walk(&cfg,va+j*0x1000,s->read,s->ctx,&leaf) ||
               !leaf.valid || leaf.level!=3 || leaf.descriptor!=expected)
                return SPTM_SHADOW_FAILED;
        }
        if(shadow_unmap(s,va,0x4000,1))return SPTM_SHADOW_FAILED;
        r=sptm_refs_leaf(m,e->pa&PAGE_MASK,e->va,e->old,e->next);if(r)return r;
        e->remove=1;changed++;last_changed=i;
    }
    enum sptm_result r=sptm_refs_validate(m);if(r)return r;
    for(uint64_t i=0;i<count;i++)if(plan[i].remove) {
        struct kernel_unmap_entry *e=&plan[i];
        if(shadow_unmap(s,e->va&((1UL<<47)-1),0x4000,0))return SPTM_SHADOW_FAILED;
        put64(e->slot,e->next);m->publish(m->ctx,e->pa,8);
    }
    sptm_refs_commit(m);
    for(uint64_t i=0;i<count;i++) {
        put64(out+i*8,plan[i].old);put64(out+512+i*24,plan[i].root);
        put64(out+520+i*24,plan[i].va);put64(out+528+i*24,plan[i].requested);
    }
    m->publish(m->ctx,scratch,bytes);
    for(uint64_t i=0;i<count;i++)for(uint64_t j=0;j<i;j++)
        if(plan[i].va==plan[j].va) {sptm_audit_duplicate(m->audit,root,plan[i].va);break;}
    if(state) {
        kernel_unmap_witness(&state->latest,&plan[count-1],target,count,changed);
        if(changed)kernel_unmap_witness(&state->changed,&plan[last_changed],target,count,changed);
    }
    return SPTM_OK;
}

enum sptm_result sptm_mac_unmap_region(const struct sptm_memory *m,struct shadow *s,
    uint64_t root,uint64_t va,uint64_t count,uint64_t options,uint64_t scratch)
{
    if (!m || !m->map || !m->publish || !s || s->txsz!=17 || (root&0x3fff) ||
        (va&0x3fff) || va<0xffff800000000000UL || !count || count>2048 ||
        count>(UINT64_MAX-va)/0x4000 || (scratch&7)) return SPTM_BAD_ADDRESS;
    /* In the audited mac17p monitor, bit 0 also removes compressed entries.
     * It does not change removal of valid leaves or empty slots, which are
     * the two descriptor classes implemented here. Compressed descriptors
     * still fail preflight. Unlike older monitors, this endpoint's callback
     * explicitly rejects 0x100 (and 0x400); do not inherit that older ABI.
     * Evidence: SPTM 0xfffffff0270fd244, option tests at +0x7c and +0xc4. */
    if (options & ~1UL) return SPTM_UNSUPPORTED_OPTIONS;
    volatile uint8_t *previous=m->map(m->ctx,scratch,count*8);
    if (!previous) return SPTM_MEMORY_UNAVAILABLE;
    if (!m->refs) return SPTM_BAD_CONFIG;
    sptm_refs_begin(m->refs);
    uint64_t off=va&((1UL<<47)-1);
    if (shadow_unmap(s,off,count*0x4000,1)) return SPTM_SHADOW_FAILED;
    /* Preflight the entire batch. No partial guest table changes on malformed
     * descriptors or inaccessible tables; previous-PTE output is also exact. */
    for (uint64_t n=0;n<count;n++) {
        volatile uint8_t *slot; uint64_t pa;
        enum sptm_result r=find_slot(m,root,va+n*0x4000,&slot,&pa);
        if (r) return r;
        if (slot && get64(slot) && (get64(slot)&3)!=3) return SPTM_BAD_TABLE;
        if (slot) {
            r=sptm_refs_leaf(m,pa&~0x3fffUL,va+n*0x4000,get64(slot),0);
            if (r) return r;
        }
    }
    enum sptm_result refs_result=sptm_refs_validate(m);
    if (refs_result) return refs_result;
    if (shadow_unmap(s,off,count*0x4000,0)) return SPTM_SHADOW_FAILED;
    for (uint64_t n=0;n<count;n++) {
        volatile uint8_t *slot; uint64_t pa;
        enum sptm_result r=find_slot(m,root,va+n*0x4000,&slot,&pa);
        if (r) return r;
        put64(previous+n*8,slot ? get64(slot) : 0);
        if (slot) { put64(slot,0); m->publish(m->ctx,pa,8); }
    }
    m->publish(m->ctx,scratch,count*8);
    sptm_refs_commit(m);
    return SPTM_OK;
}
