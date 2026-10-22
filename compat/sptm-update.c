/* SPDX-License-Identifier: MIT */
#include "sptm.h"
#include "sptm-access.h"
#include "sptm-refs.h"
#include "sptm-nx-update.h"
#include "../shadow/mmu.h"

#define PAGE_MASK 0x0000ffffffffc000UL
/* FD818..FD840 selects AP, PXN/UXN and software bits 51/59. */
#define PERMISSIONS 0x08680000000000c0UL

/* 8-byte fields: one single-copy-atomic access (compat/sptm-access.h, v67). */
static uint64_t get64(volatile uint8_t *p) {return sptm_get64(p);}
static void put64(volatile uint8_t *p,uint64_t v) {sptm_put64(p,v);}
static int overlaps(uint64_t a,uint64_t an,uint64_t b,uint64_t bn)
{
    return a<=b ? b-a<an : a-b<bn;
}
static enum sptm_result guest_slot(const struct sptm_memory *m,uint64_t root,
    uint64_t va,uint64_t scratch,uint64_t size,struct sptm_update_entry *e)
{
    e->guest=0; e->slot_pa=0; e->old=0; e->next=0;
    uint64_t table=root,path[3];
    for (unsigned level=1;level<=3;level++) {
        for (unsigned j=0;j<level-1;j++) if (path[j]==table) return SPTM_BAD_TABLE;
        path[level-1]=table;
        if ((table&0x3fff) || overlaps(table,0x4000,scratch,size))
            return SPTM_BAD_TABLE;
        volatile uint8_t *page=m->map(m->ctx,table,0x4000);
        if (!page) return SPTM_MEMORY_UNAVAILABLE;
        uint64_t offset=mmu_index(14,level,va)*8UL;
        uint64_t desc=get64(page+offset);
        if (level==3) {
            e->guest=page+offset; e->slot_pa=table+offset;
            e->old=e->next=desc; return SPTM_OK;
        }
        if (!desc) return SPTM_OK;
        if ((desc&~PAGE_MASK)!=3) return SPTM_BAD_TABLE;
        table=desc&PAGE_MASK;
    }
    return SPTM_BAD_TABLE;
}
static int shadow_slots(const struct sptm_update_backend *b,uint64_t va,
                         struct sptm_update_entry *e)
{
    for (unsigned n=0;n<4;n++) {
        uint64_t table=b->shadow_root, at=(va&((1UL<<47)-1))+n*0x1000;
        uint64_t path[4];
        for (unsigned level=0;level<=3;level++) {
            for (unsigned j=0;j<level;j++) if (path[j]==table) return 0;
            path[level]=table;
            volatile uint8_t *page=b->map_shadow(b->ctx,table,0x1000);
            if (!page) return 0;
            volatile uint8_t *slot=page+mmu_index(12,level,at)*8UL;
            uint64_t desc=get64(slot);
            if (level==3) {
                uint64_t expected=(e->old&PAGE_MASK)+n*0x1000;
                expected|=(e->old&(PT_LEAF_ATTRS|PT_LEAF_UPPER))|3;
                if (desc!=expected) return 0;
                e->shadow[n]=slot;
            } else {
                if ((desc&~PT_OA_MASK)!=3) return 0;
                table=desc&PT_OA_MASK;
            }
        }
    }
    return 1;
}

static enum sptm_result update_entry(const struct sptm_memory *m,
    const struct sptm_update_backend *b,uint64_t va,uint64_t requested,
    uint64_t options,struct sptm_update_entry *e)
{
    /* Existing executable mappings may clear AF/WIRED without changing their
     * permission selector; permission changes are restricted to kernel NX. */
    uint64_t select=options;
    if(!((e->old^requested)&PERMISSIONS))select&=~2UL;
    enum sptm_result r;
    if(select&SPTM_UPDATE_SELECT) {
        r=sptm_nx_update_pte(e->old,requested,select,&e->next,0);
        if(r)return r;
    }
    /* A new SH/AttrIndx reaches the four shadow leaves unchanged (commit);
     * the frame is cleaned before that. Only managed frames qualify. */
    if (((e->old^e->next)&SPTM_UPDATE_ATTRS) &&
        (!m->clean_frame || !sptm_managed_frame(m,e->old&PAGE_MASK)))
        return SPTM_UNSUPPORTED_OPTIONS;
    if (b->admit && !b->admit(b->ctx,va&((1UL<<47)-1),e->next&PAGE_MASK,
            0x4000,e->next&PT_LEAF_ATTRS,e->next&PT_LEAF_UPPER))
        return SPTM_SHADOW_FAILED;
    if ((e->old^e->next)&PERMISSIONS) {
        uint64_t pa=e->old&PAGE_MASK;
        if (!sptm_managed_frame(m,pa) ||
            !sptm_managed_frame(m,e->slot_pa&PAGE_MASK)) return SPTM_BAD_ADDRESS;
        r=sptm_refs_leaf(m,e->slot_pa&PAGE_MASK,va,e->old,e->next);
        if (r) return r;
    }
    return shadow_slots(b,va,e) ? SPTM_OK : SPTM_SHADOW_FAILED;
}
enum sptm_result sptm_kernel_update_prepare(const struct sptm_memory *m,
    const struct sptm_update_backend *b,uint64_t target,uint64_t va,
    uint64_t requested,uint64_t options,uint64_t scratch,uint64_t scratch_bytes,
    struct sptm_update_entry *e)
{
    if(!m || !m->map || !m->publish || !m->refs || !b || !b->map_shadow || !e ||
       !sptm_boot_memory_valid(m) || (b->kernel_root&0x3fff) || (b->shadow_root&0xfff))
        return SPTM_BAD_CONFIG;
    if((target&0x3fff) || !sptm_managed_frame(m,target) ||
       target<m->frame_low || target>=m->frame_high ||
       va<0xffff800000000000UL || (va&0x3fff) || (scratch&7) ||
       !scratch_bytes || scratch_bytes>SPTM_DISJOINT_MAX*8 ||
       scratch>UINT64_MAX-scratch_bytes)return SPTM_BAD_ADDRESS;
    if(!sptm_update_options_valid(options))return SPTM_UNSUPPORTED_OPTIONS;
    uint64_t index=(target-m->frame_low)>>14;
    if((m->frame_map_pa&15) || index>(UINT64_MAX-m->frame_map_pa-15)/16)
        return SPTM_BAD_CONFIG;
    volatile uint8_t *fm=m->map(m->ctx,m->frame_map_pa+index*16,16);
    if(!fm)return SPTM_MEMORY_UNAVAILABLE;
    if(fm[0] || fm[1])return SPTM_FRAME_BUSY;
    if(fm[2]!=SPTM_MAC_DEFAULT && fm[2]!=SPTM_MAC_KERNEL_RESTRICTED)
        return SPTM_TYPE_MISMATCH;
    for(unsigned n=0;n<4;n++)e->shadow[n]=0;
    enum sptm_result r=guest_slot(m,b->kernel_root,va,scratch,scratch_bytes,e);
    if(r || (e->old&3)!=3 || (e->old&PAGE_MASK)!=target)return r;
    return update_entry(m,b,va,requested,options,e);
}
void sptm_kernel_update_commit(const struct sptm_memory *m,struct sptm_update_entry *e)
{
    if(e->old==e->next)return;
    for(unsigned j=0;j<4;j++) {
        uint64_t desc=get64(e->shadow[j]),mask=PT_LEAF_ATTRS|PT_LEAF_UPPER;
        put64(e->shadow[j],(desc&~mask)|(e->next&mask));
    }
    put64(e->guest,e->next);m->publish(m->ctx,e->slot_pa,8);
}
/* Every distinct frame whose SH/AttrIndx changes, once, before any store. */
static enum sptm_result clean_frames(const struct sptm_memory *m,
    const struct sptm_update_workspace *w,uint64_t count)
{
    for (uint64_t n=0;n<count;n++) {
        const struct sptm_update_entry *e=&w->entries[n];
        if (!((e->old^e->next)&SPTM_UPDATE_ATTRS)) continue;
        uint64_t pa=e->old&PAGE_MASK;int seen=0;
        for (uint64_t j=0;j<n && !seen;j++)
            seen=((w->entries[j].old^w->entries[j].next)&SPTM_UPDATE_ATTRS) &&
                 (w->entries[j].old&PAGE_MASK)==pa;
        if (seen) continue;
        if (!m->clean_frame || !m->clean_frame(m->ctx,pa,0x4000))
            return SPTM_MEMORY_UNAVAILABLE;
    }
    return SPTM_OK;
}
static enum sptm_result apply_updates(const struct sptm_memory *m,
    struct sptm_update_workspace *w,uint64_t count,volatile uint8_t *previous,
    uint64_t scratch)
{
    if (m->refs) {
        enum sptm_result r=sptm_refs_validate(m);if (r) return r;
    }
    enum sptm_result r=clean_frames(m,w,count);
    if (r) return r;
    for (uint64_t n=0;n<count;n++) {
        struct sptm_update_entry *e=&w->entries[n];
        sptm_kernel_update_commit(m,e);
        put64(previous+n*8,e->old);
    }
    if (m->refs) sptm_refs_commit(m);
    m->publish(m->ctx,scratch,count*8);
    return SPTM_OK;
}

enum sptm_result sptm_mac_update_disjoint(const struct sptm_memory *m,
    const struct sptm_update_backend *b,struct sptm_update_workspace *w,
    uint64_t target,uint64_t list,uint64_t count,uint64_t options,uint64_t scratch)
{
    if (!m || !m->map || !m->publish || !sptm_boot_memory_valid(m) || !b || !b->map_shadow || !w ||
        (b->kernel_root&0x3fff) || (b->shadow_root&0xfff) ||
        m->frame_low>=m->frame_high || m->alloc_low>=m->alloc_high ||
        m->alloc_low<m->frame_low || m->alloc_high>m->frame_high ||
        ((m->frame_low|m->frame_high|m->alloc_low|m->alloc_high)&0x3fff) ||
        (m->frame_map_pa&15)) return SPTM_BAD_CONFIG;
    if (!count || count>SPTM_DISJOINT_MAX || (list&7) || (scratch&7) ||
        (target&0x3fff) || !sptm_managed_frame(m,target) ||
        target<m->frame_low || target>=m->frame_high ||
        list>UINT64_MAX-count*24 || scratch>UINT64_MAX-count*8 ||
        overlaps(list,count*24,scratch,count*8)) return SPTM_BAD_ADDRESS;
    /* FD588..FDA4: without option 0x800, AF may be cleared but cannot be
     * raised from zero. FD574 selects wired, FD5A8/FD5C0 SH and AttrIndx.
     * Permission transitions are narrowed in update_entry; nG stays refused. */
    if (!sptm_update_options_valid(options)) return SPTM_UNSUPPORTED_OPTIONS;
    uint64_t map_size=((m->frame_high-m->frame_low)>>14)*16;
    if (map_size>UINT64_MAX-m->frame_map_pa ||
        overlaps(m->frame_map_pa,map_size,scratch,count*8)) return SPTM_BAD_CONFIG;
    uint64_t index=(target-m->frame_low)>>14;
    if (index>(UINT64_MAX-m->frame_map_pa-15)/16) return SPTM_BAD_CONFIG;
    volatile uint8_t *fm=m->map(m->ctx,m->frame_map_pa+index*16,16);
    if (!fm) return SPTM_MEMORY_UNAVAILABLE;
    /* Type10 has no UPDATE permission policy in the selected image. Both
     * admitted types have descriptor+0x34 set (deferred status supported). */
    if (fm[2]!=SPTM_MAC_DEFAULT && fm[2]!=SPTM_MAC_KERNEL_RESTRICTED)
        return SPTM_TYPE_MISMATCH;
    volatile uint8_t *input=m->map(m->ctx,list,count*24);
    volatile uint8_t *previous=m->map(m->ctx,scratch,count*8);
    if (!input || !previous) return SPTM_MEMORY_UNAVAILABLE;
    sptm_refs_begin(m->refs);
    uint64_t seen[SPTM_DISJOINT_MAX];
    /* Prepare every pointer and value before making any store. In particular,
     * a bad later record must not partly clear AF or overwrite old-PTE output.
     * The caller owns the workspace and keeps guest CPUs stopped throughout. */
    for (uint64_t n=0;n<count;n++) {
        uint64_t root=get64(input+n*24),va=get64(input+n*24+8);
        uint64_t requested=get64(input+n*24+16);
        if (root!=b->kernel_root || va<0xffff800000000000UL || (va&0x3fff))
            return SPTM_BAD_ADDRESS;
        /* One root: a repeated VA is a repeated (root, VA). Counted before
         * the duplicate-slot refusal below so that stop names its cause. */
        for (uint64_t j=0;j<n;j++)
            if (seen[j]==va) {sptm_audit_duplicate(m->audit,root,va);break;}
        seen[n]=va;
        struct sptm_update_entry *e=&w->entries[n];
        enum sptm_result result=guest_slot(m,root,va,scratch,count*8,e);
        if (result) return result;
        for (uint64_t j=0;j<n;j++)
            if (e->guest && e->guest==w->entries[j].guest) return SPTM_BAD_ADDRESS;
        /* FDDCC..FDE10 returns the old entry, but only modifies valid leaves
         * still pointing at the requested frame. A stale list is not a remap. */
        if ((e->old&3)!=3 || (e->old&PAGE_MASK)!=target) continue;
        result=update_entry(m,b,va,requested,options,e);
        if (result) return result;
        for (uint64_t j=0;j<n;j++) {
            struct sptm_update_entry *prior=&w->entries[j];
            if ((prior->old&3)!=3 || (prior->old&PAGE_MASK)!=target) continue;
            for (unsigned a=0;a<4;a++) for (unsigned z=0;z<4;z++)
                if (e->shadow[a]==prior->shadow[z]) return SPTM_SHADOW_FAILED;
        }
    }
    return apply_updates(m,w,count,previous,scratch);
}

enum sptm_result sptm_mac_update_region(const struct sptm_memory *m,
    const struct sptm_update_backend *b,struct sptm_update_workspace *w,
    uint64_t root,uint64_t va,uint64_t count,uint64_t templates,
    uint64_t options,uint64_t scratch)
{
    if (!m || !m->map || !m->publish || !m->refs || !sptm_boot_memory_valid(m) || !b || !b->map_shadow || !w ||
        (b->kernel_root&0x3fff) || (b->shadow_root&0xfff) ||
        m->alloc_low>=m->alloc_high || m->frame_low>m->alloc_low ||
        m->frame_high<m->alloc_high || (m->frame_map_pa&15)) return SPTM_BAD_CONFIG;
    if (!count || count>64 || root!=b->kernel_root || va<0xffff800000000000UL ||
        (va&0x3fff) || (templates&7) || (scratch&7) ||
        count-1>(UINT64_MAX-va)/0x4000 ||
        (va>>25)!=((va+(count-1)*0x4000)>>25) ||
        templates>UINT64_MAX-count*8 || scratch>UINT64_MAX-count*8 ||
        overlaps(templates,count*8,scratch,count*8)) return SPTM_BAD_ADDRESS;
    if (!sptm_update_options_valid(options)) return SPTM_UNSUPPORTED_OPTIONS;
    uint64_t map_size=((m->frame_high-m->frame_low)>>14)*16;
    if (map_size>UINT64_MAX-m->frame_map_pa ||
        overlaps(m->frame_map_pa,map_size,scratch,count*8)) return SPTM_BAD_CONFIG;
    volatile uint8_t *input=m->map(m->ctx,templates,count*8);
    volatile uint8_t *previous=m->map(m->ctx,scratch,count*8);
    if (!input || !previous) return SPTM_MEMORY_UNAVAILABLE;
    sptm_refs_begin(m->refs);
    for (uint64_t n=0;n<count;n++) {
        struct sptm_update_entry *e=&w->entries[n];
        enum sptm_result r=guest_slot(m,root,va+n*0x4000,scratch,count*8,e);
        if (r) return r;
        if (!e->guest) return SPTM_TABLE_MISSING;
        if ((e->old&3)!=3) continue;
        r=update_entry(m,b,va+n*0x4000,get64(input+n*8),options,e);
        if (r) return r;
        for (uint64_t j=0;j<n;j++) {
            struct sptm_update_entry *prior=&w->entries[j];
            if ((prior->old&3)!=3) continue;
            if (e->guest==prior->guest) return SPTM_BAD_TABLE;
            for (unsigned a=0;a<4;a++) for (unsigned z=0;z<4;z++)
                if (e->shadow[a]==prior->shadow[z]) return SPTM_SHADOW_FAILED;
        }
    }
    return apply_updates(m,w,count,previous,scratch);
}

uint64_t sptm_update_result(const struct sptm_update_workspace *w,
    uint64_t count,uint64_t options)
{
    uint64_t changed=0;
    if(options&0x100)for(uint64_t n=0;n<count;n++) {
        uint64_t old=w->entries[n].old,next=w->entries[n].next;
        if(sptm_update_leaves_posted(old,next))return 0;
        changed|=(old^next)&~(3UL<<58);
    }
    return changed ? 5:0;
}

static uint32_t get32(volatile uint8_t *p)
{
    uint32_t v=0; for (unsigned i=0;i<4;i++) v|=(uint32_t)p[i]<<(8*i); return v;
}
/* The 16-byte record of a managed 16K frame, or NULL. */
static volatile uint8_t *frame_record(const struct sptm_memory *m,uint64_t pa)
{
    if (!sptm_managed_frame(m,pa) || (m->frame_map_pa&15)) return 0;
    uint64_t index=(pa-m->frame_low)>>14;
    if (index>(UINT64_MAX-m->frame_map_pa-15)/16) return 0;
    return m->map(m->ctx,m->frame_map_pa+index*16,16);
}
enum sptm_result sptm_mac_multipage_plan(const struct sptm_memory *m,uint64_t ops,
    uint64_t count,struct sptm_multipage_plan *p)
{
    if (!m || !m->map || !p) return SPTM_BAD_CONFIG;
    p->groups=0;
    /* ...fe52c..fe548: 1..64 records, all inside the ops buffer's 16K page. */
    if (!count || count>SPTM_MULTIPAGE_MAX || (ops&7) ||
        (ops&0x3fff)+count*24>0x4000) return SPTM_BAD_ADDRESS;
    volatile uint8_t *in=m->map(m->ctx,ops,count*24);
    if (!in) return SPTM_MEMORY_UNAVAILABLE;
    /* Snapshot and preflight every header before any group executes. */
    for (uint64_t i=0;i<count;) {
        volatile uint8_t *h=in+i*24;
        uint64_t target=get64(h),attributes=get64(h+8),flags=0;
        uint32_t mappings=get32(h+16),options=get32(h+20);
        if (!(options&0x200)) {
            /* ...fe644..fe6e4: a 16K DRAM frame whose type has a mapping
             * policy; flags 2 (option 0x20) | 0x80 (option 0x100, +0x34). */
            volatile uint8_t *fm=frame_record(m,target);
            if (!fm) return SPTM_BAD_ADDRESS;
            if (fm[0] || fm[1]) return SPTM_FRAME_BUSY;
            if (fm[2]!=SPTM_MAC_DEFAULT) return SPTM_TYPE_MISMATCH;
            flags=((options&0x20) ? 2u:0u)|((options&0x100) ? 0x80u:0u);
            if (!flags) return SPTM_UNSUPPORTED_OPTIONS;            /* ...dfe40 */
        }
        i++;
        if (!mappings && !flags) continue;
        if (mappings>count-i) return SPTM_BAD_ADDRESS;              /* ...fe748 */
        uint64_t o=options&~0x200UL;
        if (mappings && !sptm_update_options_valid(o))
            return SPTM_UNSUPPORTED_OPTIONS;                        /* ...fe758 */
        struct sptm_multipage_group *g=&p->group[p->groups++];
        g->target=target;g->list=ops+i*24;g->count=mappings;g->options=o;
        g->aperture_flags=flags;g->aperture_attr=(attributes>>2)&7;
        i+=mappings;
    }
    return SPTM_OK;
}
