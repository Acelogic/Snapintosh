/* SPDX-License-Identifier: MIT */
#include "sptm-root.h"
#include "sptm-access.h"
#include "sptm-user.h"
#include "sptm-root-memo.h"
#if SNAP_ROOT_MISS_FAST
#include "root-miss.h"
#endif
#if SNAP_NEST_FAST || SNAP_DETACH_FAST
#include "nest-fast.h"
#endif
#define MASK 0x0000ffffffffc000UL
#include "sptm-root/views.c"
#include "sptm-root/view_updates.c"
#include "sptm-root/linked_switch.c"
#if SNAP_FINE_SWITCH
#include "fine-lock.h"
#if SNAP_FINE_SWITCH_HW && !SNAP_USER_HW_WALK
#error "SNAP_FINE_SWITCH_HW requires SNAP_USER_HW_WALK (the backend's hw_eligible hook)"
#endif
static unsigned active_count_fine(const struct sptm_root_state *s,uint64_t root)
{
    unsigned n=0;
    for(unsigned i=0;i<SPTM_ROOT_CPUS;i++)n+=__atomic_load_n(&s->active[i],__ATOMIC_RELAXED)==root;
    return n;
}
int sptm_mac_switch_root_hit(const struct sptm_memory *m,
    struct sptm_root_state *s,const struct sptm_root_backend *b,unsigned cpu,
    uint64_t root,uint64_t set_flags,uint64_t clear_flags)
{
    if(!m || !m->map || !m->publish || !s || !b || !b->build || !b->install ||
       cpu>=SPTM_ROOT_CPUS || !b->kernel_root || !b->kernel_shadow ||
       (b->kernel_root&0x3fff) || (b->kernel_shadow&0xfff) ||
       !sptm_boot_memory_valid(m) ||
       ((m->frame_low|m->frame_high|m->alloc_low|m->alloc_high)&0x3fff) ||
       (m->frame_map_pa&15) || m->frame_low>=m->frame_high ||
       m->alloc_low>=m->alloc_high || m->alloc_low<m->frame_low ||
       m->alloc_high>m->frame_high ||
       m->frame_map_pa>UINT64_MAX-((m->frame_high-m->frame_low)>>14)*16)
        return 0;
    if(set_flags || clear_flags)return 0;
    if(!root || (root&0x3fff))return 0;
    uint64_t old=s->active[cpu];
    volatile uint8_t *old_meta=old ? metadata(m,old) : 0;
    struct sptm_user_geometry g;
    if(old && (!root_header(m,old_meta,&g) || get(old_meta+6,2)<active_count_fine(s,old)))
        return 0;
    if(root==b->kernel_root) {
        b->install(b->ctx,b->kernel_shadow,b->kernel_root,0,0);
        sprr_root_reset(&s->sprr[cpu],0);
        if(old) {put16(old_meta+6,(unsigned)get(old_meta+6,2)-1);
            m->publish(m->ctx,m->frame_map_pa+((old-m->frame_low)>>14)*16,16);}
        __atomic_store_n(&s->active[cpu],0,__ATOMIC_RELEASE);
        __atomic_fetch_add(&s->switches,1,__ATOMIC_RELAXED);
        __atomic_fetch_add(&s->kernel_switches,1,__ATOMIC_RELAXED);
        return 1;
    }
    volatile uint8_t *meta=metadata(m,root);
    if(!root_header(m,meta,&g))return 0;
    unsigned flags=(unsigned)get(meta+10,2),asid=(unsigned)get(meta+4,2),format=meta[12];
#if SNAP_FINE_SWITCH_HW
    /* SNAP_FINE_SWITCH_HW: sptm_mac_switch_root's hardware-walk branch, for
     * a root whose record already exists. The owner's hook answers as
     * hw_eligible does but never attaches: 1 for a record of this identity,
     * -1 for a record of another (the token path refuses it: decline, and it
     * repeats and reports the call), 0 for no record (the token path's
     * shadow path or attach: the cache-hit test below, which then declines
     * a root with no cache entry). The reference bounds are the token path's,
     * with the activity words loaded atomically; the caller holds this
     * root's stripe, so no other CPU switches to or from it meanwhile. */
    if(b->hw_eligible) {
        int hw=b->hw_eligible(b->ctx,m,root,asid,format,flags);
        if(hw<0)return 0;
        if(hw) {
            unsigned cpus=active_count_fine(s,root);
            if(get(meta+6,2)<cpus || get(meta+6,2)>g.root_groups+cpus)return 0;
            b->install(b->ctx,0,root,asid,format);goto installed;
        }
    }
#endif
    if(!cache_hit(s,root,asid,format,flags) || !b->skip_hit_validation ||
       !b->skip_hit_validation(b->ctx))return 0;
    if(get(meta+6,2)>=0x80b)return 0;
    struct sptm_root_cached *entry=0;
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++) {
        struct sptm_root_cached *e=&s->cache[i];
        if(e->root==root)entry=e;
        if(e->root && e->root!=root && e->asid==asid)return 0;
    }
    if(!entry || !entry->valid || entry->asid!=asid || entry->format!=format || entry->flags!=flags)
        return 0;
    b->install(b->ctx,entry->shadow,root,asid,format);
#if SNAP_FINE_SWITCH_HW
installed:
#endif
    sprr_root_reset(&s->sprr[cpu],flags);
    if(old!=root) {
        put16(meta+6,(unsigned)get(meta+6,2)+1);
        m->publish(m->ctx,m->frame_map_pa+((root-m->frame_low)>>14)*16,16);
        if(old) {put16(old_meta+6,(unsigned)get(old_meta+6,2)-1);
            m->publish(m->ctx,m->frame_map_pa+((old-m->frame_low)>>14)*16,16);}
    }
    __atomic_store_n(&s->active[cpu],root,__ATOMIC_RELEASE);
    __atomic_fetch_add(&s->switches,1,__ATOMIC_RELAXED);
    __atomic_fetch_add(&s->user_switches,1,__ATOMIC_RELAXED);
    return 1;
}
#endif
