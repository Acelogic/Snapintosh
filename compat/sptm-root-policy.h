/* SPDX-License-Identifier: MIT */
#pragma once
#include "sptm-root.h"

/* Saved root flags and the policy loaded by a CPU are distinct native state.
 * CONFIGURE_ROOT stores flags; SWITCH_ROOT performs the register transaction.
 * Keep this outside sptm_root_state so existing reader offsets stay stable. */
struct sptm_loaded_root {uint64_t root,flags,resets;};
_Static_assert(sizeof(struct sptm_loaded_root)==24,"loaded root audit stride");

static inline const struct sptm_root_cached *sptm_root_policy_cache(
    const struct sptm_root_state *s,uint64_t root)
{
    const struct sptm_root_cached *found=0;
    if(!s || !root || (root&0x3fff))return 0;
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(s->cache[i].root==root) {
        const struct sptm_root_cached *e=&s->cache[i];struct sptm_user_geometry g;
        if(found || e->valid!=1 || !e->shadow || (e->shadow&4095) ||
           !e->asid || e->asid>0xffff || e->format>1 || e->flags>0xffff ||
           !sptm_mac_user_geometry((unsigned)e->format,(unsigned)e->flags,&g))return 0;
        found=e;
    }
    return found;
}

static inline uint64_t sptm_root_policy_umprr(uint64_t flags)
{return ((flags&8)<<15)|((flags&1)<<11);}

/* Called only after a successful complete root installation, including the
 * initial kernel reset. Failure leaves the prior record untouched. */
static inline int sptm_root_note_loaded(const struct sptm_root_state *s,
    struct sptm_loaded_root loaded[SPTM_ROOT_CPUS],unsigned cpu)
{
    if(!s || !loaded || cpu>=SPTM_ROOT_CPUS || !sprr_fixed_state_valid(&s->sprr[cpu]))return 0;
    uint64_t root=s->active[cpu],flags=0;
    if(root) {
        const struct sptm_root_cached *e=sptm_root_policy_cache(s,root);
        if(!e)return 0;
        flags=e->flags;
    }
    if(s->sprr[cpu].umprr!=sptm_root_policy_umprr(flags))return 0;
    loaded[cpu]=(struct sptm_loaded_root){root,flags,s->sprr[cpu].resets};
    return 1;
}

static inline int sptm_root_loaded_valid(const struct sptm_root_state *s,
    const struct sptm_loaded_root loaded[SPTM_ROOT_CPUS],unsigned cpu)
{
    if(!s || !loaded || cpu>=SPTM_ROOT_CPUS)return 0;
    const struct sptm_loaded_root *l=&loaded[cpu];
    if(l->root!=s->active[cpu] || l->resets!=s->sprr[cpu].resets ||
       !sprr_fixed_state_valid(&s->sprr[cpu]) ||
       s->sprr[cpu].umprr!=sptm_root_policy_umprr(l->flags))return 0;
    if(!l->root)return !l->flags;
    const struct sptm_root_cached *e=sptm_root_policy_cache(s,l->root);
    /* Only UMPRR11 may currently differ between saved and installed state.
     * It changes neither geometry nor any admitted canonical leaf class. */
    return e && !((l->flags^e->flags)&~UINT64_C(1));
}

/* The global service token serializes saved metadata/cache updates. The
 * caller also verifies vCPU TTBR ownership. Active shadows and loaded policy
 * remain untouched; the next SWITCH_ROOT performs normal publication/TLBI.
 * Other active modifier changes require their own transition contract. */
static inline int sptm_root_configure_active(struct sptm_root_state *s,
    const struct sptm_loaded_root loaded[SPTM_ROOT_CPUS],uint64_t root,
    uint16_t before,uint16_t after)
{
    if((before^after)!=SPTM_MAC_ROOT_FLAG_UMPRR11)return 0;
    const struct sptm_root_cached *e=sptm_root_policy_cache(s,root);
    if(!e || e->flags!=before)return 0;
    unsigned active=0;
    for(unsigned cpu=0;cpu<SPTM_ROOT_CPUS;cpu++) {
        if(!sptm_root_loaded_valid(s,loaded,cpu))return 0;
        active+=s->active[cpu]==root;
    }
    if(!active)return 0;
    s->cache[e-s->cache].flags=after;
    return 1;
}
