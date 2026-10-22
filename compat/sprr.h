/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>

/* Reached mac-v1 SPTM values, pinned by inspect-sprr-contract.py. This model
 * supplies root-switch reset and register readback. Changed permission writes
 * require a shadow transaction and are refused, never acknowledged/ignored. */
#define SPRR_UPERM_INITIAL UINT64_C(0x2010002030100000)
#define SPRR_PPERM_INITIAL UINT64_C(0x2020a52a302abae6)
#define SPRR_PMPRR_INITIAL UINT64_C(0x40010)
#define SPRR_UPERM_TPRO_WRITE (UINT64_C(1)<<36)
#define SPRR_PPERM_MUTABLE (UINT64_C(0x100)|(UINT64_C(1)<<36))
#define SPRR_ISS(op2,crm) ((3u<<20)|((op2)<<17)|(6u<<14)|(15u<<10)|((crm)<<1))
#define SPRR_UPERM SPRR_ISS(5u,1u)
#define SPRR_PPERM SPRR_ISS(6u,1u)
#define SPRR_UMPRR SPRR_ISS(0u,3u)
#define SPRR_PMPRR SPRR_ISS(1u,3u)

struct sprr_state {
    uint64_t uperm,pperm,umprr,pmprr;
    uint64_t resets,reads,writes,rejected,last_reg,last_value;
};
_Static_assert(sizeof(struct sprr_state)==80,"SPRR audit stride");
enum sprr_result {SPRR_UNHANDLED,SPRR_OK,SPRR_BAD_STATE,
                  SPRR_WRITE_UNIMPLEMENTED,SPRR_CONTROL_WRITE_UNIMPLEMENTED,SPRR_VIEW_FAILED};
static inline void sprr_count(uint64_t *n) {if(*n!=UINT64_MAX)(*n)++;}
static inline void sprr_root_reset(struct sprr_state *s,unsigned flags)
{
    s->uperm=SPRR_UPERM_INITIAL;s->pperm=SPRR_PPERM_INITIAL;
    s->umprr=((uint64_t)(flags&8)<<15)|((uint64_t)(flags&1)<<11);
    s->pmprr=SPRR_PMPRR_INITIAL;sprr_count(&s->resets);
}
static inline int sprr_fixed_state_valid(const struct sprr_state *s)
{
    return s && s->resets && (s->uperm&~SPRR_UPERM_TPRO_WRITE)==SPRR_UPERM_INITIAL &&
        (!(s->uperm&SPRR_UPERM_TPRO_WRITE) || (s->umprr&0xc0000)==0x40000) &&
        (s->pperm&~SPRR_PPERM_MUTABLE)==SPRR_PPERM_INITIAL && s->pmprr==SPRR_PMPRR_INITIAL &&
        !(s->umprr&~UINT64_C(0x40800));
}
/* change_pperm completes private-view writes/publication/TLBI before the
 * register value is committed. The reached selector2 A/B and selector9 2/3
 * changes require corresponding enforcement or an unchanged-mapping proof. */
static inline enum sprr_result sprr_access_with(struct sprr_state *s,uint64_t reg,
    int is_read,uint64_t *value,int (*change_pperm)(void *,uint64_t),void *ctx)
{
    if(reg!=SPRR_UPERM && reg!=SPRR_PPERM && reg!=SPRR_UMPRR && reg!=SPRR_PMPRR)
        return SPRR_UNHANDLED;
    if(!value || !sprr_fixed_state_valid(s))return SPRR_BAD_STATE;
    s->last_reg=reg;s->last_value=*value;
    uint64_t current=reg==SPRR_UPERM ? s->uperm : reg==SPRR_PPERM ? s->pperm :
                     reg==SPRR_UMPRR ? s->umprr : s->pmprr;
    if(is_read) {*value=current;s->last_value=current;sprr_count(&s->reads);return SPRR_OK;}
    sprr_count(&s->writes);
    if(reg==SPRR_UMPRR || reg==SPRR_PMPRR) {
        sprr_count(&s->rejected);return SPRR_CONTROL_WRITE_UNIMPLEMENTED;
    }
    if(*value!=current) {
        if(reg==SPRR_PPERM && change_pperm &&
           (*value&~SPRR_PPERM_MUTABLE)==SPRR_PPERM_INITIAL) {
            if(!change_pperm(ctx,*value)) {sprr_count(&s->rejected);return SPRR_VIEW_FAILED;}
            s->pperm=*value;return SPRR_OK;
        }
        sprr_count(&s->rejected);return SPRR_WRITE_UNIMPLEMENTED;
    }
    return SPRR_OK;
}
static inline enum sprr_result sprr_access(struct sprr_state *s,uint64_t reg,
                                         int is_read,uint64_t *value)
{return sprr_access_with(s,reg,is_read,value,0,0);}
/* Reached TPRO pair only. The callback must enforce the resulting mapping
 * permissions before commit, or prove that the current view has no affected
 * pages. UMPRR field9=1 is the reached enabled policy; unknown write filters
 * remain unsupported. Root switches reset this per-CPU state. */
static inline enum sprr_result sprr_uperm_write(struct sprr_state *s,uint64_t value,
                                               int (*change)(void *,uint64_t),void *ctx)
{
    if(!sprr_fixed_state_valid(s))return SPRR_BAD_STATE;
    s->last_reg=SPRR_UPERM;s->last_value=value;sprr_count(&s->writes);
    if((value&~SPRR_UPERM_TPRO_WRITE)!=SPRR_UPERM_INITIAL ||
       (s->umprr&0xc0000)!=0x40000 || !change) {
        sprr_count(&s->rejected);return SPRR_WRITE_UNIMPLEMENTED;
    }
    if(!change(ctx,value)) {sprr_count(&s->rejected);return SPRR_VIEW_FAILED;}
    s->uperm=value;return SPRR_OK;
}
/* Reached EL0 UPERM read. Expose the same enforced state as kernel readback;
 * writes and all other Apple encodings need their own permission adapter. */
static inline enum sprr_result sprr_user_read(struct sprr_state *s,
                                             uint32_t instruction,uint64_t regs[31])
{
    if((instruction&~31U)!=0xd53ef1a0U)return SPRR_UNHANDLED;
    if(!regs)return SPRR_BAD_STATE;
    uint64_t value=0;
    enum sprr_result result=sprr_access(s,SPRR_UPERM,1,&value);
    if(result==SPRR_OK && (instruction&31)!=31)regs[instruction&31]=value;
    return result;
}
static inline enum sprr_result sprr_user_write(struct sprr_state *s,uint32_t instruction,
    const uint64_t regs[31],int (*change)(void *,uint64_t),void *ctx)
{
    if((instruction&~31U)!=0xd51ef1a0U)return SPRR_UNHANDLED;
    if(!regs)return SPRR_BAD_STATE;
    return sprr_uperm_write(s,(instruction&31)==31 ? 0 : regs[instruction&31],change,ctx);
}
static inline unsigned sprr_pte_class(uint64_t pte)
{return (unsigned)(((pte>>4)&12)|((pte>>53)&3));}
/* With the fixed UPERM/PPERM values, only these classes have the same EL0
 * and EL1 R/W/X permissions as the ordinary ARM PTE. Reject every other user
 * leaf before publishing a shadow, including TPRO and JIT. A future changing
 * write must not reuse this cache without translating its affected classes. */
static inline int sprr_fixed_native_leaf(uint64_t pte)
{return !!(UINT32_C(0xac88)&(1u<<sprr_pte_class(pte)));}
