/* SPDX-License-Identifier: MIT */
#include "pauth-domain.h"
#define ADDRESS_ENABLES 0xc8002000UL
#ifndef SNAP_AES_BITSLICE
#define SNAP_AES_BITSLICE 0
#endif
#if SNAP_AES_BITSLICE
#include "aes-bitslice.h"
#endif

int pauth_domain_init(struct pauth_domain *d,const uint8_t seed[32])
{
    if(!d || !seed)return 0;
    d->ready=0;
    if(!aes_expand(&d->master,seed,32))return 0;
    d->ready=1;return 1;
}

uint64_t pauth_root_enables(uint64_t sctlr,unsigned flags)
{
    /* Pinned SWITCH_ROOT ...2701006ec..724: flag1 selects address PA.
     * Existing partial enables are preserved; an all-clear mask becomes all-on. */
    if(!(flags&2))return sctlr&~ADDRESS_ENABLES;
    return (sctlr&ADDRESS_ENABLES) ? sctlr : sctlr|ADDRESS_ENABLES;
}

int pauth_domain_user(const struct pauth_domain *d,const struct pauth_user_state *s,
                      struct pauth_key_pair out[PAUTH_KEYS])
{return pauth_domain_user_with(d,s,out,0);}
static int encrypt(const struct aes_key *key,const uint8_t in[16],uint8_t out[16],int hardware)
#if SNAP_AES_BITSLICE
/* docs/AES-BITSLICE-20261019.md: aes_block's result without its per-byte
 * GF(2^8) inversions (325 µs per derive-cache miss on the A16, whose SVE/SME
 * keeps the hardware path off). The hardware path is unchanged. */
{return hardware ? aes_encrypt_hardware(key,in,out) : aes_encrypt_bitsliced(key,in,out);}
#else
{return hardware ? aes_encrypt_hardware(key,in,out) : aes_block(key,in,out,0);}
#endif
int pauth_domain_user_with(const struct pauth_domain *d,const struct pauth_user_state *s,
                           struct pauth_key_pair out[PAUTH_KEYS],int hardware)
{
    if(!d || !d->ready || !s || !out || s->apctl!=0x11 || (hardware!=0 && hardware!=1))return 0;
    struct pauth_key_pair next[PAUTH_KEYS];
    for(unsigned k=0;k<PAUTH_KEYS;k++) {
        /* Fixed-length CBC-MAC: exactly three blocks, never variable length.
         * Domain/version/class, register operands, then EXTRA (or zero).
         * B keys are process/thread ROP operands; A/GA use the JOP selector.
         * This defines our compatibility domain, not Apple security equivalence. */
        uint8_t block[16]="SnapintoshPACv1",tag[16];
        block[15]=(uint8_t)k;
        if(!encrypt(&d->master,block,tag,hardware))return 0;
        for(unsigned i=0;i<16;i++) {
            uint64_t word=i<8 ? s->key[k].lo : s->key[k].hi;
            block[i]=tag[i]^(uint8_t)(word>>((i&7)*8));
        }
        if(!encrypt(&d->master,block,tag,hardware))return 0;
        for(unsigned i=0;i<16;i++) {
            uint64_t word=k==PAUTH_IB || k==PAUTH_DB ? 0 :
                i<8 ? s->extra.lo : s->extra.hi;
            block[i]=tag[i]^(uint8_t)(word>>((i&7)*8));
        }
        if(!encrypt(&d->master,block,tag,hardware))return 0;
        next[k]=(struct pauth_key_pair){0,0};
        for(unsigned i=0;i<8;i++) {
            next[k].lo|=(uint64_t)tag[i]<<(i*8);
            next[k].hi|=(uint64_t)tag[i+8]<<(i*8);
        }
        aes_clear(block,sizeof(block));aes_clear(tag,sizeof(tag));
    }
    for(unsigned k=0;k<PAUTH_KEYS;k++)out[k]=next[k];
    aes_clear(next,sizeof(next));return 1;
}

static int same_inputs(const struct pauth_derive_entry *e,const struct pauth_user_state *s)
{
    if(!e->valid || e->apctl!=s->apctl || e->extra.lo!=s->extra.lo || e->extra.hi!=s->extra.hi)return 0;
    for(unsigned k=0;k<PAUTH_KEYS;k++)
        if(e->key[k].lo!=s->key[k].lo || e->key[k].hi!=s->key[k].hi)return 0;
    return 1;
}
int pauth_domain_user_cached(const struct pauth_domain *d,const struct pauth_user_state *s,
                             struct pauth_derive_cache *cache,struct pauth_key_pair out[PAUTH_KEYS],
                             int hardware)
{
    if(!cache)return 0;
    if(d && d->ready && s && out && s->apctl==0x11)
        for(unsigned n=0;n<PAUTH_DERIVE_CACHE;n++)if(same_inputs(&cache->entry[n],s)) {
            for(unsigned k=0;k<PAUTH_KEYS;k++)out[k]=cache->entry[n].out[k];
            cache->hits++;return 1;
        }
    struct pauth_key_pair next[PAUTH_KEYS];
    if(!pauth_domain_user_with(d,s,next,hardware)) {aes_clear(next,sizeof(next));return 0;}
    struct pauth_derive_entry *e=&cache->entry[cache->next%PAUTH_DERIVE_CACHE];
    e->valid=1;e->apctl=s->apctl;e->extra=s->extra;
    for(unsigned k=0;k<PAUTH_KEYS;k++){e->key[k]=s->key[k];e->out[k]=next[k];out[k]=next[k];}
    cache->next++;cache->misses++;
    aes_clear(next,sizeof(next));return 1;
}

#if defined(SNAP_EL0_MEMO) && SNAP_EL0_MEMO
/* SNAP_EL0_MEMO (pauth-domain.h). The first CBC-MAC block of key k is
 * encrypt("SnapintoshPACv1"||k): the same bytes and the same encrypt as the
 * first block of pauth_domain_user_with, so the two remaining blocks below,
 * which are its statements, give its result. */
static int first_blocks(const struct pauth_domain *d,uint8_t first[PAUTH_KEYS][16],int hardware)
{
    for(unsigned k=0;k<PAUTH_KEYS;k++) {
        uint8_t block[16]="SnapintoshPACv1";
        block[15]=(uint8_t)k;
        if(!encrypt(&d->master,block,first[k],hardware))return 0;
    }
    return 1;
}
static int derive_from_first(const struct pauth_domain *d,const struct pauth_user_state *s,
                             const uint8_t first[PAUTH_KEYS][16],struct pauth_key_pair out[PAUTH_KEYS],
                             int hardware)
{
    struct pauth_key_pair next[PAUTH_KEYS];
    uint8_t block[16],tag[16];
    int ok=1;
    for(unsigned k=0;k<PAUTH_KEYS && ok;k++) {
        for(unsigned i=0;i<16;i++) {
            uint64_t word=i<8 ? s->key[k].lo : s->key[k].hi;
            block[i]=first[k][i]^(uint8_t)(word>>((i&7)*8));
        }
        if(!encrypt(&d->master,block,tag,hardware)) {ok=0;break;}
        for(unsigned i=0;i<16;i++) {
            uint64_t word=k==PAUTH_IB || k==PAUTH_DB ? 0 :
                i<8 ? s->extra.lo : s->extra.hi;
            block[i]=tag[i]^(uint8_t)(word>>((i&7)*8));
        }
        if(!encrypt(&d->master,block,tag,hardware)) {ok=0;break;}
        next[k]=(struct pauth_key_pair){0,0};
        for(unsigned i=0;i<8;i++) {
            next[k].lo|=(uint64_t)tag[i]<<(i*8);
            next[k].hi|=(uint64_t)tag[i+8]<<(i*8);
        }
    }
    if(ok)for(unsigned k=0;k<PAUTH_KEYS;k++)out[k]=next[k];
    aes_clear(block,sizeof(block));aes_clear(tag,sizeof(tag));aes_clear(next,sizeof(next));
    return ok;
}
static void derive_store(struct pauth_derive_entry *e,const struct pauth_user_state *s,
                         const struct pauth_key_pair out[PAUTH_KEYS])
{
    e->valid=1;e->apctl=s->apctl;e->extra=s->extra;
    for(unsigned k=0;k<PAUTH_KEYS;k++){e->key[k]=s->key[k];e->out[k]=out[k];}
}
int pauth_domain_user_cached_wide(const struct pauth_domain *d,const struct pauth_user_state *s,
                                  struct pauth_derive_cache *cache,struct pauth_derive_wide *wide,uint64_t epoch,
                                  struct pauth_key_pair out[PAUTH_KEYS],int hardware)
{
    if(!cache || !wide || !epoch || !d || !d->ready || !s || !out || s->apctl!=0x11 ||
       (hardware!=0 && hardware!=1))return 0;
    /* Explicit invalidation: another domain epoch owns nothing kept here. */
    if(wide->epoch!=epoch) {
        for(unsigned n=0;n<PAUTH_DERIVE_CACHE;n++)cache->entry[n].valid=0;
        for(unsigned set=0;set<PAUTH_DERIVE_WIDE_SETS;set++)
            for(unsigned w=0;w<PAUTH_DERIVE_WIDE_WAYS;w++)wide->entry[set][w].valid=0;
        aes_clear(wide->first,sizeof(wide->first));wide->first_ready=0;
        wide->epoch=epoch;wide->flushes++;
    }
    for(unsigned n=0;n<PAUTH_DERIVE_CACHE;n++)if(same_inputs(&cache->entry[n],s)) {
        for(unsigned k=0;k<PAUTH_KEYS;k++)out[k]=cache->entry[n].out[k];
        cache->hits++;return 1;
    }
    unsigned set=pauth_derive_wide_set(s);
    for(unsigned w=0;w<PAUTH_DERIVE_WIDE_WAYS;w++)if(same_inputs(&wide->entry[set][w],s)) {
        for(unsigned k=0;k<PAUTH_KEYS;k++)out[k]=wide->entry[set][w].out[k];
        derive_store(&cache->entry[cache->next%PAUTH_DERIVE_CACHE],s,out);cache->next++;
        cache->hits++;wide->hits++;return 1;
    }
    if(!wide->first_ready || wide->first_hardware!=(uint64_t)hardware) {
        wide->first_ready=0;
        if(!first_blocks(d,wide->first,hardware)) {aes_clear(wide->first,sizeof(wide->first));return 0;}
        wide->first_ready=1;wide->first_hardware=(uint64_t)hardware;
    }
    struct pauth_key_pair next[PAUTH_KEYS];
    if(!derive_from_first(d,s,wide->first,next,hardware)) {aes_clear(next,sizeof(next));return 0;}
    derive_store(&cache->entry[cache->next%PAUTH_DERIVE_CACHE],s,next);cache->next++;
    derive_store(&wide->entry[set][wide->next[set]++%PAUTH_DERIVE_WIDE_WAYS],s,next);
    for(unsigned k=0;k<PAUTH_KEYS;k++)out[k]=next[k];
    cache->misses++;wide->derived++;
    aes_clear(next,sizeof(next));return 1;
}
#endif
