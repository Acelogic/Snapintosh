/* SPDX-License-Identifier: MIT */
#pragma once
#include "aes.h"
#include "pauth-user.h"

/* A private compatibility key domain, not Apple's hidden key transformation.
 * The seed must be fresh entropy kept outside all guest mappings. */
struct pauth_domain { struct aes_key master; uint32_t ready; };
int pauth_domain_init(struct pauth_domain *,const uint8_t seed[32]);
int pauth_domain_user(const struct pauth_domain *,const struct pauth_user_state *,
                      struct pauth_key_pair output[PAUTH_KEYS]);
/* Same derivation; hardware selects AESE/AESMC (see aes_hardware_supported). */
int pauth_domain_user_with(const struct pauth_domain *,const struct pauth_user_state *,
                           struct pauth_key_pair output[PAUTH_KEYS],int hardware);

/* Per-vCPU memo of recent derivations. An entry is keyed by every derivation
 * input (all five key operands, EXTRA and APCTL), so a hit returns exactly
 * what pauth_domain_user would. Valid for one initialized domain. */
#define PAUTH_DERIVE_CACHE 8
struct pauth_derive_entry {
    uint64_t valid, apctl;
    struct pauth_key_pair key[PAUTH_KEYS], extra, out[PAUTH_KEYS];
};
struct pauth_derive_cache {
    struct pauth_derive_entry entry[PAUTH_DERIVE_CACHE];
    uint64_t next, hits, misses;
};
int pauth_domain_user_cached(const struct pauth_domain *,const struct pauth_user_state *,
                             struct pauth_derive_cache *,struct pauth_key_pair output[PAUTH_KEYS],
                             int hardware);
uint64_t pauth_root_enables(uint64_t sctlr,unsigned root_flags);

#if defined(SNAP_EL0_MEMO) && SNAP_EL0_MEMO
/* SNAP_EL0_MEMO: a second level behind the 8-entry memo (the user return's
 * derivation, probes/xnuboot.c xnuboot_pauth_resume), per vCPU: 32 sets of 4,
 * the set picked by a hash, a hit only when every input is equal (as in the
 * first level). A derivation reuses the first CBC-MAC block of each key, which
 * depends only on the master key and the key index. Both levels and those
 * blocks belong to one domain epoch: the caller passes the current one (bumped
 * by every successful domain preparation) and a different stored epoch
 * flushes them. */
#define PAUTH_DERIVE_WIDE_SETS 32u
#define PAUTH_DERIVE_WIDE_WAYS 4u
struct pauth_derive_wide {
    uint64_t epoch;                                /* 0: never used */
    uint64_t first_ready,first_hardware;           /* the AES selector the first blocks used */
    uint8_t first[PAUTH_KEYS][16];
    struct pauth_derive_entry entry[PAUTH_DERIVE_WIDE_SETS][PAUTH_DERIVE_WIDE_WAYS];
    uint32_t next[PAUTH_DERIVE_WIDE_SETS];
    uint64_t hits,derived,flushes;                 /* second-level hits, derivations, epoch flushes */
};
static inline unsigned pauth_derive_wide_set(const struct pauth_user_state *s)
{
    uint64_t h=s->key[PAUTH_IB].lo^(s->key[PAUTH_IA].lo>>7)^(s->key[PAUTH_DB].lo<<9)^s->extra.lo^s->key[PAUTH_GA].hi;
    return (unsigned)((h*UINT64_C(0x9e3779b97f4a7c15))>>59)&(PAUTH_DERIVE_WIDE_SETS-1);
}
/* pauth_domain_user_cached's answer through both levels; 0 with neither
 * touched when the domain is not ready, APCTL is not 0x11, hardware is not 0
 * or 1, epoch is 0 or a cache is missing. cache->hits counts every answer
 * without a derivation, cache->misses every derivation. */
int pauth_domain_user_cached_wide(const struct pauth_domain *,const struct pauth_user_state *,
                                  struct pauth_derive_cache *,struct pauth_derive_wide *,uint64_t epoch,
                                  struct pauth_key_pair output[PAUTH_KEYS],int hardware);
#endif
