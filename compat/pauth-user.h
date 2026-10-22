/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>

enum pauth_key_class { PAUTH_IA, PAUTH_IB, PAUTH_DA, PAUTH_DB, PAUTH_GA, PAUTH_KEYS };
struct pauth_key_pair { uint64_t lo, hi; };

/* Guest key-register operands, not Apple's transformed hardware keys.
 * Keep this state per vCPU: context-switch MSRs and the batch caller's
 * temporary JOP selection both change it. Native user execution derives
 * its own private key domain from these operands; this record alone does
 * not enable PAC. */
struct pauth_user_state {
    struct pauth_key_pair key[PAUTH_KEYS], extra;
    uint64_t apctl, reads, writes, written_mask, extra_writes;
    uint64_t last_reg, last_read;
};

#define PAUTH_SYSREG(op0,op1,crn,crm,op2) \
    (((uint64_t)(op0)<<20)|((uint64_t)(op1)<<14)|((uint64_t)(crn)<<10)| \
     ((uint64_t)(crm)<<1)|((uint64_t)(op2)<<17))

/* The pinned T8140 SPTM initializes both boot and secondary CPUs with this
 * operator sequence. It does not imply constant physical Apple PAC keys. */
void pauth_user_init(struct pauth_user_state *state);

/* Return 1 for a modeled register, 0 without mutation for other encodings.
 * reg is ESR's sysreg tuple with Rt and direction bits removed. */
int pauth_user_reg(struct pauth_user_state *state,uint64_t reg,int read,uint64_t *value);
