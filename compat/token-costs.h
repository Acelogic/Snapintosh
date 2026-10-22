/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>
#include "service-profile.h"
/* SNAP_OTHER_PROFILE: SNAP_SERVICE_SUBCLASS's call_other bucket split by what
 * the native call was (docs/TOKEN-COSTS-20261018.md), and the report record
 * that carries it with the counters of compat/nest-fast.h and
 * compat/root-index.h. Opt-in, default 0; off, nothing changes.
 *
 * Why: in installed-fresh-20261018-v54 call_other held the token 60.8 s
 * (954,296 entries, 64 us each). It is every native call that is not an SPTM
 * endpoint below 32 -- TXM (domain 2, including the TXM35/36/37 address-space
 * calls), the DART table-3 calls (the Adreno map/unmap, 360,395 maps and
 * 20,461 unmaps in v54), the ANS SART/NVMe tables, UAT, cputrace -- and the
 * profile cannot tell them apart. The class is decided from x16 alone, the
 * same word monitor_call_impl dispatches on, at the place SNAP_SERVICE_
 * SUBCLASS tags the entry; runtime_leave charges the entry's wait and hold
 * to the class exactly when it charges them to call_other, so the classes sum
 * to the call_other bucket. */
#ifndef SNAP_OTHER_PROFILE
#define SNAP_OTHER_PROFILE 0
#endif
enum other_class {
    OTHER_TXM35, OTHER_TXM36, OTHER_TXM37, OTHER_TXM,        /* domain 2, table 0 */
    OTHER_DART_MAP_TABLE, OTHER_DART_MAP, OTHER_DART_UNMAP,  /* domain 0, table 3: 0, 2, 3 */
    OTHER_DART_ENABLE, OTHER_DART_CONTROL,                   /* 8; 5 and 6 */
    OTHER_ANS_SART, OTHER_ANS_NVME,                          /* tables 5, 6 */
    OTHER_UAT, OTHER_CPUTRACE,                               /* tables 7, 9 */
    OTHER_ENDPOINT_HIGH,                                     /* table 0, endpoint >= 32 */
    OTHER_DISPATCH,                                          /* a dispatch command other than 0 */
    OTHER_UNKNOWN,
    OTHER_CLASSES
};
_Static_assert(OTHER_CLASSES==16,"the report's other-call rows (tools/perf_counters.py OTHER_CLASSES)");
static inline unsigned other_profile_class(uint64_t x16)
{
    uint32_t cmd=(uint32_t)((x16>>56)&0xff),domain=(uint32_t)((x16>>48)&0xff);
    uint32_t table=(uint32_t)((x16>>32)&0xffff),endpoint=(uint32_t)x16;
    if(cmd)return OTHER_DISPATCH;
    if(domain==2 && !table)
        return endpoint==35 ? OTHER_TXM35 : endpoint==36 ? OTHER_TXM36 : endpoint==37 ? OTHER_TXM37 : OTHER_TXM;
    if(domain)return OTHER_UNKNOWN;
    switch(table) {
    case 0: return endpoint>=32 ? OTHER_ENDPOINT_HIGH : OTHER_UNKNOWN;
    case 3: return endpoint==0 ? OTHER_DART_MAP_TABLE : endpoint==2 ? OTHER_DART_MAP :
                   endpoint==3 ? OTHER_DART_UNMAP : endpoint==8 ? OTHER_DART_ENABLE :
                   endpoint==5 || endpoint==6 ? OTHER_DART_CONTROL : OTHER_UNKNOWN;
    case 5: return OTHER_ANS_SART;
    case 6: return OTHER_ANS_NVME;
    case 7: return OTHER_UAT;
    case 9: return OTHER_CPUTRACE;
    default: return OTHER_UNKNOWN;
    }
}
struct other_profile {
    struct service_profile_bucket buckets[OTHER_CLASSES];
    uint8_t current[SERVICE_SUB_CPUS];   /* per CPU: its entry's class so far */
} __attribute__((aligned(64)));
static inline void other_profile_tag(struct other_profile *o,unsigned cpu,uint64_t x16)
{
    if(cpu<SERVICE_SUB_CPUS)o->current[cpu]=(uint8_t)other_profile_class(x16);
}
/* After service_sub_charge, with the sub-class tag it cleared: charge the
 * entry exactly when that charge went to call_other. */
static inline void other_profile_charge(struct other_profile *o,unsigned cpu,
    const struct service_profile *p,int completed,unsigned sub)
{
    if(cpu>=SERVICE_SUB_CPUS)return;
    unsigned cls=o->current[cpu];
    o->current[cpu]=OTHER_UNKNOWN;
    if(!completed || sub!=SERVICE_SUB_CALL_OTHER || p->category!=SERVICE_SUB_CATEGORY || p->stage ||
       cls>=OTHER_CLASSES)return;
    struct service_profile_bucket *b=&o->buckets[cls];
    b->entries++;
    b->wait_ticks+=p->acquire_tick-p->enter_tick;
    b->hold_ticks+=p->last_tick-p->acquire_tick;
}
/* report.bin: behind "TOKCOST1" and a word of define bits (SNAP_NEST_FAST,
 * SNAP_DETACH_FAST, SNAP_ROOT_INDEX, SNAP_OTHER_PROFILE, SNAP_GATE_WAIT
 * in bits 0..4; SNAP_PHASE_FAIR_GATE in bit 5, with gate[4..6]: converted
 * calls that entered ahead of a queued writer, token drains that waited and
 * their ticks) | payload bytes << 32, after the fine profile (or the exit
 * profile without SNAP_FINE_LOCKS). A part whose define is off is zero. */
#define TOKEN_COSTS_MAGIC UINT64_C(0x3154534f434b4f54)   /* "TOKCOST1" */
struct token_costs_report {
    uint64_t nest[16];                    /* struct sptm_nest_fast_stats */
    uint64_t index[16];                   /* struct sptm_root_index_stats */
    struct service_profile_bucket other[OTHER_CLASSES];
    uint64_t gate[16];                    /* SNAP_GATE_WAIT counters (4..6: SNAP_PHASE_FAIR_GATE) */
};
_Static_assert(sizeof(struct token_costs_report)==96*8 &&
               __builtin_offsetof(struct token_costs_report,index)==16*8 &&
               __builtin_offsetof(struct token_costs_report,other)==32*8 &&
               __builtin_offsetof(struct token_costs_report,gate)==80*8,
               "token costs record (probes/xnuboot.c writes it word by word, tools/perf_counters.py)");
