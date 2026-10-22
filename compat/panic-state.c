/* SPDX-License-Identifier: MIT */
#include "panic-state.h"

void sptm_panic_init(struct sptm_panic_state *s)
{
    s->triggered=0;s->owner=SPTM_PANIC_NO_OWNER;s->phase=0xff;
    s->entries=s->rejected=0;
    for(unsigned cpu=0;cpu<6;cpu++)s->cpu_entries[cpu]=0;
}
static int valid(const struct sptm_panic_state *s)
{
    return s && ((!s->triggered && s->owner==SPTM_PANIC_NO_OWNER && s->phase==0xff) ||
                 (s->triggered==1 && s->owner<6 && s->phase==1));
}
int sptm_panic_enter(struct sptm_panic_state *s,unsigned cpu)
{
    if(!valid(s) || cpu>=6 || s->entries==UINT64_MAX || s->cpu_entries[cpu]==UINT64_MAX)return 0;
    s->triggered=1;
    if(s->owner==SPTM_PANIC_NO_OWNER)s->owner=cpu;
    if(s->phase==0xff)s->phase=1;
    s->entries++;s->cpu_entries[cpu]++;
    return 1;
}
int sptm_panic_dispatch(struct sptm_panic_state *s,unsigned cpu,uint64_t x16)
{
    if(!valid(s) || cpu>=6)return 0;
    if(!s->triggered || x16==UINT64_C(0x0200000000000000))return 1;
    if(s->rejected!=UINT64_MAX)s->rejected++;
    return 0;
}
