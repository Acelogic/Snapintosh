/* SPDX-License-Identifier: MIT */
#include "a16-thermal.h"
#include "early-stop.h"
_Static_assert(sizeof(struct a16_thermal_state)==A16_THERMAL_REPORT_WORDS*8,"thermal report ABI");
_Static_assert(sizeof(struct a16_thermal_state)<=4096,"one monitor-only page");
static unsigned sensors(unsigned b) {return b==1?9:b==3||b==5?8:b==7?15:13;}
static uint64_t tm(unsigned b) {return UINT64_C(0x0c22c000)+b*0x1000;}
static uint64_t srot(unsigned b) {return UINT64_C(0x0c222000)+b*0x1000;}
int a16_thermal_address_allowed(uint64_t address) {
    for(unsigned b=0;b<8;b++)
        if(address==srot(b) || address==srot(b)+4 || address==tm(b)+0xe4 ||
           (address>=tm(b)+0xa0 && address<tm(b)+0xe0 && !(address&3)))return 1;
    return 0;
}
uint64_t a16_thermal_wait(const struct a16_thermal_state *s,uint64_t now,uint64_t hz,uint64_t limit) {
    if(!s || !s->magic || s->reason || hz<1000 || hz>1000000000)return 0;
    uint64_t wait=(int64_t)(s->next_poll-now)>0?s->next_poll-now:0;
    return wait<limit?wait:limit;
}
static int trip(struct a16_thermal_state *s,struct early_stop_state *stop,unsigned why,uint64_t where,uint64_t now,uint64_t hz) {
    if(!s->reason) {
        s->reason=why;s->location=where;s->trip_ticks=now;s->ready=0;
        early_stop_request(stop,EARLY_STOP_SOURCE_THERMAL,why,where,0,0,now,hz,0,0,0);
    }
    return 1;
}
static int read_word(struct a16_thermal_state *s,const struct a16_thermal_io *io,uint64_t address,uint32_t *value) {
    s->location=address;s->reads++;s->read_inflight=1;
    __asm__ volatile("" ::: "memory");
    if(!a16_thermal_address_allowed(address) || io->read32(io->ctx,address,value)) {s->read_failures++;return -1;}
    __asm__ volatile("" ::: "memory");
    s->read_inflight=0;return 0;
}
int a16_thermal_poll(struct a16_thermal_state *s,struct early_stop_state *stop,uint64_t now,uint64_t hz,const struct a16_thermal_io *io) {
    if(!s->magic) {
        s->magic=A16_THERMAL_MAGIC;s->abi=A16_THERMAL_ABI;s->bytes=sizeof(*s);
        s->started=s->last_change=now;s->current_mc=s->peak_mc=INT64_MIN;
    }
    if(s->reason)return 1; /* immutable trip, no more MMIO */
    if(s->magic!=A16_THERMAL_MAGIC || s->abi!=A16_THERMAL_ABI || s->bytes!=sizeof(*s) || !io || !io->read32 || !io->counter)
        return trip(s,stop,A16_THERMAL_CONFIG,0,now,hz);
    if(hz<1000 || hz>1000000000)return trip(s,stop,A16_THERMAL_CLOCK,0,now,hz);
    if(s->polls) {
        uint64_t gap=now-s->last_poll;
        if(gap>s->max_gap_ticks)s->max_gap_ticks=gap;
        if(gap>=hz)return trip(s,stop,A16_THERMAL_LATE,0,now,hz);
        if((int64_t)(now-s->next_poll)<0)return 0;
    }
    s->polls++;s->last_poll=now;s->next_poll=now+hz/4;
    s->valid_count=0;s->missing_count=0;s->current_mc=INT64_MIN;s->ready=0;
    for(unsigned b=0;b<8;b++) {
        uint32_t v;unsigned count=sensors(b);uint64_t mask=(UINT64_C(1)<<count)-1;
        if(read_word(s,io,srot(b),&v))return trip(s,stop,A16_THERMAL_READ,s->location,now,hz);
        s->version[b]=v;
        if(v!=0x30020000)return trip(s,stop,A16_THERMAL_CONFIG,srot(b),now,hz);
        if(read_word(s,io,srot(b)+4,&v))return trip(s,stop,A16_THERMAL_READ,s->location,now,hz);
        s->control[b]=v;
        if(!(v&1) || (v&2) || !(v&(1u<<21)) || ((v>>3)&0xffff)!=mask)
            return trip(s,stop,A16_THERMAL_CONFIG,srot(b)+4,now,hz);
        if(read_word(s,io,tm(b)+0xe4,&v))return trip(s,stop,A16_THERMAL_READ,s->location,now,hz);
        s->trdy[b]=v;s->valid_mask[b]=0;
        for(unsigned n=0;n<count;n++) {
            unsigned slot=b*16+n;uint64_t address=tm(b)+0xa0+4*n;
            if(read_word(s,io,address,&v))return trip(s,stop,A16_THERMAL_READ,address,now,hz);
            uint64_t previous=s->raw[slot];s->raw[slot]=v;
            if(v&(1u<<19))return trip(s,stop,A16_THERMAL_CRITICAL,address,now,hz);
            if(!(v&(1u<<21))) {
                s->missing_count++;s->invalid_samples++;
                uint64_t since=s->seen_mask[b]&(UINT64_C(1)<<n)?s->last_valid[slot]:s->started;
                if(now-since>=hz)return trip(s,stop,A16_THERMAL_INVALID,address,now,hz);
                continue;
            }
            int32_t code=(int32_t)(v&0xfff);if(code&0x800)code-=4096;
            int64_t mc=code*100;
            if(mc < -40000 || mc > 120000)return trip(s,stop,A16_THERMAL_RANGE,address,now,hz);
            if(mc>s->current_mc)s->current_mc=mc;
            if(mc>s->peak_mc)s->peak_mc=mc;
            s->valid_count++;s->valid_mask[b]|=UINT64_C(1)<<n;
            if(!(s->seen_mask[b]&(UINT64_C(1)<<n)) || (v&0xfff)!=(previous&0xfff))s->last_change=now;
            s->seen_mask[b]|=UINT64_C(1)<<n;s->last_valid[slot]=now;
            if(mc>=A16_THERMAL_LIMIT_MC)return trip(s,stop,A16_THERMAL_HOT,address,now,hz);
        }
    }
    uint64_t done=io->counter(io->ctx);s->poll_ticks=done-now;
    if(s->poll_ticks>s->max_poll_ticks)s->max_poll_ticks=s->poll_ticks;
    if(s->poll_ticks>=hz/4)return trip(s,stop,A16_THERMAL_SLOW,0,done,hz);
    s->unchanged_ticks=done-s->last_change;
    if(s->unchanged_ticks>=10*hz)return trip(s,stop,A16_THERMAL_UNCHANGED,0,done,hz);
    s->location=0;s->ready=s->valid_count==92;return 0;
}
/* Initial admission resamples a brief VALID clear instead of refusing on it.
 * Each attempt is the full poll, so any trip ends the wait; sensors are never
 * merged across samples. A counter that never advances ends at the sample bound. */
int a16_thermal_admit(struct a16_thermal_state *s,struct early_stop_state *stop,uint64_t hz,const struct a16_thermal_io *io) {
    if(!io || !io->counter)return a16_thermal_poll(s,stop,0,hz,io)?1:-1;
    uint64_t start=io->counter(io->ctx);
    for(unsigned n=0;n<A16_THERMAL_ADMIT_SAMPLES;n++) {
        uint64_t now=io->counter(io->ctx);
        if(n) {
            if(now-start>=hz/2)break;
            s->next_poll=now;
        }
        if(a16_thermal_poll(s,stop,now,hz,io))return 1;
        if(s->ready)return 0;
        for(uint64_t spin=0;spin<hz/100 && io->counter(io->ctx)-now<hz/100;spin++);
    }
    return -1;
}
