/* SPDX-License-Identifier: MIT
 * Bounded CPU0 EL2 integration, no guest/GPU/PMU or sensor writes.
 * Failure inventory: docs/A16-THERMAL-GUARD-20261018.md. */
#include <stdint.h>
#include "a16-thermal.h"
#include "early-stop.h"
#include "service-lock.h"
struct report {
    uint64_t magic,status,hz,start,end,mode,local,stop_word,first_valid_count,healthy_polls;
    struct a16_thermal_state thermal;
    struct early_stop_state stop;
    struct guest_service_lock service;
};
_Static_assert(sizeof(struct report)<=4096,"probe report reservation");
struct bus {struct report *report;const uint32_t *fixture;};
static uint64_t counter(void *ctx) {
    (void)ctx;uint64_t now;__asm__ volatile("isb; mrs %0,cntpct_el0":"=r"(now)::"memory");return now;
}
static int read_word(void *ctx,uint64_t address,uint32_t *value) {
    struct bus *b=ctx;struct report *r=b->report;
    if(!a16_thermal_address_allowed(address))return -1;
    if(b->fixture) {
        int found=0;
        for(unsigned i=0;i<8;i++) {
            uint64_t sr=0xc222000+0x1000*i,tm=0xc22c000+0x1000*i;unsigned off;
            if(address==sr)off=0;
            else if(address==sr+4)off=1;
            else if(address==tm+0xe4)off=2;
            else if(address>=tm+0xa0 && address<tm+0xe0)off=3+(unsigned)(address-tm-0xa0)/4;
            else continue;
            *value=b->fixture[i*19+off];found=1;break;
        }
        if(!found)return -1;
    } else {
        *value=*(const volatile uint32_t *)address;
        __asm__ volatile("dsb sy" ::: "memory");
    }
    /* Inject only into the returned value, after one unmodified sample. */
    if(address==0xc22c0a0 && r->thermal.polls>1) {
        if(r->mode==1)*value=(1u<<21)|600u;
        if(r->mode==2)*value &= ~(1u<<21);
    }
    return 0;
}
__attribute__((section(".text.entry")))
uint64_t _start(struct report *r,const uint32_t *fixture,uint64_t mode,uint64_t unused) {
    (void)unused;r->magic=UINT64_C(0x31505248543641);r->status=1;r->mode=mode;r->local=!!fixture;
    __asm__ volatile("mrs %0,cntfrq_el0":"=r"(r->hz));
    if(mode>2 || !r->hz || (!fixture && r->hz!=19200000))return 1;
    if(guest_service_boot(&r->service)!=SERVICE_OK)return 2;
    r->start=counter(0);uint64_t budget=r->start+4*r->hz;
    early_stop_request(&r->stop,EARLY_STOP_SOURCE_GUEST,1,0,1700,1700,r->start,r->hz,0,0,0);
    struct bus bus={r,fixture};const struct a16_thermal_io io={&bus,read_word,counter};
    for(;;) {
        uint64_t now=counter(0);
        if(now-r->start>=4*r->hz){r->status=3;break;}
        uint64_t polls=r->thermal.polls;
        int trip=a16_thermal_poll(&r->thermal,&r->stop,now,r->hz,&io);
        if(r->thermal.polls!=polls) {
            if(!polls)r->first_valid_count=r->thermal.valid_count;
            if(r->thermal.ready)r->healthy_polls++;
        }
        if(trip) {
            if(!early_stop_fire(&r->stop,counter(0),budget,0)){r->status=4;break;}
            guest_service_stop(&r->service,0,SERVICE_STOP_NORMAL);
            r->stop_word=guest_service_stopped(&r->service);
            early_stop_finish(&r->stop,r->stop_word);r->status=0;break;
        }
        if(!mode && now-r->start>=2*r->hz) {
            guest_service_stop(&r->service,0,SERVICE_STOP_NORMAL);
            r->stop_word=guest_service_stopped(&r->service);r->status=0;break;
        }
        __asm__ volatile("yield");
    }
    r->end=counter(0);return r->status;
}
