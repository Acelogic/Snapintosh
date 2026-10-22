/* SPDX-License-Identifier: MIT
 * CPU0-only bounded EL2 integration probe. No guest, GPU, IRQ or PMU setup.
 * Failure inventory: docs/OPERATOR-STOP-CONTROLS-20261018.md. */
#include <stdint.h>
#include "early-stop.h"
#include "service-lock.h"
typedef uint64_t (*service_fn)(uint64_t,uint64_t,uint64_t,uint64_t);
struct report {
    uint64_t magic, status, hz, start, end, polls, delivered, stop_word;
    uint64_t local_mode, delayed_delivered, delayed_ticks, urgent_ticks;
    struct early_stop_state stop;
    struct guest_service_lock service;
};
static inline uint64_t ticks(void) { uint64_t v; __asm__ volatile("isb; mrs %0, cntpct_el0":"=r"(v));return v; }
__attribute__((section(".text.entry")))
uint64_t _start(struct report *r,service_fn call,uint64_t session,uint64_t local_mode) {
    /* Caller supplies zeroed output; all state is in that preserved work area. */
    uint64_t hz;__asm__ volatile("mrs %0, cntfrq_el0":"=r"(hz));
    r->magic=UINT64_C(0x31504f5453504f);r->status=1;r->hz=hz;r->local_mode=local_mode;
    if (!hz || !call || !session || local_mode>1) return 1;
    struct early_stop_params p={.flags=EARLY_STOP_F_ALL,.max_delay_s=3600,.session=session};
    if(guest_service_boot(&r->service)!=SERVICE_OK) return 2;
    if(call(EARLY_STOP_HOST_ARM,session,0,0)) return 3;
    r->start=ticks(); uint64_t budget=r->start+4*hz,next=r->start;
    early_stop_request(&r->stop,EARLY_STOP_SOURCE_GUEST,1,0,1700,1700,r->start,hz,0,0,0);
    for (;;) {
        uint64_t now=ticks();
        if ((int64_t)(now-budget)>=0) {r->status=4;break;}
        if ((int64_t)(now-next)>=0) {
            struct early_stop_host_request req;
            r->polls++;next=now+hz/50; /* 20 ms, production's minimum poll period. */
            uint64_t got=call(EARLY_STOP_HOST_POLL,(uint64_t)&req,sizeof req,0);
            if (got>1) {r->status=5;break;}
            if(local_mode && now-r->start>=hz/25) {
                req=(struct early_stop_host_request){.magic=EARLY_STOP_HOST_MAGIC,.session=session,.nonce=0x1234,.reason=1};got=1;
            }
            if(got) {
                uint64_t accepted;
                if(early_stop_host_admit(&p,&req,&accepted)) {r->status=6;break;}
                r->delivered++;
                if(accepted) {r->delayed_delivered++;r->delayed_ticks=now;} else r->urgent_ticks=now;
                if(early_stop_request(&r->stop,EARLY_STOP_SOURCE_HOST,req.reason,req.nonce,req.delay_s,accepted,now,hz,0,0,req.text)) {r->status=7;break;}
            }
        }
        if(early_stop_fire(&r->stop,ticks(),budget,0)) {
            guest_service_stop(&r->service,0,SERVICE_STOP_NORMAL);
            r->stop_word=guest_service_stopped(&r->service);
            early_stop_finish(&r->stop,r->stop_word);r->status=0;break;
        }
        __asm__ volatile("yield");
    }
    call(EARLY_STOP_HOST_DISARM,0,0,0);r->end=ticks();return r->status;
}
