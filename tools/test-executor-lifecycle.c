/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include "service-lock.h"

static struct guest_service_lock fresh(void)
{
    struct guest_service_lock lock={0};
    assert(!guest_service_reusable(&lock));
    assert(guest_service_boot(&lock)==SERVICE_OK);
    assert(guest_service_boot(&lock)==SERVICE_BAD_STATE);
    assert(guest_service_try(&lock,0)==SERVICE_OK);
    return lock;
}
struct racing_stop { struct guest_service_lock *lock; unsigned ready; };
static void *stop_thread(void *opaque)
{
    struct racing_stop *r=opaque;
    __atomic_store_n(&r->ready,1,__ATOMIC_RELEASE);
    guest_service_stop(r->lock,0,SERVICE_STOP_NORMAL);
    return NULL;
}
int main(void)
{
    struct guest_service_lock aborted=fresh();
    assert(guest_service_finish(&aborted,0)==SERVICE_ABORTED);
    assert(guest_service_stopped(&aborted)==((UINT64_C(2)<<32)|1));
    assert(guest_service_reusable(&aborted));
    assert(guest_service_finish(&aborted,0)==SERVICE_OK);
    struct guest_service_lock peer=fresh();
    assert(guest_service_reserve(&peer,0,1)==SERVICE_OK);
    assert(guest_service_release(&peer,0)==SERVICE_OK);
    assert(guest_service_arrive(&peer,1)==SERVICE_OK);
    assert(guest_service_try(&peer,1)==SERVICE_OK);
    assert(guest_service_finish(&peer,0)==SERVICE_OK);
    assert(guest_service_owner(&peer)==2); /* Never steal another executor. */
    assert(!guest_service_reusable(&peer));
    assert(guest_service_finish(&peer,1)==SERVICE_ABORTED);
    assert(!guest_service_reusable(&peer));
    assert(guest_service_confirm_off(&peer,0,1,1)==SERVICE_OK);
    assert(guest_service_reusable(&peer));
    for (unsigned cpu=1; cpu<GUEST_CPU_COUNT; cpu++) {
        struct guest_service_lock lock=fresh();
        assert(guest_service_reserve(&lock,0,cpu)==SERVICE_OK);
        assert(guest_service_reserve(&lock,0,cpu)==SERVICE_BAD_STATE);
        assert(guest_service_quiesce(&lock,0)==SERVICE_BAD_OWNER);
        guest_service_stop(&lock,0,SERVICE_STOP_NORMAL);
        assert(guest_service_release(&lock,0)==SERVICE_OK);
        assert(guest_service_quiesce(&lock,0)==SERVICE_OK);
        assert(!guest_service_reusable(&lock)); /* reservation survives stop */
        assert(guest_service_confirm_off(&lock,0,cpu,1)==SERVICE_BAD_STATE);
        const int64_t uncertain[]={0,-4,-5,-6,-99};
        for (unsigned i=0; i<sizeof(uncertain)/sizeof(*uncertain); i++)
            assert(guest_service_cancel_launch(&lock,0,cpu,uncertain[i],1)==SERVICE_BAD_STATE);
        assert(guest_service_arrive(&lock,cpu)==SERVICE_STOPPED);
        assert(guest_service_try(&lock,cpu)==SERVICE_STOPPED);
        assert(guest_service_cancel_launch(&lock,0,cpu,-2,1)==SERVICE_BAD_STATE);
        assert(guest_service_quiesce(&lock,cpu)==SERVICE_OK);
        assert(!guest_service_reusable(&lock)); /* quiesced is not OFF */
        for (int64_t info=-1; info<=2; info++)
            if(info!=1)assert(guest_service_confirm_off(&lock,0,cpu,info)==SERVICE_BAD_STATE);
        assert(guest_service_confirm_off(&lock,cpu,cpu,1)==SERVICE_BAD_CPU);
        assert(guest_service_confirm_off(&lock,0,cpu,1)==SERVICE_OK);
        assert(guest_service_reusable(&lock));
    }
    const int64_t refused[]={-1,-2,-3,-9};
    for (unsigned i=0; i<sizeof(refused)/sizeof(*refused); i++) {
        struct guest_service_lock lock=fresh();
        assert(guest_service_reserve(&lock,0,1)==SERVICE_OK);
        guest_service_stop(&lock,0,SERVICE_STOP_NORMAL);
        assert(guest_service_release(&lock,0)==SERVICE_OK);
        assert(guest_service_quiesce(&lock,0)==SERVICE_OK);
        assert(guest_service_cancel_launch(&lock,0,1,refused[i],0)==SERVICE_BAD_STATE);
        assert(guest_service_cancel_launch(&lock,0,1,refused[i],1)==SERVICE_OK);
        assert(guest_service_reusable(&lock));
    }
    unsigned reserved=0, refused_race=0;
    /* XNU can ask any initialized CPU to bring another CPU online. Preserve
     * token ownership, reservations and physical OFF requirements throughout. */
    for (unsigned caller=1;caller<GUEST_CPU_COUNT;caller++)
        for (unsigned target=1;target<GUEST_CPU_COUNT;target++) if (target!=caller) {
            struct guest_service_lock lock=fresh();
            assert(guest_service_reserve(&lock,0,caller)==SERVICE_OK);
            assert(guest_service_release(&lock,0)==SERVICE_OK);
            assert(guest_service_arrive(&lock,caller)==SERVICE_OK);
            assert(guest_service_try(&lock,caller)==SERVICE_OK);
            assert(guest_service_reserve(&lock,0,target)==SERVICE_BAD_OWNER);
            assert(guest_service_reserve(&lock,caller,target)==SERVICE_OK);
            uint64_t life=guest_service_lifecycle(&lock);
            assert(guest_service_reserve(&lock,caller,target)==SERVICE_BAD_STATE);
            const int64_t uncertain[]={0,-4,-5,-6,-99};
            for (unsigned i=0;i<sizeof(uncertain)/sizeof(*uncertain);i++) {
                assert(guest_service_cancel_launch(&lock,caller,target,uncertain[i],1)==SERVICE_BAD_STATE);
                assert(guest_service_lifecycle(&lock)==life);
            }
            assert(guest_service_cancel_launch(&lock,caller,target,-2,0)==SERVICE_BAD_STATE);
            assert(guest_service_release(&lock,caller)==SERVICE_OK);
            assert(guest_service_cancel_launch(&lock,caller,target,-2,1)==SERVICE_BAD_OWNER);
            assert(guest_service_lifecycle(&lock)==life);
            assert(guest_service_try(&lock,caller)==SERVICE_OK);
            assert(guest_service_cancel_launch(&lock,caller,target,-2,1)==SERVICE_OK);
            assert(guest_service_reserve(&lock,caller,target)==SERVICE_OK);
            assert(guest_service_release(&lock,caller)==SERVICE_OK);
            assert(guest_service_arrive(&lock,target)==SERVICE_OK);
            assert(guest_service_try(&lock,caller)==SERVICE_OK);
            assert(guest_service_cancel_launch(&lock,caller,target,-2,1)==SERVICE_BAD_STATE);
            guest_service_stop(&lock,caller,SERVICE_STOP_NORMAL);
            assert(guest_service_release(&lock,caller)==SERVICE_OK);
            assert(guest_service_finish(&lock,caller)==SERVICE_OK);
            assert(guest_service_finish(&lock,target)==SERVICE_OK);
            assert(guest_service_finish(&lock,0)==SERVICE_OK);
            assert(!guest_service_reusable(&lock));
            assert(guest_service_confirm_off(&lock,caller,target,1)==SERVICE_BAD_CPU);
            assert(guest_service_confirm_off(&lock,0,target,1)==SERVICE_OK);
            assert(guest_service_confirm_off(&lock,0,caller,1)==SERVICE_OK);
            assert(guest_service_reusable(&lock));
        }
    for (unsigned iteration=0; iteration<1000; iteration++) {
        struct guest_service_lock lock=fresh();
        struct racing_stop race={.lock=&lock};
        pthread_t thread;
        assert(!pthread_create(&thread,NULL,stop_thread,&race));
        while(!__atomic_load_n(&race.ready,__ATOMIC_ACQUIRE))sched_yield();
        enum guest_service_result result=guest_service_reserve(&lock,0,1);
        assert(!pthread_join(thread,NULL));
        assert(guest_service_release(&lock,0)==SERVICE_OK);
        assert(guest_service_quiesce(&lock,0)==SERVICE_OK);
        if(result==SERVICE_OK) {
            reserved++;
            assert(!guest_service_reusable(&lock));
            assert(guest_service_arrive(&lock,1)==SERVICE_STOPPED);
            assert(guest_service_quiesce(&lock,1)==SERVICE_OK);
            assert(!guest_service_reusable(&lock));
            assert(guest_service_confirm_off(&lock,0,1,1)==SERVICE_OK);
        } else { assert(result==SERVICE_STOPPED);refused_race++; }
        assert(guest_service_reusable(&lock));
    }
    struct guest_service_lock empty={0};
    assert(guest_service_finish(&empty,0)==SERVICE_OK);
    assert(guest_service_boot(&empty)==SERVICE_BAD_STATE);
    assert(guest_service_reusable(&empty)); /* setup failed before any executor */
    empty.lifecycle|=UINT64_C(4)<<3;
    assert(!guest_service_reusable(&empty));
    printf("PASS: lifecycle, late arrival, OFF confirmation, cancellation and 1000 stop/launch races (%u reserved, %u refused)\n",reserved,refused_race);
}
