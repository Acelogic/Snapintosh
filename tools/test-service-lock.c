/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdint.h>
#include "service-lock.h"

static struct guest_service_lock lock;
static uint64_t counter, complement = UINT64_MAX;
static unsigned visits[GUEST_CPU_COUNT];

static void *worker(void *opaque)
{
    unsigned cpu = (unsigned)(uintptr_t)opaque;
    for (unsigned i=0; i<20000; i++) {
        enum guest_service_result result;
        while ((result=guest_service_try(&lock,cpu)) == SERVICE_BUSY) sched_yield();
        assert(result == SERVICE_OK);
        assert(guest_service_owner(&lock) == cpu+1);
        assert(complement == ~counter);
        counter++;
        complement = ~counter;
        visits[cpu]++;
        assert(guest_service_release(&lock,cpu) == SERVICE_OK);
    }
    return NULL;
}

int main(void)
{
    for(unsigned wrap=0;wrap<2;wrap++) {
        uint64_t base=wrap ? UINT64_MAX-100:0;
        assert(guest_service_wait_expiry(base+49,base+100,1,base+50)==SERVICE_BUSY);
        assert(guest_service_wait_expiry(base+50,base+100,1,base+50)==SERVICE_STOPPED);
        assert(guest_service_wait_expiry(base+101,base+100,1,base+50)==SERVICE_STOPPED);
        assert(guest_service_wait_expiry(base+100,base+100,1,base+150)==SERVICE_TIMEOUT);
        assert(guest_service_wait_expiry(base+151,base+100,1,base+150)==SERVICE_TIMEOUT);
        assert(guest_service_wait_expiry(base+100,base+100,0,base+50)==SERVICE_TIMEOUT);
        assert(guest_service_wait_expiry(base+100,base+100,1,base+100)==SERVICE_STOPPED);
    }
    struct guest_service_lock sample = {0};
    assert(sizeof(sample)==64 && _Alignof(struct guest_service_lock)==64);
    assert(guest_service_try(&sample,0)==SERVICE_BAD_STATE);
    assert(guest_service_boot(&sample)==SERVICE_OK);
    assert(guest_service_try(NULL,0)==SERVICE_BAD_CPU);
    assert(guest_service_try(&sample,6)==SERVICE_BAD_CPU);
    assert(guest_service_release(&sample,6)==SERVICE_BAD_CPU);
    assert(guest_service_try(&sample,0)==SERVICE_OK);
    assert(guest_service_try(&sample,0)==SERVICE_REENTRY);
    assert(guest_service_try(&sample,1)==SERVICE_BAD_STATE);
    assert(guest_service_reserve(&sample,0,1)==SERVICE_OK);
    assert(guest_service_arrive(&sample,1)==SERVICE_OK);
    assert(guest_service_try(&sample,1)==SERVICE_BUSY);
    assert(guest_service_release(&sample,1)==SERVICE_BAD_OWNER);
    assert(guest_service_owner(&sample)==1);
    guest_service_stop(&sample,1,SERVICE_STOP_FAULT);
    uint64_t first = ((uint64_t)SERVICE_STOP_FAULT<<32) | 2;
    assert(guest_service_stopped(&sample)==first);
    assert(guest_service_owner(&sample)==1);
    guest_service_stop(&sample,0,SERVICE_STOP_NORMAL);
    assert(guest_service_stopped(&sample)==first);
    assert(guest_service_try(&sample,2)==SERVICE_STOPPED);
    assert(guest_service_release(&sample,0)==SERVICE_OK);
    assert(!guest_service_owner(&sample));
    assert(guest_service_try(&sample,0)==SERVICE_STOPPED);
    sample=(struct guest_service_lock){.owner=7,.lifecycle=EXECUTOR_RUNNING};
    assert(guest_service_try(&sample,0)==SERVICE_BAD_OWNER);
    assert(guest_service_release(&sample,0)==SERVICE_BAD_OWNER);
    assert(guest_service_owner(&sample)==7);
    assert(guest_service_boot(&lock)==SERVICE_OK);
    assert(guest_service_try(&lock,0)==SERVICE_OK);
    for (unsigned cpu=1; cpu<GUEST_CPU_COUNT; cpu++)
        assert(guest_service_reserve(&lock,0,cpu)==SERVICE_OK);
    assert(guest_service_release(&lock,0)==SERVICE_OK);
    for (unsigned cpu=1; cpu<GUEST_CPU_COUNT; cpu++)
        assert(guest_service_arrive(&lock,cpu)==SERVICE_OK);
    pthread_t threads[GUEST_CPU_COUNT];
    for (unsigned cpu=0; cpu<GUEST_CPU_COUNT; cpu++)
        assert(!pthread_create(&threads[cpu],NULL,worker,(void *)(uintptr_t)cpu));
    for (unsigned cpu=0; cpu<GUEST_CPU_COUNT; cpu++) {
        assert(!pthread_join(threads[cpu],NULL));
        assert(visits[cpu]==20000);
    }
    assert(counter==120000 && complement==~counter);
    assert(!guest_service_owner(&lock) && !guest_service_stopped(&lock));
    assert(!guest_service_reusable(&lock));
    guest_service_stop(&lock,0,SERVICE_STOP_NORMAL);
    for (unsigned cpu=0; cpu<GUEST_CPU_COUNT; cpu++)
        assert(guest_service_quiesce(&lock,cpu)==SERVICE_OK);
    assert(!guest_service_reusable(&lock));
    for (unsigned cpu=1; cpu<GUEST_CPU_COUNT; cpu++)
        assert(guest_service_confirm_off(&lock,0,cpu,1)==SERVICE_OK);
    assert(guest_service_reusable(&lock));
    puts("PASS: ownership, sticky stop, refusal cases and 120000 six-thread critical sections");
}
