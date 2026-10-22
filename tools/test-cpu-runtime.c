/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "cpu-runtime.h"

int main(void)
{
    struct guest_cpu_storage plan[GUEST_CPU_COUNT],before[GUEST_CPU_COUNT];
    const uint64_t begin=UINT64_C(0xbb7b8000),span=4096+5*UINT64_C(0x12000);
    uint64_t end=0;
    assert(guest_cpu_storage_plan(begin,begin+span,plan,&end)==0);
    assert(end==begin+span);
    assert(plan[0].vncr==begin && !plan[0].output && !plan[0].stack_low && !plan[0].stack_high);
    uint64_t cursor=begin+4096;
    for (unsigned n=1;n<GUEST_CPU_COUNT;n++) {
        assert(plan[n].vncr==cursor);cursor+=4096;
        assert(plan[n].output==cursor);cursor+=4096;
        assert(plan[n].stack_low==cursor);cursor+=65536;
        assert(plan[n].stack_high==cursor);
    }
    assert(cursor==end);
    memcpy(before,plan,sizeof(plan));
    const uint64_t bad[][2]={{0,0x100000},{begin+1,begin+span},{begin,begin+span-1},
        {begin,begin+span-4096},{begin,begin},{begin,begin-4096},
        {UINT64_MAX&~4095ULL,UINT64_MAX&~4095ULL}};
    for(unsigned n=0;n<sizeof(bad)/sizeof(*bad);n++) {
        assert(guest_cpu_storage_plan(bad[n][0],bad[n][1],plan,&end)!=0);
        assert(!memcmp(plan,before,sizeof(plan)) && end==begin+span);
    }
    assert(guest_cpu_storage_plan(begin,begin+span,NULL,&end)!=0);
    assert(guest_cpu_storage_plan(begin,begin+span,plan,NULL)!=0);
    puts("PASS: six private VNCR pages and five runtime banks; bounds, overflow and atomic failure");
}
