/* SPDX-License-Identifier: MIT */
#include "cpu-runtime.h"

int guest_cpu_storage_plan(uint64_t begin, uint64_t limit,
    struct guest_cpu_storage out[GUEST_CPU_COUNT], uint64_t *end)
{
    const uint64_t stride=2*GUEST_RUNTIME_PAGE+GUEST_RUNTIME_STACK;
    const uint64_t span=GUEST_RUNTIME_PAGE+(GUEST_CPU_COUNT-1)*stride;
    if (!out || !end || !begin || begin&(GUEST_RUNTIME_PAGE-1) ||
            limit&(GUEST_RUNTIME_PAGE-1) || begin>limit || span>limit-begin)
        return -1;
    out[0]=(struct guest_cpu_storage){begin,0,0,0};
    for (unsigned n=1; n<GUEST_CPU_COUNT; n++) {
        uint64_t base=begin+GUEST_RUNTIME_PAGE+(n-1)*stride;
        out[n]=(struct guest_cpu_storage){base,base+GUEST_RUNTIME_PAGE,
            base+2*GUEST_RUNTIME_PAGE,base+stride};
    }
    *end=begin+span;
    return 0;
}
