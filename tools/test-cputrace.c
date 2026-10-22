/* SPDX-License-Identifier: MIT */
#include "cputrace.h"
#include <stdio.h>
#include <stdlib.h>
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"line %d: %s\n",__LINE__,#x); exit(1); } } while(0)
int main(void)
{
    for (uint64_t ep=0;ep<256;ep++) {
        uint64_t value=0x123456789abcdef0UL;
        int handled=cputrace_empty_query(ep,&value);
        CHECK(handled==(ep==1 || ep==2));
        CHECK(value==(handled ? 0 : 0x123456789abcdef0UL));
    }
    const uint64_t endpoints[]={0x100000001UL,0x100000002UL,UINT64_MAX};
    for (unsigned i=0;i<3;i++) {
        uint64_t value=42;
        CHECK(!cputrace_empty_query(endpoints[i],&value) && value==42);
    }
    CHECK(!cputrace_empty_query(1,0));
    CHECK(!cputrace_empty_query(2,0));
    printf("PASS: %u CPUTRACE empty-reservation checks\n",checks);
}
