/* SPDX-License-Identifier: MIT */
#include "cpu-release.h"
#include <assert.h>
#include <stdio.h>
struct fake { unsigned calls,slot;int accept; };
static int launch(void *p,unsigned slot)
{
    struct fake *f=p;f->calls++;f->slot=slot;return f->accept;
}
int main(void)
{
    struct guest_cpu_release s={0};struct fake f={.accept=1};
    assert(!guest_cpu_release_write(&s,2,8,4,2,launch,&f));assert(!f.calls);
    assert(guest_cpu_release_write(&s,2,4,4,2,launch,&f));
    assert(s.armed==2 && !s.issued && !f.calls);
    assert(guest_cpu_release_write(&s,2,8,4,2,launch,&f));
    assert(s.issued==2 && f.calls==1 && f.slot==1);
    assert(!guest_cpu_release_write(&s,2,8,4,2,launch,&f));assert(f.calls==1);
    assert(guest_cpu_release_write(&s,2,12,4,0,launch,&f));assert(f.calls==1);
    for (unsigned offset=0;offset<16;offset++) {
        struct guest_cpu_release before=s;
        if (offset!=4) assert(!guest_cpu_release_write(&s,2,offset,4,2,launch,&f));
        assert(s.armed==before.armed && s.issued==before.issued);
    }
    for (unsigned width=0;width<9;width++) if (width!=4)
        assert(!guest_cpu_release_write(&s,2,4,width,2,launch,&f));
    for (unsigned value=1;value<16;value++) if (value!=2)
        assert(!guest_cpu_release_write(&s,2,4,4,value,launch,&f));
    s.issued=0;f.accept=0;
    assert(!guest_cpu_release_write(&s,2,8,4,2,launch,&f));assert(!s.issued);
    s.armed=0;s.issued=2;
    assert(!guest_cpu_release_write(&s,2,4,4,2,launch,&f));
    assert(!guest_cpu_release_write(0,2,4,4,2,launch,&f));
    /* Both P-local bits must target the correct global slots, even with all
     * E cores admitted. Test refusal before arm, wrong-cluster writes,
     * duplicate submission and backend failure without dropping the arm. */
    for (unsigned slot=1;slot<6;slot++) {
        uint64_t global=1UL<<slot,local=1UL<<(slot<4 ? slot : slot-4);
        unsigned cluster=slot<4 ? 8 : 12;
        s=(struct guest_cpu_release){0};f=(struct fake){.accept=1};
        assert(!guest_cpu_release_write(&s,0x3e,cluster,4,local,launch,&f));
        assert(!f.calls && !s.armed && !s.issued);
        assert(guest_cpu_release_write(&s,0x3e,4,4,global,launch,&f));
        assert(!f.calls && s.armed==global && !s.issued);
        assert(!guest_cpu_release_write(&s,0x3e,cluster==8 ? 12 : 8,4,local,launch,&f));
        assert(!f.calls && !s.issued);
        f.accept=0;
        assert(!guest_cpu_release_write(&s,0x3e,cluster,4,local,launch,&f));
        assert(f.slot==slot && s.armed==global && !s.issued);
        f.accept=1;
        assert(guest_cpu_release_write(&s,0x3e,cluster,4,local,launch,&f));
        assert(f.slot==slot && f.calls==2 && s.issued==global);
        assert(!guest_cpu_release_write(&s,0x3e,cluster,4,local,launch,&f));
        assert(f.calls==2);
    }
    for (unsigned offset=4;offset<=12;offset+=4)
        for (unsigned bit=0;bit<64;bit++) {
            uint64_t value=1UL<<bit;
            int admitted=offset==4 ? (bit>=1 && bit<=5) :
                         offset==8 ? (bit>=1 && bit<=3) : bit<=1;
            s=(struct guest_cpu_release){.armed=0x3e}; f=(struct fake){.accept=1};
            int got=guest_cpu_release_write(&s,0x3e,offset,4,value,launch,&f);
            assert(got==admitted);
            if (!got) assert(s.armed==0x3e && !s.issued && !f.calls);
        }
    puts("PASS: E/P-local release mapping, no premature CPU_ON, refusal atomicity, no duplicate launch");
}
