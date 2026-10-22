/* SPDX-License-Identifier: MIT */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../compat/cpu.h"

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr,"line %d: %s\n",__LINE__,#x); exit(1); } } while (0)
static const uint64_t pa=UINT64_C(0x8cec80000),va=UINT64_C(0xfffffe010ec80000);
static const uint64_t low=UINT64_C(0x8c0000000),high=UINT64_C(0xac0000000);
static const uint64_t affinity[6]={0,1,2,3,0x100,0x101};

int main(void)
{
    struct guest_cpu_registry cpus={0};
    uint64_t slot=99;
    struct guest_cpu_buffer buffer={11,22};
    CHECK(guest_cpu_buffers_valid(pa,va,low,high));
    CHECK(guest_cpu_id(&cpus,0,&slot)==CPU_NOT_REGISTERED && slot==99);
    CHECK(guest_cpu_output(&cpus,0,pa,va,low,high,&buffer)==CPU_NOT_REGISTERED);
    CHECK(buffer.pa==11 && buffer.va==22 && !cpus.output_queries);
    for(unsigned i=0;i<6;i++) {
        CHECK(guest_cpu_register(&cpus,affinity[i])==CPU_OK);
        CHECK(cpus.registered==((UINT64_C(1)<<(i+1))-1));
        CHECK(guest_cpu_id(&cpus,affinity[i],&slot)==CPU_OK && slot==i);
        CHECK(guest_cpu_output(&cpus,slot,pa,va,low,high,&buffer)==CPU_OK);
        CHECK(buffer.pa==pa+i*GUEST_CPU_SCRATCH_STRIDE);
        CHECK(buffer.va==va+i*GUEST_CPU_SCRATCH_STRIDE);
    }
    CHECK(cpus.registrations==6 && cpus.id_queries==6 && cpus.output_queries==6);
    CHECK(guest_cpu_register(&cpus,0x101)==CPU_OK && cpus.registered==63);
    CHECK(cpus.registrations==7); /* Repeat announcement is idempotent metadata. */
    for(uint64_t id=0;id<0x20000;id++) {
        struct guest_cpu_registry before=cpus;
        slot=99;
        enum guest_cpu_result r=guest_cpu_id(&cpus,id,&slot);
        if(id<4 || id==0x100 || id==0x101) {
            CHECK(r==CPU_OK && slot==(id<4?id:id-0x100+4));
        } else {
            CHECK(r==CPU_BAD_AFFINITY && slot==99);
            CHECK(!memcmp(&cpus,&before,sizeof(cpus)));
            CHECK(guest_cpu_register(&cpus,id)==CPU_BAD_AFFINITY);
            CHECK(!memcmp(&cpus,&before,sizeof(cpus)));
        }
    }
    for(unsigned i=0;i<64;i++) {
        uint64_t bad=(UINT64_C(1)<<i)|0x102;
        struct guest_cpu_registry before=cpus;
        CHECK(guest_cpu_register(&cpus,bad)==CPU_BAD_AFFINITY);
        CHECK(!memcmp(&cpus,&before,sizeof(cpus)));
    }
    /* Distinct full-size areas stay disjoint, including the last byte. */
    uint8_t *ram=calloc(1,GUEST_CPU_SCRATCH_SPAN);CHECK(ram);
    for(unsigned i=0;i<6;i++) {
        cpus.active_slot=i;
        CHECK(guest_cpu_buffer(&cpus,cpus.active_slot,pa,va,low,high,&buffer)==CPU_OK);
        memset(ram+buffer.pa-pa,(int)i+1,GUEST_CPU_SCRATCH_STRIDE);
    }
    for(unsigned i=0;i<GUEST_CPU_SCRATCH_SPAN;i++)
        CHECK(ram[i]==i/GUEST_CPU_SCRATCH_STRIDE+1);
    free(ram);
    cpus.active_slot=0;
    for(unsigned i=6;i<64;i++) {
        struct guest_cpu_registry before=cpus;
        buffer=(struct guest_cpu_buffer){11,22};
        CHECK(guest_cpu_output(&cpus,i,pa,va,low,high,&buffer)==CPU_BAD_SLOT);
        CHECK(buffer.pa==11 && buffer.va==22 && !memcmp(&cpus,&before,sizeof(cpus)));
    }
    const uint64_t bad_pa[]={0,pa+1,low-0x8000,high,UINT64_MAX-0x7fff};
    for(unsigned i=0;i<sizeof(bad_pa)/sizeof(*bad_pa);i++) {
        struct guest_cpu_registry before=cpus;
        CHECK(guest_cpu_output(&cpus,0,bad_pa[i],va,low,high,&buffer)==CPU_BAD_BUFFER);
        CHECK(!memcmp(&cpus,&before,sizeof(cpus)));
    }
    const uint64_t bad_va[]={0,va+1,UINT64_MAX-0x7fff,UINT64_C(0xffff7fff00000000)};
    for(unsigned i=0;i<sizeof(bad_va)/sizeof(*bad_va);i++)
        CHECK(guest_cpu_output(&cpus,0,pa,bad_va[i],low,high,&buffer)==CPU_BAD_BUFFER);
    CHECK(!guest_cpu_buffers_valid(pa,va,low,pa+GUEST_CPU_SCRATCH_SPAN-1));
    CHECK(guest_cpu_buffers_valid(pa,va,low,pa+GUEST_CPU_SCRATCH_SPAN));
    CHECK(!guest_cpu_buffers_valid(pa,va,high,low));
    for(unsigned i=0;i<3;i++) {
        struct guest_cpu_registry bad=cpus;
        if(i==0)bad.registered|=64;
        if(i==1)bad.active_slot=6;
        if(i==2)bad.reserved=1;
        struct guest_cpu_registry before=bad;
        CHECK(guest_cpu_register(&bad,0)==CPU_BAD_STATE);
        CHECK(guest_cpu_id(&bad,0,&slot)==CPU_BAD_STATE);
        CHECK(guest_cpu_output(&bad,0,pa,va,low,high,&buffer)==CPU_BAD_STATE);
        CHECK(!memcmp(&bad,&before,sizeof(bad)));
    }
    cpus.registrations=cpus.id_queries=cpus.output_queries=UINT64_MAX;
    CHECK(guest_cpu_register(&cpus,0)==CPU_OK);
    CHECK(guest_cpu_id(&cpus,0,&slot)==CPU_OK);
    CHECK(guest_cpu_output(&cpus,0,pa,va,low,high,&buffer)==CPU_OK);
    CHECK(cpus.registrations==UINT64_MAX && cpus.id_queries==UINT64_MAX &&
          cpus.output_queries==UINT64_MAX);
    struct guest_cpu_address_space spaces[GUEST_CPU_COUNT] = {0};
    const uint64_t live_root = UINT64_C(0x8cd800000);
    CHECK(!guest_cpu_root_busy(spaces,live_root));
    for (unsigned cpu=0; cpu<GUEST_CPU_COUNT; cpu++) {
        for (unsigned high=0; high<2; high++) {
            for (unsigned asid=0; asid<65536; asid+=257) {
                uint64_t value=live_root | ((uint64_t)asid<<48) | 1;
                if(high)spaces[cpu].ttbr1=value;else spaces[cpu].ttbr0=value;
                CHECK(guest_cpu_root_busy(spaces,live_root));
                CHECK(!guest_cpu_root_busy(spaces,live_root+0x4000));
            }
            spaces[cpu]=(struct guest_cpu_address_space){0};
            CHECK(!guest_cpu_root_busy(spaces,live_root));
        }
    }
    CHECK(guest_cpu_root_busy(NULL,live_root));
    CHECK(guest_cpu_root_busy(spaces,0));
    CHECK(guest_cpu_root_busy(spaces,live_root+1));
    CHECK(guest_cpu_root_busy(spaces,UINT64_C(1)<<48));
    printf("%u CPU registry, result-isolation and root-liveness checks passed\n",checks);
    return 0;
}
