/* SPDX-License-Identifier: MIT */
#define main shared_fixture_checks
#include "test-sptm-shared-root.c"
#undef main
static void setup(unsigned fmt)
{
    reset();create(ROOT,9,fmt,2);CHECK(!sptm_mac_retype(&m,ROOT,18,19,fmt));
    CHECK(shared_regions.slots[0].state==1 && shared_regions.slots[0].root==ROOT);
}
int main(void)
{
    for(unsigned fmt=0;fmt<2;fmt++) {
        uint64_t page=fmt ? 0x1000 : 0x4000,max=(1UL<<36)/page;
        const uint64_t starts[]={0,page,0x180000000UL,(1UL<<47)-page,(1UL<<47)-(1UL<<36)};
        const uint64_t counts[]={1,0xabc00000001UL,0xe40000000UL/page,1,max};
        for(unsigned test=0;test<5;test++) {
            setup(fmt);snapshot();
            CHECK(!sptm_mac_configure_sharedregion(&m,ROOT,starts[test],counts[test]));
            CHECK(!published && !memcmp(saved,bytes,sizeof(bytes)));
            CHECK(!memcmp(&saved_registry,&registry,sizeof(registry)));
            struct sptm_shared_slot *s=&shared_regions.slots[0];
            CHECK(s->state==3 && s->root==ROOT && s->start==starts[test] && s->size==(uint32_t)counts[test]*page);
            CHECK(shared_regions.configurations==1);
            snapshot();CHECK(sptm_mac_configure_sharedregion(&m,ROOT,starts[test],counts[test])==SPTM_FRAME_BUSY);unchanged();
            /* Both allocated and configured slots follow the same legitimate
             * TXM unregister / shared-root retirement lifetime. */
            uint64_t args[8]={service.stacks_pa,arena.va};
            CHECK(!txm_aspace(&m,&service,&arena,&registry,36,args));
            CHECK(!sptm_mac_retype(&m,ROOT,19,11,0));
            CHECK(!s->state && !s->root && !s->start && !s->size);
            create(ROOT,9,fmt,2);CHECK(!sptm_mac_retype(&m,ROOT,18,19,fmt));
            CHECK(s->state==1 && !s->start && !s->size);
            CHECK(!sptm_mac_configure_sharedregion(&m,ROOT,page,1));
            CHECK(shared_regions.configurations==2);
        }
        for(unsigned bit=0;bit<(fmt ? 12u : 14u);bit++) {
            setup(fmt);snapshot();
            CHECK(sptm_mac_configure_sharedregion(&m,ROOT,1UL<<bit,1)==SPTM_BAD_ADDRESS);unchanged();
        }
        for(unsigned test=0;test<17;test++) {
            setup(fmt);uint64_t start=0x180000000UL,count=1;
            enum sptm_result expected=SPTM_BAD_ADDRESS;
            switch(test) {
            case 0:count=0;break;case 1:count=1UL<<32;break;
            case 2:count=max+1;break;case 3:count=UINT32_MAX;break;
            case 4:start=1UL<<47;break;case 5:start=(1UL<<47)-page;count=2;break;
            case 6:start=UINT64_MAX&~(page-1);break;
            case 7:shared_regions.slots[0].root=ROOT+PAGE;expected=SPTM_TYPE_MISMATCH;break;
            case 8:shared_regions.slots[0].state=2;expected=SPTM_BAD_TABLE;break;
            case 9:shared_regions.slots[0].size=page;expected=SPTM_BAD_TABLE;break;
            case 10:meta(ROOT)[8]=255;expected=SPTM_BAD_TABLE;break;
            case 11:meta(ROOT)[12]=2;expected=SPTM_BAD_TABLE;break;
            case 12:meta(ROOT)[0]=1;expected=SPTM_FRAME_BUSY;break;
            case 13:meta(ROOT)[2]=23;expected=SPTM_TYPE_MISMATCH;break;
            case 14:deny=BASE+((ROOT-BASE)/PAGE)*16;expected=SPTM_MEMORY_UNAVAILABLE;break;
            case 15:m.shared_regions=0;expected=SPTM_BAD_CONFIG;break;
            case 16:shared_regions.configurations=UINT64_MAX;expected=SPTM_BAD_CONFIG;break;
            }
            snapshot();CHECK(sptm_mac_configure_sharedregion(&m,ROOT,start,count)==expected);unchanged();
        }
    }
    /* The SPTM and TXM range records are independently maintained contracts. */
    setup(0);uint64_t args[8]={service.stacks_pa,arena.va,0x180000000UL,0xe40000000UL};
    CHECK(!txm_aspace(&m,&service,&arena,&registry,37,args));snapshot();
    CHECK(!sptm_mac_configure_sharedregion(&m,ROOT,0,1));
    CHECK(!memcmp(&saved_registry,&registry,sizeof(registry)) && !memcmp(saved,bytes,sizeof(bytes)));
    /* Generic class1 handling through a coherent nested user-root fixture.
     * No NEST implementation is claimed by constructing its input state. */
    setup(0);create(ROOT+PAGE,10,0,0x22);meta(ROOT)[4]=1;meta(ROOT+PAGE)[8]=0;
    CHECK(!sptm_mac_configure_sharedregion(&m,ROOT+PAGE,1UL<<40,1));
    CHECK(shared_regions.slots[0].start==1UL<<40 && meta(ROOT)[4]==1);
    /* A callback failure cannot discard an already configured range. */
    setup(0);CHECK(!sptm_mac_configure_sharedregion(&m,ROOT,0x180000000UL,0x390000));
    memset(args,0,sizeof(args));args[0]=service.stacks_pa;args[1]=arena.va;
    CHECK(!txm_aspace(&m,&service,&arena,&registry,36,args));
    deny_retirement=1;snapshot();
    CHECK(sptm_mac_retype(&m,ROOT,19,11,0)==SPTM_FRAME_BUSY);unchanged();
    /* Neither slot allocation nor retirement may overlook stale registry
     * state that disagrees with the independently stored frame identities. */
    for(unsigned test=0;test<6;test++) {
        setup(0);create(ROOT+PAGE,10,0,2);
        switch(test) {
        case 0:shared_regions.slots[127]=(struct sptm_shared_slot){.state=1,.root=ROOT+2*PAGE};break;
        case 1:shared_regions.slots[0].root=ROOT+PAGE;break;
        case 2:shared_regions.slots[0].state=2;break;
        case 3:shared_regions.slots[0].size=PAGE;break;
        case 4:shared_regions.slots[0].state=3;break;
        case 5:shared_regions.slots[0].state=3;shared_regions.slots[0].size=PAGE;
               shared_regions.slots[0].start=1UL<<47;break;
        }
        snapshot();CHECK(sptm_mac_retype(&m,ROOT+PAGE,18,19,0)==SPTM_BAD_TABLE);unchanged();
    }
    printf("PASS: %u SPTM shared-region checks\n",checks);return 0;
}
