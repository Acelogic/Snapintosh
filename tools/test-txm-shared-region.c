/* SPDX-License-Identifier: MIT */
/* Exercise real register -> convert -> declare -> unregister -> free paths. */
#define main shared_root_fixture_checks
#include "test-sptm-shared-root.c"
#undef main
static uint64_t get64(uint64_t pa)
{uint64_t value;memcpy(&value,bytes+(pa-BASE),8);return value;}
static void setup(unsigned format)
{
    reset();service.stacks_pa=BASE+292*PAGE;service.stack_count=6;
    create(ROOT,9,format,2);CHECK(!sptm_mac_retype(&m,ROOT,18,19,format));
}
int main(void)
{
    const uint64_t spans[][2]={{PAGE,PAGE},{0x180000000UL,0xe40000000UL},
        {1UL<<48,PAGE},{UINT64_MAX-0x7fff,PAGE},{PAGE,UINT64_MAX-0x7fff}};
    for(unsigned fmt=0;fmt<2;fmt++)for(unsigned cpu=0;cpu<6;cpu++)
    for(unsigned span=0;span<sizeof(spans)/sizeof(spans[0]);span++) {
        setup(fmt);uint64_t stack=service.stacks_pa+cpu*PAGE;
        uint64_t args[8]={stack,arena.va,spans[span][0],spans[span][1]};
        uint64_t start=args[2],end=start+args[3];
        memset(bytes+(stack-BASE),0xa5,PAGE);snapshot();
        CHECK(!txm_aspace(&m,&service,&arena,&registry,37,args));
        CHECK(published==2 && registry.region_sets==1);
        CHECK(registry.region_start[0]==start && registry.region_end[0]==end);
        CHECK(registry.root[0]==ROOT && registry.asid[0]==0 && registry.shared[0]==1);
        CHECK(get64(arena.pa+0x58)==start && get64(arena.pa+0x60)==end);
        CHECK(get64(arena.pa+0x38)==arena.va+0x80);
        CHECK(get64(stack+0x3c08)==0 && bytes[stack-BASE+0x3c10]==0 && get64(stack+0x3c18)==0);
        for(unsigned i=0;i<6;i++)CHECK(get64(stack+0x3c20+i*8)==0);
        /* Only range words and the normal TXM reply change in guest RAM. */
        memcpy(saved+(arena.pa-BASE)+0x58,bytes+(arena.pa-BASE)+0x58,16);
        memcpy(saved+(stack-BASE)+0x3c08,bytes+(stack-BASE)+0x3c08,8);
        saved[stack-BASE+0x3c10]=bytes[stack-BASE+0x3c10];
        memcpy(saved+(stack-BASE)+0x3c18,bytes+(stack-BASE)+0x3c18,56);
        CHECK(!memcmp(saved,bytes,sizeof(bytes)));
        snapshot();CHECK(txm_aspace(&m,&service,&arena,&registry,37,args)==SPTM_FRAME_BUSY);unchanged();
        args[2]=PAGE;args[3]=PAGE;snapshot();
        CHECK(txm_aspace(&m,&service,&arena,&registry,37,args)==SPTM_FRAME_BUSY);unchanged();
        /* Range state survives until legitimate teardown, then is cleared. */
        args[2]=args[3]=0;CHECK(!txm_aspace(&m,&service,&arena,&registry,36,args));
        CHECK(!registry.root[0] && !registry.region_start[0] && !registry.region_end[0]);
        CHECK(registry.region_sets==1);
        CHECK(!sptm_mac_retype(&m,ROOT,19,11,0));create(ROOT,9,fmt,2);
        CHECK(!sptm_mac_retype(&m,ROOT,18,19,fmt));
        args[2]=PAGE;args[3]=PAGE;CHECK(!txm_aspace(&m,&service,&arena,&registry,37,args));
        CHECK(registry.region_sets==2 && registry.region_start[0]==PAGE && registry.region_end[0]==2*PAGE);
    }
    for(unsigned test=0;test<29;test++) {
        setup(0);uint64_t args[8]={service.stacks_pa,arena.va,0x180000000UL,0xe40000000UL};
        enum sptm_result expected=SPTM_BAD_ADDRESS;
        switch(test) {
        case 0:args[2]=0;break;case 1:args[3]=0;break;
        case 2:args[2]++;break;case 3:args[3]++;break;
        case 4:args[2]=UINT64_MAX-0x3fff;args[3]=PAGE;break;
        case 5:args[2]=1UL<<63;args[3]=1UL<<63;break;
        case 6:args[0]++;break;case 7:args[0]=service.stacks_pa+6*PAGE;break;
        case 8:args[1]++;break;case 9:args[1]+=256;break;
        case 10:args[1]+=PAGE;break;
        case 11:args[4]=1;expected=SPTM_UNSUPPORTED_OPTIONS;break;
        case 12:args[7]=1;expected=SPTM_UNSUPPORTED_OPTIONS;break;
        case 13:registry.shared[0]=0;registry.asid[0]=9;expected=SPTM_TYPE_MISMATCH;break;
        case 14:registry.root[0]=0;break;
        case 15:registry.root[0]=ROOT+PAGE;expected=SPTM_TYPE_MISMATCH;break;
        case 16:registry.region_start[0]=PAGE;expected=SPTM_BAD_CONFIG;break;
        case 17:registry.region_start[0]=2*PAGE;registry.region_end[0]=PAGE;expected=SPTM_BAD_CONFIG;break;
        case 18:registry.region_sets=UINT64_MAX;expected=SPTM_BAD_CONFIG;break;
        case 19:deny=service.stacks_pa;expected=SPTM_MEMORY_UNAVAILABLE;break;
        case 20:deny=arena.pa;expected=SPTM_MEMORY_UNAVAILABLE;break;
        case 21:deny=BASE;expected=SPTM_MEMORY_UNAVAILABLE;break;
        case 22:meta(ROOT)[2]=11;expected=SPTM_TABLE_MISSING;break;
        case 23:meta(ROOT)[12]=2;expected=SPTM_BAD_TABLE;break;
        case 24:bytes[arena.pa-BASE+0x24]=0;expected=SPTM_FRAME_BUSY;break;
        case 25:bytes[arena.pa-BASE+0x60]=0x80;expected=SPTM_FRAME_BUSY;break;
        case 26:bytes[arena.pa-BASE+0x38]^=0x40;expected=SPTM_FRAME_BUSY;break;
        case 27:registry.asid[0]=255;expected=SPTM_BAD_TABLE;break;
        case 28:m.publish=0;expected=SPTM_BAD_CONFIG;break;
        }
        snapshot();CHECK(txm_aspace(&m,&service,&arena,&registry,37,args)==expected);unchanged();
    }
    setup(0);
    for(unsigned bit=0;bit<14;bit++)for(unsigned which=2;which<4;which++) {
        uint64_t args[8]={service.stacks_pa,arena.va,PAGE,PAGE};
        args[which]|=1UL<<bit;snapshot();
        CHECK(txm_aspace(&m,&service,&arena,&registry,37,args)==SPTM_BAD_ADDRESS);unchanged();
    }
    /* The declaration itself neither maps pages nor resets root references. */
    meta(ROOT)[4]=2;meta(ROOT)[6]=3;
    uint64_t args[8]={service.stacks_pa,arena.va,PAGE,4*PAGE};
    CHECK(!txm_aspace(&m,&service,&arena,&registry,37,args));
    CHECK(meta(ROOT)[4]==2 && meta(ROOT)[6]==3);
    CHECK(registry.region_start[0]==PAGE && registry.region_end[0]==5*PAGE);
    printf("PASS: %u TXM shared-region checks\n",checks);return 0;
}
