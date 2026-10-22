/* SPDX-License-Identifier: MIT */
#define main shared_fixture_checks
#include "test-sptm-shared-root.c"
#undef main
#include "sptm-user.h"
static struct sptm_root_configuration configuration,saved_configuration;
static struct sptm_root_state saved_roots;
static unsigned configured;
static int configure(void *ctx,uint64_t root,uint16_t before,uint16_t after)
{
    (void)ctx;CHECK(before!=after);
    if(deny_retirement || !sptm_root_invalidate(&roots,root,0))return 0;
    configured++;return 1;
}
static void setup(unsigned fmt,unsigned flags)
{
    reset();memset(&configuration,0,sizeof(configuration));configured=0;
    m.configure_user_root=configure;m.root_configuration=&configuration;
    create(ROOT,9,fmt,flags);
}
static void save(void)
{snapshot();saved_configuration=configuration;saved_roots=roots;}
static void verify_unchanged(void)
{unchanged();CHECK(!memcmp(&configuration,&saved_configuration,sizeof(configuration)));
 CHECK(!memcmp(&roots,&saved_roots,sizeof(roots)));}
static int bind(void *ctx,uint64_t user,uint16_t asid,uint64_t parent,uint8_t slot,uint64_t start,uint64_t size)
{(void)ctx;return !txm_bind_shared(&m,&arena,&registry,user,asid,parent,slot,start,size);}
int main(void)
{
    unsigned fmts[]={0,0,1,1,1},flags[]={2,0x22,2,6,0x22};
    for(unsigned f=0;f<5;f++) {
        setup(fmts[f],flags[f]);roots.cache[0]=(struct sptm_root_cached){.root=ROOT,.asid=9,.valid=1,.flags=flags[f]};
        CHECK(!sptm_mac_configure_root(&m,ROOT,8,8));
        CHECK(meta(ROOT)[10]==(flags[f]|8) && !meta(ROOT)[11]);
        CHECK(configuration.calls==1 && configuration.changes==1 && configuration.root==ROOT &&
            configuration.before==flags[f] && configuration.after==(flags[f]|8));
        CHECK(configured==1 && !roots.cache[0].valid && roots.invalidations==1);
        CHECK(registry.root[0]==ROOT && registry.asid[0]==9 && !registry.bound_shared[0]);
        CHECK(!sptm_mac_configure_root(&m,ROOT,8,8));
        CHECK(configuration.calls==2 && configuration.changes==1 && configured==1);
        CHECK(!sptm_mac_configure_root(&m,ROOT,0,8));
        CHECK(meta(ROOT)[10]==flags[f] && configuration.calls==3 && configuration.changes==2);
        /* High argument bits are normalized by the native u16 store. */
        CHECK(!sptm_mac_configure_root(&m,ROOT,0xabcd12340000000aUL,0xffff000000000008UL));
        CHECK(configuration.value==10 && configuration.mask==8 && meta(ROOT)[10]==(flags[f]|8));
        /* Disabling address PA preserves geometry, registry and UMPRR state.
         * A stale shadow must be invalidated before the new flag is visible. */
        roots.cache[0]=(struct sptm_root_cached){.root=ROOT,.asid=9,.valid=1,.flags=flags[f]|8};
        CHECK(!sptm_mac_configure_root(&m,ROOT,0,2));
        CHECK(meta(ROOT)[10]==((flags[f]|8)&~2) && !roots.cache[0].valid);
        CHECK(configuration.before==(flags[f]|8) && configuration.after==((flags[f]|8)&~2));
        unsigned count=configured;
        CHECK(!sptm_mac_configure_root(&m,ROOT,0,2) && configured==count);
        CHECK(!sptm_mac_configure_root(&m,ROOT,2,2));
        CHECK(meta(ROOT)[10]==(flags[f]|8) && configured==count+1);
        CHECK(!sptm_mac_configure_root(&m,ROOT,0,10));
        CHECK(meta(ROOT)[10]==(flags[f]&~2));
        CHECK(!sptm_mac_configure_root(&m,ROOT,1,1));
        CHECK(meta(ROOT)[10]==((flags[f]&~2)|1));
        CHECK(!sptm_mac_configure_root(&m,ROOT,11,11));
        CHECK(meta(ROOT)[10]==(flags[f]|9));
        CHECK(!sptm_mac_configure_root(&m,ROOT,1,11));
        CHECK(meta(ROOT)[10]==((flags[f]&~2)|1));
        uint64_t child=ROOT+PAGE;CHECK(!sptm_mac_retype(&m,child,11,20,(fmts[f]?1:2)));
        struct sptm_user_backend backend={0};
        CHECK(!sptm_mac_map_user_table_live(&m,&backend,ROOT,0,fmts[f]?0:1,child|3));
        CHECK(!sptm_mac_unmap_user_table(&m,&backend,ROOT,0,fmts[f]?0:1));
        CHECK(!sptm_mac_retype(&m,child,20,11,0));
        uint64_t args[8]={service.stacks_pa,arena.va};
        CHECK(!txm_aspace(&m,&service,&arena,&registry,36,args));
        CHECK(!sptm_mac_retype(&m,ROOT,18,11,0));
    }
    /* All16 low mask bits: only the decoded modifier can change here. */
    for(unsigned bit=0;bit<64;bit++) {
        setup(0,2);save();uint64_t v=1UL<<bit;
        enum sptm_result result=sptm_mac_configure_root(&m,ROOT,v,v);
        if(bit>=16 || bit==0 || bit==1 || bit==3) {
            CHECK(!result);CHECK(meta(ROOT)[10]==(bit==0?3:bit==3?10:2));
        }
        else {CHECK(result==SPTM_UNSUPPORTED_OPTIONS);verify_unchanged();}
    }
    for(unsigned test=0;test<22;test++) {
        setup(0,2);uint64_t root=ROOT;
        switch(test) {
        case 0:root++;break;case 1:root=BASE;break;
        case 2:meta(ROOT)[2]=19;break;case 3:meta(ROOT)[0]=1;break;
        case 4:meta(ROOT)[4]=0;break;case 5:meta(ROOT)[8]=0;break;
        case 6:meta(ROOT)[10]=0x10;break;case 7:meta(ROOT)[10]=0x82;break;
        case 8:meta(ROOT)[12]=2;break;case 9:meta(ROOT)[13]=1;break;
        case 10:meta(ROOT)[6]=0xff;meta(ROOT)[7]=0xff;break;
        case 11:deny=BASE+((ROOT-BASE)/PAGE)*16;break;
        case 12:m.configure_user_root=0;break;
        case 13:configuration.calls=UINT64_MAX;break;
        case 14:configuration.changes=UINT64_MAX;break;
        case 15:deny_retirement=1;break;
        default:roots.active[test-16]=ROOT;break;
        }
        save();CHECK(sptm_mac_configure_root(&m,root,8,8)!=SPTM_OK);verify_unchanged();CHECK(!configured);
    }
    setup(0,2);m.bind_shared_root=bind;CHECK(!sptm_mac_retype(&m,ROOT,18,19,0));
    uint64_t args[8]={service.stacks_pa,arena.va,0x180000000UL,0xe40000000UL};
    CHECK(!txm_aspace(&m,&service,&arena,&registry,37,args));
    CHECK(!sptm_mac_configure_sharedregion(&m,ROOT,args[2],args[3]/PAGE));
    create(ROOT+PAGE,10,0,2);CHECK(!sptm_mac_set_shared_region(&m,ROOT+PAGE,ROOT));
    uint8_t objects[512];memcpy(objects,bytes+2*PAGE,512);
    CHECK(!sptm_mac_configure_root(&m,ROOT+PAGE,8,8));
    CHECK(meta(ROOT+PAGE)[10]==10 && meta(ROOT+PAGE)[8]==0 && meta(ROOT)[4]==1);
    CHECK(!memcmp(objects,bytes+2*PAGE,512));CHECK(registry.bindings==1 && !registry.unbindings);
    CHECK(!sptm_mac_configure_root(&m,ROOT+PAGE,0,8));
    CHECK(!sptm_mac_configure_root(&m,ROOT+PAGE,0,2));
    CHECK(!meta(ROOT+PAGE)[10] && !meta(ROOT+PAGE)[8] && meta(ROOT)[4]==1);
    CHECK(!memcmp(objects,bytes+2*PAGE,512));CHECK(registry.bindings==1 && !registry.unbindings);
    for(unsigned cpu=0;cpu<6;cpu++) {
        setup(0,2);roots.active[cpu]=ROOT;save();
        CHECK(sptm_mac_configure_root(&m,ROOT,0,2)==SPTM_FRAME_BUSY);verify_unchanged();
        CHECK(sptm_mac_configure_root(&m,ROOT,1,1)==SPTM_FRAME_BUSY);verify_unchanged();
    }
    /* Unsupported controls and conflicting geometry still cannot be constructed. */
    save();CHECK(sptm_mac_retype(&m,ROOT+2*PAGE,11,18,(11UL<<32)|(0x10UL<<16))==SPTM_UNSUPPORTED_OPTIONS);verify_unchanged();
    CHECK(sptm_mac_retype(&m,ROOT+2*PAGE,11,18,(11UL<<32)|(0x80UL<<16))==SPTM_UNSUPPORTED_OPTIONS);verify_unchanged();
    CHECK(sptm_mac_retype(&m,ROOT+2*PAGE,11,18,(11UL<<32)|(0x26UL<<16)|1)==SPTM_UNSUPPORTED_OPTIONS);verify_unchanged();
    printf("PASS: %u root-configuration checks\n",checks);return 0;
}
