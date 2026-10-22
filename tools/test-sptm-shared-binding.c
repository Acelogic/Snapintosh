/* SPDX-License-Identifier: MIT */
#define main shared_fixture_checks
#include "test-sptm-shared-root.c"
#undef main
#include "sptm-user.h"
#include "sptm-refs.h"
#define USER (ROOT+PAGE)
#define START 0x180000000UL
#define LENGTH 0xe40000000UL
static unsigned fail_binding;
static int bind_shared(void *ctx,uint64_t user,uint16_t asid,uint64_t parent,
                       uint8_t slot,uint64_t start,uint64_t size)
{
    (void)ctx;
    return !fail_binding && !txm_bind_shared(&m,&arena,&registry,user,asid,parent,slot,start,size);
}
static void setup(unsigned fmt,unsigned flags)
{
    reset();fail_binding=0;m.bind_shared_root=bind_shared;
    create(ROOT,9,fmt,2);CHECK(!sptm_mac_retype(&m,ROOT,18,19,fmt));
    uint64_t args[8]={service.stacks_pa,arena.va,START,LENGTH};
    CHECK(!txm_aspace(&m,&service,&arena,&registry,37,args));
    CHECK(!sptm_mac_configure_sharedregion(&m,ROOT,START,LENGTH/(fmt?0x1000:PAGE)));
    create(USER,10,fmt,flags);
}
static uint64_t read64(const uint8_t *p){uint64_t v;memcpy(&v,p,8);return v;}
static void verify_object(unsigned user,unsigned refs)
{
    const uint8_t *u=bytes+2*PAGE+user*256,*p=bytes+2*PAGE;
    uint64_t handle=arena.va+user*256;
    CHECK(read64(u+0x28)==handle+0x80 && !read64(u+0x38) && read64(u+0x48)==handle+0x80);
    CHECK(u[0x92]==1 && read64(u+0x98)==arena.va);
    CHECK(read64(u+0xa8)==START && read64(u+0xb0)==START+LENGTH);
    CHECK(!read64(u+0xb8) && !read64(u+0xc0) && !read64(u+0xc8));
    CHECK(read64(p+0x68)==refs && registry.bound_shared[user]==ROOT);
    CHECK(meta(ROOT)[4]==refs && meta(USER+(user-1)*PAGE)[8]==0);
}
static void retained_commpage_cleanup(unsigned fmt,unsigned flags)
{
    setup(fmt,flags);
    static struct sptm_ref_batch refs;
    memset(&refs,0,sizeof(refs));m.refs=&refs;
    create(USER+PAGE,11,fmt,flags);
    CHECK(!sptm_mac_set_shared_region(&m,USER,ROOT));
    CHECK(!sptm_mac_set_shared_region(&m,USER+PAGE,ROOT));
    uint64_t size=fmt ? 4096:PAGE;
    uint64_t last=(1UL<<(flags==6 ? 47:flags==0x22 ? 32:36))-size;
    uint64_t va=fmt ? last&~(3UL<<21):last;
    uint64_t l2=ROOT+3*PAGE,comm=l2+2*PAGE;
    uint64_t l1=comm+PAGE,l12=l1+PAGE,data=l12+PAGE,result;
    struct sptm_user_backend b={.aperture={BASE,0xfffffe0100000000UL,sizeof(bytes)}};
    CHECK(!sptm_mac_retype(&m,comm,11,23,3));
    for(unsigned user=0;user<2;user++) {
        uint64_t root=USER+user*PAGE,child=l2+user*PAGE;
        CHECK(!sptm_mac_retype(&m,child,11,20,2));
        if(fmt) {
            CHECK(!sptm_mac_retype(&m,l1+user*PAGE,11,20,1));
            CHECK(!sptm_mac_map_user_table(&m,root,va&~(3UL<<39),0,(l1+user*PAGE)|3));
        }
        CHECK(!sptm_mac_map_user_table(&m,root,fmt ? va&~(3UL<<30):va,1,child|3));
        enum sptm_result attached=sptm_mac_map_user_table_live(&m,&b,root,va,2,comm|3);
        if(attached)fprintf(stderr,"commpage attach fmt%u flags%x user%u: %u\n",fmt,flags,user,attached);
        CHECK(!attached);
        if(!user)for(unsigned n=0;n<3;n++) {
            unsigned type=n==0 ? 31:n==1 ? 30:29;
            CHECK(!sptm_mac_retype(&m,data+n*PAGE,11,type,0));
            uint64_t attrs=n ? 0x00600000000007c3UL:0x00200000000007c3UL;
            CHECK(!sptm_mac_map_user_page(&m,&b,root,last-(2-n)*size,
                                          (data+n*PAGE)|attrs,1,0,&result));
        }
    }
    CHECK(meta(comm)[6]==2 && meta(comm)[8]==3 && meta(ROOT)[4]==2);
    snapshot();struct sptm_root_state prior_roots=roots;
    uint64_t args[8]={service.stacks_pa,arena.va+256};
    CHECK(!txm_aspace(&m,&service,&arena,&registry,36,args));
    /* Every SPTM metadata byte and source page survives TXM teardown. */
    CHECK(!memcmp(saved,bytes,PAGE));
    CHECK(!memcmp(saved+(ROOT-BASE),bytes+(ROOT-BASE),sizeof(bytes)-(ROOT-BASE)));
    CHECK(!memcmp(&saved_regions,&shared_regions,sizeof(shared_regions)));
    CHECK(!memcmp(&prior_roots,&roots,sizeof(roots)));
    CHECK(!registry.root[1] && registry.root[2]==USER+PAGE);
    CHECK(registry.unbindings==1 && bytes[2*PAGE+0x68]==1 && meta(ROOT)[4]==2);
    /* Later SPTM detach drops only this parent edge, not the shared leaves. */
    CHECK(!sptm_mac_unmap_user_table(&m,&b,USER,va,2));
    CHECK(meta(comm)[6]==1 && meta(comm)[8]==3);
    CHECK(!memcmp(saved+(comm-BASE),bytes+(comm-BASE),PAGE));
    CHECK(!sptm_mac_unmap_user_table(&m,&b,USER,fmt ? va&~(3UL<<30):va,1));
    CHECK(!sptm_mac_retype(&m,l2,20,11,0));
    if(fmt) {
        CHECK(!sptm_mac_unmap_user_table(&m,&b,USER,va&~(3UL<<39),0));
        CHECK(!sptm_mac_retype(&m,l1,20,11,0));
    }
    CHECK(!sptm_mac_retype(&m,USER,18,11,0));
    CHECK(meta(ROOT)[4]==1 && meta(comm)[6]==1 && meta(comm)[8]==3);
    CHECK(read64(bytes+2*PAGE+0x68)==1 && registry.root[2]==USER+PAGE);
}
/* The TXM binding count is the native u32 at +0x68 (ldadd w / ldaddal w).
 * A byte counter wrapped at 256 bound address spaces: the 256th binding
 * read back as zero and the next TXM36 unbind was refused. Bind 290 users,
 * crossing 256 both ways, and check all four bytes and SPTM's u16 alike. */
static uint32_t read32(const uint8_t *p){uint32_t v;memcpy(&v,p,4);return v;}
static void many_bindings(void)
{
    enum {USERS=290};
    _Static_assert(ROOT+(USERS+1)*PAGE<=BASE+sizeof(bytes),"fixture holds every user root");
    setup(0,2);
    for(unsigned k=1;k<USERS;k++)create(USER+k*PAGE,10+k,0,2);
    const uint8_t *p=bytes+2*PAGE;
    for(unsigned k=0;k<USERS;k++) {
        CHECK(!sptm_mac_set_shared_region(&m,USER+k*PAGE,ROOT));
        CHECK(read32(p+0x68)==k+1);
        CHECK((unsigned)(meta(ROOT)[4]|meta(ROOT)[5]<<8)==k+1);
        if(k+1==256) {
            /* A bound shared object stays busy with a multiple of 256 users. */
            uint64_t args[8]={service.stacks_pa,arena.va};
            snapshot();CHECK(txm_aspace(&m,&service,&arena,&registry,36,args)==SPTM_FRAME_BUSY);unchanged();
        }
    }
    CHECK(registry.bindings==USERS);
    for(unsigned k=USERS;k-->0;) {
        uint64_t args[8]={service.stacks_pa,arena.va+(k+1)*256};
        CHECK(!txm_aspace(&m,&service,&arena,&registry,36,args));
        CHECK(read32(p+0x68)==k && !registry.bound_shared[k+1]);
        CHECK(!sptm_mac_retype(&m,USER+k*PAGE,18,11,0));
        CHECK((unsigned)(meta(ROOT)[4]|meta(ROOT)[5]<<8)==k);
    }
    CHECK(registry.unbindings==USERS);
    uint64_t args[8]={service.stacks_pa,arena.va};
    CHECK(!txm_aspace(&m,&service,&arena,&registry,36,args));
    CHECK(!sptm_mac_retype(&m,ROOT,19,11,0));
    /* A corrupted high byte is a mismatch with the issued view, not a count. */
    setup(0,2);CHECK(!sptm_mac_set_shared_region(&m,USER,ROOT));
    bytes[2*PAGE+0x69]=1;
    uint64_t unbind[8]={service.stacks_pa,arena.va+256};
    snapshot();CHECK(txm_aspace(&m,&service,&arena,&registry,36,unbind)!=SPTM_OK);unchanged();
}
int main(void)
{
    const unsigned formats[]={0,0,1,1,1},flags[]={2,0x22,2,6,0x22};
    for(unsigned f=0;f<5;f++) {
        retained_commpage_cleanup(formats[f],flags[f]);
        setup(formats[f],flags[f]);
        CHECK(!sptm_mac_set_shared_region(&m,USER,ROOT));verify_object(1,1);
        CHECK(sptm_mac_user_binding_valid(&m,meta(USER)));
        CHECK(registry.bindings==1 && !registry.unbindings);
        snapshot();CHECK(sptm_mac_set_shared_region(&m,USER,ROOT)==SPTM_FRAME_BUSY);unchanged();
        create(USER+PAGE,11,formats[f],flags[f]);
        CHECK(!sptm_mac_set_shared_region(&m,USER+PAGE,ROOT));verify_object(2,2);
        uint64_t args[8]={service.stacks_pa,arena.va};
        snapshot();CHECK(txm_aspace(&m,&service,&arena,&registry,36,args)==SPTM_FRAME_BUSY);unchanged();
        snapshot();CHECK(sptm_mac_retype(&m,USER,18,11,0)==SPTM_FRAME_BUSY);unchanged();
        args[1]=arena.va+256;CHECK(!txm_aspace(&m,&service,&arena,&registry,36,args));
        CHECK(registry.unbindings==1 && !registry.bound_shared[1]);
        CHECK(bytes[2*PAGE+0x68]==1 && meta(ROOT)[4]==2 && meta(USER)[8]==0);
        CHECK(!sptm_mac_retype(&m,USER,18,11,0));CHECK(meta(ROOT)[4]==1);
        /* Reuse the same frame, ASID and arena slot after both lifetimes end. */
        create(USER,10,formats[f],flags[f]);
        CHECK(!sptm_mac_set_shared_region(&m,USER,ROOT));verify_object(1,2);
        for(unsigned n=1;n<=2;n++) {
            args[1]=arena.va+n*256;CHECK(!txm_aspace(&m,&service,&arena,&registry,36,args));
            CHECK(!sptm_mac_retype(&m,USER+(n-1)*PAGE,18,11,0));
        }
        CHECK(registry.bindings==3 && registry.unbindings==3 && !meta(ROOT)[4]);
        args[1]=arena.va;CHECK(!txm_aspace(&m,&service,&arena,&registry,36,args));
        CHECK(!sptm_mac_retype(&m,ROOT,19,11,0));
    }
    for(unsigned test=0;test<24;test++) {
        setup(0,2);uint64_t user=USER,parent=ROOT;
        switch(test) {
        case 0:user++;break;case 1:parent++;break;case 2:parent=user;break;
        case 3:meta(USER)[2]=19;break;case 4:meta(ROOT)[2]=18;break;
        case 5:meta(USER)[8]=0;break;case 6:meta(ROOT)[8]=255;break;
        case 7:meta(ROOT)[12]=1;break;case 8:meta(USER)[4]=0;break;
        case 9:meta(ROOT)[4]=0xf9;meta(ROOT)[5]=0xff;break;
        case 10:shared_regions.slots[0].state=1;shared_regions.slots[0].start=shared_regions.slots[0].size=0;break;
        case 11:shared_regions.slots[0].root=USER;break;
        case 12:deny=BASE+2*PAGE;break;case 13:deny=BASE+2*PAGE+256;break;
        case 14:deny=BASE+((USER-BASE)/PAGE)*16;break;
        case 15:registry.bindings=UINT64_MAX;break;
        case 16:registry.bound_shared[1]=ROOT;break;
        case 17:registry.asid[1]=11;break;
        case 18:registry.shared[0]=0;break;
        case 19:registry.region_start[0]=START+PAGE;break;
        case 20:registry.region_end[0]=START+LENGTH-PAGE;break;
        case 21:fail_binding=1;break;case 22:m.bind_shared_root=0;break;
        case 23:meta(USER)[10]=0x82;break;
        }
        snapshot();CHECK(sptm_mac_set_shared_region(&m,user,parent)!=SPTM_OK);unchanged();
    }
    /* Corruption anywhere in either ABI object must fail before writes. */
    for(unsigned object=0;object<2;object++)for(unsigned byte=0;byte<256;byte++) {
        setup(0,2);bytes[2*PAGE+object*256+byte]^=0x80;
        snapshot();CHECK(sptm_mac_set_shared_region(&m,USER,ROOT)==SPTM_FRAME_BUSY);unchanged();
    }
    for(unsigned test=0;test<7;test++) {
        setup(0,2);CHECK(!sptm_mac_set_shared_region(&m,USER,ROOT));
        uint64_t args[8]={service.stacks_pa,arena.va+256};
        switch(test) {
        case 0:bytes[2*PAGE+0x68]=0;break;
        case 1:bytes[2*PAGE+256+0xc8]=1;break;
        case 2:deny=BASE+2*PAGE;break;
        case 3:deny=service.stacks_pa;break;
        case 4:registry.unbindings=UINT64_MAX;break;
        case 5:meta(ROOT)[4]=0;break;
        case 6:registry.bound_shared[1]=USER;break;
        }
        snapshot();CHECK(txm_aspace(&m,&service,&arena,&registry,36,args)!=SPTM_OK);unchanged();
    }
    /* A binding changes no PTE: ordinary table lifecycle still works. */
    setup(0,2);CHECK(!sptm_mac_set_shared_region(&m,USER,ROOT));
    uint64_t child=USER+PAGE;CHECK(!sptm_mac_retype(&m,child,11,20,2));
    struct sptm_user_backend backend={0};
    CHECK(!sptm_mac_map_user_table_live(&m,&backend,USER,0,1,child|3));
    CHECK(!sptm_mac_unmap_user_table(&m,&backend,USER,0,1));
    CHECK(!sptm_mac_retype(&m,child,20,11,0));
    /* TXM may go away before its empty shared SPTM hierarchy is freed. */
    setup(0,2);child=USER+PAGE;CHECK(!sptm_mac_retype(&m,child,11,21,2));
    CHECK(!sptm_mac_map_user_table_live(&m,&backend,ROOT,0,1,child|3));
    CHECK(!sptm_mac_set_shared_region(&m,USER,ROOT));
    uint64_t args[8]={service.stacks_pa,arena.va+256};
    CHECK(!txm_aspace(&m,&service,&arena,&registry,36,args));
    CHECK(!sptm_mac_retype(&m,USER,18,11,0));
    args[1]=arena.va;CHECK(!txm_aspace(&m,&service,&arena,&registry,36,args));
    CHECK(!sptm_mac_unmap_user_table(&m,&backend,ROOT,0,1));
    CHECK(!sptm_mac_retype(&m,child,21,11,0));
    CHECK(!sptm_mac_retype(&m,ROOT,19,11,0));
    many_bindings();
    printf("PASS: %u shared-binding lifecycle checks\n",checks);return 0;
}
