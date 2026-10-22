/* SPDX-License-Identifier: MIT */
/* Pre-implementation transaction replay; failure analysis: TXM-DONATION-20260925.md.
 * Reuse the aperture/private-view fixture, add the captured counted RO alias,
 * and load the exact captured payload. Metadata publication checks all CPUs. */
#define main previous_aperture_regression
#include "test-sptm-papt.c"
#undef main
#include <stdlib.h>
static uint8_t captured_page[16384];
static unsigned donation_calls;
static uint64_t counted_slot;
static void donation_publish(void *ctx,uint64_t pa,uint64_t size)
{
    (void)ctx;publications++;
    CHECK((pa==guest_slot && size==8) || (pa==MAP && size==16));
    if(pa==MAP) {
        CHECK(ram[MAP-BASE+2]==42);
        for(unsigned cpu=0;cpu<6;cpu++) {
            verify_view(cpu,4,0);
            verify_alias(cpu,MOVED_VA,counted_slot,11,0);
        }
    }
}
static int donate(void *ctx,uint64_t pa,uint64_t old,uint64_t type)
{
    (void)ctx;struct sptm_papt_change t;donation_calls++;
    CHECK(old==11 && type==42 && ram[MAP-BASE+2]==11);
    if(sptm_papt_prepare(&memory,&backend,&aperture,moved,pa,old,type,&t)!=SPTM_OK)return 0;
    CHECK(t.count==1 && sprr_pte_class(t.leaf[0].after)==4);
    if(!sprr_views_prepare(&views,&shadow,t.leaf[0].va))return 0;
    for(unsigned cpu=0;cpu<6;cpu++)if(!sprr_views_sync_cpu(&views,&shadow,cpu,pp[cpu]))return 0;
    sptm_papt_commit(&memory,&t);
    for(unsigned cpu=0;cpu<6;cpu++)if(!sprr_views_sync_cpu(&views,&shadow,cpu,pp[cpu]))return 0;
    return 1;
}
static void prepare(void)
{
    setup_moved();counted_slot=moved_slot;moved=0;
    uint64_t pte=(get(counted_slot)&~(PT_AP|PT_PXN|PT_UXN))|PT_PXN|PT_UXN|(2UL<<6);
    CHECK(!wr(0,counted_slot,pte));
    for(unsigned n=0;n<4;n++)CHECK(!wr(0,BASE+0x15000+8UL*mmu_index(12,3,MOVED_VA+n*4096),
        (pte&~PT_OA_MASK)|(DATA+n*4096)));
    ram[MAP-BASE+8]=1;
    for(unsigned cpu=0;cpu<6;cpu++)CHECK(sprr_views_sync_cpu(&views,&shadow,cpu,pp[cpu]));
    memcpy(payload,captured_page,sizeof payload);
    memory.publish=donation_publish;memory.retype_txm_default=donate;
    publications=donation_calls=0;
}
static void refuse(void)
{
    memcpy(before,ram,sizeof ram);
    CHECK(sptm_mac_retype(&memory,DATA,11,42,0)!=SPTM_OK);
    CHECK(!memcmp(before,ram,sizeof ram) && !publications);
    CHECK(!memcmp(payload,captured_page,sizeof payload));
}
#ifndef TXM_DONATION_FIXTURE_ONLY
int main(int argc,char **argv)
{
    if(argc!=2)return 2;
    FILE *f=fopen(argv[1],"rb");if(!f)return 2;
    CHECK(fread(captured_page,1,sizeof captured_page,f)==sizeof captured_page);
    CHECK(fgetc(f)==EOF);fclose(f);
    prepare();CHECK(sptm_mac_retype_supported(11,42));
    CHECK(!sptm_mac_retype(&memory,DATA,11,42,0));
    CHECK(donation_calls==1 && publications==2 && ram[MAP-BASE+8]==1);
    CHECK(!memcmp(payload,captured_page,sizeof payload));
    for(unsigned i=0;i<16;i++)CHECK(ram[MAP-BASE+i]==(i==2 ? 42:i==8 ? 1:0));
    /* The changing ROZONE write bit must never grant writes to selector4. */
    for(unsigned cpu=0;cpu<6;cpu++) {
        pp[cpu]^=0x100;CHECK(sprr_views_sync_cpu(&views,&shadow,cpu,pp[cpu]));
        verify_view(cpu,4,0);verify_alias(cpu,MOVED_VA,counted_slot,11,0);
    }
    sptm_refs_begin(memory.refs);
    CHECK(sptm_refs_leaf(&memory,BASE,MOVED_VA+0x4000,0,DATA|ATTR|(2UL<<6)|3)!=SPTM_OK);
    for(unsigned i=0;i<8;i++)if(i!=2) {prepare();ram[MAP-BASE+i]=1;refuse();}
    for(unsigned i=12;i<16;i++){prepare();ram[MAP-BASE+i]=1;refuse();}
    prepare();ram[MAP-BASE+11]=0x80;refuse();
    prepare();memory.retype_txm_default=0;refuse();
    prepare();CHECK(!wr(0,BASE+0x13000+8UL*mmu_index(12,3,VA+4096),0));refuse();
    prepare();memcpy(before,ram,sizeof ram);
    CHECK(sptm_mac_retype(&memory,DATA,11,42,1)!=SPTM_OK && !publications);
    CHECK(!memcmp(before,ram,sizeof ram));
    printf("{\"result\":\"%s\",\"checks\":%u,\"failures\":%u,\"cpus\":6,\"payload_bytes_preserved\":16384,\"boundary\":\"Captured payload and relocated source/aperture/private-view fixture; physical publication and TLBI require A16 audit\"}\n",failed ? "FAIL":"PASS",checks,failed);
    return failed ? 1:0;
}
#endif
