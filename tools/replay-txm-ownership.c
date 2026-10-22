/* SPDX-License-Identifier: MIT */
/* Native contract and failure inventory: TXM-TRUST-LOAD-20260925.md.
 * Exercise donation/import/release with captured page bytes, a counted alias,
 * canonical tables and all six CPUs' private permission views. */
#define TXM_DONATION_FIXTURE_ONLY
#include "replay-txm-donation.c"
#undef TXM_DONATION_FIXTURE_ONLY

static unsigned owned_calls, expected_type;
static void owned_publish(void *ctx,uint64_t pa,uint64_t size)
{
    (void)ctx;publications++;
    CHECK((pa==guest_slot && size==8) || (pa==MAP && size==16));
    if(pa==MAP) {
        CHECK(ram[MAP-BASE+2]==expected_type);
        for(unsigned cpu=0;cpu<6;cpu++) {
            verify_view(cpu,expected_type==60 ? 11:3,expected_type==11);
            verify_alias(cpu,MOVED_VA,counted_slot,11,0);
        }
    }
}
static int owned_change(void *ctx,uint64_t pa,uint64_t old,uint64_t type)
{
    (void)ctx;struct sptm_papt_change t;owned_calls++;
    CHECK((old==42 && type==60) || (old==60 && type==11));
    CHECK(ram[MAP-BASE+2]==old);
    if(sptm_papt_prepare(&memory,&backend,&aperture,moved,pa,old,type,&t)!=SPTM_OK)return 0;
    CHECK(t.count==1 && sprr_pte_class(t.leaf[0].after)==(type==60 ? 11u:3u));
    for(unsigned cpu=0;cpu<6;cpu++)if(!sprr_views_sync_cpu(&views,&shadow,cpu,pp[cpu]))return 0;
    sptm_papt_commit(&memory,&t);
    for(unsigned cpu=0;cpu<6;cpu++)if(!sprr_views_sync_cpu(&views,&shadow,cpu,pp[cpu]))return 0;
    return 1;
}
static void owned_prepare(unsigned type)
{
    prepare();CHECK(!sptm_mac_retype(&memory,DATA,11,42,0));
    memory.publish=owned_publish;memory.retype_txm_owned=owned_change;
    expected_type=60;
    if(type==60)CHECK(!sptm_txm_retype(&memory,DATA,42,60));
    publications=owned_calls=0;
}
int main(int argc,char **argv)
{
    if(argc!=2)return 2;
    FILE *f=fopen(argv[1],"rb");if(!f)return 2;
    CHECK(fread(captured_page,1,sizeof captured_page,f)==sizeof captured_page);
    CHECK(fgetc(f)==EOF);fclose(f);
    owned_prepare(42);
    CHECK(!sptm_txm_retype(&memory,DATA,42,60));
    expected_type=11;CHECK(!sptm_txm_retype(&memory,DATA,60,11));
    CHECK(owned_calls==2 && publications==4);
    CHECK(!memcmp(payload,captured_page,sizeof payload));
    for(unsigned i=0;i<16;i++)CHECK(ram[MAP-BASE+i]==(i==2 ? 11:i==8 ? 1:0));
    for(unsigned step=0;step<2;step++) {
        unsigned old=step ? 60:42,new=step ? 11:60;
        for(unsigned bad=0;bad<18;bad++) {
            owned_prepare(old);expected_type=new;
            uint64_t pa=DATA;
            if(bad<8 && bad!=2)ram[MAP-BASE+bad]=1;
            if(bad==2)ram[MAP-BASE+2]=11;
            if(bad>=8 && bad<12)ram[MAP-BASE+bad+4]=1;
            if(bad==12)ram[MAP-BASE+11]=0x80;
            if(bad==13)memory.retype_txm_owned=0;
            if(bad==14)pa++;
            if(bad==15)pa=DATA+0x8000;
            if(bad==16)CHECK(!wr(0,BASE+0x13000+8UL*mmu_index(12,3,VA+4096),0));
            if(bad==17)old=42,new=11;
            memcpy(before,ram,sizeof ram);
            CHECK(sptm_txm_retype(&memory,pa,old,new)!=SPTM_OK);
            CHECK(!memcmp(before,ram,sizeof ram) && !publications);
            CHECK(!memcmp(payload,captured_page,sizeof payload));
            old=step ? 60:42;new=step ? 11:60;
        }
        owned_prepare(old);memcpy(before,ram,sizeof ram);
        CHECK(sptm_mac_retype(&memory,DATA,old,new,0)==SPTM_UNSUPPORTED_RETYPE);
        CHECK(!sptm_mac_retype_supported(old,new));
        CHECK(!memcmp(before,ram,sizeof ram) && !publications && !owned_calls);
    }
    printf("{\"result\":\"%s\",\"checks\":%u,\"failures\":%u,\"cpus\":6,\"captured_bytes_preserved\":16384}\n",
           failed ? "FAIL":"PASS",checks,failed);
    return failed ? 1:0;
}
