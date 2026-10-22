/* SPDX-License-Identifier: MIT */
#define SIZE 0x200000UL
#define main sep_dart_checks
#include "test-sptm-dart-sep.c"
#undef main
#define VA 0x10000004000UL
static uint64_t output[21],old_output[21],identity[21];
static struct sptm_sep_span spans[5];
static struct sptm_memory ready(void)
{
    struct sptm_memory m=reset(0);attach(&m,0,VA);
    for(unsigned i=0;i<21;i++) {
        meta(DATA+i*0x4000)[2]=11;put(LIST+8*i,DATA+i*0x4000);identity[i]=DATA+i*0x4000;
    }
    CHECK(sptm_dart_map(&m,&state,20,0,VA,LIST,21*0x4000,0)==SPTM_OK);
    CHECK(sptm_dart_enable(&m,&state,20,0)==SPTM_OK);
    const unsigned lengths[]={5,7,5,2,2};unsigned cursor=0;
    for(unsigned i=0;i<5;i++) {
        spans[i]=(struct sptm_sep_span){VA+cursor*0x4000,lengths[i]*0x4000,identity+cursor};
        cursor+=lengths[i];
    }
    memset(output,0xa5,sizeof output);memcpy(old_output,output,sizeof output);return m;
}
int main(void)
{
    struct sptm_memory m=ready();snapshot();
    CHECK(sptm_sep_endpoint_buffers(&m,&state,spans,5,output)==SPTM_OK);
    CHECK(state.translations==42 && !memcmp(output,identity,sizeof output));
    CHECK(!memcmp(ram,saved,SIZE) && !pubs);
    /* Installed xars owns only the shared bootstrap and two 32KiB buffers.
     * Removing pnon must not omit either xars span or weaken alias/identity
     * checks. The absent peer contributes no retained mapping. */
    for(unsigned test=0;test<4;test++) {
        m=ready();spans[1]=spans[3];spans[2]=spans[4];
        if(test==1)spans[2].iova=spans[1].iova;
        if(test==2)identity[19]+=0x4000;
        if(test==3)meta(DATA+20*0x4000)[12]=0;
        snapshot();
        if(!test) {
            CHECK(sptm_sep_endpoint_buffers(&m,&state,spans,3,output)==SPTM_OK);
            CHECK(state.translations==18); /* Two ownership walks of nine pages. */
            CHECK(!memcmp(output,identity,5*sizeof(uint64_t)));
            CHECK(!memcmp(output+5,identity+17,4*sizeof(uint64_t)));
            CHECK(!memcmp(output+9,(uint64_t[12]){0},12*sizeof(uint64_t)));
            CHECK(!memcmp(ram,saved,SIZE) && !pubs);
        } else {
            CHECK(sptm_sep_endpoint_buffers(&m,&state,spans,3,output)!=SPTM_OK);
            unchanged();CHECK(!memcmp(output,old_output,sizeof output));
        }
    }
    for(unsigned page=0;page<21;page++)for(unsigned test=0;test<7;test++) {
        m=ready();uint64_t slot=LEAF+8*(((VA+page*0x4000)>>14)&2047);
        if(test==0)put(slot,0);
        if(test==1)put(slot,get(slot)|4);
        if(test==2)put(slot,get(slot)|8);
        if(test==3)meta(DATA+page*0x4000)[12]=0;
        if(test==4)identity[page]+=0x4000;
        if(test==5)put(slot,(get(slot)&~0xfffffffc00UL)|((DATA+((page+1)%21)*0x4000)>>4));
        if(test==6)put(slot,get(slot)|(1UL<<52));
        snapshot();CHECK(sptm_sep_endpoint_buffers(&m,&state,spans,5,output)!=SPTM_OK);
        unchanged();CHECK(!memcmp(output,old_output,sizeof output));
    }
    for(unsigned i=0;i<5;i++)for(unsigned j=0;j<5;j++)if(i!=j) {
        m=ready();spans[i].iova=spans[j].iova;
        snapshot();CHECK(sptm_sep_endpoint_buffers(&m,&state,spans,5,output)!=SPTM_OK);
        unchanged();CHECK(!memcmp(output,old_output,sizeof output));
    }
    for(unsigned test=0;test<4;test++) {
        m=ready();unsigned count=5;
        if(test==0)state.translations=UINT64_MAX-41;
        if(test==1)spans[4].size+=0x4000;
        if(test==2)count=0;
        if(test==3)count=6;
        snapshot();CHECK(sptm_sep_endpoint_buffers(&m,&state,spans,count,output)!=SPTM_OK);
        unchanged();CHECK(!memcmp(output,old_output,sizeof output));
    }
    printf("PASS: %u five-span SEP buffer ownership, peer alias and rollback checks\n",checks);
    return 0;
}
