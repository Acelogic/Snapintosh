/* SPDX-License-Identifier: MIT */
#define SIZE 0x200000UL
#define main sep_dart_checks
#include "test-sptm-dart-sep.c"
#undef main
#define VA 0x10000004000UL
static uint64_t output[17],old_output[17],identity[17];
static struct sptm_sep_span spans[3];
static struct sptm_memory ready(void)
{
    struct sptm_memory m=reset(0);attach(&m,0,VA);
    for(unsigned i=0;i<17;i++) {
        meta(DATA+i*0x4000)[2]=11;put(LIST+8*i,DATA+i*0x4000);identity[i]=DATA+i*0x4000;
    }
    CHECK(sptm_dart_map(&m,&state,20,0,VA,LIST,17*0x4000,0)==SPTM_OK);
    CHECK(sptm_dart_enable(&m,&state,20,0)==SPTM_OK);
    spans[0]=(struct sptm_sep_span){VA,5*0x4000,identity};
    spans[1]=(struct sptm_sep_span){VA+5*0x4000,7*0x4000,identity+5};
    spans[2]=(struct sptm_sep_span){VA+12*0x4000,5*0x4000,identity+12};
    memset(output,0xa5,sizeof output);memcpy(old_output,output,sizeof output);return m;
}
int main(void)
{
    struct sptm_memory m=ready();snapshot();
    CHECK(sptm_sep_service_buffers(&m,&state,spans,3,output)==SPTM_OK);
    CHECK(state.translations==34 && !memcmp(output,identity,sizeof output));
    CHECK(!memcmp(ram,saved,SIZE) && !pubs);
    for(unsigned page=0;page<17;page++)for(unsigned test=0;test<7;test++) {
        m=ready();uint64_t slot=LEAF+8*(((VA+page*0x4000)>>14)&2047);
        if(test==0)put(slot,0);
        if(test==1)put(slot,get(slot)|4);
        if(test==2)put(slot,get(slot)|8);
        if(test==3)meta(DATA+page*0x4000)[12]=0;
        if(test==4)identity[page]+=0x4000;
        if(test==5)put(slot,(get(slot)&~0xfffffffc00UL)|((DATA+((page+1)%17)*0x4000)>>4));
        if(test==6)put(slot,get(slot)|(1UL<<52));
        snapshot();CHECK(sptm_sep_service_buffers(&m,&state,spans,3,output)!=SPTM_OK);
        unchanged();CHECK(!memcmp(output,old_output,sizeof output));
    }
    for(unsigned test=0;test<7;test++) {
        m=ready();unsigned count=3;
        if(test==0)spans[1].iova=VA;
        if(test==1)spans[1].size++;
        if(test==2)spans[1].size=8*0x4000;
        if(test==3)spans[2].size=7*0x4000;
        if(test==4)state.translations=UINT64_MAX-33;
        if(test==5)count=0;
        if(test==6)count=4;
        snapshot();CHECK(sptm_sep_service_buffers(&m,&state,spans,count,output)!=SPTM_OK);
        unchanged();CHECK(!memcmp(output,old_output,sizeof output));
    }
    printf("PASS: %u complete SEP service-buffer ownership and identity checks\n",checks);return 0;
}
