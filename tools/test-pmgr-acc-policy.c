/* SPDX-License-Identifier: MIT */
/* The opaque ACC setting cannot stand in for energy restoration or power. */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device.h"
static unsigned checks,count;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"line %u: %s\n",__LINE__,#x); exit(1); } } while (0)
static const struct device_model original[]={
    {37,0x210e44000,0x1000,{0}}, {37,0x211e44000,0x1000,{1}},
    {21,0x210e70000,0x1000,{0}}, {21,0x211e70000,0x1000,{1}},
    {36,0x210059000,0x1000,{0}}, {36,0x210159000,0x1000,{0}},
    {36,0x210259000,0x1000,{0}}, {36,0x210359000,0x1000,{0}},
    {36,0x211059000,0x1000,{0}}, {36,0x211159000,0x1000,{0}},
    {36,0x210e48000,0x1000,{0}}, {36,0x211e48000,0x1000,{0}}
};
static struct device_model models[13];
static struct device_state states[13],saved[13],expected[13];
static enum device_result access(unsigned i,unsigned off,unsigned width,int write,uint64_t *v)
{ return device_models_access_at(models,states,count,i,0,off,width,write,v); }
static void refused(unsigned i,unsigned off,unsigned width,int write,uint64_t value,enum device_result want)
{
    uint64_t v=value;memcpy(saved,states,sizeof(states));
    enum device_result got=access(i,off,width,write,&v);
    if(got!=want)fprintf(stderr,"model%u:%x got%u want%u\n",i,off,got,want);
    CHECK(got==want);CHECK(v==value && !memcmp(saved,states,sizeof(states)));
}
static void reset(void)
{
    count=12;memset(models,0,sizeof(models));memcpy(models,original,sizeof(original));
    memset(states,0,sizeof(states));CHECK(device_models_valid(models,count,0,0));
    for(unsigned i=0;i<count;i++)CHECK(device_model_start(models+i,states+i,0,24000000)==DEVICE_OK);
}
static int belongs(unsigned i,unsigned cluster)
{ return i==2+cluster || i==10+cluster || (cluster ? i==8 || i==9 : i>=4 && i<=7); }
static void restore(unsigned cluster)
{
    for(unsigned i=4;i<12;i++)if(belongs(i,cluster))for(unsigned slot=0;slot<2;slot++) {
        uint64_t v=0x8000000000000000UL+i+slot;
        CHECK(access(i,slot*8,8,1,&v)==DEVICE_OK);
    }
    uint64_t v=0xa800000000000000UL;CHECK(access(2+cluster,0x178,8,1,&v)==DEVICE_OK);
}
static const uint64_t events[10]={0x8a0f,0x800f,0x8c0f,0x9c0f,0x9e0f,
                                 0x810f,0xb90f,0xbe0f,0xbf0f,0xd40f};
static void sampler(void)
{
    for(unsigned c=0;c<2;c++) {
        reset();
        for(unsigned i=0;i<10;i++)
            refused(c,0x18+i*16,8,1,events[i],DEVICE_BAD_VALUE);
        restore(c);uint64_t v=1;CHECK(access(c,0xf8,8,1,&v)==DEVICE_OK);
        memcpy(expected,states,sizeof(states));
        for(unsigned repeat=0;repeat<2;repeat++)for(unsigned i=0;i<10;i++) {
            unsigned off=0x18+i*16;
            v=events[i];CHECK(access(c,off,8,1,&v)==DEVICE_OK);
            expected[c].acc_selectors[i]=v;expected[c].acc_selector_written|=1UL<<i;
            CHECK(!memcmp(expected,states,sizeof(states)));
            refused(c,off,8,0,0,DEVICE_BAD_VALUE);
            for(unsigned bit=0;bit<64;bit++)
                refused(c,off,8,1,events[i]^(1UL<<bit),DEVICE_BAD_VALUE);
            for(unsigned width=1;width<=16;width++)if(width!=8)
                refused(c,off,width,1,v,DEVICE_BAD_WIDTH);
            for(unsigned byte=1;byte<8;byte++)
                refused(c,off+byte,8,1,v,DEVICE_BAD_WIDTH);
        }
        /* Counter words have no producer; programming never invents readings. */
        for(unsigned off=0;off<=0xb0;off+=16)
            refused(c,off,8,0,0,DEVICE_UNKNOWN_REGISTER);
        for(unsigned i=0;i<10;i++) {
            states[c].acc_selectors[i]^=1;
            refused(c,0xf8,8,1,1,DEVICE_BAD_VALUE);
            states[c]=expected[c];
            states[c].acc_selector_written&=~(1UL<<i);
            refused(c,0x18,8,1,events[0],DEVICE_BAD_VALUE);
            states[c]=expected[c];
        }
        for(unsigned bit=10;bit<64;bit++) {
            states[c].acc_selector_written|=1UL<<bit;
            refused(c,0x18,8,1,events[0],DEVICE_BAD_VALUE);states[c]=expected[c];
        }
        states[c].acc_boot_policy=0;
        refused(c,0xf8,8,1,1,DEVICE_BAD_VALUE);states[c]=expected[c];
        /* A failed prerequisite must preserve a partly programmed cluster. */
        states[10+c].energy_restore.written=0;
        refused(c,0x18,8,1,0,DEVICE_BAD_VALUE);
        states[10+c]=expected[10+c];
        for(unsigned i=0;i<10;i++) {
            v=0;CHECK(access(c,0x18+i*16,8,1,&v)==DEVICE_OK);
            expected[c].acc_selectors[i]=0;
            CHECK(!memcmp(expected,states,sizeof(states)));
        }
        memset(expected+c,0,sizeof(*expected));
        CHECK(device_model_start(models+c,states+c,0,24000000)==DEVICE_OK);
        CHECK(!memcmp(expected,states,sizeof(states)));
    }
}
int main(void)
{
    CHECK(sizeof(struct device_state)==13000);
    CHECK(offsetof(struct device_state,acc_boot_policy)==0);
    for(unsigned cluster=0;cluster<2;cluster++) {
        reset();refused(cluster,0xf8,8,1,1,DEVICE_BAD_VALUE);
        restore(cluster);
        memcpy(expected,states,sizeof(states));expected[cluster].acc_boot_policy=1;
        for(unsigned repeat=0;repeat<3;repeat++) {
            uint64_t v=1;CHECK(access(cluster,0xf8,8,1,&v)==DEVICE_OK);
            CHECK(v==1 && !memcmp(expected,states,sizeof(states)));
        }
        refused(1-cluster,0xf8,8,1,1,DEVICE_BAD_VALUE);
        refused(cluster,0xf8,8,0,123,DEVICE_BAD_VALUE);
        for(unsigned off=0;off<0x1000;off+=8)if(off!=0xf8)for(unsigned write=0;write<2;write++)
            refused(cluster,off,8,write,123,
                off>=0x18 && off<=0xa8 && !((off-0x18)&15) ? DEVICE_BAD_VALUE : DEVICE_UNKNOWN_REGISTER);
        refused(cluster,0x1000,8,1,1,DEVICE_NOT_FOUND);
        for(unsigned width=0;width<=16;width++)if(width!=8)for(unsigned write=0;write<2;write++)
            refused(cluster,0xf8,width,write,1,DEVICE_BAD_WIDTH);
        for(unsigned byte=1;byte<8;byte++)refused(cluster,0xf8+byte,8,1,1,DEVICE_BAD_WIDTH);
        refused(cluster,0xf8,8,1,0,DEVICE_BAD_VALUE);
        for(unsigned bit=1;bit<64;bit++) {
            refused(cluster,0xf8,8,1,1UL<<bit,DEVICE_BAD_VALUE);
            states[cluster].acc_boot_policy=1UL<<bit;
            refused(cluster,0xf8,8,1,1,DEVICE_BAD_VALUE);states[cluster].acc_boot_policy=1;
        }
        for(unsigned i=2;i<12;i++)if(belongs(i,cluster)) {
            uint64_t *state=i<4 ? &states[i].pmgr_energy_control : &states[i].energy_restore.written;
            uint64_t old=*state;
            for(unsigned bit=0;bit<64;bit++) {
                *state=old^(1UL<<bit);refused(cluster,0xf8,8,1,1,DEVICE_BAD_VALUE);
            }
            *state=old;
            struct device_model m=models[i];
            models[i].base+=0x1000;refused(cluster,0xf8,8,1,1,DEVICE_BAD_CONFIG);models[i]=m;
            models[i].span*=2;refused(cluster,0xf8,8,1,1,DEVICE_BAD_CONFIG);models[i]=m;
            models[i].kind=37;refused(cluster,0xf8,8,1,1,DEVICE_BAD_CONFIG);models[i]=m;
            models[i].config[1]=1;refused(cluster,0xf8,8,1,1,DEVICE_BAD_CONFIG);models[i]=m;
            models[12]=m;count=13;refused(cluster,0xf8,8,1,1,DEVICE_BAD_CONFIG);count=12;
        }
        for(unsigned word=0;word<5;word++) {
            models[cluster].config[word]=word ? 1 : 2;
            refused(cluster,0xf8,8,1,1,DEVICE_BAD_CONFIG);models[cluster]=original[cluster];
        }
        models[cluster].base+=0x1000;refused(cluster,0xf8,8,1,1,DEVICE_BAD_CONFIG);models[cluster]=original[cluster];
        models[12]=models[cluster];count=13;refused(cluster,0xf8,8,1,1,DEVICE_BAD_CONFIG);count=12;
        uint64_t v=1;
        CHECK(device_model_access_state(models+cluster,states+cluster,0xf8,8,1,&v)==DEVICE_BAD_CONFIG);
        memcpy(expected,states,sizeof(states));memset(expected+cluster,0,sizeof(*states));
        CHECK(device_model_start(models+cluster,states+cluster,0,24000000)==DEVICE_OK);
        CHECK(!memcmp(expected,states,sizeof(states)));
    }
    sampler();
    printf("PASS: ACC boot and sampler policy %u checks; ordered restore, isolation, no counter fabrication\n",checks);
    return 0;
}
