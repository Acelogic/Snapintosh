/* SPDX-License-Identifier: MIT */
#include "native-writer-debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);}} while(0)
struct bank {
    uint64_t value[6],control[6],original_value[6],original_control[6];
    unsigned writes,reads,barriers,drop_write,bad_read;
};
static uint64_t read_reg(void *ctx,unsigned index,int control)
{
    struct bank *b=ctx;CHECK(index<6);b->reads++;
    uint64_t value=control ? b->control[index]:b->value[index];
    return b->reads==b->bad_read ? value^4:value;
}
static void write_reg(void *ctx,unsigned index,int control,uint64_t value)
{
    struct bank *b=ctx;CHECK(index<6);b->writes++;
    if(b->writes==b->drop_write)return;
    if(control)b->control[index]=value;else b->value[index]=value;
}
static void barrier(void *ctx) {((struct bank *)ctx)->barriers++;}
static void reset(struct bank *b)
{
    memset(b,0,sizeof(*b));
    for(unsigned i=0;i<6;i++) {
        b->value[i]=b->original_value[i]=0xfffffe0012345000UL+i*4;
        b->control[i]=b->original_control[i]=0x800001e3UL+i*0x10000;
    }
}
static void restored(const struct bank *b,const struct native_writer_debug *s)
{
    CHECK(!memcmp(b->value,b->original_value,sizeof(b->value)));
    CHECK(!memcmp(b->control,b->original_control,sizeof(b->control)));
    CHECK(s->saved && !s->installed && s->restores==1 && !s->restore_failed);
}
int main(void)
{
    struct bank b;struct native_writer_debug s;
    struct native_writer_debug_ops o={read_reg,write_reg,barrier,&b};
    const uint64_t dfr0=0xf11f010305719UL;
    reset(&b);memset(&s,0,sizeof(s));
    CHECK(native_writer_debug_install(&s,&o,dfr0));
    CHECK(s.install_verified && s.installed && s.saved && b.barriers==3);
    for(unsigned i=0;i<6;i++) {
        CHECK(b.value[i]==native_writer_sites[i].va);
        CHECK(b.control[i]==NATIVE_WRITER_BCR);
    }
    unsigned writes=b.writes;
    CHECK(!native_writer_debug_install(&s,&o,dfr0) && b.writes==writes);
    CHECK(native_writer_debug_restore(&s,&o));restored(&b,&s);
    /* Missing capacity must not touch even one physical register. */
    for(unsigned count=0;count<5;count++) {
        reset(&b);memset(&s,0,sizeof(s));
        CHECK(!native_writer_debug_install(&s,&o,(dfr0&~0xf000UL)|((uint64_t)count<<12)));
        CHECK(!b.reads && !b.writes && !s.saved);
    }
    /* Lose each installation write in turn, including bank disable. Failure
     * restores the original bank and never claims an installed breakpoint. */
    for(unsigned drop=1;drop<=18;drop++) {
        reset(&b);memset(&s,0,sizeof(s));b.drop_write=drop;
        CHECK(!native_writer_debug_install(&s,&o,dfr0));
        CHECK(!s.install_verified);restored(&b,&s);
    }
    /* Corrupt every post-write installation readback, independently. */
    for(unsigned bad=13;bad<=30;bad++) {
        reset(&b);memset(&s,0,sizeof(s));b.bad_read=bad;
        CHECK(!native_writer_debug_install(&s,&o,dfr0));restored(&b,&s);
    }
    /* Restoration failures remain visible instead of becoming a success. */
    for(unsigned drop=1;drop<=18;drop++) {
        reset(&b);memset(&s,0,sizeof(s));
        CHECK(native_writer_debug_install(&s,&o,dfr0));
        b.drop_write=b.writes+drop;
        CHECK(!native_writer_debug_restore(&s,&o));
        CHECK(s.restore_failed==1 && s.restores==1 && !s.installed);
    }
    /* Armed subsets (SNAP_ERET_SNAPSHOT leaves site 5 unarmed): an unarmed
     * site keeps its address with a zero control word and is verified so;
     * an empty or out-of-range set touches nothing. */
    for(unsigned armed=0;armed<128;armed++) {
        reset(&b);memset(&s,0,sizeof(s));
        int ok=native_writer_debug_install_armed(&s,&o,dfr0,armed);
        if(!armed || armed>NATIVE_WRITER_ARMED_ALL) {
            CHECK(!ok && !b.reads && !b.writes && !s.saved);
            continue;
        }
        CHECK(ok && s.install_verified && s.installed);
        for(unsigned i=0;i<6;i++) {
            CHECK(b.value[i]==native_writer_sites[i].va);
            CHECK(b.control[i]==((armed>>i)&1 ? NATIVE_WRITER_BCR : 0));
            CHECK(s.observed_control[i]==b.control[i]);
        }
        CHECK(native_writer_debug_restore(&s,&o));restored(&b,&s);
    }
    const unsigned eret=NATIVE_WRITER_ARMED_ALL&~(1u<<NATIVE_WRITER_RETURN_SITE);
    for(unsigned bad=13;bad<=30;bad++) {
        reset(&b);memset(&s,0,sizeof(s));b.bad_read=bad;
        CHECK(!native_writer_debug_install_armed(&s,&o,dfr0,eret));restored(&b,&s);
    }
    for(unsigned drop=1;drop<=18;drop++) {
        reset(&b);memset(&s,0,sizeof(s));b.drop_write=drop;
        int ok=native_writer_debug_install_armed(&s,&o,dfr0,eret);
        /* The unarmed site's final control write repeats the disable phase's
         * zero, so losing it changes nothing; losing its disable write leaves
         * the original enabled word, which the disable check refuses. */
        if(drop==12+1+NATIVE_WRITER_RETURN_SITE) {
            CHECK(ok && s.install_verified && !b.control[NATIVE_WRITER_RETURN_SITE]);
            CHECK(native_writer_debug_restore(&s,&o));restored(&b,&s);
        } else {
            CHECK(!ok && !s.install_verified);restored(&b,&s);
        }
    }
    reset(&b);memset(&s,0,sizeof(s));
    CHECK(native_writer_debug_restore(&s,&o));CHECK(!b.reads && !b.writes);
    CHECK(!native_writer_debug_install(0,&o,dfr0));
    CHECK(!native_writer_debug_install(&s,0,dfr0));
    CHECK(!native_writer_debug_restore(0,&o));
    CHECK(!native_writer_debug_restore(&s,0));
    printf("PASS %u native-writer debug-bank lifecycle checks\n",checks);
    return 0;
}
